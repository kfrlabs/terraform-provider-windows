// Package provider - resource_windows_iis_site implements the full
// Terraform resource lifecycle for windows_iis_site.
//
// An IIS site is provisioned through the WebAdministration module
// (New-Item IIS:\Sites\<name> -Bindings @() plus Set-WebConfigurationProperty
// / Set-ItemProperty writes, Start-Website / Stop-Website for runtime
// state). Bindings are deliberately NOT managed here: the site is always
// created with zero bindings and the bindings attribute is a read-only
// view (protocol plus binding_information) owned by the
// windows_iis_binding resource (issue #285).
//
// Every setting except name is Optional+Computed: only configured
// attributes are enforced, unconfigured ones reflect the observed value
// (same semantics as windows_firewall_profile and windows_iis_app_pool).
// site_id is Optional+Computed + ForceNew: when left unconfigured IIS
// allocates the lowest free ID itself.
//
// A configured state = "Started" on a site with no bindings leaves the
// site Stopped with a warning (IIS cannot run an unbound site) instead of
// failing; a plan modifier suppresses the resulting perpetual diff while
// the site stays unbound.
//
// Spec alignment: windows_iis_site spec v1 (issue #284).
// Framework:      terraform-plugin-framework v1.19.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

var (
	_ resource.Resource                = (*windowsIISSiteResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsIISSiteResource)(nil)
	_ resource.ResourceWithImportState = (*windowsIISSiteResource)(nil)
)

// NewWindowsIISSiteResource is the constructor registered in provider.go.
func NewWindowsIISSiteResource() resource.Resource {
	return &windowsIISSiteResource{}
}

// windowsIISSiteResource is the TPF resource type for windows_iis_site.
type windowsIISSiteResource struct {
	site winclient.WindowsIISSiteClient
}

// iisSiteDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Site operations are
// normally fast, but a stalled PowerShell/SSH session must never block
// Terraform forever: every CRUD handler bounds its work with this default.
const iisSiteDefaultTimeout = 10 * time.Minute

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

// windowsIISSiteBindingModel is one element of the read-only bindings view.
type windowsIISSiteBindingModel struct {
	Protocol           types.String `tfsdk:"protocol"`
	BindingInformation types.String `tfsdk:"binding_information"`
}

// windowsIISSiteModel is the Terraform state/plan model for
// windows_iis_site. Every tfsdk tag matches an attribute key in
// windowsIISSiteSchemaDefinition.
type windowsIISSiteModel struct {
	ID                       types.String   `tfsdk:"id"`
	Name                     types.String   `tfsdk:"name"`
	SiteID                   types.Int64    `tfsdk:"site_id"`
	PhysicalPath             types.String   `tfsdk:"physical_path"`
	ApplicationPool          types.String   `tfsdk:"application_pool"`
	AutoStart                types.Bool     `tfsdk:"auto_start"`
	PreloadEnabled           types.Bool     `tfsdk:"preload_enabled"`
	EnabledProtocols         types.String   `tfsdk:"enabled_protocols"`
	LogEnabled               types.Bool     `tfsdk:"log_enabled"`
	LogDirectory             types.String   `tfsdk:"log_directory"`
	LogFormat                types.String   `tfsdk:"log_format"`
	ConnectionTimeoutSeconds types.Int64    `tfsdk:"connection_timeout_seconds"`
	MaxConnections           types.Int64    `tfsdk:"max_connections"`
	Bindings                 types.List     `tfsdk:"bindings"`
	State                    types.String   `tfsdk:"state"`
	Timeouts                 timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsIISSiteResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iis_site"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_iis_site resource.
func (r *windowsIISSiteResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsIISSiteSchemaDefinition(ctx)
}

// windowsIISSiteBindingObjectType is the element type of the read-only
// bindings view. The shape (protocol plus binding_information) is frozen
// for issue #285, which promotes this exact view to a managed resource.
func windowsIISSiteBindingObjectType() attr.Type {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"protocol":            types.StringType,
		"binding_information": types.StringType,
	}}
}

// windowsIISSiteSchemaDefinition returns the complete TPF schema for
// windows_iis_site. `name` is Required + ForceNew (the id); `site_id` is
// Optional+Computed + ForceNew; `physical_path` is Required and updated in
// place; every other setting is Optional+Computed (partial management:
// only configured attributes are sent to the host). `bindings` is
// Computed-only (managed by windows_iis_binding, issue #285).
func windowsIISSiteSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages an IIS site on a remote Windows host via SSH and PowerShell " +
			"(`WebAdministration` module: `New-Item IIS:\\Sites\\<name> -Bindings @()`, " +
			"`Get/Set-WebConfigurationProperty`, `Set-ItemProperty IIS:\\Sites\\<name>`, " +
			"`Remove-Website`, `Start-Website` / `Stop-Website`).\n\n" +
			"The site is always created with zero bindings: bindings are not managed here (see " +
			"`windows_iis_binding`). The read-only `bindings` attribute (`protocol` plus " +
			"`binding_information`) reflects the observed view so plans stay stable.\n\n" +
			"Only the attributes configured in Terraform are written; every other setting on the host is " +
			"left untouched and undiffed (unconfigured attributes reflect the observed value). The runtime " +
			"`state` (`Started` / `Stopped`) is enforced only when configured — except that a `Started` " +
			"site with no bindings stays `Stopped` with a warning (IIS cannot run an unbound site) " +
			"instead of failing.\n\n" +
			"Requires IIS on the target host: install it with the `windows_feature` resource (`Web-Server`; " +
			"add `Web-Mgmt-Console` / `Web-Scripting-Tools` for the `WebAdministration` module on Server Core).\n\n" +
			"**Partial failures:** if creation fails after the site was already registered in IIS, " +
			"the provider persists the observed state before reporting the error, so the resource is marked " +
			"tainted. If update fails after IIS applied part of the change, the provider saves the observed " +
			"partial state before reporting the error. Fix the cause and run `terraform apply` again to reconcile.\n\n" +
			"A nil state on error does not guarantee nothing was created: a failure that returns no state " +
			"leaves an orphaned site that must be removed with `Remove-Website` or re-adopted " +
			"with `terraform import`.\n\n" +
			"Import format: `<site name>`.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier. Set to the site name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"name": schema.StringAttribute{
				Required: true,
				Description: "Site name. 1-64 characters; must not contain `/ \\ [ ] : ; , ? * \" < > |` " +
					"and must not have leading or trailing spaces. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					iisSiteNameValidator{},
				},
			},

			"site_id": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Numeric site ID (1-4294967295). Immutable after creation (ForceNew). When left unconfigured, IIS allocates the lowest free ID itself.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.Between(1, 4294967295),
				},
			},

			"physical_path": schema.StringAttribute{
				Required:    true,
				Description: "Physical path of the site root on the target host (e.g. `C:\\inetpub\\wwwroot`). The directory must already exist (manage it with `windows_directory`): references to `%SystemDrive%`-style environment variables are expanded host-side for the existence check and stored verbatim. Never created implicitly; updated in place.",
			},

			"application_pool": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Application pool serving the site root. The pool must already exist (manage it with `windows_iis_app_pool`); it is never created implicitly. Updated in place.",
			},

			"auto_start": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the site starts automatically when WAS starts (`serverAutoStart`).",
			},

			"preload_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the site root application is preloaded (`application[@path='/'] preloadEnabled`).",
			},

			"enabled_protocols": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Protocols the site root application listens on (`application[@path='/'] enabledProtocols`, e.g. `http`).",
			},

			"log_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether IIS logging is enabled for the site (`logFile.enabled`).",
			},

			"log_directory": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Directory for the site log files (`logFile.directory`, e.g. `%SystemDrive%\\inetpub\\logs\\LogFiles`).",
			},

			"log_format": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Log file format. One of `W3C`, `IIS`, `NCSA`.",
				Validators: []validator.String{
					stringvalidator.OneOf("W3C", "IIS", "NCSA"),
				},
			},

			"connection_timeout_seconds": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Connection timeout in whole seconds (`limits.connectionTimeout`, 0 disables the timeout).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},

			"max_connections": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Maximum concurrent connections (`limits.maxConnections`; 0 means unlimited).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},

			"bindings": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Read-only view of the site bindings (`protocol` plus `binding_information`, e.g. `*:80:example.com`). Managed by the `windows_iis_binding` resource — never written by this resource.",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"protocol": schema.StringAttribute{
							Computed:    true,
							Description: "Binding protocol (e.g. `http`, `https`).",
						},
						"binding_information": schema.StringAttribute{
							Computed:    true,
							Description: "Binding information (`IP:port:hostheader`, e.g. `*:80:example.com`).",
						},
					},
				},
			},

			"state": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Runtime state of the site. One of `Started`, `Stopped`. Enforced only when configured (`Start-Website` / `Stop-Website`). A `Started` site with no bindings stays `Stopped` with a warning (IIS cannot run an unbound site); the diff is suppressed while the site stays unbound.",
				Validators: []validator.String{
					stringvalidator.OneOf("Started", "Stopped"),
				},
				PlanModifiers: []planmodifier.String{
					iisSiteStateSuppressUnboundModifier{},
				},
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// iisSiteDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, iisSiteTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// iisSiteNameValidator enforces the site-name rules at plan time
// (mirroring winclient.ValidateIISSiteName): no forbidden characters and
// no leading/trailing spaces. Length is covered by LengthBetween.
type iisSiteNameValidator struct{}

func (v iisSiteNameValidator) Description(_ context.Context) string {
	return "Site name must not contain / \\ [ ] : ; , ? * \" < > | and must not have leading or trailing spaces."
}

func (v iisSiteNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisSiteNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if strings.TrimSpace(val) != val {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid IIS site name",
			fmt.Sprintf("IIS site name %q must not have leading or trailing spaces.", val),
		)
		return
	}
	if strings.ContainsAny(val, `/\[]:;,?*"<>|`) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid IIS site name",
			fmt.Sprintf("IIS site name %q must not contain any of / \\ [ ] : ; , ? * \" < > |.", val),
		)
	}
}

// iisSiteStateSuppressUnboundModifier suppresses the perpetual
// Started-vs-Stopped diff while the site has no bindings: IIS cannot run
// an unbound site, so the CRUD scripts deliberately leave it Stopped and
// warn. Planning Stopped matches the host reality; once bindings appear
// (managed by windows_iis_binding) the modifier goes quiet and the
// next plan proposes Started again.
type iisSiteStateSuppressUnboundModifier struct{}

func (m iisSiteStateSuppressUnboundModifier) Description(_ context.Context) string {
	return "Plans Stopped instead of Started while the site has no bindings (IIS cannot run an unbound site)."
}

func (m iisSiteStateSuppressUnboundModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m iisSiteStateSuppressUnboundModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if req.PlanValue.ValueString() != "Started" {
		return
	}
	var planModel windowsIISSiteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &planModel)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if planModel.Bindings.IsNull() || planModel.Bindings.IsUnknown() {
		return
	}
	if len(planModel.Bindings.Elements()) == 0 {
		resp.PlanValue = types.StringValue("Stopped")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates an
// IISSiteClient for this resource instance.
func (r *windowsIISSiteResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T.", req.ProviderData),
		)
		return
	}
	r.site = winclient.NewIISSiteClient(client)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create provisions the site with zero bindings, applies the configured
// settings in one script and enforces the configured runtime state. A
// Started site with no bindings stays Stopped with a warning (IIS cannot
// run an unbound site) instead of failing.
func (r *windowsIISSiteResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsIISSiteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, iisSiteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	name := plan.Name.ValueString()
	tflog.Debug(ctx, "Creating Windows IIS site", map[string]any{
		"name": name,
	})

	settings := modelToIISSiteSettings(plan)

	state, err := r.site.Create(ctx, winclient.IISSiteInput{
		Name:     name,
		Settings: settings,
	})
	if err != nil {
		// Partial failure (ADR-0012): persist the observed state so the
		// resource is tainted rather than dropped from state. A nil state
		// (for example, the already_exists pre-flight, or the
		// script-side rollback of a half-created site) stays error-only.
		if state != nil {
			m, diags := iisSiteStateToModel(state)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				m.Timeouts = plan.Timeouts
				m.Name = plan.Name
				m.ID = types.StringValue(name)
				resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
			}
		}
		addIISSiteDiag(&resp.Diagnostics, "Error creating Windows IIS site", err)
		return
	}
	if state == nil {
		resp.Diagnostics.AddError(
			"Windows IIS site not found",
			fmt.Sprintf("IIS site %q does not exist on the target host.", name),
		)
		return
	}

	warnIISSiteLeftStopped(&resp.Diagnostics, plan.State, state)

	m, diags := iisSiteStateToModel(state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Preserve the user-configured per-operation timeouts and the ForceNew
	// identity: the projection covers only host-observed fields, and Set
	// overwrites the full state.
	m.Timeouts = plan.Timeouts
	m.Name = plan.Name
	m.ID = types.StringValue(name)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live site. A site deleted
// out-of-band removes the resource from state. The timeouts block is
// preserved from prior state (it is user configuration, not observed
// state).
func (r *windowsIISSiteResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsIISSiteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, iisSiteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	name := state.Name.ValueString()
	tflog.Debug(ctx, "Reading Windows IIS site", map[string]any{
		"name": name,
	})

	observed, err := r.site.Read(ctx, name)
	if err != nil {
		addIISSiteDiag(&resp.Diagnostics, "Error reading Windows IIS site", err)
		return
	}
	if observed == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	m, diags := iisSiteStateToModel(observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.Timeouts = state.Timeouts
	m.Name = state.Name
	m.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place changes: only configured attributes that
// changed since the prior state are sent (site_id is ForceNew and is
// never re-sent). Like Create, a Started enforcement with zero bindings
// leaves the site Stopped with a warning instead of failing.
func (r *windowsIISSiteResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsIISSiteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, iisSiteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// name and site_id are ForceNew so they never change here.
	name := plan.Name.ValueString()
	tflog.Debug(ctx, "Updating Windows IIS site", map[string]any{
		"name": name,
	})

	settings := planToIISSiteDelta(plan, prior)

	if !settings.IISSiteConfigured() {
		// Nothing changed: refresh from the host instead of issuing a
		// no-op write.
		observed, err := r.site.Read(ctx, name)
		if err != nil {
			addIISSiteDiag(&resp.Diagnostics, "Error updating Windows IIS site", err)
			return
		}
		if observed == nil {
			resp.Diagnostics.AddError(
				"Windows IIS site not found",
				fmt.Sprintf("IIS site %q does not exist on the target host.", name),
			)
			return
		}
		m, diags := iisSiteStateToModel(observed)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		m.Timeouts = plan.Timeouts
		m.Name = plan.Name
		m.ID = prior.ID
		resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
		return
	}

	observed, err := r.site.Update(ctx, winclient.IISSiteInput{
		Name:     name,
		Settings: settings,
	})
	if err != nil {
		// Partial failure (ADR-0012): persist the observed state so the
		// resource keeps its partial state rather than staying at prior
		// state. A nil state stays error-only.
		if observed != nil {
			m, diags := iisSiteStateToModel(observed)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				m.Timeouts = plan.Timeouts
				m.Name = plan.Name
				m.ID = prior.ID
				resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
			}
		}
		addIISSiteDiag(&resp.Diagnostics, "Error updating Windows IIS site", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"Windows IIS site not found",
			fmt.Sprintf("IIS site %q does not exist on the target host.", name),
		)
		return
	}

	warnIISSiteLeftStopped(&resp.Diagnostics, plan.State, observed)

	m, diags := iisSiteStateToModel(observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.Timeouts = plan.Timeouts
	m.Name = plan.Name
	m.ID = prior.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the site (Remove-Website). A site already gone
// out-of-band is already absent (no error).
func (r *windowsIISSiteResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsIISSiteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, iisSiteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	name := state.Name.ValueString()
	tflog.Debug(ctx, "Deleting Windows IIS site", map[string]any{
		"name": name,
	})

	if err := r.site.Delete(ctx, name); err != nil {
		addIISSiteDiag(&resp.Diagnostics, "Error deleting Windows IIS site", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing site by name. The site_id starts
// managed (it is part of the identity); bindings are observed as the
// read-only view (owned by windows_iis_binding).
func (r *windowsIISSiteResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if err := winclient.ValidateIISSiteName(name); err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID %q is not a valid IIS site name: %s.", req.ID, err),
		)
		return
	}

	tflog.Debug(ctx, "Importing Windows IIS site", map[string]any{
		"name": name,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, iisSiteDefaultTimeout)
	defer cancel()

	observed, err := r.site.Read(ctx, name)
	if err != nil {
		addIISSiteDiag(&resp.Diagnostics, "Error importing Windows IIS site", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"Windows IIS site not found",
			fmt.Sprintf("IIS site %q does not exist on the target host.", name),
		)
		return
	}

	m, diags := iisSiteStateToModel(observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by State.Set — use a typed null instead (the
	// subsequent Read fills in the configured values).
	m.Timeouts = iisSiteNullTimeouts()
	m.Name = types.StringValue(observed.Name)
	m.ID = types.StringValue(observed.Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helpers: settings projection (partial management)
// ---------------------------------------------------------------------------

// modelToIISSiteSettings converts a Terraform model to an IISSiteSettings
// delta: null or unknown attributes stay nil and are never sent to the
// host. Optional+Computed attributes not configured are Unknown in the
// plan during Create, so Unknown is skipped (never sent) rather than
// aborting. site_id is included (create-only; Update strips it via the
// delta below).
func modelToIISSiteSettings(m windowsIISSiteModel) winclient.IISSiteSettings {
	var s winclient.IISSiteSettings

	strPtr := func(st types.String) *string {
		if st.IsNull() || st.IsUnknown() {
			return nil
		}
		v := st.ValueString()
		return &v
	}
	boolPtr := func(b types.Bool) *bool {
		if b.IsNull() || b.IsUnknown() {
			return nil
		}
		v := b.ValueBool()
		return &v
	}
	intPtr := func(n types.Int64) *int64 {
		if n.IsNull() || n.IsUnknown() {
			return nil
		}
		v := n.ValueInt64()
		return &v
	}

	// site_id is ForceNew: always include the planned value on Create
	// (null/unknown means "let IIS allocate the lowest free ID").
	s.SiteID = intPtr(m.SiteID)
	s.PhysicalPath = strPtr(m.PhysicalPath)
	s.ApplicationPool = strPtr(m.ApplicationPool)
	s.AutoStart = boolPtr(m.AutoStart)
	s.PreloadEnabled = boolPtr(m.PreloadEnabled)
	s.EnabledProtocols = strPtr(m.EnabledProtocols)
	s.LogEnabled = boolPtr(m.LogEnabled)
	s.LogDirectory = strPtr(m.LogDirectory)
	s.LogFormat = strPtr(m.LogFormat)
	s.ConnectionTimeoutSeconds = intPtr(m.ConnectionTimeoutSeconds)
	s.MaxConnections = intPtr(m.MaxConnections)
	s.State = strPtr(m.State)

	return s
}

// planToIISSiteDelta narrows the full plan projection to only the
// configured attributes that changed since the prior state: unchanged
// values (including unconfigured attributes retaining their observed
// prior values) are nilled so the host write touches only what drifted.
// site_id is ForceNew and is always stripped: replacement recreates the
// site with the new ID instead of re-setting it in place.
func planToIISSiteDelta(plan, prior windowsIISSiteModel) winclient.IISSiteSettings {
	s := modelToIISSiteSettings(plan)

	// site_id never participates in an in-place update.
	s.SiteID = nil

	changedStr := func(p, o types.String, v **string) {
		if *v != nil && p.Equal(o) {
			*v = nil
		}
	}
	changedBool := func(p, o types.Bool, v **bool) {
		if *v != nil && p.Equal(o) {
			*v = nil
		}
	}
	changedInt := func(p, o types.Int64, v **int64) {
		if *v != nil && p.Equal(o) {
			*v = nil
		}
	}

	changedStr(plan.PhysicalPath, prior.PhysicalPath, &s.PhysicalPath)
	changedStr(plan.ApplicationPool, prior.ApplicationPool, &s.ApplicationPool)
	changedBool(plan.AutoStart, prior.AutoStart, &s.AutoStart)
	changedBool(plan.PreloadEnabled, prior.PreloadEnabled, &s.PreloadEnabled)
	changedStr(plan.EnabledProtocols, prior.EnabledProtocols, &s.EnabledProtocols)
	changedBool(plan.LogEnabled, prior.LogEnabled, &s.LogEnabled)
	changedStr(plan.LogDirectory, prior.LogDirectory, &s.LogDirectory)
	changedStr(plan.LogFormat, prior.LogFormat, &s.LogFormat)
	changedInt(plan.ConnectionTimeoutSeconds, prior.ConnectionTimeoutSeconds, &s.ConnectionTimeoutSeconds)
	changedInt(plan.MaxConnections, prior.MaxConnections, &s.MaxConnections)
	changedStr(plan.State, prior.State, &s.State)

	return s
}

// ---------------------------------------------------------------------------
// Helpers: state projection, timeouts, diagnostics
// ---------------------------------------------------------------------------

// iisSiteTimeoutsOpts declares which per-operation timeouts the resource exposes.
var iisSiteTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// iisSiteNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO
// attribute types, which the framework rejects on State.Set — the
// failure mode on import, where there is no prior state to copy the
// value from.
func iisSiteNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if iisSiteTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if iisSiteTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if iisSiteTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if iisSiteTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// iisSiteBindingsToModel projects the observed bindings view into a
// Terraform list. The view is read-only and fully observed (no declared
// schedule-style unmanaged case): an empty host collection is an empty
// list.
func iisSiteBindingsToModel(bindings []winclient.IISSiteBinding) (types.List, diag.Diagnostics) {
	vals := make([]attr.Value, 0, len(bindings))
	for _, b := range bindings {
		obj, d := types.ObjectValue(
			map[string]attr.Type{
				"protocol":            types.StringType,
				"binding_information": types.StringType,
			},
			map[string]attr.Value{
				"protocol":            types.StringValue(b.Protocol),
				"binding_information": types.StringValue(b.BindingInformation),
			},
		)
		if d.HasError() {
			return types.ListNull(windowsIISSiteBindingObjectType()), d
		}
		vals = append(vals, obj)
	}
	list, d := types.ListValue(windowsIISSiteBindingObjectType(), vals)
	return list, d
}

// iisSiteStateToModel projects an observed IISSiteState into a Terraform
// model. Every setting is fully observed (the provider narrows to the
// configured delta only on write paths): after Read the state always
// reflects the host, and unconfigured attributes stay undiffed because
// they are Optional+Computed.
func iisSiteStateToModel(s *winclient.IISSiteState) (windowsIISSiteModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	bindings, d := iisSiteBindingsToModel(s.Bindings)
	diags.Append(d...)
	if diags.HasError() {
		return windowsIISSiteModel{}, diags
	}

	return windowsIISSiteModel{
		ID:                       types.StringValue(s.Name),
		Name:                     types.StringValue(s.Name),
		SiteID:                   types.Int64Value(s.SiteID),
		PhysicalPath:             types.StringValue(s.PhysicalPath),
		ApplicationPool:          types.StringValue(s.ApplicationPool),
		AutoStart:                types.BoolValue(s.AutoStart),
		PreloadEnabled:           types.BoolValue(s.PreloadEnabled),
		EnabledProtocols:         types.StringValue(s.EnabledProtocols),
		LogEnabled:               types.BoolValue(s.LogEnabled),
		LogDirectory:             types.StringValue(s.LogDirectory),
		LogFormat:                types.StringValue(s.LogFormat),
		ConnectionTimeoutSeconds: types.Int64Value(s.ConnectionTimeoutSeconds),
		MaxConnections:           types.Int64Value(s.MaxConnections),
		Bindings:                 bindings,
		State:                    types.StringValue(s.State),
	}, diags
}

// warnIISSiteLeftStopped warns when a configured Started state could not
// be enforced because the site has no bindings: IIS cannot run an
// unbound site, so the scripts leave it Stopped instead of failing (the
// state attribute plan modifier then suppresses the perpetual diff while
// the site stays unbound).
func warnIISSiteLeftStopped(d *diag.Diagnostics, plannedState types.String, observed *winclient.IISSiteState) {
	if plannedState.IsNull() || plannedState.IsUnknown() {
		return
	}
	if plannedState.ValueString() != "Started" {
		return
	}
	if observed.State == "Started" || len(observed.Bindings) > 0 {
		return
	}
	d.AddWarning(
		"IIS site left Stopped: no bindings",
		fmt.Sprintf("IIS site %q is configured with state = \"Started\" but has no bindings, and IIS cannot run an unbound site, so it was left Stopped. Add bindings (windows_iis_binding) and the next apply will start it.", observed.Name),
	)
}

// addIISSiteDiag appends a diagnostic from a site client error.
// Id-conflict, missing-pool and missing-path refusals keep their full
// guidance; other kinds are enriched with context fields when available.
func addIISSiteDiag(d *diag.Diagnostics, summary string, err error) {
	var ae *winclient.IISSiteError
	if errors.As(err, &ae) {
		switch ae.Kind {
		case winclient.IISSiteErrorIDConflict,
			winclient.IISSiteErrorAppPoolNotFound,
			winclient.IISSiteErrorPathNotFound,
			winclient.IISSiteErrorAlreadyExists,
			winclient.IISSiteErrorIISNotInstalled:
			d.AddError(summary+" ["+string(ae.Kind)+"]", ae.Message)
			return
		}
		detail := ae.Message
		if len(ae.Context) > 0 {
			var parts []string
			for k, v := range ae.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if ae.Cause != nil {
			detail += "\n\nCause: " + ae.Cause.Error()
		}
		d.AddError(summary+" ["+string(ae.Kind)+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
