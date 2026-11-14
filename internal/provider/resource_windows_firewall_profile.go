// Package provider - resource_windows_firewall_profile implements the full
// Terraform resource lifecycle for windows_firewall_profile.
//
// A firewall profile (Domain, Private, Public) always exists — Windows
// creates it with the OS. Create and Update are therefore the same operation
// (Set-NetFirewallProfile); only the attributes configured in Terraform are
// sent (-PolicyStore PersistentStore). Read refreshes from
// Get-NetFirewallProfile and never removes the resource from state. Delete
// makes no remote change by default; with restore_on_destroy it re-applies
// the pre-existing values captured into private state at Create (or import)
// time.
//
// An SSH lockout guard runs fail-closed inside every Apply: tightening the
// profile that carries the provider's own SSH session without an enabled
// inbound Allow rule for the provider port is refused before anything is
// written (see winclient/firewall_profile.go and sshpath.go).
//
// Spec alignment: windows_firewall_profile spec v1 (issue #223).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
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
	_ resource.Resource                     = (*windowsFirewallProfileResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsFirewallProfileResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsFirewallProfileResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsFirewallProfileResource)(nil)
)

// NewWindowsFirewallProfileResource is the constructor registered in provider.go.
func NewWindowsFirewallProfileResource() resource.Resource {
	return &windowsFirewallProfileResource{}
}

// windowsFirewallProfileResource is the TPF resource type for windows_firewall_profile.
type windowsFirewallProfileResource struct {
	fp winclient.WindowsFirewallProfileClient
}

// firewallProfileDefaultTimeout is the fallback per-operation timeout when
// the user does not provide a `timeouts {}` block. Profile operations are
// normally fast, but a stalled PowerShell/SSH session must never block
// Terraform forever: every CRUD handler bounds its work with this default.
const firewallProfileDefaultTimeout = 10 * time.Minute

// firewallProfilePrivateKey is the private-state key holding the JSON-encoded
// pre-existing profile snapshot captured at Create (or import) time. Delete
// with restore_on_destroy re-applies it verbatim.
const firewallProfilePrivateKey = "original_state"

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsFirewallProfileModel is the Terraform state/plan model for
// windows_firewall_profile. Every tfsdk tag matches an attribute key in
// windowsFirewallProfileSchemaDefinition.
type windowsFirewallProfileModel struct {
	ID                              types.String   `tfsdk:"id"`
	Name                            types.String   `tfsdk:"name"`
	Enabled                         types.Bool     `tfsdk:"enabled"`
	DefaultInboundAction            types.String   `tfsdk:"default_inbound_action"`
	DefaultOutboundAction           types.String   `tfsdk:"default_outbound_action"`
	AllowInboundRules               types.Bool     `tfsdk:"allow_inbound_rules"`
	AllowLocalFirewallRules         types.Bool     `tfsdk:"allow_local_firewall_rules"`
	AllowLocalIPsecRules            types.Bool     `tfsdk:"allow_local_ipsec_rules"`
	AllowUnicastResponseToMulticast types.Bool     `tfsdk:"allow_unicast_response_to_multicast"`
	NotifyOnListen                  types.Bool     `tfsdk:"notify_on_listen"`
	LogFileName                     types.String   `tfsdk:"log_file_name"`
	LogMaxSizeKilobytes             types.Int64    `tfsdk:"log_max_size_kilobytes"`
	LogAllowed                      types.Bool     `tfsdk:"log_allowed"`
	LogBlocked                      types.Bool     `tfsdk:"log_blocked"`
	LogIgnored                      types.Bool     `tfsdk:"log_ignored"`
	DisabledInterfaceAliases        types.Set      `tfsdk:"disabled_interface_aliases"`
	RestoreOnDestroy                types.Bool     `tfsdk:"restore_on_destroy"`
	Timeouts                        timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsFirewallProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_profile"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_firewall_profile resource.
func (r *windowsFirewallProfileResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsFirewallProfileSchemaDefinition(ctx)
}

// windowsFirewallProfileSchemaDefinition returns the complete TPF schema for
// windows_firewall_profile. `name` is Required + ForceNew (the id); every
// other setting is Optional+Computed (partial management: only configured
// attributes are sent to Set-NetFirewallProfile).
func windowsFirewallProfileSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a Windows Defender Firewall profile (`Domain`, `Private` or `Public`) " +
			"on a remote Windows host via SSH and PowerShell (`NetSecurity` module). " +
			"A profile always exists — Windows creates it with the OS — so creating this resource never " +
			"provisions anything new: it only tunes the profile's settings in place, and deleting it makes no " +
			"remote change unless `restore_on_destroy` is set.\n\n" +
			"Only the attributes configured in Terraform are written (`Set-NetFirewallProfile -PolicyStore " +
			"PersistentStore`); every other setting on the host is left untouched and undiffed. Group Policy " +
			"owns the `ActiveStore` view: when a GPO manages a profile, what `Get-NetFirewallProfile` reports " +
			"(ActiveStore) can diverge from what Terraform writes (PersistentStore), and GPO-managed " +
			"`NotConfigured` tri-states are observed as unset rather than exposed as values.\n\n" +
			"Lockout guard: tightening the profile that carries the provider's own SSH session (blocking " +
			"inbound by default, or disabling inbound rules) without an enabled inbound `Allow` TCP rule for " +
			"the provider port is refused fail-closed before anything is applied. When you manage that " +
			"profile, declare the SSH allowance first and add `depends_on = [windows_firewall_rule.ssh]` so " +
			"the rule exists before the profile tightens. Disabling a profile (`enabled = false`) turns the " +
			"firewall off for that network location and is only ever appropriate on hosts that are otherwise " +
			"isolated.\n\n" +
			"Import format: `<Domain|Private|Public>`.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier. Set to the profile name (`Domain`, `Private` or `Public`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"name": schema.StringAttribute{
				Required: true,
				Description: "Firewall profile name. One of `Domain`, `Private`, `Public`. " +
					"Immutable after creation (ForceNew); the profile always exists on the host.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("Domain", "Private", "Public"),
				},
			},

			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether the firewall is active for this profile. Disabling it (`false`) turns the firewall off for that network location: plan warns, and it should only be used on otherwise isolated hosts.",
			},

			"default_inbound_action": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Default action for inbound traffic that matches no rule. One of `Allow`, `Block`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Allow", "Block"),
				},
			},

			"default_outbound_action": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Default action for outbound traffic that matches no rule. One of `Allow`, `Block`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Allow", "Block"),
				},
			},

			"allow_inbound_rules": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether inbound firewall rules are honoured for this profile. Disabling it on the profile carrying the SSH session trips the lockout guard.",
			},

			"allow_local_firewall_rules": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether locally created firewall rules are honoured for this profile.",
			},

			"allow_local_ipsec_rules": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether locally created IPsec rules are honoured for this profile.",
			},

			"allow_unicast_response_to_multicast": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether unicast responses to multicast traffic are allowed for this profile.",
			},

			"notify_on_listen": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether the user is notified when an application starts listening on a port.",
			},

			"log_file_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Path of the firewall log file. Must be an absolute Windows path or start with `%systemroot%` (case-insensitive).",
				Validators: []validator.String{
					firewallProfileLogPathValidator{},
				},
			},

			"log_max_size_kilobytes": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Description: "Maximum size of the firewall log file, in kilobytes (1-32767).",
				Validators: []validator.Int64{
					int64validator.Between(1, 32767),
				},
			},

			"log_allowed": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether allowed connections are written to the firewall log.",
			},

			"log_blocked": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether blocked connections are written to the firewall log.",
			},

			"log_ignored": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether ignored (dropped before filtering) packets are written to the firewall log.",
			},

			"disabled_interface_aliases": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
				Description: "Interfaces excluded from this profile (e.g. a VPN adapter). Null means unmanaged; an empty set clears the exclusion list.",
			},

			"restore_on_destroy": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "When `true`, destroy re-applies the pre-existing profile values captured at creation (or import) time. Defaults to `false`: destroy makes no remote change.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// firewallProfileDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, fwProfileTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// ConfigValidators returns the resource-level cross-field validators:
//   - firewallProfileEnabledValidator: warns when the profile is disabled.
func (r *windowsFirewallProfileResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		firewallProfileEnabledValidator{},
	}
}

// firewallProfileEnabledValidator warns (never errors) when enabled = false:
// disabling a profile turns the firewall off for that network location.
type firewallProfileEnabledValidator struct{}

func (v firewallProfileEnabledValidator) Description(_ context.Context) string {
	return "Warns when the firewall profile is disabled."
}

func (v firewallProfileEnabledValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallProfileEnabledValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var enabled types.Bool
	diags := req.Config.GetAttribute(ctx, path.Root("enabled"), &enabled)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if enabled.IsNull() || enabled.IsUnknown() {
		return
	}
	if !enabled.ValueBool() {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("enabled"),
			"Firewall profile disabled",
			"Disabling this firewall profile turns the Windows firewall off for that network location. "+
				"Only use enabled = false on hosts that are otherwise isolated from untrusted networks.",
		)
	}
}

// firewallProfileLogPathValidator accepts an absolute Windows path or a
// %systemroot%-prefixed one (the host default is
// %systemroot%\system32\LogFiles\Firewall\pfirewall.log).
type firewallProfileLogPathValidator struct{}

func (v firewallProfileLogPathValidator) Description(_ context.Context) string {
	return "Log file name must be an absolute Windows path or start with %systemroot%."
}

func (v firewallProfileLogPathValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallProfileLogPathValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	upper := strings.ToUpper(val)
	if strings.HasPrefix(upper, "%SYSTEMROOT%") {
		return
	}
	// Absolute Windows path: drive-letter (C:\...) or UNC (\\server\share).
	if len(val) >= 3 && ((val[0] >= 'A' && val[0] <= 'Z') || (val[0] >= 'a' && val[0] <= 'z')) && val[1] == ':' && (val[2] == '\\' || val[2] == '/') {
		return
	}
	if strings.HasPrefix(val, `\\`) {
		return
	}
	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid log file path",
		fmt.Sprintf("log_file_name must be an absolute Windows path (e.g. C:\\Logs\\pfirewall.log or \\\\server\\share\\pfirewall.log) or start with %%systemroot%%; got %q.", val),
	)
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates a
// FirewallProfileClient for this resource instance.
func (r *windowsFirewallProfileResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.fp = winclient.NewFirewallProfileClient(client)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create tunes the (always pre-existing) firewall profile in place and saves
// the full state. When restore_on_destroy is set, the pre-existing values
// are captured into private state first so Delete can re-apply them.
func (r *windowsFirewallProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsFirewallProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, firewallProfileDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	name := plan.Name.ValueString()

	if plan.RestoreOnDestroy.ValueBool() {
		pre, err := r.fp.Read(ctx, name)
		if err != nil {
			addFirewallProfileDiag(&resp.Diagnostics, "Error reading pre-existing Windows Firewall profile", err)
			return
		}
		if pre == nil {
			resp.Diagnostics.AddError(
				"Firewall profile not found",
				fmt.Sprintf("Firewall profile %q does not exist on the target host.", name),
			)
			return
		}
		if err := setFirewallProfileSnapshot(ctx, resp.Private.SetKey, pre); err != nil {
			addFirewallProfileDiag(&resp.Diagnostics, "Error capturing pre-existing Windows Firewall profile", err)
			return
		}
	}

	settings, diags := modelToFirewallProfileSettings(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Windows Firewall profile (tuning in place)", map[string]any{
		"name": name,
	})

	state, err := r.fp.Apply(ctx, name, settings)
	if err != nil {
		addFirewallProfileDiag(&resp.Diagnostics, "Error creating Windows Firewall profile", err)
		return
	}

	m, diags := firewallProfileStateToModel(ctx, plan.DisabledInterfaceAliases, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Preserve the user-configured per-operation timeouts and the
	// restore_on_destroy intent: the projection covers only host-observed
	// fields, and Set overwrites the full state.
	m.Timeouts = plan.Timeouts
	m.RestoreOnDestroy = plan.RestoreOnDestroy
	m.Name = plan.Name
	m.ID = types.StringValue(name)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live Windows Firewall profile.
// Profiles always exist, so a missing profile surfaces an error diagnostic
// instead of silently removing the resource from state.
func (r *windowsFirewallProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsFirewallProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, firewallProfileDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	name := state.Name.ValueString()

	tflog.Debug(ctx, "Reading Windows Firewall profile", map[string]any{
		"name": name,
	})

	fpState, err := r.fp.Read(ctx, name)
	if err != nil {
		addFirewallProfileDiag(&resp.Diagnostics, "Error reading Windows Firewall profile", err)
		return
	}

	if fpState == nil {
		resp.Diagnostics.AddError(
			"Firewall profile not found",
			fmt.Sprintf("Firewall profile %q does not exist on the target host. Profiles always exist; "+
				"the profile may have been renamed out-of-band or the host firewall stack may be broken.", name),
		)
		return
	}

	m, diags := firewallProfileStateToModel(ctx, state.DisabledInterfaceAliases, fpState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.Timeouts = state.Timeouts
	m.RestoreOnDestroy = state.RestoreOnDestroy
	m.Name = state.Name
	m.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place attribute changes to the firewall profile. Like
// Create it writes only the configured attributes; the restore snapshot
// captured at Create time is left untouched (restore always returns to the
// pre-existing values, not to the previous plan).
func (r *windowsFirewallProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsFirewallProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsFirewallProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, firewallProfileDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// name is ForceNew so it never changes here.
	name := plan.Name.ValueString()

	settings, diags := modelToFirewallProfileSettings(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating Windows Firewall profile", map[string]any{
		"name": name,
	})

	fpState, err := r.fp.Apply(ctx, name, settings)
	if err != nil {
		addFirewallProfileDiag(&resp.Diagnostics, "Error updating Windows Firewall profile", err)
		return
	}

	m, diags := firewallProfileStateToModel(ctx, plan.DisabledInterfaceAliases, fpState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.Timeouts = plan.Timeouts
	m.RestoreOnDestroy = plan.RestoreOnDestroy
	m.Name = plan.Name
	m.ID = prior.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the resource from state. By default it makes no remote
// change (profiles always exist and are owned by Windows). With
// restore_on_destroy it re-applies the snapshot captured at Create (or
// import) time; when no snapshot exists it warns and leaves the host
// untouched rather than guessing.
func (r *windowsFirewallProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsFirewallProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, firewallProfileDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	name := state.Name.ValueString()

	tflog.Debug(ctx, "Deleting Windows Firewall profile", map[string]any{
		"name":               name,
		"restore_on_destroy": state.RestoreOnDestroy.ValueBool(),
	})

	if !state.RestoreOnDestroy.ValueBool() {
		return
	}

	snap, ok := getFirewallProfileSnapshot(ctx, req.Private.GetKey)
	if !ok {
		resp.Diagnostics.AddWarning(
			"Firewall profile restore skipped: no snapshot",
			fmt.Sprintf("restore_on_destroy is set, but the pre-existing snapshot of profile %q could not be read "+
				"(it may be corrupt or from an incompatible version). Leaving the host untouched.", name),
		)
		return
	}
	if snap == nil {
		resp.Diagnostics.AddWarning(
			"Firewall profile restore skipped: no snapshot",
			fmt.Sprintf("restore_on_destroy is set, but no pre-existing snapshot of profile %q was captured "+
				"(the resource may predate snapshotting or the snapshot was lost). Leaving the host untouched.", name),
		)
		return
	}

	if _, err := r.fp.Restore(ctx, *snap); err != nil {
		addFirewallProfileDiag(&resp.Diagnostics, "Error restoring Windows Firewall profile", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing firewall profile by name
// (Domain, Private or Public). The observed values become the snapshot for a
// later restore_on_destroy, and the interface-alias set starts unmanaged
// (null): declare it to take that list over.
func (r *windowsFirewallProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if err := winclient.ValidateFirewallProfileName(name); err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID %q must be one of Domain, Private, Public.", req.ID),
		)
		return
	}

	tflog.Debug(ctx, "Importing Windows Firewall profile", map[string]any{
		"name": name,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, firewallProfileDefaultTimeout)
	defer cancel()

	fpState, err := r.fp.Read(ctx, name)
	if err != nil {
		addFirewallProfileDiag(&resp.Diagnostics, "Error importing Windows Firewall profile", err)
		return
	}
	if fpState == nil {
		resp.Diagnostics.AddError(
			"Firewall profile not found",
			fmt.Sprintf("Firewall profile %q does not exist on the target host.", name),
		)
		return
	}

	if err := setFirewallProfileSnapshot(ctx, resp.Private.SetKey, fpState); err != nil {
		addFirewallProfileDiag(&resp.Diagnostics, "Error capturing pre-existing Windows Firewall profile", err)
		return
	}

	m, diags := firewallProfileStateToModel(ctx, types.SetNull(types.StringType), fpState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by State.Set — use a typed null instead (the
	// subsequent Read fills in the configured values).
	m.Timeouts = fwProfileNullTimeouts()
	m.RestoreOnDestroy = types.BoolValue(false)
	m.Name = types.StringValue(fpState.Name)
	m.ID = types.StringValue(fpState.Name)
	// Import starts with the alias list unmanaged (null): declaring it takes
	// the list over authoritatively.
	m.DisabledInterfaceAliases = types.SetNull(types.StringType)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helper: modelToFirewallProfileSettings
// ---------------------------------------------------------------------------

// modelToFirewallProfileSettings converts a Terraform model to a
// FirewallProfileSettings delta: null (or unknown) attributes stay nil and
// are never sent to Set-NetFirewallProfile. An unknown attribute aborts with
// a diagnostic so the run defers instead of converging on a guess.
func modelToFirewallProfileSettings(ctx context.Context, m windowsFirewallProfileModel) (winclient.FirewallProfileSettings, diag.Diagnostics) {
	var diags diag.Diagnostics
	var s winclient.FirewallProfileSettings

	boolPtr := func(b types.Bool) *bool {
		if b.IsNull() || b.IsUnknown() {
			return nil
		}
		v := b.ValueBool()
		return &v
	}
	strPtr := func(st types.String) *string {
		if st.IsNull() || st.IsUnknown() {
			return nil
		}
		v := st.ValueString()
		return &v
	}

	for _, b := range []types.Bool{m.Enabled, m.AllowInboundRules, m.AllowLocalFirewallRules,
		m.AllowLocalIPsecRules, m.AllowUnicastResponseToMulticast, m.NotifyOnListen,
		m.LogAllowed, m.LogBlocked, m.LogIgnored} {
		if b.IsUnknown() {
			diags.AddError(
				"Unknown Windows Firewall profile setting",
				"One or more profile settings are unknown. Retry the apply once the referenced values are known instead of converging the profile on a guess.",
			)
			return winclient.FirewallProfileSettings{}, diags
		}
	}
	for _, st := range []types.String{m.DefaultInboundAction, m.DefaultOutboundAction, m.LogFileName} {
		if st.IsUnknown() {
			diags.AddError(
				"Unknown Windows Firewall profile setting",
				"One or more profile settings are unknown. Retry the apply once the referenced values are known instead of converging the profile on a guess.",
			)
			return winclient.FirewallProfileSettings{}, diags
		}
	}
	if m.LogMaxSizeKilobytes.IsUnknown() || m.DisabledInterfaceAliases.IsUnknown() {
		diags.AddError(
			"Unknown Windows Firewall profile setting",
			"One or more profile settings are unknown. Retry the apply once the referenced values are known instead of converging the profile on a guess.",
		)
		return winclient.FirewallProfileSettings{}, diags
	}

	s.Enabled = boolPtr(m.Enabled)
	s.DefaultInboundAction = strPtr(m.DefaultInboundAction)
	s.DefaultOutboundAction = strPtr(m.DefaultOutboundAction)
	s.AllowInboundRules = boolPtr(m.AllowInboundRules)
	s.AllowLocalFirewallRules = boolPtr(m.AllowLocalFirewallRules)
	s.AllowLocalIPsecRules = boolPtr(m.AllowLocalIPsecRules)
	s.AllowUnicastResponseToMulticast = boolPtr(m.AllowUnicastResponseToMulticast)
	s.NotifyOnListen = boolPtr(m.NotifyOnListen)
	s.LogFileName = strPtr(m.LogFileName)
	if !m.LogMaxSizeKilobytes.IsNull() {
		v := m.LogMaxSizeKilobytes.ValueInt64()
		s.LogMaxSizeKilobytes = &v
	}
	s.LogAllowed = boolPtr(m.LogAllowed)
	s.LogBlocked = boolPtr(m.LogBlocked)
	s.LogIgnored = boolPtr(m.LogIgnored)

	if !m.DisabledInterfaceAliases.IsNull() {
		var aliases []string
		diags.Append(m.DisabledInterfaceAliases.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return winclient.FirewallProfileSettings{}, diags
		}
		if aliases == nil {
			aliases = []string{}
		}
		s.DisabledInterfaceAliases = dedupeFirewallAliases(aliases)
		s.DisabledInterfaceAliasesSet = true
	}

	return s, diags
}

// dedupeFirewallAliases removes duplicate interface aliases
// case-insensitively, preserving the first spelling. Set semantics already
// collapse exact duplicates; this keeps the emitted -DisabledInterfaceAliases
// list deterministic when spellings differ only by case.
func dedupeFirewallAliases(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, a := range in {
		trimmed := strings.TrimSpace(a)
		key := strings.ToUpper(trimmed)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, trimmed)
	}
	return out
}

// ---------------------------------------------------------------------------
// Helper: firewallProfileStateToModel
// ---------------------------------------------------------------------------

// fwProfileTimeoutsOpts declares which per-operation timeouts the resource exposes.
var fwProfileTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// fwProfileNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func fwProfileNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if fwProfileTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if fwProfileTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if fwProfileTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if fwProfileTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// triToBool maps a host tri-state spelling to a Terraform bool: True/False
// become values, NotConfigured (GPO-managed) becomes null — the tri-state is
// observed as unset rather than exposed.
func triToBool(v string) types.Bool {
	switch v {
	case "True":
		return types.BoolValue(true)
	case "False":
		return types.BoolValue(false)
	default:
		return types.BoolNull()
	}
}

// triActionToString maps a host action spelling to a Terraform string:
// NotConfigured (GPO-managed) becomes null — the action is observed as
// unset rather than exposed (schema OneOf is Allow/Block only).
func triActionToString(v string) types.String {
	if v == "NotConfigured" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

// firewallProfileStateToModel projects an observed FirewallProfileState into
// a Terraform model. declaredAliases is the prior (plan on write paths,
// state on read paths) disabled_interface_aliases value: a null declared set
// means unmanaged and stays null, otherwise the observed list is returned
// verbatim so the plan shows drift.
func firewallProfileStateToModel(ctx context.Context, declaredAliases types.Set, s *winclient.FirewallProfileState) (windowsFirewallProfileModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	var aliases types.Set
	if declaredAliases.IsNull() || declaredAliases.IsUnknown() {
		aliases = types.SetNull(types.StringType)
	} else {
		observed := s.DisabledInterfaceAliases
		if observed == nil {
			observed = []string{}
		}
		set, d := types.SetValueFrom(ctx, types.StringType, observed)
		diags.Append(d...)
		if d.HasError() {
			return windowsFirewallProfileModel{}, diags
		}
		aliases = set
	}

	return windowsFirewallProfileModel{
		ID:                              types.StringValue(s.Name),
		Name:                            types.StringValue(s.Name),
		Enabled:                         types.BoolValue(s.Enabled),
		DefaultInboundAction:            triActionToString(s.DefaultInboundAction),
		DefaultOutboundAction:           triActionToString(s.DefaultOutboundAction),
		AllowInboundRules:               triToBool(s.AllowInboundRules),
		AllowLocalFirewallRules:         triToBool(s.AllowLocalFirewallRules),
		AllowLocalIPsecRules:            triToBool(s.AllowLocalIPsecRules),
		AllowUnicastResponseToMulticast: triToBool(s.AllowUnicastResponseToMulticast),
		NotifyOnListen:                  types.BoolValue(s.NotifyOnListen),
		LogFileName:                     types.StringValue(s.LogFileName),
		LogMaxSizeKilobytes:             types.Int64Value(s.LogMaxSizeKilobytes),
		LogAllowed:                      triToBool(s.LogAllowed),
		LogBlocked:                      triToBool(s.LogBlocked),
		LogIgnored:                      triToBool(s.LogIgnored),
		DisabledInterfaceAliases:        aliases,
	}, diags
}

// ---------------------------------------------------------------------------
// Helper: private-state snapshot
// ---------------------------------------------------------------------------

// setFirewallProfileSnapshot stores the pre-existing profile state as JSON in
// private state so Delete with restore_on_destroy can re-apply it. setKey is
// a closure over the response Private data (kept injectable so unit tests can
// capture the snapshot without framework internals).
func setFirewallProfileSnapshot(ctx context.Context, setKey func(context.Context, string, []byte) diag.Diagnostics, st *winclient.FirewallProfileState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	diags := setKey(ctx, firewallProfilePrivateKey, raw)
	if diags.HasError() {
		return errors.New(diagsToString(diags))
	}
	return nil
}

// getFirewallProfileSnapshot reads the snapshot back. A nil snapshot with a
// true return means "no snapshot captured". getKey is a closure over the
// request Private data.
func getFirewallProfileSnapshot(ctx context.Context, getKey func(context.Context, string) ([]byte, diag.Diagnostics)) (*winclient.FirewallProfileState, bool) {
	raw, diags := getKey(ctx, firewallProfilePrivateKey)
	if diags.HasError() {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, true
	}
	var st winclient.FirewallProfileState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, false
	}
	return &st, true
}

// diagsToString flattens diagnostics for the error return of the snapshot helpers.
func diagsToString(diags diag.Diagnostics) string {
	parts := make([]string, 0, len(diags))
	for _, d := range diags {
		parts = append(parts, d.Summary()+": "+d.Detail())
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// Helper: addFirewallProfileDiag
// ---------------------------------------------------------------------------

// addFirewallProfileDiag appends a diagnostic from a firewall-profile client
// error. WouldLockOut errors keep their full guidance (naming the missing
// rule and pointing at windows_firewall_rule); other kinds are enriched with
// context fields when available.
func addFirewallProfileDiag(d *diag.Diagnostics, summary string, err error) {
	var fe *winclient.FirewallProfileError
	if errors.As(err, &fe) {
		if fe.Kind == winclient.FirewallProfileErrorWouldLockOut {
			d.AddError(summary+" [would_lock_out]", fe.Message)
			return
		}
		detail := fe.Message
		if len(fe.Context) > 0 {
			var parts []string
			for k, v := range fe.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if fe.Cause != nil {
			detail += "\n\nCause: " + fe.Cause.Error()
		}
		d.AddError(summary+" ["+fe.Kind+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
