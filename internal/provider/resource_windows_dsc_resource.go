// Package provider: windows_dsc_resource resource implementation.
//
// This file contains the TPF schema, model and full CRUD handlers for the
// windows_dsc_resource generic DSC gateway. All SSH interaction is delegated
// to winclient.DSCResourceClient (internal/winclient).
//
// Spec alignment: issue #293 (windows_dsc_resource, resource only, no data
// source in v1).
// Framework:       terraform-plugin-framework v1.19.0.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsDSCResourceResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsDSCResourceResource)(nil)
	_ resource.ResourceWithImportState = (*windowsDSCResourceResource)(nil)
)

// NewWindowsDSCResource is the constructor registered in provider.go.
func NewWindowsDSCResource() resource.Resource { return &windowsDSCResourceResource{} }

// windowsDSCResourceResource is the TPF resource type for
// windows_dsc_resource.
type windowsDSCResourceResource struct {
	dsc winclient.WindowsDSCResourceClient
}

// dscDefaultTimeout bounds create/update/delete, which run Test/Set/Get
// round trips and may compile MOFs on slow hosts. Read only runs Test/Get
// and defaults to dscDefaultReadTimeout.
const (
	dscDefaultTimeout     = 30 * time.Minute
	dscDefaultReadTimeout = 10 * time.Minute
)

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsDSCResourceModel is the Terraform state/plan model for
// windows_dsc_resource. Every tfsdk tag matches an attribute key in
// windowsDSCResourceSchemaDefinition.
type windowsDSCResourceModel struct {
	ID                        types.String   `tfsdk:"id"`
	ModuleName                types.String   `tfsdk:"module_name"`
	ModuleVersion             types.String   `tfsdk:"module_version"`
	ResolvedModuleVersion     types.String   `tfsdk:"resolved_module_version"`
	ResourceName              types.String   `tfsdk:"resource_name"`
	Properties                types.Dynamic  `tfsdk:"properties"`
	CredentialPropertiesWO    types.Map      `tfsdk:"credential_properties_wo"`
	CredentialPropertiesWOVer types.Int64    `tfsdk:"credential_properties_wo_version"`
	DestroyProperties         types.Dynamic  `tfsdk:"destroy_properties"`
	InDesiredState            types.Bool     `tfsdk:"in_desired_state"`
	CurrentStateJSON          types.String   `tfsdk:"current_state_json"`
	RebootRequired            types.Bool     `tfsdk:"reboot_required"`
	Timeouts                  timeouts.Value `tfsdk:"timeouts"`
}

// dscCredentialModel is one entry of credential_properties_wo: the map key
// is the DSC property name, the value carries the PSCredential material.
type dscCredentialModel struct {
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsDSCResourceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dsc_resource"
}

// Schema returns the complete TPF schema for windows_dsc_resource.
func (r *windowsDSCResourceResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsDSCResourceSchemaDefinition(ctx)
}

// windowsDSCResourceSchemaDefinition returns the complete TPF schema for
// the windows_dsc_resource resource.
func windowsDSCResourceSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages one instance of any Windows DSC resource on a remote host " +
			"via `Invoke-DscResource` (`Test`/`Set`/`Get`) over SSH and PowerShell.\n\n" +
			"Every operation first checks the Local Configuration Manager and fails closed with " +
			"`lcm_conflict` when the node uses Pull refresh mode or reports a busy/pending LCM state. " +
			"The provider never changes LCM settings.\n\n" +
			"Convergence is Test-driven: `Set` runs only on drift and a follow-up `Test` verifies it " +
			"(`not_converged` otherwise). `in_desired_state` reports the last `Test` outcome. " +
			"Delete applies `destroy_properties` when configured (full replacement, e.g. `Ensure = \"Absent\"`), " +
			"and is state-only otherwise.\n\n" +
			"Import is not supported: a generic gateway cannot reconstruct the original property " +
			"authorship from live state. Write configuration matching the live state and let the first " +
			"apply adopt it (no-op when already in the desired state).\n\n" +
			"Windows PowerShell 5.1 only (`Invoke-DscResource`, DSC 1.1): PowerShell 7 / DSCv3 is not supported.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier: `<module>|<resource>|<sha256 hex of the canonical key-properties JSON>`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"module_name": schema.StringAttribute{
				Required:    true,
				Description: "DSC module name (for example `PSDesiredStateConfiguration`). ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"module_version": schema.StringAttribute{
				Optional:    true,
				Description: "Exact DSC module version to use. When unset, the highest installed version is used and reported in `resolved_module_version`. ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"resolved_module_version": schema.StringAttribute{
				Computed:    true,
				Description: "Module version the last operation ran against: the pinned `module_version`, or the highest installed version.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"resource_name": schema.StringAttribute{
				Required:    true,
				Description: "DSC resource name within the module (for example `Environment`). ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"properties": schema.DynamicAttribute{
				Required: true,
				MarkdownDescription: "Desired DSC resource properties as an object (for example " +
					"`{ Ensure = \"Present\", Name = \"FOO\", Value = \"bar\" }`). Property names are " +
					"case-insensitive and validated against the live `Get-DscResource` schema on every " +
					"operation; values are coerced pure-Go (string/int/bool/list/one-level objects, " +
					"ValueMap-enforced). PSCredential properties must NOT appear here: pass them through " +
					"`credential_properties_wo` instead.",
			},
			"credential_properties_wo": schema.MapNestedAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"username": schema.StringAttribute{
							Required:  true,
							WriteOnly: true,
							Description: "Credential user name for this DSC property. " +
								"Must not contain carriage return or line feed characters.",
							Validators: []validator.String{
								secretNoLineBreakValidator{},
							},
						},
						"password": schema.StringAttribute{
							Required:  true,
							Sensitive: true,
							WriteOnly: true,
							Description: "Credential password for this DSC property. " +
								"Must not contain carriage return or line feed characters.",
							Validators: []validator.String{
								secretNoLineBreakValidator{},
							},
						},
					},
				},
				MarkdownDescription: "PSCredential property values keyed by DSC property name. " +
					"Write-only: the map key is the property name and each value carries `username` plus " +
					"the secret `password`, which travels to the host on stdin and is never persisted in " +
					"state. Rotation is marked with `credential_properties_wo_version`: changing only the " +
					"map without bumping the version is a no-op for converge decisions that need no new " +
					"credential, while DSC `Set` calls always forward the configured values. " +
					"At destroy time no credential is available (WriteOnly values do not survive to the " +
					"destroy plan): destroying a credential-bearing resource whose destroy configuration " +
					"still requires the credential fails closed.",
				Validators: []validator.Map{
					// A credential map without its version marker is a no-op
					// rotation signal (windows_service precedent).
					mapvalidator.AlsoRequires(path.MatchRoot("credential_properties_wo_version")),
				},
			},
			"credential_properties_wo_version": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Version counter for `credential_properties_wo` rotation. " +
					"Conventionally starts at 1. Changing only the credential map without changing " +
					"this version leaves converge decisions that need no new credential untouched.",
				Description: "Version counter for credential_properties_wo rotation. " +
					"Conventionally starts at 1.",
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
			"destroy_properties": schema.DynamicAttribute{
				Optional: true,
				MarkdownDescription: "Absent-state properties applied with `Set` on destroy " +
					"(full replacement, for example `{ Ensure = \"Absent\", Name = \"FOO\" }`). " +
					"When unset, destroy is state-only and makes no remote call. Credential-typed " +
					"values cannot be supplied at destroy time (see `credential_properties_wo`).",
			},
			"in_desired_state": schema.BoolAttribute{
				Computed: true,
				Description: "Outcome of the last `Test-DscConfiguration`-equivalent `Invoke-DscResource -Method Test` " +
					"call: true when the host reports the desired state. Always planned as true so a failed " +
					"Test produces an update plan that re-converges on apply.",
				PlanModifiers: []planmodifier.Bool{
					dscInDesiredStateModifier{},
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"current_state_json": schema.StringAttribute{
				Computed: true,
				Description: "Redacted `Invoke-DscResource -Method Get` output as canonical JSON " +
					"(credential values dropped, nulls omitted, schema-declared properties only). " +
					"Informational only: never produces drift.",
			},
			"reboot_required": schema.BoolAttribute{
				Computed: true,
				Description: "Whether the last converge reported RebootRequired. Advisory only: " +
					"the provider schedules no reboot (warns instead).",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			// Per-operation timeouts. Create/Update/Delete run Test/Set/Get
			// round trips (30m defaults); Read only runs Test/Get (10m).
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

// Configure extracts the shared winclient.Client from provider config.
func (r *windowsDSCResourceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.dsc = winclient.NewDSCResourceClient(c)
}

// -----------------------------------------------------------------------------
// ImportState — unsupported by design
// ---------------------------------------------------------------------------

// ImportState always fails: a generic gateway cannot reconstruct the
// original property authorship (key selection, credential bindings, destroy
// intent) from live host state. The diagnostic guides the operator to write
// configuration matching the live state and let the first apply adopt it.
func (r *windowsDSCResourceResource) ImportState(_ context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.AddError(
		"Import is not supported for windows_dsc_resource",
		"windows_dsc_resource cannot be imported: the gateway cannot reconstruct the configured "+
			"property set, credential bindings or destroy intent from live host state.\n\n"+
			"To adopt an existing DSC configuration, write a windows_dsc_resource block whose "+
			"module_name, resource_name and properties match the live state, then apply: when the "+
			"host already reports the desired state the first converge is a no-op Test and the "+
			"resource is adopted into state.",
	)
}

// -----------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

// Create converges the target to the desired state and persists the observed
// outcome.
func (r *windowsDSCResourceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config windowsDSCResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, dscDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_dsc_resource Create", map[string]interface{}{
		"module":   plan.ModuleName.ValueString(),
		"resource": plan.ResourceName.ValueString(),
	})

	input, diags := dscEnsureInputFromPlan(ctx, plan, config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.dsc.Ensure(ctx, input)
	if err != nil {
		addDSCDiag(&resp.Diagnostics, "Create windows_dsc_resource failed", err)
		return
	}

	final, diags := dscModelFromResult(plan, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if result.RebootRequired {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("reboot_required"),
			"DSC resource reports a reboot is required",
			"The converge of DSC resource \""+plan.ResourceName.ValueString()+"\" (module \""+
				plan.ModuleName.ValueString()+"\") reported RebootRequired. windows_dsc_resource "+
				"never reboots the node: reboot the host out-of-band when the pending reboot matters.",
		)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Read refreshes the observed state without changing the host (Test plus
// Get, never Set). A module or resource gone from the host drops the
// Terraform resource from state.
func (r *windowsDSCResourceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsDSCResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, dscDefaultReadTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_dsc_resource Read", map[string]interface{}{
		"module":   state.ModuleName.ValueString(),
		"resource": state.ResourceName.ValueString(),
	})

	props, diags := dscDynamicToGo(ctx, state.Properties, path.Root("properties"))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// WriteOnly credentials do not survive to refresh: Read runs without
	// them. A missing_property outcome therefore means a mandatory
	// credential is unavailable at refresh time — keep the prior observed
	// state, mark the resource not-verified (the always-true plan modifier
	// turns this into an update plan that re-converges with the configured
	// credentials on apply) and warn, instead of failing every plan.
	input := winclient.DSCEnsureInput{
		ModuleName:    state.ModuleName.ValueString(),
		ModuleVersion: state.ModuleVersion.ValueString(),
		ResourceName:  state.ResourceName.ValueString(),
		Properties:    props,
		Credentials:   map[string]winclient.DSCredential{},
	}
	result, err := r.dsc.Read(ctx, input)
	if err != nil {
		if winclient.IsDSCResourceError(err, winclient.DSCResourceErrorMissingProperty) {
			state.InDesiredState = types.BoolValue(false)
			resp.Diagnostics.AddAttributeWarning(
				path.Root("in_desired_state"),
				"DSC state could not be verified without credentials",
				"The refresh Test of DSC resource \""+state.ResourceName.ValueString()+"\" (module \""+
					state.ModuleName.ValueString()+"\") needs a mandatory PSCredential that is WriteOnly "+
					"and therefore unavailable at refresh time. The prior observed state is kept and the "+
					"next apply re-converges with the configured credential_properties_wo.",
			)
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
		addDSCDiag(&resp.Diagnostics, "Read windows_dsc_resource failed", err)
		return
	}
	if result == nil {
		// Module or resource gone from the host.
		resp.State.RemoveResource(ctx)
		return
	}

	final, diags := dscModelFromResult(state, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Update re-converges the target to the desired state.
func (r *windowsDSCResourceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior, config windowsDSCResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, dscDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_dsc_resource Update", map[string]interface{}{
		"module":   plan.ModuleName.ValueString(),
		"resource": plan.ResourceName.ValueString(),
	})

	input, diags := dscEnsureInputFromPlan(ctx, plan, config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.dsc.Ensure(ctx, input)
	if err != nil {
		addDSCDiag(&resp.Diagnostics, "Update windows_dsc_resource failed", err)
		return
	}

	final, diags := dscModelFromResult(plan, result)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if result.RebootRequired {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("reboot_required"),
			"DSC resource reports a reboot is required",
			"The converge of DSC resource \""+plan.ResourceName.ValueString()+"\" (module \""+
				plan.ModuleName.ValueString()+"\") reported RebootRequired. windows_dsc_resource "+
				"never reboots the node: reboot the host out-of-band when the pending reboot matters.",
		)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Delete applies destroy_properties via Set (full replacement) when
// configured, and is state-only otherwise.
func (r *windowsDSCResourceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsDSCResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteTimeout, diags := state.Timeouts.Delete(ctx, dscDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_dsc_resource Delete", map[string]interface{}{
		"module":   state.ModuleName.ValueString(),
		"resource": state.ResourceName.ValueString(),
	})

	if state.DestroyProperties.IsNull() || state.DestroyProperties.IsUnknown() {
		// State-only destroy: no remote call.
		return
	}
	props, diags := dscDynamicToGo(ctx, state.DestroyProperties, path.Root("destroy_properties"))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// WriteOnly credentials are unavailable at destroy time, so destroy
	// configurations requiring a mandatory PSCredential fail closed with a
	// guided diagnostic instead of a bare host error.
	input := winclient.DSCDeleteInput{
		ModuleName:        state.ModuleName.ValueString(),
		ModuleVersion:     state.ModuleVersion.ValueString(),
		ResourceName:      state.ResourceName.ValueString(),
		DestroyProperties: props,
		HasDestroy:        true,
		Credentials:       map[string]winclient.DSCredential{},
	}
	if err := r.dsc.Delete(ctx, input); err != nil {
		if winclient.IsDSCResourceError(err, winclient.DSCResourceErrorMissingProperty) {
			resp.Diagnostics.AddError(
				"Delete windows_dsc_resource failed: destroy needs a credential",
				"The destroy Set of DSC resource \""+state.ResourceName.ValueString()+"\" (module \""+
					state.ModuleName.ValueString()+"\") requires a mandatory PSCredential, but "+
					"credential_properties_wo is WriteOnly and therefore unavailable at destroy time. "+
					"Remove the credential requirement from the destroy configuration (for example a "+
					"credential-free Ensure=Absent state) or clean up the instance out-of-band and "+
					"remove it from state with terraform state rm.",
			)
			return
		}
		addDSCDiag(&resp.Diagnostics, "Delete windows_dsc_resource failed", err)
		return
	}
}

// -----------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// dscEnsureInputFromPlan builds the winclient input from the plan plus the
// WriteOnly credentials from config (the values are null in the plan handed
// to ApplyResourceChange, so they must be read from config — the
// service_password_wo precedent). Fail-closed guards mirror the service
// rotation guard: a version without credentials, or credentials without a
// version, never reaches Windows silently.
func dscEnsureInputFromPlan(ctx context.Context, plan, config windowsDSCResourceModel) (winclient.DSCEnsureInput, diag.Diagnostics) {
	var diags diag.Diagnostics

	props, d := dscDynamicToGo(ctx, plan.Properties, path.Root("properties"))
	diags.Append(d...)
	if diags.HasError() {
		return winclient.DSCEnsureInput{}, diags
	}

	creds, d := dscCredentialsFromConfig(ctx, config)
	diags.Append(d...)
	if diags.HasError() {
		return winclient.DSCEnsureInput{}, diags
	}

	versionSet := !plan.CredentialPropertiesWOVer.IsNull() && !plan.CredentialPropertiesWOVer.IsUnknown()
	if len(creds) > 0 && !versionSet {
		// The mapvalidator AlsoRequires guard normally catches this at
		// plan time; this is the defence-in-depth path for callers that
		// bypass config validation.
		diags.AddAttributeError(
			path.Root("credential_properties_wo_version"),
			"credential_properties_wo requires credential_properties_wo_version",
			"credential_properties_wo is set but credential_properties_wo_version is not. "+
				"Set the version counter (conventionally 1) alongside the credential map.",
		)
		return winclient.DSCEnsureInput{}, diags
	}
	if versionSet && len(creds) == 0 {
		diags.AddAttributeError(
			path.Root("credential_properties_wo_version"),
			"credential_properties_wo_version is set but no credential supplied",
			"credential_properties_wo_version is set but credential_properties_wo carries no entry. "+
				"Provide the credential map entry or remove the version (fail-closed: no blank credential is sent).",
		)
		return winclient.DSCEnsureInput{}, diags
	}

	return winclient.DSCEnsureInput{
		ModuleName:    plan.ModuleName.ValueString(),
		ModuleVersion: plan.ModuleVersion.ValueString(),
		ResourceName:  plan.ResourceName.ValueString(),
		Properties:    props,
		Credentials:   creds,
	}, diags
}

// dscCredentialsFromConfig reads the WriteOnly credential map from config.
// Unknown values never count as configured.
func dscCredentialsFromConfig(ctx context.Context, config windowsDSCResourceModel) (map[string]winclient.DSCredential, diag.Diagnostics) {
	var diags diag.Diagnostics
	out := map[string]winclient.DSCredential{}
	if config.CredentialPropertiesWO.IsNull() || config.CredentialPropertiesWO.IsUnknown() {
		return out, diags
	}
	var raw map[string]dscCredentialModel
	diags.Append(config.CredentialPropertiesWO.ElementsAs(ctx, &raw, false)...)
	if diags.HasError() {
		return nil, diags
	}
	for name, entry := range raw {
		if entry.Username.IsUnknown() || entry.Password.IsUnknown() {
			continue
		}
		out[name] = winclient.DSCredential{
			Username: entry.Username.ValueString(),
			Password: entry.Password.ValueString(),
		}
	}
	return out, diags
}

// dscModelFromResult projects a converge/read outcome onto the state model.
// properties and destroy intent carry over from the prior model (properties
// is Required, so config and state agree); the ID is the deterministic
// module|resource|key-hash. current_state_json is the canonical redacted Get
// JSON: informational only and never a drift source.
func dscModelFromResult(prior windowsDSCResourceModel, result *winclient.DSCEnsureResult) (windowsDSCResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	out := windowsDSCResourceModel{
		ModuleName:                prior.ModuleName,
		ModuleVersion:             prior.ModuleVersion,
		ResolvedModuleVersion:     types.StringValue(result.ResolvedModuleVersion),
		ResourceName:              prior.ResourceName,
		Properties:                prior.Properties,
		CredentialPropertiesWO:    types.MapNull(dscCredentialObjectType()),
		CredentialPropertiesWOVer: prior.CredentialPropertiesWOVer,
		DestroyProperties:         prior.DestroyProperties,
		InDesiredState:            types.BoolValue(result.InDesiredState),
		RebootRequired:            types.BoolValue(result.RebootRequired),
		Timeouts:                  prior.Timeouts,
	}

	if result.ID == "" {
		diags.AddError(
			"windows_dsc_resource converge returned no ID",
			"The DSC converge completed but returned no resource ID. This is a provider bug: "+
				"report it with the module and resource names.",
		)
		return windowsDSCResourceModel{}, diags
	}
	out.ID = types.StringValue(result.ID)

	stateJSON, err := json.Marshal(result.CurrentState)
	if err != nil {
		diags.AddError(
			"windows_dsc_resource failed to encode observed state",
			"The DSC Get output could not be encoded as JSON: "+err.Error(),
		)
		return windowsDSCResourceModel{}, diags
	}
	out.CurrentStateJSON = types.StringValue(string(stateJSON))
	return out, diags
}

// dscCredentialObjectType is the element type of credential_properties_wo.
func dscCredentialObjectType() attr.Type {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"username": types.StringType,
			"password": types.StringType,
		},
	}
}

// dscDynamicToGo converts a types.Dynamic object value into a native
// map[string]any. Null converts to an empty map (treated as unset); unknown
// values — at any depth — are an error, since the host call cannot run on
// values Terraform has not resolved yet. attrPath names the source attribute
// ("properties" or "destroy_properties") for diagnostics.
func dscDynamicToGo(ctx context.Context, dv types.Dynamic, attrPath path.Path) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics
	if dv.IsNull() {
		return map[string]any{}, diags
	}
	if dv.IsUnknown() {
		diags.AddAttributeError(
			attrPath,
			"Unknown DSC properties",
			"The DSC properties value is unknown at apply time. Values feeding properties must be known before apply.",
		)
		return nil, diags
	}
	uv := dv.UnderlyingValue()
	if uv == nil {
		return map[string]any{}, diags
	}
	tv, err := uv.ToTerraformValue(ctx)
	if err != nil {
		diags.AddAttributeError(
			attrPath,
			"Unreadable DSC properties",
			"The DSC properties value could not be decoded: "+err.Error(),
		)
		return nil, diags
	}
	native, err := dscTftypesToGo(tv)
	if err != nil {
		diags.AddAttributeError(
			attrPath,
			"Unknown DSC property value",
			"The DSC properties contain an unknown value nested inside the object: "+err.Error(),
		)
		return nil, diags
	}
	m, ok := native.(map[string]any)
	if !ok {
		diags.AddAttributeError(
			attrPath,
			"Invalid DSC properties shape",
			"The DSC properties value must be an object mapping property names to values.",
		)
		return nil, diags
	}
	return m, diags
}

// dscTftypesToGo converts a tftypes.Value into native Go values (string,
// bool, int64 for integral numbers, float64 otherwise, []any, map[string]any,
// nil for null). Unknown values are an error.
func dscTftypesToGo(v tftypes.Value) (any, error) {
	if !v.IsKnown() {
		return nil, fmt.Errorf("unknown value")
	}
	if v.IsNull() {
		return nil, nil
	}
	t := v.Type()
	switch {
	case t.Equal(tftypes.String):
		var s string
		if err := v.As(&s); err != nil {
			return nil, err
		}
		return s, nil
	case t.Equal(tftypes.Bool):
		var b bool
		if err := v.As(&b); err != nil {
			return nil, err
		}
		return b, nil
	case t.Equal(tftypes.Number):
		var f *big.Float
		if err := v.As(&f); err != nil {
			return nil, err
		}
		if f.IsInt() {
			i, _ := f.Int64()
			return i, nil
		}
		fl, _ := f.Float64()
		return fl, nil
	case t.Equal(tftypes.DynamicPseudoType):
		// Dynamic-wrapped concrete value: unwrap one level.
		var inner tftypes.Value
		if err := v.As(&inner); err != nil {
			return nil, err
		}
		return dscTftypesToGo(inner)
	}
	switch t.(type) {
	case tftypes.Map, tftypes.Object:
		var m map[string]tftypes.Value
		if err := v.As(&m); err != nil {
			return nil, err
		}
		out := make(map[string]any, len(m))
		for k, ev := range m {
			nv, err := dscTftypesToGo(ev)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = nv
		}
		return out, nil
	case tftypes.List, tftypes.Set, tftypes.Tuple:
		var elems []tftypes.Value
		if err := v.As(&elems); err != nil {
			return nil, err
		}
		out := make([]any, 0, len(elems))
		for _, ev := range elems {
			nv, err := dscTftypesToGo(ev)
			if err != nil {
				return nil, err
			}
			out = append(out, nv)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported type %T", t)
}

// addDSCDiag converts a winclient error into a TPF diagnostic. The error
// Message is safe to surface; Context is appended as a detail block with
// any password-carrying key dropped defence-in-depth (winclient never sets
// such keys, but diagnostics must stay secret-free by construction).
func addDSCDiag(diags *diag.Diagnostics, summary string, err error) {
	var de *winclient.DSCResourceError
	if errors.As(err, &de) {
		detail := de.Message
		if len(de.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range de.Context {
				if strings.Contains(strings.ToLower(k), "password") {
					continue
				}
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if de.Cause != nil {
			detail += "\n\nCause: " + de.Cause.Error()
		}
		if de.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", de.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// -----------------------------------------------------------------------------
// dscInDesiredStateModifier — always-plan-true
// ---------------------------------------------------------------------------

// dscInDesiredStateModifier plans in_desired_state as true unconditionally.
// A failed Test persists state=false; without this modifier the next plan
// would echo state (no diff, no update). Planning true forces the update
// that re-converges on apply. Refresh (Read) always overwrites with the
// live Test outcome, so the modifier never masks drift: it only decides the
// plan when the value would otherwise be unknown.
type dscInDesiredStateModifier struct{}

var _ planmodifier.Bool = dscInDesiredStateModifier{}

// Description returns a plain-text description.
func (m dscInDesiredStateModifier) Description(_ context.Context) string {
	return "Plans in_desired_state as true so a failed Test produces an update plan."
}

// MarkdownDescription returns a Markdown description.
func (m dscInDesiredStateModifier) MarkdownDescription(_ context.Context) string {
	return "Plans `in_desired_state` as `true` so a failed `Test` produces an update plan that re-converges on apply."
}

// PlanModifyBool always plans true.
func (m dscInDesiredStateModifier) PlanModifyBool(_ context.Context, _ planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	resp.PlanValue = types.BoolValue(true)
}
