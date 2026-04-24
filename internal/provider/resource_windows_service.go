// Package provider: windows_service resource implementation.
//
// This file contains the TPF schema, model, cross-field validator and full
// CRUD + ImportState handlers for the windows_service resource. All WinRM
// interaction is delegated to winclient.ServiceClient (internal/winclient).
//
// Spec alignment: windows_service spec v7 (2026-04-24).
// Framework:       terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ecritel/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsServiceResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsServiceResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsServiceResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsServiceResource)(nil)
)

// NewWindowsServiceResource is the constructor registered in provider.go.
func NewWindowsServiceResource() resource.Resource { return &windowsServiceResource{} }

// windowsServiceResource is the TPF resource type for windows_service.
type windowsServiceResource struct {
	client *winclient.Client
	svc    winclient.WindowsServiceClient
}

// builtinAccountRe matches Windows built-in service accounts that must not
// receive a service_password (EC-11). Case-insensitive.
var builtinAccountRe = regexp.MustCompile(`(?i)^(LocalSystem$|NT AUTHORITY\\)`)

// windowsServiceModel is the Terraform state/plan model for windows_service.
//
// service_password is included (Sensitive: true) but is never populated from a
// live Windows read: the Read handler copies the value from prior state
// (semantic write-only, ADR SS6).
type windowsServiceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	DisplayName     types.String `tfsdk:"display_name"`
	Description     types.String `tfsdk:"description"`
	BinaryPath      types.String `tfsdk:"binary_path"`
	StartType       types.String `tfsdk:"start_type"`
	Status          types.String `tfsdk:"status"`
	CurrentStatus   types.String `tfsdk:"current_status"`
	ServiceAccount  types.String `tfsdk:"service_account"`
	ServicePassword types.String `tfsdk:"service_password"`
	Dependencies    types.List   `tfsdk:"dependencies"`
}

// Metadata sets the resource type name.
func (r *windowsServiceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

// Schema returns the complete TPF schema for the windows_service resource.
func (r *windowsServiceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsServiceSchemaDefinition()
}

// windowsServiceSchemaDefinition returns the complete TPF schema for the
// windows_service resource (10 attributes, validators, plan modifiers, defaults).
func windowsServiceSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the full lifecycle of a Windows service on a remote host " +
			"via WinRM and PowerShell. Supports create, update, in-place reconfiguration, " +
			"runtime state control (Running/Stopped/Paused), deletion and import.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier, equal to the Windows short service name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Short name of the Windows service. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[A-Za-z0-9_\-\.]{1,256}$`),
						"must contain only alphanumeric characters, underscores, hyphens, or dots and be 1-256 characters",
					),
				},
			},
			"display_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Human-readable display name shown in services.msc. Defaults to name if omitted.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Textual description of the service.",
			},
			"binary_path": schema.StringAttribute{
				Required:    true,
				Description: "Full path to the service executable including any arguments. ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 32767),
				},
			},
			"start_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Service start mode. One of: Automatic, AutomaticDelayedStart, Manual, Disabled.",
				Default:     stringdefault.StaticString("Automatic"),
				Validators: []validator.String{
					stringvalidator.OneOf("Automatic", "AutomaticDelayedStart", "Manual", "Disabled"),
				},
			},
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Desired runtime state: Running, Stopped, or Paused. Null = observe-only.",
				Validators: []validator.String{
					stringvalidator.OneOf("Running", "Stopped", "Paused"),
				},
			},
			"current_status": schema.StringAttribute{
				Computed:    true,
				Description: "Observed runtime state from the last Read (Running, Stopped, Paused).",
			},
			"service_account": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Account under which the service runs. Defaults to LocalSystem.",
			},
			"service_password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Password for service_account. Sensitive and semantic write-only; not read back from Windows.",
			},
			"dependencies": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Ordered list of short service names this service depends on.",
			},
		},
	}
}

// Configure extracts the shared winclient.Client from provider config.
func (r *windowsServiceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = c
	r.svc = winclient.NewServiceClient(c)
}

// ConfigValidators wires up the EC-4 / EC-11 cross-field validator.
func (r *windowsServiceResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{serviceAccountPasswordValidator{}}
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

// ImportState populates the id+name attribute from the import argument.
// The remaining fields are populated by the subsequent Read call.
func (r *windowsServiceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

// -----------------------------------------------------------------------------
// CRUD
// -----------------------------------------------------------------------------

// Create creates the service on Windows and persists the full returned state.
func (r *windowsServiceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsServiceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deps, diags := listToStrings(ctx, plan.Dependencies)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := winclient.ServiceInput{
		Name:            plan.Name.ValueString(),
		BinaryPath:      plan.BinaryPath.ValueString(),
		DisplayName:     plan.DisplayName.ValueString(),
		Description:     plan.Description.ValueString(),
		StartType:       plan.StartType.ValueString(),
		DesiredStatus:   plan.Status.ValueString(),
		ServiceAccount:  plan.ServiceAccount.ValueString(),
		ServicePassword: plan.ServicePassword.ValueString(),
		Dependencies:    deps,
	}

	state, err := r.svc.Create(ctx, input)
	if err != nil {
		addServiceDiag(&resp.Diagnostics, "Create windows_service failed", err)
		return
	}

	final := modelFromState(state, plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Read refreshes the Terraform state from the observed Windows state. Returns
// RemoveResource() on EC-2 (service not found).
func (r *windowsServiceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsServiceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()
	if name == "" {
		name = state.ID.ValueString()
	}

	obs, err := r.svc.Read(ctx, name)
	if err != nil {
		addServiceDiag(&resp.Diagnostics, "Read windows_service failed", err)
		return
	}
	if obs == nil {
		// EC-2: service no longer exists.
		resp.State.RemoveResource(ctx)
		return
	}

	final := modelFromState(obs, state)
	// Preserve prior-state service_password (semantic write-only, SS6).
	final.ServicePassword = state.ServicePassword
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Update applies in-place changes to the service.
func (r *windowsServiceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsServiceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var deps []string
	if !plan.Dependencies.IsNull() && !plan.Dependencies.IsUnknown() {
		d, diags := listToStrings(ctx, plan.Dependencies)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		if d == nil {
			d = []string{}
		}
		deps = d
	}

	name := plan.Name.ValueString()
	if name == "" {
		name = prior.Name.ValueString()
	}

	input := winclient.ServiceInput{
		Name:            name,
		DisplayName:     plan.DisplayName.ValueString(),
		Description:     plan.Description.ValueString(),
		StartType:       plan.StartType.ValueString(),
		DesiredStatus:   plan.Status.ValueString(),
		ServiceAccount:  plan.ServiceAccount.ValueString(),
		ServicePassword: plan.ServicePassword.ValueString(),
		Dependencies:    deps,
	}

	state, err := r.svc.Update(ctx, name, input)
	if err != nil {
		addServiceDiag(&resp.Diagnostics, "Update windows_service failed", err)
		return
	}

	final := modelFromState(state, plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Delete removes the service from Windows (idempotent on EC-2 / 1060).
func (r *windowsServiceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsServiceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	if name == "" {
		name = state.ID.ValueString()
	}
	if err := r.svc.Delete(ctx, name); err != nil {
		addServiceDiag(&resp.Diagnostics, "Delete windows_service failed", err)
		return
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// listToStrings converts a types.List of strings into a native []string.
// Returns (nil, nil) when the list is null or unknown.
func listToStrings(ctx context.Context, list types.List) ([]string, diagsType) {
	if list.IsNull() || list.IsUnknown() {
		return nil, nil
	}
	var out []string
	diags := list.ElementsAs(ctx, &out, false)
	return out, diags
}

// diagsType is a shorthand to keep helper signatures compact; aliasing the
// framework diagnostics type avoids importing it at every helper site.
type diagsType = diag.Diagnostics

// modelFromState projects an observed ServiceState onto a windowsServiceModel,
// preserving the desired-state fields (status, service_password) from prior.
func modelFromState(s *winclient.ServiceState, prior windowsServiceModel) windowsServiceModel {
	out := windowsServiceModel{
		ID:             types.StringValue(s.Name),
		Name:           types.StringValue(s.Name),
		DisplayName:    types.StringValue(s.DisplayName),
		BinaryPath:     types.StringValue(s.BinaryPath),
		StartType:      types.StringValue(s.StartType),
		CurrentStatus:  types.StringValue(s.CurrentStatus),
		ServiceAccount: types.StringValue(s.ServiceAccount),
	}

	// description: preserve null-ness if the prior value was null AND Windows
	// returns empty (avoids spurious "" <-> null diffs).
	if prior.Description.IsNull() && s.Description == "" {
		out.Description = types.StringNull()
	} else {
		out.Description = types.StringValue(s.Description)
	}

	// status is desired state (never observed).
	out.Status = prior.Status

	// service_password is never read from Windows (SS6).
	out.ServicePassword = prior.ServicePassword

	// dependencies
	depVals := make([]attr.Value, 0, len(s.Dependencies))
	for _, d := range s.Dependencies {
		depVals = append(depVals, types.StringValue(d))
	}
	depList, _ := types.ListValue(types.StringType, depVals)
	out.Dependencies = depList
	return out
}

// addServiceDiag converts a winclient error into a TPF diagnostic. The error
// Message is safe to surface; Context is appended as a detail block.
func addServiceDiag(diags *diag.Diagnostics, summary string, err error) {
	var se *winclient.ServiceError
	if errors.As(err, &se) {
		detail := se.Message
		if len(se.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range se.Context {
				if k == "service_password" {
					continue
				}
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if se.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", se.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// -----------------------------------------------------------------------------
// serviceAccountPasswordValidator — EC-4 + EC-11
// -----------------------------------------------------------------------------

// serviceAccountPasswordValidator enforces the cross-field rules:
//   - EC-4: service_password requires a non-null, non-empty service_account.
//   - EC-11: service_password must not be paired with a built-in account
//     (LocalSystem, NT AUTHORITY\*).
type serviceAccountPasswordValidator struct{}

var _ resource.ConfigValidator = serviceAccountPasswordValidator{}

// Description returns a plain-text description.
func (v serviceAccountPasswordValidator) Description(_ context.Context) string {
	return "service_password requires a non-empty, non-built-in service_account (EC-4, EC-11)."
}

// MarkdownDescription returns a Markdown description.
func (v serviceAccountPasswordValidator) MarkdownDescription(_ context.Context) string {
	return "`service_password` requires a non-empty, non-built-in `service_account` (EC-4, EC-11)."
}

// ValidateResource applies the rules at plan time.
func (v serviceAccountPasswordValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data windowsServiceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.ServicePassword.IsNull() || data.ServicePassword.IsUnknown() {
		return
	}

	if data.ServiceAccount.IsNull() || data.ServiceAccount.IsUnknown() || data.ServiceAccount.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("service_password"),
			"service_password requires service_account (EC-4)",
			"service_password is set but service_account is null or empty. Provide a non-built-in service_account (e.g. DOMAIN\\svc-app or .\\localuser) when using service_password.",
		)
		return
	}

	if builtinAccountRe.MatchString(data.ServiceAccount.ValueString()) {
		resp.Diagnostics.AddAttributeError(
			path.Root("service_password"),
			"service_password must not be used with built-in accounts (EC-11)",
			"service_account '"+data.ServiceAccount.ValueString()+"' is a built-in account. Built-in accounts (LocalSystem, NT AUTHORITY\\*) do not accept a password; passing one causes SCM error 87.",
		)
	}
}
