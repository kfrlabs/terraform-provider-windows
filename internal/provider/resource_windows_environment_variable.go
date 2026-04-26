// Package provider: windows_environment_variable resource implementation.
//
// Manages a single Windows environment variable (machine or user scope) on a
// remote host via WinRM + PowerShell using the .NET Microsoft.Win32.Registry
// API (ADR-EV-1). Broadcasts WM_SETTINGCHANGE after every mutation so that
// newly started processes inherit the change without a reboot (ADR-EV-2).
//
// Spec alignment: windows_environment_variable spec v1 (2026-04-26).
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsEnvVarResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsEnvVarResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsEnvVarResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsEnvVarResource)(nil)
)

// NewWindowsEnvironmentVariableResource is the constructor registered in provider.go.
func NewWindowsEnvironmentVariableResource() resource.Resource {
	return &windowsEnvVarResource{}
}

// windowsEnvVarResource is the TPF resource type for windows_environment_variable.
type windowsEnvVarResource struct {
	client winclient.EnvVarClient
}

// ---------------------------------------------------------------------------
// windowsEnvVarModel — Terraform state/plan model
// ---------------------------------------------------------------------------

// windowsEnvVarModel is the Terraform state/plan model for the
// windows_environment_variable resource and its data source counterpart.
//
// The computed id is assembled at Create/Import time as "<scope>:<name>"
// (e.g. "machine:JAVA_HOME"). It is never mutated by Update operations.
type windowsEnvVarModel struct {
	ID     types.String `tfsdk:"id"`
	Name   types.String `tfsdk:"name"`
	Value  types.String `tfsdk:"value"`
	Scope  types.String `tfsdk:"scope"`
	Expand types.Bool   `tfsdk:"expand"`
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// envVarNameValidator rejects environment variable names that are empty or
// that contain the equals sign character ('=').
type envVarNameValidator struct{}

func (v envVarNameValidator) Description(_ context.Context) string {
	return "environment variable name must be non-empty and must not contain '='"
}

func (v envVarNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v envVarNameValidator) ValidateString(
	_ context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Environment Variable Name",
			"Environment variable name must not be empty.",
		)
		return
	}
	if strings.ContainsRune(val, '=') {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Environment Variable Name",
			fmt.Sprintf(
				"Environment variable name %q contains '=', which is the "+
					"key=value delimiter in the Windows environment block and "+
					"is not allowed in variable names.",
				val,
			),
		)
	}
}

// ---------------------------------------------------------------------------
// Schema definition
// ---------------------------------------------------------------------------

// windowsEnvVarSchemaDefinition returns the schema.Schema for the
// windows_environment_variable resource.
func windowsEnvVarSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a single Windows environment variable " +
			"(`machine` or `user` scope) on a remote host via WinRM + PowerShell. " +
			"Uses the .NET `Microsoft.Win32.Registry` API for type-safe `REG_SZ` / " +
			"`REG_EXPAND_SZ` storage and broadcasts `WM_SETTINGCHANGE` after every " +
			"mutation so that newly started processes inherit the change without a reboot.\n\n" +
			"**Scope registry paths:**\n" +
			"- `machine` → `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment` (requires Local Administrator)\n" +
			"- `user` → `HKCU\\Environment` (no elevation required)\n\n" +
			"**Out of scope:** PATH-like list semantics.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "Terraform resource ID. Composite string formatted as " +
					"`\"<scope>:<name>\"` (e.g. `\"machine:JAVA_HOME\"`). " +
					"Identical to the import ID format.",
			},
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					envVarNameValidator{},
				},
				MarkdownDescription: "Windows environment variable name (e.g. `JAVA_HOME`). " +
					"Must be non-empty and must not contain `=`. " +
					"**ForceNew:** changing `name` destroys the old variable and creates a new one.",
			},
			"value": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Value of the environment variable, written verbatim to the " +
					"registry. An empty string is valid. For `expand = true`, the value should " +
					"contain `%VAR%` tokens; they are stored as-is and read back unexpanded.",
			},
			"scope": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("machine", "user"),
				},
				MarkdownDescription: "Scope of the environment variable. " +
					"`\"machine\"` targets `HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Environment` " +
					"(requires **Local Administrator**). " +
					"`\"user\"` targets `HKCU\\\\Environment`. " +
					"**ForceNew:** changing `scope` destroys the old variable and creates a new one.",
			},
			"expand": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Controls the registry value kind. " +
					"`false` (default): `REG_SZ` — plain string. " +
					"`true`: `REG_EXPAND_SZ` — Windows expands `%VAR%` tokens for applications. " +
					"Updatable in-place: changing `expand` rewrites the registry kind without replacement.",
			},
		},
	}
}

// windowsEnvVarConfigValidators returns resource-level ConfigValidators.
// No cross-attribute invariants are required in v1.
func windowsEnvVarConfigValidators() []resource.ConfigValidator {
	return []resource.ConfigValidator{}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators
// ---------------------------------------------------------------------------

// Metadata sets the resource type name ("windows_environment_variable").
func (r *windowsEnvVarResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment_variable"
}

// Schema returns the full TPF schema for windows_environment_variable.
func (r *windowsEnvVarResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsEnvVarSchemaDefinition()
}

// ConfigValidators returns resource-level config validators.
func (r *windowsEnvVarResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return windowsEnvVarConfigValidators()
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the EnvVarClient.
func (r *windowsEnvVarResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.client = winclient.NewEnvVarClient(c)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// envVarID constructs the composite resource ID "<scope>:<name>" (ADR-EV-4).
func envVarID(scope winclient.EnvVarScope, name string) string {
	return string(scope) + ":" + name
}

// addEnvVarDiag appends a diagnostic from an EnvVarClient error.
func addEnvVarDiag(diags *diag.Diagnostics, op string, err error) {
	var eve *winclient.EnvVarError
	if errors.As(err, &eve) {
		switch eve.Kind {
		case winclient.EnvVarErrorPermission:
			diags.AddError(
				fmt.Sprintf("Permission denied during %s", op),
				fmt.Sprintf("%s. Ensure the WinRM credentials have the required privileges "+
					"(Local Administrator required for scope=machine).", eve.Message),
			)
		case winclient.EnvVarErrorInvalidInput:
			diags.AddError(
				fmt.Sprintf("Invalid input during %s", op),
				eve.Message,
			)
		default:
			diags.AddError(
				fmt.Sprintf("Error during windows_environment_variable %s", op),
				eve.Message,
			)
		}
		return
	}
	diags.AddError(
		fmt.Sprintf("Error during windows_environment_variable %s", op),
		err.Error(),
	)
}

// ---------------------------------------------------------------------------
// CRUD handlers
// ---------------------------------------------------------------------------

// Create creates a new Windows environment variable and sets the resource ID.
func (r *windowsEnvVarResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsEnvVarModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope := winclient.EnvVarScope(plan.Scope.ValueString())
	input := winclient.EnvVarInput{
		Scope:  scope,
		Name:   plan.Name.ValueString(),
		Value:  plan.Value.ValueString(),
		Expand: plan.Expand.ValueBool(),
	}

	tflog.Debug(ctx, "windows_environment_variable Create", map[string]interface{}{
		"scope": string(scope),
		"name":  input.Name,
	})

	evState, err := r.client.Set(ctx, input)
	if err != nil {
		addEnvVarDiag(&resp.Diagnostics, "Create", err)
		return
	}

	if evState.BroadcastWarning != "" {
		tflog.Warn(ctx, "WM_SETTINGCHANGE broadcast warning after Create", map[string]interface{}{
			"warning": evState.BroadcastWarning,
		})
	}

	model := windowsEnvVarModel{
		ID:     types.StringValue(envVarID(scope, input.Name)),
		Scope:  plan.Scope,
		Name:   plan.Name,
		Value:  types.StringValue(evState.Value),
		Expand: types.BoolValue(evState.Expand),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// Read refreshes Terraform state from the actual Windows environment variable.
//
// Returns (nil, nil) from the client when the variable is absent (EC-4);
// calls resp.State.RemoveResource() to signal drift.
func (r *windowsEnvVarResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsEnvVarModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		// EC-7: malformed state ID.
		resp.Diagnostics.AddError(
			"Malformed resource ID",
			fmt.Sprintf(
				"Resource ID %q is malformed (expected \"<scope>:<name>\"). "+
					"Run 'terraform state rm' on this resource and re-import.",
				id,
			),
		)
		return
	}

	scope := winclient.EnvVarScope(parts[0])
	if scope != winclient.EnvVarScopeMachine && scope != winclient.EnvVarScopeUser {
		resp.Diagnostics.AddError(
			"Malformed resource ID — unknown scope",
			fmt.Sprintf(
				"Resource ID %q has unknown scope %q. "+
					"Run 'terraform state rm' on this resource and re-import.",
				id, parts[0],
			),
		)
		return
	}
	name := parts[1]

	tflog.Debug(ctx, "windows_environment_variable Read", map[string]interface{}{
		"scope": string(scope),
		"name":  name,
	})

	evState, err := r.client.Read(ctx, scope, name)
	if err != nil {
		addEnvVarDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if evState == nil {
		// EC-4: variable deleted out-of-band; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.Value = types.StringValue(evState.Value)
	state.Expand = types.BoolValue(evState.Expand)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies an in-place update to value and/or expand.
//
// name and scope are ForceNew so they cannot change here.
func (r *windowsEnvVarResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsEnvVarModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope := winclient.EnvVarScope(plan.Scope.ValueString())
	input := winclient.EnvVarInput{
		Scope:  scope,
		Name:   plan.Name.ValueString(),
		Value:  plan.Value.ValueString(),
		Expand: plan.Expand.ValueBool(),
	}

	tflog.Debug(ctx, "windows_environment_variable Update", map[string]interface{}{
		"scope": string(scope),
		"name":  input.Name,
	})

	evState, err := r.client.Set(ctx, input)
	if err != nil {
		addEnvVarDiag(&resp.Diagnostics, "Update", err)
		return
	}

	if evState.BroadcastWarning != "" {
		tflog.Warn(ctx, "WM_SETTINGCHANGE broadcast warning after Update", map[string]interface{}{
			"warning": evState.BroadcastWarning,
		})
	}

	plan.Value = types.StringValue(evState.Value)
	plan.Expand = types.BoolValue(evState.Expand)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete removes the Windows environment variable.
//
// Idempotent via the client: a missing variable is a silent no-op (EC-8).
func (r *windowsEnvVarResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsEnvVarModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		// Malformed state; nothing to delete.
		return
	}

	scope := winclient.EnvVarScope(parts[0])
	name := parts[1]

	tflog.Debug(ctx, "windows_environment_variable Delete", map[string]interface{}{
		"scope": string(scope),
		"name":  name,
	})

	if err := r.client.Delete(ctx, scope, name); err != nil {
		addEnvVarDiag(&resp.Diagnostics, "Delete", err)
	}
}

// ImportState imports a Windows environment variable by its composite ID.
//
// ID format: "<scope>:<name>"  (e.g. "machine:JAVA_HOME" or "user:MY_VAR").
// Splits on the first colon (ADR-EV-4). Returns a Terraform error (not
// RemoveResource) when the variable does not exist (EC-10).
func (r *windowsEnvVarResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf(
				"Import ID must be in the format \"<scope>:<name>\" (e.g. \"machine:JAVA_HOME\"), got %q.",
				id,
			),
		)
		return
	}

	scope := winclient.EnvVarScope(parts[0])
	name := parts[1]

	if scope != winclient.EnvVarScopeMachine && scope != winclient.EnvVarScopeUser {
		resp.Diagnostics.AddError(
			"Invalid import ID — unknown scope",
			fmt.Sprintf("scope must be \"machine\" or \"user\", got %q.", parts[0]),
		)
		return
	}

	if strings.ContainsRune(name, '=') {
		resp.Diagnostics.AddError(
			"Invalid import ID — illegal character in name",
			fmt.Sprintf("Variable name %q contains '=', which is not allowed.", name),
		)
		return
	}

	tflog.Debug(ctx, "windows_environment_variable ImportState", map[string]interface{}{
		"scope": string(scope),
		"name":  name,
	})

	evState, err := r.client.Read(ctx, scope, name)
	if err != nil {
		addEnvVarDiag(&resp.Diagnostics, "ImportState", err)
		return
	}
	if evState == nil {
		// EC-10: import for a non-existent variable returns an error (not RemoveResource).
		resp.Diagnostics.AddError(
			"Import failed: variable not found",
			fmt.Sprintf(
				"Environment variable %q (scope=%q) does not exist on the target host. "+
					"Verify the scope and name, or use config+apply to create it.",
				name, string(scope),
			),
		)
		return
	}

	model := windowsEnvVarModel{
		ID:     types.StringValue(envVarID(scope, name)),
		Scope:  types.StringValue(string(scope)),
		Name:   types.StringValue(name),
		Value:  types.StringValue(evState.Value),
		Expand: types.BoolValue(evState.Expand),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
