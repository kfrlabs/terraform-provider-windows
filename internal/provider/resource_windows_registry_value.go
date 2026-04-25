// Package provider: windows_registry_value resource implementation.
//
// This file contains the Terraform Plugin Framework schema, model, validators,
// and full CRUD + ImportState handlers for the windows_registry_value resource.
// WinRM interaction is delegated to winclient.RegistryValueClientImpl.
//
// Spec alignment: windows_registry_value spec v1 (2026-04-25).
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsRegistryValueResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsRegistryValueResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsRegistryValueResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsRegistryValueResource)(nil)
)

// NewWindowsRegistryValueResource is the constructor registered in provider.go.
func NewWindowsRegistryValueResource() resource.Resource {
	return &windowsRegistryValueResource{}
}

// windowsRegistryValueResource is the TPF resource type for windows_registry_value.
type windowsRegistryValueResource struct {
	client winclient.RegistryValueClient
}

// windowsRegistryValueModel is the Terraform state/plan model for windows_registry_value.
type windowsRegistryValueModel struct {
	ID                         types.String `tfsdk:"id"`
	Hive                       types.String `tfsdk:"hive"`
	Path                       types.String `tfsdk:"path"`
	Name                       types.String `tfsdk:"name"`
	Type                       types.String `tfsdk:"type"`
	ValueString                types.String `tfsdk:"value_string"`
	ValueStrings               types.List   `tfsdk:"value_strings"`
	ValueBinary                types.String `tfsdk:"value_binary"`
	ExpandEnvironmentVariables types.Bool   `tfsdk:"expand_environment_variables"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators
// ---------------------------------------------------------------------------

// Metadata sets the resource type name ("windows_registry_value").
func (r *windowsRegistryValueResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_registry_value"
}

// Schema returns the full TPF schema for windows_registry_value.
func (r *windowsRegistryValueResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsRegistryValueSchemaDefinition()
}

// ConfigValidators returns resource-level cross-attribute validators (CV-1..CV-7).
func (r *windowsRegistryValueResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return windowsRegistryValueConfigValidators()
}

// ---------------------------------------------------------------------------
// Schema definition (inlined from work/schema.go)
// ---------------------------------------------------------------------------

// registryPathRegex validates path format (EC-6c/d/e).
// Regex: ^[^\\\x00]+(\\[^\\\x00]+)*$
var registryPathRegex = regexp.MustCompile("^[^\\\\\\x00]+(\\\\[^\\\\\\x00]+)*$")

// knownHiveAbbreviations used to detect hive prefix in path (EC-6b).
var knownHiveAbbreviations = []string{
	"HKLM", "HKCU", "HKCR", "HKU", "HKCC",
	"HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT",
	"HKEY_USERS", "HKEY_CURRENT_CONFIG",
}

// windowsRegistryValueSchemaDefinition returns the schema.Schema for windows_registry_value.
func windowsRegistryValueSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a single named value (or the unnamed Default value) inside a Windows " +
			"registry key on a remote host via WinRM + PowerShell.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Composite ID: \"<HIVE>\\<PATH>\\<NAME>\". Trailing backslash when name=\"\" (Default value).",
			},
			"hive": schema.StringAttribute{
				Required: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					hiveNormalizePlanModifier{},
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{hiveEnumValidator{}},
				Description: "Registry hive: HKLM, HKCU, HKCR, HKU, or HKCC (case-insensitive, normalised to uppercase). ForceNew.",
			},
			"path": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{registryPathValidator{}},
				Description: "Subkey path under the hive (backslash-separated, no leading/trailing backslash). ForceNew.",
			},
			"name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile("^[^\\x00]*$"),
						"value name must not contain NUL bytes",
					),
				},
				Description: "Value name (\"\" = Default value). ForceNew.",
			},
			"type": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY", "REG_NONE"),
				},
				Description: "Registry value type (case-sensitive). ForceNew.",
			},
			"value_string": schema.StringAttribute{
				Optional:    true,
				Description: "String value for REG_SZ, REG_EXPAND_SZ, REG_DWORD (decimal uint32), REG_QWORD (decimal uint64).",
			},
			"value_strings": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Multi-string value for REG_MULTI_SZ. Empty list [] is valid (EC-10).",
			},
			"value_binary": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile("^[0-9a-f]*$"),
						"value_binary must be a lowercase hexadecimal string without separators",
					),
					hexEvenLengthValidator{},
				},
				Description: "Binary value for REG_BINARY/REG_NONE as a lowercase hex string (e.g. \"deadbeef\", \"\" for zero bytes).",
			},
			"expand_environment_variables": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "When true, Read returns expanded REG_EXPAND_SZ values. Only valid with type=REG_EXPAND_SZ (CV-7).",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Validators (from work/schema.go)
// ---------------------------------------------------------------------------

// hiveEnumValidator validates the hive attribute (case-insensitive).
type hiveEnumValidator struct{}

func (hiveEnumValidator) Description(_ context.Context) string {
	return "must be one of HKLM, HKCU, HKCR, HKU, HKCC (case-insensitive)"
}
func (v hiveEnumValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (hiveEnumValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	switch strings.ToUpper(req.ConfigValue.ValueString()) {
	case "HKLM", "HKCU", "HKCR", "HKU", "HKCC":
	default:
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid registry hive",
			fmt.Sprintf("hive must be one of HKLM, HKCU, HKCR, HKU, HKCC (case-insensitive); got %q (EC-6a).", req.ConfigValue.ValueString()))
	}
}

// hiveNormalizePlanModifier normalises the hive to uppercase in the plan (ADR-RV-6).
// Must be ordered BEFORE RequiresReplace.
type hiveNormalizePlanModifier struct{}

func (hiveNormalizePlanModifier) Description(_ context.Context) string {
	return "Normalises registry hive to uppercase (HKLM, HKCU, HKCR, HKU, HKCC)."
}
func (m hiveNormalizePlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}
func (hiveNormalizePlanModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	resp.PlanValue = types.StringValue(strings.ToUpper(req.ConfigValue.ValueString()))
}

// registryPathValidator validates path format and detects hive prefix (EC-6).
type registryPathValidator struct{}

func (registryPathValidator) Description(_ context.Context) string {
	return "registry subkey path must be non-empty, no leading/trailing backslash, no hive prefix"
}
func (v registryPathValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (registryPathValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	upper := strings.ToUpper(val)
	for _, hive := range knownHiveAbbreviations {
		if upper == hive || strings.HasPrefix(upper, hive+"\\") {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid registry path — hive prefix detected",
				fmt.Sprintf("path %q must not include the hive prefix (EC-6b). Use the hive attribute instead.", val))
			return
		}
	}
	if !registryPathRegex.MatchString(val) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid registry path",
			fmt.Sprintf("path %q is invalid: must be non-empty, no leading/trailing backslash, no NUL bytes (EC-6c/d/e).", val))
	}
}

// hexEvenLengthValidator rejects odd-length value_binary strings (EC-8).
type hexEvenLengthValidator struct{}

func (hexEvenLengthValidator) Description(_ context.Context) string {
	return "value_binary must have an even number of hex characters"
}
func (v hexEvenLengthValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (hexEvenLengthValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if len(val)%2 != 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid binary value — odd hex length",
			fmt.Sprintf("value_binary must have an even number of hex characters; got %d character(s) (EC-8).", len(val)))
	}
}

// registryValueTypeDataValidator enforces CV-1..CV-6 cross-attribute type/value rules.
type registryValueTypeDataValidator struct{}

func (registryValueTypeDataValidator) Description(_ context.Context) string {
	return "Validates that the correct value_* attribute is set for the declared registry value type (CV-1..CV-6)"
}
func (v registryValueTypeDataValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (registryValueTypeDataValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var typeVal types.String
	var valueString types.String
	var valueStrings types.List
	var valueBinary types.String

	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("type"), &typeVal)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_string"), &valueString)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_strings"), &valueStrings)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_binary"), &valueBinary)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if typeVal.IsNull() || typeVal.IsUnknown() {
		return
	}

	t := typeVal.ValueString()
	valueStringSet := !valueString.IsNull()
	valueStringsSet := !valueStrings.IsNull()
	valueBinarySet := !valueBinary.IsNull()

	switch t {
	case "REG_SZ", "REG_EXPAND_SZ":
		if valueString.IsNull() || (!valueString.IsUnknown() && valueString.ValueString() == "") {
			resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Required attribute missing or empty",
				fmt.Sprintf("value_string is required and must be non-empty when type = %q (CV-1).", t))
		}
		if valueStringsSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_strings"), "Forbidden attribute for this type",
				fmt.Sprintf("value_strings must not be set when type = %q (CV-1).", t))
		}
		if valueBinarySet {
			resp.Diagnostics.AddAttributeError(path.Root("value_binary"), "Forbidden attribute for this type",
				fmt.Sprintf("value_binary must not be set when type = %q (CV-1).", t))
		}
	case "REG_DWORD":
		if valueString.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Required attribute missing",
				"value_string is required for REG_DWORD (decimal uint32 in [0,4294967295]) (CV-2).")
		} else if !valueString.IsUnknown() {
			if _, err := strconv.ParseUint(valueString.ValueString(), 10, 32); err != nil {
				resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Invalid REG_DWORD value",
					fmt.Sprintf("value_string for REG_DWORD must be a decimal integer in [0,4294967295]; got %q (CV-2).", valueString.ValueString()))
			}
		}
		if valueStringsSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_strings"), "Forbidden attribute", "value_strings must not be set when type = \"REG_DWORD\" (CV-2).")
		}
		if valueBinarySet {
			resp.Diagnostics.AddAttributeError(path.Root("value_binary"), "Forbidden attribute", "value_binary must not be set when type = \"REG_DWORD\" (CV-2).")
		}
	case "REG_QWORD":
		if valueString.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Required attribute missing",
				"value_string is required for REG_QWORD (decimal uint64 in [0,18446744073709551615]) (CV-3).")
		} else if !valueString.IsUnknown() {
			if _, err := strconv.ParseUint(valueString.ValueString(), 10, 64); err != nil {
				resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Invalid REG_QWORD value",
					fmt.Sprintf("value_string for REG_QWORD must be a decimal integer in [0,18446744073709551615]; got %q (CV-3).", valueString.ValueString()))
			}
		}
		if valueStringsSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_strings"), "Forbidden attribute", "value_strings must not be set when type = \"REG_QWORD\" (CV-3).")
		}
		if valueBinarySet {
			resp.Diagnostics.AddAttributeError(path.Root("value_binary"), "Forbidden attribute", "value_binary must not be set when type = \"REG_QWORD\" (CV-3).")
		}
	case "REG_MULTI_SZ":
		if valueStrings.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("value_strings"), "Required attribute missing",
				"value_strings is required for REG_MULTI_SZ (use [] for empty) (CV-4).")
		}
		if valueStringSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Forbidden attribute", "value_string must not be set when type = \"REG_MULTI_SZ\" (CV-4).")
		}
		if valueBinarySet {
			resp.Diagnostics.AddAttributeError(path.Root("value_binary"), "Forbidden attribute", "value_binary must not be set when type = \"REG_MULTI_SZ\" (CV-4).")
		}
	case "REG_BINARY":
		if valueBinary.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root("value_binary"), "Required attribute missing",
				"value_binary is required for REG_BINARY (CV-5).")
		}
		if valueStringSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Forbidden attribute", "value_string must not be set when type = \"REG_BINARY\" (CV-5).")
		}
		if valueStringsSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_strings"), "Forbidden attribute", "value_strings must not be set when type = \"REG_BINARY\" (CV-5).")
		}
	case "REG_NONE":
		if valueStringSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_string"), "Forbidden attribute", "value_string must not be set when type = \"REG_NONE\" (CV-6).")
		}
		if valueStringsSet {
			resp.Diagnostics.AddAttributeError(path.Root("value_strings"), "Forbidden attribute", "value_strings must not be set when type = \"REG_NONE\" (CV-6).")
		}
	}
}

// registryValueExpandEnvVarsValidator enforces CV-7: expand_environment_variables=true requires REG_EXPAND_SZ.
type registryValueExpandEnvVarsValidator struct{}

func (registryValueExpandEnvVarsValidator) Description(_ context.Context) string {
	return "expand_environment_variables = true is only valid when type = \"REG_EXPAND_SZ\" (CV-7)"
}
func (v registryValueExpandEnvVarsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (registryValueExpandEnvVarsValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var expandEnvVars types.Bool
	var typeVal types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("expand_environment_variables"), &expandEnvVars)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("type"), &typeVal)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if expandEnvVars.IsNull() || expandEnvVars.IsUnknown() || !expandEnvVars.ValueBool() {
		return
	}
	if typeVal.IsNull() || typeVal.IsUnknown() {
		return
	}
	if typeVal.ValueString() != "REG_EXPAND_SZ" {
		resp.Diagnostics.AddAttributeError(path.Root("expand_environment_variables"), "Invalid attribute combination",
			fmt.Sprintf("expand_environment_variables = true is only valid when type = \"REG_EXPAND_SZ\"; got type = %q (CV-7).", typeVal.ValueString()))
	}
}

// windowsRegistryValueConfigValidators returns the resource-level ConfigValidators.
func windowsRegistryValueConfigValidators() []resource.ConfigValidator {
	return []resource.ConfigValidator{
		registryValueTypeDataValidator{},
		registryValueExpandEnvVarsValidator{},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the RegistryValueClient from provider configuration.
func (r *windowsRegistryValueResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.client = winclient.NewRegistryValueClient(c)
}

// ---------------------------------------------------------------------------
// CRUD + ImportState
// ---------------------------------------------------------------------------

// Create implements resource.Resource.
func (r *windowsRegistryValueResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsRegistryValueModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input, err := rvModelToInput(&plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid registry value input", err.Error())
		return
	}

	rv, err := r.client.Set(ctx, input)
	if err != nil {
		addRVDiag(&resp.Diagnostics, "Create", err)
		return
	}
	if rv == nil {
		resp.Diagnostics.AddError("Unexpected empty response", "Set returned nil state after Create")
		return
	}

	plan.ID = types.StringValue(rvID(plan.Hive.ValueString(), plan.Path.ValueString(), plan.Name.ValueString()))
	applyRVState(&plan, rv, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read implements resource.Resource.
func (r *windowsRegistryValueResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsRegistryValueModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rv, err := r.client.Read(ctx,
		state.Hive.ValueString(),
		state.Path.ValueString(),
		state.Name.ValueString(),
		state.ExpandEnvironmentVariables.ValueBool(),
	)
	if err != nil {
		addRVDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if rv == nil {
		// Value not found — remove from state (EC-4).
		resp.State.RemoveResource(ctx)
		return
	}

	applyRVState(&state, rv, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update implements resource.Resource.
// Only value_string / value_strings / value_binary / expand_environment_variables may change.
// type / hive / path / name are all ForceNew.
func (r *windowsRegistryValueResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsRegistryValueModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Preserve id from state (UseStateForUnknown handles this, but be explicit).
	var state windowsRegistryValueModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = state.ID

	input, err := rvModelToInput(&plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid registry value input", err.Error())
		return
	}

	rv, err := r.client.Set(ctx, input)
	if err != nil {
		addRVDiag(&resp.Diagnostics, "Update", err)
		return
	}
	if rv == nil {
		resp.Diagnostics.AddError("Unexpected empty response", "Set returned nil state after Update")
		return
	}

	applyRVState(&plan, rv, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete implements resource.Resource.
// Idempotent: missing value or key is a no-op (EC-12).
func (r *windowsRegistryValueResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsRegistryValueModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.Delete(ctx, state.Hive.ValueString(), state.Path.ValueString(), state.Name.ValueString()); err != nil {
		addRVDiag(&resp.Diagnostics, "Delete", err)
	}
}

// ImportState implements resource.ResourceWithImportState.
//
// Import ID format: HIVE\PATH\NAME
// For the Default value (name=""), the ID ends with a trailing backslash: HIVE\PATH\
//
// After ImportState, Terraform will call Read to populate all computed attributes.
func (r *windowsRegistryValueResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	// Split on first backslash to extract hive.
	firstBS := strings.IndexByte(id, '\\')
	if firstBS < 0 {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("import ID %q must be of the form HIVE\\PATH\\NAME (e.g. HKLM\\SOFTWARE\\MyApp\\Version)", id))
		return
	}
	hive := strings.ToUpper(id[:firstBS])
	rest := id[firstBS+1:]

	// Validate hive.
	switch hive {
	case "HKLM", "HKCU", "HKCR", "HKU", "HKCC":
	default:
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("unknown hive %q in import ID %q; must be one of HKLM, HKCU, HKCR, HKU, HKCC", hive, id))
		return
	}

	// Split on last backslash to separate path from name.
	// Trailing backslash → name="" (Default value).
	lastBS := strings.LastIndexByte(rest, '\\')
	if lastBS < 0 {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("import ID %q has no path separator after hive; expected HIVE\\PATH\\NAME", id))
		return
	}
	regPath := rest[:lastBS]
	name := rest[lastBS+1:]

	if regPath == "" {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("path is empty in import ID %q", id))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("hive"), hive)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), regPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	// Defaults for computed/optional fields so Read can populate them.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("expand_environment_variables"), false)...)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// rvID builds the resource ID: HIVE\PATH\NAME (trailing \ when name="").
func rvID(hive, regPath, name string) string {
	return hive + "\\" + regPath + "\\" + name
}

// rvModelToInput converts a windowsRegistryValueModel to a RegistryValueInput.
func rvModelToInput(m *windowsRegistryValueModel) (winclient.RegistryValueInput, error) {
	input := winclient.RegistryValueInput{
		Hive:                       m.Hive.ValueString(),
		Path:                       m.Path.ValueString(),
		Name:                       m.Name.ValueString(),
		Kind:                       winclient.RegistryValueKind(m.Type.ValueString()),
		ExpandEnvironmentVariables: m.ExpandEnvironmentVariables.ValueBool(),
	}

	switch input.Kind {
	case winclient.RegistryValueKindString, winclient.RegistryValueKindExpandString,
		winclient.RegistryValueKindDWord, winclient.RegistryValueKindQWord:
		if !m.ValueString.IsNull() && !m.ValueString.IsUnknown() {
			s := m.ValueString.ValueString()
			input.ValueString = &s
		}

	case winclient.RegistryValueKindMultiString:
		if !m.ValueStrings.IsNull() && !m.ValueStrings.IsUnknown() {
			elems := m.ValueStrings.Elements()
			strs := make([]string, len(elems))
			for i, v := range elems {
				strs[i] = v.(types.String).ValueString()
			}
			input.ValueStrings = strs
		} else {
			input.ValueStrings = []string{}
		}

	case winclient.RegistryValueKindBinary, winclient.RegistryValueKindNone:
		if !m.ValueBinary.IsNull() && !m.ValueBinary.IsUnknown() {
			s := m.ValueBinary.ValueString()
			input.ValueBinary = &s
		} else {
			empty := ""
			input.ValueBinary = &empty
		}
	}

	return input, nil
}

// applyRVState updates the model fields that come from the live registry state.
// It does NOT touch id, hive, path, name, or expand_environment_variables.
func applyRVState(m *windowsRegistryValueModel, rv *winclient.RegistryValueState, diags *diag.Diagnostics) {
	m.Type = types.StringValue(string(rv.Kind))

	// Reset all value fields.
	m.ValueString = types.StringNull()
	m.ValueStrings = types.ListNull(types.StringType)
	m.ValueBinary = types.StringNull()

	switch rv.Kind {
	case winclient.RegistryValueKindMultiString:
		strs := rv.ValueStrings
		if strs == nil {
			strs = []string{}
		}
		elems := make([]attr.Value, len(strs))
		for i, s := range strs {
			elems[i] = types.StringValue(s)
		}
		list, d := types.ListValue(types.StringType, elems)
		diags.Append(d...)
		if !d.HasError() {
			m.ValueStrings = list
		}

	case winclient.RegistryValueKindBinary, winclient.RegistryValueKindNone:
		hex := ""
		if rv.ValueBinary != nil {
			hex = *rv.ValueBinary
		}
		m.ValueBinary = types.StringValue(hex)

	default:
		if rv.ValueString != nil {
			m.ValueString = types.StringValue(*rv.ValueString)
		}
	}
}

// addRVDiag adds a Terraform diagnostic from a RegistryValueClient error.
func addRVDiag(diags *diag.Diagnostics, op string, err error) {
	var rve *winclient.RegistryValueError
	if errors.As(err, &rve) {
		switch rve.Kind {
		case winclient.RegistryValueErrorTypeConflict:
			diags.AddError(
				fmt.Sprintf("Registry value %s failed: type conflict", op),
				rve.Message+" — use terraform import to adopt the existing value, then plan a ForceNew type change.",
			)
		case winclient.RegistryValueErrorPermission:
			diags.AddError(
				fmt.Sprintf("Registry value %s failed: permission denied", op),
				rve.Message+" (Local Administrator on the target host is required for HKLM/HKCR/HKU/HKCC).",
			)
		case winclient.RegistryValueErrorInvalidInput:
			diags.AddError(fmt.Sprintf("Registry value %s failed: invalid input", op), rve.Message)
		default:
			diags.AddError(fmt.Sprintf("Registry value %s failed", op), rve.Error())
		}
		return
	}
	diags.AddError(fmt.Sprintf("Registry value %s failed", op), err.Error())
}