// Package provider: windows_registry_key resource implementation.
//
// This file contains the Terraform Plugin Framework schema, model, and full
// CRUD + ImportState handlers for the windows_registry_key resource. The key
// resource owns the key itself plus an opt-in purge of unmanaged value names.
// It never carries value payloads: use one windows_registry_value resource
// per value for data, and list those names in managed_value_names so the
// purge does not delete them. SSH interaction is delegated to
// winclient.RegistryKeyClientImpl.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsRegistryKeyResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsRegistryKeyResource)(nil)
	_ resource.ResourceWithImportState = (*windowsRegistryKeyResource)(nil)
)

// NewWindowsRegistryKeyResource is the constructor registered in provider.go.
func NewWindowsRegistryKeyResource() resource.Resource {
	return &windowsRegistryKeyResource{}
}

// windowsRegistryKeyResource is the TPF resource type for windows_registry_key.
type windowsRegistryKeyResource struct {
	client winclient.RegistryKeyClient
}

// registryKeyDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Registry operations issue
// blocking Win32 calls that can stall on an unhealthy host, so every CRUD
// handler bounds its work with this default instead of blocking Terraform
// indefinitely (issue #139).
const registryKeyDefaultTimeout = 10 * time.Minute

// windowsRegistryKeyModel is the Terraform state/plan model for windows_registry_key.
type windowsRegistryKeyModel struct {
	ID                 types.String   `tfsdk:"id"`
	Hive               types.String   `tfsdk:"hive"`
	Path               types.String   `tfsdk:"path"`
	PurgeUnknownValues types.Bool     `tfsdk:"purge_unknown_values"`
	ManagedValueNames  types.List     `tfsdk:"managed_value_names"`
	DeleteKeyOnDestroy types.Bool     `tfsdk:"delete_key_on_destroy"`
	Recursive          types.Bool     `tfsdk:"recursive"`
	ValueNames         types.List     `tfsdk:"value_names"`
	UnknownValueNames  types.List     `tfsdk:"unknown_value_names"`
	Timeouts           timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

// Metadata sets the resource type name ("windows_registry_key").
func (r *windowsRegistryKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_registry_key"
}

// registryKeyGPODescription is appended to the hive/path descriptions: keys
// under a Policies segment are typically enforced by Group Policy.
const registryKeyGPODescription = " Warning: keys under a path containing a Policies segment " +
	"(e.g. SOFTWARE\\Policies or SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies) are typically " +
	"enforced by Group Policy: purged values may be recreated and a deleted key may reappear after the next policy refresh."

// registryKeyCoexistenceDescription documents the single-owner rule shared by
// the purge-related attributes.
const registryKeyCoexistenceDescription = " Each hive/path/name has a single owner: list every name managed by " +
	"windows_registry_value resources in managed_value_names. The key resource never sets value data; " +
	"managing the same name from both resources is last-write-wins, so order the key after its values " +
	"with depends_on when purge_unknown_values is true."

// Schema returns the full TPF schema for windows_registry_key.
func (r *windowsRegistryKeyResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsRegistryKeySchemaDefinition(ctx)
}

// windowsRegistryKeySchemaDefinition returns the schema.Schema for windows_registry_key.
func windowsRegistryKeySchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a Windows registry key on a remote host over SSH + PowerShell: " +
			"ensures the key exists, optionally purges unmanaged value names, and optionally removes " +
			"the key on destroy.\n\n" +
			"The key resource never carries value payloads: manage each value with a " +
			"`windows_registry_value` resource and list its name in `managed_value_names` so the purge " +
			"does not delete it." + registryKeyCoexistenceDescription + "\n\n" +
			"By default (`purge_unknown_values = false`, `delete_key_on_destroy = false`) the resource " +
			"is a no-op towards unknown values and leaves the key in place on destroy.\n\n" +
			"Import example: `terraform import windows_registry_key.example 'HKLM\\SOFTWARE\\MyApp'`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Composite ID: \"<HIVE>\\<PATH>\".",
			},
			"hive": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					hiveNormalizePlanModifier{},
					stringplanmodifier.RequiresReplace(),
				},
				Validators:  []validator.String{hiveEnumValidator{}},
				Description: "Registry hive: HKLM, HKCU, HKCR, HKU, or HKCC (case-insensitive, normalised to uppercase). ForceNew." + registryKeyGPODescription,
			},
			"path": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators:  []validator.String{registryPathValidator{}},
				Description: "Subkey path under the hive (backslash-separated, no leading/trailing backslash). ForceNew." + registryKeyGPODescription,
			},
			"purge_unknown_values": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "When true, Create and Update delete every live value name that is not listed " +
					"in managed_value_names. The purge set is the live enumeration minus managed_value_names; " +
					"no Terraform state outside this resource is consulted, so every managed name must be " +
					"listed explicitly. Default false: unknown values are left in place and only reported " +
					"in unknown_value_names." + registryKeyCoexistenceDescription,
			},
			"managed_value_names": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default: listdefault.StaticValue(
					types.ListValueMust(types.StringType, []attr.Value{}),
				),
				Description: "Value names owned elsewhere (typically the name attributes of " +
					"windows_registry_value resources targeting this key) and therefore excluded from the " +
					"purge. Use \"\" for the Default (unnamed) value, consistently with windows_registry_value. " +
					"Default: empty list.",
			},
			"delete_key_on_destroy": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "When true, Destroy removes the key. Subkeys are only removed when recursive " +
					"is also true. Default false: the key (and everything under it) is left in place on destroy.",
			},
			"recursive": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Allow Destroy to remove the key tree including subkeys. Only takes effect " +
					"with delete_key_on_destroy = true. Purging values never touches subkeys.",
			},
			"value_names": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Live value names enumerated in the key. The Default (unnamed) value appears as \"\".",
			},
			"unknown_value_names": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Preview of the purge: live value names not listed in managed_value_names. " +
					"Populated on every Read; values are only deleted when purge_unknown_values is true.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// registryKeyDefaultTimeout so a stalled registry operation
			// surfaces a timeout diagnostic instead of blocking Terraform
			// indefinitely (issue #139).
			"timeouts": timeouts.Attributes(ctx, rkTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the RegistryKeyClient from provider configuration.
func (r *windowsRegistryKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = winclient.NewRegistryKeyClient(c)
}

// ---------------------------------------------------------------------------
// CRUD + ImportState
// ---------------------------------------------------------------------------

// Create implements resource.Resource.
func (r *windowsRegistryKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsRegistryKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, registryKeyDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_registry_key Create", map[string]interface{}{
		"hive": plan.Hive.ValueString(),
		"path": plan.Path.ValueString(),
	})

	managed, d := rkManagedNames(&plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	live, err := r.client.EnsureKey(ctx, plan.Hive.ValueString(), plan.Path.ValueString())
	if err != nil {
		addRKDiag(&resp.Diagnostics, "Create", err)
		return
	}
	if live == nil {
		resp.Diagnostics.AddError("Unexpected empty response", "EnsureKey returned nil state after Create")
		return
	}

	live, err = r.purgeUnknown(ctx, live, managed, plan.PurgeUnknownValues.ValueBool())
	if err != nil {
		addRKDiag(&resp.Diagnostics, "Create", err)
		return
	}
	if live == nil {
		resp.Diagnostics.AddError("Unexpected empty response", "List returned nil state after purge in Create")
		return
	}

	plan.ID = types.StringValue(rkID(plan.Hive.ValueString(), plan.Path.ValueString()))
	applyRKState(&plan, live, managed, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read implements resource.Resource.
func (r *windowsRegistryKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsRegistryKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, registryKeyDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_registry_key Read", map[string]interface{}{
		"hive": state.Hive.ValueString(),
		"path": state.Path.ValueString(),
	})

	live, err := r.client.List(ctx, state.Hive.ValueString(), state.Path.ValueString())
	if err != nil {
		addRKDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if live == nil || !live.Found {
		// Key no longer exists — remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	managed, d := rkManagedNames(&state)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	applyRKState(&state, live, managed, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update implements resource.Resource.
// Only purge_unknown_values / managed_value_names / delete_key_on_destroy /
// recursive may change in place; hive / path are ForceNew.
func (r *windowsRegistryKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsRegistryKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Preserve id from state (UseStateForUnknown handles this, but be explicit).
	var state windowsRegistryKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = state.ID

	updateTimeout, diags := plan.Timeouts.Update(ctx, registryKeyDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_registry_key Update", map[string]interface{}{
		"hive": plan.Hive.ValueString(),
		"path": plan.Path.ValueString(),
	})

	managed, d := rkManagedNames(&plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	live, err := r.client.List(ctx, plan.Hive.ValueString(), plan.Path.ValueString())
	if err != nil {
		addRKDiag(&resp.Diagnostics, "Update", err)
		return
	}
	if live == nil || !live.Found {
		resp.Diagnostics.AddError("Registry key not found",
			fmt.Sprintf("key %s no longer exists on the target host; taint or remove the resource to recreate it.",
				rkID(plan.Hive.ValueString(), plan.Path.ValueString())))
		return
	}

	live, err = r.purgeUnknown(ctx, live, managed, plan.PurgeUnknownValues.ValueBool())
	if err != nil {
		addRKDiag(&resp.Diagnostics, "Update", err)
		return
	}
	if live == nil {
		resp.Diagnostics.AddError("Unexpected empty response", "List returned nil state after purge in Update")
		return
	}

	applyRKState(&plan, live, managed, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete implements resource.Resource.
// By default the key is left in place; only delete_key_on_destroy=true
// removes it (recursively only with recursive=true).
func (r *windowsRegistryKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsRegistryKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, registryKeyDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_registry_key Delete", map[string]interface{}{
		"hive": state.Hive.ValueString(),
		"path": state.Path.ValueString(),
	})

	if !state.DeleteKeyOnDestroy.ValueBool() {
		return
	}

	if err := r.client.DeleteKey(ctx,
		state.Hive.ValueString(),
		state.Path.ValueString(),
		state.Recursive.ValueBool(),
	); err != nil {
		addRKDiag(&resp.Diagnostics, "Delete", err)
	}
}

// ImportState implements resource.ResourceWithImportState.
//
// Import ID format: HIVE\PATH (e.g. HKLM\SOFTWARE\MyApp).
//
// After ImportState, Terraform will call Read to populate all computed attributes.
func (r *windowsRegistryKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	// Split on first backslash to extract hive.
	firstBS := strings.IndexByte(id, '\\')
	if firstBS < 0 {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("import ID %q must be of the form HIVE\\PATH (e.g. HKLM\\SOFTWARE\\MyApp)", id))
		return
	}
	hive := strings.ToUpper(id[:firstBS])
	regPath := id[firstBS+1:]

	// Validate hive.
	switch hive {
	case "HKLM", "HKCU", "HKCR", "HKU", "HKCC":
	default:
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("unknown hive %q in import ID %q; must be one of HKLM, HKCU, HKCR, HKU, HKCC", hive, id))
		return
	}

	if regPath == "" {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("path is empty in import ID %q", id))
		return
	}

	// Validate the path with the same rules as configuration (EC-6 plus
	// traversal rejection): no leading/trailing backslash, no hive prefix,
	// no empty / "." / ".." segments.
	if err := validateRegistryPathString(regPath); err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("invalid path in import ID %q: %s", id, err.Error()))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), rkID(hive, regPath))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("hive"), hive)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), regPath)...)
	// Defaults for computed/optional fields so Read can populate them.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("purge_unknown_values"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("delete_key_on_destroy"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("recursive"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("managed_value_names"),
		types.ListValueMust(types.StringType, []attr.Value{}))...)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// rkTimeoutsOpts declares which per-operation timeouts the resource exposes.
var rkTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// rkID builds the resource ID: HIVE\PATH.
func rkID(hive, regPath string) string {
	return hive + "\\" + regPath
}

// purgeUnknown deletes the live names not listed in managed when purge is
// enabled, then re-lists the key so callers observe the post-purge state.
// With purge disabled (or nothing unknown) the input state is returned as-is.
func (r *windowsRegistryKeyResource) purgeUnknown(ctx context.Context, live *winclient.RegistryKeyState, managed []string, purge bool) (*winclient.RegistryKeyState, error) {
	if live == nil || !purge {
		return live, nil
	}
	unknown := rkUnknownNames(live.ValueNames, managed)
	if len(unknown) == 0 {
		return live, nil
	}
	if err := r.client.DeleteValues(ctx, live.Hive, live.Path, unknown); err != nil {
		return nil, err
	}
	return r.client.List(ctx, live.Hive, live.Path)
}

// rkManagedNames extracts managed_value_names from the model.
// A null or unknown list means no managed names.
func rkManagedNames(m *windowsRegistryKeyModel) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if m.ManagedValueNames.IsNull() || m.ManagedValueNames.IsUnknown() {
		return []string{}, diags
	}
	elems := m.ManagedValueNames.Elements()
	out := make([]string, 0, len(elems))
	for i, v := range elems {
		s, ok := v.(types.String)
		if !ok {
			diags.AddError("Invalid managed_value_names",
				fmt.Sprintf("expected managed_value_names element %d to be a string, got %T", i, v))
			return nil, diags
		}
		if s.IsUnknown() || s.IsNull() {
			continue
		}
		out = append(out, s.ValueString())
	}
	return out, diags
}

// rkUnknownNames returns the live names that are not listed in managed.
// Comparison is case-insensitive (registry value lookups are
// case-insensitive) while the returned names keep their live casing and
// enumeration order.
func rkUnknownNames(live, managed []string) []string {
	owned := make(map[string]struct{}, len(managed))
	for _, m := range managed {
		owned[strings.ToLower(m)] = struct{}{}
	}
	var out []string
	for _, n := range live {
		if _, ok := owned[strings.ToLower(n)]; !ok {
			out = append(out, n)
		}
	}
	return out
}

// applyRKState updates the computed list fields from the live key state and
// the managed names. It does NOT touch id, hive, path, purge flags, or timeouts.
func applyRKState(m *windowsRegistryKeyModel, live *winclient.RegistryKeyState, managed []string, diags *diag.Diagnostics) {
	names := []string{}
	unknown := []string{}
	if live != nil && live.Found {
		names = live.ValueNames
		if names == nil {
			names = []string{}
		}
		unknown = rkUnknownNames(names, managed)
		if unknown == nil {
			unknown = []string{}
		}
	}

	nameElems := make([]attr.Value, len(names))
	for i, n := range names {
		nameElems[i] = types.StringValue(n)
	}
	list, d := types.ListValue(types.StringType, nameElems)
	diags.Append(d...)
	if !d.HasError() {
		m.ValueNames = list
	}

	unknownElems := make([]attr.Value, len(unknown))
	for i, n := range unknown {
		unknownElems[i] = types.StringValue(n)
	}
	ulist, d := types.ListValue(types.StringType, unknownElems)
	diags.Append(d...)
	if !d.HasError() {
		m.UnknownValueNames = ulist
	}
}

// addRKDiag adds a Terraform diagnostic from a RegistryKeyClient error.
func addRKDiag(diags *diag.Diagnostics, op string, err error) {
	var rke *winclient.RegistryKeyError
	if errors.As(err, &rke) {
		switch rke.Kind {
		case winclient.RegistryKeyErrorPermission:
			diags.AddError(
				fmt.Sprintf("Registry key %s failed: permission denied", op),
				rke.Message+" (Local Administrator on the target host is required for HKLM/HKCR/HKU/HKCC).",
			)
		case winclient.RegistryKeyErrorInvalidInput:
			diags.AddError(fmt.Sprintf("Registry key %s failed: invalid input", op), rke.Message)
		case winclient.RegistryKeyErrorNotFound:
			diags.AddError(fmt.Sprintf("Registry key %s failed: not found", op), rke.Message)
		default:
			diags.AddError(fmt.Sprintf("Registry key %s failed", op), rke.Error())
		}
		return
	}
	diags.AddError(fmt.Sprintf("Registry key %s failed", op), err.Error())
}
