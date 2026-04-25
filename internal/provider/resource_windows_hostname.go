// Package provider: windows_hostname resource implementation.
//
// This file contains the TPF schema, model, custom validator and full
// CRUD + ImportState handlers for the windows_hostname resource. All WinRM
// interaction is delegated to winclient.HostnameClient (internal/winclient).
//
// Spec alignment: windows_hostname spec v1 (2026-04-25).
// Framework:       terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsHostnameResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsHostnameResource)(nil)
	_ resource.ResourceWithImportState = (*windowsHostnameResource)(nil)
)

// NewWindowsHostnameResource is the constructor registered in provider.go.
func NewWindowsHostnameResource() resource.Resource { return &windowsHostnameResource{} }

// windowsHostnameResource is the TPF resource type for windows_hostname.
type windowsHostnameResource struct {
	client *winclient.Client
	hn     winclient.WindowsHostnameClient
}

// windowsHostnameModel is the Terraform state/plan model for the
// windows_hostname resource. Field tags match the snake_case attribute names
// declared in the schema below.
//
// MachineID is anchored as the Terraform resource ID (EC-8, EC-10): it
// survives renames and detects machine replacement out-of-band.
type windowsHostnameModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	CurrentName   types.String `tfsdk:"current_name"`
	PendingName   types.String `tfsdk:"pending_name"`
	RebootPending types.Bool   `tfsdk:"reboot_pending"`
	MachineID     types.String `tfsdk:"machine_id"`
	Force         types.Bool   `tfsdk:"force"`
}

// netbiosNameRegex enforces the structural part of the NetBIOS rule.
var netbiosNameRegex = regexp.MustCompile(
	"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$",
)

// pureNumericRegex matches a string composed only of digits.
var pureNumericRegex = regexp.MustCompile("^[0-9]+$")

// netbiosNameValidator is the cross-rule validator for the `name` attribute.
// It complements the regex/length validators by rejecting purely numeric
// names (EC-1).
type netbiosNameValidator struct{}

// Description returns a human-readable description for plan output.
func (netbiosNameValidator) Description(_ context.Context) string {
	return "must be a valid NetBIOS computer name (1..15 chars, alphanumeric + hyphen, not starting/ending with a hyphen, not purely numeric)"
}

// MarkdownDescription returns the Markdown variant of Description.
func (v netbiosNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString rejects purely numeric NetBIOS names.
func (netbiosNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if pureNumericRegex.MatchString(val) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid NetBIOS name",
			fmt.Sprintf("name %q is purely numeric, which is not a valid NetBIOS computer name", val),
		)
	}
}

// Metadata sets the resource type name ("windows_hostname").
func (r *windowsHostnameResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hostname"
}

// Schema returns the complete TPF schema.
func (r *windowsHostnameResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsHostnameSchemaDefinition()
}

// windowsHostnameSchemaDefinition returns the resource schema. Extracted into
// a function so it can be unit-tested independently of the resource type.
func windowsHostnameSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the NetBIOS computer name (hostname) of a remote Windows machine over WinRM/PowerShell.\n\n" +
			"Renames are **asynchronous**: `Rename-Computer` only persists the new name to the registry; the change becomes active after the next reboot. " +
			"This resource never reboots the host \u2014 it surfaces `pending_name` and `reboot_pending` so an operator (or a downstream `null_resource` / `windows_reboot`) can orchestrate the reboot.\n\n" +
			"**Scope (v1):** workgroup machines only. Domain-joined machines are rejected at runtime (EC-5). The Terraform resource ID is anchored on `machine_id` (HKLM MachineGuid), not on the hostname, so the ID survives renames and detects machine replacement out-of-band.\n\n" +
			"**Destroy is a no-op:** a Windows machine cannot exist without a hostname; `terraform destroy` only removes the resource from state.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform resource ID. Equal to machine_id (HKLM MachineGuid). Stable across renames.",
				MarkdownDescription: "Terraform resource ID. Equal to `machine_id` (HKLM `MachineGuid`). Stable across renames; if it changes between two reads, the underlying machine has been replaced (EC-10).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Target NetBIOS computer name. 1..15 chars, alphanumeric + hyphen, cannot start/end with a hyphen, cannot be purely numeric. Case-insensitive comparison to current_name/pending_name.",
				MarkdownDescription: "Target NetBIOS computer name.\n\n" +
					"Constraints (enforced by schema validators and re-checked server-side, EC-1):\n" +
					"  * length 1..15 characters\n" +
					"  * alphanumeric + hyphen only\n" +
					"  * cannot start or end with a hyphen\n" +
					"  * cannot be purely numeric\n\n" +
					"Comparison against `current_name` / `pending_name` is **case-insensitive** (idempotency, EC-2).",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 15),
					stringvalidator.RegexMatches(netbiosNameRegex,
						"must match ^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$ (NetBIOS structural rule)"),
					netbiosNameValidator{},
				},
			},
			"current_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Active computer name (Win32_ComputerSystem.Name == HKLM ActiveComputerName). May differ from name while a rename is pending a reboot.",
				MarkdownDescription: "Active computer name as exposed by `Win32_ComputerSystem.Name`. May differ from `name` while a rename is pending a reboot (EC-3).",
			},
			"pending_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Hostname queued to take effect on next reboot (HKLM ComputerName/ComputerName). Equal to current_name when no rename is pending.",
				MarkdownDescription: "Hostname queued to take effect on next reboot. Equal to `current_name` when no rename is pending. Drift comparison for `name` is performed against `pending_name` (NOT `current_name`) to avoid an apply loop while a reboot is pending (EC-3).",
			},
			"reboot_pending": schema.BoolAttribute{
				Computed:            true,
				Description:         "True when pending_name (case-insensitive) differs from current_name.",
				MarkdownDescription: "True when `pending_name` differs from `current_name` (case-insensitive). Drives downstream reboot triggers.",
			},
			"machine_id": schema.StringAttribute{
				Computed:            true,
				Description:         "Stable per-machine identifier (HKLM Cryptography MachineGuid).",
				MarkdownDescription: "Stable per-machine identifier read from `HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`. Anchors the Terraform resource ID across renames (EC-10).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"force": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "When true, passes -Force to Rename-Computer. Default: false.",
				MarkdownDescription: "When `true`, passes `-Force` to `Rename-Computer` to suppress the interactive confirmation prompt. Default: `false`.",
				Default:             booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (r *windowsHostnameResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.hn = winclient.NewHostnameClient(c)
}

// ImportState lets `terraform import windows_hostname.this <machine_guid>` work.
// The resource is then refreshed via Read which verifies the live MachineGuid.
func (r *windowsHostnameResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("machine_id"), req.ID)...)
}

// -----------------------------------------------------------------------------
// CRUD
// -----------------------------------------------------------------------------

// Create renames the host (idempotent if already at the desired name) and
// persists the observed state.
func (r *windowsHostnameResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsHostnameModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := winclient.HostnameInput{
		Name:  plan.Name.ValueString(),
		Force: plan.Force.ValueBool(),
	}
	state, err := r.hn.Create(ctx, in)
	if err != nil {
		addHostnameDiag(&resp.Diagnostics, "Create windows_hostname failed", err)
		return
	}
	final := modelFromHostnameState(state, plan)
	maybeWarnRebootPending(&resp.Diagnostics, final, plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Read refreshes Terraform state from the live host. Surfaces EC-5
// (domain-joined) and EC-10 (machine replaced) explicitly. On EC-10 the
// resource is removed from state so Terraform recreates it.
func (r *windowsHostnameResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsHostnameModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.MachineID.ValueString()
	if id == "" {
		id = state.ID.ValueString()
	}
	live, err := r.hn.Read(ctx, id)
	if err != nil {
		if winclient.IsHostnameError(err, winclient.HostnameErrorMachineMismatch) {
			tflog.Warn(ctx, "windows_hostname machine_id mismatch \u2014 removing from state for re-creation",
				map[string]interface{}{"expected_id": id})
			resp.State.RemoveResource(ctx)
			return
		}
		if winclient.IsHostnameError(err, winclient.HostnameErrorDomainJoined) {
			addHostnameDiag(&resp.Diagnostics, "windows_hostname is domain-joined (EC-5)", err)
			return
		}
		addHostnameDiag(&resp.Diagnostics, "Read windows_hostname failed", err)
		return
	}
	final := modelFromHostnameState(live, state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Update applies in-place rename. `name` is the only mutable user-facing
// attribute; toggling `force` alone never triggers a rename because the
// client short-circuits when current_name == pending_name == desired (EC-2/EC-8).
func (r *windowsHostnameResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsHostnameModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := prior.MachineID.ValueString()
	if id == "" {
		id = prior.ID.ValueString()
	}
	in := winclient.HostnameInput{
		Name:  plan.Name.ValueString(),
		Force: plan.Force.ValueBool(),
	}
	state, err := r.hn.Update(ctx, id, in)
	if err != nil {
		if winclient.IsHostnameError(err, winclient.HostnameErrorMachineMismatch) {
			addHostnameDiag(&resp.Diagnostics, "windows_hostname machine has been replaced (EC-10)", err)
			return
		}
		addHostnameDiag(&resp.Diagnostics, "Update windows_hostname failed", err)
		return
	}
	final := modelFromHostnameState(state, plan)
	maybeWarnRebootPending(&resp.Diagnostics, final, plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Delete is a no-op (EC-7). It only emits a tflog.Warn and removes the
// resource from state.
func (r *windowsHostnameResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsHostnameModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current := state.CurrentName.ValueString()
	tflog.Warn(ctx,
		fmt.Sprintf("windows_hostname destroy is a no-op; the computer keeps its current name (%s)", current),
		map[string]interface{}{
			"machine_id":   state.MachineID.ValueString(),
			"current_name": current,
		})
	// Best-effort delegation; HostnameClient.Delete is documented as a no-op.
	_ = r.hn.Delete(ctx, state.MachineID.ValueString())
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// modelFromHostnameState projects a winclient.HostnameState onto a
// windowsHostnameModel, preserving desired-input fields (name, force) from
// the prior plan/state when present.
func modelFromHostnameState(state *winclient.HostnameState, prior windowsHostnameModel) windowsHostnameModel {
	name := prior.Name
	if name.IsNull() || name.IsUnknown() || name.ValueString() == "" {
		// No prior plan/state \u2014 fall back to pending_name (drift target).
		name = types.StringValue(state.PendingName)
	}
	force := prior.Force
	if force.IsNull() || force.IsUnknown() {
		force = types.BoolValue(false)
	}
	return windowsHostnameModel{
		ID:            types.StringValue(state.MachineID),
		Name:          name,
		CurrentName:   types.StringValue(state.CurrentName),
		PendingName:   types.StringValue(state.PendingName),
		RebootPending: types.BoolValue(state.RebootPending),
		MachineID:     types.StringValue(state.MachineID),
		Force:         force,
	}
}

// maybeWarnRebootPending emits a TPF warning when the host needs a reboot to
// activate the rename. The resource never reboots on its own (EC-9).
func maybeWarnRebootPending(diags *diag.Diagnostics, m, _ windowsHostnameModel) {
	if !m.RebootPending.ValueBool() {
		return
	}
	diags.AddWarning(
		"Reboot pending to activate hostname change",
		fmt.Sprintf(
			"The active computer name is %q but the pending name (effective on next reboot) is %q. "+
				"Reboot the target host to complete the rename. The windows_hostname resource never reboots automatically (EC-9).",
			m.CurrentName.ValueString(), m.PendingName.ValueString()),
	)
}

// addHostnameDiag converts a *winclient.HostnameError into a TPF diagnostic.
func addHostnameDiag(diags *diag.Diagnostics, summary string, err error) {
	var he *winclient.HostnameError
	if errors.As(err, &he) {
		detail := he.Message
		if len(he.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range he.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if he.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", he.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
