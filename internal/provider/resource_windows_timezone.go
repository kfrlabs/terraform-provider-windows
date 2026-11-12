// Package provider: windows_timezone resource implementation.
//
// This file contains the TPF schema, model, custom validator and full
// CRUD + ImportState handlers for the windows_timezone resource. All SSH
// interaction is delegated to winclient.TimezoneClient (internal/winclient).
//
// The system time zone is a singleton: the host always has exactly one, so
// Create and Update share the same Set operation, Read refreshes from the
// live host and never removes the resource from state, and Delete makes no
// remote change unless restore_on_destroy re-applies the pre-existing values
// captured into private state at Create (or import) time.
//
// Spec alignment: windows_timezone spec (issue #286).
// Framework:       terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	_ resource.Resource                = (*windowsTimezoneResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsTimezoneResource)(nil)
	_ resource.ResourceWithImportState = (*windowsTimezoneResource)(nil)
)

// NewWindowsTimezoneResource is the constructor registered in provider.go.
func NewWindowsTimezoneResource() resource.Resource { return &windowsTimezoneResource{} }

// windowsTimezoneResource is the TPF resource type for windows_timezone.
type windowsTimezoneResource struct {
	tz winclient.WindowsTimezoneClient
}

// timezoneDefaultTimeout is the fallback per-operation timeout when the user
// does not provide a `timeouts {}` block. Time zone reads and writes are
// normally fast, but a stalled PowerShell/SSH session must never block
// Terraform forever: every CRUD handler bounds its work with this default.
const timezoneDefaultTimeout = 5 * time.Minute

// timezonePrivateKey is the private-state key holding the JSON-encoded
// pre-existing time zone state captured at Create (or import) time. Delete
// with restore_on_destroy re-applies it verbatim.
const timezonePrivateKey = "original_state"

// windowsTimezoneModel is the Terraform state/plan model for the
// windows_timezone resource. Field tags match the snake_case attribute names
// declared in the schema below.
//
// ID is anchored on MachineID (HKLM MachineGuid): it survives zone changes
// and is refreshed from the live host on every Read.
type windowsTimezoneModel struct {
	ID                     types.String   `tfsdk:"id"`
	TimezoneID             types.String   `tfsdk:"timezone_id"`
	DaylightSavingDisabled types.Bool     `tfsdk:"daylight_saving_disabled"`
	DisplayName            types.String   `tfsdk:"display_name"`
	BaseUTCOffset          types.String   `tfsdk:"base_utc_offset"`
	SupportsDST            types.Bool     `tfsdk:"supports_daylight_saving_time"`
	CurrentUTCOffset       types.String   `tfsdk:"current_utc_offset"`
	TzautoupdateEnabled    types.Bool     `tfsdk:"tzautoupdate_enabled"`
	RestoreOnDestroy       types.Bool     `tfsdk:"restore_on_destroy"`
	Timeouts               timeouts.Value `tfsdk:"timeouts"`
}

// timezoneIDValidator rejects IANA-style IDs containing "/". Windows time
// zone IDs (e.g. "Romance Standard Time") never contain a slash.
type timezoneIDValidator struct{}

// Description returns a human-readable description for plan output.
func (timezoneIDValidator) Description(_ context.Context) string {
	return "must be a Windows time zone ID (IANA IDs are not supported)"
}

// MarkdownDescription returns the Markdown variant of Description.
func (v timezoneIDValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString rejects values containing "/". Null and unknown values
// are skipped.
func (timezoneIDValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.Contains(req.ConfigValue.ValueString(), "/") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Windows time zone ID",
			"Windows time zone IDs never contain '/'; IANA IDs such as Europe/Paris are not supported — use e.g. Romance Standard Time",
		)
	}
}

// Metadata sets the resource type name ("windows_timezone").
func (r *windowsTimezoneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_timezone"
}

// Schema returns the complete TPF schema.
func (r *windowsTimezoneResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsTimezoneSchemaDefinition(ctx)
}

// windowsTimezoneSchemaDefinition returns the resource schema. Extracted into
// a function so it can be unit-tested independently of the resource type.
func windowsTimezoneSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the system time zone of a remote Windows machine over SSH/PowerShell.\n\n" +
			"The system time zone is a **singleton**: the host always has exactly one, so creating this resource never " +
			"provisions anything new — it only sets the zone in place (`Set-TimeZone`, or `tzutil.exe /s \"<id>_dstoff\"` " +
			"when `daylight_saving_disabled` is true), and deleting it makes no remote change unless `restore_on_destroy` is set.\n\n" +
			"Windows time zone IDs are used (e.g. `Romance Standard Time`); IANA IDs such as `Europe/Paris` are rejected at plan time. " +
			"The Terraform resource ID is anchored on `id` (HKLM `MachineGuid`), not on the zone, so it survives zone changes.\n\n" +
			"When the `tzautoupdate` service may change the zone automatically (`tzautoupdate_enabled`), every operation warns: " +
			"Windows can move the zone out from under Terraform.\n\n" +
			"**Destroy is a no-op by default:** a Windows machine cannot exist without a time zone; `terraform destroy` only removes " +
			"the resource from state unless `restore_on_destroy` re-applies the pre-existing zone.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform resource ID. Equal to the host MachineGuid (HKLM Cryptography MachineGuid). Stable across time zone changes.",
				MarkdownDescription: "Terraform resource ID. Equal to the host `MachineGuid` (`HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`). Stable across time zone changes.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"timezone_id": schema.StringAttribute{
				Required:            true,
				Description:         "Windows time zone ID (e.g. Romance Standard Time). Windows IDs never contain '/'; IANA IDs such as Europe/Paris are not supported.",
				MarkdownDescription: "Windows time zone ID (e.g. `Romance Standard Time`). Windows IDs never contain `/`; IANA IDs such as `Europe/Paris` are not supported — use the Windows ID instead. Comparison is **case-insensitive**.",
				Validators: []validator.String{
					timezoneIDValidator{},
				},
			},
			"daylight_saving_disabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "When true, daylight saving time is disabled for the zone (tzutil <id>_dstoff). Default: false.",
				MarkdownDescription: "When `true`, daylight saving time is disabled for the zone (`tzutil.exe /s \"<id>_dstoff\"`). Default: `false`.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"display_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Localized display name of the configured time zone.",
				MarkdownDescription: "Localized display name of the configured time zone (e.g. `(UTC+01:00) Brussels, Copenhagen, Madrid, Paris`).",
			},
			"base_utc_offset": schema.StringAttribute{
				Computed:            true,
				Description:         "Standard (non-DST) UTC offset of the zone, formatted as +HH:mm (e.g. +01:00).",
				MarkdownDescription: "Standard (non-DST) UTC offset of the zone, formatted as `+HH:mm` (e.g. `+01:00`).",
			},
			"supports_daylight_saving_time": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the zone definition includes daylight saving time.",
				MarkdownDescription: "Whether the zone definition includes daylight saving time.",
			},
			"current_utc_offset": schema.StringAttribute{
				Computed:            true,
				Description:         "Live effective UTC offset (base plus the active DST delta, if any), formatted as +HH:mm.",
				MarkdownDescription: "Live effective UTC offset (base plus the active DST delta, if any), formatted as `+HH:mm` (e.g. `+02:00` in summer).",
			},
			"tzautoupdate_enabled": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the tzautoupdate service may change the time zone automatically. When true, every operation warns.",
				MarkdownDescription: "Whether the `tzautoupdate` service may change the time zone automatically. When `true`, every operation warns that Windows can move the zone out from under Terraform.",
			},
			"restore_on_destroy": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "When true, destroy re-applies the pre-existing time zone values captured at creation (or import) time. Defaults to false: destroy makes no remote change.",
				MarkdownDescription: "When `true`, destroy re-applies the pre-existing time zone values captured at creation (or import) time. Defaults to `false`: destroy makes no remote change.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to timezoneDefaultTimeout
			// so a stalled PowerShell/SSH session surfaces a timeout
			// diagnostic instead of blocking Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, tzTimeoutsOpts),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (r *windowsTimezoneResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.tz = winclient.NewTimezoneClient(c)
}

// ImportState adopts the live time zone: any import ID is accepted and
// ignored (the zone is a singleton), the observed values become the snapshot
// for a later restore_on_destroy.
func (r *windowsTimezoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if strings.TrimSpace(req.ID) == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			"Import requires a non-empty ID (its value is ignored; the live time zone is adopted). For example: terraform import windows_timezone.this current",
		)
		return
	}

	tflog.Debug(ctx, "Importing windows_timezone (singleton: live zone is adopted)")

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, timezoneDefaultTimeout)
	defer cancel()

	live, err := r.tz.Read(ctx)
	if err != nil {
		addTimezoneDiag(&resp.Diagnostics, "Error importing windows_timezone", err)
		return
	}

	if err := setTimezoneSnapshot(ctx, resp.Private.SetKey, live); err != nil {
		addTimezoneDiag(&resp.Diagnostics, "Error capturing pre-existing windows_timezone state", err)
		return
	}

	m := modelFromTimezoneState(live, windowsTimezoneModel{})
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by the framework on State.Set — use a typed
	// null instead (the subsequent Read fills in the configured values).
	m.Timeouts = tzNullTimeouts()
	m.RestoreOnDestroy = types.BoolValue(false)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// -----------------------------------------------------------------------------
// CRUD
// -----------------------------------------------------------------------------

// Create sets the system time zone in place (idempotent if already at the
// desired zone) and persists the observed state. When restore_on_destroy is
// set, the pre-existing values are captured into private state first so
// Delete can re-apply them.
func (r *windowsTimezoneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsTimezoneModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, timezoneDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	if plan.RestoreOnDestroy.ValueBool() {
		pre, err := r.tz.Read(ctx)
		if err != nil {
			addTimezoneDiag(&resp.Diagnostics, "Error reading pre-existing windows_timezone state", err)
			return
		}
		if err := setTimezoneSnapshot(ctx, resp.Private.SetKey, pre); err != nil {
			addTimezoneDiag(&resp.Diagnostics, "Error capturing pre-existing windows_timezone state", err)
			return
		}
	}

	in := winclient.TimezoneInput{
		TimezoneID:             plan.TimezoneID.ValueString(),
		DaylightSavingDisabled: plan.DaylightSavingDisabled.ValueBool(),
	}
	state, err := r.tz.Set(ctx, in)
	if err != nil {
		addTimezoneDiag(&resp.Diagnostics, "Create windows_timezone failed", err)
		return
	}
	if !timezoneIDsEqual(state.TimezoneID, in.TimezoneID) || state.DaylightSavingDisabled != in.DaylightSavingDisabled {
		addTimezoneDiag(&resp.Diagnostics, "Create windows_timezone failed",
			winclient.NewTimezoneError(winclient.TimezoneErrorInvalidTimezone,
				fmt.Sprintf("time zone change did not take effect: desired %q (DST disabled: %v), observed %q (DST disabled: %v)",
					in.TimezoneID, in.DaylightSavingDisabled, state.TimezoneID, state.DaylightSavingDisabled),
				nil, map[string]string{"timezone_id": in.TimezoneID, "observed_id": state.TimezoneID}))
		return
	}
	final := modelFromTimezoneState(state, plan)
	maybeWarnTzautoupdate(&resp.Diagnostics, final)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Read refreshes Terraform state from the live host time zone. The zone
// always exists, so a read failure surfaces an error diagnostic instead of
// silently removing the resource from state.
func (r *windowsTimezoneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsTimezoneModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, timezoneDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	live, err := r.tz.Read(ctx)
	if err != nil {
		addTimezoneDiag(&resp.Diagnostics, "Read windows_timezone failed", err)
		return
	}
	final := modelFromTimezoneState(live, state)
	maybeWarnTzautoupdate(&resp.Diagnostics, final)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Update applies the new time zone in place. Like Create it funnels into
// Set; the restore snapshot captured at Create time is left untouched
// (restore always returns to the pre-existing values, not to the previous
// plan).
func (r *windowsTimezoneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsTimezoneModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsTimezoneModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, timezoneDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	in := winclient.TimezoneInput{
		TimezoneID:             plan.TimezoneID.ValueString(),
		DaylightSavingDisabled: plan.DaylightSavingDisabled.ValueBool(),
	}
	state, err := r.tz.Set(ctx, in)
	if err != nil {
		addTimezoneDiag(&resp.Diagnostics, "Update windows_timezone failed", err)
		return
	}
	if !timezoneIDsEqual(state.TimezoneID, in.TimezoneID) || state.DaylightSavingDisabled != in.DaylightSavingDisabled {
		addTimezoneDiag(&resp.Diagnostics, "Update windows_timezone failed",
			winclient.NewTimezoneError(winclient.TimezoneErrorInvalidTimezone,
				fmt.Sprintf("time zone change did not take effect: desired %q (DST disabled: %v), observed %q (DST disabled: %v)",
					in.TimezoneID, in.DaylightSavingDisabled, state.TimezoneID, state.DaylightSavingDisabled),
				nil, map[string]string{"timezone_id": in.TimezoneID, "observed_id": state.TimezoneID}))
		return
	}
	final := modelFromTimezoneState(state, plan)
	maybeWarnTzautoupdate(&resp.Diagnostics, final)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Delete removes the resource from state. By default it makes no remote
// change (a Windows machine always has a time zone). With
// restore_on_destroy it re-applies the snapshot captured at Create (or
// import) time; when no snapshot exists it warns and leaves the host
// untouched rather than guessing.
func (r *windowsTimezoneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsTimezoneModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, timezoneDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	tflog.Debug(ctx, "Deleting windows_timezone", map[string]any{
		"timezone_id":        state.TimezoneID.ValueString(),
		"restore_on_destroy": state.RestoreOnDestroy.ValueBool(),
	})

	if !state.RestoreOnDestroy.ValueBool() {
		return
	}

	snap, ok := getTimezoneSnapshot(ctx, req.Private.GetKey)
	if !ok {
		resp.Diagnostics.AddWarning(
			"Time zone restore skipped: no snapshot",
			fmt.Sprintf("restore_on_destroy is set, but the pre-existing snapshot of the time zone could not be read "+
				"(it may be corrupt or from an incompatible version). Leaving the host zone %q untouched.",
				state.TimezoneID.ValueString()),
		)
		return
	}
	if snap == nil {
		resp.Diagnostics.AddWarning(
			"Time zone restore skipped: no snapshot",
			"restore_on_destroy is set, but no pre-existing time zone snapshot was captured "+
				"(the resource may predate snapshotting or the snapshot was lost). Leaving the host untouched.",
		)
		return
	}

	if _, err := r.tz.Set(ctx, winclient.TimezoneInput{
		TimezoneID:             snap.TimezoneID,
		DaylightSavingDisabled: snap.DaylightSavingDisabled,
	}); err != nil {
		addTimezoneDiag(&resp.Diagnostics, "Error restoring windows_timezone", err)
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// tzTimeoutsOpts declares which per-operation timeouts the resource exposes.
// The schema derives from it; keep the values together with the handlers,
// since a null timeouts value whose attribute types disagree with the schema
// is rejected by the framework as a provider type error.
var tzTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// tzNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func tzNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if tzTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if tzTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if tzTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if tzTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// timezoneIDsEqual compares a live zone ID with the desired one
// case-insensitively, tolerating the host reporting the DST-disabled
// "<id>_dstoff" spelling (Windows IDs are case-insensitive).
func timezoneIDsEqual(live, desired string) bool {
	strip := func(id string) string {
		if len(id) > 7 && strings.EqualFold(id[len(id)-7:], "_dstoff") {
			return id[:len(id)-7]
		}
		return id
	}
	return strings.EqualFold(strip(live), desired)
}

// modelFromTimezoneState projects an observed TimezoneState into a
// Terraform model, preserving the desired-input fields (timezone_id,
// daylight_saving_disabled) from the prior plan/state when present and the
// user-configured per-operation timeouts and restore intent across the
// projection (Set overwrites the full state object).
func modelFromTimezoneState(state *winclient.TimezoneState, prior windowsTimezoneModel) windowsTimezoneModel {
	// Managed attributes always reflect the live host state so out-of-band
	// drift surfaces on refresh (unlike ForceNew identity attributes, the
	// zone is enforced in place). Import works the same way: there is no
	// prior plan, so the live zone is adopted.
	timezoneID := types.StringValue(state.TimezoneID)
	daylight := types.BoolValue(state.DaylightSavingDisabled)
	restore := prior.RestoreOnDestroy
	if restore.IsNull() || restore.IsUnknown() {
		restore = types.BoolValue(false)
	}
	return windowsTimezoneModel{
		ID:                     types.StringValue(state.MachineID),
		TimezoneID:             timezoneID,
		DaylightSavingDisabled: daylight,
		DisplayName:            types.StringValue(state.DisplayName),
		BaseUTCOffset:          types.StringValue(state.BaseUTCOffset),
		SupportsDST:            types.BoolValue(state.SupportsDaylightSavingTime),
		CurrentUTCOffset:       types.StringValue(state.CurrentUTCOffset),
		TzautoupdateEnabled:    types.BoolValue(state.TzautoupdateEnabled),
		RestoreOnDestroy:       restore,
		// Preserve the user-configured per-operation timeouts across the
		// projection (Set overwrites the full state object).
		Timeouts: prior.Timeouts,
	}
}

// maybeWarnTzautoupdate emits a TPF warning when the tzautoupdate service may
// change the host time zone automatically: Windows can then move the zone
// out from under Terraform between applies.
func maybeWarnTzautoupdate(diags *diag.Diagnostics, m windowsTimezoneModel) {
	if !m.TzautoupdateEnabled.ValueBool() {
		return
	}
	diags.AddWarning(
		"Automatic time zone updates are enabled",
		"The tzautoupdate service on the target host may change the system time zone automatically. "+
			"Windows can move the zone out from under Terraform; consider disabling automatic updates "+
			"or expect recurring drift on this resource.",
	)
}

// addTimezoneDiag converts a *winclient.TimezoneError into a TPF diagnostic,
// enriching it with context fields when available.
func addTimezoneDiag(diags *diag.Diagnostics, summary string, err error) {
	var te *winclient.TimezoneError
	if errors.As(err, &te) {
		detail := te.Message
		if len(te.Context) > 0 {
			var parts []string
			for k, v := range te.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if te.Cause != nil {
			detail += "\n\nCause: " + te.Cause.Error()
		}
		if te.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", te.Kind)
		}
		diags.AddError(summary+" ["+string(te.Kind)+"]", detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// -----------------------------------------------------------------------------
// Helper: private-state snapshot
// -----------------------------------------------------------------------------

// setTimezoneSnapshot stores the pre-existing time zone state as JSON in
// private state so Delete with restore_on_destroy can re-apply it. setKey is
// a closure over the response Private data (kept injectable so unit tests can
// capture the snapshot without framework internals).
func setTimezoneSnapshot(ctx context.Context, setKey func(context.Context, string, []byte) diag.Diagnostics, st *winclient.TimezoneState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	diags := setKey(ctx, timezonePrivateKey, raw)
	if diags.HasError() {
		return errors.New(diagsToString(diags))
	}
	return nil
}

// getTimezoneSnapshot reads the snapshot back. A nil snapshot with a true
// return means "no snapshot captured". getKey is a closure over the request
// Private data.
func getTimezoneSnapshot(ctx context.Context, getKey func(context.Context, string) ([]byte, diag.Diagnostics)) (*winclient.TimezoneState, bool) {
	raw, diags := getKey(ctx, timezonePrivateKey)
	if diags.HasError() {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, true
	}
	var st winclient.TimezoneState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, false
	}
	return &st, true
}
