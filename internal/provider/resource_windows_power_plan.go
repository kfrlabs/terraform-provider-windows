// Package provider: windows_power_plan resource implementation.
//
// This file contains the TPF schema, model, custom validators and full
// CRUD + ImportState handlers for the windows_power_plan resource. All SSH
// interaction is delegated to winclient.PowerPlanClient
// (internal/winclient).
//
// The active power plan is a singleton: the host always has exactly one,
// so Create and Update share one idempotent Apply operation (resolve the
// plan to a GUID, write the configured AC/DC values with powercfg
// /setacvalueindex|/setdcvalueindex, activate with powercfg /setactive,
// verify by re-reading), Read refreshes from the live host and never
// removes the resource from state, and Delete makes no remote change
// unless restore_on_destroy re-applies the pre-existing values captured
// into private state at Create (or import) time.
//
// Spec alignment: windows_power_plan spec (issue #288).
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
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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
	_ resource.Resource                     = (*windowsPowerPlanResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsPowerPlanResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsPowerPlanResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsPowerPlanResource)(nil)
)

// NewWindowsPowerPlanResource is the constructor registered in provider.go.
func NewWindowsPowerPlanResource() resource.Resource { return &windowsPowerPlanResource{} }

// windowsPowerPlanResource is the TPF resource type for windows_power_plan.
type windowsPowerPlanResource struct {
	pp winclient.WindowsPowerPlanClient
}

// powerPlanDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Power plan reads and writes
// are normally fast, but a stalled PowerShell/SSH session must never block
// Terraform forever: every CRUD handler bounds its work with this default.
const powerPlanDefaultTimeout = 5 * time.Minute

// powerPlanPrivateKey is the private-state key holding the JSON-encoded
// pre-existing power plan state captured at Create (or import) time, plus
// the GUID of a plan duplicated via create_if_missing. Delete with
// restore_on_destroy re-applies the pre-existing values; the owned
// duplicated plan is deleted whenever it is inactive.
const powerPlanPrivateKey = "original_state"

// windowsPowerPlanSettingModel is one element of the settings list. Field
// tags match the nested attribute names declared in the schema below.
type windowsPowerPlanSettingModel struct {
	Subgroup types.String `tfsdk:"subgroup"`
	Setting  types.String `tfsdk:"setting"`
	ACValue  types.Int64  `tfsdk:"ac_value"`
	DCValue  types.Int64  `tfsdk:"dc_value"`
}

// windowsPowerPlanModel is the Terraform state/plan model for the
// windows_power_plan resource. Field tags match the snake_case attribute
// names declared in the schema below.
//
// ID is anchored on MachineID (HKLM MachineGuid): it survives plan
// changes and is refreshed from the live host on every Read.
type windowsPowerPlanModel struct {
	ID               types.String   `tfsdk:"id"`
	Plan             types.String   `tfsdk:"plan"`
	Settings         types.List     `tfsdk:"settings"`
	CreateIfMissing  types.Bool     `tfsdk:"create_if_missing"`
	RestoreOnDestroy types.Bool     `tfsdk:"restore_on_destroy"`
	PlanGUID         types.String   `tfsdk:"plan_guid"`
	PlanName         types.String   `tfsdk:"plan_name"`
	Timeouts         timeouts.Value `tfsdk:"timeouts"`
}

// powerPlanSettingElementAttrTypes returns the attribute types of one
// settings list element.
func powerPlanSettingElementAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"subgroup": types.StringType,
		"setting":  types.StringType,
		"ac_value": types.Int64Type,
		"dc_value": types.Int64Type,
	}
}

// powerPlanSettingElementObjectType returns the object type of one
// settings list element.
func powerPlanSettingElementObjectType() attr.Type {
	return types.ObjectType{AttrTypes: powerPlanSettingElementAttrTypes()}
}

// powerPlanReferenceValidator accepts a plan GUID (any case) or one of the
// known aliases (balanced, high_performance, power_saver,
// ultimate_performance, case-insensitive). Plan names are never accepted:
// ElementName is localised.
type powerPlanReferenceValidator struct{}

// Description returns a human-readable description for plan output.
func (powerPlanReferenceValidator) Description(_ context.Context) string {
	return "must be a power plan GUID or alias (balanced, high_performance, power_saver, ultimate_performance)"
}

// MarkdownDescription returns the Markdown variant of Description.
func (v powerPlanReferenceValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString rejects values that are neither a GUID nor a known alias.
// Null and unknown values are skipped.
func (powerPlanReferenceValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := winclient.ResolvePowerPlanReference(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid power plan",
			fmt.Sprintf("plan %q is not a GUID or known alias: must be a GUID or one of balanced, high_performance, power_saver, ultimate_performance (plan names are localised and never accepted).",
				req.ConfigValue.ValueString()),
		)
	}
}

// powerPlanCanonicalModifier normalises the plan reference to its canonical
// lower-case GUID at plan time (aliases resolve via the static table).
// Without it a configured alias would plan a perpetual diff against the
// observed GUID.
type powerPlanCanonicalModifier struct{}

// Description returns a human-readable description for plan output.
func (powerPlanCanonicalModifier) Description(_ context.Context) string {
	return "Normalises the power plan reference to its canonical GUID."
}

// MarkdownDescription returns the Markdown variant of Description.
func (m powerPlanCanonicalModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

// PlanModifyString resolves a known, non-null alias or GUID to its
// canonical lower-case GUID. Unresolvable values pass through unchanged
// so the validator reports them.
func (powerPlanCanonicalModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	guid, err := winclient.ResolvePowerPlanReference(req.PlanValue.ValueString())
	if err != nil {
		resp.PlanValue = req.PlanValue
		return
	}
	resp.PlanValue = types.StringValue(guid)
}

// Metadata sets the resource type name ("windows_power_plan").
func (r *windowsPowerPlanResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_power_plan"
}

// Schema returns the complete TPF schema.
func (r *windowsPowerPlanResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsPowerPlanSchemaDefinition(ctx)
}

// windowsPowerPlanSchemaDefinition returns the resource schema. Extracted
// into a function so it can be unit-tested independently of the resource
// type.
func windowsPowerPlanSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the active power plan of a remote Windows machine over SSH/PowerShell.\n\n" +
			"The active plan is a **singleton**: the host always has exactly one, so creating this resource never " +
			"provisions anything new — it only writes the configured AC/DC setting values in place " +
			"(`powercfg /setacvalueindex` / `/setdcvalueindex`) and activates the plan (`powercfg /setactive`), and deleting it makes no remote change unless " +
			"`restore_on_destroy` is set.\n\n" +
			"`plan` takes a GUID or an alias (`balanced`, `high_performance`, `power_saver`, `ultimate_performance`), normalised to the " +
			"canonical GUID at plan time. Plan names are never accepted: `ElementName` is localised. When the desired plan is absent from the host " +
			"(e.g. `ultimate_performance`), `create_if_missing` duplicates the well-known template (`powercfg /duplicatescheme`); custom plan GUIDs have no template " +
			"source and still fail with `plan_not_found`. Otherwise a missing plan is an error. " +
			"Only the listed `settings` are managed. Identity is GUID-only everywhere: `powercfg /query` text is never parsed.\n\n" +
			"**Destroy is a no-op by default:** a Windows machine cannot exist without an active plan; `terraform destroy` only removes " +
			"the resource from state unless `restore_on_destroy` re-applies the pre-existing plan and values. A plan duplicated by " +
			"`create_if_missing` is deleted on destroy whenever it is inactive (`powercfg /delete`).\n\n" +
			"Import format: any non-empty ID (its value is ignored; the live active plan is adopted, e.g. `current`).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform resource ID. Equal to the host MachineGuid (HKLM Cryptography MachineGuid). Stable across power plan changes.",
				MarkdownDescription: "Terraform resource ID. Equal to the host `MachineGuid` (`HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`). Stable across power plan changes.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"plan": schema.StringAttribute{
				Required:            true,
				Description:         "Desired active power plan: a GUID or an alias (balanced, high_performance, power_saver, ultimate_performance). Normalised to the canonical GUID at plan time. Plan names are localised and never accepted.",
				MarkdownDescription: "Desired active power plan: a GUID or an alias (`balanced`, `high_performance`, `power_saver`, `ultimate_performance`). Normalised to the canonical GUID at plan time. Plan names are localised and never accepted.",
				Validators: []validator.String{
					powerPlanReferenceValidator{},
				},
				PlanModifiers: []planmodifier.String{
					powerPlanCanonicalModifier{},
				},
			},
			"settings": schema.ListNestedAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Power setting overrides applied to the selected plan, in order. Only listed settings are managed; every other setting is left untouched.",
				MarkdownDescription: "Power setting overrides applied to the selected plan, in order. Only listed settings are managed; every other setting is left untouched.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"subgroup": schema.StringAttribute{
							Required:            true,
							Description:         "Setting subgroup: a GUID or powercfg alias (SUB_SLEEP, SUB_DISK, SUB_PROCESSOR, SUB_VIDEO, SUB_BUTTONS, ...). Resolved on the host via powercfg /aliases.",
							MarkdownDescription: "Setting subgroup: a GUID or `powercfg` alias (`SUB_SLEEP`, `SUB_DISK`, `SUB_PROCESSOR`, `SUB_VIDEO`, `SUB_BUTTONS`, ...). Resolved on the host via `powercfg /aliases`.",
						},
						"setting": schema.StringAttribute{
							Required:            true,
							Description:         "Setting: a GUID or powercfg alias (STANDBYIDLE, HIBERNATEIDLE, DISKIDLE, VIDEOIDLE, PROCTHROTTLEMIN, ...). Resolved on the host via powercfg /aliases.",
							MarkdownDescription: "Setting: a GUID or `powercfg` alias (`STANDBYIDLE`, `HIBERNATEIDLE`, `DISKIDLE`, `VIDEOIDLE`, `PROCTHROTTLEMIN`, ...). Resolved on the host via `powercfg /aliases`.",
						},
						"ac_value": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							Description:         "Setting value when on AC power (setting index, >= 0). At least one of ac_value or dc_value is required per setting. DC values are stored even on hosts without a battery.",
							MarkdownDescription: "Setting value when on AC power (setting index, `>= 0`). At least one of `ac_value` or `dc_value` is required per setting. DC values are stored even on hosts without a battery.",
							Validators: []validator.Int64{
								int64validator.AtLeast(0),
							},
						},
						"dc_value": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							Description:         "Setting value when on DC (battery) power (setting index, >= 0). At least one of ac_value or dc_value is required per setting. Stored even on hosts without a battery.",
							MarkdownDescription: "Setting value when on DC (battery) power (setting index, `>= 0`). At least one of `ac_value` or `dc_value` is required per setting. Stored even on hosts without a battery.",
							Validators: []validator.Int64{
								int64validator.AtLeast(0),
							},
						},
					},
				},
			},
			"create_if_missing": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "When true, duplicate the plan template on the host (powercfg /duplicatescheme) when the desired plan is absent. Only well-known template GUIDs (balanced, high_performance, power_saver, ultimate_performance aliases) can be duplicated; arbitrary custom plan GUIDs have no template source and still fail with plan_not_found. Defaults to false: a missing plan is an error. The duplicated plan is deleted on destroy whenever it is inactive.",
				MarkdownDescription: "When `true`, duplicate the plan template on the host (`powercfg /duplicatescheme`) when the desired plan is absent. Only well-known template GUIDs (`balanced`, `high_performance`, `power_saver`, `ultimate_performance` aliases) can be duplicated; arbitrary custom plan GUIDs have no template source and still fail with `plan_not_found`. Defaults to `false`: a missing plan is an error. The duplicated plan is deleted on destroy whenever it is inactive.",
			},
			"restore_on_destroy": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "When true, destroy re-activates the plan that was active at creation (or import) time and restores the captured setting values. Defaults to false: destroy makes no remote change.",
				MarkdownDescription: "When `true`, destroy re-activates the plan that was active at creation (or import) time and restores the captured setting values. Defaults to `false`: destroy makes no remote change.",
			},
			"plan_guid": schema.StringAttribute{
				Computed:            true,
				Description:         "Resolved GUID of the active power plan as observed on the host.",
				MarkdownDescription: "Resolved GUID of the active power plan as observed on the host.",
			},
			"plan_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Localised display name (ElementName) of the active power plan as observed on the host. Informational only: never used for identity or drift.",
				MarkdownDescription: "Localised display name (`ElementName`) of the active power plan as observed on the host. Informational only: never used for identity or drift.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// powerPlanDefaultTimeout so a stalled PowerShell/SSH session
			// surfaces a timeout diagnostic instead of blocking Terraform
			// indefinitely.
			"timeouts": timeouts.Attributes(ctx, powerPlanTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// ConfigValidators returns the resource-level cross-field validator:
// every settings element needs at least one of ac_value / dc_value.
func (r *windowsPowerPlanResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		windowsPowerPlanConfigValidator{},
	}
}

// windowsPowerPlanConfigValidator enforces the per-setting ac/dc matrix at
// plan time (at least one value required, both optional individually so a
// single-source override is possible).
type windowsPowerPlanConfigValidator struct{}

func (v windowsPowerPlanConfigValidator) Description(_ context.Context) string {
	return "Requires at least one of ac_value or dc_value per power setting."
}

func (v windowsPowerPlanConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v windowsPowerPlanConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var settings types.List
	diags := req.Config.GetAttribute(ctx, path.Root("settings"), &settings)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if settings.IsNull() || settings.IsUnknown() {
		return
	}
	var elems []windowsPowerPlanSettingModel
	diags = settings.ElementsAs(ctx, &elems, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	for i, e := range elems {
		if e.ACValue.IsUnknown() || e.DCValue.IsUnknown() {
			continue
		}
		if e.ACValue.IsNull() && e.DCValue.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("settings").AtListIndex(i),
				"Missing power setting value",
				"Each power setting requires at least one of ac_value or dc_value.",
			)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates a
// PowerPlanClient for this resource instance.
func (r *windowsPowerPlanResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.pp = winclient.NewPowerPlanClient(client)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create activates the desired power plan in place (idempotent when
// already active with the same values) and saves the full state. When
// restore_on_destroy is set, the pre-existing values are captured into
// private state first so Delete can re-apply them. A plan duplicated via
// create_if_missing is recorded in private state so Delete can remove it
// when inactive.
func (r *windowsPowerPlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsPowerPlanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, powerPlanDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	if plan.RestoreOnDestroy.ValueBool() {
		pre, err := r.pp.Read(ctx, powerPlanKeysFromModel(ctx, &resp.Diagnostics, plan))
		if err != nil {
			addPowerPlanDiag(&resp.Diagnostics, "Error reading pre-existing Windows power plan state", err)
			return
		}
		if resp.Diagnostics.HasError() {
			return
		}
		if err := setPowerPlanSnapshot(ctx, resp.Private.SetKey, &winclient.PowerPlanSnapshot{
			PlanGUID: pre.PlanGUID,
			Settings: pre.Settings,
		}); err != nil {
			addPowerPlanDiag(&resp.Diagnostics, "Error capturing pre-existing Windows power plan state", err)
			return
		}
	}

	in, diags := powerPlanModelToInput(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Windows power plan (activating in place)", map[string]any{
		"plan": in.Plan,
	})

	state, err := r.pp.Apply(ctx, in)
	if err != nil {
		addPowerPlanDiag(&resp.Diagnostics, "Error creating Windows power plan", err)
		return
	}

	// Remember a duplicated plan so Delete can remove it when inactive,
	// even when restore_on_destroy is false.
	if state.DuplicatedPlanGUID != "" {
		if err := updatePowerPlanOwnedPlan(ctx, r.pp, resp.Private.GetKey, resp.Private.SetKey, state.DuplicatedPlanGUID); err != nil {
			addPowerPlanDiag(&resp.Diagnostics, "Error recording duplicated Windows power plan", err)
			return
		}
	}

	m, diags := powerPlanStateToModel(state, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live active power plan. The plan
// always exists, so a read failure surfaces an error diagnostic instead
// of silently removing the resource from state. Drift (another plan
// active, or out-of-band value changes) surfaces through the observed
// plan / plan_guid / settings values.
func (r *windowsPowerPlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsPowerPlanModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, powerPlanDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "Reading Windows power plan", map[string]any{
		"plan": state.Plan.ValueString(),
	})

	live, err := r.pp.Read(ctx, powerPlanKeysFromModel(ctx, &resp.Diagnostics, state))
	if err != nil {
		addPowerPlanDiag(&resp.Diagnostics, "Error reading Windows power plan", err)
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	m, diags := powerPlanStateToModel(live, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place power plan changes. Like Create it funnels into
// Apply; the restore snapshot captured at Create time is preserved
// (restore always returns to the pre-existing values, not to the previous
// plan). When the plan adds setting keys absent from the snapshot, their
// pre-Update values are read and merged so a later restore_on_destroy
// still returns them to the pre-existing values.
func (r *windowsPowerPlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsPowerPlanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsPowerPlanModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, powerPlanDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// Extend the restore snapshot with pre-Update values for setting keys
	// the snapshot does not yet cover (e.g. settings added after Create).
	// Best-effort: a failed pre-read warns and the Update still proceeds
	// with the existing snapshot.
	extendPowerPlanSnapshot(ctx, r.pp, req.Private.GetKey, resp.Private.SetKey, &resp.Diagnostics, plan)

	in, diags := powerPlanModelToInput(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating Windows power plan", map[string]any{
		"plan": in.Plan,
	})

	live, err := r.pp.Apply(ctx, in)
	if err != nil {
		addPowerPlanDiag(&resp.Diagnostics, "Error updating Windows power plan", err)
		return
	}

	if live.DuplicatedPlanGUID != "" {
		if err := updatePowerPlanOwnedPlan(ctx, r.pp, resp.Private.GetKey, resp.Private.SetKey, live.DuplicatedPlanGUID); err != nil {
			addPowerPlanDiag(&resp.Diagnostics, "Error recording duplicated Windows power plan", err)
			return
		}
	}

	m, diags := powerPlanStateToModel(live, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the resource from state. By default it makes no remote
// change (the host always has an active plan). With restore_on_destroy it
// re-activates the snapshot plan and values captured at Create (or
// import) time. A plan duplicated via create_if_missing is deleted
// whenever it is inactive; an active owned plan is left in place with a
// warning.
func (r *windowsPowerPlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsPowerPlanModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, powerPlanDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	tflog.Debug(ctx, "Deleting Windows power plan", map[string]any{
		"plan":               state.Plan.ValueString(),
		"restore_on_destroy": state.RestoreOnDestroy.ValueBool(),
	})

	snap, ok := getPowerPlanSnapshot(ctx, req.Private.GetKey)
	if state.RestoreOnDestroy.ValueBool() {
		if !ok || snap == nil || snap.PlanGUID == "" {
			resp.Diagnostics.AddWarning(
				"Power plan restore skipped: no snapshot",
				"restore_on_destroy is set, but the pre-existing snapshot of the power plan could not be read "+
					"(it may be corrupt, from an incompatible version, or was never captured). Leaving the host untouched.",
			)
		} else if _, err := r.pp.Restore(ctx, *snap); err != nil {
			addPowerPlanDiag(&resp.Diagnostics, "Error restoring Windows power plan", err)
			// Continue to owned-plan cleanup below so a failed restore
			// does not leak a duplicated plan; both diagnostics are
			// collected.
		}
	}

	// Clean up a duplicated plan owned by this resource. It is only
	// ever deleted when inactive: deleting the active plan would fail
	// and would leave the host without an active plan. A missing owned
	// plan is success (idempotent).
	owned := ""
	if ok && snap != nil {
		owned = snap.OwnedPlanGUID
	}
	if owned == "" {
		return
	}
	live, err := r.pp.Read(ctx, nil)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Duplicated power plan cleanup skipped: read failed",
			fmt.Sprintf("Could not verify whether the duplicated plan (%s) is inactive before deleting it: %v. Leaving it in place and removing the resource from state.", owned, err),
		)
		return
	}
	if strings.EqualFold(live.PlanGUID, owned) {
		resp.Diagnostics.AddWarning(
			"Duplicated power plan left in place",
			fmt.Sprintf("The plan duplicated by create_if_missing (%s) is the active plan: it cannot be deleted while active. Leaving it in place.", owned),
		)
		return
	}
	if err := r.pp.DeletePlan(ctx, owned); err != nil {
		if winclient.IsPowerPlanError(err, winclient.PowerPlanErrorPlanNotFound) {
			return
		}
		addPowerPlanDiag(&resp.Diagnostics, "Error deleting duplicated Windows power plan", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts the live active power plan: any non-empty import ID
// is accepted and ignored (the plan is a singleton), the observed plan
// becomes the snapshot for a later restore_on_destroy. No settings are
// captured (there is no configuration to select keys from), so a restore
// after an import-only lifecycle re-activates the snapshot plan but does
// not restore setting values; declare settings and apply once to capture
// a full snapshot.
func (r *windowsPowerPlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if strings.TrimSpace(req.ID) == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			"Import requires a non-empty ID (its value is ignored; the live active power plan is adopted). For example: terraform import windows_power_plan.this current",
		)
		return
	}

	tflog.Debug(ctx, "Importing Windows power plan (singleton: live active plan is adopted)")

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, powerPlanDefaultTimeout)
	defer cancel()

	live, err := r.pp.Read(ctx, nil)
	if err != nil {
		addPowerPlanDiag(&resp.Diagnostics, "Error importing Windows power plan", err)
		return
	}

	if err := setPowerPlanSnapshot(ctx, resp.Private.SetKey, &winclient.PowerPlanSnapshot{
		PlanGUID: live.PlanGUID,
		Settings: live.Settings,
	}); err != nil {
		addPowerPlanDiag(&resp.Diagnostics, "Error capturing pre-existing Windows power plan state", err)
		return
	}

	m, diags := powerPlanStateToModel(live, windowsPowerPlanModel{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by the framework on State.Set — use a typed
	// null instead (the subsequent Read fills in the configured values).
	m.Timeouts = powerPlanNullTimeouts()
	m.CreateIfMissing = types.BoolValue(false)
	m.RestoreOnDestroy = types.BoolValue(false)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------------------------------------------------------------------------
// Helper: modelToInput
// ---------------------------------------------------------------------------

// powerPlanKeysFromModel extracts the managed setting references from a
// model so Read can refresh exactly those values. Unknown settings lists
// (first plan with Optional+Computed) yield no keys; the post-apply Read
// fills the state.
func powerPlanKeysFromModel(ctx context.Context, diags *diag.Diagnostics, m windowsPowerPlanModel) []winclient.PowerPlanSettingKey {
	if m.Settings.IsNull() || m.Settings.IsUnknown() {
		return nil
	}
	var elems []windowsPowerPlanSettingModel
	ds := diag.Diagnostics{}
	ds.Append(m.Settings.ElementsAs(ctx, &elems, false)...)
	diags.Append(ds...)
	if ds.HasError() {
		return nil
	}
	keys := make([]winclient.PowerPlanSettingKey, 0, len(elems))
	for _, e := range elems {
		if e.Subgroup.IsNull() || e.Subgroup.IsUnknown() || e.Setting.IsNull() || e.Setting.IsUnknown() {
			continue
		}
		keys = append(keys, winclient.PowerPlanSettingKey{
			Subgroup: e.Subgroup.ValueString(),
			Setting:  e.Setting.ValueString(),
		})
	}
	return keys
}

// powerPlanModelToInput converts a Terraform plan to a PowerPlanInput
// delta: null or unknown attributes stay unmanaged and are never written.
// Unknowns arise on first plan for Optional+Computed attributes; the
// post-apply Read fills the state.
func powerPlanModelToInput(ctx context.Context, m windowsPowerPlanModel) (winclient.PowerPlanInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	in := winclient.PowerPlanInput{
		Plan:            m.Plan.ValueString(),
		CreateIfMissing: m.CreateIfMissing.ValueBool(),
	}
	if m.Settings.IsNull() || m.Settings.IsUnknown() {
		return in, diags
	}
	var elems []windowsPowerPlanSettingModel
	diags.Append(m.Settings.ElementsAs(ctx, &elems, false)...)
	if diags.HasError() {
		return in, diags
	}
	for _, e := range elems {
		s := winclient.PowerPlanSettingInput{
			Subgroup: e.Subgroup.ValueString(),
			Setting:  e.Setting.ValueString(),
		}
		if !e.ACValue.IsNull() && !e.ACValue.IsUnknown() {
			v := e.ACValue.ValueInt64()
			s.ACValue = &v
		}
		if !e.DCValue.IsNull() && !e.DCValue.IsUnknown() {
			v := e.DCValue.ValueInt64()
			s.DCValue = &v
		}
		in.Settings = append(in.Settings, s)
	}
	return in, diags
}

// ---------------------------------------------------------------------------
// Helper: stateToModel
// ---------------------------------------------------------------------------

// powerPlanTimeoutsOpts declares which per-operation timeouts the resource
// exposes.
var powerPlanTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// powerPlanNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func powerPlanNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if powerPlanTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if powerPlanTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if powerPlanTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if powerPlanTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// powerPlanSettingsToListValue projects observed settings onto a Terraform
// list value (empty list, never null, when no settings are managed), in
// the order returned by the client (input order on apply).
func powerPlanSettingsToListValue(settings []winclient.PowerPlanSettingState) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := powerPlanSettingElementObjectType()
	if len(settings) == 0 {
		lv, d := types.ListValue(elemType, []attr.Value{})
		diags.Append(d...)
		return lv, diags
	}
	vals := make([]attr.Value, 0, len(settings))
	for _, s := range settings {
		var ac, dc attr.Value = types.Int64Null(), types.Int64Null()
		if s.ACValue != nil {
			ac = types.Int64Value(*s.ACValue)
		}
		if s.DCValue != nil {
			dc = types.Int64Value(*s.DCValue)
		}
		obj, d := types.ObjectValue(powerPlanSettingElementAttrTypes(), map[string]attr.Value{
			"subgroup": types.StringValue(s.SubgroupGUID),
			"setting":  types.StringValue(s.SettingGUID),
			"ac_value": ac,
			"dc_value": dc,
		})
		diags.Append(d...)
		vals = append(vals, obj)
	}
	lv, d := types.ListValue(elemType, vals)
	diags.Append(d...)
	return lv, diags
}

// powerPlanStateToModel projects an observed PowerPlanState into a
// Terraform model. The managed plan attribute always reflects the observed
// active plan (canonical GUID) so an out-of-band switch surfaces as drift;
// plan_guid mirrors it for consumers, plan_name is informational. The
// input-only intent (create_if_missing, restore_on_destroy), the
// user-configured timeouts and the resource ID anchor are preserved from
// the prior plan/state across the projection (Set overwrites the full
// state object).
//
// Settings refs are preserved from the prior model when the counts match:
// the host always reports canonical GUIDs while configuration may use
// powercfg aliases (SUB_DISK, DISKIDLE, ...), so projecting observed GUIDs
// would plan a perpetual diff against configured aliases. Only the AC/DC
// values are taken from the observed state; when the counts differ (added
// or removed settings, or no prior refs such as import) the observed GUIDs
// are used.
func powerPlanStateToModel(state *winclient.PowerPlanState, prior windowsPowerPlanModel) (windowsPowerPlanModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	settings := state.Settings
	if len(settings) > 0 {
		if elems, ok := powerPlanPriorSettingRefs(prior); ok && len(elems) == len(settings) {
			merged := make([]winclient.PowerPlanSettingState, 0, len(settings))
			for i, s := range settings {
				merged = append(merged, winclient.PowerPlanSettingState{
					SubgroupGUID: elems[i].Subgroup,
					SettingGUID:  elems[i].Setting,
					ACValue:      s.ACValue,
					DCValue:      s.DCValue,
				})
			}
			settings = merged
		}
	}
	settingsList, d := powerPlanSettingsToListValue(settings)
	diags.Append(d...)
	if diags.HasError() {
		return windowsPowerPlanModel{}, diags
	}
	id := types.StringValue(state.MachineID)
	if state.MachineID == "" {
		// The host must always report a MachineGuid. If it ever goes
		// missing mid-life, keep the anchored ID rather than writing an
		// empty one Terraform forbids; with no prior ID (Create with an
		// unreadable MachineGuid) fall back to the singleton literal,
		// mirroring the windows_ntp data source.
		if !prior.ID.IsNull() && !prior.ID.IsUnknown() && prior.ID.ValueString() != "" {
			id = prior.ID
		} else {
			id = types.StringValue("current")
		}
	}
	create := prior.CreateIfMissing
	if create.IsNull() || create.IsUnknown() {
		create = types.BoolValue(false)
	}
	restore := prior.RestoreOnDestroy
	if restore.IsNull() || restore.IsUnknown() {
		restore = types.BoolValue(false)
	}
	return windowsPowerPlanModel{
		ID:               id,
		Plan:             types.StringValue(state.PlanGUID),
		Settings:         settingsList,
		CreateIfMissing:  create,
		RestoreOnDestroy: restore,
		PlanGUID:         types.StringValue(state.PlanGUID),
		PlanName:         types.StringValue(state.PlanName),
		Timeouts:         prior.Timeouts,
	}, diags
}

// powerPlanPriorSettingRefs extracts the configured subgroup/setting refs
// from a prior model. It reports false when there is nothing to preserve
// (null, unknown, or undecodable settings), in which case the caller falls
// back to the observed canonical GUIDs.
func powerPlanPriorSettingRefs(prior windowsPowerPlanModel) ([]powerPlanSettingRef, bool) {
	if prior.Settings.IsNull() || prior.Settings.IsUnknown() {
		return nil, false
	}
	ctx := context.Background()
	var elems []windowsPowerPlanSettingModel
	if diags := prior.Settings.ElementsAs(ctx, &elems, false); diags.HasError() {
		return nil, false
	}
	refs := make([]powerPlanSettingRef, 0, len(elems))
	for _, e := range elems {
		if e.Subgroup.IsNull() || e.Subgroup.IsUnknown() || e.Setting.IsNull() || e.Setting.IsUnknown() {
			return nil, false
		}
		refs = append(refs, powerPlanSettingRef{Subgroup: e.Subgroup.ValueString(), Setting: e.Setting.ValueString()})
	}
	return refs, true
}

// powerPlanSettingRef is a configured subgroup/setting reference pair,
// preserved verbatim (alias or GUID) to avoid perpetual diffs against the
// host-reported canonical GUIDs.
type powerPlanSettingRef struct {
	Subgroup string
	Setting  string
}

// ---------------------------------------------------------------------------
// Helper: private-state snapshot
// ---------------------------------------------------------------------------

// setPowerPlanSnapshot stores the pre-existing power plan state as JSON in
// private state so Delete with restore_on_destroy can re-apply it and so
// Delete can clean up a duplicated plan. setKey is a closure over the
// response Private data (kept injectable so unit tests can capture the
// snapshot without framework internals).
func setPowerPlanSnapshot(ctx context.Context, setKey func(context.Context, string, []byte) diag.Diagnostics, st *winclient.PowerPlanSnapshot) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	diags := setKey(ctx, powerPlanPrivateKey, raw)
	if diags.HasError() {
		return errors.New(diagsToString(diags))
	}
	return nil
}

// getPowerPlanSnapshot reads the snapshot back. A nil snapshot with a true
// return means "no snapshot captured". getKey is a closure over the request
// Private data.
func getPowerPlanSnapshot(ctx context.Context, getKey func(context.Context, string) ([]byte, diag.Diagnostics)) (*winclient.PowerPlanSnapshot, bool) {
	raw, diags := getKey(ctx, powerPlanPrivateKey)
	if diags.HasError() {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, true
	}
	var st winclient.PowerPlanSnapshot
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, false
	}
	return &st, true
}

// updatePowerPlanOwnedPlan records the GUID of a plan duplicated via
// create_if_missing in the existing private-state snapshot (preserving the
// captured pre-existing values) so Delete can remove it when inactive.
// When a previous owned GUID differs from the new one, the stale plan is
// deleted first whenever it is inactive, so a re-duplication never leaks
// the previous duplicate. A missing stale plan is success; a stale plan
// that is still active, or whose state cannot be verified, is left in
// place and overwritten.
func updatePowerPlanOwnedPlan(ctx context.Context, client winclient.WindowsPowerPlanClient, getKey func(context.Context, string) ([]byte, diag.Diagnostics), setKey func(context.Context, string, []byte) diag.Diagnostics, owned string) error {
	snap, ok := getPowerPlanSnapshot(ctx, getKey)
	if !ok {
		return errors.New("cannot record duplicated power plan: existing snapshot is unreadable")
	}
	if snap == nil {
		snap = &winclient.PowerPlanSnapshot{}
	}
	if old := strings.TrimSpace(snap.OwnedPlanGUID); old != "" && !strings.EqualFold(old, owned) && client != nil {
		if live, err := client.Read(ctx, nil); err == nil && !strings.EqualFold(strings.TrimSpace(live.PlanGUID), old) {
			if err := client.DeletePlan(ctx, old); err != nil && !winclient.IsPowerPlanError(err, winclient.PowerPlanErrorPlanNotFound) {
				return fmt.Errorf("cannot clean up previous duplicated power plan %q: %w", old, err)
			}
		}
	}
	snap.OwnedPlanGUID = owned
	return setPowerPlanSnapshot(ctx, setKey, snap)
}

// extendPowerPlanSnapshot merges pre-Update setting values for keys absent
// from the restore snapshot. Create captures the configured keys; Update
// may introduce new ones, and without this merge a later
// restore_on_destroy would leave those settings at their updated values.
// Best-effort: failures warn and the Update proceeds with the existing
// snapshot. The merged (or copied) snapshot is always written to setKey so
// a later owned-plan update preserves it.
func extendPowerPlanSnapshot(ctx context.Context, client winclient.WindowsPowerPlanClient, getKey func(context.Context, string) ([]byte, diag.Diagnostics), setKey func(context.Context, string, []byte) diag.Diagnostics, diags *diag.Diagnostics, plan windowsPowerPlanModel) {
	snap, ok := getPowerPlanSnapshot(ctx, getKey)
	if !ok || snap == nil || snap.PlanGUID == "" {
		return
	}
	keys := powerPlanKeysFromModel(ctx, diags, plan)
	if diags.HasError() || len(keys) == 0 {
		// Still copy the prior snapshot forward so a later owned-plan
		// update does not lose it.
		if err := setPowerPlanSnapshot(ctx, setKey, snap); err != nil {
			diags.AddWarning("Power plan snapshot not extended", fmt.Sprintf("Could not carry the restore snapshot forward: %v.", err))
		}
		return
	}
	known := make(map[string]struct{}, len(snap.Settings))
	for _, s := range snap.Settings {
		known[strings.ToLower(s.SettingGUID)] = struct{}{}
	}
	// Fast path: if every snapshot setting is already covered there is
	// still a copy-forward to do (owned-plan bookkeeping reads the
	// response store), so fall through to the write below when no merge
	// is needed.
	pre, err := client.Read(ctx, keys)
	if err != nil {
		diags.AddWarning(
			"Power plan snapshot not extended",
			fmt.Sprintf("Could not read pre-update values for new settings: %v. The restore snapshot keeps its existing keys.", err),
		)
		if serr := setPowerPlanSnapshot(ctx, setKey, snap); serr != nil {
			diags.AddWarning("Power plan snapshot not extended", fmt.Sprintf("Could not carry the restore snapshot forward: %v.", serr))
		}
		return
	}
	merged := snap
	for _, s := range pre.Settings {
		if _, covered := known[strings.ToLower(s.SettingGUID)]; !covered {
			merged.Settings = append(merged.Settings, s)
			known[strings.ToLower(s.SettingGUID)] = struct{}{}
		}
	}
	if err := setPowerPlanSnapshot(ctx, setKey, merged); err != nil {
		diags.AddWarning("Power plan snapshot not extended", fmt.Sprintf("Could not merge pre-update setting values: %v.", err))
	}
}

// ---------------------------------------------------------------------------
// Helper: addPowerPlanDiag
// ---------------------------------------------------------------------------

// addPowerPlanDiag appends a diagnostic from a power plan client error,
// enriching it with context fields when available.
func addPowerPlanDiag(d *diag.Diagnostics, summary string, err error) {
	var pe *winclient.PowerPlanError
	if errors.As(err, &pe) {
		detail := pe.Message
		if len(pe.Context) > 0 {
			var parts []string
			for k, v := range pe.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if pe.Cause != nil {
			detail += "\n\nCause: " + pe.Cause.Error()
		}
		d.AddError(summary+" ["+string(pe.Kind)+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
