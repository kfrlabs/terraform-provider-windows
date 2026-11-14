// Package provider: windows_scheduled_task resource implementation.
//
// Spec: windows_scheduled_task v1 (2026-04-27).
// Framework: terraform-plugin-framework v1.13.0.
// Client: winclient.ScheduledTaskClientImpl (ScheduledTasks PS module + COM).
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
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// stDefaultTimeout is the fallback per-operation timeout when the user does
// not provide a `timeouts {}` block. Scheduled-task CRUD over SSH is fast
// (PowerShell module Register-/Set-/Unregister-ScheduledTask), so 5 minutes
// is more than enough for nominal cases while still bounding pathological
// hangs (e.g. SSH degradation, slow DC for principals).
const stDefaultTimeout = 5 * time.Minute

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsScheduledTaskResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsScheduledTaskResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsScheduledTaskResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsScheduledTaskResource)(nil)
	_ resource.ResourceWithUpgradeState     = (*windowsScheduledTaskResource)(nil)
)

// NewWindowsScheduledTaskResource is the constructor registered in provider.go.
func NewWindowsScheduledTaskResource() resource.Resource { return &windowsScheduledTaskResource{} }

// windowsScheduledTaskResource is the TPF resource for windows_scheduled_task.
type windowsScheduledTaskResource struct {
	stClient winclient.ScheduledTaskClient
}

// Configure wires the winclient.Client and creates the ScheduledTaskClient.
func (r *windowsScheduledTaskResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData))
		return
	}
	r.stClient = winclient.NewScheduledTaskClient(c)
}

// ---------------------------------------------------------------------------
// CRUD — Create
// ---------------------------------------------------------------------------

// Create creates a new Windows Scheduled Task.
func (r *windowsScheduledTaskResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, dt := plan.Timeouts.Create(ctx, stDefaultTimeout)
	resp.Diagnostics.Append(dt...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_scheduled_task Create", map[string]interface{}{
		"name":    plan.Name.ValueString(),
		"path":    plan.Path.ValueString(),
		"enabled": plan.Enabled.ValueBool(),
	})

	input, diags := modelToInput(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// WriteOnly principal.password_wo is null in the plan at apply time;
	// overlay the config value (windows_file content_wo precedent).
	resp.Diagnostics.Append(overlayScheduledTaskPasswordFromConfig(ctx, &input, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validateScheduledTaskPrincipalCredentials(input, true)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state, err := r.stClient.Create(ctx, input)
	if err != nil {
		// Partial failure (ADR-0012): the task may already be registered
		// on the host. Persist the observed state so the resource is
		// tainted rather than dropped from state. A nil state (for
		// example, the already_exists pre-flight) stays error-only.
		if state != nil {
			partial, diags := stateToModel(ctx, state, &plan)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				resp.Diagnostics.Append(resp.State.Set(ctx, partial)...)
			}
		}
		resp.Diagnostics.Append(scheduledTaskErrDiag("Create", err)...)
		return
	}

	// stateToModel preserves password / password_wo_version from plan
	newModel, diags := stateToModel(ctx, state, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newModel)...)
}

// ---------------------------------------------------------------------------
// CRUD — Read
// ---------------------------------------------------------------------------

// Read refreshes state from the Windows host.
func (r *windowsScheduledTaskResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var current windowsScheduledTaskModel
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := current.Timeouts.Read(ctx, stDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	id := current.ID.ValueString()
	tflog.Debug(ctx, "windows_scheduled_task Read", map[string]interface{}{"id": id})
	state, err := r.stClient.Read(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(scheduledTaskErrDiag("Read", err)...)
		return
	}
	if state == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	newModel, diags := stateToModel(ctx, state, &current)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newModel)...)
}

// ---------------------------------------------------------------------------
// CRUD — Update
// ---------------------------------------------------------------------------

// Update applies in-place changes to the Scheduled Task.
func (r *windowsScheduledTaskResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, currentState, config windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &currentState)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, dt := plan.Timeouts.Update(ctx, stDefaultTimeout)
	resp.Diagnostics.Append(dt...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// Detect password bump (ADR-ST-3 / EC-6)
	planInput, diags := modelToInput(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// WriteOnly principal.password_wo is null in the plan at apply time;
	// overlay the config value before the bump gate below decides whether
	// to keep or clear it (windows_file content_wo precedent).
	resp.Diagnostics.Append(overlayScheduledTaskPasswordFromConfig(ctx, &planInput, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// WriteOnly values can make the nested principal's computed siblings
	// unknown/null in the update plan. Keep the existing identity fields when
	// the plan omitted them; otherwise Set-ScheduledTask would receive an empty
	// User alongside a valid password and Windows reports a misleading
	// "user name or password is incorrect" error.
	if planInput.Principal != nil && !currentState.Principal.IsNull() && !currentState.Principal.IsUnknown() {
		var priorPrincipal windowsScheduledTaskPrincipalModel
		resp.Diagnostics.Append(currentState.Principal.As(ctx, &priorPrincipal, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
		if resp.Diagnostics.HasError() {
			return
		}
		if planInput.Principal.UserID == "" && !priorPrincipal.UserID.IsNull() && !priorPrincipal.UserID.IsUnknown() {
			planInput.Principal.UserID = priorPrincipal.UserID.ValueString()
		}
		if planInput.Principal.LogonType == "" && !priorPrincipal.LogonType.IsNull() && !priorPrincipal.LogonType.IsUnknown() {
			planInput.Principal.LogonType = priorPrincipal.LogonType.ValueString()
		}
		if planInput.Principal.RunLevel == "" && !priorPrincipal.RunLevel.IsNull() && !priorPrincipal.RunLevel.IsUnknown() {
			planInput.Principal.RunLevel = priorPrincipal.RunLevel.ValueString()
		}
	}
	resp.Diagnostics.Append(validateScheduledTaskPrincipalCredentials(planInput, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Only send password if password_wo_version bumped
	planPwVersion := int64(0)
	statePwVersion := int64(0)
	if !plan.Principal.IsNull() && !plan.Principal.IsUnknown() {
		var pp windowsScheduledTaskPrincipalModel
		resp.Diagnostics.Append(plan.Principal.As(ctx, &pp, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
		planPwVersion = pp.PasswordWoVersion.ValueInt64()
	}
	if !currentState.Principal.IsNull() && !currentState.Principal.IsUnknown() {
		var sp windowsScheduledTaskPrincipalModel
		resp.Diagnostics.Append(currentState.Principal.As(ctx, &sp, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
		statePwVersion = sp.PasswordWoVersion.ValueInt64()
	}
	priorHasPrincipal := !currentState.Principal.IsNull() && !currentState.Principal.IsUnknown()
	pwBumped := deriveScheduledTaskPwBumped(planPwVersion, statePwVersion, priorHasPrincipal, scheduledTaskEffectivePassword(planInput))
	if !pwBumped && planInput.Principal != nil {
		// No bump: clear password so it's not re-sent
		planInput.Principal.Password = nil
	}
	// Fail closed: a rotation — or a first-time Password principal — with
	// no effective password would otherwise silently register a task that
	// cannot log on. Mirrors the local_user "password required for
	// rotation" guard. Steady-state no-bump updates (prior principal, no
	// version change) still pass so unrelated attribute updates succeed.
	if planInput.Principal != nil && scheduledTaskPasswordFailClosed(planInput.Principal.LogonType, scheduledTaskEffectivePassword(planInput), pwBumped, priorHasPrincipal) {
		resp.Diagnostics.AddAttributeError(
			scheduledTaskPasswordDiagPath(ctx, &plan, &config),
			"password required for rotation",
			"password_wo_version changed but neither `password` nor `password_wo` is set. "+
				"Provide a non-empty value on one of them.",
		)
		return
	}

	id := currentState.ID.ValueString()
	tflog.Debug(ctx, "windows_scheduled_task Update", map[string]interface{}{
		"id":               id,
		"name":             plan.Name.ValueString(),
		"plan_pw_version":  planPwVersion,
		"state_pw_version": statePwVersion,
		"password_rotated": pwBumped,
	})
	state, err := r.stClient.Update(ctx, id, planInput)
	if err != nil {
		// Partial failure (ADR-0012): persist the observed state so the
		// resource keeps its partial state rather than staying at prior
		// state. A nil state stays error-only. Credential markers come
		// from prior state: a failed rotation must not advance the stored
		// version marker or a retry would no longer diff.
		if state != nil {
			partial, diags := stateToModel(ctx, state, &plan)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				resp.Diagnostics.Append(restoreScheduledTaskPrincipalSecrets(ctx, partial, currentState)...)
			}
			if !resp.Diagnostics.HasError() {
				resp.Diagnostics.Append(resp.State.Set(ctx, partial)...)
			}
		}
		resp.Diagnostics.Append(scheduledTaskErrDiag("Update", err)...)
		return
	}

	// Use plan as prior model to preserve new password value
	newModel, diags2 := stateToModel(ctx, state, &plan)
	resp.Diagnostics.Append(diags2...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newModel)...)
}

// ---------------------------------------------------------------------------
// CRUD — Delete
// ---------------------------------------------------------------------------

// Delete unregisters the Scheduled Task.
func (r *windowsScheduledTaskResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsScheduledTaskModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteTimeout, dt := state.Timeouts.Delete(ctx, stDefaultTimeout)
	resp.Diagnostics.Append(dt...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_scheduled_task Delete", map[string]interface{}{
		"id":   state.ID.ValueString(),
		"name": state.Name.ValueString(),
	})

	err := r.stClient.Delete(ctx, state.ID.ValueString())
	if err != nil && !winclient.IsScheduledTaskError(err, winclient.ScheduledTaskErrorNotFound) {
		resp.Diagnostics.Append(scheduledTaskErrDiag("Delete", err)...)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState imports a Scheduled Task by its composite ID.
func (r *windowsScheduledTaskResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID
	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with stDefaultTimeout instead.
	ctx, cancel := context.WithTimeout(ctx, stDefaultTimeout)
	defer cancel()
	state, err := r.stClient.ImportByID(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(scheduledTaskErrDiag("Import", err)...)
		return
	}

	newModel, diags := stateToModel(ctx, state, nil)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, newModel)...)
}

// ---------------------------------------------------------------------------
// Helper: modelToInput
// ---------------------------------------------------------------------------

// modelToInput converts the Terraform plan/state model to a ScheduledTaskInput.
func modelToInput(ctx context.Context, m *windowsScheduledTaskModel) (winclient.ScheduledTaskInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	input := winclient.ScheduledTaskInput{
		Name:        m.Name.ValueString(),
		Path:        m.Path.ValueString(),
		Description: m.Description.ValueString(),
		Enabled:     m.Enabled.ValueBool(),
	}

	// Principal
	if !m.Principal.IsNull() && !m.Principal.IsUnknown() {
		var pm windowsScheduledTaskPrincipalModel
		diags.Append(m.Principal.As(ctx, &pm, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
		if diags.HasError() {
			return input, diags
		}
		p := &winclient.ScheduledTaskPrincipalInput{
			UserID:            pm.UserID.ValueString(),
			PasswordWoVersion: pm.PasswordWoVersion.ValueInt64(),
			LogonType:         pm.LogonType.ValueString(),
			RunLevel:          pm.RunLevel.ValueString(),
		}
		// Tier 3: pick whichever credential attribute the operator set.
		// The cross-field validator (scheduledTaskPrincipalCrossFieldValidator)
		// guarantees at most one of password / password_wo is non-null at
		// this point, so the order of checks is for routing only. password_wo
		// takes precedence when both happen to be set in tests that bypass
		// the validator.
		if !pm.PasswordWO.IsNull() && !pm.PasswordWO.IsUnknown() {
			pw := pm.PasswordWO.ValueString()
			if pw != "" {
				p.Password = &pw
			}
		} else if !pm.Password.IsNull() && !pm.Password.IsUnknown() {
			pw := pm.Password.ValueString()
			p.Password = &pw
		}
		input.Principal = p
	}

	// Actions
	var actions []windowsScheduledTaskActionModel
	diags.Append(m.Actions.ElementsAs(ctx, &actions, false)...)
	if diags.HasError() {
		return input, diags
	}
	input.Actions = make([]winclient.ScheduledTaskActionInput, len(actions))
	for i, a := range actions {
		input.Actions[i] = winclient.ScheduledTaskActionInput{
			Execute:          a.Execute.ValueString(),
			Arguments:        a.Arguments.ValueString(),
			WorkingDirectory: a.WorkingDirectory.ValueString(),
		}
	}

	// Triggers
	var triggers []windowsScheduledTaskTriggerModel
	diags.Append(m.Triggers.ElementsAs(ctx, &triggers, false)...)
	if diags.HasError() {
		return input, diags
	}
	input.Triggers = make([]winclient.ScheduledTaskTriggerInput, len(triggers))
	for i, t := range triggers {
		var dows []string
		// days_of_week is Optional+Computed: on a first plan with no prior
		// state the value is Unknown. ElementsAs rejects unknowns, and an
		// unset weekday set means "no restriction" to winclient either way,
		// so only extract when known.
		if !t.DaysOfWeek.IsNull() && !t.DaysOfWeek.IsUnknown() {
			diags.Append(t.DaysOfWeek.ElementsAs(ctx, &dows, false)...)
		}
		enabled := true
		if !t.Enabled.IsNull() && !t.Enabled.IsUnknown() {
			enabled = t.Enabled.ValueBool()
		}
		input.Triggers[i] = winclient.ScheduledTaskTriggerInput{
			Type:               t.Type.ValueString(),
			Enabled:            &enabled,
			StartBoundary:      t.StartBoundary.ValueString(),
			EndBoundary:        t.EndBoundary.ValueString(),
			ExecutionTimeLimit: t.ExecutionTimeLimit.ValueString(),
			Delay:              t.Delay.ValueString(),
			DaysInterval:       t.DaysInterval.ValueInt64(),
			DaysOfWeek:         dows,
			WeeksInterval:      t.WeeksInterval.ValueInt64(),
			UserID:             t.UserID.ValueString(),
			Subscription:       t.Subscription.ValueString(),
		}
	}

	// Settings
	if !m.Settings.IsNull() && !m.Settings.IsUnknown() {
		var sm windowsScheduledTaskSettingsModel
		diags.Append(m.Settings.As(ctx, &sm, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
		if diags.HasError() {
			return input, diags
		}
		input.Settings = &winclient.ScheduledTaskSettingsInput{
			AllowDemandStart:           sm.AllowDemandStart.ValueBool(),
			AllowHardTerminate:         sm.AllowHardTerminate.ValueBool(),
			StartWhenAvailable:         sm.StartWhenAvailable.ValueBool(),
			RunOnlyIfNetworkAvailable:  sm.RunOnlyIfNetworkAvailable.ValueBool(),
			ExecutionTimeLimit:         sm.ExecutionTimeLimit.ValueString(),
			MultipleInstances:          sm.MultipleInstances.ValueString(),
			DisallowStartIfOnBatteries: sm.DisallowStartIfOnBatteries.ValueBool(),
			StopIfGoingOnBatteries:     sm.StopIfGoingOnBatteries.ValueBool(),
			WakeToRun:                  sm.WakeToRun.ValueBool(),
			RunOnlyIfIdle:              sm.RunOnlyIfIdle.ValueBool(),
		}
	}

	return input, diags
}

// overlayScheduledTaskPasswordFromConfig copies principal.password_wo from
// config into the converted input. WriteOnly values are null in the plan
// handed to ApplyResourceChange, so the plan-derived input carries no
// password at apply time (windows_file content_wo precedent). No-op when
// there is no principal, when config has no principal, or when the config
// WriteOnly value is null/unknown/empty. Never clears an input password:
// callers apply the password_wo_version bump gate afterwards.
func overlayScheduledTaskPasswordFromConfig(ctx context.Context, input *winclient.ScheduledTaskInput, config *windowsScheduledTaskModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if input == nil || input.Principal == nil || config == nil {
		return diags
	}
	if config.Principal.IsNull() || config.Principal.IsUnknown() {
		return diags
	}
	var pm windowsScheduledTaskPrincipalModel
	diags.Append(config.Principal.As(ctx, &pm, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
	if diags.HasError() {
		return diags
	}
	// The principal object may carry unknown optional/computed siblings in the
	// apply plan when a WriteOnly field is present. Restore explicitly
	// configured identity fields from Config before the client builds the
	// Register/Set parameter set.
	if !pm.UserID.IsNull() && !pm.UserID.IsUnknown() {
		input.Principal.UserID = pm.UserID.ValueString()
	}
	if !pm.LogonType.IsNull() && !pm.LogonType.IsUnknown() {
		input.Principal.LogonType = pm.LogonType.ValueString()
	}
	if !pm.RunLevel.IsNull() && !pm.RunLevel.IsUnknown() {
		input.Principal.RunLevel = pm.RunLevel.ValueString()
	}
	if pm.PasswordWO.IsNull() || pm.PasswordWO.IsUnknown() {
		return diags
	}
	if pw := pm.PasswordWO.ValueString(); pw != "" {
		if input.Principal.Password != nil && *input.Principal.Password != "" {
			diags.AddAttributeError(
				path.Root("principal").AtName("password_wo"),
				"Conflicting attributes",
				"`principal.password` and `principal.password_wo` are mutually exclusive.",
			)
			return diags
		}
		input.Principal.Password = &pw
	}
	return diags
}

// validateScheduledTaskPrincipalCredentials validates the effective password
// after WriteOnly values have been overlaid from config. requirePassword is
// true for Create; Update separately enforces the version-bump fail-closed
// rule while allowing unrelated steady-state changes without resending a
// password.
func validateScheduledTaskPrincipalCredentials(input winclient.ScheduledTaskInput, requirePassword bool) diag.Diagnostics {
	var diags diag.Diagnostics
	if input.Principal == nil {
		return diags
	}
	password := scheduledTaskEffectivePassword(input)
	logonType := input.Principal.LogonType
	if logonType == "Password" && requirePassword && password == "" {
		diags.AddAttributeError(
			path.Root("principal").AtName("password_wo"),
			"Missing required attribute",
			`password (or password_wo) is required when logon_type is "Password" (EC-4).`,
		)
	}
	for _, forbidden := range []string{"Interactive", "S4U", "Group", "ServiceAccount"} {
		if logonType == forbidden && password != "" {
			diags.AddAttributeError(
				path.Root("principal").AtName("password_wo"),
				"Conflicting attribute",
				fmt.Sprintf("a password must not be set when principal.logon_type is %q (EC-5).", forbidden),
			)
			break
		}
	}
	return diags
}

// scheduledTaskEffectivePassword returns the effective plaintext held by a
// converted input ("" when nil). Centralises the nil/empty checks for the
// bump gate and the fail-closed guard below.
func scheduledTaskEffectivePassword(input winclient.ScheduledTaskInput) string {
	if input.Principal == nil || input.Principal.Password == nil {
		return ""
	}
	return *input.Principal.Password
}

// deriveScheduledTaskPwBumped reports whether Update must (re-)send the
// principal password: version bump, or first-time principal with a newly
// supplied non-empty effective password (prior state had no principal so
// the version gate compares 0 against 0 and would silently drop it).
func deriveScheduledTaskPwBumped(planPwVersion, statePwVersion int64, priorHasPrincipal bool, effectivePassword string) bool {
	if planPwVersion != statePwVersion {
		return true
	}
	if !priorHasPrincipal && effectivePassword != "" {
		return true
	}
	return false
}

// scheduledTaskPasswordFailClosed reports whether Update must fail closed:
// Password logon with an empty effective password on rotation or on a
// first-time principal. Steady-state no-bump updates (prior principal, no
// version change) return false so unrelated attribute updates still
// succeed; the plan-time cross-field validator remains the primary guard
// there.
func scheduledTaskPasswordFailClosed(logonType, effectivePassword string, pwBumped, priorHasPrincipal bool) bool {
	if logonType != "Password" {
		return false
	}
	if effectivePassword != "" {
		return false
	}
	return pwBumped || !priorHasPrincipal
}

// scheduledTaskPasswordDiagPath routes the fail-closed diagnostic at the
// credential attribute the operator intended (effectiveLocalUserPassword
// precedent): legacy `principal.password` when set in plan or config,
// else `principal.password_wo`.
func scheduledTaskPasswordDiagPath(ctx context.Context, plan, config *windowsScheduledTaskModel) path.Path {
	for _, m := range []*windowsScheduledTaskModel{plan, config} {
		if m == nil || m.Principal.IsNull() || m.Principal.IsUnknown() {
			continue
		}
		var pm windowsScheduledTaskPrincipalModel
		if d := m.Principal.As(ctx, &pm, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true}); d.HasError() {
			continue
		}
		if !pm.Password.IsNull() && !pm.Password.IsUnknown() {
			return path.Root("principal").AtName("password")
		}
	}
	return path.Root("principal").AtName("password_wo")
}

// ---------------------------------------------------------------------------
// Helper: stateToModel
// ---------------------------------------------------------------------------

// stateToModel converts a ScheduledTaskState from Windows to a Terraform model.
// priorModel is the previous state/plan (used to preserve write-only fields).
// Pass nil for priorModel on import.
func stateToModel(ctx context.Context, s *winclient.ScheduledTaskState, priorModel *windowsScheduledTaskModel) (*windowsScheduledTaskModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := &windowsScheduledTaskModel{
		ID:             types.StringValue(s.Path + s.Name),
		Name:           types.StringValue(s.Name),
		Path:           types.StringValue(s.Path),
		Enabled:        types.BoolValue(s.Enabled),
		State:          types.StringValue(s.State),
		LastRunTime:    types.StringValue(s.LastRunTime),
		LastTaskResult: types.Int64Value(s.LastTaskResult),
		NextRunTime:    types.StringValue(s.NextRunTime),
	}

	// Preserve user-configured per-operation timeouts across the projection
	// (resp.State.Set overwrites the full state object). On import there is no
	// prior model, and leaving the zero value would put an object with no
	// attribute types into state, which the framework rejects.
	if priorModel != nil {
		m.Timeouts = priorModel.Timeouts
	} else {
		m.Timeouts = stNullTimeouts()
	}

	// description: map empty string to null (Optional-only field)
	if s.Description != "" {
		m.Description = types.StringValue(s.Description)
	} else {
		m.Description = types.StringNull()
	}

	// Principal
	m.Principal = buildPrincipalModel(ctx, s.Principal, priorModel, &diags)

	// Actions
	actionElems := make([]attr.Value, len(s.Actions))
	for i, a := range s.Actions {
		obj, d := types.ObjectValueFrom(ctx, scheduledTaskActionAttrTypes, windowsScheduledTaskActionModel{
			Execute:          types.StringValue(a.Execute),
			Arguments:        strOrNull(a.Arguments),
			WorkingDirectory: strOrNull(a.WorkingDirectory),
		})
		diags.Append(d...)
		actionElems[i] = obj
	}
	actList, d := types.ListValue(types.ObjectType{AttrTypes: scheduledTaskActionAttrTypes}, actionElems)
	diags.Append(d...)
	m.Actions = actList

	// Triggers
	var priorTriggersAlign []windowsScheduledTaskTriggerModel
	var priorUsed []bool
	if priorModel != nil && !priorModel.Triggers.IsNull() && !priorModel.Triggers.IsUnknown() {
		var pts []windowsScheduledTaskTriggerModel
		if d2 := priorModel.Triggers.ElementsAs(ctx, &pts, false); !d2.HasError() {
			priorTriggersAlign = pts
			priorUsed = make([]bool, len(pts))
		}
	}
	trigElems := make([]attr.Value, len(s.Triggers))
	for i, t := range s.Triggers {
		// Sets have no stable index: align each live trigger with the first
		// still-unused prior trigger of the same type, so a reorder of the
		// trigger set cannot attach the wrong prior days/weeks interval to
		// a trigger. Each prior element is consumed at most once: a second
		// duplicate with no unused match left falls back to nil, which
		// resolves a Windows 0 interval to null — the correct create-path outcome.
		var priorTrigger *windowsScheduledTaskTriggerModel
		for j := range priorTriggersAlign {
			if priorUsed[j] {
				continue
			}
			if !priorTriggersAlign[j].Type.IsNull() && !priorTriggersAlign[j].Type.IsUnknown() && priorTriggersAlign[j].Type.ValueString() == t.Type {
				priorTrigger = &priorTriggersAlign[j]
				priorUsed[j] = true
				break
			}
		}
		obj, d2 := buildTriggerObject(ctx, t, priorTrigger)
		diags.Append(d2...)
		trigElems[i] = obj
	}
	trigSet, d2 := types.SetValue(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}, trigElems)
	diags.Append(d2...)
	m.Triggers = trigSet

	// Settings
	if s.Settings != nil && priorModel != nil && !priorModel.Settings.IsNull() {
		settingsObj, d3 := types.ObjectValueFrom(ctx, scheduledTaskSettingsAttrTypes, windowsScheduledTaskSettingsModel{
			AllowDemandStart:           types.BoolValue(s.Settings.AllowDemandStart),
			AllowHardTerminate:         types.BoolValue(s.Settings.AllowHardTerminate),
			StartWhenAvailable:         types.BoolValue(s.Settings.StartWhenAvailable),
			RunOnlyIfNetworkAvailable:  types.BoolValue(s.Settings.RunOnlyIfNetworkAvailable),
			ExecutionTimeLimit:         durationValueOf(s.Settings.ExecutionTimeLimit),
			MultipleInstances:          types.StringValue(s.Settings.MultipleInstances),
			DisallowStartIfOnBatteries: types.BoolValue(s.Settings.DisallowStartIfOnBatteries),
			StopIfGoingOnBatteries:     types.BoolValue(s.Settings.StopIfGoingOnBatteries),
			WakeToRun:                  types.BoolValue(s.Settings.WakeToRun),
			RunOnlyIfIdle:              types.BoolValue(s.Settings.RunOnlyIfIdle),
		})
		diags.Append(d3...)
		m.Settings = settingsObj
	} else if priorModel == nil && s.Settings != nil {
		// Import path: always populate settings
		settingsObj, d3 := types.ObjectValueFrom(ctx, scheduledTaskSettingsAttrTypes, windowsScheduledTaskSettingsModel{
			AllowDemandStart:           types.BoolValue(s.Settings.AllowDemandStart),
			AllowHardTerminate:         types.BoolValue(s.Settings.AllowHardTerminate),
			StartWhenAvailable:         types.BoolValue(s.Settings.StartWhenAvailable),
			RunOnlyIfNetworkAvailable:  types.BoolValue(s.Settings.RunOnlyIfNetworkAvailable),
			ExecutionTimeLimit:         durationValueOf(s.Settings.ExecutionTimeLimit),
			MultipleInstances:          types.StringValue(s.Settings.MultipleInstances),
			DisallowStartIfOnBatteries: types.BoolValue(s.Settings.DisallowStartIfOnBatteries),
			StopIfGoingOnBatteries:     types.BoolValue(s.Settings.StopIfGoingOnBatteries),
			WakeToRun:                  types.BoolValue(s.Settings.WakeToRun),
			RunOnlyIfIdle:              types.BoolValue(s.Settings.RunOnlyIfIdle),
		})
		diags.Append(d3...)
		m.Settings = settingsObj
	} else {
		m.Settings = types.ObjectNull(scheduledTaskSettingsAttrTypes)
	}

	return m, diags
}

// buildPrincipalModel builds the principal types.Object for state.
// Write-only fields (password, password_wo_version) are preserved from priorModel.
// logon_type is preserved from priorModel (Optional-only, not read from Windows).
func buildPrincipalModel(ctx context.Context, s *winclient.ScheduledTaskPrincipalState, priorModel *windowsScheduledTaskModel, diags *diag.Diagnostics) types.Object {
	// If priorModel had no principal, keep null (user doesn't manage principal)
	priorHasPrincipal := priorModel != nil && !priorModel.Principal.IsNull() && !priorModel.Principal.IsUnknown()

	if !priorHasPrincipal && priorModel != nil {
		// Not on import path AND no prior principal: keep null
		return types.ObjectNull(scheduledTaskPrincipalAttrTypes)
	}

	pm := windowsScheduledTaskPrincipalModel{}

	// user_id: Computed+Default("SYSTEM") — always from Windows
	if s != nil {
		pm.UserID = types.StringValue(s.UserID)
	} else {
		pm.UserID = types.StringValue("SYSTEM")
	}
	// PowerShell/Task Scheduler can return a local account as its short SAM
	// name even when configuration supplied COMPUTER\user. Preserve the
	// configured representation during Create/Read so Framework does not
	// report an inconsistent nested principal after registration.
	if priorHasPrincipal {
		var prior windowsScheduledTaskPrincipalModel
		if d := priorModel.Principal.As(ctx, &prior, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true}); !d.HasError() &&
			!prior.UserID.IsNull() && !prior.UserID.IsUnknown() {
			pm.UserID = prior.UserID
		}
	}

	// password (legacy): semantic write-only — preserve from prior model so
	// the value does not vanish from state on Read. Windows never returns
	// the plaintext.
	pm.Password = types.StringNull()
	// password_wo (Tier 3 WriteOnly): never preserved by us. The framework
	// strips WriteOnly attributes from state on resp.State.Set; explicitly
	// nulling it here documents the intent and protects against accidental
	// preservation if `priorModel` carries a non-null value (it should not,
	// but defensive zeroing keeps the contract obvious).
	pm.PasswordWO = types.StringNull()
	if priorHasPrincipal {
		var prior windowsScheduledTaskPrincipalModel
		if d := priorModel.Principal.As(ctx, &prior, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true}); !d.HasError() {
			pm.Password = prior.Password
			// pm.PasswordWO stays null on purpose — see comment above.
		}
	}

	// password_wo_version: preserve from prior
	pm.PasswordWoVersion = types.Int64Value(0)
	if priorHasPrincipal {
		var prior windowsScheduledTaskPrincipalModel
		if d := priorModel.Principal.As(ctx, &prior, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true}); !d.HasError() {
			pm.PasswordWoVersion = prior.PasswordWoVersion
		}
	}

	// logon_type: Optional-only — preserve from prior (avoid spurious drift)
	pm.LogonType = types.StringNull()
	if priorHasPrincipal {
		var prior windowsScheduledTaskPrincipalModel
		if d := priorModel.Principal.As(ctx, &prior, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true}); !d.HasError() {
			pm.LogonType = prior.LogonType
		}
	}

	// run_level: Computed+Default("Limited") — from Windows
	if s != nil {
		pm.RunLevel = types.StringValue(s.RunLevel)
	} else {
		pm.RunLevel = types.StringValue("Limited")
	}

	obj, d := types.ObjectValueFrom(ctx, scheduledTaskPrincipalAttrTypes, pm)
	diags.Append(d...)
	return obj
}

// restoreScheduledTaskPrincipalSecrets overwrites the credential markers
// (legacy password and password_wo_version) on a partial-failure model with
// the prior-state values (ADR-0012). A failed rotation must not advance the
// stored version marker, otherwise the retry would no longer diff and the
// rotation would be silently lost. Non-credential fields stay on the
// plan-based projection. When prior state managed no principal, the observed
// principal object is kept and only its secrets are zeroed (Password and
// PasswordWO null, PasswordWoVersion null).
func restoreScheduledTaskPrincipalSecrets(ctx context.Context, model *windowsScheduledTaskModel, prior windowsScheduledTaskModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if model.Principal.IsNull() || model.Principal.IsUnknown() {
		return diags
	}
	if prior.Principal.IsNull() || prior.Principal.IsUnknown() {
		var cur windowsScheduledTaskPrincipalModel
		diags.Append(model.Principal.As(ctx, &cur, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
		if diags.HasError() {
			return diags
		}
		cur.Password = types.StringNull()
		cur.PasswordWO = types.StringNull()
		cur.PasswordWoVersion = types.Int64Null()
		obj, d := types.ObjectValueFrom(ctx, scheduledTaskPrincipalAttrTypes, cur)
		diags.Append(d...)
		if !diags.HasError() {
			model.Principal = obj
		}
		return diags
	}
	var cur, prev windowsScheduledTaskPrincipalModel
	diags.Append(model.Principal.As(ctx, &cur, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
	diags.Append(prior.Principal.As(ctx, &prev, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true})...)
	if diags.HasError() {
		return diags
	}
	cur.Password = prev.Password
	cur.PasswordWO = types.StringNull()
	cur.PasswordWoVersion = prev.PasswordWoVersion
	obj, d := types.ObjectValueFrom(ctx, scheduledTaskPrincipalAttrTypes, cur)
	diags.Append(d...)
	if !diags.HasError() {
		model.Principal = obj
	}
	return diags
}

// buildTriggerObject converts a ScheduledTaskTriggerState to a types.Object.
func buildTriggerObject(ctx context.Context, t winclient.ScheduledTaskTriggerState, prior *windowsScheduledTaskTriggerModel) (attr.Value, diag.Diagnostics) {
	var diags diag.Diagnostics

	var dows attr.Value
	if len(t.DaysOfWeek) > 0 {
		v, d := types.SetValueFrom(ctx, types.StringType, t.DaysOfWeek)
		diags.Append(d...)
		dows = v
	} else {
		dows = types.SetNull(types.StringType)
	}

	// days_interval / weeks_interval: Computed — use Windows value; 0 -> null.
	// Only preserve a prior value when it is known: on a create prior == plan,
	// and an unset Optional+Computed interval is Unknown there. A Computed
	// attribute must never stay Unknown after apply, so resolve those to null.
	//
	// Windows-default suppression (plan-clean, issue #324): a Daily trigger
	// created without -DaysInterval reports DaysInterval 1 (likewise
	// WeeksInterval 1 for a Weekly trigger created without -WeeksInterval),
	// because Create omits empty fields and Windows applies its own default.
	// The minimal acc-test Daily shape omits both, so the create plan carries
	// Null; writing the live default into state breaks Set element
	// correlation ("planned set element does not correlate with any element
	// in actual") on first create, where there is no prior state for
	// UseStateForUnknown to copy. When the prior value is Null and live
	// equals the Windows default, keep Null so plan == state. Explicitly
	// configured or drifted non-default values are still surfaced, and the
	// import path (prior == nil) always reports live values.
	var di, wi types.Int64
	diLive, wiLive := t.DaysInterval, t.WeeksInterval
	if t.Type == "Daily" && diLive == 1 && prior != nil && prior.DaysInterval.IsNull() {
		diLive = 0
	}
	if t.Type == "Weekly" && wiLive == 1 && prior != nil && prior.WeeksInterval.IsNull() {
		wiLive = 0
	}
	if diLive > 0 {
		di = types.Int64Value(diLive)
	} else if prior != nil && !prior.DaysInterval.IsUnknown() {
		di = prior.DaysInterval // preserve known null/value from state
	} else {
		di = types.Int64Null()
	}
	if wiLive > 0 {
		wi = types.Int64Value(wiLive)
	} else if prior != nil && !prior.WeeksInterval.IsUnknown() {
		wi = prior.WeeksInterval
	} else {
		wi = types.Int64Null()
	}

	dowsSet, ok := dows.(types.Set)
	if !ok {
		diags.Append(diag.NewErrorDiagnostic("Unexpected days-of-week value", fmt.Sprintf("Expected days-of-week to be a set of strings, got %T.", dows)))
		return types.ObjectNull(scheduledTaskTriggerAttrTypes), diags
	}

	tm := windowsScheduledTaskTriggerModel{
		Type:               types.StringValue(t.Type),
		Enabled:            types.BoolValue(t.Enabled),
		StartBoundary:      strOrNull(t.StartBoundary),
		EndBoundary:        strOrNull(t.EndBoundary),
		ExecutionTimeLimit: strOrNull(t.ExecutionTimeLimit),
		Delay:              strOrNull(t.Delay),
		DaysInterval:       di,
		DaysOfWeek:         dowsSet,
		WeeksInterval:      wi,
		UserID:             strOrNull(t.UserID),
		Subscription:       subscriptionXMLValueOrNull(t.Subscription),
	}
	return types.ObjectValueFrom(ctx, scheduledTaskTriggerAttrTypes, tm)
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// stTimeoutsOpts declares which per-operation timeouts the resource exposes.
// The schema and stNullTimeouts both derive from it; keep them together, since
// a null timeouts value whose attribute types disagree with the schema is
// rejected by the framework as a provider type error.
var stTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// stNullTimeouts returns a null timeouts value carrying the schema's attribute
// types. The zero timeouts.Value wraps an object with NO attribute types, which
// the framework reports as "Expected timeouts.Type / underlying type
// tftypes.Object[...] / Received tftypes.Object[]" -- the failure mode on
// import, where there is no prior state to copy the value from.
func stNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if stTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if stTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if stTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if stTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// strOrNull returns types.StringNull() for empty strings (Optional-only fields).
func strOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// scheduledTaskErrDiag converts a ScheduledTaskError to Terraform diagnostics.
func scheduledTaskErrDiag(op string, err error) diag.Diagnostics {
	var diags diag.Diagnostics
	var ste *winclient.ScheduledTaskError
	if errors.As(err, &ste) {
		summary := fmt.Sprintf("windows_scheduled_task %s error [%s]", op, ste.Kind)
		detail := ste.Message
		if ste.Cause != nil {
			detail += ": " + ste.Cause.Error()
		}
		if stderr := ste.Context["stderr"]; stderr != "" {
			detail += "\nstderr: " + stderr
		}
		diags.AddError(summary, detail)
		return diags
	}
	diags.AddError(fmt.Sprintf("windows_scheduled_task %s error", op), err.Error())
	return diags
}

// Ensure unused import for tfsdk is referenced (it's used transitively).
var _ tfsdk.Config
var _ strings.Builder
