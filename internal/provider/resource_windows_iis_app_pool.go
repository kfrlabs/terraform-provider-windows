// Package provider - resource_windows_iis_app_pool implements the full
// Terraform resource lifecycle for windows_iis_app_pool.
//
// An IIS application pool is provisioned through the WebAdministration
// module (New-WebAppPool plus per-attribute Set-ItemProperty in one script,
// Start/Stop-WebAppPool for runtime state). Every non-identity attribute is
// Optional+Computed: only configured attributes are enforced, unconfigured
// ones reflect the observed value (same semantics as
// windows_firewall_profile).
//
// The SpecificUser identity password is WriteOnly + Sensitive
// (identity_password_wo): it travels to the host on stdin, is never
// persisted in state, and is re-sent only when identity_password_wo_version
// changes (same pattern as windows_local_user password_wo).
//
// Spec alignment: windows_iis_app_pool spec v1 (issue #283).
// Framework:      terraform-plugin-framework v1.19.0.
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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

var (
	_ resource.Resource                     = (*windowsIISAppPoolResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsIISAppPoolResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsIISAppPoolResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsIISAppPoolResource)(nil)
)

// NewWindowsIISAppPoolResource is the constructor registered in provider.go.
func NewWindowsIISAppPoolResource() resource.Resource {
	return &windowsIISAppPoolResource{}
}

// windowsIISAppPoolResource is the TPF resource type for windows_iis_app_pool.
type windowsIISAppPoolResource struct {
	pool winclient.WindowsIISAppPoolClient
}

// iisAppPoolDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Pool operations are normally
// fast, but a stalled PowerShell/SSH session must never block Terraform
// forever: every CRUD handler bounds its work with this default.
const iisAppPoolDefaultTimeout = 10 * time.Minute

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates an
// IISAppPoolClient for this resource instance.
func (r *windowsIISAppPoolResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.pool = winclient.NewIISAppPoolClient(client)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create provisions the application pool, applies the configured settings in
// one script and enforces the configured runtime state. A SpecificUser
// identity requires the WriteOnly password from config (fail-closed); the
// version counter must accompany it (AlsoRequires at plan time, re-checked
// here against the effective value).
func (r *windowsIISAppPoolResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config windowsIISAppPoolModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, iisAppPoolDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	name := plan.Name.ValueString()
	tflog.Debug(ctx, "Creating Windows IIS application pool", map[string]any{
		"name": name,
		// The version counter is safe to log; the secret itself never is.
		"identity_password_wo_version": plan.IdentityPasswordWOVersion.ValueInt64(),
	})

	password := effectiveIISAppPoolPassword(plan, config)
	if plan.IdentityType.ValueString() == "SpecificUser" {
		if plan.IdentityUsername.IsNull() || plan.IdentityUsername.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("identity_username"),
				"identity_username is required for SpecificUser",
				"identity_type = \"SpecificUser\" requires identity_username (e.g. \"CONTOSO\\svc-web\").",
			)
			return
		}
		if password == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("identity_password_wo"),
				"identity_password_wo is required for SpecificUser",
				"identity_type = \"SpecificUser\" requires identity_password_wo together with "+
					"identity_password_wo_version (fail-closed: the pool is not created with a blank credential).",
			)
			return
		}
	}
	// Fail-closed rotation guard (windows_service precedent): a set version
	// with no password supplied must not reach the host as a blank
	// credential.
	if !plan.IdentityPasswordWOVersion.IsNull() && !plan.IdentityPasswordWOVersion.IsUnknown() && password == "" &&
		plan.IdentityType.ValueString() == "SpecificUser" {
		resp.Diagnostics.AddAttributeError(
			path.Root("identity_password_wo_version"),
			"identity_password_wo_version is set but no password supplied",
			"`identity_password_wo_version` is set but `identity_password_wo` is not configured. Provide "+
				"a non-empty value (fail-closed: the pool is not created with a blank credential).",
		)
		return
	}

	settings, diags := modelToIISAppPoolSettings(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state, err := r.pool.Create(ctx, winclient.IISAppPoolInput{
		Name:     name,
		Settings: settings,
		Password: password,
	})
	if err != nil {
		// Partial failure (ADR-0012): persist the observed state so the
		// resource is tainted rather than dropped from state. A nil state
		// (for example, the already_exists pre-flight) stays error-only.
		if state != nil {
			m, diags := iisAppPoolStateToModel(ctx, plan.RecyclingSchedule, state)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				m.Timeouts = plan.Timeouts
				m.Name = plan.Name
				m.ID = types.StringValue(name)
				m.IdentityPasswordWOVersion = plan.IdentityPasswordWOVersion
				resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
			}
		}
		addIISAppPoolDiag(&resp.Diagnostics, "Error creating Windows IIS application pool", err)
		return
	}
	if state == nil {
		resp.Diagnostics.AddError(
			"Windows IIS application pool not found",
			fmt.Sprintf("Application pool %q does not exist on the target host.", name),
		)
		return
	}

	m, diags := iisAppPoolStateToModel(ctx, plan.RecyclingSchedule, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Preserve the user-configured per-operation timeouts, the ForceNew
	// identity and the rotation counter: the projection covers only
	// host-observed fields (the WriteOnly password is never in state), and
	// Set overwrites the full state.
	m.Timeouts = plan.Timeouts
	m.Name = plan.Name
	m.ID = types.StringValue(name)
	m.IdentityPasswordWOVersion = plan.IdentityPasswordWOVersion
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live pool. A pool deleted
// out-of-band removes the resource from state; the password is never
// returned (identity_password_wo stays null, the version is preserved).
func (r *windowsIISAppPoolResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsIISAppPoolModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, iisAppPoolDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	name := state.Name.ValueString()
	tflog.Debug(ctx, "Reading Windows IIS application pool", map[string]any{
		"name": name,
	})

	observed, err := r.pool.Read(ctx, name)
	if err != nil {
		addIISAppPoolDiag(&resp.Diagnostics, "Error reading Windows IIS application pool", err)
		return
	}
	if observed == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	m, diags := iisAppPoolStateToModel(ctx, state.RecyclingSchedule, observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.Timeouts = state.Timeouts
	m.Name = state.Name
	m.ID = state.ID
	m.IdentityPasswordWOVersion = state.IdentityPasswordWOVersion
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place changes: only configured attributes that changed
// since the prior state are sent (plus the password, and only when
// identity_password_wo_version changed). Switching to a SpecificUser
// identity without bumping the version fails closed instead of leaving the
// pool with a blank credential. Recycling the pool is IIS' own behavior on
// config change; no explicit recycle is issued.
func (r *windowsIISAppPoolResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior, config windowsIISAppPoolModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, iisAppPoolDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// name is ForceNew so it never changes here.
	name := plan.Name.ValueString()
	tflog.Debug(ctx, "Updating Windows IIS application pool", map[string]any{
		"name":                         name,
		"identity_password_wo_version": plan.IdentityPasswordWOVersion.ValueInt64(),
	})

	settings, diags := planToIISAppPoolDelta(ctx, plan, prior)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Password rotation is version-gated: the WriteOnly value is null in
	// state, so only a version bump between prior state and plan re-sends
	// the configured secret.
	password := ""
	if iisAppPoolPasswordVersionChanged(plan, prior) {
		password = effectiveIISAppPoolPassword(plan, config)
		if password == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("identity_password_wo_version"),
				"identity_password_wo_version changed but no password supplied",
				"`identity_password_wo_version` changed but `identity_password_wo` is not configured. "+
					"Provide a non-empty value (fail-closed: the stored credential is never blanked).",
			)
			return
		}
	}

	// Fail closed when the update newly requires a credential: adopting (or
	// re-pointing) a SpecificUser identity without re-sending the password
	// would leave the pool unable to start its workers.
	if plan.IdentityType.ValueString() == "SpecificUser" && password == "" &&
		(!plan.IdentityType.Equal(prior.IdentityType) || !plan.IdentityUsername.Equal(prior.IdentityUsername)) {
		resp.Diagnostics.AddAttributeError(
			path.Root("identity_password_wo_version"),
			"SpecificUser identity change requires a password rotation",
			"The pool identity changed to (or re-pointed within) SpecificUser without a new "+
				"`identity_password_wo_version`. Bump the version and set `identity_password_wo` so the "+
				"new identity receives its credential.",
		)
		return
	}

	if !settings.IISAppPoolConfigured() && password == "" {
		// Nothing changed: refresh from the host instead of issuing a
		// no-op write.
		observed, err := r.pool.Read(ctx, name)
		if err != nil {
			addIISAppPoolDiag(&resp.Diagnostics, "Error updating Windows IIS application pool", err)
			return
		}
		if observed == nil {
			resp.Diagnostics.AddError(
				"Windows IIS application pool not found",
				fmt.Sprintf("Application pool %q does not exist on the target host.", name),
			)
			return
		}
		m, diags := iisAppPoolStateToModel(ctx, plan.RecyclingSchedule, observed)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		m.Timeouts = plan.Timeouts
		m.Name = plan.Name
		m.ID = prior.ID
		m.IdentityPasswordWOVersion = plan.IdentityPasswordWOVersion
		resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
		return
	}

	observed, err := r.pool.Update(ctx, winclient.IISAppPoolInput{
		Name:     name,
		Settings: settings,
		Password: password,
	})
	if err != nil {
		// Partial failure (ADR-0012): persist the observed state so the
		// resource keeps its partial state rather than staying at prior
		// state. A nil state stays error-only. The rotation marker comes
		// from prior state: a failed rotation must not advance the stored
		// version marker or a retry would no longer diff.
		if observed != nil {
			m, diags := iisAppPoolStateToModel(ctx, plan.RecyclingSchedule, observed)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				m.Timeouts = plan.Timeouts
				m.Name = plan.Name
				m.ID = prior.ID
				m.IdentityPasswordWOVersion = prior.IdentityPasswordWOVersion
				resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
			}
		}
		addIISAppPoolDiag(&resp.Diagnostics, "Error updating Windows IIS application pool", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"Windows IIS application pool not found",
			fmt.Sprintf("Application pool %q does not exist on the target host.", name),
		)
		return
	}

	m, diags := iisAppPoolStateToModel(ctx, plan.RecyclingSchedule, observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.Timeouts = plan.Timeouts
	m.Name = plan.Name
	m.ID = prior.ID
	m.IdentityPasswordWOVersion = plan.IdentityPasswordWOVersion
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the pool. When sites or applications still reference it,
// the delete is refused with in_use listing them; a pool already gone
// out-of-band is already absent (no error).
func (r *windowsIISAppPoolResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsIISAppPoolModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, iisAppPoolDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	name := state.Name.ValueString()
	tflog.Debug(ctx, "Deleting Windows IIS application pool", map[string]any{
		"name": name,
	})

	if err := r.pool.Delete(ctx, name); err != nil {
		addIISAppPoolDiag(&resp.Diagnostics, "Error deleting Windows IIS application pool", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing pool by name. The password cannot be
// imported (documented): after import, set identity_password_wo together
// with a fresh identity_password_wo_version before the next apply when the
// pool uses a SpecificUser identity. The schedule starts unmanaged (null):
// declare it to take that collection over.
func (r *windowsIISAppPoolResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if err := winclient.ValidateIISAppPoolName(name); err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID %q is not a valid application pool name: %s.", req.ID, err),
		)
		return
	}

	tflog.Debug(ctx, "Importing Windows IIS application pool", map[string]any{
		"name": name,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, iisAppPoolDefaultTimeout)
	defer cancel()

	observed, err := r.pool.Read(ctx, name)
	if err != nil {
		addIISAppPoolDiag(&resp.Diagnostics, "Error importing Windows IIS application pool", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"Windows IIS application pool not found",
			fmt.Sprintf("Application pool %q does not exist on the target host.", name),
		)
		return
	}

	m, diags := iisAppPoolStateToModel(ctx, types.SetNull(types.StringType), observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by State.Set — use a typed null instead (the
	// subsequent Read fills in the configured values).
	m.Timeouts = iisAppPoolNullTimeouts()
	m.Name = types.StringValue(observed.Name)
	m.ID = types.StringValue(observed.Name)
	// Import starts with the schedule unmanaged (null): declaring it takes
	// the collection over authoritatively.
	m.RecyclingSchedule = types.SetNull(types.StringType)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helpers: settings projection (partial management)
// ---------------------------------------------------------------------------

// modelToIISAppPoolSettings converts a Terraform model to an
// IISAppPoolSettings delta: null or unknown attributes stay nil and are
// never sent to the host. Optional+Computed attributes not configured are
// Unknown in the plan during Create, so Unknown is skipped (never sent)
// rather than aborting.
func modelToIISAppPoolSettings(ctx context.Context, m windowsIISAppPoolModel) (winclient.IISAppPoolSettings, diag.Diagnostics) {
	var diags diag.Diagnostics
	var s winclient.IISAppPoolSettings

	strPtr := func(st types.String) *string {
		if st.IsNull() || st.IsUnknown() {
			return nil
		}
		v := st.ValueString()
		return &v
	}
	boolPtr := func(b types.Bool) *bool {
		if b.IsNull() || b.IsUnknown() {
			return nil
		}
		v := b.ValueBool()
		return &v
	}
	intPtr := func(n types.Int64) *int64 {
		if n.IsNull() || n.IsUnknown() {
			return nil
		}
		v := n.ValueInt64()
		return &v
	}

	s.ManagedRuntimeVersion = strPtr(m.ManagedRuntimeVersion)
	s.ManagedPipelineMode = strPtr(m.ManagedPipelineMode)
	s.Enable32BitAppOnWin64 = boolPtr(m.Enable32BitAppOnWin64)
	s.StartMode = strPtr(m.StartMode)
	s.AutoStart = boolPtr(m.AutoStart)
	s.QueueLength = intPtr(m.QueueLength)
	s.IdentityType = strPtr(m.IdentityType)
	s.IdentityUsername = strPtr(m.IdentityUsername)
	s.LoadUserProfile = boolPtr(m.LoadUserProfile)
	s.IdleTimeoutMinutes = intPtr(m.IdleTimeoutMinutes)
	s.IdleTimeoutAction = strPtr(m.IdleTimeoutAction)
	s.MaxProcesses = intPtr(m.MaxProcesses)
	s.RecyclingPeriodicRestartMinutes = intPtr(m.RecyclingPeriodicRestartMinutes)
	s.RecyclingPrivateMemoryKB = intPtr(m.RecyclingPrivateMemoryKB)
	s.RapidFailProtection = boolPtr(m.RapidFailProtection)
	s.CPULimitPercent = intPtr(m.CPULimitPercent)
	s.CPUAction = strPtr(m.CPUAction)
	s.State = strPtr(m.State)

	// An Unknown schedule is skipped (never sent), like every other
	// Optional+Computed attribute that is not configured in the plan.
	if !m.RecyclingSchedule.IsNull() && !m.RecyclingSchedule.IsUnknown() {
		var entries []string
		diags.Append(m.RecyclingSchedule.ElementsAs(ctx, &entries, false)...)
		if diags.HasError() {
			return winclient.IISAppPoolSettings{}, diags
		}
		if entries == nil {
			entries = []string{}
		}
		s.RecyclingSchedule = entries
		s.RecyclingScheduleSet = true
	}

	return s, diags
}

// planToIISAppPoolDelta narrows the full plan projection to only the
// configured attributes that changed since the prior state: unchanged values
// (including unconfigured attributes retaining their observed prior values)
// are nilled so the host write touches only what drifted.
func planToIISAppPoolDelta(ctx context.Context, plan, prior windowsIISAppPoolModel) (winclient.IISAppPoolSettings, diag.Diagnostics) {
	s, diags := modelToIISAppPoolSettings(ctx, plan)
	if diags.HasError() {
		return winclient.IISAppPoolSettings{}, diags
	}

	changedStr := func(p, o types.String, v **string) {
		if *v != nil && p.Equal(o) {
			*v = nil
		}
	}
	changedBool := func(p, o types.Bool, v **bool) {
		if *v != nil && p.Equal(o) {
			*v = nil
		}
	}
	changedInt := func(p, o types.Int64, v **int64) {
		if *v != nil && p.Equal(o) {
			*v = nil
		}
	}

	changedStr(plan.ManagedRuntimeVersion, prior.ManagedRuntimeVersion, &s.ManagedRuntimeVersion)
	changedStr(plan.ManagedPipelineMode, prior.ManagedPipelineMode, &s.ManagedPipelineMode)
	changedBool(plan.Enable32BitAppOnWin64, prior.Enable32BitAppOnWin64, &s.Enable32BitAppOnWin64)
	changedStr(plan.StartMode, prior.StartMode, &s.StartMode)
	changedBool(plan.AutoStart, prior.AutoStart, &s.AutoStart)
	changedInt(plan.QueueLength, prior.QueueLength, &s.QueueLength)
	changedStr(plan.IdentityType, prior.IdentityType, &s.IdentityType)
	changedStr(plan.IdentityUsername, prior.IdentityUsername, &s.IdentityUsername)
	changedBool(plan.LoadUserProfile, prior.LoadUserProfile, &s.LoadUserProfile)
	changedInt(plan.IdleTimeoutMinutes, prior.IdleTimeoutMinutes, &s.IdleTimeoutMinutes)
	changedStr(plan.IdleTimeoutAction, prior.IdleTimeoutAction, &s.IdleTimeoutAction)
	changedInt(plan.MaxProcesses, prior.MaxProcesses, &s.MaxProcesses)
	changedInt(plan.RecyclingPeriodicRestartMinutes, prior.RecyclingPeriodicRestartMinutes, &s.RecyclingPeriodicRestartMinutes)
	changedInt(plan.RecyclingPrivateMemoryKB, prior.RecyclingPrivateMemoryKB, &s.RecyclingPrivateMemoryKB)
	changedBool(plan.RapidFailProtection, prior.RapidFailProtection, &s.RapidFailProtection)
	changedInt(plan.CPULimitPercent, prior.CPULimitPercent, &s.CPULimitPercent)
	changedStr(plan.CPUAction, prior.CPUAction, &s.CPUAction)
	changedStr(plan.State, prior.State, &s.State)

	if s.RecyclingScheduleSet && plan.RecyclingSchedule.Equal(prior.RecyclingSchedule) {
		s.RecyclingSchedule = nil
		s.RecyclingScheduleSet = false
	}

	return s, diags
}

// effectiveIISAppPoolPassword returns the SpecificUser plaintext to use for
// Create / Update. The WriteOnly value is null in the plan handed to
// ApplyResourceChange, so it must be read from config (windows_local_user
// password_wo precedent); the plan value is still consulted as a fallback
// for callers that bypass Config (unit tests driving Plan only). The secret
// itself is never logged.
func effectiveIISAppPoolPassword(plan, config windowsIISAppPoolModel) string {
	if !config.IdentityPasswordWO.IsNull() && !config.IdentityPasswordWO.IsUnknown() {
		if v := config.IdentityPasswordWO.ValueString(); v != "" {
			return v
		}
	}
	if !plan.IdentityPasswordWO.IsNull() && !plan.IdentityPasswordWO.IsUnknown() {
		if v := plan.IdentityPasswordWO.ValueString(); v != "" {
			return v
		}
	}
	return ""
}

// iisAppPoolPasswordVersionChanged reports whether
// identity_password_wo_version changed between prior state and plan.
// Unknown values (first apply, import paths) never count as a change:
// Int64 Equal returns false when either side is unknown, which would
// otherwise trigger a spurious rotation.
func iisAppPoolPasswordVersionChanged(plan, prior windowsIISAppPoolModel) bool {
	if plan.IdentityPasswordWOVersion.IsUnknown() || prior.IdentityPasswordWOVersion.IsUnknown() {
		return false
	}
	return !plan.IdentityPasswordWOVersion.Equal(prior.IdentityPasswordWOVersion)
}

// ---------------------------------------------------------------------------
// Helpers: state projection, timeouts, diagnostics
// ---------------------------------------------------------------------------

// iisAppPoolTimeoutsOpts declares which per-operation timeouts the resource exposes.
var iisAppPoolTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// iisAppPoolNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func iisAppPoolNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if iisAppPoolTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if iisAppPoolTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if iisAppPoolTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if iisAppPoolTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// iisAppPoolStateToModel projects an observed IISAppPoolState into a
// Terraform model. declaredSchedule is the prior (plan on write paths,
// state on read paths) recycling_schedule value: a null declared set means
// unmanaged and stays null, otherwise the observed list is returned verbatim
// so the plan shows drift. The WriteOnly password is never projected (it
// stays null); the caller preserves the version counter.
func iisAppPoolStateToModel(ctx context.Context, declaredSchedule types.Set, s *winclient.IISAppPoolState) (windowsIISAppPoolModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	var sched types.Set
	if declaredSchedule.IsNull() || declaredSchedule.IsUnknown() {
		sched = types.SetNull(types.StringType)
	} else {
		observed := s.RecyclingSchedule
		if observed == nil {
			observed = []string{}
		}
		set, d := types.SetValueFrom(ctx, types.StringType, observed)
		diags.Append(d...)
		if d.HasError() {
			return windowsIISAppPoolModel{}, diags
		}
		sched = set
	}

	return windowsIISAppPoolModel{
		ID:                              types.StringValue(s.Name),
		Name:                            types.StringValue(s.Name),
		ManagedRuntimeVersion:           types.StringValue(s.ManagedRuntimeVersion),
		ManagedPipelineMode:             types.StringValue(s.ManagedPipelineMode),
		Enable32BitAppOnWin64:           types.BoolValue(s.Enable32BitAppOnWin64),
		StartMode:                       types.StringValue(s.StartMode),
		AutoStart:                       types.BoolValue(s.AutoStart),
		QueueLength:                     types.Int64Value(s.QueueLength),
		IdentityType:                    types.StringValue(s.IdentityType),
		IdentityUsername:                types.StringValue(s.IdentityUsername),
		LoadUserProfile:                 types.BoolValue(s.LoadUserProfile),
		IdleTimeoutMinutes:              types.Int64Value(s.IdleTimeoutMinutes),
		IdleTimeoutAction:               types.StringValue(s.IdleTimeoutAction),
		MaxProcesses:                    types.Int64Value(s.MaxProcesses),
		RecyclingPeriodicRestartMinutes: types.Int64Value(s.RecyclingPeriodicRestartMinutes),
		RecyclingSchedule:               sched,
		RecyclingPrivateMemoryKB:        types.Int64Value(s.RecyclingPrivateMemoryKB),
		RapidFailProtection:             types.BoolValue(s.RapidFailProtection),
		CPULimitPercent:                 types.Int64Value(s.CPULimitPercent),
		CPUAction:                       types.StringValue(s.CPUAction),
		State:                           types.StringValue(s.State),
	}, diags
}

// addIISAppPoolDiag appends a diagnostic from an app-pool client error.
// In-use refusals keep their full guidance (naming the referencing sites);
// other kinds are enriched with context fields when available. The
// SpecificUser password can never appear: it travels on stdin and is
// excluded from every error message and context map by construction.
func addIISAppPoolDiag(d *diag.Diagnostics, summary string, err error) {
	var ae *winclient.IISAppPoolError
	if errors.As(err, &ae) {
		if ae.Kind == winclient.IISAppPoolErrorInUse {
			d.AddError(summary+" [in_use]", ae.Message)
			return
		}
		if ae.Kind == winclient.IISAppPoolErrorIISNotInstalled {
			d.AddError(summary+" [iis_not_installed]", ae.Message)
			return
		}
		detail := ae.Message
		if len(ae.Context) > 0 {
			var parts []string
			for k, v := range ae.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if ae.Cause != nil {
			detail += "\n\nCause: " + ae.Cause.Error()
		}
		d.AddError(summary+" ["+ae.Kind+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
