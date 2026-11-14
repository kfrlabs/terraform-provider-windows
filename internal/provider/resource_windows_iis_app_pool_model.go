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
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Plan/state model. Split from resource_windows_iis_app_pool.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsIISAppPoolModel is the Terraform state/plan model for
// windows_iis_app_pool. Every tfsdk tag matches an attribute key in
// windowsIISAppPoolSchemaDefinition.
type windowsIISAppPoolModel struct {
	ID                              types.String   `tfsdk:"id"`
	Name                            types.String   `tfsdk:"name"`
	ManagedRuntimeVersion           types.String   `tfsdk:"managed_runtime_version"`
	ManagedPipelineMode             types.String   `tfsdk:"managed_pipeline_mode"`
	Enable32BitAppOnWin64           types.Bool     `tfsdk:"enable_32bit_app_on_win64"`
	StartMode                       types.String   `tfsdk:"start_mode"`
	AutoStart                       types.Bool     `tfsdk:"auto_start"`
	QueueLength                     types.Int64    `tfsdk:"queue_length"`
	IdentityType                    types.String   `tfsdk:"identity_type"`
	IdentityUsername                types.String   `tfsdk:"identity_username"`
	IdentityPasswordWO              types.String   `tfsdk:"identity_password_wo"`
	IdentityPasswordWOVersion       types.Int64    `tfsdk:"identity_password_wo_version"`
	LoadUserProfile                 types.Bool     `tfsdk:"load_user_profile"`
	IdleTimeoutMinutes              types.Int64    `tfsdk:"idle_timeout_minutes"`
	IdleTimeoutAction               types.String   `tfsdk:"idle_timeout_action"`
	MaxProcesses                    types.Int64    `tfsdk:"max_processes"`
	RecyclingPeriodicRestartMinutes types.Int64    `tfsdk:"recycling_periodic_restart_minutes"`
	RecyclingSchedule               types.Set      `tfsdk:"recycling_schedule"`
	RecyclingPrivateMemoryKB        types.Int64    `tfsdk:"recycling_private_memory_kb"`
	RapidFailProtection             types.Bool     `tfsdk:"rapid_fail_protection"`
	CPULimitPercent                 types.Int64    `tfsdk:"cpu_limit_percent"`
	CPUAction                       types.String   `tfsdk:"cpu_action"`
	State                           types.String   `tfsdk:"state"`
	Timeouts                        timeouts.Value `tfsdk:"timeouts"`
}
