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

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Metadata, Schema definition and ConfigValidators. Split from resource_windows_iis_app_pool.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsIISAppPoolResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iis_app_pool"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_iis_app_pool resource.
func (r *windowsIISAppPoolResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsIISAppPoolSchemaDefinition(ctx)
}

// windowsIISAppPoolSchemaDefinition returns the complete TPF schema for
// windows_iis_app_pool. `name` is Required + ForceNew (the id); every other
// setting is Optional+Computed (partial management: only configured
// attributes are sent to the host).
func windowsIISAppPoolSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages an IIS application pool on a remote Windows host via SSH and " +
			"PowerShell (`WebAdministration` module: `New-WebAppPool`, `Get-ItemProperty` / " +
			"`Set-ItemProperty IIS:\\AppPools\\<name>`, `Remove-WebAppPool`, `Start-WebAppPool` / " +
			"`Stop-WebAppPool`).\n\n" +
			"Only the attributes configured in Terraform are written; every other setting on the host is " +
			"left untouched and undiffed (unconfigured attributes reflect the observed value). The runtime " +
			"`state` (`Started` / `Stopped`) is enforced only when configured.\n\n" +
			"A `SpecificUser` identity needs `identity_username` plus the WriteOnly `identity_password_wo`, " +
			"which travels to the host on stdin and is never persisted in state; rotation is driven " +
			"exclusively by `identity_password_wo_version`. After `terraform import` the password cannot " +
			"be recovered: set it together with a fresh version before the next apply.\n\n" +
			"Requires IIS on the target host: install it with the `windows_feature` resource (`Web-Server`; " +
			"add `Web-Mgmt-Console` / `Web-Scripting-Tools` for the `WebAdministration` module on Server Core).\n\n" +
			"**Partial failures:** if creation fails after the pool was already registered in IIS, " +
			"the provider persists the observed state before reporting the error, so the resource is marked " +
			"tainted. If update fails after IIS applied part of the change, the provider saves the observed " +
			"partial state before reporting the error, restoring `identity_password_wo_version` from prior " +
			"state so a failed rotation still diffs on retry. Fix the cause and run `terraform apply` again " +
			"to reconcile.\n\n" +
			"A nil state on error does not guarantee nothing was created: a failure that returns no state " +
			"leaves an orphaned pool that must be removed with `Remove-WebAppPool` or re-adopted " +
			"with `terraform import`.\n\n" +
			"Import format: `<pool name>`.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier. Set to the application pool name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"name": schema.StringAttribute{
				Required: true,
				Description: "Application pool name. 1-64 characters; must not contain `/ \\ [ ] : ; , ? * \" < > |` " +
					"and must not have leading or trailing spaces. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					iisAppPoolNameValidator{},
				},
			},

			"managed_runtime_version": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "CLR version for the pool (`\"\"` means No Managed Code, `v2.0`, `v4.0`).",
				Validators: []validator.String{
					stringvalidator.OneOf("", "v2.0", "v4.0"),
				},
			},

			"managed_pipeline_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Managed pipeline mode. One of `Integrated`, `Classic`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Integrated", "Classic"),
				},
			},

			"enable_32bit_app_on_win64": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether 32-bit applications run on 64-bit Windows (`enable32BitAppOnWin64`).",
			},

			"start_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Pool start mode. One of `OnDemand`, `AlwaysRunning`.",
				Validators: []validator.String{
					stringvalidator.OneOf("OnDemand", "AlwaysRunning"),
				},
			},

			"auto_start": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether the pool starts automatically (`autoStart`).",
			},

			"queue_length": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Description: "HTTP.sys request queue length (`queueLength`, 10-65535).",
				Validators: []validator.Int64{
					int64validator.Between(10, 65535),
				},
			},

			"identity_type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Pool identity (`processModel.identityType`). One of `ApplicationPoolIdentity`, `LocalSystem`, `LocalService`, `NetworkService`, `SpecificUser`. `LocalSystem` runs with full machine privileges: plan warns. `SpecificUser` additionally requires `identity_username` and `identity_password_wo`.",
				Validators: []validator.String{
					stringvalidator.OneOf("ApplicationPoolIdentity", "LocalSystem", "LocalService", "NetworkService", "SpecificUser"),
				},
			},

			"identity_username": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Account for a `SpecificUser` identity (`processModel.userName`, e.g. `CONTOSO\\svc-web`). Required when `identity_type = \"SpecificUser\"`; inert otherwise.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.RegexMatches(iisAppPoolUsernameRe, iisAppPoolUsernameDesc),
				},
			},

			"identity_password_wo": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				Validators: []validator.String{
					secretNoLineBreakValidator{},
					// A WriteOnly value cannot be diffed, so the version
					// counter is what drives rotation and is mandatory
					// (windows_local_user password_wo precedent).
					stringvalidator.AlsoRequires(path.MatchRoot("identity_password_wo_version")),
				},
				Description: "Write-only password for a `SpecificUser` identity (TPF WriteOnly). " +
					"Sent to the host on stdin — never in the script body, state or logs — " +
					"and re-sent only when `identity_password_wo_version` changes. " +
					"Required when `identity_type = \"SpecificUser\"`. " +
					"The value must not contain carriage return or line feed characters " +
					"(rejected at plan time): secrets are read with `ReadLine()`, so anything from the " +
					"first line break on would be silently truncated. If the value comes from `file()`, wrap " +
					"it with `trimspace()` to strip the trailing newline.",
			},

			"identity_password_wo_version": schema.Int64Attribute{
				Optional: true,
				Description: "Monotonically increasing version counter for the `SpecificUser` password. " +
					"When this value changes between plan and apply, the provider re-sends " +
					"`identity_password_wo` to IIS. Conventionally starts at 1. Must be a positive integer if set.",
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},

			"load_user_profile": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether IIS loads the user profile for the pool identity (`processModel.loadUserProfile`).",
			},

			"idle_timeout_minutes": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Description: "Idle timeout in minutes (`processModel.idleTimeout`, 0-43200; `0` disables the timeout).",
				Validators: []validator.Int64{
					int64validator.Between(0, 43200),
				},
			},

			"idle_timeout_action": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Action when the idle timeout elapses. One of `Terminate`, `Suspend`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Terminate", "Suspend"),
				},
			},

			"max_processes": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Description: "Maximum worker processes (`processModel.maxProcesses`, 0-2147483647; `0` is NUMA aware).",
				Validators: []validator.Int64{
					int64validator.Between(0, 2147483647),
				},
			},

			"recycling_periodic_restart_minutes": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Description: "Periodic restart interval in minutes (`recycling.periodicRestart.time`; `0` disables the interval restart).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},

			"recycling_schedule": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
				Description: "Daily recycle schedule (`recycling.periodicRestart.schedule`), each entry `HH:MM:SS` (24h). Null means unmanaged; an empty set clears the schedule (full replace of the collection).",
				Validators: []validator.Set{
					iisAppPoolScheduleValidator{},
				},
			},

			"recycling_private_memory_kb": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Description: "Private-memory recycle threshold in kilobytes (`recycling.periodicRestart.privateMemory`).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},

			"rapid_fail_protection": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
				Description: "Whether rapid-fail protection is enabled (`failure.rapidFailProtection`).",
			},

			"cpu_limit_percent": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				Description: "CPU limit in whole percent (`cpu.limit`, 0-100; converted ×1000 server-side).",
				Validators: []validator.Int64{
					int64validator.Between(0, 100),
				},
			},

			"cpu_action": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Action when the CPU limit is exceeded. One of `NoAction`, `KillW3wp`, `Throttle`, `ThrottleUnderLoad`.",
				Validators: []validator.String{
					stringvalidator.OneOf("NoAction", "KillW3wp", "Throttle", "ThrottleUnderLoad"),
				},
			},

			"state": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Runtime state of the pool. One of `Started`, `Stopped`. Enforced only when configured (`Start-WebAppPool` / `Stop-WebAppPool`).",
				Validators: []validator.String{
					stringvalidator.OneOf("Started", "Stopped"),
				},
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// iisAppPoolDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, iisAppPoolTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// ConfigValidators returns the resource-level cross-field validators:
//   - iisAppPoolIdentityValidator: SpecificUser requires identity_username
//     and identity_password_wo; LocalSystem warns.
func (r *windowsIISAppPoolResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		iisAppPoolIdentityValidator{},
	}
}
