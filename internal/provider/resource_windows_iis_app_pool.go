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
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
				Optional:    true,
				Computed:    true,
				Description: "CLR version for the pool (`\"\"` means No Managed Code, `v2.0`, `v4.0`).",
				Validators: []validator.String{
					stringvalidator.OneOf("", "v2.0", "v4.0"),
				},
			},

			"managed_pipeline_mode": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Managed pipeline mode. One of `Integrated`, `Classic`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Integrated", "Classic"),
				},
			},

			"enable_32bit_app_on_win64": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether 32-bit applications run on 64-bit Windows (`enable32BitAppOnWin64`).",
			},

			"start_mode": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Pool start mode. One of `OnDemand`, `AlwaysRunning`.",
				Validators: []validator.String{
					stringvalidator.OneOf("OnDemand", "AlwaysRunning"),
				},
			},

			"auto_start": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the pool starts automatically (`autoStart`).",
			},

			"queue_length": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "HTTP.sys request queue length (`queueLength`, 10-65535).",
				Validators: []validator.Int64{
					int64validator.Between(10, 65535),
				},
			},

			"identity_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Pool identity (`processModel.identityType`). One of `ApplicationPoolIdentity`, `LocalSystem`, `LocalService`, `NetworkService`, `SpecificUser`. `LocalSystem` runs with full machine privileges: plan warns. `SpecificUser` additionally requires `identity_username` and `identity_password_wo`.",
				Validators: []validator.String{
					stringvalidator.OneOf("ApplicationPoolIdentity", "LocalSystem", "LocalService", "NetworkService", "SpecificUser"),
				},
			},

			"identity_username": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Account for a `SpecificUser` identity (`processModel.userName`, e.g. `CONTOSO\\svc-web`). Required when `identity_type = \"SpecificUser\"`; inert otherwise.",
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
				Optional:    true,
				Computed:    true,
				Description: "Whether IIS loads the user profile for the pool identity (`processModel.loadUserProfile`).",
			},

			"idle_timeout_minutes": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Idle timeout in minutes (`processModel.idleTimeout`, 0-43200; `0` disables the timeout).",
				Validators: []validator.Int64{
					int64validator.Between(0, 43200),
				},
			},

			"idle_timeout_action": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Action when the idle timeout elapses. One of `Terminate`, `Suspend`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Terminate", "Suspend"),
				},
			},

			"max_processes": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Maximum worker processes (`processModel.maxProcesses`, 0-2147483647; `0` is NUMA aware).",
				Validators: []validator.Int64{
					int64validator.Between(0, 2147483647),
				},
			},

			"recycling_periodic_restart_minutes": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Periodic restart interval in minutes (`recycling.periodicRestart.time`; `0` disables the interval restart).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},

			"recycling_schedule": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Daily recycle schedule (`recycling.periodicRestart.schedule`), each entry `HH:MM:SS` (24h). Null means unmanaged; an empty set clears the schedule (full replace of the collection).",
				Validators: []validator.Set{
					iisAppPoolScheduleValidator{},
				},
			},

			"recycling_private_memory_kb": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Private-memory recycle threshold in kilobytes (`recycling.periodicRestart.privateMemory`).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},

			"rapid_fail_protection": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether rapid-fail protection is enabled (`failure.rapidFailProtection`).",
			},

			"cpu_limit_percent": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "CPU limit in whole percent (`cpu.limit`, 0-100; converted ×1000 server-side).",
				Validators: []validator.Int64{
					int64validator.Between(0, 100),
				},
			},

			"cpu_action": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Action when the CPU limit is exceeded. One of `NoAction`, `KillW3wp`, `Throttle`, `ThrottleUnderLoad`.",
				Validators: []validator.String{
					stringvalidator.OneOf("NoAction", "KillW3wp", "Throttle", "ThrottleUnderLoad"),
				},
			},

			"state": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
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
// Validators
// ---------------------------------------------------------------------------

// iisAppPoolNameValidator enforces the pool-name rules at plan time
// (mirroring winclient.ValidateIISAppPoolName): no forbidden characters and
// no leading/trailing spaces. Length is covered by LengthBetween.
type iisAppPoolNameValidator struct{}

func (v iisAppPoolNameValidator) Description(_ context.Context) string {
	return "Application pool name must not contain / \\ [ ] : ; , ? * \" < > | and must not have leading or trailing spaces."
}

func (v iisAppPoolNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisAppPoolNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if strings.TrimSpace(val) != val {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid application pool name",
			fmt.Sprintf("Application pool name %q must not have leading or trailing spaces.", val),
		)
		return
	}
	if strings.ContainsAny(val, `/\[]:;,?*"<>|`) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid application pool name",
			fmt.Sprintf("Application pool name %q must not contain any of / \\ [ ] : ; , ? * \" < > |.", val),
		)
	}
}

// iisAppPoolScheduleRe matches a 24h HH:MM:SS entry.
var iisAppPoolScheduleRe = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d:[0-5]\d$`)

// iisAppPoolScheduleValidator validates every recycling_schedule entry as
// HH:MM:SS (24h). Null and unknown sets are skipped; unknown elements defer
// to apply-time handling.
type iisAppPoolScheduleValidator struct{}

func (v iisAppPoolScheduleValidator) Description(_ context.Context) string {
	return "Each recycling schedule entry must be HH:MM:SS (24h)."
}

func (v iisAppPoolScheduleValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisAppPoolScheduleValidator) ValidateSet(ctx context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var entries []types.String
	diags := req.ConfigValue.ElementsAs(ctx, &entries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, e := range entries {
		if e.IsNull() || e.IsUnknown() {
			continue
		}
		if !iisAppPoolScheduleRe.MatchString(e.ValueString()) {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid recycling schedule entry",
				fmt.Sprintf("Recycling schedule entry %q must be HH:MM:SS (24h), e.g. \"03:00:00\".", e.ValueString()),
			)
		}
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

// iisAppPoolIdentityValidator enforces the SpecificUser credential contract
// at plan time and warns on the LocalSystem identity.
type iisAppPoolIdentityValidator struct{}

func (v iisAppPoolIdentityValidator) Description(_ context.Context) string {
	return "Requires identity_username and identity_password_wo when identity_type is SpecificUser; warns on LocalSystem."
}

func (v iisAppPoolIdentityValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisAppPoolIdentityValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var identityType types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_type"), &identityType)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if identityType.IsNull() || identityType.IsUnknown() {
		return
	}
	switch identityType.ValueString() {
	case "LocalSystem":
		resp.Diagnostics.AddAttributeWarning(
			path.Root("identity_type"),
			"Application pool runs as LocalSystem",
			"identity_type = \"LocalSystem\" runs the pool's worker processes with full machine privileges. "+
				"Prefer \"ApplicationPoolIdentity\" (the default, least privilege) unless the workload genuinely "+
				"requires SYSTEM.",
		)
	case "SpecificUser":
		var username types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_username"), &username)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if username.IsNull() || (!username.IsUnknown() && username.ValueString() == "") {
			if !username.IsUnknown() {
				resp.Diagnostics.AddAttributeError(
					path.Root("identity_username"),
					"identity_username is required for SpecificUser",
					"identity_type = \"SpecificUser\" requires identity_username (e.g. \"CONTOSO\\svc-web\").",
				)
			}
		}
		var password types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_password_wo"), &password)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if password.IsNull() || (!password.IsUnknown() && password.ValueString() == "") {
			if !password.IsUnknown() {
				resp.Diagnostics.AddAttributeError(
					path.Root("identity_password_wo"),
					"identity_password_wo is required for SpecificUser",
					"identity_type = \"SpecificUser\" requires identity_password_wo together with "+
						"identity_password_wo_version (rotation counter).",
				)
			}
		}
	default:
		// A username or password configured without SpecificUser is inert:
		// IIS only consumes the credential for that identity type.
		var username types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_username"), &username)...)
		var password types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_password_wo"), &password)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if (!username.IsNull() && !username.IsUnknown() && username.ValueString() != "") ||
			(!password.IsNull() && !password.IsUnknown() && password.ValueString() != "") {
			resp.Diagnostics.AddAttributeWarning(
				path.Root("identity_type"),
				"Identity credential without SpecificUser",
				"identity_username / identity_password_wo are only consumed when identity_type = "+
					"\"SpecificUser\"; with the current identity type they are stored but inert.",
			)
		}
	}
}

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
		d.AddError(summary+" ["+string(ae.Kind)+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
