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
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsScheduledTaskResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsScheduledTaskResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsScheduledTaskResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsScheduledTaskResource)(nil)
)

// NewWindowsScheduledTaskResource is the constructor registered in provider.go.
func NewWindowsScheduledTaskResource() resource.Resource { return &windowsScheduledTaskResource{} }

// windowsScheduledTaskResource is the TPF resource for windows_scheduled_task.
type windowsScheduledTaskResource struct {
	client    *winclient.Client
	stClient  winclient.ScheduledTaskClient
}

// ---------------------------------------------------------------------------
// Attribute type maps (for types.Object / types.List creation)
// ---------------------------------------------------------------------------

var scheduledTaskPrincipalAttrTypes = map[string]attr.Type{
	"user_id":             types.StringType,
	"password":            types.StringType,
	"password_wo_version": types.Int64Type,
	"logon_type":          types.StringType,
	"run_level":           types.StringType,
}

var scheduledTaskActionAttrTypes = map[string]attr.Type{
	"execute":           types.StringType,
	"arguments":         types.StringType,
	"working_directory": types.StringType,
}

var scheduledTaskTriggerAttrTypes = map[string]attr.Type{
	"type":                 types.StringType,
	"enabled":              types.BoolType,
	"start_boundary":       types.StringType,
	"end_boundary":         types.StringType,
	"execution_time_limit": types.StringType,
	"delay":                types.StringType,
	"days_interval":        types.Int64Type,
	"days_of_week":         types.ListType{ElemType: types.StringType},
	"weeks_interval":       types.Int64Type,
	"user_id":              types.StringType,
	"subscription":         types.StringType,
}

var scheduledTaskSettingsAttrTypes = map[string]attr.Type{
	"allow_demand_start":             types.BoolType,
	"allow_hard_terminate":           types.BoolType,
	"start_when_available":           types.BoolType,
	"run_only_if_network_available":  types.BoolType,
	"execution_time_limit":           types.StringType,
	"multiple_instances":             types.StringType,
	"disallow_start_if_on_batteries": types.BoolType,
	"stop_if_going_on_batteries":     types.BoolType,
	"wake_to_run":                    types.BoolType,
	"run_only_if_idle":               types.BoolType,
}

// ---------------------------------------------------------------------------
// Model types
// ---------------------------------------------------------------------------

type windowsScheduledTaskPrincipalModel struct {
	UserID            types.String `tfsdk:"user_id"`
	Password          types.String `tfsdk:"password"`
	PasswordWoVersion types.Int64  `tfsdk:"password_wo_version"`
	LogonType         types.String `tfsdk:"logon_type"`
	RunLevel          types.String `tfsdk:"run_level"`
}

type windowsScheduledTaskActionModel struct {
	Execute          types.String `tfsdk:"execute"`
	Arguments        types.String `tfsdk:"arguments"`
	WorkingDirectory types.String `tfsdk:"working_directory"`
}

type windowsScheduledTaskTriggerModel struct {
	Type               types.String `tfsdk:"type"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	StartBoundary      types.String `tfsdk:"start_boundary"`
	EndBoundary        types.String `tfsdk:"end_boundary"`
	ExecutionTimeLimit types.String `tfsdk:"execution_time_limit"`
	Delay              types.String `tfsdk:"delay"`
	DaysInterval       types.Int64  `tfsdk:"days_interval"`
	DaysOfWeek         types.List   `tfsdk:"days_of_week"`
	WeeksInterval      types.Int64  `tfsdk:"weeks_interval"`
	UserID             types.String `tfsdk:"user_id"`
	Subscription       types.String `tfsdk:"subscription"`
}

type windowsScheduledTaskSettingsModel struct {
	AllowDemandStart           types.Bool   `tfsdk:"allow_demand_start"`
	AllowHardTerminate         types.Bool   `tfsdk:"allow_hard_terminate"`
	StartWhenAvailable         types.Bool   `tfsdk:"start_when_available"`
	RunOnlyIfNetworkAvailable  types.Bool   `tfsdk:"run_only_if_network_available"`
	ExecutionTimeLimit         types.String `tfsdk:"execution_time_limit"`
	MultipleInstances          types.String `tfsdk:"multiple_instances"`
	DisallowStartIfOnBatteries types.Bool   `tfsdk:"disallow_start_if_on_batteries"`
	StopIfGoingOnBatteries     types.Bool   `tfsdk:"stop_if_going_on_batteries"`
	WakeToRun                  types.Bool   `tfsdk:"wake_to_run"`
	RunOnlyIfIdle              types.Bool   `tfsdk:"run_only_if_idle"`
}

type windowsScheduledTaskModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Path           types.String `tfsdk:"path"`
	Description    types.String `tfsdk:"description"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	State          types.String `tfsdk:"state"`
	LastRunTime    types.String `tfsdk:"last_run_time"`
	LastTaskResult types.Int64  `tfsdk:"last_task_result"`
	NextRunTime    types.String `tfsdk:"next_run_time"`
	Principal      types.Object `tfsdk:"principal"`
	Actions        types.List   `tfsdk:"actions"`
	Triggers       types.List   `tfsdk:"triggers"`
	Settings       types.Object `tfsdk:"settings"`
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

var scheduledTaskNameRe = regexp.MustCompile(`^[^\\]{1,238}$`)

type scheduledTaskNameValidator struct{}

func (v scheduledTaskNameValidator) Description(_ context.Context) string {
	return "task name must not contain backslash and be 1-238 characters"
}
func (v scheduledTaskNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if !scheduledTaskNameRe.MatchString(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path,
			"Invalid task name",
			"Task name must not contain a backslash and must be 1–238 characters long.")
	}
}

var scheduledTaskPathRe = regexp.MustCompile(`^\\([A-Za-z0-9_\-. ]+\\)*$`)

type scheduledTaskPathValidator struct{}

func (v scheduledTaskPathValidator) Description(_ context.Context) string {
	return `task path must start and end with backslash (e.g. "\" or "\Custom\Sub\")`
}
func (v scheduledTaskPathValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskPathValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val != "\\" && !scheduledTaskPathRe.MatchString(val) {
		resp.Diagnostics.AddAttributeError(req.Path,
			"Invalid task path",
			`Task path must start and end with backslash (e.g. "\" or "\Custom\Sub\").`)
	}
}

// scheduledTaskPrincipalCrossFieldValidator enforces EC-4/EC-5 password rules.
type scheduledTaskPrincipalCrossFieldValidator struct{}

func (v scheduledTaskPrincipalCrossFieldValidator) Description(_ context.Context) string {
	return "validates principal password/logon_type mutual-exclusion (EC-4/EC-5)"
}
func (v scheduledTaskPrincipalCrossFieldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskPrincipalCrossFieldValidator) ValidateResource(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var model windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.Principal.IsNull() || model.Principal.IsUnknown() {
		return
	}
	var principal windowsScheduledTaskPrincipalModel
	resp.Diagnostics.Append(model.Principal.As(ctx, &principal, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})...)
	if resp.Diagnostics.HasError() {
		return
	}
	if principal.LogonType.IsNull() || principal.LogonType.IsUnknown() {
		return
	}
	logonType := principal.LogonType.ValueString()
	if logonType == "Password" && principal.Password.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("principal").AtName("password"),
			"Missing required attribute",
			`password is required when logon_type is "Password" (EC-4).`)
	}
	for _, forbidden := range []string{"Interactive", "S4U", "Group", "ServiceAccount"} {
		if logonType == forbidden && !principal.Password.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("principal").AtName("password"),
				"Conflicting attributes",
				fmt.Sprintf(`password must not be set when logon_type is %q (EC-5).`, logonType))
			break
		}
	}
}

// scheduledTaskTriggerCrossFieldValidator enforces EC-7 trigger type rules.
type scheduledTaskTriggerCrossFieldValidator struct{}

func (v scheduledTaskTriggerCrossFieldValidator) Description(_ context.Context) string {
	return "validates trigger type cross-field rules (EC-7)"
}
func (v scheduledTaskTriggerCrossFieldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskTriggerCrossFieldValidator) ValidateResource(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var model windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.Triggers.IsNull() || model.Triggers.IsUnknown() {
		return
	}
	var triggers []windowsScheduledTaskTriggerModel
	resp.Diagnostics.Append(model.Triggers.ElementsAs(ctx, &triggers, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for i, t := range triggers {
		trigPath := path.Root("triggers").AtListIndex(i)
		if t.Type.IsNull() || t.Type.IsUnknown() {
			continue
		}
		tt := t.Type.ValueString()
		if (tt == "Once" || tt == "Daily" || tt == "Weekly") && t.StartBoundary.IsNull() {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("start_boundary"),
				"Missing required attribute",
				fmt.Sprintf(`start_boundary is required when trigger type is %q (EC-7).`, tt))
		}
		if tt == "Weekly" {
			if t.DaysOfWeek.IsNull() || t.DaysOfWeek.IsUnknown() {
				resp.Diagnostics.AddAttributeError(trigPath.AtName("days_of_week"),
					"Missing required attribute", `days_of_week is required when trigger type is "Weekly" (EC-7).`)
			} else {
				var days []string
				resp.Diagnostics.Append(t.DaysOfWeek.ElementsAs(ctx, &days, false)...)
				if len(days) == 0 {
					resp.Diagnostics.AddAttributeError(trigPath.AtName("days_of_week"),
						"Invalid attribute value", `days_of_week must not be empty when trigger type is "Weekly" (EC-7).`)
				}
			}
		} else if !t.DaysOfWeek.IsNull() && !t.DaysOfWeek.IsUnknown() {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("days_of_week"),
				"Conflicting attribute",
				fmt.Sprintf(`days_of_week must not be set when trigger type is %q (EC-7).`, tt))
		}
		if !t.DaysInterval.IsNull() && !t.DaysInterval.IsUnknown() && tt != "Daily" {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("days_interval"),
				"Conflicting attribute",
				fmt.Sprintf(`days_interval is only valid for "Daily" triggers, got %q (EC-7).`, tt))
		}
		if !t.WeeksInterval.IsNull() && !t.WeeksInterval.IsUnknown() && tt != "Weekly" {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("weeks_interval"),
				"Conflicting attribute",
				fmt.Sprintf(`weeks_interval is only valid for "Weekly" triggers, got %q (EC-7).`, tt))
		}
		if !t.UserID.IsNull() && !t.UserID.IsUnknown() && tt != "AtLogon" {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("user_id"),
				"Conflicting attribute",
				fmt.Sprintf(`user_id (trigger-level) is only valid for "AtLogon" triggers, got %q (EC-7).`, tt))
		}
		if tt == "OnEvent" {
			if t.Subscription.IsNull() || t.Subscription.IsUnknown() || t.Subscription.ValueString() == "" {
				resp.Diagnostics.AddAttributeError(trigPath.AtName("subscription"),
					"Missing required attribute",
					`subscription (XPath query) is required when trigger type is "OnEvent" (EC-7).`)
			}
		} else if !t.Subscription.IsNull() && !t.Subscription.IsUnknown() {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("subscription"),
				"Conflicting attribute",
				fmt.Sprintf(`subscription must not be set when trigger type is %q (EC-7).`, tt))
		}
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsScheduledTaskResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scheduled_task"
}

// Schema returns the full TPF schema.
func (r *windowsScheduledTaskResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Windows Scheduled Task via WinRM + PowerShell (ScheduledTasks module, Windows 2012+).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "Composite ID `<TaskPath><TaskName>` (ADR-ST-2).",
			},
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{scheduledTaskNameValidator{}},
				MarkdownDescription: "Task leaf name. No backslash; max 238 chars. **ForceNew**.",
			},
			"path": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("\\"),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{scheduledTaskPathValidator{}},
				MarkdownDescription: `Task folder path (starts and ends with "\"). Defaults to "\". **ForceNew**.`,
			},
			"description": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{stringvalidator.LengthAtMost(2048)},
				MarkdownDescription: "Human-readable task description (max 2048 chars).",
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				MarkdownDescription: "Whether the task is enabled. Defaults to `true`.",
			},
			"state": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current operational state: Ready|Disabled|Running|Queued|Unknown.",
			},
			"last_run_time": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "RFC 3339 timestamp of last execution, or empty string.",
			},
			"last_task_result": schema.Int64Attribute{
				Computed: true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
				MarkdownDescription: "Win32 exit code of last execution (0=success).",
			},
			"next_run_time": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "RFC 3339 timestamp of next scheduled run, or empty string.",
			},
			"principal": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Security context. Omit for Windows default (SYSTEM/ServiceAccount).",
				Attributes: map[string]schema.Attribute{
					"user_id": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Default:  stringdefault.StaticString("SYSTEM"),
						MarkdownDescription: "Account identifier. Defaults to `\"SYSTEM\"`.",
					},
					"password": schema.StringAttribute{
						Optional:  true,
						Sensitive: true,
						MarkdownDescription: "Write-only account password (ADR-ST-3). Required when `logon_type=\"Password\"` (EC-4).",
					},
					"password_wo_version": schema.Int64Attribute{
						Optional: true,
						Computed: true,
						Default:  int64default.StaticInt64(0),
						Validators: []validator.Int64{int64validator.AtLeast(0)},
						PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
						MarkdownDescription: "Increment to rotate the password without task replacement (EC-6 / ADR-ST-3).",
					},
					"logon_type": schema.StringAttribute{
						Optional: true,
						Validators: []validator.String{
							stringvalidator.OneOf("Password", "S4U", "Interactive", "Group", "ServiceAccount", "InteractiveOrPassword"),
						},
						MarkdownDescription: "Authentication mode. One of: Password|S4U|Interactive|Group|ServiceAccount|InteractiveOrPassword.",
					},
					"run_level": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Default:  stringdefault.StaticString("Limited"),
						Validators: []validator.String{stringvalidator.OneOf("Limited", "Highest")},
						PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
						MarkdownDescription: "Privilege level: `Limited` (default) or `Highest`.",
					},
				},
			},
			"actions": schema.ListNestedAttribute{
				Required: true,
				Validators: []validator.List{listvalidator.SizeBetween(1, 32)},
				MarkdownDescription: "One or more executable actions (1-32). Executed sequentially.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"execute":           schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.LengthAtLeast(1)}, MarkdownDescription: "Executable path."},
						"arguments":         schema.StringAttribute{Optional: true, MarkdownDescription: "Command-line arguments."},
						"working_directory": schema.StringAttribute{Optional: true, MarkdownDescription: "Working directory."},
					},
				},
			},
			"triggers": schema.ListNestedAttribute{
				Required: true,
				Validators: []validator.List{listvalidator.SizeBetween(1, 48)},
				MarkdownDescription: "One or more triggers (1-48). `OnEvent` uses XML injection (ADR-ST-5).",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.OneOf("Once", "Daily", "Weekly", "AtLogon", "AtStartup", "OnEvent"),
							},
							MarkdownDescription: "Trigger type discriminator.",
						},
						"enabled": schema.BoolAttribute{
							Optional: true, Computed: true, Default: booldefault.StaticBool(true),
							PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
							MarkdownDescription: "Whether this trigger is enabled. Defaults to `true`.",
						},
						"start_boundary": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "RFC 3339 activation datetime. Required for Once/Daily/Weekly (EC-7).",
						},
						"end_boundary": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "RFC 3339 deactivation datetime.",
						},
						"execution_time_limit": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "ISO 8601 per-trigger time cap.",
						},
						"delay": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "ISO 8601 delay before task start (AtStartup/AtLogon/OnEvent).",
						},
						"days_interval": schema.Int64Attribute{
							Optional: true, Computed: true,
							Validators:          []validator.Int64{int64validator.AtLeast(1)},
							PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
							MarkdownDescription: "Daily recurrence interval. Only valid for `Daily`. Windows default: 1.",
						},
						"days_of_week": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Validators: []validator.List{
								listvalidator.ValueStringsAre(
									stringvalidator.OneOf("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"),
								),
							},
							MarkdownDescription: "Weekday names. Required non-empty for `Weekly`.",
						},
						"weeks_interval": schema.Int64Attribute{
							Optional: true, Computed: true,
							Validators:          []validator.Int64{int64validator.AtLeast(1)},
							PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
							MarkdownDescription: "Weekly recurrence interval. Only valid for `Weekly`. Windows default: 1.",
						},
						"user_id": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Restrict `AtLogon` trigger to a specific user.",
						},
						"subscription": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "XPath event query. Required for `OnEvent` (ADR-ST-5).",
						},
					},
				},
			},
			"settings": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Task-level execution settings (New-ScheduledTaskSettingsSet).",
				Attributes: map[string]schema.Attribute{
					"allow_demand_start":             schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Allow on-demand start."},
					"allow_hard_terminate":           schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Allow forcible termination."},
					"start_when_available":           schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Start on next opportunity if missed."},
					"run_only_if_network_available":  schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Only start with network."},
					"execution_time_limit":           schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("PT72H"), MarkdownDescription: "Max runtime (ISO 8601). `PT0S` disables."},
					"multiple_instances":             schema.StringAttribute{
						Optional: true, Computed: true, Default: stringdefault.StaticString("Queue"),
						Validators: []validator.String{stringvalidator.OneOf("Parallel", "Queue", "IgnoreNew", "StopExisting")},
						MarkdownDescription: "Concurrent instance policy.",
					},
					"disallow_start_if_on_batteries": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Do not start on battery."},
					"stop_if_going_on_batteries":     schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Stop on battery switch."},
					"wake_to_run":                    schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Wake machine to run."},
					"run_only_if_idle":               schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Only run when idle."},
				},
			},
		},
	}
}

// ConfigValidators registers the cross-field validators.
func (r *windowsScheduledTaskResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		scheduledTaskPrincipalCrossFieldValidator{},
		scheduledTaskTriggerCrossFieldValidator{},
	}
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
	r.client = c
	r.stClient = winclient.NewScheduledTaskClient(c)
}

// ---------------------------------------------------------------------------
// CRUD — Create
// ---------------------------------------------------------------------------

// Create creates a new Windows Scheduled Task.
func (r *windowsScheduledTaskResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input, diags := modelToInput(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state, err := r.stClient.Create(ctx, input)
	if err != nil {
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

	id := current.ID.ValueString()
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
	var plan, currentState windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &currentState)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Detect password bump (ADR-ST-3 / EC-6)
	planInput, diags := modelToInput(ctx, &plan)
	resp.Diagnostics.Append(diags...)
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
	if planPwVersion == statePwVersion && planInput.Principal != nil {
		// No bump: clear password so it's not re-sent
		planInput.Principal.Password = nil
	}

	id := currentState.ID.ValueString()
	state, err := r.stClient.Update(ctx, id, planInput)
	if err != nil {
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
		if !pm.Password.IsNull() && !pm.Password.IsUnknown() {
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
		diags.Append(t.DaysOfWeek.ElementsAs(ctx, &dows, false)...)
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
	trigElems := make([]attr.Value, len(s.Triggers))
	for i, t := range s.Triggers {
		var priorTrigger *windowsScheduledTaskTriggerModel
		if priorModel != nil && !priorModel.Triggers.IsNull() {
			var pts []windowsScheduledTaskTriggerModel
			if d2 := priorModel.Triggers.ElementsAs(ctx, &pts, false); !d2.HasError() && i < len(pts) {
				priorTrigger = &pts[i]
			}
		}
		obj, d2 := buildTriggerObject(ctx, t, priorTrigger)
		diags.Append(d2...)
		trigElems[i] = obj
	}
	trigList, d2 := types.ListValue(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}, trigElems)
	diags.Append(d2...)
	m.Triggers = trigList

	// Settings
	if s.Settings != nil && priorModel != nil && !priorModel.Settings.IsNull() {
		settingsObj, d3 := types.ObjectValueFrom(ctx, scheduledTaskSettingsAttrTypes, windowsScheduledTaskSettingsModel{
			AllowDemandStart:           types.BoolValue(s.Settings.AllowDemandStart),
			AllowHardTerminate:         types.BoolValue(s.Settings.AllowHardTerminate),
			StartWhenAvailable:         types.BoolValue(s.Settings.StartWhenAvailable),
			RunOnlyIfNetworkAvailable:  types.BoolValue(s.Settings.RunOnlyIfNetworkAvailable),
			ExecutionTimeLimit:         types.StringValue(s.Settings.ExecutionTimeLimit),
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
			ExecutionTimeLimit:         types.StringValue(s.Settings.ExecutionTimeLimit),
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

	// password: write-only — preserve from prior
	pm.Password = types.StringNull()
	if priorHasPrincipal {
		var prior windowsScheduledTaskPrincipalModel
		if d := priorModel.Principal.As(ctx, &prior, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true}); !d.HasError() {
			pm.Password = prior.Password
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

// buildTriggerObject converts a ScheduledTaskTriggerState to a types.Object.
func buildTriggerObject(ctx context.Context, t winclient.ScheduledTaskTriggerState, prior *windowsScheduledTaskTriggerModel) (attr.Value, diag.Diagnostics) {
	var diags diag.Diagnostics

	var dows attr.Value
	if len(t.DaysOfWeek) > 0 {
		v, d := types.ListValueFrom(ctx, types.StringType, t.DaysOfWeek)
		diags.Append(d...)
		dows = v
	} else {
		dows = types.ListNull(types.StringType)
	}

	// days_interval / weeks_interval: Computed — use Windows value; 0 -> null
	var di, wi types.Int64
	if t.DaysInterval > 0 {
		di = types.Int64Value(t.DaysInterval)
	} else if prior != nil {
		di = prior.DaysInterval // preserve Unknown/null from plan
	} else {
		di = types.Int64Null()
	}
	if t.WeeksInterval > 0 {
		wi = types.Int64Value(t.WeeksInterval)
	} else if prior != nil {
		wi = prior.WeeksInterval
	} else {
		wi = types.Int64Null()
	}

	tm := windowsScheduledTaskTriggerModel{
		Type:               types.StringValue(t.Type),
		Enabled:            types.BoolValue(t.Enabled),
		StartBoundary:      strOrNull(t.StartBoundary),
		EndBoundary:        strOrNull(t.EndBoundary),
		ExecutionTimeLimit: strOrNull(t.ExecutionTimeLimit),
		Delay:              strOrNull(t.Delay),
		DaysInterval:       di,
		DaysOfWeek:         dows.(types.List),
		WeeksInterval:      wi,
		UserID:             strOrNull(t.UserID),
		Subscription:       strOrNull(t.Subscription),
	}
	return types.ObjectValueFrom(ctx, scheduledTaskTriggerAttrTypes, tm)
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

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
		diags.AddError(summary, detail)
		return diags
	}
	diags.AddError(fmt.Sprintf("windows_scheduled_task %s error", op), err.Error())
	return diags
}

// Ensure unused import for tfsdk is referenced (it's used transitively).
var _ tfsdk.Config
var _ strings.Builder

// windowsScheduledTaskDSPrincipalModel is the data source variant (no password).
type windowsScheduledTaskDSPrincipalModel struct {
	UserID    types.String `tfsdk:"user_id"`
	LogonType types.String `tfsdk:"logon_type"`
	RunLevel  types.String `tfsdk:"run_level"`
}

var scheduledTaskDSPrincipalAttrTypes = map[string]attr.Type{
	"user_id":    types.StringType,
	"logon_type": types.StringType,
	"run_level":  types.StringType,
}

// windowsScheduledTaskDSModel is the data source root model.
type windowsScheduledTaskDSModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Path           types.String `tfsdk:"path"`
	Description    types.String `tfsdk:"description"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	State          types.String `tfsdk:"state"`
	LastRunTime    types.String `tfsdk:"last_run_time"`
	LastTaskResult types.Int64  `tfsdk:"last_task_result"`
	NextRunTime    types.String `tfsdk:"next_run_time"`
	Principal      types.Object `tfsdk:"principal"`
	Actions        types.List   `tfsdk:"actions"`
	Triggers       types.List   `tfsdk:"triggers"`
	Settings       types.Object `tfsdk:"settings"`
}
