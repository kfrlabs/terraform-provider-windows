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
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
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
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// stDefaultTimeout is the fallback per-operation timeout when the user does
// not provide a `timeouts {}` block. Scheduled-task CRUD over SSH is fast
// (PowerShell module Register-/Set-/Unregister-ScheduledTask), so 5 minutes
// is more than enough for nominal cases while still bounding pathological
// hangs (e.g. SSH degradation, slow DC for principals).
const stDefaultTimeout = 5 * time.Minute

// stXSDTimePart matches the time half of an XSD duration, separator included,
// requiring at least one of the H/M/S components so that a bare "PT" cannot
// match: TnH, TnM, TnS, TnHnM, TnHnMnS (seconds may carry a fraction).
const stXSDTimePart = `T(?:\d+H(?:\d+M)?(?:\d+(?:\.\d+)?S)?|\d+M(?:\d+(?:\.\d+)?S)?|\d+(?:\.\d+)?S)`

// stXSDDatePart matches the date half of an XSD duration, requiring at least one
// of the Y/M/D components. Components must appear in Y, M, D order, so the
// alternation enumerates the three legal shapes (D, MD, YMD) plus Y-only and
// M-only. The alternation is self-contained: always embed it in a non-capturing
// group when composing it into a larger pattern.
const stXSDDatePart = `(?:(?:\d+Y)?(?:\d+M)?\d+D|\d+Y|\d+M)`

// scheduledTaskDurationRegex accepts the XSD/ISO 8601 durations that
// settings.execution_time_limit carries: days or less (PnD, PTnH, PTnM, PTnS,
// e.g. P3D, PT72H, PT1H30M15S; PT0S runs indefinitely). The value is converted
// through XmlConvert::ToTimeSpan on apply — the New-ScheduledTaskSettingsSet
// -ExecutionTimeLimit parameter is [TimeSpan] — and XmlConvert::ToTimeSpan
// approximates years and months as 365 and 30 days respectively, so those
// components are rejected here rather than silently turned into an arbitrary
// interval. Day components are exact: P3D is 72h.
//
// At least one component is required: a bare "P" or "PT" carries no duration
// and also makes ToTimeSpan throw.
var scheduledTaskDurationRegex = regexp.MustCompile(`^P(?:(?:\d+D)` + stXSDTimePart + `|\d+D|` + stXSDTimePart + `)$`)

const scheduledTaskDurationDesc = "must be an ISO 8601 duration of days or less (e.g. PT72H, P3D, PT1H30M15S; PT0S runs indefinitely)"

// scheduledTaskTriggerDurationRegex accepts the full XSD/ISO 8601 duration
// grammar for trigger execution_time_limit/delay, including year and month
// components (P1M4DT2H5M). Those are string-typed CIM properties assigned and
// reported verbatim, and trigger durations are documented in that format, so
// any schema-valid duration round-trips unchanged there — the settings-level
// XmlConvert::ToTimeSpan restriction does not apply. At least one component is
// required, as above.
var scheduledTaskTriggerDurationRegex = regexp.MustCompile(`^P(?:` + stXSDDatePart + `(?:` + stXSDTimePart + `)?|` + stXSDTimePart + `)$`)

const scheduledTaskTriggerDurationDesc = "must be an ISO 8601 duration (e.g. PT72H, P3D, P1M4DT2H5M; PT0S runs indefinitely)"

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
	stClient winclient.ScheduledTaskClient
}

// ---------------------------------------------------------------------------
// Attribute type maps (for types.Object / types.List creation)
// ---------------------------------------------------------------------------

var scheduledTaskPrincipalAttrTypes = map[string]attr.Type{
	"user_id":             types.StringType,
	"password":            types.StringType,
	"password_wo":         types.StringType,
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
	"subscription":         subscriptionXMLType{},
}

var scheduledTaskSettingsAttrTypes = map[string]attr.Type{
	"allow_demand_start":             types.BoolType,
	"allow_hard_terminate":           types.BoolType,
	"start_when_available":           types.BoolType,
	"run_only_if_network_available":  types.BoolType,
	"execution_time_limit":           durationType{},
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
	UserID types.String `tfsdk:"user_id"`
	// Password (legacy, DEPRECATED): plaintext persisted in state (Sensitive).
	Password types.String `tfsdk:"password"`
	// PasswordWO (Tier 3, TPF v1.14+): WriteOnly, never persisted in state.
	// Mutually exclusive with Password.
	PasswordWO        types.String `tfsdk:"password_wo"`
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
	Type               types.String         `tfsdk:"type"`
	Enabled            types.Bool           `tfsdk:"enabled"`
	StartBoundary      types.String         `tfsdk:"start_boundary"`
	EndBoundary        types.String         `tfsdk:"end_boundary"`
	ExecutionTimeLimit types.String         `tfsdk:"execution_time_limit"`
	Delay              types.String         `tfsdk:"delay"`
	DaysInterval       types.Int64          `tfsdk:"days_interval"`
	DaysOfWeek         types.List           `tfsdk:"days_of_week"`
	WeeksInterval      types.Int64          `tfsdk:"weeks_interval"`
	UserID             types.String         `tfsdk:"user_id"`
	Subscription       subscriptionXMLValue `tfsdk:"subscription"`
}

type windowsScheduledTaskSettingsModel struct {
	AllowDemandStart           types.Bool    `tfsdk:"allow_demand_start"`
	AllowHardTerminate         types.Bool    `tfsdk:"allow_hard_terminate"`
	StartWhenAvailable         types.Bool    `tfsdk:"start_when_available"`
	RunOnlyIfNetworkAvailable  types.Bool    `tfsdk:"run_only_if_network_available"`
	ExecutionTimeLimit         durationValue `tfsdk:"execution_time_limit"`
	MultipleInstances          types.String  `tfsdk:"multiple_instances"`
	DisallowStartIfOnBatteries types.Bool    `tfsdk:"disallow_start_if_on_batteries"`
	StopIfGoingOnBatteries     types.Bool    `tfsdk:"stop_if_going_on_batteries"`
	WakeToRun                  types.Bool    `tfsdk:"wake_to_run"`
	RunOnlyIfIdle              types.Bool    `tfsdk:"run_only_if_idle"`
}

type windowsScheduledTaskModel struct {
	ID             types.String   `tfsdk:"id"`
	Name           types.String   `tfsdk:"name"`
	Path           types.String   `tfsdk:"path"`
	Description    types.String   `tfsdk:"description"`
	Enabled        types.Bool     `tfsdk:"enabled"`
	State          types.String   `tfsdk:"state"`
	LastRunTime    types.String   `tfsdk:"last_run_time"`
	LastTaskResult types.Int64    `tfsdk:"last_task_result"`
	NextRunTime    types.String   `tfsdk:"next_run_time"`
	Principal      types.Object   `tfsdk:"principal"`
	Actions        types.List     `tfsdk:"actions"`
	Triggers       types.List     `tfsdk:"triggers"`
	Settings       types.Object   `tfsdk:"settings"`
	Timeouts       timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// scheduledTaskNameRe rejects Windows-reserved characters (\/:*?"<>|) and enforces
// a 1-238 character length limit matching the Task Scheduler maximum.
// Uses a double-quoted Go string so each `\\` produces one literal backslash in the
// compiled regex pattern, making the intent explicit and gofmt-stable.
var scheduledTaskNameRe = regexp.MustCompile("^[^\\\\/:*?\"<>|]{1,238}$")

type scheduledTaskNameValidator struct{}

func (v scheduledTaskNameValidator) Description(_ context.Context) string {
	return `task name must not contain \ / : * ? " < > | and be 1-238 characters`
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
			`Task name must be 1–238 characters and must not contain any of: \ / : * ? " < > |`)
	}
}

// scheduledTaskPathRe validates the Task Scheduler folder path format.
// A valid path starts with a backslash and every segment ends with a backslash,
// e.g. "\" (root) or "\Custom\" or "\Custom\Sub\".
// Segment content is any non-backslash sequence, allowing Unicode names, digits,
// spaces, and punctuation — matching the actual Task Scheduler folder name rules.
// Uses a double-quoted Go string: each `\\\\` produces one literal backslash in the
// compiled regex pattern, keeping the escape intent transparent.
var scheduledTaskPathRe = regexp.MustCompile(`^\\([^\\]+\\)*$`)

type scheduledTaskPathValidator struct{}

func (v scheduledTaskPathValidator) Description(_ context.Context) string {
	return `task path must start with a backslash and each folder segment must end with a backslash, e.g. "\" or "\Custom\" or "\Custom\Sub\"`
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

	// Tier 3: enforce mutual exclusion between password (legacy) and
	// password_wo (WriteOnly) inside the principal block. Cannot use
	// resourcevalidator.Conflicting at the top level because the
	// attributes are nested inside a SingleNestedAttribute; resolved
	// inline here against the As-decoded principal model.
	pwSet := !principal.Password.IsNull() && !principal.Password.IsUnknown()
	pwWoSet := !principal.PasswordWO.IsNull() && !principal.PasswordWO.IsUnknown()
	if pwSet && pwWoSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("principal").AtName("password_wo"),
			"Conflicting attributes",
			"`principal.password` and `principal.password_wo` are mutually exclusive. "+
				"Pick one: `password_wo` (recommended, never persisted in state) "+
				"or `password` (legacy, persisted as Sensitive in state).")
		return
	}

	// EC-4 is checked after WriteOnly values are overlaid from req.Config in
	// Create/Update. The framework intentionally omits WriteOnly values from
	// ValidateConfig, so checking them here rejects valid password_wo configs.
	// EC-5: forbidden logon types must have neither credential attribute.
	for _, forbidden := range []string{"Interactive", "S4U", "Group", "ServiceAccount"} {
		if logonType == forbidden && (pwSet || pwWoSet) {
			attrName := "password"
			if pwWoSet {
				attrName = "password_wo"
			}
			resp.Diagnostics.AddAttributeError(
				path.Root("principal").AtName(attrName),
				"Conflicting attributes",
				fmt.Sprintf(`%s must not be set when logon_type is %q (EC-5).`, attrName, logonType))
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
		if !t.Delay.IsNull() && !t.Delay.IsUnknown() && t.Delay.ValueString() != "" && !scheduledTaskTriggerAllowsDelay(tt) {
			// MSFT_TaskDailyTrigger / MSFT_TaskTimeTrigger (Once) /
			// MSFT_TaskWeeklyTrigger expose no Delay property: assigning it
			// throws, the winclient try/catch swallows it, Windows registers
			// the trigger without delay, and apply then fails with
			// "inconsistent result after apply". Fail fast at plan instead.
			resp.Diagnostics.AddAttributeError(trigPath.AtName("delay"),
				"Conflicting attribute",
				fmt.Sprintf(`delay is only valid for "AtLogon", "AtStartup" and "OnEvent" triggers, got %q (EC-7).`, tt))
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

func scheduledTaskTriggerAllowsDelay(triggerType string) bool {
	switch triggerType {
	case "AtLogon", "AtStartup", "OnEvent":
		return true
	default:
		return false
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
func (r *windowsScheduledTaskResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Windows Scheduled Task via SSH + PowerShell (ScheduledTasks module, Windows 2012+).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "Composite ID `<TaskPath><TaskName>` (ADR-ST-2).",
			},
			"name": schema.StringAttribute{
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{scheduledTaskNameValidator{}},
				MarkdownDescription: "Task leaf name. No backslash; max 238 chars. **ForceNew**.",
			},
			"path": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("\\"),
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:          []validator.String{scheduledTaskPathValidator{}},
				MarkdownDescription: `Task folder path (starts and ends with "\"). Defaults to "\". **ForceNew**.`,
			},
			"description": schema.StringAttribute{
				Optional:            true,
				Validators:          []validator.String{stringvalidator.LengthAtMost(2048)},
				MarkdownDescription: "Human-readable task description (max 2048 chars).",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the task is enabled. Defaults to `true`.",
			},
			"state": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current operational state: Ready|Disabled|Running|Queued|Unknown.",
			},
			"last_run_time": schema.StringAttribute{
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "RFC 3339 timestamp of last execution, or empty string.",
			},
			"last_task_result": schema.Int64Attribute{
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
				MarkdownDescription: "Win32 exit code of last execution (0=success).",
			},
			"next_run_time": schema.StringAttribute{
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "RFC 3339 timestamp of next scheduled run, or empty string.",
			},
			"principal": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Security context. Omit for Windows default (SYSTEM/ServiceAccount).",
				Attributes: map[string]schema.Attribute{
					"user_id": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("SYSTEM"),
						MarkdownDescription: "Account identifier. Defaults to `\"SYSTEM\"`.",
					},
					"password": schema.StringAttribute{
						Optional:           true,
						Sensitive:          true,
						DeprecationMessage: "Use `password_wo` instead. The `password` attribute persists the plaintext in `terraform.tfstate` (Sensitive but readable by anyone with state access). `password_wo` is a WriteOnly attribute (TPF v1.14+) and is never written to state. Both share the existing `password_wo_version` counter for rotation. This attribute will be removed in v2.x.",
						MarkdownDescription: "**Deprecated, use `password_wo`.** Account password (ADR-ST-3). Required when `logon_type=\"Password\"` (EC-4). " +
							"Sensitive on the wire **but persisted in `terraform.tfstate`**.",
					},
					"password_wo": schema.StringAttribute{
						Optional:  true,
						Sensitive: true,
						WriteOnly: true,
						MarkdownDescription: "Write-only account password (TPF v1.14+ WriteOnly). " +
							"Same Windows-side semantics as `password` (ADR-ST-3) but **the plaintext " +
							"is never persisted in `terraform.tfstate`** \u2014 the framework drops it " +
							"from state automatically.\n\n" +
							"Mutually exclusive with `password`. Rotation is driven exclusively by " +
							"`password_wo_version`: increment the version and re-apply with the new " +
							"value. The provider re-registers the principal whenever the version " +
							"changes between prior state and current plan.",
					},
					"password_wo_version": schema.Int64Attribute{
						Optional:            true,
						Computed:            true,
						Default:             int64default.StaticInt64(0),
						Validators:          []validator.Int64{int64validator.AtLeast(0)},
						PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
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
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("Limited"),
						Validators:          []validator.String{stringvalidator.OneOf("Limited", "Highest")},
						PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
						MarkdownDescription: "Privilege level: `Limited` (default) or `Highest`.",
					},
				},
			},
			"actions": schema.ListNestedAttribute{
				Required:            true,
				Validators:          []validator.List{listvalidator.SizeBetween(1, 32)},
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
				Required:            true,
				Validators:          []validator.List{listvalidator.SizeBetween(1, 48)},
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
							Validators:          []validator.String{stringvalidator.RegexMatches(scheduledTaskTriggerDurationRegex, scheduledTaskTriggerDurationDesc)},
							MarkdownDescription: "ISO 8601 per-trigger time cap. Assigned to Windows as an XSD string and compared verbatim.",
						},
						"delay": schema.StringAttribute{
							Optional:            true,
							Validators:          []validator.String{stringvalidator.RegexMatches(scheduledTaskTriggerDurationRegex, scheduledTaskTriggerDurationDesc)},
							MarkdownDescription: "ISO 8601 delay before task start (AtStartup/AtLogon/OnEvent). Assigned to Windows as an XSD string and compared verbatim.",
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
							Optional: true,
							// CustomType gives this attribute semantic-equality XML comparison
							// (see subscriptionXMLValue), so Windows re-serializing this value's
							// whitespace on round-trip doesn't trip TPF's plan/apply consistency
							// checks or show as configuration drift.
							CustomType:          subscriptionXMLType{},
							MarkdownDescription: "XPath event query. Required for `OnEvent` (ADR-ST-5).",
						},
					},
				},
			},
			"settings": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Task-level execution settings (New-ScheduledTaskSettingsSet).",
				Attributes: map[string]schema.Attribute{
					"allow_demand_start":            schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Allow on-demand start."},
					"allow_hard_terminate":          schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Allow forcible termination."},
					"start_when_available":          schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Start on next opportunity if missed."},
					"run_only_if_network_available": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Only start with network."},
					"execution_time_limit": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("PT72H"),
						Validators:          []validator.String{stringvalidator.RegexMatches(scheduledTaskDurationRegex, scheduledTaskDurationDesc)},
						MarkdownDescription: "Max runtime (ISO 8601). `PT0S` runs indefinitely. Converted to a `TimeSpan` on apply because the cmdlet requires one; compared by value, so an equivalent re-read spelling does not drift.",
						CustomType:          durationType{},
					},
					"multiple_instances": schema.StringAttribute{
						Optional: true, Computed: true, Default: stringdefault.StaticString("Queue"),
						Validators:          []validator.String{stringvalidator.OneOf("Parallel", "Queue", "IgnoreNew", "StopExisting")},
						MarkdownDescription: "Concurrent instance policy.",
					},
					"disallow_start_if_on_batteries": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Do not start on battery."},
					"stop_if_going_on_batteries":     schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), MarkdownDescription: "Stop on battery switch."},
					"wake_to_run":                    schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Wake machine to run."},
					"run_only_if_idle":               schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Only run when idle."},
				},
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			"timeouts": timeouts.Attributes(ctx, stTimeoutsOpts),
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

	// days_interval / weeks_interval: Computed — use Windows value; 0 -> null.
	// Only preserve a prior value when it is known: on a create prior == plan,
	// and an unset Optional+Computed interval is Unknown there. A Computed
	// attribute must never stay Unknown after apply, so resolve those to null.
	var di, wi types.Int64
	if t.DaysInterval > 0 {
		di = types.Int64Value(t.DaysInterval)
	} else if prior != nil && !prior.DaysInterval.IsUnknown() {
		di = prior.DaysInterval // preserve known null/value from state
	} else {
		di = types.Int64Null()
	}
	if t.WeeksInterval > 0 {
		wi = types.Int64Value(t.WeeksInterval)
	} else if prior != nil && !prior.WeeksInterval.IsUnknown() {
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

// normalizeXMLWhitespace collapses whitespace-only text between XML tags and
// trims the result. Used only for equality comparisons (see
// subscriptionXMLValue.StringSemanticEquals below), never for storage: it
// lets a heredoc config's indentation/blank lines compare equal to the
// (differently whitespaced) value Windows Task Scheduler returns after it
// re-serializes an OnEvent trigger's <Subscription> XML fragment through
// Register/Export-ScheduledTask.
var xmlInterTagWhitespace = regexp.MustCompile(`>\s+<`)

func normalizeXMLWhitespace(s string) string {
	s = strings.TrimSpace(s)
	return xmlInterTagWhitespace.ReplaceAllString(s, "><")
}

// subscriptionXMLValue is the framework value type for the OnEvent trigger's
// "subscription" attribute. It implements semantic equality so that a
// heredoc config and Windows' differently-whitespaced round-tripped value are
// treated as unchanged, avoiding both a "provider produced inconsistent
// result after apply" error (on create) and a false diff on later refresh.
type subscriptionXMLValue struct {
	basetypes.StringValue
}

func subscriptionXMLValueOf(s string) subscriptionXMLValue {
	return subscriptionXMLValue{StringValue: types.StringValue(s)}
}

func subscriptionXMLValueOrNull(s string) subscriptionXMLValue {
	if s == "" {
		return subscriptionXMLValue{StringValue: types.StringNull()}
	}
	return subscriptionXMLValueOf(s)
}

func (v subscriptionXMLValue) Equal(o attr.Value) bool {
	other, ok := o.(subscriptionXMLValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v subscriptionXMLValue) Type(context.Context) attr.Type {
	return subscriptionXMLType{}
}

func (v subscriptionXMLValue) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	other, ok := newValuable.(subscriptionXMLValue)
	if !ok {
		diags.AddError("Semantic Equality Check Error",
			fmt.Sprintf("expected subscriptionXMLValue, got %T", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || other.IsNull() || other.IsUnknown() {
		return false, diags
	}
	return normalizeXMLWhitespace(v.ValueString()) == normalizeXMLWhitespace(other.ValueString()), diags
}

// subscriptionXMLType is the attr.Type counterpart of subscriptionXMLValue.
type subscriptionXMLType struct {
	basetypes.StringType
}

func (t subscriptionXMLType) Equal(o attr.Type) bool {
	other, ok := o.(subscriptionXMLType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t subscriptionXMLType) String() string {
	return "subscriptionXMLType"
}

func (t subscriptionXMLType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return subscriptionXMLValue{StringValue: in}, nil
}

func (t subscriptionXMLType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T for subscriptionXMLType", attrValue)
	}
	valuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("error converting StringValue to subscriptionXMLValue: %v", diags)
	}
	return valuable, nil
}

func (t subscriptionXMLType) ValueType(context.Context) attr.Value {
	return subscriptionXMLValue{}
}

// durationValue is the framework value type for the ISO 8601 duration
// attributes. It implements value-semantic equality so that equivalent
// spellings of the same duration compare equal, avoiding both a "provider
// produced inconsistent result after apply" error on create and a false diff on
// later refresh.
//
// The state value is never rewritten: the raw string Windows reports is kept
// as-is. Equality is only relaxed at comparison time, because the attribute is
// Optional+Computed with a default, so any spelling difference on a
// semantically identical value would otherwise be a hard apply failure.
//
// Which spelling comes back is not guaranteed: TaskSettings.ExecutionTimeLimit
// is documented as a String in the PnYnMnDTnHnMnS format, but the apply path
// hands Windows a [TimeSpan], so a re-serialisation could legitimately produce
// P3D where the configuration said PT72H. Comparing by value is correct in both
// cases.
type durationValue struct {
	basetypes.StringValue
}

func durationValueOf(s string) durationValue {
	return durationValue{StringValue: types.StringValue(s)}
}

func durationValueOrNull(s string) durationValue {
	if s == "" {
		return durationValue{StringValue: types.StringNull()}
	}
	return durationValueOf(s)
}

func (v durationValue) Equal(o attr.Value) bool {
	other, ok := o.(durationValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v durationValue) Type(context.Context) attr.Type {
	return durationType{}
}

func (v durationValue) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	other, ok := newValuable.(durationValue)
	if !ok {
		diags.AddError("Semantic Equality Check Error",
			fmt.Sprintf("expected durationValue, got %T", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || other.IsNull() || other.IsUnknown() {
		return false, diags
	}
	return durationsEquivalent(v.ValueString(), other.ValueString()), diags
}

// durationType is the attr.Type counterpart of durationValue.
type durationType struct {
	basetypes.StringType
}

func (t durationType) Equal(o attr.Type) bool {
	other, ok := o.(durationType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t durationType) String() string {
	return "durationType"
}

func (t durationType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return durationValue{StringValue: in}, nil
}

func (t durationType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T for durationType", attrValue)
	}
	valuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("error converting StringValue to durationValue: %v", diags)
	}
	return valuable, nil
}

func (t durationType) ValueType(context.Context) attr.Value {
	return durationValue{}
}

// xsdDurationRe matches the XSD duration grammar used by Task Scheduler,
// including the optional week form and an optional negative sign.
var xsdDurationRe = regexp.MustCompile(`^(-?)P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// dotNetTimeSpanRe matches the .NET TimeSpan.ToString() form, "[d.]hh:mm:ss.fffffff".
var dotNetTimeSpanRe = regexp.MustCompile(`^(-)?(?:(\d+)\.)?(\d+):(\d{1,2}):(\d{1,2})(?:\.(\d+))?$`)

// durationsEquivalent reports whether two duration spellings denote the same
// length of time. It falls back to exact string equality when either side
// cannot be parsed, so an unexpected value still compares strictly rather than
// silently matching something else.
func durationsEquivalent(a, b string) bool {
	if a == b {
		return true
	}
	da, okA := durationNanos(a)
	db, okB := durationNanos(b)
	if !okA || !okB {
		return false
	}
	return da == db
}

// durationNanos converts an XSD duration or a .NET TimeSpan string to
// nanoseconds. It reports false for anything it cannot parse and for values
// large enough to overflow the nanosecond range, keeping the comparison
// conservative.
//
// Year and month components use the same 365- and 30-day estimate as
// XmlConvert::ToTimeSpan, so a value means the same length here as it does on
// the apply path.
func durationNanos(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if m := xsdDurationRe.FindStringSubmatch(s); m != nil {
		sign := int64(1)
		if m[1] == "-" {
			sign = -1
		}
		seconds, fracNanos := parseSeconds(m[8])
		if seconds < 0 {
			return 0, false
		}
		// Each component is range-checked against the remaining budget
		// BEFORE it is multiplied. An int64 overflow wraps rather than
		// saturating, so validating the accumulated total afterwards would
		// let a huge component wrap to a small value and compare equal to a
		// legitimate duration.
		total, ok := stCheckedAdd(0, atoi64(m[2]), 365*86400)
		if !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[3]), 30*86400); !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[4]), 7*86400); !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[5]), 86400); !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[6]), 3600); !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[7]), 60); !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, seconds, 1); !ok {
			return 0, false
		}
		return sign * (total*int64(time.Second) + fracNanos), true
	}
	if m := dotNetTimeSpanRe.FindStringSubmatch(s); m != nil {
		sign := int64(1)
		if m[1] == "-" {
			sign = -1
		}
		fracNanos := int64(0)
		if m[6] != "" {
			frac, err := strconv.ParseFloat("0."+m[6], 64)
			if err != nil {
				return 0, false
			}
			// Sub-nanosecond precision is below Windows tick granularity.
			fracNanos = int64(math.Round(frac * 1e9))
		}
		total, ok := stCheckedAdd(0, atoi64(m[2]), 86400)
		if !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[3]), 3600); !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[4]), 60); !ok {
			return 0, false
		}
		if total, ok = stCheckedAdd(total, atoi64(m[5]), 1); !ok {
			return 0, false
		}
		return sign * (total*int64(time.Second) + fracNanos), true
	}
	return 0, false
}

// stCheckedAdd adds count*multiplier to total, reporting false when the result
// would exceed stMaxDurationSeconds. The bound is checked before multiplying, so
// no intermediate value can overflow.
func stCheckedAdd(total, count, multiplier int64) (int64, bool) {
	if count < 0 || count > stMaxDurationSeconds/multiplier {
		return 0, false
	}
	sum := total + count*multiplier
	if sum > stMaxDurationSeconds {
		return 0, false
	}
	return sum, true
}

// parseSeconds splits an XSD seconds component into whole seconds and
// nanoseconds. It returns a negative whole-second count for a malformed value.
func parseSeconds(s string) (int64, int64) {
	if s == "" {
		return 0, 0
	}
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return atoi64(s), 0
	}
	whole := atoi64(s[:dot])
	frac, err := strconv.ParseFloat("0."+s[dot+1:], 64)
	if err != nil {
		return -1, 0
	}
	return whole, int64(math.Round(frac * 1e9))
}

// stMaxDurationSeconds bounds a duration to roughly 290 years. One second is
// held back from the int64 nanosecond ceiling so that adding the
// fractional-nanosecond remainder (up to 999_999_999) to the scaled total can
// never wrap.
const stMaxDurationSeconds = int64(math.MaxInt64)/int64(time.Second) - 1

// atoi64 parses a non-negative decimal group, reporting 0 for an absent group.
// Overflow saturates, which durationNanos then rejects via its range check.
func atoi64(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return math.MaxInt64
	}
	if n > uint64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(n)
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
