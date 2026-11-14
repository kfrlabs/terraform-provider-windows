// Package provider: windows_scheduled_task resource implementation.
//
// Spec: windows_scheduled_task v1 (2026-04-27).
// Framework: terraform-plugin-framework v1.13.0.
// Client: winclient.ScheduledTaskClientImpl (ScheduledTasks PS module + COM).
package provider

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Schema, attribute types, duration custom types and ConfigValidators. Split from resource_windows_scheduled_task.go (issue #349, no changes).

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
	"days_of_week":         types.SetType{ElemType: types.StringType},
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
// Schema
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsScheduledTaskResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scheduled_task"
}

// Schema returns the full TPF schema.
func (r *windowsScheduledTaskResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version: 1,
		MarkdownDescription: "Manages a Windows Scheduled Task via SSH + PowerShell (ScheduledTasks module, Windows 2012+).\n\n" +
			"**Partial failures:** if creation fails after the task was already registered on the host, " +
			"the provider persists the observed state before reporting the error, so the resource is marked " +
			"tainted. If update fails after Windows applied part of the change, the provider saves the observed " +
			"partial state before reporting the error, restoring the credential markers (`password`, " +
			"`password_wo_version`) from prior state so a failed rotation still diffs on retry. " +
			"Fix the cause and run `terraform apply` again to reconcile.\n\n" +
			"A nil state on error does not guarantee nothing was created: a failure that returns no state " +
			"leaves an orphaned task that must be removed with `Unregister-ScheduledTask` or re-adopted " +
			"with `terraform import`.",
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
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
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
							"Sensitive on the wire **but persisted in `terraform.tfstate`**.\n\n" +
							"The value must not contain carriage return or line feed characters " +
							"(rejected at plan time): secrets are read with `ReadLine()`, so anything " +
							"from the first line break on would be silently truncated. If the value " +
							"comes from `file()`, wrap it with `trimspace()` to strip the trailing newline.",
						Validators: []validator.String{
							secretNoLineBreakValidator{},
						},
					},
					"password_wo": schema.StringAttribute{
						Optional:  true,
						Sensitive: true,
						WriteOnly: true,
						Validators: []validator.String{
							secretNoLineBreakValidator{},
						},
						MarkdownDescription: "Write-only account password (TPF v1.14+ WriteOnly). " +
							"Same Windows-side semantics as `password` (ADR-ST-3) but **the plaintext " +
							"is never persisted in `terraform.tfstate`** \u2014 the framework drops it " +
							"from state automatically.\n\n" +
							"The value must not contain carriage return or line feed characters " +
							"(rejected at plan time against the configured value): secrets are read " +
							"with `ReadLine()`, so anything from the first line break on would be " +
							"silently truncated. If the value comes from `file()`, wrap it with " +
							"`trimspace()` to strip the trailing newline.\n\n" +
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
			"triggers": schema.SetNestedAttribute{
				Required:            true,
				Validators:          []validator.Set{setvalidator.SizeBetween(1, 48)},
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
							Computed:            true,
							PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							MarkdownDescription: "RFC 3339 deactivation datetime.",
						},
						"execution_time_limit": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							Validators:          []validator.String{stringvalidator.RegexMatches(scheduledTaskTriggerDurationRegex, scheduledTaskTriggerDurationDesc)},
							MarkdownDescription: "ISO 8601 per-trigger time cap. Assigned to Windows as an XSD string and compared verbatim.",
						},
						"delay": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							Validators:          []validator.String{stringvalidator.RegexMatches(scheduledTaskTriggerDurationRegex, scheduledTaskTriggerDurationDesc)},
							MarkdownDescription: "ISO 8601 delay before task start (AtStartup/AtLogon/OnEvent). Assigned to Windows as an XSD string and compared verbatim.",
						},
						"days_interval": schema.Int64Attribute{
							Optional: true, Computed: true,
							Validators:          []validator.Int64{int64validator.AtLeast(1)},
							PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
							MarkdownDescription: "Daily recurrence interval. Only valid for `Daily`. Windows default: 1.",
						},
						"days_of_week": schema.SetAttribute{
							Optional: true,
							Computed: true,
							PlanModifiers: []planmodifier.Set{
								setplanmodifier.UseStateForUnknown(),
							},
							ElementType: types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(
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
							Computed:            true,
							PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							MarkdownDescription: "Restrict `AtLogon` trigger to a specific user.",
						},
						"subscription": schema.StringAttribute{
							Optional: true,
							Computed: true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
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
