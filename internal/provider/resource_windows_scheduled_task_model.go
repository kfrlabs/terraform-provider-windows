// Package provider: windows_scheduled_task resource implementation.
//
// Spec: windows_scheduled_task v1 (2026-04-27).
// Framework: terraform-plugin-framework v1.13.0.
// Client: winclient.ScheduledTaskClientImpl (ScheduledTasks PS module + COM).
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Plan/state models and state upgrade. Split from resource_windows_scheduled_task.go (issue #349, no changes).
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
	DaysOfWeek         types.Set            `tfsdk:"days_of_week"`
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
	Triggers       types.Set      `tfsdk:"triggers"`
	Settings       types.Object   `tfsdk:"settings"`
	Timeouts       timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// State upgrade (issue #324: triggers/days_of_week List -> Set)
// ---------------------------------------------------------------------------

// windowsScheduledTaskTriggerModelV0 is the prior (v0) trigger shape, which
// still carries `days_of_week` as a List.
type windowsScheduledTaskTriggerModelV0 struct {
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

// windowsScheduledTaskModelV0 is the prior (v0) state shape, which still
// carries `triggers` as a List of the V0 trigger objects.
type windowsScheduledTaskModelV0 struct {
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

// windowsScheduledTaskPriorSchemaV0 returns the v0 schema: the current schema
// with `triggers` (and its nested `days_of_week`) as List collections.
func windowsScheduledTaskPriorSchemaV0(ctx context.Context) *schema.Schema {
	r := &windowsScheduledTaskResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, resp)
	s := resp.Schema
	s.Version = 0
	triggersAttr, ok := s.Attributes["triggers"].(schema.SetNestedAttribute)
	if !ok {
		return &s
	}
	nestedAttrs := map[string]schema.Attribute{}
	for k, a := range triggersAttr.NestedObject.Attributes {
		nestedAttrs[k] = a
	}
	nestedAttrs["days_of_week"] = schema.ListAttribute{
		Optional:    true,
		ElementType: types.StringType,
	}
	s.Attributes["triggers"] = schema.ListNestedAttribute{
		Required:            true,
		Validators:          []validator.List{listvalidator.SizeBetween(1, 48)},
		MarkdownDescription: "One or more triggers (1-48). `OnEvent` uses XML injection (ADR-ST-5).",
		NestedObject:        schema.NestedAttributeObject{Attributes: nestedAttrs},
	}
	return &s
}

// UpgradeState maps the v0 List-based state to the v1 Set-based state.
func (r *windowsScheduledTaskResource) UpgradeState(_ context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema:   windowsScheduledTaskPriorSchemaV0(context.Background()),
			StateUpgrader: upgradeWindowsScheduledTaskStateV0ToV1,
		},
	}
}

// upgradeWindowsScheduledTaskStateV0ToV1 copies every v0 field into the
// current (v1) shape, converting the `triggers` list and each nested
// `days_of_week` list into sets. Element values are preserved; only the
// collection kind changes, so order no longer matters.
func upgradeWindowsScheduledTaskStateV0ToV1(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	var prior windowsScheduledTaskModelV0
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var priorTriggers []windowsScheduledTaskTriggerModelV0
	triggersNull := prior.Triggers.IsNull()
	triggersUnknown := prior.Triggers.IsUnknown()
	if !triggersNull && !triggersUnknown {
		resp.Diagnostics.Append(prior.Triggers.ElementsAs(ctx, &priorTriggers, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	// Null stays null (safer for hand-edited state: Required triggers means
	// a null list is a user hand-edit, not a value the provider would write);
	// unknown stays unknown; otherwise convert each element.
	var trigSet types.Set
	switch {
	case triggersNull:
		trigSet = types.SetNull(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes})
	case triggersUnknown:
		trigSet = types.SetUnknown(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes})
	default:
		trigElems := make([]attr.Value, len(priorTriggers))
		for i, pt := range priorTriggers {
			var dows types.Set
			switch {
			case pt.DaysOfWeek.IsNull():
				dows = types.SetNull(types.StringType)
			case pt.DaysOfWeek.IsUnknown():
				dows = types.SetUnknown(types.StringType)
			default:
				var days []string
				resp.Diagnostics.Append(pt.DaysOfWeek.ElementsAs(ctx, &days, false)...)
				if resp.Diagnostics.HasError() {
					return
				}
				v, d := types.SetValueFrom(ctx, types.StringType, days)
				resp.Diagnostics.Append(d...)
				if resp.Diagnostics.HasError() {
					return
				}
				dows = v
			}
			obj, d := types.ObjectValueFrom(ctx, scheduledTaskTriggerAttrTypes, windowsScheduledTaskTriggerModel{
				Type:               pt.Type,
				Enabled:            pt.Enabled,
				StartBoundary:      pt.StartBoundary,
				EndBoundary:        pt.EndBoundary,
				ExecutionTimeLimit: pt.ExecutionTimeLimit,
				Delay:              pt.Delay,
				DaysInterval:       pt.DaysInterval,
				DaysOfWeek:         dows,
				WeeksInterval:      pt.WeeksInterval,
				UserID:             pt.UserID,
				Subscription:       pt.Subscription,
			})
			resp.Diagnostics.Append(d...)
			if resp.Diagnostics.HasError() {
				return
			}
			trigElems[i] = obj
		}
		v, d := types.SetValue(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}, trigElems)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		trigSet = v
	}

	upgraded := windowsScheduledTaskModel{
		ID:             prior.ID,
		Name:           prior.Name,
		Path:           prior.Path,
		Description:    prior.Description,
		Enabled:        prior.Enabled,
		State:          prior.State,
		LastRunTime:    prior.LastRunTime,
		LastTaskResult: prior.LastTaskResult,
		NextRunTime:    prior.NextRunTime,
		Principal:      prior.Principal,
		Actions:        prior.Actions,
		Triggers:       trigSet,
		Settings:       prior.Settings,
		Timeouts:       prior.Timeouts,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
}
