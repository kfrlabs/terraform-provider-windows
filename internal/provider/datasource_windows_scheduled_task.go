// Package provider: windows_scheduled_task data source implementation.
//
// Reads the current state of a Windows Scheduled Task by name+path.
// Does NOT expose write-only fields (password, password_wo_version).
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsScheduledTaskDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsScheduledTaskDataSource)(nil)
)

// NewWindowsScheduledTaskDataSource is the constructor registered in provider.go.
func NewWindowsScheduledTaskDataSource() datasource.DataSource {
	return &windowsScheduledTaskDataSource{}
}

// windowsScheduledTaskDataSource reads a Windows Scheduled Task.
type windowsScheduledTaskDataSource struct {
	client   *winclient.Client
	stClient winclient.ScheduledTaskClient
}

// Metadata sets the type name.
func (d *windowsScheduledTaskDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scheduled_task"
}

// Schema returns the data source schema.
func (d *windowsScheduledTaskDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the current state of a Windows Scheduled Task.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Composite ID `<TaskPath><TaskName>`.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Task leaf name.",
			},
			"path": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: `Task folder path. Defaults to "\\".`,
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Task description.",
			},
			"enabled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the task is enabled.",
			},
			"state": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current operational state.",
			},
			"last_run_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "RFC 3339 timestamp of last execution.",
			},
			"last_task_result": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Win32 exit code of last execution.",
			},
			"next_run_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "RFC 3339 timestamp of next scheduled run.",
			},
			"principal": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Security context under which the task runs.",
				Attributes: map[string]schema.Attribute{
					"user_id":    schema.StringAttribute{Computed: true, MarkdownDescription: "Account identifier."},
					"logon_type": schema.StringAttribute{Computed: true, MarkdownDescription: "Authentication mode."},
					"run_level":  schema.StringAttribute{Computed: true, MarkdownDescription: "Privilege level."},
				},
			},
			"actions": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Executable actions.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"execute":           schema.StringAttribute{Computed: true},
						"arguments":         schema.StringAttribute{Computed: true},
						"working_directory": schema.StringAttribute{Computed: true},
					},
				},
			},
			"triggers": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Task triggers.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type":                 schema.StringAttribute{Computed: true},
						"enabled":              schema.BoolAttribute{Computed: true},
						"start_boundary":       schema.StringAttribute{Computed: true},
						"end_boundary":         schema.StringAttribute{Computed: true},
						"execution_time_limit": schema.StringAttribute{Computed: true},
						"delay":                schema.StringAttribute{Computed: true},
						"days_interval":        schema.Int64Attribute{Computed: true},
						"days_of_week": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"weeks_interval": schema.Int64Attribute{Computed: true},
						"user_id":        schema.StringAttribute{Computed: true},
						"subscription":   schema.StringAttribute{Computed: true},
					},
				},
			},
			"settings": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Task-level execution settings.",
				Attributes: map[string]schema.Attribute{
					"allow_demand_start":             schema.BoolAttribute{Computed: true},
					"allow_hard_terminate":           schema.BoolAttribute{Computed: true},
					"start_when_available":           schema.BoolAttribute{Computed: true},
					"run_only_if_network_available":  schema.BoolAttribute{Computed: true},
					"execution_time_limit":           schema.StringAttribute{Computed: true},
					"multiple_instances":             schema.StringAttribute{Computed: true},
					"disallow_start_if_on_batteries": schema.BoolAttribute{Computed: true},
					"stop_if_going_on_batteries":     schema.BoolAttribute{Computed: true},
					"wake_to_run":                    schema.BoolAttribute{Computed: true},
					"run_only_if_idle":               schema.BoolAttribute{Computed: true},
				},
			},
		},
	}
}

// Configure wires the provider client.
func (d *windowsScheduledTaskDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData))
		return
	}
	d.client = c
	d.stClient = winclient.NewScheduledTaskClient(c)
}

// Read fetches the scheduled task state.
func (d *windowsScheduledTaskDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsScheduledTaskDSModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	taskName := config.Name.ValueString()
	taskPath := config.Path.ValueString()
	if taskPath == "" {
		taskPath = "\\"
	}
	id := taskPath + taskName

	state, err := d.stClient.Read(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(scheduledTaskErrDiag("DataSource.Read", err)...)
		return
	}
	if state == nil {
		resp.Diagnostics.AddError("Scheduled task not found",
			fmt.Sprintf("No scheduled task found with name=%q, path=%q.", taskName, taskPath))
		return
	}

	model, diags := dsStateToModel(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

// dsStateToModel converts a ScheduledTaskState to the DS model.
func dsStateToModel(ctx context.Context, s *winclient.ScheduledTaskState) (*windowsScheduledTaskDSModel, diag.Diagnostics) {
	var allDiags diag.Diagnostics
	m := &windowsScheduledTaskDSModel{
		ID:             types.StringValue(s.Path + s.Name),
		Name:           types.StringValue(s.Name),
		Path:           types.StringValue(s.Path),
		Description:    types.StringValue(s.Description),
		Enabled:        types.BoolValue(s.Enabled),
		State:          types.StringValue(s.State),
		LastRunTime:    types.StringValue(s.LastRunTime),
		LastTaskResult: types.Int64Value(s.LastTaskResult),
		NextRunTime:    types.StringValue(s.NextRunTime),
	}

	// Principal
	if s.Principal != nil {
		obj, d := types.ObjectValueFrom(ctx, scheduledTaskDSPrincipalAttrTypes, windowsScheduledTaskDSPrincipalModel{
			UserID:    types.StringValue(s.Principal.UserID),
			LogonType: types.StringValue(s.Principal.LogonType),
			RunLevel:  types.StringValue(s.Principal.RunLevel),
		})
		allDiags.Append(d...)
		m.Principal = obj
	} else {
		m.Principal = types.ObjectNull(scheduledTaskDSPrincipalAttrTypes)
	}

	// Actions
	actionElems := make([]attr.Value, len(s.Actions))
	for i, a := range s.Actions {
		obj, d := types.ObjectValueFrom(ctx, scheduledTaskActionAttrTypes, windowsScheduledTaskActionModel{
			Execute:          types.StringValue(a.Execute),
			Arguments:        types.StringValue(a.Arguments),
			WorkingDirectory: types.StringValue(a.WorkingDirectory),
		})
		allDiags.Append(d...)
		actionElems[i] = obj
	}
	actList, d := types.ListValue(types.ObjectType{AttrTypes: scheduledTaskActionAttrTypes}, actionElems)
	allDiags.Append(d...)
	m.Actions = actList

	// Triggers
	trigElems := make([]attr.Value, len(s.Triggers))
	for i, t := range s.Triggers {
		var dows attr.Value
		if len(t.DaysOfWeek) > 0 {
			v, d2 := types.ListValueFrom(ctx, types.StringType, t.DaysOfWeek)
			allDiags.Append(d2...)
			dows = v
		} else {
			dows = types.ListValueMust(types.StringType, []attr.Value{})
		}
		obj, d2 := types.ObjectValueFrom(ctx, scheduledTaskTriggerAttrTypes, windowsScheduledTaskTriggerModel{
			Type:               types.StringValue(t.Type),
			Enabled:            types.BoolValue(t.Enabled),
			StartBoundary:      types.StringValue(t.StartBoundary),
			EndBoundary:        types.StringValue(t.EndBoundary),
			ExecutionTimeLimit: types.StringValue(t.ExecutionTimeLimit),
			Delay:              types.StringValue(t.Delay),
			DaysInterval:       types.Int64Value(t.DaysInterval),
			DaysOfWeek:         dows.(types.List),
			WeeksInterval:      types.Int64Value(t.WeeksInterval),
			UserID:             types.StringValue(t.UserID),
			Subscription:       types.StringValue(t.Subscription),
		})
		allDiags.Append(d2...)
		trigElems[i] = obj
	}
	trigList, d2 := types.ListValue(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}, trigElems)
	allDiags.Append(d2...)
	m.Triggers = trigList

	// Settings
	if s.Settings != nil {
		obj, d3 := types.ObjectValueFrom(ctx, scheduledTaskSettingsAttrTypes, windowsScheduledTaskSettingsModel{
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
		allDiags.Append(d3...)
		m.Settings = obj
	} else {
		m.Settings = types.ObjectNull(scheduledTaskSettingsAttrTypes)
	}

	return m, allDiags
}
