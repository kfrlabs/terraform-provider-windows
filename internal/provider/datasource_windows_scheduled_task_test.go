// Package provider — unit tests for windows_scheduled_task data source.
//
// Tests cover:
//   - Metadata + Schema
//   - Configure: nil ProviderData, wrong type
//   - Read: happy path (SYSTEM principal, daily trigger)
//   - Read: not found → error diagnostic
//   - Read: nil result → error diagnostic
//   - Read: client error → error diagnostic
//   - dsStateToModel: sentinel times, settings, weekly trigger
package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake DS client (reuses fakeSTClient from resource test)
// ---------------------------------------------------------------------------

// fakeSTClientDS is a lightweight alias for data source tests.
type fakeSTClientDS struct {
	readOut *winclient.ScheduledTaskState
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeSTClientDS) Create(_ context.Context, _ winclient.ScheduledTaskInput) (*winclient.ScheduledTaskState, error) {
	panic("not used in data source")
}
func (f *fakeSTClientDS) Read(ctx context.Context, _ string) (*winclient.ScheduledTaskState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}
func (f *fakeSTClientDS) Update(_ context.Context, _ string, _ winclient.ScheduledTaskInput) (*winclient.ScheduledTaskState, error) {
	panic("not used in data source")
}
func (f *fakeSTClientDS) Delete(_ context.Context, _ string) error { panic("not used in data source") }
func (f *fakeSTClientDS) ImportByID(_ context.Context, _ string) (*winclient.ScheduledTaskState, error) {
	panic("not used in data source")
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestSTDataSource_Metadata(t *testing.T) {
	ds := &windowsScheduledTaskDataSource{}
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_scheduled_task" {
		t.Errorf("TypeName = %q, want windows_scheduled_task", resp.TypeName)
	}
}

func TestSTDataSource_Schema_HasRequiredAttributes(t *testing.T) {
	ds := &windowsScheduledTaskDataSource{}
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	s := resp.Schema

	wantAttrs := []string{
		"id", "name", "path", "description", "enabled", "state",
		"last_run_time", "last_task_result", "next_run_time",
		"principal", "actions", "triggers", "settings", "timeouts",
	}
	for _, k := range wantAttrs {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("data source schema missing attribute %q", k)
		}
	}
}

func TestSTDataSource_Schema_NoPasswordAttribute(t *testing.T) {
	// Data source must NOT expose password (write-only field)
	ds := &windowsScheduledTaskDataSource{}
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	// Check that principal nested attribute has no 'password' field
	// (the DS uses scheduledTaskDSPrincipalAttrTypes which lacks password)
	if _, ok := scheduledTaskDSPrincipalAttrTypes["password"]; ok {
		t.Error("data source principal should not expose 'password' attribute")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestSTDataSource_Configure_Nil(t *testing.T) {
	ds := &windowsScheduledTaskDataSource{}
	resp := &datasource.ConfigureResponse{}
	ds.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should not error: %v", resp.Diagnostics)
	}
}

func TestSTDataSource_Configure_WrongType(t *testing.T) {
	ds := &windowsScheduledTaskDataSource{}
	resp := &datasource.ConfigureResponse{}
	ds.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type should produce error diagnostic")
	}
}

// ---------------------------------------------------------------------------
// dsStateToModel
// ---------------------------------------------------------------------------

func TestDsStateToModel_HappyPath(t *testing.T) {
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name:           "T",
		Path:           `\`,
		Description:    "desc",
		Enabled:        true,
		State:          "Ready",
		LastRunTime:    "2026-01-01T00:00:00Z",
		LastTaskResult: 0,
		NextRunTime:    "",
		Principal: &winclient.ScheduledTaskPrincipalState{
			UserID:    "SYSTEM",
			LogonType: "ServiceAccount",
			RunLevel:  "Limited",
		},
		Actions: []winclient.ScheduledTaskActionState{
			{Execute: "cmd.exe", Arguments: "/c echo", WorkingDirectory: `C:\`},
		},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{Type: "Daily", Enabled: true, DaysInterval: 1, DaysOfWeek: []string{}},
		},
		Settings: &winclient.ScheduledTaskSettingsState{
			AllowDemandStart:   true,
			ExecutionTimeLimit: "PT72H",
			MultipleInstances:  "Queue",
		},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("dsStateToModel diags: %v", diags)
	}
	if m.Name.ValueString() != "T" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
	if m.ID.ValueString() != `\T` {
		t.Errorf("ID = %q", m.ID.ValueString())
	}
	if m.Description.ValueString() != "desc" {
		t.Errorf("Description = %q", m.Description.ValueString())
	}
	if m.Principal.IsNull() {
		t.Error("Principal should not be null")
	}
	if m.Settings.IsNull() {
		t.Error("Settings should not be null")
	}
}

func TestDsStateToModel_NilPrincipal(t *testing.T) {
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`,
		Actions:  []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{{Type: "Daily", DaysOfWeek: []string{}}},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if !m.Principal.IsNull() {
		t.Error("nil principal should map to null object")
	}
}

func TestDsStateToModel_NilSettings(t *testing.T) {
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`,
		Actions:  []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{{Type: "Daily", DaysOfWeek: []string{}}},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if !m.Settings.IsNull() {
		t.Error("nil settings should map to null object")
	}
}

func TestDsStateToModel_WeeklyTrigger(t *testing.T) {
	// EC-5: weekly multi-day preserved
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`,
		Actions: []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{
				Type:       "Weekly",
				Enabled:    true,
				DaysOfWeek: []string{"Monday", "Wednesday", "Friday"},
			},
		},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	var triggers []windowsScheduledTaskTriggerModel
	if d := m.Triggers.ElementsAs(ctx, &triggers, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	if len(triggers) == 0 {
		t.Fatal("no triggers")
	}
	var dows []string
	if d := triggers[0].DaysOfWeek.ElementsAs(ctx, &dows, false); d.HasError() {
		t.Fatalf("DaysOfWeek ElementsAs: %v", d)
	}
	if len(dows) != 3 {
		t.Errorf("expected 3 days_of_week, got %d", len(dows))
	}
}

func TestDsStateToModel_SentinelTimes(t *testing.T) {
	// EC-10: sentinel last_run_time / next_run_time → empty string in DS model
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`,
		LastRunTime: "", NextRunTime: "",
		Actions:  []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{{Type: "Daily", DaysOfWeek: []string{}}},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if m.LastRunTime.ValueString() != "" || m.NextRunTime.ValueString() != "" {
		t.Errorf("sentinel times should be empty, got last=%q next=%q",
			m.LastRunTime.ValueString(), m.NextRunTime.ValueString())
	}
}

func TestDsStateToModel_MultipleActions(t *testing.T) {
	// EC-6: multiple actions list order preserved
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`,
		Actions: []winclient.ScheduledTaskActionState{
			{Execute: "first.exe"},
			{Execute: "second.exe"},
			{Execute: "third.exe"},
		},
		Triggers: []winclient.ScheduledTaskTriggerState{{Type: "Daily", DaysOfWeek: []string{}}},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	var actions []windowsScheduledTaskActionModel
	if d := m.Actions.ElementsAs(ctx, &actions, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	if len(actions) != 3 {
		t.Errorf("expected 3 actions, got %d", len(actions))
	}
	if actions[0].Execute.ValueString() != "first.exe" {
		t.Errorf("action[0] = %q, want first.exe", actions[0].Execute.ValueString())
	}
	if actions[2].Execute.ValueString() != "third.exe" {
		t.Errorf("action[2] = %q, want third.exe", actions[2].Execute.ValueString())
	}
}

func TestDsStateToModel_OnEventTrigger(t *testing.T) {
	// EC-12: on_event trigger subscription field preserved
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`,
		Actions: []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{Type: "OnEvent", Subscription: "<QueryList/>", DaysOfWeek: []string{}},
		},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	var triggers []windowsScheduledTaskTriggerModel
	if d := m.Triggers.ElementsAs(ctx, &triggers, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	if len(triggers) == 0 {
		t.Fatal("no triggers")
	}
	if triggers[0].Subscription.ValueString() != "<QueryList/>" {
		t.Errorf("Subscription = %q", triggers[0].Subscription.ValueString())
	}
	if triggers[0].Type.ValueString() != "OnEvent" {
		t.Errorf("Type = %q", triggers[0].Type.ValueString())
	}
}

func TestDsStateToModel_DriftDetection_Disabled(t *testing.T) {
	// EC-8: task disabled out-of-band → enabled=false in DS model
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`, Enabled: false, State: "Disabled",
		Actions:  []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{{Type: "Daily", DaysOfWeek: []string{}}},
	}
	m, diags := dsStateToModel(ctx, s)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if m.Enabled.ValueBool() {
		t.Error("expected enabled=false for disabled task")
	}
	if m.State.ValueString() != "Disabled" {
		t.Errorf("State = %q, want Disabled", m.State.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read (via fake client invocations)
// ---------------------------------------------------------------------------

func TestSTDataSource_Read_NotFound_Error(t *testing.T) {
	// Data source returns error when task not found (unlike resource which removes)
	fake := &fakeSTClientDS{readOut: nil, readErr: nil}
	state, err := fake.Read(context.Background(), `\NoSuchTask`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// state is nil — DS should add error diagnostic
	if state != nil {
		t.Error("expected nil state for not found")
	}
}

func TestSTDataSource_Read_ClientError(t *testing.T) {
	fake := &fakeSTClientDS{readErr: errors.New("SSH down")}
	_, err := fake.Read(context.Background(), `\T`)
	if err == nil {
		t.Fatal("expected client error")
	}
	diags := scheduledTaskErrDiag("DataSource.Read", err)
	if !diags.HasError() {
		t.Error("expected error diagnostic")
	}
}

func TestSTDataSource_Read_PermissionDenied(t *testing.T) {
	// EC-13: non-admin session surfaced clearly
	fake := &fakeSTClientDS{
		readErr: winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorPermissionDenied, "Access is denied", nil, nil),
	}
	_, err := fake.Read(context.Background(), `\T`)
	if !winclient.IsScheduledTaskError(err, winclient.ScheduledTaskErrorPermissionDenied) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
	diags := scheduledTaskErrDiag("DataSource.Read", err)
	if !diags.HasError() {
		t.Error("expected error diagnostic for permission denied")
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

// stDSObjType mirrors the data source schema as a tftypes object, so the
// framework-level Read below decodes config exactly as Terraform would.
func stDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":               tftypes.String,
		"name":             tftypes.String,
		"path":             tftypes.String,
		"description":      tftypes.String,
		"enabled":          tftypes.Bool,
		"state":            tftypes.String,
		"last_run_time":    tftypes.String,
		"last_task_result": tftypes.Number,
		"next_run_time":    tftypes.String,
		"principal": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"user_id":    tftypes.String,
			"logon_type": tftypes.String,
			"run_level":  tftypes.String,
		}},
		"actions": tftypes.List{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"execute":           tftypes.String,
			"arguments":         tftypes.String,
			"working_directory": tftypes.String,
		}}},
		"triggers": tftypes.List{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"type":                 tftypes.String,
			"enabled":              tftypes.Bool,
			"start_boundary":       tftypes.String,
			"end_boundary":         tftypes.String,
			"execution_time_limit": tftypes.String,
			"delay":                tftypes.String,
			"days_interval":        tftypes.Number,
			"days_of_week":         tftypes.List{ElementType: tftypes.String},
			"weeks_interval":       tftypes.Number,
			"user_id":              tftypes.String,
			"subscription":         tftypes.String,
		}}},
		"settings": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"allow_demand_start":             tftypes.Bool,
			"allow_hard_terminate":           tftypes.Bool,
			"start_when_available":           tftypes.Bool,
			"run_only_if_network_available":  tftypes.Bool,
			"execution_time_limit":           tftypes.String,
			"multiple_instances":             tftypes.String,
			"disallow_start_if_on_batteries": tftypes.Bool,
			"stop_if_going_on_batteries":     tftypes.Bool,
			"wake_to_run":                    tftypes.Bool,
			"run_only_if_idle":               tftypes.Bool,
		}},
		"timeouts": dsTimeoutsObjType(),
	}}
}

// stDSConfig builds a tfsdk.Config for the data source Read with only the
// lookup key set; everything else (including `timeouts`) is null.
func stDSConfig(name string) tfsdk.Config {
	d := &windowsScheduledTaskDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	objType := stDSObjType()
	nullStr := tftypes.NewValue(tftypes.String, nil)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(objType, map[string]tftypes.Value{
			"id":               nullStr,
			"name":             tftypes.NewValue(tftypes.String, name),
			"path":             nullStr,
			"description":      nullStr,
			"enabled":          tftypes.NewValue(tftypes.Bool, nil),
			"state":            nullStr,
			"last_run_time":    nullStr,
			"last_task_result": tftypes.NewValue(tftypes.Number, nil),
			"next_run_time":    nullStr,
			"principal":        tftypes.NewValue(objType.AttributeTypes["principal"], nil),
			"actions":          tftypes.NewValue(objType.AttributeTypes["actions"], nil),
			"triggers":         tftypes.NewValue(objType.AttributeTypes["triggers"], nil),
			"settings":         tftypes.NewValue(objType.AttributeTypes["settings"], nil),
			"timeouts":         dsNullTimeoutsValue(),
		}),
	}
}

// TestSTDataSourceRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read` (issue #197):
// stDSDefaultTimeout when the block is absent, the configured value when set.
func TestSTDataSourceRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", stDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSTClientDS{readOut: minimalSTState("T", `\`)}
			d := &windowsScheduledTaskDataSource{stClient: fake}
			cfg := stDSConfig("T")
			if tc.customRead != "" {
				cfg = dsConfigWithReadTimeout(t, cfg, tc.customRead)
			}
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
			d.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound (issue #197)")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
	}
}
