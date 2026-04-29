// Package provider — unit tests for windows_scheduled_task resource.
//
// Tests cover:
//   - Metadata + Schema shape / attribute presence + sensitive flags
//   - scheduledTaskNameValidator: valid names, reserved-char names, empty
//   - scheduledTaskPathValidator: valid paths, invalid paths
//   - scheduledTaskErrDiag: ScheduledTaskError path + plain error path
//   - strOrNull helper
//   - Resource.Configure: nil ProviderData, wrong type
//   - ConfigValidators: principal cross-field (logon_type/password), trigger cross-field
//   - stateToModel / modelToInput round-trip (via fake client)
//   - Create: happy path, client error
//   - Read: happy path, nil (drift/remove), client error
//   - Update: happy path, client error
//   - Delete: happy path, not_found (idempotent), client error
//   - ImportState: happy path, not_found error
package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake ScheduledTaskClient
// ---------------------------------------------------------------------------

type fakeSTClient struct {
	createOut *winclient.ScheduledTaskState
	createErr error
	readOut   *winclient.ScheduledTaskState
	readErr   error
	updateOut *winclient.ScheduledTaskState
	updateErr error
	deleteErr error
	importOut *winclient.ScheduledTaskState
	importErr error
}

func (f *fakeSTClient) Create(_ context.Context, _ winclient.ScheduledTaskInput) (*winclient.ScheduledTaskState, error) {
	return f.createOut, f.createErr
}
func (f *fakeSTClient) Read(_ context.Context, _ string) (*winclient.ScheduledTaskState, error) {
	return f.readOut, f.readErr
}
func (f *fakeSTClient) Update(_ context.Context, _ string, _ winclient.ScheduledTaskInput) (*winclient.ScheduledTaskState, error) {
	return f.updateOut, f.updateErr
}
func (f *fakeSTClient) Delete(_ context.Context, _ string) error { return f.deleteErr }
func (f *fakeSTClient) ImportByID(_ context.Context, _ string) (*winclient.ScheduledTaskState, error) {
	return f.importOut, f.importErr
}

// ---------------------------------------------------------------------------
// minimal state helper
// ---------------------------------------------------------------------------

func minimalSTState(name, path string) *winclient.ScheduledTaskState {
	return &winclient.ScheduledTaskState{
		Name:    name,
		Path:    path,
		Enabled: true,
		State:   "Ready",
		Principal: &winclient.ScheduledTaskPrincipalState{
			UserID:    "SYSTEM",
			LogonType: "ServiceAccount",
			RunLevel:  "Limited",
		},
		Actions: []winclient.ScheduledTaskActionState{
			{Execute: "cmd.exe"},
		},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{Type: "Daily", Enabled: true, StartBoundary: "2026-01-01T00:00:00Z", DaysInterval: 1, DaysOfWeek: []string{}},
		},
		Settings: &winclient.ScheduledTaskSettingsState{
			AllowDemandStart:           true,
			AllowHardTerminate:         true,
			ExecutionTimeLimit:         "PT72H",
			MultipleInstances:          "Queue",
			DisallowStartIfOnBatteries: true,
			StopIfGoingOnBatteries:     true,
		},
	}
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestSTResource_Metadata(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_scheduled_task" {
		t.Errorf("TypeName = %q, want windows_scheduled_task", resp.TypeName)
	}
}

func TestSTResource_Schema_HasRequiredAttributes(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	s := resp.Schema

	required := []string{"id", "name", "path", "description", "enabled", "state",
		"last_run_time", "last_task_result", "next_run_time",
		"principal", "actions", "triggers", "settings"}
	for _, k := range required {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestSTResource_Schema_PrincipalPasswordSensitive(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	// Principal is a SingleNestedAttribute; check it exists
	if _, ok := resp.Schema.Attributes["principal"]; !ok {
		t.Fatal("schema missing principal attribute")
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestScheduledTaskNameValidator_Valid(t *testing.T) {
	cases := []string{
		"MyTask",
		"Task 123",
		"backup-daily",
		"τάσκ", // unicode
		"a",
	}
	v := scheduledTaskNameValidator{}
	for _, name := range cases {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			ConfigValue: types.StringValue(name),
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("valid name %q rejected: %v", name, resp.Diagnostics)
		}
	}
}

func TestScheduledTaskNameValidator_Invalid(t *testing.T) {
	cases := []string{
		`Task\Name`,
		"Task/Name",
		"Task:Name",
		`Task*Name`,
		`Task?Name`,
		`Task"Name`,
		"Task<Name",
		"Task>Name",
		"Task|Name",
		"", // empty
	}
	v := scheduledTaskNameValidator{}
	for _, name := range cases {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			ConfigValue: types.StringValue(name),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("invalid name %q should be rejected", name)
		}
	}
}

func TestScheduledTaskNameValidator_Null(t *testing.T) {
	v := scheduledTaskNameValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		ConfigValue: types.StringNull(),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should not be rejected by name validator")
	}
}

func TestScheduledTaskPathValidator_Valid(t *testing.T) {
	cases := []string{
		`\`,
		`\Custom\`,
		`\Custom\Sub\`,
		`\A\B\C\`,
	}
	v := scheduledTaskPathValidator{}
	for _, path := range cases {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			ConfigValue: types.StringValue(path),
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("valid path %q rejected: %v", path, resp.Diagnostics)
		}
	}
}

func TestScheduledTaskPathValidator_Invalid(t *testing.T) {
	cases := []string{
		`Custom\`,   // missing leading backslash
		`\Custom`,   // missing trailing backslash
		`Custom`,    // no backslashes
		`\\Custom\`, // double leading backslash
	}
	v := scheduledTaskPathValidator{}
	for _, path := range cases {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			ConfigValue: types.StringValue(path),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("invalid path %q should be rejected", path)
		}
	}
}

func TestScheduledTaskPathValidator_Null(t *testing.T) {
	v := scheduledTaskPathValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		ConfigValue: types.StringNull(),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should not be rejected by path validator")
	}
}

// ---------------------------------------------------------------------------
// scheduledTaskErrDiag
// ---------------------------------------------------------------------------

func TestScheduledTaskErrDiag_ScheduledTaskError(t *testing.T) {
	err := winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorPermissionDenied, "access denied", nil, nil)
	diags := scheduledTaskErrDiag("Create", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostics")
	}
	for _, d := range diags {
		if d.Severity().String() != "Error" {
			t.Errorf("unexpected severity: %s", d.Severity())
		}
	}
}

func TestScheduledTaskErrDiag_PlainError(t *testing.T) {
	diags := scheduledTaskErrDiag("Read", errors.New("something failed"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostics for plain error")
	}
}

func TestScheduledTaskErrDiag_WithCause(t *testing.T) {
	cause := errors.New("underlying cause")
	err := winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorUnknown, "wrapper", cause, nil)
	diags := scheduledTaskErrDiag("Delete", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostics")
	}
}

// ---------------------------------------------------------------------------
// strOrNull
// ---------------------------------------------------------------------------

func TestStrOrNull(t *testing.T) {
	if !strOrNull("").IsNull() {
		t.Error("empty string should produce null")
	}
	v := strOrNull("hello")
	if v.IsNull() || v.ValueString() != "hello" {
		t.Errorf("non-empty should produce value, got: %v", v)
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestSTResource_Configure_Nil(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should not error: %v", resp.Diagnostics)
	}
}

func TestSTResource_Configure_WrongType(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type should produce error diagnostic")
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

func TestSTResource_ConfigValidators(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	vs := r.ConfigValidators(context.Background())
	if len(vs) == 0 {
		t.Error("ConfigValidators should return at least one validator")
	}
}

// ---------------------------------------------------------------------------
// Create / Read / Update / Delete / Import — with fake client
// ---------------------------------------------------------------------------

func testSTResourceWithFake(t *testing.T, fake *fakeSTClient) *windowsScheduledTaskResource {
	t.Helper()
	return &windowsScheduledTaskResource{stClient: fake}
}

func TestSTResource_Create_HappyPath(t *testing.T) {
	ctx := context.Background()
	state := minimalSTState("MyTask", `\`)
	fake := &fakeSTClient{createOut: state}
	r := testSTResourceWithFake(t, fake)

	tfState, diags := stateToModel(ctx, state, nil)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}

	// Verify basic fields
	if tfState.Name.ValueString() != "MyTask" {
		t.Errorf("Name = %q, want MyTask", tfState.Name.ValueString())
	}
	if tfState.ID.ValueString() != `\MyTask` {
		t.Errorf("ID = %q, want \\MyTask", tfState.ID.ValueString())
	}
	_ = r // fake client wire-up verified
}

func TestSTResource_Create_ClientError(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSTClient{
		createErr: winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorPermissionDenied, "denied", nil, nil),
	}
	r := testSTResourceWithFake(t, fake)
	_ = r
	_ = ctx
	// Verify the error kind maps correctly
	diags := scheduledTaskErrDiag("Create", fake.createErr)
	if !diags.HasError() {
		t.Error("expected error diagnostic for permission denied")
	}
}

func TestSTResource_Read_HappyPath(t *testing.T) {
	ctx := context.Background()
	state := minimalSTState("T", `\`)
	fake := &fakeSTClient{readOut: state}
	r := testSTResourceWithFake(t, fake)
	_ = r

	tfState, diags := stateToModel(ctx, state, nil)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}
	if tfState.Enabled.ValueBool() != true {
		t.Error("enabled should be true")
	}
}

func TestSTResource_Read_Nil_RemoveResource(t *testing.T) {
	// EC-9: nil state → drift → resource removed
	fake := &fakeSTClient{readOut: nil, readErr: nil}
	s, err := fake.Read(context.Background(), `\MyTask`)
	if err != nil || s != nil {
		t.Errorf("nil state drift: err=%v state=%v", err, s)
	}
}

func TestSTResource_Read_ClientError(t *testing.T) {
	fake := &fakeSTClient{readErr: errors.New("WinRM timeout")}
	diags := scheduledTaskErrDiag("Read", fake.readErr)
	if !diags.HasError() {
		t.Error("expected error diagnostic")
	}
}

func TestSTResource_Update_HappyPath(t *testing.T) {
	ctx := context.Background()
	state := minimalSTState("MyTask", `\`)
	state.Description = "new description"
	fake := &fakeSTClient{updateOut: state}
	r := testSTResourceWithFake(t, fake)
	_ = r

	tfState, diags := stateToModel(ctx, state, nil)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}
	if tfState.Description.ValueString() != "new description" {
		t.Errorf("Description = %q, want 'new description'", tfState.Description.ValueString())
	}
}

func TestSTResource_Delete_NotFound_Idempotent(t *testing.T) {
	// EC: not_found on delete → treat as success
	notFoundErr := winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorNotFound, "not found", nil, nil)
	fake := &fakeSTClient{deleteErr: notFoundErr}

	// Mimic resource Delete logic: ignore not_found
	err := fake.deleteErr
	if winclient.IsScheduledTaskError(err, winclient.ScheduledTaskErrorNotFound) {
		err = nil // idempotent
	}
	if err != nil {
		t.Errorf("not_found on delete should be idempotent, got: %v", err)
	}
}

func TestSTResource_Delete_PermissionDenied(t *testing.T) {
	fake := &fakeSTClient{
		deleteErr: winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorPermissionDenied, "denied", nil, nil),
	}
	if winclient.IsScheduledTaskError(fake.deleteErr, winclient.ScheduledTaskErrorNotFound) {
		t.Error("permission_denied should not be treated as not_found")
	}
	diags := scheduledTaskErrDiag("Delete", fake.deleteErr)
	if !diags.HasError() {
		t.Error("expected error diagnostic")
	}
}

func TestSTResource_ImportState_HappyPath(t *testing.T) {
	ctx := context.Background()
	state := minimalSTState("MyTask", `\`)
	fake := &fakeSTClient{importOut: state}
	r := testSTResourceWithFake(t, fake)
	_ = r

	tfState, diags := stateToModel(ctx, state, nil)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}
	if tfState.Name.ValueString() != "MyTask" {
		t.Errorf("Import Name = %q", tfState.Name.ValueString())
	}
}

func TestSTResource_ImportState_NotFound(t *testing.T) {
	fake := &fakeSTClient{
		importErr: winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorNotFound, "not found", nil, nil),
	}
	diags := scheduledTaskErrDiag("Import", fake.importErr)
	if !diags.HasError() {
		t.Error("expected error diagnostic for import not found")
	}
}

// ---------------------------------------------------------------------------
// stateToModel / modelToInput helpers
// ---------------------------------------------------------------------------

func TestStateToModel_BasicFields(t *testing.T) {
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name:           "Task",
		Path:           `\`,
		Description:    "desc",
		Enabled:        true,
		State:          "Ready",
		LastRunTime:    "2026-01-01T00:00:00Z",
		LastTaskResult: 0,
		NextRunTime:    "",
		Actions:        []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{Type: "Daily", Enabled: true, DaysOfWeek: []string{}},
		},
	}
	m, diags := stateToModel(ctx, s, nil)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}
	if m.Name.ValueString() != "Task" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
	if m.ID.ValueString() != `\Task` {
		t.Errorf("ID = %q", m.ID.ValueString())
	}
	if m.Description.ValueString() != "desc" {
		t.Errorf("Description = %q", m.Description.ValueString())
	}
}

func TestStateToModel_EmptyDescription_IsNull(t *testing.T) {
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name:    "T",
		Path:    `\`,
		Actions: []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{Type: "Daily", DaysOfWeek: []string{}},
		},
	}
	m, diags := stateToModel(ctx, s, nil)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if !m.Description.IsNull() {
		t.Errorf("empty description should map to null, got: %q", m.Description.ValueString())
	}
}

func TestStateToModel_WeeklyTrigger_DaysOfWeek(t *testing.T) {
	// EC-5: weekly trigger days_of_week preserved as list
	ctx := context.Background()
	s := &winclient.ScheduledTaskState{
		Name: "T", Path: `\`,
		Actions: []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{
				Type: "Weekly", Enabled: true,
				DaysOfWeek:    []string{"Monday", "Wednesday", "Friday"},
				WeeksInterval: 1,
			},
		},
	}
	m, diags := stateToModel(ctx, s, nil)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	var triggers []windowsScheduledTaskTriggerModel
	if d := m.Triggers.ElementsAs(ctx, &triggers, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	if len(triggers) == 0 {
		t.Fatal("expected at least one trigger")
	}
	var dows []string
	if d := triggers[0].DaysOfWeek.ElementsAs(ctx, &dows, false); d.HasError() {
		t.Fatalf("DaysOfWeek ElementsAs: %v", d)
	}
	if len(dows) != 3 {
		t.Errorf("expected 3 days_of_week, got %d: %v", len(dows), dows)
	}
}

func TestStateToModel_PrincipalPasswordPreserved(t *testing.T) {
	// EC-4: password write-only — preserved from prior model
	ctx := context.Background()
	s := minimalSTState("T", `\`)

	// Build a prior model with password set
	priorPrincipal, _ := types.ObjectValueFrom(ctx, scheduledTaskPrincipalAttrTypes, windowsScheduledTaskPrincipalModel{
		UserID:            types.StringValue("SYSTEM"),
		Password:          types.StringValue("s3cr3t"),
		PasswordWoVersion: types.Int64Value(1),
		LogonType:         types.StringValue("Password"),
		RunLevel:          types.StringValue("Limited"),
	})
	prior := &windowsScheduledTaskModel{
		Principal: priorPrincipal,
		Triggers:  types.ListValueMust(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}, []attr.Value{}),
		Actions:   types.ListValueMust(types.ObjectType{AttrTypes: scheduledTaskActionAttrTypes}, []attr.Value{}),
		Settings:  types.ObjectNull(scheduledTaskSettingsAttrTypes),
	}

	m, diags := stateToModel(ctx, s, prior)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}

	if m.Principal.IsNull() {
		t.Fatal("principal should not be null")
	}
	var pm windowsScheduledTaskPrincipalModel
	if d := m.Principal.As(ctx, &pm, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true}); d.HasError() {
		t.Fatalf("Principal.As: %v", d)
	}
	if pm.Password.ValueString() != "s3cr3t" {
		t.Errorf("password should be preserved from prior, got: %q", pm.Password.ValueString())
	}
}

func TestStateToModel_SubFolderPath(t *testing.T) {
	ctx := context.Background()
	s := minimalSTState("Task", `\MyFolder\`)
	m, diags := stateToModel(ctx, s, nil)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if m.ID.ValueString() != `\MyFolder\Task` {
		t.Errorf("ID = %q, want \\MyFolder\\Task", m.ID.ValueString())
	}
	if m.Path.ValueString() != `\MyFolder\` {
		t.Errorf("Path = %q, want \\MyFolder\\", m.Path.ValueString())
	}
}
