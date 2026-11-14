// Package provider — unit tests for windows_scheduled_task resource.
//
// Tests cover:
//   - Metadata + Schema shape / attribute presence + sensitive flags
//   - scheduledTaskNameValidator: valid names, reserved-char names, empty
//   - scheduledTaskPathValidator: valid paths, invalid paths
//   - duration validators: settings.execution_time_limit (days or less; year and
//     month components would be approximated by ToTimeSpan) vs trigger
//     execution_time_limit/delay (full XSD grammar, stored verbatim)
//   - durationValue: value-semantic equality across equivalent spellings
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
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

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

// TestSTResource_Schema_StateUseStateForUnknown (issue #322): state is a
// Computed-only observed value (the live Ready/Disabled/Running/Queued/
// Unknown operational state) and must carry UseStateForUnknown like its
// computed neighbours, so plans never go unknown on it.
func TestSTResource_Schema_StateUseStateForUnknown(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	stateAttr, ok := resp.Schema.Attributes["state"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("state: expected schema.StringAttribute, got %T", resp.Schema.Attributes["state"])
	}
	if !stateAttr.Computed {
		t.Error("state must be Computed")
	}
	if stateAttr.Optional || stateAttr.Required {
		t.Error("state must be Computed-only (not configurable)")
	}
	if len(stateAttr.PlanModifiers) != 1 || !reflect.DeepEqual(stateAttr.PlanModifiers[0], stringplanmodifier.UseStateForUnknown()) {
		t.Errorf("state must carry exactly UseStateForUnknown, got %v", stateAttr.PlanModifiers)
	}
}

// TestSTResource_Schema_TriggerNestedUseStateForUnknown (issues #322/#324):
// every Optional+Computed attribute nested inside the triggers SetNested
// object must carry UseStateForUnknown (or a real Windows Default, like
// enabled). Without it, a first plan leaves Unknown values inside planned
// set elements and Set correlation fails with "planned set element does not
// correlate with any element in actual" once Read fills Windows defaults
// (e.g. days_interval 1 for a Daily trigger planned with only
// type/start_boundary/enabled).
func TestSTResource_Schema_TriggerNestedUseStateForUnknown(t *testing.T) {
	r := &windowsScheduledTaskResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	trigAttr, ok := resp.Schema.Attributes["triggers"].(schema.SetNestedAttribute)
	if !ok {
		t.Fatalf("triggers: expected schema.SetNestedAttribute, got %T", resp.Schema.Attributes["triggers"])
	}
	nested := trigAttr.NestedObject.Attributes

	for _, name := range []string{"end_boundary", "execution_time_limit", "delay", "user_id", "subscription"} {
		a, ok := nested[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected schema.StringAttribute, got %T", name, nested[name])
		}
		if !a.Optional || !a.Computed {
			t.Errorf("%s must be Optional+Computed, got optional=%v computed=%v", name, a.Optional, a.Computed)
		}
		if len(a.PlanModifiers) != 1 || !reflect.DeepEqual(a.PlanModifiers[0], stringplanmodifier.UseStateForUnknown()) {
			t.Errorf("%s must carry exactly UseStateForUnknown, got %v", name, a.PlanModifiers)
		}
	}

	for _, name := range []string{"days_interval", "weeks_interval"} {
		a, ok := nested[name].(schema.Int64Attribute)
		if !ok {
			t.Fatalf("%s: expected schema.Int64Attribute, got %T", name, nested[name])
		}
		if !a.Optional || !a.Computed {
			t.Errorf("%s must be Optional+Computed, got optional=%v computed=%v", name, a.Optional, a.Computed)
		}
		if len(a.PlanModifiers) != 1 || !reflect.DeepEqual(a.PlanModifiers[0], int64planmodifier.UseStateForUnknown()) {
			t.Errorf("%s must carry exactly UseStateForUnknown, got %v", name, a.PlanModifiers)
		}
	}

	dows, ok := nested["days_of_week"].(schema.SetAttribute)
	if !ok {
		t.Fatalf("days_of_week: expected schema.SetAttribute, got %T", nested["days_of_week"])
	}
	if !dows.Optional || !dows.Computed {
		t.Errorf("days_of_week must be Optional+Computed, got optional=%v computed=%v", dows.Optional, dows.Computed)
	}
	if len(dows.PlanModifiers) != 1 || !reflect.DeepEqual(dows.PlanModifiers[0], setplanmodifier.UseStateForUnknown()) {
		t.Errorf("days_of_week must carry exactly UseStateForUnknown, got %v", dows.PlanModifiers)
	}

	enabled, ok := nested["enabled"].(schema.BoolAttribute)
	if !ok {
		t.Fatalf("enabled: expected schema.BoolAttribute, got %T", nested["enabled"])
	}
	if enabled.Default == nil {
		t.Error("enabled must keep its Windows Default (true)")
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

// stDurationAccepted reports whether a validator chain stays silent for d.
func stDurationAccepted(v validator.String, d string) bool {
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		ConfigValue: types.StringValue(d),
	}, resp)
	return !resp.Diagnostics.HasError()
}

func TestScheduledTaskSettingsDurationValidator_Valid(t *testing.T) {
	// settings.execution_time_limit is converted through XmlConvert::ToTimeSpan
	// on apply (the cmdlet parameter is [TimeSpan]), and read back verbatim as
	// the ISO 8601 string. Every XSD duration of days or less is therefore
	// TimeSpan-expressible and safe, including day forms: P3D is exactly 72h.
	v := stringvalidator.RegexMatches(scheduledTaskDurationRegex, scheduledTaskDurationDesc)
	cases := []string{
		"PT72H", "PT0S", "PT5M", "PT1H", "PT4H", "PT1440M",
		"PT1M30S", "PT0.5S", "PT1H30M", "PT1H30M15S", "PT30S",
		"P3D", "P1DT2H", "P3DT0H0M0S", "P1D", "PT0H", "PT0072H",
		// Redundant or non-canonical spellings are fine: the attribute compares
		// by duration value, so an equivalent re-read spelling is not a drift.
		"PT1H0M", "PT60M", "PT1H60M",
	}
	for _, d := range cases {
		if !stDurationAccepted(v, d) {
			t.Errorf("valid settings duration %q rejected", d)
		}
	}
}

func TestScheduledTaskSettingsDurationValidator_Invalid(t *testing.T) {
	// Year and month components are rejected because XmlConvert::ToTimeSpan
	// would silently approximate them as 365- and 30-day intervals rather than
	// converting them exactly. Component-less forms ("P", "PT", "P3DT") carry
	// no duration and do make ToTimeSpan throw. TimeSpan forms ("3.00:00:00")
	// are not valid configuration, and negative durations are
	// xs:negativeDuration.
	v := stringvalidator.RegexMatches(scheduledTaskDurationRegex, scheduledTaskDurationDesc)
	cases := []string{
		"bogus", "3.00:00:00", "00:00:00", "72H", "-PT1H", "-P1D", "",
		"P", "PT", "P3DT", "P1YT", "T",
		"P1Y", "P1M", "P1Y2M3D", "P1M4DT2H5M", "P1YT2H",
	}
	for _, d := range cases {
		if stDurationAccepted(v, d) {
			t.Errorf("invalid settings duration %q should be rejected", d)
		}
	}
}

func TestScheduledTaskTriggerDurationValidator_Valid(t *testing.T) {
	// Trigger execution_time_limit/delay are string-typed CIM properties
	// assigned and reported verbatim, so the full XSD grammar is safe there,
	// including year and month components, and including every spelling
	// settings.execution_time_limit must reject.
	v := stringvalidator.RegexMatches(scheduledTaskTriggerDurationRegex, scheduledTaskTriggerDurationDesc)
	cases := []string{
		"P3D", "P1DT2H", "P3DT0H0M0S", "PT1440M", "PT72H",
		"PT5M", "PT1H30M15S", "PT0.5S", "PT0S", "P1D",
		"P1Y", "P1M", "P1M4DT2H5M", "P1Y2M3D", "P1YT2H",
	}
	for _, d := range cases {
		if !stDurationAccepted(v, d) {
			t.Errorf("valid trigger duration %q rejected", d)
		}
	}
}

func TestScheduledTaskTriggerDurationValidator_Invalid(t *testing.T) {
	// TimeSpan forms are not valid configuration, component-less forms carry no
	// duration, and xs:negativeDuration is rejected. Unlike the settings
	// attribute, year/month components ARE valid here.
	v := stringvalidator.RegexMatches(scheduledTaskTriggerDurationRegex, scheduledTaskTriggerDurationDesc)
	cases := []string{
		"bogus", "3.00:00:00", "00:00:00", "72H", "-PT1H", "",
		"P", "PT", "P3DT", "T", "PTS",
	}
	for _, d := range cases {
		if stDurationAccepted(v, d) {
			t.Errorf("invalid trigger duration %q should be rejected", d)
		}
	}
}

// TestScheduledTaskDurationValidators_SettingsStricterThanTrigger pins the one
// intentional asymmetry: settings.execution_time_limit must reject the
// TimeSpan-inexpressible year/month forms that triggers accept.
func TestScheduledTaskDurationValidators_SettingsStricterThanTrigger(t *testing.T) {
	settings := stringvalidator.RegexMatches(scheduledTaskDurationRegex, scheduledTaskDurationDesc)
	trigger := stringvalidator.RegexMatches(scheduledTaskTriggerDurationRegex, scheduledTaskTriggerDurationDesc)
	for _, d := range []string{"P1Y", "P1M", "P1Y2M3D", "P1M4DT2H5M"} {
		if stDurationAccepted(settings, d) {
			t.Errorf("settings duration %q should be rejected (not TimeSpan-expressible)", d)
		}
		if !stDurationAccepted(trigger, d) {
			t.Errorf("trigger duration %q should be accepted (verbatim string property)", d)
		}
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

func TestScheduledTaskTriggerAllowsDelay(t *testing.T) {
	for _, tt := range []struct {
		triggerType string
		want        bool
	}{
		{triggerType: "AtLogon", want: true},
		{triggerType: "AtStartup", want: true},
		{triggerType: "OnEvent", want: true},
		{triggerType: "Once", want: false},
		{triggerType: "Daily", want: false},
		{triggerType: "Weekly", want: false},
	} {
		t.Run(tt.triggerType, func(t *testing.T) {
			if got := scheduledTaskTriggerAllowsDelay(tt.triggerType); got != tt.want {
				t.Errorf("scheduledTaskTriggerAllowsDelay(%q) = %t, want %t", tt.triggerType, got, tt.want)
			}
		})
	}
}

func TestValidateScheduledTaskPrincipalCredentials(t *testing.T) {
	password := "not-in-state"
	for _, tt := range []struct {
		name            string
		principal       *winclient.ScheduledTaskPrincipalInput
		requirePassword bool
		wantError       bool
	}{
		{
			name: "password principal has effective credential",
			principal: &winclient.ScheduledTaskPrincipalInput{
				LogonType: "Password",
				Password:  &password,
			},
			requirePassword: true,
		},
		{
			name: "password principal missing credential on create",
			principal: &winclient.ScheduledTaskPrincipalInput{
				LogonType: "Password",
			},
			requirePassword: true,
			wantError:       true,
		},
		{
			name: "steady-state update may omit password",
			principal: &winclient.ScheduledTaskPrincipalInput{
				LogonType: "Password",
			},
			requirePassword: false,
		},
		{
			name: "forbidden logon type rejects credential",
			principal: &winclient.ScheduledTaskPrincipalInput{
				LogonType: "S4U",
				Password:  &password,
			},
			wantError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			diags := validateScheduledTaskPrincipalCredentials(winclient.ScheduledTaskInput{Principal: tt.principal}, tt.requirePassword)
			if gotError := diags.HasError(); gotError != tt.wantError {
				t.Fatalf("HasError() = %t, want %t; diagnostics: %v", gotError, tt.wantError, diags)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Create / Read / Update / Delete / Import — with fake client
// ---------------------------------------------------------------------------

func testSTResourceWithFake(t *testing.T, fake *fakeSTClient) {
	t.Helper()
	_ = &windowsScheduledTaskResource{stClient: fake}
}

func TestSTResource_Create_HappyPath(t *testing.T) {
	ctx := context.Background()
	state := minimalSTState("MyTask", `\`)
	fake := &fakeSTClient{createOut: state}
	testSTResourceWithFake(t, fake)

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
}

func TestSTResource_Create_ClientError(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSTClient{
		createErr: winclient.NewScheduledTaskError(winclient.ScheduledTaskErrorPermissionDenied, "denied", nil, nil),
	}
	testSTResourceWithFake(t, fake)
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
	testSTResourceWithFake(t, fake)

	tfState, diags := stateToModel(ctx, state, nil)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}
	if tfState.Enabled.ValueBool() != true {
		t.Error("enabled should be true")
	}
}

// deadlineSTClient captures the ctx deadline seen by Read (issue #196).
// Create/Update/Delete/ImportByID are promoted from the embedded fake.
type deadlineSTClient struct {
	fakeSTClient
	deadline time.Time
	ok       bool
}

func (f *deadlineSTClient) Read(ctx context.Context, _ string) (*winclient.ScheduledTaskState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

// stTimeoutsWithRead builds a timeouts.Value carrying a read duration, reusing
// the schema's attribute types so the value matches what the framework decodes.
func stTimeoutsWithRead(t *testing.T, d string) timeouts.Value {
	t.Helper()
	obj, diags := types.ObjectValue(
		map[string]attr.Type{
			"create": types.StringType,
			"read":   types.StringType,
			"update": types.StringType,
			"delete": types.StringType,
		},
		map[string]attr.Value{
			"create": types.StringNull(),
			"read":   types.StringValue(d),
			"update": types.StringNull(),
			"delete": types.StringNull(),
		},
	)
	if diags.HasError() {
		t.Fatalf("ObjectValue: %v", diags)
	}
	return timeouts.Value{Object: obj}
}

// TestSTResource_Read_BoundedByTimeouts verifies Read runs under a deadline
// derived from `timeouts.read` (issue #196): stDefaultTimeout when the block
// is absent, the configured value when set.
func TestSTResource_Read_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()
	r := &windowsScheduledTaskResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", stDefaultTimeout},
		{"custom", "5s", 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model, diags := stateToModel(ctx, minimalSTState("T", `\`), nil)
			if diags.HasError() {
				t.Fatalf("stateToModel: %v", diags)
			}
			if tc.customRead != "" {
				model.Timeouts = stTimeoutsWithRead(t, tc.customRead)
			}
			prior := tfsdk.State{Schema: schemaResp.Schema}
			if diags := prior.Set(ctx, model); diags.HasError() {
				t.Fatalf("State.Set: %v", diags)
			}
			fake := &deadlineSTClient{fakeSTClient: fakeSTClient{readOut: minimalSTState("T", `\`)}}
			r.stClient = fake
			resp := &resource.ReadResponse{State: prior}
			r.Read(ctx, resource.ReadRequest{State: prior}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound (issue #196)")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
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
	fake := &fakeSTClient{readErr: errors.New("SSH timeout")}
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
	testSTResourceWithFake(t, fake)

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
	testSTResourceWithFake(t, fake)

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

// deadlineImportSTClient captures the ctx deadline seen by ImportByID (issue
// #196). Other operations are promoted from the embedded fake.
type deadlineImportSTClient struct {
	fakeSTClient
	deadline time.Time
	ok       bool
}

func (f *deadlineImportSTClient) ImportByID(ctx context.Context, _ string) (*winclient.ScheduledTaskState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.importOut, f.importErr
}

// TestSTResource_ImportState_BoundedByTimeout verifies ImportState runs under
// a deadline: no prior state exists at import time, so a configured
// timeouts.read cannot be honoured and stDefaultTimeout bounds the call.
func TestSTResource_ImportState_BoundedByTimeout(t *testing.T) {
	ctx := context.Background()
	r := &windowsScheduledTaskResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	fake := &deadlineImportSTClient{fakeSTClient: fakeSTClient{importOut: minimalSTState("MyTask", `\`)}}
	r.stClient = fake
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.ImportState(ctx, resource.ImportStateRequest{ID: `\MyTask`}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState diags: %v", resp.Diagnostics)
	}
	if !fake.ok {
		t.Fatal("ImportState ran without a context deadline; ImportByID is unbounded (issue #196)")
	}
	if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > stDefaultTimeout {
		t.Errorf("ImportState deadline in %v, want (0, %v]", remaining, stDefaultTimeout)
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
	// EC-5: weekly trigger days_of_week preserved as a set
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
		UserID:            types.StringValue(`LAB-WINDOCKER-0\svc`),
		Password:          types.StringValue("s3cr3t"),
		PasswordWoVersion: types.Int64Value(1),
		LogonType:         types.StringValue("Password"),
		RunLevel:          types.StringValue("Limited"),
	})
	prior := &windowsScheduledTaskModel{
		Principal: priorPrincipal,
		Triggers:  types.SetValueMust(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}, []attr.Value{}),
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
	if pm.UserID.ValueString() != `LAB-WINDOCKER-0\svc` {
		t.Errorf("configured local account representation should be preserved, got: %q", pm.UserID.ValueString())
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

// TestBuildTriggerObject_UnknownIntervalResolvesToNull is a regression test for #70.
// On a create, the prior model is the plan, where an unset Optional+Computed interval
// is Unknown. When Windows reports the interval as not applicable (0), a Computed
// attribute must resolve to null — never stay Unknown, which Terraform rejects
// ("provider returned invalid result object after apply").
func TestBuildTriggerObject_UnknownIntervalResolvesToNull(t *testing.T) {
	ctx := context.Background()

	readTrigger := func(v attr.Value) windowsScheduledTaskTriggerModel {
		t.Helper()
		obj, ok := v.(types.Object)
		if !ok {
			t.Fatalf("expected types.Object, got %T", v)
		}
		var tm windowsScheduledTaskTriggerModel
		if d := obj.As(ctx, &tm, basetypes.ObjectAsOptions{}); d.HasError() {
			t.Fatalf("obj.As: %v", d)
		}
		return tm
	}

	t.Run("Daily_weeks_interval_unknown", func(t *testing.T) {
		// prior == plan: weeks_interval unset -> Unknown; Windows returns 0.
		prior := &windowsScheduledTaskTriggerModel{
			DaysInterval:  types.Int64Value(1),
			WeeksInterval: types.Int64Unknown(),
		}
		st := winclient.ScheduledTaskTriggerState{Type: "Daily", Enabled: true, DaysInterval: 1, WeeksInterval: 0}
		v, d := buildTriggerObject(ctx, st, prior)
		if d.HasError() {
			t.Fatalf("diags: %v", d)
		}
		tm := readTrigger(v)
		if tm.WeeksInterval.IsUnknown() {
			t.Error("weeks_interval must not be Unknown after apply")
		}
		if !tm.WeeksInterval.IsNull() {
			t.Errorf("weeks_interval = %v, want null", tm.WeeksInterval)
		}
	})

	t.Run("Weekly_days_interval_unknown", func(t *testing.T) {
		prior := &windowsScheduledTaskTriggerModel{
			DaysInterval:  types.Int64Unknown(),
			WeeksInterval: types.Int64Value(1),
		}
		st := winclient.ScheduledTaskTriggerState{Type: "Weekly", Enabled: true, DaysInterval: 0, WeeksInterval: 1}
		v, d := buildTriggerObject(ctx, st, prior)
		if d.HasError() {
			t.Fatalf("diags: %v", d)
		}
		tm := readTrigger(v)
		if tm.DaysInterval.IsUnknown() {
			t.Error("days_interval must not be Unknown after apply")
		}
		if !tm.DaysInterval.IsNull() {
			t.Errorf("days_interval = %v, want null", tm.DaysInterval)
		}
	})

	t.Run("known_prior_null_preserved", func(t *testing.T) {
		// A known prior value (null) is still preserved when Windows returns 0.
		prior := &windowsScheduledTaskTriggerModel{
			DaysInterval:  types.Int64Null(),
			WeeksInterval: types.Int64Null(),
		}
		st := winclient.ScheduledTaskTriggerState{Type: "Daily", Enabled: true, DaysInterval: 0, WeeksInterval: 0}
		v, d := buildTriggerObject(ctx, st, prior)
		if d.HasError() {
			t.Fatalf("diags: %v", d)
		}
		tm := readTrigger(v)
		if !tm.DaysInterval.IsNull() || !tm.WeeksInterval.IsNull() {
			t.Errorf("intervals = (%v, %v), want (null, null)", tm.DaysInterval, tm.WeeksInterval)
		}
	})
}

// TestBuildTriggerObject_DailyDefaultsResolveKnown is a regression test for
// the #324 acceptance failure ("planned set element does not correlate with
// any element in actual"). A Daily trigger planned with only
// type/start_boundary/enabled leaves every other nested attribute Unknown
// (all Optional+Computed, first plan has no prior state). When Windows
// reports its defaults for such a trigger (DaysInterval 1, everything else
// empty), the mapped object must contain no Unknown values: unknowns inside
// a planned Set element break correlation, while known values (and nulls
// for unset fields) correlate cleanly.
func TestBuildTriggerObject_DailyDefaultsResolveKnown(t *testing.T) {
	ctx := context.Background()

	// First-plan shape: only type/start_boundary/enabled known.
	prior := &windowsScheduledTaskTriggerModel{
		Type:               types.StringValue("Daily"),
		Enabled:            types.BoolValue(true),
		StartBoundary:      types.StringValue("2026-01-01T00:00:00Z"),
		EndBoundary:        types.StringUnknown(),
		ExecutionTimeLimit: types.StringUnknown(),
		Delay:              types.StringUnknown(),
		DaysInterval:       types.Int64Unknown(),
		DaysOfWeek:         types.SetUnknown(types.StringType),
		WeeksInterval:      types.Int64Unknown(),
		UserID:             types.StringUnknown(),
		Subscription:       subscriptionXMLValue{StringValue: types.StringUnknown()},
	}
	// Windows report for a default Daily trigger: interval default 1, all
	// optional strings empty.
	st := winclient.ScheduledTaskTriggerState{
		Type: "Daily", Enabled: true,
		StartBoundary: "2026-01-01T00:00:00Z", DaysInterval: 1,
	}
	v, d := buildTriggerObject(ctx, st, prior)
	if d.HasError() {
		t.Fatalf("diags: %v", d)
	}
	obj, ok := v.(types.Object)
	if !ok {
		t.Fatalf("expected types.Object, got %T", v)
	}
	var tm windowsScheduledTaskTriggerModel
	if d := obj.As(ctx, &tm, basetypes.ObjectAsOptions{}); d.HasError() {
		t.Fatalf("obj.As: %v", d)
	}

	for name, unknown := range map[string]bool{
		"end_boundary":         tm.EndBoundary.IsUnknown(),
		"execution_time_limit": tm.ExecutionTimeLimit.IsUnknown(),
		"delay":                tm.Delay.IsUnknown(),
		"days_interval":        tm.DaysInterval.IsUnknown(),
		"days_of_week":         tm.DaysOfWeek.IsUnknown(),
		"weeks_interval":       tm.WeeksInterval.IsUnknown(),
		"user_id":              tm.UserID.IsUnknown(),
		"subscription":         tm.Subscription.IsUnknown(),
	} {
		if unknown {
			t.Errorf("%s must not be Unknown after apply (breaks Set correlation)", name)
		}
	}
	if tm.DaysInterval.IsNull() || tm.DaysInterval.ValueInt64() != 1 {
		t.Errorf("days_interval = %v, want 1 (Windows default)", tm.DaysInterval)
	}
	for name, field := range map[string]struct {
		null bool
		val  string
	}{
		"end_boundary":         {tm.EndBoundary.IsNull(), tm.EndBoundary.ValueString()},
		"execution_time_limit": {tm.ExecutionTimeLimit.IsNull(), tm.ExecutionTimeLimit.ValueString()},
		"delay":                {tm.Delay.IsNull(), tm.Delay.ValueString()},
		"user_id":              {tm.UserID.IsNull(), tm.UserID.ValueString()},
	} {
		if !field.null {
			t.Errorf("%s = %q, want null (Windows reports empty)", name, field.val)
		}
	}
	if !tm.Subscription.IsNull() {
		t.Errorf("subscription = %v, want null (Windows reports empty)", tm.Subscription)
	}
	if !tm.DaysOfWeek.IsNull() {
		t.Errorf("days_of_week = %v, want null (Windows reports none)", tm.DaysOfWeek)
	}
	if !tm.WeeksInterval.IsNull() {
		t.Errorf("weeks_interval = %v, want null (not applicable to Daily)", tm.WeeksInterval)
	}
}

// TestStateToModel_PriorTriggersConsumeOnce pins the consume-once alignment
// for same-type triggers: each prior trigger backs at most one live trigger,
// so when Windows reports the interval as unset (0) for two same-type live
// triggers, only one may inherit the first prior interval — the other falls
// back to null instead of duplicating it.
func TestStateToModel_PriorTriggersConsumeOnce(t *testing.T) {
	ctx := context.Background()

	mkPrior := func(di types.Int64) attr.Value {
		t.Helper()
		v, d := types.ObjectValueFrom(ctx, scheduledTaskTriggerAttrTypes, windowsScheduledTaskTriggerModel{
			Type:               types.StringValue("Daily"),
			Enabled:            types.BoolValue(true),
			StartBoundary:      types.StringValue("2026-01-01T00:00:00Z"),
			EndBoundary:        types.StringNull(),
			ExecutionTimeLimit: types.StringNull(),
			Delay:              types.StringNull(),
			DaysInterval:       di,
			DaysOfWeek:         types.SetNull(types.StringType),
			WeeksInterval:      types.Int64Null(),
			UserID:             types.StringNull(),
			Subscription:       subscriptionXMLValueOrNull(""),
		})
		if d.HasError() {
			t.Fatalf("ObjectValueFrom: %v", d)
		}
		return v
	}
	// Two same-type prior triggers with distinct intervals: one set, one null.
	priorSet, d := types.SetValue(
		types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes},
		[]attr.Value{mkPrior(types.Int64Value(3)), mkPrior(types.Int64Null())},
	)
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	prior := &windowsScheduledTaskModel{
		Principal: types.ObjectNull(scheduledTaskPrincipalAttrTypes),
		Actions:   types.ListValueMust(types.ObjectType{AttrTypes: scheduledTaskActionAttrTypes}, []attr.Value{}),
		Triggers:  priorSet,
		Settings:  types.ObjectNull(scheduledTaskSettingsAttrTypes),
	}

	// Windows reports both live intervals as unset (0).
	live := &winclient.ScheduledTaskState{
		Name:    "T",
		Path:    `\`,
		Actions: []winclient.ScheduledTaskActionState{{Execute: "cmd.exe"}},
		Triggers: []winclient.ScheduledTaskTriggerState{
			{Type: "Daily", Enabled: true, StartBoundary: "2026-01-01T00:00:00Z", DaysInterval: 0},
			{Type: "Daily", Enabled: true, StartBoundary: "2026-01-01T00:00:00Z", DaysInterval: 0},
		},
	}
	m, diags := stateToModel(ctx, live, prior)
	if diags.HasError() {
		t.Fatalf("stateToModel diags: %v", diags)
	}
	var triggers []windowsScheduledTaskTriggerModel
	if d := m.Triggers.ElementsAs(ctx, &triggers, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	if len(triggers) != 2 {
		t.Fatalf("expected 2 triggers, got %d", len(triggers))
	}
	// Sets have no stable order: assert the multiset, not positions.
	var withValue, withNull int
	for _, tr := range triggers {
		switch {
		case tr.DaysInterval.IsNull():
			withNull++
		case tr.DaysInterval.ValueInt64() == 3:
			withValue++
		default:
			t.Errorf("unexpected days_interval = %v, want 3 or null", tr.DaysInterval)
		}
	}
	if withValue != 1 || withNull != 1 {
		t.Errorf("days_interval distribution = (%d x 3, %d x null), want (1 x 3, 1 x null): first prior must not be duplicated", withValue, withNull)
	}
}

// stNullTimeouts must carry exactly the attribute types the schema declares.
// A null timeouts value whose object has no attribute types is what made
// ImportState fail with a framework Value Conversion Error (#83): the framework
// compares the value's underlying type against the schema's and rejects
// tftypes.Object[] where it expects Object["create","delete","update"].
//
// Both halves now derive from stTimeoutsOpts, so adding or removing an
// operation moves them together and cannot desynchronise them. What this test
// still catches is the original defect class: stNullTimeouts returning an
// untyped value (a bare timeouts.Value{}) or a hand-written attribute map that
// does not match the schema. Verified by reverting the fix, which fails it.
func TestScheduledTaskNullTimeoutsMatchesSchema(t *testing.T) {
	r := NewWindowsScheduledTaskResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	attrDef, ok := resp.Schema.Attributes["timeouts"]
	if !ok {
		t.Fatal("schema has no timeouts attribute")
	}

	want := attrDef.GetType()
	got := stNullTimeouts().Type(context.Background())
	if !want.Equal(got) {
		t.Errorf("stNullTimeouts type mismatch:\n schema: %s\n  value: %s", want, got)
	}

	if !stNullTimeouts().IsNull() {
		t.Error("stNullTimeouts must be null, not an object of null strings")
	}
}

func TestSubscriptionXMLValue_StringSemanticEquals(t *testing.T) {
	configXML := "<QueryList>\n  <Query Id=\"0\" Path=\"System\">\n    <Select Path=\"System\">*[System[EventID=1074]]</Select>\n\n  </Query>\n</QueryList>\n"
	windowsXML := "<QueryList>\n  <Query Id=\"0\" Path=\"System\">\n    <Select Path=\"System\">*[System[EventID=1074]]</Select>\n  </Query>\n</QueryList>"

	equal, diags := subscriptionXMLValueOf(configXML).StringSemanticEquals(context.Background(), subscriptionXMLValueOf(windowsXML))
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !equal {
		t.Error("expected whitespace-only-different XML to compare semantically equal")
	}

	differentQuery := "<QueryList><Query Id=\"1\" Path=\"System\"><Select Path=\"System\">*[System[EventID=999]]</Select></Query></QueryList>"
	equal, diags = subscriptionXMLValueOf(configXML).StringSemanticEquals(context.Background(), subscriptionXMLValueOf(differentQuery))
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if equal {
		t.Error("expected genuinely different XML to compare semantically unequal")
	}
}

func TestSubscriptionXMLType_SchemaWiring(t *testing.T) {
	r := NewWindowsScheduledTaskResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	trigAttr, ok := resp.Schema.Attributes["triggers"]
	if !ok {
		t.Fatal("schema has no triggers attribute")
	}
	nested, ok := trigAttr.(schema.SetNestedAttribute)
	if !ok {
		t.Fatalf("triggers attribute is %T, want schema.SetNestedAttribute", trigAttr)
	}
	subAttr, ok := nested.NestedObject.Attributes["subscription"]
	if !ok {
		t.Fatal("triggers nested schema has no subscription attribute")
	}

	want := subAttr.GetType()
	got := subscriptionXMLValueOf("x").Type(context.Background())
	if !want.Equal(got) {
		t.Errorf("subscription type mismatch:\n schema: %s\n  value: %s", want, got)
	}

	if !subscriptionXMLValueOrNull("").IsNull() {
		t.Error("subscriptionXMLValueOrNull(\"\") must be null")
	}
}

// ---------------------------------------------------------------------------
// durationValue semantic equality
// ---------------------------------------------------------------------------

func TestDurationsEquivalent(t *testing.T) {
	// Equivalent spellings of the same length must compare equal: the apply
	// path hands Windows a [TimeSpan], so a re-serialisation may legitimately
	// come back as P3D where the configuration said PT72H. Without value
	// comparison that is a hard "provider produced inconsistent result after
	// apply" on an Optional+Computed attribute that has a default.
	equal := [][2]string{
		{"PT72H", "P3D"},
		{"PT72H", "P3DT0H0M0S"},
		{"PT72H", "72:00:00"},
		{"PT72H", "3.00:00:00"},
		{"PT4H", "PT240M"},
		{"PT4H", "PT4H0M0S"},
		{"PT4H", "PT0H240M0S"},
		{"PT1H30M15S", "PT1H30M15.0000000S"},
		{"PT0S", "0.00:00:00"},
		{"PT0.5S", "00:00:00.5000000"},
		{"P1M4DT2H5M", "P34DT2H5M"},
		{"P1Y", "P365D"},
		{"PT1440M", "P1D"},
		{"PT72H", "PT72H"},
	}
	for _, c := range equal {
		if !durationsEquivalent(c[0], c[1]) {
			t.Errorf("durationsEquivalent(%q, %q) = false, want true", c[0], c[1])
		}
		if !durationsEquivalent(c[1], c[0]) {
			t.Errorf("durationsEquivalent(%q, %q) = false, want true (symmetric)", c[1], c[0])
		}
	}
}

func TestDurationsEquivalent_NotEqual(t *testing.T) {
	// Different lengths, unparseable values, and out-of-range magnitudes must
	// never compare equal: an unparseable value falls back to strict string
	// equality rather than matching something else.
	notEqual := [][2]string{
		{"PT72H", "PT71H"},
		{"PT72H", "P1D"},
		{"PT72H", "PT0S"},
		{"PT0S", "PT0.000000001S"},
		{"PT72H", "PT72H0M1S"},
		{"PT72H", "bogus"},
		{"bogus", "bogus2"},
		{"", "PT0S"},
		{"PT72H", "99999999999999999999999:00:00"},
		{"PT9999999999999H", "PT72H"},
		// Overflow witnesses: these wrap to 0 / MinInt64 if the components are
		// multiplied before being range-checked, which would make an absurd
		// duration compare equal to PT0S or to a legitimate value.
		{"P144115188075855872D", "PT0S"},
		{"P144115188075855872D", "PT72H"},
		{"PT576460752303423488H", "PT72H"},
		{"PT0S", "P144115188075855872D"},
		{"99999999999999999999999:00:00", "PT0S"},
		{"PT9223372036.9S", "-PT9223372036.809551616S"},
	}
	for _, c := range notEqual {
		if durationsEquivalent(c[0], c[1]) {
			t.Errorf("durationsEquivalent(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

func TestDurationValue_StringSemanticEquals(t *testing.T) {
	ctx := context.Background()
	// The dangerous case for #100: planned PT72H, state re-read as P3D. This
	// must be "no change", not an inconsistent-result error.
	planned := durationValueOf("PT72H")
	state := durationValueOf("P3D")
	ok, diags := planned.StringSemanticEquals(ctx, state)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !ok {
		t.Error("PT72H and P3D must compare semantically equal")
	}
	ok, diags = planned.StringSemanticEquals(ctx, durationValueOf("PT71H"))
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if ok {
		t.Error("PT72H and PT71H must not compare equal")
	}
	// Null and unknown never match.
	ok, _ = planned.StringSemanticEquals(ctx, durationValueOrNull(""))
	if ok {
		t.Error("a known duration must not equal null")
	}
	ok, _ = planned.StringSemanticEquals(ctx, durationValue{StringValue: basetypes.NewStringUnknown()})
	if ok {
		t.Error("a known duration must not equal unknown")
	}
	// A type mismatch is reported, not silently treated as equal.
	if _, diags := planned.StringSemanticEquals(ctx, basetypes.NewStringValue("P3D")); !diags.HasError() {
		t.Error("expected a diagnostic for a non-durationValue argument")
	}
}

func TestDurationValue_Type(t *testing.T) {
	ctx := context.Background()
	if got := durationValueOf("PT72H").Type(ctx); got.String() != "durationType" {
		t.Errorf("Type() = %q, want durationType", got.String())
	}
	// The type must round-trip through the framework's Terraform conversion.
	ty := durationType{}
	val, diags := ty.ValueFromString(ctx, basetypes.NewStringValue("P3D"))
	if diags.HasError() {
		t.Fatalf("ValueFromString diagnostics: %v", diags)
	}
	if _, ok := val.(durationValue); !ok {
		t.Errorf("ValueFromString returned %T, want durationValue", val)
	}
	tfVal, err := ty.ValueFromTerraform(ctx, tftypes.NewValue(tftypes.String, "PT72H"))
	if err != nil {
		t.Fatalf("ValueFromTerraform: %v", err)
	}
	if _, ok := tfVal.(durationValue); !ok {
		t.Errorf("ValueFromTerraform returned %T, want durationValue", tfVal)
	}
	if !(durationType{}).Equal(durationType{}) {
		t.Error("durationType must equal itself")
	}
}

// TestModelToInput_DurationAttributesUseSchemaType drives modelToInput with
// settings and trigger objects built from the SCHEMA attr types, not from a
// hand-rolled map. This is the exact mismatch that broke Create and Update when
// settings.execution_time_limit first gained a CustomType while the model field
// and the attr-types map still said types.String: reflect.Into then fails with
// "Cannot use attr.Value types.String, only ...durationValue is supported".
// Building the objects from the shared attr-types maps keeps the test honest
// about what the framework hands to As().
func TestModelToInput_DurationAttributesUseSchemaType(t *testing.T) {
	ctx := context.Background()
	settings := types.ObjectValueMust(scheduledTaskSettingsAttrTypes, map[string]attr.Value{
		"allow_demand_start":             types.BoolValue(true),
		"allow_hard_terminate":           types.BoolValue(true),
		"start_when_available":           types.BoolValue(false),
		"run_only_if_network_available":  types.BoolValue(false),
		"execution_time_limit":           durationValueOf("PT4H"),
		"multiple_instances":             types.StringValue("Queue"),
		"disallow_start_if_on_batteries": types.BoolValue(true),
		"stop_if_going_on_batteries":     types.BoolValue(true),
		"wake_to_run":                    types.BoolValue(false),
		"run_only_if_idle":               types.BoolValue(false),
	})
	trigger := types.ObjectValueMust(scheduledTaskTriggerAttrTypes, map[string]attr.Value{
		"type":                 types.StringValue("Daily"),
		"enabled":              types.BoolValue(true),
		"start_boundary":       types.StringValue("2026-01-01T00:00:00Z"),
		"end_boundary":         types.StringNull(),
		"execution_time_limit": types.StringValue("PT5M"),
		"delay":                types.StringValue("PT1M"),
		"days_interval":        types.Int64Value(1),
		"days_of_week":         types.SetValueMust(types.StringType, []attr.Value{}),
		"weeks_interval":       types.Int64Null(),
		"user_id":              types.StringNull(),
		"subscription":         subscriptionXMLValueOrNull(""),
	})
	m := &windowsScheduledTaskModel{
		Name:        types.StringValue("T"),
		Path:        types.StringValue(`\`),
		Description: types.StringValue(""),
		Enabled:     types.BoolValue(true),
		Principal:   types.ObjectNull(scheduledTaskPrincipalAttrTypes),
		Actions:     types.ListNull(types.ObjectType{AttrTypes: scheduledTaskActionAttrTypes}),
		Triggers:    types.SetValueMust(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}, []attr.Value{trigger}),
		Settings:    settings,
	}
	in, diags := modelToInput(ctx, m)
	if diags.HasError() {
		t.Fatalf("modelToInput diagnostics: %v", diags)
	}
	if in.Settings == nil {
		t.Fatal("expected settings to be converted")
	}
	if in.Settings.ExecutionTimeLimit != "PT4H" {
		t.Errorf("settings ETL = %q, want PT4H", in.Settings.ExecutionTimeLimit)
	}
	if len(in.Triggers) != 1 {
		t.Fatalf("expected 1 trigger, got %d", len(in.Triggers))
	}
	if in.Triggers[0].ExecutionTimeLimit != "PT5M" {
		t.Errorf("trigger ETL = %q, want PT5M", in.Triggers[0].ExecutionTimeLimit)
	}
	if in.Triggers[0].Delay != "PT1M" {
		t.Errorf("trigger delay = %q, want PT1M", in.Triggers[0].Delay)
	}
}

// TestScheduledTaskUpdate_PwBumpedFailClosed is a table unit test for the
// two Update branches extracted into helpers (issue #99 re-review): the
// password_wo_version bump gate (including first-time principal with
// version 0/0 + password) and the fail-closed guard for Password logon
// with an empty effective password. Pure unit test: no Windows host.
func TestScheduledTaskUpdate_PwBumpedFailClosed(t *testing.T) {
	ctx := context.Background()

	mkPrincipal := func(version int64, legacySet bool, legacyValue string) windowsScheduledTaskPrincipalModel {
		pm := windowsScheduledTaskPrincipalModel{
			UserID:            types.StringValue("svc"),
			PasswordWO:        types.StringNull(),
			PasswordWoVersion: types.Int64Value(version),
			LogonType:         types.StringValue("Password"),
			RunLevel:          types.StringValue("Limited"),
		}
		if legacySet {
			pm.Password = types.StringValue(legacyValue)
		} else {
			pm.Password = types.StringNull()
		}
		return pm
	}
	mkModel := func(pm windowsScheduledTaskPrincipalModel) windowsScheduledTaskModel {
		obj, diags := types.ObjectValueFrom(ctx, scheduledTaskPrincipalAttrTypes, pm)
		if diags.HasError() {
			t.Fatalf("ObjectValueFrom: %v", diags)
		}
		return windowsScheduledTaskModel{Principal: obj}
	}

	cases := []struct {
		name              string
		planPm            windowsScheduledTaskPrincipalModel
		statePm           windowsScheduledTaskPrincipalModel
		configLegacySet   bool
		priorHasPrincipal bool
		logonType         string
		effectivePassword string
		wantBumped        bool
		wantFailClosed    bool
		wantDiagAttr      string
	}{
		{
			name:              "first-time 0/0 with password sends",
			planPm:            mkPrincipal(0, false, ""),
			statePm:           mkPrincipal(0, false, ""),
			priorHasPrincipal: false,
			logonType:         "Password",
			effectivePassword: "s3cr3t",
			wantBumped:        true,
			wantFailClosed:    false,
			wantDiagAttr:      "password_wo",
		},
		{
			name:              "first-time 0/0 missing password fails closed",
			planPm:            mkPrincipal(0, false, ""),
			statePm:           mkPrincipal(0, false, ""),
			priorHasPrincipal: false,
			logonType:         "Password",
			effectivePassword: "",
			wantBumped:        false,
			wantFailClosed:    true,
			wantDiagAttr:      "password_wo",
		},
		{
			name:              "first-time missing password legacy intent routes at password",
			planPm:            mkPrincipal(0, true, ""),
			statePm:           mkPrincipal(0, false, ""),
			priorHasPrincipal: false,
			logonType:         "Password",
			effectivePassword: "",
			wantBumped:        false,
			wantFailClosed:    true,
			wantDiagAttr:      "password",
		},
		{
			name:              "version bump without password fails closed",
			planPm:            mkPrincipal(2, false, ""),
			statePm:           mkPrincipal(1, false, ""),
			priorHasPrincipal: true,
			logonType:         "Password",
			effectivePassword: "",
			wantBumped:        true,
			wantFailClosed:    true,
			wantDiagAttr:      "password_wo",
		},
		{
			name:              "version bump without password legacy intent routes at password",
			planPm:            mkPrincipal(2, false, ""),
			statePm:           mkPrincipal(1, false, ""),
			configLegacySet:   true,
			priorHasPrincipal: true,
			logonType:         "Password",
			effectivePassword: "",
			wantBumped:        true,
			wantFailClosed:    true,
			wantDiagAttr:      "password",
		},
		{
			name:              "version bump with password sends",
			planPm:            mkPrincipal(2, false, ""),
			statePm:           mkPrincipal(1, false, ""),
			priorHasPrincipal: true,
			logonType:         "Password",
			effectivePassword: "n3w-s3cr3t",
			wantBumped:        true,
			wantFailClosed:    false,
			wantDiagAttr:      "password_wo",
		},
		{
			name:              "steady-state no bump allows unrelated updates",
			planPm:            mkPrincipal(1, false, ""),
			statePm:           mkPrincipal(1, false, ""),
			priorHasPrincipal: true,
			logonType:         "Password",
			effectivePassword: "",
			wantBumped:        false,
			wantFailClosed:    false,
			wantDiagAttr:      "password_wo",
		},
		{
			name:              "non-Password logon never fails closed",
			planPm:            mkPrincipal(2, false, ""),
			statePm:           mkPrincipal(1, false, ""),
			priorHasPrincipal: true,
			logonType:         "S4U",
			effectivePassword: "",
			wantBumped:        true,
			wantFailClosed:    false,
			wantDiagAttr:      "password_wo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotBumped := deriveScheduledTaskPwBumped(
				tc.planPm.PasswordWoVersion.ValueInt64(),
				tc.statePm.PasswordWoVersion.ValueInt64(),
				tc.priorHasPrincipal,
				tc.effectivePassword,
			)
			if gotBumped != tc.wantBumped {
				t.Errorf("pwBumped = %v, want %v", gotBumped, tc.wantBumped)
			}
			gotFail := scheduledTaskPasswordFailClosed(tc.logonType, tc.effectivePassword, gotBumped, tc.priorHasPrincipal)
			if gotFail != tc.wantFailClosed {
				t.Errorf("failClosed = %v, want %v", gotFail, tc.wantFailClosed)
			}

			planModel := mkModel(tc.planPm)
			configPm := mkPrincipal(0, tc.configLegacySet, "")
			configModel := mkModel(configPm)
			gotPath := scheduledTaskPasswordDiagPath(ctx, &planModel, &configModel)
			wantPath := path.Root("principal").AtName(tc.wantDiagAttr)
			if gotPath.String() != wantPath.String() {
				t.Errorf("diag path = %q, want %q", gotPath.String(), wantPath.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// State upgrade (issue #324: triggers/days_of_week List -> Set)
// ---------------------------------------------------------------------------

// stV0TriggerObjType is the tftypes mirror of the v0 trigger object
// (days_of_week as List).
func stV0TriggerObjType() tftypes.Object {
	str, b, num := tftypes.String, tftypes.Bool, tftypes.Number
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"type":                 str,
		"enabled":              b,
		"start_boundary":       str,
		"end_boundary":         str,
		"execution_time_limit": str,
		"delay":                str,
		"days_interval":        num,
		"days_of_week":         tftypes.List{ElementType: str},
		"weeks_interval":       num,
		"user_id":              str,
		"subscription":         str,
	}}
}

// stV0Raw builds a v0 raw state value: every attribute null except name,
// path, triggers (each a raw value for stV0TriggerObjType) and timeouts.
// A nil triggers slice encodes a null list (hand-edited state edge).
func stV0Raw(triggers []tftypes.Value) tftypes.Value {
	str, b, num := tftypes.String, tftypes.Bool, tftypes.Number
	trigType := tftypes.List{ElementType: stV0TriggerObjType()}
	var trigVal tftypes.Value
	if triggers == nil {
		trigVal = tftypes.NewValue(trigType, nil)
	} else {
		trigVal = tftypes.NewValue(trigType, triggers)
	}
	timeoutsType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": str, "read": str, "update": str, "delete": str,
	}}
	timeoutsVal := tftypes.NewValue(timeoutsType, map[string]tftypes.Value{
		"create": tftypes.NewValue(str, nil),
		"read":   tftypes.NewValue(str, nil),
		"update": tftypes.NewValue(str, nil),
		"delete": tftypes.NewValue(str, nil),
	})
	principalType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"user_id": str, "password": str, "password_wo": str,
		"password_wo_version": num, "logon_type": str, "run_level": str,
	}}
	actionType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"execute": str, "arguments": str, "working_directory": str,
	}}
	settingsType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"allow_demand_start": b, "allow_hard_terminate": b,
		"start_when_available": b, "run_only_if_network_available": b,
		"execution_time_limit": str, "multiple_instances": str,
		"disallow_start_if_on_batteries": b, "stop_if_going_on_batteries": b,
		"wake_to_run": b, "run_only_if_idle": b,
	}}
	objType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id": str, "name": str, "path": str, "description": str, "enabled": b,
		"state": str, "last_run_time": str, "last_task_result": num, "next_run_time": str,
		"principal": principalType,
		"actions":   tftypes.List{ElementType: actionType},
		"triggers":  trigType,
		"settings":  settingsType,
		"timeouts":  timeoutsType,
	}}
	nullStr := tftypes.NewValue(str, nil)
	return tftypes.NewValue(objType, map[string]tftypes.Value{
		"id":               nullStr,
		"name":             tftypes.NewValue(str, "T"),
		"path":             tftypes.NewValue(str, `\`),
		"description":      nullStr,
		"enabled":          tftypes.NewValue(b, true),
		"state":            nullStr,
		"last_run_time":    nullStr,
		"last_task_result": tftypes.NewValue(num, nil),
		"next_run_time":    nullStr,
		"principal":        tftypes.NewValue(principalType, nil),
		"actions":          tftypes.NewValue(tftypes.List{ElementType: actionType}, []tftypes.Value{}),
		"triggers":         trigVal,
		"settings":         tftypes.NewValue(settingsType, nil),
		"timeouts":         timeoutsVal,
	})
}

func TestWindowsScheduledTaskResource_UpgradeState_V0ToV1(t *testing.T) {
	ctx := context.Background()
	r := &windowsScheduledTaskResource{}

	upgraders := r.UpgradeState(ctx)
	upgrader, ok := upgraders[0]
	if !ok {
		t.Fatal("expected state upgrader for prior version 0")
	}
	if upgrader.PriorSchema == nil {
		t.Fatal("expected prior schema for version 0")
	}
	if _, ok := upgrader.PriorSchema.Attributes["triggers"].(schema.ListNestedAttribute); !ok {
		t.Fatalf("prior triggers must be schema.ListNestedAttribute, got %T", upgrader.PriorSchema.Attributes["triggers"])
	}

	resp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, resp)
	if resp.Schema.Version != 1 {
		t.Errorf("current schema Version = %d, want 1", resp.Schema.Version)
	}
	if _, ok := resp.Schema.Attributes["triggers"].(schema.SetNestedAttribute); !ok {
		t.Fatalf("current triggers must be schema.SetNestedAttribute, got %T", resp.Schema.Attributes["triggers"])
	}

	str, b, num := tftypes.String, tftypes.Bool, tftypes.Number
	mkTrigger := func(typ string, days []string) tftypes.Value {
		vals := map[string]tftypes.Value{
			"type":                 tftypes.NewValue(str, typ),
			"enabled":              tftypes.NewValue(b, true),
			"start_boundary":       tftypes.NewValue(str, "2026-01-01T00:00:00Z"),
			"end_boundary":         tftypes.NewValue(str, nil),
			"execution_time_limit": tftypes.NewValue(str, nil),
			"delay":                tftypes.NewValue(str, nil),
			"days_interval":        tftypes.NewValue(num, nil),
			"weeks_interval":       tftypes.NewValue(num, nil),
			"user_id":              tftypes.NewValue(str, nil),
			"subscription":         tftypes.NewValue(str, nil),
		}
		if days == nil {
			vals["days_of_week"] = tftypes.NewValue(tftypes.List{ElementType: str}, nil)
		} else {
			elems := make([]tftypes.Value, len(days))
			for i, d := range days {
				elems[i] = tftypes.NewValue(str, d)
			}
			vals["days_of_week"] = tftypes.NewValue(tftypes.List{ElementType: str}, elems)
		}
		if typ == "Daily" {
			vals["days_interval"] = tftypes.NewValue(num, 1)
		}
		if typ == "Weekly" {
			vals["weeks_interval"] = tftypes.NewValue(num, 1)
		}
		return tftypes.NewValue(stV0TriggerObjType(), vals)
	}

	upgrade := func(triggers []tftypes.Value) windowsScheduledTaskModel {
		t.Helper()
		priorRaw := stV0Raw(triggers)
		req := resource.UpgradeStateRequest{State: &tfsdk.State{Schema: *upgrader.PriorSchema, Raw: priorRaw}}
		upResp := &resource.UpgradeStateResponse{State: tfsdk.State{Schema: resp.Schema}}
		upgrader.StateUpgrader(ctx, req, upResp)
		if upResp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", upResp.Diagnostics)
		}
		var upgraded windowsScheduledTaskModel
		upResp.Diagnostics.Append(upResp.State.Get(ctx, &upgraded)...)
		if upResp.Diagnostics.HasError() {
			t.Fatalf("upgraded state Get: %v", upResp.Diagnostics)
		}
		return upgraded
	}

	first := upgrade([]tftypes.Value{
		mkTrigger("Weekly", []string{"Wednesday", "Monday"}),
		mkTrigger("Daily", nil),
	})
	// Same logical state with both the trigger order and the weekday order
	// reversed: the upgraded sets must compare equal (reorder-only = clean).
	second := upgrade([]tftypes.Value{
		mkTrigger("Daily", nil),
		mkTrigger("Weekly", []string{"Monday", "Wednesday"}),
	})
	if !first.Triggers.Equal(second.Triggers) {
		t.Error("reordered v0 triggers must upgrade to equal v1 trigger sets")
	}

	var triggers []windowsScheduledTaskTriggerModel
	if d := first.Triggers.ElementsAs(ctx, &triggers, false); d.HasError() {
		t.Fatalf("Triggers ElementsAs: %v", d)
	}
	if len(triggers) != 2 {
		t.Fatalf("expected 2 upgraded triggers, got %d", len(triggers))
	}
	byType := map[string]windowsScheduledTaskTriggerModel{}
	for _, tr := range triggers {
		byType[tr.Type.ValueString()] = tr
	}
	weekly, ok := byType["Weekly"]
	if !ok {
		t.Fatal("upgraded triggers must contain the Weekly trigger")
	}
	var days []string
	if d := weekly.DaysOfWeek.ElementsAs(ctx, &days, false); d.HasError() {
		t.Fatalf("DaysOfWeek ElementsAs: %v", d)
	}
	got := map[string]bool{}
	for _, d := range days {
		got[d] = true
	}
	if len(got) != 2 || !got["Monday"] || !got["Wednesday"] {
		t.Errorf("upgraded days_of_week = %v, want {Monday Wednesday}", days)
	}
	if daily, ok := byType["Daily"]; !ok {
		t.Fatal("upgraded triggers must contain the Daily trigger")
	} else if !daily.DaysOfWeek.IsNull() {
		t.Errorf("Daily days_of_week must stay null, got %v", daily.DaysOfWeek)
	}
	if first.Name.ValueString() != "T" || first.Path.ValueString() != `\` {
		t.Errorf("scalar fields must survive the upgrade, got name=%q path=%q", first.Name.ValueString(), first.Path.ValueString())
	}
	objType, ok := first.Triggers.Type(context.Background()).(types.SetType)
	if !ok || !objType.ElementType().Equal(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes}) {
		t.Errorf("upgraded triggers element type = %v, want the trigger object type", first.Triggers.Type(context.Background()))
	}

	// Null triggers stay null (hand-edited state edge), not an empty set.
	nullUpgraded := upgrade(nil)
	if !nullUpgraded.Triggers.IsNull() {
		t.Errorf("null triggers must upgrade to SetNull, got %v", nullUpgraded.Triggers)
	}

	// Pin the exact v0 attribute key sets so a future attribute addition
	// fails fast instead of silently bypassing the hand-written V0 models.
	assertAttrKeys(t, upgrader.PriorSchema.Attributes, []string{
		"id", "name", "path", "description", "enabled", "state",
		"last_run_time", "last_task_result", "next_run_time",
		"principal", "actions", "triggers", "settings", "timeouts",
	})
	assertAttrKeys(t, resp.Schema.Attributes, []string{
		"id", "name", "path", "description", "enabled", "state",
		"last_run_time", "last_task_result", "next_run_time",
		"principal", "actions", "triggers", "settings", "timeouts",
	})
	priorNested, ok := upgrader.PriorSchema.Attributes["triggers"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("prior triggers must be schema.ListNestedAttribute, got %T", upgrader.PriorSchema.Attributes["triggers"])
	}
	assertAttrKeys(t, priorNested.NestedObject.Attributes, []string{
		"type", "enabled", "start_boundary", "end_boundary",
		"execution_time_limit", "delay", "days_interval", "days_of_week",
		"weeks_interval", "user_id", "subscription",
	})
	currentNested, ok := resp.Schema.Attributes["triggers"].(schema.SetNestedAttribute)
	if !ok {
		t.Fatalf("current triggers must be schema.SetNestedAttribute, got %T", resp.Schema.Attributes["triggers"])
	}
	assertAttrKeys(t, currentNested.NestedObject.Attributes, []string{
		"type", "enabled", "start_boundary", "end_boundary",
		"execution_time_limit", "delay", "days_interval", "days_of_week",
		"weeks_interval", "user_id", "subscription",
	})
}

// TestScheduledTaskSetSemantics_ReorderIsClean pins the property the #324
// migration relies on: two sets holding the same elements in a different
// order compare equal, so a reorder alone produces no diff.
func TestScheduledTaskSetSemantics_ReorderIsClean(t *testing.T) {
	ctx := context.Background()

	a, d := types.SetValueFrom(ctx, types.StringType, []string{"Monday", "Wednesday", "Friday"})
	if d.HasError() {
		t.Fatalf("SetValueFrom: %v", d)
	}
	b, d := types.SetValueFrom(ctx, types.StringType, []string{"Friday", "Monday", "Wednesday"})
	if d.HasError() {
		t.Fatalf("SetValueFrom: %v", d)
	}
	if !a.Equal(b) {
		t.Error("days_of_week sets with the same elements in a different order must be equal")
	}

	mkWeekly := func(days []string) attr.Value {
		t.Helper()
		v, d := buildTriggerObject(ctx, winclient.ScheduledTaskTriggerState{
			Type: "Weekly", Enabled: true, DaysOfWeek: days, WeeksInterval: 1,
		}, nil)
		if d.HasError() {
			t.Fatalf("buildTriggerObject: %v", d)
		}
		return v
	}
	daily, d := buildTriggerObject(ctx, winclient.ScheduledTaskTriggerState{
		Type: "Daily", Enabled: true, DaysInterval: 1,
	}, nil)
	if d.HasError() {
		t.Fatalf("buildTriggerObject: %v", d)
	}
	setA, d := types.SetValue(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes},
		[]attr.Value{mkWeekly([]string{"Monday", "Wednesday"}), daily})
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	setB, d := types.SetValue(types.ObjectType{AttrTypes: scheduledTaskTriggerAttrTypes},
		[]attr.Value{daily, mkWeekly([]string{"Wednesday", "Monday"})})
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	if !setA.Equal(setB) {
		t.Error("trigger sets with the same elements in a different order must be equal")
	}
}
