// Package winclient — unit tests for ScheduledTaskClientImpl.
//
// All tests stub the runSTPS hook so no real WinRM connection is needed.
// Edge cases covered:
//
//   - splitTaskID: root path, sub-folder, no separator
//   - buildActionsFragment: single action, multi-action, arguments+working_directory
//   - buildTriggersFragment: Once, Daily, Weekly, AtLogon, AtStartup, OnEvent skipped
//   - buildPrincipalFragment: nil (SYSTEM default), explicit user, LogonType+RunLevel
//   - buildSettingsFragment: nil (defaults), full settings, enabled flag
//   - buildOnEventFragment: XML injection contains Subscription + Enabled nodes
//   - hasOnEventTrigger / hasNonEventTrigger
//   - stPayloadToState: full round-trip, nil payload, nil days_of_week normalised
//   - mapSTKind: all known kinds + unknown fallback
//   - runSTEnvelope: ctx cancel, transport error, empty stdout, bad JSON, error envelope
//   - Read: happy path, not-found (nil,nil), permission_denied, malformed JSON
//   - Create: happy path, already_exists, builtin path guard, SYSTEM principal (EC-3)
//   - Update: happy path, not-found after update, description-only (EC-7)
//   - Delete: happy path, already-absent (not_found → nil), builtin path guard
//   - ImportByID: happy path, not-found returns ScheduledTaskErrorNotFound
//   - ScheduledTaskError: Error(), Unwrap(), Is(), NewScheduledTaskError, IsScheduledTaskError
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSTTestClient(t *testing.T) (*Client, *ScheduledTaskClientImpl) {
	t.Helper()
	c, err := New(Config{
		Host:     "winhost",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewScheduledTaskClient(c)
}

// stubSTRun replaces runSTPS for the duration of a test. Caller must defer
// the returned restorer.
func stubSTRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runSTPS
	runSTPS = fn
	return func() { runSTPS = prev }
}

func stOKEnvelope(t *testing.T, data any) string {
	if t != nil {
		t.Helper()
	}
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		if t != nil {
			t.Fatalf("stOKEnvelope: %v", err)
		}
		panic(err)
	}
	return string(b) + "\n"
}

func stErrEnvelope(t *testing.T, kind, msg string) string {
	if t != nil {
		t.Helper()
	}
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		if t != nil {
			t.Fatalf("stErrEnvelope: %v", err)
		}
		panic(err)
	}
	return string(b) + "\n"
}

// buildMinimalPayloadJSON returns a minimal valid task payload JSON string.
func buildMinimalPayloadJSON(t *testing.T, name, taskPath string) string {
	t.Helper()
	payload := map[string]any{
		"name":             name,
		"path":             taskPath,
		"description":      "",
		"enabled":          true,
		"state":            "Ready",
		"last_run_time":    "",
		"last_task_result": int64(0),
		"next_run_time":    "",
		"principal": map[string]any{
			"user_id":    "SYSTEM",
			"logon_type": "ServiceAccount",
			"run_level":  "Limited",
		},
		"actions": []map[string]any{
			{"execute": "C:\\Windows\\System32\\cmd.exe", "arguments": "", "working_directory": ""},
		},
		"triggers": []map[string]any{
			{
				"type": "Daily", "enabled": true,
				"start_boundary": "2026-01-01T00:00:00Z", "end_boundary": "",
				"execution_time_limit": "", "delay": "",
				"days_interval": int64(1), "days_of_week": []string{},
				"weeks_interval": int64(0), "user_id": "", "subscription": "",
			},
		},
		"settings": map[string]any{
			"allow_demand_start": true, "allow_hard_terminate": true,
			"start_when_available": false, "run_only_if_network_available": false,
			"execution_time_limit": "PT72H", "multiple_instances": "Queue",
			"disallow_start_if_on_batteries": true, "stop_if_going_on_batteries": true,
			"wake_to_run": false, "run_only_if_idle": false,
		},
	}
	return stOKEnvelope(t, payload)
}

// ---------------------------------------------------------------------------
// splitTaskID
// ---------------------------------------------------------------------------

func TestSplitTaskID(t *testing.T) {
	cases := []struct {
		id, wantPath, wantName string
	}{
		{`\MyTask`, `\`, "MyTask"},
		{`\Folder\MyTask`, `\Folder\`, "MyTask"},
		{`\A\B\C\Task`, `\A\B\C\`, "Task"},
		{"NoSep", `\`, "NoSep"},
	}
	for _, tc := range cases {
		p, n := splitTaskID(tc.id)
		if p != tc.wantPath || n != tc.wantName {
			t.Errorf("splitTaskID(%q) = (%q,%q), want (%q,%q)", tc.id, p, n, tc.wantPath, tc.wantName)
		}
	}
}

// ---------------------------------------------------------------------------
// buildActionsFragment
// ---------------------------------------------------------------------------

func TestBuildActionsFragment_SingleAction(t *testing.T) {
	actions := []ScheduledTaskActionInput{
		{Execute: `C:\Windows\system32\cmd.exe`},
	}
	got := buildActionsFragment(actions)
	if !strings.Contains(got, "New-ScheduledTaskAction") {
		t.Error("expected New-ScheduledTaskAction")
	}
	if !strings.Contains(got, `cmd.exe`) {
		t.Errorf("expected execute path in fragment, got:\n%s", got)
	}
}

func TestBuildActionsFragment_MultiAction(t *testing.T) {
	actions := []ScheduledTaskActionInput{
		{Execute: "cmd.exe", Arguments: "/c echo hello"},
		{Execute: "pwsh.exe", WorkingDirectory: `C:\Work`},
	}
	got := buildActionsFragment(actions)
	if !strings.Contains(got, "_stAct0") || !strings.Contains(got, "_stAct1") {
		t.Errorf("expected _stAct0 and _stAct1, got:\n%s", got)
	}
	if !strings.Contains(got, "-Argument") {
		t.Error("expected -Argument for first action")
	}
	if !strings.Contains(got, "-WorkingDirectory") {
		t.Error("expected -WorkingDirectory for second action")
	}
}

func TestBuildActionsFragment_EmptyList(t *testing.T) {
	got := buildActionsFragment(nil)
	if !strings.Contains(got, "$_stActions = @()") {
		t.Errorf("expected empty array init, got: %s", got)
	}
}

// ---------------------------------------------------------------------------
// buildTriggersFragment
// ---------------------------------------------------------------------------

func TestBuildTriggersFragment_Once(t *testing.T) {
	enabled := true
	triggers := []ScheduledTaskTriggerInput{
		{Type: "Once", StartBoundary: "2026-06-01T08:00:00Z", Enabled: &enabled},
	}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "-Once") {
		t.Errorf("expected -Once flag, got: %s", got)
	}
}

func TestBuildTriggersFragment_Daily(t *testing.T) {
	triggers := []ScheduledTaskTriggerInput{
		{Type: "Daily", StartBoundary: "2026-06-01T00:00:00Z", DaysInterval: 2},
	}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "-Daily") {
		t.Errorf("expected -Daily, got: %s", got)
	}
	if !strings.Contains(got, "-DaysInterval 2") {
		t.Errorf("expected -DaysInterval 2, got: %s", got)
	}
}

func TestBuildTriggersFragment_Weekly_MultiDay(t *testing.T) {
	// EC-5: weekly trigger with multiple days_of_week
	triggers := []ScheduledTaskTriggerInput{
		{Type: "Weekly", StartBoundary: "2026-06-01T00:00:00Z",
			DaysOfWeek: []string{"Monday", "Wednesday", "Friday"}, WeeksInterval: 1},
	}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "-Weekly") {
		t.Errorf("expected -Weekly, got: %s", got)
	}
	for _, day := range []string{"Monday", "Wednesday", "Friday"} {
		if !strings.Contains(got, day) {
			t.Errorf("expected day %q in fragment, got: %s", day, got)
		}
	}
}

func TestBuildTriggersFragment_AtLogon_WithUser(t *testing.T) {
	triggers := []ScheduledTaskTriggerInput{
		{Type: "AtLogon", UserID: `DOMAIN\user`},
	}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "-AtLogon") {
		t.Errorf("expected -AtLogon, got: %s", got)
	}
	if !strings.Contains(got, "-User") {
		t.Errorf("expected -User flag, got: %s", got)
	}
}

func TestBuildTriggersFragment_AtLogon_AnyUser(t *testing.T) {
	triggers := []ScheduledTaskTriggerInput{
		{Type: "AtLogon"}, // no UserID = any user
	}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "-AtLogon") {
		t.Errorf("expected -AtLogon, got: %s", got)
	}
	if strings.Contains(got, "-User") {
		t.Errorf("expected no -User flag for any-user, got: %s", got)
	}
}

func TestBuildTriggersFragment_AtStartup(t *testing.T) {
	triggers := []ScheduledTaskTriggerInput{{Type: "AtStartup"}}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "-AtStartup") {
		t.Errorf("expected -AtStartup, got: %s", got)
	}
}

func TestBuildTriggersFragment_OnEvent_Skipped(t *testing.T) {
	// EC-12 / ADR-ST-5: OnEvent triggers must be skipped here
	triggers := []ScheduledTaskTriggerInput{
		{Type: "OnEvent", Subscription: "<QueryList/>"},
	}
	got := buildTriggersFragment(triggers)
	if strings.Contains(got, "EventTrigger") {
		t.Errorf("OnEvent should be skipped in buildTriggersFragment, got: %s", got)
	}
}

func TestBuildTriggersFragment_DisabledTrigger(t *testing.T) {
	disabled := false
	triggers := []ScheduledTaskTriggerInput{
		{Type: "AtStartup", Enabled: &disabled},
	}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "$false") {
		t.Errorf("expected $false for disabled trigger, got: %s", got)
	}
}

func TestBuildTriggersFragment_OptionalFields(t *testing.T) {
	triggers := []ScheduledTaskTriggerInput{
		{
			Type:               "Once",
			StartBoundary:      "2026-01-01T00:00:00Z",
			EndBoundary:        "2027-01-01T00:00:00Z",
			Delay:              "PT5M",
			ExecutionTimeLimit: "PT1H",
		},
	}
	got := buildTriggersFragment(triggers)
	if !strings.Contains(got, "EndBoundary") {
		t.Errorf("expected EndBoundary, got: %s", got)
	}
	if !strings.Contains(got, "Delay") {
		t.Errorf("expected Delay, got: %s", got)
	}
	if !strings.Contains(got, "ExecutionTimeLimit") {
		t.Errorf("expected ExecutionTimeLimit, got: %s", got)
	}
}

// ---------------------------------------------------------------------------
// buildPrincipalFragment
// ---------------------------------------------------------------------------

func TestBuildPrincipalFragment_Nil(t *testing.T) {
	// EC-3: nil principal → SYSTEM / ServiceAccount defaults
	got := buildPrincipalFragment(nil)
	if !strings.Contains(got, "SYSTEM") {
		t.Errorf("nil principal should default to SYSTEM, got: %s", got)
	}
	if !strings.Contains(got, "ServiceAccount") {
		t.Errorf("nil principal should use ServiceAccount logon type, got: %s", got)
	}
}

func TestBuildPrincipalFragment_ExplicitUser(t *testing.T) {
	p := &ScheduledTaskPrincipalInput{
		UserID:    `DOMAIN\svc`,
		LogonType: "Password",
		RunLevel:  "Highest",
	}
	got := buildPrincipalFragment(p)
	if !strings.Contains(got, "Password") {
		t.Errorf("expected Password logon type, got: %s", got)
	}
	if !strings.Contains(got, "Highest") {
		t.Errorf("expected Highest run level, got: %s", got)
	}
}

func TestBuildPrincipalFragment_EmptyUserDefaultsToSYSTEM(t *testing.T) {
	// EC-3: empty UserID → SYSTEM
	p := &ScheduledTaskPrincipalInput{UserID: ""}
	got := buildPrincipalFragment(p)
	if !strings.Contains(got, "SYSTEM") {
		t.Errorf("empty UserID should default to SYSTEM, got: %s", got)
	}
}

// ---------------------------------------------------------------------------
// buildSettingsFragment
// ---------------------------------------------------------------------------

func TestBuildSettingsFragment_Nil(t *testing.T) {
	got := buildSettingsFragment(nil, true)
	if !strings.Contains(got, "New-ScheduledTaskSettingsSet") {
		t.Errorf("expected New-ScheduledTaskSettingsSet, got: %s", got)
	}
	if !strings.Contains(got, "$true") {
		t.Errorf("expected enabled=$true, got: %s", got)
	}
}

func TestBuildSettingsFragment_Disabled(t *testing.T) {
	got := buildSettingsFragment(nil, false)
	if !strings.Contains(got, "$false") {
		t.Errorf("expected enabled=$false, got: %s", got)
	}
}

func TestBuildSettingsFragment_Full(t *testing.T) {
	s := &ScheduledTaskSettingsInput{
		AllowDemandStart:           true,
		AllowHardTerminate:         true,
		StartWhenAvailable:         true,
		RunOnlyIfNetworkAvailable:  false,
		ExecutionTimeLimit:         "PT1H",
		MultipleInstances:          "IgnoreNew",
		DisallowStartIfOnBatteries: false,
		StopIfGoingOnBatteries:     false,
		WakeToRun:                  false,
		RunOnlyIfIdle:              false,
	}
	got := buildSettingsFragment(s, true)
	if !strings.Contains(got, "PT1H") {
		t.Errorf("expected PT1H execution time limit, got: %s", got)
	}
	if !strings.Contains(got, "IgnoreNew") {
		t.Errorf("expected IgnoreNew, got: %s", got)
	}
}

func TestBuildSettingsFragment_DefaultsETL(t *testing.T) {
	// Empty ETL → default PT72H
	s := &ScheduledTaskSettingsInput{}
	got := buildSettingsFragment(s, true)
	if !strings.Contains(got, "PT72H") {
		t.Errorf("expected default PT72H, got: %s", got)
	}
}

// ---------------------------------------------------------------------------
// buildOnEventFragment
// ---------------------------------------------------------------------------

func TestBuildOnEventFragment_ContainsXMLElements(t *testing.T) {
	// EC-12 / ADR-ST-5: on_event XML route
	triggers := []ScheduledTaskTriggerInput{
		{Type: "OnEvent", Subscription: "<QueryList><Query Id='0'><Select>*</Select></Query></QueryList>"},
		{Type: "Daily"},                    // should be ignored
		{Type: "OnEvent", Subscription: "<QueryList/>"}, // second event trigger
	}
	got := buildOnEventFragment("MyTask", `\`, triggers)
	if !strings.Contains(got, "EventTrigger") {
		t.Errorf("expected EventTrigger in XML fragment, got: %s", got)
	}
	if !strings.Contains(got, "Subscription") {
		t.Errorf("expected Subscription element, got: %s", got)
	}
	if !strings.Contains(got, "Export-ScheduledTask") {
		t.Errorf("expected Export-ScheduledTask, got: %s", got)
	}
	if !strings.Contains(got, "Register-ScheduledTask") {
		t.Errorf("expected Register-ScheduledTask for XML re-register, got: %s", got)
	}
}

// ---------------------------------------------------------------------------
// hasOnEventTrigger / hasNonEventTrigger
// ---------------------------------------------------------------------------

func TestHasOnEventTrigger(t *testing.T) {
	if hasOnEventTrigger([]ScheduledTaskTriggerInput{{Type: "Daily"}}) {
		t.Error("no OnEvent trigger expected")
	}
	if !hasOnEventTrigger([]ScheduledTaskTriggerInput{{Type: "OnEvent"}, {Type: "Daily"}}) {
		t.Error("expected OnEvent detection")
	}
	if hasOnEventTrigger(nil) {
		t.Error("nil slice should return false")
	}
}

func TestHasNonEventTrigger(t *testing.T) {
	if hasNonEventTrigger([]ScheduledTaskTriggerInput{{Type: "OnEvent"}}) {
		t.Error("only OnEvent, hasNonEventTrigger should be false")
	}
	if !hasNonEventTrigger([]ScheduledTaskTriggerInput{{Type: "OnEvent"}, {Type: "Daily"}}) {
		t.Error("expected non-event trigger detected")
	}
}

// ---------------------------------------------------------------------------
// stPayloadToState
// ---------------------------------------------------------------------------

func TestStPayloadToState_Nil(t *testing.T) {
	if stPayloadToState(nil) != nil {
		t.Error("nil payload should return nil state")
	}
}

func TestStPayloadToState_Full(t *testing.T) {
	p := &stTaskPayload{
		Name:           "MyTask",
		Path:           `\Folder\`,
		Description:    "Test task",
		Enabled:        true,
		State:          "Ready",
		LastRunTime:    "2026-01-01T00:00:00Z",
		LastTaskResult: 0,
		NextRunTime:    "2026-02-01T00:00:00Z",
		Principal: &stPrincipalPayload{
			UserID:    "SYSTEM",
			LogonType: "ServiceAccount",
			RunLevel:  "Limited",
		},
		Actions: []stActionPayload{
			{Execute: "cmd.exe", Arguments: "/c echo hi", WorkingDirectory: `C:\`},
		},
		Triggers: []stTriggerPayload{
			{
				Type:          "Weekly",
				Enabled:       true,
				StartBoundary: "2026-01-01T08:00:00Z",
				DaysOfWeek:    []string{"Monday", "Wednesday"},
				WeeksInterval: 1,
			},
		},
		Settings: &stSettingsPayload{
			AllowDemandStart:           true,
			AllowHardTerminate:         true,
			ExecutionTimeLimit:         "PT72H",
			MultipleInstances:          "Queue",
			DisallowStartIfOnBatteries: true,
			StopIfGoingOnBatteries:     true,
		},
	}
	s := stPayloadToState(p)
	if s == nil {
		t.Fatal("expected non-nil state")
	}
	if s.Name != "MyTask" || s.Path != `\Folder\` {
		t.Errorf("Name/Path mismatch: %s / %s", s.Name, s.Path)
	}
	if len(s.Actions) != 1 || s.Actions[0].Execute != "cmd.exe" {
		t.Errorf("Actions mismatch: %+v", s.Actions)
	}
	if len(s.Triggers) != 1 || len(s.Triggers[0].DaysOfWeek) != 2 {
		t.Errorf("Triggers/DaysOfWeek mismatch: %+v", s.Triggers)
	}
	if s.Settings == nil {
		t.Error("Settings should not be nil")
	}
	if s.Principal == nil || s.Principal.UserID != "SYSTEM" {
		t.Errorf("Principal mismatch: %+v", s.Principal)
	}
}

func TestStPayloadToState_NilDaysOfWeekNormalized(t *testing.T) {
	p := &stTaskPayload{
		Triggers: []stTriggerPayload{
			{Type: "Daily", DaysOfWeek: nil},
		},
	}
	s := stPayloadToState(p)
	if s.Triggers[0].DaysOfWeek == nil {
		t.Error("nil DaysOfWeek should be normalized to empty slice")
	}
}

func TestStPayloadToState_NilPrincipal(t *testing.T) {
	p := &stTaskPayload{Name: "T", Path: `\`}
	s := stPayloadToState(p)
	if s.Principal != nil {
		t.Error("nil principal payload should yield nil state principal")
	}
}

func TestStPayloadToState_NilSettings(t *testing.T) {
	p := &stTaskPayload{Name: "T", Path: `\`}
	s := stPayloadToState(p)
	if s.Settings != nil {
		t.Error("nil settings payload should yield nil state settings")
	}
}

// ---------------------------------------------------------------------------
// mapSTKind
// ---------------------------------------------------------------------------

func TestMapSTKind(t *testing.T) {
	cases := map[string]ScheduledTaskErrorKind{
		"already_exists":     ScheduledTaskErrorAlreadyExists,
		"not_found":          ScheduledTaskErrorNotFound,
		"builtin_task":       ScheduledTaskErrorBuiltinTask,
		"invalid_path":       ScheduledTaskErrorInvalidPath,
		"invalid_trigger":    ScheduledTaskErrorInvalidTrigger,
		"invalid_action":     ScheduledTaskErrorInvalidAction,
		"password_required":  ScheduledTaskErrorPasswordRequired,
		"password_forbidden": ScheduledTaskErrorPasswordForbidden,
		"permission_denied":  ScheduledTaskErrorPermissionDenied,
		"task_running":       ScheduledTaskErrorRunning,
		"totally_unknown":    ScheduledTaskErrorUnknown,
		"":                   ScheduledTaskErrorUnknown,
	}
	for in, want := range cases {
		if got := mapSTKind(in); got != want {
			t.Errorf("mapSTKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// ScheduledTaskError
// ---------------------------------------------------------------------------

func TestScheduledTaskError_Error_NoWrap(t *testing.T) {
	e := &ScheduledTaskError{Kind: ScheduledTaskErrorNotFound, Message: "not found"}
	s := e.Error()
	if !strings.Contains(s, "not_found") {
		t.Errorf("Error() missing kind: %s", s)
	}
	if !strings.Contains(s, "not found") {
		t.Errorf("Error() missing message: %s", s)
	}
}

func TestScheduledTaskError_Error_WithCause(t *testing.T) {
	cause := errors.New("rpc error")
	e := &ScheduledTaskError{Kind: ScheduledTaskErrorUnknown, Message: "wrap", Cause: cause}
	s := e.Error()
	if !strings.Contains(s, "rpc error") {
		t.Errorf("Error() should include cause: %s", s)
	}
}

func TestScheduledTaskError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	e := &ScheduledTaskError{Cause: inner}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should chain to inner error")
	}
}

func TestScheduledTaskError_Is_SameKind(t *testing.T) {
	e := &ScheduledTaskError{Kind: ScheduledTaskErrorNotFound}
	if !errors.Is(e, ErrScheduledTaskNotFound) {
		t.Error("errors.Is with sentinel should match by Kind")
	}
}

func TestScheduledTaskError_Is_DifferentKind(t *testing.T) {
	e := &ScheduledTaskError{Kind: ScheduledTaskErrorNotFound}
	if errors.Is(e, ErrScheduledTaskAlreadyExists) {
		t.Error("different kind should not match")
	}
}

func TestScheduledTaskError_Is_NonMatchingType(t *testing.T) {
	e := &ScheduledTaskError{Kind: ScheduledTaskErrorNotFound}
	if errors.Is(e, errors.New("plain")) {
		t.Error("non-ScheduledTaskError should not match")
	}
}

func TestNewScheduledTaskError(t *testing.T) {
	e := NewScheduledTaskError(ScheduledTaskErrorPermissionDenied, "access denied", nil, map[string]string{"x": "y"})
	if e.Kind != ScheduledTaskErrorPermissionDenied {
		t.Errorf("Kind = %q", e.Kind)
	}
	if e.Context["x"] != "y" {
		t.Error("context should be preserved")
	}
}

func TestIsScheduledTaskError(t *testing.T) {
	e := NewScheduledTaskError(ScheduledTaskErrorPermissionDenied, "denied", nil, nil)
	if !IsScheduledTaskError(e, ScheduledTaskErrorPermissionDenied) {
		t.Error("IsScheduledTaskError should return true for matching kind")
	}
	if IsScheduledTaskError(e, ScheduledTaskErrorNotFound) {
		t.Error("IsScheduledTaskError should return false for non-matching kind")
	}
	if IsScheduledTaskError(errors.New("plain"), ScheduledTaskErrorNotFound) {
		t.Error("IsScheduledTaskError should return false for non-ScheduledTaskError")
	}
}

// ---------------------------------------------------------------------------
// runSTEnvelope — tested via Read
// ---------------------------------------------------------------------------

func TestRunSTEnvelope_ContextCanceled(t *testing.T) {
	_, impl := newSTTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", context.Canceled
	})()
	_, err := impl.Read(ctx, `\MyTask`)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	if !IsScheduledTaskError(err, ScheduledTaskErrorUnknown) {
		t.Errorf("expected unknown error, got: %v", err)
	}
}

func TestRunSTEnvelope_TransportError(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "connection refused", errors.New("dial tcp: connection refused")
	})()
	_, err := impl.Read(context.Background(), `\MyTask`)
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestRunSTEnvelope_NoJSONOutput(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "no json here\n", "", nil
	})()
	_, err := impl.Read(context.Background(), `\MyTask`)
	if err == nil {
		t.Fatal("expected error when no JSON envelope found")
	}
}

func TestRunSTEnvelope_BadJSON(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{not valid json}\n", "", nil
	})()
	_, err := impl.Read(context.Background(), `\MyTask`)
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestRunSTEnvelope_ErrorEnvelope_PermissionDenied(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stErrEnvelope(t, "permission_denied", "Access is denied"), "", nil
	})()
	_, err := impl.Read(context.Background(), `\MyTask`)
	if !IsScheduledTaskError(err, ScheduledTaskErrorPermissionDenied) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestSTRead_HappyPath(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "MyTask", `\`), "", nil
	})()
	state, err := impl.Read(context.Background(), `\MyTask`)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Name != "MyTask" {
		t.Errorf("Name = %q, want MyTask", state.Name)
	}
}

func TestSTRead_NotFound_ReturnsNil(t *testing.T) {
	// EC-9: task deleted out-of-band → (nil, nil)
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":null}` + "\n", "", nil
	})()
	state, err := impl.Read(context.Background(), `\MyTask`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != nil {
		t.Errorf("expected nil state for not-found, got: %+v", state)
	}
}

func TestSTRead_PermissionDenied(t *testing.T) {
	// EC-13: non-admin session → permission_denied
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stErrEnvelope(t, "permission_denied", "Access is denied"), "", nil
	})()
	_, err := impl.Read(context.Background(), `\MyTask`)
	if !IsScheduledTaskError(err, ScheduledTaskErrorPermissionDenied) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestSTRead_MalformedPayload(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		// ok=true but data is not a valid task object
		return `{"ok":true,"data":"not-an-object"}` + "\n", "", nil
	})()
	_, err := impl.Read(context.Background(), `\MyTask`)
	if err == nil {
		t.Fatal("expected error on malformed payload")
	}
}

func TestSTRead_SubFolderTask(t *testing.T) {
	// EC-2: task in sub-folder
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "MyTask", `\Custom\`), "", nil
	})()
	state, err := impl.Read(context.Background(), `\Custom\MyTask`)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if state.Path != `\Custom\` {
		t.Errorf("Path = %q, want \\Custom\\", state.Path)
	}
}

func TestSTRead_SentinelTimes(t *testing.T) {
	// EC-10: sentinel last_run_time/next_run_time should be empty string
	_, impl := newSTTestClient(t)
	payload := map[string]any{
		"name": "T", "path": `\`, "description": "", "enabled": true,
		"state": "Ready", "last_run_time": "", "last_task_result": int64(0),
		"next_run_time": "", "principal": nil, "actions": []any{},
		"triggers": []any{}, "settings": nil,
	}
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stOKEnvelope(t, payload), "", nil
	})()
	state, err := impl.Read(context.Background(), `\T`)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if state.LastRunTime != "" || state.NextRunTime != "" {
		t.Errorf("sentinel times should be empty, got LastRun=%q NextRun=%q",
			state.LastRunTime, state.NextRunTime)
	}
}

func TestSTRead_DriftDetection_Disabled(t *testing.T) {
	// EC-8: task disabled out-of-band → enabled=false, state=Disabled
	_, impl := newSTTestClient(t)
	payload := map[string]any{
		"name": "DisabledTask", "path": `\`, "description": "",
		"enabled": false, "state": "Disabled",
		"last_run_time": "", "last_task_result": int64(0), "next_run_time": "",
		"principal": map[string]any{"user_id": "SYSTEM", "logon_type": "ServiceAccount", "run_level": "Limited"},
		"actions":   []map[string]any{{"execute": "cmd.exe", "arguments": "", "working_directory": ""}},
		"triggers":  []map[string]any{{"type": "Daily", "enabled": true, "start_boundary": "", "end_boundary": "", "execution_time_limit": "", "delay": "", "days_interval": int64(1), "days_of_week": []string{}, "weeks_interval": int64(0), "user_id": "", "subscription": ""}},
		"settings":  nil,
	}
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stOKEnvelope(t, payload), "", nil
	})()
	state, err := impl.Read(context.Background(), `\DisabledTask`)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if state.Enabled {
		t.Error("expected enabled=false for drifted disabled task")
	}
	if state.State != "Disabled" {
		t.Errorf("expected state=Disabled, got %q", state.State)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestSTCreate_HappyPath(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "NewTask", `\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name:    "NewTask",
		Path:    `\`,
		Enabled: true,
		Actions: []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{
			{Type: "Daily", StartBoundary: "2026-01-01T00:00:00Z"},
		},
	}
	state, err := impl.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if state == nil || state.Name != "NewTask" {
		t.Errorf("unexpected state: %+v", state)
	}
}

func TestSTCreate_AlreadyExists(t *testing.T) {
	// EC-1
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stErrEnvelope(t, "already_exists", "Task already exists"), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "Existing", Path: `\`,
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily"}},
	}
	_, err := impl.Create(context.Background(), input)
	if !IsScheduledTaskError(err, ScheduledTaskErrorAlreadyExists) {
		t.Errorf("expected already_exists, got: %v", err)
	}
}

func TestSTCreate_BuiltinPathGuard(t *testing.T) {
	// EC-13: protected \Microsoft\Windows\ path rejected client-side
	_, impl := newSTTestClient(t)
	input := ScheduledTaskInput{
		Name: "BadTask", Path: `\Microsoft\Windows\`,
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily"}},
	}
	_, err := impl.Create(context.Background(), input)
	if !IsScheduledTaskError(err, ScheduledTaskErrorBuiltinTask) {
		t.Errorf("expected builtin_task error, got: %v", err)
	}
}

func TestSTCreate_SYSTEMPrincipal_NoPassword(t *testing.T) {
	// EC-3: SYSTEM principal — no password in script
	_, impl := newSTTestClient(t)
	var capturedScript string
	defer stubSTRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return buildMinimalPayloadJSON(t, "SysTask", `\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "SysTask", Path: `\`, Enabled: true,
		Principal: &ScheduledTaskPrincipalInput{
			UserID:    "SYSTEM",
			LogonType: "ServiceAccount",
		},
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "AtStartup"}},
	}
	_, err := impl.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	_ = capturedScript // password is nil so it won't be added to the script
}

func TestSTCreate_MultipleActions(t *testing.T) {
	// EC-6: multiple sequential actions
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "MultiAction", `\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "MultiAction", Path: `\`, Enabled: true,
		Actions: []ScheduledTaskActionInput{
			{Execute: "cmd.exe", Arguments: "/c echo 1"},
			{Execute: "pwsh.exe", Arguments: "-NonInteractive"},
		},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily", StartBoundary: "2026-01-01T00:00:00Z"}},
	}
	state, err := impl.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if state == nil {
		t.Fatal("expected state")
	}
}

func TestSTCreate_OnEventTrigger(t *testing.T) {
	// EC-12 / ADR-ST-5: OnEvent triggers use XML injection
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "EventTask", `\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "EventTask", Path: `\`, Enabled: true,
		Actions: []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{
			{Type: "OnEvent", Subscription: "<QueryList/>"},
		},
	}
	_, err := impl.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
}

func TestSTCreate_PasswordSensitive_NotInErrorContext(t *testing.T) {
	// EC-4: password must never appear in error context
	_, impl := newSTTestClient(t)
	pw := "s3cr3tP@ssword"
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stErrEnvelope(t, "permission_denied", "Access is denied"), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "PwTask", Path: `\`, Enabled: true,
		Principal: &ScheduledTaskPrincipalInput{
			UserID:    `DOMAIN\svc`,
			Password:  &pw,
			LogonType: "Password",
		},
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily", StartBoundary: "2026-01-01T00:00:00Z"}},
	}
	_, err := impl.Create(context.Background(), input)
	if err == nil {
		t.Fatal("expected error")
	}
	var ste *ScheduledTaskError
	if errors.As(err, &ste) {
		for k, v := range ste.Context {
			if strings.Contains(v, pw) || strings.Contains(k, pw) {
				t.Errorf("password appeared in error context key=%q value=%q", k, v)
			}
		}
		if strings.Contains(ste.Message, pw) {
			t.Error("password should not appear in error message")
		}
	}
}

func TestSTCreate_RecursiveFolderCreation(t *testing.T) {
	// EC-2: sub-folder created via Ensure-TaskFolder call in script
	_, impl := newSTTestClient(t)
	var capturedScript string
	defer stubSTRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return buildMinimalPayloadJSON(t, "DeepTask", `\A\B\C\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "DeepTask", Path: `\A\B\C\`, Enabled: true,
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily", StartBoundary: "2026-01-01T00:00:00Z"}},
	}
	_, err := impl.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if !strings.Contains(capturedScript, "Ensure-TaskFolder") {
		t.Errorf("expected Ensure-TaskFolder call in script, got: %s", capturedScript[:min(500, len(capturedScript))])
	}
}

func TestSTCreate_RootPath_NoDoubleBackslash(t *testing.T) {
	// EC-1: root path (\) — no double-backslash issues
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "RootTask", `\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "RootTask", Path: `\`, Enabled: true,
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "AtStartup"}},
	}
	state, err := impl.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if state.Path != `\` {
		t.Errorf("Path should be root \\, got %q", state.Path)
	}
}

func TestSTCreate_NullDataAfterCreate_Error(t *testing.T) {
	// Task not found after create → error
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":null}` + "\n", "", nil
	})()
	input := ScheduledTaskInput{
		Name: "T", Path: `\`,
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily", StartBoundary: "2026-01-01T00:00:00Z"}},
	}
	_, err := impl.Create(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when task not found after create")
	}
	if !IsScheduledTaskError(err, ScheduledTaskErrorUnknown) {
		t.Errorf("expected unknown error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestSTUpdate_HappyPath(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "MyTask", `\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "MyTask", Path: `\`, Description: "updated",
		Enabled: true,
		Actions: []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{
			{Type: "Daily", StartBoundary: "2026-01-01T00:00:00Z"},
		},
	}
	state, err := impl.Update(context.Background(), `\MyTask`, input)
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestSTUpdate_NullDataAfterUpdate_Error(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":null}` + "\n", "", nil
	})()
	input := ScheduledTaskInput{
		Name: "Gone", Path: `\`,
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily"}},
	}
	_, err := impl.Update(context.Background(), `\Gone`, input)
	if err == nil {
		t.Fatal("expected error for null data after update")
	}
}

func TestSTUpdate_DescriptionOnly_UsesSetScheduledTask(t *testing.T) {
	// EC-7: description-only update must use Set-ScheduledTask (in-place)
	_, impl := newSTTestClient(t)
	var capturedScript string
	defer stubSTRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return buildMinimalPayloadJSON(t, "MyTask", `\`), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "MyTask", Path: `\`, Description: "new description",
		Enabled: true,
		Actions: []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily", StartBoundary: "2026-01-01T00:00:00Z"}},
	}
	_, err := impl.Update(context.Background(), `\MyTask`, input)
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if !strings.Contains(capturedScript, "Set-ScheduledTask") {
		t.Errorf("expected Set-ScheduledTask in update script, got: %s", capturedScript[:min(500, len(capturedScript))])
	}
}

func TestSTUpdate_PermissionDenied(t *testing.T) {
	// EC-13: non-admin access denied during update
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stErrEnvelope(t, "permission_denied", "Access is denied"), "", nil
	})()
	input := ScheduledTaskInput{
		Name: "T", Path: `\`,
		Actions:  []ScheduledTaskActionInput{{Execute: "cmd.exe"}},
		Triggers: []ScheduledTaskTriggerInput{{Type: "Daily"}},
	}
	_, err := impl.Update(context.Background(), `\T`, input)
	if !IsScheduledTaskError(err, ScheduledTaskErrorPermissionDenied) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestSTDelete_HappyPath(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":"deleted"}` + "\n", "", nil
	})()
	err := impl.Delete(context.Background(), `\MyTask`)
	if err != nil {
		t.Fatalf("Delete error: %v", err)
	}
}

func TestSTDelete_BuiltinPathGuard(t *testing.T) {
	// EC-13: protected path rejected client-side
	_, impl := newSTTestClient(t)
	err := impl.Delete(context.Background(), `\Microsoft\Windows\SomeTask`)
	if !IsScheduledTaskError(err, ScheduledTaskErrorBuiltinTask) {
		t.Errorf("expected builtin_task error, got: %v", err)
	}
}

func TestSTDelete_AlreadyAbsent_Idempotent(t *testing.T) {
	// Idempotent: task missing → OK
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":"not_found"}` + "\n", "", nil
	})()
	err := impl.Delete(context.Background(), `\GoneTask`)
	if err != nil {
		t.Fatalf("Delete for absent task should succeed, got: %v", err)
	}
}

func TestSTDelete_PermissionDenied(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stErrEnvelope(t, "permission_denied", "Access is denied"), "", nil
	})()
	err := impl.Delete(context.Background(), `\ProtectedTask`)
	if !IsScheduledTaskError(err, ScheduledTaskErrorPermissionDenied) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestSTDelete_UppercasePath(t *testing.T) {
	// Builtin guard is case-insensitive
	_, impl := newSTTestClient(t)
	err := impl.Delete(context.Background(), `\MICROSOFT\WINDOWS\SomeTask`)
	if !IsScheduledTaskError(err, ScheduledTaskErrorBuiltinTask) {
		t.Errorf("expected builtin_task error for uppercase path, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ImportByID
// ---------------------------------------------------------------------------

func TestSTImportByID_HappyPath(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "MyTask", `\`), "", nil
	})()
	state, err := impl.ImportByID(context.Background(), `\MyTask`)
	if err != nil {
		t.Fatalf("ImportByID error: %v", err)
	}
	if state == nil || state.Name != "MyTask" {
		t.Errorf("unexpected state: %+v", state)
	}
}

func TestSTImportByID_NotFound(t *testing.T) {
	// EC-11: import of non-existent task → ScheduledTaskErrorNotFound
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return stErrEnvelope(t, "not_found", "Task not found for import"), "", nil
	})()
	_, err := impl.ImportByID(context.Background(), `\NoSuchTask`)
	if !IsScheduledTaskError(err, ScheduledTaskErrorNotFound) {
		t.Errorf("expected not_found, got: %v", err)
	}
}

func TestSTImportByID_NullData(t *testing.T) {
	// ok=true but data=null → not_found
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":null}` + "\n", "", nil
	})()
	_, err := impl.ImportByID(context.Background(), `\NoTask`)
	if !IsScheduledTaskError(err, ScheduledTaskErrorNotFound) {
		t.Errorf("expected not_found for null data, got: %v", err)
	}
}

func TestSTImportByID_SubFolder(t *testing.T) {
	_, impl := newSTTestClient(t)
	defer stubSTRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return buildMinimalPayloadJSON(t, "SubTask", `\Folder\`), "", nil
	})()
	state, err := impl.ImportByID(context.Background(), `\Folder\SubTask`)
	if err != nil {
		t.Fatalf("ImportByID error: %v", err)
	}
	if state.Path != `\Folder\` {
		t.Errorf("Path = %q, want \\Folder\\", state.Path)
	}
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
