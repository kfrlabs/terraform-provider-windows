// Package winclient — unit tests for EventLogClient.
//
// These tests stub the package-level runPowerShell seam (shared with
// service.go) so no real SSH connection is needed. Coverage targets (issue
// #289):
//
//	EventLogError: Error(), Unwrap(), Is(), sentinels, IsEventLogError
//	mapEventLogKind: all known kinds + unknown fallback
//	ValidateEventLogSize: 1 MiB floor, 64 KiB multiple, invalid_size kind
//	EventLogRetentionToLogMode / EventLogLogModeToRetention: mapping + fallbacks
//	EventLogSettings.EventLogConfigured
//	buildEventLogSetBlock: only-configured-attrs emission, psQuote, fail-closed
//	buildEventLogGuard: disable-guard only when Enabled=false
//	buildEventLogRestoreBlock: verbatim incl. raw LogMode
//	parseEventLogState: null, valid, bad JSON, Analytic normalisation
//	verifyEventLogState: per-field mismatch detection
//	runEventLogEnvelope: timeout/transport/no-envelope/bad-JSON/Emit-Err mapping
//	Read/Apply/Restore: happy paths, literal-match fragment, no-op Apply,
//	not_found, unsupported, invalid_size
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// elTestStatePayload is a minimal valid event-log state JSON payload.
func elTestStatePayload() map[string]any {
	return map[string]any{
		"log_name":           "Application",
		"log_type":           "Administrative",
		"is_classic":         true,
		"is_enabled":         true,
		"log_mode":           "Circular",
		"maximum_size_bytes": 20971520,
		"log_file_path":      `%SystemRoot%\System32\Winevt\Logs\Application.evtx`,
		"record_count":       1234,
		"file_size_bytes":    2105344,
		"policy_override":    false,
	}
}

// ---------------------------------------------------------------------------
// EventLogError
// ---------------------------------------------------------------------------

func TestEventLogError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewEventLogError(EventLogErrorAccessDenied, "denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewEventLogError(EventLogErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestEventLogError_Is(t *testing.T) {
	e := NewEventLogError(EventLogErrorUnsupported, "x", nil, nil)
	if !errors.Is(e, ErrEventLogUnsupported) {
		t.Error("errors.Is(ErrEventLogUnsupported) should match by kind")
	}
	if errors.Is(e, ErrEventLogAccessDenied) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsEventLogError(e, EventLogErrorUnsupported) {
		t.Error("IsEventLogError should match")
	}
	if IsEventLogError(errors.New("plain"), EventLogErrorUnsupported) {
		t.Error("IsEventLogError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-EventLogError should be false")
	}
}

func TestMapEventLogKind(t *testing.T) {
	cases := map[string]EventLogErrorKind{
		"not_found":     EventLogErrorNotFound,
		"access_denied": EventLogErrorAccessDenied,
		"unsupported":   EventLogErrorUnsupported,
		"invalid_size":  EventLogErrorInvalidSize,
		"":              EventLogErrorUnknown,
		"weird_kind":    EventLogErrorUnknown,
	}
	for in, want := range cases {
		if got := mapEventLogKind(in); got != want {
			t.Errorf("mapEventLogKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Size validation and retention mapping
// ---------------------------------------------------------------------------

func TestValidateEventLogSize(t *testing.T) {
	for _, size := range []int64{1048576, 20971520, 1073741824} {
		if err := ValidateEventLogSize(size); err != nil {
			t.Errorf("size %d should be valid, got %v", size, err)
		}
	}
	for _, size := range []int64{0, 1, 1048575, 1048577, 20971519, 1000000} {
		err := ValidateEventLogSize(size)
		if !IsEventLogError(err, EventLogErrorInvalidSize) {
			t.Errorf("size %d should yield invalid_size, got %v", size, err)
		}
	}
}

func TestEventLogRetentionMapping(t *testing.T) {
	cases := map[string]string{
		"overwrite": "Circular",
		"archive":   "AutoBackup",
		"retain":    "Retain",
	}
	for retention, want := range cases {
		got, err := EventLogRetentionToLogMode(retention)
		if err != nil || got != want {
			t.Errorf("EventLogRetentionToLogMode(%q) = %q, %v; want %q, nil", retention, got, err, want)
		}
		if back := EventLogLogModeToRetention(want); back != retention {
			t.Errorf("EventLogLogModeToRetention(%q) = %q, want %q", want, back, retention)
		}
	}
	if _, err := EventLogRetentionToLogMode("bogus"); err == nil {
		t.Error("unknown retention must fail closed")
	}
	// Unknown host modes pass through verbatim so they are observed, not dropped.
	if got := EventLogLogModeToRetention("FutureMode"); got != "FutureMode" {
		t.Errorf("unknown LogMode must pass through, got %q", got)
	}
}

func TestEventLogSettings_Configured(t *testing.T) {
	if (EventLogSettings{}).EventLogConfigured() {
		t.Error("empty settings must be unconfigured")
	}
	size := int64(20971520)
	if !(EventLogSettings{MaximumSizeBytes: &size}).EventLogConfigured() {
		t.Error("size-only settings must be configured")
	}
	retention := "overwrite"
	if !(EventLogSettings{Retention: &retention}).EventLogConfigured() {
		t.Error("retention-only settings must be configured")
	}
	enabled := true
	if !(EventLogSettings{Enabled: &enabled}).EventLogConfigured() {
		t.Error("enabled-only settings must be configured")
	}
	path := `C:\Logs\app.evtx`
	if !(EventLogSettings{LogFilePath: &path}).EventLogConfigured() {
		t.Error("path-only settings must be configured")
	}
}

// ---------------------------------------------------------------------------
// Script builders: only configured attributes are emitted
// ---------------------------------------------------------------------------

func TestBuildEventLogSetBlock_OnlyConfigured(t *testing.T) {
	// Retention-only: nothing else written.
	retention := "archive"
	block, err := buildEventLogSetBlock(EventLogSettings{Retention: &retention})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(block, "$c.LogMode = 'AutoBackup'") {
		t.Errorf("retention must map to LogMode AutoBackup, got:\n%s", block)
	}
	for _, absent := range []string{"MaximumSizeInBytes", "IsEnabled", "LogFilePath"} {
		if strings.Contains(block, absent) {
			t.Errorf("unconfigured attribute %q must be omitted, got:\n%s", absent, block)
		}
	}

	// Full settings: every line present.
	size := int64(20971520)
	enabled := true
	logPath := `C:\Logs\app.evtx`
	block, err = buildEventLogSetBlock(EventLogSettings{
		MaximumSizeBytes: &size,
		Retention:        &retention,
		Enabled:          &enabled,
		LogFilePath:      &logPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"$c.MaximumSizeInBytes = 20971520",
		"$c.LogMode = 'AutoBackup'",
		"$c.IsEnabled = $true",
		"$c.LogFilePath = 'C:\\Logs\\app.evtx'",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("set block missing %q, got:\n%s", want, block)
		}
	}

	// User strings travel through psQuote.
	evil := "x'; Write-Host pwned; '"
	block, err = buildEventLogSetBlock(EventLogSettings{LogFilePath: &evil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(block, evil) {
		t.Errorf("user value must be quoted, got:\n%s", block)
	}
	if !strings.Contains(block, psQuote(evil)) {
		t.Errorf("user value must appear psQuote'd, got:\n%s", block)
	}
}

func TestBuildEventLogSetBlock_FailClosed(t *testing.T) {
	small := int64(1024)
	if _, err := buildEventLogSetBlock(EventLogSettings{MaximumSizeBytes: &small}); !IsEventLogError(err, EventLogErrorInvalidSize) {
		t.Errorf("undersized value must fail closed with invalid_size, got %v", err)
	}
	odd := int64(1048577)
	if _, err := buildEventLogSetBlock(EventLogSettings{MaximumSizeBytes: &odd}); !IsEventLogError(err, EventLogErrorInvalidSize) {
		t.Errorf("non-multiple value must fail closed with invalid_size, got %v", err)
	}
	bogus := "circular"
	if _, err := buildEventLogSetBlock(EventLogSettings{Retention: &bogus}); err == nil {
		t.Error("unknown retention must fail closed")
	}
}

func TestBuildEventLogGuard(t *testing.T) {
	if got := buildEventLogGuard(EventLogSettings{}); got != "" {
		t.Errorf("no Enabled setting must emit no guard, got %q", got)
	}
	enabled := true
	if got := buildEventLogGuard(EventLogSettings{Enabled: &enabled}); got != "" {
		t.Errorf("Enabled=true must emit no guard, got %q", got)
	}
	disabled := false
	guard := buildEventLogGuard(EventLogSettings{Enabled: &disabled})
	for _, want := range []string{"IsClassic", "unsupported", "cannot be disabled"} {
		if !strings.Contains(guard, want) {
			t.Errorf("disable guard missing %q, got:\n%s", want, guard)
		}
	}
}

func TestBuildEventLogRestoreBlock_Verbatim(t *testing.T) {
	snap := EventLogState{
		Name: "Security", MaximumSizeBytes: 1073741824, LogMode: "Retain",
		IsEnabled: true, LogFilePath: `%SystemRoot%\System32\Winevt\Logs\Security.evtx`,
	}
	block := buildEventLogRestoreBlock(snap)
	for _, want := range []string{
		"$c.MaximumSizeInBytes = 1073741824",
		"$c.LogMode = 'Retain'",
		"$c.IsEnabled = $true",
		`%SystemRoot%\System32\Winevt\Logs\Security.evtx`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("restore block missing %q, got:\n%s", want, block)
		}
	}
	// Disabled snapshots round-trip verbatim (they came from the host).
	snap.IsEnabled = false
	if block := buildEventLogRestoreBlock(snap); !strings.Contains(block, "$c.IsEnabled = $false") {
		t.Errorf("restore must preserve disabled snapshots, got:\n%s", block)
	}
}

// ---------------------------------------------------------------------------
// parseEventLogState
// ---------------------------------------------------------------------------

func TestParseEventLogState_Null(t *testing.T) {
	resp := &psResponse{Data: json.RawMessage("null")}
	st, err := parseEventLogState(resp, "Application")
	if err != nil || st != nil {
		t.Errorf("null data should be (nil, nil), got (%+v, %v)", st, err)
	}
}

func TestParseEventLogState_HappyPath(t *testing.T) {
	raw, _ := json.Marshal(elTestStatePayload())
	resp := &psResponse{Data: raw}
	st, err := parseEventLogState(resp, "Application")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "Application" || st.LogType != "Administrative" {
		t.Errorf("unexpected identity: %+v", st)
	}
	if !st.IsClassic || !st.IsEnabled {
		t.Errorf("unexpected flags: %+v", st)
	}
	if st.LogMode != "Circular" || st.MaximumSizeBytes != 20971520 {
		t.Errorf("unexpected size/mode: %+v", st)
	}
	if st.RecordCount != 1234 || st.FileSizeBytes != 2105344 {
		t.Errorf("counts must be observed verbatim: %+v", st)
	}
	if st.PolicyOverride {
		t.Errorf("policy_override must be false: %+v", st)
	}
}

func TestParseEventLogState_BadJSON(t *testing.T) {
	resp := &psResponse{Data: json.RawMessage("{nope")}
	if _, err := parseEventLogState(resp, "Application"); !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestParseEventLogState_AnalyticNormalisation(t *testing.T) {
	payload := elTestStatePayload()
	payload["log_type"] = "Analytical"
	raw, _ := json.Marshal(payload)
	resp := &psResponse{Data: raw}
	st, err := parseEventLogState(resp, "Microsoft-Windows-PowerShell/Operational")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.LogType != "Analytic" {
		t.Errorf("Analytical must normalise to Analytic, got %q", st.LogType)
	}
}

func TestParseEventLogState_EmptyNameFallsBack(t *testing.T) {
	payload := elTestStatePayload()
	payload["log_name"] = ""
	raw, _ := json.Marshal(payload)
	resp := &psResponse{Data: raw}
	st, err := parseEventLogState(resp, "Application")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "Application" {
		t.Errorf("empty log_name must fall back to the requested name, got %q", st.Name)
	}
}

// ---------------------------------------------------------------------------
// verifyEventLogState
// ---------------------------------------------------------------------------

func TestVerifyEventLogState(t *testing.T) {
	size := int64(20971520)
	retention := "overwrite"
	enabled := true
	logPath := `%SystemRoot%\System32\Winevt\Logs\Application.evtx`
	want := EventLogSettings{
		MaximumSizeBytes: &size,
		Retention:        &retention,
		Enabled:          &enabled,
		LogFilePath:      &logPath,
	}
	got := &EventLogState{
		Name: "Application", MaximumSizeBytes: 20971520, LogMode: "Circular",
		IsEnabled: true, LogFilePath: logPath,
	}
	if err := verifyEventLogState(want, got); err != nil {
		t.Errorf("matching state must verify, got %v", err)
	}
	// Empty settings always verify.
	if err := verifyEventLogState(EventLogSettings{}, got); err != nil {
		t.Errorf("empty settings must verify, got %v", err)
	}
	// Each field mismatches independently with an unknown error.
	bad := *got
	bad.MaximumSizeBytes = 1048576
	if err := verifyEventLogState(want, &bad); !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("size mismatch must be unknown, got %v", err)
	}
	bad = *got
	bad.LogMode = "Retain"
	if err := verifyEventLogState(want, &bad); !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("mode mismatch must be unknown, got %v", err)
	}
	bad = *got
	bad.IsEnabled = false
	if err := verifyEventLogState(want, &bad); !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("enabled mismatch must be unknown, got %v", err)
	}
	bad = *got
	bad.LogFilePath = `C:\other.evtx`
	if err := verifyEventLogState(want, &bad); !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("path mismatch must be unknown, got %v", err)
	}
}

func TestVerifyEventLogState_PathEquivalence(t *testing.T) {
	logPath := `%SystemRoot%\System32\Winevt\Logs\Application.evtx`
	want := EventLogSettings{LogFilePath: &logPath}
	// Case, separator and %SystemRoot%-expansion variants must verify:
	// Windows paths are case-insensitive, "/" and "\" are interchangeable,
	// and the host may report the expanded %SystemRoot% location.
	for _, equivalent := range []string{
		`%SYSTEMROOT%\System32\Winevt\Logs\Application.evtx`,
		`%SystemRoot%/System32/Winevt/Logs/Application.evtx`,
		`C:\Windows\System32\Winevt\Logs\Application.evtx`,
		`c:\windows\system32\winevt\logs\application.evtx`,
		`C:/Windows/System32/Winevt/Logs/Application.evtx`,
	} {
		got := &EventLogState{Name: "Application", LogFilePath: equivalent}
		if err := verifyEventLogState(want, got); err != nil {
			t.Errorf("path %q must verify against %q, got %v", equivalent, logPath, err)
		}
	}
	// Genuinely different locations must still fail.
	for _, different := range []string{
		`C:\other.evtx`,
		`C:\Windows\System32\Winevt\Logs\Security.evtx`,
		`D:\Logs\Application.evtx`,
	} {
		got := &EventLogState{Name: "Application", LogFilePath: different}
		if err := verifyEventLogState(want, got); !IsEventLogError(err, EventLogErrorUnknown) {
			t.Errorf("path %q must mismatch, got %v", different, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Script content pins
// ---------------------------------------------------------------------------

func TestEventLogScript_LiteralMatchAndEnvelope(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(elTestStatePayload())
		return okEnvelope(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	if _, err := c.Read(context.Background(), "Microsoft-Windows-PowerShell/Operational"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"function Classify-EventLog",
		"Get-WinEvent -ListLog",
		"Where-Object { $_.LogName -eq $logName }",
		"InvariantCulture",
		"'not_found'",
		"'access_denied'",
		"'unsupported'",
		"'invalid_size'",
		`HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\`,
		"'MaxSize'",
		"'Retention'",
		"'AutoBackupLogFiles'",
		"-LiteralPath",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("script missing %q", want)
		}
	}
	// Read never writes: SaveChanges ships only on Apply/Restore (pinned
	// by TestEventLogApply_HappyPath and TestEventLogRestore_HappyPath).
	if strings.Contains(gotScript, "SaveChanges") {
		t.Errorf("read script must not contain SaveChanges, got:\n%s", gotScript)
	}
	// The channel name must travel psQuote'd, never raw.
	if !strings.Contains(gotScript, psQuote("Microsoft-Windows-PowerShell/Operational")) {
		t.Error("log name must appear psQuote'd")
	}
	// Names are matched literally: no wildcard expansion of -ListLog.
	if strings.Contains(gotScript, "-ListLog $logName") || strings.Contains(gotScript, "-ListLog '") {
		t.Errorf("Get-WinEvent -ListLog must not take the raw name (wildcard risk); filter literally instead, got:\n%s", gotScript)
	}
	// -ListLog takes a String[] argument: a bare switch fails on the host
	// with "Missing an argument for parameter 'ListLog'". List all logs and
	// filter literally instead.
	if !strings.Contains(gotScript, "-ListLog *") {
		t.Errorf("Get-WinEvent -ListLog requires an argument; expected '-ListLog *', got:\n%s", gotScript)
	}
}

func TestEventLogApply_DisableClassicGuardShips(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		payload := elTestStatePayload()
		payload["is_enabled"] = false
		raw, _ := json.Marshal(payload)
		return okEnvelope(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	disabled := false
	if _, err := c.Apply(context.Background(), "Application", EventLogSettings{Enabled: &disabled}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "IsClassic") || !strings.Contains(gotScript, "'unsupported'") {
		t.Errorf("disable apply must ship the classic guard, got:\n%s", gotScript)
	}
}

// ---------------------------------------------------------------------------
// runEventLogEnvelope: ctx cancel / transport / no envelope / bad JSON
// ---------------------------------------------------------------------------

func TestRunEventLogEnvelope_Timeout(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewEventLogClient(newTestClient(t))
	_, err := c.Read(ctx, "Application")
	if !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("expected unknown (timeout) kind, got %v", err)
	}
	var ee *EventLogError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *EventLogError, got %T", err)
	}
	if !strings.Contains(ee.Message, `"Read"`) || !strings.Contains(ee.Message, "Application") {
		t.Errorf("Message = %q, want operation and log name", ee.Message)
	}
}

func TestRunEventLogEnvelope_TransportError(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "boom", errors.New("ssh dial failed")
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	_, err := c.Read(context.Background(), "Application")
	if !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunEventLogEnvelope_NoEnvelope(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "not json at all", "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	_, err := c.Read(context.Background(), "Application")
	if !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunEventLogEnvelope_BadJSON(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{not valid json}", "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	_, err := c.Read(context.Background(), "Application")
	if !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Remote error kinds, one fixture each
// ---------------------------------------------------------------------------

func TestEventLogRemoteKinds(t *testing.T) {
	cases := []struct {
		remote string
		want   EventLogErrorKind
	}{
		{"not_found", EventLogErrorNotFound},
		{"access_denied", EventLogErrorAccessDenied},
		{"unsupported", EventLogErrorUnsupported},
		{"invalid_size", EventLogErrorInvalidSize},
	}
	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
				return errEnvelope(t, tc.remote, "boom "+tc.remote), "", nil
			})
			defer restore()

			c := NewEventLogClient(newTestClient(t))
			_, err := c.Read(context.Background(), "Application")
			if !IsEventLogError(err, tc.want) {
				t.Errorf("remote kind %q should map to %q, got %v", tc.remote, tc.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestEventLogRead_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(elTestStatePayload())
		return okEnvelope(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	st, err := c.Read(context.Background(), "Application")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "Application" || !st.IsClassic || st.LogMode != "Circular" {
		t.Errorf("unexpected state: %+v", st)
	}
	if !strings.Contains(gotScript, psQuote("Application")) {
		t.Error("log name must travel psQuote'd")
	}
}

func TestEventLogRead_MissingIsNil(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return okEnvelope(t, nil), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	st, err := c.Read(context.Background(), "NoSuchLog")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != nil {
		t.Errorf("missing log must be (nil, nil), got %+v", st)
	}
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

func TestEventLogApply_HappyPath(t *testing.T) {
	var gotScript string
	payload := elTestStatePayload()
	payload["maximum_size_bytes"] = 1073741824
	payload["log_mode"] = "AutoBackup"
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(payload)
		return okEnvelope(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	size := int64(1073741824)
	retention := "archive"
	st, err := c.Apply(context.Background(), "Application", EventLogSettings{
		MaximumSizeBytes: &size, Retention: &retention,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st == nil || st.MaximumSizeBytes != 1073741824 || st.LogMode != "AutoBackup" {
		t.Errorf("unexpected state: %+v", st)
	}
	// Partial management: only the configured properties are assigned.
	if !strings.Contains(gotScript, "$c.MaximumSizeInBytes = 1073741824") {
		t.Errorf("script must set the configured size, got:\n%s", gotScript)
	}
	if !strings.Contains(gotScript, "$c.LogMode = 'AutoBackup'") {
		t.Errorf("script must set the configured mode, got:\n%s", gotScript)
	}
	for _, absent := range []string{"$c.IsEnabled =", "$c.LogFilePath ="} {
		if strings.Contains(gotScript, absent) {
			t.Errorf("script must not assign unconfigured property %q, got:\n%s", absent, gotScript)
		}
	}
	if !strings.Contains(gotScript, "SaveChanges") {
		t.Errorf("script must persist via SaveChanges, got:\n%s", gotScript)
	}
}

func TestEventLogApply_NoOpWithoutSettings(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(elTestStatePayload())
		return okEnvelope(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	if _, err := c.Apply(context.Background(), "Application", EventLogSettings{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Nothing configured: short-circuit to Read, no SaveChanges round trip.
	if strings.Contains(gotScript, "SaveChanges") {
		t.Errorf("unconfigured Apply must not write, got:\n%s", gotScript)
	}
}

func TestEventLogApply_VerifyMismatch(t *testing.T) {
	payload := elTestStatePayload()
	payload["maximum_size_bytes"] = 20971520 // host ignores the request
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		raw, _ := json.Marshal(payload)
		return okEnvelope(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	size := int64(1073741824)
	_, err := c.Apply(context.Background(), "Application", EventLogSettings{MaximumSizeBytes: &size})
	if !IsEventLogError(err, EventLogErrorUnknown) {
		t.Errorf("verify mismatch must be unknown, got %v", err)
	}
}

func TestEventLogApply_UnsupportedDisableClassic(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return errEnvelope(t, "unsupported", "classic log cannot be disabled"), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	disabled := false
	_, err := c.Apply(context.Background(), "Application", EventLogSettings{Enabled: &disabled})
	if !IsEventLogError(err, EventLogErrorUnsupported) {
		t.Errorf("expected unsupported, got %v", err)
	}
}

func TestEventLogApply_NotFound(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return errEnvelope(t, "not_found", "Event log Bogus was not found"), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	size := int64(20971520)
	_, err := c.Apply(context.Background(), "Bogus", EventLogSettings{MaximumSizeBytes: &size})
	if !IsEventLogError(err, EventLogErrorNotFound) {
		t.Errorf("expected not_found, got %v", err)
	}
}

func TestEventLogApply_InvalidSizeShortCircuits(t *testing.T) {
	called := false
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	small := int64(512)
	size := small
	_, err := c.Apply(context.Background(), "Application", EventLogSettings{MaximumSizeBytes: &size})
	if !IsEventLogError(err, EventLogErrorInvalidSize) {
		t.Errorf("expected invalid_size, got %v", err)
	}
	if called {
		t.Error("invalid size must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

func TestEventLogRestore_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(elTestStatePayload())
		return okEnvelope(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	snap := EventLogState{
		Name: "Application", LogType: "Administrative", IsClassic: true, IsEnabled: true,
		LogMode: "Circular", MaximumSizeBytes: 20971520,
		LogFilePath:   `%SystemRoot%\System32\Winevt\Logs\Application.evtx`,
		RecordCount:   1234,
		FileSizeBytes: 2105344,
	}
	if _, err := c.Restore(context.Background(), snap); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"$c.MaximumSizeInBytes = 20971520",
		"$c.LogMode = 'Circular'",
		"$c.IsEnabled = $true",
		"SaveChanges",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("restore script missing %q, got:\n%s", want, gotScript)
		}
	}
}

func TestEventLogRestore_InvalidSizeShortCircuits(t *testing.T) {
	called := false
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	snap := EventLogState{
		Name: "Application", LogMode: "Circular", IsEnabled: true,
		MaximumSizeBytes: 512,
		LogFilePath:      `%SystemRoot%\System32\Winevt\Logs\Application.evtx`,
	}
	_, err := c.Restore(context.Background(), snap)
	if !IsEventLogError(err, EventLogErrorInvalidSize) {
		t.Errorf("expected invalid_size, got %v", err)
	}
	if called {
		t.Error("invalid snapshot size must not reach the host")
	}
}

func TestEventLogRestore_NotFound(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return okEnvelope(t, nil), "", nil
	})
	defer restore()

	c := NewEventLogClient(newTestClient(t))
	snap := EventLogState{
		Name: "Gone", LogMode: "Circular", IsEnabled: true,
		MaximumSizeBytes: 20971520,
		LogFilePath:      `%SystemRoot%\System32\Winevt\Logs\Gone.evtx`,
	}
	_, err := c.Restore(context.Background(), snap)
	if !IsEventLogError(err, EventLogErrorNotFound) {
		t.Errorf("restore of a missing log must be not_found, got %v", err)
	}
}
