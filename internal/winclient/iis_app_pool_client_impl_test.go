// Package winclient — unit tests for IISAppPoolClient (issue #283 B).
//
// These tests stub the package-level runPowerShell / runPSInput seams (shared
// with service.go / local_user.go) so no real SSH connection is needed.
//
// Coverage targets:
//   - IISAppPoolError: Error(), Unwrap(), Is(), sentinels
//   - mapIISAppPoolKind: all known kinds + 0x8007052e fallback + unknown
//   - buildIISAppPoolSetStatements: only-configured-attrs emission, psQuote,
//     password variable reference (never plaintext), schedule clear+add,
//     cpu x1000
//   - Scripts: Ensure-IIS gate, literal Where-Object lookups, no password in
//     script text (password on stdin), partial-failure cleanup on create,
//     in_use refusal on delete, already_exists import hint
//   - Retry: file-has-changed-on-disk retried 3x then config_locked; other
//     errors not retried
//   - parseIISAppPoolState: null, happy path, bad JSON, schedule quirks
//   - CRUD happy paths + validation short-circuit
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

// iisNewClient returns an *IISAppPoolClient for tests.
func iisNewClient(t *testing.T) *IISAppPoolClient {
	t.Helper()
	c, err := New(Config{Host: "winiis01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewIISAppPoolClient(c)
}

// iisOK returns a JSON ok-envelope whose data field is the supplied value.
func iisOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("iisOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// iisErr returns a JSON error-envelope for the given kind/message.
func iisErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("iisErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// testIISAppPoolState is a minimal valid app-pool JSON payload.
func testIISAppPoolState() map[string]any {
	return map[string]any{
		"name": "api", "managed_runtime_version": "v4.0", "managed_pipeline_mode": "Integrated",
		"enable_32bit_app_on_win64": false, "start_mode": "OnDemand", "auto_start": true,
		"queue_length": 1000, "identity_type": "ApplicationPoolIdentity", "identity_username": "",
		"load_user_profile": true, "idle_timeout_minutes": 20, "idle_timeout_action": "Terminate",
		"max_processes": 1, "recycling_periodic_restart_minutes": 1740,
		"recycling_schedule": []any{}, "recycling_private_memory_kb": 0,
		"rapid_fail_protection": true, "cpu_limit_percent": 0, "cpu_action": "NoAction",
		"state": "Started",
	}
}

// iisStubSequence stubs runPowerShell with a fixed ordered list of responses.
func iisStubSequence(responses []frResponse) func() {
	i := 0
	return stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		r := responses[i]
		if i < len(responses)-1 {
			i++
		}
		return r.stdout, r.stderr, r.err
	})
}

// ---------------------------------------------------------------------------
// IISAppPoolError
// ---------------------------------------------------------------------------

func TestIISAppPoolError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewIISAppPoolError(IISAppPoolErrorAccessDenied, "denied", cause, map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewIISAppPoolError(IISAppPoolErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestIISAppPoolError_Is(t *testing.T) {
	e := NewIISAppPoolError(IISAppPoolErrorInUse, "x", nil, nil)
	if !errors.Is(e, ErrIISAppPoolInUse) {
		t.Error("errors.Is(ErrIISAppPoolInUse) should match by kind")
	}
	if errors.Is(e, ErrIISAppPoolNotFound) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsIISAppPoolError(e, IISAppPoolErrorInUse) {
		t.Error("IsIISAppPoolError should match")
	}
	if IsIISAppPoolError(errors.New("plain"), IISAppPoolErrorInUse) {
		t.Error("IsIISAppPoolError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-IISAppPoolError should be false")
	}
}

func TestMapIISAppPoolKind(t *testing.T) {
	cases := map[string]IISAppPoolErrorKind{
		"not_found":         IISAppPoolErrorNotFound,
		"already_exists":    IISAppPoolErrorAlreadyExists,
		"in_use":            IISAppPoolErrorInUse,
		"iis_not_installed": IISAppPoolErrorIISNotInstalled,
		"invalid_identity":  IISAppPoolErrorInvalidIdentity,
		"access_denied":     IISAppPoolErrorAccessDenied,
		"config_locked":     IISAppPoolErrorConfigLocked,
		"":                  IISAppPoolErrorUnknown,
		"weird_kind":        IISAppPoolErrorUnknown,
	}
	for in, want := range cases {
		if got := mapIISAppPoolKind(in, "some message"); got != want {
			t.Errorf("mapIISAppPoolKind(%q) = %q, want %q", in, got, want)
		}
	}
	// Logon failure maps to invalid_identity even when the script-side
	// classifier missed it — without echoing the password.
	if got := mapIISAppPoolKind("unknown", "The user name or password is incorrect. (Exception from HRESULT: 0x8007052E)"); got != IISAppPoolErrorInvalidIdentity {
		t.Errorf("0x8007052e fallback = %q, want invalid_identity", got)
	}
}

// ---------------------------------------------------------------------------
// Set-statement builder: only configured attributes are emitted
// ---------------------------------------------------------------------------

func TestBuildIISAppPoolSetStatements_OnlyConfigured(t *testing.T) {
	script := buildIISAppPoolSetStatements(IISAppPoolSettings{}, false)
	if strings.Contains(script, "Set-ItemProperty") {
		t.Errorf("empty settings must emit no writes, got:\n%s", script)
	}

	v := "v4.0"
	size := int64(8192)
	script = buildIISAppPoolSetStatements(IISAppPoolSettings{
		ManagedRuntimeVersion:    &v,
		RecyclingPrivateMemoryKB: &size,
	}, false)
	for _, want := range []string{
		"managedRuntimeVersion", "'v4.0'",
		"recycling.periodicRestart.privateMemory", "8192",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q, got:\n%s", want, script)
		}
	}
	for _, absent := range []string{
		"managedPipelineMode", "processModel.identityType", "cpu.limit",
		"recycling.periodicRestart.schedule", "processModel.password",
	} {
		if strings.Contains(script, absent) {
			t.Errorf("script must not emit unconfigured attribute %q, got:\n%s", absent, script)
		}
	}
}

func TestBuildIISAppPoolSetStatements_PasswordNeverPlaintext(t *testing.T) {
	id := "SpecificUser"
	user := `CONTOSO\svc-web`
	script := buildIISAppPoolSetStatements(IISAppPoolSettings{
		IdentityType: &id, IdentityUsername: &user,
	}, true)
	if !strings.Contains(script, "$AppPoolPassword") {
		t.Errorf("password write must reference the stdin variable, got:\n%s", script)
	}
	if strings.Contains(script, "P@ss") {
		t.Errorf("password plaintext must never appear in script text, got:\n%s", script)
	}
	if !strings.Contains(script, psQuote(user)) {
		t.Errorf("username must appear psQuote'd, got:\n%s", script)
	}
	// Without a password the credential line is omitted entirely.
	script = buildIISAppPoolSetStatements(IISAppPoolSettings{IdentityType: &id}, false)
	if strings.Contains(script, "processModel.password") {
		t.Errorf("no password supplied: credential line must be omitted, got:\n%s", script)
	}
}

func TestBuildIISAppPoolSetStatements_ScheduleAndCPU(t *testing.T) {
	script := buildIISAppPoolSetStatements(IISAppPoolSettings{
		RecyclingSchedule: []string{"03:00:00"}, RecyclingScheduleSet: true,
	}, false)
	for _, want := range []string{
		"Clear-ItemProperty", "recycling.periodicRestart.schedule",
		"Add-WebConfigurationProperty", "'03:00:00'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("schedule write missing %q, got:\n%s", want, script)
		}
	}
	// Configured-but-empty schedule clears the collection authoritatively.
	script = buildIISAppPoolSetStatements(IISAppPoolSettings{
		RecyclingSchedule: []string{}, RecyclingScheduleSet: true,
	}, false)
	if !strings.Contains(script, "Clear-ItemProperty") {
		t.Errorf("empty-but-set schedule must clear the collection, got:\n%s", script)
	}
	if strings.Contains(script, "Add-WebConfigurationProperty") {
		t.Errorf("empty schedule must add no entries, got:\n%s", script)
	}

	cpu := int64(50)
	script = buildIISAppPoolSetStatements(IISAppPoolSettings{CPULimitPercent: &cpu}, false)
	if !strings.Contains(script, "cpu.limit") || !strings.Contains(script, "50000") {
		t.Errorf("cpu_limit_percent must convert x1000, got:\n%s", script)
	}

	idle := int64(20)
	script = buildIISAppPoolSetStatements(IISAppPoolSettings{IdleTimeoutMinutes: &idle}, false)
	if !strings.Contains(script, "New-TimeSpan -Minutes 20") {
		t.Errorf("idle timeout must write a TimeSpan, got:\n%s", script)
	}
}

func TestBuildIISAppPoolSetStatements_UserValueQuoting(t *testing.T) {
	evil := "x'; Write-Host pwned; '"
	script := buildIISAppPoolSetStatements(IISAppPoolSettings{ManagedPipelineMode: &evil}, false)
	if strings.Contains(script, evil) {
		t.Errorf("user value must be quoted, got:\n%s", script)
	}
	if !strings.Contains(script, psQuote(evil)) {
		t.Errorf("user value must appear psQuote'd, got:\n%s", script)
	}
}

// ---------------------------------------------------------------------------
// Script content: gate, literal lookups, cleanup, import hint
// ---------------------------------------------------------------------------

func TestIISAppPoolScripts_ShipPreludeAndGate(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisOK(t, testIISAppPoolState()), "", nil
	})
	defer restore()

	c := iisNewClient(t)
	if _, err := c.Read(context.Background(), "api"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'",
		"function Ensure-IIS",
		"if (-not (Ensure-IIS)) { return }",
		"function Classify-IIS",
		"function Get-AppPoolData",
		"function Classify-AppPool",
		"Where-Object { $_.Name -eq $Name }",
		"$Name = 'api'",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("read script missing %q", want)
		}
	}
}

func TestIISAppPoolCreate_ScriptContent(t *testing.T) {
	var gotScript, gotStdin string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisOK(t, testIISAppPoolState()), "", nil
	})
	defer restore()
	restoreInput := stubRunInput(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		gotScript = script
		gotStdin = stdin
		return iisOK(t, testIISAppPoolState()), "", nil
	})
	defer restoreInput()

	c := iisNewClient(t)
	id := "SpecificUser"
	user := `CONTOSO\svc-web`
	if _, err := c.Create(context.Background(), IISAppPoolInput{
		Name:     "svc",
		Settings: IISAppPoolSettings{IdentityType: &id, IdentityUsername: &user},
		Password: "s3cret!",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"New-WebAppPool", "already_exists", "terraform import",
		"Remove-WebAppPool", // best-effort cleanup on partial failure
		"[Console]::In.ReadLine()",
		psQuote(user),
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("create script missing %q", want)
		}
	}
	if strings.Contains(gotScript, "s3cret!") {
		t.Error("password plaintext must never appear in script text")
	}
	if gotStdin != "s3cret!\n" {
		t.Errorf("password must travel on stdin, got %q", gotStdin)
	}
}

func TestIISAppPoolUpdate_NoPasswordStdin(t *testing.T) {
	var gotScript string
	usedInput := false
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisOK(t, testIISAppPoolState()), "", nil
	})
	defer restore()
	restoreInput := stubRunInput(func(_ context.Context, _ *Client, script, _ string) (string, string, error) {
		usedInput = true
		gotScript = script
		return iisOK(t, testIISAppPoolState()), "", nil
	})
	defer restoreInput()

	c := iisNewClient(t)
	mode := "Classic"
	if _, err := c.Update(context.Background(), IISAppPoolInput{
		Name: "api", Settings: IISAppPoolSettings{ManagedPipelineMode: &mode},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usedInput {
		t.Error("update without a password must not use the stdin transport")
	}
	if strings.Contains(gotScript, "ReadLine") || strings.Contains(gotScript, "processModel.password") {
		t.Errorf("update without a password must not touch the credential, got:\n%s", gotScript)
	}
	if !strings.Contains(gotScript, "'Classic'") {
		t.Errorf("update must set the configured attribute, got:\n%s", gotScript)
	}
}

func TestIISAppPoolDelete_RefusesInUse(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisOK(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	c := iisNewClient(t)
	if err := c.Delete(context.Background(), "api"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"Get-Website", "Get-WebApplication", "'in_use'",
		"Where-Object { $_.applicationPool -eq $Name }",
		"Remove-WebAppPool",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
}

func TestIISAppPoolRead_MissingIsNil(t *testing.T) {
	restore := iisStubSequence([]frResponse{{stdout: iisOK(t, nil), stderr: "", err: nil}})
	defer restore()

	c := iisNewClient(t)
	st, err := c.Read(context.Background(), "gone")
	if err != nil || st != nil {
		t.Errorf("missing pool should be (nil, nil), got (%+v, %v)", st, err)
	}
}

func TestIISAppPoolValidation_ShortCircuits(t *testing.T) {
	called := false
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	restoreInput := stubRunInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restoreInput()

	c := iisNewClient(t)
	if _, err := c.Read(context.Background(), "a/b"); err == nil {
		t.Error("invalid name must fail")
	}
	if _, err := c.Create(context.Background(), IISAppPoolInput{Name: ""}); err == nil {
		t.Error("empty name must fail")
	}
	if _, err := c.Update(context.Background(), IISAppPoolInput{Name: " trailing "}); err == nil {
		t.Error("padded name must fail")
	}
	if err := c.Delete(context.Background(), "a*b"); err == nil {
		t.Error("wildcard name must fail")
	}
	if called {
		t.Error("invalid pool names must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// Retry: only the file-has-changed-on-disk flake retries
// ---------------------------------------------------------------------------

func TestIISAppPoolWrite_RetriesFlakeThenConfigLocked(t *testing.T) {
	oldBackoff := iisRetryBackoff
	iisRetryBackoff = func(int) time.Duration { return 0 }
	defer func() { iisRetryBackoff = oldBackoff }()

	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return iisErr(t, "unknown", "Cannot commit configuration changes because the file has changed on disk."), "", nil
	})
	defer restore()

	c := iisNewClient(t)
	mode := "Classic"
	_, err := c.Update(context.Background(), IISAppPoolInput{
		Name: "api", Settings: IISAppPoolSettings{ManagedPipelineMode: &mode},
	})
	if !IsIISAppPoolError(err, IISAppPoolErrorConfigLocked) {
		t.Errorf("persistent flake must surface as config_locked, got %v", err)
	}
	if calls != 3 {
		t.Errorf("flake must be retried up to 3 attempts, got %d calls", calls)
	}
}

func TestIISAppPoolWrite_FlakeRecovers(t *testing.T) {
	oldBackoff := iisRetryBackoff
	iisRetryBackoff = func(int) time.Duration { return 0 }
	defer func() { iisRetryBackoff = oldBackoff }()

	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		if calls == 1 {
			return iisErr(t, "unknown", "Cannot commit configuration changes because the file has changed on disk."), "", nil
		}
		return iisOK(t, testIISAppPoolState()), "", nil
	})
	defer restore()

	c := iisNewClient(t)
	mode := "Classic"
	st, err := c.Update(context.Background(), IISAppPoolInput{
		Name: "api", Settings: IISAppPoolSettings{ManagedPipelineMode: &mode},
	})
	if err != nil || st == nil {
		t.Fatalf("recovered write should succeed, got (%+v, %v)", st, err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls (flake + success), got %d", calls)
	}
}

func TestIISAppPoolCreate_FlakeThenAlreadyExistsIsConfigLocked(t *testing.T) {
	oldBackoff := iisRetryBackoff
	iisRetryBackoff = func(int) time.Duration { return 0 }
	defer func() { iisRetryBackoff = oldBackoff }()

	flakeMsg := "Cannot commit configuration changes because the file has changed on disk."
	restore := iisStubSequence([]frResponse{
		{stdout: iisErr(t, "unknown", flakeMsg), stderr: "", err: nil},
		{stdout: iisErr(t, "already_exists", "IIS application pool 'api' already exists on this host."), stderr: "", err: nil},
	})
	defer restore()

	c := iisNewClient(t)
	mode := "Classic"
	_, err := c.Create(context.Background(), IISAppPoolInput{
		Name: "api", Settings: IISAppPoolSettings{ManagedPipelineMode: &mode},
	})
	if !IsIISAppPoolError(err, IISAppPoolErrorConfigLocked) {
		t.Fatalf("flake-then-already_exists on create must surface as config_locked, got %v", err)
	}
	if !strings.Contains(err.Error(), flakeMsg) {
		t.Errorf("config_locked error must keep the original flake message, got %v", err)
	}

	// Control: already_exists with no prior flake stays already_exists.
	restoreControl := iisStubSequence([]frResponse{
		{stdout: iisErr(t, "already_exists", "IIS application pool 'api' already exists on this host."), stderr: "", err: nil},
	})
	defer restoreControl()
	if _, err := c.Create(context.Background(), IISAppPoolInput{
		Name: "api", Settings: IISAppPoolSettings{ManagedPipelineMode: &mode},
	}); !IsIISAppPoolError(err, IISAppPoolErrorAlreadyExists) {
		t.Errorf("already_exists without a prior flake must stay already_exists, got %v", err)
	}
}

func TestIISAppPoolWrite_OtherErrorsNotRetried(t *testing.T) {
	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return iisErr(t, "access_denied", "Access is denied"), "", nil
	})
	defer restore()

	c := iisNewClient(t)
	if err := c.Delete(context.Background(), "api"); !IsIISAppPoolError(err, IISAppPoolErrorAccessDenied) {
		t.Errorf("expected access_denied, got %v", err)
	}
	if calls != 1 {
		t.Errorf("non-flake failures must not retry, got %d calls", calls)
	}
}

// ---------------------------------------------------------------------------
// Remote kinds + payload parsing
// ---------------------------------------------------------------------------

func TestIISAppPoolRemoteKinds(t *testing.T) {
	cases := []struct {
		remote string
		want   IISAppPoolErrorKind
	}{
		{"not_found", IISAppPoolErrorNotFound},
		{"already_exists", IISAppPoolErrorAlreadyExists},
		{"in_use", IISAppPoolErrorInUse},
		{"iis_not_installed", IISAppPoolErrorIISNotInstalled},
		{"invalid_identity", IISAppPoolErrorInvalidIdentity},
		{"access_denied", IISAppPoolErrorAccessDenied},
		{"config_locked", IISAppPoolErrorConfigLocked},
	}
	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			restore := iisStubSequence([]frResponse{{stdout: iisErr(t, tc.remote, "boom "+tc.remote), stderr: "", err: nil}})
			defer restore()

			c := iisNewClient(t)
			_, err := c.Read(context.Background(), "api")
			if tc.remote == "not_found" {
				if err != nil {
					t.Errorf("read not_found should be (nil, nil), got %v", err)
				}
				return
			}
			if !IsIISAppPoolError(err, tc.want) {
				t.Errorf("remote kind %q should map to %q, got %v", tc.remote, tc.want, err)
			}
		})
	}
}

func TestParseIISAppPoolState_HappyPath(t *testing.T) {
	raw, _ := json.Marshal(testIISAppPoolState())
	st, err := parseIISAppPoolState("read", "api", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "api" || st.ManagedRuntimeVersion != "v4.0" || st.QueueLength != 1000 {
		t.Errorf("unexpected state: %+v", st)
	}
	if st.IdleTimeoutMinutes != 20 || st.RecyclingPeriodicRestartMinutes != 1740 {
		t.Errorf("minutes conversion wrong: %+v", st)
	}
	if len(st.RecyclingSchedule) != 0 {
		t.Errorf("empty schedule = %v, want []", st.RecyclingSchedule)
	}
	if st.State != "Started" {
		t.Errorf("state = %q, want Started", st.State)
	}
}

func TestParseIISAppPoolState_Null(t *testing.T) {
	st, err := parseIISAppPoolState("read", "api", json.RawMessage("null"))
	if err != nil || st != nil {
		t.Errorf("null data should be (nil, nil), got (%+v, %v)", st, err)
	}
}

func TestParseIISAppPoolState_BadJSON(t *testing.T) {
	if _, err := parseIISAppPoolState("read", "api", json.RawMessage("{nope")); !IsIISAppPoolError(err, IISAppPoolErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestParseIISAppPoolSchedule_Quirks(t *testing.T) {
	// Bare string: ConvertTo-Json single-element quirk.
	st, err := parseIISAppPoolSchedule(json.RawMessage(`"03:00:00"`))
	if err != nil || len(st) != 1 || st[0] != "03:00:00" {
		t.Errorf("bare string schedule = %v, %v", st, err)
	}
	// Array round-trips.
	st, err = parseIISAppPoolSchedule(json.RawMessage(`["03:00:00","04:00:00"]`))
	if err != nil || len(st) != 2 {
		t.Errorf("array schedule = %v, %v", st, err)
	}
	// Null and empty.
	for _, raw := range []string{"null", ""} {
		st, err = parseIISAppPoolSchedule(json.RawMessage(raw))
		if err != nil || len(st) != 0 {
			t.Errorf("raw %q schedule = %v, %v; want empty", raw, st, err)
		}
	}
}

// ---------------------------------------------------------------------------
// CRUD happy paths
// ---------------------------------------------------------------------------

func TestIISAppPoolCRUD_HappyPaths(t *testing.T) {
	restore := iisStubSequence([]frResponse{{stdout: iisOK(t, testIISAppPoolState()), stderr: "", err: nil}})
	defer restore()

	c := iisNewClient(t)
	mode := "Integrated"
	st, err := c.Create(context.Background(), IISAppPoolInput{
		Name: "api", Settings: IISAppPoolSettings{ManagedPipelineMode: &mode},
	})
	if err != nil || st == nil || st.Name != "api" {
		t.Fatalf("create: (%+v, %v)", st, err)
	}
	st, err = c.Update(context.Background(), IISAppPoolInput{
		Name: "api", Settings: IISAppPoolSettings{ManagedPipelineMode: &mode},
	})
	if err != nil || st == nil {
		t.Fatalf("update: (%+v, %v)", st, err)
	}
	if err := c.Delete(context.Background(), "api"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestIISAppPoolIISNotInstalled(t *testing.T) {
	restore := iisStubSequence([]frResponse{{stdout: iisErr(t, "iis_not_installed", "IIS is not installed on this host. Install it with the windows_feature resource (Web-Server)."), stderr: "", err: nil}})
	defer restore()

	c := iisNewClient(t)
	_, err := c.Read(context.Background(), "api")
	if !IsIISAppPoolError(err, IISAppPoolErrorIISNotInstalled) {
		t.Errorf("expected iis_not_installed, got %v", err)
	}
	var ae *IISAppPoolError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "windows_feature") {
		t.Errorf("missing-IIS error must point at windows_feature, got %v", err)
	}
}
