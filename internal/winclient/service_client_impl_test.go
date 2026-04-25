// Package winclient unit tests for ServiceClient.
//
// These tests stub the `runPowerShell` package-level seam to inject scripted
// stdout responses, covering:
//   - psQuote / psQuoteList / extractLastJSONLine / truncate / mapKind pure helpers
//   - ServiceError structured error (Error, Unwrap, Is, NewServiceError, IsServiceError)
//   - normaliseState EC-14 outer-quote strip + SS10 account normalisation
//   - Create happy path + EC-1 (already_exists) + EC-11 (invalid_parameter) + validation
//   - Read happy path + EC-2 (not_found) + malformed JSON
//   - Update happy path + not_found + empty-name validation
//   - Delete happy path + already-absent + timeout + empty-name validation
//   - StartService / StopService / PauseService success + EC-13 PauseService guard
//   - runEnvelope: ctx cancellation (EC-7 timeout) + transport error + missing envelope
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:     "localhost",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

// stubRun replaces the package-level runPowerShell hook with a deterministic
// fake. It returns a restorer closure the caller must defer.
func stubRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runPowerShell
	runPowerShell = fn
	return func() { runPowerShell = prev }
}

func okEnvelope(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok envelope: %v", err)
	}
	return string(b) + "\n"
}

func errEnvelope(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("marshal err envelope: %v", err)
	}
	return string(b) + "\n"
}

// -----------------------------------------------------------------------------
// Pure helpers
// -----------------------------------------------------------------------------

func TestPsQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "''"},
		{"hello", "'hello'"},
		{"it's", "'it''s'"},
		{"a'b'c", "'a''b''c'"},
	}
	for _, tc := range cases {
		if got := psQuote(tc.in); got != tc.want {
			t.Errorf("psQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPsQuoteList(t *testing.T) {
	if got := psQuoteList(nil); got != "@()" {
		t.Errorf("nil list = %q", got)
	}
	if got := psQuoteList([]string{}); got != "@()" {
		t.Errorf("empty list = %q", got)
	}
	if got := psQuoteList([]string{"A", "B"}); got != "@('A','B')" {
		t.Errorf("two items = %q", got)
	}
	if got := psQuoteList([]string{"it's"}); got != "@('it''s')" {
		t.Errorf("quote in item = %q", got)
	}
}

func TestExtractLastJSONLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"WARNING: foo\n{\"ok\":true}\n", `{"ok":true}`},
		{"no json here", ""},
		{"{\"a\":1}\n{\"b\":2}\n", `{"b":2}`},
		{"  {\"ok\":true}  ", `{"ok":true}`},
	}
	for _, tc := range cases {
		if got := extractLastJSONLine(tc.in); got != tc.want {
			t.Errorf("extractLastJSONLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abc", 10); got != "abc" {
		t.Errorf("short = %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc...[truncated]" {
		t.Errorf("long = %q", got)
	}
}

func TestMapKind(t *testing.T) {
	cases := map[string]ServiceErrorKind{
		"not_found":         ServiceErrorNotFound,
		"already_exists":    ServiceErrorAlreadyExists,
		"permission_denied": ServiceErrorPermission,
		"timeout":           ServiceErrorTimeout,
		"invalid_parameter": ServiceErrorInvalidParameter,
		"already_running":   ServiceErrorRunning,
		"not_running":       ServiceErrorNotRunning,
		"disabled":          ServiceErrorDisabled,
		"":                  ServiceErrorUnknown,
		"weird":             ServiceErrorUnknown,
	}
	for in, want := range cases {
		if got := mapKind(in); got != want {
			t.Errorf("mapKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// ServiceError structured type
// -----------------------------------------------------------------------------

func TestServiceError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("boom")
	e := NewServiceError(ServiceErrorTimeout, "op timed out", cause, map[string]string{"op": "Delete"})

	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "timeout") || !strings.Contains(msg, "op timed out") || !strings.Contains(msg, "boom") {
		t.Errorf("Error() = %q", msg)
	}
	e2 := NewServiceError(ServiceErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error() leaks nil: %q", e2.Error())
	}
}

func TestServiceError_Is_And_IsServiceError(t *testing.T) {
	e := NewServiceError(ServiceErrorNotFound, "x", nil, nil)
	if !errors.Is(e, ErrServiceNotFound) {
		t.Error("errors.Is(ServiceNotFound) should match on kind")
	}
	if errors.Is(e, ErrServicePermission) {
		t.Error("errors.Is across kinds should NOT match")
	}
	if !IsServiceError(e, ServiceErrorNotFound) {
		t.Error("IsServiceError kind match")
	}
	if IsServiceError(errors.New("plain"), ServiceErrorNotFound) {
		t.Error("IsServiceError plain error should be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-ServiceError should be false")
	}
}

// -----------------------------------------------------------------------------
// normaliseState (EC-14 + SS10)
// -----------------------------------------------------------------------------

func TestNormaliseState_NilReturnsNil(t *testing.T) {
	if normaliseState(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

func TestNormaliseState_StripsOuterQuotes_EC14(t *testing.T) {
	d := &stateData{Name: "s", BinaryPath: `"C:\path\svc.exe --flag"`, ServiceAccount: "LocalSystem"}
	st := normaliseState(d)
	if st.BinaryPath != `C:\path\svc.exe --flag` {
		t.Errorf("EC-14 outer quote strip failed: %q", st.BinaryPath)
	}
}

func TestNormaliseState_KeepsUnquotedBinary(t *testing.T) {
	d := &stateData{Name: "s", BinaryPath: `C:\plain.exe`, ServiceAccount: "LocalSystem"}
	st := normaliseState(d)
	if st.BinaryPath != `C:\plain.exe` {
		t.Errorf("unquoted should pass through: %q", st.BinaryPath)
	}
}

func TestNormaliseState_AccountLocalSystem_SS10(t *testing.T) {
	d := &stateData{Name: "s", ServiceAccount: "NT AUTHORITY\\SYSTEM"}
	st := normaliseState(d)
	if st.ServiceAccount != "LocalSystem" {
		t.Errorf("expected LocalSystem, got %q", st.ServiceAccount)
	}
	d2 := &stateData{Name: "s", ServiceAccount: "LocalSystem"}
	if normaliseState(d2).ServiceAccount != "LocalSystem" {
		t.Error("LocalSystem unchanged")
	}
}

func TestNormaliseState_DotAccountResolved_SS10(t *testing.T) {
	d := &stateData{Name: "s", ServiceAccount: ".\\svcuser", Hostname: "WIN01"}
	st := normaliseState(d)
	if st.ServiceAccount != "WIN01\\svcuser" {
		t.Errorf("expected WIN01\\svcuser, got %q", st.ServiceAccount)
	}
}

func TestNormaliseState_DepsNilBecomesEmpty(t *testing.T) {
	d := &stateData{Name: "s", Dependencies: nil}
	st := normaliseState(d)
	if st.Dependencies == nil || len(st.Dependencies) != 0 {
		t.Errorf("deps should be empty slice, got %#v", st.Dependencies)
	}
}

// -----------------------------------------------------------------------------
// Input validation short-circuits
// -----------------------------------------------------------------------------

func TestCreate_ValidationErrors(t *testing.T) {
	s := NewServiceClient(newTestClient(t))
	ctx := context.Background()

	if _, err := s.Create(ctx, ServiceInput{}); !IsServiceError(err, ServiceErrorInvalidParameter) {
		t.Errorf("empty Name should yield invalid_parameter, got %v", err)
	}
	if _, err := s.Create(ctx, ServiceInput{Name: "svc"}); !IsServiceError(err, ServiceErrorInvalidParameter) {
		t.Errorf("empty BinaryPath should yield invalid_parameter, got %v", err)
	}
}

func TestRead_EmptyName(t *testing.T) {
	s := NewServiceClient(newTestClient(t))
	if _, err := s.Read(context.Background(), ""); !IsServiceError(err, ServiceErrorInvalidParameter) {
		t.Errorf("empty name should yield invalid_parameter, got %v", err)
	}
}

func TestUpdate_EmptyName(t *testing.T) {
	s := NewServiceClient(newTestClient(t))
	if _, err := s.Update(context.Background(), "", ServiceInput{}); !IsServiceError(err, ServiceErrorInvalidParameter) {
		t.Errorf("empty name should yield invalid_parameter, got %v", err)
	}
}

func TestDelete_EmptyName(t *testing.T) {
	s := NewServiceClient(newTestClient(t))
	if err := s.Delete(context.Background(), ""); !IsServiceError(err, ServiceErrorInvalidParameter) {
		t.Errorf("empty name should yield invalid_parameter, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// runEnvelope — ctx cancellation / transport errors / missing envelope
// -----------------------------------------------------------------------------

func TestRunEnvelope_ContextCancelled_EC7(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Read(ctx, "svc")
	if !IsServiceError(err, ServiceErrorTimeout) {
		t.Errorf("expected timeout (EC-7), got %v", err)
	}
}

func TestRunEnvelope_TransportErrorUnknown(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "some stderr", errors.New("winrm: broken pipe")
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	_, err := s.Read(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestRunEnvelope_NoJSONEnvelope(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "WARNING: no JSON printed\n", "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	_, err := s.Read(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorUnknown) {
		t.Errorf("expected unknown for missing envelope, got %v", err)
	}
}

func TestRunEnvelope_MalformedJSON(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "{not:valid,json}\n", "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	_, err := s.Read(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorUnknown) {
		t.Errorf("expected unknown for malformed JSON, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Create — happy path + EC-1 + EC-11
// -----------------------------------------------------------------------------

func fakeState(name string) map[string]any {
	return map[string]any{
		"name": name, "display_name": name, "description": "",
		"binary_path": `C:\svc.exe`, "start_type": "Automatic", "current_status": "Stopped",
		"service_account": "LocalSystem", "dependencies": []string{}, "hostname": "WIN01",
	}
}

func TestCreate_HappyPath(t *testing.T) {
	calls := 0
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		calls++
		if !strings.Contains(script, `'C:\svc.exe'`) {
			t.Errorf("script missing quoted binary path")
		}
		return okEnvelope(t, fakeState("svc")), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	st, err := s.Create(context.Background(), ServiceInput{
		Name: "svc", BinaryPath: `C:\svc.exe`, DisplayName: "My Svc",
	})
	if err != nil {
		t.Fatalf("Create err: %v", err)
	}
	if st == nil || st.Name != "svc" {
		t.Errorf("unexpected state: %+v", st)
	}
	if calls == 0 {
		t.Error("runPowerShell was never invoked")
	}
}

func TestCreate_AlreadyExists_EC1(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "already_exists", "service 'svc' already exists"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	_, err := s.Create(context.Background(), ServiceInput{Name: "svc", BinaryPath: `C:\x.exe`})
	if !IsServiceError(err, ServiceErrorAlreadyExists) {
		t.Errorf("EC-1 expected already_exists, got %v", err)
	}
}

func TestCreate_InvalidParameter_EC11_NoPasswordLeak(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "invalid_parameter", "The parameter is incorrect (87)"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	_, err := s.Create(context.Background(), ServiceInput{
		Name: "svc", BinaryPath: `C:\x.exe`,
		ServiceAccount: "LocalSystem", ServicePassword: "leakybucket!",
	})
	if !IsServiceError(err, ServiceErrorInvalidParameter) {
		t.Errorf("EC-11 expected invalid_parameter, got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "leakybucket!") {
		t.Errorf("EC-11 error leaks password: %s", err.Error())
	}
}

func TestCreate_ReconcileRunning(t *testing.T) {
	step := 0
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		step++
		switch step {
		case 1:
			return okEnvelope(t, fakeState("svc")), "", nil
		case 2:
			return okEnvelope(t, map[string]any{"status": "Running"}), "", nil
		default:
			running := fakeState("svc")
			running["current_status"] = "Running"
			return okEnvelope(t, running), "", nil
		}
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	st, err := s.Create(context.Background(), ServiceInput{
		Name: "svc", BinaryPath: `C:\svc.exe`, DesiredStatus: "Running",
	})
	if err != nil {
		t.Fatalf("Create err: %v", err)
	}
	if st.CurrentStatus != "Running" {
		t.Errorf("expected Running, got %q", st.CurrentStatus)
	}
	if step < 3 {
		t.Errorf("expected ≥3 PS calls, got %d", step)
	}
}

// -----------------------------------------------------------------------------
// Read — happy path + EC-2 not_found + null payload
// -----------------------------------------------------------------------------

func TestRead_HappyPath(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		d := fakeState("svc")
		d["service_account"] = ".\\svcuser"
		d["binary_path"] = `"C:\with space.exe"`
		return okEnvelope(t, d), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	st, err := s.Read(context.Background(), "svc")
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if st == nil {
		t.Fatal("expected state, got nil")
	}
	if st.BinaryPath != `C:\with space.exe` {
		t.Errorf("EC-14 strip failed: %q", st.BinaryPath)
	}
	if st.ServiceAccount != "WIN01\\svcuser" {
		t.Errorf("SS10 dot-resolve failed: %q", st.ServiceAccount)
	}
}

func TestRead_NotFound_EC2(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":null}` + "\n", "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	st, err := s.Read(context.Background(), "svc")
	if err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
	if st != nil {
		t.Errorf("expected nil state, got %+v", st)
	}
}

func TestRead_NotFoundViaKind(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "not_found", "service 'svc' does not exist"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	st, err := s.Read(context.Background(), "svc")
	if err != nil {
		t.Errorf("not_found must be swallowed at Read, got %v", err)
	}
	if st != nil {
		t.Errorf("expected nil state, got %+v", st)
	}
}

// -----------------------------------------------------------------------------
// Update — happy + not_found + clear deps
// -----------------------------------------------------------------------------

func TestUpdate_HappyPath(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return okEnvelope(t, fakeState("svc")), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	st, err := s.Update(context.Background(), "svc", ServiceInput{
		DisplayName: "New Display", Description: "desc", StartType: "Manual",
		Dependencies: []string{"Dep1", "Dep2"},
	})
	if err != nil {
		t.Fatalf("Update err: %v", err)
	}
	if st == nil {
		t.Fatal("expected state")
	}
}

func TestUpdate_ClearsDependencies(t *testing.T) {
	var captured string
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return okEnvelope(t, fakeState("svc")), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	_, err := s.Update(context.Background(), "svc", ServiceInput{Dependencies: []string{}})
	if err != nil {
		t.Fatalf("Update err: %v", err)
	}
	if !strings.Contains(captured, "'clear'") || !strings.Contains(captured, "'/'") {
		t.Errorf("expected 'clear' mode and '/' dep arg, fragment=%s",
			firstContainingLine(captured, "depsMode"))
	}
}

func TestUpdate_NotFound(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "not_found", "no such"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	_, err := s.Update(context.Background(), "svc", ServiceInput{})
	if !IsServiceError(err, ServiceErrorNotFound) {
		t.Errorf("expected not_found, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Delete — happy + already-absent + timeout
// -----------------------------------------------------------------------------

func TestDelete_HappyPath(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return okEnvelope(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	if err := s.Delete(context.Background(), "svc"); err != nil {
		t.Errorf("Delete err: %v", err)
	}
}

func TestDelete_AlreadyAbsent_Idempotent(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "not_found", "service 'svc' does not exist"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	if err := s.Delete(context.Background(), "svc"); err != nil {
		t.Errorf("Delete should be idempotent on not_found, got %v", err)
	}
}

func TestDelete_Timeout_EC7(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "timeout", "service 'svc' did not stop within 30 s"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	err := s.Delete(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorTimeout) {
		t.Errorf("expected timeout EC-7, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// StartService / StopService / PauseService
// -----------------------------------------------------------------------------

func TestStartService_Success(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return okEnvelope(t, map[string]any{"status": "Running"}), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	if err := s.StartService(context.Background(), "svc"); err != nil {
		t.Errorf("Start err: %v", err)
	}
}

func TestStartService_AlreadyRunning(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "already_running", "Win32 1056"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	err := s.StartService(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorRunning) {
		t.Errorf("expected already_running, got %v", err)
	}
}

func TestStartService_Disabled(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "disabled", "Win32 1058"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	err := s.StartService(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorDisabled) {
		t.Errorf("expected disabled, got %v", err)
	}
}

func TestStopService_Success(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return okEnvelope(t, map[string]any{"status": "Stopped"}), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	if err := s.StopService(context.Background(), "svc"); err != nil {
		t.Errorf("Stop err: %v", err)
	}
}

func TestStopService_NotRunning(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "not_running", "Win32 1062"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	err := s.StopService(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorNotRunning) {
		t.Errorf("expected not_running, got %v", err)
	}
}

func TestPauseService_Success(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return okEnvelope(t, map[string]any{"status": "Paused"}), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	if err := s.PauseService(context.Background(), "svc"); err != nil {
		t.Errorf("Pause err: %v", err)
	}
}

func TestPauseService_NotPausable_EC13(t *testing.T) {
	restore := stubRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return errEnvelope(t, "invalid_parameter",
			"service 'svc' does not support Pause (CanPauseAndContinue=false, EC-13)"), "", nil
	})
	defer restore()

	s := NewServiceClient(newTestClient(t))
	err := s.PauseService(context.Background(), "svc")
	if !IsServiceError(err, ServiceErrorInvalidParameter) {
		t.Errorf("EC-13 expected invalid_parameter, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "EC-13") {
		t.Errorf("EC-13 marker missing: %s", err.Error())
	}
}

// -----------------------------------------------------------------------------
// Classification & helpers coverage
// -----------------------------------------------------------------------------

func TestQuoteOuterRegex(t *testing.T) {
	m := quoteOuterRe.FindStringSubmatch(`"abc"`)
	if m == nil || m[1] != "abc" {
		t.Errorf("symmetric quote: %v", m)
	}
	if quoteOuterRe.FindStringSubmatch(`"abc`) != nil {
		t.Error("asymmetric should not match")
	}
}

// firstContainingLine returns the first line of s containing needle, to
// produce informative failures when inspecting rendered PS scripts.
func firstContainingLine(s, needle string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			return strings.TrimSpace(line)
		}
	}
	return fmt.Sprintf("(no line contained %q)", needle)
}
