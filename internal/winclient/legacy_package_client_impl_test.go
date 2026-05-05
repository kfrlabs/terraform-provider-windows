// Package winclient — unit tests for LegacyPackageClientImpl.
//
// Tests stub the package-level runPSInput seam (shared with local_user.go) so
// no real WinRM connection is needed.
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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func lpNewClient(t *testing.T) (*Client, *LegacyPackageClientImpl) {
	t.Helper()
	c, err := New(Config{Host: "winlp01", Username: "u", Password: "p", Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewLegacyPackageClient(c)
}

// stubLPInput replaces the package-level runPSInput hook for the duration of
// the test. It returns a restorer the caller MUST defer.
func stubLPInput(fn func(ctx context.Context, c *Client, script, stdin string) (string, string, error)) func() {
	prev := runPSInput
	runPSInput = fn
	return func() { runPSInput = prev }
}

func lpOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("lpOK marshal: %v", err)
	}
	return string(b) + "\n"
}

func lpOKNull() string { return `{"ok":true,"data":null}` + "\n" }

func lpErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": map[string]string{"foo": "bar"},
	})
	if err != nil {
		t.Fatalf("lpErr marshal: %v", err)
	}
	return string(b) + "\n"
}

func lpStateMap(id, version string) map[string]any {
	return map[string]any{
		"id":                id,
		"product_id":        id,
		"installed_version": version,
		"installed":         true,
		"install_date":      "2026-01-15",
		"log_path":          `C:\Windows\TEMP\windows_legacy_package\install.log`,
	}
}

// ---------------------------------------------------------------------------
// LegacyPackageError
// ---------------------------------------------------------------------------

func TestLPError_ErrorWithCause(t *testing.T) {
	cause := errors.New("network down")
	e := &LegacyPackageError{
		Kind: "timeout", Message: "winrm cancelled",
		Cause: cause, Context: map[string]string{"host": "winlp01"},
	}
	msg := e.Error()
	for _, want := range []string{"timeout", "winrm cancelled", "network down"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in Error(): %q", want, msg)
		}
	}
}

func TestLPError_ErrorNoCause(t *testing.T) {
	e := &LegacyPackageError{Kind: "checksum_mismatch", Message: "hash differs"}
	msg := e.Error()
	if strings.Contains(msg, "<nil>") {
		t.Errorf("nil cause should not appear: %q", msg)
	}
	if !strings.Contains(msg, "checksum_mismatch") {
		t.Errorf("missing kind: %q", msg)
	}
}

func TestLPError_Unwrap(t *testing.T) {
	cause := errors.New("boom")
	e := &LegacyPackageError{Kind: "unknown", Message: "x", Cause: cause}
	if e.Unwrap() != cause {
		t.Error("Unwrap should return cause")
	}
	e2 := &LegacyPackageError{Kind: "unknown", Message: "x"}
	if e2.Unwrap() != nil {
		t.Error("Unwrap with no cause should return nil")
	}
}

func TestIsLegacyPackageError_Match(t *testing.T) {
	e := &LegacyPackageError{Kind: "timeout", Message: "x"}
	if !IsLegacyPackageError(e, "timeout") {
		t.Error("should match on kind")
	}
}

func TestIsLegacyPackageError_WrongKind(t *testing.T) {
	e := &LegacyPackageError{Kind: "timeout", Message: "x"}
	if IsLegacyPackageError(e, "permission_denied") {
		t.Error("should NOT match different kind")
	}
}

func TestIsLegacyPackageError_PlainAndNil(t *testing.T) {
	if IsLegacyPackageError(errors.New("plain"), "timeout") {
		t.Error("plain error must not match")
	}
	if IsLegacyPackageError(nil, "timeout") {
		t.Error("nil must not match")
	}
}

func TestIsLegacyPackageError_Wrapped(t *testing.T) {
	inner := &LegacyPackageError{Kind: "checksum_mismatch", Message: "x"}
	wrapped := fmt.Errorf("outer: %w", inner)
	if !IsLegacyPackageError(wrapped, "checksum_mismatch") {
		t.Error("errors.As traversal must find wrapped *LegacyPackageError")
	}
}

// ---------------------------------------------------------------------------
// parseLPState
// ---------------------------------------------------------------------------

func TestLPParseState_NilData(t *testing.T) {
	st, err := parseLPState(&psResponse{OK: true, Data: nil})
	if err != nil || st != nil {
		t.Errorf("nil data: state=%v err=%v", st, err)
	}
}

func TestLPParseState_LiteralNullData(t *testing.T) {
	st, err := parseLPState(&psResponse{OK: true, Data: json.RawMessage("null")})
	if err != nil || st != nil {
		t.Errorf("null data: state=%v err=%v", st, err)
	}
}

func TestLPParseState_Valid(t *testing.T) {
	raw, _ := json.Marshal(lpStateMap("{ABC}", "1.2.3"))
	st, err := parseLPState(&psResponse{OK: true, Data: raw})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if st == nil || st.ID != "{ABC}" || st.InstalledVersion != "1.2.3" || !st.Installed {
		t.Errorf("decoded state = %+v", st)
	}
}

func TestLPParseState_MalformedJSON(t *testing.T) {
	st, err := parseLPState(&psResponse{OK: true, Data: json.RawMessage(`{"installed":"not-a-bool"}`)})
	if err == nil || st != nil {
		t.Errorf("expected error on malformed JSON, got state=%v err=%v", st, err)
	}
	if !IsLegacyPackageError(err, "unknown") {
		t.Errorf("kind = %T %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// runEnvelope — error paths
// ---------------------------------------------------------------------------

func TestLPRunEnvelope_TransportError(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "winrm: connection refused", errors.New("dial tcp: refused")
	})()

	_, err := lp.runEnvelope(context.Background(), "Create", LegacyPackageInput{Name: "x"}, "Emit-OK $null")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsLegacyPackageError(err, "unknown") {
		t.Errorf("kind = %v", err)
	}
}

func TestLPRunEnvelope_CtxCancelled(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(ctx context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "", ctx.Err()
	})()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := lp.runEnvelope(ctx, "Read", readPayload{ID: "x"}, "Emit-OK $null")
	if !IsLegacyPackageError(err, "timeout") {
		t.Errorf("expected timeout kind, got %v", err)
	}
}

func TestLPRunEnvelope_NoEnvelope(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "no json here\n", "", nil
	})()

	_, err := lp.runEnvelope(context.Background(), "Delete", deletePayload{ID: "x"}, "Emit-OK $null")
	if !IsLegacyPackageError(err, "unknown") {
		t.Errorf("kind = %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "no JSON envelope") {
		t.Errorf("missing 'no JSON envelope' in: %v", err)
	}
}

func TestLPRunEnvelope_MalformedJSON(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return `{not valid json` + "\n", "", nil
	})()

	_, err := lp.runEnvelope(context.Background(), "Create", LegacyPackageInput{}, "Emit-OK $null")
	if !IsLegacyPackageError(err, "unknown") {
		t.Errorf("kind = %v", err)
	}
}

func TestLPRunEnvelope_EmitErr(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return lpErr(t, "checksum_mismatch", "hash differs"), "", nil
	})()

	resp, err := lp.runEnvelope(context.Background(), "Create", LegacyPackageInput{}, "Emit-OK $null")
	if !IsLegacyPackageError(err, "checksum_mismatch") {
		t.Fatalf("kind = %v", err)
	}
	if resp == nil || resp.OK {
		t.Errorf("resp should be the parsed envelope with OK=false, got %+v", resp)
	}
	var le *LegacyPackageError
	if !errors.As(err, &le) {
		t.Fatal("expected *LegacyPackageError")
	}
	if le.Context["operation"] != "Create" || le.Context["host"] != "winlp01" {
		t.Errorf("context not enriched: %+v", le.Context)
	}
	if le.Context["foo"] != "bar" {
		t.Errorf("PS-side context not propagated: %+v", le.Context)
	}
}

func TestLPRunEnvelope_Happy(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		// Sanity: header must be prepended and stdin must be valid JSON.
		if !strings.Contains(script, "Emit-OK") {
			t.Errorf("header not prepended (first 64 chars): %s", safeHead(script, 64))
		}
		var any map[string]any
		if jerr := json.Unmarshal([]byte(stdin), &any); jerr != nil {
			t.Errorf("stdin not JSON: %v (%q)", jerr, stdin)
		}
		return lpOK(t, lpStateMap("{XYZ}", "9.9.9")), "", nil
	})()

	resp, err := lp.runEnvelope(context.Background(), "Create", LegacyPackageInput{Name: "test"}, "Emit-OK $null")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !resp.OK {
		t.Errorf("ok = false: %+v", resp)
	}
}

// Marshal-error path: channels are unsupported by encoding/json.
func TestLPRunEnvelope_MarshalError(t *testing.T) {
	_, lp := lpNewClient(t)
	type bad struct {
		C chan int `json:"c"`
	}
	_, err := lp.runEnvelope(context.Background(), "Create", bad{C: make(chan int)}, "")
	if !IsLegacyPackageError(err, "unknown") {
		t.Fatalf("expected marshal error → unknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CRUD methods
// ---------------------------------------------------------------------------

func TestLPCreate_Happy(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return lpOK(t, lpStateMap("{ABC}", "1.0.0")), "", nil
	})()

	st, err := lp.Create(context.Background(), LegacyPackageInput{
		Name: "demo", InstallerType: "msi", SourcePath: `C:\inst.msi`,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if st == nil || st.ID != "{ABC}" || st.InstalledVersion != "1.0.0" {
		t.Errorf("state = %+v", st)
	}
}

func TestLPCreate_Transport(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "", errors.New("connection reset")
	})()

	_, err := lp.Create(context.Background(), LegacyPackageInput{Name: "demo"})
	if !IsLegacyPackageError(err, "unknown") {
		t.Errorf("kind = %v", err)
	}
}

func TestLPRead_Happy(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, stdin string) (string, string, error) {
		if !strings.Contains(stdin, `"id":"{ABC}"`) {
			t.Errorf("stdin missing id: %q", stdin)
		}
		return lpOK(t, lpStateMap("{ABC}", "2.0.0")), "", nil
	})()

	st, err := lp.Read(context.Background(), "{ABC}")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if st == nil || st.InstalledVersion != "2.0.0" {
		t.Errorf("state = %+v", st)
	}
}

func TestLPRead_Absent(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return lpOKNull(), "", nil
	})()

	st, err := lp.Read(context.Background(), "{GONE}")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if st != nil {
		t.Errorf("expected nil state, got %+v", st)
	}
}

func TestLPRead_EmitErr(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return lpErr(t, "permission_denied", "registry locked"), "", nil
	})()

	_, err := lp.Read(context.Background(), "{ABC}")
	if !IsLegacyPackageError(err, "permission_denied") {
		t.Errorf("kind = %v", err)
	}
}

func TestLPUpdate_DelegatesToRead(t *testing.T) {
	_, lp := lpNewClient(t)
	calls := 0
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		calls++
		return lpOK(t, lpStateMap("{ABC}", "1.5.0")), "", nil
	})()

	st, err := lp.Update(context.Background(), "{ABC}", LegacyPackageInput{TimeoutSeconds: 600})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if st.InstalledVersion != "1.5.0" {
		t.Errorf("state = %+v", st)
	}
	if calls != 1 {
		t.Errorf("expected 1 PS call, got %d", calls)
	}
}

func TestLPUpdate_PropagatesError(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return lpErr(t, "unknown", "boom"), "", nil
	})()

	_, err := lp.Update(context.Background(), "{ABC}", LegacyPackageInput{})
	if !IsLegacyPackageError(err, "unknown") {
		t.Errorf("kind = %v", err)
	}
}

func TestLPDelete_Happy(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, stdin string) (string, string, error) {
		if !strings.Contains(stdin, `"id":"{ABC}"`) {
			t.Errorf("stdin missing id: %q", stdin)
		}
		return lpOK(t, nil), "", nil
	})()

	if err := lp.Delete(context.Background(), "{ABC}"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestLPDelete_EmitErr(t *testing.T) {
	_, lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return lpErr(t, "exit_code_invalid", "1603"), "", nil
	})()

	err := lp.Delete(context.Background(), "{ABC}")
	if !IsLegacyPackageError(err, "exit_code_invalid") {
		t.Errorf("kind = %v", err)
	}
}

// safeHead returns the first n runes (or fewer) of s.
func safeHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
