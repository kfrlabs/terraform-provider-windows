// Package winclient — unit tests for EnvVarClientImpl.
//
// Tests stub the package-level runEnvVarPowerShell hook so no real WinRM
// connection is required. Edge cases covered:
//
//	registryPathForScope   — machine, user, invalid scope
//	mapEnvVarErrorKind     — all branches including unknown fallback
//	EnvVarError            — Error(), Unwrap(), Is(), sentinels, IsEnvVarError()
//	NewEnvVarError         — constructor and nil cause
//	Set (happy path)       — machine scope REG_SZ
//	Set (happy path)       — user scope REG_EXPAND_SZ with broadcast warning
//	Set (EC-12)            — empty value is valid
//	Set (EC-2)             — invalid_input when registry key absent
//	Set (permission)       — permission_denied from PS
//	Set (transport error)  — WinRM transport failure
//	Set (context cancel)   — cancelled context
//	Set (no envelope)      — missing JSON in stdout
//	Set (bad JSON)         — malformed envelope
//	Set (bad data JSON)    — envelope OK but data unparseable
//	Set (invalid scope)    — unknown scope before PS call
//	Read (happy path)      — found=true, REG_SZ
//	Read (not found)       — found=false -> (nil, nil) — EC-4
//	Read (expand true)     — REG_EXPAND_SZ, expand=true
//	Read (permission)      — permission_denied
//	Read (transport)       — transport error
//	Read (no envelope)     — missing JSON
//	Read (bad data JSON)   — data unparseable
//	Read (invalid scope)   — unknown scope
//	Delete (happy path)    — variable deleted
//	Delete (key absent)    — key_not_found ok=true (EC-8)
//	Delete (idempotent)    — ok=true deleted=false still returns nil
//	Delete (permission)    — permission_denied
//	Delete (transport)     — transport error
//	Delete (invalid scope) — unknown scope
//	Script content         — psQuote embedding of name/value/scope
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

// newEVTestClient creates a *Client and *EnvVarClientImpl for tests.
func newEVTestClient(t *testing.T) (*Client, *EnvVarClientImpl) {
	t.Helper()
	c, err := New(Config{
		Host:     "winev01",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewEnvVarClient(c)
}

// stubEVRun replaces runEnvVarPowerShell for the duration of a test.
// Returns a restore closure that must be deferred.
func stubEVRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runEnvVarPowerShell
	runEnvVarPowerShell = fn
	return func() { runEnvVarPowerShell = prev }
}

// evOKEnvelope marshals an ok=true envelope to a newline-terminated JSON string.
func evOKEnvelope(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("evOKEnvelope marshal: %v", err)
	}
	return string(b) + "\n"
}

// evErrEnvelope marshals an ok=false envelope to a newline-terminated JSON string.
func evErrEnvelope(t *testing.T, kind, msg string, ctx map[string]string) string {
	t.Helper()
	if ctx == nil {
		ctx = map[string]string{}
	}
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": ctx,
	})
	if err != nil {
		t.Fatalf("evErrEnvelope marshal: %v", err)
	}
	return string(b) + "\n"
}

// setOKData returns a valid Set response payload.
func setOKData(value string, expand bool, broadcastWarn string) map[string]any {
	return map[string]any{
		"value":             value,
		"expand":            expand,
		"broadcast_warning": broadcastWarn,
	}
}

// readOKData returns a valid Read response payload (found=true).
func readOKData(value string, expand bool) map[string]any {
	return map[string]any{
		"found":  true,
		"value":  value,
		"expand": expand,
	}
}

// readNotFoundData returns a Read response payload with found=false.
func readNotFoundData() map[string]any {
	return map[string]any{
		"found":  false,
		"value":  "",
		"expand": false,
	}
}

// deleteOKData returns a valid Delete response payload.
func deleteOKData(deleted bool) map[string]any {
	return map[string]any{
		"deleted":           deleted,
		"broadcast_warning": "",
	}
}

// deleteKeyNotFoundData mimics the PS key_not_found path.
func deleteKeyNotFoundData() map[string]any {
	return map[string]any{
		"deleted":           false,
		"reason":            "key_not_found",
		"broadcast_warning": "",
	}
}

// evMin returns the smaller of two ints.
func evMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// registryPathForScope
// ---------------------------------------------------------------------------

func TestRegistryPathForScope_Machine(t *testing.T) {
	hive, subkey, err := registryPathForScope(EnvVarScopeMachine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hive != "LocalMachine" {
		t.Errorf("hive = %q, want LocalMachine", hive)
	}
	if !strings.Contains(subkey, "Session Manager") {
		t.Errorf("subkey missing 'Session Manager': %q", subkey)
	}
}

func TestRegistryPathForScope_User(t *testing.T) {
	hive, subkey, err := registryPathForScope(EnvVarScopeUser)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hive != "CurrentUser" {
		t.Errorf("hive = %q, want CurrentUser", hive)
	}
	if subkey != "Environment" {
		t.Errorf("subkey = %q, want Environment", subkey)
	}
}

func TestRegistryPathForScope_Invalid(t *testing.T) {
	_, _, err := registryPathForScope(EnvVarScope("bogus"))
	if err == nil {
		t.Fatal("expected error for unknown scope")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error message missing scope name: %v", err)
	}
}

// ---------------------------------------------------------------------------
// mapEnvVarErrorKind
// ---------------------------------------------------------------------------

func TestMapEnvVarErrorKind(t *testing.T) {
	cases := map[string]EnvVarErrorKind{
		"not_found":         EnvVarErrorNotFound,
		"permission_denied": EnvVarErrorPermission,
		"invalid_input":     EnvVarErrorInvalidInput,
		"unknown":           EnvVarErrorUnknown,
		"":                  EnvVarErrorUnknown,
		"totally_unknown":   EnvVarErrorUnknown,
	}
	for in, want := range cases {
		if got := mapEnvVarErrorKind(in); got != want {
			t.Errorf("mapEnvVarErrorKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// EnvVarError type coverage
// ---------------------------------------------------------------------------

func TestEnvVarError_ErrorWithCause(t *testing.T) {
	cause := errors.New("transport-fail")
	e := NewEnvVarError(EnvVarErrorPermission, "access denied", cause,
		map[string]string{"host": "winev01", "operation": "set"})
	if e.Unwrap() != cause {
		t.Error("Unwrap() must return underlying cause")
	}
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") {
		t.Errorf("Error() missing kind: %q", msg)
	}
	if !strings.Contains(msg, "access denied") {
		t.Errorf("Error() missing message: %q", msg)
	}
	if !strings.Contains(msg, "transport-fail") {
		t.Errorf("Error() missing cause: %q", msg)
	}
}

func TestEnvVarError_ErrorNoCause(t *testing.T) {
	e := NewEnvVarError(EnvVarErrorNotFound, "gone", nil, nil)
	msg := e.Error()
	if strings.Contains(msg, "<nil>") {
		t.Errorf("no-cause Error() leaks <nil>: %q", msg)
	}
	if !strings.Contains(msg, "not_found") {
		t.Errorf("missing kind in Error(): %q", msg)
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

func TestEnvVarError_Is(t *testing.T) {
	e := NewEnvVarError(EnvVarErrorPermission, "denied", nil, nil)
	if !errors.Is(e, ErrEnvVarPermission) {
		t.Error("errors.Is(ErrEnvVarPermission) must be true")
	}
	if errors.Is(e, ErrEnvVarNotFound) {
		t.Error("errors.Is across different kinds must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is() against a non-EnvVarError must return false")
	}
}

func TestEnvVarError_IsEnvVarError(t *testing.T) {
	e := NewEnvVarError(EnvVarErrorInvalidInput, "bad input", nil, nil)
	if !IsEnvVarError(e, EnvVarErrorInvalidInput) {
		t.Error("IsEnvVarError() must be true for matching kind")
	}
	if IsEnvVarError(e, EnvVarErrorNotFound) {
		t.Error("IsEnvVarError() with different kind must be false")
	}
	if IsEnvVarError(errors.New("plain"), EnvVarErrorInvalidInput) {
		t.Error("IsEnvVarError() on plain error must be false")
	}
}

func TestEnvVarError_Sentinels(t *testing.T) {
	pairs := []struct {
		s    *EnvVarError
		kind EnvVarErrorKind
	}{
		{ErrEnvVarNotFound, EnvVarErrorNotFound},
		{ErrEnvVarPermission, EnvVarErrorPermission},
		{ErrEnvVarInvalidInput, EnvVarErrorInvalidInput},
		{ErrEnvVarUnknown, EnvVarErrorUnknown},
	}
	for _, p := range pairs {
		if p.s.Kind != p.kind {
			t.Errorf("sentinel kind = %q, want %q", p.s.Kind, p.kind)
		}
	}
}

func TestEnvVarError_NilContext(t *testing.T) {
	e := NewEnvVarError(EnvVarErrorUnknown, "oops", nil, nil)
	if e.Context != nil {
		t.Error("nil ctx should result in nil Context")
	}
}

// ---------------------------------------------------------------------------
// Set — happy paths
// ---------------------------------------------------------------------------

func TestEnvVarSet_HappyPath_Machine_REG_SZ(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, setOKData("C:\\java", false, "")), "", nil
	})()
	_, ev := newEVTestClient(t)
	state, err := ev.Set(context.Background(), EnvVarInput{
		Scope:  EnvVarScopeMachine,
		Name:   "JAVA_HOME",
		Value:  "C:\\java",
		Expand: false,
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Value != "C:\\java" {
		t.Errorf("Value = %q, want C:\\java", state.Value)
	}
	if state.Expand {
		t.Error("Expand should be false for REG_SZ")
	}
	if state.Scope != EnvVarScopeMachine {
		t.Errorf("Scope = %q, want machine", state.Scope)
	}
	if state.Name != "JAVA_HOME" {
		t.Errorf("Name = %q, want JAVA_HOME", state.Name)
	}
	// Verify script contains PS single-quoted literals
	for _, want := range []string{"LocalMachine", "'JAVA_HOME'"} {
		if !strings.Contains(capturedScript, want) {
			t.Errorf("Set script missing %q", want)
		}
	}
	// expand=false → $false in script
	if !strings.Contains(capturedScript, "$false") {
		t.Errorf("expand=false should produce '$false' in script")
	}
}

func TestEnvVarSet_HappyPath_User_REG_EXPAND_SZ(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		if !strings.Contains(script, "CurrentUser") {
			t.Errorf("user scope should contain 'CurrentUser' in script")
		}
		if !strings.Contains(script, "$true") {
			t.Errorf("expand=true should produce '$true' in script")
		}
		return evOKEnvelope(t, setOKData("%SystemRoot%\\bin", true, "")), "", nil
	})()
	_, ev := newEVTestClient(t)
	state, err := ev.Set(context.Background(), EnvVarInput{
		Scope:  EnvVarScopeUser,
		Name:   "MY_PATH",
		Value:  "%SystemRoot%\\bin",
		Expand: true,
	})
	if err != nil {
		t.Fatalf("Set user REG_EXPAND_SZ: %v", err)
	}
	if !state.Expand {
		t.Error("Expand should be true for REG_EXPAND_SZ")
	}
	if state.Scope != EnvVarScopeUser {
		t.Errorf("Scope = %q, want user", state.Scope)
	}
}

func TestEnvVarSet_HappyPath_WithBroadcastWarning(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evOKEnvelope(t, setOKData("val", false, "SendMessageTimeout returned 0")), "", nil
	})()
	_, ev := newEVTestClient(t)
	state, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "X", Value: "val", Expand: false,
	})
	if err != nil {
		t.Fatalf("Set with broadcast warning: %v", err)
	}
	if state.BroadcastWarning == "" {
		t.Error("BroadcastWarning should be populated")
	}
}

func TestEnvVarSet_HappyPath_EmptyValue(t *testing.T) {
	// EC-12: empty value is valid
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		_ = script
		return evOKEnvelope(t, setOKData("", false, "")), "", nil
	})()
	_, ev := newEVTestClient(t)
	state, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeUser, Name: "EMPTY_VAR", Value: "", Expand: false,
	})
	if err != nil {
		t.Fatalf("Set empty value: %v", err)
	}
	if state.Value != "" {
		t.Errorf("Value = %q, want empty", state.Value)
	}
}

func TestEnvVarSet_HappyPath_NameWithSingleQuote(t *testing.T) {
	// Single quote in name should be escaped via psQuote (doubled)
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, setOKData("x", false, "")), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeUser, Name: "IT'S_VAR", Value: "x", Expand: false,
	})
	if err != nil {
		t.Fatalf("Set name with quote: %v", err)
	}
	// psQuote doubles the single quote
	if !strings.Contains(capturedScript, "IT''S_VAR") {
		t.Errorf("single quote in name should be doubled in script (first 300 chars): %q",
			capturedScript[:evMin(len(capturedScript), 300)])
	}
}

func TestEnvVarSet_HappyPath_ValueWithSingleQuote(t *testing.T) {
	// Single quote in value should be escaped via psQuote
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, setOKData("it's fine", false, "")), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeUser, Name: "VAR", Value: "it's fine", Expand: false,
	})
	if err != nil {
		t.Fatalf("Set value with quote: %v", err)
	}
	if !strings.Contains(capturedScript, "it''s fine") {
		t.Errorf("single quote in value should be doubled in script")
	}
}

// ---------------------------------------------------------------------------
// Set — error paths
// ---------------------------------------------------------------------------

func TestEnvVarSet_EC2_InvalidInput(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evErrEnvelope(t, "invalid_input",
			"Environment registry key not found for scope machine", nil), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected invalid_input error (EC-2)")
	}
	if !IsEnvVarError(err, EnvVarErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

func TestEnvVarSet_PermissionDenied(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evErrEnvelope(t, "permission_denied", "access denied", nil), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !IsEnvVarError(err, EnvVarErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestEnvVarSet_TransportError(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "connection refused", fmt.Errorf("transport error")
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsEnvVarError(err, EnvVarErrorUnknown) {
		t.Errorf("transport error should be unknown kind, got: %v", err)
	}
}

func TestEnvVarSet_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", fmt.Errorf("cancelled")
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(ctx, EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	var eve *EnvVarError
	if !errors.As(err, &eve) {
		t.Fatalf("expected *EnvVarError, got %T: %v", err, err)
	}
	if eve.Cause == nil {
		t.Error("expected non-nil cause for context cancellation")
	}
}

func TestEnvVarSet_MissingEnvelope(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "Warning: PS warning output\nno json here\n", "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected error for missing JSON envelope")
	}
	if !IsEnvVarError(err, EnvVarErrorUnknown) {
		t.Errorf("missing envelope should be unknown kind, got: %v", err)
	}
}

func TestEnvVarSet_MalformedJSON(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{malformed json}\n", "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestEnvVarSet_UnparsableDataField(t *testing.T) {
	// ok=true but data field is a string instead of an object -> unmarshal into evSetData will fail
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		b, _ := json.Marshal(map[string]any{"ok": true, "data": "not-an-object"})
		return string(b) + "\n", "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected error when data field cannot be parsed as evSetData")
	}
}

func TestEnvVarSet_InvalidScope(t *testing.T) {
	// No PS call needed — error returned before script execution
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScope("invalid"), Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
	if !IsEnvVarError(err, EnvVarErrorInvalidInput) {
		t.Errorf("invalid scope should produce invalid_input, got: %v", err)
	}
}

func TestEnvVarSet_UnknownPSError(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evErrEnvelope(t, "unknown", "something failed", nil), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "x", Expand: false,
	})
	if err == nil {
		t.Fatal("expected error for unknown PS error")
	}
	if !IsEnvVarError(err, EnvVarErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read — happy paths
// ---------------------------------------------------------------------------

func TestEnvVarRead_HappyPath_REG_SZ(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evOKEnvelope(t, readOKData("hello", false)), "", nil
	})()
	_, ev := newEVTestClient(t)
	state, err := ev.Read(context.Background(), EnvVarScopeMachine, "JAVA_HOME")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Value != "hello" {
		t.Errorf("Value = %q, want hello", state.Value)
	}
	if state.Expand {
		t.Error("Expand should be false for REG_SZ")
	}
	if state.Scope != EnvVarScopeMachine {
		t.Errorf("Scope = %q, want machine", state.Scope)
	}
	if state.Name != "JAVA_HOME" {
		t.Errorf("Name = %q, want JAVA_HOME", state.Name)
	}
}

func TestEnvVarRead_HappyPath_REG_EXPAND_SZ(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evOKEnvelope(t, readOKData("%SystemRoot%\\bin", true)), "", nil
	})()
	_, ev := newEVTestClient(t)
	state, err := ev.Read(context.Background(), EnvVarScopeUser, "MY_PATH")
	if err != nil {
		t.Fatalf("Read REG_EXPAND_SZ: %v", err)
	}
	if !state.Expand {
		t.Error("Expand should be true for REG_EXPAND_SZ")
	}
	// ADR-EV-5: value must be verbatim (unexpanded)
	if state.Value != "%SystemRoot%\\bin" {
		t.Errorf("Value = %q, want verbatim %%SystemRoot%%\\bin (ADR-EV-5)", state.Value)
	}
}

// EC-4: Read returns (nil, nil) when found=false
func TestEnvVarRead_EC4_NotFound_FoundFalse(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evOKEnvelope(t, readNotFoundData()), "", nil
	})()
	_, ev := newEVTestClient(t)
	state, err := ev.Read(context.Background(), EnvVarScopeMachine, "MISSING_VAR")
	if err != nil {
		t.Fatalf("Read not_found: %v", err)
	}
	if state != nil {
		t.Error("not_found (found=false) must return nil state (EC-4)")
	}
}

// Verify the script contains expected PS literals for Read
func TestEnvVarRead_ScriptContainsExpectedLiterals(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, readOKData("v", false)), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, _ = ev.Read(context.Background(), EnvVarScopeUser, "MY_VAR")
	if !strings.Contains(capturedScript, "CurrentUser") {
		t.Errorf("user scope read script should contain 'CurrentUser'")
	}
	if !strings.Contains(capturedScript, "'MY_VAR'") {
		t.Errorf("read script should contain psQuote'd name 'MY_VAR'")
	}
}

// ---------------------------------------------------------------------------
// Read — error paths
// ---------------------------------------------------------------------------

func TestEnvVarRead_PermissionDenied(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evErrEnvelope(t, "permission_denied", "access denied", nil), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Read(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !IsEnvVarError(err, EnvVarErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestEnvVarRead_TransportError(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", fmt.Errorf("connection refused")
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Read(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsEnvVarError(err, EnvVarErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

func TestEnvVarRead_MissingEnvelope(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "no json here\n", "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Read(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected error for missing JSON envelope")
	}
}

func TestEnvVarRead_UnparsableDataField(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		b, _ := json.Marshal(map[string]any{"ok": true, "data": "not-an-object"})
		return string(b) + "\n", "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Read(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected error when data field cannot be parsed as evReadData")
	}
}

func TestEnvVarRead_InvalidScope(t *testing.T) {
	_, ev := newEVTestClient(t)
	_, err := ev.Read(context.Background(), EnvVarScope("nope"), "V")
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
	if !IsEnvVarError(err, EnvVarErrorInvalidInput) {
		t.Errorf("invalid scope should produce invalid_input, got: %v", err)
	}
}

func TestEnvVarRead_UnknownPS(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evErrEnvelope(t, "unknown", "Unexpected registry value kind: DWORD", map[string]string{
			"actual_kind": "DWord",
		}), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Read(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected error for unknown PS error")
	}
	if !IsEnvVarError(err, EnvVarErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

func TestEnvVarRead_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", fmt.Errorf("cancelled")
	})()
	_, ev := newEVTestClient(t)
	_, err := ev.Read(ctx, EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	var eve *EnvVarError
	if !errors.As(err, &eve) {
		t.Fatalf("expected *EnvVarError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Delete — happy paths
// ---------------------------------------------------------------------------

func TestEnvVarDelete_HappyPath(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, deleteOKData(true)), "", nil
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeMachine, "JAVA_HOME")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !strings.Contains(capturedScript, "'JAVA_HOME'") {
		t.Errorf("delete script should contain psQuote'd name 'JAVA_HOME'")
	}
	if !strings.Contains(capturedScript, "LocalMachine") {
		t.Errorf("delete script should contain 'LocalMachine' for machine scope")
	}
}

// EC-8: Delete is idempotent — ok=true but deleted=false (variable was absent)
func TestEnvVarDelete_EC8_Idempotent_VariableMissing(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evOKEnvelope(t, deleteOKData(false)), "", nil
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeMachine, "MISSING")
	if err != nil {
		t.Fatalf("EC-8: idempotent delete (deleted=false) should return nil, got: %v", err)
	}
}

// EC-8: Delete is idempotent — key_not_found case (ok=true)
func TestEnvVarDelete_EC8_KeyNotFound(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evOKEnvelope(t, deleteKeyNotFoundData()), "", nil
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeMachine, "V")
	if err != nil {
		t.Fatalf("EC-8: key_not_found delete should return nil, got: %v", err)
	}
}

func TestEnvVarDelete_UserScope(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, deleteOKData(true)), "", nil
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeUser, "MY_VAR")
	if err != nil {
		t.Fatalf("Delete user scope: %v", err)
	}
	if !strings.Contains(capturedScript, "CurrentUser") {
		t.Errorf("delete script should contain 'CurrentUser' for user scope")
	}
}

// ---------------------------------------------------------------------------
// Delete — error paths
// ---------------------------------------------------------------------------

func TestEnvVarDelete_PermissionDenied(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evErrEnvelope(t, "permission_denied", "access denied", nil), "", nil
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !IsEnvVarError(err, EnvVarErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestEnvVarDelete_TransportError(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", fmt.Errorf("connection refused")
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsEnvVarError(err, EnvVarErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

func TestEnvVarDelete_InvalidScope(t *testing.T) {
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScope("bad"), "V")
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
	if !IsEnvVarError(err, EnvVarErrorInvalidInput) {
		t.Errorf("invalid scope should produce invalid_input, got: %v", err)
	}
}

func TestEnvVarDelete_MissingEnvelope(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "no json here\n", "", nil
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected error for missing JSON envelope")
	}
}

func TestEnvVarDelete_UnknownPS(t *testing.T) {
	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return evErrEnvelope(t, "unknown", "something went wrong", nil), "", nil
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(context.Background(), EnvVarScopeUser, "V")
	if err == nil {
		t.Fatal("expected error for unknown PS error")
	}
	if !IsEnvVarError(err, EnvVarErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

func TestEnvVarDelete_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer stubEVRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", fmt.Errorf("cancelled")
	})()
	_, ev := newEVTestClient(t)
	err := ev.Delete(ctx, EnvVarScopeMachine, "V")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	var eve *EnvVarError
	if !errors.As(err, &eve) {
		t.Fatalf("expected *EnvVarError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Script content verification
// ---------------------------------------------------------------------------

func TestEnvVarSet_ScriptContainsScope_Machine(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, setOKData("v", false, "")), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, _ = ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeMachine, Name: "V", Value: "v", Expand: false,
	})
	if !strings.Contains(capturedScript, "LocalMachine") {
		t.Errorf("machine scope script should contain 'LocalMachine'")
	}
	if !strings.Contains(capturedScript, "Session Manager") {
		t.Errorf("machine scope script should contain 'Session Manager'")
	}
}

func TestEnvVarSet_ScriptContainsScope_User(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, setOKData("v", false, "")), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, _ = ev.Set(context.Background(), EnvVarInput{
		Scope: EnvVarScopeUser, Name: "V", Value: "v", Expand: false,
	})
	if !strings.Contains(capturedScript, "CurrentUser") {
		t.Errorf("user scope script should contain 'CurrentUser'")
	}
}

func TestEnvVarRead_ScriptContainsScope_Machine(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, readOKData("v", false)), "", nil
	})()
	_, ev := newEVTestClient(t)
	_, _ = ev.Read(context.Background(), EnvVarScopeMachine, "V")
	if !strings.Contains(capturedScript, "LocalMachine") {
		t.Errorf("machine scope read script should contain 'LocalMachine'")
	}
}

func TestEnvVarDelete_ScriptContainsValueLiterals(t *testing.T) {
	var capturedScript string
	defer stubEVRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		capturedScript = script
		return evOKEnvelope(t, deleteOKData(true)), "", nil
	})()
	_, ev := newEVTestClient(t)
	_ = ev.Delete(context.Background(), EnvVarScopeUser, "MY_TOKEN")
	for _, want := range []string{"CurrentUser", "'MY_TOKEN'"} {
		if !strings.Contains(capturedScript, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// NewEnvVarClient constructor
// ---------------------------------------------------------------------------

func TestNewEnvVarClient_NotNil(t *testing.T) {
	_, ev := newEVTestClient(t)
	if ev == nil {
		t.Fatal("NewEnvVarClient must not return nil")
	}
}
