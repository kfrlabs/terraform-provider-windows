// Package winclient — unit tests for RegistryValueClientImpl.
//
// Tests stub the package-level runRegistryValuePowerShell hook so no real
// SSH connection is required. Edge cases covered:
//
//	EC-3  Type conflict detection (type_conflict response from PS)
//	EC-4  Read: value not found → (nil, nil) — not an error
//	EC-12 Delete: idempotent — not_found silently treated as success
//	buildRVSetStdin: all 7 types, overflow rejection, nil-value errors
//	Set stdin transport: secrets travel as JSON on stdin, never in the script
//	parseMultiStringPayload: JSON array, PS single-element quirk, null, malformed
//	parseDataPayload: all 7 value kinds + found=false + malformed JSON
//	runScript: context cancellation, transport error, missing envelope, bad JSON
//	RegistryValueError: Error(), Unwrap(), Is(), sentinels, IsRegistryValueError()
//	mapRegistryValueErrorKind: all branches including unknown fallback
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

// newRVTestClient creates a *RegistryValueClientImpl for tests.
func newRVTestClient(t *testing.T) *RegistryValueClientImpl {
	t.Helper()
	c, err := New(Config{
		Host:                  "winrv01",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewRegistryValueClient(c)
}

// stubRVRun replaces runRegistryValuePowerShell for the duration of a test.
// Returns a restore closure that must be deferred.
func stubRVRun(fn func(ctx context.Context, c *Client, script, stdin string) (string, string, error)) func() {
	prev := runRegistryValuePowerShell
	runRegistryValuePowerShell = fn
	return func() { runRegistryValuePowerShell = prev }
}

// rvOKEnvelope marshals an ok=true envelope to a newline-terminated JSON string.
func rvOKEnvelope(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("rvOKEnvelope marshal: %v", err)
	}
	return string(b) + "\n"
}

// rvErrEnvelope marshals an ok=false envelope to a newline-terminated JSON string.
func rvErrEnvelope(t *testing.T, kind, msg string, ctx map[string]string) string {
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
		t.Fatalf("rvErrEnvelope marshal: %v", err)
	}
	return string(b) + "\n"
}

// rvFoundData returns a PS Set/Read data payload for string-type values.
func rvFoundData(kind, valueString string) map[string]any {
	return map[string]any{
		"found":         true,
		"kind":          kind,
		"value_string":  valueString,
		"value_strings": nil,
		"value_binary":  nil,
	}
}

// rvFoundBinary returns a PS Set/Read data payload for binary/none values.
func rvFoundBinary(kind, hexVal string) map[string]any {
	return map[string]any{
		"found":         true,
		"kind":          kind,
		"value_string":  nil,
		"value_strings": nil,
		"value_binary":  hexVal,
	}
}

// rvFoundMulti returns a PS Set/Read data payload for multi-string values.
func rvFoundMulti(strs []string) map[string]any {
	return map[string]any{
		"found":         true,
		"kind":          "REG_MULTI_SZ",
		"value_string":  nil,
		"value_strings": strs,
		"value_binary":  nil,
	}
}

// rvPtr is a helper to take the address of a string.
func rvPtr(s string) *string { return &s }

// rvMax returns the larger of two ints.
func rvMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// RegistryValueError type coverage
// ---------------------------------------------------------------------------

func TestRegistryValueError_ErrorWithCause(t *testing.T) {
	cause := errors.New("transport-fail")
	e := NewRegistryValueError(RegistryValueErrorPermission, "access denied", cause,
		map[string]string{"host": "winrv01", "operation": "set"})
	if !errors.Is(e, cause) {
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

func TestRegistryValueError_ErrorNoCause(t *testing.T) {
	e := NewRegistryValueError(RegistryValueErrorNotFound, "gone", nil, nil)
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

func TestRegistryValueError_Is(t *testing.T) {
	e := NewRegistryValueError(RegistryValueErrorTypeConflict, "conflict", nil, nil)
	if !errors.Is(e, ErrRegistryValueTypeConflict) {
		t.Error("errors.Is(ErrRegistryValueTypeConflict) must be true")
	}
	if errors.Is(e, ErrRegistryValueNotFound) {
		t.Error("errors.Is across different kinds must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is() against a non-RegistryValueError must return false")
	}
}

func TestRegistryValueError_IsRegistryValueError(t *testing.T) {
	e := NewRegistryValueError(RegistryValueErrorTypeConflict, "conflict", nil, nil)
	if !IsRegistryValueError(e, RegistryValueErrorTypeConflict) {
		t.Error("IsRegistryValueError() must be true for matching kind")
	}
	if IsRegistryValueError(e, RegistryValueErrorNotFound) {
		t.Error("IsRegistryValueError() with different kind must be false")
	}
	if IsRegistryValueError(errors.New("plain"), RegistryValueErrorTypeConflict) {
		t.Error("IsRegistryValueError() on plain error must be false")
	}
}

func TestRegistryValueError_Sentinels(t *testing.T) {
	pairs := []struct {
		s    *RegistryValueError
		kind RegistryValueErrorKind
	}{
		{ErrRegistryValueNotFound, RegistryValueErrorNotFound},
		{ErrRegistryValueTypeConflict, RegistryValueErrorTypeConflict},
		{ErrRegistryValuePermission, RegistryValueErrorPermission},
		{ErrRegistryValueInvalidInput, RegistryValueErrorInvalidInput},
		{ErrRegistryValueUnknown, RegistryValueErrorUnknown},
	}
	for _, p := range pairs {
		if p.s.Kind != string(p.kind) {
			t.Errorf("sentinel kind = %q, want %q", p.s.Kind, p.kind)
		}
	}
}

// ---------------------------------------------------------------------------
// mapRegistryValueErrorKind — all branches
// ---------------------------------------------------------------------------

func TestMapRegistryValueErrorKind(t *testing.T) {
	cases := map[string]RegistryValueErrorKind{
		"not_found":         RegistryValueErrorNotFound,
		"type_conflict":     RegistryValueErrorTypeConflict,
		"permission_denied": RegistryValueErrorPermission,
		"invalid_input":     RegistryValueErrorInvalidInput,
		"unknown":           RegistryValueErrorUnknown,
		"":                  RegistryValueErrorUnknown,
		"totally_unknown":   RegistryValueErrorUnknown,
	}
	for in, want := range cases {
		if got := mapRegistryValueErrorKind(in); got != want {
			t.Errorf("mapRegistryValueErrorKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// buildRVSetStdin — all 7 types + edge cases
//
// The secret value payload travels as JSON on stdin, never in the script
// body. These tests pin the payload shape and the Go-side validation
// (DWORD/QWORD range checks, nil-value errors, unknown kinds).
// ---------------------------------------------------------------------------

// rvStdinPayload decodes the stdin JSON document produced by buildRVSetStdin.
func rvStdinPayload(t *testing.T, raw string) rvSetStdin {
	t.Helper()
	var p rvSetStdin
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("stdin is not valid JSON: %v\nraw: %s", err, raw)
	}
	return p
}

func TestBuildRVSetStdin_REG_SZ(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindString,
		ValueString: rvPtr("hello world"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueString; got == nil || *got != "hello world" {
		t.Errorf("value_string = %v, want %q", got, "hello world")
	}
}

func TestBuildRVSetStdin_REG_SZ_SingleQuotePreserved(t *testing.T) {
	// No PS quoting happens Go-side any more: the raw value must round-trip
	// byte-for-byte through the JSON payload.
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindString,
		ValueString: rvPtr("it's a test"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueString; got == nil || *got != "it's a test" {
		t.Errorf("value_string = %v, want single quotes preserved verbatim", got)
	}
}

func TestBuildRVSetStdin_REG_SZ_NilValueString(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindString,
		ValueString: nil,
	})
	if err == nil {
		t.Error("expected error for nil ValueString with REG_SZ")
	}
	if !IsRegistryValueError(err, RegistryValueErrorInvalidInput) {
		t.Errorf("expected invalid_input error, got: %v", err)
	}
}

func TestBuildRVSetStdin_REG_EXPAND_SZ(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindExpandString,
		ValueString: rvPtr(`%SystemRoot%\system32`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueString; got == nil || *got != `%SystemRoot%\system32` {
		t.Errorf("value_string = %v, want the raw expand string", got)
	}
}

func TestBuildRVSetStdin_REG_EXPAND_SZ_NilValueString(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindExpandString,
		ValueString: nil,
	})
	if err == nil {
		t.Error("expected error for nil ValueString with REG_EXPAND_SZ")
	}
	if !IsRegistryValueError(err, RegistryValueErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

func TestBuildRVSetStdin_REG_DWORD_Valid(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindDWord,
		ValueString: rvPtr("4294967295"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueString; got == nil || *got != "4294967295" {
		t.Errorf("value_string = %v, want %q", got, "4294967295")
	}
}

func TestBuildRVSetStdin_REG_DWORD_Zero(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindDWord,
		ValueString: rvPtr("0"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueString; got == nil || *got != "0" {
		t.Errorf("value_string = %v, want %q", got, "0")
	}
}

func TestBuildRVSetStdin_REG_DWORD_Overflow(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindDWord,
		ValueString: rvPtr("4294967296"), // exceeds uint32 max
	})
	if err == nil {
		t.Error("expected error for DWORD overflow")
	}
	if !IsRegistryValueError(err, RegistryValueErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

func TestBuildRVSetStdin_REG_DWORD_NilValueString(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{Kind: RegistryValueKindDWord})
	if err == nil {
		t.Error("expected error for nil ValueString with REG_DWORD")
	}
}

func TestBuildRVSetStdin_REG_DWORD_NonNumeric(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindDWord,
		ValueString: rvPtr("not-a-number"),
	})
	if err == nil {
		t.Error("expected error for non-numeric DWORD value")
	}
}

func TestBuildRVSetStdin_REG_QWORD_Valid(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindQWord,
		ValueString: rvPtr("18446744073709551615"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueString; got == nil || *got != "18446744073709551615" {
		t.Errorf("value_string = %v, want uint64 max", got)
	}
}

func TestBuildRVSetStdin_REG_QWORD_Overflow(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindQWord,
		ValueString: rvPtr("18446744073709551616"), // exceeds uint64 max
	})
	if err == nil {
		t.Error("expected error for QWORD overflow")
	}
	if !IsRegistryValueError(err, RegistryValueErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

func TestBuildRVSetStdin_REG_QWORD_NilValueString(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{Kind: RegistryValueKindQWord})
	if err == nil {
		t.Error("expected error for nil ValueString with REG_QWORD")
	}
}

func TestBuildRVSetStdin_REG_MULTI_SZ_MultipleItems(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:         RegistryValueKindMultiString,
		ValueStrings: []string{"line1", "line2", "line3"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := rvStdinPayload(t, raw).ValueStrings
	if len(got) != 3 || got[0] != "line1" || got[1] != "line2" || got[2] != "line3" {
		t.Errorf("value_strings = %v, want the three items verbatim", got)
	}
}

func TestBuildRVSetStdin_REG_MULTI_SZ_Empty(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:         RegistryValueKindMultiString,
		ValueStrings: []string{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueStrings; len(got) != 0 {
		t.Errorf("value_strings = %v, want empty", got)
	}
}

func TestBuildRVSetStdin_REG_MULTI_SZ_Nil(t *testing.T) {
	// nil slice treated as empty
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:         RegistryValueKindMultiString,
		ValueStrings: nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueStrings; len(got) != 0 {
		t.Errorf("value_strings = %v, want empty", got)
	}
}

func TestBuildRVSetStdin_REG_BINARY_Valid(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindBinary,
		ValueBinary: rvPtr("deadbeef"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueBinary; got == nil || *got != "deadbeef" {
		t.Errorf("value_binary = %v, want %q", got, "deadbeef")
	}
}

func TestBuildRVSetStdin_REG_BINARY_Empty(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindBinary,
		ValueBinary: rvPtr(""),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueBinary; got == nil || *got != "" {
		t.Errorf("value_binary = %v, want empty (zero-length byte array)", got)
	}
}

func TestBuildRVSetStdin_REG_NONE_NilBinary(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindNone,
		ValueBinary: nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueBinary; got == nil || *got != "" {
		t.Errorf("value_binary = %v, want empty (zero-length byte array)", got)
	}
}

func TestBuildRVSetStdin_REG_NONE_WithBinary(t *testing.T) {
	raw, err := buildRVSetStdin(RegistryValueInput{
		Kind:        RegistryValueKindNone,
		ValueBinary: rvPtr("0102"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rvStdinPayload(t, raw).ValueBinary; got == nil || *got != "0102" {
		t.Errorf("value_binary = %v, want %q", got, "0102")
	}
}

func TestBuildRVSetStdin_UnknownKind(t *testing.T) {
	_, err := buildRVSetStdin(RegistryValueInput{Kind: RegistryValueKind("REG_BOGUS")})
	if err == nil {
		t.Error("expected error for unknown kind")
	}
	if !IsRegistryValueError(err, RegistryValueErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseMultiStringPayload — all branches
// ---------------------------------------------------------------------------

func TestParseMultiStringPayload_Null(t *testing.T) {
	strs, err := parseMultiStringPayload(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 0 {
		t.Errorf("expected empty slice, got %v", strs)
	}
}

func TestParseMultiStringPayload_NullJSON(t *testing.T) {
	strs, err := parseMultiStringPayload(json.RawMessage("null"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 0 {
		t.Errorf("expected empty slice for 'null', got %v", strs)
	}
}

func TestParseMultiStringPayload_EmptyArray(t *testing.T) {
	strs, err := parseMultiStringPayload(json.RawMessage("[]"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 0 {
		t.Errorf("expected empty slice, got %v", strs)
	}
}

func TestParseMultiStringPayload_MultipleItems(t *testing.T) {
	strs, err := parseMultiStringPayload(json.RawMessage(`["alpha","beta","gamma"]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 3 || strs[0] != "alpha" || strs[1] != "beta" || strs[2] != "gamma" {
		t.Errorf("unexpected values: %v", strs)
	}
}

func TestParseMultiStringPayload_SingleItemArray(t *testing.T) {
	strs, err := parseMultiStringPayload(json.RawMessage(`["only"]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 1 || strs[0] != "only" {
		t.Errorf(`expected ["only"], got %v`, strs)
	}
}

func TestParseMultiStringPayload_PSScalarQuirk(t *testing.T) {
	// PowerShell ConvertTo-Json quirk: single-element [string[]] → JSON scalar string
	strs, err := parseMultiStringPayload(json.RawMessage(`"single-line"`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strs) != 1 || strs[0] != "single-line" {
		t.Errorf(`expected ["single-line"], got %v`, strs)
	}
}

func TestParseMultiStringPayload_Malformed(t *testing.T) {
	_, err := parseMultiStringPayload(json.RawMessage(`{not-valid}`))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

// ---------------------------------------------------------------------------
// parseDataPayload — all 7 kinds + found=false + null/malformed
// ---------------------------------------------------------------------------

func TestParseDataPayload_NotFound(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(map[string]any{"found": false})
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\MyApp`, "Version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != nil {
		t.Error("not_found must return nil state")
	}
}

func TestParseDataPayload_NullRaw(t *testing.T) {
	rv := newRVTestClient(t)
	state, err := rv.parseDataPayload(nil, "HKLM", `SOFTWARE\MyApp`, "Version")
	if err != nil {
		t.Fatalf("unexpected error for nil raw: %v", err)
	}
	if state != nil {
		t.Error("null raw must return nil state")
	}
}

func TestParseDataPayload_REG_SZ(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundData("REG_SZ", "hello"))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\MyApp`, "Version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Kind != RegistryValueKindString {
		t.Errorf("Kind = %q, want REG_SZ", state.Kind)
	}
	if state.ValueString == nil || *state.ValueString != "hello" {
		t.Errorf("ValueString = %v", state.ValueString)
	}
	if state.Hive != "HKLM" || state.Path != `SOFTWARE\MyApp` || state.Name != "Version" {
		t.Errorf("identity fields wrong: hive=%q path=%q name=%q", state.Hive, state.Path, state.Name)
	}
}

func TestParseDataPayload_REG_EXPAND_SZ(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundData("REG_EXPAND_SZ", `%SystemRoot%\system32`))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "Path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Kind != RegistryValueKindExpandString {
		t.Errorf("Kind = %q", state.Kind)
	}
	if state.ValueString == nil || !strings.Contains(*state.ValueString, "SystemRoot") {
		t.Errorf("ValueString = %v", state.ValueString)
	}
}

func TestParseDataPayload_REG_DWORD(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundData("REG_DWORD", "12345"))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "Count")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Kind != RegistryValueKindDWord {
		t.Errorf("Kind = %q", state.Kind)
	}
	if state.ValueString == nil || *state.ValueString != "12345" {
		t.Errorf("ValueString = %v", state.ValueString)
	}
}

func TestParseDataPayload_REG_QWORD(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundData("REG_QWORD", "9876543210987654321"))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "Big")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Kind != RegistryValueKindQWord {
		t.Errorf("Kind = %q", state.Kind)
	}
	if state.ValueString == nil || *state.ValueString != "9876543210987654321" {
		t.Errorf("ValueString = %v", state.ValueString)
	}
}

func TestParseDataPayload_REG_MULTI_SZ(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundMulti([]string{"a", "b", "c"}))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "Multi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Kind != RegistryValueKindMultiString {
		t.Errorf("Kind = %q", state.Kind)
	}
	if len(state.ValueStrings) != 3 {
		t.Errorf("ValueStrings len = %d, want 3", len(state.ValueStrings))
	}
}

func TestParseDataPayload_REG_MULTI_SZ_Empty(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundMulti([]string{}))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "Empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(state.ValueStrings) != 0 {
		t.Errorf("ValueStrings should be empty, got %v", state.ValueStrings)
	}
}

func TestParseDataPayload_REG_MULTI_SZ_PSScalarQuirk(t *testing.T) {
	// PS serialises single-element [string[]] as a JSON scalar string
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(map[string]any{
		"found":         true,
		"kind":          "REG_MULTI_SZ",
		"value_string":  nil,
		"value_strings": "single-entry",
		"value_binary":  nil,
	})
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "MS")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(state.ValueStrings) != 1 || state.ValueStrings[0] != "single-entry" {
		t.Errorf("ValueStrings = %v", state.ValueStrings)
	}
}

func TestParseDataPayload_REG_BINARY(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundBinary("REG_BINARY", "deadbeef"))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "Bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Kind != RegistryValueKindBinary {
		t.Errorf("Kind = %q", state.Kind)
	}
	if state.ValueBinary == nil || *state.ValueBinary != "deadbeef" {
		t.Errorf("ValueBinary = %v", state.ValueBinary)
	}
}

func TestParseDataPayload_REG_NONE(t *testing.T) {
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(rvFoundBinary("REG_NONE", ""))
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "None")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Kind != RegistryValueKindNone {
		t.Errorf("Kind = %q", state.Kind)
	}
	if state.ValueBinary == nil || *state.ValueBinary != "" {
		t.Errorf("ValueBinary = %v", state.ValueBinary)
	}
}

func TestParseDataPayload_REG_NONE_NilValueBinary(t *testing.T) {
	// PS returns null for value_binary when REG_NONE has no data
	rv := newRVTestClient(t)
	raw, _ := json.Marshal(map[string]any{
		"found":         true,
		"kind":          "REG_NONE",
		"value_string":  nil,
		"value_strings": nil,
		"value_binary":  nil,
	})
	state, err := rv.parseDataPayload(json.RawMessage(raw), "HKLM", `SOFTWARE\Test`, "N")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ValueBinary == nil {
		t.Error("ValueBinary should be non-nil (empty string) when PS returns null")
	}
}

func TestParseDataPayload_Malformed(t *testing.T) {
	rv := newRVTestClient(t)
	_, err := rv.parseDataPayload(json.RawMessage(`{bad-json}`), "HKLM", `SOFTWARE\Test`, "V")
	if err == nil {
		t.Error("expected error for malformed JSON payload")
	}
}

// ---------------------------------------------------------------------------
// Set — happy path + error paths
// ---------------------------------------------------------------------------

func TestRegistryValueSet_HappyPath_REG_SZ(t *testing.T) {
	var capturedScript, capturedStdin string
	defer stubRVRun(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		capturedScript, capturedStdin = script, stdin
		return rvOKEnvelope(t, rvFoundData("REG_SZ", "1.0.0")), "", nil
	})()

	rv := newRVTestClient(t)
	state, err := rv.Set(context.Background(), RegistryValueInput{
		Hive:        "HKLM",
		Path:        `SOFTWARE\MyApp`,
		Name:        "Version",
		Kind:        RegistryValueKindString,
		ValueString: rvPtr("1.0.0"),
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Kind != RegistryValueKindString {
		t.Errorf("Kind = %q", state.Kind)
	}
	if state.ValueString == nil || *state.ValueString != "1.0.0" {
		t.Errorf("ValueString = %v", state.ValueString)
	}
	// Non-secret addressing (hive/path/name/kind) stays in the script body.
	for _, want := range []string{"'HKLM'", `'SOFTWARE\MyApp'`, "'Version'", "'REG_SZ'"} {
		if !strings.Contains(capturedScript, want) {
			t.Errorf("Set script missing %q", want)
		}
	}
	// The secret value travels on stdin, never in the script body.
	if strings.Contains(capturedScript, "1.0.0") {
		t.Error("Set script must not embed the secret value_string; it travels on stdin")
	}
	if got := rvStdinPayload(t, capturedStdin).ValueString; got == nil || *got != "1.0.0" {
		t.Errorf("stdin value_string = %v, want %q", got, "1.0.0")
	}
	if !strings.Contains(capturedScript, "[Console]::In.ReadToEnd()") {
		t.Error("Set script should decode its stdin payload with ReadToEnd")
	}
}

// TestRegistryValueSet_SecretsTravelOnStdinOnly pins the fail-closed
// invariant for every kind: the secret value must appear in the stdin JSON
// payload and nowhere in the script body.
func TestRegistryValueSet_SecretsTravelOnStdinOnly(t *testing.T) {
	qwordMax := "18446744073709551615"
	binaryHex := "deadbeef0102"
	empty := ""
	special := "it's a $ecret with `backtick` and 'quotes'"
	cases := []struct {
		name       string
		input      RegistryValueInput
		secret     string
		checkStdin func(t *testing.T, p rvSetStdin)
	}{
		{
			name:   "REG_SZ",
			input:  RegistryValueInput{Kind: RegistryValueKindString, ValueString: rvPtr("s3cr3t-sz-value")},
			secret: "s3cr3t-sz-value",
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueString == nil || *p.ValueString != "s3cr3t-sz-value" {
					t.Errorf("stdin value_string = %v", p.ValueString)
				}
			},
		},
		{
			name:   "REG_EXPAND_SZ",
			input:  RegistryValueInput{Kind: RegistryValueKindExpandString, ValueString: rvPtr("s3cr3t-expand-%PATH%")},
			secret: "s3cr3t-expand-%PATH%",
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueString == nil || *p.ValueString != "s3cr3t-expand-%PATH%" {
					t.Errorf("stdin value_string = %v", p.ValueString)
				}
			},
		},
		{
			name:   "REG_MULTI_SZ",
			input:  RegistryValueInput{Kind: RegistryValueKindMultiString, ValueStrings: []string{"s3cr3t-multi-a", "s3cr3t-multi-b"}},
			secret: "s3cr3t-multi-a",
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if len(p.ValueStrings) != 2 || p.ValueStrings[0] != "s3cr3t-multi-a" || p.ValueStrings[1] != "s3cr3t-multi-b" {
					t.Errorf("stdin value_strings = %v", p.ValueStrings)
				}
			},
		},
		{
			name:   "REG_DWORD",
			input:  RegistryValueInput{Kind: RegistryValueKindDWord, ValueString: rvPtr("4294967295")},
			secret: "4294967295",
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueString == nil || *p.ValueString != "4294967295" {
					t.Errorf("stdin value_string = %v", p.ValueString)
				}
			},
		},
		{
			name:   "REG_QWORD max",
			input:  RegistryValueInput{Kind: RegistryValueKindQWord, ValueString: rvPtr(qwordMax)},
			secret: qwordMax,
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueString == nil || *p.ValueString != qwordMax {
					t.Errorf("stdin value_string = %v", p.ValueString)
				}
			},
		},
		{
			name:   "REG_BINARY",
			input:  RegistryValueInput{Kind: RegistryValueKindBinary, ValueBinary: rvPtr(binaryHex)},
			secret: binaryHex,
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueBinary == nil || *p.ValueBinary != binaryHex {
					t.Errorf("stdin value_binary = %v", p.ValueBinary)
				}
			},
		},
		{
			name:   "REG_NONE with binary",
			input:  RegistryValueInput{Kind: RegistryValueKindNone, ValueBinary: rvPtr(binaryHex)},
			secret: binaryHex,
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueBinary == nil || *p.ValueBinary != binaryHex {
					t.Errorf("stdin value_binary = %v", p.ValueBinary)
				}
			},
		},
		{
			name:   "REG_BINARY empty",
			input:  RegistryValueInput{Kind: RegistryValueKindBinary, ValueBinary: rvPtr("")},
			secret: `"value_binary":""`,
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueBinary == nil || *p.ValueBinary != "" {
					t.Errorf("stdin value_binary = %v, want empty", p.ValueBinary)
				}
			},
		},
		{
			name:   "empty string",
			input:  RegistryValueInput{Kind: RegistryValueKindString, ValueString: &empty},
			secret: `"value_string":""`,
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueString == nil || *p.ValueString != "" {
					t.Errorf("stdin value_string = %v, want empty", p.ValueString)
				}
			},
		},
		{
			name:   "special chars",
			input:  RegistryValueInput{Kind: RegistryValueKindString, ValueString: rvPtr(special)},
			secret: special,
			checkStdin: func(t *testing.T, p rvSetStdin) {
				if p.ValueString == nil || *p.ValueString != special {
					t.Errorf("stdin value_string = %v, want special chars verbatim", p.ValueString)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotScript, gotStdin string
			defer stubRVRun(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
				gotScript, gotStdin = script, stdin
				return rvOKEnvelope(t, map[string]any{"found": true, "kind": string(tc.input.Kind)}), "", nil
			})()
			in := tc.input
			in.Hive = "HKLM"
			in.Path = `SOFTWARE\Test`
			in.Name = "V"
			if _, err := newRVTestClient(t).Set(context.Background(), in); err != nil {
				t.Fatalf("Set: %v", err)
			}
			if strings.Contains(gotScript, tc.secret) {
				t.Errorf("Set script embeds the secret %q; it must travel on stdin only", tc.secret)
			}
			if gotStdin == "" {
				t.Fatal("Set must stream the value payload on stdin")
			}
			tc.checkStdin(t, rvStdinPayload(t, gotStdin))
		})
	}
}

func TestRegistryValueSet_HappyPath_REG_MULTI_SZ(t *testing.T) {
	var gotScript, gotStdin string
	defer stubRVRun(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		gotScript, gotStdin = script, stdin
		return rvOKEnvelope(t, rvFoundMulti([]string{"alpha", "beta"})), "", nil
	})()
	rv := newRVTestClient(t)
	state, err := rv.Set(context.Background(), RegistryValueInput{
		Hive:         "HKLM",
		Path:         `SOFTWARE\Test`,
		Name:         "Multi",
		Kind:         RegistryValueKindMultiString,
		ValueStrings: []string{"alpha", "beta"},
	})
	if err != nil {
		t.Fatalf("Set MULTI_SZ: %v", err)
	}
	if len(state.ValueStrings) != 2 {
		t.Errorf("ValueStrings len = %d", len(state.ValueStrings))
	}
	if strings.Contains(gotScript, "'alpha'") || strings.Contains(gotScript, "'beta'") {
		t.Error("Set script must not embed value_strings; they travel on stdin")
	}
	if got := rvStdinPayload(t, gotStdin).ValueStrings; len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Errorf("stdin value_strings = %v", got)
	}
}

func TestRegistryValueSet_HappyPath_REG_BINARY(t *testing.T) {
	var gotScript, gotStdin string
	defer stubRVRun(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		gotScript, gotStdin = script, stdin
		return rvOKEnvelope(t, rvFoundBinary("REG_BINARY", "deadbeef")), "", nil
	})()
	rv := newRVTestClient(t)
	state, err := rv.Set(context.Background(), RegistryValueInput{
		Hive:        "HKLM",
		Path:        `SOFTWARE\Test`,
		Name:        "Bin",
		Kind:        RegistryValueKindBinary,
		ValueBinary: rvPtr("deadbeef"),
	})
	if err != nil {
		t.Fatalf("Set BINARY: %v", err)
	}
	if state.ValueBinary == nil || *state.ValueBinary != "deadbeef" {
		t.Errorf("ValueBinary = %v", state.ValueBinary)
	}
	if strings.Contains(gotScript, "deadbeef") {
		t.Error("Set script must not embed value_binary; it travels on stdin")
	}
	if got := rvStdinPayload(t, gotStdin).ValueBinary; got == nil || *got != "deadbeef" {
		t.Errorf("stdin value_binary = %v", got)
	}
}

func TestRegistryValueSet_HappyPath_DefaultValue(t *testing.T) {
	// Default value: name="" (empty string)
	var gotStdin string
	defer stubRVRun(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		// Verify name is quoted as empty string ''
		if !strings.Contains(script, "''") {
			t.Errorf("script should contain '' for default value name")
		}
		if strings.Contains(script, "'default'") {
			t.Error("script must not embed the secret value; it travels on stdin")
		}
		gotStdin = stdin
		return rvOKEnvelope(t, rvFoundData("REG_SZ", "default")), "", nil
	})()
	rv := newRVTestClient(t)
	state, err := rv.Set(context.Background(), RegistryValueInput{
		Hive:        "HKLM",
		Path:        `SOFTWARE\Test`,
		Name:        "",
		Kind:        RegistryValueKindString,
		ValueString: rvPtr("default"),
	})
	if err != nil {
		t.Fatalf("Set default value: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if got := rvStdinPayload(t, gotStdin).ValueString; got == nil || *got != "default" {
		t.Errorf("stdin value_string = %v", got)
	}
}

func TestRegistryValueSet_ExpandTrue_ScriptContainsTrueFlag(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, script, _ string) (string, string, error) {
		if !strings.Contains(script, "$true") {
			t.Errorf("expand=true should produce '$true' in script")
		}
		return rvOKEnvelope(t, rvFoundData("REG_EXPAND_SZ", "%PATH%")), "", nil
	})()
	rv := newRVTestClient(t)
	_, err := rv.Set(context.Background(), RegistryValueInput{
		Hive:                       "HKLM",
		Path:                       `SOFTWARE\Test`,
		Name:                       "Env",
		Kind:                       RegistryValueKindExpandString,
		ValueString:                rvPtr("%PATH%"),
		ExpandEnvironmentVariables: true,
	})
	if err != nil {
		t.Fatalf("Set with expand=true: %v", err)
	}
}

// EC-3: type conflict
func TestRegistryValueSet_EC3_TypeConflict(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvErrEnvelope(t, "type_conflict",
			"type_conflict: existing=REG_SZ declared=REG_DWORD",
			map[string]string{"existing_type": "REG_SZ", "declared_type": "REG_DWORD"},
		), "", nil
	})()
	rv := newRVTestClient(t)
	_, err := rv.Set(context.Background(), RegistryValueInput{
		Hive:        "HKLM",
		Path:        `SOFTWARE\Test`,
		Name:        "Version",
		Kind:        RegistryValueKindDWord,
		ValueString: rvPtr("42"),
	})
	if err == nil {
		t.Fatal("expected type_conflict error (EC-3)")
	}
	if !IsRegistryValueError(err, RegistryValueErrorTypeConflict) {
		t.Errorf("expected type_conflict, got: %v", err)
	}
}

func TestRegistryValueSet_PermissionDenied(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvErrEnvelope(t, "permission_denied", "access denied", nil), "", nil
	})()
	rv := newRVTestClient(t)
	_, err := rv.Set(context.Background(), RegistryValueInput{
		Hive: "HKLM", Path: `SOFTWARE\Test`, Name: "V",
		Kind: RegistryValueKindString, ValueString: rvPtr("x"),
	})
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !IsRegistryValueError(err, RegistryValueErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestRegistryValueSet_TransportError(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "connection refused", fmt.Errorf("transport error")
	})()
	rv := newRVTestClient(t)
	_, err := rv.Set(context.Background(), RegistryValueInput{
		Hive: "HKLM", Path: `SOFTWARE\Test`, Name: "V",
		Kind: RegistryValueKindString, ValueString: rvPtr("x"),
	})
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsRegistryValueError(err, RegistryValueErrorUnknown) {
		t.Errorf("transport error should be unknown kind, got: %v", err)
	}
}

func TestRegistryValueSet_MissingEnvelope(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "Warning: some PS warning\nno json line here\n", "", nil
	})()
	rv := newRVTestClient(t)
	_, err := rv.Set(context.Background(), RegistryValueInput{
		Hive: "HKLM", Path: `SOFTWARE\Test`, Name: "V",
		Kind: RegistryValueKindString, ValueString: rvPtr("x"),
	})
	if err == nil {
		t.Fatal("expected error for missing JSON envelope")
	}
}

func TestRegistryValueSet_MalformedJSON(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "{malformed}\n", "", nil
	})()
	rv := newRVTestClient(t)
	_, err := rv.Set(context.Background(), RegistryValueInput{
		Hive: "HKLM", Path: `SOFTWARE\Test`, Name: "V",
		Kind: RegistryValueKindString, ValueString: rvPtr("x"),
	})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestRegistryValueSet_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before call

	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "", fmt.Errorf("cancelled")
	})()

	rv := newRVTestClient(t)
	_, err := rv.Set(ctx, RegistryValueInput{
		Hive: "HKLM", Path: `SOFTWARE\Test`, Name: "V",
		Kind: RegistryValueKindString, ValueString: rvPtr("x"),
	})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	var rve *RegistryValueError
	if !errors.As(err, &rve) {
		t.Fatalf("expected *RegistryValueError, got %T: %v", err, err)
	}
	if rve.Cause == nil {
		t.Error("expected non-nil cause for context cancellation")
	}
}

func TestRegistryValueSet_InvalidInput_BuildExprFails(t *testing.T) {
	// buildRVSetStdin fails before runScript is reached
	rv := newRVTestClient(t)
	_, err := rv.Set(context.Background(), RegistryValueInput{
		Hive: "HKLM", Path: `SOFTWARE\Test`, Name: "V",
		Kind: RegistryValueKindDWord, // Missing ValueString
	})
	if err == nil {
		t.Fatal("expected invalid_input error")
	}
	if !IsRegistryValueError(err, RegistryValueErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path + not_found + error paths
// ---------------------------------------------------------------------------

func TestRegistryValueRead_HappyPath(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvOKEnvelope(t, rvFoundData("REG_SZ", "hello")), "", nil
	})()
	rv := newRVTestClient(t)
	state, err := rv.Read(context.Background(), "HKLM", `SOFTWARE\Test`, "V", false)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Kind != RegistryValueKindString {
		t.Errorf("Kind = %q", state.Kind)
	}
}

func TestRegistryValueRead_EC4_NotFound_FoundFalse(t *testing.T) {
	// PS returns ok=true, data.found=false → (nil, nil)
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvOKEnvelope(t, map[string]any{"found": false}), "", nil
	})()
	rv := newRVTestClient(t)
	state, err := rv.Read(context.Background(), "HKLM", `SOFTWARE\Test`, "V", false)
	if err != nil {
		t.Fatalf("Read not_found: %v", err)
	}
	if state != nil {
		t.Error("not_found (found=false) must return nil state")
	}
}

func TestRegistryValueRead_EC4_NotFound_ErrorKind(t *testing.T) {
	// PS returns ok=false, kind=not_found → (nil, nil) via EC-4 path in Read
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvErrEnvelope(t, "not_found", "value absent", nil), "", nil
	})()
	rv := newRVTestClient(t)
	state, err := rv.Read(context.Background(), "HKLM", `SOFTWARE\Test`, "V", false)
	if err != nil {
		t.Fatalf("Read not_found error kind: %v", err)
	}
	if state != nil {
		t.Error("not_found error kind must return nil state")
	}
}

func TestRegistryValueRead_PermissionDenied(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvErrEnvelope(t, "permission_denied", "access denied", nil), "", nil
	})()
	rv := newRVTestClient(t)
	_, err := rv.Read(context.Background(), "HKLM", `SOFTWARE\Test`, "V", false)
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !IsRegistryValueError(err, RegistryValueErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestRegistryValueRead_ScriptContainsExpandTrueFlag(t *testing.T) {
	var script string
	defer stubRVRun(func(_ context.Context, _ *Client, s, _ string) (string, string, error) {
		script = s
		return rvOKEnvelope(t, rvFoundData("REG_EXPAND_SZ", "%PATH%")), "", nil
	})()
	rv := newRVTestClient(t)
	_, _ = rv.Read(context.Background(), "HKLM", `SOFTWARE\Test`, "Env", true)
	if !strings.Contains(script, "$true") {
		end := rvMax(0, len(script)-200)
		t.Errorf("expand=true should produce '$true' in script (tail: ...%s)", script[end:])
	}
}

func TestRegistryValueRead_MissingEnvelope(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "no json here\n", "", nil
	})()
	rv := newRVTestClient(t)
	_, err := rv.Read(context.Background(), "HKLM", `SOFTWARE\Test`, "V", false)
	if err == nil {
		t.Fatal("expected error for missing JSON envelope")
	}
}

func TestRegistryValueRead_TransportError(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "", fmt.Errorf("connection refused")
	})()
	rv := newRVTestClient(t)
	_, err := rv.Read(context.Background(), "HKLM", `SOFTWARE\Test`, "V", false)
	if err == nil {
		t.Fatal("expected error for transport failure")
	}
}

// ---------------------------------------------------------------------------
// Delete — happy path + EC-12 idempotent + permission error
// ---------------------------------------------------------------------------

func TestRegistryValueDelete_HappyPath(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvOKEnvelope(t, map[string]any{"deleted": true}), "", nil
	})()
	rv := newRVTestClient(t)
	err := rv.Delete(context.Background(), "HKLM", `SOFTWARE\Test`, "V")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// EC-12: Delete is idempotent — not_found treated as success.
func TestRegistryValueDelete_EC12_Idempotent(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvErrEnvelope(t, "not_found", "value does not exist", nil), "", nil
	})()
	rv := newRVTestClient(t)
	err := rv.Delete(context.Background(), "HKLM", `SOFTWARE\Test`, "V")
	if err != nil {
		t.Fatalf("EC-12: idempotent Delete should return nil, got: %v", err)
	}
}

func TestRegistryValueDelete_KeyNotFound_OKResponse(t *testing.T) {
	// PS returns ok=true when parent key is absent (key_not_found reason)
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvOKEnvelope(t, map[string]any{"deleted": false, "reason": "key_not_found"}), "", nil
	})()
	rv := newRVTestClient(t)
	err := rv.Delete(context.Background(), "HKLM", `SOFTWARE\Ghost`, "V")
	if err != nil {
		t.Fatalf("Delete key_not_found: %v", err)
	}
}

func TestRegistryValueDelete_PermissionDenied(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return rvErrEnvelope(t, "permission_denied", "access denied", nil), "", nil
	})()
	rv := newRVTestClient(t)
	err := rv.Delete(context.Background(), "HKLM", `SOFTWARE\Test`, "V")
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !IsRegistryValueError(err, RegistryValueErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

func TestRegistryValueDelete_TransportError(t *testing.T) {
	defer stubRVRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "", fmt.Errorf("connection refused")
	})()
	rv := newRVTestClient(t)
	err := rv.Delete(context.Background(), "HKLM", `SOFTWARE\Test`, "V")
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestRegistryValueDelete_ScriptContainsExpectedLiterals(t *testing.T) {
	var capturedScript string
	defer stubRVRun(func(_ context.Context, _ *Client, script, _ string) (string, string, error) {
		capturedScript = script
		return rvOKEnvelope(t, map[string]any{"deleted": true}), "", nil
	})()
	rv := newRVTestClient(t)
	_ = rv.Delete(context.Background(), "HKCU", `Software\Test`, "MyVal")
	for _, want := range []string{"'HKCU'", `'Software\Test'`, "'MyVal'"} {
		if !strings.Contains(capturedScript, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
}
