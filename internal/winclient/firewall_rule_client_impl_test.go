// Package winclient — unit tests for FirewallRuleClient.
//
// Tests stub the package-level runPowerShell seam (shared with service.go)
// so no real WinRM connection is needed. Coverage targets:
//
//   - FirewallRuleError: Error(), Unwrap(), Is(), NewFirewallRuleError, IsFirewallRuleError
//   - mapFirewallKind: all known kinds + unknown fallback
//   - checkWritableStore: GroupPolicy / RSOP → error; writable stores → nil
//   - normaliseStrArr: nil/empty → ["Any"], non-empty → pass-through
//   - buildFirewallParams: create/update variants, optional fields, group only on create
//   - parseFirewallRuleState: null data → (nil,nil), valid JSON, invalid JSON, fallback store
//   - runFirewallEnvelope: transport error, ctx cancelled, missing JSON, bad JSON, Emit-Err
//   - Create: happy path (create + auto-read), already_exists, read_only_store, transport
//   - Read: happy path, not-found (null data), permission error
//   - Update: happy path (update + auto-read), not_found, read_only_store
//   - Delete: happy path, idempotent (not_found), read_only_store, transport error
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
// Firewall-specific test helpers
// ---------------------------------------------------------------------------

// frNewClient returns a *Client + *FirewallRuleClient pair for tests.
func frNewClient(t *testing.T) (*Client, *FirewallRuleClient) {
	t.Helper()
	c, err := New(Config{Host: "winfw01", Username: "u", Password: "p", Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewFirewallRuleClient(c)
}

// frOK returns a JSON ok-envelope whose data field is the supplied value.
func frOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("frOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// frOKNull returns a JSON ok-envelope with data=null (rule absent in Read).
func frOKNull() string { return `{"ok":true,"data":null}` + "\n" }

// frErr returns a JSON error-envelope for the given kind/message.
func frErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("frErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// testFRStateData is a minimal valid FirewallRuleState JSON payload.
var testFRStateData = map[string]any{
	"name":                  "TEST-RULE-01",
	"display_name":          "Test Firewall Rule",
	"description":           "A test rule",
	"enabled":               true,
	"direction":             "Inbound",
	"action":                "Allow",
	"profile":               []string{"Domain"},
	"edge_traversal_policy": "Block",
	"group":                 "TestGroup",
	"policy_store":          "PersistentStore",
	"protocol":              "TCP",
	"local_port":            []string{"443"},
	"remote_port":           []string{"Any"},
	"local_address":         []string{"Any"},
	"remote_address":        []string{"Any"},
	"program":               "Any",
	"service":               "Any",
	"interface_type":        "Any",
}

// frResponse captures one stubbed PS call's output.
type frResponse struct {
	stdout string
	stderr string
	err    error
}

// frStubSequence stubs runPowerShell with a fixed ordered list of responses.
// After the last one, every subsequent call replays the last entry.
// Returns a restore closure that must be deferred.
func frStubSequence(responses []frResponse) func() {
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
// FirewallRuleError
// ---------------------------------------------------------------------------

func TestFirewallRuleError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewFirewallRuleError(FirewallRuleErrorPermission, "access denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") {
		t.Errorf("missing kind: %q", msg)
	}
	if !strings.Contains(msg, "access denied") {
		t.Errorf("missing message: %q", msg)
	}
	if !strings.Contains(msg, "boom") {
		t.Errorf("missing cause: %q", msg)
	}
}

func TestFirewallRuleError_ErrorNoCause(t *testing.T) {
	e := NewFirewallRuleError(FirewallRuleErrorNotFound, "not found", nil, nil)
	msg := e.Error()
	if strings.Contains(msg, "<nil>") {
		t.Errorf("nil cause should not appear in Error(): %q", msg)
	}
	if !strings.Contains(msg, "not_found") {
		t.Errorf("missing kind: %q", msg)
	}
}

func TestFirewallRuleError_Unwrap(t *testing.T) {
	cause := errors.New("transport")
	e := NewFirewallRuleError(FirewallRuleErrorUnknown, "msg", cause, nil)
	if e.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
	e2 := NewFirewallRuleError(FirewallRuleErrorUnknown, "msg", nil, nil)
	if e2.Unwrap() != nil {
		t.Error("Unwrap with no cause should return nil")
	}
}

func TestFirewallRuleError_Is_SameKind(t *testing.T) {
	e := NewFirewallRuleError(FirewallRuleErrorNotFound, "x", nil, nil)
	if !errors.Is(e, ErrFirewallRuleNotFound) {
		t.Error("errors.Is should match on same kind")
	}
}

func TestFirewallRuleError_Is_DifferentKind(t *testing.T) {
	e := NewFirewallRuleError(FirewallRuleErrorNotFound, "x", nil, nil)
	if errors.Is(e, ErrFirewallRulePermission) {
		t.Error("errors.Is should NOT match across different kinds")
	}
}

func TestFirewallRuleError_Is_NotFirewallError(t *testing.T) {
	e := NewFirewallRuleError(FirewallRuleErrorNotFound, "x", nil, nil)
	if e.Is(errors.New("plain")) {
		t.Error("Is should return false for non-FirewallRuleError targets")
	}
}

func TestNewFirewallRuleError_Context(t *testing.T) {
	ctx := map[string]string{"rule": "RULE-01", "host": "winfw01"}
	e := NewFirewallRuleError(FirewallRuleErrorInvalidInput, "bad param", nil, ctx)
	if e.Kind != FirewallRuleErrorInvalidInput {
		t.Errorf("kind = %q", e.Kind)
	}
	if e.Context["rule"] != "RULE-01" {
		t.Error("context not preserved")
	}
}

func TestIsFirewallRuleError_Match(t *testing.T) {
	e := NewFirewallRuleError(FirewallRuleErrorAlreadyExists, "dup", nil, nil)
	if !IsFirewallRuleError(e, FirewallRuleErrorAlreadyExists) {
		t.Error("should match on kind")
	}
}

func TestIsFirewallRuleError_WrongKind(t *testing.T) {
	e := NewFirewallRuleError(FirewallRuleErrorAlreadyExists, "dup", nil, nil)
	if IsFirewallRuleError(e, FirewallRuleErrorNotFound) {
		t.Error("should NOT match on wrong kind")
	}
}

func TestIsFirewallRuleError_PlainError(t *testing.T) {
	if IsFirewallRuleError(errors.New("plain"), FirewallRuleErrorNotFound) {
		t.Error("plain error should return false")
	}
}

func TestSentinels_AllKinds(t *testing.T) {
	cases := []struct {
		sentinel *FirewallRuleError
		kind     FirewallRuleErrorKind
	}{
		{ErrFirewallRuleNotFound, FirewallRuleErrorNotFound},
		{ErrFirewallRuleAlreadyExists, FirewallRuleErrorAlreadyExists},
		{ErrFirewallRulePermission, FirewallRuleErrorPermission},
		{ErrFirewallRuleReadOnlyStore, FirewallRuleErrorReadOnlyStore},
		{ErrFirewallRuleInvalidInput, FirewallRuleErrorInvalidInput},
		{ErrFirewallRuleUnknown, FirewallRuleErrorUnknown},
	}
	for _, tc := range cases {
		e := NewFirewallRuleError(tc.kind, "msg", nil, nil)
		if !errors.Is(e, tc.sentinel) {
			t.Errorf("errors.Is(kind=%q) failed", tc.kind)
		}
	}
}

// ---------------------------------------------------------------------------
// mapFirewallKind
// ---------------------------------------------------------------------------

func TestMapFirewallKind_Known(t *testing.T) {
	cases := map[string]FirewallRuleErrorKind{
		"not_found":         FirewallRuleErrorNotFound,
		"already_exists":    FirewallRuleErrorAlreadyExists,
		"permission_denied": FirewallRuleErrorPermission,
		"read_only_store":   FirewallRuleErrorReadOnlyStore,
		"invalid_input":     FirewallRuleErrorInvalidInput,
	}
	for in, want := range cases {
		if got := mapFirewallKind(in); got != want {
			t.Errorf("mapFirewallKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapFirewallKind_Unknown(t *testing.T) {
	for _, in := range []string{"", "weird", "UNKNOWN"} {
		if got := mapFirewallKind(in); got != FirewallRuleErrorUnknown {
			t.Errorf("mapFirewallKind(%q) = %q, want unknown", in, got)
		}
	}
}

// ---------------------------------------------------------------------------
// checkWritableStore
// ---------------------------------------------------------------------------

func TestCheckWritableStore_GroupPolicy(t *testing.T) {
	err := checkWritableStore("GroupPolicy")
	if err == nil {
		t.Fatal("expected error for GroupPolicy")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorReadOnlyStore) {
		t.Errorf("expected read_only_store, got %v", err)
	}
}

func TestCheckWritableStore_RSOP(t *testing.T) {
	err := checkWritableStore("RSOP")
	if err == nil {
		t.Fatal("expected error for RSOP")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorReadOnlyStore) {
		t.Errorf("expected read_only_store, got %v", err)
	}
	if !strings.Contains(err.Error(), "RSOP") {
		t.Errorf("error should mention 'RSOP': %v", err)
	}
}

func TestCheckWritableStore_Writable(t *testing.T) {
	for _, store := range []string{"PersistentStore", "ActiveStore", "SystemDefaults", ""} {
		if err := checkWritableStore(store); err != nil {
			t.Errorf("checkWritableStore(%q) unexpected error: %v", store, err)
		}
	}
}

// ---------------------------------------------------------------------------
// normaliseStrArr
// ---------------------------------------------------------------------------

func TestNormaliseStrArr_Nil(t *testing.T) {
	got := normaliseStrArr(nil)
	if len(got) != 1 || got[0] != "Any" {
		t.Errorf("nil → %v, want [Any]", got)
	}
}

func TestNormaliseStrArr_Empty(t *testing.T) {
	got := normaliseStrArr([]string{})
	if len(got) != 1 || got[0] != "Any" {
		t.Errorf("empty → %v, want [Any]", got)
	}
}

func TestNormaliseStrArr_NonEmpty(t *testing.T) {
	in := []string{"TCP", "UDP"}
	got := normaliseStrArr(in)
	if len(got) != 2 || got[0] != "TCP" || got[1] != "UDP" {
		t.Errorf("non-empty → %v, want %v", got, in)
	}
}

// ---------------------------------------------------------------------------
// buildFirewallParams
// ---------------------------------------------------------------------------

func TestBuildFirewallParams_CreateMinimal(t *testing.T) {
	input := FirewallRuleInput{
		Name:        "RULE-MIN",
		DisplayName: "Minimal Rule",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "PersistentStore",
	}
	got := buildFirewallParams("create", "RULE-MIN", "PersistentStore", input)
	for _, want := range []string{
		"'RULE-MIN'", "'PersistentStore'", "'Minimal Rule'", "'Inbound'", "'Allow'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in params:\n%s", want, got)
		}
	}
}

func TestBuildFirewallParams_CreateWithOptionalFields(t *testing.T) {
	enabled := true
	input := FirewallRuleInput{
		Name:                "RULE-ALL",
		DisplayName:         "Full Rule",
		Description:         "My description",
		Enabled:             &enabled,
		Direction:           "Outbound",
		Action:              "Block",
		Profile:             []string{"Domain", "Private"},
		EdgeTraversalPolicy: "Allow",
		Group:               "MyGroup",
		PolicyStore:         "PersistentStore",
		Protocol:            "TCP",
		LocalPort:           []string{"80", "443"},
		RemotePort:          []string{"Any"},
		LocalAddress:        []string{"192.168.1.0/24"},
		RemoteAddress:       []string{"Any"},
		Program:             `C:\App\app.exe`,
		Service:             "MyService",
		InterfaceType:       "Wired",
	}
	got := buildFirewallParams("create", "RULE-ALL", "PersistentStore", input)

	for _, want := range []string{
		"'My description'",
		"Enabled = 'True'",
		"@('Domain','Private')",
		"'MyGroup'",
		"'TCP'",
		"@('80','443')",
		"'MyService'",
		"'Wired'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in params:\n%s", want, got)
		}
	}
}

func TestBuildFirewallParams_UpdateNoGroup(t *testing.T) {
	input := FirewallRuleInput{
		Name:        "RULE-UPD",
		DisplayName: "Updated Rule",
		Direction:   "Inbound",
		Action:      "Allow",
		Group:       "ShouldBeIgnored",
		PolicyStore: "PersistentStore",
	}
	got := buildFirewallParams("update", "RULE-UPD", "PersistentStore", input)
	if strings.Contains(got, "ShouldBeIgnored") {
		t.Error("Group must NOT be included in Update params")
	}
}

func TestBuildFirewallParams_EnabledFalse(t *testing.T) {
	disabled := false
	input := FirewallRuleInput{
		Name:        "RULE-DIS",
		DisplayName: "Disabled Rule",
		Enabled:     &disabled,
		Direction:   "Inbound",
		Action:      "Block",
		PolicyStore: "PersistentStore",
	}
	got := buildFirewallParams("create", "RULE-DIS", "PersistentStore", input)
	if !strings.Contains(got, "Enabled = 'False'") {
		t.Errorf("expected Enabled = 'False' for Enabled=false: %s", got)
	}
}

func TestBuildFirewallParams_NilEnabled(t *testing.T) {
	input := FirewallRuleInput{
		Name:        "RULE-NOENA",
		DisplayName: "No Enabled Field",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "PersistentStore",
	}
	got := buildFirewallParams("create", "RULE-NOENA", "PersistentStore", input)
	// No "Enabled =" key must appear when Enabled is nil.
	if strings.Contains(got, "Enabled =") {
		t.Error("nil Enabled should not add Enabled key to params")
	}
}

// ---------------------------------------------------------------------------
// parseFirewallRuleState
// ---------------------------------------------------------------------------

func TestParseFirewallRuleState_Null(t *testing.T) {
	resp := &psResponse{OK: true, Data: json.RawMessage("null")}
	state, err := parseFirewallRuleState(resp, "PersistentStore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != nil {
		t.Errorf("expected nil state, got %+v", state)
	}
}

func TestParseFirewallRuleState_NilData(t *testing.T) {
	resp := &psResponse{OK: true, Data: nil}
	state, err := parseFirewallRuleState(resp, "PersistentStore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != nil {
		t.Errorf("expected nil state, got %+v", state)
	}
}

func TestParseFirewallRuleState_Valid(t *testing.T) {
	raw, err := json.Marshal(testFRStateData)
	if err != nil {
		t.Fatalf("marshal testFRStateData: %v", err)
	}
	resp := &psResponse{OK: true, Data: json.RawMessage(raw)}
	state, err := parseFirewallRuleState(resp, "PersistentStore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Name != "TEST-RULE-01" {
		t.Errorf("Name = %q", state.Name)
	}
	if state.Direction != "Inbound" {
		t.Errorf("Direction = %q", state.Direction)
	}
	if state.Action != "Allow" {
		t.Errorf("Action = %q", state.Action)
	}
	if len(state.Profile) != 1 || state.Profile[0] != "Domain" {
		t.Errorf("Profile = %v", state.Profile)
	}
	if len(state.LocalPort) != 1 || state.LocalPort[0] != "443" {
		t.Errorf("LocalPort = %v", state.LocalPort)
	}
	if len(state.RemotePort) == 0 {
		t.Error("RemotePort should not be empty (normalised to [Any])")
	}
}

func TestParseFirewallRuleState_InvalidJSON(t *testing.T) {
	resp := &psResponse{OK: true, Data: json.RawMessage(`{not valid json`)}
	_, err := parseFirewallRuleState(resp, "PersistentStore")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestParseFirewallRuleState_FallbackPolicyStore(t *testing.T) {
	data := map[string]any{
		"name":                  "R",
		"display_name":          "R",
		"description":           "",
		"enabled":               true,
		"direction":             "Inbound",
		"action":                "Allow",
		"profile":               []string{"Any"},
		"edge_traversal_policy": "Block",
		"group":                 "",
		"protocol":              "Any",
		"local_port":            []string{"Any"},
		"remote_port":           []string{"Any"},
		"local_address":         []string{"Any"},
		"remote_address":        []string{"Any"},
		"program":               "Any",
		"service":               "Any",
		"interface_type":        "Any",
		// policy_store intentionally absent to test fallback
	}
	raw, _ := json.Marshal(data)
	resp := &psResponse{OK: true, Data: json.RawMessage(raw)}
	state, err := parseFirewallRuleState(resp, "ActiveStore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.PolicyStore != "ActiveStore" {
		t.Errorf("PolicyStore fallback = %q, want ActiveStore", state.PolicyStore)
	}
}

// ---------------------------------------------------------------------------
// runFirewallEnvelope error paths
// ---------------------------------------------------------------------------

func TestRunFirewallEnvelope_TransportError(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "WinRM error", errors.New("connection refused")
	})()

	_, err := fw.runFirewallEnvelope(context.Background(), "Read", "RULE", "script")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunFirewallEnvelope_CtxCancelled(t *testing.T) {
	_, fw := frNewClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("context cancelled")
	})()

	_, err := fw.runFirewallEnvelope(ctx, "Read", "RULE", "script")
	if err == nil {
		t.Fatal("expected error for cancelled ctx")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestRunFirewallEnvelope_MissingJSON(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "no json here\n", "", nil
	})()

	_, err := fw.runFirewallEnvelope(context.Background(), "Read", "RULE", "script")
	if err == nil {
		t.Fatal("expected error for missing JSON")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestRunFirewallEnvelope_BadJSON(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{not valid json}\n", "", nil
	})()

	_, err := fw.runFirewallEnvelope(context.Background(), "Read", "RULE", "script")
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestRunFirewallEnvelope_ErrorResponse(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frErr(t, "permission_denied", "access denied"), "", nil
	})()

	_, err := fw.runFirewallEnvelope(context.Background(), "Read", "RULE", "script")
	if err == nil {
		t.Fatal("expected error for Emit-Err response")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestFirewallCreate_HappyPath(t *testing.T) {
	_, fw := frNewClient(t)

	stateJSON := frOK(t, testFRStateData)
	defer frStubSequence([]frResponse{
		{stdout: frOK(t, nil)}, // create script: Emit-OK $null
		{stdout: stateJSON},    // read script: Emit-OK $state
	})()

	input := FirewallRuleInput{
		Name:        "TEST-RULE-01",
		DisplayName: "Test Firewall Rule",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "PersistentStore",
	}
	state, err := fw.Create(context.Background(), input)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Name != "TEST-RULE-01" {
		t.Errorf("Name = %q", state.Name)
	}
	if state.Direction != "Inbound" {
		t.Errorf("Direction = %q", state.Direction)
	}
}

func TestFirewallCreate_AlreadyExists(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frErr(t, "already_exists", "rule already exists"), "", nil
	})()

	input := FirewallRuleInput{
		Name:        "EXISTING-RULE",
		DisplayName: "Rule",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "PersistentStore",
	}
	_, err := fw.Create(context.Background(), input)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorAlreadyExists) {
		t.Errorf("expected already_exists, got %v", err)
	}
}

func TestFirewallCreate_ReadOnlyStore_GroupPolicy(t *testing.T) {
	_, fw := frNewClient(t)
	called := false
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})()

	input := FirewallRuleInput{
		Name:        "R",
		DisplayName: "R",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "GroupPolicy",
	}
	_, err := fw.Create(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for read-only store")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorReadOnlyStore) {
		t.Errorf("expected read_only_store, got %v", err)
	}
	if called {
		t.Error("runPowerShell should not be called for read-only store")
	}
}

func TestFirewallCreate_RSOP_ReadOnly(t *testing.T) {
	_, fw := frNewClient(t)
	input := FirewallRuleInput{
		Name:        "R",
		DisplayName: "R",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "RSOP",
	}
	_, err := fw.Create(context.Background(), input)
	if !IsFirewallRuleError(err, FirewallRuleErrorReadOnlyStore) {
		t.Errorf("expected read_only_store for RSOP, got %v", err)
	}
}

func TestFirewallCreate_TransportError(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("connection lost")
	})()

	input := FirewallRuleInput{
		Name:        "R",
		DisplayName: "R",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "PersistentStore",
	}
	_, err := fw.Create(context.Background(), input)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestFirewallCreate_InvalidInput(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frErr(t, "invalid_input", "invalid argument"), "", nil
	})()

	input := FirewallRuleInput{
		Name:        "R",
		DisplayName: "R",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "PersistentStore",
	}
	_, err := fw.Create(context.Background(), input)
	if !IsFirewallRuleError(err, FirewallRuleErrorInvalidInput) {
		t.Errorf("expected invalid_input, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestFirewallRead_HappyPath(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frOK(t, testFRStateData), "", nil
	})()

	state, err := fw.Read(context.Background(), "TEST-RULE-01", "PersistentStore")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.Name != "TEST-RULE-01" {
		t.Errorf("Name = %q", state.Name)
	}
	if !state.Enabled {
		t.Error("Enabled should be true")
	}
	if state.Protocol != "TCP" {
		t.Errorf("Protocol = %q", state.Protocol)
	}
}

func TestFirewallRead_NotFound_NullData(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frOKNull(), "", nil
	})()

	state, err := fw.Read(context.Background(), "GONE-RULE", "PersistentStore")
	if err != nil {
		t.Fatalf("Read error (should be nil for not-found): %v", err)
	}
	if state != nil {
		t.Errorf("expected nil state for not-found rule, got %+v", state)
	}
}

func TestFirewallRead_PermissionDenied(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frErr(t, "permission_denied", "access denied"), "", nil
	})()

	_, err := fw.Read(context.Background(), "RULE", "PersistentStore")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

func TestFirewallRead_TransportError(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("network timeout")
	})()

	_, err := fw.Read(context.Background(), "RULE", "PersistentStore")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestFirewallRead_MalformedStateJSON(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":{invalid}}` + "\n", "", nil
	})()

	_, err := fw.Read(context.Background(), "RULE", "PersistentStore")
	if err == nil {
		t.Fatal("expected error for malformed state JSON")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestFirewallUpdate_HappyPath(t *testing.T) {
	_, fw := frNewClient(t)

	updatedState := map[string]any{
		"name":                  "TEST-RULE-01",
		"display_name":          "Updated Display Name",
		"description":           "Updated",
		"enabled":               false,
		"direction":             "Inbound",
		"action":                "Block",
		"profile":               []string{"Private"},
		"edge_traversal_policy": "Block",
		"group":                 "TestGroup",
		"policy_store":          "PersistentStore",
		"protocol":              "UDP",
		"local_port":            []string{"53"},
		"remote_port":           []string{"Any"},
		"local_address":         []string{"Any"},
		"remote_address":        []string{"Any"},
		"program":               "Any",
		"service":               "Any",
		"interface_type":        "Any",
	}

	defer frStubSequence([]frResponse{
		{stdout: frOK(t, nil)},          // update script: Emit-OK $null
		{stdout: frOK(t, updatedState)}, // read script: Emit-OK $state
	})()

	input := FirewallRuleInput{
		Name:        "TEST-RULE-01",
		DisplayName: "Updated Display Name",
		Direction:   "Inbound",
		Action:      "Block",
		PolicyStore: "PersistentStore",
	}
	state, err := fw.Update(context.Background(), "TEST-RULE-01", "PersistentStore", input)
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.DisplayName != "Updated Display Name" {
		t.Errorf("DisplayName = %q", state.DisplayName)
	}
}

func TestFirewallUpdate_NotFound(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frErr(t, "not_found", "rule not found"), "", nil
	})()

	input := FirewallRuleInput{
		Name:        "GONE",
		DisplayName: "Gone",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "PersistentStore",
	}
	_, err := fw.Update(context.Background(), "GONE", "PersistentStore", input)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorNotFound) {
		t.Errorf("expected not_found, got %v", err)
	}
}

func TestFirewallUpdate_ReadOnlyStore(t *testing.T) {
	_, fw := frNewClient(t)
	called := false
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})()

	input := FirewallRuleInput{
		Name:        "R",
		DisplayName: "R",
		Direction:   "Inbound",
		Action:      "Allow",
		PolicyStore: "RSOP",
	}
	_, err := fw.Update(context.Background(), "R", "RSOP", input)
	if err == nil {
		t.Fatal("expected error for read-only store")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorReadOnlyStore) {
		t.Errorf("expected read_only_store, got %v", err)
	}
	if called {
		t.Error("runPowerShell should not be called for read-only store")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestFirewallDelete_HappyPath(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frOK(t, nil), "", nil
	})()

	err := fw.Delete(context.Background(), "TEST-RULE-01", "PersistentStore")
	if err != nil {
		t.Fatalf("Delete error: %v", err)
	}
}

func TestFirewallDelete_Idempotent_NotFound(t *testing.T) {
	// The PS script handles not_found inside frDeleteBody by emitting Emit-OK $null.
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frOK(t, nil), "", nil
	})()

	err := fw.Delete(context.Background(), "ALREADY-GONE", "PersistentStore")
	if err != nil {
		t.Fatalf("Delete idempotent error: %v", err)
	}
}

func TestFirewallDelete_ReadOnlyStore(t *testing.T) {
	_, fw := frNewClient(t)
	called := false
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})()

	err := fw.Delete(context.Background(), "R", "GroupPolicy")
	if err == nil {
		t.Fatal("expected error for read-only store")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorReadOnlyStore) {
		t.Errorf("expected read_only_store, got %v", err)
	}
	if called {
		t.Error("runPowerShell should not be called for read-only store")
	}
}

func TestFirewallDelete_TransportError(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("connection reset")
	})()

	err := fw.Delete(context.Background(), "R", "PersistentStore")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsFirewallRuleError(err, FirewallRuleErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestFirewallDelete_PermissionDenied(t *testing.T) {
	_, fw := frNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return frErr(t, "permission_denied", "access denied"), "", nil
	})()

	err := fw.Delete(context.Background(), "R", "PersistentStore")
	if !IsFirewallRuleError(err, FirewallRuleErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// buildFirewallReplacer
// ---------------------------------------------------------------------------

func TestBuildFirewallReplacer(t *testing.T) {
	r := buildFirewallReplacer("MY-RULE", "PersistentStore")
	script := "Name=@@NAME@@ PolicyStore=@@PSTORE@@"
	got := r.Replace(script)
	if !strings.Contains(got, "'MY-RULE'") {
		t.Errorf("@@NAME@@ not replaced: %s", got)
	}
	if !strings.Contains(got, "'PersistentStore'") {
		t.Errorf("@@PSTORE@@ not replaced: %s", got)
	}
}
