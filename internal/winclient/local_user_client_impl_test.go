// Package winclient — unit tests for LocalUserClientImpl.
//
// Coverage targets: local_user.go ≥ 85%, local_user_helpers.go ≥ 85%.
//
// Tests stub the package-level runPowerShell and runPSInput hooks so no real
// WinRM connection is required. Edge cases covered:
//
//	EC-1  Create: name collision (already_exists)
//	EC-2  Delete: built-in RID guard (500/501/503/504) → builtin_account
//	EC-3  Read: user not found → (nil, nil) — not an error
//	EC-5  Rename: target name conflict (rename_conflict)
//	EC-6  SetPassword: password injected via stdin, plaintext never in logs
//	EC-7  Context cancellation (timeout) → LocalUserErrorUnknown
//	EC-9  AccessDenied → permission_denied
//	EC-10 Invalid name → invalid_name
//	parseLUEnvelope: missing JSON, malformed JSON
//	parseUserData: all fields including null/non-null dates, SID inversion
//	mapLUKind: all 8 kinds + unknown fallback
//	LocalUserError: Error(), Unwrap(), Is(), sentinels, IsLocalUserError()
//	ResolveLocalUserSID: SID vs name routing
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
// Shared test helpers
// ---------------------------------------------------------------------------

func newLUTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:     "winlu01",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// stubLURun replaces runPowerShell for the duration of a test.
func stubLURun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runPowerShell
	runPowerShell = fn
	return func() { runPowerShell = prev }
}

// stubLUInput replaces runPSInput for the duration of a test.
func stubLUInput(fn func(ctx context.Context, c *Client, script, stdin string) (string, string, error)) func() {
	prev := runPSInput
	runPSInput = fn
	return func() { runPSInput = prev }
}

// luOK returns a JSON ok-envelope with arbitrary data.
func luOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("luOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// luErr returns a JSON err-envelope.
func luErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("luErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// fakeUserData returns the JSON shape produced by Get-UserData.
func fakeUserData(name, sid string) map[string]any {
	return map[string]any{
		"Name":                  name,
		"FullName":              "Full " + name,
		"Description":           "desc",
		"Enabled":               true,
		"PasswordNeverExpires":  false,
		"UserMayChangePassword": true,
		"AccountExpires":        nil,
		"LastLogon":             nil,
		"PasswordLastSet":       "2026-01-01T00:00:00Z",
		"PrincipalSource":       "Local",
		"SID":                   sid,
	}
}

// newLUClient wraps newLUTestClient + NewLocalUserClient.
func newLUClient(t *testing.T) (*Client, *LocalUserClientImpl) {
	t.Helper()
	c := newLUTestClient(t)
	return c, NewLocalUserClient(c)
}

// ---------------------------------------------------------------------------
// LocalUserError type coverage
// ---------------------------------------------------------------------------

func TestLocalUserError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("transport-fail")
	e := NewLocalUserError(LocalUserErrorPermission, "access denied", cause,
		map[string]string{"host": "winlu01", "operation": "create"})
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

	// No-cause variant must not leak "<nil>".
	e2 := NewLocalUserError(LocalUserErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error() leaks <nil>: %q", e2.Error())
	}
}

func TestLocalUserError_Is_And_IsLocalUserError(t *testing.T) {
	e := NewLocalUserError(LocalUserErrorBuiltinAccount, "builtin", nil, nil)

	if !errors.Is(e, ErrLocalUserBuiltinAccount) {
		t.Error("errors.Is(ErrLocalUserBuiltinAccount) must be true")
	}
	if errors.Is(e, ErrLocalUserNotFound) {
		t.Error("errors.Is across kinds must be false")
	}
	if !IsLocalUserError(e, LocalUserErrorBuiltinAccount) {
		t.Error("IsLocalUserError() must be true for matching kind")
	}
	if IsLocalUserError(errors.New("plain"), LocalUserErrorBuiltinAccount) {
		t.Error("IsLocalUserError() on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is() against non-LocalUserError must be false")
	}
}

func TestLocalUserError_Sentinels(t *testing.T) {
	pairs := []struct {
		s    *LocalUserError
		kind LocalUserErrorKind
	}{
		{ErrLocalUserNotFound, LocalUserErrorNotFound},
		{ErrLocalUserAlreadyExists, LocalUserErrorAlreadyExists},
		{ErrLocalUserBuiltinAccount, LocalUserErrorBuiltinAccount},
		{ErrLocalUserRenameConflict, LocalUserErrorRenameConflict},
		{ErrLocalUserPasswordPolicy, LocalUserErrorPasswordPolicy},
		{ErrLocalUserPermission, LocalUserErrorPermission},
		{ErrLocalUserInvalidName, LocalUserErrorInvalidName},
		{ErrLocalUserUnknown, LocalUserErrorUnknown},
	}
	for _, p := range pairs {
		if p.s.Kind != p.kind {
			t.Errorf("sentinel kind = %q, want %q", p.s.Kind, p.kind)
		}
	}
}

// ---------------------------------------------------------------------------
// mapLUKind — all branches
// ---------------------------------------------------------------------------

func TestMapLUKind(t *testing.T) {
	cases := map[string]LocalUserErrorKind{
		"not_found":         LocalUserErrorNotFound,
		"already_exists":    LocalUserErrorAlreadyExists,
		"builtin_account":   LocalUserErrorBuiltinAccount,
		"rename_conflict":   LocalUserErrorRenameConflict,
		"password_policy":   LocalUserErrorPasswordPolicy,
		"permission_denied": LocalUserErrorPermission,
		"invalid_name":      LocalUserErrorInvalidName,
		"unknown":           LocalUserErrorUnknown,
		"":                  LocalUserErrorUnknown,
		"totally_unknown":   LocalUserErrorUnknown,
	}
	for in, want := range cases {
		if got := mapLUKind(in); got != want {
			t.Errorf("mapLUKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// parseUserData — happy path + edge cases
// ---------------------------------------------------------------------------

func TestParseUserData_HappyPath(t *testing.T) {
	raw, _ := json.Marshal(fakeUserData("alice", "S-1-5-21-111-222-333-1001"))
	us, err := parseUserData("test", json.RawMessage(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if us.Name != "alice" {
		t.Errorf("Name = %q", us.Name)
	}
	if us.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", us.SID)
	}
	// UserMayChangePassword=true in data → UserMayNotChangePassword=false in state
	if us.UserMayNotChangePassword {
		t.Error("UserMayNotChangePassword should be false when UserMayChangePassword=true")
	}
	// AccountExpires=null → AccountNeverExpires=true
	if !us.AccountNeverExpires {
		t.Error("AccountNeverExpires must be true when AccountExpires is null")
	}
	if us.AccountExpires != "" {
		t.Errorf("AccountExpires should be empty, got %q", us.AccountExpires)
	}
	// PasswordLastSet non-null
	if us.PasswordLastSet == "" {
		t.Error("PasswordLastSet should be set")
	}
	// LastLogon null → empty
	if us.LastLogon != "" {
		t.Errorf("LastLogon should be empty, got %q", us.LastLogon)
	}
}

func TestParseUserData_WithAccountExpires(t *testing.T) {
	data := fakeUserData("bob", "S-1-5-21-1-2-3-1002")
	exp := "2028-01-01T00:00:00Z"
	data["AccountExpires"] = exp
	raw, _ := json.Marshal(data)
	us, err := parseUserData("test", json.RawMessage(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if us.AccountNeverExpires {
		t.Error("AccountNeverExpires must be false when AccountExpires is set")
	}
	if us.AccountExpires != exp {
		t.Errorf("AccountExpires = %q, want %q", us.AccountExpires, exp)
	}
}

func TestParseUserData_UserMayNotChangePassword_Inversion(t *testing.T) {
	data := fakeUserData("carol", "S-1-5-21-1-2-3-1003")
	data["UserMayChangePassword"] = false
	raw, _ := json.Marshal(data)
	us, err := parseUserData("test", json.RawMessage(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !us.UserMayNotChangePassword {
		t.Error("UserMayNotChangePassword must be true when UserMayChangePassword=false")
	}
}

func TestParseUserData_EmptySID_Error(t *testing.T) {
	data := fakeUserData("ghost", "")
	raw, _ := json.Marshal(data)
	_, err := parseUserData("test", json.RawMessage(raw))
	if err == nil {
		t.Fatal("expected error for empty SID")
	}
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("wrong error kind: %v", err)
	}
}

func TestParseUserData_InvalidJSON(t *testing.T) {
	_, err := parseUserData("test", json.RawMessage(`{not-json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// parseLUEnvelope — missing JSON, malformed JSON
// ---------------------------------------------------------------------------

func TestParseLUEnvelope_NoJSON(t *testing.T) {
	_, lc := newLUClient(t)
	_, err := lc.parseLUEnvelope("test_op", "key1", "no json here\n", "")
	if err == nil {
		t.Fatal("expected error for missing JSON envelope")
	}
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

func TestParseLUEnvelope_MalformedJSON(t *testing.T) {
	_, lc := newLUClient(t)
	_, err := lc.parseLUEnvelope("test_op", "key1", "{broken\n", "")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

func TestParseLUEnvelope_ErrorEnvelope(t *testing.T) {
	_, lc := newLUClient(t)
	b, _ := json.Marshal(map[string]any{
		"ok": false, "kind": "permission_denied", "message": "access denied",
		"context": map[string]string{},
	})
	_, err := lc.parseLUEnvelope("test_op", "key1", string(b)+"\n", "")
	if err == nil {
		t.Fatal("expected error from err-envelope")
	}
	if !IsLocalUserError(err, LocalUserErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runLUEnvelope — transport error + context cancellation
// ---------------------------------------------------------------------------

func TestRunLUEnvelope_TransportError(t *testing.T) {
	_, lc := newLUClient(t)
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "stderr-output", errors.New("connection refused")
	})()

	_, err := lc.runLUEnvelope(context.Background(), "test_op", "sid1", "# script")
	if err == nil {
		t.Fatal("expected error from transport failure")
	}
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown kind for transport error, got: %v", err)
	}
}

func TestRunLUEnvelope_ContextCancelled(t *testing.T) {
	_, lc := newLUClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	defer stubLURun(func(ctx context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", ctx.Err()
	})()

	_, err := lc.runLUEnvelope(ctx, "test_op", "sid1", "# script")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runLUEnvelopeWithInput — stdin transport error + context cancel
// ---------------------------------------------------------------------------

func TestRunLUEnvelopeWithInput_TransportError(t *testing.T) {
	_, lc := newLUClient(t)
	defer stubLUInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "", errors.New("stdin transport error")
	})()

	_, err := lc.runLUEnvelopeWithInput(context.Background(), "set_pw", "sid1", "# script", "password\n")
	if err == nil {
		t.Fatal("expected error from transport failure")
	}
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown kind, got: %v", err)
	}
}

func TestRunLUEnvelopeWithInput_ContextCancelled(t *testing.T) {
	_, lc := newLUClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer stubLUInput(func(ctx context.Context, _ *Client, _, _ string) (string, string, error) {
		return "", "", ctx.Err()
	})()

	_, err := lc.runLUEnvelopeWithInput(ctx, "set_pw", "sid1", "# script", "password\n")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	// Error message must NOT contain the plaintext password
	if strings.Contains(err.Error(), "password") {
		t.Errorf("error message must not contain plaintext password: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Create — happy path + EC-1 already_exists + password never in context
// ---------------------------------------------------------------------------

func TestLocalUserClient_Create_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLUInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	input := UserInput{
		Name:    "alice",
		Enabled: true,
	}
	us, err := lc.Create(context.Background(), input, "Sup3rS3cr3t!")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if us == nil {
		t.Fatal("Create() returned nil state")
	}
	if us.Name != "alice" {
		t.Errorf("Name = %q, want alice", us.Name)
	}
	if us.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", us.SID)
	}
}

func TestLocalUserClient_Create_AlreadyExists(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLUInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return luErr(t, "already_exists", "user already exists"), "", nil
	})()

	_, err := lc.Create(context.Background(), UserInput{Name: "alice", Enabled: true}, "pass")
	if err == nil {
		t.Fatal("expected error for already_exists")
	}
	if !IsLocalUserError(err, LocalUserErrorAlreadyExists) {
		t.Errorf("expected already_exists, got: %v", err)
	}
}

func TestLocalUserClient_Create_PasswordNotInContext(t *testing.T) {
	_, lc := newLUClient(t)

	const secret = "T0pS3cr3t!Pass"
	defer stubLUInput(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		// The plaintext secret must never appear in the script body
		if strings.Contains(script, secret) {
			return "", "", errors.New("PASSWORD LEAKED INTO SCRIPT BODY")
		}
		return luErr(t, "password_policy", "does not meet complexity"), "", nil
	})()

	_, err := lc.Create(context.Background(), UserInput{Name: "u", Enabled: true}, secret)
	if err == nil {
		t.Fatal("expected password_policy error")
	}
	if !IsLocalUserError(err, LocalUserErrorPasswordPolicy) {
		t.Errorf("expected password_policy, got: %v", err)
	}
	// Error message and context must not contain the secret
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error must not contain plaintext password: %q", err.Error())
	}
}

func TestLocalUserClient_Create_WithAllOptions(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("svc", "S-1-5-21-1-2-3-1005")
	defer stubLUInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	input := UserInput{
		Name:                     "svc",
		FullName:                 "Service Account",
		Description:              "Test service",
		PasswordNeverExpires:     true,
		UserMayNotChangePassword: true,
		AccountNeverExpires:      true,
		Enabled:                  true,
	}
	us, err := lc.Create(context.Background(), input, "P@ssw0rd!")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if us.SID == "" {
		t.Error("SID must not be empty")
	}
}

func TestLocalUserClient_Create_WithAccountExpires(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("expiring", "S-1-5-21-1-2-3-1006")
	userData["AccountExpires"] = "2028-12-31T23:59:59Z"
	defer stubLUInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	input := UserInput{
		Name:                "expiring",
		AccountNeverExpires: false,
		AccountExpires:      "2028-12-31T23:59:59Z",
		Enabled:             true,
	}
	us, err := lc.Create(context.Background(), input, "P@ssw0rd!")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if us.AccountNeverExpires {
		t.Error("AccountNeverExpires should be false")
	}
}

// ---------------------------------------------------------------------------
// Read — happy path + EC-3 not_found + transport error
// ---------------------------------------------------------------------------

func TestLocalUserClient_Read_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	us, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if us == nil {
		t.Fatal("Read() returned nil for existing user")
	}
	if us.Name != "alice" {
		t.Errorf("Name = %q, want alice", us.Name)
	}
}

func TestLocalUserClient_Read_NotFound_ReturnsNilNil(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "not_found", "user was not found"), "", nil
	})()

	us, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-9999")
	if err != nil {
		t.Fatalf("Read() not_found must return nil error, got: %v", err)
	}
	if us != nil {
		t.Error("Read() not_found must return nil state (EC-3)")
	}
}

func TestLocalUserClient_Read_TransportError(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("connection refused")
	})()

	_, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-1001")
	if err == nil {
		t.Fatal("expected error for transport failure")
	}
}

// ---------------------------------------------------------------------------
// Update — happy path + not_found + permission_denied
// ---------------------------------------------------------------------------

func TestLocalUserClient_Update_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	updated := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	updated["Description"] = "updated desc"
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, updated), "", nil
	})()

	us, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001", UserInput{
		Name:        "alice",
		Description: "updated desc",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if us.Description != "updated desc" {
		t.Errorf("Description = %q", us.Description)
	}
}

func TestLocalUserClient_Update_AccountNeverExpires(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	_, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001", UserInput{
		Name:                "alice",
		AccountNeverExpires: true,
		Enabled:             true,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
}

func TestLocalUserClient_Update_WithAccountExpires(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	userData["AccountExpires"] = "2029-06-01T00:00:00Z"
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	_, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001", UserInput{
		Name:                "alice",
		AccountNeverExpires: false,
		AccountExpires:      "2029-06-01T00:00:00Z",
		Enabled:             true,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
}

func TestLocalUserClient_Update_NoExpiryChange(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	_, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001", UserInput{
		Name:                "alice",
		AccountNeverExpires: false,
		AccountExpires:      "", // no change
		Enabled:             true,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
}

func TestLocalUserClient_Update_PermissionDenied(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "permission_denied", "Access is denied"), "", nil
	})()

	_, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001", UserInput{Name: "alice"})
	if err == nil {
		t.Fatal("expected error for permission_denied")
	}
	if !IsLocalUserError(err, LocalUserErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Rename — happy path + EC-5 rename_conflict
// ---------------------------------------------------------------------------

func TestLocalUserClient_Rename_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, map[string]any{"renamed": true}), "", nil
	})()

	err := lc.Rename(context.Background(), "S-1-5-21-111-222-333-1001", "alice-new")
	if err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
}

func TestLocalUserClient_Rename_Conflict(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "rename_conflict", "name is not unique"), "", nil
	})()

	err := lc.Rename(context.Background(), "S-1-5-21-111-222-333-1001", "existing-name")
	if err == nil {
		t.Fatal("expected error for rename_conflict")
	}
	if !IsLocalUserError(err, LocalUserErrorRenameConflict) {
		t.Errorf("expected rename_conflict, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SetPassword — happy path + password_policy + plaintext guard
// ---------------------------------------------------------------------------

func TestLocalUserClient_SetPassword_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLUInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return luOK(t, map[string]any{"password_set": true}), "", nil
	})()

	err := lc.SetPassword(context.Background(), "S-1-5-21-111-222-333-1001", "N3wP@ss!")
	if err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
}

func TestLocalUserClient_SetPassword_PolicyViolation(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLUInput(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return luErr(t, "password_policy", "does not meet the minimum length"), "", nil
	})()

	err := lc.SetPassword(context.Background(), "S-1-5-21-111-222-333-1001", "short")
	if err == nil {
		t.Fatal("expected password_policy error")
	}
	if !IsLocalUserError(err, LocalUserErrorPasswordPolicy) {
		t.Errorf("expected password_policy, got: %v", err)
	}
}

func TestLocalUserClient_SetPassword_PlaintextNotInScript(t *testing.T) {
	_, lc := newLUClient(t)

	const secret = "S3cr3tPl@ntext!"
	defer stubLUInput(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		if strings.Contains(script, secret) {
			return "", "", errors.New("PASSWORD LEAKED INTO SCRIPT BODY")
		}
		// Check that the secret is in stdin but not the script
		if !strings.Contains(stdin, secret) {
			return "", "", errors.New("PASSWORD NOT IN STDIN")
		}
		return luOK(t, map[string]any{"password_set": true}), "", nil
	})()

	err := lc.SetPassword(context.Background(), "S-1-5-21-111-222-333-1001", secret)
	if err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Enable / Disable
// ---------------------------------------------------------------------------

func TestLocalUserClient_Enable_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, map[string]any{"enabled": true}), "", nil
	})()

	if err := lc.Enable(context.Background(), "S-1-5-21-111-222-333-1001"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
}

func TestLocalUserClient_Disable_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, map[string]any{"disabled": true}), "", nil
	})()

	if err := lc.Disable(context.Background(), "S-1-5-21-111-222-333-1001"); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
}

func TestLocalUserClient_Enable_PermissionDenied(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "permission_denied", "Access is denied"), "", nil
	})()

	err := lc.Enable(context.Background(), "S-1-5-21-111-222-333-1001")
	if !IsLocalUserError(err, LocalUserErrorPermission) {
		t.Errorf("expected permission_denied, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delete — happy path + EC-2 builtin RID guard + already-absent + invalid_name
// ---------------------------------------------------------------------------

func TestLocalUserClient_Delete_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, map[string]any{"deleted": true}), "", nil
	})()

	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestLocalUserClient_Delete_AlreadyAbsent(t *testing.T) {
	_, lc := newLUClient(t)

	// When not_found during delete, the script emits Emit-OK already_absent
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, map[string]any{"deleted": true, "note": "already_absent"}), "", nil
	})()

	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-9999")
	if err != nil {
		t.Fatalf("Delete already-absent must succeed, got: %v", err)
	}
}

func TestLocalUserClient_Delete_Builtin_RID500(t *testing.T) {
	_, lc := newLUClient(t)

	// Stub Read called inside Delete for built-in guard name resolution
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		userData := fakeUserData("Administrator", "S-1-5-21-111-222-333-500")
		return luOK(t, userData), "", nil
	})()

	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-500")
	if err == nil {
		t.Fatal("expected error for built-in RID 500")
	}
	if !IsLocalUserError(err, LocalUserErrorBuiltinAccount) {
		t.Errorf("expected builtin_account, got: %v", err)
	}
	// Error message must contain the SID and RID
	msg := err.Error()
	if !strings.Contains(msg, "500") {
		t.Errorf("error message missing RID: %q", msg)
	}
}

func TestLocalUserClient_Delete_Builtin_RID501(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, fakeUserData("Guest", "S-1-5-21-111-222-333-501")), "", nil
	})()

	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-501")
	if !IsLocalUserError(err, LocalUserErrorBuiltinAccount) {
		t.Errorf("expected builtin_account for RID 501, got: %v", err)
	}
}

func TestLocalUserClient_Delete_Builtin_RID503(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, fakeUserData("DefaultAccount", "S-1-5-21-111-222-333-503")), "", nil
	})()

	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-503")
	if !IsLocalUserError(err, LocalUserErrorBuiltinAccount) {
		t.Errorf("expected builtin_account for RID 503, got: %v", err)
	}
}

func TestLocalUserClient_Delete_Builtin_RID504(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, fakeUserData("WDAGUtilityAccount", "S-1-5-21-111-222-333-504")), "", nil
	})()

	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-504")
	if !IsLocalUserError(err, LocalUserErrorBuiltinAccount) {
		t.Errorf("expected builtin_account for RID 504, got: %v", err)
	}
}

func TestLocalUserClient_Delete_NonBuiltinRID_Proceeds(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, map[string]any{"deleted": true}), "", nil
	})()

	// RID 1001 is not a built-in account
	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("Delete non-builtin must succeed, got: %v", err)
	}
}

func TestLocalUserClient_Delete_InvalidName(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "invalid_name", "invalid.*name"), "", nil
	})()

	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-1099")
	if !IsLocalUserError(err, LocalUserErrorInvalidName) {
		t.Errorf("expected invalid_name, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ImportByName / ImportBySID
// ---------------------------------------------------------------------------

func TestLocalUserClient_ImportByName_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	us, err := lc.ImportByName(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ImportByName() error = %v", err)
	}
	if us.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", us.SID)
	}
}

func TestLocalUserClient_ImportByName_NotFound(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "not_found", "user was not found"), "", nil
	})()

	_, err := lc.ImportByName(context.Background(), "ghost")
	if err == nil {
		t.Fatal("expected not_found error")
	}
	if !IsLocalUserError(err, LocalUserErrorNotFound) {
		t.Errorf("expected not_found, got: %v", err)
	}
}

func TestLocalUserClient_ImportBySID_HappyPath(t *testing.T) {
	_, lc := newLUClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, userData), "", nil
	})()

	us, err := lc.ImportBySID(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("ImportBySID() error = %v", err)
	}
	if us.Name != "alice" {
		t.Errorf("Name = %q, want alice", us.Name)
	}
}

func TestLocalUserClient_ImportBySID_NotFound(t *testing.T) {
	_, lc := newLUClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "not_found", "SID was not found"), "", nil
	})()

	_, err := lc.ImportBySID(context.Background(), "S-1-5-21-999-999-999-9999")
	if !IsLocalUserError(err, LocalUserErrorNotFound) {
		t.Errorf("expected not_found, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ResolveLocalUserSID helper (local_user_helpers.go)
// ---------------------------------------------------------------------------

func TestResolveLocalUserSID_BySID(t *testing.T) {
	c := newLUTestClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLURun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		// The script must use -SID when input starts with "S-"
		if !strings.Contains(script, "-SID") {
			return "", "", errors.New("expected -SID param")
		}
		return luOK(t, userData), "", nil
	})()

	us, err := ResolveLocalUserSID(context.Background(), c, "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("ResolveLocalUserSID by SID error = %v", err)
	}
	if us.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", us.SID)
	}
}

func TestResolveLocalUserSID_ByName(t *testing.T) {
	c := newLUTestClient(t)

	userData := fakeUserData("alice", "S-1-5-21-111-222-333-1001")
	defer stubLURun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		// The script must use -Name when input does not start with "S-"
		if !strings.Contains(script, "-Name") {
			return "", "", errors.New("expected -Name param")
		}
		return luOK(t, userData), "", nil
	})()

	us, err := ResolveLocalUserSID(context.Background(), c, "alice")
	if err != nil {
		t.Fatalf("ResolveLocalUserSID by name error = %v", err)
	}
	if us.Name != "alice" {
		t.Errorf("Name = %q", us.Name)
	}
}

func TestResolveLocalUserSID_NotFound(t *testing.T) {
	c := newLUTestClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "not_found", "user was not found"), "", nil
	})()

	_, err := ResolveLocalUserSID(context.Background(), c, "ghost")
	if !IsLocalUserError(err, LocalUserErrorNotFound) {
		t.Errorf("expected not_found, got: %v", err)
	}
}

func TestResolveLocalUserSID_TransportError(t *testing.T) {
	c := newLUTestClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("network unreachable")
	})()

	_, err := ResolveLocalUserSID(context.Background(), c, "alice")
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown, got: %v", err)
	}
}

func TestResolveLocalUserSID_ContextCancelled(t *testing.T) {
	c := newLUTestClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer stubLURun(func(ctx context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", ctx.Err()
	})()

	_, err := ResolveLocalUserSID(ctx, c, "alice")
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown for cancelled context, got: %v", err)
	}
}

func TestResolveLocalUserSID_NoJSON(t *testing.T) {
	c := newLUTestClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "no json output here\n", "", nil
	})()

	_, err := ResolveLocalUserSID(context.Background(), c, "alice")
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown for no-JSON output, got: %v", err)
	}
}

func TestResolveLocalUserSID_InvalidJSON(t *testing.T) {
	c := newLUTestClient(t)

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{broken json\n", "", nil
	})()

	_, err := ResolveLocalUserSID(context.Background(), c, "alice")
	if !IsLocalUserError(err, LocalUserErrorUnknown) {
		t.Errorf("expected unknown for invalid JSON, got: %v", err)
	}
}
