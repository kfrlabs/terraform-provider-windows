// Package winclient — unit tests for LocalGroupClient.
//
// These tests stub the package-level runPowerShell seam to inject scripted
// stdout/stderr/error triples. They cover the documented edge cases from the
// windows_local_group spec:
//
//	EC-1  Group already exists at Create time    -> already_exists
//	EC-2  Delete built-in group (BUILTIN SID)    -> builtin_group hard error
//	EC-3  Group disappears outside Terraform     -> Read returns (nil, nil)
//	EC-4  Name casing drift                      -> GroupState.Name carries Windows casing
//	EC-5  Rename (Update with new name)          -> Rename-LocalGroup invoked
//	EC-6  Invalid name (server-side, defence-in-depth) -> invalid_name
//	EC-8  AccessDenied                           -> permission_denied
//	EC-10 Import by name vs by SID               -> ImportByName / ImportBySID
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func newLGTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:     "winlg01",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// stubLGRun replaces runPowerShell for the duration of a test and returns a
// restore function (must be deferred).
func stubLGRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runPowerShell
	runPowerShell = fn
	return func() { runPowerShell = prev }
}

// stubLGSequence stubs runPowerShell with a fixed ordered list of
// (stdout, stderr, err) triples, consumed in sequence.  After the last triple,
// every subsequent call repeats the last entry.
func stubLGSequence(triples ...[3]any) func() {
	i := 0
	return stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		tr := triples[i]
		if i < len(triples)-1 {
			i++
		}
		var e error
		if tr[2] != nil {
			e = tr[2].(error)
		}
		return tr[0].(string), tr[1].(string), e
	})
}

// lgOK emits a JSON ok-envelope with data.
func lgOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("lgOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// lgErr emits a JSON err-envelope with kind + message.
func lgErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("lgErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// fakeGroupData builds the JSON object returned by Get-LocalGroup | ConvertTo-Json.
func fakeGroupData(name, description, sid string) map[string]any {
	return map[string]any{
		"Name":        name,
		"Description": description,
		"SID": map[string]any{
			"Value": sid,
		},
	}
}

// -----------------------------------------------------------------------------
// LocalGroupError type tests
// -----------------------------------------------------------------------------

func TestLocalGroupError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying-winrm-error")
	e := NewLocalGroupError(LocalGroupErrorPermission, "access denied", cause,
		map[string]string{"host": "winlg01", "operation": "create"})
	if e.Unwrap() != cause {
		t.Error("Unwrap() did not return the underlying cause")
	}
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") {
		t.Errorf("Error() missing kind: %q", msg)
	}
	if !strings.Contains(msg, "access denied") {
		t.Errorf("Error() missing message: %q", msg)
	}
	if !strings.Contains(msg, "underlying-winrm-error") {
		t.Errorf("Error() missing cause: %q", msg)
	}

	// No-cause variant must not leak "<nil>".
	e2 := NewLocalGroupError(LocalGroupErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error() leaks <nil>: %q", e2.Error())
	}
}

func TestLocalGroupError_Is_And_IsLocalGroupError(t *testing.T) {
	e := NewLocalGroupError(LocalGroupErrorBuiltinGroup, "builtin", nil, nil)

	// errors.Is with matching sentinel
	if !errors.Is(e, ErrLocalGroupBuiltinGroup) {
		t.Error("errors.Is(ErrLocalGroupBuiltinGroup) should be true")
	}
	// errors.Is with non-matching sentinel
	if errors.Is(e, ErrLocalGroupNotFound) {
		t.Error("errors.Is across kinds must not match")
	}
	// IsLocalGroupError helper
	if !IsLocalGroupError(e, LocalGroupErrorBuiltinGroup) {
		t.Error("IsLocalGroupError() should be true for matching kind")
	}
	if IsLocalGroupError(errors.New("plain"), LocalGroupErrorBuiltinGroup) {
		t.Error("IsLocalGroupError() on plain error must be false")
	}
	// Is() against non-*LocalGroupError
	if e.Is(errors.New("plain")) {
		t.Error("Is() against non-LocalGroupError must be false")
	}
}

func TestLocalGroupError_Sentinels(t *testing.T) {
	sentinels := []*LocalGroupError{
		ErrLocalGroupNotFound,
		ErrLocalGroupAlreadyExists,
		ErrLocalGroupBuiltinGroup,
		ErrLocalGroupPermission,
		ErrLocalGroupNameConflict,
		ErrLocalGroupInvalidName,
		ErrLocalGroupUnknown,
	}
	kinds := []LocalGroupErrorKind{
		LocalGroupErrorNotFound,
		LocalGroupErrorAlreadyExists,
		LocalGroupErrorBuiltinGroup,
		LocalGroupErrorPermission,
		LocalGroupErrorNameConflict,
		LocalGroupErrorInvalidName,
		LocalGroupErrorUnknown,
	}
	for i, s := range sentinels {
		if s.Kind != kinds[i] {
			t.Errorf("sentinel[%d] kind = %q, want %q", i, s.Kind, kinds[i])
		}
	}
}

// -----------------------------------------------------------------------------
// mapLGKind — pure helper
// -----------------------------------------------------------------------------

func TestMapLGKind(t *testing.T) {
	cases := map[string]LocalGroupErrorKind{
		"not_found":         LocalGroupErrorNotFound,
		"already_exists":    LocalGroupErrorAlreadyExists,
		"builtin_group":     LocalGroupErrorBuiltinGroup,
		"permission_denied": LocalGroupErrorPermission,
		"name_conflict":     LocalGroupErrorNameConflict,
		"invalid_name":      LocalGroupErrorInvalidName,
		"unknown":           LocalGroupErrorUnknown,
		"":                  LocalGroupErrorUnknown,
		"totally_unknown":   LocalGroupErrorUnknown,
	}
	for in, want := range cases {
		if got := mapLGKind(in); got != want {
			t.Errorf("mapLGKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// parseGroupData — pure helper
// -----------------------------------------------------------------------------

func TestParseGroupData_HappyPath(t *testing.T) {
	data, _ := json.Marshal(fakeGroupData("AppAdmins", "App team admins", "S-1-5-21-111-222-333-1001"))
	gs, err := parseGroupData("test", json.RawMessage(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.Name != "AppAdmins" {
		t.Errorf("Name = %q, want AppAdmins", gs.Name)
	}
	if gs.Description != "App team admins" {
		t.Errorf("Description = %q", gs.Description)
	}
	if gs.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", gs.SID)
	}
}

func TestParseGroupData_InvalidJSON(t *testing.T) {
	_, err := parseGroupData("test", json.RawMessage(`{not valid json`))
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("invalid JSON should yield unknown error, got %v", err)
	}
}

func TestParseGroupData_EmptySID(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"Name":        "AppAdmins",
		"Description": "desc",
		"SID":         map[string]any{"Value": ""},
	})
	_, err := parseGroupData("test", json.RawMessage(data))
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("empty SID should yield unknown error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// runLGEnvelope — transport/envelope error paths
// -----------------------------------------------------------------------------

func TestRunLGEnvelope_ContextCancelled(t *testing.T) {
	restore := stubLGRun(func(ctx context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Read(ctx, "S-1-5-21-1-1-1-1001")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("cancelled ctx should yield unknown error, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "timed out or was cancelled") {
		t.Errorf("error message should mention cancellation: %v", err)
	}
}

func TestRunLGEnvelope_TransportError(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "stdout-junk", "stderr-junk", errors.New("winrm: tcp reset")
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Read(context.Background(), "S-1-5-21-1-1-1-1001")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("transport error should yield unknown, got %v", err)
	}
	var lge *LocalGroupError
	if !errors.As(err, &lge) {
		t.Fatal("expected *LocalGroupError")
	}
	if lge.Context["host"] != "winlg01" {
		t.Errorf("context[host] = %q, want winlg01", lge.Context["host"])
	}
}

func TestRunLGEnvelope_NoJSONOutput(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "WARNING: no envelope here\nsome text\n", "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Read(context.Background(), "S-1-5-21-1-1-1-1001")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("missing JSON envelope should yield unknown, got %v", err)
	}
}

func TestRunLGEnvelope_MalformedJSON(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{not-valid-json\n", "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Read(context.Background(), "S-1-5-21-1-1-1-1001")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("malformed JSON envelope should yield unknown, got %v", err)
	}
}

func TestRunLGEnvelope_ClassifiedError_Permission(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Read(context.Background(), "S-1-5-21-1-1-1-1001")
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Create — happy path, EC-1 (already_exists), EC-8 (permission), EC-6 (invalid_name)
// -----------------------------------------------------------------------------

func TestLocalGroupCreate_HappyPath(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("AppAdmins", "Application admins", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Create(context.Background(), GroupInput{Name: "AppAdmins", Description: "Application admins"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.Name != "AppAdmins" {
		t.Errorf("Name = %q, want AppAdmins", gs.Name)
	}
	if gs.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", gs.SID)
	}
	if gs.Description != "Application admins" {
		t.Errorf("Description = %q", gs.Description)
	}
}

func TestLocalGroupCreate_AlreadyExists_EC1(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "already_exists", "local group 'AppAdmins' already exists (SID: S-1-5-21-111-222-333-1001)"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Create(context.Background(), GroupInput{Name: "AppAdmins"})
	if !IsLocalGroupError(err, LocalGroupErrorAlreadyExists) {
		t.Errorf("EC-1 expected already_exists, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "already_exists") {
		t.Errorf("error message should mention already_exists: %v", err)
	}
}

func TestLocalGroupCreate_PermissionDenied_EC8(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied; Local Administrator required"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Create(context.Background(), GroupInput{Name: "AppAdmins"})
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("EC-8 expected permission_denied, got %v", err)
	}
}

func TestLocalGroupCreate_InvalidName_EC6(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "invalid_name", "Group name contains forbidden characters"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Create(context.Background(), GroupInput{Name: "Bad/Name"})
	if !IsLocalGroupError(err, LocalGroupErrorInvalidName) {
		t.Errorf("EC-6 expected invalid_name, got %v", err)
	}
}

func TestLocalGroupCreate_EmptyDescription(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("EmptyDesc", "", "S-1-5-21-1-2-3-999")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Create(context.Background(), GroupInput{Name: "EmptyDesc", Description: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.Description != "" {
		t.Errorf("Description = %q, want empty", gs.Description)
	}
}

// -----------------------------------------------------------------------------
// Read — happy path, EC-3 (not found → nil, nil), EC-8 (permission)
// -----------------------------------------------------------------------------

func TestLocalGroupRead_HappyPath(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("AppAdmins", "desc", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs == nil {
		t.Fatal("expected non-nil GroupState")
	}
	if gs.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", gs.SID)
	}
	if gs.Name != "AppAdmins" {
		t.Errorf("Name = %q", gs.Name)
	}
}

func TestLocalGroupRead_GroupNotFound_EC3(t *testing.T) {
	// EC-3: GroupNotFound → (nil, nil) — not an error.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "not_found", "the group was not found"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-9999")
	if err != nil {
		t.Errorf("EC-3 Read should return (nil, nil) on not_found, got err=%v", err)
	}
	if gs != nil {
		t.Errorf("EC-3 Read should return nil state on not_found, got %+v", gs)
	}
}

func TestLocalGroupRead_PermissionDenied_EC8(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-1001")
	if err == nil {
		t.Fatal("EC-8 expected permission_denied error")
	}
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
	if gs != nil {
		t.Error("on error, GroupState should be nil")
	}
}

func TestLocalGroupRead_WindowsCasingPreserved_EC4(t *testing.T) {
	// EC-4: Windows returns "AppAdmins" even if we stored "appadmins".
	// The GroupState carries the Windows casing; provider layer applies EqualFold.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("AppAdmins", "desc", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// GroupState carries Windows casing — provider layer applies EqualFold.
	if gs.Name != "AppAdmins" {
		t.Errorf("Name should carry Windows casing AppAdmins, got %q", gs.Name)
	}
}

// -----------------------------------------------------------------------------
// Update — happy path, rename (EC-5), name conflict (EC-5), description change
// -----------------------------------------------------------------------------

func TestLocalGroupUpdate_HappyPath_RenameAndDescription(t *testing.T) {
	// The update PS script reads, renames, sets description, returns final state.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("NewName", "New Description", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001",
		GroupInput{Name: "NewName", Description: "New Description"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.Name != "NewName" {
		t.Errorf("Name = %q, want NewName", gs.Name)
	}
	if gs.Description != "New Description" {
		t.Errorf("Description = %q, want 'New Description'", gs.Description)
	}
	// SID must be unchanged by rename.
	if gs.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID changed unexpectedly: %q", gs.SID)
	}
}

func TestLocalGroupUpdate_DescriptionOnly(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("AppAdmins", "Updated description", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001",
		GroupInput{Name: "AppAdmins", Description: "Updated description"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.Description != "Updated description" {
		t.Errorf("Description = %q", gs.Description)
	}
}

func TestLocalGroupUpdate_NameConflict_EC5(t *testing.T) {
	// EC-5: new name already taken by another group.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "name_conflict", "group name 'TakenName' is not unique"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001",
		GroupInput{Name: "TakenName", Description: ""})
	if !IsLocalGroupError(err, LocalGroupErrorNameConflict) {
		t.Errorf("EC-5 expected name_conflict, got %v", err)
	}
}

func TestLocalGroupUpdate_PermissionDenied_EC8(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.Update(context.Background(), "S-1-5-21-111-222-333-1001",
		GroupInput{Name: "AppAdmins", Description: "desc"})
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("EC-8 expected permission_denied on update, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Delete — happy path, EC-2 (BUILTIN guard), idempotent (already gone)
// -----------------------------------------------------------------------------

func TestLocalGroupDelete_HappyPath(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Errorf("unexpected error on delete: %v", err)
	}
}

func TestLocalGroupDelete_BuiltinGuard_EC2(t *testing.T) {
	// EC-2: any SID starting with S-1-5-32- must be refused before PS is called.
	// The builtin guard in Delete() may call Read() to get the group name —
	// provide a response for that.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		// This covers the Read call inside Delete for the name lookup.
		return lgOK(t, fakeGroupData("Administrators", "", "S-1-5-32-544")), "", nil
	})
	defer restore()

	builtinSIDs := []string{
		"S-1-5-32-544", // Administrators
		"S-1-5-32-545", // Users
		"S-1-5-32-546", // Guests
		"S-1-5-32-568", // IIS_IUSRS
	}

	lc := NewLocalGroupClient(newLGTestClient(t))
	for _, sid := range builtinSIDs {
		err := lc.Delete(context.Background(), sid)
		if !IsLocalGroupError(err, LocalGroupErrorBuiltinGroup) {
			t.Errorf("EC-2 expected builtin_group for %s, got %v", sid, err)
		}
		var lge *LocalGroupError
		if errors.As(err, &lge) {
			if !strings.Contains(lge.Message, "cannot destroy") {
				t.Errorf("EC-2 error message should mention 'cannot destroy': %q", lge.Message)
			}
		}
	}
}

func TestLocalGroupDelete_NonBuiltinSIDNotBlocked(t *testing.T) {
	// A regular SID (not S-1-5-32-*) must go through to PowerShell.
	calls := 0
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return lgOK(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Errorf("regular SID delete should succeed: %v", err)
	}
	if calls == 0 {
		t.Error("PowerShell should be invoked for non-builtin SID")
	}
}

func TestLocalGroupDelete_AlreadyGone_Idempotent(t *testing.T) {
	// EC-3 meets Delete: Remove-LocalGroup returns not_found → success (already_absent).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, map[string]any{"deleted": true, "note": "already_absent"}), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Errorf("idempotent delete should not error: %v", err)
	}
}

func TestLocalGroupDelete_PermissionDenied_EC8(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	err := lc.Delete(context.Background(), "S-1-5-21-111-222-333-1001")
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("EC-8 expected permission_denied on delete, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Delete + Read integration: builtin guard uses Read for name in error message
// -----------------------------------------------------------------------------

func TestLocalGroupDelete_BuiltinGuard_ReadFailFallback(t *testing.T) {
	// If the Read inside Delete fails (transport error), the SID is used as name.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		// Simulate a transport error on the Read call inside Delete.
		return "", "", errors.New("winrm: connection refused")
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	err := lc.Delete(context.Background(), "S-1-5-32-544")
	if !IsLocalGroupError(err, LocalGroupErrorBuiltinGroup) {
		t.Errorf("EC-2 expected builtin_group even when Read fails, got %v", err)
	}
	// Error message should contain the SID when name look-up failed.
	if err != nil && !strings.Contains(err.Error(), "S-1-5-32-544") {
		t.Errorf("error should contain the SID: %v", err)
	}
}

// -----------------------------------------------------------------------------
// ImportByName — EC-10 (name-based import)
// -----------------------------------------------------------------------------

func TestLocalGroupImportByName_HappyPath_EC10(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("AppAdmins", "Application admins", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.ImportByName(context.Background(), "AppAdmins")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs == nil {
		t.Fatal("expected non-nil GroupState")
	}
	if gs.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", gs.SID)
	}
}

func TestLocalGroupImportByName_NotFound_EC10(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "not_found", "the group was not found"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.ImportByName(context.Background(), "NonExistentGroup")
	if !IsLocalGroupError(err, LocalGroupErrorNotFound) {
		t.Errorf("EC-10 expected not_found, got %v", err)
	}
}

func TestLocalGroupImportByName_PermissionDenied_EC8(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.ImportByName(context.Background(), "AppAdmins")
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("EC-8 expected permission_denied on ImportByName, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// ImportBySID — EC-10 (SID-based import)
// -----------------------------------------------------------------------------

func TestLocalGroupImportBySID_HappyPath_EC10(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("AppAdmins", "desc", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	gs, err := lc.ImportBySID(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.Name != "AppAdmins" {
		t.Errorf("Name = %q", gs.Name)
	}
	if gs.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", gs.SID)
	}
}

func TestLocalGroupImportBySID_NotFound_EC10(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "not_found", "no group with SID S-1-5-21-999"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.ImportBySID(context.Background(), "S-1-5-21-999-1")
	if !IsLocalGroupError(err, LocalGroupErrorNotFound) {
		t.Errorf("EC-10 expected not_found, got %v", err)
	}
}

func TestLocalGroupImportBySID_PermissionDenied_EC8(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	lc := NewLocalGroupClient(newLGTestClient(t))
	_, err := lc.ImportBySID(context.Background(), "S-1-5-21-111-222-333-1001")
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("EC-8 expected permission_denied on ImportBySID, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// psQuote reachable from local group test (same package, defined in service.go)
// -----------------------------------------------------------------------------

func TestPsQuoteFromLGTest(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "''"},
		{"normal", "'normal'"},
		{"it's tricky", "'it''s tricky'"},
		{"double''quote", "'double''''quote'"},
	}
	for _, tc := range cases {
		if got := psQuote(tc.in); got != tc.want {
			t.Errorf("psQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
