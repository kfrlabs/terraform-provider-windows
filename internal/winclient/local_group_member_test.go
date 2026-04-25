// Package winclient — unit tests for LocalGroupMemberClient.
//
// These tests stub the package-level runPowerShell seam to inject scripted
// stdout/stderr/error triples, following the same pattern as
// local_group_client_impl_test.go.
//
// Edge cases covered (aligned with spec EC-* identifiers):
//
//	EC-1  Duplicate membership at Create        → ErrLocalGroupMemberAlreadyExists
//	EC-2  Group not found at Create             → ErrLocalGroupMemberGroupNotFound
//	EC-3  Member identity unresolvable          → ErrLocalGroupMemberUnresolvable
//	EC-4  Drift: membership removed externally  → Get returns (nil, nil)
//	EC-5  Drift: group deleted externally       → List/Get returns GroupNotFound error
//	EC-6  Orphaned AD SID — WMI fallback (tier2)
//	EC-6  Orphaned AD SID — net localgroup fallback (tier3)
//	EC-6  All fallbacks fail → empty slice, no error
//	EC-7  SID case-insensitive match in Get
//	EC-8  Permission denied on Add
//	      resolveMemberSID: 5 input formats (DOMAIN\u, MACHINE\u, u, u@d, S-1-5-…)
//	      Remove: success, idempotent (member/group not found), permission denied
//	      normalizePrincipalSource: all enum values including integer forms
//	      mapLGMKind: all known + unknown strings
//	      LocalGroupMemberError: Error, Unwrap, Is, New, IsLocalGroupMemberError, sentinels
//	      runLGMEnvelope: context cancellation, transport error, no JSON, malformed JSON
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// lgm helpers (supplement helpers from local_group_client_impl_test.go)
// ---------------------------------------------------------------------------

// lgmNewClient creates a LocalGroupMemberClient wrapping the shared LG test client.
func lgmNewClient(t *testing.T) *LocalGroupMemberClient {
	t.Helper()
	return NewLocalGroupMemberClient(newLGTestClient(t))
}

// lgmListRespData builds the "data" payload for a List response.
// members is a slice of map[string]any with keys SID, Name, PrincipalSource.
func lgmListRespData(tier string, members []map[string]any) map[string]any {
	if members == nil {
		members = []map[string]any{}
	}
	return map[string]any{
		"tier":    tier,
		"members": members,
	}
}

// lgmMemberEntry builds a single member map for lgmListRespData.
func lgmMemberEntry(sid, name, source string) map[string]any {
	return map[string]any{
		"SID":             sid,
		"Name":            name,
		"PrincipalSource": source,
	}
}

// lgmSIDRespData builds the data payload for resolveMemberSID response.
func lgmSIDRespData(sid string) map[string]any {
	return map[string]any{"sid": sid}
}

// lgmAddedRespData builds the data payload for addMember response.
func lgmAddedRespData() map[string]any {
	return map[string]any{"added": true}
}

// lgmRemovedRespData builds the data payload for Remove response.
func lgmRemovedRespData() map[string]any {
	return map[string]any{"removed": true}
}

// ---------------------------------------------------------------------------
// LocalGroupMemberError — type tests
// ---------------------------------------------------------------------------

func TestLocalGroupMemberError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying-winrm-error")
	e := NewLocalGroupMemberError(
		LocalGroupMemberErrorPermission,
		"access denied",
		cause,
		map[string]string{"host": "win01", "operation": "add"},
	)
	if e.Unwrap() != cause {
		t.Error("Unwrap() did not return underlying cause")
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
	e2 := NewLocalGroupMemberError(LocalGroupMemberErrorGroupNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error() leaks <nil>: %q", e2.Error())
	}
}

func TestLocalGroupMemberError_Is_And_IsLocalGroupMemberError(t *testing.T) {
	e := NewLocalGroupMemberError(LocalGroupMemberErrorAlreadyExists, "dup", nil, nil)

	// errors.Is with matching sentinel.
	if !errors.Is(e, ErrLocalGroupMemberAlreadyExists) {
		t.Error("errors.Is(ErrLocalGroupMemberAlreadyExists) should be true")
	}
	// errors.Is with non-matching sentinel.
	if errors.Is(e, ErrLocalGroupMemberGroupNotFound) {
		t.Error("errors.Is across kinds must not match")
	}
	// IsLocalGroupMemberError helper.
	if !IsLocalGroupMemberError(e, LocalGroupMemberErrorAlreadyExists) {
		t.Error("IsLocalGroupMemberError() should be true for matching kind")
	}
	if IsLocalGroupMemberError(errors.New("plain"), LocalGroupMemberErrorAlreadyExists) {
		t.Error("IsLocalGroupMemberError() on plain error must be false")
	}
	// Is() against non-*LocalGroupMemberError.
	if e.Is(errors.New("plain")) {
		t.Error("Is() against non-LocalGroupMemberError must be false")
	}
}

func TestLocalGroupMemberError_Sentinels(t *testing.T) {
	sentinels := []*LocalGroupMemberError{
		ErrLocalGroupMemberGroupNotFound,
		ErrLocalGroupMemberAlreadyExists,
		ErrLocalGroupMemberUnresolvable,
		ErrLocalGroupMemberNotFound,
		ErrLocalGroupMemberPermission,
		ErrLocalGroupMemberUnknown,
	}
	kinds := []LocalGroupMemberErrorKind{
		LocalGroupMemberErrorGroupNotFound,
		LocalGroupMemberErrorAlreadyExists,
		LocalGroupMemberErrorUnresolvable,
		LocalGroupMemberErrorNotFound,
		LocalGroupMemberErrorPermission,
		LocalGroupMemberErrorUnknown,
	}
	for i, s := range sentinels {
		if s.Kind != kinds[i] {
			t.Errorf("sentinel[%d] kind = %q, want %q", i, s.Kind, kinds[i])
		}
	}
}

// ---------------------------------------------------------------------------
// mapLGMKind — pure helper
// ---------------------------------------------------------------------------

func TestMapLGMKind(t *testing.T) {
	cases := map[string]LocalGroupMemberErrorKind{
		"group_not_found":       LocalGroupMemberErrorGroupNotFound,
		"member_already_exists": LocalGroupMemberErrorAlreadyExists,
		"member_unresolvable":   LocalGroupMemberErrorUnresolvable,
		"member_not_found":      LocalGroupMemberErrorNotFound,
		"permission_denied":     LocalGroupMemberErrorPermission,
		"unknown":               LocalGroupMemberErrorUnknown,
		"":                      LocalGroupMemberErrorUnknown,
		"totally_unknown_kind":  LocalGroupMemberErrorUnknown,
	}
	for in, want := range cases {
		if got := mapLGMKind(in); got != want {
			t.Errorf("mapLGMKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// normalizePrincipalSource — pure helper
// ---------------------------------------------------------------------------

func TestNormalizePrincipalSource(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Local", "Local"},
		{"1", "Local"},
		{"ActiveDirectory", "ActiveDirectory"},
		{"2", "ActiveDirectory"},
		{"MicrosoftAccount", "MicrosoftAccount"},
		{"4", "MicrosoftAccount"},
		{"AzureAD", "AzureAD"},
		{"8", "AzureAD"},
		{"Unknown", "Unknown"},
		{"0", "Unknown"},
		{"", "Unknown"},
		{"garbage", "Unknown"},
	}
	for _, tc := range cases {
		got := normalizePrincipalSource(tc.in)
		if got != tc.want {
			t.Errorf("normalizePrincipalSource(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// runLGMEnvelope — transport/envelope error paths
// ---------------------------------------------------------------------------

func TestRunLGMEnvelope_ContextCancelled(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mc := lgmNewClient(t)
	err := mc.Remove(ctx, "S-1-5-32-544", "S-1-5-21-1-2-3-500")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnknown) {
		t.Errorf("cancelled ctx should yield unknown error, got %v", err)
	}
	if !strings.Contains(err.Error(), "timed out or was cancelled") {
		t.Errorf("error should mention cancellation: %v", err)
	}
}

func TestRunLGMEnvelope_TransportError(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "junk", "stderr-junk", errors.New("winrm: tcp reset")
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-544", "S-1-5-21-1-2-3-500")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnknown) {
		t.Errorf("transport error should yield unknown, got %v", err)
	}
	var lgme *LocalGroupMemberError
	if !errors.As(err, &lgme) {
		t.Fatal("expected *LocalGroupMemberError")
	}
	if lgme.Context["host"] != "winlg01" {
		t.Errorf("context[host] = %q, want winlg01", lgme.Context["host"])
	}
}

func TestRunLGMEnvelope_NoJSONOutput(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "no JSON here\nplain text\n", "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-544", "S-1-5-21-1-2-3-500")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnknown) {
		t.Errorf("no JSON should yield unknown, got %v", err)
	}
}

func TestRunLGMEnvelope_MalformedJSON(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{not-valid-json\n", "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-544", "S-1-5-21-1-2-3-500")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnknown) {
		t.Errorf("malformed JSON should yield unknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// List — tier1 (primary), tier2 (WMI), tier3 (net localgroup), all-failed
// ---------------------------------------------------------------------------

func TestLGMList_Primary_HappyPath(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("primary", []map[string]any{
			lgmMemberEntry("S-1-5-21-100-200-300-500", "DOMAIN\\alice", "ActiveDirectory"),
			lgmMemberEntry("S-1-5-21-100-200-300-501", "WIN01\\bob", "Local"),
		})), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	members, err := mc.List(context.Background(), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
	if members[0].MemberSID != "S-1-5-21-100-200-300-500" {
		t.Errorf("members[0].MemberSID = %q", members[0].MemberSID)
	}
	if members[0].MemberName != "DOMAIN\\alice" {
		t.Errorf("members[0].MemberName = %q", members[0].MemberName)
	}
	if members[0].PrincipalSource != "ActiveDirectory" {
		t.Errorf("members[0].PrincipalSource = %q", members[0].PrincipalSource)
	}
	if members[0].GroupSID != "S-1-5-32-544" {
		t.Errorf("members[0].GroupSID = %q, want S-1-5-32-544", members[0].GroupSID)
	}
}

func TestLGMList_Empty(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("primary", nil)), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	members, err := mc.List(context.Background(), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("expected 0 members, got %d", len(members))
	}
}

func TestLGMList_WMIFallback_EC6(t *testing.T) {
	// EC-6: orphaned SID — tier2 WMI fallback.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("wmi", []map[string]any{
			lgmMemberEntry("S-1-5-21-ORPHAN-999", "S-1-5-21-ORPHAN-999", "Unknown"),
		})), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	members, err := mc.List(context.Background(), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
	if members[0].MemberSID != "S-1-5-21-ORPHAN-999" {
		t.Errorf("expected orphan SID, got %q", members[0].MemberSID)
	}
	if members[0].PrincipalSource != "Unknown" {
		t.Errorf("orphan member source = %q, want Unknown", members[0].PrincipalSource)
	}
}

func TestLGMList_NetLocalGroupFallback_EC6(t *testing.T) {
	// EC-6: tier3 net localgroup fallback.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("net_localgroup", []map[string]any{
			lgmMemberEntry("S-1-5-21-100-200-300-500", "DOMAIN\\charlie", "Unknown"),
		})), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	members, err := mc.List(context.Background(), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("expected 1 member, got %d", len(members))
	}
}

func TestLGMList_AllFallbacksFail_EC6(t *testing.T) {
	// EC-6: all tiers fail → empty slice, no error (conservative, ADR-LGM-5).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("all_failed", nil)), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	members, err := mc.List(context.Background(), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("all-failed should return ([], nil), got err=%v", err)
	}
	if len(members) != 0 {
		t.Errorf("all-failed should return empty slice, got %d members", len(members))
	}
}

func TestLGMList_GroupNotFound_EC5(t *testing.T) {
	// EC-5: group SID not found → ErrLocalGroupMemberGroupNotFound.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "group_not_found", "group S-1-5-32-9999 was not found"), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.List(context.Background(), "S-1-5-32-9999")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorGroupNotFound) {
		t.Errorf("EC-5: expected group_not_found, got %v", err)
	}
}

func TestLGMList_PermissionDenied(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.List(context.Background(), "S-1-5-32-544")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

func TestLGMList_MalformedData(t *testing.T) {
	// Data field is present but not a valid lgmListData object.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		b, _ := json.Marshal(map[string]any{"ok": true, "data": "not an object"})
		return string(b) + "\n", "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.List(context.Background(), "S-1-5-32-544")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnknown) {
		t.Errorf("malformed data should yield unknown error, got %v", err)
	}
}

func TestLGMList_MemberNameFallsBackToSID(t *testing.T) {
	// When Name is empty, MemberName should fall back to MemberSID (EC-6 orphan).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("primary", []map[string]any{
			{"SID": "S-1-5-21-ORPHAN-999", "Name": "", "PrincipalSource": "Unknown"},
		})), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	members, err := mc.List(context.Background(), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(members) == 0 {
		t.Fatal("expected at least 1 member")
	}
	if members[0].MemberName != "S-1-5-21-ORPHAN-999" {
		t.Errorf("empty Name should fall back to SID, got MemberName=%q", members[0].MemberName)
	}
}

// ---------------------------------------------------------------------------
// Get — happy path, EC-4 drift, EC-5 group gone, EC-7 case-insensitive SID
// ---------------------------------------------------------------------------

func TestLGMGet_HappyPath(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("primary", []map[string]any{
			lgmMemberEntry("S-1-5-21-100-200-300-500", "DOMAIN\\alice", "ActiveDirectory"),
		})), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Get(context.Background(), "S-1-5-32-544", "S-1-5-21-100-200-300-500")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.MemberSID != "S-1-5-21-100-200-300-500" {
		t.Errorf("MemberSID = %q", state.MemberSID)
	}
	if state.PrincipalSource != "ActiveDirectory" {
		t.Errorf("PrincipalSource = %q", state.PrincipalSource)
	}
}

func TestLGMGet_MemberAbsent_EC4(t *testing.T) {
	// EC-4: membership removed out-of-band → Get returns (nil, nil).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("primary", []map[string]any{
			lgmMemberEntry("S-1-5-21-100-200-300-502", "DOMAIN\\other", "ActiveDirectory"),
		})), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Get(context.Background(), "S-1-5-32-544", "S-1-5-21-100-200-300-500")
	if err != nil {
		t.Fatalf("EC-4: expected (nil, nil), got err=%v", err)
	}
	if state != nil {
		t.Errorf("EC-4: expected nil state (member absent), got %+v", state)
	}
}

func TestLGMGet_GroupNotFound_EC5(t *testing.T) {
	// EC-5: group deleted → Get returns (nil, ErrLocalGroupMemberGroupNotFound).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "group_not_found", "group not found"), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Get(context.Background(), "S-1-5-32-9999", "S-1-5-21-100-200-300-500")
	if err == nil {
		t.Fatal("EC-5: expected error, got nil")
	}
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorGroupNotFound) {
		t.Errorf("EC-5: expected group_not_found, got %v", err)
	}
	if state != nil {
		t.Error("EC-5: state must be nil when group not found")
	}
}

func TestLGMGet_SIDCaseInsensitive_EC7(t *testing.T) {
	// EC-7: SID comparison must be case-insensitive (strings.EqualFold).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmListRespData("primary", []map[string]any{
			lgmMemberEntry("S-1-5-21-100-200-300-500", "DOMAIN\\alice", "ActiveDirectory"),
		})), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	// Look up with lowercase SID — should still match via EqualFold.
	state, err := mc.Get(context.Background(), "S-1-5-32-544", "s-1-5-21-100-200-300-500")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("EC-7: case-insensitive SID match failed — expected non-nil state")
	}
}

// ---------------------------------------------------------------------------
// resolveMemberSID — 5 identity formats + shortcut for S- prefix
// ---------------------------------------------------------------------------

func TestResolveMemberSID_SkipIfSIDPrefix(t *testing.T) {
	// If member starts with "S-", no PS call — returned as-is.
	callCount := 0
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		callCount++
		return lgOK(t, lgmSIDRespData("S-1-5-21-100-200-300-500")), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	sid, err := mc.resolveMemberSID(context.Background(), "S-1-5-21-100-200-300-500")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "S-1-5-21-100-200-300-500" {
		t.Errorf("SID = %q, want S-1-5-21-100-200-300-500", sid)
	}
	if callCount != 0 {
		t.Errorf("S- prefix should bypass PS call, but runPowerShell was called %d times", callCount)
	}
}

func TestResolveMemberSID_DomainBackslash(t *testing.T) {
	// DOMAIN\user format.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmSIDRespData("S-1-5-21-100-200-300-501")), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	sid, err := mc.resolveMemberSID(context.Background(), "DOMAIN\\jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "S-1-5-21-100-200-300-501" {
		t.Errorf("SID = %q", sid)
	}
}

func TestResolveMemberSID_MachineBackslash(t *testing.T) {
	// MACHINE\user format.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmSIDRespData("S-1-5-21-100-200-300-502")), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	sid, err := mc.resolveMemberSID(context.Background(), "WIN01\\localuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "S-1-5-21-100-200-300-502" {
		t.Errorf("SID = %q", sid)
	}
}

func TestResolveMemberSID_BareUsername(t *testing.T) {
	// bare "username" format (implicit local machine).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmSIDRespData("S-1-5-21-100-200-300-503")), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	sid, err := mc.resolveMemberSID(context.Background(), "localadmin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "S-1-5-21-100-200-300-503" {
		t.Errorf("SID = %q", sid)
	}
}

func TestResolveMemberSID_UPN(t *testing.T) {
	// user@domain.tld format.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmSIDRespData("S-1-5-21-100-200-300-504")), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	sid, err := mc.resolveMemberSID(context.Background(), "alice@corp.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != "S-1-5-21-100-200-300-504" {
		t.Errorf("SID = %q", sid)
	}
}

func TestResolveMemberSID_Unresolvable_Local_EC3(t *testing.T) {
	// EC-3: member unresolvable (local sub_type).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		b, _ := json.Marshal(map[string]any{
			"ok":      false,
			"kind":    "member_unresolvable",
			"message": "The user does not exist",
			"context": map[string]string{"member": "nosuchuser", "sub_type": "local"},
		})
		return string(b) + "\n", "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.resolveMemberSID(context.Background(), "nosuchuser")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnresolvable) {
		t.Errorf("EC-3: expected member_unresolvable, got %v", err)
	}
}

func TestResolveMemberSID_Unresolvable_Domain_EC10(t *testing.T) {
	// EC-10: member unresolvable (domain sub_type).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		b, _ := json.Marshal(map[string]any{
			"ok":      false,
			"kind":    "member_unresolvable",
			"message": "The specified domain either does not exist or could not be contacted",
			"context": map[string]string{"member": "UNREACHABLE\\jdoe", "sub_type": "domain"},
		})
		return string(b) + "\n", "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.resolveMemberSID(context.Background(), "UNREACHABLE\\jdoe")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnresolvable) {
		t.Errorf("EC-10: expected member_unresolvable, got %v", err)
	}
	var lgme *LocalGroupMemberError
	if errors.As(err, &lgme) {
		if lgme.Context["sub_type"] != "domain" {
			t.Errorf("EC-10: sub_type = %q, want domain", lgme.Context["sub_type"])
		}
	}
}

func TestResolveMemberSID_UnexpectedDataShape(t *testing.T) {
	// PS returns OK but data.sid is missing.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		b, _ := json.Marshal(map[string]any{"ok": true, "data": map[string]any{"not_sid": "value"}})
		return string(b) + "\n", "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.resolveMemberSID(context.Background(), "someuser")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnknown) {
		t.Errorf("missing sid field should yield unknown error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Remove — success, idempotent (member not found, group not found), permission
// ---------------------------------------------------------------------------

func TestLGMRemove_Success(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmRemovedRespData()), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-544", "S-1-5-21-100-200-300-500")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLGMRemove_MemberNotFound_Idempotent_EC4(t *testing.T) {
	// EC-4: PowerShell emits Emit-OK with note=member_not_found (idempotent).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, map[string]any{"removed": true, "note": "member_not_found"}), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-544", "S-1-5-21-100-200-300-500")
	if err != nil {
		t.Errorf("EC-4: remove of absent member should succeed, got %v", err)
	}
}

func TestLGMRemove_GroupNotFound_Idempotent_EC5(t *testing.T) {
	// EC-5: PowerShell emits Emit-OK with note=group_not_found (idempotent).
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, map[string]any{"removed": true, "note": "group_not_found"}), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-9999", "S-1-5-21-100-200-300-500")
	if err != nil {
		t.Errorf("EC-5: remove from absent group should succeed, got %v", err)
	}
}

func TestLGMRemove_OrphanedSID_EC6(t *testing.T) {
	// EC-6: orphaned AD SID — Remove uses SID string directly so it succeeds.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, lgmRemovedRespData()), "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-544", "S-1-5-21-ORPHAN-999")
	if err != nil {
		t.Errorf("EC-6: orphaned SID remove should succeed, got %v", err)
	}
}

func TestLGMRemove_PermissionDenied_EC8(t *testing.T) {
	// EC-8: permission denied on remove.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		b, _ := json.Marshal(map[string]any{
			"ok":      false,
			"kind":    "permission_denied",
			"message": "Access is denied",
			"context": map[string]string{"group_sid": "S-1-5-32-544", "operation": "remove"},
		})
		return string(b) + "\n", "", nil
	})
	defer restore()

	mc := lgmNewClient(t)
	err := mc.Remove(context.Background(), "S-1-5-32-544", "S-1-5-21-100-200-300-500")
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorPermission) {
		t.Errorf("EC-8: expected permission_denied, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Add — success, EC-1 (duplicate), EC-2 (group not found during List),
//       EC-3 (unresolvable), EC-8 (permission), member-as-SID bypass,
//       nil-Get fallback, principal source normalisation
// ---------------------------------------------------------------------------

// lgmAddSuccessSeq returns stub triples for a successful Add with a non-SID member:
//
//	call 1: resolveMemberSID → sid
//	call 2: List (pre-flight) → empty
//	call 3: addMember → {added: true}
//	call 4: Get → List → member entry
func lgmAddSuccessSeq(t *testing.T, memberSID, memberName, source string) [][3]any {
	t.Helper()
	return [][3]any{
		{lgOK(t, lgmSIDRespData(memberSID)), "", nil},
		{lgOK(t, lgmListRespData("primary", nil)), "", nil},
		{lgOK(t, lgmAddedRespData()), "", nil},
		{lgOK(t, lgmListRespData("primary", []map[string]any{lgmMemberEntry(memberSID, memberName, source)})), "", nil},
	}
}

func TestLGMAdd_HappyPath_DomainUser(t *testing.T) {
	const memberSID = "S-1-5-21-100-200-300-500"
	restore := stubLGSequence(lgmAddSuccessSeq(t, memberSID, "DOMAIN\\alice", "ActiveDirectory")...)
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "DOMAIN\\alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.MemberSID != memberSID {
		t.Errorf("MemberSID = %q, want %q", state.MemberSID, memberSID)
	}
	if state.MemberName != "DOMAIN\\alice" {
		t.Errorf("MemberName = %q", state.MemberName)
	}
	if state.PrincipalSource != "ActiveDirectory" {
		t.Errorf("PrincipalSource = %q", state.PrincipalSource)
	}
	if state.GroupSID != "S-1-5-32-544" {
		t.Errorf("GroupSID = %q", state.GroupSID)
	}
}

func TestLGMAdd_HappyPath_SIDInputBypass(t *testing.T) {
	// When member starts with "S-", resolveMemberSID skips PS → only 3 PS calls.
	const memberSID = "S-1-5-21-100-200-300-500"
	seq := [][3]any{
		// No resolveMemberSID call (SID bypass).
		{lgOK(t, lgmListRespData("primary", nil)), "", nil},
		{lgOK(t, lgmAddedRespData()), "", nil},
		{lgOK(t, lgmListRespData("primary", []map[string]any{lgmMemberEntry(memberSID, "WIN01\\Administrator", "Local")})), "", nil},
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   memberSID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.MemberSID != memberSID {
		t.Errorf("MemberSID = %q", state.MemberSID)
	}
}

func TestLGMAdd_HappyPath_UPN(t *testing.T) {
	const memberSID = "S-1-5-21-100-200-300-600"
	restore := stubLGSequence(lgmAddSuccessSeq(t, memberSID, "bob@corp.example.com", "ActiveDirectory")...)
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "bob@corp.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.MemberSID != memberSID {
		t.Errorf("MemberSID = %q", state.MemberSID)
	}
}

func TestLGMAdd_HappyPath_LocalUser(t *testing.T) {
	const memberSID = "S-1-5-21-100-200-300-700"
	restore := stubLGSequence(lgmAddSuccessSeq(t, memberSID, "WIN01\\localadmin", "Local")...)
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "localadmin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.PrincipalSource != "Local" {
		t.Errorf("PrincipalSource = %q", state.PrincipalSource)
	}
}

func TestLGMAdd_Duplicate_EC1(t *testing.T) {
	// EC-1: pre-flight List finds existing member → ErrLocalGroupMemberAlreadyExists.
	const memberSID = "S-1-5-21-100-200-300-500"
	seq := [][3]any{
		// resolveMemberSID
		{lgOK(t, lgmSIDRespData(memberSID)), "", nil},
		// List (pre-flight) — member already present!
		{lgOK(t, lgmListRespData("primary", []map[string]any{
			lgmMemberEntry(memberSID, "DOMAIN\\alice", "ActiveDirectory"),
		})), "", nil},
		// No further calls — returns error immediately.
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "DOMAIN\\alice",
	})
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorAlreadyExists) {
		t.Errorf("EC-1: expected member_already_exists, got %v", err)
	}
	var lgme *LocalGroupMemberError
	if errors.As(err, &lgme) {
		if !strings.Contains(lgme.Message, memberSID) {
			t.Errorf("EC-1: diagnostic should mention member SID: %q", lgme.Message)
		}
		if !strings.Contains(lgme.Message, "terraform import") {
			t.Errorf("EC-1: diagnostic should contain import hint: %q", lgme.Message)
		}
	}
}

func TestLGMAdd_Duplicate_EC1_CaseInsensitiveSID(t *testing.T) {
	// EC-1 + EC-7: duplicate detected even if SID case differs.
	const memberSID = "S-1-5-21-100-200-300-500"
	seq := [][3]any{
		{lgOK(t, lgmSIDRespData(memberSID)), "", nil},
		// List returns member with uppercase SID; resolvedSID is lowercase → EqualFold catches it.
		{lgOK(t, lgmListRespData("primary", []map[string]any{
			lgmMemberEntry(strings.ToUpper(memberSID), "DOMAIN\\alice", "ActiveDirectory"),
		})), "", nil},
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "DOMAIN\\alice",
	})
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorAlreadyExists) {
		t.Errorf("EC-1+EC-7: expected member_already_exists with case-insensitive SID, got %v", err)
	}
}

func TestLGMAdd_GroupNotFound_EC2_DuringList(t *testing.T) {
	// EC-2: group not found during pre-flight List.
	seq := [][3]any{
		{lgOK(t, lgmSIDRespData("S-1-5-21-100-200-300-500")), "", nil},
		{lgErr(t, "group_not_found", "group not found"), "", nil},
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-9999",
		Member:   "DOMAIN\\alice",
	})
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorGroupNotFound) {
		t.Errorf("EC-2: expected group_not_found from List, got %v", err)
	}
}

func TestLGMAdd_MemberUnresolvable_EC3(t *testing.T) {
	// EC-3: resolveMemberSID fails → ErrLocalGroupMemberUnresolvable.
	seq := [][3]any{
		{lgErr(t, "member_unresolvable", "The user 'nosuchuser' was not found"), "", nil},
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "nosuchuser",
	})
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnresolvable) {
		t.Errorf("EC-3: expected member_unresolvable, got %v", err)
	}
}

func TestLGMAdd_PermissionDenied_EC8(t *testing.T) {
	// EC-8: addMember returns permission_denied.
	const memberSID = "S-1-5-21-100-200-300-500"
	seq := [][3]any{
		{lgOK(t, lgmSIDRespData(memberSID)), "", nil},
		{lgOK(t, lgmListRespData("primary", nil)), "", nil},
		{lgErr(t, "permission_denied", "Access is denied"), "", nil},
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	_, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "DOMAIN\\alice",
	})
	if !IsLocalGroupMemberError(err, LocalGroupMemberErrorPermission) {
		t.Errorf("EC-8: expected permission_denied, got %v", err)
	}
}

func TestLGMAdd_GetReturnsNil_FallbackMinimalState(t *testing.T) {
	// Edge case: Get returns nil after successful Add → minimal state returned.
	const memberSID = "S-1-5-21-100-200-300-500"
	seq := [][3]any{
		{lgOK(t, lgmSIDRespData(memberSID)), "", nil},
		{lgOK(t, lgmListRespData("primary", nil)), "", nil},
		{lgOK(t, lgmAddedRespData()), "", nil},
		{lgOK(t, lgmListRespData("primary", nil)), "", nil}, // Get→List returns empty → nil
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "DOMAIN\\alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fallback minimal state must have correct SIDs.
	if state.GroupSID != "S-1-5-32-544" {
		t.Errorf("GroupSID = %q", state.GroupSID)
	}
	if state.MemberSID != memberSID {
		t.Errorf("MemberSID = %q", state.MemberSID)
	}
	if state.PrincipalSource != "Unknown" {
		t.Errorf("PrincipalSource = %q, want Unknown", state.PrincipalSource)
	}
}

func TestLGMAdd_PrincipalSourceNormalization(t *testing.T) {
	// Verify numeric PS enum value "1" (Local) is normalised to "Local".
	const memberSID = "S-1-5-21-100-200-300-777"
	seq := [][3]any{
		{lgOK(t, lgmSIDRespData(memberSID)), "", nil},
		{lgOK(t, lgmListRespData("primary", nil)), "", nil},
		{lgOK(t, lgmAddedRespData()), "", nil},
		{lgOK(t, lgmListRespData("primary", []map[string]any{
			{"SID": memberSID, "Name": "WIN01\\dave", "PrincipalSource": "1"}, // numeric Local
		})), "", nil},
	}
	restore := stubLGSequence(seq...)
	defer restore()

	mc := lgmNewClient(t)
	state, err := mc.Add(context.Background(), LocalGroupMemberInput{
		GroupSID: "S-1-5-32-544",
		Member:   "WIN01\\dave",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.PrincipalSource != "Local" {
		t.Errorf("PrincipalSource = %q, want Local (numeric 1 → Local)", state.PrincipalSource)
	}
}
