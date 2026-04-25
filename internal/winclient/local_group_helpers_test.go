// Package winclient — unit tests for ResolveGroup (local_group_helpers.go).
//
// ADR-LGM-6: ResolveGroup is used by both LocalGroupClient and
// LocalGroupMemberClient to resolve a name-or-SID to a canonical GroupState.
//
// Test coverage:
//   - SID direct: groupOrSID starts with "S-" → uses -SID param
//   - Name path:  groupOrSID is a plain name   → uses -Name param
//   - Group not found                          → LocalGroupErrorNotFound
//   - Transport error                          → LocalGroupErrorUnknown
//   - Context cancellation                     → LocalGroupErrorUnknown
//   - No JSON output                           → LocalGroupErrorUnknown
//   - Permission denied                        → LocalGroupErrorPermission
//
// NOTE: ResolveGroup is also tested indirectly via LocalGroupMemberClient.Add
// integration stubs in local_group_member_test.go, and via LocalGroupClient
// CRUD stubs in local_group_client_impl_test.go. The tests here focus on the
// helper function's own auto-detection logic and error mapping.
package winclient

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Happy paths — SID vs. name auto-detection
// ---------------------------------------------------------------------------

func TestResolveGroup_BySID_UsesMinusSIDParam(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		if !strings.Contains(script, "-SID") {
			t.Errorf("expected -SID parameter in script, got: ...%s...",
				truncate(script, 300))
		}
		return lgOK(t, fakeGroupData("Administrators", "Built-in Administrators", "S-1-5-32-544")), "", nil
	})
	defer restore()

	gs, err := ResolveGroup(context.Background(), newLGTestClient(t), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.SID != "S-1-5-32-544" {
		t.Errorf("SID = %q, want S-1-5-32-544", gs.SID)
	}
	if gs.Name != "Administrators" {
		t.Errorf("Name = %q, want Administrators", gs.Name)
	}
}

func TestResolveGroup_ByName_UsesMinusNameParam(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		if !strings.Contains(script, "-Name") {
			t.Errorf("expected -Name parameter in script, got: ...%s...",
				truncate(script, 300))
		}
		return lgOK(t, fakeGroupData("MyCustomGroup", "Custom group", "S-1-5-21-111-222-333-1001")), "", nil
	})
	defer restore()

	gs, err := ResolveGroup(context.Background(), newLGTestClient(t), "MyCustomGroup")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", gs.SID)
	}
	if gs.Name != "MyCustomGroup" {
		t.Errorf("Name = %q", gs.Name)
	}
	if gs.Description != "Custom group" {
		t.Errorf("Description = %q", gs.Description)
	}
}

func TestResolveGroup_BuiltinSID_Administrators(t *testing.T) {
	// BUILTIN\Administrators has a well-known SID prefix S-1-5-32-.
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, fakeGroupData("Administrators", "", "S-1-5-32-544")), "", nil
	})
	defer restore()

	gs, err := ResolveGroup(context.Background(), newLGTestClient(t), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs.SID != "S-1-5-32-544" {
		t.Errorf("SID = %q", gs.SID)
	}
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestResolveGroup_GroupNotFound(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "not_found", "the group 'NoSuchGroup' was not found"), "", nil
	})
	defer restore()

	_, err := ResolveGroup(context.Background(), newLGTestClient(t), "NoSuchGroup")
	if !IsLocalGroupError(err, LocalGroupErrorNotFound) {
		t.Errorf("expected not_found error, got %v", err)
	}
}

func TestResolveGroup_GroupNotFound_BySID(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "not_found", "the group 'S-1-5-21-9999' was not found"), "", nil
	})
	defer restore()

	_, err := ResolveGroup(context.Background(), newLGTestClient(t), "S-1-5-21-9999")
	if !IsLocalGroupError(err, LocalGroupErrorNotFound) {
		t.Errorf("expected not_found error for unknown SID, got %v", err)
	}
}

func TestResolveGroup_PermissionDenied(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()

	_, err := ResolveGroup(context.Background(), newLGTestClient(t), "Administrators")
	if !IsLocalGroupError(err, LocalGroupErrorPermission) {
		t.Errorf("expected permission_denied error, got %v", err)
	}
}

func TestResolveGroup_TransportError(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "winrm closed connection", errors.New("winrm: connection reset by peer")
	})
	defer restore()

	_, err := ResolveGroup(context.Background(), newLGTestClient(t), "Administrators")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("transport error should yield unknown, got %v", err)
	}
	var lge *LocalGroupError
	if errors.As(err, &lge) {
		if lge.Context["host"] != "winlg01" {
			t.Errorf("context[host] = %q, want winlg01", lge.Context["host"])
		}
	}
}

func TestResolveGroup_ContextCancellation(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ResolveGroup(ctx, newLGTestClient(t), "Administrators")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("cancelled ctx should yield unknown error, got %v", err)
	}
	if !strings.Contains(err.Error(), "timed out or was cancelled") {
		t.Errorf("error should mention cancellation: %v", err)
	}
}

func TestResolveGroup_NoJSONOutput(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "WARNING: no JSON here\n", "", nil
	})
	defer restore()

	_, err := ResolveGroup(context.Background(), newLGTestClient(t), "Administrators")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("no JSON output should yield unknown error, got %v", err)
	}
}

func TestResolveGroup_MalformedJSONEnvelope(t *testing.T) {
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{invalid json\n", "", nil
	})
	defer restore()

	_, err := ResolveGroup(context.Background(), newLGTestClient(t), "Administrators")
	if !IsLocalGroupError(err, LocalGroupErrorUnknown) {
		t.Errorf("malformed JSON should yield unknown error, got %v", err)
	}
}

func TestResolveGroup_ContextKeyPopulated(t *testing.T) {
	// Verify the error context carries "group" and "host".
	restore := stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "not_found", "group not found"), "", nil
	})
	defer restore()

	_, err := ResolveGroup(context.Background(), newLGTestClient(t), "MyGroup")
	var lge *LocalGroupError
	if !errors.As(err, &lge) {
		t.Fatalf("expected *LocalGroupError, got %T", err)
	}
	if lge.Context["group"] != "MyGroup" {
		t.Errorf("context[group] = %q, want MyGroup", lge.Context["group"])
	}
	if lge.Context["host"] != "winlg01" {
		t.Errorf("context[host] = %q, want winlg01", lge.Context["host"])
	}
}
