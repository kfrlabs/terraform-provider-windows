// Package winclient — unit tests for LocalUserClientImpl.List.
//
// List lives in local_user.go (not a new file) so the inventory shares the
// exact Get-UserData projection and parseUserData mapping of Read; the
// Read/Create/Update/Delete/Import scripts are byte-identical. These tests
// stub the package-level runPowerShell hook so no real SSH connection is
// required. Edge cases covered:
//
//	mapping parity with Read (same stub JSON -> identical UserState fields)
//	is_builtin RID derivation (500/501/503/504 true, 1001 false)
//	filters (name_regex, enabled, include_builtin) applied Go-side
//	sort by name (case-insensitive), empty inventory valid
//	DC guard error kind (stubbed unsupported_on_domain_controller envelope)
//	invalid name_regex -> invalid_parameter with no host call
//	script assertions: DC guard first, shared module check, Get-LocalUser
//	  without -SID, no exit
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// stubLUList returns a runPowerShell stub serving one Emit-OK envelope with
// the given users array, capturing the script it was called with.
func stubLUList(t *testing.T, users []map[string]any, script *string) func() {
	t.Helper()
	return stubLURun(func(_ context.Context, _ *Client, s string) (string, string, error) {
		*script = s
		return luOK(t, users), "", nil
	})
}

// luUser builds one Get-UserData-shaped payload with the given overrides.
func luUser(name, sid string, enabled bool) map[string]any {
	u := fakeUserData(name, sid)
	u["Enabled"] = enabled
	return u
}

func TestLocalUserLister_Assertion(t *testing.T) {
	var _ LocalUserLister = newLUClient(t)
}

// TestLocalUserList_MappingParityWithRead feeds the same per-user JSON to
// Read (single envelope) and List (array envelope) and requires identical
// UserState fields — the shared-projection contract of issue #297.
func TestLocalUserList_MappingParityWithRead(t *testing.T) {
	raw, err := json.Marshal(fakeUserData("alice", "S-1-5-21-111-222-333-1001"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	lc := newLUClient(t)
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, json.RawMessage(raw)), "", nil
	})()
	readState, err := lc.Read(context.Background(), "S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luOK(t, []any{json.RawMessage(raw)}), "", nil
	})()
	list, err := lc.List(context.Background(), LocalUserFilter{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d users, want 1", len(list))
	}
	got := list[0]
	if got != *readState {
		t.Errorf("List[0] = %+v, want Read result %+v", got, *readState)
	}
}

// TestLocalUserList_SortedCaseInsensitive verifies the sort contract with
// mixed-case names.
func TestLocalUserList_SortedCaseInsensitive(t *testing.T) {
	lc := newLUClient(t)
	var script string
	defer stubLUList(t, []map[string]any{
		luUser("zebra", "S-1-5-21-1-2-3-1003", true),
		luUser("Alice", "S-1-5-21-1-2-3-1001", true),
		luUser("bob", "S-1-5-21-1-2-3-1002", true),
	}, &script)()
	list, err := lc.List(context.Background(), LocalUserFilter{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"Alice", "bob", "zebra"}
	if len(list) != len(want) {
		t.Fatalf("List returned %d users, want %d", len(list), len(want))
	}
	for i, name := range want {
		if list[i].Name != name {
			t.Errorf("list[%d].Name = %q, want %q", i, list[i].Name, name)
		}
	}
}

// TestLocalUserList_Filters covers the Go-side filter trio.
func TestLocalUserList_Filters(t *testing.T) {
	users := []map[string]any{
		luUser("Administrator", "S-1-5-21-1-2-3-500", true),
		luUser("svc-app", "S-1-5-21-1-2-3-1001", true),
		luUser("svc-batch", "S-1-5-21-1-2-3-1002", false),
		luUser("Guest", "S-1-5-21-1-2-3-501", false),
	}
	cases := []struct {
		name   string
		filter LocalUserFilter
		want   []string
	}{
		{"all", LocalUserFilter{IncludeBuiltin: true}, []string{"Administrator", "Guest", "svc-app", "svc-batch"}},
		{"no_builtin", LocalUserFilter{}, []string{"svc-app", "svc-batch"}},
		{"regex", LocalUserFilter{IncludeBuiltin: true, NameRegex: `^svc-`}, []string{"svc-app", "svc-batch"}},
		{"regex_case_insensitive_flag", LocalUserFilter{IncludeBuiltin: true, NameRegex: `(?i)^SVC-APP$`}, []string{"svc-app"}},
		{"enabled_only", LocalUserFilter{IncludeBuiltin: true, Enabled: luBool(true)}, []string{"Administrator", "svc-app"}},
		{"disabled_only", LocalUserFilter{IncludeBuiltin: true, Enabled: luBool(false)}, []string{"Guest", "svc-batch"}},
		{"disabled_no_builtin", LocalUserFilter{Enabled: luBool(false)}, []string{"svc-batch"}},
		{"regex_no_match", LocalUserFilter{IncludeBuiltin: true, NameRegex: `^nope`}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := newLUClient(t)
			var script string
			defer stubLUList(t, users, &script)()
			list, err := lc.List(context.Background(), tc.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(list) != len(tc.want) {
				t.Fatalf("List returned %d users %v, want %v", len(list), list, tc.want)
			}
			for i, name := range tc.want {
				if list[i].Name != name {
					t.Errorf("list[%d].Name = %q, want %q", i, list[i].Name, name)
				}
			}
		})
	}
}

func luBool(b bool) *bool { return &b }

// TestIsBuiltinLocalUserSID_Table pins the RID derivation: numeric RID below
// 1000 is built-in, anything else (including non-numeric) is not.
func TestIsBuiltinLocalUserSID_Table(t *testing.T) {
	cases := map[string]bool{
		"S-1-5-21-111-222-333-500":  true,
		"S-1-5-21-111-222-333-501":  true,
		"S-1-5-21-111-222-333-503":  true,
		"S-1-5-21-111-222-333-504":  true,
		"S-1-5-21-111-222-333-502":  true,
		"S-1-5-21-111-222-333-999":  true,
		"S-1-5-21-111-222-333-1000": false,
		"S-1-5-21-111-222-333-1001": false,
		"S-1-5-32-544":              true,
		"not-a-sid":                 false,
		"":                          false,
	}
	for sid, want := range cases {
		if got := IsBuiltinLocalUserSID(sid); got != want {
			t.Errorf("IsBuiltinLocalUserSID(%q) = %v, want %v", sid, got, want)
		}
	}
}

// TestLocalUserList_Empty verifies an empty inventory is valid: a non-nil
// empty slice and no error.
func TestLocalUserList_Empty(t *testing.T) {
	lc := newLUClient(t)
	var script string
	defer stubLUList(t, nil, &script)()
	list, err := lc.List(context.Background(), LocalUserFilter{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if list == nil {
		t.Fatal("List must return a non-nil empty slice")
	}
	if len(list) != 0 {
		t.Errorf("List returned %d users, want 0", len(list))
	}
}

// TestLocalUserList_UnsupportedOnDC simulates the host-side DC guard firing:
// the envelope kind maps to LocalUserErrorUnsupportedOnDC.
func TestLocalUserList_UnsupportedOnDC(t *testing.T) {
	lc := newLUClient(t)
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return luErr(t, "unsupported_on_domain_controller", "not supported on a domain controller"), "", nil
	})()
	_, err := lc.List(context.Background(), LocalUserFilter{IncludeBuiltin: true})
	if err == nil {
		t.Fatal("expected unsupported_on_domain_controller error")
	}
	if !IsLocalUserError(err, LocalUserErrorUnsupportedOnDC) {
		t.Errorf("error kind = %v, want unsupported_on_domain_controller", err)
	}
	if !errors.Is(err, ErrLocalUserUnsupportedOnDC) {
		t.Errorf("errors.Is(err, ErrLocalUserUnsupportedOnDC) = false: %v", err)
	}
}

// TestLocalUserList_InvalidRegexNoHostCall verifies filter validation runs
// before any host call: a runPowerShell stub that fails the test is never
// invoked.
func TestLocalUserList_InvalidRegexNoHostCall(t *testing.T) {
	lc := newLUClient(t)
	defer stubLURun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		t.Error("invalid filter must not reach the host")
		return "", "", errors.New("must not be called")
	})()
	_, err := lc.List(context.Background(), LocalUserFilter{NameRegex: "(unclosed"})
	if err == nil {
		t.Fatal("expected invalid_parameter error")
	}
	if !IsLocalUserError(err, LocalUserErrorInvalidParameter) {
		t.Errorf("error kind = %v, want invalid_parameter", err)
	}
}

// TestMapLUKind_ListKinds pins the two new kind mappings.
func TestMapLUKind_ListKinds(t *testing.T) {
	if got := mapLUKind("unsupported_on_domain_controller"); got != LocalUserErrorUnsupportedOnDC {
		t.Errorf("mapLUKind(unsupported_on_domain_controller) = %q", got)
	}
	if got := mapLUKind("invalid_parameter"); got != LocalUserErrorInvalidParameter {
		t.Errorf("mapLUKind(invalid_parameter) = %q", got)
	}
}

// TestLocalUserList_Script asserts the inventory script shape: the DC guard
// runs first, the shared LocalAccounts module check follows, enumeration
// uses Get-LocalUser with no -SID restriction, the per-user projection is
// Get-UserData, and no exit statement can tear down the shared session.
func TestLocalUserList_Script(t *testing.T) {
	lc := newLUClient(t)
	var script string
	defer stubLUList(t, nil, &script)()
	if _, err := lc.List(context.Background(), LocalUserFilter{IncludeBuiltin: true}); err != nil {
		t.Fatalf("List: %v", err)
	}

	dcGuard := strings.Index(script, "DomainRole")
	moduleCheck := strings.Index(script, "Get-Command Get-LocalUser")
	moduleMsg := "Microsoft.PowerShell.LocalAccounts module not available"
	enumerate := strings.Index(script, "Get-LocalUser -ErrorAction Stop")
	for _, want := range []string{
		"DomainRole",
		"-ge 4",
		"unsupported_on_domain_controller",
		"Get-Command Get-LocalUser",
		moduleMsg,
		"Get-UserData",
		"Emit-OK $data",
		"list_local_users",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("List script missing %q", want)
		}
	}
	if dcGuard < 0 || moduleCheck < 0 || enumerate < 0 {
		t.Fatalf("List script missing DC guard, module check or enumeration")
	}
	if dcGuard >= moduleCheck || moduleCheck >= enumerate {
		t.Error("DC guard must run first, then the module check, then enumeration")
	}
	if strings.Contains(script, "-SID") {
		t.Error("List script must not restrict Get-LocalUser with -SID")
	}
	// Line-anchored, case-insensitive: a bare exit would kill the shared
	// persistent session (#81). Substring matching would false-fail on
	// words like "complexity" in the shared classifier.
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(strings.ToLower(line))
		if trimmed == "exit" || strings.HasPrefix(trimmed, "exit ") ||
			strings.HasPrefix(trimmed, "exit;") || strings.HasPrefix(trimmed, "exit\t") {
			t.Errorf("List script contains an exit statement: %q", line)
		}
	}
}
