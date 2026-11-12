// Package winclient — unit tests for LocalGroupClient.List.
//
// List lives in local_group.go (not a new file) so the inventory shares the
// exact per-group JSON projection of Read; the member projection is the
// shared Get-LgmMembers function also used by ClientLocalGroupMember.List
// (issue #298). These tests stub the package-level runPowerShell hook so no
// real SSH connection is required. Edge cases covered:
//
//	mapping parity with Read (same stub JSON -> identical GroupState fields)
//	members nil vs empty list (IncludeMembers false vs true with no members)
//	members populated incl ObjectClass "User" and the "Unknown" fallback
//	orphaned SID keeps MemberName "" (no ""-to-SID coercion on this path)
//	is_builtin prefix derivation, filters (names/sids host-side, name_regex
//	and include_builtin Go-side), sort by name (case-insensitive) and
//	members by SID, empty inventory valid, DC guard error kind,
//	invalid name_regex -> invalid_parameter with no host call,
//	script assertions: DC guard first, shared module check, single
//	Get-LocalGroup, Get-LgmMembers defined once and called in a loop,
//	no N round trips, no exit
package winclient

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// lgListGroup builds one Get-LocalGroup-shaped payload with the given
// members value (nil renders as JSON null, i.e. membership not requested).
func lgListGroup(name, description, sid string, members any) map[string]any {
	return map[string]any{
		"Name":        name,
		"Description": description,
		"SID":         map[string]any{"Value": sid},
		"Members":     members,
	}
}

// lgListMember builds one Get-LgmMembers-shaped member payload.
func lgListMember(sid, name, source, objectClass string) map[string]any {
	return map[string]any{
		"SID":             sid,
		"Name":            name,
		"PrincipalSource": source,
		"ObjectClass":     objectClass,
	}
}

// stubLGList returns a runPowerShell stub serving one Emit-OK envelope with
// the given group array, capturing the script it was called with and
// counting calls.
func stubLGList(t *testing.T, groups []map[string]any, script *string, calls *int) func() {
	t.Helper()
	return stubLGRun(func(_ context.Context, _ *Client, s string) (string, string, error) {
		*script = s
		*calls++
		return lgOK(t, groups), "", nil
	})
}

func TestLocalGroupLister_Assertion(t *testing.T) {
	var _ LocalGroupLister = NewLocalGroupClient(newLGTestClient(t))
}

// TestLocalGroupList_MappingParityWithRead feeds the same per-group JSON to
// Read (single envelope) and List (array envelope) and requires identical
// GroupState fields — the shared-projection contract of issue #298.
func TestLocalGroupList_MappingParityWithRead(t *testing.T) {
	payload := lgListGroup("Administrators", "Built-in admins", "S-1-5-32-544", nil)

	lc := NewLocalGroupClient(newLGTestClient(t))
	defer stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgOK(t, payload), "", nil
	})()
	readState, err := lc.Read(context.Background(), "S-1-5-32-544")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	var script string
	var calls int
	defer stubLGList(t, []map[string]any{payload}, &script, &calls)()
	list, err := lc.List(context.Background(), LocalGroupFilter{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d groups, want 1", len(list))
	}
	got := list[0]
	if got.Name != readState.Name || got.Description != readState.Description || got.SID != readState.SID {
		t.Errorf("List[0] = %+v, want Read result %+v", got, *readState)
	}
	if got.Members != nil {
		t.Errorf("List[0].Members = %v, want nil (not requested)", got.Members)
	}
	if calls != 1 {
		t.Errorf("List made %d host calls, want exactly 1", calls)
	}
}

// TestLocalGroupList_MembersNullVsEmpty pins the nil-vs-empty contract:
// IncludeMembers false leaves Members nil; true with no members yields a
// non-nil empty slice.
func TestLocalGroupList_MembersNullVsEmpty(t *testing.T) {
	lc := NewLocalGroupClient(newLGTestClient(t))

	var script string
	var calls int
	defer stubLGList(t, []map[string]any{
		lgListGroup("Empty", "", "S-1-5-21-1-2-3-1001", nil),
	}, &script, &calls)()
	without, err := lc.List(context.Background(), LocalGroupFilter{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("List without members: %v", err)
	}
	if len(without) != 1 {
		t.Fatalf("List returned %d groups, want 1", len(without))
	}
	if without[0].Members != nil {
		t.Errorf("Members = %v, want nil when not requested", without[0].Members)
	}

	defer stubLGList(t, []map[string]any{
		lgListGroup("Empty", "", "S-1-5-21-1-2-3-1001", []any{}),
	}, &script, &calls)()
	with, err := lc.List(context.Background(), LocalGroupFilter{IncludeBuiltin: true, IncludeMembers: true})
	if err != nil {
		t.Fatalf("List with members: %v", err)
	}
	if with[0].Members == nil {
		t.Fatal("Members must be a non-nil empty slice when requested but absent")
	}
	if len(with[0].Members) != 0 {
		t.Errorf("Members has %d entries, want 0", len(with[0].Members))
	}
}

// TestLocalGroupList_MembersPopulated covers the Tier 1 ObjectClass capture,
// the "Unknown" fallback for payloads without ObjectClass, member sort by
// SID, and the orphaned-SID rule (MemberName "" stays "", no coercion).
func TestLocalGroupList_MembersPopulated(t *testing.T) {
	lc := NewLocalGroupClient(newLGTestClient(t))
	var script string
	var calls int
	defer stubLGList(t, []map[string]any{
		lgListGroup("TestGroup", "desc", "S-1-5-21-1-2-3-1001", []any{
			lgListMember("S-1-5-21-1-2-3-1003", "WIN01\\carol", "Local", "User"),
			// Legacy payload without ObjectClass + orphaned SID with no name.
			map[string]any{"SID": "S-1-5-21-orphan-999", "Name": "", "PrincipalSource": "Unknown"},
		}),
	}, &script, &calls)()
	list, err := lc.List(context.Background(), LocalGroupFilter{IncludeBuiltin: true, IncludeMembers: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d groups, want 1", len(list))
	}
	members := list[0].Members
	if len(members) != 2 {
		t.Fatalf("Members has %d entries, want 2", len(members))
	}
	// Sorted by member SID ascending ("...-1-2-3-1003" < "...-orphan-999").
	if members[0].MemberSID != "S-1-5-21-1-2-3-1003" {
		t.Errorf("members[0].MemberSID = %q, want carol SID (sorted)", members[0].MemberSID)
	}
	if members[0].MemberName != "WIN01\\carol" {
		t.Errorf("members[0].MemberName = %q, want carol (Tier 1 name kept)", members[0].MemberName)
	}
	if members[0].ObjectClass != "User" {
		t.Errorf("members[0].ObjectClass = %q, want User (Tier 1 capture)", members[0].ObjectClass)
	}
	if members[1].MemberSID != "S-1-5-21-orphan-999" {
		t.Errorf("members[1].MemberSID = %q, want orphan SID (sorted)", members[1].MemberSID)
	}
	if members[1].MemberName != "" {
		t.Errorf("members[1].MemberName = %q, want empty (no coercion on this path)", members[1].MemberName)
	}
	if members[1].ObjectClass != "Unknown" {
		t.Errorf("members[1].ObjectClass = %q, want Unknown fallback", members[1].ObjectClass)
	}
	if members[1].PrincipalSource != "Unknown" {
		t.Errorf("members[1].PrincipalSource = %q, want Unknown", members[1].PrincipalSource)
	}
	if members[0].GroupSID != "S-1-5-21-1-2-3-1001" || members[1].GroupSID != "S-1-5-21-1-2-3-1001" {
		t.Errorf("member GroupSID not propagated: %+v", members)
	}
}

// TestLocalGroupList_SortedCaseInsensitive verifies the sort contract with
// mixed-case names.
func TestLocalGroupList_SortedCaseInsensitive(t *testing.T) {
	lc := NewLocalGroupClient(newLGTestClient(t))
	var script string
	var calls int
	defer stubLGList(t, []map[string]any{
		lgListGroup("zebra", "", "S-1-5-21-1-2-3-1003", nil),
		lgListGroup("Alice", "", "S-1-5-21-1-2-3-1001", nil),
		lgListGroup("bob", "", "S-1-5-21-1-2-3-1002", nil),
	}, &script, &calls)()
	list, err := lc.List(context.Background(), LocalGroupFilter{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"Alice", "bob", "zebra"}
	if len(list) != len(want) {
		t.Fatalf("List returned %d groups, want %d", len(list), len(want))
	}
	for i, name := range want {
		if list[i].Name != name {
			t.Errorf("list[%d].Name = %q, want %q", i, list[i].Name, name)
		}
	}
}

// TestLocalGroupList_Filters covers the Go-side filter pair: name_regex and
// the built-in drop. Names/sids filter host-side (see script test); the stub
// returns a fixed inventory so only Go-side behaviour is asserted here.
func TestLocalGroupList_Filters(t *testing.T) {
	groups := []map[string]any{
		lgListGroup("Administrators", "", "S-1-5-32-544", nil),
		lgListGroup("svc-app", "", "S-1-5-21-1-2-3-1001", nil),
		lgListGroup("svc-batch", "", "S-1-5-21-1-2-3-1002", nil),
		lgListGroup("Users", "", "S-1-5-32-545", nil),
	}
	cases := []struct {
		name   string
		filter LocalGroupFilter
		want   []string
	}{
		{"all", LocalGroupFilter{IncludeBuiltin: true}, []string{"Administrators", "svc-app", "svc-batch", "Users"}},
		{"no_builtin", LocalGroupFilter{}, []string{"svc-app", "svc-batch"}},
		{"regex", LocalGroupFilter{IncludeBuiltin: true, NameRegex: `^svc-`}, []string{"svc-app", "svc-batch"}},
		{"regex_case_insensitive_flag", LocalGroupFilter{IncludeBuiltin: true, NameRegex: `(?i)^SVC-APP$`}, []string{"svc-app"}},
		{"regex_no_match", LocalGroupFilter{IncludeBuiltin: true, NameRegex: `^nope`}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := NewLocalGroupClient(newLGTestClient(t))
			var script string
			var calls int
			defer stubLGList(t, groups, &script, &calls)()
			list, err := lc.List(context.Background(), tc.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(list) != len(tc.want) {
				t.Fatalf("List returned %d groups %v, want %v", len(list), list, tc.want)
			}
			for i, name := range tc.want {
				if list[i].Name != name {
					t.Errorf("list[%d].Name = %q, want %q", i, list[i].Name, name)
				}
			}
		})
	}
}

// TestIsBuiltinLocalGroupSID_Table pins the BUILTIN authority prefix rule.
func TestIsBuiltinLocalGroupSID_Table(t *testing.T) {
	cases := map[string]bool{
		"S-1-5-32-544":              true,
		"S-1-5-32-545":              true,
		"S-1-5-32-555":              true,
		"S-1-5-21-111-222-333-513":  false,
		"S-1-5-21-111-222-333-1001": false,
		"":                          false,
	}
	for sid, want := range cases {
		if got := IsBuiltinLocalGroupSID(sid); got != want {
			t.Errorf("IsBuiltinLocalGroupSID(%q) = %v, want %v", sid, got, want)
		}
	}
}

// TestLocalGroupList_Empty verifies an empty inventory is valid: a non-nil
// empty slice and no error.
func TestLocalGroupList_Empty(t *testing.T) {
	lc := NewLocalGroupClient(newLGTestClient(t))
	var script string
	var calls int
	defer stubLGList(t, nil, &script, &calls)()
	list, err := lc.List(context.Background(), LocalGroupFilter{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if list == nil {
		t.Fatal("List must return a non-nil empty slice")
	}
	if len(list) != 0 {
		t.Errorf("List returned %d groups, want 0", len(list))
	}
}

// TestLocalGroupList_UnsupportedOnDC simulates the host-side DC guard firing:
// the envelope kind maps to LocalGroupErrorUnsupportedOnDC.
func TestLocalGroupList_UnsupportedOnDC(t *testing.T) {
	lc := NewLocalGroupClient(newLGTestClient(t))
	defer stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return lgErr(t, "unsupported_on_domain_controller", "not supported on a domain controller"), "", nil
	})()
	_, err := lc.List(context.Background(), LocalGroupFilter{IncludeBuiltin: true})
	if err == nil {
		t.Fatal("expected unsupported_on_domain_controller error")
	}
	if !IsLocalGroupError(err, LocalGroupErrorUnsupportedOnDC) {
		t.Errorf("error kind = %v, want unsupported_on_domain_controller", err)
	}
	if !errors.Is(err, ErrLocalGroupUnsupportedOnDC) {
		t.Errorf("errors.Is(err, ErrLocalGroupUnsupportedOnDC) = false: %v", err)
	}
}

// TestLocalGroupList_InvalidRegexNoHostCall verifies filter validation runs
// before any host call: a runPowerShell stub that fails the test is never
// invoked.
func TestLocalGroupList_InvalidRegexNoHostCall(t *testing.T) {
	lc := NewLocalGroupClient(newLGTestClient(t))
	defer stubLGRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		t.Error("invalid filter must not reach the host")
		return "", "", errors.New("must not be called")
	})()
	_, err := lc.List(context.Background(), LocalGroupFilter{NameRegex: "(unclosed"})
	if err == nil {
		t.Fatal("expected invalid_parameter error")
	}
	if !IsLocalGroupError(err, LocalGroupErrorInvalidParameter) {
		t.Errorf("error kind = %v, want invalid_parameter", err)
	}
}

// TestMapLGKind_ListKinds pins the two new kind mappings.
func TestMapLGKind_ListKinds(t *testing.T) {
	if got := mapLGKind("unsupported_on_domain_controller"); got != LocalGroupErrorUnsupportedOnDC {
		t.Errorf("mapLGKind(unsupported_on_domain_controller) = %q", got)
	}
	if got := mapLGKind("invalid_parameter"); got != LocalGroupErrorInvalidParameter {
		t.Errorf("mapLGKind(invalid_parameter) = %q", got)
	}
}

// TestLocalGroupList_Script asserts the inventory script shape: the DC guard
// runs first, the shared LocalAccounts module check follows, enumeration
// uses Get-LocalGroup once with host-side Where-Object filters, the member
// loop calls the shared Get-LgmMembers function, user input is psQuote'd,
// and no exit statement can tear down the shared session.
func TestLocalGroupList_Script(t *testing.T) {
	lc := NewLocalGroupClient(newLGTestClient(t))
	var script string
	var calls int
	defer stubLGList(t, nil, &script, &calls)()
	filter := LocalGroupFilter{
		Names:          []string{"O'Brien"},
		SIDs:           []string{"S-1-5-32-544"},
		IncludeBuiltin: true,
		IncludeMembers: true,
	}
	if _, err := lc.List(context.Background(), filter); err != nil {
		t.Fatalf("List: %v", err)
	}
	if calls != 1 {
		t.Fatalf("List made %d host calls, want exactly 1 (no N round trips)", calls)
	}

	for _, want := range []string{
		"DomainRole",
		"-ge 4",
		"unsupported_on_domain_controller",
		"Get-Command Get-LocalGroup",
		"Microsoft.PowerShell.LocalAccounts module not available",
		"function Get-LgmMembers",
		"Get-LgmMembers $sidVal",
		"foreach ($g in $groups)",
		"Where-Object",
		"Emit-OK $out",
		"list_local_groups",
		"'O''Brien'",
		"'S-1-5-32-544'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("List script missing %q", want)
		}
	}
	dcGuard := strings.Index(script, "DomainRole")
	moduleCheck := strings.Index(script, "Get-Command Get-LocalGroup")
	enumerate := strings.Index(script, "Get-LocalGroup -ErrorAction Stop")
	if dcGuard < 0 || moduleCheck < 0 || enumerate < 0 {
		t.Fatalf("List script missing DC guard, module check or enumeration")
	}
	if dcGuard >= moduleCheck || moduleCheck >= enumerate {
		t.Error("DC guard must run first, then the module check, then enumeration")
	}
	if n := strings.Count(script, "Get-LocalGroup -ErrorAction Stop"); n != 1 {
		t.Errorf("List script has %d Get-LocalGroup enumerations, want exactly 1", n)
	}
	if n := strings.Count(script, "function Get-LgmMembers"); n != 1 {
		t.Errorf("List script defines Get-LgmMembers %d times, want exactly 1", n)
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
