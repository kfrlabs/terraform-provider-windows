// Package winclient — unit tests for DomainMembershipClient.ReadWithOptions,
// mapDomainRole and the toDomainMembershipState empty-string/null rules
// backing the windows_domain_membership data source (#299).
//
// These tests reuse the stubDMRun/dmOK/fakeDMState helpers from
// domain_membership_client_impl_test.go.
package winclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// boolPtr builds a *bool payload value.
func boolPtr(t *testing.T, v bool) *bool {
	t.Helper()
	return &v
}

// fullDMState builds a joined-host payload exercising every new field.
func fullDMState() map[string]any {
	return map[string]any{
		"domain":            "corp.example.com",
		"part_of_domain":    true,
		"computer_name":     "WIN01",
		"workgroup":         "",
		"dns_host_name":     "win01.corp.example.com",
		"netbios_domain":    "CORP",
		"domain_role":       3,
		"machine_id":        "machine-guid-123",
		"pending_reboot":    false,
		"secure_channel_ok": true,
	}
}

// -----------------------------------------------------------------------------
// mapDomainRole
// -----------------------------------------------------------------------------

func TestMapDomainRole_Table(t *testing.T) {
	cases := map[int]string{
		0: "StandaloneWorkstation",
		1: "MemberWorkstation",
		2: "StandaloneServer",
		3: "MemberServer",
		4: "BackupDomainController",
		5: "PrimaryDomainController",
	}
	for in, want := range cases {
		got, err := mapDomainRole(in)
		if err != nil {
			t.Errorf("mapDomainRole(%d): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("mapDomainRole(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestMapDomainRole_UnknownErrors(t *testing.T) {
	for _, in := range []int{-1, 6, 42} {
		if got, err := mapDomainRole(in); err == nil {
			t.Errorf("mapDomainRole(%d) = %q, want hard error (never a silent default)", in, got)
		} else if !IsDomainMembershipError(err, DomainMembershipErrorUnknown) {
			t.Errorf("mapDomainRole(%d) error kind = %v, want unknown", in, err)
		}
	}
}

// -----------------------------------------------------------------------------
// toDomainMembershipState rules
// -----------------------------------------------------------------------------

func TestToDomainMembershipState_Nil(t *testing.T) {
	if got, err := toDomainMembershipState(nil); got != nil || err != nil {
		t.Errorf("nil payload = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestToDomainMembershipState_Joined(t *testing.T) {
	p := &domainMembershipStatePayload{
		Domain:          "corp.example.com",
		PartOfDomain:    true,
		ComputerName:    "WIN01",
		Workgroup:       "SHOULD-BE-CLEARED",
		DNSHostName:     "win01.corp.example.com",
		NetBIOSDomain:   "CORP",
		DomainRole:      3,
		MachineID:       "machine-guid-123",
		SecureChannelOk: boolPtr(t, true),
	}
	st, err := toDomainMembershipState(p)
	if err != nil {
		t.Fatalf("toDomainMembershipState: %v", err)
	}
	if st.Domain != "corp.example.com" || !st.PartOfDomain {
		t.Errorf("unexpected identity: %+v", st)
	}
	if st.Workgroup != "" {
		t.Errorf("Workgroup = %q, want empty when joined", st.Workgroup)
	}
	if st.NetBIOSDomain != "CORP" {
		t.Errorf("NetBIOSDomain = %q, want CORP", st.NetBIOSDomain)
	}
	if st.DomainRole != "MemberServer" {
		t.Errorf("DomainRole = %q, want MemberServer", st.DomainRole)
	}
	if st.MachineID != "machine-guid-123" {
		t.Errorf("MachineID = %q", st.MachineID)
	}
	if st.DNSHostName != "win01.corp.example.com" {
		t.Errorf("DNSHostName = %q", st.DNSHostName)
	}
	if st.SecureChannelNull || !st.SecureChannelOk {
		t.Errorf("SecureChannel = (%v, null=%v), want (true, false)", st.SecureChannelOk, st.SecureChannelNull)
	}
}

func TestToDomainMembershipState_Workgroup(t *testing.T) {
	p := &domainMembershipStatePayload{
		Domain:          "WORKGROUP",
		PartOfDomain:    false,
		ComputerName:    "WIN01",
		Workgroup:       "WORKGROUP",
		DNSHostName:     "win01",
		NetBIOSDomain:   "SHOULD-BE-CLEARED",
		DomainRole:      0,
		MachineID:       "machine-guid-456",
		SecureChannelOk: boolPtr(t, false),
	}
	st, err := toDomainMembershipState(p)
	if err != nil {
		t.Fatalf("toDomainMembershipState: %v", err)
	}
	if st.Domain != "" {
		t.Errorf("Domain = %q, want empty (never the workgroup name)", st.Domain)
	}
	if st.Workgroup != "WORKGROUP" {
		t.Errorf("Workgroup = %q, want WORKGROUP", st.Workgroup)
	}
	if st.NetBIOSDomain != "" {
		t.Errorf("NetBIOSDomain = %q, want empty when not joined", st.NetBIOSDomain)
	}
	if st.DomainRole != "StandaloneWorkstation" {
		t.Errorf("DomainRole = %q", st.DomainRole)
	}
	if !st.SecureChannelNull {
		t.Error("SecureChannelNull should be true for a workgroup host")
	}
	if st.SecureChannelOk {
		t.Error("SecureChannelOk should be false when null")
	}
}

func TestToDomainMembershipState_NullSecureChannelWhenJoined(t *testing.T) {
	p := &domainMembershipStatePayload{
		Domain:          "corp.example.com",
		PartOfDomain:    true,
		DomainRole:      3,
		SecureChannelOk: nil, // CheckSecureChannel=false probe skip
	}
	st, err := toDomainMembershipState(p)
	if err != nil {
		t.Fatalf("toDomainMembershipState: %v", err)
	}
	if !st.SecureChannelNull {
		t.Error("SecureChannelNull should be true when the probe is skipped")
	}
	if st.SecureChannelOk {
		t.Error("SecureChannelOk should be false when null")
	}
}

func TestToDomainMembershipState_UnknownRoleErrors(t *testing.T) {
	p := &domainMembershipStatePayload{DomainRole: 99}
	if _, err := toDomainMembershipState(p); err == nil {
		t.Error("unknown domain role must produce an error diagnostic, never a silent default")
	} else if !IsDomainMembershipError(err, DomainMembershipErrorUnknown) {
		t.Errorf("error kind = %v, want unknown", err)
	}
}

// TestToDomainMembershipState_LegacyPayload verifies backward compatibility:
// payloads from older hosts (or the existing unit fixtures) that omit the
// new keys unmarshal to zero values and still map without error.
func TestToDomainMembershipState_LegacyPayload(t *testing.T) {
	raw, err := json.Marshal(fakeDMState("corp.example.com", true))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p domainMembershipStatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	st, err := toDomainMembershipState(&p)
	if err != nil {
		t.Fatalf("legacy payload must still map: %v", err)
	}
	if st.Domain != "corp.example.com" || !st.PartOfDomain || !st.SecureChannelOk {
		t.Errorf("unexpected state: %+v", st)
	}
	if st.DomainRole != "StandaloneWorkstation" {
		t.Errorf("zero role maps to %q, want StandaloneWorkstation", st.DomainRole)
	}
}

// -----------------------------------------------------------------------------
// ReadWithOptions
// -----------------------------------------------------------------------------

func TestDomainMembershipReadWithOptions_SkipsProbe(t *testing.T) {
	c := newDMTestClient(t)
	restore, gotScript, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		// secure_channel_ok:null — the skipped-probe envelope.
		return dmOK(t, map[string]any{
			"domain":            "corp.example.com",
			"part_of_domain":    true,
			"computer_name":     "WIN01",
			"workgroup":         "",
			"dns_host_name":     "win01.corp.example.com",
			"netbios_domain":    "CORP",
			"domain_role":       3,
			"machine_id":        "machine-guid-123",
			"pending_reboot":    false,
			"secure_channel_ok": nil,
		}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, err := dm.ReadWithOptions(context.Background(), DomainMembershipReadOptions{CheckSecureChannel: false})
	if err != nil {
		t.Fatalf("ReadWithOptions: %v", err)
	}
	if !strings.Contains(*gotScript, "-CheckSecureChannel:$false") {
		t.Errorf("script must disable the probe, got: %s", *gotScript)
	}
	if !st.SecureChannelNull {
		t.Error("SecureChannelNull should be true when the probe is skipped")
	}
	if st.DomainRole != "MemberServer" || st.MachineID != "machine-guid-123" {
		t.Errorf("unexpected state: %+v", st)
	}
}

func TestDomainMembershipReadWithOptions_ProbeEnabled(t *testing.T) {
	c := newDMTestClient(t)
	restore, gotScript, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, fullDMState()), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, err := dm.ReadWithOptions(context.Background(), DomainMembershipReadOptions{CheckSecureChannel: true})
	if err != nil {
		t.Fatalf("ReadWithOptions: %v", err)
	}
	if !strings.Contains(*gotScript, "-CheckSecureChannel:$true") {
		t.Errorf("script must enable the probe, got: %s", *gotScript)
	}
	if st.SecureChannelNull || !st.SecureChannelOk {
		t.Errorf("SecureChannel = (%v, null=%v), want (true, false)", st.SecureChannelOk, st.SecureChannelNull)
	}
}

// TestDomainMembershipRead_DelegatesWithProbe verifies Read keeps its
// historical behavior: the secure-channel probe stays enabled.
func TestDomainMembershipRead_DelegatesWithProbe(t *testing.T) {
	c := newDMTestClient(t)
	restore, gotScript, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, fullDMState()), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	if _, err := dm.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !strings.Contains(*gotScript, "-CheckSecureChannel:$true") {
		t.Errorf("Read must probe the channel, got: %s", *gotScript)
	}
}

func TestDomainMembershipReadWithOptions_UnknownRoleErrors(t *testing.T) {
	c := newDMTestClient(t)
	data := fullDMState()
	data["domain_role"] = 99
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, data), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	if _, err := dm.ReadWithOptions(context.Background(), DomainMembershipReadOptions{CheckSecureChannel: true}); err == nil {
		t.Error("unknown domain role must surface an error, never silently default")
	}
}

func TestDomainMembershipJoin_UnknownRoleLenient(t *testing.T) {
	c := newDMTestClient(t)
	state := fullDMState()
	state["domain_role"] = 99
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{
			"state":            state,
			"reboot_scheduled": true,
		}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, res, err := dm.Join(context.Background(), DomainJoinInput{
		Domain: "corp.example.com", Username: "u", Password: "p",
	})
	if err != nil {
		t.Fatalf("Join with unknown role must not fail the successful mutation: %v", err)
	}
	if st == nil || st.DomainRole != "" {
		t.Errorf("DomainRole = %q, want empty (lenient) on Join", st.DomainRole)
	}
	if res == nil || !res.RebootScheduled {
		t.Errorf("Join result lost on unknown role: %+v", res)
	}
}

func TestDomainMembershipUnjoin_UnknownRoleLenient(t *testing.T) {
	c := newDMTestClient(t)
	state := fullDMState()
	state["domain_role"] = 99
	state["part_of_domain"] = false
	state["workgroup"] = "WORKGROUP"
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{
			"state":            state,
			"already_absent":   false,
			"reboot_scheduled": false,
		}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, res, err := dm.Unjoin(context.Background(), DomainUnjoinInput{
		Username: "u", Password: "p", WorkgroupName: "WORKGROUP",
	})
	if err != nil {
		t.Fatalf("Unjoin with unknown role must not fail the successful mutation: %v", err)
	}
	if st == nil || st.DomainRole != "" {
		t.Errorf("DomainRole = %q, want empty (lenient) on Unjoin", st.DomainRole)
	}
	if res == nil {
		t.Error("Unjoin result lost on unknown role")
	}
}
