// Package winclient — unit tests for NetworkAdaptersClient and its
// mapping tables.
//
// The package-level seams runNetworkAdaptersPowerShell (script transport)
// and networkAdaptersManagementPath (guard probe) are stubbed so no real
// SSH connection is needed. Coverage targets (issue #295):
//
//	NetworkAdapterError: Error(), Unwrap(), Is(), sentinels
//	mapNetworkAdaptersKind: access_denied / cim_unavailable / unknown fallback
//	deriveNetworkAdapterStatus: full numeric-triple table
//	normalizeNetworkAdapterMAC: separator/case formats + invalid
//	canonicalizeNetworkAdapterCIDR/Strings: canonical form + sort + dedupe
//	validateNetworkAdapterFilter: invalid regex/mac/status -> invalid_parameter
//	script builder: single round-trip (every cmdlet once), no "exit",
//	names via psQuote, bools as literals
//	List: Go-side filter combos, ifIndex sort, is_management marking and
//	unreachable-probe tolerance, envelope mapping
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
// Helpers
// ---------------------------------------------------------------------------

// naNewClient returns a *NetworkAdaptersClient for tests.
func naNewClient(t *testing.T) *NetworkAdaptersClient {
	t.Helper()
	c, err := New(Config{Host: "winna01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewNetworkAdaptersClient(c)
}

// naOK returns a JSON ok-envelope whose data field is the supplied value.
func naOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("naOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// naErr returns a JSON error-envelope for the given kind/message.
func naErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("naErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// naStubRun replaces runNetworkAdaptersPowerShell for one test and counts
// calls.
func naStubRun(calls *int, fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runNetworkAdaptersPowerShell
	runNetworkAdaptersPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
		if calls != nil {
			*calls++
		}
		return fn(ctx, c, script)
	}
	return func() { runNetworkAdaptersPowerShell = prev }
}

// naStubManagementPath replaces the management-path probe for one test.
func naStubManagementPath(mp *ManagementPath, err error) func() {
	prev := networkAdaptersManagementPath
	networkAdaptersManagementPath = func(_ context.Context, _ *Client) (*ManagementPath, error) {
		return mp, err
	}
	return func() { networkAdaptersManagementPath = prev }
}

// naPayload builds a minimal valid per-adapter payload.
func naPayload(name string, ifIndex int64, oper, media int, mac string) map[string]any {
	return map[string]any{
		"name":                  name,
		"interface_index":       ifIndex,
		"interface_description": "Test Adapter",
		"mac_address":           mac,
		"oper_status":           oper,
		"media_state":           media,
		"admin_status":          1,
		"link_speed_bps":        1000000000,
		"ndis_medium":           14,
		"ndis_physical_medium":  14,
		"is_virtual":            false,
		"vlan_id":               0,
		"driver_description":    "Test Driver",
		"driver_version":        "1.0",
		"driver_provider":       "Test",
		"mtu_ipv4":              1500,
		"mtu_ipv6":              0,
		"dhcp_enabled":          true,
		"ipv4_addresses":        []string{"192.168.1.10/24"},
		"ipv6_addresses":        []string{"fe80::1/64"},
		"default_gateways":      []string{"192.168.1.1"},
		"dns_servers":           []string{"192.168.1.1"},
		"network_category":      "Private",
	}
}

// naThreeAdapters returns three adapters: Ethernet (Up), Ethernet 2
// (Disconnected) and vEthernet (WSL) (Up, virtual).
func naThreeAdapters() []any {
	eth2 := naPayload("Ethernet 2", 2, 2, 2, "BB-BB-BB-BB-BB-BB")
	eth2["ipv4_addresses"] = []string{}
	eth2["mtu_ipv4"] = 0
	veth := naPayload("vEthernet (WSL)", 3, 1, 1, "CC-CC-CC-CC-CC-CC")
	veth["is_virtual"] = true
	veth["ndis_medium"] = 15
	veth["ndis_physical_medium"] = 0
	return []any{
		naPayload("Ethernet", 1, 1, 1, "AA-BB-CC-DD-EE-FF"),
		eth2,
		veth,
	}
}

// ---------------------------------------------------------------------------
// NetworkAdapterError
// ---------------------------------------------------------------------------

func TestNetworkAdapterError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewNetworkAdapterError(NetworkAdapterErrorAccessDenied, "access denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") {
		t.Errorf("missing kind: %s", msg)
	}
	if !strings.Contains(msg, "boom") {
		t.Errorf("missing cause: %s", msg)
	}
	if e.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestNetworkAdapterError_ErrorWithoutCause(t *testing.T) {
	e := NewNetworkAdapterError(NetworkAdapterErrorUnknown, "weird", nil, nil)
	if !strings.Contains(e.Error(), "weird") {
		t.Errorf("unexpected message: %s", e.Error())
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap should be nil")
	}
}

func TestNetworkAdapterError_Is(t *testing.T) {
	e := NewNetworkAdapterError(NetworkAdapterErrorCIMUnavailable, "cim down", nil, nil)
	if !errors.Is(e, ErrNetworkAdapterCIMUnavailable) {
		t.Error("should match the cim_unavailable sentinel")
	}
	if errors.Is(e, ErrNetworkAdapterAccessDenied) {
		t.Error("must not match a different kind")
	}
	if errors.Is(e, errors.New("x")) {
		t.Error("must not match a foreign error")
	}
	if !IsNetworkAdapterError(e, NetworkAdapterErrorCIMUnavailable) {
		t.Error("IsNetworkAdapterError should match")
	}
	if IsNetworkAdapterError(e, NetworkAdapterErrorTimeout) {
		t.Error("IsNetworkAdapterError must not match a different kind")
	}
}

// ---------------------------------------------------------------------------
// mapNetworkAdaptersKind
// ---------------------------------------------------------------------------

func TestMapNetworkAdaptersKind(t *testing.T) {
	cases := map[string]NetworkAdapterErrorKind{
		"access_denied":     NetworkAdapterErrorAccessDenied,
		"cim_unavailable":   NetworkAdapterErrorCIMUnavailable,
		"timeout":           NetworkAdapterErrorTimeout,
		"invalid_parameter": NetworkAdapterErrorInvalidParameter,
		"bogus":             NetworkAdapterErrorUnknown,
		"":                  NetworkAdapterErrorUnknown,
	}
	for in, want := range cases {
		if got := mapNetworkAdaptersKind(in); got != want {
			t.Errorf("mapNetworkAdaptersKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// deriveNetworkAdapterStatus
// ---------------------------------------------------------------------------

func TestDeriveNetworkAdapterStatus(t *testing.T) {
	cases := []struct {
		name               string
		oper, media, admin int
		want               string
	}{
		{"up", 1, 1, 1, "Up"},
		{"admin down beats everything", 1, 1, 2, "Disabled"},
		{"admin down on missing adapter", 6, 0, 2, "Disabled"},
		{"not present", 6, 2, 1, "NotPresent"},
		{"lower layer down", 7, 2, 1, "NotPresent"},
		{"media disconnected", 1, 2, 1, "Disconnected"},
		{"oper down", 2, 1, 1, "Disconnected"},
		{"oper down media disconnected", 2, 2, 1, "Disconnected"},
		{"testing maps to disconnected", 3, 1, 1, "Disconnected"},
		{"unknown maps to disconnected", 4, 1, 1, "Disconnected"},
		{"dormant maps to disconnected", 5, 1, 1, "Disconnected"},
		{"up oper unknown media", 1, 0, 1, "Disconnected"},
		{"zero triple", 0, 0, 0, "Disconnected"},
		{"admin testing counts as up", 1, 1, 3, "Up"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveNetworkAdapterStatus(tc.oper, tc.media, tc.admin); got != tc.want {
				t.Errorf("deriveNetworkAdapterStatus(%d,%d,%d) = %q, want %q",
					tc.oper, tc.media, tc.admin, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Media tables
// ---------------------------------------------------------------------------

func TestNetworkAdapterMediaTables(t *testing.T) {
	if got := networkAdapterMediaType(14); got != "InfiniBand" {
		t.Errorf("MediaType(14) = %q, want InfiniBand (NDIS_MEDIUM 14)", got)
	}
	if got := networkAdapterMediaType(16); got != "Native802.11" {
		t.Errorf("MediaType(16) = %q, want Native802.11", got)
	}
	if got := networkAdapterMediaType(17); got != "Loopback" {
		t.Errorf("MediaType(17) = %q, want Loopback", got)
	}
	if got := networkAdapterMediaType(99); got != "" {
		t.Errorf("MediaType(99) = %q, want empty", got)
	}
	if got := networkAdapterMediaType(-1); got != "" {
		t.Errorf("MediaType(-1) = %q, want empty", got)
	}
	if got := networkAdapterPhysicalMediaType(14); got != "802.3" {
		t.Errorf("PhysicalMediaType(14) = %q, want 802.3", got)
	}
	if got := networkAdapterPhysicalMediaType(1); got != "WirelessLan" {
		t.Errorf("PhysicalMediaType(1) = %q, want WirelessLan", got)
	}
	if got := networkAdapterPhysicalMediaType(99); got != "" {
		t.Errorf("PhysicalMediaType(99) = %q, want empty", got)
	}
	if got := networkAdapterPhysicalMediaType(-1); got != "" {
		t.Errorf("PhysicalMediaType(-1) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// normalizeNetworkAdapterMAC
// ---------------------------------------------------------------------------

func TestNormalizeNetworkAdapterMAC(t *testing.T) {
	valid := map[string]string{
		"AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff",
		"aa:bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"AABBCCDDEEFF":      "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
	}
	for in, want := range valid {
		if got, err := normalizeNetworkAdapterMAC(in); err != nil || got != want {
			t.Errorf("normalizeNetworkAdapterMAC(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	invalid := []string{
		"ZZ-BB-CC-DD-EE-FF",    // non-hex
		"aa:bb:cc:dd:ee",       // too short
		"aa:bb:cc:dd:ee:ff:00", // too long
		"aa:bb:cc:dd:ee:ff!",   // bad character
		"",
	}
	for _, in := range invalid {
		if _, err := normalizeNetworkAdapterMAC(in); !IsNetworkAdapterError(err, NetworkAdapterErrorInvalidParameter) {
			t.Errorf("normalizeNetworkAdapterMAC(%q) should be invalid_parameter, got %v", in, err)
		}
	}
}

// ---------------------------------------------------------------------------
// CIDR canonicalisation
// ---------------------------------------------------------------------------

func TestCanonicalizeNetworkAdapterCIDR(t *testing.T) {
	cases := map[string]string{
		"192.168.1.10/24":         "192.168.1.10/24", // host bits preserved
		"FE80::1/64":              "fe80::1/64",
		"::ffff:192.168.1.10/120": "192.168.1.10/120", // mapped unmapped
	}
	for in, want := range cases {
		got, err := canonicalizeNetworkAdapterCIDR(in, "h")
		if err != nil || got != want {
			t.Errorf("canonicalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := canonicalizeNetworkAdapterCIDR("bogus", "h"); !IsNetworkAdapterError(err, NetworkAdapterErrorUnknown) {
		t.Errorf("unparsable host value should be unknown, got %v", err)
	}
}

func TestCanonicalizeNetworkAdapterStrings_SortDedupe(t *testing.T) {
	got, err := canonicalizeNetworkAdapterStrings(
		[]string{"192.168.1.20/24", "  ", "10.0.0.1/8", "192.168.1.20/24"},
		"h", canonicalizeNetworkAdapterCIDR)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.0.0.1/8", "192.168.1.20/24"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Script builder: single round-trip, quoting, no exit
// ---------------------------------------------------------------------------

func TestBuildNetworkAdaptersListScript_SingleRoundTrip(t *testing.T) {
	script := buildNetworkAdaptersListScript([]string{"Ethernet"}, true, false)
	for _, call := range []string{
		"Get-NetAdapter @splat",
		"Get-NetIPInterface -ErrorAction Stop",
		"Get-NetIPAddress -ErrorAction Stop",
		"Get-NetRoute -DestinationPrefix",
		"Get-DnsClientServerAddress -ErrorAction Stop",
		"Get-NetConnectionProfile -ErrorAction Stop",
	} {
		if n := strings.Count(script, call); n != 1 {
			t.Errorf("script contains %q %d times, want exactly once", call, n)
		}
	}
	// Line-anchored, case-insensitive: a bare exit would kill the shared
	// persistent session (#81). Substring matching would false-fail on
	// words like "exists".
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(strings.ToLower(line))
		if trimmed == "exit" || strings.HasPrefix(trimmed, "exit ") ||
			strings.HasPrefix(trimmed, "exit;") || strings.HasPrefix(trimmed, "exit\t") {
			t.Errorf("script body contains an exit statement: %q", line)
		}
	}
	if !strings.Contains(script, "$PhysicalOnly = $true") {
		t.Error("physical_only should render as $true")
	}
	if !strings.Contains(script, "$IncludeHidden = $false") {
		t.Error("include_hidden should render as $false")
	}
}

func TestBuildNetworkAdaptersListScript_NamesQuoted(t *testing.T) {
	script := buildNetworkAdaptersListScript([]string{"O'Brien", "Ethernet 2"}, false, true)
	if !strings.Contains(script, "'O''Brien'") {
		t.Error("names must travel through psQuote (doubled single quote)")
	}
	if !strings.Contains(script, "'Ethernet 2'") {
		t.Error("names must be interpolated as PS literals")
	}
	if !strings.Contains(script, "$IncludeHidden = $true") {
		t.Error("include_hidden should render as $true")
	}
}

// ---------------------------------------------------------------------------
// List: filters, sorting, management, envelope mapping
// ---------------------------------------------------------------------------

func TestNetworkAdaptersList_NamesCaseInsensitive(t *testing.T) {
	var calls int
	defer naStubRun(&calls, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, naThreeAdapters()), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{Names: []string{"ETHERNET 2"}})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 host call, got %d", calls)
	}
	if len(got) != 1 || got[0].InterfaceIndex != 2 {
		t.Errorf("expected only Ethernet 2, got %+v", got)
	}
}

func TestNetworkAdaptersList_RegexFilter(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, naThreeAdapters()), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{NameRegex: `vEthernet.*`})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Name != "vEthernet (WSL)" {
		t.Errorf("expected only vEthernet (WSL), got %+v", got)
	}
}

func TestNetworkAdaptersList_MACFilter(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, naThreeAdapters()), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{MACAddress: "bb-bb-bb-bb-bb-bb"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].InterfaceIndex != 2 {
		t.Errorf("expected only Ethernet 2, got %+v", got)
	}
}

func TestNetworkAdaptersList_StatusFilter(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, naThreeAdapters()), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{Status: "up"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].InterfaceIndex != 1 || got[1].InterfaceIndex != 3 {
		t.Errorf("expected Ethernet + vEthernet sorted, got %+v", got)
	}
}

func TestNetworkAdaptersList_InvalidFiltersNoHostCall(t *testing.T) {
	cases := []struct {
		name   string
		filter NetworkAdapterFilter
	}{
		{"bad regex", NetworkAdapterFilter{NameRegex: "([invalid"}},
		{"bad mac", NetworkAdapterFilter{MACAddress: "not-a-mac"}},
		{"bad status", NetworkAdapterFilter{Status: "Sluggish"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			defer naStubRun(&calls, func(_ context.Context, _ *Client, _ string) (string, string, error) {
				return naOK(t, naThreeAdapters()), "", nil
			})()
			defer naStubManagementPath(nil, errors.New("no probe"))()
			_, err := naNewClient(t).List(context.Background(), tc.filter)
			if !IsNetworkAdapterError(err, NetworkAdapterErrorInvalidParameter) {
				t.Errorf("expected invalid_parameter, got %v", err)
			}
			if calls != 0 {
				t.Errorf("invalid filter must not reach the host, got %d calls", calls)
			}
		})
	}
}

func TestNetworkAdaptersList_SortsByInterfaceIndex(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		adapters := naThreeAdapters()
		// Reverse the payload order: the client must sort by ifIndex.
		for i, j := 0, len(adapters)-1; i < j; i, j = i+1, j-1 {
			adapters[i], adapters[j] = adapters[j], adapters[i]
		}
		return naOK(t, adapters), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 adapters, got %d", len(got))
	}
	for i, want := range []int64{1, 2, 3} {
		if got[i].InterfaceIndex != want {
			t.Errorf("position %d: ifIndex = %d, want %d", i, got[i].InterfaceIndex, want)
		}
	}
	if got[0].Status != "Up" || got[1].Status != "Disconnected" {
		t.Errorf("unexpected statuses: %q %q", got[0].Status, got[1].Status)
	}
	if got[0].MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %q, want normalised form", got[0].MACAddress)
	}
	if got[0].MTUIPv6 != 0 {
		t.Errorf("unbound MTU must stay 0 in winclient, got %d", got[0].MTUIPv6)
	}
}

func TestNetworkAdaptersList_IsManagement(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, naThreeAdapters()), "", nil
	})()
	defer naStubManagementPath(&ManagementPath{InterfaceIndex: 3}, nil)()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, a := range got {
		want := a.InterfaceIndex == 3
		if a.IsManagement != want {
			t.Errorf("ifIndex %d: IsManagement = %v, want %v", a.InterfaceIndex, a.IsManagement, want)
		}
	}
}

func TestNetworkAdaptersList_ManagementProbeFailureClearsFlags(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, naThreeAdapters()), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("probe failed"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{})
	if err != nil {
		t.Fatalf("a failed probe must not fail the listing: %v", err)
	}
	for _, a := range got {
		if a.IsManagement {
			t.Errorf("ifIndex %d: IsManagement must be false when the probe fails", a.InterfaceIndex)
		}
	}
}

func TestNetworkAdaptersList_EmptyResultNoError(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, []any{}), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{Status: "Disabled"})
	if err != nil {
		t.Fatalf("empty match must not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %+v", got)
	}
}

func TestNetworkAdaptersList_EnvelopeMapping(t *testing.T) {
	n := naNewClient(t)
	defer naStubManagementPath(nil, errors.New("no probe"))()

	t.Run("transport maps to unknown", func(t *testing.T) {
		defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
			return "", "", errors.New("dial refused")
		})()
		_, err := n.List(context.Background(), NetworkAdapterFilter{})
		if !IsNetworkAdapterError(err, NetworkAdapterErrorUnknown) {
			t.Errorf("expected unknown, got %v", err)
		}
	})

	t.Run("remote access_denied", func(t *testing.T) {
		defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
			return naErr(t, "access_denied", "Access is denied"), "", nil
		})()
		_, err := n.List(context.Background(), NetworkAdapterFilter{})
		if !IsNetworkAdapterError(err, NetworkAdapterErrorAccessDenied) {
			t.Errorf("expected access_denied, got %v", err)
		}
	})

	t.Run("remote cim_unavailable", func(t *testing.T) {
		defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
			return naErr(t, "cim_unavailable", "CimException"), "", nil
		})()
		_, err := n.List(context.Background(), NetworkAdapterFilter{})
		if !IsNetworkAdapterError(err, NetworkAdapterErrorCIMUnavailable) {
			t.Errorf("expected cim_unavailable, got %v", err)
		}
	})

	t.Run("cancelled maps to timeout", func(t *testing.T) {
		defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
			return "", "", errors.New("boom")
		})()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := n.List(ctx, NetworkAdapterFilter{})
		if !IsNetworkAdapterError(err, NetworkAdapterErrorTimeout) {
			t.Errorf("expected timeout, got %v", err)
		}
	})
}

func TestNetworkAdaptersList_NamesNotFoundEmpty(t *testing.T) {
	// Get-NetAdapter -Name <absent> throws a CimCmdlets query-not-found
	// record; the script answers Emit-OK @() for that case (PS-shaped
	// empty), so List returns an empty slice and nil error.
	var calls int
	var script string
	defer naStubRun(&calls, func(_ context.Context, _ *Client, s string) (string, string, error) {
		script = s
		return naOK(t, []any{}), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{Names: []string{"Absent"}})
	if err != nil {
		t.Fatalf("names not-found must return empty, nil error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %+v", got)
	}
	if calls != 1 {
		t.Errorf("expected a single host call, got %d", calls)
	}
	if !strings.Contains(script, "No MSFT_NetAdapter objects found") {
		t.Error("script must carry the not-found guard for the adapters step")
	}
}

func TestNetworkAdaptersList_PerAdapterDegrade(t *testing.T) {
	// One unparsable host MAC and one unparsable address must not abort
	// the whole inventory: bad MAC degrades to "", the bad address is
	// dropped with the rest kept.
	badMAC := naPayload("BadMAC", 1, 1, 1, "ZZ-ZZ-ZZ-ZZ-ZZ-ZZ")
	mixed := naPayload("Mixed", 2, 1, 1, "AA-BB-CC-DD-EE-FF")
	mixed["ipv4_addresses"] = []string{"bogus", "192.168.1.10/24"}
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, []any{badMAC, mixed}), "", nil
	})()
	defer naStubManagementPath(nil, errors.New("no probe"))()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{})
	if err != nil {
		t.Fatalf("per-adapter degrade must not error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 adapters, got %+v", got)
	}
	if got[0].MACAddress != "" {
		t.Errorf("bad host MAC must degrade to empty, got %q", got[0].MACAddress)
	}
	if len(got[1].IPv4Addresses) != 1 || got[1].IPv4Addresses[0] != "192.168.1.10/24" {
		t.Errorf("bad address must be dropped, rest kept: %v", got[1].IPv4Addresses)
	}
}

func TestNetworkAdaptersList_EmptySkipsManagementProbe(t *testing.T) {
	defer naStubRun(nil, func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return naOK(t, []any{}), "", nil
	})()
	var mgmtCalls int
	prev := networkAdaptersManagementPath
	networkAdaptersManagementPath = func(_ context.Context, _ *Client) (*ManagementPath, error) {
		mgmtCalls++
		return nil, errors.New("must not be called")
	}
	defer func() { networkAdaptersManagementPath = prev }()

	got, err := naNewClient(t).List(context.Background(), NetworkAdapterFilter{Status: "Disabled"})
	if err != nil {
		t.Fatalf("empty match must not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %+v", got)
	}
	if mgmtCalls != 0 {
		t.Errorf("empty result must skip the management-path probe (calls=%d)", mgmtCalls)
	}
}
