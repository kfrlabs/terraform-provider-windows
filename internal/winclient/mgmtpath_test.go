// Package winclient — unit tests for the shared management-path guard.
//
// These tests exercise only pure Go helpers (no SSH): SSH_CONNECTION
// parsing, the TouchesAddress / TouchesRoute / WouldHijack decision tables,
// the probe script shape, and the fail-closed parsing of the probe payload.
// The live probe itself is covered by the acceptance suite, which runs
// against a real Windows target.
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testManagementPath returns a ManagementPath resembling a typical lab
// session: client 172.31.248.83 reaches the host at 172.18.122.203,
// default route via 172.18.122.1 on interface 4.
func testManagementPath() *ManagementPath {
	return &ManagementPath{
		ClientIP:               netip.MustParseAddr("172.31.248.83"),
		ServerIP:               netip.MustParseAddr("172.18.122.203"),
		ClientPort:             49890,
		ServerPort:             22,
		InterfaceIndex:         4,
		InterfaceAlias:         "Ethernet",
		RouteDestinationPrefix: "0.0.0.0/0",
		RouteNextHop:           "172.18.122.1",
		RouteInterfaceIndex:    4,
		Source:                 ManagementPathSourceSSH,
	}
}

// ---------------------------------------------------------------------------
// parseManagementSSHConnection
// ---------------------------------------------------------------------------

func TestParseManagementSSHConnection_IPv4(t *testing.T) {
	cIP, sIP, cPort, sPort, err := parseManagementSSHConnection("172.31.248.83 49890 172.18.122.203 22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cIP.String() != "172.31.248.83" || sIP.String() != "172.18.122.203" {
		t.Errorf("IPs = %v, %v; want 172.31.248.83, 172.18.122.203", cIP, sIP)
	}
	if cPort != 49890 || sPort != 22 {
		t.Errorf("ports = %d, %d; want 49890, 22", cPort, sPort)
	}
}

func TestParseManagementSSHConnection_IPv6(t *testing.T) {
	// IPv6 addresses contain no whitespace, so the plain split applies.
	cIP, sIP, _, _, err := parseManagementSSHConnection("fe80::1 51234 fe80::2 22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cIP.String() != "fe80::1" || sIP.String() != "fe80::2" {
		t.Errorf("IPs = %v, %v; want fe80::1, fe80::2", cIP, sIP)
	}
}

func TestParseManagementSSHConnection_IPv4MappedUnmapped(t *testing.T) {
	_, sIP, _, _, err := parseManagementSSHConnection("10.0.0.1 1234 ::ffff:172.18.122.203 22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sIP.String() != "172.18.122.203" || !sIP.Is4() {
		t.Errorf("mapped server IP = %v; want unmapped 172.18.122.203", sIP)
	}
}

func TestParseManagementSSHConnection_MalformedFailClosed(t *testing.T) {
	for _, bad := range []string{
		"",
		"   ",
		"only-two tokens",
		"a b c",
		"not-an-ip 1 2 3",
		"10.0.0.1 1 not-an-ip 22",
		"10.0.0.1 notaport 10.0.0.2 22",
		"10.0.0.1 0 10.0.0.2 22",
		"10.0.0.1 1 10.0.0.2 99999",
	} {
		if _, _, _, _, err := parseManagementSSHConnection(bad); err == nil {
			t.Errorf("connection %q should fail closed, got nil error", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// TouchesAddress
// ---------------------------------------------------------------------------

func TestManagementPathTouchesAddress(t *testing.T) {
	mp := testManagementPath()
	if !mp.TouchesAddress(netip.MustParseAddr("172.18.122.203")) {
		t.Error("the management server IP must touch")
	}
	// IPv4-mapped spelling of the same address touches too.
	if !mp.TouchesAddress(netip.MustParseAddr("::ffff:172.18.122.203")) {
		t.Error("an IPv4-mapped spelling of the management IP must touch")
	}
	for _, other := range []string{"172.18.122.204", "172.31.248.83", "192.0.2.10"} {
		if mp.TouchesAddress(netip.MustParseAddr(other)) {
			t.Errorf("unrelated address %s must not touch", other)
		}
	}
	// Fail-closed inputs never touch (callers refuse unknown paths first).
	var nilPath *ManagementPath
	if nilPath.TouchesAddress(netip.MustParseAddr("172.18.122.203")) {
		t.Error("nil path must not touch")
	}
	if mp.TouchesAddress(netip.Addr{}) {
		t.Error("invalid address must not touch")
	}
	if (&ManagementPath{}).TouchesAddress(netip.MustParseAddr("172.18.122.203")) {
		t.Error("empty path must not touch")
	}
}

// ---------------------------------------------------------------------------
// TouchesRoute
// ---------------------------------------------------------------------------

func TestManagementPathTouchesRoute(t *testing.T) {
	mp := testManagementPath()
	client := netip.MustParseAddr("172.31.248.83")
	other := netip.MustParseAddr("172.18.122.1")

	// A covering route with a different next hop touches.
	if !mp.TouchesRoute(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("172.18.122.99"), 4) {
		t.Error("covering route with a different next hop must touch")
	}
	// A covering route via a different interface touches.
	if !mp.TouchesRoute(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("172.18.122.1"), 7) {
		t.Error("covering route via a different interface must touch")
	}
	// A more specific covering route that reroutes the client touches.
	if !mp.TouchesRoute(netip.MustParsePrefix("172.31.248.0/24"), client, 7) {
		t.Error("covering route via a different interface must touch")
	}
	// The identical route (a no-op re-apply) does not touch.
	if mp.TouchesRoute(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("172.18.122.1"), 4) {
		t.Error("the identical management route must not touch")
	}
	// A route that does not cover the management client never touches.
	if mp.TouchesRoute(netip.MustParsePrefix("192.0.2.0/24"), other, 4) {
		t.Error("a non-covering route must not touch")
	}
	// Nil path, invalid prefix, unparseable current route.
	var nilPath *ManagementPath
	if nilPath.TouchesRoute(netip.MustParsePrefix("0.0.0.0/0"), other, 4) {
		t.Error("nil path must not touch")
	}
	if mp.TouchesRoute(netip.Prefix{}, other, 4) {
		t.Error("invalid prefix must not touch")
	}
	unparseable := testManagementPath()
	unparseable.RouteDestinationPrefix = "not-a-prefix"
	if !unparseable.TouchesRoute(netip.MustParsePrefix("0.0.0.0/0"), other, 9) {
		t.Error("an unparseable current route must fail closed (touch)")
	}
}

// ---------------------------------------------------------------------------
// WouldHijack
// ---------------------------------------------------------------------------

func TestManagementPathWouldHijack(t *testing.T) {
	mp := testManagementPath()
	current := RouteInfo{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.1", InterfaceIndex: 4}

	// Same route re-applied: no hijack.
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.1", InterfaceIndex: 4}, current) {
		t.Error("re-applying the identical route must not hijack")
	}
	// Different next hop: hijack.
	if !mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.99", InterfaceIndex: 4}, current) {
		t.Error("changing the next hop of the management route must hijack")
	}
	// Different interface: hijack.
	if !mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.1", InterfaceIndex: 9}, current) {
		t.Error("moving the management route to another interface must hijack")
	}
	// A candidate that does not cover the client cannot win selection:
	// no hijack (additive semantics; replacement of the management prefix
	// itself is refused by the exact-match check).
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "192.0.2.0/24", NextHop: "172.18.122.1", InterfaceIndex: 4}, current) {
		t.Error("a candidate that does not cover the client must not hijack")
	}
	// Cross-family candidates never hijack (Contains across families is false).
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "2001:db8::/32", NextHop: "fe80::2", InterfaceIndex: 4}, current) {
		t.Error("a cross-family candidate must not hijack")
	}
	// Current route unrelated to the client: no hijack whatever the candidate.
	unrelated := RouteInfo{DestinationPrefix: "192.0.2.0/24", NextHop: "172.18.122.1", InterfaceIndex: 4}
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "192.0.2.0/24", NextHop: "192.0.2.99", InterfaceIndex: 9}, unrelated) {
		t.Error("replacing a route that does not carry the session must not hijack")
	}
	// Nil path never hijacks (callers refuse unknown paths first).
	var nilPath *ManagementPath
	if nilPath.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.99", InterfaceIndex: 4}, current) {
		t.Error("nil path must not hijack")
	}
}

// ---------------------------------------------------------------------------
// WouldHijack — metric-aware selection (windows_net_route, issue #231)
// ---------------------------------------------------------------------------

func TestManagementPathWouldHijackMetricAware(t *testing.T) {
	mp := testManagementPath()
	mgmt := RouteInfo{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.1", InterfaceIndex: 4, EffectiveMetric: 100}

	// A more specific covering route hijacks even with a worse metric:
	// longest-prefix wins regardless of metric.
	if !mp.WouldHijack(RouteCandidate{DestinationPrefix: "172.31.248.0/24", NextHop: "172.18.122.99", InterfaceIndex: 9, EffectiveMetric: 5000}, mgmt) {
		t.Error("a more specific covering route via a different next hop must hijack regardless of metric")
	}
	// Same prefix length, lower effective metric via a different next hop:
	// hijack (the candidate wins the selection).
	if !mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.99", InterfaceIndex: 4, EffectiveMetric: 50}, mgmt) {
		t.Error("same prefix with a lower effective metric via a different next hop must hijack")
	}
	// Same prefix length, tied effective metric: hijack (fail closed —
	// Windows tie-breaking is not stable across builds).
	if !mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.99", InterfaceIndex: 4, EffectiveMetric: 100}, mgmt) {
		t.Error("same prefix with a tied effective metric must hijack (tie fails closed)")
	}
	// Same prefix length, higher effective metric (the supported backup
	// gateway pattern): allowed.
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.99", InterfaceIndex: 9, EffectiveMetric: 500}, mgmt) {
		t.Error("same prefix with a higher effective metric must not hijack (backup gateway pattern)")
	}
	// A less specific candidate never hijacks: it cannot win the
	// longest-prefix selection. (Covered with a /0 current best via a
	// narrower current route.)
	narrowMgmt := RouteInfo{DestinationPrefix: "172.31.0.0/16", NextHop: "172.18.122.1", InterfaceIndex: 4, EffectiveMetric: 100}
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.99", InterfaceIndex: 9, EffectiveMetric: 1}, narrowMgmt) {
		t.Error("a less specific candidate must not hijack even with the best metric")
	}
	// The identical route re-applied never hijacks, even on a metric tie.
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.1", InterfaceIndex: 4, EffectiveMetric: 100}, mgmt) {
		t.Error("re-applying the identical route must not hijack")
	}
	// A more specific route via the SAME next hop and interface does not
	// divert the traffic.
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "172.31.248.0/24", NextHop: "172.18.122.1", InterfaceIndex: 4, EffectiveMetric: 5000}, mgmt) {
		t.Error("a more specific route via the same next hop and interface must not hijack")
	}
	// Unknown current metric compares as a tie: the create path passes the
	// candidate metric for both sides when the probe fails.
	tied := mgmt
	tied.EffectiveMetric = 50
	if !mp.WouldHijack(RouteCandidate{DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.99", InterfaceIndex: 4, EffectiveMetric: 50}, tied) {
		t.Error("an unknown current metric must compare as a tie (fail closed)")
	}
	// IPv6: a covering route for this client's prefix hijacks; a route for
	// another family never does.
	mp6 := testManagementPath()
	mp6.ClientIP = netip.MustParseAddr("2001:db8:1::99")
	v6Mgmt := RouteInfo{DestinationPrefix: "2001:db8::/32", NextHop: "fe80::1", InterfaceIndex: 4, EffectiveMetric: 100}
	if !mp6.WouldHijack(RouteCandidate{DestinationPrefix: "2001:db8:1::/48", NextHop: "fe80::2", InterfaceIndex: 9, EffectiveMetric: 5000}, v6Mgmt) {
		t.Error("a more specific IPv6 covering route must hijack")
	}
	if mp.WouldHijack(RouteCandidate{DestinationPrefix: "2001:db8::/32", NextHop: "fe80::2", InterfaceIndex: 4, EffectiveMetric: 1}, v6Mgmt) {
		t.Error("a candidate covering another client's prefix must not hijack this session")
	}
}

// ---------------------------------------------------------------------------
// Probe script shape (pure assertions, no SSH)
// ---------------------------------------------------------------------------

func TestBuildMgmtPathScript_Probes(t *testing.T) {
	script := buildMgmtPathScript(2222)
	for _, want := range []string{
		"$env:SSH_CONNECTION",
		"Get-NetTCPConnection",
		"Get-NetIPAddress",
		"Find-NetRoute",
		"DestinationPrefix",
		"2222",
		"'ssh_connection'",
		"'tcp_connection'",
		"'unknown'",
		"InvariantCulture",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("probe script missing %q", want)
		}
	}
	// The sshd port is rendered at build time; the fallback source port
	// stays an execution-time placeholder so run/runOneShot substitute the
	// session that actually executes the probe (issue #230).
	if strings.Contains(script, "@@SSHPORT@@") {
		t.Error("probe script still carries an unreplaced @@SSHPORT@@ placeholder")
	}
	if !strings.Contains(script, "@@LOCALPORT@@") {
		t.Error("probe script must defer the fallback port to execution time via @@LOCALPORT@@")
	}
}

// ---------------------------------------------------------------------------
// parseManagementPath (fail-closed payload parsing)
// ---------------------------------------------------------------------------

func mgmtPathEnvelope(t *testing.T, data any) *Envelope {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return &env
}

func TestParseManagementPath_HappyPath(t *testing.T) {
	resp := mgmtPathEnvelope(t, map[string]any{
		"client_ip": "172.31.248.83", "client_port": 49890,
		"server_ip": "172.18.122.203", "server_port": 22,
		"interface_index": 4, "interface_alias": "Ethernet",
		"route_destination_prefix": "0.0.0.0/0",
		"route_next_hop":           "172.18.122.1",
		"route_interface_index":    4,
		"source":                   "ssh_connection",
	})
	mp, err := parseManagementPath(resp, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mp.ServerIP.String() != "172.18.122.203" || mp.ClientIP.String() != "172.31.248.83" {
		t.Errorf("unexpected IPs: %+v", mp)
	}
	if mp.Source != ManagementPathSourceSSH {
		t.Errorf("source = %q, want ssh_connection", mp.Source)
	}
	if !mp.TouchesAddress(netip.MustParseAddr("172.18.122.203")) {
		t.Error("parsed path must touch its own server IP")
	}
}

func TestParseManagementPath_FailClosed(t *testing.T) {
	bad := []struct {
		name string
		data any
	}{
		{"null data", nil},
		{"bad client IP", map[string]any{"client_ip": "nope", "client_port": 1, "server_ip": "10.0.0.2", "server_port": 22, "interface_index": 4, "interface_alias": "Ethernet", "route_destination_prefix": "0.0.0.0/0", "source": "ssh_connection"}},
		{"bad server IP", map[string]any{"client_ip": "10.0.0.1", "client_port": 1, "server_ip": "nope", "server_port": 22, "interface_index": 4, "interface_alias": "Ethernet", "route_destination_prefix": "0.0.0.0/0", "source": "ssh_connection"}},
		{"zero ports", map[string]any{"client_ip": "10.0.0.1", "client_port": 0, "server_ip": "10.0.0.2", "server_port": 22, "interface_index": 4, "interface_alias": "Ethernet", "route_destination_prefix": "0.0.0.0/0", "source": "ssh_connection"}},
		{"no interface", map[string]any{"client_ip": "10.0.0.1", "client_port": 1, "server_ip": "10.0.0.2", "server_port": 22, "interface_index": 0, "interface_alias": "", "route_destination_prefix": "0.0.0.0/0", "source": "ssh_connection"}},
		{"no route", map[string]any{"client_ip": "10.0.0.1", "client_port": 1, "server_ip": "10.0.0.2", "server_port": 22, "interface_index": 4, "interface_alias": "Ethernet", "route_destination_prefix": "", "source": "ssh_connection"}},
		{"unparsable route destination prefix", map[string]any{"client_ip": "10.0.0.1", "client_port": 1, "server_ip": "10.0.0.2", "server_port": 22, "interface_index": 4, "interface_alias": "Ethernet", "route_destination_prefix": "not-a-prefix", "route_next_hop": "10.0.0.254", "route_interface_index": 4, "source": "ssh_connection"}},
		{"unparsable route next hop", map[string]any{"client_ip": "10.0.0.1", "client_port": 1, "server_ip": "10.0.0.2", "server_port": 22, "interface_index": 4, "interface_alias": "Ethernet", "route_destination_prefix": "0.0.0.0/0", "route_next_hop": "not-an-ip", "route_interface_index": 4, "source": "ssh_connection"}},
		{"unknown source", map[string]any{"client_ip": "10.0.0.1", "client_port": 1, "server_ip": "10.0.0.2", "server_port": 22, "interface_index": 4, "interface_alias": "Ethernet", "route_destination_prefix": "0.0.0.0/0", "source": "carrier_pigeon"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			var resp *Envelope
			if tc.data == nil {
				resp = &Envelope{OK: true, Data: json.RawMessage("null")}
			} else {
				resp = mgmtPathEnvelope(t, tc.data)
			}
			if _, err := parseManagementPath(resp, nil); !errors.Is(err, ErrManagementPathUnknown) {
				t.Errorf("expected unknown, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Client.ManagementPath transport failure (loopback, no SSH)
// ---------------------------------------------------------------------------

func TestClientManagementPath_TransportFailsClosed(t *testing.T) {
	// Nothing listens on 127.0.0.1:1, so dial fails immediately and the
	// probe reports unknown instead of guessing.
	c, err := New(Config{
		Host: "127.0.0.1", Port: 1, Username: "u", Password: "p",
		Timeout: 5 * time.Second, InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.ManagementPath(context.Background()); !errors.Is(err, ErrManagementPathUnknown) {
		t.Errorf("expected unknown on transport failure, got %v", err)
	}
}

func TestManagementPathError_Is(t *testing.T) {
	e := NewManagementPathError(ManagementPathErrorUnknown, "x", nil, nil)
	if !errors.Is(e, ErrManagementPathUnknown) {
		t.Error("errors.Is(ErrManagementPathUnknown) should match")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against a plain error should be false")
	}
}
