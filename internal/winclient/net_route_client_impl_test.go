// Package winclient — unit tests for NetRouteClientImpl and the
// management-path guard integration.
//
// The package-level seams runNetRoutePowerShell (script transport) and
// netRouteManagementPath (guard probe) are stubbed so no real SSH
// connection is needed. Coverage targets (issue #231):
//
//	NetRouteError: Error(), Unwrap(), Is(), sentinels
//	mapNetRouteKind: all remote kinds + unknown fallback
//	normalize/validate: canonical masked prefixes, host-bits rejection,
//	                    family agreement, next-hop rejections, metric range
//	script builders: user values only via psQuote, exact -eq alias match,
//	                 -InterfaceIndex + Where-Object triplet, no -PolicyStore
//	                 anywhere (New/Set-Remove default to both stores)
//	envelope mapping: unreachable on transport/timeout, typed remote kinds
//	Create/Read/Lookup/Update/Delete: happy paths, pre-flight kinds,
//	 guard refusals (exact + hijack), unsafe_skip bypass, single
//	 management probe per op, import hint, blank-alias handling
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nrNewClient returns a *NetRouteClientImpl for tests.
func nrNewClient(t *testing.T) *NetRouteClientImpl {
	t.Helper()
	c, err := New(Config{Host: "winroute01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewNetRouteClient(c)
}

// nrOK returns a JSON ok-envelope whose data field is the supplied value.
func nrOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("nrOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// nrErr returns a JSON error-envelope for the given kind/message.
func nrErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("nrErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// nrStubRun replaces runNetRoutePowerShell for one test.
func nrStubRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runNetRoutePowerShell
	runNetRoutePowerShell = fn
	return func() { runNetRoutePowerShell = prev }
}

// nrStubSequence stubs runNetRoutePowerShell with a fixed ordered list of
// responses. After the last one, every subsequent call replays it.
func nrStubSequence(responses []frResponse) func() {
	i := 0
	calls := 0
	_ = calls
	return nrStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		r := responses[i]
		if i < len(responses)-1 {
			i++
		}
		return r.stdout, r.stderr, r.err
	})
}

// nrStubManagementPath replaces the guard probe for one test and counts
// calls so tests can assert a single probe per operation.
func nrStubManagementPath(mp *ManagementPath, err error, calls *int) func() {
	prev := netRouteManagementPath
	netRouteManagementPath = func(_ context.Context, _ *Client) (*ManagementPath, error) {
		if calls != nil {
			*calls++
		}
		return mp, err
	}
	return func() { netRouteManagementPath = prev }
}

// testNetRouteJSON is a minimal valid ConvertTo-NetRouteJson payload.
func testNetRouteJSON() map[string]any {
	return map[string]any{
		"interface_alias":    "Ethernet 2",
		"interface_index":    7,
		"destination_prefix": "198.51.100.0/24",
		"next_hop":           "192.0.2.1",
		"route_metric":       10,
		"interface_metric":   25,
		"effective_metric":   35,
		"protocol":           "NetMgmt",
	}
}

// nrResolveOK is the resolve-only probe response for the given index.
func nrResolveOK(t *testing.T, index int) string {
	t.Helper()
	return nrOK(t, map[string]any{"interface_index": index, "interface_alias": "Ethernet 2", "interface_metric": 25})
}

// nrMgmtMetricOK is the management-route metric probe response.
func nrMgmtMetricOK(t *testing.T, routeMetric, ifMetric int) string {
	t.Helper()
	return nrOK(t, map[string]any{"route_metric": routeMetric, "interface_metric": ifMetric})
}

// nrUnrelatedPath is a guard probe result that no test candidate touches:
// the observed best route does not cover the session client, so WouldHijack
// short-circuits to false for every candidate.
func nrUnrelatedPath() *ManagementPath {
	mp := testManagementPath()
	mp.ClientIP = netip.MustParseAddr("10.255.255.99")
	mp.RouteDestinationPrefix = "192.168.0.0/16"
	mp.RouteNextHop = "192.168.0.1"
	return mp
}

// ---------------------------------------------------------------------------
// NetRouteError
// ---------------------------------------------------------------------------

func TestNetRouteError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewNetRouteError(NetRouteErrorPermission, "denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewNetRouteError(NetRouteErrorUnknown, "bad", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestNetRouteError_Is(t *testing.T) {
	e := NewNetRouteError(NetRouteErrorMgmtAtRisk, "x", nil, nil)
	if !errors.Is(e, ErrNetRouteMgmtAtRisk) {
		t.Error("errors.Is(ErrNetRouteMgmtAtRisk) should match by kind")
	}
	if errors.Is(e, ErrNetRouteMgmtUnknown) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsNetRouteError(e, NetRouteErrorMgmtAtRisk) {
		t.Error("IsNetRouteError should match")
	}
	if IsNetRouteError(errors.New("plain"), NetRouteErrorMgmtAtRisk) {
		t.Error("IsNetRouteError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-NetRouteError should be false")
	}
}

func TestMapNetRouteKind(t *testing.T) {
	cases := map[string]NetRouteErrorKind{
		"interface_not_found":           NetRouteErrorInterfaceNotFound,
		"not_found":                     NetRouteErrorNotFound,
		"already_exists":                NetRouteErrorAlreadyExists,
		"route_owned_by_other_protocol": NetRouteErrorOwnedByOtherProtocol,
		"invalid_route":                 NetRouteErrorInvalidRoute,
		"next_hop_unreachable":          NetRouteErrorNextHopUnreachable,
		"permission_denied":             NetRouteErrorPermission,
		"management_path_at_risk":       NetRouteErrorMgmtAtRisk,
		"management_path_unknown":       NetRouteErrorMgmtUnknown,
		"":                              NetRouteErrorUnknown,
		"weird_kind":                    NetRouteErrorUnknown,
		"address_in_use_elsewhere":      NetRouteErrorUnknown,
		"management_path_at_risk ":      NetRouteErrorUnknown,
	}
	for in, want := range cases {
		if got := mapNetRouteKind(in); got != want {
			t.Errorf("mapNetRouteKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// normalize + validate
// ---------------------------------------------------------------------------

func TestNormalizeNetRouteTriplet(t *testing.T) {
	prefix, nextHop, isV6, err := normalizeNetRouteTriplet("Ethernet 2", "198.51.100.0/24", "192.0.2.1")
	if err != nil || prefix != "198.51.100.0/24" || nextHop != "192.0.2.1" || isV6 {
		t.Errorf("ipv4 = %q, %q, %v, %v", prefix, nextHop, isV6, err)
	}
	// Unmasked prefixes are normalised here (strict rejection is
	// validate-only).
	prefix, _, _, err = normalizeNetRouteTriplet("Ethernet 2", "198.51.100.7/24", "192.0.2.1")
	if err != nil || prefix != "198.51.100.0/24" {
		t.Errorf("unmasked normalise = %q, %v; want 198.51.100.0/24, nil", prefix, err)
	}
	// IPv6 + on-link unspecified next hop.
	prefix, nextHop, isV6, err = normalizeNetRouteTriplet("Ethernet 2", "2001:db8::/32", "::")
	if err != nil || prefix != "2001:db8::/32" || nextHop != "::" || !isV6 {
		t.Errorf("ipv6 onlink = %q, %q, %v, %v", prefix, nextHop, isV6, err)
	}
	// IPv4-mapped next hop unmaps.
	_, nextHop, isV6, err = normalizeNetRouteTriplet("Ethernet 2", "198.51.100.0/24", "::ffff:192.0.2.1")
	if err != nil || nextHop != "192.0.2.1" || isV6 {
		t.Errorf("mapped nexthop = %q, %v, %v; want 192.0.2.1, false, nil", nextHop, isV6, err)
	}
	// Default routes.
	if _, _, _, err = normalizeNetRouteTriplet("Ethernet 2", "0.0.0.0/0", "192.0.2.1"); err != nil {
		t.Errorf("default v4 rejected: %v", err)
	}
	if _, _, _, err = normalizeNetRouteTriplet("Ethernet 2", "::/0", "fe80::1"); err != nil {
		t.Errorf("default v6 rejected: %v", err)
	}

	bad := []struct {
		name   string
		alias  string
		prefix string
		next   string
	}{
		{"empty alias", "", "198.51.100.0/24", "192.0.2.1"},
		{"bad prefix", "Ethernet 2", "not-a-prefix", "192.0.2.1"},
		{"bad next hop", "Ethernet 2", "198.51.100.0/24", "not-an-ip"},
		{"family mismatch", "Ethernet 2", "198.51.100.0/24", "fe80::1"},
		{"family mismatch v6", "Ethernet 2", "2001:db8::/32", "192.0.2.1"},
		{"multicast", "Ethernet 2", "198.51.100.0/24", "224.0.0.1"},
		{"multicast v6", "Ethernet 2", "2001:db8::/32", "ff02::1"},
		{"loopback", "Ethernet 2", "198.51.100.0/24", "127.0.0.1"},
		{"broadcast", "Ethernet 2", "198.51.100.0/24", "255.255.255.255"},
		{"zone id", "Ethernet 2", "2001:db8::/32", "fe80::1%12"},
	}
	for _, tc := range bad {
		if _, _, _, err := normalizeNetRouteTriplet(tc.alias, tc.prefix, tc.next); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		} else if !IsNetRouteError(err, NetRouteErrorInvalidRoute) && !IsNetRouteError(err, NetRouteErrorInterfaceNotFound) {
			t.Errorf("%s: expected invalid_route/interface_not_found, got %v", tc.name, err)
		}
	}
}

func TestValidateNetRouteInput(t *testing.T) {
	// Canonical masked form passes.
	if _, _, _, err := validateNetRouteInput("Ethernet 2", "198.51.100.0/24", "192.0.2.1", 10); err != nil {
		t.Errorf("canonical input rejected: %v", err)
	}
	// Host bits set names the canonical form.
	_, _, _, err := validateNetRouteInput("Ethernet 2", "198.51.100.7/24", "192.0.2.1", 10)
	if !IsNetRouteError(err, NetRouteErrorInvalidRoute) || !strings.Contains(err.Error(), "198.51.100.0/24") {
		t.Errorf("host bits must name 198.51.100.0/24, got %v", err)
	}
	// IPv6 host bits.
	_, _, _, err = validateNetRouteInput("Ethernet 2", "2001:db8::1/32", "fe80::1", 10)
	if !IsNetRouteError(err, NetRouteErrorInvalidRoute) || !strings.Contains(err.Error(), "2001:db8::/32") {
		t.Errorf("ipv6 host bits must name 2001:db8::/32, got %v", err)
	}
	// Metric range 0-9999 (Windows default 256 accepted).
	for _, metric := range []int{-1, 10000} {
		if _, _, _, err := validateNetRouteInput("Ethernet 2", "198.51.100.0/24", "192.0.2.1", metric); !IsNetRouteError(err, NetRouteErrorInvalidRoute) {
			t.Errorf("metric %d: expected invalid_route, got %v", metric, err)
		}
	}
	for _, metric := range []int{0, 256, 9999} {
		if _, _, _, err := validateNetRouteInput("Ethernet 2", "198.51.100.0/24", "192.0.2.1", metric); err != nil {
			t.Errorf("metric %d rejected: %v", metric, err)
		}
	}
	// /32 and /128 host routes pass.
	if _, _, _, err := validateNetRouteInput("Ethernet 2", "192.0.2.1/32", "192.0.2.1", 10); err != nil {
		t.Errorf("/32 rejected: %v", err)
	}
	if _, _, _, err := validateNetRouteInput("Ethernet 2", "2001:db8::1/128", "fe80::1", 10); err != nil {
		t.Errorf("/128 rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Script builders: quoting, exact match, no -PolicyStore
// ---------------------------------------------------------------------------

func TestNetRouteScripts_QuotingAndSemantics(t *testing.T) {
	evil := "Ethernet [2]'; Write-Host pwned; '"
	scripts := map[string]string{
		"resolve": buildNetRouteResolveScript(evil, false),
		"read":    buildNetRouteReadScript(evil, "198.51.100.0/24", "192.0.2.1", false),
		"lookup":  buildNetRouteLookupScript("198.51.100.0/24", evil, "192.0.2.1"),
		"create":  buildNetRouteCreateScript(evil, "198.51.100.0/24", "192.0.2.1", 10, false),
		"set":     buildNetRouteSetScript(evil, "198.51.100.0/24", "192.0.2.1", 10, false),
		"remove":  buildNetRouteRemoveScript(evil, "198.51.100.0/24", "192.0.2.1", false),
		"mgmt":    buildNetRouteMgmtRouteScript("0.0.0.0/0", "172.18.122.1", 4),
	}
	for name, script := range scripts {
		if name == "mgmt" {
			continue // the metric probe takes no alias: nothing to quote
		}
		if strings.Contains(script, evil) {
			t.Errorf("%s script interpolates the raw value", name)
		}
		if !strings.Contains(script, psQuote(evil)) {
			t.Errorf("%s script must carry the psQuote'd alias", name)
		}
	}
	// The triplet is matched with -eq on DestinationPrefix and NextHop
	// behind -InterfaceIndex, never wildcard-capable parameters.
	for _, name := range []string{"read", "create", "set", "remove"} {
		script := scripts[name]
		if !strings.Contains(script, "Get-NetRoute -InterfaceIndex $ifIndex") {
			t.Errorf("%s script must query Get-NetRoute with -InterfaceIndex", name)
		}
		if !strings.Contains(script, "$_.DestinationPrefix -eq $wantPrefix") || !strings.Contains(script, "$_.NextHop -eq $wantNextHop") {
			t.Errorf("%s script must filter the triplet with exact -eq", name)
		}
	}
	if !strings.Contains(scripts["lookup"], "$_.DestinationPrefix -eq $wantPrefix") {
		t.Error("lookup script must filter the prefix with exact -eq")
	}
	// Alias resolution is exact -eq, never -InterfaceAlias wildcard
	// parameter semantics.
	for _, name := range []string{"resolve", "read", "create", "set", "remove"} {
		if !strings.Contains(scripts[name], "Where-Object { $_.InterfaceAlias -eq $alias }") {
			t.Errorf("%s script must resolve the alias with exact -eq comparison", name)
		}
		if strings.Contains(scripts[name], "-InterfaceAlias $alias") {
			t.Errorf("%s script must not pass the alias to -InterfaceAlias (wildcard semantics)", name)
		}
	}
	// No script passes -PolicyStore: New/Set/Remove-NetRoute default to both
	// stores (reboot-surviving), and -PolicyStore PersistentStore is rejected
	// by New-NetRoute ("Invalid parameter"). Reads observe the effective
	// ActiveStore view; persistence itself is asserted by the acceptance
	// suite (Get-NetRoute -PolicyStore PersistentStore).
	for _, name := range []string{"resolve", "read", "lookup", "create", "set", "remove", "mgmt"} {
		if strings.Contains(scripts[name], "-PolicyStore") {
			t.Errorf("%s script must not pass -PolicyStore", name)
		}
	}
	// Delete is idempotent via -Confirm:$false and null-tolerant readback.
	if !strings.Contains(scripts["remove"], "-Confirm:$false") {
		t.Error("remove script must pass -Confirm:$false")
	}
	// Protocol discrimination in the create pre-flight.
	for _, want := range []string{"'already_exists'", "'route_owned_by_other_protocol'", "terraform import"} {
		if !strings.Contains(scripts["create"], want) {
			t.Errorf("create script must handle %q", want)
		}
	}
	// Locale pinning for enum decoding.
	if !strings.Contains(scripts["create"], "InvariantCulture") {
		t.Error("create script must pin InvariantCulture for enum decoding")
	}
	// Classify prefers codes over localized text.
	for _, want := range []string{
		"0x80070005", "0x80070490", "0x800700B7", "0x80070057",
		"No matching MSFT_NetRoute", "No MSFT_NetIPInterface", "unreachable",
		"'permission_denied'", "'not_found'", "'interface_not_found'",
		"'already_exists'", "'invalid_route'", "'next_hop_unreachable'",
	} {
		if !strings.Contains(scripts["create"], want) {
			t.Errorf("Classify-NetRoute must handle %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Envelope mapping: transport/timeout/remote
// ---------------------------------------------------------------------------

func TestNetRouteEnvelope_TransportMapsUnreachable(t *testing.T) {
	restore := nrStubSequence([]frResponse{{stdout: "", stderr: "boom", err: errors.New("ssh dial failed")}})
	defer restore()
	defer nrStubManagementPath(nrUnrelatedPath(), nil, nil)()
	c := nrNewClient(t)
	_, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "192.0.2.1", RouteMetric: 10,
	})
	if !IsNetRouteError(err, NetRouteErrorUnreachable) {
		t.Errorf("transport failure must map to unreachable, got %v", err)
	}
}

func TestNetRouteEnvelope_RemoteKinds(t *testing.T) {
	cases := map[string]NetRouteErrorKind{
		"interface_not_found":           NetRouteErrorInterfaceNotFound,
		"not_found":                     NetRouteErrorNotFound,
		"already_exists":                NetRouteErrorAlreadyExists,
		"route_owned_by_other_protocol": NetRouteErrorOwnedByOtherProtocol,
		"invalid_route":                 NetRouteErrorInvalidRoute,
		"next_hop_unreachable":          NetRouteErrorNextHopUnreachable,
		"permission_denied":             NetRouteErrorPermission,
	}
	for kind, want := range cases {
		restore := nrStubSequence([]frResponse{{stdout: nrErr(t, kind, "host says no"), stderr: "", err: nil}})
		defer restore()
		c := nrNewClient(t)
		// Lookup propagates every remote kind (Read maps not_found and
		// interface_not_found to a state drop instead).
		_, err := c.Lookup(context.Background(), "198.51.100.0/24", "", "")
		if !IsNetRouteError(err, want) {
			t.Errorf("remote kind %q must map to %q, got %v", kind, want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// parseNetRouteInfo
// ---------------------------------------------------------------------------

func TestParseNetRouteInfo(t *testing.T) {
	raw, _ := json.Marshal(testNetRouteJSON())
	info, err := parseNetRouteInfo(raw, "winroute01")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.DestinationPrefix != "198.51.100.0/24" || info.NextHop != "192.0.2.1" {
		t.Errorf("identity = %q via %q", info.DestinationPrefix, info.NextHop)
	}
	// Effective metric is recomputed Go-side, never trusted from the host.
	if info.EffectiveMetric != info.RouteMetric+info.InterfaceMetric || info.EffectiveMetric != 35 {
		t.Errorf("effective = %d, want route+interface = 35", info.EffectiveMetric)
	}
	if info.AddressFamily != "IPv4" || info.Protocol != "NetMgmt" {
		t.Errorf("family/protocol = %q/%q", info.AddressFamily, info.Protocol)
	}
	// IPv6 canonicalisation + family.
	raw, _ = json.Marshal(map[string]any{
		"interface_alias": "Ethernet 2", "interface_index": 7,
		"destination_prefix": "2001:DB8::/32", "next_hop": "FE80::1",
		"route_metric": 10, "interface_metric": 5, "effective_metric": 0, "protocol": "NetMgmt",
	})
	info, err = parseNetRouteInfo(raw, "winroute01")
	if err != nil {
		t.Fatalf("parse v6: %v", err)
	}
	if info.DestinationPrefix != "2001:db8::/32" || info.NextHop != "fe80::1" || info.AddressFamily != "IPv6" {
		t.Errorf("v6 canonical = %q via %q %q", info.DestinationPrefix, info.NextHop, info.AddressFamily)
	}
	if info.EffectiveMetric != 15 {
		t.Errorf("v6 effective = %d, want 15", info.EffectiveMetric)
	}
	for _, bad := range []map[string]any{
		{"destination_prefix": "nope", "next_hop": "192.0.2.1"},
		{"destination_prefix": "198.51.100.0/24", "next_hop": "nope"},
	} {
		raw, _ := json.Marshal(bad)
		if _, err := parseNetRouteInfo(raw, "winroute01"); err == nil {
			t.Errorf("unparsable payload %v must fail", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Create: happy path, pre-flights, guard
// ---------------------------------------------------------------------------

func TestNetRouteCreate_HappyPath(t *testing.T) {
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrMgmtMetricOK(t, 256, 25), err: nil},
		{stdout: nrOK(t, testNetRouteJSON()), err: nil},
	})
	defer restore()
	var mgmtCalls int
	defer nrStubManagementPath(nrUnrelatedPath(), nil, &mgmtCalls)()
	c := nrNewClient(t)
	info, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "192.0.2.1", RouteMetric: 10,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if info.DestinationPrefix != "198.51.100.0/24" || info.NextHop != "192.0.2.1" || info.InterfaceIndex != 7 {
		t.Errorf("unexpected info: %+v", info)
	}
	if mgmtCalls != 1 {
		t.Errorf("one management probe per operation, got %d", mgmtCalls)
	}
}

func TestNetRouteCreate_Preflights(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want NetRouteErrorKind
	}{
		{"already_exists", NetRouteErrorAlreadyExists},
		{"route_owned_by_other_protocol", NetRouteErrorOwnedByOtherProtocol},
	} {
		restore := nrStubSequence([]frResponse{
			{stdout: nrResolveOK(t, 7), err: nil},
			{stdout: nrMgmtMetricOK(t, 256, 25), err: nil},
			{stdout: nrErr(t, tc.kind, "preflight hit"), err: nil},
		})
		defer restore()
		defer nrStubManagementPath(nrUnrelatedPath(), nil, nil)()
		c := nrNewClient(t)
		_, err := c.Create(context.Background(), NetRouteInput{
			InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "192.0.2.1", RouteMetric: 10,
		})
		if !IsNetRouteError(err, tc.want) {
			t.Errorf("kind %q: expected %q, got %v", tc.kind, tc.want, err)
		}
	}
	// already_exists must suggest import.
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrMgmtMetricOK(t, 256, 25), err: nil},
		{stdout: nrErr(t, "already_exists", "Route 198.51.100.0/24 via 192.0.2.1 already exists. Import it with terraform import"), err: nil},
	})
	defer restore()
	defer nrStubManagementPath(nrUnrelatedPath(), nil, nil)()
	c := nrNewClient(t)
	_, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "192.0.2.1", RouteMetric: 10,
	})
	if !IsNetRouteError(err, NetRouteErrorAlreadyExists) || !strings.Contains(err.Error(), "terraform import") {
		t.Errorf("already_exists must suggest import, got %v", err)
	}
}

func TestNetRouteCreate_GuardExactManagementRoute(t *testing.T) {
	// The candidate IS the management route: refused before any mutation.
	// Only the resolve probe runs; the create script never executes.
	runs := 0
	restore := nrStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		runs++
		return nrResolveOK(t, 4), "", nil
	})
	defer restore()
	var mgmtCalls int
	defer nrStubManagementPath(testManagementPath(), nil, &mgmtCalls)()
	c := nrNewClient(t)
	_, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet", DestinationPrefix: "0.0.0.0/0", NextHop: "172.18.122.1", RouteMetric: 10,
	})
	if !IsNetRouteError(err, NetRouteErrorMgmtAtRisk) {
		t.Fatalf("expected management_path_at_risk, got %v", err)
	}
	if !strings.Contains(err.Error(), "unsafe_skip_management_check") {
		t.Errorf("refusal must name the escape hatch: %v", err)
	}
	if mgmtCalls != 1 {
		t.Errorf("one management probe per operation, got %d", mgmtCalls)
	}
	if runs != 1 {
		t.Errorf("guard must refuse before the create script runs (want 1 probe call, got %d)", runs)
	}
}

func TestNetRouteCreate_GuardHijack(t *testing.T) {
	// A more specific covering route via a different next hop hijacks.
	runs := 0
	restore := nrStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		runs++
		if strings.Contains(script, "$wantIfIndex") {
			return nrMgmtMetricOK(t, 256, 25), "", nil
		}
		return nrResolveOK(t, 7), "", nil
	})
	defer restore()
	defer nrStubManagementPath(testManagementPath(), nil, nil)()
	c := nrNewClient(t)
	_, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet 2", DestinationPrefix: "172.31.248.0/24", NextHop: "192.0.2.1", RouteMetric: 10,
	})
	if !IsNetRouteError(err, NetRouteErrorMgmtAtRisk) {
		t.Fatalf("expected management_path_at_risk for hijack candidate, got %v", err)
	}
	if runs != 2 {
		t.Errorf("guard must refuse before the create script runs (want 2 probe calls, got %d)", runs)
	}
}

func TestNetRouteCreate_GuardUnknownFailClosed(t *testing.T) {
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
	})
	defer restore()
	defer nrStubManagementPath(nil, NewManagementPathError(ManagementPathErrorUnknown, "no SSH_CONNECTION", nil, nil), nil)()
	c := nrNewClient(t)
	_, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "192.0.2.1", RouteMetric: 10,
	})
	if !IsNetRouteError(err, NetRouteErrorMgmtUnknown) {
		t.Fatalf("expected management_path_unknown, got %v", err)
	}
}

func TestNetRouteCreate_UnsafeSkipBypassesGuard(t *testing.T) {
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrOK(t, testNetRouteJSON()), err: nil},
	})
	defer restore()
	var mgmtCalls int
	defer nrStubManagementPath(nil, errors.New("must not be called"), &mgmtCalls)()
	c := nrNewClient(t)
	info, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "192.0.2.1", RouteMetric: 10,
		UnsafeSkipManagementCheck: true,
	})
	if err != nil {
		t.Fatalf("Create with skip: %v", err)
	}
	if info == nil || mgmtCalls != 0 {
		t.Errorf("skip must bypass the probe entirely (calls=%d)", mgmtCalls)
	}
}

func TestNetRouteCreate_BackupGatewayAllowed(t *testing.T) {
	// Same prefix length but a HIGHER effective metric than the management
	// route: the backup-gateway pattern is allowed.
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrMgmtMetricOK(t, 10, 15), err: nil}, // management eff 25
		{stdout: nrOK(t, testNetRouteJSON()), err: nil},
	})
	defer restore()
	mp := testManagementPath()
	defer nrStubManagementPath(mp, nil, nil)()
	c := nrNewClient(t)
	_, err := c.Create(context.Background(), NetRouteInput{
		InterfaceAlias: "Ethernet 2", DestinationPrefix: "0.0.0.0/0", NextHop: "192.0.2.254", RouteMetric: 500,
	})
	if err != nil {
		t.Errorf("backup gateway (higher metric) must be allowed, got %v", err)
	}
}

func TestNetRouteCreate_InvalidInput(t *testing.T) {
	c := nrNewClient(t)
	for _, in := range []NetRouteInput{
		{InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.7/24", NextHop: "192.0.2.1", RouteMetric: 10},
		{InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "fe80::1", RouteMetric: 10},
		{InterfaceAlias: "Ethernet 2", DestinationPrefix: "198.51.100.0/24", NextHop: "192.0.2.1", RouteMetric: 10000},
	} {
		if _, err := c.Create(context.Background(), in); !IsNetRouteError(err, NetRouteErrorInvalidRoute) {
			t.Errorf("input %+v: expected invalid_route, got %v", in, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Read / Lookup
// ---------------------------------------------------------------------------

func TestNetRouteRead_HappyAndMissing(t *testing.T) {
	restore := nrStubSequence([]frResponse{
		{stdout: nrOK(t, testNetRouteJSON()), err: nil},
	})
	defer restore()
	c := nrNewClient(t)
	info, err := c.Read(context.Background(), "Ethernet 2", "198.51.100.0/24", "192.0.2.1")
	if err != nil || info == nil {
		t.Fatalf("Read: %v", err)
	}
	if info.EffectiveMetric != 35 || info.Protocol != "NetMgmt" {
		t.Errorf("unexpected info: %+v", info)
	}

	restore2 := nrStubSequence([]frResponse{
		{stdout: nrErr(t, "not_found", "no route"), err: nil},
	})
	defer restore2()
	info, err = c.Read(context.Background(), "Ethernet 2", "198.51.100.0/24", "192.0.2.1")
	if err != nil || info != nil {
		t.Errorf("missing route must return (nil, nil), got %v, %v", info, err)
	}
}

func TestNetRouteLookup(t *testing.T) {
	payload := []map[string]any{testNetRouteJSON(), testNetRouteJSON()}
	restore := nrStubSequence([]frResponse{
		{stdout: nrOK(t, payload), err: nil},
	})
	defer restore()
	c := nrNewClient(t)
	routes, err := c.Lookup(context.Background(), "198.51.100.0/24", "", "")
	if err != nil || len(routes) != 2 {
		t.Fatalf("Lookup: %v (%d routes)", err, len(routes))
	}
	// Zero matches surface not_found.
	restore2 := nrStubSequence([]frResponse{
		{stdout: nrErr(t, "not_found", "no route"), err: nil},
	})
	defer restore2()
	if _, err := c.Lookup(context.Background(), "198.51.100.0/24", "", ""); !IsNetRouteError(err, NetRouteErrorNotFound) {
		t.Errorf("zero matches must be not_found, got %v", err)
	}
	// A whitespace-only alias is rejected instead of widening the lookup.
	if _, err := c.Lookup(context.Background(), "198.51.100.0/24", "   ", ""); !IsNetRouteError(err, NetRouteErrorInterfaceNotFound) {
		t.Errorf("blank alias must be interface_not_found, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestNetRouteUpdate_HappyPath(t *testing.T) {
	updated := testNetRouteJSON()
	updated["route_metric"] = 99
	updated["effective_metric"] = 124
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrOK(t, testNetRouteJSON()), err: nil}, // update preflight
		{stdout: nrMgmtMetricOK(t, 256, 25), err: nil},
		{stdout: nrOK(t, updated), err: nil},
	})
	defer restore()
	var mgmtCalls int
	defer nrStubManagementPath(nrUnrelatedPath(), nil, &mgmtCalls)()
	c := nrNewClient(t)
	info, err := c.Update(context.Background(), "Ethernet 2", "198.51.100.0/24", "192.0.2.1", 99, false)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if info.RouteMetric != 99 {
		t.Errorf("metric = %d, want 99", info.RouteMetric)
	}
	if mgmtCalls != 1 {
		t.Errorf("one management probe per operation, got %d", mgmtCalls)
	}
}

func TestNetRouteUpdate_GuardExactManagementRoute(t *testing.T) {
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 4), err: nil},
		{stdout: nrOK(t, testNetRouteJSON()), err: nil}, // update preflight
	})
	defer restore()
	defer nrStubManagementPath(testManagementPath(), nil, nil)()
	c := nrNewClient(t)
	// Re-metricing the exact management route is refused.
	_, err := c.Update(context.Background(), "Ethernet", "0.0.0.0/0", "172.18.122.1", 5, false)
	if !IsNetRouteError(err, NetRouteErrorMgmtAtRisk) {
		t.Fatalf("expected management_path_at_risk, got %v", err)
	}
}

func TestNetRouteUpdate_GuardHijackOnLowerMetric(t *testing.T) {
	// Same prefix, different next hop, new metric beating the management
	// route's effective metric: hijack.
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrOK(t, testNetRouteJSON()), err: nil}, // update preflight
		{stdout: nrMgmtMetricOK(t, 256, 25), err: nil},  // management eff 281
	})
	defer restore()
	defer nrStubManagementPath(testManagementPath(), nil, nil)()
	c := nrNewClient(t)
	_, err := c.Update(context.Background(), "Ethernet 2", "0.0.0.0/0", "192.0.2.254", 5, false)
	if !IsNetRouteError(err, NetRouteErrorMgmtAtRisk) {
		t.Fatalf("expected management_path_at_risk for winning metric, got %v", err)
	}
}

func TestNetRouteDelete_HappyAndIdempotent(t *testing.T) {
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrOK(t, testNetRouteJSON()), err: nil}, // delete preflight
		{stdout: nrOK(t, map[string]any{"removed": true}), err: nil},
	})
	defer restore()
	var mgmtCalls int
	defer nrStubManagementPath(nrUnrelatedPath(), nil, &mgmtCalls)()
	c := nrNewClient(t)
	if err := c.Delete(context.Background(), "Ethernet 2", "198.51.100.0/24", "192.0.2.1", false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if mgmtCalls != 1 {
		t.Errorf("one management probe per operation, got %d", mgmtCalls)
	}
	// Missing route is a no-op.
	restore2 := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrErr(t, "not_found", "no route"), err: nil},
	})
	defer restore2()
	if err := c.Delete(context.Background(), "Ethernet 2", "198.51.100.0/24", "192.0.2.1", false); err != nil {
		t.Errorf("missing route delete must be a no-op, got %v", err)
	}
}

func TestNetRouteDelete_GuardExactManagementRoute(t *testing.T) {
	runs := 0
	restore := nrStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		runs++
		if runs == 1 {
			return nrResolveOK(t, 4), "", nil
		}
		return nrOK(t, testNetRouteJSON()), "", nil
	})
	defer restore()
	defer nrStubManagementPath(testManagementPath(), nil, nil)()
	c := nrNewClient(t)
	err := c.Delete(context.Background(), "Ethernet", "0.0.0.0/0", "172.18.122.1", false)
	if !IsNetRouteError(err, NetRouteErrorMgmtAtRisk) {
		t.Fatalf("expected management_path_at_risk, got %v", err)
	}
	if runs != 2 {
		t.Errorf("guard must refuse before the remove script runs (want 2 probe calls, got %d)", runs)
	}
}

func TestNetRouteDelete_UnknownPathFailClosed(t *testing.T) {
	restore := nrStubSequence([]frResponse{
		{stdout: nrResolveOK(t, 7), err: nil},
		{stdout: nrOK(t, testNetRouteJSON()), err: nil},
	})
	defer restore()
	defer nrStubManagementPath(nil, NewManagementPathError(ManagementPathErrorUnknown, "no path", nil, nil), nil)()
	c := nrNewClient(t)
	err := c.Delete(context.Background(), "Ethernet 2", "198.51.100.0/24", "192.0.2.1", false)
	if !IsNetRouteError(err, NetRouteErrorMgmtUnknown) {
		t.Fatalf("expected management_path_unknown, got %v", err)
	}
}
