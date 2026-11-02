// Package winclient — unit tests for NetIPAddressClientImpl and the
// management-path guard integration.
//
// The package-level seams runNetIPAddressPowerShell (script transport) and
// netIPAddressManagementPath (guard probe) are stubbed so no real SSH
// connection is needed. Coverage targets (issue #230):
//
//	NetIPAddressError: Error(), Unwrap(), Is(), sentinels
//	mapNetIPAddressKind: all remote kinds + unknown fallback
//	validateNetIPAddressInput: canonicalisation, family ranges, rejections
//	script builders: user values only via psQuote, exact -eq alias match,
//	                 no wildcard -InterfaceAlias, no -PolicyStore override,
//	                 no DefaultGateway
//	envelope mapping: unreachable on transport/timeout, typed remote kinds
//	Create/Read/Lookup/Update/Delete/RestoreDHCP: happy paths, pre-flight
//	 kinds, Duplicate rollback, guard refusals, unsafe_skip bypass, single
//	 management probe per op, DHCP restore after post-disable failures,
//	 Manual-gated import hint, exact -eq lookup filter, blank-alias and
//	 alias-trim handling, session-port placeholder substitution
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

// niNewClient returns a *Client + *NetIPAddressClientImpl pair for tests.
func niNewClient(t *testing.T) (*Client, *NetIPAddressClientImpl) {
	t.Helper()
	c, err := New(Config{Host: "winip01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewNetIPAddressClient(c)
}

// niOK returns a JSON ok-envelope whose data field is the supplied value.
func niOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("niOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// niErr returns a JSON error-envelope for the given kind/message.
func niErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("niErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// niStubRun replaces runNetIPAddressPowerShell for one test.
func niStubRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runNetIPAddressPowerShell
	runNetIPAddressPowerShell = fn
	return func() { runNetIPAddressPowerShell = prev }
}

// niStubSequence stubs runNetIPAddressPowerShell with a fixed ordered list
// of responses. After the last one, every subsequent call replays it.
func niStubSequence(responses []frResponse) func() {
	i := 0
	return niStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		r := responses[i]
		if i < len(responses)-1 {
			i++
		}
		return r.stdout, r.stderr, r.err
	})
}

// niStubManagementPath replaces the guard probe for one test.
func niStubManagementPath(mp *ManagementPath, err error) func() {
	prev := netIPAddressManagementPath
	netIPAddressManagementPath = func(_ context.Context, _ *Client) (*ManagementPath, error) {
		return mp, err
	}
	return func() { netIPAddressManagementPath = prev }
}

// testNetAddressJSON is a minimal valid ConvertTo-NetAddressJson payload.
func testNetAddressJSON() map[string]any {
	return map[string]any{
		"interface_alias": "Ethernet 2",
		"interface_index": 7,
		"ip_address":      "192.0.2.10",
		"prefix_length":   24,
		"address_state":   "Preferred",
		"prefix_origin":   "Manual",
		"skip_as_source":  false,
	}
}

// niResolveOK is the resolve-only probe response for interface index 7.
func niResolveOK(t *testing.T) string {
	t.Helper()
	return niOK(t, map[string]any{"interface_index": 7, "interface_alias": "Ethernet 2"})
}

// nonManagementPath is a guard probe result that does not touch the
// documentation addresses used in tests.
func nonManagementPath() *ManagementPath {
	mp := testManagementPath()
	return mp
}

// ---------------------------------------------------------------------------
// NetIPAddressError
// ---------------------------------------------------------------------------

func TestNetIPAddressError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewNetIPAddressError(NetIPAddressErrorPermission, "denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewNetIPAddressError(NetIPAddressErrorUnknown, "bad", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestNetIPAddressError_Is(t *testing.T) {
	e := NewNetIPAddressError(NetIPAddressErrorMgmtAtRisk, "x", nil, nil)
	if !errors.Is(e, ErrNetIPAddressMgmtAtRisk) {
		t.Error("errors.Is(ErrNetIPAddressMgmtAtRisk) should match by kind")
	}
	if errors.Is(e, ErrNetIPAddressMgmtUnknown) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsNetIPAddressError(e, NetIPAddressErrorMgmtAtRisk) {
		t.Error("IsNetIPAddressError should match")
	}
	if IsNetIPAddressError(errors.New("plain"), NetIPAddressErrorMgmtAtRisk) {
		t.Error("IsNetIPAddressError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-NetIPAddressError should be false")
	}
}

func TestMapNetIPAddressKind(t *testing.T) {
	cases := map[string]NetIPAddressErrorKind{
		"interface_not_found":      NetIPAddressErrorInterfaceNotFound,
		"not_found":                NetIPAddressErrorNotFound,
		"already_exists":           NetIPAddressErrorAlreadyExists,
		"address_in_use_elsewhere": NetIPAddressErrorInUseElsewhere,
		"invalid_address":          NetIPAddressErrorInvalidAddress,
		"dhcp_enabled":             NetIPAddressErrorDHCPEnabled,
		"duplicate_address":        NetIPAddressErrorDuplicate,
		"permission_denied":        NetIPAddressErrorPermission,
		"management_path_at_risk":  NetIPAddressErrorMgmtAtRisk,
		"management_path_unknown":  NetIPAddressErrorMgmtUnknown,
		"":                         NetIPAddressErrorUnknown,
		"weird_kind":               NetIPAddressErrorUnknown,
		"would_lock_out":           NetIPAddressErrorUnknown,
		"management_path_at_risk ": NetIPAddressErrorUnknown,
	}
	for in, want := range cases {
		if got := mapNetIPAddressKind(in); got != want {
			t.Errorf("mapNetIPAddressKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// validateNetIPAddressInput
// ---------------------------------------------------------------------------

func TestValidateNetIPAddressInput(t *testing.T) {
	// Canonicalisation: uppercase + leading zeros collapse.
	got, isV6, err := validateNetIPAddressInput("Ethernet 2", "2001:DB8::0010", 64, false)
	if err != nil || got != "2001:db8::10" || !isV6 {
		t.Errorf("canonicalise = %q, %v, %v; want 2001:db8::10, true, nil", got, isV6, err)
	}
	got, isV6, err = validateNetIPAddressInput("Ethernet 2", "192.0.2.10", 24, false)
	if err != nil || got != "192.0.2.10" || isV6 {
		t.Errorf("ipv4 = %q, %v, %v; want 192.0.2.10, false, nil", got, isV6, err)
	}
	// IPv4-mapped IPv6 unmaps to IPv4.
	got, isV6, err = validateNetIPAddressInput("Ethernet 2", "::ffff:192.0.2.10", 24, false)
	if err != nil || got != "192.0.2.10" || isV6 {
		t.Errorf("mapped = %q, %v, %v; want 192.0.2.10, false, nil", got, isV6, err)
	}

	// Rejections.
	bad := []struct {
		name   string
		ip     string
		prefix int
		dhcp   bool
	}{
		{"empty alias", "", 24, false},
		{"unparsable", "999.1.1.1", 24, false},
		{"unspecified v4", "0.0.0.0", 24, false},
		{"unspecified v6", "::", 64, false},
		{"loopback v4", "127.0.0.1", 8, false},
		{"loopback v6", "::1", 128, false},
		{"multicast v4", "224.0.0.1", 4, false},
		{"multicast v6", "ff02::1", 64, false},
		{"broadcast", "255.255.255.255", 32, false},
		{"v4 prefix 0", "192.0.2.10", 0, false},
		{"v4 prefix 33", "192.0.2.10", 33, false},
		{"v6 prefix 0", "2001:db8::10", 0, false},
		{"v6 prefix 129", "2001:db8::10", 129, false},
		{"dhcp on v6", "2001:db8::10", 64, true},
	}
	for _, tc := range bad {
		alias := "Ethernet 2"
		if tc.name == "empty alias" {
			alias = ""
		}
		ip := tc.ip
		if tc.name == "empty alias" {
			ip = "192.0.2.10"
		}
		if _, _, err := validateNetIPAddressInput(alias, ip, tc.prefix, tc.dhcp); !IsNetIPAddressError(err, NetIPAddressErrorInvalidAddress) &&
			!IsNetIPAddressError(err, NetIPAddressErrorInterfaceNotFound) {
			t.Errorf("%s: expected invalid_address/interface_not_found, got %v", tc.name, err)
		}
	}
	// Zone IDs are rejected (Get-NetIPAddress cannot match them reliably).
	if _, _, err := validateNetIPAddressInput("Ethernet 2", "fe80::1%12", 64, false); !IsNetIPAddressError(err, NetIPAddressErrorInvalidAddress) {
		t.Errorf("zone ID: expected invalid_address, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Script builders: quoting, exact match, no gateway, no policy store
// ---------------------------------------------------------------------------

func TestNetIPAddressScripts_QuotingAndSemantics(t *testing.T) {
	evil := "Ethernet [2]'; Write-Host pwned; '"
	scripts := map[string]string{
		"resolve":    buildNetIPAddressResolveScript(evil, false),
		"read":       buildNetIPAddressReadScript(evil, "192.0.2.10", false),
		"lookup":     buildNetIPAddressLookupScript("192.0.2.10", evil),
		"ensuredhcp": buildNetIPAddressEnsureDHCPDisabledScript(evil, true),
		"create":     buildNetIPAddressCreateScript(evil, "192.0.2.10", 24, true, false),
		"set":        buildNetIPAddressSetScript(evil, "192.0.2.10", 24, true),
		"remove":     buildNetIPAddressRemoveScript(evil, "192.0.2.10", false),
		"restore":    buildNetIPAddressRestoreDHCPScript(evil),
		"origin":     buildNetIPAddressPrefixOriginScript("192.0.2.10"),
		"mgmt":       buildMgmtPathScript(22),
	}
	for name, script := range scripts {
		if name == "mgmt" || name == "origin" {
			continue
		}
		if strings.Contains(script, evil) {
			t.Errorf("%s script interpolates the raw alias", name)
		}
		if !strings.Contains(script, psQuote(evil)) {
			t.Errorf("%s script must carry the psQuote'd alias", name)
		}
	}
	// Exact alias resolution: -eq via Where-Object, never -InterfaceAlias
	// wildcard parameter semantics (aliases like "Ethernet [2]" contain
	// wildcard characters).
	for name, script := range scripts {
		if name == "lookup" || name == "origin" || name == "mgmt" {
			continue
		}
		if !strings.Contains(script, "Where-Object { $_.InterfaceAlias -eq $alias }") {
			t.Errorf("%s script must resolve the alias with exact -eq comparison", name)
		}
		if strings.Contains(script, "-InterfaceAlias $alias") {
			t.Errorf("%s script must not pass the alias to -InterfaceAlias (wildcard semantics)", name)
		}
	}
	// No -PolicyStore override (default store) and no DefaultGateway. The
	// DHCP hint quotes the host's own "PolicyStore PersistentStore" error
	// text, so only the cmdlet flag form is banned.
	for name, script := range scripts {
		if strings.Contains(script, "-PolicyStore") {
			t.Errorf("%s script must use the default policy store", name)
		}
		if strings.Contains(script, "DefaultGateway") {
			t.Errorf("%s script must not manage the default gateway", name)
		}
	}
	// Locale pinning for enum decoding.
	if !strings.Contains(scripts["create"], "InvariantCulture") {
		t.Error("create script must pin InvariantCulture for enum decoding")
	}
	// Classify covers HRESULTs and the DHCP inconsistency message.
	for _, want := range []string{
		"0x80070005", "0x80070490", "0x800700B7", "0x80070057",
		"Inconsistent parameters", "Dhcp",
		"'permission_denied'", "'not_found'", "'interface_not_found'",
		"'already_exists'", "'dhcp_enabled'", "'invalid_address'",
	} {
		if !strings.Contains(scripts["create"], want) {
			t.Errorf("Classify-NetIpAddress must handle %q", want)
		}
	}
	// SkipAsSource switch present only when requested.
	if !strings.Contains(buildNetIPAddressCreateScript("a", "192.0.2.10", 24, true, false), "-SkipAsSource") {
		t.Error("create with skip_as_source must pass -SkipAsSource")
	}
	if strings.Contains(buildNetIPAddressCreateScript("a", "192.0.2.10", 24, false, false), "-SkipAsSource") {
		t.Error("create without skip_as_source must not pass -SkipAsSource")
	}
}

// ---------------------------------------------------------------------------
// Envelope mapping: transport/timeout/remote
// ---------------------------------------------------------------------------

func TestNetIPAddressEnvelope_TransportMapsUnreachable(t *testing.T) {
	restore := niStubSequence([]frResponse{{stdout: "", stderr: "boom", err: errors.New("ssh dial failed")}})
	defer restore()

	_, c := niNewClient(t)
	_, err := c.Read(context.Background(), "Ethernet 2", "192.0.2.10")
	if !IsNetIPAddressError(err, NetIPAddressErrorUnreachable) {
		t.Errorf("expected unreachable, got %v", err)
	}
}

func TestNetIPAddressEnvelope_TimeoutMapsUnreachable(t *testing.T) {
	restore := niStubSequence([]frResponse{{stdout: "", stderr: "", err: context.Canceled}})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, c := niNewClient(t)
	_, err := c.Read(ctx, "Ethernet 2", "192.0.2.10")
	if !IsNetIPAddressError(err, NetIPAddressErrorUnreachable) {
		t.Errorf("expected unreachable, got %v", err)
	}
}

func TestNetIPAddressRemoteKinds(t *testing.T) {
	cases := []struct {
		remote string
		want   NetIPAddressErrorKind
	}{
		{"interface_not_found", NetIPAddressErrorInterfaceNotFound},
		{"not_found", NetIPAddressErrorNotFound},
		{"already_exists", NetIPAddressErrorAlreadyExists},
		{"address_in_use_elsewhere", NetIPAddressErrorInUseElsewhere},
		{"invalid_address", NetIPAddressErrorInvalidAddress},
		{"dhcp_enabled", NetIPAddressErrorDHCPEnabled},
		{"duplicate_address", NetIPAddressErrorDuplicate},
		{"permission_denied", NetIPAddressErrorPermission},
	}
	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			// Lookup passes remote kinds through untouched (unlike Read,
			// which maps not_found to a state drop).
			restore := niStubSequence([]frResponse{{stdout: niErr(t, tc.remote, "boom "+tc.remote), stderr: "", err: nil}})
			defer restore()

			_, c := niNewClient(t)
			_, err := c.Lookup(context.Background(), "192.0.2.10", "")
			if !IsNetIPAddressError(err, tc.want) {
				t.Errorf("remote kind %q should map to %q, got %v", tc.remote, tc.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestNetIPAddressCreate_HappyPath(t *testing.T) {
	var scripts []string
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		scripts = append(scripts, script)
		switch {
		case strings.Contains(script, "interface_index = $ifIndex"):
			return niResolveOK(t), "", nil
		default:
			return niOK(t, testNetAddressJSON()), "", nil
		}
	})
	defer restore()
	defer niStubManagementPath(nonManagementPath(), nil)()

	_, c := niNewClient(t)
	info, dhcpDisabled, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dhcpDisabled {
		t.Error("dhcpDisabled must be false when disable_dhcp is not set")
	}
	if info.IPAddress != "192.0.2.10" || info.PrefixLength != 24 || info.AddressFamily != "IPv4" {
		t.Errorf("unexpected info: %+v", info)
	}
	if info.InterfaceIndex != 7 || info.PrefixOrigin != "Manual" {
		t.Errorf("unexpected info: %+v", info)
	}
	joined := strings.Join(scripts, "\n")
	for _, want := range []string{
		"New-NetIPAddress -InterfaceIndex $ifIndex",
		"Get-NetIPAddress -IPAddress $wantIP",
		"Where-Object { $_.InterfaceAlias -eq $alias }",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("create flow missing %q", want)
		}
	}
}

func TestNetIPAddressCreate_Preflights(t *testing.T) {
	// interface_not_found short-circuits before any guard probe.
	guardCalls := 0
	defer niStubManagementPath(nonManagementPath(), nil)()
	prevMgmt := netIPAddressManagementPath
	netIPAddressManagementPath = func(ctx context.Context, c *Client) (*ManagementPath, error) {
		guardCalls++
		return prevMgmt(ctx, c)
	}
	defer func() { netIPAddressManagementPath = prevMgmt }()

	restore := niStubSequence([]frResponse{
		{stdout: niErr(t, "interface_not_found", "no such alias"), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	if _, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Nope", IPAddress: "192.0.2.10", PrefixLength: 24,
	}); !IsNetIPAddressError(err, NetIPAddressErrorInterfaceNotFound) {
		t.Errorf("expected interface_not_found, got %v", err)
	}
	if guardCalls != 0 {
		t.Error("interface resolution failure must short-circuit before the guard")
	}
}

func TestNetIPAddressCreate_AlreadyExists(t *testing.T) {
	defer niStubManagementPath(nonManagementPath(), nil)()
	restore := niStubSequence([]frResponse{
		{stdout: niResolveOK(t), stderr: "", err: nil},
		{stdout: niErr(t, "already_exists", "already there"), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	_, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
	})
	if !IsNetIPAddressError(err, NetIPAddressErrorAlreadyExists) {
		t.Errorf("expected already_exists, got %v", err)
	}
}

func TestNetIPAddressCreate_DHCPEnabledHint(t *testing.T) {
	defer niStubManagementPath(nonManagementPath(), nil)()
	restore := niStubSequence([]frResponse{
		{stdout: niResolveOK(t), stderr: "", err: nil},
		{stdout: niErr(t, "dhcp_enabled", "inconsistent parameters"), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	_, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
	})
	if !IsNetIPAddressError(err, NetIPAddressErrorDHCPEnabled) {
		t.Errorf("expected dhcp_enabled, got %v", err)
	}
}

func TestNetIPAddressCreate_DuplicateRollsBack(t *testing.T) {
	var scripts []string
	defer niStubManagementPath(nonManagementPath(), nil)()
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		scripts = append(scripts, script)
		switch {
		case strings.Contains(script, "interface_index = $ifIndex"):
			return niResolveOK(t), "", nil
		case strings.Contains(script, "Remove-NetIPAddress"):
			return niOK(t, map[string]any{"removed": true}), "", nil
		default:
			dup := testNetAddressJSON()
			dup["address_state"] = "Duplicate"
			return niOK(t, dup), "", nil
		}
	})
	defer restore()

	_, c := niNewClient(t)
	_, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
	})
	if !IsNetIPAddressError(err, NetIPAddressErrorDuplicate) {
		t.Fatalf("expected duplicate_address, got %v", err)
	}
	if !strings.Contains(strings.Join(scripts, "\n"), "Remove-NetIPAddress") {
		t.Error("Duplicate must roll the address back with Remove-NetIPAddress")
	}
}

func TestNetIPAddressCreate_GuardRefusesManagementIP(t *testing.T) {
	mgmt := testManagementPath() // server IP 172.18.122.203
	defer niStubManagementPath(mgmt, nil)()
	called := false
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		called = true
		return niResolveOK(t), "", nil
	})
	defer restore()

	_, c := niNewClient(t)
	_, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet", IPAddress: "172.18.122.203", PrefixLength: 24,
	})
	if !IsNetIPAddressError(err, NetIPAddressErrorMgmtAtRisk) {
		t.Fatalf("expected management_path_at_risk, got %v", err)
	}
	if !strings.Contains(err.Error(), "172.18.122.203") || !strings.Contains(err.Error(), "unsafe_skip_management_check") {
		t.Errorf("refusal must name the address and the escape hatch: %v", err)
	}
	_ = called
}

func TestNetIPAddressCreate_GuardUnknownFailsClosed(t *testing.T) {
	defer niStubManagementPath(nil, NewManagementPathError(ManagementPathErrorUnknown, "nope", nil, nil))()
	restore := niStubSequence([]frResponse{{stdout: niResolveOK(t), stderr: "", err: nil}})
	defer restore()

	_, c := niNewClient(t)
	_, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
	})
	if !IsNetIPAddressError(err, NetIPAddressErrorMgmtUnknown) {
		t.Errorf("expected management_path_unknown, got %v", err)
	}
}

func TestNetIPAddressCreate_UnsafeSkipBypassesGuard(t *testing.T) {
	defer niStubManagementPath(nil, NewManagementPathError(ManagementPathErrorUnknown, "nope", nil, nil))()
	restore := niStubSequence([]frResponse{
		{stdout: niResolveOK(t), stderr: "", err: nil},
		{stdout: niOK(t, testNetAddressJSON()), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	info, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
		UnsafeSkipManagementCheck: true,
	})
	if err != nil {
		t.Fatalf("unsafe_skip must bypass the unknown-path refusal, got %v", err)
	}
	if info.IPAddress != "192.0.2.10" {
		t.Errorf("unexpected info: %+v", info)
	}
}

func TestNetIPAddressCreate_SingleManagementProbe(t *testing.T) {
	// One operation probes the management path exactly once, even with
	// disable_dhcp (the address guard and the DHCP-disable guard share the
	// probe instead of racing two probes around the mutation).
	probeCalls := 0
	defer niStubManagementPath(nonManagementPath(), nil)()
	prevMgmt := netIPAddressManagementPath
	netIPAddressManagementPath = func(ctx context.Context, c *Client) (*ManagementPath, error) {
		probeCalls++
		return prevMgmt(ctx, c)
	}
	defer func() { netIPAddressManagementPath = prevMgmt }()

	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		switch {
		case strings.Contains(script, "interface_index = $ifIndex"):
			return niResolveOK(t), "", nil
		case strings.Contains(script, "$disableDhcp"):
			return niOK(t, map[string]any{"dhcp_disabled": true}), "", nil
		default:
			return niOK(t, testNetAddressJSON()), "", nil
		}
	})
	defer restore()

	_, c := niNewClient(t)
	_, dhcpDisabled, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
		DisableDHCP: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dhcpDisabled {
		t.Error("dhcpDisabled must be true when this call disabled DHCP")
	}
	if probeCalls != 1 {
		t.Errorf("one Create must probe the management path exactly once, got %d", probeCalls)
	}
}

func TestNetIPAddressCreate_FailureRestoresDHCP(t *testing.T) {
	// A Create failure after disabling DHCP best-effort restores DHCP, so
	// the failed apply leaves no DHCP side effect behind and the flag is
	// cleared.
	var scripts []string
	defer niStubManagementPath(nonManagementPath(), nil)()
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		scripts = append(scripts, script)
		switch {
		case strings.Contains(script, "interface_index = $ifIndex"):
			return niResolveOK(t), "", nil
		case strings.Contains(script, "$disableDhcp"):
			return niOK(t, map[string]any{"dhcp_disabled": true}), "", nil
		case strings.Contains(script, "-Dhcp Enabled"):
			return niOK(t, map[string]any{"dhcp_enabled": true}), "", nil
		default:
			return niErr(t, "already_exists", "already there"), "", nil
		}
	})
	defer restore()

	_, c := niNewClient(t)
	_, dhcpDisabled, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
		DisableDHCP: true,
	})
	if !IsNetIPAddressError(err, NetIPAddressErrorAlreadyExists) {
		t.Fatalf("expected already_exists, got %v", err)
	}
	if dhcpDisabled {
		t.Error("a successful DHCP restore must clear the flag")
	}
	if !strings.Contains(strings.Join(scripts, "\n"), "-Dhcp Enabled") {
		t.Error("a post-disable Create failure must attempt to restore DHCP")
	}
}

func TestNetIPAddressCreate_FailureRestoreFailsKeepsFlag(t *testing.T) {
	// When the best-effort restore also fails, the flag stays set so the
	// caller surfaces it (private state, warning diagnostic) instead of
	// silently dropping the DHCP disable.
	defer niStubManagementPath(nonManagementPath(), nil)()
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		switch {
		case strings.Contains(script, "interface_index = $ifIndex"):
			return niResolveOK(t), "", nil
		case strings.Contains(script, "$disableDhcp"):
			return niOK(t, map[string]any{"dhcp_disabled": true}), "", nil
		case strings.Contains(script, "-Dhcp Enabled"):
			return niErr(t, "permission_denied", "denied"), "", nil
		default:
			return niErr(t, "already_exists", "already there"), "", nil
		}
	})
	defer restore()

	_, c := niNewClient(t)
	_, dhcpDisabled, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: "Ethernet 2", IPAddress: "192.0.2.10", PrefixLength: 24,
		DisableDHCP: true,
	})
	if !IsNetIPAddressError(err, NetIPAddressErrorAlreadyExists) {
		t.Fatalf("expected the original already_exists error, got %v", err)
	}
	if !dhcpDisabled {
		t.Error("a failed DHCP restore must keep the flag so the caller can surface it")
	}
}

func TestNetIPAddressCreate_TrimsAlias(t *testing.T) {
	// Surrounding whitespace on the alias is trimmed for host operations:
	// " Ethernet 2 " must resolve the same interface as "Ethernet 2".
	var resolveScript string
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		if strings.Contains(script, "interface_index = $ifIndex") {
			resolveScript = script
			return niResolveOK(t), "", nil
		}
		return niOK(t, testNetAddressJSON()), "", nil
	})
	defer restore()
	defer niStubManagementPath(nonManagementPath(), nil)()

	_, c := niNewClient(t)
	if _, _, err := c.Create(context.Background(), NetIPAddressInput{
		InterfaceAlias: " Ethernet 2 ", IPAddress: "192.0.2.10", PrefixLength: 24,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resolveScript, psQuote("Ethernet 2")) {
		t.Errorf("resolve must carry the trimmed alias, got:\n%s", resolveScript)
	}
	if strings.Contains(resolveScript, psQuote(" Ethernet 2 ")) {
		t.Errorf("resolve must not carry the untrimmed alias, got:\n%s", resolveScript)
	}
}

func TestNetIPAddressCreateScript_ImportHintManualOnly(t *testing.T) {
	// The already_exists import hint fires only for Manual addresses: any
	// other prefix origin is refused on import, so hinting it would
	// mislead.
	s := buildNetIPAddressCreateScript("Ethernet 2", "192.0.2.10", 24, false, false)
	if !strings.Contains(s, "[string]$e.PrefixOrigin -eq 'Manual'") {
		t.Error("create pre-flight must gate the import hint on PrefixOrigin Manual")
	}
	if !strings.Contains(s, "Import it with terraform import") {
		t.Error("create pre-flight must keep the import hint for Manual addresses")
	}
	if !strings.Contains(s, "only Manual addresses are importable") {
		t.Error("create pre-flight must explain non-Manual duplicates without the import hint")
	}
}

func TestNetIPAddressLookupScript_ExactAliasMatch(t *testing.T) {
	// Like every other alias resolution, the lookup filter must use an
	// exact (-eq, case-insensitive) comparison — never wildcard parameter
	// semantics, and never a substring of user input.
	s := buildNetIPAddressLookupScript("192.0.2.10", "Ethernet 2")
	if !strings.Contains(s, "Where-Object { $_.InterfaceAlias -eq") {
		t.Error("lookup must resolve the alias with an exact -eq comparison")
	}
	if strings.Contains(s, "-InterfaceAlias $alias") {
		t.Error("lookup must not pass the alias to -InterfaceAlias (wildcard semantics)")
	}
	if !strings.Contains(s, psQuote("Ethernet 2")) {
		t.Error("lookup must carry the psQuote'd alias")
	}
	unrestricted := buildNetIPAddressLookupScript("192.0.2.10", "")
	if strings.Contains(unrestricted, "Where-Object") {
		t.Error("an unrestricted lookup must not filter by alias")
	}
}

// ---------------------------------------------------------------------------
// Read / Lookup
// ---------------------------------------------------------------------------

func TestNetIPAddressRead_HappyPath(t *testing.T) {
	restore := niStubSequence([]frResponse{
		{stdout: niOK(t, testNetAddressJSON()), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	info, err := c.Read(context.Background(), "ethernet 2", "192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.InterfaceIndex != 7 || info.AddressState != "Preferred" || info.SkipAsSource {
		t.Errorf("unexpected info: %+v", info)
	}
}

func TestNetIPAddressRead_MissingDropsToNil(t *testing.T) {
	for _, kind := range []string{"not_found", "interface_not_found"} {
		t.Run(kind, func(t *testing.T) {
			restore := niStubSequence([]frResponse{{stdout: niErr(t, kind, "gone"), stderr: "", err: nil}})
			defer restore()

			_, c := niNewClient(t)
			info, err := c.Read(context.Background(), "Ethernet 2", "192.0.2.10")
			if err != nil || info != nil {
				t.Errorf("missing must be (nil, nil), got (%+v, %v)", info, err)
			}
		})
	}
}

func TestNetIPAddressLookup(t *testing.T) {
	// Single match.
	restore := niStubSequence([]frResponse{{stdout: niOK(t, testNetAddressJSON()), stderr: "", err: nil}})
	defer restore()

	_, c := niNewClient(t)
	got, err := c.Lookup(context.Background(), "192.0.2.10", "")
	if err != nil || len(got) != 1 || got[0].IPAddress != "192.0.2.10" {
		t.Errorf("lookup = %+v, %v; want one match", got, err)
	}
}

func TestNetIPAddressLookup_Errors(t *testing.T) {
	// Zero matches.
	restore := niStubSequence([]frResponse{{stdout: niErr(t, "not_found", "none"), stderr: "", err: nil}})
	defer restore()
	_, c := niNewClient(t)
	if _, err := c.Lookup(context.Background(), "192.0.2.99", ""); !IsNetIPAddressError(err, NetIPAddressErrorNotFound) {
		t.Errorf("expected not_found, got %v", err)
	}
}

func TestNetIPAddressLookup_BlankAliasRejected(t *testing.T) {
	// A whitespace-only alias is rejected instead of widening the lookup
	// to all interfaces — and before any script runs.
	called := false
	restore := niStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return niOK(t, testNetAddressJSON()), "", nil
	})
	defer restore()

	_, c := niNewClient(t)
	if _, err := c.Lookup(context.Background(), "192.0.2.10", "   "); !IsNetIPAddressError(err, NetIPAddressErrorInterfaceNotFound) {
		t.Errorf("expected interface_not_found, got %v", err)
	}
	if called {
		t.Error("a blank alias must fail before any script runs")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete / RestoreDHCP
// ---------------------------------------------------------------------------

func TestNetIPAddressUpdate_HappyPath(t *testing.T) {
	defer niStubManagementPath(nonManagementPath(), nil)()
	updated := testNetAddressJSON()
	updated["prefix_length"] = 25
	updated["skip_as_source"] = true
	restore := niStubSequence([]frResponse{
		{stdout: niResolveOK(t), stderr: "", err: nil},
		{stdout: niOK(t, testNetAddressJSON()), stderr: "", err: nil},
		{stdout: niOK(t, updated), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	info, dhcpDisabled, err := c.Update(context.Background(), "Ethernet 2", "192.0.2.10", 25, true, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dhcpDisabled {
		t.Error("dhcpDisabled must be false")
	}
	if info.PrefixLength != 25 || !info.SkipAsSource {
		t.Errorf("unexpected info: %+v", info)
	}
}

func TestNetIPAddressUpdate_GuardRefusesManagementIP(t *testing.T) {
	mgmt := testManagementPath()
	defer niStubManagementPath(mgmt, nil)()
	restore := niStubSequence([]frResponse{
		{stdout: niResolveOK(t), stderr: "", err: nil},
		{stdout: niOK(t, testNetAddressJSON()), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	_, _, err := c.Update(context.Background(), "Ethernet", "172.18.122.203", 24, false, false, false)
	if !IsNetIPAddressError(err, NetIPAddressErrorMgmtAtRisk) {
		t.Errorf("expected management_path_at_risk, got %v", err)
	}
}

func TestNetIPAddressUpdate_FailureRestoresDHCP(t *testing.T) {
	// Like Create, an Update failure after disabling DHCP best-effort
	// restores DHCP; a failed restore keeps the flag so the caller can
	// persist it.
	t.Run("restore succeeds", func(t *testing.T) {
		var scripts []string
		defer niStubManagementPath(nonManagementPath(), nil)()
		restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
			scripts = append(scripts, script)
			switch {
			case strings.Contains(script, "interface_index = $ifIndex"):
				return niResolveOK(t), "", nil
			case strings.Contains(script, "$disableDhcp"):
				return niOK(t, map[string]any{"dhcp_disabled": true}), "", nil
			case strings.Contains(script, "-Dhcp Enabled"):
				return niOK(t, map[string]any{"dhcp_enabled": true}), "", nil
			case strings.Contains(script, "Set-NetIPAddress"):
				return niErr(t, "invalid_address", "bad prefix"), "", nil
			default:
				return niOK(t, testNetAddressJSON()), "", nil
			}
		})
		defer restore()

		_, c := niNewClient(t)
		_, dhcpDisabled, err := c.Update(context.Background(), "Ethernet 2", "192.0.2.10", 25, true, true, false)
		if !IsNetIPAddressError(err, NetIPAddressErrorInvalidAddress) {
			t.Fatalf("expected the original invalid_address error, got %v", err)
		}
		if dhcpDisabled {
			t.Error("a successful DHCP restore must clear the flag")
		}
		if !strings.Contains(strings.Join(scripts, "\n"), "-Dhcp Enabled") {
			t.Error("a post-disable Update failure must attempt to restore DHCP")
		}
	})

	t.Run("restore fails", func(t *testing.T) {
		defer niStubManagementPath(nonManagementPath(), nil)()
		restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
			switch {
			case strings.Contains(script, "interface_index = $ifIndex"):
				return niResolveOK(t), "", nil
			case strings.Contains(script, "$disableDhcp"):
				return niOK(t, map[string]any{"dhcp_disabled": true}), "", nil
			case strings.Contains(script, "-Dhcp Enabled"):
				return niErr(t, "permission_denied", "denied"), "", nil
			case strings.Contains(script, "Set-NetIPAddress"):
				return niErr(t, "invalid_address", "bad prefix"), "", nil
			default:
				return niOK(t, testNetAddressJSON()), "", nil
			}
		})
		defer restore()

		_, c := niNewClient(t)
		_, dhcpDisabled, err := c.Update(context.Background(), "Ethernet 2", "192.0.2.10", 25, true, true, false)
		if !IsNetIPAddressError(err, NetIPAddressErrorInvalidAddress) {
			t.Fatalf("expected the original invalid_address error, got %v", err)
		}
		if !dhcpDisabled {
			t.Error("a failed DHCP restore must keep the flag so the caller can persist it")
		}
	})
}

func TestSubstituteSessionPort(t *testing.T) {
	// The execution-time placeholder renders the in-flight session's port;
	// scripts without it pass through unchanged.
	script := buildMgmtPathScript(22)
	rendered := substituteSessionPort(script, 49890)
	if strings.Contains(rendered, mgmtPathLocalPortPlaceholder) {
		t.Error("substitution must replace the placeholder")
	}
	if !strings.Contains(rendered, "49890") {
		t.Error("substitution must render the executing session's port")
	}
	if got := substituteSessionPort("Get-NetIPAddress", 49890); got != "Get-NetIPAddress" {
		t.Errorf("scripts without the placeholder must pass through unchanged, got %q", got)
	}
	if got := sessionSourcePort(nil); got != 0 {
		t.Errorf("nil address must yield port 0, got %d", got)
	}
}

func TestNetIPAddressDelete_HappyPath(t *testing.T) {
	var scripts []string
	defer niStubManagementPath(nonManagementPath(), nil)()
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		scripts = append(scripts, script)
		switch {
		case strings.Contains(script, "interface_index = $ifIndex"):
			return niResolveOK(t), "", nil
		case strings.Contains(script, "Remove-NetIPAddress"):
			return niOK(t, map[string]any{"removed": true}), "", nil
		default:
			return niOK(t, testNetAddressJSON()), "", nil
		}
	})
	defer restore()

	_, c := niNewClient(t)
	if err := c.Delete(context.Background(), "Ethernet 2", "192.0.2.10", false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(strings.Join(scripts, "\n"), "Remove-NetIPAddress") {
		t.Error("delete must run Remove-NetIPAddress")
	}
}

func TestNetIPAddressDelete_Idempotent(t *testing.T) {
	// Missing address and missing interface are both successful no-ops.
	// A delete flow resolves the interface first, so the not_found case
	// needs a two-step sequence (resolve OK, pre-flight missing).
	t.Run("not_found", func(t *testing.T) {
		defer niStubManagementPath(nonManagementPath(), nil)()
		restore := niStubSequence([]frResponse{
			{stdout: niResolveOK(t), stderr: "", err: nil},
			{stdout: niErr(t, "not_found", "gone"), stderr: "", err: nil},
		})
		defer restore()

		_, c := niNewClient(t)
		if err := c.Delete(context.Background(), "Ethernet 2", "192.0.2.10", false); err != nil {
			t.Errorf("idempotent delete must be nil, got %v", err)
		}
	})
	t.Run("interface_not_found", func(t *testing.T) {
		defer niStubManagementPath(nonManagementPath(), nil)()
		restore := niStubSequence([]frResponse{{stdout: niErr(t, "interface_not_found", "gone"), stderr: "", err: nil}})
		defer restore()

		_, c := niNewClient(t)
		if err := c.Delete(context.Background(), "Ethernet 2", "192.0.2.10", false); err != nil {
			t.Errorf("idempotent delete must be nil, got %v", err)
		}
	})
}

func TestNetIPAddressDelete_GuardRefusesManagementIP(t *testing.T) {
	mgmt := testManagementPath()
	defer niStubManagementPath(mgmt, nil)()
	restore := niStubSequence([]frResponse{
		{stdout: niResolveOK(t), stderr: "", err: nil},
		{stdout: niOK(t, func() map[string]any {
			m := testNetAddressJSON()
			m["ip_address"] = "172.18.122.203"
			return m
		}()), stderr: "", err: nil},
	})
	defer restore()

	_, c := niNewClient(t)
	if err := c.Delete(context.Background(), "Ethernet", "172.18.122.203", false); !IsNetIPAddressError(err, NetIPAddressErrorMgmtAtRisk) {
		t.Errorf("expected management_path_at_risk, got %v", err)
	}
}

func TestNetIPAddressRestoreDHCP(t *testing.T) {
	var gotScript string
	restore := niStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		if strings.Contains(script, "interface_index = $ifIndex") {
			return niResolveOK(t), "", nil
		}
		return niOK(t, map[string]any{"dhcp_enabled": true}), "", nil
	})
	defer restore()

	_, c := niNewClient(t)
	if err := c.RestoreDHCP(context.Background(), "Ethernet 2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "Set-NetIPInterface") || !strings.Contains(gotScript, "-Dhcp Enabled") {
		t.Errorf("restore must re-enable DHCP, got:\n%s", gotScript)
	}
}
