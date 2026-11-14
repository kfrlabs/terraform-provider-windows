// Package winclient — unit tests for DnsClientClientImpl.
//
// The package-level seam runDnsClientPowerShell (script transport) is
// stubbed so no real SSH connection is needed. Coverage targets (issue
// #229):
//
//	DnsClientError: Error(), Unwrap(), Is(), sentinels
//	mapDnsClientKind: all known kinds + unknown fallback
//	ValidateDnsClientAlias / ValidateDnsClientServerAddresses /
//	ValidateDnsClientSuffix: canonicalisation, family, uniqueness,
//	rejections (loopback allowed)
//	script builders: user values only via psQuote/psQuoteList, exact -eq
//	alias match, no wildcard -InterfaceAlias, cross-family merge,
//	ResetServerAddresses on empty merge
//	envelope mapping: unreachable on transport/timeout, typed remote kinds
//	Read/Apply/Reset: happy paths, interface_not_found as nil, validation
//	gating (no remote call), empty Reset short-circuit to Read
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

// dcNewClient returns a *DnsClientClientImpl for tests.
func dcNewClient(t *testing.T) *DnsClientClientImpl {
	t.Helper()
	c, err := New(Config{Host: "windns01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewDnsClientClient(c)
}

// dcOK returns a JSON ok-envelope whose data field is the supplied value.
func dcOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("dcOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// dcErr returns a JSON error-envelope for the given kind/message.
func dcErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("dcErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// dcStubRun replaces runDnsClientPowerShell for one test.
func dcStubRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runDnsClientPowerShell
	runDnsClientPowerShell = fn
	return func() { runDnsClientPowerShell = prev }
}

// testDNSClientState is a minimal valid DnsClientState JSON payload.
func testDNSClientState() map[string]any {
	return map[string]any{
		"interface_alias":                  "Ethernet 2",
		"interface_index":                  14,
		"interface_guid":                   "{11111111-2222-3333-4444-555555555555}",
		"static_ipv4":                      []any{"192.0.2.53"},
		"static_ipv6":                      []any{},
		"effective_ipv4":                   []any{"192.0.2.53", "198.51.100.53"},
		"effective_ipv6":                   []any{},
		"connection_specific_suffix":       "corp.example.com",
		"register_this_connection_address": true,
		"use_suffix_when_registering":      true,
	}
}

// dcStubState stubs a single successful state response.
func dcStubState(t *testing.T, state map[string]any) func() {
	t.Helper()
	return dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return dcOK(t, state), "", nil
	})
}

// ---------------------------------------------------------------------------
// DnsClientError
// ---------------------------------------------------------------------------

func TestDnsClientError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewDnsClientError(DnsClientErrorPermission, "denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewDnsClientError(DnsClientErrorInterfaceNotFound, "bad", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestDnsClientError_Is(t *testing.T) {
	e := NewDnsClientError(DnsClientErrorInvalidAddress, "x", nil, nil)
	if !errors.Is(e, ErrDnsClientInvalidAddress) {
		t.Error("errors.Is should match by kind")
	}
	if errors.Is(e, ErrDnsClientInvalidSuffix) {
		t.Error("errors.Is must not match a different kind")
	}
	if errors.Is(e, errors.New("other")) {
		t.Error("errors.Is must not match a foreign type")
	}
}

func TestIsDnsClientError(t *testing.T) {
	e := NewDnsClientError(DnsClientErrorUnreachable, "down", nil, nil)
	if !IsDnsClientError(e, DnsClientErrorUnreachable) {
		t.Error("IsDnsClientError should report the matching kind")
	}
	if IsDnsClientError(e, DnsClientErrorUnknown) {
		t.Error("IsDnsClientError must not report a different kind")
	}
	if IsDnsClientError(errors.New("plain"), DnsClientErrorUnreachable) {
		t.Error("IsDnsClientError must be false for plain errors")
	}
}

func TestDnsClientSentinels(t *testing.T) {
	for _, tc := range []struct {
		sentinel *DnsClientError
		kind     DnsClientErrorKind
	}{
		{ErrDnsClientInterfaceNotFound, DnsClientErrorInterfaceNotFound},
		{ErrDnsClientInvalidAddress, DnsClientErrorInvalidAddress},
		{ErrDnsClientInvalidSuffix, DnsClientErrorInvalidSuffix},
		{ErrDnsClientPermission, DnsClientErrorPermission},
		{ErrDnsClientUnreachable, DnsClientErrorUnreachable},
		{ErrDnsClientUnknown, DnsClientErrorUnknown},
	} {
		if !errors.Is(tc.sentinel, &DnsClientError{Resource: "windows_dns_client", Kind: string(tc.kind)}) {
			t.Errorf("sentinel for %q does not match", tc.kind)
		}
	}
}

// ---------------------------------------------------------------------------
// mapDnsClientKind
// ---------------------------------------------------------------------------

func TestMapDnsClientKind(t *testing.T) {
	for _, kind := range []DnsClientErrorKind{
		DnsClientErrorInterfaceNotFound,
		DnsClientErrorInvalidAddress,
		DnsClientErrorInvalidSuffix,
		DnsClientErrorPermission,
	} {
		if got := mapDnsClientKind(string(kind)); got != kind {
			t.Errorf("mapDnsClientKind(%q) = %q, want identity", kind, got)
		}
	}
	for _, unknown := range []string{"", "nope", "management_path_at_risk", "dhcp_enabled"} {
		if got := mapDnsClientKind(unknown); got != DnsClientErrorUnknown {
			t.Errorf("mapDnsClientKind(%q) = %q, want unknown", unknown, got)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateDnsClientAlias
// ---------------------------------------------------------------------------

func TestValidateDnsClientAlias(t *testing.T) {
	if err := ValidateDnsClientAlias("Ethernet 2"); err != nil {
		t.Errorf("valid alias rejected: %v", err)
	}
	for _, bad := range []string{"", "   ", "\t"} {
		err := ValidateDnsClientAlias(bad)
		if !IsDnsClientError(err, DnsClientErrorInterfaceNotFound) {
			t.Errorf("alias %q: want interface_not_found, got %v", bad, err)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateDnsClientServerAddresses (pure-Go)
// ---------------------------------------------------------------------------

func TestValidateDnsClientServerAddresses_HappyPath(t *testing.T) {
	got, err := ValidateDnsClientServerAddresses([]string{"192.0.2.53", "198.51.100.1"}, false)
	if err != nil {
		t.Fatalf("valid IPv4 list rejected: %v", err)
	}
	if len(got) != 2 || got[0] != "192.0.2.53" || got[1] != "198.51.100.1" {
		t.Errorf("order not preserved: %v", got)
	}
	// IPv6 canonicalisation preserves order.
	got6, err := ValidateDnsClientServerAddresses([]string{"2001:DB8::53", "2001:db8::1"}, true)
	if err != nil {
		t.Fatalf("valid IPv6 list rejected: %v", err)
	}
	if len(got6) != 2 || got6[0] != "2001:db8::53" || got6[1] != "2001:db8::1" {
		t.Errorf("IPv6 not canonicalised in order: %v", got6)
	}
	// Loopback is allowed (local resolver).
	if _, err := ValidateDnsClientServerAddresses([]string{"127.0.0.1", "::1"}, false); err == nil {
		t.Error("mixed-family list must fail the IPv4 validator")
	} else if !IsDnsClientError(err, DnsClientErrorInvalidAddress) {
		t.Errorf("want invalid_address, got %v", err)
	}
	if _, err := ValidateDnsClientServerAddresses([]string{"127.0.0.1"}, false); err != nil {
		t.Errorf("loopback must be allowed: %v", err)
	}
	if _, err := ValidateDnsClientServerAddresses([]string{"::1"}, true); err != nil {
		t.Errorf("IPv6 loopback must be allowed: %v", err)
	}
}

func TestValidateDnsClientServerAddresses_Rejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		addrs  []string
		wantV6 bool
	}{
		{"unparsable", []string{"not-an-ip"}, false},
		{"wrong family v6 in v4", []string{"2001:db8::53"}, false},
		{"wrong family v4 in v6", []string{"192.0.2.53"}, true},
		{"unspecified v4", []string{"0.0.0.0"}, false},
		{"unspecified v6", []string{"::"}, true},
		{"multicast v4", []string{"224.0.0.251"}, false},
		{"multicast v6", []string{"ff02::1"}, true},
		{"broadcast", []string{"255.255.255.255"}, false},
		{"zone id", []string{"fe80::1%eth0"}, true},
		{"duplicate raw", []string{"192.0.2.53", "192.0.2.53"}, false},
		{"duplicate canonical", []string{"2001:DB8::53", "2001:db8::53"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateDnsClientServerAddresses(tc.addrs, tc.wantV6)
			if !IsDnsClientError(err, DnsClientErrorInvalidAddress) {
				t.Errorf("want invalid_address, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateDnsClientSuffix (pure-Go)
// ---------------------------------------------------------------------------

func TestValidateDnsClientSuffix(t *testing.T) {
	for _, ok := range []string{"corp", "corp.example.com", "a-b.c0m", "x"} {
		if err := ValidateDnsClientSuffix(ok); err != nil {
			t.Errorf("suffix %q rejected: %v", ok, err)
		}
	}
	for _, tc := range []struct {
		name   string
		suffix string
	}{
		{"empty", ""},
		{"empty label", "corp..example.com"},
		{"leading dot", ".example.com"},
		{"trailing dot", "example.com."},
		{"leading hyphen", "-corp.example.com"},
		{"trailing hyphen", "corp-.example.com"},
		{"underscore", "under_score.example.com"},
		{"space", "corp example.com"},
		{"label too long", strings.Repeat("a", 64) + ".example.com"},
		{"total too long", strings.Repeat("a.", 130) + "com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDnsClientSuffix(tc.suffix)
			if !IsDnsClientError(err, DnsClientErrorInvalidSuffix) {
				t.Errorf("suffix %q: want invalid_suffix, got %v", tc.suffix, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

func TestBuildDnsClientScripts_QuotingAndMatching(t *testing.T) {
	nasty := "Eth'er 2"
	read := buildDnsClientReadScript(nasty)
	if !strings.Contains(read, "'Eth''er 2'") {
		t.Errorf("read script must psQuote the alias: %s", read)
	}
	if !strings.Contains(read, "Where-Object { $_.InterfaceAlias -eq $alias }") {
		t.Error("read script must resolve with an exact -eq comparison")
	}
	if strings.Contains(read, "-InterfaceAlias") {
		t.Error("read script must not use wildcard -InterfaceAlias matching")
	}
	if !strings.Contains(read, "-InterfaceIndex $ifIndex") && !strings.Contains(read, "-InterfaceIndex $IfIndex") {
		t.Error("read script must scope Get-DnsClientServerAddress via -InterfaceIndex")
	}

	suffix := "corp.example'com"
	reg, use := true, false
	apply := buildDnsClientApplyScript(nasty, DnsClientSettings{
		IPv4Set: true, IPv4Addresses: []string{"192.0.2.53"},
		IPv6Set: true, IPv6Addresses: []string{},
		SuffixSet: true, ConnectionSpecificSuffix: &suffix,
		RegisterThisConnectionAddress: &reg, UseSuffixWhenRegistering: &use,
	})
	if !strings.Contains(apply, "'Eth''er 2'") {
		t.Error("apply script must psQuote the alias")
	}
	if !strings.Contains(apply, "@('192.0.2.53')") {
		t.Error("apply script must render addresses via psQuoteList")
	}
	if !strings.Contains(apply, "'corp.example''com'") {
		t.Error("apply script must psQuote the suffix")
	}
	if !strings.Contains(apply, "-ResetServerAddresses") {
		t.Error("apply script must use -ResetServerAddresses for an empty merge")
	}
	if !strings.Contains(apply, "$merged += @($curV4)") || !strings.Contains(apply, "$merged += @($curV6)") {
		t.Error("apply script must merge unmanaged families from observed state")
	}
}

func TestBuildDnsClientApplyScript_SingleFamilyResetReAddsPreserved(t *testing.T) {
	// Resetting IPv4 while keeping an IPv6 server must reset all addresses
	// first and then re-add the preserved family.
	apply := buildDnsClientApplyScript("Ethernet 2", DnsClientSettings{
		IPv4Set: true, IPv4Addresses: []string{},
		IPv6Set: true, IPv6Addresses: []string{"2001:db8::53"},
	})
	for _, want := range []string{
		"$singleFamilyReset",
		"-ResetServerAddresses",
		"-ServerAddresses $merged",
	} {
		if !strings.Contains(apply, want) {
			t.Errorf("single-family reset script must contain %q", want)
		}
	}
}

func TestBuildDnsClientScripts_SurfaceLookupFailures(t *testing.T) {
	// Registry and adapter-lookup failures must surface as typed errors
	// instead of masquerading as empty (automatic) lists.
	read := buildDnsClientReadScript("Ethernet 2")
	for _, want := range []string{
		"Test-DnsClientAccessDenied",
		"step = 'read'",
		"step = 'resolve_guid'",
	} {
		if !strings.Contains(read, want) {
			t.Errorf("read script must contain %q", want)
		}
	}
	apply := buildDnsClientApplyScript("Ethernet 2", DnsClientSettings{
		IPv4Set: true, IPv4Addresses: []string{"192.0.2.53"},
	})
	if !strings.Contains(apply, "step = 'read_current'") {
		t.Error("apply script must fail the current-state read instead of merging empty lists")
	}
}

func TestBuildDnsClientApplyScript_UnmanagedOmitsSet(t *testing.T) {
	// Fully unmanaged settings still render the script, but every write is
	// guarded so nothing is sent: all managed flags render $false.
	apply := buildDnsClientApplyScript("Ethernet 2", DnsClientSettings{})
	if !strings.Contains(apply, "if ($wantV4Set -or $wantV6Set)") {
		t.Error("server write must be guarded by the managed-family flags")
	}
	if !strings.Contains(apply, "if ($suffixSet -or $regSet -or $useSet)") {
		t.Error("suffix/flag write must be guarded by the managed-attribute flags")
	}
	for _, want := range []string{
		"$wantV4Set = $false", "$wantV6Set = $false",
		"$suffixSet = $false", "$regSet = $false", "$useSet = $false",
	} {
		if !strings.Contains(apply, want) {
			t.Errorf("unmanaged apply script must render %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Envelope mapping
// ---------------------------------------------------------------------------

func TestDnsClientEnvelope_TransportMapsUnreachable(t *testing.T) {
	c := dcNewClient(t)
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "boom", errors.New("ssh: connection refused")
	})()
	_, err := c.runDnsClientEnvelope(context.Background(), "read", "script", nil)
	if !IsDnsClientError(err, DnsClientErrorUnreachable) {
		t.Errorf("transport failure: want unreachable, got %v", err)
	}
}

func TestDnsClientEnvelope_TimeoutMapsUnreachable(t *testing.T) {
	c := dcNewClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer dcStubRun(func(ctx context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", ctx.Err()
	})()
	_, err := c.runDnsClientEnvelope(ctx, "read", "script", nil)
	if !IsDnsClientError(err, DnsClientErrorUnreachable) {
		t.Errorf("cancelled context: want unreachable, got %v", err)
	}
}

func TestDnsClientEnvelope_RemoteKindMapping(t *testing.T) {
	for kind, want := range map[string]DnsClientErrorKind{
		"interface_not_found": DnsClientErrorInterfaceNotFound,
		"invalid_address":     DnsClientErrorInvalidAddress,
		"invalid_suffix":      DnsClientErrorInvalidSuffix,
		"permission_denied":   DnsClientErrorPermission,
		"something_else":      DnsClientErrorUnknown,
	} {
		c := dcNewClient(t)
		k := kind
		defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
			// dcErr needs *testing.T; build the envelope inline.
			b, _ := json.Marshal(map[string]any{
				"ok": false, "kind": k, "message": "m " + k, "context": map[string]string{},
			})
			return string(b) + "\n", "", nil
		})()
		_, err := c.runDnsClientEnvelope(context.Background(), "apply", "script", nil)
		if !IsDnsClientError(err, want) {
			t.Errorf("kind %q: want %q, got %v", k, want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestDnsClientRead_HappyPath(t *testing.T) {
	c := dcNewClient(t)
	defer dcStubState(t, testDNSClientState())()
	got, err := c.Read(context.Background(), "ethernet 2")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.InterfaceIndex != 14 {
		t.Errorf("InterfaceIndex = %d, want 14", got.InterfaceIndex)
	}
	if got.InterfaceGUID != "{11111111-2222-3333-4444-555555555555}" {
		t.Errorf("InterfaceGUID = %q", got.InterfaceGUID)
	}
	if len(got.StaticIPv4) != 1 || got.StaticIPv4[0] != "192.0.2.53" {
		t.Errorf("StaticIPv4 = %v", got.StaticIPv4)
	}
	if len(got.StaticIPv6) != 0 {
		t.Errorf("StaticIPv6 should be empty, got %v", got.StaticIPv6)
	}
	if len(got.EffectiveIPv4) != 2 {
		t.Errorf("EffectiveIPv4 = %v (DHCP-inclusive)", got.EffectiveIPv4)
	}
	if got.ConnectionSpecificSuffix != "corp.example.com" {
		t.Errorf("Suffix = %q", got.ConnectionSpecificSuffix)
	}
}

func TestDnsClientRead_InterfaceGoneReturnsNil(t *testing.T) {
	c := dcNewClient(t)
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return dcErr(t, "interface_not_found", "No interface matches alias"), "", nil
	})()
	got, err := c.Read(context.Background(), "Ethernet 9")
	if err != nil {
		t.Fatalf("missing interface must not error: %v", err)
	}
	if got != nil {
		t.Errorf("missing interface must return nil, got %+v", got)
	}
}

func TestDnsClientRead_BlankAliasRejected(t *testing.T) {
	c := dcNewClient(t)
	called := false
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})()
	if _, err := c.Read(context.Background(), "  "); !IsDnsClientError(err, DnsClientErrorInterfaceNotFound) {
		t.Errorf("want interface_not_found, got %v", err)
	}
	if called {
		t.Error("blank alias must not reach the transport")
	}
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

func TestDnsClientApply_HappyPath(t *testing.T) {
	c := dcNewClient(t)
	var gotScript string
	defer dcStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return dcOK(t, testDNSClientState()), "", nil
	})()
	suffix := "corp.example.com"
	reg, use := true, true
	got, err := c.Apply(context.Background(), "Ethernet 2", DnsClientSettings{
		IPv4Set: true, IPv4Addresses: []string{"192.0.2.53"},
		IPv6Set: true, IPv6Addresses: []string{},
		SuffixSet: true, ConnectionSpecificSuffix: &suffix,
		RegisterThisConnectionAddress: &reg, UseSuffixWhenRegistering: &use,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got.InterfaceAlias != "Ethernet 2" {
		t.Errorf("InterfaceAlias = %q", got.InterfaceAlias)
	}
	if !strings.Contains(gotScript, "$alias = 'Ethernet 2'") {
		t.Error("apply script must carry the quoted alias")
	}
}

func TestDnsClientApply_ValidationGatesTransport(t *testing.T) {
	c := dcNewClient(t)
	called := false
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})()
	badSuffix := "bad_suffix.example.com"
	for _, tc := range []struct {
		name     string
		settings DnsClientSettings
		kind     DnsClientErrorKind
	}{
		{"bad v4", DnsClientSettings{IPv4Set: true, IPv4Addresses: []string{"999.1.1.1"}}, DnsClientErrorInvalidAddress},
		{"v6 in v4", DnsClientSettings{IPv4Set: true, IPv4Addresses: []string{"2001:db8::53"}}, DnsClientErrorInvalidAddress},
		{"dup v4", DnsClientSettings{IPv4Set: true, IPv4Addresses: []string{"192.0.2.53", "192.0.2.53"}}, DnsClientErrorInvalidAddress},
		{"bad suffix", DnsClientSettings{SuffixSet: true, ConnectionSpecificSuffix: &badSuffix}, DnsClientErrorInvalidSuffix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Apply(context.Background(), "Ethernet 2", tc.settings); !IsDnsClientError(err, tc.kind) {
				t.Errorf("want %q, got %v", tc.kind, err)
			}
		})
	}
	if called {
		t.Error("invalid input must not reach the transport")
	}
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

func TestDnsClientReset_HappyPath(t *testing.T) {
	c := dcNewClient(t)
	var gotScript string
	defer dcStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		empty := testDNSClientState()
		empty["static_ipv4"] = []any{}
		empty["connection_specific_suffix"] = ""
		return dcOK(t, empty), "", nil
	})()
	got, err := c.Reset(context.Background(), "Ethernet 2", true, false, true)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if len(got.StaticIPv4) != 0 {
		t.Errorf("StaticIPv4 should be reset, got %v", got.StaticIPv4)
	}
	if got.ConnectionSpecificSuffix != "" {
		t.Errorf("suffix should be cleared, got %q", got.ConnectionSpecificSuffix)
	}
	if !strings.Contains(gotScript, "$wantV4Set = $true") || !strings.Contains(gotScript, "$wantV6Set = $false") {
		t.Error("reset script must manage only the requested families")
	}
}

func TestDnsClientReset_MissingInterfaceIsNoop(t *testing.T) {
	c := dcNewClient(t)
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return dcErr(t, "interface_not_found", "No interface matches alias"), "", nil
	})()
	got, err := c.Reset(context.Background(), "Ethernet 9", true, true, true)
	if err != nil {
		t.Fatalf("missing interface must not error: %v", err)
	}
	if got != nil {
		t.Errorf("missing interface must return nil, got %+v", got)
	}
}

func TestDnsClientReset_NothingToDoReads(t *testing.T) {
	c := dcNewClient(t)
	ops := 0
	defer dcStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		ops++
		if !strings.Contains(script, "ConvertTo-DnsClientJson $client") {
			t.Error("expected a read-only script for an empty Reset")
		}
		return dcOK(t, testDNSClientState()), "", nil
	})()
	got, err := c.Reset(context.Background(), "Ethernet 2", false, false, false)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got == nil || ops != 1 {
		t.Errorf("empty Reset must short-circuit to a single Read (ops=%d)", ops)
	}
}

// ---------------------------------------------------------------------------
// parseDnsClientState
// ---------------------------------------------------------------------------

func TestParseDnsClientState_Canonicalises(t *testing.T) {
	raw, _ := json.Marshal(testDNSClientState())
	got, err := parseDnsClientState(raw, "h")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.StaticIPv4[0] != "192.0.2.53" || got.EffectiveIPv4[1] != "198.51.100.53" {
		t.Errorf("unexpected state: %+v", got)
	}
}

func TestParseDnsClientState_BadJSON(t *testing.T) {
	if _, err := parseDnsClientState(json.RawMessage("{oops"), "h"); !IsDnsClientError(err, DnsClientErrorUnknown) {
		t.Errorf("want unknown, got %v", err)
	}
}

func TestParseDnsClientState_BadAddressFails(t *testing.T) {
	// One unparsable host value fails the operation even when the rest of
	// the list is valid; bad values are never silently dropped.
	state := testDNSClientState()
	state["static_ipv4"] = []any{"192.0.2.53", "not-an-ip"}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseDnsClientState(raw, "h"); !IsDnsClientError(err, DnsClientErrorUnknown) {
		t.Errorf("mixed good/bad host list: want unknown, got %v", err)
	}
}
