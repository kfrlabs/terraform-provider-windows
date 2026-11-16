// Package winclient — unit tests for DNSClientClientImpl.
//
// The package-level seam runDNSClientPowerShell (script transport) is
// stubbed so no real SSH connection is needed. Coverage targets (issue
// #229):
//
//	DNSClientError: Error(), Unwrap(), Is(), sentinels
//	mapDNSClientKind: all known kinds + unknown fallback
//	ValidateDNSClientAlias / ValidateDNSClientServerAddresses /
//	ValidateDNSClientSuffix: canonicalisation, family, uniqueness,
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

// dcNewClient returns a *DNSClientClientImpl for tests.
func dcNewClient(t *testing.T) *DNSClientClientImpl {
	t.Helper()
	c, err := New(Config{Host: "windns01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: BoolPtr(true)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewDNSClientClient(c)
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

// dcStubRun replaces runDNSClientPowerShell for one test.
func dcStubRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runDNSClientPowerShell
	runDNSClientPowerShell = fn
	return func() { runDNSClientPowerShell = prev }
}

// testDNSClientState is a minimal valid DNSClientState JSON payload.
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
// DNSClientError
// ---------------------------------------------------------------------------

func TestDNSClientError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewDNSClientError(DNSClientErrorPermission, "denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewDNSClientError(DNSClientErrorInterfaceNotFound, "bad", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestDNSClientError_Is(t *testing.T) {
	e := NewDNSClientError(DNSClientErrorInvalidAddress, "x", nil, nil)
	if !errors.Is(e, ErrDNSClientInvalidAddress) {
		t.Error("errors.Is should match by kind")
	}
	if errors.Is(e, ErrDNSClientInvalidSuffix) {
		t.Error("errors.Is must not match a different kind")
	}
	if errors.Is(e, errors.New("other")) {
		t.Error("errors.Is must not match a foreign type")
	}
}

func TestIsDNSClientError(t *testing.T) {
	e := NewDNSClientError(DNSClientErrorUnreachable, "down", nil, nil)
	if !IsDNSClientError(e, DNSClientErrorUnreachable) {
		t.Error("IsDNSClientError should report the matching kind")
	}
	if IsDNSClientError(e, DNSClientErrorUnknown) {
		t.Error("IsDNSClientError must not report a different kind")
	}
	if IsDNSClientError(errors.New("plain"), DNSClientErrorUnreachable) {
		t.Error("IsDNSClientError must be false for plain errors")
	}
}

func TestDNSClientSentinels(t *testing.T) {
	for _, tc := range []struct {
		sentinel *DNSClientError
		kind     DNSClientErrorKind
	}{
		{ErrDNSClientInterfaceNotFound, DNSClientErrorInterfaceNotFound},
		{ErrDNSClientInvalidAddress, DNSClientErrorInvalidAddress},
		{ErrDNSClientInvalidSuffix, DNSClientErrorInvalidSuffix},
		{ErrDNSClientPermission, DNSClientErrorPermission},
		{ErrDNSClientUnreachable, DNSClientErrorUnreachable},
		{ErrDNSClientUnknown, DNSClientErrorUnknown},
	} {
		if !errors.Is(tc.sentinel, &DNSClientError{Resource: "windows_dns_client", Kind: string(tc.kind)}) {
			t.Errorf("sentinel for %q does not match", tc.kind)
		}
	}
}

// ---------------------------------------------------------------------------
// mapDNSClientKind
// ---------------------------------------------------------------------------

func TestMapDNSClientKind(t *testing.T) {
	for _, kind := range []DNSClientErrorKind{
		DNSClientErrorInterfaceNotFound,
		DNSClientErrorInvalidAddress,
		DNSClientErrorInvalidSuffix,
		DNSClientErrorPermission,
	} {
		if got := mapDNSClientKind(string(kind)); got != kind {
			t.Errorf("mapDNSClientKind(%q) = %q, want identity", kind, got)
		}
	}
	for _, unknown := range []string{"", "nope", "management_path_at_risk", "dhcp_enabled"} {
		if got := mapDNSClientKind(unknown); got != DNSClientErrorUnknown {
			t.Errorf("mapDNSClientKind(%q) = %q, want unknown", unknown, got)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateDNSClientAlias
// ---------------------------------------------------------------------------

func TestValidateDNSClientAlias(t *testing.T) {
	if err := ValidateDNSClientAlias("Ethernet 2"); err != nil {
		t.Errorf("valid alias rejected: %v", err)
	}
	for _, bad := range []string{"", "   ", "\t"} {
		err := ValidateDNSClientAlias(bad)
		if !IsDNSClientError(err, DNSClientErrorInterfaceNotFound) {
			t.Errorf("alias %q: want interface_not_found, got %v", bad, err)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateDNSClientServerAddresses (pure-Go)
// ---------------------------------------------------------------------------

func TestValidateDNSClientServerAddresses_HappyPath(t *testing.T) {
	got, err := ValidateDNSClientServerAddresses([]string{"192.0.2.53", "198.51.100.1"}, false)
	if err != nil {
		t.Fatalf("valid IPv4 list rejected: %v", err)
	}
	if len(got) != 2 || got[0] != "192.0.2.53" || got[1] != "198.51.100.1" {
		t.Errorf("order not preserved: %v", got)
	}
	// IPv6 canonicalisation preserves order.
	got6, err := ValidateDNSClientServerAddresses([]string{"2001:DB8::53", "2001:db8::1"}, true)
	if err != nil {
		t.Fatalf("valid IPv6 list rejected: %v", err)
	}
	if len(got6) != 2 || got6[0] != "2001:db8::53" || got6[1] != "2001:db8::1" {
		t.Errorf("IPv6 not canonicalised in order: %v", got6)
	}
	// Loopback is allowed (local resolver).
	if _, err := ValidateDNSClientServerAddresses([]string{"127.0.0.1", "::1"}, false); err == nil {
		t.Error("mixed-family list must fail the IPv4 validator")
	} else if !IsDNSClientError(err, DNSClientErrorInvalidAddress) {
		t.Errorf("want invalid_address, got %v", err)
	}
	if _, err := ValidateDNSClientServerAddresses([]string{"127.0.0.1"}, false); err != nil {
		t.Errorf("loopback must be allowed: %v", err)
	}
	if _, err := ValidateDNSClientServerAddresses([]string{"::1"}, true); err != nil {
		t.Errorf("IPv6 loopback must be allowed: %v", err)
	}
}

func TestValidateDNSClientServerAddresses_Rejections(t *testing.T) {
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
			_, err := ValidateDNSClientServerAddresses(tc.addrs, tc.wantV6)
			if !IsDNSClientError(err, DNSClientErrorInvalidAddress) {
				t.Errorf("want invalid_address, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateDNSClientSuffix (pure-Go)
// ---------------------------------------------------------------------------

func TestValidateDNSClientSuffix(t *testing.T) {
	for _, ok := range []string{"corp", "corp.example.com", "a-b.c0m", "x"} {
		if err := ValidateDNSClientSuffix(ok); err != nil {
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
			err := ValidateDNSClientSuffix(tc.suffix)
			if !IsDNSClientError(err, DNSClientErrorInvalidSuffix) {
				t.Errorf("suffix %q: want invalid_suffix, got %v", tc.suffix, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

func TestBuildDNSClientScripts_QuotingAndMatching(t *testing.T) {
	nasty := "Eth'er 2"
	read := buildDNSClientReadScript(nasty)
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
	apply := buildDNSClientApplyScript(nasty, DNSClientSettings{
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

func TestBuildDNSClientApplyScript_SingleFamilyResetReAddsPreserved(t *testing.T) {
	// Resetting IPv4 while keeping an IPv6 server must reset all addresses
	// first and then re-add the preserved family.
	apply := buildDNSClientApplyScript("Ethernet 2", DNSClientSettings{
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

func TestBuildDNSClientScripts_SurfaceLookupFailures(t *testing.T) {
	// Registry and adapter-lookup failures must surface as typed errors
	// instead of masquerading as empty (automatic) lists.
	read := buildDNSClientReadScript("Ethernet 2")
	for _, want := range []string{
		"Test-DnsClientAccessDenied",
		"step = 'read'",
		"step = 'resolve_guid'",
	} {
		if !strings.Contains(read, want) {
			t.Errorf("read script must contain %q", want)
		}
	}
	apply := buildDNSClientApplyScript("Ethernet 2", DNSClientSettings{
		IPv4Set: true, IPv4Addresses: []string{"192.0.2.53"},
	})
	if !strings.Contains(apply, "step = 'read_current'") {
		t.Error("apply script must fail the current-state read instead of merging empty lists")
	}
}

func TestBuildDNSClientApplyScript_UnmanagedOmitsSet(t *testing.T) {
	// Fully unmanaged settings still render the script, but every write is
	// guarded so nothing is sent: all managed flags render $false.
	apply := buildDNSClientApplyScript("Ethernet 2", DNSClientSettings{})
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

func TestDNSClientEnvelope_TransportMapsUnreachable(t *testing.T) {
	c := dcNewClient(t)
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "boom", errors.New("ssh: connection refused")
	})()
	_, err := c.runDNSClientEnvelope(context.Background(), "read", "script", nil)
	if !IsDNSClientError(err, DNSClientErrorUnreachable) {
		t.Errorf("transport failure: want unreachable, got %v", err)
	}
}

func TestDNSClientEnvelope_TimeoutMapsUnreachable(t *testing.T) {
	c := dcNewClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer dcStubRun(func(ctx context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", ctx.Err()
	})()
	_, err := c.runDNSClientEnvelope(ctx, "read", "script", nil)
	if !IsDNSClientError(err, DNSClientErrorUnreachable) {
		t.Errorf("cancelled context: want unreachable, got %v", err)
	}
}

func TestDNSClientEnvelope_RemoteKindMapping(t *testing.T) {
	for kind, want := range map[string]DNSClientErrorKind{
		"interface_not_found": DNSClientErrorInterfaceNotFound,
		"invalid_address":     DNSClientErrorInvalidAddress,
		"invalid_suffix":      DNSClientErrorInvalidSuffix,
		"permission_denied":   DNSClientErrorPermission,
		"something_else":      DNSClientErrorUnknown,
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
		_, err := c.runDNSClientEnvelope(context.Background(), "apply", "script", nil)
		if !IsDNSClientError(err, want) {
			t.Errorf("kind %q: want %q, got %v", k, want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestDNSClientRead_HappyPath(t *testing.T) {
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

func TestDNSClientRead_InterfaceGoneReturnsNil(t *testing.T) {
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

func TestDNSClientRead_BlankAliasRejected(t *testing.T) {
	c := dcNewClient(t)
	called := false
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})()
	if _, err := c.Read(context.Background(), "  "); !IsDNSClientError(err, DNSClientErrorInterfaceNotFound) {
		t.Errorf("want interface_not_found, got %v", err)
	}
	if called {
		t.Error("blank alias must not reach the transport")
	}
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

func TestDNSClientApply_HappyPath(t *testing.T) {
	c := dcNewClient(t)
	var gotScript string
	defer dcStubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return dcOK(t, testDNSClientState()), "", nil
	})()
	suffix := "corp.example.com"
	reg, use := true, true
	got, err := c.Apply(context.Background(), "Ethernet 2", DNSClientSettings{
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

func TestDNSClientApply_ValidationGatesTransport(t *testing.T) {
	c := dcNewClient(t)
	called := false
	defer dcStubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})()
	badSuffix := "bad_suffix.example.com"
	for _, tc := range []struct {
		name     string
		settings DNSClientSettings
		kind     DNSClientErrorKind
	}{
		{"bad v4", DNSClientSettings{IPv4Set: true, IPv4Addresses: []string{"999.1.1.1"}}, DNSClientErrorInvalidAddress},
		{"v6 in v4", DNSClientSettings{IPv4Set: true, IPv4Addresses: []string{"2001:db8::53"}}, DNSClientErrorInvalidAddress},
		{"dup v4", DNSClientSettings{IPv4Set: true, IPv4Addresses: []string{"192.0.2.53", "192.0.2.53"}}, DNSClientErrorInvalidAddress},
		{"bad suffix", DNSClientSettings{SuffixSet: true, ConnectionSpecificSuffix: &badSuffix}, DNSClientErrorInvalidSuffix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Apply(context.Background(), "Ethernet 2", tc.settings); !IsDNSClientError(err, tc.kind) {
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

func TestDNSClientReset_HappyPath(t *testing.T) {
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

func TestDNSClientReset_MissingInterfaceIsNoop(t *testing.T) {
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

func TestDNSClientReset_NothingToDoReads(t *testing.T) {
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
// parseDNSClientState
// ---------------------------------------------------------------------------

func TestParseDNSClientState_Canonicalises(t *testing.T) {
	raw, _ := json.Marshal(testDNSClientState())
	got, err := parseDNSClientState(raw, "h")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.StaticIPv4[0] != "192.0.2.53" || got.EffectiveIPv4[1] != "198.51.100.53" {
		t.Errorf("unexpected state: %+v", got)
	}
}

func TestParseDNSClientState_BadJSON(t *testing.T) {
	if _, err := parseDNSClientState(json.RawMessage("{oops"), "h"); !IsDNSClientError(err, DNSClientErrorUnknown) {
		t.Errorf("want unknown, got %v", err)
	}
}

func TestParseDNSClientState_BadAddressFails(t *testing.T) {
	// One unparsable host value fails the operation even when the rest of
	// the list is valid; bad values are never silently dropped.
	state := testDNSClientState()
	state["static_ipv4"] = []any{"192.0.2.53", "not-an-ip"}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseDNSClientState(raw, "h"); !IsDNSClientError(err, DNSClientErrorUnknown) {
		t.Errorf("mixed good/bad host list: want unknown, got %v", err)
	}
}
