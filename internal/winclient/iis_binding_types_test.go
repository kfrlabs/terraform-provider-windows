// Package winclient — unit tests for the IIS binding types (issue #285).
//
// Coverage targets:
//   - Build/ParseIISBindingInformation round-trip: IPv4, "*", empty,
//     wildcard, IPv6 bracketed, empty host, bad shapes
//   - IISBindingSslFlags / IISBindingRequireSNIFromSslFlags
//   - Normalize/Validate helpers: IP, host, thumbprint, protocol, port,
//     store
//   - ParseIISBindingID / IISBindingID round-trip plus rejections
//   - IISBindingWouldLockOut decisions
//   - ValidateIISBindingInput matrix
//   - IISBindingError: Error(), Unwrap(), Is(), sentinels
//   - mapIISBindingKind: all known kinds plus unknown
package winclient

import (
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// bindingInformation round-trip
// ---------------------------------------------------------------------------

func TestBuildIISBindingInformation(t *testing.T) {
	cases := []struct {
		ip, host string
		port     int64
		want     string
	}{
		{"*", "example.com", 80, "*:80:example.com"},
		{"*", "", 80, "*:80:"},
		{"192.168.1.10", "example.com", 443, "192.168.1.10:443:example.com"},
		{"::1", "example.com", 443, "[::1]:443:example.com"},
		{"2001:db8::1", "", 80, "[2001:db8::1]:80:"},
	}
	for _, tc := range cases {
		if got := BuildIISBindingInformation(tc.ip, tc.port, tc.host); got != tc.want {
			t.Errorf("BuildIISBindingInformation(%q, %d, %q) = %q, want %q",
				tc.ip, tc.port, tc.host, got, tc.want)
		}
	}
}

func TestParseIISBindingInformation_RoundTrip(t *testing.T) {
	for _, bi := range []string{
		"*:80:example.com",
		"*:80:",
		"*:443:",
		"192.168.1.10:443:example.com",
		"10.0.0.5:8080:",
		"[::1]:443:example.com",
		"[2001:db8::1]:80:",
		":80:example.com", // empty IP normalises to *
	} {
		ip, port, host, err := ParseIISBindingInformation(bi)
		if err != nil {
			t.Errorf("ParseIISBindingInformation(%q) unexpected error: %v", bi, err)
			continue
		}
		rebuilt := BuildIISBindingInformation(ip, port, host)
		ip2, port2, host2, err := ParseIISBindingInformation(rebuilt)
		if err != nil {
			t.Errorf("re-parse of %q unexpected error: %v", rebuilt, err)
			continue
		}
		if ip != ip2 || port != port2 || host != host2 {
			t.Errorf("round-trip of %q unstable: got (%q, %d, %q)", bi, ip2, port2, host2)
		}
		if strings.HasPrefix(bi, "[") && !strings.HasPrefix(rebuilt, "[") {
			t.Errorf("IPv6 %q lost its brackets: %q", bi, rebuilt)
		}
	}
}

func TestParseIISBindingInformation_Canonical(t *testing.T) {
	ip, port, host, err := ParseIISBindingInformation("*:80:Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "*" || port != 80 || host != "example.com" {
		t.Errorf("got (%q, %d, %q), want (*, 80, example.com)", ip, port, host)
	}
	ip, _, _, err = ParseIISBindingInformation(":80:x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "*" {
		t.Errorf("empty IP must normalise to *, got %q", ip)
	}
}

func TestParseIISBindingInformation_Bad(t *testing.T) {
	for _, bad := range []string{
		"", "*:80", "*:notaport:x", "*:80abc:x", "*:0x50:x", "*: 80:x", "*:0:x", "*:65536:x",
		"999.999.999.999:80:x", "[::1:80:x", "[::1]x", "*:80:has space",
		"*:80:has:colon", // host headers cannot carry colons
	} {
		if _, _, _, err := ParseIISBindingInformation(bad); err == nil {
			t.Errorf("ParseIISBindingInformation(%q) should be rejected", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// SslFlags
// ---------------------------------------------------------------------------

func TestIISBindingSslFlags(t *testing.T) {
	if got := IISBindingSslFlags(true); got != 1 {
		t.Errorf("SslFlags(true) = %d, want 1", got)
	}
	if got := IISBindingSslFlags(false); got != 0 {
		t.Errorf("SslFlags(false) = %d, want 0", got)
	}
	for flags, want := range map[int64]bool{0: false, 1: true, 3: true, 2: false} {
		if got := IISBindingRequireSNIFromSslFlags(flags); got != want {
			t.Errorf("RequireSNIFromSslFlags(%d) = %v, want %v", flags, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Normalise / validate helpers
// ---------------------------------------------------------------------------

func TestNormalizeIISBindingIPAddress(t *testing.T) {
	for in, want := range map[string]string{
		"*": "*", "": "*",
		"  *  ":              "*",
		"192.168.1.10":       "192.168.1.10",
		"::1":                "::1",
		"2001:DB8::1":        "2001:db8::1",
		"::ffff:192.168.1.1": "192.168.1.1",
	} {
		got, err := NormalizeIISBindingIPAddress(in)
		if err != nil {
			t.Errorf("NormalizeIISBindingIPAddress(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeIISBindingIPAddress(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"nope", "[::1]", "fe80::1%eth0", "1.2.3.4/24"} {
		if _, err := NormalizeIISBindingIPAddress(bad); err == nil {
			t.Errorf("NormalizeIISBindingIPAddress(%q) should be rejected", bad)
		}
	}
}

func TestValidateIISBindingHostHeader(t *testing.T) {
	for _, ok := range []string{"", "example.com", "EXAMPLE.com", "a-b.c_d"} {
		if err := ValidateIISBindingHostHeader(ok); err != nil {
			t.Errorf("host %q should be valid, got %v", ok, err)
		}
	}
	for _, bad := range []string{"a|b", "a:b", "has space", "tab\there"} {
		if err := ValidateIISBindingHostHeader(bad); err == nil {
			t.Errorf("host %q should be rejected", bad)
		}
	}
	if got := NormalizeIISBindingHostHeader("  Example.COM "); got != "example.com" {
		t.Errorf("host normalisation = %q, want example.com", got)
	}
}

func TestNormalizeIISBindingThumbprint(t *testing.T) {
	got, err := NormalizeIISBindingThumbprint("ab cd ef 0123456789abcdef0123456789abcdef01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ABCDEF0123456789ABCDEF0123456789ABCDEF01" {
		t.Errorf("thumbprint normalisation = %q", got)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("G", 40), strings.Repeat("A", 39), strings.Repeat("A", 41)} {
		if _, err := NormalizeIISBindingThumbprint(bad); err == nil {
			t.Errorf("thumbprint %q should be rejected", bad)
		}
	}
}

func TestIISBindingProtocolAndPortAndStore(t *testing.T) {
	for _, ok := range []string{"http", "https", "HTTP", "Https", " https "} {
		if err := ValidateIISBindingProtocol(ok); err != nil {
			t.Errorf("protocol %q should be valid, got %v", ok, err)
		}
	}
	if err := ValidateIISBindingProtocol("ftp"); err == nil {
		t.Error("protocol ftp should be rejected")
	}
	if got, _ := CanonicalizeIISBindingProtocol("HTTPS"); got != "https" {
		t.Errorf("protocol canonical = %q, want https", got)
	}
	for _, ok := range []int64{1, 80, 443, 65535} {
		if err := ValidateIISBindingPort(ok); err != nil {
			t.Errorf("port %d should be valid, got %v", ok, err)
		}
	}
	for _, bad := range []int64{0, -1, 65536} {
		if err := ValidateIISBindingPort(bad); err == nil {
			t.Errorf("port %d should be rejected", bad)
		}
	}
	if got, _ := CanonicalizeIISBindingStoreName("my"); got != "My" {
		t.Errorf("store canonical = %q, want My", got)
	}
	if got, _ := CanonicalizeIISBindingStoreName("webhosting"); got != "WebHosting" {
		t.Errorf("store canonical = %q, want WebHosting", got)
	}
	if err := ValidateIISBindingStoreName("Root"); err == nil {
		t.Error("store Root should be rejected")
	}
}

// ---------------------------------------------------------------------------
// Import ID
// ---------------------------------------------------------------------------

func TestIISBindingID_RoundTrip(t *testing.T) {
	id := IISBindingID("web", "https", "*:443:example.com")
	if id != "web|https|*:443:example.com" {
		t.Fatalf("ID = %q", id)
	}
	site, proto, bi, err := ParseIISBindingID(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if site != "web" || proto != "https" || bi != "*:443:example.com" {
		t.Errorf("got (%q, %q, %q)", site, proto, bi)
	}
	// IPv6 survives the pipe split; empty IP canonicalises to *.
	_, _, bi, err = ParseIISBindingID("web|https|[::1]:443:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bi != "[::1]:443:" {
		t.Errorf("IPv6 ID binding_information = %q", bi)
	}
	_, proto, bi, err = ParseIISBindingID("web|HTTPS|:80:Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != "https" || bi != "*:80:example.com" {
		t.Errorf("canonical ID parts = (%q, %q)", proto, bi)
	}
}

func TestParseIISBindingID_Bad(t *testing.T) {
	for _, bad := range []string{
		"", "web", "web|https", "web|https|*:443:x|extra",
		"web|ftp|*:21:x", "bad|name|*:80:x", "web|https|*:80",
		"web|https|*:0:x", "|https|*:80:x", "web||*:80:x", "web|https|",
	} {
		if _, _, _, err := ParseIISBindingID(bad); err == nil {
			t.Errorf("ParseIISBindingID(%q) should be rejected", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Lockout decisions
// ---------------------------------------------------------------------------

func TestIISBindingWouldLockOut(t *testing.T) {
	if !IISBindingWouldLockOut(22, 22) {
		t.Error("port 22 vs SSH 22 must lock out")
	}
	if !IISBindingWouldLockOut(22, 2222, 22) {
		t.Error("port 22 vs ServerPort 22 must lock out")
	}
	if IISBindingWouldLockOut(80, 22) {
		t.Error("port 80 vs SSH 22 must not lock out")
	}
	if IISBindingWouldLockOut(443, 22, 2222) {
		t.Error("port 443 vs SSH 22/2222 must not lock out")
	}
	if IISBindingWouldLockOut(80, 0, -1) {
		t.Error("non-positive candidates must never match")
	}
}

// ---------------------------------------------------------------------------
// ValidateIISBindingInput matrix
// ---------------------------------------------------------------------------

func iisBindingTestInput() IISBindingInput {
	sni := false
	return IISBindingInput{SiteName: "web", Protocol: "https", IPAddress: "*", Port: 443, HostHeader: "example.com", RequireSNI: &sni}
}

func TestValidateIISBindingInput_OK(t *testing.T) {
	if err := ValidateIISBindingInput(IISSiteNameInput("web")); err != nil {
		t.Fatalf("http without cert must be valid: %v", err)
	}
	in := iisBindingTestInput()
	if err := ValidateIISBindingInput(in); err != nil {
		t.Fatalf("https with host must be valid: %v", err)
	}
	sni := true
	thumb := strings.Repeat("A", 40)
	in.RequireSNI = &sni
	in.CertificateThumbprint = &thumb
	in.CertificateStoreName = "WebHosting"
	if err := ValidateIISBindingInput(in); err != nil {
		t.Fatalf("full https input must be valid: %v", err)
	}
}

func TestValidateIISBindingInput_Removal(t *testing.T) {
	// Certificate removal (plan null with a prior certificate) reaches the
	// client as a pointer to "" / whitespace: it must validate as "no
	// certificate" instead of failing thumbprint normalisation.
	for _, raw := range []string{"", "   "} {
		s := raw
		in := iisBindingTestInput()
		in.CertificateThumbprint = &s
		in.CertificateStoreName = "My"
		if err := ValidateIISBindingInput(in); err != nil {
			t.Errorf("empty thumbprint %q must validate as removal, got %v", raw, err)
		}
	}
	// A nil thumbprint is "no certificate change" on Update.
	in := iisBindingTestInput()
	in.CertificateThumbprint = nil
	if err := ValidateIISBindingInput(in); err != nil {
		t.Errorf("nil thumbprint must be valid, got %v", err)
	}
	// Removal of an https binding with a non-default store still validates
	// (the store is ignored without a certificate).
	empty := ""
	in = iisBindingTestInput()
	in.CertificateThumbprint = &empty
	in.CertificateStoreName = "WebHosting"
	if err := ValidateIISBindingInput(in); err != nil {
		t.Errorf("removal with a store must be valid, got %v", err)
	}
	// Genuine thumbprint junk is still rejected.
	bad := "zzz"
	in = iisBindingTestInput()
	in.CertificateThumbprint = &bad
	in.CertificateStoreName = "My"
	if err := ValidateIISBindingInput(in); err == nil {
		t.Error("non-empty invalid thumbprint must be rejected")
	}
}

// IISSiteNameInput builds a minimal http input for one site name.
func IISSiteNameInput(site string) IISBindingInput {
	return IISBindingInput{SiteName: site, Protocol: "http", IPAddress: "*", Port: 80}
}

func TestValidateIISBindingInput_Matrix(t *testing.T) {
	thumb := strings.Repeat("A", 40)
	badThumb := "zzz"
	sni := true
	noSNI := false
	store := "My"
	badStore := "Root"
	cases := []struct {
		name string
		in   IISBindingInput
	}{
		{"bad site", IISBindingInput{SiteName: "a/b", Protocol: "http", IPAddress: "*", Port: 80}},
		{"bad protocol", IISBindingInput{SiteName: "web", Protocol: "ftp", IPAddress: "*", Port: 21}},
		{"bad ip", IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "nope", Port: 80}},
		{"bad port", IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 0}},
		{"bad host pipe", IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 80, HostHeader: "a|b"}},
		{"bad host colon", IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 80, HostHeader: "a:b"}},
		{"sni on http", IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 80, RequireSNI: &sni}},
		{"sni without host", IISBindingInput{SiteName: "web", Protocol: "https", IPAddress: "*", Port: 443, RequireSNI: &sni}},
		{"thumb on http", IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 80, CertificateThumbprint: &thumb, CertificateStoreName: store}},
		{"bad thumb", IISBindingInput{SiteName: "web", Protocol: "https", IPAddress: "*", Port: 443, HostHeader: "x", CertificateThumbprint: &badThumb, CertificateStoreName: store}},
		{"bad store", IISBindingInput{SiteName: "web", Protocol: "https", IPAddress: "*", Port: 443, HostHeader: "x", CertificateThumbprint: &thumb, CertificateStoreName: badStore}},
	}
	for _, tc := range cases {
		if err := ValidateIISBindingInput(tc.in); err == nil {
			t.Errorf("%s should be rejected", tc.name)
		}
	}
	// SNI explicitly false without a host is fine (plain IP binding).
	in := IISBindingInput{SiteName: "web", Protocol: "https", IPAddress: "*", Port: 443, RequireSNI: &noSNI}
	if err := ValidateIISBindingInput(in); err != nil {
		t.Errorf("explicit require_sni=false without host must be valid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error type and kind mapping
// ---------------------------------------------------------------------------

func TestIISBindingError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewIISBindingError(IISBindingErrorAccessDenied, "denied", cause, map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewIISBindingError(IISBindingErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestIISBindingError_Is(t *testing.T) {
	e := NewIISBindingError(IISBindingErrorConflict, "x", nil, nil)
	if !errors.Is(e, ErrIISBindingConflict) {
		t.Error("errors.Is(ErrIISBindingConflict) should match by kind")
	}
	if errors.Is(e, ErrIISBindingNotFound) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsIISBindingError(e, IISBindingErrorConflict) {
		t.Error("IsIISBindingError should match")
	}
	if IsIISBindingError(errors.New("plain"), IISBindingErrorConflict) {
		t.Error("IsIISBindingError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-IISBindingError should be false")
	}
}

func TestMapIISBindingKind(t *testing.T) {
	cases := map[string]IISBindingErrorKind{
		"not_found":                  IISBindingErrorNotFound,
		"site_not_found":             IISBindingErrorSiteNotFound,
		"already_exists":             IISBindingErrorAlreadyExists,
		"conflict":                   IISBindingErrorConflict,
		"ssl_binding_conflict":       IISBindingErrorSSLBindingConflict,
		"certificate_not_found":      IISBindingErrorCertificateNotFound,
		"certificate_no_private_key": IISBindingErrorCertificateNoPrivateKey,
		"would_lock_out":             IISBindingErrorWouldLockOut,
		"iis_not_installed":          IISBindingErrorIISNotInstalled,
		"access_denied":              IISBindingErrorAccessDenied,
		"":                           IISBindingErrorUnknown,
		"weird_kind":                 IISBindingErrorUnknown,
	}
	for in, want := range cases {
		if got := mapIISBindingKind(in, "some message"); got != want {
			t.Errorf("mapIISBindingKind(%q) = %q, want %q", in, got, want)
		}
	}
}
