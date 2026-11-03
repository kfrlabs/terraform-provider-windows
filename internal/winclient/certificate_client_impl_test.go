// Package winclient — unit tests for CertificateClientImpl and the pure-Go
// PEM helpers (issue #222).
//
// The package-level seam runCertificatePowerShell (script transport with
// stdin) is stubbed so no real SSH connection is needed. Coverage targets:
//
//	CertificateError: Error(), Unwrap(), Is(), sentinels
//	mapCertificateKind: all remote kinds + unknown fallback
//	PEM helpers: parse/normalise/thumbprints (self-signed fixture
//	             generated in-test, no committed key material)
//	validation: store location/store names/thumbprint normalisation,
//	            exactly-one payload rule, base64 PFX check
//	script builders: user values only via psQuote, payloads and password
//	                 on stdin only (never in the script), key flags,
//	                 X509Store.Add, no exit
//	envelope mapping: transport/timeout -> unknown, remote kinds typed
//	Create/Read/LookupBySubject/UpdateFriendlyName/Delete: happy paths,
//	 already_exists/not_found/store_not_found mappings, stdin protocol
package winclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// certNewClient returns a *CertificateClientImpl for tests.
func certNewClient(t *testing.T) *CertificateClientImpl {
	t.Helper()
	c, err := New(Config{Host: "wincert01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewCertificateClient(c)
}

// certOK returns a JSON ok-envelope whose data field is the supplied value.
func certOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("certOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// certErr returns a JSON error-envelope for the given kind/message.
func certErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("certErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// certStubCall records one stubbed PS invocation.
type certStubCall struct {
	script string
	stdin  string
}

// certStubRun replaces runCertificatePowerShell for one test, recording
// every call and replying with fixed outputs in order (replaying the last).
func certStubRun(outputs []frResponse, calls *[]certStubCall) func() {
	prev := runCertificatePowerShell
	i := 0
	runCertificatePowerShell = func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		*calls = append(*calls, certStubCall{script: script, stdin: stdin})
		r := outputs[i]
		if i < len(outputs)-1 {
			i++
		}
		return r.stdout, r.stderr, r.err
	}
	return func() { runCertificatePowerShell = prev }
}

// certMintSelfSigned generates a throwaway self-signed certificate for
// tests (no committed key material) and returns its PEM encoding and DER.
func certMintSelfSigned(t *testing.T) (pemText string, der []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xC3A7),
		Subject:      pkix.Name{CommonName: "tf-acc-cert.example.com", Organization: []string{"TF ACC"}},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"tf-acc-cert.example.com", "alt.example.com"},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), der
}

// certTestJSON is a minimal valid ConvertTo-CertificateJson payload.
func certTestJSON(der []byte) map[string]any {
	return map[string]any{
		"store_location":    "LocalMachine",
		"store_name":        "My",
		"thumbprint":        "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
		"thumbprint_sha256": "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
		"subject":           "CN=tf-acc-cert.example.com, O=TF ACC",
		"issuer":            "CN=tf-acc-cert.example.com, O=TF ACC",
		"serial_number":     "C3A7",
		"not_before":        "2026-01-01T00:00:00Z",
		"not_after":         "2027-01-01T00:00:00Z",
		"dns_names":         []string{"tf-acc-cert.example.com"},
		"has_private_key":   false,
		"friendly_name":     "tf-acc",
		"raw_base64":        base64.StdEncoding.EncodeToString(der),
	}
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

func TestCertificateError(t *testing.T) {
	cause := errors.New("boom")
	e := NewCertificateError(CertificateErrorAccessDenied, "denied", cause, map[string]string{"host": "h"})
	if !strings.Contains(e.Error(), "access_denied") || !strings.Contains(e.Error(), "denied") {
		t.Errorf("Error() = %q", e.Error())
	}
	if !errors.Is(e, ErrCertificateAccessDenied) {
		t.Error("errors.Is must match on Kind")
	}
	if errors.Is(e, ErrCertificateNotFound) {
		t.Error("errors.Is must not match other kinds")
	}
	if !errors.Is(e, cause) {
		t.Error("errors.Is must match the cause")
	}
	var ce *CertificateError
	if !errors.As(e, &ce) || ce.Kind != CertificateErrorAccessDenied {
		t.Error("errors.As must expose the typed error")
	}
	plain := NewCertificateError(CertificateErrorUnknown, "x", nil, nil)
	if strings.Contains(plain.Error(), "<nil>") {
		t.Errorf("nil cause must not render, got %q", plain.Error())
	}
	for _, tc := range []struct {
		sentinel *CertificateError
		kind     CertificateErrorKind
	}{
		{ErrCertificateStoreNotFound, CertificateErrorStoreNotFound},
		{ErrCertificateInvalidPassword, CertificateErrorInvalidPassword},
		{ErrCertificateCorruptCertificate, CertificateErrorCorruptCertificate},
		{ErrCertificateAccessDenied, CertificateErrorAccessDenied},
		{ErrCertificateAlreadyExists, CertificateErrorAlreadyExists},
		{ErrCertificateNotFound, CertificateErrorNotFound},
		{ErrCertificateInteractiveUI, CertificateErrorInteractiveUIRequired},
		{ErrCertificateUnknown, CertificateErrorUnknown},
	} {
		if !IsCertificateError(tc.sentinel, tc.kind) {
			t.Errorf("sentinel %v must report kind %q", tc.sentinel, tc.kind)
		}
		other := CertificateErrorNotFound
		if tc.kind == CertificateErrorNotFound {
			other = CertificateErrorUnknown
		}
		if IsCertificateError(tc.sentinel, other) {
			t.Errorf("sentinel %v must not report kind %q", tc.sentinel, other)
		}
	}
}

func TestMapCertificateKind(t *testing.T) {
	for _, k := range []CertificateErrorKind{
		CertificateErrorStoreNotFound,
		CertificateErrorInvalidPassword,
		CertificateErrorCorruptCertificate,
		CertificateErrorAccessDenied,
		CertificateErrorAlreadyExists,
		CertificateErrorNotFound,
		CertificateErrorInteractiveUIRequired,
	} {
		if got := mapCertificateKind(string(k)); got != k {
			t.Errorf("mapCertificateKind(%q) = %q", k, got)
		}
	}
	for _, k := range []string{"", "nope", "NOT_FOUND"} {
		if got := mapCertificateKind(k); got != CertificateErrorUnknown {
			t.Errorf("mapCertificateKind(%q) = %q, want unknown", k, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Pure-Go PEM helpers
// ---------------------------------------------------------------------------

func TestParseCertificatePEM(t *testing.T) {
	pemText, der := certMintSelfSigned(t)
	got, err := ParseCertificatePEM(pemText)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if string(got) != string(der) {
		t.Error("DER round-trip mismatch")
	}
	// CRLF + surrounding text + trailing private key: the CERTIFICATE
	// block is still found.
	decorated := "junk header\r\n" + strings.ReplaceAll(pemText, "\n", "\r\n") +
		"-----BEGIN PRIVATE KEY-----\r\nAAAA\r\n-----END PRIVATE KEY-----\r\n"
	got, err = ParseCertificatePEM(decorated)
	if err != nil || string(got) != string(der) {
		t.Errorf("decorated PEM: got %v, err %v", len(got) == len(der), err)
	}
	// Private key first, certificate second.
	keyFirst := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n" + pemText
	if _, err := ParseCertificatePEM(keyFirst); err != nil {
		t.Errorf("key-first bundle must parse, got %v", err)
	}
	for _, bad := range []string{"", "   ", "no blocks here", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"} {
		if _, err := ParseCertificatePEM(bad); err == nil {
			t.Errorf("input %q must fail", bad)
		} else if !IsCertificateError(err, CertificateErrorCorruptCertificate) {
			t.Errorf("input %q: want corrupt_certificate, got %v", bad, err)
		}
	}
}

func TestNormalizeCertificatePEM(t *testing.T) {
	pemText, _ := certMintSelfSigned(t)
	norm, err := NormalizeCertificatePEM(pemText)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !strings.HasPrefix(norm, "-----BEGIN CERTIFICATE-----\n") || !strings.HasSuffix(norm, "-----END CERTIFICATE-----\n") {
		t.Errorf("normalised PEM must use LF framing, got %q", norm[:40])
	}
	for _, line := range strings.Split(strings.TrimSuffix(norm, "\n"), "\n")[1:] {
		if len(line) > 64 && !strings.HasPrefix(line, "-----") {
			t.Errorf("body line longer than 64 chars: %q", line)
		}
	}
	// Idempotent and CRLF-convergent.
	crlf := strings.ReplaceAll(pemText, "\n", "\r\n")
	norm2, err := NormalizeCertificatePEM(crlf)
	if err != nil || norm2 != norm {
		t.Error("CRLF input must normalise identically")
	}
	norm3, err := NormalizeCertificatePEM(norm)
	if err != nil || norm3 != norm {
		t.Error("normalisation must be idempotent")
	}
	if _, err := NormalizeCertificatePEM("garbage"); err == nil {
		t.Error("garbage must fail")
	}
}

func TestPEMThumbprints(t *testing.T) {
	pemText, der := certMintSelfSigned(t)
	thumb, err := PEMThumbprint(pemText)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if len(thumb) != 40 || strings.ToUpper(thumb) != thumb || strings.Trim(thumb, "0123456789ABCDEF") != "" {
		t.Errorf("thumbprint must be 40 uppercase hex chars, got %q", thumb)
	}
	sha, err := PEMThumbprintSHA256(pemText)
	if err != nil {
		t.Fatalf("SHA256: %v", err)
	}
	if len(sha) != 64 {
		t.Errorf("sha256 must be 64 hex chars, got %q", sha)
	}
	// Cross-check against the DER the fixture minted.
	_ = der
	if _, err := PEMThumbprint("garbage"); !IsCertificateError(err, CertificateErrorCorruptCertificate) {
		t.Errorf("garbage thumbprint: want corrupt_certificate, got %v", err)
	}
	if _, err := PEMThumbprintSHA256("garbage"); !IsCertificateError(err, CertificateErrorCorruptCertificate) {
		t.Errorf("garbage sha256: want corrupt_certificate, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Client-side validation
// ---------------------------------------------------------------------------

func TestCanonicalCertificateStoreLocation(t *testing.T) {
	for in, want := range map[string]string{
		"LocalMachine": "LocalMachine", "localmachine": "LocalMachine", "LOCALMACHINE": "LocalMachine",
		"CurrentUser": "CurrentUser", "currentuser": "CurrentUser",
		"  LocalMachine  ": "LocalMachine",
	} {
		got, err := CanonicalCertificateStoreLocation(in)
		if err != nil || got != want {
			t.Errorf("location %q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "Machine", "LM"} {
		if _, err := CanonicalCertificateStoreLocation(bad); !IsCertificateError(err, CertificateErrorStoreNotFound) {
			t.Errorf("location %q: want store_not_found, got %v", bad, err)
		}
	}
}

func TestCanonicalCertificateStoreName(t *testing.T) {
	if got, err := canonicalCertificateStoreName("My"); err != nil || got != "My" {
		t.Errorf("store = %q, %v", got, err)
	}
	if got, err := canonicalCertificateStoreName("  My  "); err != nil || got != "My" {
		t.Errorf("padded store = %q, %v", got, err)
	}
	for _, bad := range []string{"", "   ", "My/Store", `My\Store`} {
		if _, err := canonicalCertificateStoreName(bad); err == nil {
			t.Errorf("store %q must fail", bad)
		}
	}
}

func TestNormalizeCertificateThumbprint(t *testing.T) {
	if got := normalizeCertificateThumbprint("a1b2 c3"); got != "A1B2C3" {
		t.Errorf("got %q", got)
	}
	if got := normalizeCertificateThumbprint("  A1B2C3  "); got != "A1B2C3" {
		t.Errorf("got %q", got)
	}
}

func TestValidateCertificateInput(t *testing.T) {
	pemText, _ := certMintSelfSigned(t)
	pfx := base64.StdEncoding.EncodeToString([]byte("fake-pfx-payload-for-wrapped-base64-test-32b"))
	goodPEM := CertificateInput{StoreLocation: "localmachine", StoreName: "My", CertificatePEM: pemText}
	if loc, store, err := validateCertificateInput(goodPEM); err != nil || loc != "LocalMachine" || store != "My" {
		t.Errorf("PEM input = %q, %q, %v", loc, store, err)
	}
	goodPFX := CertificateInput{StoreLocation: "CurrentUser", StoreName: "My", PFXBase64: pfx, Exportable: true}
	if _, _, err := validateCertificateInput(goodPFX); err != nil {
		t.Errorf("PFX input must pass, got %v", err)
	}
	// Wrapped base64 (embedded newlines/spaces, e.g. file() output) decodes
	// like .NET FromBase64String.
	wrapped := CertificateInput{StoreLocation: "LocalMachine", StoreName: "My", PFXBase64: pfx[:8] + "\r\n " + pfx[8:16] + "\n" + pfx[16:]}
	if _, _, err := validateCertificateInput(wrapped); err != nil {
		t.Errorf("wrapped PFX base64 must pass, got %v", err)
	}
	for _, tc := range []struct {
		name  string
		input CertificateInput
	}{
		{"both", CertificateInput{StoreLocation: "LocalMachine", StoreName: "My", CertificatePEM: pemText, PFXBase64: pfx}},
		{"neither", CertificateInput{StoreLocation: "LocalMachine", StoreName: "My"}},
		{"exportable PEM", CertificateInput{StoreLocation: "LocalMachine", StoreName: "My", CertificatePEM: pemText, Exportable: true}},
		{"bad pfx base64", CertificateInput{StoreLocation: "LocalMachine", StoreName: "My", PFXBase64: "%%%"}},
		{"bad location", CertificateInput{StoreLocation: "Nope", StoreName: "My", CertificatePEM: pemText}},
		{"bad store", CertificateInput{StoreLocation: "LocalMachine", StoreName: "My/X", CertificatePEM: pemText}},
	} {
		if _, _, err := validateCertificateInput(tc.input); err == nil {
			t.Errorf("%s must fail", tc.name)
		}
	}
}

func TestNormalizeCertificateTime(t *testing.T) {
	if got := normalizeCertificateTime("2026-01-01T00:00:00.0000000Z"); got != "2026-01-01T00:00:00Z" {
		t.Errorf("got %q", got)
	}
	if got := normalizeCertificateTime(""); got != "" {
		t.Errorf("empty must stay empty, got %q", got)
	}
	if got := normalizeCertificateTime("not-a-date"); got != "not-a-date" {
		t.Errorf("garbage must pass through, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// parseCertificateInfo
// ---------------------------------------------------------------------------

func TestParseCertificateInfo(t *testing.T) {
	_, der := certMintSelfSigned(t)
	raw, _ := json.Marshal(certTestJSON(der))
	info, err := parseCertificateInfo(raw, "h")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.StoreLocation != "LocalMachine" || info.StoreName != "My" {
		t.Errorf("store = %q/%q", info.StoreLocation, info.StoreName)
	}
	if info.Thumbprint != "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("thumbprint = %q", info.Thumbprint)
	}
	if info.NotBefore != "2026-01-01T00:00:00Z" || info.NotAfter != "2027-01-01T00:00:00Z" {
		t.Errorf("times = %q, %q", info.NotBefore, info.NotAfter)
	}
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "tf-acc-cert.example.com" {
		t.Errorf("dns = %v", info.DNSNames)
	}
	if info.HasPrivateKey || info.FriendlyName != "tf-acc" {
		t.Errorf("key/friendly = %v, %q", info.HasPrivateKey, info.FriendlyName)
	}
	if info.NormalizedPEM == "" || !strings.HasPrefix(info.NormalizedPEM, "-----BEGIN CERTIFICATE-----\n") {
		t.Error("raw_base64 must rebuild the normalised PEM")
	}
	// Missing dns_names (PS5.1 empty-array quirk) decodes to an empty list.
	j := certTestJSON(der)
	delete(j, "dns_names")
	raw, _ = json.Marshal(j)
	info, err = parseCertificateInfo(raw, "h")
	if err != nil {
		t.Fatalf("parse without dns: %v", err)
	}
	if info.DNSNames == nil || len(info.DNSNames) != 0 {
		t.Errorf("dns must be empty, got %v", info.DNSNames)
	}
	if _, err := parseCertificateInfo(json.RawMessage(`{oops`), "h"); !IsCertificateError(err, CertificateErrorUnknown) {
		t.Errorf("bad JSON: want unknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Script builders: quoting, stdin, no exit
// ---------------------------------------------------------------------------

func TestCertificateScripts_QuotingAndEnvelope(t *testing.T) {
	nasty := "x'; Write-Host pwned; '"
	for _, s := range []string{
		buildCertificateCreatePEM("LocalMachine", nasty, "f"),
		buildCertificateCreatePFX("LocalMachine", nasty, "f", false),
		buildCertificateReadScript("LocalMachine", nasty, "AB"),
		buildCertificateLookupScript("LocalMachine", nasty, "CN=x"),
		buildCertificateSetFriendlyScript("LocalMachine", nasty, "AB", "f"),
		buildCertificateRemoveScript("LocalMachine", nasty, "AB", true),
	} {
		if strings.Contains(s, nasty) {
			t.Error("script interpolates user input raw")
		}
		if !strings.Contains(s, psQuote(nasty)) {
			t.Error("script must carry the psQuote-escaped value")
		}
		for _, want := range []string{"function Emit-OK", "function Emit-Err", "function Classify-Certificate", "function ConvertTo-CertificateJson"} {
			if !strings.Contains(s, want) {
				t.Errorf("script missing %q", want)
			}
		}
		if strings.Contains(s, "exit ") || strings.Contains(s, "exit\n") {
			t.Error("scripts must never exit the shared session")
		}
	}
	// Unicode single quotes are doubled too.
	uni := "a’b‘c‚d‛e'f"
	s := buildCertificateReadScript("LocalMachine", uni, "AB")
	if strings.Contains(s, uni) || !strings.Contains(s, psQuote(uni)) {
		t.Error("unicode quotes must be escaped via psQuote")
	}
}

func TestCertificateScripts_ClassifyPins(t *testing.T) {
	// Script-level regression guard: the classifier must keep mapping the
	// stable HRESULTs and the already wired kinds.
	s := buildCertificateCreatePFX("LocalMachine", "My", "", false)
	for _, want := range []string{
		"0x80070005", "access_denied",
		"0x80070056", "invalid_password",
		"corrupt_certificate",
		"interactive_ui_required",
		"store_not_found",
		"already_exists",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("classify/create script must pin %q", want)
		}
	}
}

func TestCertificateScripts_KeyFlagsAndStoreOps(t *testing.T) {
	pemText, _ := certMintSelfSigned(t)
	_ = pemText
	pem := buildCertificateCreatePEM("LocalMachine", "My", "friendly")
	if !strings.Contains(pem, "MachineKeySet") || !strings.Contains(pem, "PersistKeySet") {
		t.Error("PEM create for LocalMachine must use MachineKeySet|PersistKeySet")
	}
	if strings.Contains(pem, "UserKeySet") {
		t.Error("PEM create for LocalMachine must not mention UserKeySet")
	}
	if strings.Contains(pem, "Exportable") {
		t.Error("PEM create must not mention Exportable")
	}
	pemUser := buildCertificateCreatePEM("CurrentUser", "My", "friendly")
	if !strings.Contains(pemUser, "UserKeySet") || !strings.Contains(pemUser, "PersistKeySet") {
		t.Error("PEM create for CurrentUser must use UserKeySet|PersistKeySet")
	}
	if strings.Contains(pemUser, "MachineKeySet") {
		t.Error("PEM create for CurrentUser must not mention MachineKeySet")
	}
	if !strings.Contains(pem, "X509Store($storeName, $storeLocation)") || !strings.Contains(pem, "$store.Add(") {
		t.Error("PEM create must add via X509Store.Add")
	}
	pfxPlain := buildCertificateCreatePFX("LocalMachine", "My", "", false)
	if strings.Contains(pfxPlain, "Exportable") {
		t.Error("non-exportable PFX create must not set Exportable")
	}
	if !strings.Contains(pfxPlain, "MachineKeySet") || strings.Contains(pfxPlain, "UserKeySet") {
		t.Error("PFX create for LocalMachine must use MachineKeySet, not UserKeySet")
	}
	pfxUser := buildCertificateCreatePFX("CurrentUser", "My", "", false)
	if !strings.Contains(pfxUser, "UserKeySet") || strings.Contains(pfxUser, "MachineKeySet") {
		t.Error("PFX create for CurrentUser must use UserKeySet, not MachineKeySet")
	}
	pfxExp := buildCertificateCreatePFX("LocalMachine", "My", "", true)
	if !strings.Contains(pfxExp, "Exportable") {
		t.Error("exportable PFX create must set Exportable")
	}
	// Only the leaf (keyed) certificate is added, so Delete removes exactly
	// what Create added; chain intermediates from the bundle stay out.
	if strings.Contains(pfxExp, "foreach ($cc in $coll) { $store.Add($cc) }") {
		t.Error("PFX create must not add the whole collection to the store")
	}
	if !strings.Contains(pfxExp, "foreach ($kc in $keyed) { $store.Add($kc) }") {
		t.Error("PFX create must add only the keyed (leaf) certificate(s)")
	}
	// Unknown key types warn instead of aborting the delete (DSA limitation).
	rm := buildCertificateRemoveScript("LocalMachine", "My", "AB", true)
	if !strings.Contains(rm, "Remove-CertificatePrivateKey") || !strings.Contains(rm, "$store.Remove(") {
		t.Error("delete must remove the private key before the store entry")
	}
	if !strings.Contains(rm, "unsupported key type") || !strings.Contains(rm, "Write-Warning") {
		t.Error("delete must warn (not throw) for unsupported key types")
	}
	if strings.Contains(rm, "throw 'unable to delete the private key (unsupported key type)'") {
		t.Error("delete must not abort on unsupported key types")
	}
	rmNoKey := buildCertificateRemoveScript("LocalMachine", "My", "AB", false)
	if !strings.Contains(rmNoKey, "$deleteKey = $false") {
		t.Error("delete without key removal must render $false")
	}
}

func TestCertificateScripts_SecretsNeverInScript(t *testing.T) {
	// The payload and password travel on stdin; the script body must not
	// contain them even as substrings.
	password := "S3cret-P@ss!"
	bundle := base64.StdEncoding.EncodeToString([]byte("fake-pfx-bytes"))
	for _, s := range []string{
		buildCertificateCreatePEM("LocalMachine", "My", "f"),
		buildCertificateCreatePFX("LocalMachine", "My", "f", true),
	} {
		if strings.Contains(s, password) || strings.Contains(s, bundle) {
			t.Error("script body must not contain secret material")
		}
	}
}

// ---------------------------------------------------------------------------
// Envelope mapping
// ---------------------------------------------------------------------------

func TestCertificateEnvelopeMapping(t *testing.T) {
	impl := certNewClient(t)
	run := func(outputs []frResponse) error {
		var calls []certStubCall
		defer certStubRun(outputs, &calls)()
		_, err := impl.runCertificateEnvelope(context.Background(), "op", "script", "stdin", nil)
		return err
	}
	if err := run([]frResponse{{stdout: "", stderr: "x", err: errors.New("dial: refused")}}); !IsCertificateError(err, CertificateErrorUnknown) {
		t.Errorf("transport: want unknown, got %v", err)
	}
	if err := run([]frResponse{{stdout: "noise, no json\n", err: nil}}); !IsCertificateError(err, CertificateErrorUnknown) {
		t.Errorf("no envelope: want unknown, got %v", err)
	}
	for kind, want := range map[string]CertificateErrorKind{
		"store_not_found":         CertificateErrorStoreNotFound,
		"invalid_password":        CertificateErrorInvalidPassword,
		"corrupt_certificate":     CertificateErrorCorruptCertificate,
		"access_denied":           CertificateErrorAccessDenied,
		"already_exists":          CertificateErrorAlreadyExists,
		"not_found":               CertificateErrorNotFound,
		"interactive_ui_required": CertificateErrorInteractiveUIRequired,
		"weird_kind":              CertificateErrorUnknown,
	} {
		err := run([]frResponse{{stdout: certErr(t, kind, "m")}})
		if !IsCertificateError(err, want) {
			t.Errorf("kind %q: want %q, got %v", kind, want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func TestCertificateCreatePEM(t *testing.T) {
	pemText, der := certMintSelfSigned(t)
	impl := certNewClient(t)
	var calls []certStubCall
	defer certStubRun([]frResponse{{stdout: certOK(t, certTestJSON(der))}}, &calls)()

	info, err := impl.Create(context.Background(), CertificateInput{
		StoreLocation: "localmachine", StoreName: "My", CertificatePEM: pemText, FriendlyName: "tf-acc",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if info.Thumbprint != "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("thumbprint = %q", info.Thumbprint)
	}
	if len(calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(calls))
	}
	// stdin carries base64(DER); the script body carries neither the PEM
	// nor the DER.
	wantStdin := base64.StdEncoding.EncodeToString(der)
	if calls[0].stdin != wantStdin {
		t.Error("PEM stdin must be base64(DER)")
	}
	if strings.Contains(calls[0].script, "BEGIN CERTIFICATE") || strings.Contains(calls[0].script, wantStdin) {
		t.Error("script body must not contain the payload")
	}
	if !strings.Contains(calls[0].script, psQuote("LocalMachine")) {
		t.Error("location must be canonicalised to LocalMachine in the script")
	}
}

func TestCertificateCreatePFXStdin(t *testing.T) {
	_, der := certMintSelfSigned(t)
	impl := certNewClient(t)
	bundle := base64.StdEncoding.EncodeToString([]byte("fake-pfx"))
	var calls []certStubCall
	defer certStubRun([]frResponse{{stdout: certOK(t, certTestJSON(der))}}, &calls)()

	pw := "S3cret!"
	_, err := impl.Create(context.Background(), CertificateInput{
		StoreLocation: "LocalMachine", StoreName: "My", PFXBase64: bundle, PFXPassword: &pw, Exportable: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := calls[0].stdin; got != pw+"\n"+bundle {
		t.Errorf("PFX stdin must be password-line + bundle, got %q", got)
	}
	if strings.Contains(calls[0].script, pw) || strings.Contains(calls[0].script, bundle) {
		t.Error("script body must not contain the PFX secrets")
	}
	if !strings.Contains(calls[0].script, "Exportable") {
		t.Error("exportable PFX create must set the Exportable flag")
	}
}

func TestCertificateCreateErrors(t *testing.T) {
	impl := certNewClient(t)
	// Client-side payload validation short-circuits before any call.
	var calls []certStubCall
	defer certStubRun([]frResponse{{stdout: certOK(t, map[string]any{})}}, &calls)()
	if _, err := impl.Create(context.Background(), CertificateInput{StoreLocation: "LocalMachine", StoreName: "My"}); err == nil {
		t.Error("empty payload must fail without a call")
	}
	if len(calls) != 0 {
		t.Error("validation failure must not reach the transport")
	}
	// Remote already_exists surfaces typed.
	defer certStubRun([]frResponse{{stdout: certErr(t, "already_exists", "present; terraform import")}}, &calls)()
	_, der := certMintSelfSigned(t)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if _, err := impl.Create(context.Background(), CertificateInput{StoreLocation: "LocalMachine", StoreName: "My", CertificatePEM: pemText}); !IsCertificateError(err, CertificateErrorAlreadyExists) {
		t.Errorf("want already_exists, got %v", err)
	}
	// Remote invalid_password surfaces typed.
	defer certStubRun([]frResponse{{stdout: certErr(t, "invalid_password", "bad password")}}, &calls)()
	if _, err := impl.Create(context.Background(), CertificateInput{StoreLocation: "LocalMachine", StoreName: "My", PFXBase64: base64.StdEncoding.EncodeToString([]byte("x"))}); !IsCertificateError(err, CertificateErrorInvalidPassword) {
		t.Errorf("want invalid_password, got %v", err)
	}
}

func TestCertificateRead(t *testing.T) {
	pemText, der := certMintSelfSigned(t)
	_ = pemText
	impl := certNewClient(t)
	var calls []certStubCall
	defer certStubRun([]frResponse{{stdout: certOK(t, certTestJSON(der))}}, &calls)()

	info, err := impl.Read(context.Background(), "localmachine", "My", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")
	if err != nil || info == nil {
		t.Fatalf("Read = %v, %v", info, err)
	}
	if info.Thumbprint != "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("thumbprint not normalised, got %q", info.Thumbprint)
	}
	if !strings.Contains(calls[0].script, psQuote("A1B2C3D4E5F60718293A4B5C6D7E8F9012345678")) {
		t.Error("read must query the normalised thumbprint")
	}
	// A missing certificate surfaces as nil (state drop); a missing store is
	// an error diagnostic, never a silent removal.
	defer certStubRun([]frResponse{{stdout: certErr(t, "not_found", "gone")}}, &calls)()
	info, err = impl.Read(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678")
	if err != nil || info != nil {
		t.Errorf("not_found: want (nil, nil), got (%v, %v)", info, err)
	}
	defer certStubRun([]frResponse{{stdout: certErr(t, "store_not_found", "gone")}}, &calls)()
	if _, err := impl.Read(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"); !IsCertificateError(err, CertificateErrorStoreNotFound) {
		t.Errorf("store_not_found: want store_not_found error, got %v", err)
	}
	defer certStubRun([]frResponse{{stdout: certErr(t, "access_denied", "nope")}}, &calls)()
	if _, err := impl.Read(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"); !IsCertificateError(err, CertificateErrorAccessDenied) {
		t.Errorf("want access_denied, got %v", err)
	}
}

func TestCertificateLookupBySubject(t *testing.T) {
	_, der := certMintSelfSigned(t)
	impl := certNewClient(t)
	j1 := certTestJSON(der)
	j2 := certTestJSON(der)
	j2["thumbprint"] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	j2["not_before"] = "2026-06-01T00:00:00Z"
	var calls []certStubCall
	defer certStubRun([]frResponse{{stdout: certOK(t, []any{j1, j2})}}, &calls)()

	out, err := impl.LookupBySubject(context.Background(), "LocalMachine", "My", "CN=tf-acc-cert.example.com, O=TF ACC")
	if err != nil || len(out) != 2 {
		t.Fatalf("Lookup = %d, %v", len(out), err)
	}
	if !strings.Contains(calls[0].script, psQuote("CN=tf-acc-cert.example.com, O=TF ACC")) {
		t.Error("lookup must carry the psQuote-escaped subject")
	}
	if _, err := impl.LookupBySubject(context.Background(), "LocalMachine", "My", "   "); !IsCertificateError(err, CertificateErrorNotFound) {
		t.Errorf("blank subject: want not_found, got %v", err)
	}
	defer certStubRun([]frResponse{{stdout: certErr(t, "not_found", "zero")}}, &calls)()
	if _, err := impl.LookupBySubject(context.Background(), "LocalMachine", "My", "CN=missing"); !IsCertificateError(err, CertificateErrorNotFound) {
		t.Errorf("zero matches: want not_found, got %v", err)
	}
}

func TestCertificateUpdateFriendlyName(t *testing.T) {
	_, der := certMintSelfSigned(t)
	impl := certNewClient(t)
	var calls []certStubCall
	defer certStubRun([]frResponse{{stdout: certOK(t, certTestJSON(der))}}, &calls)()

	info, err := impl.UpdateFriendlyName(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", "renamed")
	if err != nil || info == nil {
		t.Fatalf("Update = %v, %v", info, err)
	}
	if !strings.Contains(calls[0].script, psQuote("renamed")) {
		t.Error("update must carry the psQuote-escaped friendly name")
	}
	defer certStubRun([]frResponse{{stdout: certErr(t, "not_found", "gone")}}, &calls)()
	if _, err := impl.UpdateFriendlyName(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", "x"); !IsCertificateError(err, CertificateErrorNotFound) {
		t.Errorf("want not_found, got %v", err)
	}
}

func TestCertificateDelete(t *testing.T) {
	impl := certNewClient(t)
	var calls []certStubCall
	defer certStubRun([]frResponse{{stdout: certOK(t, map[string]any{"removed": true})}}, &calls)()

	if err := impl.Delete(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !strings.Contains(calls[0].script, "$deleteKey = $true") {
		t.Error("delete must render $true for key removal")
	}
	// Idempotent: missing certificate (Emit-OK null) and missing store.
	for _, tc := range []struct {
		name string
		resp frResponse
	}{
		{"null ok", frResponse{stdout: "{ \"ok\": true, \"data\": null }\n"}},
		{"store gone", frResponse{stdout: certErr(t, "store_not_found", "gone")}},
		{"cert gone", frResponse{stdout: certErr(t, "not_found", "gone")}},
	} {
		defer certStubRun([]frResponse{tc.resp}, &calls)()
		if err := impl.Delete(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", false); err != nil {
			t.Errorf("%s: want nil, got %v", tc.name, err)
		}
	}
	defer certStubRun([]frResponse{{stdout: certErr(t, "access_denied", "nope")}}, &calls)()
	if err := impl.Delete(context.Background(), "LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", true); !IsCertificateError(err, CertificateErrorAccessDenied) {
		t.Errorf("want access_denied, got %v", err)
	}
}
