// Package winclient — unit tests for IISBindingClient (issue #285).
//
// These tests stub the package-level runPowerShell seam (shared with
// service.go) and the iisBindingManagementPath probe seam so no real SSH
// connection is needed.
//
// Coverage targets:
//   - Scripts: Ensure-IIS gate, literal Where-Object lookups (never
//     Get-WebBinding -Name with raw user input), site pre-check,
//     already_exists import hint, conflict naming the other site,
//     certificate and private-key pre-checks, SslBindings clash scan,
//     New-WebBinding -SslFlags, AddSslCertificate with binding rollback,
//     auto-start, Update remove plus re-add with old-binding restore,
//     Delete certificate-then-binding idempotency
//   - SSH-port guard: provider port refusal, ServerPort refusal,
//     fail-closed probe failure, non-SSH ports pass
//   - Retry: file-has-changed-on-disk retried; other errors not retried
//   - parseIISBindingState: null, happy path, bad JSON
//   - CRUD happy paths plus validation short-circuit
package winclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// iisBindingNewClient returns an *IISBindingClient for tests.
func iisBindingNewClient(t *testing.T) *IISBindingClient {
	t.Helper()
	c, err := New(Config{Host: "winiis01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewIISBindingClient(c)
}

// iisBindingOK returns a JSON ok-envelope whose data field is the supplied value.
func iisBindingOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("iisBindingOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// iisBindingErr returns a JSON error-envelope for the given kind/message.
func iisBindingErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("iisBindingErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// testIISBindingState is a minimal valid https binding JSON payload.
func testIISBindingState() map[string]any {
	return map[string]any{
		"protocol": "https", "binding_information": "*:443:example.com",
		"ip_address": "*", "port": 443, "host_header": "example.com",
		"ssl_flags": 1, "require_sni": true,
		"certificate_thumbprint": strings.Repeat("A", 40),
		"certificate_store_name": "My",
	}
}

// iisBindingStubSequence stubs runPowerShell with a fixed ordered list of responses.
func iisBindingStubSequence(responses []frResponse) func() {
	i := 0
	return stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		r := responses[i]
		if i < len(responses)-1 {
			i++
		}
		return r.stdout, r.stderr, r.err
	})
}

// stubIISBindingManagementPath stubs the management-path probe with a fixed
// ServerPort.
func stubIISBindingManagementPath(serverPort int) func() {
	prev := iisBindingManagementPath
	iisBindingManagementPath = func(_ context.Context, _ *Client) (*ManagementPath, error) {
		return &ManagementPath{ServerPort: serverPort, Source: "ssh_connection"}, nil
	}
	return func() { iisBindingManagementPath = prev }
}

func iisBindingCreateInput() IISBindingInput {
	sni := true
	thumb := strings.Repeat("A", 40)
	return IISBindingInput{
		SiteName: "web", Protocol: "https", IPAddress: "*",
		Port: 443, HostHeader: "Example.COM", RequireSNI: &sni,
		CertificateThumbprint: &thumb, CertificateStoreName: "My",
	}
}

// ---------------------------------------------------------------------------
// Script content: gate, literal lookups, guards, cert/SNI flow
// ---------------------------------------------------------------------------

func TestIISBindingScripts_ShipPreludeAndGate(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	if _, err := c.Create(context.Background(), iisBindingCreateInput()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'",
		"function Ensure-IIS",
		"if (-not (Ensure-IIS)) { return }",
		"function Classify-IIS",
		"function Get-BindingData",
		"function Escape-BindingWildcard",
		"$siteNames -contains $Name", // literal site check (no -Name wildcard lookup)
		"Where-Object { $_.site -eq $Name",
		"Where-Object { $_.protocol -eq $Protocol -and $_.bindingInformation -eq $BindingInfo }",
		"$Name = 'web'",
		"Get-WebBinding -Name $escSn",
		"Get-ChildItem 'IIS:\\SslBindings'",
		"Get-ChildItem $certPath",
		"HasPrivateKey",
		"New-WebBinding",
		"-SslFlags $SslFlags",
		"AddSslCertificate($Thumb, $Store)",
		"Remove-WebBinding",
		"Start-Website",
		"serverAutoStart",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("create script missing %q", want)
		}
	}
	for _, absent := range []string{
		"Get-Website -Name",
		"Get-WebBinding -Name $Name",
		"Get-WebBinding -Name $Protocol",
	} {
		if strings.Contains(gotScript, absent) {
			t.Errorf("create script must not pass raw variables to -Name (wildcard expansion), found %q", absent)
		}
	}
}

func TestIISBindingCreate_ScriptDecisions(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	if _, err := c.Create(context.Background(), iisBindingCreateInput()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"'site_not_found'",
		"'already_exists'",
		"terraform import",
		"'conflict'",
		"conflicting_site",
		"one listener cannot serve two sites",
		"'certificate_not_found'",
		"windows_certificate",
		"'certificate_no_private_key'",
		"'ssl_binding_conflict'",
		"$Thumb = '" + strings.Repeat("A", 40) + "'",
		"$WantedHost = 'example.com'", // host lower-cased in the script vars
		"$BindingInfo = '*:443:example.com'",
		"$SslFlags = 1",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("create script missing %q", want)
		}
	}
}

func TestIISBindingCreate_HTTPOmitsCertFlow(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisBindingOK(t, map[string]any{
			"protocol": "http", "binding_information": "*:80:",
			"ip_address": "*", "port": 80, "host_header": "",
			"ssl_flags": 0, "require_sni": false,
			"certificate_thumbprint": "", "certificate_store_name": "",
		}), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	got, err := c.Create(context.Background(), IISBindingInput{
		SiteName: "web", Protocol: "http", IPAddress: "*", Port: 80,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "$SslFlags = 0") {
		t.Errorf("http create must set SslFlags 0, got:\n%s", gotScript)
	}
	if !strings.Contains(gotScript, "$Thumb = ''") {
		t.Errorf("http create without a certificate must pass an empty thumbprint, got:\n%s", gotScript)
	}
	if got.RequireSNI {
		t.Error("http binding must not report require_sni")
	}
	if got.CertificateThumbprint != "" {
		t.Errorf("http binding must not report a thumbprint, got %q", got.CertificateThumbprint)
	}
}

func TestIISBindingUpdate_ScriptContent(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	if _, err := c.Update(context.Background(), iisBindingCreateInput()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"'site_not_found'",
		"'not_found'",
		"Remove-WebBinding",
		"New-WebBinding",
		"AddSslCertificate",
		"$OldFlags", "$OldThumb", "$OldStore", // failed re-add restores the old binding
		"$restored.AddSslCertificate", // old certificate re-bound on restore
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("update script missing %q", want)
		}
	}
	// No SSH-port guard on the update path: the port is ForceNew and never
	// changes in place.
	if strings.Contains(gotScript, "would_lock_out") {
		t.Error("update script must not carry the SSH-port guard (port is ForceNew)")
	}
}

func TestIISBindingDelete_ScriptContent(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisBindingOK(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	if err := c.Delete(context.Background(), "web", "https", "*:443:example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"RemoveSslCertificate", // certificate removed before the binding
		"Remove-WebBinding",
		"already_absent",
		"Escape-BindingWildcard $Name",
		"Where-Object { $_.protocol -eq $Protocol -and $_.bindingInformation -eq $BindingInfo }",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
}

func TestIISBindingRead_ScriptContent(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	got, err := c.Read(context.Background(), "web", "HTTPS", "*:443:Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"$Protocol = 'https'",
		"$BindingInfo = '*:443:example.com'", // canonicalised before quoting
		"Get-BindingData $Name $Protocol $BindingInfo",
		"Where-Object { $_.Name -eq $Name }", // literal site lookup, never Get-Website -Name
		"Emit-OK $null",                      // missing site reads as absent
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("read script missing %q", want)
		}
	}
	if got == nil || got.BindingInformation != "*:443:example.com" {
		t.Fatalf("read must return the exact binding, got %+v", got)
	}
	if !got.RequireSNI || got.SslFlags != 1 {
		t.Errorf("read must project SNI from ssl_flags, got %+v", got)
	}
	if got.CertificateThumbprint != strings.Repeat("A", 40) {
		t.Errorf("read must project the thumbprint, got %q", got.CertificateThumbprint)
	}
}

// ---------------------------------------------------------------------------
// SSH-port guard
// ---------------------------------------------------------------------------

func TestIISBindingCreate_LockoutOnProviderPort(t *testing.T) {
	c := iisBindingNewClient(t) // cfg port defaults to 22
	in := IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 22}
	_, err := c.Create(context.Background(), in)
	if !IsIISBindingError(err, IISBindingErrorWouldLockOut) {
		t.Fatalf("binding port 22 with provider port 22 must be would_lock_out, got %v", err)
	}
}

func TestIISBindingCreate_LockoutOnServerPort(t *testing.T) {
	defer stubIISBindingManagementPath(2222)()
	var called bool
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	in := IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 2222}
	_, err := c.Create(context.Background(), in)
	if !IsIISBindingError(err, IISBindingErrorWouldLockOut) {
		t.Fatalf("binding port 2222 with ServerPort 2222 must be would_lock_out, got %v", err)
	}
	if called {
		t.Error("lockout refusal must happen before any script runs")
	}
}

func TestIISBindingCreate_LockoutProbeFailureClosed(t *testing.T) {
	prev := iisBindingManagementPath
	iisBindingManagementPath = func(_ context.Context, _ *Client) (*ManagementPath, error) {
		return nil, NewManagementPathError(ManagementPathErrorUnknown, "no probe", nil, nil)
	}
	defer func() { iisBindingManagementPath = prev }()

	var called bool
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	in := IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 8080}
	_, err := c.Create(context.Background(), in)
	if !IsIISBindingError(err, IISBindingErrorWouldLockOut) {
		t.Fatalf("undeterminable management path must fail closed with would_lock_out, got %v", err)
	}
	if called {
		t.Error("fail-closed refusal must happen before any script runs")
	}
}

func TestIISBindingCreate_NonSSHPortPassesGuard(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	in := IISBindingInput{SiteName: "web", Protocol: "http", IPAddress: "*", Port: 8080}
	if _, err := c.Create(context.Background(), in); err != nil {
		t.Fatalf("port 8080 must pass the SSH-port guard, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Remote kinds, retry, parsing, validation short-circuit
// ---------------------------------------------------------------------------

func TestIISBindingCRUD_RemoteKinds(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	cases := []struct {
		kind string
		want IISBindingErrorKind
	}{
		{"site_not_found", IISBindingErrorSiteNotFound},
		{"already_exists", IISBindingErrorAlreadyExists},
		{"conflict", IISBindingErrorConflict},
		{"ssl_binding_conflict", IISBindingErrorSSLBindingConflict},
		{"certificate_not_found", IISBindingErrorCertificateNotFound},
		{"certificate_no_private_key", IISBindingErrorCertificateNoPrivateKey},
		{"iis_not_installed", IISBindingErrorIISNotInstalled},
		{"access_denied", IISBindingErrorAccessDenied},
	}
	for _, tc := range cases {
		restore := iisBindingStubSequence([]frResponse{
			{stdout: iisBindingErr(t, tc.kind, "nope"), stderr: "", err: nil},
		})
		c := iisBindingNewClient(t)
		_, err := c.Create(context.Background(), iisBindingCreateInput())
		restore()
		if !IsIISBindingError(err, tc.want) {
			t.Errorf("kind %q must map to %q, got %v", tc.kind, tc.want, err)
		}
	}
}

func TestIISBindingRead_NullMeansAbsent(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return iisBindingOK(t, nil), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	got, err := c.Read(context.Background(), "web", "https", "*:443:example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("null data must read as absent, got %+v", got)
	}
}

func TestIISBindingRead_BadJSON(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return iisBindingOK(t, "not-an-object"), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	if _, err := c.Read(context.Background(), "web", "https", "*:443:example.com"); !IsIISBindingError(err, IISBindingErrorUnknown) {
		t.Errorf("bad JSON must be unknown, got %v", err)
	}
}

func TestIISBindingCreate_RetryOnFlake(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	oldBackoff := iisRetryBackoff
	iisRetryBackoff = func(int) time.Duration { return 0 }
	defer func() { iisRetryBackoff = oldBackoff }()

	restore := iisBindingStubSequence([]frResponse{
		{stdout: iisBindingErr(t, "unknown", "Cannot commit configuration changes because the file has changed on disk"), stderr: "", err: nil},
		{stdout: iisBindingOK(t, testIISBindingState()), stderr: "", err: nil},
	})
	defer restore()

	c := iisBindingNewClient(t)
	if _, err := c.Create(context.Background(), iisBindingCreateInput()); err != nil {
		t.Fatalf("flake then success must succeed, got %v", err)
	}
}

func TestIISBindingCreate_NoRetryOnConflict(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return iisBindingErr(t, "conflict", "taken"), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	if _, err := c.Create(context.Background(), iisBindingCreateInput()); !IsIISBindingError(err, IISBindingErrorConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if calls != 1 {
		t.Errorf("non-flake errors must not be retried, got %d calls", calls)
	}
}

func TestIISBindingValidation_ShortCircuits(t *testing.T) {
	defer stubIISBindingManagementPath(22)()
	var called bool
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return iisBindingOK(t, testIISBindingState()), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	bad := IISBindingInput{SiteName: "a/b", Protocol: "http", IPAddress: "*", Port: 80}
	if _, err := c.Create(context.Background(), bad); !IsIISBindingError(err, IISBindingErrorUnknown) {
		t.Errorf("invalid input must fail validation, got %v", err)
	}
	if _, err := c.Update(context.Background(), bad); !IsIISBindingError(err, IISBindingErrorUnknown) {
		t.Errorf("invalid update input must fail validation, got %v", err)
	}
	if err := c.Delete(context.Background(), "a/b", "http", "*:80:"); err == nil {
		t.Error("invalid delete name must fail validation")
	}
	if called {
		t.Error("validation failures must not run any script")
	}
}

func TestIISBindingDelete_MissingIsAbsent(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return iisBindingOK(t, map[string]any{"deleted": true, "note": "already_absent"}), "", nil
	})
	defer restore()

	c := iisBindingNewClient(t)
	if err := c.Delete(context.Background(), "web", "https", "*:443:example.com"); err != nil {
		t.Fatalf("missing binding delete must succeed, got %v", err)
	}
}
