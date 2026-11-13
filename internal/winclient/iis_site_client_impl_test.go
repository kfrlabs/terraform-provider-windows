// Package winclient — unit tests for IISSiteClient (issue #284).
//
// These tests stub the package-level runPowerShell seam (shared with
// service.go / local_user.go) so no real SSH connection is needed.
//
// Coverage targets:
//   - IISSiteError: Error(), Unwrap(), Is(), sentinels
//   - mapIISSiteKind: all known kinds + unknown
//   - ValidateIISSiteName / ValidateIISSiteID
//   - buildIISSiteSetStatements: only-configured-attrs emission, psQuote,
//     TimeSpan seconds, dotted provider property names
//   - buildIISSiteStateStatement: nil silence, Started guard on binding
//     count, Stopped plain stop
//   - Scripts: Ensure-IIS gate, literal Where-Object lookups (never
//     Get-Website -Name), zero-binding New-Item -Bindings @(), pool/path
//     pre-checks, id_conflict guard, import hint, partial-failure cleanup
//   - Retry: file-has-changed-on-disk retried 3x; create flake then
//     already_exists returns the original flake; other errors not retried
//   - parseIISSiteState: null, happy path (incl. bindings view), bad JSON
//   - CRUD happy paths + validation short-circuit
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

// iisSiteNewClient returns an *IISSiteClient for tests.
func iisSiteNewClient(t *testing.T) *IISSiteClient {
	t.Helper()
	c, err := New(Config{Host: "winiis01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewIISSiteClient(c)
}

// iisSiteOK returns a JSON ok-envelope whose data field is the supplied value.
func iisSiteOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("iisSiteOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// iisSiteErr returns a JSON error-envelope for the given kind/message.
func iisSiteErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("iisSiteErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// testIISSiteState is a minimal valid site JSON payload.
func testIISSiteState() map[string]any {
	return map[string]any{
		"name": "web", "site_id": 2, "physical_path": `C:\inetpub\wwwroot`,
		"application_pool": "DefaultAppPool", "auto_start": true,
		"preload_enabled": false, "enabled_protocols": "http",
		"log_enabled": true, "log_directory": `%SystemDrive%\inetpub\logs\LogFiles`,
		"log_format": "W3C", "connection_timeout_seconds": 120,
		"max_connections": 0, "bindings": []any{}, "state": "Started",
	}
}

// testIISSiteStateBound is testIISSiteState with one http binding.
func testIISSiteStateBound() map[string]any {
	m := testIISSiteState()
	m["bindings"] = []any{map[string]any{"protocol": "http", "binding_information": "*:80:web"}}
	return m
}

// iisSiteStubSequence stubs runPowerShell with a fixed ordered list of responses.
func iisSiteStubSequence(responses []frResponse) func() {
	i := 0
	return stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		r := responses[i]
		if i < len(responses)-1 {
			i++
		}
		return r.stdout, r.stderr, r.err
	})
}

// ---------------------------------------------------------------------------
// IISSiteError
// ---------------------------------------------------------------------------

func TestIISSiteError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewIISSiteError(IISSiteErrorAccessDenied, "denied", cause, map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewIISSiteError(IISSiteErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestIISSiteError_Is(t *testing.T) {
	e := NewIISSiteError(IISSiteErrorIDConflict, "x", nil, nil)
	if !errors.Is(e, ErrIISSiteIDConflict) {
		t.Error("errors.Is(ErrIISSiteIDConflict) should match by kind")
	}
	if errors.Is(e, ErrIISSiteNotFound) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsIISSiteError(e, IISSiteErrorIDConflict) {
		t.Error("IsIISSiteError should match")
	}
	if IsIISSiteError(errors.New("plain"), IISSiteErrorIDConflict) {
		t.Error("IsIISSiteError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-IISSiteError should be false")
	}
}

func TestMapIISSiteKind(t *testing.T) {
	cases := map[string]IISSiteErrorKind{
		"not_found":          IISSiteErrorNotFound,
		"already_exists":     IISSiteErrorAlreadyExists,
		"id_conflict":        IISSiteErrorIDConflict,
		"app_pool_not_found": IISSiteErrorAppPoolNotFound,
		"path_not_found":     IISSiteErrorPathNotFound,
		"iis_not_installed":  IISSiteErrorIISNotInstalled,
		"access_denied":      IISSiteErrorAccessDenied,
		"":                   IISSiteErrorUnknown,
		"weird_kind":         IISSiteErrorUnknown,
	}
	for in, want := range cases {
		if got := mapIISSiteKind(in, "some message"); got != want {
			t.Errorf("mapIISSiteKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestValidateIISSiteName(t *testing.T) {
	for _, ok := range []string{"web", "Default Web Site", "a", "site-1_name.test", "x'y", strings.Repeat("a", 64)} {
		if err := ValidateIISSiteName(ok); err != nil {
			t.Errorf("name %q should be valid, got %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", strings.Repeat("a", 65),
		" leading", "trailing ", " ",
		"a/b", `a\b`, "a[b", "a]b", "a:b", "a;b", "a,b", "a?b", "a*b",
		`a"b`, "a<b", "a>b", "a|b",
	} {
		if err := ValidateIISSiteName(bad); err == nil {
			t.Errorf("name %q should be rejected", bad)
		}
	}
}

func TestValidateIISSiteID(t *testing.T) {
	for _, ok := range []int64{1, 2, 4294967295} {
		if err := ValidateIISSiteID(ok); err != nil {
			t.Errorf("id %d should be valid, got %v", ok, err)
		}
	}
	for _, bad := range []int64{0, -1, 4294967296} {
		if err := ValidateIISSiteID(bad); err == nil {
			t.Errorf("id %d should be rejected", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Set-statement builder: only configured attributes are emitted
// ---------------------------------------------------------------------------

func TestBuildIISSiteSetStatements_OnlyConfigured(t *testing.T) {
	script := buildIISSiteSetStatements(IISSiteSettings{})
	if strings.Contains(script, "Set-ItemProperty") || strings.Contains(script, "Set-WebConfigurationProperty") {
		t.Errorf("empty settings must emit no writes, got:\n%s", script)
	}

	pool := "DefaultAppPool"
	script = buildIISSiteSetStatements(IISSiteSettings{ApplicationPool: &pool})
	for _, want := range []string{
		"applicationPool", "$AppPool", "$appFilter",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q, got:\n%s", want, script)
		}
	}
	for _, absent := range []string{
		"physicalPath", "enabledProtocols", "preloadEnabled",
		"serverAutoStart", "logFile.enabled", "limits.connectionTimeout",
	} {
		if strings.Contains(script, absent) {
			t.Errorf("script must not emit unconfigured attribute %q, got:\n%s", absent, script)
		}
	}
}

func TestBuildIISSiteSetStatements_AllAttrs(t *testing.T) {
	path := `C:\inetpub\wwwroot`
	pool := "pool1"
	auto := true
	preload := true
	protos := "http"
	logOn := true
	logDir := `%SystemDrive%\inetpub\logs\LogFiles`
	logFormat := "W3C"
	timeout := int64(120)
	maxConn := int64(100)
	script := buildIISSiteSetStatements(IISSiteSettings{
		PhysicalPath: &path, ApplicationPool: &pool, AutoStart: &auto,
		PreloadEnabled: &preload, EnabledProtocols: &protos, LogEnabled: &logOn,
		LogDirectory: &logDir, LogFormat: &logFormat,
		ConnectionTimeoutSeconds: &timeout, MaxConnections: &maxConn,
	})
	for _, want := range []string{
		"physicalPath", "$vdirFilter", "$PhysicalPath",
		"applicationPool", "$AppPool",
		"enabledProtocols", "'http'",
		"preloadEnabled", "$true",
		"serverAutoStart",
		"logFile.enabled", "logFile.directory", "logFile.logFormat", "'W3C'",
		"limits.connectionTimeout", "New-TimeSpan -Seconds 120",
		"limits.maxConnections", "100",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q, got:\n%s", want, script)
		}
	}
	// User values travel psQuote'd; the pool/path lines reference the
	// script variables (quoted once at assignment), never raw text.
	if strings.Contains(script, "C:\\inetpub") && !strings.Contains(script, "$PhysicalPath") {
		t.Errorf("physical path must flow through the $PhysicalPath variable, got:\n%s", script)
	}
}

func TestBuildIISSiteSetStatements_UserValueQuoting(t *testing.T) {
	evil := "x'; Write-Host pwned; '"
	script := buildIISSiteSetStatements(IISSiteSettings{EnabledProtocols: &evil})
	if strings.Contains(script, evil) {
		t.Errorf("user value must be quoted, got:\n%s", script)
	}
	if !strings.Contains(script, psQuote(evil)) {
		t.Errorf("user value must appear psQuote'd, got:\n%s", script)
	}
}

func TestBuildIISSiteStateStatement(t *testing.T) {
	if got := buildIISSiteStateStatement(nil, "'web'"); got != "" {
		t.Errorf("nil state must emit nothing, got:\n%s", got)
	}
	started := "Started"
	got := buildIISSiteStateStatement(&started, "'web'")
	for _, want := range []string{
		"Start-Website", "Where-Object { $_.Name -eq $Name }",
		"Bindings", // zero-binding guard: skip the start when unbound
	} {
		if !strings.Contains(got, want) {
			t.Errorf("started statement missing %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Stop-Website") {
		t.Errorf("started statement must not stop, got:\n%s", got)
	}
	stopped := "Stopped"
	got = buildIISSiteStateStatement(&stopped, "'web'")
	if !strings.Contains(got, "Stop-Website") || strings.Contains(got, "Start-Website") {
		t.Errorf("stopped statement must only stop, got:\n%s", got)
	}
}

// ---------------------------------------------------------------------------
// Script content: gate, literal lookups, zero-binding create, guards
// ---------------------------------------------------------------------------

// TestIISSiteScripts_XPathNameQuoting guards the XPath site-name filter
// for names containing an apostrophe (allowed by ValidateIISSiteName
// while " is forbidden): the filter must use a double-quoted XPath
// literal, never single-quote doubling (invalid in XPath 1.0).
func TestIISSiteScripts_XPathNameQuoting(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisSiteOK(t, testIISSiteState()), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	if _, err := c.Read(context.Background(), "x'y"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		`site[@name="`,
		`'"]/application[@path=''/']'`,
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("read script must build the XPath filter with a double-quoted literal, missing %q", want)
		}
	}
	for _, absent := range []string{
		`site[@name='`,
		`$xName`,
		`-replace "'", "''"`,
	} {
		if strings.Contains(gotScript, absent) {
			t.Errorf("read script must not use single-quote doubling for the XPath filter, found %q", absent)
		}
	}
	if !strings.Contains(iisSitePreamble(), `site[@name="`) {
		t.Error("iisSitePreamble must build the XPath filter with a double-quoted literal")
	}
	if strings.Contains(iisSitePreamble(), `$xName`) {
		t.Error("iisSitePreamble must not use single-quote doubling for the XPath filter")
	}
}

func TestIISSiteScripts_ShipPreludeAndGate(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisSiteOK(t, testIISSiteState()), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	if _, err := c.Read(context.Background(), "web"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'",
		"function Ensure-IIS",
		"if (-not (Ensure-IIS)) { return }",
		"function Classify-IIS",
		"function Get-SiteData",
		"function Classify-Site",
		"Where-Object { $_.Name -eq $Name }",
		"$Name = 'web'",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("read script missing %q", want)
		}
	}
	if strings.Contains(gotScript, "Get-Website -Name") {
		t.Error("lookups must never use Get-Website -Name (wildcard expansion)")
	}
}

func TestIISSiteCreate_ScriptContent(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisSiteOK(t, testIISSiteState()), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	siteID := int64(7)
	pool := "DefaultAppPool"
	path := `C:\inetpub\wwwroot`
	started := "Started"
	if _, err := c.Create(context.Background(), IISSiteInput{
		Name: "web",
		Settings: IISSiteSettings{
			SiteID: &siteID, PhysicalPath: &path, ApplicationPool: &pool, State: &started,
		},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"New-Item", "bindings = @()", // zero-binding create: no transient *:80:http
		"already_exists", "terraform import",
		"id_conflict",                // site-ID precheck
		"app_pool_not_found",         // pool precheck
		"path_not_found",             // path precheck
		"Test-Path -LiteralPath",     // literal existence check, never mkdir
		"ExpandEnvironmentVariables", // %SystemDrive% expands host-side
		"Get-ChildItem 'IIS:\\AppPools'",
		"Remove-Website", // best-effort cleanup on partial failure
		"$PhysicalPath = 'C:\\inetpub\\wwwroot'",
		"$AppPool = 'DefaultAppPool'",
		"Start-Website", // configured Started...
		"$bindCount",    // ...guarded by the live binding count
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("create script missing %q", want)
		}
	}
	if strings.Contains(gotScript, "Get-Website -Name") {
		t.Error("lookups must never use Get-Website -Name (wildcard expansion)")
	}
}

func TestIISSiteCreate_UnmanagedPoolAndPathAreNull(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisSiteOK(t, testIISSiteState()), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	path := `C:\inetpub\wwwroot`
	if _, err := c.Create(context.Background(), IISSiteInput{
		Name:     "web",
		Settings: IISSiteSettings{PhysicalPath: &path},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "$AppPool = $null") {
		t.Error("unmanaged application_pool must assign $null (guard skips the check)")
	}
	if !strings.Contains(gotScript, "$SiteId = $null") {
		t.Error("unmanaged site_id must assign $null (IIS allocates the lowest free ID)")
	}
	if strings.Contains(gotScript, "applicationPool' -Value") {
		t.Error("unmanaged application_pool must emit no write")
	}
}

func TestIISSiteUpdate_ScriptContent(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisSiteOK(t, testIISSiteState()), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	pool := "pool2"
	path := `C:\srv\web`
	if _, err := c.Update(context.Background(), IISSiteInput{
		Name:     "web",
		Settings: IISSiteSettings{PhysicalPath: &path, ApplicationPool: &pool},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"'not_found'",
		"app_pool_not_found",
		"path_not_found",
		"Test-Path -LiteralPath",
		"Where-Object { $_.Name -eq $Name }",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("update script missing %q", want)
		}
	}
	if strings.Contains(gotScript, "New-Item") {
		t.Error("update must never create the site")
	}
	if strings.Contains(gotScript, "id_conflict") {
		t.Error("update must never re-check the site ID (ForceNew)")
	}
}

func TestIISSiteDelete_ScriptContent(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return iisSiteOK(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	if err := c.Delete(context.Background(), "web"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"Remove-Website",
		"already_absent",
		"Where-Object { $_.Name -eq $Name }",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
	if strings.Contains(gotScript, "Get-Website -Name") {
		t.Error("lookups must never use Get-Website -Name (wildcard expansion)")
	}
}

func TestIISSiteRead_MissingIsNil(t *testing.T) {
	restore := iisSiteStubSequence([]frResponse{{stdout: iisSiteOK(t, nil), stderr: "", err: nil}})
	defer restore()

	c := iisSiteNewClient(t)
	st, err := c.Read(context.Background(), "gone")
	if err != nil || st != nil {
		t.Errorf("missing site should be (nil, nil), got (%+v, %v)", st, err)
	}
}

func TestIISSiteValidation_ShortCircuits(t *testing.T) {
	called := false
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	if _, err := c.Read(context.Background(), "a/b"); err == nil {
		t.Error("invalid name must fail")
	}
	if _, err := c.Create(context.Background(), IISSiteInput{Name: ""}); err == nil {
		t.Error("empty name must fail")
	}
	badID := int64(0)
	if _, err := c.Create(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{SiteID: &badID},
	}); err == nil {
		t.Error("out-of-range site_id must fail")
	}
	if _, err := c.Update(context.Background(), IISSiteInput{Name: " trailing "}); err == nil {
		t.Error("padded name must fail")
	}
	siteID := int64(3)
	if _, err := c.Update(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{SiteID: &siteID},
	}); err == nil {
		t.Error("site_id on update must fail (ForceNew)")
	}
	if err := c.Delete(context.Background(), "a*b"); err == nil {
		t.Error("wildcard name must fail")
	}
	if called {
		t.Error("invalid site inputs must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// Retry: only the file-has-changed-on-disk flake retries
// ---------------------------------------------------------------------------

func TestIISSiteWrite_RetriesFlake(t *testing.T) {
	oldBackoff := iisRetryBackoff
	iisRetryBackoff = func(int) time.Duration { return 0 }
	defer func() { iisRetryBackoff = oldBackoff }()

	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return iisSiteErr(t, "unknown", "Cannot commit configuration changes because the file has changed on disk."), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	pool := "pool1"
	_, err := c.Update(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{ApplicationPool: &pool},
	})
	if !IsIISSiteError(err, IISSiteErrorUnknown) {
		t.Errorf("persistent flake must surface with its message, got %v", err)
	}
	if calls != 3 {
		t.Errorf("flake must be retried up to 3 attempts, got %d calls", calls)
	}
}

func TestIISSiteWrite_FlakeRecovers(t *testing.T) {
	oldBackoff := iisRetryBackoff
	iisRetryBackoff = func(int) time.Duration { return 0 }
	defer func() { iisRetryBackoff = oldBackoff }()

	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		if calls == 1 {
			return iisSiteErr(t, "unknown", "Cannot commit configuration changes because the file has changed on disk."), "", nil
		}
		return iisSiteOK(t, testIISSiteState()), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	pool := "pool1"
	st, err := c.Update(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{ApplicationPool: &pool},
	})
	if err != nil || st == nil {
		t.Fatalf("recovered write should succeed, got (%+v, %v)", st, err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls (flake + success), got %d", calls)
	}
}

func TestIISSiteCreate_FlakeThenAlreadyExistsKeepsFlake(t *testing.T) {
	oldBackoff := iisRetryBackoff
	iisRetryBackoff = func(int) time.Duration { return 0 }
	defer func() { iisRetryBackoff = oldBackoff }()

	flakeMsg := "Cannot commit configuration changes because the file has changed on disk."
	restore := iisSiteStubSequence([]frResponse{
		{stdout: iisSiteErr(t, "unknown", flakeMsg), stderr: "", err: nil},
		{stdout: iisSiteErr(t, "already_exists", "IIS site 'web' already exists on this host."), stderr: "", err: nil},
	})
	defer restore()

	c := iisSiteNewClient(t)
	pool := "pool1"
	_, err := c.Create(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{ApplicationPool: &pool},
	})
	if IsIISSiteError(err, IISSiteErrorAlreadyExists) {
		t.Fatalf("flake-then-already_exists on create must not mislead, got %v", err)
	}
	if !strings.Contains(err.Error(), flakeMsg) {
		t.Errorf("error must keep the original flake message, got %v", err)
	}

	// Control: already_exists with no prior flake stays already_exists.
	restoreControl := iisSiteStubSequence([]frResponse{
		{stdout: iisSiteErr(t, "already_exists", "IIS site 'web' already exists on this host."), stderr: "", err: nil},
	})
	defer restoreControl()
	if _, err := c.Create(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{ApplicationPool: &pool},
	}); !IsIISSiteError(err, IISSiteErrorAlreadyExists) {
		t.Errorf("already_exists without a prior flake must stay already_exists, got %v", err)
	}
}

func TestIISSiteWrite_OtherErrorsNotRetried(t *testing.T) {
	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return iisSiteErr(t, "access_denied", "Access is denied"), "", nil
	})
	defer restore()

	c := iisSiteNewClient(t)
	if err := c.Delete(context.Background(), "web"); !IsIISSiteError(err, IISSiteErrorAccessDenied) {
		t.Errorf("expected access_denied, got %v", err)
	}
	if calls != 1 {
		t.Errorf("non-flake failures must not retry, got %d calls", calls)
	}
}

// ---------------------------------------------------------------------------
// Remote kinds + payload parsing
// ---------------------------------------------------------------------------

func TestIISSiteRemoteKinds(t *testing.T) {
	cases := []struct {
		remote string
		want   IISSiteErrorKind
	}{
		{"not_found", IISSiteErrorNotFound},
		{"already_exists", IISSiteErrorAlreadyExists},
		{"id_conflict", IISSiteErrorIDConflict},
		{"app_pool_not_found", IISSiteErrorAppPoolNotFound},
		{"path_not_found", IISSiteErrorPathNotFound},
		{"iis_not_installed", IISSiteErrorIISNotInstalled},
		{"access_denied", IISSiteErrorAccessDenied},
	}
	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			restore := iisSiteStubSequence([]frResponse{{stdout: iisSiteErr(t, tc.remote, "boom "+tc.remote), stderr: "", err: nil}})
			defer restore()

			c := iisSiteNewClient(t)
			_, err := c.Read(context.Background(), "web")
			if tc.remote == "not_found" {
				if err != nil {
					t.Errorf("read not_found should be (nil, nil), got %v", err)
				}
				return
			}
			if !IsIISSiteError(err, tc.want) {
				t.Errorf("remote kind %q should map to %q, got %v", tc.remote, tc.want, err)
			}
		})
	}
}

func TestParseIISSiteState_HappyPath(t *testing.T) {
	raw, _ := json.Marshal(testIISSiteStateBound())
	st, err := parseIISSiteState("read", "web", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "web" || st.SiteID != 2 {
		t.Errorf("unexpected identity: %+v", st)
	}
	if st.PhysicalPath != `C:\inetpub\wwwroot` || st.ApplicationPool != "DefaultAppPool" {
		t.Errorf("unexpected paths: %+v", st)
	}
	if !st.AutoStart || st.PreloadEnabled || st.EnabledProtocols != "http" {
		t.Errorf("unexpected app settings: %+v", st)
	}
	if !st.LogEnabled || st.LogDirectory != `%SystemDrive%\inetpub\logs\LogFiles` || st.LogFormat != "W3C" {
		t.Errorf("unexpected log settings: %+v", st)
	}
	if st.ConnectionTimeoutSeconds != 120 || st.MaxConnections != 0 {
		t.Errorf("unexpected limits: %+v", st)
	}
	if len(st.Bindings) != 1 || st.Bindings[0].Protocol != "http" || st.Bindings[0].BindingInformation != "*:80:web" {
		t.Errorf("unexpected bindings view: %+v", st.Bindings)
	}
	if st.State != "Started" {
		t.Errorf("state = %q, want Started", st.State)
	}
}

func TestParseIISSiteState_Null(t *testing.T) {
	st, err := parseIISSiteState("read", "web", json.RawMessage("null"))
	if err != nil || st != nil {
		t.Errorf("null data should be (nil, nil), got (%+v, %v)", st, err)
	}
}

func TestParseIISSiteState_BadJSON(t *testing.T) {
	if _, err := parseIISSiteState("read", "web", json.RawMessage("{nope")); !IsIISSiteError(err, IISSiteErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestParseIISSiteState_EmptyBindingsIsEmpty(t *testing.T) {
	raw, _ := json.Marshal(testIISSiteState())
	st, err := parseIISSiteState("read", "web", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Bindings == nil || len(st.Bindings) != 0 {
		t.Errorf("empty bindings must decode to an empty (non-nil) slice, got %+v", st.Bindings)
	}
}

// ---------------------------------------------------------------------------
// CRUD happy paths
// ---------------------------------------------------------------------------

func TestIISSiteCRUD_HappyPaths(t *testing.T) {
	restore := iisSiteStubSequence([]frResponse{{stdout: iisSiteOK(t, testIISSiteState()), stderr: "", err: nil}})
	defer restore()

	c := iisSiteNewClient(t)
	path := `C:\inetpub\wwwroot`
	st, err := c.Create(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{PhysicalPath: &path},
	})
	if err != nil || st == nil || st.Name != "web" {
		t.Fatalf("create: (%+v, %v)", st, err)
	}
	pool := "pool1"
	st, err = c.Update(context.Background(), IISSiteInput{
		Name: "web", Settings: IISSiteSettings{ApplicationPool: &pool},
	})
	if err != nil || st == nil {
		t.Fatalf("update: (%+v, %v)", st, err)
	}
	if err := c.Delete(context.Background(), "web"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestIISSiteIISNotInstalled(t *testing.T) {
	restore := iisSiteStubSequence([]frResponse{{stdout: iisSiteErr(t, "iis_not_installed", "IIS is not installed on this host. Install it with the windows_feature resource (Web-Server)."), stderr: "", err: nil}})
	defer restore()

	c := iisSiteNewClient(t)
	_, err := c.Read(context.Background(), "web")
	if !IsIISSiteError(err, IISSiteErrorIISNotInstalled) {
		t.Errorf("expected iis_not_installed, got %v", err)
	}
	var ae *IISSiteError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "windows_feature") {
		t.Errorf("missing-IIS error must point at windows_feature, got %v", err)
	}
}
