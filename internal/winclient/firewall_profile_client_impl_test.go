// Package winclient — unit tests for FirewallProfileClient and the shared
// sshpath lockout-guard helpers.
//
// These tests stub the package-level runPowerShell seam (shared with
// service.go) so no real SSH connection is needed. Coverage targets (issue
// #223):
//
//	FirewallProfileError: Error(), Unwrap(), Is(), sentinels
//	mapFirewallProfileKind: all known kinds + unknown fallback
//	ValidateFirewallProfileName: case-insensitive accept, reject, short-circuit
//	sshConnectionServerIP: IPv4, IPv6, missing/malformed fail-closed
//	normalizeNetworkCategory: Public/Private/DomainAuthenticated/Domain + bad
//	firewallRuleCoversProfile: Any/exact/Any-absent + lab case (Private-only rule vs Public SSH)
//	sshProviderPort: default 22, honour non-22, clamp garbage
//	buildFirewallProfileParams: only-configured-attrs emission
//	buildFirewallProfileRestoreParams: verbatim incl. NotConfigured tri-states
//	effectiveGuardInputs: configured vs CURRENT
//	parseFirewallProfileState: null, valid, bad JSON, alias quirk, NotConfigured filter
//	runFirewallProfileEnvelope: transport/ctx/no-envelope/bad-JSON/Emit-Err mapping
//	Read/Apply/Restore: happy paths, guard fragment shipped, no-op Apply, invalid names
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

// fpNewClient returns a *Client + *FirewallProfileClient pair for tests.
func fpNewClient(t *testing.T) (*Client, *FirewallProfileClient) {
	t.Helper()
	c, err := New(Config{Host: "winfp01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewFirewallProfileClient(c)
}

// fpOK returns a JSON ok-envelope whose data field is the supplied value.
func fpOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("fpOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// fpErr returns a JSON error-envelope for the given kind/message.
func fpErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("fpErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// testFirewallProfileState is a minimal valid FirewallProfileState JSON payload.
func testFirewallProfileState() map[string]any {
	return map[string]any{
		"name":                                "Public",
		"enabled":                             true,
		"default_inbound_action":              "Allow",
		"default_outbound_action":             "Allow",
		"allow_inbound_rules":                 "True",
		"allow_local_firewall_rules":          "NotConfigured",
		"allow_local_ipsec_rules":             "NotConfigured",
		"allow_unicast_response_to_multicast": "NotConfigured",
		"notify_on_listen":                    false,
		"log_file_name":                       `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`,
		"log_max_size_kilobytes":              4096,
		"log_allowed":                         "False",
		"log_blocked":                         "False",
		"log_ignored":                         "False",
		"disabled_interface_aliases":          []any{},
	}
}

// fpStubSequence stubs runPowerShell with a fixed ordered list of responses.
func fpStubSequence(responses []frResponse) func() {
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
// FirewallProfileError
// ---------------------------------------------------------------------------

func TestFirewallProfileError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewFirewallProfileError(FirewallProfileErrorAccessDenied, "denied", cause,
		map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewFirewallProfileError(FirewallProfileErrorInvalidProfile, "bad", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestFirewallProfileError_Is(t *testing.T) {
	e := NewFirewallProfileError(FirewallProfileErrorWouldLockOut, "x", nil, nil)
	if !errors.Is(e, ErrFirewallProfileWouldLockOut) {
		t.Error("errors.Is(ErrFirewallProfileWouldLockOut) should match by kind")
	}
	if errors.Is(e, ErrFirewallProfileAccessDenied) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsFirewallProfileError(e, FirewallProfileErrorWouldLockOut) {
		t.Error("IsFirewallProfileError should match")
	}
	if IsFirewallProfileError(errors.New("plain"), FirewallProfileErrorWouldLockOut) {
		t.Error("IsFirewallProfileError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-FirewallProfileError should be false")
	}
}

func TestMapFirewallProfileKind(t *testing.T) {
	cases := map[string]FirewallProfileErrorKind{
		"invalid_profile":              FirewallProfileErrorInvalidProfile,
		"access_denied":                FirewallProfileErrorAccessDenied,
		"would_lock_out":               FirewallProfileErrorWouldLockOut,
		"firewall_service_unavailable": FirewallProfileErrorServiceUnavailable,
		"":                             FirewallProfileErrorUnknown,
		"weird_kind":                   FirewallProfileErrorUnknown,
	}
	for in, want := range cases {
		if got := mapFirewallProfileKind(in); got != want {
			t.Errorf("mapFirewallProfileKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateFirewallProfileName
// ---------------------------------------------------------------------------

func TestValidateFirewallProfileName(t *testing.T) {
	for _, n := range []string{"Domain", "Private", "Public", "domain", "PRIVATE", "public"} {
		if err := ValidateFirewallProfileName(n); err != nil {
			t.Errorf("name %q should be valid, got %v", n, err)
		}
	}
	for _, n := range []string{"", "Any", "All", "Domainx", "Private ", "GPO"} {
		if err := ValidateFirewallProfileName(n); !IsFirewallProfileError(err, FirewallProfileErrorInvalidProfile) {
			t.Errorf("name %q should yield invalid_profile, got %v", n, err)
		}
	}
	if got := canonicalFirewallProfileName("private"); got != "Private" {
		t.Errorf("canonicalFirewallProfileName(private) = %q, want Private", got)
	}
}

func TestFirewallProfileRead_InvalidNameShortCircuits(t *testing.T) {
	called := false
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	if _, err := c.Read(context.Background(), "Bogus"); !IsFirewallProfileError(err, FirewallProfileErrorInvalidProfile) {
		t.Errorf("expected invalid_profile, got %v", err)
	}
	if called {
		t.Error("invalid profile name must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// sshpath helpers
// ---------------------------------------------------------------------------

func TestSSHConnectionServerIP(t *testing.T) {
	// Lab shape: client IP/port + server IP/port.
	got, err := sshConnectionServerIP("172.31.248.83 49890 172.18.122.203 22")
	if err != nil || got != "172.18.122.203" {
		t.Errorf("IPv4 parse = %q, %v; want 172.18.122.203, nil", got, err)
	}
	// IPv6 tokens contain no whitespace: same split applies.
	got, err = sshConnectionServerIP("fe80::1 51234 fe80::2 22")
	if err != nil || got != "fe80::2" {
		t.Errorf("IPv6 parse = %q, %v; want fe80::2, nil", got, err)
	}
	// Fail closed on missing/malformed values.
	for _, bad := range []string{"", "   ", "only-two tokens", "a b c"} {
		if _, err := sshConnectionServerIP(bad); err == nil {
			t.Errorf("connection %q should fail closed, got nil error", bad)
		}
	}
}

func TestNormalizeNetworkCategory(t *testing.T) {
	cases := map[string]string{
		"Public":              "Public",
		"Private":             "Private",
		"DomainAuthenticated": "Domain",
		"Domain":              "Domain",
	}
	for in, want := range cases {
		got, err := normalizeNetworkCategory(in)
		if err != nil || got != want {
			t.Errorf("normalizeNetworkCategory(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}
	if _, err := normalizeNetworkCategory("Nope"); err == nil {
		t.Error("unknown category should fail")
	}
	if _, err := normalizeNetworkCategory(""); err == nil {
		t.Error("empty category should fail")
	}
}

func TestFirewallRuleCoversProfile(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		ssh   string
		want  bool
	}{
		{"any covers", []string{"Any"}, "Public", true},
		{"empty covers (windows default)", nil, "Public", true},
		{"exact match", []string{"Private"}, "Private", true},
		{"case-insensitive", []string{"public"}, "Public", true},
		// Lab case: the SSH session rides Public while OpenSSH-Server-In-TCP
		// covers Private only — that rule must NOT count as coverage.
		{"lab private-only vs public ssh", []string{"Private"}, "Public", false},
		{"multi without ssh profile", []string{"Domain", "Private"}, "Public", false},
		{"multi with ssh profile", []string{"Domain", "Public"}, "Public", true},
		{"any among others", []string{"Private", "Any"}, "Domain", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firewallRuleCoversProfile(tc.rules, tc.ssh); got != tc.want {
				t.Errorf("firewallRuleCoversProfile(%v, %q) = %v, want %v", tc.rules, tc.ssh, got, tc.want)
			}
		})
	}
}

func TestSSHProviderPort(t *testing.T) {
	if got := sshProviderPort(0); got != 22 {
		t.Errorf("unset port = %d, want 22", got)
	}
	if got := sshProviderPort(2222); got != 2222 {
		t.Errorf("custom port = %d, want 2222 (non-22 ports must be honoured)", got)
	}
	for _, bad := range []int{-1, 70000} {
		if got := sshProviderPort(bad); got != 22 {
			t.Errorf("garbage port %d = %d, want fail-closed 22", bad, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Guard decision table (Go-side inputs the PS guard reasons about)
// ---------------------------------------------------------------------------

func TestEffectiveGuardInputs(t *testing.T) {
	allow := "Allow"
	// Nothing configured: both resolve live on the host.
	in, ai := effectiveGuardInputs(FirewallProfileSettings{})
	if in != "CURRENT" || ai != "CURRENT" {
		t.Errorf("empty settings = (%q, %q), want (CURRENT, CURRENT)", in, ai)
	}
	// Risky pair: Block + disabled inbound rules.
	f := false
	in, _ = effectiveGuardInputs(FirewallProfileSettings{DefaultInboundAction: &allow, AllowInboundRules: &f})
	_ = in
	block := "Block"
	in, ai = effectiveGuardInputs(FirewallProfileSettings{DefaultInboundAction: &block, AllowInboundRules: &f})
	if in != "Block" || ai != "False" {
		t.Errorf("risky settings = (%q, %q), want (Block, False)", in, ai)
	}
	// Safe pair stays safe.
	tr := true
	in, ai = effectiveGuardInputs(FirewallProfileSettings{DefaultInboundAction: &allow, AllowInboundRules: &tr})
	if in != "Allow" || ai != "True" {
		t.Errorf("safe settings = (%q, %q), want (Allow, True)", in, ai)
	}
}

// ---------------------------------------------------------------------------
// Param builders: only configured attributes are emitted
// ---------------------------------------------------------------------------

func TestBuildFirewallProfileParams_OnlyConfigured(t *testing.T) {
	// Empty settings: identity only, nothing to write.
	script := buildFirewallProfileParams("Public", FirewallProfileSettings{})
	if strings.Contains(script, "Enabled") || strings.Contains(script, "LogAllowed") ||
		strings.Contains(script, "DisabledInterfaceAliases") || strings.Contains(script, "DefaultInboundAction") {
		t.Errorf("empty settings must emit no attribute params, got:\n%s", script)
	}
	if !strings.Contains(script, "PersistentStore") {
		t.Errorf("params must pin -PolicyStore PersistentStore, got:\n%s", script)
	}

	allow := "Allow"
	f := false
	size := int64(8192)
	script = buildFirewallProfileParams("Private", FirewallProfileSettings{
		Enabled:              &f,
		DefaultInboundAction: &allow,
		LogMaxSizeKilobytes:  &size,
	})
	for _, want := range []string{"Enabled = $false", "'Allow'", "LogMaxSizeKilobytes = 8192"} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q, got:\n%s", want, script)
		}
	}
	if strings.Contains(script, "DisabledInterfaceAliases") {
		t.Errorf("unset alias list must be omitted (unmanaged), got:\n%s", script)
	}

	// Configured-but-empty alias list IS authoritative: emits @().
	script = buildFirewallProfileParams("Private", FirewallProfileSettings{
		DisabledInterfaceAliases:    []string{},
		DisabledInterfaceAliasesSet: true,
	})
	if !strings.Contains(script, "DisabledInterfaceAliases = @()") {
		t.Errorf("empty-but-set alias list must clear exclusions, got:\n%s", script)
	}

	// User strings travel through psQuote.
	evil := "x'; Write-Host pwned; '"
	script = buildFirewallProfileParams("Public", FirewallProfileSettings{LogFileName: &evil})
	if strings.Contains(script, evil) {
		t.Errorf("user value must be quoted, got:\n%s", script)
	}
	if !strings.Contains(script, psQuote(evil)) {
		t.Errorf("user value must appear psQuote'd, got:\n%s", script)
	}
}

func TestFirewallProfileApply_GuardCoversAnyProtocol(t *testing.T) {
	// Any-protocol inbound Allow rule covering the SSH port must count as
	// coverage alongside TCP (lab: Get-NetFirewallPortFilter may report
	// Protocol Any).
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(testFirewallProfileState())
		return fpOK(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	block := "Block"
	f := false
	if _, err := c.Apply(context.Background(), "Public", FirewallProfileSettings{
		DefaultInboundAction: &block, AllowInboundRules: &f,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "$f.Protocol -eq 'Any'") {
		t.Errorf("guard must treat Protocol 'Any' as covering alongside 'TCP', got:\n%s", gotScript)
	}
}

func TestBuildFirewallProfileRestoreParams_Verbatim(t *testing.T) {
	snap := FirewallProfileState{
		Name: "Public", Enabled: true,
		DefaultInboundAction: "Block", DefaultOutboundAction: "Allow",
		AllowInboundRules: "False", AllowLocalFirewallRules: "NotConfigured",
		AllowLocalIPsecRules: "True", AllowUnicastResponseToMulticast: "False",
		NotifyOnListen: false, LogFileName: "C:\\Logs\\fw.log", LogMaxSizeKilobytes: 4096,
		LogAllowed: "NotConfigured", LogBlocked: "True", LogIgnored: "False",
		DisabledInterfaceAliases: []string{"Ethernet 2"},
	}
	script := buildFirewallProfileRestoreParams("Public", snap)
	for _, want := range []string{
		"Enabled = $true", "'Block'", "AllowInboundRules = $false",
		"AllowLocalFirewallRules = 'NotConfigured'", "LogAllowed = 'NotConfigured'",
		"'Ethernet 2'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("restore params missing %q, got:\n%s", want, script)
		}
	}
}

func TestBuildFirewallProfileRestoreParams_NotConfiguredActionsVerbatim(t *testing.T) {
	// Lab evidence: Set-NetFirewallProfile -PolicyStore PersistentStore
	// accepts NotConfigured for DefaultInboundAction/DefaultOutboundAction
	// (Action type) as well as the GPO tri-states — a snapshot containing
	// NotConfigured actions must round-trip verbatim, never dropped.
	snap := FirewallProfileState{
		Name: "Public", Enabled: true,
		DefaultInboundAction: "NotConfigured", DefaultOutboundAction: "NotConfigured",
		AllowInboundRules: "NotConfigured", AllowLocalFirewallRules: "NotConfigured",
		AllowLocalIPsecRules: "NotConfigured", AllowUnicastResponseToMulticast: "NotConfigured",
		NotifyOnListen: false, LogFileName: `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`,
		LogMaxSizeKilobytes: 4096,
		LogAllowed:          "NotConfigured", LogBlocked: "NotConfigured", LogIgnored: "NotConfigured",
		DisabledInterfaceAliases: []string{},
	}
	script := buildFirewallProfileRestoreParams("Public", snap)
	for _, want := range []string{
		"DefaultInboundAction = 'NotConfigured'",
		"DefaultOutboundAction = 'NotConfigured'",
		"AllowInboundRules = 'NotConfigured'",
		"LogBlocked = 'NotConfigured'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("restore params must emit verbatim %q, got:\n%s", want, script)
		}
	}
}

// ---------------------------------------------------------------------------
// parseFirewallProfileState
// ---------------------------------------------------------------------------

func TestParseFirewallProfileState_Null(t *testing.T) {
	resp := &psResponse{Data: json.RawMessage("null")}
	st, err := parseFirewallProfileState(resp, "Public")
	if err != nil || st != nil {
		t.Errorf("null data should be (nil, nil), got (%+v, %v)", st, err)
	}
}

func TestParseFirewallProfileState_HappyPath(t *testing.T) {
	raw, _ := json.Marshal(testFirewallProfileState())
	resp := &psResponse{Data: raw}
	st, err := parseFirewallProfileState(resp, "Public")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "Public" || !st.Enabled || st.DefaultInboundAction != "Allow" {
		t.Errorf("unexpected state: %+v", st)
	}
	if st.AllowLocalFirewallRules != "NotConfigured" {
		t.Errorf("tri-state must round-trip raw, got %q", st.AllowLocalFirewallRules)
	}
	if st.LogMaxSizeKilobytes != 4096 {
		t.Errorf("log size = %d, want 4096", st.LogMaxSizeKilobytes)
	}
	if len(st.DisabledInterfaceAliases) != 0 {
		t.Errorf("empty aliases = %v, want []", st.DisabledInterfaceAliases)
	}
}

func TestParseFirewallProfileState_BadJSON(t *testing.T) {
	resp := &psResponse{Data: json.RawMessage("{nope")}
	if _, err := parseFirewallProfileState(resp, "Public"); !IsFirewallProfileError(err, FirewallProfileErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestParseFirewallProfileAliases_Quirks(t *testing.T) {
	// Bare string: ConvertTo-Json single-element quirk.
	st, err := parseFirewallProfileAliases(json.RawMessage(`"Ethernet 2"`))
	if err != nil || len(st) != 1 || st[0] != "Ethernet 2" {
		t.Errorf("bare string aliases = %v, %v", st, err)
	}
	// NotConfigured sentinel filters to empty.
	st, err = parseFirewallProfileAliases(json.RawMessage(`["NotConfigured"]`))
	if err != nil || len(st) != 0 {
		t.Errorf("NotConfigured aliases = %v, %v; want empty", st, err)
	}
	// Null and empty.
	for _, raw := range []string{"null", ""} {
		st, err = parseFirewallProfileAliases(json.RawMessage(raw))
		if err != nil || len(st) != 0 {
			t.Errorf("raw %q aliases = %v, %v; want empty", raw, st, err)
		}
	}
}

// ---------------------------------------------------------------------------
// runFirewallProfileEnvelope: ctx cancel / transport / no envelope / bad JSON
// ---------------------------------------------------------------------------

func TestRunFirewallProfileEnvelope_Timeout(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: "", stderr: "", err: context.Canceled}})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, c := fpNewClient(t)
	_, err := c.Read(ctx, "Public")
	if !IsFirewallProfileError(err, FirewallProfileErrorUnknown) {
		t.Errorf("expected unknown (timeout) kind, got %v", err)
	}
	var fe *FirewallProfileError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FirewallProfileError, got %T", err)
	}
	if !strings.Contains(fe.Message, `"Read"`) || !strings.Contains(fe.Message, "Public") {
		t.Errorf("Message = %q, want operation and profile name", fe.Message)
	}
}

func TestRunFirewallProfileEnvelope_TransportError(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: "", stderr: "boom", err: errors.New("ssh dial failed")}})
	defer restore()

	_, c := fpNewClient(t)
	_, err := c.Read(context.Background(), "Public")
	if !IsFirewallProfileError(err, FirewallProfileErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunFirewallProfileEnvelope_NoEnvelope(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: "not json at all", stderr: "", err: nil}})
	defer restore()

	_, c := fpNewClient(t)
	_, err := c.Read(context.Background(), "Public")
	if !IsFirewallProfileError(err, FirewallProfileErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunFirewallProfileEnvelope_BadJSON(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: "{not valid json}", stderr: "", err: nil}})
	defer restore()

	_, c := fpNewClient(t)
	_, err := c.Read(context.Background(), "Public")
	if !IsFirewallProfileError(err, FirewallProfileErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Remote error kinds, one fixture each
// ---------------------------------------------------------------------------

func TestFirewallProfileRemoteKinds(t *testing.T) {
	cases := []struct {
		remote string
		want   FirewallProfileErrorKind
	}{
		{"invalid_profile", FirewallProfileErrorInvalidProfile},
		{"access_denied", FirewallProfileErrorAccessDenied},
		{"would_lock_out", FirewallProfileErrorWouldLockOut},
		{"firewall_service_unavailable", FirewallProfileErrorServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			restore := fpStubSequence([]frResponse{{stdout: fpErr(t, tc.remote, "boom "+tc.remote), stderr: "", err: nil}})
			defer restore()

			_, c := fpNewClient(t)
			_, err := c.Read(context.Background(), "Public")
			if !IsFirewallProfileError(err, tc.want) {
				t.Errorf("remote kind %q should map to %q, got %v", tc.remote, tc.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Classify-FirewallProfile pins: envelope fixtures for InvalidProfile,
// AccessDenied and MpsSvc-stopped records
// ---------------------------------------------------------------------------

func TestClassifyFirewallProfile_ScriptContent(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(testFirewallProfileState())
		return fpOK(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	if _, err := c.Read(context.Background(), "Public"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"function Classify-FirewallProfile",
		"MpsSvc",
		"Windows Firewall service",
		"Access is denied",
		"No MSFT_NetFirewallProfile",
		"InvalidProfile",
		"'firewall_service_unavailable'",
		"'access_denied'",
		"'invalid_profile'",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("Classify-FirewallProfile must handle the MpsSvc-stopped/access/invalid records; script missing %q", want)
		}
	}
	// Locale safety: the session culture is pinned like firewall_rule.
	if !strings.Contains(gotScript, "InvariantCulture") {
		t.Error("script must pin InvariantCulture for locale-stable enum decoding")
	}
}

// ---------------------------------------------------------------------------
// SSHProfile
// ---------------------------------------------------------------------------

func TestFirewallProfileSSHProfile_HappyPath(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: fpOK(t, "Public"), stderr: "", err: nil}})
	defer restore()

	_, c := fpNewClient(t)
	got, err := c.SSHProfile(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "Public" {
		t.Errorf("SSHProfile = %q, want Public", got)
	}
}

func TestFirewallProfileSSHProfile_FailClosed(t *testing.T) {
	// Unresolvable SSH profile surfaces a typed error (the guard fails
	// closed on it); an unparseable payload is unknown, never a guess.
	restore := fpStubSequence([]frResponse{{stdout: fpErr(t, "unknown", "SSH_CONNECTION is not set"), stderr: "", err: nil}})
	defer restore()

	_, c := fpNewClient(t)
	if _, err := c.SSHProfile(context.Background()); !IsFirewallProfileError(err, FirewallProfileErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestFirewallProfileSSHProfile_RejectsUnknownProfile(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: fpOK(t, "Bogus"), stderr: "", err: nil}})
	defer restore()

	_, c := fpNewClient(t)
	if _, err := c.SSHProfile(context.Background()); !IsFirewallProfileError(err, FirewallProfileErrorUnknown) {
		t.Errorf("expected unknown for a non-profile answer, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestFirewallProfileRead_HappyPath(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: fpOK(t, testFirewallProfileState()), stderr: "", err: nil}})
	defer restore()

	_, c := fpNewClient(t)
	st, err := c.Read(context.Background(), "public")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "Public" || !st.Enabled || st.NotifyOnListen {
		t.Errorf("unexpected state: %+v", st)
	}
	if st.AllowLocalFirewallRules != "NotConfigured" {
		t.Errorf("tri-state must survive Read raw, got %q", st.AllowLocalFirewallRules)
	}
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

func TestFirewallProfileApply_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(testFirewallProfileState())
		return fpOK(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	tr := true
	st, err := c.Apply(context.Background(), "Public", FirewallProfileSettings{LogBlocked: &tr})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st == nil || st.Name != "Public" {
		t.Errorf("unexpected state: %+v", st)
	}
	// Partial management: only the configured attribute is written.
	// ($params entries use two-space indent and PascalCase names; the
	// readback block below uses four-space indent and snake_case keys.)
	if !strings.Contains(gotScript, "  LogBlocked = $true") {
		t.Errorf("script must set the configured attribute, got:\n%s", gotScript)
	}
	for _, absent := range []string{"  LogAllowed = ", "  DefaultInboundAction = ", "  Enabled = "} {
		if strings.Contains(gotScript, absent) {
			t.Errorf("script must not emit unconfigured attribute %q, got:\n%s", absent, gotScript)
		}
	}
	if !strings.Contains(gotScript, "Set-NetFirewallProfile") || !strings.Contains(gotScript, "PersistentStore") {
		t.Errorf("script must use Set-NetFirewallProfile -PolicyStore PersistentStore, got:\n%s", gotScript)
	}
}

func TestFirewallProfileApply_ShipsGuard(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(testFirewallProfileState())
		return fpOK(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	block := "Block"
	f := false
	// Risky change: Block + disabled inbound rules. The unit seam cannot run
	// the host-side check; it pins that the guard ships with the risky
	// effective values and the would_lock_out refusal path.
	if _, err := c.Apply(context.Background(), "Public", FirewallProfileSettings{
		DefaultInboundAction: &block, AllowInboundRules: &f,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"$env:SSH_CONNECTION",
		"Get-NetIPAddress",
		"Get-NetConnectionProfile",
		"Get-NetFirewallRule",
		"Get-NetFirewallPortFilter",
		"would_lock_out",
		"windows_firewall_rule",
		"'Block'",
		"'False'",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("guard script missing %q", want)
		}
	}
	// The non-22 provider port must be honoured in the coverage check.
	c2 := NewFirewallProfileClient(mustFPClientWithPort(t, 2222))
	var gotScript2 string
	restore2 := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript2 = script
		raw, _ := json.Marshal(testFirewallProfileState())
		return fpOK(t, json.RawMessage(raw)), "", nil
	})
	defer restore2()
	if _, err := c2.Apply(context.Background(), "Public", FirewallProfileSettings{
		DefaultInboundAction: &block, AllowInboundRules: &f,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript2, "2222") {
		t.Errorf("guard must check coverage for the provider port (2222), got:\n%s", gotScript2)
	}
}

// mustFPClientWithPort builds a client whose SSH port is port.
func mustFPClientWithPort(t *testing.T, port int) *Client {
	t.Helper()
	c, err := New(Config{Host: "winfp01", Port: port, Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestFirewallProfileApply_NoOpWithoutSettings(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(testFirewallProfileState())
		return fpOK(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	if _, err := c.Apply(context.Background(), "Public", FirewallProfileSettings{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Nothing configured: short-circuit to Read, no Set round trip.
	if strings.Contains(gotScript, "Set-NetFirewallProfile") {
		t.Errorf("unconfigured Apply must not write, got:\n%s", gotScript)
	}
}

func TestFirewallProfileApply_WouldLockOut(t *testing.T) {
	restore := fpStubSequence([]frResponse{{stdout: fpErr(t, "would_lock_out", "Refusing to tighten firewall profile Public"), stderr: "", err: nil}})
	defer restore()

	_, c := fpNewClient(t)
	block := "Block"
	f := false
	_, err := c.Apply(context.Background(), "Public", FirewallProfileSettings{
		DefaultInboundAction: &block, AllowInboundRules: &f,
	})
	if !IsFirewallProfileError(err, FirewallProfileErrorWouldLockOut) {
		t.Errorf("expected would_lock_out, got %v", err)
	}
}

func TestFirewallProfileApply_InvalidNameShortCircuits(t *testing.T) {
	called := false
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	if _, err := c.Apply(context.Background(), "Bogus", FirewallProfileSettings{}); !IsFirewallProfileError(err, FirewallProfileErrorInvalidProfile) {
		t.Errorf("expected invalid_profile, got %v", err)
	}
	if called {
		t.Error("invalid profile name must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

func TestFirewallProfileRestore_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		raw, _ := json.Marshal(testFirewallProfileState())
		return fpOK(t, json.RawMessage(raw)), "", nil
	})
	defer restore()

	_, c := fpNewClient(t)
	snap := FirewallProfileState{
		Name: "Public", Enabled: true,
		DefaultInboundAction: "Allow", DefaultOutboundAction: "Allow",
		AllowInboundRules: "True", AllowLocalFirewallRules: "NotConfigured",
		AllowLocalIPsecRules: "NotConfigured", AllowUnicastResponseToMulticast: "NotConfigured",
		NotifyOnListen: false, LogFileName: `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`,
		LogMaxSizeKilobytes: 4096,
		LogAllowed:          "False", LogBlocked: "False", LogIgnored: "False",
		DisabledInterfaceAliases: []string{},
	}
	if _, err := c.Restore(context.Background(), snap); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "Set-NetFirewallProfile") {
		t.Errorf("restore must write via Set-NetFirewallProfile, got:\n%s", gotScript)
	}
}

func TestFirewallProfileRestore_InvalidName(t *testing.T) {
	_, c := fpNewClient(t)
	if _, err := c.Restore(context.Background(), FirewallProfileState{Name: "Bogus"}); !IsFirewallProfileError(err, FirewallProfileErrorInvalidProfile) {
		t.Errorf("expected invalid_profile, got %v", err)
	}
}
