// Package winclient — unit tests for NTPClient.
//
// These tests stub the package-level runPowerShell seam (shared with
// service.go) so no real SSH connection is needed. Coverage targets (issue
// #287):
//
//	NTPError: Error(), Unwrap(), Is(), sentinels, IsNTPError
//	mapNTPKind: all known kinds + unknown fallback
//	ValidateNTPType / NTPTypeUsesPeers
//	ValidateNTPFlags / NormalizeNTPFlags / ValidateNTPPeerAddress
//	Parse/BuildNtpServerString round-trip + defaults + fail-closed
//	NTPPeersEqual (order matters, address case-insensitive)
//	AnnounceFlags mapping (5/10) + poll-interval bounds + ValidateNTPInput
//	Header conventions: Classify-NTP, InvariantCulture, $LASTEXITCODE
//	gates, Set-ItemProperty, w32tm, no exit, no locale-dependent w32tm
//	query parsing
//	Read: happy-path mapping, preflight service_unavailable, timeout,
//	transport and remote-kind mapping
//	Set: script shape (service ensure on/off, registry writes, /config
//	/update, resync), verify mismatch, resync warning recorded not
//	errored, client-side invalid_peer without host traffic
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ntpOK marshals data as an Emit-OK envelope line.
func ntpOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

// ntpErr marshals an Emit-Err envelope line.
func ntpErr(t *testing.T, kind, msg string, ctx map[string]string) string {
	t.Helper()
	if ctx == nil {
		ctx = map[string]string{}
	}
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": ctx,
	})
	if err != nil {
		t.Fatalf("marshal err: %v", err)
	}
	return string(b) + "\n"
}

// ntpPayload builds a Read-NTPState payload with the given overrides.
func ntpPayload(overrides map[string]any) map[string]any {
	base := map[string]any{
		"machine_id":               "11111111-2222-3333-4444-555555555555",
		"type":                     "NTP",
		"ntp_server":               "0.fr.pool.ntp.org,0x9 ntp1.example.net,0x1",
		"special_poll_interval":    900,
		"reliable":                 false,
		"announce_flags":           10,
		"ntp_server_enabled":       false,
		"max_pos_phase_correction": 54000,
		"max_neg_phase_correction": 54000,
		"current_source":           "0.fr.pool.ntp.org,0x9",
		"policy_override":          false,
		"domain_joined":            false,
		"vmic_enabled":             false,
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

func newNTPTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:                  "win01",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

var ntpExitRe = regexp.MustCompile(`(?m)^\s*exit(\s|;|$)`)

// ---------------------------------------------------------------------------
// NTPError
// ---------------------------------------------------------------------------

func TestNTPError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewNTPError(NTPErrorAccessDenied, "denied", cause, map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewNTPError(NTPErrorServiceUnavailable, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestNTPError_Is(t *testing.T) {
	e := NewNTPError(NTPErrorInvalidPeer, "x", nil, nil)
	if !errors.Is(e, ErrNTPInvalidPeer) {
		t.Error("errors.Is(ErrNTPInvalidPeer) should match by kind")
	}
	if errors.Is(e, ErrNTPAccessDenied) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsNTPError(e, NTPErrorInvalidPeer) {
		t.Error("IsNTPError should match")
	}
	if IsNTPError(errors.New("plain"), NTPErrorInvalidPeer) {
		t.Error("IsNTPError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-NTPError should be false")
	}
	var ne *NTPError
	if !errors.As(NewNTPError(NTPErrorUnknown, "m", nil, nil), &ne) {
		t.Error("errors.As should extract *NTPError")
	}
}

func TestMapNTPKind(t *testing.T) {
	cases := map[string]NTPErrorKind{
		"service_unavailable": NTPErrorServiceUnavailable,
		"access_denied":       NTPErrorAccessDenied,
		"invalid_peer":        NTPErrorInvalidPeer,
		"":                    NTPErrorUnknown,
		"weird_kind":          NTPErrorUnknown,
	}
	for in, want := range cases {
		if got := mapNTPKind(in); got != want {
			t.Errorf("mapNTPKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Sync type
// ---------------------------------------------------------------------------

func TestValidateNTPType(t *testing.T) {
	for _, typ := range []string{"NTP", "NT5DS", "AllSync", "NoSync"} {
		if err := ValidateNTPType(typ); err != nil {
			t.Errorf("type %q should be valid, got %v", typ, err)
		}
	}
	for _, typ := range []string{"", "ntp", "PDC", "domain"} {
		if err := ValidateNTPType(typ); err == nil {
			t.Errorf("type %q should be rejected", typ)
		}
	}
}

func TestNTPTypeUsesPeers(t *testing.T) {
	if !NTPTypeUsesPeers("NTP") || !NTPTypeUsesPeers("AllSync") {
		t.Error("NTP/AllSync must consume peers")
	}
	if NTPTypeUsesPeers("NT5DS") || NTPTypeUsesPeers("NoSync") {
		t.Error("NT5DS/NoSync must not consume peers")
	}
}

// ---------------------------------------------------------------------------
// Flags / address validation
// ---------------------------------------------------------------------------

func TestValidateNTPFlags(t *testing.T) {
	for _, f := range []string{"0x1", "0x9", "0xf", "0XF", "0XA"} {
		if err := ValidateNTPFlags(f); err != nil {
			t.Errorf("flags %q should be valid, got %v", f, err)
		}
	}
	for _, f := range []string{"", "0x0", "0x10", "9", "0b1", "0x", "0xg", "0x1,0x2"} {
		if err := ValidateNTPFlags(f); !IsNTPError(err, NTPErrorInvalidPeer) {
			t.Errorf("flags %q should yield invalid_peer, got %v", f, err)
		}
	}
}

func TestNormalizeNTPFlags(t *testing.T) {
	for in, want := range map[string]string{"0x9": "0x9", "0X9": "0x9", "0XF": "0xf"} {
		got, err := NormalizeNTPFlags(in)
		if err != nil {
			t.Errorf("NormalizeNTPFlags(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeNTPFlags(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeNTPFlags("bogus"); !IsNTPError(err, NTPErrorInvalidPeer) {
		t.Errorf("bogus flags should yield invalid_peer, got %v", err)
	}
}

func TestValidateNTPPeerAddress(t *testing.T) {
	for _, a := range []string{"0.fr.pool.ntp.org", "ntp1.example.net", "192.0.2.1", "2001:db8::1"} {
		if err := ValidateNTPPeerAddress(a); err != nil {
			t.Errorf("address %q should be valid, got %v", a, err)
		}
	}
	for _, a := range []string{"", "has space.example", "a,b", "tab\there", "nl\nhost"} {
		if err := ValidateNTPPeerAddress(a); !IsNTPError(err, NTPErrorInvalidPeer) {
			t.Errorf("address %q should yield invalid_peer, got %v", a, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Parse / build round-trip
// ---------------------------------------------------------------------------

func TestParseBuildNtpServerString_RoundTrip(t *testing.T) {
	raw := "0.fr.pool.ntp.org,0x9 ntp1.example.net,0x1 192.0.2.1,0x8"
	peers, err := ParseNtpServerString(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != 3 {
		t.Fatalf("want 3 peers, got %d", len(peers))
	}
	if peers[0] != (NTPPeer{Address: "0.fr.pool.ntp.org", Flags: "0x9"}) {
		t.Errorf("peer[0] = %+v", peers[0])
	}
	built, err := BuildNtpServerString(peers)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built != raw {
		t.Errorf("round-trip = %q, want %q", built, raw)
	}
}

func TestParseNtpServerString_DefaultsAndNormalises(t *testing.T) {
	peers, err := ParseNtpServerString("host.example  OTHER.example,0X1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(peers))
	}
	if peers[0].Flags != DefaultNTPPeerFlags {
		t.Errorf("missing flags should default to %q, got %q", DefaultNTPPeerFlags, peers[0].Flags)
	}
	if peers[1].Flags != "0x1" {
		t.Errorf("flags should normalise to lower-case, got %q", peers[1].Flags)
	}
	if got, err := ParseNtpServerString(""); err != nil || got != nil {
		t.Errorf("empty string should yield nil peers without error, got %+v, %v", got, err)
	}
}

func TestParseNtpServerString_FailClosed(t *testing.T) {
	for _, raw := range []string{"host,0x0", "host,0x10", ",0x9", "a b,0xg"} {
		if _, err := ParseNtpServerString(raw); !IsNTPError(err, NTPErrorInvalidPeer) {
			t.Errorf("raw %q should yield invalid_peer, got %v", raw, err)
		}
	}
}

func TestBuildNtpServerString_FailClosed(t *testing.T) {
	if s, err := BuildNtpServerString(nil); err != nil || s != "" {
		t.Errorf("nil peers should yield empty string, got %q, %v", s, err)
	}
	if _, err := BuildNtpServerString([]NTPPeer{{Address: "bad host", Flags: "0x9"}}); !IsNTPError(err, NTPErrorInvalidPeer) {
		t.Errorf("bad address should yield invalid_peer, got %v", err)
	}
	if _, err := BuildNtpServerString([]NTPPeer{{Address: "ok.example", Flags: "0x0"}}); !IsNTPError(err, NTPErrorInvalidPeer) {
		t.Errorf("bad flags should yield invalid_peer, got %v", err)
	}
}

func TestNTPPeersEqual(t *testing.T) {
	a := []NTPPeer{{Address: "Host.Example", Flags: "0x9"}}
	b := []NTPPeer{{Address: "host.example", Flags: "0x9"}}
	if !NTPPeersEqual(a, b) {
		t.Error("addresses should compare case-insensitively")
	}
	if NTPPeersEqual(a, []NTPPeer{{Address: "host.example", Flags: "0x1"}}) {
		t.Error("differing flags must not compare equal")
	}
	if NTPPeersEqual(a, append(a, NTPPeer{Address: "x", Flags: "0x9"})) {
		t.Error("differing lengths must not compare equal")
	}
	if NTPPeersEqual(a, []NTPPeer{{Address: "other.example", Flags: "0x9"}}) {
		t.Error("differing addresses must not compare equal")
	}
}

// ---------------------------------------------------------------------------
// AnnounceFlags / poll interval / input validation
// ---------------------------------------------------------------------------

func TestNTPAnnounceFlagsMapping(t *testing.T) {
	if got := NTPAnnounceFlagsFromReliable(true); got != 5 {
		t.Errorf("reliable=true should map to 5, got %d", got)
	}
	if got := NTPAnnounceFlagsFromReliable(false); got != 10 {
		t.Errorf("reliable=false should map to 10, got %d", got)
	}
	if !NTPReliableFromAnnounceFlags(5) {
		t.Error("AnnounceFlags 5 must observe as reliable")
	}
	for _, f := range []int64{0, 1, 2, 10, 11} {
		if NTPReliableFromAnnounceFlags(f) {
			t.Errorf("AnnounceFlags %d must observe as not reliable", f)
		}
	}
}

func TestValidateNTPPollInterval(t *testing.T) {
	for _, v := range []int64{16, 900, 86400} {
		if err := ValidateNTPPollInterval(v); err != nil {
			t.Errorf("poll %d should be valid, got %v", v, err)
		}
	}
	for _, v := range []int64{0, 15, 86401, -1} {
		if err := ValidateNTPPollInterval(v); err == nil {
			t.Errorf("poll %d should be rejected", v)
		}
	}
}

func TestValidateNTPInput(t *testing.T) {
	peer := NTPPeer{Address: "host.example", Flags: "0x9"}
	if err := ValidateNTPInput(NTPInput{Type: "NTP", Servers: []NTPPeer{peer}}); err != nil {
		t.Errorf("valid NTP input rejected: %v", err)
	}
	if err := ValidateNTPInput(NTPInput{Type: "NT5DS"}); err != nil {
		t.Errorf("NT5DS without peers must be valid, got %v", err)
	}
	if err := ValidateNTPInput(NTPInput{Type: "NTP"}); !IsNTPError(err, NTPErrorInvalidPeer) {
		t.Errorf("NTP without peers should yield invalid_peer, got %v", err)
	}
	if err := ValidateNTPInput(NTPInput{Type: "bogus"}); err == nil {
		t.Error("unknown type should be rejected")
	}
	bad := peer
	bad.Address = "bad host"
	if err := ValidateNTPInput(NTPInput{Type: "NTP", Servers: []NTPPeer{bad}}); !IsNTPError(err, NTPErrorInvalidPeer) {
		t.Errorf("bad peer should yield invalid_peer, got %v", err)
	}
	poll := int64(15)
	if err := ValidateNTPInput(NTPInput{Type: "NTP", Servers: []NTPPeer{peer}, SpecialPollIntervalSeconds: &poll}); err == nil {
		t.Error("out-of-range poll interval should be rejected")
	}
	neg := int64(-1)
	if err := ValidateNTPInput(NTPInput{Type: "NTP", Servers: []NTPPeer{peer}, MaxPosPhaseCorrectionSeconds: &neg}); err == nil {
		t.Error("negative phase correction should be rejected")
	}
}

// ---------------------------------------------------------------------------
// Header invariants
// ---------------------------------------------------------------------------

func TestNTPHeader_Conventions(t *testing.T) {
	for _, want := range []string{
		"function Classify-NTP",
		"InvariantCulture",
		"function Read-NTPState",
		"MachineGuid",
		"SpecialPollInterval",
		"AnnounceFlags",
		"VMICTimeProvider",
		"PartOfDomain",
		"function Emit-OK",
		"function Emit-Err",
	} {
		if !strings.Contains(psNTPHeader, want) {
			t.Errorf("psNTPHeader missing %q", want)
		}
	}
	if !strings.Contains(psNTPHeader, `SOFTWARE\Policies\Microsoft\W32Time`) {
		t.Error("psNTPHeader missing the Group Policy override path")
	}
	// Script-level commands live in the read/set bodies, not the header.
	full := psNTPHeader + ntpReadBody + ntpSetBody
	for _, want := range []string{
		"w32tm /config /update",
		"w32tm /resync /rediscover",
		"w32tm /query /source",
		"$LASTEXITCODE",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("NTP scripts missing %q", want)
		}
	}
	// Set-ItemProperty lines are rendered by Go per configured input, so
	// assert on the builder output rather than the static template.
	setBlock, err := buildNTPSetBlock(ntpSetInput())
	if err != nil {
		t.Fatalf("buildNTPSetBlock: %v", err)
	}
	if !strings.Contains(setBlock, "Set-ItemProperty") {
		t.Error("set block must write values via Set-ItemProperty")
	}
	if strings.Contains(psNTPHeader, "/query /configuration") || strings.Contains(psNTPHeader, "/query /status") {
		t.Error("Read-NTPState must not parse w32tm /query /configuration or /status (localised output)")
	}
	if ntpExitRe.MatchString(psNTPHeader) || ntpExitRe.MatchString(ntpSetBody) || ntpExitRe.MatchString(ntpReadBody) {
		t.Error("NTP scripts must not contain an exit statement (shared session)")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestNTPRead_MapsPayload(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		if !strings.Contains(script, "Get-Service -Name W32Time") {
			return "", "", fmt.Errorf("preflight Get-Service check missing")
		}
		return ntpOK(t, ntpPayload(nil)), "", nil
	})
	defer restore()

	st, err := NewNTPClient(newNTPTestClient(t)).Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st.Type != "NTP" {
		t.Errorf("Type = %q", st.Type)
	}
	if len(st.Servers) != 2 || st.Servers[0].Address != "0.fr.pool.ntp.org" || st.Servers[0].Flags != "0x9" {
		t.Errorf("Servers = %+v", st.Servers)
	}
	if st.SpecialPollIntervalSeconds != 900 {
		t.Errorf("SpecialPollIntervalSeconds = %d", st.SpecialPollIntervalSeconds)
	}
	if st.Reliable {
		t.Error("Reliable must be false for AnnounceFlags 10")
	}
	if st.AnnounceFlags != 10 {
		t.Errorf("AnnounceFlags = %d", st.AnnounceFlags)
	}
	if st.CurrentSource == "" {
		t.Error("CurrentSource must be populated")
	}
	if st.PolicyOverride || st.DomainJoined || st.VmICEnabled {
		t.Error("policy/domain/vmic flags must be false in the base payload")
	}
	if st.MachineID == "" {
		t.Error("MachineID must be populated")
	}
	if st.ResyncWarning != "" {
		t.Error("Read must not carry a resync warning")
	}
}

func TestNTPRead_ServiceUnavailable(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return ntpErr(t, "service_unavailable", "W32Time service is not available on the target host", nil), "", nil
	})
	defer restore()

	_, err := NewNTPClient(newNTPTestClient(t)).Read(context.Background())
	if !errors.Is(err, ErrNTPServiceUnavailable) {
		t.Errorf("expected ErrNTPServiceUnavailable, got %v", err)
	}
}

func TestNTPRead_Timeout(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", context.DeadlineExceeded
	})
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	_, err := NewNTPClient(newNTPTestClient(t)).Read(ctx)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected a timeout error, got %v", err)
	}
}

func TestNTPRead_Transport(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "boom", fmt.Errorf("dial tcp: connection refused")
	})
	defer restore()

	_, err := NewNTPClient(newNTPTestClient(t)).Read(context.Background())
	if !errors.Is(err, ErrNTPUnknown) {
		t.Errorf("expected ErrNTPUnknown, got %v", err)
	}
}

func TestNTPRead_RemoteKindMapping(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want *NTPError
	}{
		{"service_unavailable", ErrNTPServiceUnavailable},
		{"access_denied", ErrNTPAccessDenied},
		{"invalid_peer", ErrNTPInvalidPeer},
		{"bogus_kind", ErrNTPUnknown},
	} {
		restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
			return ntpErr(t, tc.kind, "remote failure", nil), "", nil
		})
		_, err := NewNTPClient(newNTPTestClient(t)).Read(context.Background())
		restore()
		if !errors.Is(err, tc.want) {
			t.Errorf("kind %q: expected %v, got %v", tc.kind, tc.want, err)
		}
	}
}

func TestNTPRead_UnparseableHostPeersFailClosed(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return ntpOK(t, ntpPayload(map[string]any{"ntp_server": "host,0x0"})), "", nil
	})
	defer restore()

	_, err := NewNTPClient(newNTPTestClient(t)).Read(context.Background())
	if err == nil {
		t.Fatal("an unparseable host NtpServer value must fail closed, not silently drop peers")
	}
}

// ---------------------------------------------------------------------------
// Set
// ---------------------------------------------------------------------------

func ntpSetInput() NTPInput {
	poll := int64(900)
	reliable := false
	serverEnabled := false
	maxPos := int64(54000)
	maxNeg := int64(54000)
	return NTPInput{
		Type:                         "NTP",
		Servers:                      []NTPPeer{{Address: "0.fr.pool.ntp.org", Flags: "0x9"}},
		SpecialPollIntervalSeconds:   &poll,
		Reliable:                     &reliable,
		NtpServerEnabled:             &serverEnabled,
		MaxPosPhaseCorrectionSeconds: &maxPos,
		MaxNegPhaseCorrectionSeconds: &maxNeg,
		ManageService:                true,
		ResyncOnApply:                true,
	}
}

func TestNTPSet_ScriptShape(t *testing.T) {
	var got string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return ntpOK(t, ntpPayload(map[string]any{
			"ntp_server":            "0.fr.pool.ntp.org,0x9",
			"special_poll_interval": 900,
		})), "", nil
	})
	defer restore()

	if _, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), ntpSetInput()); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for _, want := range []string{
		"Set-Service -Name W32Time -StartupType Automatic",
		"Start-Service -Name W32Time",
		"Set-ItemProperty -Path $ParamsPath -Name Type -Value 'NTP'",
		"Set-ItemProperty -Path $ParamsPath -Name NtpServer -Value '0.fr.pool.ntp.org,0x9'",
		"Set-ItemProperty -Path $NtpClientPath -Name SpecialPollInterval -Value 900",
		"Set-ItemProperty -Path $ConfigPath -Name AnnounceFlags -Value 10",
		"Set-ItemProperty -Path $NtpServerPath -Name Enabled -Value 0",
		"Set-ItemProperty -Path $ConfigPath -Name MaxPosPhaseCorrection -Value 54000",
		"Set-ItemProperty -Path $ConfigPath -Name MaxNegPhaseCorrection -Value 54000",
		"w32tm /config /update",
		"w32tm /resync /rediscover",
		"$LASTEXITCODE",
		"'NTP'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("set script missing %q", want)
		}
	}
	if ntpExitRe.MatchString(got) {
		t.Error("set script must not contain an exit statement (shared session)")
	}
}

func TestNTPSet_ManageServiceFalseLeavesServiceUntouched(t *testing.T) {
	var got string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return ntpOK(t, ntpPayload(nil)), "", nil
	})
	defer restore()

	in := ntpSetInput()
	in.ManageService = false
	in.ResyncOnApply = false
	if _, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), in); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !strings.Contains(got, "$ManageService = $false") {
		t.Error("manage_service=false must render $ManageService = $false")
	}
	if strings.Contains(got, "Set-Service -Name W32Time") && strings.Contains(got, "$ManageService = $false") {
		// The Set-Service line only ever runs under `if ($ManageService)`;
		// assert the guard is present rather than the line being absent.
		if !strings.Contains(got, "if ($ManageService)") {
			t.Error("service ensure must be guarded by if ($ManageService)")
		}
	}
	if !strings.Contains(got, "$DoResync = $false") {
		t.Error("resync_on_apply=false must render $DoResync = $false")
	}
}

func TestNTPSet_OnlyConfiguredValuesWritten(t *testing.T) {
	var got string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return ntpOK(t, ntpPayload(map[string]any{
			"ntp_server":            "",
			"special_poll_interval": 3600,
		})), "", nil
	})
	defer restore()

	poll := int64(3600)
	in := NTPInput{Type: "NT5DS", SpecialPollIntervalSeconds: &poll}
	st, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), in)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if st.Type != "NTP" {
		t.Errorf("state must reflect the live host, got Type %q", st.Type)
	}
	for _, want := range []string{"-Name Type -Value 'NT5DS'", "-Name SpecialPollInterval -Value 3600"} {
		if !strings.Contains(got, want) {
			t.Errorf("set script missing %q", want)
		}
	}
	for _, absent := range []string{"-Name NtpServer", "AnnounceFlags -Value", "-Name Enabled -Value", "MaxPosPhaseCorrection -Value", "MaxNegPhaseCorrection -Value"} {
		if strings.Contains(got, absent) {
			t.Errorf("unmanaged value must not be written (found %q)", absent)
		}
	}
	if !strings.Contains(got, "$DesiredNtpServer = $null") {
		t.Error("unmanaged peers must render $DesiredNtpServer = $null so verify skips them")
	}
}

func TestNTPSet_AnnounceFlagsVerbatimBeatsReliable(t *testing.T) {
	var got string
	restore := stubRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return ntpOK(t, ntpPayload(map[string]any{"announce_flags": 5, "reliable": true})), "", nil
	})
	defer restore()

	reliable := false
	verbatim := int64(5)
	in := NTPInput{Type: "NTP", Servers: []NTPPeer{{Address: "h", Flags: "0x9"}}, Reliable: &reliable, AnnounceFlags: &verbatim}
	if _, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), in); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !strings.Contains(got, "AnnounceFlags -Value 5") {
		t.Error("verbatim AnnounceFlags must win over the Reliable mapping")
	}
	if !strings.Contains(got, "$DesiredAnnounce = 5") {
		t.Error("verify preamble must carry the verbatim AnnounceFlags")
	}
}

func TestNTPSet_VerifyMismatchErrors(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		// Host kept the old type: the static verify block rejects it.
		return ntpErr(t, "unknown", "W32Time change did not take effect: Type does not match the desired values",
			map[string]string{"step": "verify", "mismatched": "Type"}), "", nil
	})
	defer restore()

	if _, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), ntpSetInput()); !errors.Is(err, ErrNTPUnknown) {
		t.Errorf("verify mismatch should yield ErrNTPUnknown, got %v", err)
	}
}

func TestNTPSet_ResyncFailureIsWarningOnly(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		p := ntpPayload(map[string]any{
			"ntp_server":            "0.fr.pool.ntp.org,0x9",
			"special_poll_interval": 900,
		})
		p["resync_warning"] = "w32tm /resync /rediscover exited 1: No time data was available"
		return ntpOK(t, p), "", nil
	})
	defer restore()

	st, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), ntpSetInput())
	if err != nil {
		t.Fatalf("resync failure must not error, got %v", err)
	}
	if st.ResyncWarning == "" || !strings.Contains(st.ResyncWarning, "/resync") {
		t.Errorf("ResyncWarning must carry the failure, got %q", st.ResyncWarning)
	}
}

func TestNTPSet_InvalidPeerFailsClientSide(t *testing.T) {
	calls := 0
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return ntpOK(t, ntpPayload(nil)), "", nil
	})
	defer restore()

	in := ntpSetInput()
	in.Servers = []NTPPeer{{Address: "bad host", Flags: "0x9"}}
	if _, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), in); !errors.Is(err, ErrNTPInvalidPeer) {
		t.Errorf("bad peer should yield ErrNTPInvalidPeer, got %v", err)
	}
	if calls != 0 {
		t.Error("client-side peer rejection must not reach the host")
	}

	if _, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), NTPInput{Type: "NTP"}); !errors.Is(err, ErrNTPInvalidPeer) {
		t.Errorf("NTP without peers should yield ErrNTPInvalidPeer, got %v", err)
	}
}

func TestNTPSet_ServiceUnavailable(t *testing.T) {
	restore := stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return ntpErr(t, "service_unavailable", "W32Time service is not available", map[string]string{"step": "preflight"}), "", nil
	})
	defer restore()

	if _, err := NewNTPClient(newNTPTestClient(t)).Set(context.Background(), ntpSetInput()); !errors.Is(err, ErrNTPServiceUnavailable) {
		t.Errorf("expected ErrNTPServiceUnavailable, got %v", err)
	}
}

func TestNTPPayloadToState_ReliableMapping(t *testing.T) {
	st, err := ntpPayloadToState(ntpStatePayloadT(t, map[string]any{"announce_flags": 5, "reliable": true}))
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !st.Reliable || st.AnnounceFlags != 5 {
		t.Errorf("AnnounceFlags 5 must project reliable=true, got %+v", st)
	}
}

// ntpStatePayloadT remarshals a map payload through JSON into the typed
// struct (keeps the table small without duplicating field tags).
func ntpStatePayloadT(t *testing.T, overrides map[string]any) ntpStatePayload {
	t.Helper()
	raw, err := json.Marshal(ntpPayload(overrides))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var p ntpStatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return p
}
