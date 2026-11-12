// Package winclient — unit tests for TimezoneClient.
//
// These tests stub the package-level seam runTimezonePowerShell to inject
// scripted stdout/stderr/err triples and capture the emitted scripts. They
// cover:
//
//	Set idempotency            — matching live zone returns pre-set-read
//	Set-TimeZone path          — DST enabled writes via Set-TimeZone
//	tzutil path                — DST disabled writes via tzutil + _dstoff
//	$LASTEXITCODE gate         — tzutil failures never rely on stdout text
//	Suggestions                — invalid_timezone carries close matches
//	IANA rejection             — IDs containing "/" fail client-side
//	DST-disabled mapping       — DynamicDaylightTimeDisabled 0/1 -> bool
//	Offset formatting          — invariant "+HH:mm" base + current
//	tzautoupdate flag          — service Start mapping, best-effort
//	No exit                    — scripts never terminate the shared session
//	Classify/kind mapping      — envelope kinds to typed errors + timeout
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTzTestClient(t *testing.T) *Client {
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

// tzCall records one invocation of the stubbed runner.
type tzCall struct {
	script string
}

// stubTzRun replaces runTimezonePowerShell with fn and captures every
// script. It returns the captured calls and a restore function.
func stubTzRun(calls *[]tzCall, fn func(script string) (string, string, error)) func() {
	prev := runTimezonePowerShell
	runTimezonePowerShell = func(_ context.Context, _ *Client, script string) (string, string, error) {
		*calls = append(*calls, tzCall{script: script})
		return fn(script)
	}
	return func() { runTimezonePowerShell = prev }
}

func tzOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func tzErr(t *testing.T, kind, msg string, ctx map[string]string) string {
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

// tzPayload builds a Read-TimezoneState payload with the given overrides.
func tzPayload(overrides map[string]any) map[string]any {
	base := map[string]any{
		"machine_id":               "11111111-2222-3333-4444-555555555555",
		"timezone_id":              "Romance Standard Time",
		"display_name":             "(UTC+01:00) Brussels, Copenhagen, Madrid, Paris",
		"base_utc_offset":          "+01:00",
		"supports_dst":             true,
		"current_utc_offset":       "+02:00",
		"daylight_saving_disabled": false,
		"tzautoupdate_enabled":     false,
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

var tzExitRe = regexp.MustCompile(`(?m)^\s*exit(\s|;|$)`)

// ---------------------------------------------------------------------------
// Header invariants
// ---------------------------------------------------------------------------

func TestTimezoneHeader_Conventions(t *testing.T) {
	for _, want := range []string{
		"function Classify-Timezone",
		"InvariantCulture",
		"GetUtcOffset",
		"DynamicDaylightTimeDisabled",
		"tzautoupdate",
		"Get-TimeZone -ListAvailable",
		"function Emit-OK",
		"function Emit-Err",
	} {
		if !strings.Contains(psTimezoneHeader, want) {
			t.Errorf("psTimezoneHeader missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestTimezoneRead_MapsPayload(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(string) (string, string, error) {
		return tzOK(t, tzPayload(map[string]any{
			"daylight_saving_disabled": true,
			"tzautoupdate_enabled":     true,
			"base_utc_offset":          "-05:00",
			"current_utc_offset":       "-05:00",
		})), "", nil
	})()

	st, err := NewTimezoneClient(newTzTestClient(t)).Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st.TimezoneID != "Romance Standard Time" {
		t.Errorf("TimezoneID = %q", st.TimezoneID)
	}
	if st.DisplayName == "" {
		t.Error("DisplayName must be populated")
	}
	if st.BaseUTCOffset != "-05:00" {
		t.Errorf("BaseUTCOffset = %q, want -05:00", st.BaseUTCOffset)
	}
	if st.CurrentUTCOffset != "-05:00" {
		t.Errorf("CurrentUTCOffset = %q, want -05:00", st.CurrentUTCOffset)
	}
	if !st.SupportsDaylightSavingTime {
		t.Error("SupportsDaylightSavingTime must be true")
	}
	if !st.DaylightSavingDisabled {
		t.Error("DaylightSavingDisabled must be true (registry value 1)")
	}
	if !st.TzautoupdateEnabled {
		t.Error("TzautoupdateEnabled must be true")
	}
	if st.MachineID == "" {
		t.Error("MachineID must be populated")
	}
	for _, s := range calls {
		if tzExitRe.MatchString(s.script) {
			t.Error("read script must not contain an exit statement (shared session)")
		}
	}
}

func TestTimezoneRead_Timeout(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(string) (string, string, error) {
		return "", "", context.DeadlineExceeded
	})()

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	_, err := NewTimezoneClient(newTzTestClient(t)).Read(ctx)
	if !errors.Is(err, ErrTimezoneTimeout) {
		t.Errorf("expected ErrTimezoneTimeout, got %v", err)
	}
}

func TestTimezoneRead_Transport(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(string) (string, string, error) {
		return "", "boom", fmt.Errorf("dial tcp: connection refused")
	})()

	_, err := NewTimezoneClient(newTzTestClient(t)).Read(context.Background())
	if !errors.Is(err, ErrTimezoneUnknown) {
		t.Errorf("expected ErrTimezoneUnknown, got %v", err)
	}
}

func TestTimezoneRead_RemoteKindMapping(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want *TimezoneError
	}{
		{"invalid_timezone", ErrTimezoneInvalidTimezone},
		{"access_denied", ErrTimezoneAccessDenied},
		{"timeout", ErrTimezoneTimeout},
		{"bogus_kind", ErrTimezoneUnknown},
	} {
		var calls []tzCall
		restore := stubTzRun(&calls, func(string) (string, string, error) {
			return tzErr(t, tc.kind, "remote failure", nil), "", nil
		})
		_, err := NewTimezoneClient(newTzTestClient(t)).Read(context.Background())
		restore()
		if !errors.Is(err, tc.want) {
			t.Errorf("kind %q: expected %v, got %v", tc.kind, tc.want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Set
// ---------------------------------------------------------------------------

func TestTimezoneSet_Idempotent(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(string) (string, string, error) {
		return tzOK(t, tzPayload(nil)), "", nil
	})()

	st, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID: "romance standard time", // case-insensitive match
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if st.TimezoneID != "Romance Standard Time" {
		t.Errorf("TimezoneID = %q", st.TimezoneID)
	}
	if len(calls) != 1 {
		t.Errorf("idempotent Set must issue exactly the pre-set read, got %d calls", len(calls))
	}
}

func TestTimezoneSet_IdempotentDstDisabled(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(string) (string, string, error) {
		return tzOK(t, tzPayload(map[string]any{"daylight_saving_disabled": true})), "", nil
	})()

	_, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID:             "Romance Standard Time",
		DaylightSavingDisabled: true,
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("idempotent Set must issue exactly the pre-set read, got %d calls", len(calls))
	}
}

func TestTimezoneSet_UsesSetTimezone(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(script string) (string, string, error) {
		if strings.Contains(script, "Read-TimezoneState; Emit-OK") && !strings.Contains(script, "Set-TimeZone") {
			return tzOK(t, tzPayload(nil)), "", nil
		}
		return tzOK(t, tzPayload(nil)), "", nil
	})()

	_, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID: "UTC",
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected pre-set read + set, got %d calls", len(calls))
	}
	setScript := calls[1].script
	if !strings.Contains(setScript, "Set-TimeZone") {
		t.Error("DST-enabled Set must use Set-TimeZone")
	}
	if strings.Contains(setScript, "tzutil") {
		t.Error("DST-enabled Set must not invoke tzutil")
	}
	if !strings.Contains(setScript, "'UTC'") {
		t.Error("zone ID must be interpolated via psQuote")
	}
	if tzExitRe.MatchString(setScript) {
		t.Error("set script must not contain an exit statement (shared session)")
	}
}

func TestTimezoneSet_UsesTzutilWhenDstDisabled(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(script string) (string, string, error) {
		if strings.Contains(script, "tzutil.exe") {
			return tzOK(t, tzPayload(map[string]any{
				"timezone_id":              "Romance Standard Time_dstoff",
				"daylight_saving_disabled": true,
			})), "", nil
		}
		return tzOK(t, tzPayload(nil)), "", nil
	})()

	st, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID:             "Romance Standard Time",
		DaylightSavingDisabled: true,
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !st.DaylightSavingDisabled {
		t.Error("DaylightSavingDisabled must be true after tzutil apply")
	}
	if len(calls) != 2 {
		t.Fatalf("expected pre-set read + set, got %d calls", len(calls))
	}
	setScript := calls[1].script
	if !strings.Contains(setScript, "tzutil.exe") {
		t.Error("DST-disabled Set must invoke tzutil.exe")
	}
	if !strings.Contains(setScript, "_dstoff") {
		t.Error("DST-disabled Set must append the _dstoff suffix")
	}
	if !strings.Contains(setScript, "$LASTEXITCODE") {
		t.Error("tzutil failures must be gated on $LASTEXITCODE, never on localized stdout")
	}
	if strings.Contains(setScript, "Set-TimeZone") {
		t.Error("DST-disabled Set must not invoke Set-TimeZone")
	}
	if tzExitRe.MatchString(setScript) {
		t.Error("set script must not contain an exit statement (shared session)")
	}
}

func TestTimezoneSet_RejectsIANAClientSide(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(string) (string, string, error) {
		return tzOK(t, tzPayload(nil)), "", nil
	})()

	_, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID: "Europe/Paris",
	})
	if !errors.Is(err, ErrTimezoneInvalidTimezone) {
		t.Fatalf("expected ErrTimezoneInvalidTimezone, got %v", err)
	}
	if len(calls) != 0 {
		t.Error("client-side IANA rejection must not reach the host")
	}
}

func TestTimezoneSet_RejectsEmpty(t *testing.T) {
	_, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{})
	if !errors.Is(err, ErrTimezoneInvalidTimezone) {
		t.Fatalf("expected ErrTimezoneInvalidTimezone, got %v", err)
	}
}

func TestTimezoneSet_InvalidCarriesSuggestions(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(script string) (string, string, error) {
		if strings.Contains(script, "Set-TimeZone") {
			return tzErr(t, "invalid_timezone", "The time zone ID 'Romace' was not found on the local computer.",
				map[string]string{"desired": "Romace", "suggestions": "Romance Standard Time"}), "", nil
		}
		return tzOK(t, tzPayload(nil)), "", nil
	})()

	_, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID: "Romace",
	})
	if !errors.Is(err, ErrTimezoneInvalidTimezone) {
		t.Fatalf("expected ErrTimezoneInvalidTimezone, got %v", err)
	}
	var te *TimezoneError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TimezoneError, got %T", err)
	}
	if te.Context["suggestions"] != "Romance Standard Time" {
		t.Errorf("suggestions = %q, want close matches", te.Context["suggestions"])
	}
}

func TestTimezoneSet_AccessDenied(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(script string) (string, string, error) {
		if strings.Contains(script, "Set-TimeZone") {
			return tzErr(t, "access_denied", "Access is denied. (SeTimeZonePrivilege)", nil), "", nil
		}
		return tzOK(t, tzPayload(nil)), "", nil
	})()

	_, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID: "UTC",
	})
	if !errors.Is(err, ErrTimezoneAccessDenied) {
		t.Fatalf("expected ErrTimezoneAccessDenied, got %v", err)
	}
}

func TestTimezoneSet_PreReadFailurePropagates(t *testing.T) {
	var calls []tzCall
	defer stubTzRun(&calls, func(string) (string, string, error) {
		return "", "", fmt.Errorf("dial tcp: connection refused")
	})()

	_, err := NewTimezoneClient(newTzTestClient(t)).Set(context.Background(), TimezoneInput{
		TimezoneID: "UTC",
	})
	if !errors.Is(err, ErrTimezoneUnknown) {
		t.Fatalf("expected ErrTimezoneUnknown, got %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("failed pre-set read must not be followed by a set, got %d calls", len(calls))
	}
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

func TestNormalizeTimezoneID(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"Romance Standard Time", "Romance Standard Time"},
		{"Romance Standard Time_dstoff", "Romance Standard Time"},
		{"ROMANCE STANDARD TIME_DSTOFF", "ROMANCE STANDARD TIME"},
		{"UTC", "UTC"},
		{"", ""},
	} {
		if got := normalizeTimezoneID(tc.in); got != tc.want {
			t.Errorf("normalizeTimezoneID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMapTimezoneKind(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want TimezoneErrorKind
	}{
		{"invalid_timezone", TimezoneErrorInvalidTimezone},
		{"access_denied", TimezoneErrorAccessDenied},
		{"timeout", TimezoneErrorTimeout},
		{"unknown", TimezoneErrorUnknown},
		{"bogus", TimezoneErrorUnknown},
		{"", TimezoneErrorUnknown},
	} {
		if got := mapTimezoneKind(tc.in); got != tc.want {
			t.Errorf("mapTimezoneKind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTimezoneError_Is(t *testing.T) {
	if !errors.Is(NewTimezoneError(TimezoneErrorInvalidTimezone, "m", nil, nil), ErrTimezoneInvalidTimezone) {
		t.Error("Kind-only Is matching must hold for invalid_timezone")
	}
	if errors.Is(NewTimezoneError(TimezoneErrorUnknown, "m", nil, nil), ErrTimezoneAccessDenied) {
		t.Error("unknown must not match access_denied")
	}
	if !IsTimezoneError(NewTimezoneError(TimezoneErrorTimeout, "m", nil, nil), TimezoneErrorTimeout) {
		t.Error("IsTimezoneError must report timeout")
	}
}
