// Package winclient — unit tests for DomainMembershipClient.
//
// These tests stub the package-level seams runPowerShell (read path) and
// runPSInput (join/unjoin paths) to inject scripted stdout/stderr/err
// triples. They cover the domain-membership edge cases: already-joined and
// joined-to-other-domain pre-flights, Win32-code classification, secret
// hygiene (password on stdin, never in the script), the no-exit invariant
// (#81) and the deferred-reboot gate.
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func newDMTestClient(t *testing.T) *Client {
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

// stubDMRun replaces runPowerShell and runPSInput for the duration of a test,
// capturing the script and stdin the client sends.
func stubDMRun(t *testing.T, fn func(script, stdin string) (string, string, error)) (func(), *string, *string) {
	t.Helper()
	prevRun := runPowerShell
	prevInput := runPSInput
	var gotScript, gotStdin string
	runPowerShell = func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return fn(script, "")
	}
	runPSInput = func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		gotScript = script
		gotStdin = stdin
		return fn(script, stdin)
	}
	return func() {
		runPowerShell = prevRun
		runPSInput = prevInput
	}, &gotScript, &gotStdin
}

func dmOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func dmErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("marshal err: %v", err)
	}
	return string(b) + "\n"
}

func fakeDMState(domain string, partOfDomain bool) map[string]any {
	return map[string]any{
		"domain":            domain,
		"part_of_domain":    partOfDomain,
		"computer_name":     "WIN01",
		"pending_reboot":    false,
		"secure_channel_ok": partOfDomain,
	}
}

// -----------------------------------------------------------------------------
// DomainMembershipError type
// -----------------------------------------------------------------------------

func TestDomainMembershipError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	e := NewDomainMembershipError(DomainMembershipErrorTimeout, "join timed out", cause,
		map[string]string{"domain": "corp.example.com"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "timeout") || !strings.Contains(msg, "join timed out") ||
		!strings.Contains(msg, "underlying") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewDomainMembershipError(DomainMembershipErrorUnknown, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestDomainMembershipError_Is_And_IsDomainMembershipError(t *testing.T) {
	e := NewDomainMembershipError(DomainMembershipErrorBadCredentials, "x", nil, nil)
	if !errors.Is(e, ErrDomainMembershipBadCredentials) {
		t.Error("errors.Is must match by kind")
	}
	if errors.Is(e, ErrDomainMembershipDomainNotFound) {
		t.Error("errors.Is must not match a different kind")
	}
	if !IsDomainMembershipError(e, DomainMembershipErrorBadCredentials) {
		t.Error("IsDomainMembershipError must report the kind")
	}
	if IsDomainMembershipError(e, DomainMembershipErrorUnknown) {
		t.Error("IsDomainMembershipError must not report a different kind")
	}
	if IsDomainMembershipError(errors.New("plain"), DomainMembershipErrorUnknown) {
		t.Error("IsDomainMembershipError must be false for plain errors")
	}
}

// -----------------------------------------------------------------------------
// mapDomainMembershipKind
// -----------------------------------------------------------------------------

func TestMapDomainMembershipKind(t *testing.T) {
	cases := map[string]DomainMembershipErrorKind{
		"already_joined":         DomainMembershipErrorAlreadyJoined,
		"joined_to_other_domain": DomainMembershipErrorJoinedToOtherDomain,
		"domain_not_found":       DomainMembershipErrorDomainNotFound,
		"bad_credentials":        DomainMembershipErrorBadCredentials,
		"account_exists":         DomainMembershipErrorAccountExists,
		"ou_not_found":           DomainMembershipErrorOuNotFound,
		"access_denied":          DomainMembershipErrorAccessDenied,
		"reboot_pending":         DomainMembershipErrorRebootPending,
		"timeout":                DomainMembershipErrorTimeout,
		"invalid_parameter":      DomainMembershipErrorInvalidParameter,
		"bogus":                  DomainMembershipErrorUnknown,
		"":                       DomainMembershipErrorUnknown,
	}
	for in, want := range cases {
		if got := mapDomainMembershipKind(in); got != want {
			t.Errorf("mapDomainMembershipKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestDomainMembershipRead_HappyPath(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, fakeDMState("corp.example.com", true)), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, err := dm.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st.Domain != "corp.example.com" || !st.PartOfDomain {
		t.Errorf("unexpected state: %+v", st)
	}
	if st.ComputerName != "WIN01" {
		t.Errorf("ComputerName = %q, want WIN01", st.ComputerName)
	}
	if !st.SecureChannelOk {
		t.Error("SecureChannelOk should be true")
	}
}

func TestDomainMembershipRead_WorkgroupHost(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, fakeDMState("WORKGROUP", false)), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, err := dm.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st.PartOfDomain {
		t.Error("PartOfDomain should be false for a workgroup host")
	}
}

func TestDomainMembershipRead_TransportError(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return "", "boom", errors.New("winclient: powershell run: dial tcp: connection refused")
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, err := dm.Read(context.Background())
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsDomainMembershipError(err, DomainMembershipErrorUnknown) {
		t.Errorf("transport failure must map to unknown, got %v", err)
	}
}

func TestDomainMembershipRead_Timeout(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return "", "", context.DeadlineExceeded
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has passed
	_, err := dm.Read(ctx)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !IsDomainMembershipError(err, DomainMembershipErrorTimeout) {
		t.Errorf("cancelled context must map to timeout, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Join
// -----------------------------------------------------------------------------

func TestDomainMembershipJoin_HappyPath(t *testing.T) {
	c := newDMTestClient(t)
	restore, gotScript, gotStdin := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{
			"state":            fakeDMState("corp.example.com", true),
			"reboot_scheduled": false,
		}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, res, err := dm.Join(context.Background(), DomainJoinInput{
		Domain:   "corp.example.com",
		Username: "joiner@corp.example.com",
		Password: "S3cret!",
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if st == nil || st.Domain != "corp.example.com" || !st.PartOfDomain {
		t.Errorf("unexpected state: %+v", st)
	}
	if res == nil || res.RebootScheduled {
		t.Errorf("unexpected result: %+v", res)
	}
	// Secret hygiene: the password travels on stdin, never in the script.
	if strings.Contains(*gotScript, "S3cret!") {
		t.Error("join script must not contain the plaintext password")
	}
	if *gotStdin != "S3cret!\n" {
		t.Errorf("stdin = %q, want password plus newline", *gotStdin)
	}
}

func TestDomainMembershipJoin_AlreadyJoined(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmErr(t, "already_joined", "already joined"), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, _, err := dm.Join(context.Background(), DomainJoinInput{
		Domain: "corp.example.com", Username: "u", Password: "p",
	})
	if !IsDomainMembershipError(err, DomainMembershipErrorAlreadyJoined) {
		t.Errorf("want already_joined, got %v", err)
	}
}

func TestDomainMembershipJoin_JoinedToOtherDomain(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmErr(t, "joined_to_other_domain", "joined elsewhere"), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, _, err := dm.Join(context.Background(), DomainJoinInput{
		Domain: "corp.example.com", Username: "u", Password: "p",
	})
	if !IsDomainMembershipError(err, DomainMembershipErrorJoinedToOtherDomain) {
		t.Errorf("want joined_to_other_domain, got %v", err)
	}
}

func TestDomainMembershipJoin_BadCredentials(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmErr(t, "bad_credentials", "Logon failure (1326)"), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, _, err := dm.Join(context.Background(), DomainJoinInput{
		Domain: "corp.example.com", Username: "u", Password: "wrong",
	})
	if !IsDomainMembershipError(err, DomainMembershipErrorBadCredentials) {
		t.Errorf("want bad_credentials, got %v", err)
	}
}

func TestDomainMembershipJoin_Validation(t *testing.T) {
	dm := NewDomainMembershipClient(newDMTestClient(t))
	if _, _, err := dm.Join(context.Background(), DomainJoinInput{Username: "u"}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("empty domain must fail with invalid_parameter, got %v", err)
	}
	if _, _, err := dm.Join(context.Background(), DomainJoinInput{Domain: "corp.example.com"}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("empty username must fail with invalid_parameter, got %v", err)
	}
	if _, _, err := dm.Join(context.Background(), DomainJoinInput{Domain: "corp.example.com", Username: "u"}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("empty password must fail with invalid_parameter, got %v", err)
	}
	if _, _, err := dm.Join(context.Background(), DomainJoinInput{Domain: "corp.example.com", Username: "u", Password: "   "}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("whitespace password must fail with invalid_parameter, got %v", err)
	}
}

func TestDomainMembershipJoin_QuotesInjection(t *testing.T) {
	c := newDMTestClient(t)
	restore, gotScript, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{
			"state":            fakeDMState("corp.example.com", true),
			"reboot_scheduled": false,
		}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	evil := "corp.example.com'; Remove-Item C:\\ -Recurse -Force; '"
	_, _, err := dm.Join(context.Background(), DomainJoinInput{
		Domain: evil, OUPath: evil, Server: evil, Username: evil, Password: "p",
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	// psQuote doubles embedded quotes, so the payload cannot terminate the
	// literal. The raw unescaped payload must not appear verbatim.
	if strings.Contains(*gotScript, evil) {
		t.Error("unescaped user input found in join script")
	}
	if !strings.Contains(*gotScript, "''") {
		t.Error("expected doubled quotes from psQuote in join script")
	}
}

// TestDomainMembershipScripts_NeverExit guards the #81 invariant: scripts may
// run inside a reused PowerShell session, so "exit" would kill the session.
func TestDomainMembershipScripts_NeverExit(t *testing.T) {
	for name, body := range map[string]string{
		"header": psDomainMembershipHeader,
		"join":   psDomainJoinBody,
		"unjoin": psDomainUnjoinBody,
	} {
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(strings.ToLower(line))
			if trimmed == "exit" || strings.HasPrefix(trimmed, "exit ") ||
				strings.HasPrefix(trimmed, "exit;") || strings.HasPrefix(trimmed, "exit\t") {
				t.Errorf("%s body contains an exit statement: %q", name, line)
			}
		}
	}
}

// TestDomainMembershipJoin_DeferredRebootGate mirrors the windows_feature
// (#200) gate: shutdown.exe only when Restart was requested, with an
// explicit LASTEXITCODE check that never fails the join.
func TestDomainMembershipJoin_DeferredRebootGate(t *testing.T) {
	for _, body := range []string{psDomainJoinBody, psDomainUnjoinBody} {
		if !strings.Contains(body, "shutdown.exe /r /t 60") {
			t.Error("deferred reboot must use shutdown.exe /r /t 60")
		}
		if !strings.Contains(body, "$LASTEXITCODE -eq 0") {
			t.Error("deferred reboot must check $LASTEXITCODE explicitly")
		}
		if !strings.Contains(body, "-Restart") {
			t.Error("Add-Computer/Remove-Computer must never receive -Restart")
		}
	}
}

// -----------------------------------------------------------------------------
// Unjoin
// -----------------------------------------------------------------------------

func TestDomainMembershipUnjoin_HappyPath(t *testing.T) {
	c := newDMTestClient(t)
	restore, gotScript, gotStdin := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{
			"state":            fakeDMState("WORKGROUP", false),
			"already_absent":   false,
			"reboot_scheduled": true,
		}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	st, res, err := dm.Unjoin(context.Background(), DomainUnjoinInput{
		Username: "joiner@corp.example.com", Password: "S3cret!", WorkgroupName: "WORKGROUP",
	})
	if err != nil {
		t.Fatalf("Unjoin: %v", err)
	}
	if st == nil || st.PartOfDomain {
		t.Errorf("unexpected state: %+v", st)
	}
	if res == nil || res.AlreadyAbsent || !res.RebootScheduled {
		t.Errorf("unexpected result: %+v", res)
	}
	if strings.Contains(*gotScript, "S3cret!") {
		t.Error("unjoin script must not contain the plaintext password")
	}
	if *gotStdin != "S3cret!\n" {
		t.Errorf("stdin = %q, want password plus newline", *gotStdin)
	}
}

func TestDomainMembershipUnjoin_AlreadyAbsent(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{
			"state":            fakeDMState("WORKGROUP", false),
			"already_absent":   true,
			"reboot_scheduled": false,
		}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, res, err := dm.Unjoin(context.Background(), DomainUnjoinInput{
		Username: "u", Password: "p", WorkgroupName: "WORKGROUP",
	})
	if err != nil {
		t.Fatalf("Unjoin: %v", err)
	}
	if res == nil || !res.AlreadyAbsent {
		t.Errorf("want AlreadyAbsent=true, got %+v", res)
	}
}

func TestDomainMembershipUnjoin_Validation(t *testing.T) {
	dm := NewDomainMembershipClient(newDMTestClient(t))
	if _, _, err := dm.Unjoin(context.Background(), DomainUnjoinInput{Password: "p", WorkgroupName: "W"}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("empty username must fail with invalid_parameter, got %v", err)
	}
	if _, _, err := dm.Unjoin(context.Background(), DomainUnjoinInput{Username: "u", Password: "p"}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("empty workgroup must fail with invalid_parameter, got %v", err)
	}
	if _, _, err := dm.Unjoin(context.Background(), DomainUnjoinInput{Username: "u", WorkgroupName: "W"}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("empty password must fail with invalid_parameter, got %v", err)
	}
	if _, _, err := dm.Unjoin(context.Background(), DomainUnjoinInput{Username: "u", Password: "   ", WorkgroupName: "W"}); !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("whitespace password must fail with invalid_parameter, got %v", err)
	}
}

func TestDomainMembershipJoin_MissingState(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{"reboot_scheduled": false}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, _, err := dm.Join(context.Background(), DomainJoinInput{
		Domain: "corp.example.com", Username: "u", Password: "p",
	})
	if !IsDomainMembershipError(err, DomainMembershipErrorUnknown) {
		t.Fatalf("missing state must fail with unknown, got %v", err)
	}
	if !strings.Contains(err.Error(), "missing state in payload") {
		t.Errorf("error must mention the missing state, got %q", err.Error())
	}
}

func TestDomainMembershipUnjoin_MissingState(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmOK(t, map[string]any{"already_absent": false, "reboot_scheduled": false}), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, _, err := dm.Unjoin(context.Background(), DomainUnjoinInput{
		Username: "u", Password: "p", WorkgroupName: "WORKGROUP",
	})
	if !IsDomainMembershipError(err, DomainMembershipErrorUnknown) {
		t.Fatalf("missing state must fail with unknown, got %v", err)
	}
	if !strings.Contains(err.Error(), "missing state in payload") {
		t.Errorf("error must mention the missing state, got %q", err.Error())
	}
}

func TestDomainMembershipUnjoin_UnknownKindFallsThrough(t *testing.T) {
	c := newDMTestClient(t)
	restore, _, _ := stubDMRun(t, func(_, _ string) (string, string, error) {
		return dmErr(t, "weird_kind", "weird"), "", nil
	})
	defer restore()

	dm := NewDomainMembershipClient(c)
	_, _, err := dm.Unjoin(context.Background(), DomainUnjoinInput{
		Username: "u", Password: "p", WorkgroupName: "WORKGROUP",
	})
	if !IsDomainMembershipError(err, DomainMembershipErrorUnknown) {
		t.Errorf("unmapped kind must fall through to unknown, got %v", err)
	}
}
