// Package winclient — unit tests for HostnameClient.
//
// These tests stub the package-level seam runHostnamePowerShell to inject
// scripted stdout/stderr/err triples. They cover the documented edge cases
// from the windows_hostname spec:
//
//	EC-1  Invalid NetBIOS name              -> validateNetBIOS / invalid_name
//	EC-2  Idempotency at desired name       -> Create/Update no-op
//	EC-3  Pending rename surfaced           -> reboot_pending=true
//	EC-4  Permission denied                 -> permission_denied via Classify
//	EC-5  Domain-joined host                -> guardDomain / domain_joined
//	EC-6  WinRM unreachable / timeout       -> unreachable
//	EC-7  Delete is a no-op                 -> Delete returns nil
//	EC-10 Machine replaced                  -> machine_mismatch
//	EC-11 Concurrent external rename        -> concurrent_modification
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

func newHnTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:     "win01",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// stubHnRun replaces runHostnamePowerShell for the duration of a test and
// returns a restore function (typically deferred).
func stubHnRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runHostnamePowerShell
	runHostnamePowerShell = fn
	return func() { runHostnamePowerShell = prev }
}

// stubHnSequence stubs runHostnamePowerShell with a fixed list of
// (stdout, stderr, err) triples consumed in order. After the last triple,
// every subsequent call returns the last triple again. Use it for tests
// that emit several PowerShell calls (read + rename + re-read).
func stubHnSequence(triples ...[3]any) func() {
	i := 0
	return stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		t := triples[i]
		if i < len(triples)-1 {
			i++
		}
		var e error
		if t[2] != nil {
			e = t[2].(error)
		}
		return t[0].(string), t[1].(string), e
	})
}

func hnOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func hnErr(t *testing.T, kind, msg string) string {
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

func hnState(name, pending, guid string, domain bool, dom string) map[string]any {
	rp := !strings.EqualFold(name, pending)
	return map[string]any{
		"machine_id":     guid,
		"current_name":   name,
		"pending_name":   pending,
		"reboot_pending": rp,
		"part_of_domain": domain,
		"domain":         dom,
	}
}

// -----------------------------------------------------------------------------
// HostnameError type
// -----------------------------------------------------------------------------

func TestHostnameError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying-cause")
	e := NewHostnameError(HostnameErrorUnreachable, "transport failed", cause,
		map[string]string{"host": "win01"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "unreachable") || !strings.Contains(msg, "transport failed") ||
		!strings.Contains(msg, "underlying-cause") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewHostnameError(HostnameErrorInvalidName, "bad", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestHostnameError_Is_And_Helper(t *testing.T) {
	e := NewHostnameError(HostnameErrorDomainJoined, "x", nil, nil)
	if !errors.Is(e, ErrHostnameDomainJoined) {
		t.Error("errors.Is(ErrHostnameDomainJoined) should match by kind")
	}
	if errors.Is(e, ErrHostnamePermission) {
		t.Error("errors.Is across kinds must not match")
	}
	if !IsHostnameError(e, HostnameErrorDomainJoined) {
		t.Error("IsHostnameError should match")
	}
	if IsHostnameError(errors.New("plain"), HostnameErrorDomainJoined) {
		t.Error("IsHostnameError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-HostnameError should be false")
	}
}

func TestMapHostnameKind(t *testing.T) {
	cases := map[string]HostnameErrorKind{
		"invalid_name":            HostnameErrorInvalidName,
		"permission_denied":       HostnameErrorPermission,
		"domain_joined":           HostnameErrorDomainJoined,
		"unreachable":             HostnameErrorUnreachable,
		"machine_mismatch":        HostnameErrorMachineMismatch,
		"concurrent_modification": HostnameErrorConcurrent,
		"":                        HostnameErrorUnknown,
		"weird_kind":              HostnameErrorUnknown,
		"unknown":                 HostnameErrorUnknown,
	}
	for in, want := range cases {
		if got := mapHostnameKind(in); got != want {
			t.Errorf("mapHostnameKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// validateNetBIOS — EC-1
// -----------------------------------------------------------------------------

func TestValidateNetBIOS(t *testing.T) {
	valid := []string{"WIN01", "web-01", "a", "A1", "abcdefghijklmno" /* 15 */, "server-2025"}
	for _, n := range valid {
		if err := validateNetBIOS(n); err != nil {
			t.Errorf("validateNetBIOS(%q) unexpected err: %v", n, err)
		}
	}
	invalid := []string{
		"",                 // empty
		"abcdefghijklmnop", // 16 chars
		"-foo",             // leading hyphen
		"foo-",             // trailing hyphen
		"123",              // purely numeric
		"foo bar",          // space
		"foo_bar",          // underscore
		"foo.bar",          // dot
	}
	for _, n := range invalid {
		if err := validateNetBIOS(n); !IsHostnameError(err, HostnameErrorInvalidName) {
			t.Errorf("validateNetBIOS(%q) expected invalid_name, got %v", n, err)
		}
	}
}

// -----------------------------------------------------------------------------
// runHostnameEnvelope: timeout / transport / no JSON / bad JSON
// -----------------------------------------------------------------------------

func TestRunHostnameEnvelope_Timeout_EC6(t *testing.T) {
	restore := stubHnRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Read(ctx, "")
	if !IsHostnameError(err, HostnameErrorUnreachable) {
		t.Errorf("expected unreachable on cancelled ctx, got %v", err)
	}
}

func TestRunHostnameEnvelope_TransportError_EC6(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "junk-out", "junk-err", errors.New("winrm: tcp reset")
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Read(context.Background(), "")
	if !IsHostnameError(err, HostnameErrorUnreachable) {
		t.Errorf("expected unreachable on transport error, got %v", err)
	}
	var he *HostnameError
	if !errors.As(err, &he) {
		t.Fatal("expected *HostnameError")
	}
	if he.Context["host"] != "win01" {
		t.Errorf("context[host] = %q", he.Context["host"])
	}
	if _, ok := he.Context["transport"]; !ok {
		t.Error("context should include transport")
	}
}

func TestRunHostnameEnvelope_NoJSON(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "WARNING: nothing here\nfoo\n", "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Read(context.Background(), "")
	if !IsHostnameError(err, HostnameErrorUnknown) {
		t.Errorf("missing JSON envelope should yield unknown, got %v", err)
	}
}

func TestRunHostnameEnvelope_BadJSON(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{not-json\n", "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Read(context.Background(), "")
	if !IsHostnameError(err, HostnameErrorUnknown) {
		t.Errorf("malformed JSON envelope should yield unknown, got %v", err)
	}
}

func TestRunHostnameEnvelope_ClassifiedError_EC4(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return hnErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Read(context.Background(), "")
	if !IsHostnameError(err, HostnameErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestHostnameRead_HappyPath(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return hnOK(t, hnState("WIN01", "WIN01", "abc-123", false, "")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	st, err := h.Read(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if st.MachineID != "abc-123" || st.CurrentName != "WIN01" || st.PendingName != "WIN01" {
		t.Errorf("unexpected state: %+v", st)
	}
	if st.RebootPending {
		t.Error("reboot_pending should be false when current==pending")
	}
}

func TestHostnameRead_RebootPending_EC3(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return hnOK(t, hnState("WIN01", "WIN02", "abc-123", false, "")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	st, err := h.Read(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !st.RebootPending {
		t.Error("reboot_pending should be true when current!=pending")
	}
}

func TestHostnameRead_MachineMismatch_EC10(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return hnOK(t, hnState("WIN01", "WIN01", "different-guid", false, "")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Read(context.Background(), "original-guid")
	if !IsHostnameError(err, HostnameErrorMachineMismatch) {
		t.Errorf("expected machine_mismatch, got %v", err)
	}
}

func TestHostnameRead_EmptyIDSkipsGuard(t *testing.T) {
	// When id is empty (e.g. import flow), MachineGuid mismatch must NOT fire.
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return hnOK(t, hnState("WIN01", "WIN01", "any-guid", false, "")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	if _, err := h.Read(context.Background(), ""); err != nil {
		t.Errorf("empty id should not trigger mismatch: %v", err)
	}
}

func TestHostnameRead_BadDataPayload(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		// Valid envelope, but data is a string, not an object.
		return `{"ok":true,"data":"not-an-object"}` + "\n", "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Read(context.Background(), "")
	if !IsHostnameError(err, HostnameErrorUnknown) {
		t.Errorf("expected unknown for bad payload, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Create / Update — EC-1, EC-2, EC-5, EC-10, EC-11
// -----------------------------------------------------------------------------

func TestHostnameCreate_InvalidName_EC1(t *testing.T) {
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Create(context.Background(), HostnameInput{Name: ""})
	if !IsHostnameError(err, HostnameErrorInvalidName) {
		t.Errorf("empty name should be rejected, got %v", err)
	}
	_, err = h.Create(context.Background(), HostnameInput{Name: "123"})
	if !IsHostnameError(err, HostnameErrorInvalidName) {
		t.Errorf("purely numeric name should be rejected, got %v", err)
	}
	_, err = h.Create(context.Background(), HostnameInput{Name: "-bad"})
	if !IsHostnameError(err, HostnameErrorInvalidName) {
		t.Errorf("leading hyphen should be rejected, got %v", err)
	}
}

func TestHostnameCreate_DomainJoined_EC5(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return hnOK(t, hnState("WIN01", "WIN01", "guid", true, "corp.local")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Create(context.Background(), HostnameInput{Name: "WIN02"})
	if !IsHostnameError(err, HostnameErrorDomainJoined) {
		t.Errorf("expected domain_joined, got %v", err)
	}
	var he *HostnameError
	_ = errors.As(err, &he)
	if he == nil || he.Context["domain"] != "corp.local" {
		t.Errorf("domain context missing/wrong: %+v", he)
	}
}

func TestHostnameCreate_Idempotent_EC2(t *testing.T) {
	calls := 0
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return hnOK(t, hnState("WIN01", "WIN01", "guid", false, "")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	st, err := h.Create(context.Background(), HostnameInput{Name: "WIN01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if st.CurrentName != "WIN01" {
		t.Errorf("unexpected state: %+v", st)
	}
	if calls != 1 {
		t.Errorf("idempotent create should call PowerShell only once (read), got %d", calls)
	}
}

func TestHostnameCreate_RenameSuccess(t *testing.T) {
	restore := stubHnSequence(
		// 1) pre-rename read: current=OLD, pending=OLD
		[3]any{hnOK(t, hnState("OLDNAME", "OLDNAME", "guid", false, "")), "", nil},
		// 2) rename + read-back: pending=NEWNAME (reboot pending)
		[3]any{hnOK(t, hnState("OLDNAME", "NEWNAME", "guid", false, "")), "", nil},
	)
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	st, err := h.Create(context.Background(), HostnameInput{Name: "NEWNAME", Force: true})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !st.RebootPending {
		t.Error("reboot_pending should be true after rename")
	}
	if st.PendingName != "NEWNAME" || st.CurrentName != "OLDNAME" {
		t.Errorf("unexpected state: %+v", st)
	}
}

func TestHostnameCreate_ConcurrentRename_EC11(t *testing.T) {
	restore := stubHnSequence(
		// 1) pre-rename read: current=OLD, pending=OLD
		[3]any{hnOK(t, hnState("OLDNAME", "OLDNAME", "guid", false, "")), "", nil},
		// 2) rename + read-back: pending=ROGUE (someone else renamed)
		[3]any{hnOK(t, hnState("OLDNAME", "ROGUE", "guid", false, "")), "", nil},
	)
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Create(context.Background(), HostnameInput{Name: "NEWNAME"})
	if !IsHostnameError(err, HostnameErrorConcurrent) {
		t.Errorf("expected concurrent_modification, got %v", err)
	}
}

func TestHostnameCreate_RenamePermissionDenied_EC4(t *testing.T) {
	restore := stubHnSequence(
		[3]any{hnOK(t, hnState("OLDNAME", "OLDNAME", "guid", false, "")), "", nil},
		[3]any{hnErr(t, "permission_denied", "Access is denied (RenameComputerNotAuthorized)"), "", nil},
	)
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Create(context.Background(), HostnameInput{Name: "NEWNAME"})
	if !IsHostnameError(err, HostnameErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

func TestHostnameUpdate_MachineMismatch_EC10(t *testing.T) {
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return hnOK(t, hnState("WIN01", "WIN01", "new-guid", false, "")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Update(context.Background(), "original-guid", HostnameInput{Name: "WIN02"})
	if !IsHostnameError(err, HostnameErrorMachineMismatch) {
		t.Errorf("expected machine_mismatch on Update, got %v", err)
	}
}

func TestHostnameUpdate_Success(t *testing.T) {
	restore := stubHnSequence(
		[3]any{hnOK(t, hnState("OLD", "OLD", "guid", false, "")), "", nil},
		[3]any{hnOK(t, hnState("OLD", "NEW", "guid", false, "")), "", nil},
	)
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	st, err := h.Update(context.Background(), "guid", HostnameInput{Name: "NEW"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if st.PendingName != "NEW" {
		t.Errorf("unexpected state: %+v", st)
	}
}

func TestHostnameUpdate_BadDataPayload(t *testing.T) {
	// Pre-rename read OK; rename returns ok=true but data is malformed.
	restore := stubHnSequence(
		[3]any{hnOK(t, hnState("OLD", "OLD", "guid", false, "")), "", nil},
		[3]any{`{"ok":true,"data":"not-an-object"}` + "\n", "", nil},
	)
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	_, err := h.Update(context.Background(), "guid", HostnameInput{Name: "NEW"})
	if !IsHostnameError(err, HostnameErrorUnknown) {
		t.Errorf("expected unknown on malformed rename payload, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Delete — EC-7
// -----------------------------------------------------------------------------

func TestHostnameDelete_NoOp_EC7(t *testing.T) {
	calls := 0
	restore := stubHnRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		calls++
		return hnOK(t, hnState("WIN01", "WIN01", "guid", false, "")), "", nil
	})
	defer restore()
	h := NewHostnameClient(newHnTestClient(t))
	if err := h.Delete(context.Background(), "guid"); err != nil {
		t.Errorf("Delete must return nil; got %v", err)
	}
	if calls != 0 {
		t.Errorf("Delete must not invoke PowerShell; got %d calls", calls)
	}
}

// -----------------------------------------------------------------------------
// payloadToState — sanity
// -----------------------------------------------------------------------------

func TestPayloadToState(t *testing.T) {
	p := hostnameStatePayload{
		MachineID: "g", CurrentName: "a", PendingName: "b",
		RebootPending: true, PartOfDomain: true, Domain: "d",
	}
	s := payloadToState(p)
	if s.MachineID != "g" || s.CurrentName != "a" || s.PendingName != "b" ||
		!s.RebootPending || !s.PartOfDomain || s.Domain != "d" {
		t.Errorf("payloadToState mismatch: %+v", s)
	}
}
