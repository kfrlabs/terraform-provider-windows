// Package winclient — adversarial regression tests: newline-framed secrets
// must fail closed Go-side (campaign).
//
// Every secret streamed on stdin and consumed with [Console]::In.ReadLine()
// is framed by a trailing newline. An embedded \r or \n would silently
// truncate the secret host-side, so each entry point rejects line breaks
// before dialing, mirroring the DSC credential rule (ComposeDSCStdin):
// "must not contain carriage return or line feed characters: secrets are
// read with ReadLine()." No secret (or its length) may reach error context.
package winclient

import (
	"context"
	"strings"
	"testing"
	"time"
)

func newSecretRegressionClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:                  "winsecret01",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func assertLineBreakRejected(t *testing.T, err error, secret string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a line-break rejection error, got nil")
	}
	if !strings.Contains(err.Error(), "carriage return or line feed") ||
		!strings.Contains(err.Error(), "ReadLine") {
		t.Errorf("error should mirror the DSC credential message, got: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error must not contain the secret, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// local_user
// ---------------------------------------------------------------------------

func TestLocalUserCreate_RejectsNewlinePassword(t *testing.T) {
	lc := &LocalUserClientImpl{c: newSecretRegressionClient(t)}
	for _, pw := range []string{"a\nb", "a\rb", "a\r\nb", "trailing\n"} {
		_, err := lc.Create(context.Background(), UserInput{Name: "alice", Enabled: true}, pw)
		assertLineBreakRejected(t, err, pw)
		if !IsLocalUserError(err, LocalUserErrorInvalidParameter) {
			t.Errorf("password %q: expected invalid_parameter, got: %v", pw, err)
		}
	}
}

func TestLocalUserSetPassword_RejectsNewlinePassword(t *testing.T) {
	lc := &LocalUserClientImpl{c: newSecretRegressionClient(t)}
	for _, pw := range []string{"a\nb", "a\rb"} {
		err := lc.SetPassword(context.Background(), "S-1-5-21-1-2-3-1001", pw)
		assertLineBreakRejected(t, err, pw)
		if !IsLocalUserError(err, LocalUserErrorInvalidParameter) {
			t.Errorf("password %q: expected invalid_parameter, got: %v", pw, err)
		}
	}
}

func TestLocalUserCreate_ScriptHasNoPwlen(t *testing.T) {
	lc := &LocalUserClientImpl{c: newSecretRegressionClient(t)}
	prev := runPSInput
	defer func() { runPSInput = prev }()
	var gotScript string
	dialed := false
	runPSInput = func(_ context.Context, _ *Client, script, _ string) (string, string, error) {
		dialed = true
		gotScript = script
		return luErr(t, "password_policy", "does not meet complexity"), "", nil
	}
	_, err := lc.Create(context.Background(), UserInput{Name: "u", Enabled: true}, "clean-password-123!")
	if err == nil {
		t.Fatal("expected password_policy error")
	}
	if !dialed {
		t.Fatal("expected the runner to be dialed for a clean password")
	}
	if strings.Contains(gotScript, "pwlen") {
		t.Errorf("create script must not contain pwlen (password length leaks into context)")
	}
	if le, ok := err.(*LocalUserError); ok {
		for k, v := range le.Context {
			if k == "pwlen" || strings.Contains(v, "pwlen") {
				t.Errorf("error context must not contain pwlen: %q=%q", k, v)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// domain_membership
// ---------------------------------------------------------------------------

func TestDomainJoin_RejectsNewlinePassword(t *testing.T) {
	d := &DomainMembershipClient{c: newSecretRegressionClient(t)}
	_, _, err := d.Join(context.Background(), DomainJoinInput{
		Domain: "corp.example.com", Username: "u", Password: "a\nb",
	})
	assertLineBreakRejected(t, err, "a\nb")
	if !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("expected invalid_parameter, got: %v", err)
	}
}

func TestDomainUnjoin_RejectsNewlinePassword(t *testing.T) {
	d := &DomainMembershipClient{c: newSecretRegressionClient(t)}
	_, _, err := d.Unjoin(context.Background(), DomainUnjoinInput{
		Username: "u", Password: "a\rb", WorkgroupName: "WORKGROUP",
	})
	assertLineBreakRejected(t, err, "a\rb")
	if !IsDomainMembershipError(err, DomainMembershipErrorInvalidParameter) {
		t.Errorf("expected invalid_parameter, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// scheduled_task
// ---------------------------------------------------------------------------

func strptr(s string) *string { return &s }

func TestScheduledTaskCreate_RejectsNewlinePassword(t *testing.T) {
	c := &ScheduledTaskClientImpl{c: newSecretRegressionClient(t)}
	in := ScheduledTaskInput{
		Name: "t", Path: `\`,
		Principal: &ScheduledTaskPrincipalInput{UserID: "u", Password: strptr("a\nb")},
	}
	_, err := c.Create(context.Background(), in)
	assertLineBreakRejected(t, err, "a\nb")
	if !IsScheduledTaskError(err, ScheduledTaskErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

func TestScheduledTaskUpdate_RejectsNewlinePassword(t *testing.T) {
	c := &ScheduledTaskClientImpl{c: newSecretRegressionClient(t)}
	in := ScheduledTaskInput{
		Name: "t", Path: `\`,
		Principal: &ScheduledTaskPrincipalInput{UserID: "u", Password: strptr("a\rb")},
	}
	_, err := c.Update(context.Background(), `\t`, in)
	assertLineBreakRejected(t, err, "a\rb")
	if !IsScheduledTaskError(err, ScheduledTaskErrorInvalidInput) {
		t.Errorf("expected invalid_input, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// iis_app_pool
// ---------------------------------------------------------------------------

func TestIISAppPoolCreate_RejectsNewlinePassword(t *testing.T) {
	a := &IISAppPoolClient{c: newSecretRegressionClient(t)}
	_, err := a.Create(context.Background(), IISAppPoolInput{Name: "TestPool1", Password: "a\nb"})
	assertLineBreakRejected(t, err, "a\nb")
}

func TestIISAppPoolUpdate_RejectsNewlinePassword(t *testing.T) {
	a := &IISAppPoolClient{c: newSecretRegressionClient(t)}
	_, err := a.Update(context.Background(), IISAppPoolInput{Name: "TestPool1", Password: "a\rb"})
	assertLineBreakRejected(t, err, "a\rb")
}

// ---------------------------------------------------------------------------
// certificate (PFX password is framed by newline: password + "\n" + b64)
// ---------------------------------------------------------------------------

func TestCertificateCreate_RejectsNewlinePassword(t *testing.T) {
	n := &CertificateClientImpl{c: newSecretRegressionClient(t)}
	for _, pw := range []string{"a\nb", "a\rb"} {
		pwCopy := pw
		_, err := n.Create(context.Background(), CertificateInput{
			StoreLocation: CertificateStoreLocalMachine,
			StoreName:     "My",
			PFXBase64:     "eA==",
			PFXPassword:   &pwCopy,
		})
		assertLineBreakRejected(t, err, pw)
	}
}
