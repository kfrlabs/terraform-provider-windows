package winclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Transport-level tests: a real SSH handshake against the in-process server in
// sshtest_test.go. Unlike the tests in auth_test.go, which check how a
// configuration is turned into callbacks, these prove that the resulting
// client actually connects — or actually refuses to — and, since #81, that
// it correctly drives the persistent PowerShell REPL protocol.

const testTimeout = 10 * time.Second

// newTestClient builds a Client and registers its persistent session (if any
// gets established) to be closed at test end. Without this, a session left
// open forever blocks the in-process test server's per-connection goroutine
// on its next read, which in turn hangs startTestServer's cleanup.
func newTransportTestClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// knownHostsFile writes a known_hosts entry for addr and returns its path.
func knownHostsFile(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}

// mustRun runs script and trims the single trailing newline the REPL framing
// requires between real output and its end-of-response marker (real scripts
// already end their JSON envelope with WriteLine's own "\n"; canned test
// fixtures below deliberately don't include one, so this normalises both).
func mustRun(t *testing.T, c *Client, script string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stdout, stderr, err := c.RunPowerShell(ctx, script)
	if err != nil {
		t.Fatalf("RunPowerShell: %v (stderr=%q)", err, stderr)
	}
	return strings.TrimSuffix(stdout, "\n"), strings.TrimSuffix(stderr, "\n")
}

// A full round trip over public-key auth with the host key pinned: the case
// the provider should be steering everyone towards.
func TestTransportPublicKeyAuthWithPinnedHostKey(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: `{"ok":true}`})

	c := newTransportTestClient(t, Config{
		Host:       "127.0.0.1",
		Port:       srv.Port,
		Username:   "tester",
		PrivateKey: string(keyPEM),
		HostKey:    srv.AuthorizedKeyLine(),
		Timeout:    testTimeout,
	})

	stdout, _ := mustRun(t, c, "Get-Thing")
	if stdout != `{"ok":true}` {
		t.Errorf("stdout = %q", stdout)
	}
	if got := srv.AuthAttempts(); len(got) == 0 || got[len(got)-1] != "publickey" {
		t.Errorf("expected publickey to be the accepted method, attempts: %v", got)
	}
}

// The command line must stay the fixed REPL bootstrap and the real script
// must arrive on stdin as UTF-16LE base64, one request per call.
func TestTransportBootstrapPutsScriptOnStdin(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})

	// Non-ASCII on purpose: UTF-16LE fidelity is the reason for this encoding.
	script := "Write-Output 'héllo ✓'"
	mustRun(t, c, script)

	if cmd := srv.Command(); cmd != replBootstrapCommand() {
		t.Errorf("command line drifted from the fixed REPL bootstrap:\n got %q\nwant %q", cmd, replBootstrapCommand())
	}
	if len(srv.Command()) >= 4096 {
		t.Errorf("bootstrap command is %d chars; it must stay constant and well under Windows' ~8191-char limit", len(srv.Command()))
	}
	if strings.Contains(srv.Command(), "héllo") {
		t.Error("script body must not appear on the command line")
	}

	reqs := srv.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 REPL request, got %d", len(reqs))
	}
	if got := decodePowerShell(t, reqs[0].scriptB64); got != script {
		t.Errorf("script decoded from stdin = %q, want %q", got, script)
	}
}

// Secrets passed via RunPowerShellWithInput must travel on stdin, base64
// encoded, never on the command line where they could be captured by
// session logging.
func TestTransportSecretStaysOffCommandLine(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})

	const secret = "correct-horse-battery-staple"
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, _, err := c.RunPowerShellWithInput(ctx, "Set-Password", secret); err != nil {
		t.Fatalf("RunPowerShellWithInput: %v", err)
	}

	if strings.Contains(srv.Command(), secret) {
		t.Error("secret leaked onto the command line")
	}
	reqs := srv.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 REPL request, got %d", len(reqs))
	}
	gotSecret, err := decodeReplSecretForTest(reqs[0].secretB64)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if gotSecret != secret {
		t.Errorf("secret = %q, want %q", gotSecret, secret)
	}
}

func TestTransportPasswordAuth(t *testing.T) {
	noAgent(t)
	srv := startTestServer(t, testServerOptions{password: "s3cr3t", stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		Password: "s3cr3t", HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestTransportAgentAuth(t *testing.T) {
	_, pub, priv := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	// A keyring served over a unix socket: a real agent protocol exchange,
	// with no ssh-agent binary and no key on disk. Keep the socket path short,
	// since sun_path is capped around 104 bytes.
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sockPath := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: &priv}); err != nil {
		t.Fatalf("add key to keyring: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", sockPath)

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
		t.Errorf("stdout = %q", stdout)
	}
}

// The security-critical path: an impostor presenting a different host key must
// not be reachable, even though the credentials themselves are valid.
func TestTransportRejectsWrongPinnedHostKey(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	impostor, err := ssh.NewPublicKey(otherPub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM),
		HostKey:    string(ssh.MarshalAuthorizedKey(impostor)),
		Timeout:    testTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, _, err := c.RunPowerShell(ctx, "Get-Thing"); err == nil {
		t.Fatal("connection succeeded despite a host key that does not match the pin")
	}
}

func TestTransportKnownHosts(t *testing.T) {
	keyPEM, pub, _ := newClientKeypair(t)

	t.Run("listed host is accepted", func(t *testing.T) {
		noAgent(t)
		srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})
		c := newTransportTestClient(t, Config{
			Host: "127.0.0.1", Port: srv.Port, Username: "tester",
			PrivateKey:     string(keyPEM),
			KnownHostsPath: knownHostsFile(t, srv.Addr, srv.HostKey),
			Timeout:        testTimeout,
		})
		if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
			t.Errorf("stdout = %q", stdout)
		}
	})

	t.Run("changed key is reported as possible MITM", func(t *testing.T) {
		noAgent(t)
		srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

		// Same address, a key we never met: exactly the rebuilt-host or
		// interception scenario.
		staleKeyPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		stale, err := ssh.NewPublicKey(staleKeyPub)
		if err != nil {
			t.Fatalf("wrap key: %v", err)
		}

		c := newTransportTestClient(t, Config{
			Host: "127.0.0.1", Port: srv.Port, Username: "tester",
			PrivateKey:     string(keyPEM),
			KnownHostsPath: knownHostsFile(t, srv.Addr, stale),
			Timeout:        testTimeout,
		})

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		_, _, err = c.RunPowerShell(ctx, "Get-Thing")
		if err == nil {
			t.Fatal("a changed host key must abort the connection")
		}
		if !strings.Contains(err.Error(), "MISMATCH") {
			t.Errorf("error should flag the mismatch loudly, got: %v", err)
		}
	})

	t.Run("unlisted host is refused with guidance", func(t *testing.T) {
		noAgent(t)
		srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

		empty := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
			t.Fatalf("write known_hosts: %v", err)
		}

		c := newTransportTestClient(t, Config{
			Host: "127.0.0.1", Port: srv.Port, Username: "tester",
			PrivateKey: string(keyPEM), KnownHostsPath: empty, Timeout: testTimeout,
		})

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		_, _, err := c.RunPowerShell(ctx, "Get-Thing")
		if err == nil {
			t.Fatal("an unlisted host must be refused")
		}
		if strings.Contains(err.Error(), "MISMATCH") {
			t.Errorf("unknown host must not be reported as a mismatch: %v", err)
		}
		if !strings.Contains(err.Error(), "ssh-keyscan") {
			t.Errorf("error should say how to add the host, got: %v", err)
		}
	})
}

// The opt-out must genuinely connect, otherwise operators cannot fall back.
func TestTransportInsecureOptOutConnects(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), InsecureIgnoreHostKey: true, Timeout: testTimeout,
	})
	if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestTransportPassphraseProtectedKey(t *testing.T) {
	noAgent(t)
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(&privEd, "", []byte("hunter2"))
	if err != nil {
		t.Fatalf("marshal encrypted key: %v", err)
	}
	pub, err := ssh.NewPublicKey(pubEd)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey:           string(pem.EncodeToMemory(block)),
		PrivateKeyPassphrase: "hunter2",
		HostKey:              srv.AuthorizedKeyLine(),
		Timeout:              testTimeout,
	})
	if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
		t.Errorf("stdout = %q", stdout)
	}
}

// A key the server does not know must fail, rather than silently falling
// through to some other identity.
func TestTransportUnauthorizedKeyIsRejected(t *testing.T) {
	noAgent(t)
	_, serverKnownPub, _ := newClientKeypair(t)
	otherPEM, _, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: serverKnownPub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(otherPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, _, err := c.RunPowerShell(ctx, "Get-Thing"); err == nil {
		t.Fatal("an unauthorized key must not authenticate")
	}
}

// With both a key and a password configured, a server that refuses the key
// must still be reachable via the password.
func TestTransportFallsBackFromKeyToPassword(t *testing.T) {
	noAgent(t)
	otherPEM, _, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{password: "s3cr3t", stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(otherPEM), Password: "s3cr3t",
		HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
		t.Errorf("stdout = %q", stdout)
	}
}

// An uncaught PowerShell error is reported through the REPL's in-band status
// marker (there is no longer a process exit code to read, since the
// persistent session keeps running).
func TestTransportScriptErrorIsReported(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{
		authorizedKey: pub,
		stderr:        "boom",
		status:        1,
	})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	_, stderr, err := c.RunPowerShell(ctx, "Get-Thing")
	if err == nil {
		t.Fatal("an uncaught script error must surface as an error")
	}
	if strings.TrimSuffix(stderr, "\n") != "boom" {
		t.Errorf("stderr = %q, want %q", stderr, "boom")
	}
}

// Session reuse (#81): two calls in a row must not open a second SSH
// connection, and must both be served by the same REPL loop.
func TestTransportReusesSessionAcrossCalls(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})

	mustRun(t, c, "Get-Thing")
	mustRun(t, c, "Get-OtherThing")

	if got := srv.Connections(); got != 1 {
		t.Errorf("connections = %d, want 1 (session should be reused)", got)
	}
	if got := len(srv.Requests()); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
}

// Concurrent callers must be serialised onto the single persistent session
// rather than corrupting each other's request/response framing.
func TestTransportConcurrentCallsAreSerialised(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			stdout, _, err := c.RunPowerShell(ctx, "Get-Thing")
			if err != nil {
				errs <- err
				return
			}
			if strings.TrimSuffix(stdout, "\n") != "ok" {
				errs <- errors.New("stdout = " + stdout)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent RunPowerShell: %v", err)
	}

	if got := srv.Connections(); got != 1 {
		t.Errorf("connections = %d, want 1 (session should be reused under concurrency)", got)
	}
	if got := len(srv.Requests()); got != n {
		t.Errorf("requests = %d, want %d", got, n)
	}
}

// A session that dies mid-use (dropped connection, crashed remote process)
// must be transparently re-established rather than permanently failing every
// subsequent call.
func TestTransportRecoversFromDroppedSession(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{
		authorizedKey:  pub,
		stdout:         "ok",
		dropAfterCalls: 1, // the second request on a given connection is never answered
	})

	c := newTransportTestClient(t, Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})

	if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
		t.Fatalf("first call: stdout = %q", stdout)
	}
	// The server drops the connection after serving request 1 on it. This
	// second call must transparently reconnect and succeed rather than
	// surfacing the dropped session as an error.
	if stdout, _ := mustRun(t, c, "Get-OtherThing"); stdout != "ok" {
		t.Fatalf("second call: stdout = %q", stdout)
	}

	if got := srv.Connections(); got != 2 {
		t.Errorf("connections = %d, want 2 (one reconnect after the drop)", got)
	}
}

// decodeReplSecretForTest decodes a REPL request's raw base64 secret field
// (see encodeReplSecret) back to plaintext for assertions.
func decodeReplSecretForTest(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
