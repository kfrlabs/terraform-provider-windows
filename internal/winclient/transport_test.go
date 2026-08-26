package winclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Transport-level tests: a real SSH handshake against the in-process server in
// sshtest_test.go. Unlike the tests in auth_test.go, which check how a
// configuration is turned into callbacks, these prove that the resulting
// client actually connects — or actually refuses to.

const testTimeout = 10 * time.Second

// decodeUTF16LEBase64 reverses the wire encoding the bootstrap expects.
func decodeUTF16LEBase64(t *testing.T, s string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("UTF-16LE payload has odd length %d", len(raw))
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(units))
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

func mustRun(t *testing.T, c *Client, script string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stdout, stderr, err := c.RunPowerShell(ctx, script)
	if err != nil {
		t.Fatalf("RunPowerShell: %v (stderr=%q)", err, stderr)
	}
	return stdout, stderr
}

// A full round trip over public-key auth with the host key pinned: the case
// the provider should be steering everyone towards.
func TestTransportPublicKeyAuthWithPinnedHostKey(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: `{"ok":true}`})

	c, err := New(Config{
		Host:       "127.0.0.1",
		Port:       srv.Port,
		Username:   "tester",
		PrivateKey: string(keyPEM),
		HostKey:    srv.AuthorizedKeyLine(),
		Timeout:    testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stdout, _ := mustRun(t, c, "Get-Thing")
	if stdout != `{"ok":true}` {
		t.Errorf("stdout = %q", stdout)
	}
	if got := srv.AuthAttempts(); len(got) == 0 || got[len(got)-1] != "publickey" {
		t.Errorf("expected publickey to be the accepted method, attempts: %v", got)
	}
}

// The command line must stay the fixed bootstrap and the real script must
// arrive on stdin as UTF-16LE base64. Nothing covered this end to end before.
func TestTransportBootstrapPutsScriptOnStdin(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Non-ASCII on purpose: UTF-16LE fidelity is the reason for this encoding.
	script := "Write-Output 'héllo ✓'"
	mustRun(t, c, script)

	if cmd := srv.Command(); cmd != bootstrapCommand() {
		t.Errorf("command line drifted from the fixed bootstrap:\n got %q\nwant %q", cmd, bootstrapCommand())
	}
	if len(srv.Command()) > 1000 {
		t.Errorf("bootstrap command is %d chars; it must stay constant and small", len(srv.Command()))
	}

	firstLine, _, _ := strings.Cut(srv.Stdin(), "\n")
	if got := decodeUTF16LEBase64(t, strings.TrimRight(firstLine, "\r")); got != script {
		t.Errorf("script decoded from stdin = %q, want %q", got, script)
	}
	if strings.Contains(srv.Command(), "héllo") {
		t.Error("script body must not appear on the command line")
	}
}

// Secrets passed via RunPowerShellWithInput must travel on stdin, never on the
// command line where they could be captured by session logging.
func TestTransportSecretStaysOffCommandLine(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{authorizedKey: pub, stdout: "ok"})

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const secret = "correct-horse-battery-staple"
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, _, err := c.RunPowerShellWithInput(ctx, "Set-Password", secret); err != nil {
		t.Fatalf("RunPowerShellWithInput: %v", err)
	}

	if strings.Contains(srv.Command(), secret) {
		t.Error("secret leaked onto the command line")
	}
	if !strings.Contains(srv.Stdin(), secret) {
		t.Error("secret should have been delivered on stdin")
	}
}

func TestTransportPasswordAuth(t *testing.T) {
	noAgent(t)
	srv := startTestServer(t, testServerOptions{password: "s3cr3t", stdout: "ok"})

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		Password: "s3cr3t", HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM),
		HostKey:    string(ssh.MarshalAuthorizedKey(impostor)),
		Timeout:    testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

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
		c, err := New(Config{
			Host: "127.0.0.1", Port: srv.Port, Username: "tester",
			PrivateKey:     string(keyPEM),
			KnownHostsPath: knownHostsFile(t, srv.Addr, srv.HostKey),
			Timeout:        testTimeout,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
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

		c, err := New(Config{
			Host: "127.0.0.1", Port: srv.Port, Username: "tester",
			PrivateKey:     string(keyPEM),
			KnownHostsPath: knownHostsFile(t, srv.Addr, stale),
			Timeout:        testTimeout,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

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

		c, err := New(Config{
			Host: "127.0.0.1", Port: srv.Port, Username: "tester",
			PrivateKey: string(keyPEM), KnownHostsPath: empty, Timeout: testTimeout,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		_, _, err = c.RunPowerShell(ctx, "Get-Thing")
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

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), InsecureIgnoreHostKey: true, Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey:           string(pem.EncodeToMemory(block)),
		PrivateKeyPassphrase: "hunter2",
		HostKey:              srv.AuthorizedKeyLine(),
		Timeout:              testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(otherPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

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

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(otherPEM), Password: "s3cr3t",
		HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if stdout, _ := mustRun(t, c, "Get-Thing"); stdout != "ok" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestTransportNonZeroExitIsReported(t *testing.T) {
	noAgent(t)
	keyPEM, pub, _ := newClientKeypair(t)
	srv := startTestServer(t, testServerOptions{
		authorizedKey: pub,
		stderr:        "boom",
		exitStatus:    3,
	})

	c, err := New(Config{
		Host: "127.0.0.1", Port: srv.Port, Username: "tester",
		PrivateKey: string(keyPEM), HostKey: srv.AuthorizedKeyLine(), Timeout: testTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	_, stderr, err := c.RunPowerShell(ctx, "Get-Thing")
	if err == nil {
		t.Fatal("a non-zero exit status must surface as an error")
	}
	if !strings.Contains(err.Error(), "code 3") {
		t.Errorf("error should carry the exit code, got: %v", err)
	}
	if stderr != "boom" {
		t.Errorf("stderr = %q, want %q", stderr, "boom")
	}
}
