package winclient

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// newTestKey returns a fresh ed25519 keypair as an unencrypted PEM private key
// plus its authorized_keys-form public key.
func newTestKey(t *testing.T) (privPEM []byte, authorizedKey string, pub ssh.PublicKey) {
	t.Helper()
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(&privEd, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pubEd)
	if err != nil {
		t.Fatalf("wrap public key: %v", err)
	}
	return pem.EncodeToMemory(block), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), sshPub
}

// noAgent makes agent auto-detection deterministic: without this the result
// depends on whether the developer's shell happens to run an ssh-agent.
func noAgent(t *testing.T) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
}

// setHome points os.UserHomeDir at dir. It sets USERPROFILE as well as HOME
// because os.UserHomeDir reads USERPROFILE on Windows, and these tests must
// not fall through to the real developer's ~/.ssh/known_hosts on any platform.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func TestBuildAuthMethodsPasswordOnly(t *testing.T) {
	noAgent(t)
	methods, _, err := buildAuthMethods(Config{Password: "s3cr3t"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("got %d auth methods, want 1", len(methods))
	}
}

func TestBuildAuthMethodsPrivateKeyPEM(t *testing.T) {
	noAgent(t)
	privPEM, _, _ := newTestKey(t)
	methods, _, err := buildAuthMethods(Config{PrivateKey: string(privPEM)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("got %d auth methods, want 1", len(methods))
	}
}

func TestBuildAuthMethodsPrivateKeyPath(t *testing.T) {
	noAgent(t)
	privPEM, _, _ := newTestKey(t)
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, privPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	methods, _, err := buildAuthMethods(Config{PrivateKeyPath: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("got %d auth methods, want 1", len(methods))
	}
}

// Key before password: a server configured for publickey must not be handed
// the password first.
func TestBuildAuthMethodsKeyPrecedesPassword(t *testing.T) {
	noAgent(t)
	privPEM, _, _ := newTestKey(t)
	methods, _, err := buildAuthMethods(Config{PrivateKey: string(privPEM), Password: "s3cr3t"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("got %d auth methods, want 2", len(methods))
	}
}

func TestBuildAuthMethodsRejectsNoCredentials(t *testing.T) {
	noAgent(t)
	if _, _, err := buildAuthMethods(Config{}); err == nil {
		t.Fatal("expected an error when no authentication method is configured")
	}
}

func TestBuildAuthMethodsRejectsBothKeyForms(t *testing.T) {
	noAgent(t)
	privPEM, _, _ := newTestKey(t)
	_, _, err := buildAuthMethods(Config{PrivateKey: string(privPEM), PrivateKeyPath: "/tmp/whatever"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestPrivateKeyPassphrase(t *testing.T) {
	pubEd, privEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = pubEd
	block, err := ssh.MarshalPrivateKeyWithPassphrase(&privEd, "", []byte("hunter2"))
	if err != nil {
		t.Fatalf("marshal encrypted key: %v", err)
	}
	encrypted := string(pem.EncodeToMemory(block))

	t.Run("correct passphrase", func(t *testing.T) {
		signer, err := privateKeySigner(Config{PrivateKey: encrypted, PrivateKeyPassphrase: "hunter2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if signer == nil {
			t.Fatal("expected a signer")
		}
	})

	// The bare "ssh: this private key is passphrase protected" is opaque;
	// the operator needs to be told which knob to reach for.
	t.Run("missing passphrase is actionable", func(t *testing.T) {
		_, err := privateKeySigner(Config{PrivateKey: encrypted})
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "private_key_passphrase") {
			t.Errorf("error should name private_key_passphrase, got: %v", err)
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		if _, err := privateKeySigner(Config{PrivateKey: encrypted, PrivateKeyPassphrase: "wrong"}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// A parse failure must never echo the key itself into Terraform's logs.
func TestPrivateKeyErrorsDoNotLeakMaterial(t *testing.T) {
	privPEM, _, _ := newTestKey(t)
	truncated := string(privPEM[:len(privPEM)/2])
	_, err := privateKeySigner(Config{PrivateKey: truncated})
	if err == nil {
		t.Fatal("expected a parse error")
	}
	for _, line := range strings.Split(truncated, "\n") {
		body := strings.TrimSpace(line)
		if len(body) < 20 || strings.HasPrefix(body, "-----") {
			continue
		}
		if strings.Contains(err.Error(), body) {
			t.Fatalf("error message leaks private key material: %v", err)
		}
	}
}

func TestParseHostKey(t *testing.T) {
	_, authorizedKey, pub := newTestKey(t)

	t.Run("authorized_keys form", func(t *testing.T) {
		got, err := parseHostKey(authorizedKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got.Marshal()) != string(pub.Marshal()) {
			t.Error("parsed key does not match the original")
		}
	})

	// ssh-keyscan output pasted verbatim, host field included.
	t.Run("known_hosts line", func(t *testing.T) {
		got, err := parseHostKey("192.0.2.10 " + authorizedKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got.Marshal()) != string(pub.Marshal()) {
			t.Error("parsed key does not match the original")
		}
	})

	t.Run("surrounding whitespace", func(t *testing.T) {
		if _, err := parseHostKey("\n  " + authorizedKey + "  \n"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, bad := range []string{"", "not-a-key", "ssh-ed25519 !!!notbase64!!!"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			if _, err := parseHostKey(bad); err == nil {
				t.Fatalf("expected an error for %q", bad)
			}
		})
	}
}

// The default must verify. A Config with no host-key settings and no
// known_hosts file must fail closed rather than connect blindly.
func TestHostKeyCallbackFailsClosedByDefault(t *testing.T) {
	setHome(t, t.TempDir())
	_, _, err := hostKeyCallback(Config{Host: "192.0.2.10"})
	if err == nil {
		t.Fatal("expected an error when no known_hosts file exists")
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") || !strings.Contains(err.Error(), "host_key") {
		t.Errorf("error should tell the operator how to fix it, got: %v", err)
	}
}

func TestHostKeyCallbackPinnedKey(t *testing.T) {
	_, authorizedKey, pub := newTestKey(t)
	cb, algos, err := hostKeyCallback(Config{HostKey: authorizedKey})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(algos) != 1 || algos[0] != "ssh-ed25519" {
		t.Errorf("pinned ed25519 should restrict negotiation to ssh-ed25519, got %v", algos)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	if err := cb("192.0.2.10:22", addr, pub); err != nil {
		t.Errorf("pinned key should be accepted: %v", err)
	}

	_, _, other := newTestKey(t)
	if err := cb("192.0.2.10:22", addr, other); err == nil {
		t.Error("a different host key must be rejected")
	}
}

func TestHostKeyCallbackRejectsAmbiguousConfig(t *testing.T) {
	_, authorizedKey, _ := newTestKey(t)
	cases := map[string]Config{
		"host_key and known_hosts_path": {HostKey: authorizedKey, KnownHostsPath: "/tmp/known_hosts"},
		"insecure and host_key":         {InsecureIgnoreHostKey: BoolPtr(true), HostKey: authorizedKey},
		"insecure and known_hosts_path": {InsecureIgnoreHostKey: BoolPtr(true), KnownHostsPath: "/tmp/known_hosts"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := hostKeyCallback(cfg); err == nil {
				t.Fatal("expected a configuration error")
			}
		})
	}
}

func TestHostKeyCallbackInsecureOptOut(t *testing.T) {
	cb, algos, err := hostKeyCallback(Config{InsecureIgnoreHostKey: BoolPtr(true)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(algos) != 0 {
		t.Errorf("opt-out must not restrict algorithms, got %v", algos)
	}
	_, _, pub := newTestKey(t)
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	if err := cb("192.0.2.10:22", addr, pub); err != nil {
		t.Errorf("opt-out should accept any key: %v", err)
	}
}

func TestKnownHostsVerification(t *testing.T) {
	_, trustedAuthorizedKey, trustedPub := newTestKey(t)
	_, _, impostorPub := newTestKey(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, []byte("[192.0.2.10]:22 "+trustedAuthorizedKey+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cb, _, err := hostKeyCallback(Config{KnownHostsPath: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}

	t.Run("known host accepted", func(t *testing.T) {
		if err := cb("192.0.2.10:22", addr, trustedPub); err != nil {
			t.Errorf("trusted key should be accepted: %v", err)
		}
	})

	// The security-critical case: right host, wrong key.
	t.Run("mismatch is flagged as possible MITM", func(t *testing.T) {
		err := cb("192.0.2.10:22", addr, impostorPub)
		if err == nil {
			t.Fatal("a mismatched host key must be rejected")
		}
		if !strings.Contains(err.Error(), "MISMATCH") {
			t.Errorf("error should flag the mismatch loudly, got: %v", err)
		}
		if !strings.Contains(err.Error(), "man-in-the-middle") {
			t.Errorf("error should name the risk, got: %v", err)
		}
	})

	t.Run("unknown host is distinguished from mismatch", func(t *testing.T) {
		otherAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 22}
		err := cb("192.0.2.99:22", otherAddr, trustedPub)
		if err == nil {
			t.Fatal("an unlisted host must be rejected")
		}
		if strings.Contains(err.Error(), "MISMATCH") {
			t.Errorf("unknown host must not be reported as a mismatch, got: %v", err)
		}
		if !strings.Contains(err.Error(), "ssh-keyscan") {
			t.Errorf("error should tell the operator how to add the host, got: %v", err)
		}
	})
}

func TestResolveKnownHostsRejectsMissingExplicitFile(t *testing.T) {
	_, _, err := hostKeyCallback(Config{KnownHostsPath: filepath.Join(t.TempDir(), "absent")})
	if err == nil {
		t.Fatal("expected an error for a known_hosts path that does not exist")
	}
}

func TestAgentRequested(t *testing.T) {
	yes, no := true, false

	t.Run("explicit true wins over absent socket", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", "")
		if !agentRequested(Config{UseAgent: &yes}) {
			t.Error("explicit use_agent=true should request the agent")
		}
	})
	t.Run("explicit false wins over present socket", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
		if agentRequested(Config{UseAgent: &no}) {
			t.Error("explicit use_agent=false should not request the agent")
		}
	})
	t.Run("auto-detects from socket", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
		if !agentRequested(Config{}) {
			t.Error("agent should be auto-detected when SSH_AUTH_SOCK is set")
		}
		t.Setenv("SSH_AUTH_SOCK", "")
		if agentRequested(Config{}) {
			t.Error("agent should not be used when SSH_AUTH_SOCK is empty")
		}
	})
}

// An explicitly requested agent that cannot be reached is a configuration
// error; an auto-detected one that is unreachable is merely skipped.
func TestBuildAuthMethodsAgentFailureHandling(t *testing.T) {
	yes := true
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing.sock"))

	if _, _, err := buildAuthMethods(Config{UseAgent: &yes, Password: "p"}); err == nil {
		t.Error("explicitly requested but broken agent should error")
	}

	methods, _, err := buildAuthMethods(Config{Password: "p"})
	if err != nil {
		t.Fatalf("auto-detected broken agent should be skipped, got: %v", err)
	}
	if len(methods) != 1 {
		t.Errorf("got %d auth methods, want 1 (password only)", len(methods))
	}
}

func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	cases := map[string]string{
		"~":                filepath.Join(home),
		"~/.ssh/id_ed2551": filepath.Join(home, ".ssh", "id_ed2551"),
		"/etc/keys/id":     "/etc/keys/id",
		"relative/path":    "relative/path",
	}
	for in, want := range cases {
		got, err := expandHome(in)
		if err != nil {
			t.Fatalf("expandHome(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveFromEnvNewFields(t *testing.T) {
	t.Setenv(EnvPrivateKey, "PEM-BODY")
	t.Setenv(EnvPrivateKeyPath, "/keys/id_ed25519")
	t.Setenv(EnvPrivateKeyPassphrase, "hunter2")
	t.Setenv(EnvKnownHosts, "/etc/ssh/known_hosts")
	t.Setenv(EnvHostKey, "ssh-ed25519 AAAA")
	t.Setenv(EnvUseAgent, "true")
	t.Setenv(EnvInsecureIgnoreHostKey, "true")

	var cfg Config
	if err := ResolveFromEnv(&cfg); err != nil {
		t.Fatalf("ResolveFromEnv: %v", err)
	}

	if cfg.PrivateKey != "PEM-BODY" {
		t.Errorf("PrivateKey = %q", cfg.PrivateKey)
	}
	if cfg.PrivateKeyPath != "/keys/id_ed25519" {
		t.Errorf("PrivateKeyPath = %q", cfg.PrivateKeyPath)
	}
	if cfg.PrivateKeyPassphrase != "hunter2" {
		t.Errorf("PrivateKeyPassphrase = %q", cfg.PrivateKeyPassphrase)
	}
	if cfg.KnownHostsPath != "/etc/ssh/known_hosts" {
		t.Errorf("KnownHostsPath = %q", cfg.KnownHostsPath)
	}
	if cfg.HostKey != "ssh-ed25519 AAAA" {
		t.Errorf("HostKey = %q", cfg.HostKey)
	}
	if cfg.UseAgent == nil || !*cfg.UseAgent {
		t.Error("UseAgent should be true")
	}
	if cfg.InsecureIgnoreHostKey == nil || !*cfg.InsecureIgnoreHostKey {
		t.Error("InsecureIgnoreHostKey should be true")
	}
}

// Explicit configuration must win over the environment.
func TestResolveFromEnvDoesNotOverrideExplicitValues(t *testing.T) {
	t.Setenv(EnvPrivateKey, "from-env")
	t.Setenv(EnvUseAgent, "true")
	t.Setenv(EnvInsecureIgnoreHostKey, "true")

	no := false
	cfg := Config{PrivateKey: "from-config", UseAgent: &no, InsecureIgnoreHostKey: &no}
	if err := ResolveFromEnv(&cfg); err != nil {
		t.Fatalf("ResolveFromEnv: %v", err)
	}

	if cfg.PrivateKey != "from-config" {
		t.Errorf("PrivateKey = %q, want from-config", cfg.PrivateKey)
	}
	if cfg.UseAgent == nil || *cfg.UseAgent {
		t.Error("explicit UseAgent=false must survive ResolveFromEnv")
	}
	if cfg.InsecureIgnoreHostKey == nil || *cfg.InsecureIgnoreHostKey {
		t.Error("explicit InsecureIgnoreHostKey=false must survive ResolveFromEnv")
	}
}

// WINDOWS_PORT fills in only when no port was configured. A set-but-malformed
// or out-of-range value is an error rather than a silent fallback to 22, and
// an explicit port wins even over a malformed variable.
func TestResolveFromEnvPort(t *testing.T) {
	t.Run("fills empty port", func(t *testing.T) {
		t.Setenv(EnvPort, "2222")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("ResolveFromEnv: %v", err)
		}
		if cfg.Port != 2222 {
			t.Errorf("Port = %d, want 2222", cfg.Port)
		}
	})

	t.Run("explicit port wins", func(t *testing.T) {
		t.Setenv(EnvPort, "2222")
		cfg := Config{Port: 2200}
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("ResolveFromEnv: %v", err)
		}
		if cfg.Port != 2200 {
			t.Errorf("Port = %d, want the explicit 2200", cfg.Port)
		}
	})

	t.Run("explicit port wins over malformed env", func(t *testing.T) {
		t.Setenv(EnvPort, "not-a-port")
		cfg := Config{Port: 2200}
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("explicit port must skip env validation, got: %v", err)
		}
		if cfg.Port != 2200 {
			t.Errorf("Port = %d, want the explicit 2200", cfg.Port)
		}
	})

	t.Run("empty means unset", func(t *testing.T) {
		t.Setenv(EnvPort, "")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("empty WINDOWS_PORT must count as unset, got: %v", err)
		}
		if cfg.Port != 0 {
			t.Errorf("empty WINDOWS_PORT should leave Port unset, got %d", cfg.Port)
		}
	})

	for _, bad := range []string{"twenty-two", "0", "-1", "65536", "22 "} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv(EnvPort, bad)
			var cfg Config
			err := ResolveFromEnv(&cfg)
			if err == nil {
				t.Fatalf("WINDOWS_PORT=%q should be an error, got Port=%d", bad, cfg.Port)
			}
			assertEnvError(t, err, EnvPort, "port")
			if cfg.Port != 0 {
				t.Errorf("WINDOWS_PORT=%q should leave Port unset, got %d", bad, cfg.Port)
			}
		})
	}
}

// WINDOWS_TIMEOUT fills in only when no timeout was configured. A
// set-but-malformed or non-positive value is an error rather than a silent
// fallback to 30s, and an explicit timeout wins even over a malformed
// variable.
func TestResolveFromEnvTimeout(t *testing.T) {
	t.Run("fills empty timeout", func(t *testing.T) {
		t.Setenv(EnvTimeout, "45s")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("ResolveFromEnv: %v", err)
		}
		if cfg.Timeout != 45*time.Second {
			t.Errorf("Timeout = %v, want 45s", cfg.Timeout)
		}
	})

	t.Run("explicit timeout wins", func(t *testing.T) {
		t.Setenv(EnvTimeout, "45s")
		cfg := Config{Timeout: 15 * time.Second}
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("ResolveFromEnv: %v", err)
		}
		if cfg.Timeout != 15*time.Second {
			t.Errorf("Timeout = %v, want the explicit 15s", cfg.Timeout)
		}
	})

	t.Run("explicit timeout wins over malformed env", func(t *testing.T) {
		t.Setenv(EnvTimeout, "soon")
		cfg := Config{Timeout: 15 * time.Second}
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("explicit timeout must skip env validation, got: %v", err)
		}
		if cfg.Timeout != 15*time.Second {
			t.Errorf("Timeout = %v, want the explicit 15s", cfg.Timeout)
		}
	})

	t.Run("empty means unset", func(t *testing.T) {
		t.Setenv(EnvTimeout, "")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("empty WINDOWS_TIMEOUT must count as unset, got: %v", err)
		}
		if cfg.Timeout != 0 {
			t.Errorf("empty WINDOWS_TIMEOUT should leave Timeout unset, got %v", cfg.Timeout)
		}
	})

	for _, bad := range []string{"soon", "0", "0s", "-5s"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv(EnvTimeout, bad)
			var cfg Config
			err := ResolveFromEnv(&cfg)
			if err == nil {
				t.Fatalf("WINDOWS_TIMEOUT=%q should be an error, got Timeout=%v", bad, cfg.Timeout)
			}
			assertEnvError(t, err, EnvTimeout, "timeout")
			if cfg.Timeout != 0 {
				t.Errorf("WINDOWS_TIMEOUT=%q should leave Timeout unset, got %v", bad, cfg.Timeout)
			}
		})
	}
}

// WINDOWS_MAX_SESSIONS fills in only when no pool size was configured. A
// set-but-malformed or non-positive value is an error rather than a silent
// fallback, and an explicit pool size wins even over a malformed variable.
// Values above MaxMaxSessions are applied here so the caller's max_sessions
// attribute check reports them.
func TestResolveFromEnvMaxSessions(t *testing.T) {
	t.Run("fills empty pool size", func(t *testing.T) {
		t.Setenv(EnvMaxSessions, "2")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("ResolveFromEnv: %v", err)
		}
		if cfg.MaxSessions != 2 {
			t.Errorf("MaxSessions = %d, want 2", cfg.MaxSessions)
		}
	})

	t.Run("explicit pool size wins", func(t *testing.T) {
		t.Setenv(EnvMaxSessions, "2")
		cfg := Config{MaxSessions: 6}
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("ResolveFromEnv: %v", err)
		}
		if cfg.MaxSessions != 6 {
			t.Errorf("MaxSessions = %d, want the explicit 6", cfg.MaxSessions)
		}
	})

	t.Run("explicit pool size wins over malformed env", func(t *testing.T) {
		t.Setenv(EnvMaxSessions, "soon")
		cfg := Config{MaxSessions: 6}
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("explicit pool size must skip env validation, got: %v", err)
		}
		if cfg.MaxSessions != 6 {
			t.Errorf("MaxSessions = %d, want the explicit 6", cfg.MaxSessions)
		}
	})

	t.Run("empty means unset", func(t *testing.T) {
		t.Setenv(EnvMaxSessions, "")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("empty WINDOWS_MAX_SESSIONS must count as unset, got: %v", err)
		}
		if cfg.MaxSessions != 0 {
			t.Errorf("empty WINDOWS_MAX_SESSIONS should leave MaxSessions unset, got %d", cfg.MaxSessions)
		}
	})

	t.Run("above MaxMaxSessions applies for caller to reject", func(t *testing.T) {
		t.Setenv(EnvMaxSessions, "33")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("ResolveFromEnv: %v", err)
		}
		if cfg.MaxSessions != 33 {
			t.Errorf("MaxSessions = %d, want 33 for the caller to reject", cfg.MaxSessions)
		}
	})

	for _, bad := range []string{"many", "0", "-1", "4.5"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv(EnvMaxSessions, bad)
			var cfg Config
			err := ResolveFromEnv(&cfg)
			if err == nil {
				t.Fatalf("WINDOWS_MAX_SESSIONS=%q should be an error, got MaxSessions=%d", bad, cfg.MaxSessions)
			}
			assertEnvError(t, err, EnvMaxSessions, "max_sessions")
			if cfg.MaxSessions != 0 {
				t.Errorf("WINDOWS_MAX_SESSIONS=%q should leave MaxSessions unset, got %d", bad, cfg.MaxSessions)
			}
		})
	}
}

// A set-but-malformed WINDOWS_USE_AGENT or WINDOWS_INSECURE_IGNORE_HOST_KEY
// is an error rather than a silent fallback; an explicit value wins even over
// a malformed variable, and an empty string counts as unset.
func TestResolveFromEnvRejectsMalformedBools(t *testing.T) {
	t.Run("malformed use_agent is an error", func(t *testing.T) {
		t.Setenv(EnvUseAgent, "yes-please")
		var cfg Config
		err := ResolveFromEnv(&cfg)
		if err == nil {
			t.Fatal("malformed WINDOWS_USE_AGENT should be an error")
		}
		assertEnvError(t, err, EnvUseAgent, "use_agent")
		if cfg.UseAgent != nil {
			t.Errorf("malformed WINDOWS_USE_AGENT should leave UseAgent unset, got %v", *cfg.UseAgent)
		}
	})

	t.Run("malformed insecure is an error", func(t *testing.T) {
		t.Setenv(EnvInsecureIgnoreHostKey, "maybe")
		var cfg Config
		err := ResolveFromEnv(&cfg)
		if err == nil {
			t.Fatal("malformed WINDOWS_INSECURE_IGNORE_HOST_KEY should be an error")
		}
		assertEnvError(t, err, EnvInsecureIgnoreHostKey, "insecure_ignore_host_key")
		if cfg.InsecureIgnoreHostKey != nil {
			t.Error("malformed WINDOWS_INSECURE_IGNORE_HOST_KEY must not enable the opt-out")
		}
	})

	t.Run("empty means unset", func(t *testing.T) {
		t.Setenv(EnvUseAgent, "")
		t.Setenv(EnvInsecureIgnoreHostKey, "")
		var cfg Config
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("empty bool env must count as unset, got: %v", err)
		}
		if cfg.UseAgent != nil {
			t.Errorf("empty WINDOWS_USE_AGENT should leave UseAgent unset, got %v", *cfg.UseAgent)
		}
		if cfg.InsecureIgnoreHostKey != nil {
			t.Errorf("empty WINDOWS_INSECURE_IGNORE_HOST_KEY should leave InsecureIgnoreHostKey unset, got %v", *cfg.InsecureIgnoreHostKey)
		}
	})

	t.Run("explicit false wins over malformed env", func(t *testing.T) {
		t.Setenv(EnvUseAgent, "yes-please")
		t.Setenv(EnvInsecureIgnoreHostKey, "maybe")
		no := false
		cfg := Config{UseAgent: &no, InsecureIgnoreHostKey: &no}
		if err := ResolveFromEnv(&cfg); err != nil {
			t.Fatalf("explicit false must skip env validation, got: %v", err)
		}
		if cfg.UseAgent == nil || *cfg.UseAgent {
			t.Error("explicit UseAgent=false must survive malformed env")
		}
		if cfg.InsecureIgnoreHostKey == nil || *cfg.InsecureIgnoreHostKey {
			t.Error("explicit InsecureIgnoreHostKey=false must survive malformed env")
		}
	})
}

// assertEnvError checks that err is an *EnvError naming the expected variable
// and attribute, so Configure can map it to an attribute-scoped diagnostic.
func assertEnvError(t *testing.T, err error, wantVar, wantAttr string) {
	t.Helper()
	var envErr *EnvError
	if !errors.As(err, &envErr) {
		t.Fatalf("error type = %T, want *EnvError (%v)", err, err)
	}
	if envErr.Var != wantVar {
		t.Errorf("error Var = %q, want %q", envErr.Var, wantVar)
	}
	if envErr.Attr != wantAttr {
		t.Errorf("error Attr = %q, want %q", envErr.Attr, wantAttr)
	}
}

// New must not build a client that skips verification by default.
func TestNewRequiresHostVerification(t *testing.T) {
	noAgent(t)
	setHome(t, t.TempDir())
	if _, err := New(Config{Host: "h", Username: "u", Password: "p"}); err == nil {
		t.Fatal("New should refuse to build a client with no way to verify the host")
	}
}

func TestNewAcceptsKeyOnlyAuth(t *testing.T) {
	noAgent(t)
	privPEM, authorizedKey, _ := newTestKey(t)
	c, err := New(Config{
		Host:       "h",
		Username:   "u",
		PrivateKey: string(privPEM),
		HostKey:    authorizedKey,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected a client")
	}
}

func TestNewRejectsMissingCredentials(t *testing.T) {
	noAgent(t)
	_, authorizedKey, _ := newTestKey(t)
	_, err := New(Config{Host: "h", Username: "u", HostKey: authorizedKey})
	if err == nil {
		t.Fatal("expected an error when no credential is configured")
	}
}

// A pinned key must restrict negotiation to its own type (issue #393), so a
// multi-key server presents the pinned key instead of its preferred one.
func TestHostKeyAlgorithmsForKey(t *testing.T) {
	newECDSAPub := func(t *testing.T) ssh.PublicKey {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa key: %v", err)
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatalf("wrap ecdsa key: %v", err)
		}
		return pub
	}
	newRSAPub := func(t *testing.T) ssh.PublicKey {
		t.Helper()
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate rsa key: %v", err)
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatalf("wrap rsa key: %v", err)
		}
		return pub
	}

	_, _, edPub := newTestKey(t)
	if got := hostKeyAlgorithmsForKey(edPub); len(got) != 1 || got[0] != "ssh-ed25519" {
		t.Errorf("ed25519 algorithms = %v, want [ssh-ed25519]", got)
	}
	if got := hostKeyAlgorithmsForKey(newECDSAPub(t)); len(got) != 1 || got[0] != "ecdsa-sha2-nistp256" {
		t.Errorf("ecdsa algorithms = %v, want [ecdsa-sha2-nistp256]", got)
	}
	gotRSA := hostKeyAlgorithmsForKey(newRSAPub(t))
	wantRSA := []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}
	if strings.Join(gotRSA, ",") != strings.Join(wantRSA, ",") {
		t.Errorf("rsa algorithms = %v, want %v", gotRSA, wantRSA)
	}
	if got := hostKeyAlgorithmsForKey(stubPublicKey{typ: "ssh-ed25519-cert-v01@openssh.com"}); len(got) != 1 ||
		got[0] != "ssh-ed25519-cert-v01@openssh.com" {
		t.Errorf("cert algorithms = %v, want the cert type itself", got)
	}
	if got := hostKeyAlgorithmsForKey(nil); got != nil {
		t.Errorf("nil key algorithms = %v, want nil", got)
	}
}

type stubPublicKey struct{ typ string }

func (s stubPublicKey) Type() string                        { return s.typ }
func (s stubPublicKey) Marshal() []byte                     { return []byte(s.typ) }
func (s stubPublicKey) Verify([]byte, *ssh.Signature) error { return nil }

// known_hosts entries restrict negotiation to their recorded types; an
// unknown host leaves negotiation unrestricted while the callback still
// refuses it closed.
func TestKnownHostKeyAlgorithms(t *testing.T) {
	writeKnownHosts := func(t *testing.T, lines ...string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "known_hosts")
		content := strings.Join(lines, "\n")
		if content != "" {
			content += "\n"
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write known_hosts: %v", err)
		}
		return path
	}

	_, edLine, _ := newTestKey(t)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaPub, err := ssh.NewPublicKey(rsaPriv.Public())
	if err != nil {
		t.Fatalf("wrap rsa key: %v", err)
	}
	rsaLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rsaPub)))

	host := "192.0.2.10:22"
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}

	t.Run("ed25519 only", func(t *testing.T) {
		path := writeKnownHosts(t, "[192.0.2.10]:22 "+edLine)
		if got := knownHostKeyAlgorithms(path, host, addr); len(got) != 1 || got[0] != "ssh-ed25519" {
			t.Errorf("algorithms = %v, want [ssh-ed25519]", got)
		}
	})

	t.Run("rsa expands", func(t *testing.T) {
		path := writeKnownHosts(t, "[192.0.2.10]:22 "+rsaLine)
		got := knownHostKeyAlgorithms(path, host, addr)
		want := []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("algorithms = %v, want %v", got, want)
		}
	})

	t.Run("unknown host leaves negotiation alone", func(t *testing.T) {
		path := writeKnownHosts(t, "[192.0.2.10]:22 "+edLine)
		other := &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 22}
		if got := knownHostKeyAlgorithms(path, "192.0.2.99:22", other); got != nil {
			t.Errorf("algorithms = %v, want nil for an unlisted host", got)
		}
	})
}

// A different-type key with no entry of its own must not be reported as a
// mismatch: only a same-type difference is a possible MITM (issue #393).
func TestExplainKnownHostsErrorDistinguishesKeyType(t *testing.T) {
	_, edLine, _ := newTestKey(t)
	_, _, impostorEd := newTestKey(t)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaPub, err := ssh.NewPublicKey(rsaPriv.Public())
	if err != nil {
		t.Fatalf("wrap rsa key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("[192.0.2.10]:22 "+edLine+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	raw, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}
	cb := explainKnownHostsError(raw, path)
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}

	t.Run("same type mismatch", func(t *testing.T) {
		err := cb("192.0.2.10:22", addr, impostorEd)
		if err == nil {
			t.Fatal("a mismatched key must be rejected")
		}
		if !strings.Contains(err.Error(), "MISMATCH") {
			t.Errorf("same-type difference must be flagged as mismatch, got: %v", err)
		}
	})

	t.Run("different type without entry", func(t *testing.T) {
		err := cb("192.0.2.10:22", addr, rsaPub)
		if err == nil {
			t.Fatal("an unlisted key type must be rejected")
		}
		if strings.Contains(err.Error(), "MISMATCH") {
			t.Errorf("different-type key must not be reported as mismatch, got: %v", err)
		}
		if !strings.Contains(err.Error(), "ssh-keyscan") {
			t.Errorf("different-type key must carry ssh-keyscan guidance, got: %v", err)
		}
	})
}
