package winclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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
	methods, err := buildAuthMethods(Config{Password: "s3cr3t"})
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
	methods, err := buildAuthMethods(Config{PrivateKey: string(privPEM)})
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
	methods, err := buildAuthMethods(Config{PrivateKeyPath: path})
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
	methods, err := buildAuthMethods(Config{PrivateKey: string(privPEM), Password: "s3cr3t"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("got %d auth methods, want 2", len(methods))
	}
}

func TestBuildAuthMethodsRejectsNoCredentials(t *testing.T) {
	noAgent(t)
	if _, err := buildAuthMethods(Config{}); err == nil {
		t.Fatal("expected an error when no authentication method is configured")
	}
}

func TestBuildAuthMethodsRejectsBothKeyForms(t *testing.T) {
	noAgent(t)
	privPEM, _, _ := newTestKey(t)
	_, err := buildAuthMethods(Config{PrivateKey: string(privPEM), PrivateKeyPath: "/tmp/whatever"})
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
	_, err := hostKeyCallback(Config{Host: "192.0.2.10"})
	if err == nil {
		t.Fatal("expected an error when no known_hosts file exists")
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") || !strings.Contains(err.Error(), "host_key") {
		t.Errorf("error should tell the operator how to fix it, got: %v", err)
	}
}

func TestHostKeyCallbackPinnedKey(t *testing.T) {
	_, authorizedKey, pub := newTestKey(t)
	cb, err := hostKeyCallback(Config{HostKey: authorizedKey})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
		"insecure and host_key":         {InsecureIgnoreHostKey: true, HostKey: authorizedKey},
		"insecure and known_hosts_path": {InsecureIgnoreHostKey: true, KnownHostsPath: "/tmp/known_hosts"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := hostKeyCallback(cfg); err == nil {
				t.Fatal("expected a configuration error")
			}
		})
	}
}

func TestHostKeyCallbackInsecureOptOut(t *testing.T) {
	cb, err := hostKeyCallback(Config{InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

	cb, err := hostKeyCallback(Config{KnownHostsPath: path})
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
	_, err := hostKeyCallback(Config{KnownHostsPath: filepath.Join(t.TempDir(), "absent")})
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

	if _, err := buildAuthMethods(Config{UseAgent: &yes, Password: "p"}); err == nil {
		t.Error("explicitly requested but broken agent should error")
	}

	methods, err := buildAuthMethods(Config{Password: "p"})
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
	ResolveFromEnv(&cfg)

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
	if !cfg.InsecureIgnoreHostKey {
		t.Error("InsecureIgnoreHostKey should be true")
	}
}

// Explicit configuration must win over the environment.
func TestResolveFromEnvDoesNotOverrideExplicitValues(t *testing.T) {
	t.Setenv(EnvPrivateKey, "from-env")
	t.Setenv(EnvUseAgent, "true")

	no := false
	cfg := Config{PrivateKey: "from-config", UseAgent: &no}
	ResolveFromEnv(&cfg)

	if cfg.PrivateKey != "from-config" {
		t.Errorf("PrivateKey = %q, want from-config", cfg.PrivateKey)
	}
	if cfg.UseAgent == nil || *cfg.UseAgent {
		t.Error("explicit UseAgent=false must survive ResolveFromEnv")
	}
}

// WINDOWS_PORT fills in only when no port was configured, and a value that is
// not a usable TCP port is ignored rather than dialed.
func TestResolveFromEnvPort(t *testing.T) {
	t.Run("fills empty port", func(t *testing.T) {
		t.Setenv(EnvPort, "2222")
		var cfg Config
		ResolveFromEnv(&cfg)
		if cfg.Port != 2222 {
			t.Errorf("Port = %d, want 2222", cfg.Port)
		}
	})

	t.Run("explicit port wins", func(t *testing.T) {
		t.Setenv(EnvPort, "2222")
		cfg := Config{Port: 2200}
		ResolveFromEnv(&cfg)
		if cfg.Port != 2200 {
			t.Errorf("Port = %d, want the explicit 2200", cfg.Port)
		}
	})

	for _, bad := range []string{"", "twenty-two", "0", "-1", "65536", "22 "} {
		t.Run("ignores "+bad, func(t *testing.T) {
			t.Setenv(EnvPort, bad)
			var cfg Config
			ResolveFromEnv(&cfg)
			if cfg.Port != 0 {
				t.Errorf("WINDOWS_PORT=%q should leave Port unset for New to default, got %d", bad, cfg.Port)
			}
		})
	}
}

// An unparseable WINDOWS_USE_AGENT must not silently read as false.
func TestResolveFromEnvIgnoresMalformedBools(t *testing.T) {
	t.Setenv(EnvUseAgent, "yes-please")
	t.Setenv(EnvInsecureIgnoreHostKey, "maybe")

	var cfg Config
	ResolveFromEnv(&cfg)

	if cfg.UseAgent != nil {
		t.Errorf("malformed WINDOWS_USE_AGENT should leave UseAgent unset, got %v", *cfg.UseAgent)
	}
	if cfg.InsecureIgnoreHostKey {
		t.Error("malformed WINDOWS_INSECURE_IGNORE_HOST_KEY must not enable the opt-out")
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
