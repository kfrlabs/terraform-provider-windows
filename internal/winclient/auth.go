// SSH authentication and host identity verification.
//
// This file isolates the two security-critical decisions the client makes
// before any byte is exchanged: which credentials to offer, and whether the
// server on the other end is the one we meant to reach.
package winclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// defaultKnownHosts is the OpenSSH default, relative to the user's home.
var defaultKnownHosts = filepath.Join(".ssh", "known_hosts")

// buildAuthMethods assembles the authentication methods to offer, in the
// conventional OpenSSH order: explicit private key, then agent, then password.
// Offering several lets a server that refuses one still accept another.
//
// When the agent contributes a method, the second return value is the open
// agent socket, owned by the caller: it must stay open across handshakes and
// be closed when the client is done. It is nil when no agent is used.
func buildAuthMethods(cfg Config) ([]ssh.AuthMethod, io.Closer, error) {
	var methods []ssh.AuthMethod
	var agentConn io.Closer

	signer, err := privateKeySigner(cfg)
	if err != nil {
		return nil, nil, err
	}
	if signer != nil {
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if agentRequested(cfg) {
		m, conn, agentErr := agentAuthMethod()
		switch {
		case agentErr == nil:
			methods = append(methods, m)
			agentConn = conn
		case cfg.UseAgent != nil && *cfg.UseAgent:
			// The operator asked for the agent explicitly, so a broken agent
			// is a configuration error rather than something to skip past.
			return nil, nil, agentErr
		}
	}

	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}

	if len(methods) == 0 {
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return nil, nil, errors.New("winclient: no authentication method configured; set one of private_key, " +
			"private_key_path, password (or WINDOWS_PRIVATE_KEY / WINDOWS_PRIVATE_KEY_PATH / WINDOWS_PASSWORD), " +
			"or run an ssh-agent holding the key")
	}
	return methods, agentConn, nil
}

// privateKeySigner loads and parses the configured private key, returning
// (nil, nil) when no key is configured. Error messages never echo key
// material.
func privateKeySigner(cfg Config) (ssh.Signer, error) {
	if cfg.PrivateKey != "" && cfg.PrivateKeyPath != "" {
		return nil, errors.New("winclient: private_key and private_key_path are mutually exclusive; set only one")
	}

	pem := []byte(cfg.PrivateKey)
	if len(pem) == 0 {
		if cfg.PrivateKeyPath == "" {
			return nil, nil
		}
		path, err := expandHome(cfg.PrivateKeyPath)
		if err != nil {
			return nil, err
		}
		// #nosec G304 -- the path is operator-supplied provider configuration,
		// exactly like OpenSSH's own -i flag.
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("winclient: read private key %s: %w", path, err)
		}
		pem = raw
	}

	if cfg.PrivateKeyPassphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(pem, []byte(cfg.PrivateKeyPassphrase))
		if err != nil {
			return nil, fmt.Errorf("winclient: parse encrypted private key: %w", err)
		}
		return signer, nil
	}

	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("winclient: private key is passphrase-protected; set private_key_passphrase " +
				"(or WINDOWS_PRIVATE_KEY_PASSPHRASE), or load the key into an ssh-agent")
		}
		return nil, fmt.Errorf("winclient: parse private key: %w", err)
	}
	return signer, nil
}

// agentRequested reports whether the ssh-agent should be consulted. Absent an
// explicit setting it follows the usual client behaviour: use the agent when
// one is advertised.
func agentRequested(cfg Config) bool {
	if cfg.UseAgent != nil {
		return *cfg.UseAgent
	}
	return os.Getenv("SSH_AUTH_SOCK") != ""
}

// agentAuthMethod connects to the ssh-agent advertised by SSH_AUTH_SOCK. The
// signers are fetched lazily at handshake time, so an agent whose keys change
// between calls stays usable. The returned closer owns the agent socket and
// must stay open across handshakes; the caller closes it when done.
func agentAuthMethod() (ssh.AuthMethod, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("winclient: ssh-agent authentication requested but SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", sock) //nolint:gosec // dialing the operator-configured ssh-agent socket is intended
	if err != nil {
		return nil, nil, fmt.Errorf("winclient: connect to ssh-agent at %s: %w", sock, err)
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), conn, nil
}

// hostKeyCallback builds the server identity check. Verification is on by
// default: callers must opt out deliberately. The second return value lists
// the host key algorithms the client may negotiate, so a server offering
// several host keys presents the one we can actually verify (issue #393):
// without it the handshake may settle on a key type we never pinned, and a
// correct pin would then fail as a false man-in-the-middle.
func hostKeyCallback(cfg Config) (ssh.HostKeyCallback, []string, error) {
	pinned := strings.TrimSpace(cfg.HostKey)

	if cfg.InsecureIgnoreHostKey != nil && *cfg.InsecureIgnoreHostKey {
		if pinned != "" || cfg.KnownHostsPath != "" {
			return nil, nil, errors.New("winclient: insecure_ignore_host_key cannot be combined with host_key or " +
				"known_hosts_path; drop insecure_ignore_host_key to keep verifying the server")
		}
		// #nosec G106 -- deliberate, documented operator opt-out.
		return ssh.InsecureIgnoreHostKey(), nil, nil
	}

	if pinned != "" {
		if cfg.KnownHostsPath != "" {
			return nil, nil, errors.New("winclient: host_key and known_hosts_path are mutually exclusive; set only one")
		}
		key, err := parseHostKey(pinned)
		if err != nil {
			return nil, nil, err
		}
		return ssh.FixedHostKey(key), hostKeyAlgorithmsForKey(key), nil
	}

	path, err := resolveKnownHosts(cfg)
	if err != nil {
		return nil, nil, err
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, nil, fmt.Errorf("winclient: load known_hosts %s: %w", path, err)
	}
	return explainKnownHostsError(cb, path),
		knownHostKeyAlgorithms(path, knownHostsProbeID(cfg), knownHostsProbeAddr(cfg)), nil
}

// hostKeyAlgorithmsForKey restricts algorithm negotiation to the pinned key's
// type, so a multi-key server presents the key we pinned rather than whatever
// the handshake prefers first (issue #393). RSA negotiates as rsa-sha2-512,
// rsa-sha2-256 or the legacy ssh-rsa signature; every other type negotiates
// under its own name, including certificates.
func hostKeyAlgorithmsForKey(key ssh.PublicKey) []string {
	if key == nil {
		return nil
	}
	if key.Type() == "ssh-rsa" {
		return []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}
	}
	return []string{key.Type()}
}

// hostKeyAlgorithmsForKnownKeys restricts negotiation to the key types
// recorded for the host, expanding RSA as in hostKeyAlgorithmsForKey and
// de-duplicating while preserving first-seen order.
func hostKeyAlgorithmsForKnownKeys(keys []knownhosts.KnownKey) []string {
	seen := make(map[string]bool)
	var out []string
	for _, wk := range keys {
		if wk.Key == nil {
			continue
		}
		for _, algo := range hostKeyAlgorithmsForKey(wk.Key) {
			if !seen[algo] {
				seen[algo] = true
				out = append(out, algo)
			}
		}
	}
	return out
}

// knownHostKeyAlgorithms collects the key types recorded for hostname in the
// known_hosts file, so negotiation settles on a verifiable type. It probes a
// throwaway knownhosts callback with a fresh random key and reads the wanted
// keys from (*knownhosts.KeyError).Want: no new dependency, no file format
// knowledge. An unknown host (empty Want) or any probe failure returns nil,
// leaving negotiation unrestricted while the real callback still refuses the
// host closed with ssh-keyscan guidance.
func knownHostKeyAlgorithms(path, hostname string, remote net.Addr) []string {
	if hostname == "" && remote == nil {
		return nil
	}
	rawCb, err := knownhosts.New(path)
	if err != nil {
		return nil
	}
	probePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probeKey, err := ssh.NewPublicKey(probePub)
	if err != nil {
		return nil
	}
	err = rawCb(hostname, remote, probeKey)
	if err == nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return nil
	}
	if len(keyErr.Want) == 0 {
		return nil
	}
	return hostKeyAlgorithmsForKnownKeys(keyErr.Want)
}

// knownHostsProbeID renders the hostname the handshake will present to the
// host key callback, so the algorithm probe reads the same entry.
func knownHostsProbeID(cfg Config) string {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return ""
	}
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// knownHostsProbeAddr synthesises the remote address for the algorithm probe
// when the host is a literal IP. Hostnames resolve only at dial time, so the
// probe passes nil there and matches on the hostname alone.
func knownHostsProbeAddr(cfg Config) net.Addr {
	ip := net.ParseIP(strings.TrimSpace(cfg.Host))
	if ip == nil {
		return nil
	}
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

// resolveKnownHosts returns the known_hosts file to trust, defaulting to the
// OpenSSH location. A missing file is an error rather than a silent bypass:
// failing closed is the whole point of verifying host identity.
func resolveKnownHosts(cfg Config) (string, error) {
	if cfg.KnownHostsPath != "" {
		path, err := expandHome(cfg.KnownHostsPath)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("winclient: known_hosts file %s is unreadable: %w", path, err)
		}
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("winclient: cannot locate the default known_hosts file: %w; set known_hosts_path "+
			"or host_key explicitly", err)
	}
	path := filepath.Join(home, defaultKnownHosts)
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("winclient: no known_hosts file at %s: %w. Populate it with "+
			"`ssh-keyscan <host> >> %s`, or pin the server key with the provider's host_key attribute "+
			"(or WINDOWS_HOST_KEY)", path, err, path)
	}
	return path, nil
}

// explainKnownHostsError turns knownhosts' terse failures into guidance that
// distinguishes the two cases an operator must never confuse: a host we have
// simply not met yet, and a host whose key changed under us.
func explainKnownHostsError(cb ssh.HostKeyCallback, path string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) > 0 {
				// Only a same-type mismatch is a possible MITM. A
				// different-type key with no entry of its own is an
				// unlisted key type, not proof the host changed its
				// key: conflating the two trains operators to ignore
				// a real attack signal (issue #393).
				for _, want := range keyErr.Want {
					if want.Key != nil && want.Key.Type() == key.Type() {
						return fmt.Errorf("winclient: HOST KEY MISMATCH for %s: the server presented %s key %s, "+
							"which does not match the entry in %s. This may be a man-in-the-middle attack. If the host "+
							"was legitimately rebuilt, remove the stale entry (`ssh-keygen -R %s -f %s`) and re-add it",
							hostname, key.Type(), ssh.FingerprintSHA256(key), path, hostname, path)
					}
				}
				return fmt.Errorf("winclient: host %s has no %s entry in %s (it offered %s key %s). Add it with "+
					"`ssh-keyscan %s >> %s` after verifying the fingerprint out of band, or pin it with the "+
					"provider's host_key attribute", hostname, key.Type(), path, key.Type(),
					ssh.FingerprintSHA256(key), hostname, path)
			}
			return fmt.Errorf("winclient: host %s is not present in %s (it offered %s key %s). Add it with "+
				"`ssh-keyscan %s >> %s` after verifying the fingerprint out of band, or pin it with the "+
				"provider's host_key attribute", hostname, path, key.Type(), ssh.FingerprintSHA256(key), hostname, path)
		}
		return err
	}
}

// parseHostKey accepts a public key in authorized_keys form
// ("ssh-ed25519 AAAA... comment") and also tolerates a full known_hosts line
// with a leading host field, which is what `ssh-keyscan` prints.
func parseHostKey(s string) (ssh.PublicKey, error) {
	line := strings.TrimSpace(s)

	if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
		return key, nil
	}
	if _, rest, found := strings.Cut(line, " "); found {
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(rest))); err == nil {
			return key, nil
		}
	}
	return nil, errors.New(`winclient: could not parse host_key; expected an OpenSSH public key such as ` +
		`"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..." as printed by ssh-keyscan`)
}

// expandHome resolves a leading "~" against the current user's home directory.
func expandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("winclient: cannot expand %q: %w", p, err)
	}
	if p == "~" {
		return home, nil
	}
	return filepath.Join(home, p[2:]), nil
}
