// SSH authentication and host identity verification.
//
// This file isolates the two security-critical decisions the client makes
// before any byte is exchanged: which credentials to offer, and whether the
// server on the other end is the one we meant to reach.
package winclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
func buildAuthMethods(cfg Config) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	signer, err := privateKeySigner(cfg)
	if err != nil {
		return nil, err
	}
	if signer != nil {
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if agentRequested(cfg) {
		m, agentErr := agentAuthMethod()
		switch {
		case agentErr == nil:
			methods = append(methods, m)
		case cfg.UseAgent != nil && *cfg.UseAgent:
			// The operator asked for the agent explicitly, so a broken agent
			// is a configuration error rather than something to skip past.
			return nil, agentErr
		}
	}

	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}

	if len(methods) == 0 {
		return nil, errors.New("winclient: no authentication method configured; set one of private_key, " +
			"private_key_path, password (or WINDOWS_PRIVATE_KEY / WINDOWS_PRIVATE_KEY_PATH / WINDOWS_PASSWORD), " +
			"or run an ssh-agent holding the key")
	}
	return methods, nil
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
// between calls stays usable.
func agentAuthMethod() (ssh.AuthMethod, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("winclient: ssh-agent authentication requested but SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("winclient: connect to ssh-agent at %s: %w", sock, err)
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
}

// hostKeyCallback builds the server identity check. Verification is on by
// default: callers must opt out deliberately.
func hostKeyCallback(cfg Config) (ssh.HostKeyCallback, error) {
	pinned := strings.TrimSpace(cfg.HostKey)

	if cfg.InsecureIgnoreHostKey {
		if pinned != "" || cfg.KnownHostsPath != "" {
			return nil, errors.New("winclient: insecure_ignore_host_key cannot be combined with host_key or " +
				"known_hosts_path; drop insecure_ignore_host_key to keep verifying the server")
		}
		// #nosec G106 -- deliberate, documented operator opt-out.
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if pinned != "" {
		if cfg.KnownHostsPath != "" {
			return nil, errors.New("winclient: host_key and known_hosts_path are mutually exclusive; set only one")
		}
		key, err := parseHostKey(pinned)
		if err != nil {
			return nil, err
		}
		return ssh.FixedHostKey(key), nil
	}

	path, err := resolveKnownHosts(cfg)
	if err != nil {
		return nil, err
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("winclient: load known_hosts %s: %w", path, err)
	}
	return explainKnownHostsError(cb, path), nil
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
				return fmt.Errorf("winclient: HOST KEY MISMATCH for %s: the server presented %s key %s, "+
					"which does not match the entry in %s. This may be a man-in-the-middle attack. If the host "+
					"was legitimately rebuilt, remove the stale entry (`ssh-keygen -R %s -f %s`) and re-add it",
					hostname, key.Type(), ssh.FingerprintSHA256(key), path, hostname, path)
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
