// Package winclient provides an SSH client wrapper used by the Terraform
// provider to execute PowerShell scripts against Windows hosts.
package winclient

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds connection settings for an SSH session. No credentials are
// ever hardcoded: values come from the provider block or environment.
//
// Authentication follows the usual OpenSSH precedence: an explicitly supplied
// private key first, then the ssh-agent, then the password. Every method that
// is configured is offered to the server, so a host that rejects one can still
// accept another.
//
// Host identity is verified by default. Exactly one of HostKey,
// KnownHostsPath (or the default known_hosts file) or InsecureIgnoreHostKey
// decides how.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	Timeout  time.Duration

	// PrivateKey is a PEM-encoded private key. Mutually exclusive with
	// PrivateKeyPath.
	PrivateKey string
	// PrivateKeyPath points at a PEM-encoded private key on disk. A leading
	// "~" is expanded to the current user's home directory.
	PrivateKeyPath string
	// PrivateKeyPassphrase decrypts PrivateKey/PrivateKeyPath when it is
	// passphrase-protected.
	PrivateKeyPassphrase string
	// UseAgent forces ssh-agent authentication on (true) or off (false).
	// When nil, the agent is used if SSH_AUTH_SOCK is set.
	UseAgent *bool

	// KnownHostsPath is the OpenSSH known_hosts file used to verify the
	// server. Defaults to ~/.ssh/known_hosts.
	KnownHostsPath string
	// HostKey pins the server's public key directly, in authorized_keys form
	// ("ssh-ed25519 AAAAC3Nz..."). It removes the need for a known_hosts file,
	// which is what CI runners and Terraform Cloud generally lack.
	HostKey string
	// InsecureIgnoreHostKey disables host identity verification entirely. It
	// exposes every connection to man-in-the-middle interception and exists
	// only as an explicit, deliberate opt-out. When nil, verification stays
	// on (false). An explicit false wins over WINDOWS_INSECURE_IGNORE_HOST_KEY,
	// matching the UseAgent precedent.
	InsecureIgnoreHostKey *bool
	// MaxSessions bounds how many SSH/PowerShell sessions the client keeps
	// open concurrently (issue #180). Each call borrows a slot; beyond the
	// limit callers wait until a slot frees or ctx is done. Zero means
	// DefaultMaxSessions (applied by New and ResolveFromEnv callers).
	MaxSessions int
}

// Environment variable names used as fallback when provider attributes are
// unset.
const (
	EnvHost                  = "WINDOWS_HOST"
	EnvPort                  = "WINDOWS_PORT"
	EnvUsername              = "WINDOWS_USERNAME"
	EnvPassword              = "WINDOWS_PASSWORD"               //nolint:gosec // name of env var, not a secret
	EnvPrivateKey            = "WINDOWS_PRIVATE_KEY"            //nolint:gosec // name of env var, not a secret
	EnvPrivateKeyPath        = "WINDOWS_PRIVATE_KEY_PATH"       //nolint:gosec // name of env var, not a secret
	EnvPrivateKeyPassphrase  = "WINDOWS_PRIVATE_KEY_PASSPHRASE" //nolint:gosec // name of env var, not a secret
	EnvUseAgent              = "WINDOWS_USE_AGENT"
	EnvKnownHosts            = "WINDOWS_KNOWN_HOSTS"
	EnvHostKey               = "WINDOWS_HOST_KEY"
	EnvInsecureIgnoreHostKey = "WINDOWS_INSECURE_IGNORE_HOST_KEY"
	// EnvTimeout bounds the SSH connection establishment (TCP dial plus
	// handshake) as a Go duration string (e.g. "45s", "2m").
	EnvTimeout = "WINDOWS_TIMEOUT"
	// EnvMaxSessions bounds the client session pool (issue #180) as a
	// positive integer string (e.g. "4").
	EnvMaxSessions = "WINDOWS_MAX_SESSIONS"
)

// DefaultMaxSessions is the pool size used when neither the provider
// attribute nor WINDOWS_MAX_SESSIONS sets one. It stays well under sshd's
// default MaxSessions 10 so a cold-start dial storm never throttles.
const DefaultMaxSessions = 4

// MaxMaxSessions caps the pool so an extreme value cannot turn every plan
// into a dial storm against sshd's MaxStartups throttle.
const MaxMaxSessions = 32

// BoolPtr boxes a bool so explicit test and provider configuration can
// distinguish false from unset (nil), matching the UseAgent precedent.
func BoolPtr(b bool) *bool { return &b }

// EnvError reports a set-but-malformed environment fallback. Var names the
// environment variable (for example WINDOWS_PORT) and Attr names the provider
// attribute it maps to (for example port), so Configure can emit an
// attribute-scoped diagnostic.
type EnvError struct {
	Var   string
	Attr  string
	Value string
	Msg   string
}

func (e *EnvError) Error() string {
	return fmt.Sprintf("winclient: %s=%q %s", e.Var, e.Value, e.Msg)
}

// lookupEnv returns the variable value when it is set to a non-blank string.
// An unset variable, an empty string and a whitespace-only string all count
// as unset, preserving the clearProviderEnv test helper semantics where every
// variable is set to "".
func lookupEnv(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return "", false
	}
	return v, true
}

// ResolveFromEnv fills any empty field in cfg with the corresponding
// environment variable value, if set. It never logs secret values.
//
// Precedence is explicit HCL > set environment variable > built-in default:
// a field that is already set keeps its value and its environment variable is
// not even validated. A set-but-malformed WINDOWS_PORT, WINDOWS_TIMEOUT,
// WINDOWS_MAX_SESSIONS, WINDOWS_USE_AGENT or
// WINDOWS_INSECURE_IGNORE_HOST_KEY is an error rather than a silent fallback,
// so a typo cannot silently dial the wrong port or disable verification.
func ResolveFromEnv(cfg *Config) error {
	if cfg.Host == "" {
		if v, ok := lookupEnv(EnvHost); ok {
			cfg.Host = v
		}
	}
	if cfg.Port == 0 {
		if raw, ok := lookupEnv(EnvPort); ok {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 || v > 65535 {
				return &EnvError{Var: EnvPort, Attr: "port", Value: raw, Msg: "must be an integer between 1 and 65535"}
			}
			cfg.Port = v
		}
	}
	if cfg.Username == "" {
		if v, ok := lookupEnv(EnvUsername); ok {
			cfg.Username = v
		}
	}
	if cfg.Password == "" {
		if v, ok := lookupEnv(EnvPassword); ok {
			cfg.Password = v
		}
	}
	if cfg.PrivateKey == "" {
		if v, ok := lookupEnv(EnvPrivateKey); ok {
			cfg.PrivateKey = v
		}
	}
	if cfg.PrivateKeyPath == "" {
		if v, ok := lookupEnv(EnvPrivateKeyPath); ok {
			cfg.PrivateKeyPath = v
		}
	}
	if cfg.PrivateKeyPassphrase == "" {
		if v, ok := lookupEnv(EnvPrivateKeyPassphrase); ok {
			cfg.PrivateKeyPassphrase = v
		}
	}
	if cfg.UseAgent == nil {
		if raw, ok := lookupEnv(EnvUseAgent); ok {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				return &EnvError{Var: EnvUseAgent, Attr: "use_agent", Value: raw, Msg: "must be a boolean (true/false)"}
			}
			cfg.UseAgent = &v
		}
	}
	if cfg.KnownHostsPath == "" {
		if v, ok := lookupEnv(EnvKnownHosts); ok {
			cfg.KnownHostsPath = v
		}
	}
	if cfg.HostKey == "" {
		if v, ok := lookupEnv(EnvHostKey); ok {
			cfg.HostKey = v
		}
	}
	if cfg.InsecureIgnoreHostKey == nil {
		if raw, ok := lookupEnv(EnvInsecureIgnoreHostKey); ok {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				return &EnvError{Var: EnvInsecureIgnoreHostKey, Attr: "insecure_ignore_host_key", Value: raw, Msg: "must be a boolean (true/false)"}
			}
			cfg.InsecureIgnoreHostKey = &v
		}
	}
	if cfg.Timeout == 0 {
		if raw, ok := lookupEnv(EnvTimeout); ok {
			v, err := time.ParseDuration(raw)
			if err != nil || v <= 0 {
				return &EnvError{Var: EnvTimeout, Attr: "timeout", Value: raw, Msg: "must be a positive Go duration string (e.g. 30s, 2m)"}
			}
			cfg.Timeout = v
		}
	}
	if cfg.MaxSessions == 0 {
		if raw, ok := lookupEnv(EnvMaxSessions); ok {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 {
				return &EnvError{Var: EnvMaxSessions, Attr: "max_sessions", Value: raw, Msg: "must be a positive integer"}
			}
			// Values above MaxMaxSessions are applied here and rejected by
			// the caller's max_sessions attribute check, so the diagnostic
			// points at max_sessions either way.
			cfg.MaxSessions = v
		}
	}
	return nil
}
