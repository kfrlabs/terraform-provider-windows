// Package winclient provides an SSH client wrapper used by the Terraform
// provider to execute PowerShell scripts against Windows hosts.
package winclient

import (
	"os"
	"strconv"
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
	// only as an explicit, deliberate opt-out.
	InsecureIgnoreHostKey bool
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

// ResolveFromEnv fills any empty field in cfg with the corresponding
// environment variable value, if set. It never logs secret values.
func ResolveFromEnv(cfg *Config) {
	if cfg.Host == "" {
		cfg.Host = os.Getenv(EnvHost)
	}
	// A malformed or out-of-range WINDOWS_PORT is left for New to default to
	// 22 rather than silently dialing a port the operator did not mean.
	if cfg.Port == 0 {
		if v, err := strconv.Atoi(os.Getenv(EnvPort)); err == nil && v > 0 && v <= 65535 {
			cfg.Port = v
		}
	}
	if cfg.Username == "" {
		cfg.Username = os.Getenv(EnvUsername)
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv(EnvPassword)
	}
	if cfg.PrivateKey == "" {
		cfg.PrivateKey = os.Getenv(EnvPrivateKey)
	}
	if cfg.PrivateKeyPath == "" {
		cfg.PrivateKeyPath = os.Getenv(EnvPrivateKeyPath)
	}
	if cfg.PrivateKeyPassphrase == "" {
		cfg.PrivateKeyPassphrase = os.Getenv(EnvPrivateKeyPassphrase)
	}
	if cfg.UseAgent == nil {
		if v, err := strconv.ParseBool(os.Getenv(EnvUseAgent)); err == nil {
			cfg.UseAgent = &v
		}
	}
	if cfg.KnownHostsPath == "" {
		cfg.KnownHostsPath = os.Getenv(EnvKnownHosts)
	}
	if cfg.HostKey == "" {
		cfg.HostKey = os.Getenv(EnvHostKey)
	}
	if !cfg.InsecureIgnoreHostKey {
		if v, err := strconv.ParseBool(os.Getenv(EnvInsecureIgnoreHostKey)); err == nil {
			cfg.InsecureIgnoreHostKey = v
		}
	}
	// A malformed or non-positive WINDOWS_TIMEOUT is left for New to default
	// to 30s rather than dialing with a surprising timeout — the same stance
	// as WINDOWS_PORT above.
	if cfg.Timeout == 0 {
		if v, err := time.ParseDuration(os.Getenv(EnvTimeout)); err == nil && v > 0 {
			cfg.Timeout = v
		}
	}
	// A malformed or non-positive WINDOWS_MAX_SESSIONS is left for New to
	// default to DefaultMaxSessions rather than serialising the pool or
	// failing Configure on a typo — the same stance as WINDOWS_PORT above.
	if cfg.MaxSessions == 0 {
		if v, err := strconv.Atoi(os.Getenv(EnvMaxSessions)); err == nil && v > 0 {
			cfg.MaxSessions = v
		}
	}
}
