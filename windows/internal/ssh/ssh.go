package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
)

// Config contains SSH connection parameters
type Config struct {
	Host                  string
	Username              string
	Password              string
	KeyPath               string
	UseSSHAgent           bool
	ConnTimeout           time.Duration
	KnownHostsPath        string
	HostKeyFingerprints   []string
	StrictHostKeyChecking bool
}

// Client encapsulates SSH connection
type Client struct {
	*ssh.Client
}

// NewClient creates a new SSH connection with provided parameters
func NewClient(config Config) (*Client, error) {
	var authMethods []ssh.AuthMethod

	if config.UseSSHAgent {
		if agentAuth, err := sshAgentAuth(); err == nil {
			authMethods = append(authMethods, agentAuth)
		}
	}

	if config.KeyPath != "" {
		if keyAuth, err := publicKeyAuth(config.KeyPath); err == nil {
			authMethods = append(authMethods, keyAuth)
		}
	} else if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	hostKeyCallback, err := createHostKeyCallback(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create host key callback: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            config.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         config.ConnTimeout,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(config.Host, "22"), sshConfig)
	if err != nil {
		return nil, err
	}

	return &Client{client}, nil
}

// ============================================================================
// POWERSHELL EXECUTION METHODS
// ============================================================================

// ExecuteCommand executes a PowerShell command securely using the powershell package
// Returns (stdout, stderr, error)
func (c *Client) ExecuteCommand(command string, timeoutSeconds int) (string, string, error) {
	session, err := c.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	// Use PowerShell executor from powershell package
	executor := powershell.NewExecutor(session, powershell.DefaultOptions())
	stdout, stderr, err := executor.Execute(ctx, command)

	return stdout, stderr, err
}

// Close closes the SSH connection
func (c *Client) Close() error {
	return c.Client.Close()
}

// ============================================================================
// HOST KEY VERIFICATION
// ============================================================================

func createHostKeyCallback(config Config) (ssh.HostKeyCallback, error) {
	if len(config.HostKeyFingerprints) > 0 {
		return createFingerprintCallback(config.Host, config.HostKeyFingerprints, config.StrictHostKeyChecking), nil
	}

	knownHostsPath := config.KnownHostsPath
	if knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot determine home directory for known_hosts: %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	return createKnownHostsCallback(knownHostsPath, config.StrictHostKeyChecking)
}

func createKnownHostsCallback(knownHostsPath string, strictMode bool) (ssh.HostKeyCallback, error) {
	if strings.HasPrefix(knownHostsPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve home directory: %w", err)
		}
		knownHostsPath = filepath.Join(home, knownHostsPath[1:])
	}

	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		if strictMode {
			return nil, fmt.Errorf(
				"known_hosts file not found at %s (strict mode enabled)\n"+
					"Please run: ssh-keyscan -H <host> >> %s\n"+
					"Or provide host_key_fingerprints in provider configuration",
				knownHostsPath, knownHostsPath)
		}

		if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); err != nil {
			return nil, fmt.Errorf("failed to create known_hosts directory: %w", err)
		}
		if _, err := os.Create(knownHostsPath); err != nil {
			return nil, fmt.Errorf("failed to create known_hosts file: %w", err)
		}
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load known_hosts: %w", err)
	}

	return hostKeyCallback, nil
}

func createFingerprintCallback(host string, fingerprints []string, strictMode bool) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		keyFingerprint := ssh.FingerprintSHA256(key)

		for _, expectedFingerprint := range fingerprints {
			if keyFingerprint == expectedFingerprint {
				return nil
			}
		}

		errorMsg := fmt.Sprintf(
			"host key verification failed for %s\nExpected one of: %v\nGot: %s",
			hostname,
			fingerprints,
			keyFingerprint,
		)

		if strictMode {
			return fmt.Errorf(errorMsg)
		}

		fmt.Fprintf(os.Stderr, "WARNING: %s\n", errorMsg)
		return nil
	}
}

// ============================================================================
// AUTHENTICATION METHODS
// ============================================================================

func sshAgentAuth() (ssh.AuthMethod, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}
	agentClient := agent.NewClient(sshAgent)
	return ssh.PublicKeysCallback(agentClient.Signers), nil
}

func publicKeyAuth(keyPath string) (ssh.AuthMethod, error) {
	if strings.HasPrefix(keyPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve home directory: %w", err)
		}
		keyPath = filepath.Join(home, keyPath[1:])
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return ssh.PublicKeys(signer), nil
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// NewClientSecure creates a new SSH connection with strict host key verification
// This is the recommended function for production use
func NewClientSecure(config Config) (*Client, error) {
	if config.ConnTimeout == 0 {
		config.ConnTimeout = 30 * time.Second
	}

	config.StrictHostKeyChecking = true

	if config.KnownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		config.KnownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}

	return NewClient(config)
}

// GetHostKeyFingerprint returns the SHA256 fingerprint of an SSH server
func GetHostKeyFingerprint(host string, port string) (string, error) {
	if port == "" {
		port = "22"
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s:%s: %w", host, port, err)
	}
	defer conn.Close()

	var hostKey ssh.PublicKey

	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hostKey = key
		return nil
	}

	config := &ssh.ClientConfig{
		User:            "dummy",
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
		Auth:            []ssh.AuthMethod{},
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host, port), config)
	if err != nil {
		if hostKey == nil {
			return "", fmt.Errorf("failed to retrieve host key: %w", err)
		}
	} else {
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
	}

	return ssh.FingerprintSHA256(hostKey), nil
}

// GetHostKeyFingerprintLegacy returns the fingerprint in MD5 format (legacy)
// Provided for compatibility with older systems
func GetHostKeyFingerprintLegacy(host string, port string) (string, error) {
	if port == "" {
		port = "22"
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s:%s: %w", host, port, err)
	}
	defer conn.Close()

	var hostKey ssh.PublicKey

	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hostKey = key
		return nil
	}

	config := &ssh.ClientConfig{
		User:            "dummy",
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
		Auth:            []ssh.AuthMethod{},
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host, port), config)
	if err != nil {
		if hostKey == nil {
			return "", fmt.Errorf("failed to retrieve host key: %w", err)
		}
	} else {
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
	}

	return ssh.FingerprintLegacyMD5(hostKey), nil
}
