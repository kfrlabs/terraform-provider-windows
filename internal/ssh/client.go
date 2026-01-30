package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Config holds the SSH connection configuration
type Config struct {
	// Connection details
	Host     string
	Port     int
	Username string
	Password string
	KeyPath  string

	// Authentication options
	UseSSHAgent bool

	// Connection settings
	ConnTimeout time.Duration

	// Host key verification
	KnownHostsPath        string
	HostKeyFingerprints   []string
	StrictHostKeyChecking bool
}

// Client represents an SSH client connection to a Windows server
type Client struct {
	config    Config
	client    *ssh.Client
	session   *ssh.Session
	connected bool
	lastUsed  time.Time
	createdAt time.Time
}

// NewClient creates a new SSH client with the given configuration.
// It establishes the connection but doesn't create a session yet.
//
// Parameters:
//   - config: SSH connection configuration
//
// Returns:
//   - *Client: The initialized SSH client
//   - error: Error if connection fails
func NewClient(config Config) (*Client, error) {
	// Set default port if not specified
	if config.Port == 0 {
		config.Port = 22
	}

	// Set default timeout if not specified
	if config.ConnTimeout == 0 {
		config.ConnTimeout = 30 * time.Second
	}

	// Build SSH client configuration
	sshConfig, err := buildSSHConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSH config: %w", err)
	}

	// Establish connection
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	return &Client{
		config:    config,
		client:    client,
		connected: true,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}, nil
}

// buildSSHConfig constructs the SSH client configuration from Config
func buildSSHConfig(config Config) (*ssh.ClientConfig, error) {
	sshConfig := &ssh.ClientConfig{
		User:    config.Username,
		Timeout: config.ConnTimeout,
	}

	// Setup authentication methods
	authMethods, err := setupAuthMethods(config)
	if err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}
	sshConfig.Auth = authMethods

	// Setup host key verification
	hostKeyCallback, err := setupHostKeyVerification(config)
	if err != nil {
		return nil, fmt.Errorf("failed to setup host key verification: %w", err)
	}
	sshConfig.HostKeyCallback = hostKeyCallback

	return sshConfig, nil
}

// setupAuthMethods configures SSH authentication methods based on config
func setupAuthMethods(config Config) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	// Password authentication
	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	// Public key authentication from file
	if config.KeyPath != "" {
		key, err := ioutil.ReadFile(config.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key from %s: %w", config.KeyPath, err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// SSH agent authentication
	if config.UseSSHAgent {
		if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method configured")
	}

	return authMethods, nil
}

// setupHostKeyVerification configures host key verification based on config
func setupHostKeyVerification(config Config) (ssh.HostKeyCallback, error) {
	// If strict checking is disabled and no fingerprints provided, accept any host key (INSECURE)
	if !config.StrictHostKeyChecking && len(config.HostKeyFingerprints) == 0 && config.KnownHostsPath == "" {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	// If fingerprints are provided, verify against them
	if len(config.HostKeyFingerprints) > 0 {
		return createFingerprintVerifier(config.HostKeyFingerprints), nil
	}

	// If known_hosts path is provided, use it
	if config.KnownHostsPath != "" {
		callback, err := knownhosts.New(config.KnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts from %s: %w", config.KnownHostsPath, err)
		}
		return callback, nil
	}

	// Default: try to use ~/.ssh/known_hosts
	home, err := os.UserHomeDir()
	if err == nil {
		knownHostsFile := fmt.Sprintf("%s/.ssh/known_hosts", home)
		if _, err := os.Stat(knownHostsFile); err == nil {
			callback, err := knownhosts.New(knownHostsFile)
			if err == nil {
				return callback, nil
			}
		}
	}

	// If strict checking is required but no verification method is available, fail
	if config.StrictHostKeyChecking {
		return nil, fmt.Errorf("strict host key checking is enabled but no verification method is configured")
	}

	// Fall back to insecure mode with a warning
	return ssh.InsecureIgnoreHostKey(), nil
}

// createFingerprintVerifier creates a host key callback that verifies against provided fingerprints
func createFingerprintVerifier(expectedFingerprints []string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)

		for _, expected := range expectedFingerprints {
			if fingerprint == expected {
				return nil
			}
		}

		return fmt.Errorf("host key verification failed: fingerprint %s not in expected list", fingerprint)
	}
}

// ExecuteCommand executes a PowerShell command on the remote Windows server.
// It creates a new session for each command to ensure isolation.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - command: PowerShell command to execute
//
// Returns:
//   - stdout: Standard output from the command
//   - stderr: Standard error from the command
//   - error: Error if execution fails
func (c *Client) ExecuteCommand(ctx context.Context, command string) (stdout, stderr string, err error) {
	if !c.connected {
		return "", "", fmt.Errorf("client is not connected")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf strings.Builder
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	psCommand := fmt.Sprintf("powershell -NoProfile -NonInteractive -EncodedCommand %s",
		encodePowerShellCommand(command))

	errChan := make(chan error, 1)
	go func() {
		errChan <- session.Run(psCommand)
	}()

	select {
	case <-ctx.Done():
		session.Close()
		return "", "", fmt.Errorf("command execution cancelled: %w", ctx.Err())
	case execErr := <-errChan:
		c.lastUsed = time.Now()

		stdoutStr := stdoutBuf.String()
		stderrStr := stderrBuf.String()

		// Parse CLIXML errors if present
		if stderrStr != "" && (strings.Contains(stderrStr, "CLIXML") || strings.Contains(stderrStr, "<Objs")) {
			cleanError := ParseCLIXMLError(stderrStr)
			if cleanError != "" {
				stderrStr = cleanError
			}
		}

		return stdoutStr, stderrStr, execErr
	}
}

// encodePowerShellCommand encodes a PowerShell command in base64 for safe execution
func encodePowerShellCommand(command string) string {
	// Convert command to UTF-16LE (required by PowerShell -EncodedCommand)
	utf16 := encodeUTF16LE(command)

	// Base64 encode
	return base64Encode(utf16)
}

// encodeUTF16LE converts a string to UTF-16 Little Endian bytes
func encodeUTF16LE(s string) []byte {
	// Convert string to runes
	runes := []rune(s)

	// Allocate buffer (2 bytes per rune for UTF-16)
	buf := make([]byte, len(runes)*2)

	for i, r := range runes {
		// UTF-16LE encoding
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}

	return buf
}

// base64Encode encodes bytes to base64 string
func base64Encode(data []byte) string {
	// Use standard base64 encoding
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	result := make([]byte, (len(data)+2)/3*4)
	j := 0

	for i := 0; i < len(data); i += 3 {
		b := []byte{0, 0, 0}
		copy(b, data[i:min(i+3, len(data))])

		result[j] = base64Chars[b[0]>>2]
		result[j+1] = base64Chars[((b[0]&0x03)<<4)|(b[1]>>4)]

		if i+1 < len(data) {
			result[j+2] = base64Chars[((b[1]&0x0F)<<2)|(b[2]>>6)]
		} else {
			result[j+2] = '='
		}

		if i+2 < len(data) {
			result[j+3] = base64Chars[b[2]&0x3F]
		} else {
			result[j+3] = '='
		}

		j += 4
	}

	return string(result)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IsHealthy checks if the SSH connection is still alive and responsive
func (c *Client) IsHealthy(ctx context.Context) bool {
	if !c.connected {
		return false
	}

	// Try to execute a simple command
	_, _, err := c.ExecuteCommand(ctx, "Write-Output 'health-check'")
	return err == nil
}

// GetLastUsed returns the timestamp of when this client was last used
func (c *Client) GetLastUsed() time.Time {
	return c.lastUsed
}

// GetAge returns how long ago this client was created
func (c *Client) GetAge() time.Duration {
	return time.Since(c.createdAt)
}

// Close closes the SSH connection and cleans up resources
func (c *Client) Close() error {
	if !c.connected {
		return nil
	}

	c.connected = false

	if c.session != nil {
		if err := c.session.Close(); err != nil {
			// Session might already be closed, ignore error
		}
		c.session = nil
	}

	if c.client != nil {
		return c.client.Close()
	}

	return nil
}

// GetConfig returns the configuration used by this client
func (c *Client) GetConfig() Config {
	return c.config
}
