package common

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/kfrlabs/terraform-provider-windows/internal/ssh"
)

// ProviderData holds provider-level shared data that is made available to all
// resources and data sources. It manages SSH client connections and the connection pool.
type ProviderData struct {
	// connectionPool is the SSH connection pool for managing multiple reusable connections.
	// This is used when enable_connection_pool is true (recommended for production).
	connectionPool *ssh.ConnectionPool

	// sshConfig contains the SSH connection configuration including host, credentials,
	// timeout settings, and host key verification options.
	sshConfig ssh.Config

	// sshClient is a single persistent SSH client used when connection pooling is disabled.
	// This is the legacy mode and should only be used for debugging or specific use cases.
	sshClient *ssh.Client
}

// GetSSHClient retrieves an SSH client for executing commands on the Windows server.
// It handles both pooled and non-pooled connection modes automatically.
//
// When connection pooling is enabled (recommended):
//   - Gets a client from the connection pool
//   - The cleanup function MUST be called to return the client to the pool
//   - Failure to call cleanup will leak connections and eventually exhaust the pool
//
// When connection pooling is disabled:
//   - Returns the single persistent client
//   - The cleanup function is a no-op but should still be called for consistency
//
// Usage example:
//
//	client, cleanup, err := providerData.GetSSHClient(ctx)
//	if err != nil {
//	    return err
//	}
//	defer cleanup()
//
//	// Use client to execute commands
//	stdout, stderr, err := client.ExecuteCommand(ctx, "Get-WindowsFeature")
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//
// Returns:
//   - *ssh.Client: The SSH client to use for commands
//   - func(): Cleanup function that MUST be called when done (use defer)
//   - error: Error if client retrieval fails
func (d *ProviderData) GetSSHClient(ctx context.Context) (*ssh.Client, func(), error) {
	// Connection pool mode (recommended)
	if d.connectionPool != nil {
		tflog.Debug(ctx, "Getting SSH client from connection pool")

		client, err := d.connectionPool.Get(ctx)
		if err != nil {
			tflog.Error(ctx, "Failed to get client from connection pool", map[string]interface{}{
				"error": err.Error(),
			})
			return nil, nil, fmt.Errorf("failed to get connection from pool: %w", err)
		}

		// Log pool statistics for monitoring
		stats := d.connectionPool.Stats()
		tflog.Trace(ctx, "Connection pool status", map[string]interface{}{
			"active_count": stats.ActiveCount,
			"idle_count":   stats.IdleCount,
			"wait_count":   stats.WaitCount,
			"wait_time_ms": stats.WaitDuration.Milliseconds(),
		})

		// Cleanup function returns the client to the pool
		cleanup := func() {
			tflog.Trace(ctx, "Returning SSH client to connection pool")
			d.connectionPool.Put(client)
		}

		return client, cleanup, nil
	}

	// Single client mode (legacy)
	if d.sshClient != nil {
		tflog.Debug(ctx, "Using single SSH client (connection pool disabled)")

		// No cleanup needed for single client mode
		cleanup := func() {}

		return d.sshClient, cleanup, nil
	}

	// This should never happen if provider is configured correctly
	tflog.Error(ctx, "No SSH client or connection pool available")
	return nil, nil, fmt.Errorf("no SSH client or connection pool available - provider may not be configured correctly")
}

// GetPoolStats returns current statistics about the connection pool.
// This is useful for monitoring, debugging, and understanding connection usage patterns.
//
// Returns:
//   - ssh.PoolStats: Statistics structure containing pool metrics
//   - bool: true if connection pool is enabled, false otherwise
//
// The PoolStats structure includes:
//   - ActiveCount: Number of connections currently in use
//   - IdleCount: Number of idle connections available in the pool
//   - WaitCount: Number of requests waiting for a connection
//   - WaitDuration: Total time spent waiting for connections
//   - MaxActive: Maximum number of active connections allowed
//   - MaxIdle: Maximum number of idle connections to keep
//
// Usage example:
//
//	if stats, ok := providerData.GetPoolStats(); ok {
//	    tflog.Info(ctx, "Connection pool statistics", map[string]interface{}{
//	        "active": stats.ActiveCount,
//	        "idle":   stats.IdleCount,
//	    })
//	}
func (d *ProviderData) GetPoolStats() (ssh.PoolStats, bool) {
	if d.connectionPool != nil {
		return d.connectionPool.Stats(), true
	}
	return ssh.PoolStats{}, false
}

// GetSSHConfig returns the SSH configuration used by this provider.
// This can be useful for resources that need to access configuration details
// like the host, username, or timeout settings.
//
// Returns:
//   - ssh.Config: The SSH configuration structure
func (d *ProviderData) GetSSHConfig() ssh.Config {
	return d.sshConfig
}

// IsPoolingEnabled returns whether connection pooling is enabled for this provider.
// Resources can use this to log different messages or adjust behavior based on the mode.
//
// Returns:
//   - bool: true if connection pooling is enabled, false otherwise
func (d *ProviderData) IsPoolingEnabled() bool {
	return d.connectionPool != nil
}

// SetConnectionPool sets the connection pool (called by provider during configuration).
// This method is used by the provider to inject the connection pool after it's created.
//
// Parameters:
//   - pool: The configured connection pool instance
func (d *ProviderData) SetConnectionPool(pool *ssh.ConnectionPool) {
	d.connectionPool = pool
}

// SetSSHClient sets the SSH client (called by provider in legacy/non-pooled mode).
// This method is used by the provider to inject a single SSH client when pooling is disabled.
//
// Parameters:
//   - client: The configured SSH client instance
func (d *ProviderData) SetSSHClient(client *ssh.Client) {
	d.sshClient = client
}

// SetSSHConfig sets the SSH configuration (called by provider during configuration).
// This method is used by the provider to store the SSH configuration for later reference.
//
// Parameters:
//   - config: The SSH configuration with connection details
func (d *ProviderData) SetSSHConfig(config ssh.Config) {
	d.sshConfig = config
}

// ValidateConnection tests that the SSH connection is working properly.
// This can be called during resource creation or data source reads to fail fast
// if there are connection issues.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//
// Returns:
//   - error: nil if connection is valid, error with details otherwise
func (d *ProviderData) ValidateConnection(ctx context.Context) error {
	tflog.Debug(ctx, "Validating SSH connection")

	client, cleanup, err := d.GetSSHClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get SSH client: %w", err)
	}
	defer cleanup()

	// Execute a simple command to verify connectivity
	stdout, stderr, err := client.ExecuteCommand(ctx, "Write-Output 'connection-test'")
	if err != nil {
		tflog.Error(ctx, "Connection validation failed", map[string]interface{}{
			"error":  err.Error(),
			"stderr": stderr,
		})
		return fmt.Errorf("failed to validate connection: %w", err)
	}

	if stdout != "connection-test\n" && stdout != "connection-test\r\n" {
		tflog.Warn(ctx, "Unexpected output from validation command", map[string]interface{}{
			"expected": "connection-test",
			"actual":   stdout,
		})
		return fmt.Errorf("unexpected output from validation command: %s", stdout)
	}

	tflog.Debug(ctx, "SSH connection validated successfully")
	return nil
}

// Close gracefully closes all SSH connections and cleans up resources.
// This should be called when the provider is being shut down.
//
// Parameters:
//   - ctx: Context for cancellation and timeout handling
//
// Returns:
//   - error: Error if cleanup fails, nil otherwise
func (d *ProviderData) Close(ctx context.Context) error {
	tflog.Info(ctx, "Closing provider data and cleaning up connections")

	if d.connectionPool != nil {
		stats := d.connectionPool.Stats()
		tflog.Info(ctx, "Closing connection pool", map[string]interface{}{
			"active_connections": stats.ActiveCount,
			"idle_connections":   stats.IdleCount,
		})

		if err := d.connectionPool.Close(); err != nil {
			tflog.Error(ctx, "Error closing connection pool", map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to close connection pool: %w", err)
		}
	}

	if d.sshClient != nil {
		tflog.Debug(ctx, "Closing single SSH client")
		if err := d.sshClient.Close(); err != nil {
			tflog.Error(ctx, "Error closing SSH client", map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to close SSH client: %w", err)
		}
	}

	tflog.Info(ctx, "Provider data closed successfully")
	return nil
}

// LogPoolMetrics logs detailed connection pool metrics.
// This is useful for debugging performance issues or monitoring resource usage.
//
// Parameters:
//   - ctx: Context for logging
func (d *ProviderData) LogPoolMetrics(ctx context.Context) {
	if stats, ok := d.GetPoolStats(); ok {
		tflog.Info(ctx, "Connection pool metrics", map[string]interface{}{
			"active_count":    stats.ActiveCount,
			"idle_count":      stats.IdleCount,
			"wait_count":      stats.WaitCount,
			"wait_duration":   stats.WaitDuration.String(),
			"max_active":      stats.MaxActive,
			"max_idle":        stats.MaxIdle,
			"pooling_enabled": true,
		})
	} else {
		tflog.Debug(ctx, "Connection pool metrics not available (pooling disabled)")
	}
}
