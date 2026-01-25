package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

// ProviderMeta holds provider-level metadata including the connection pool
type ProviderMeta struct {
	connectionPool *ssh.ConnectionPool
	sshConfig      ssh.Config
}

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"host": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The hostname or IP address of the Windows server.",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The username for SSH authentication.",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The password for SSH authentication. Required if use_ssh_agent is false and key_path is not set.",
			},
			"key_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The path to the private key for SSH authentication (PEM format).",
			},
			"use_ssh_agent": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to use the SSH agent for authentication.",
			},
			"conn_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     30,
				Description: "Timeout in seconds for SSH connection.",
			},
			"known_hosts_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH known_hosts file for host key verification (e.g., ~/.ssh/known_hosts). If not specified, ~/.ssh/known_hosts will be used by default.",
			},
			"host_key_fingerprints": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Description: "List of expected SSH host key fingerprints (SHA256 format: 'SHA256:xxxxxx...'). " +
					"If provided, the host key will be verified against these fingerprints instead of known_hosts.",
			},
			"strict_host_key_checking": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				Description: "If true, fail if host key is not found in known_hosts or fingerprints don't match. " +
					"If false, log a warning but proceed. Default is true for security.",
			},
			// Connection Pool Settings
			"enable_connection_pool": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable SSH connection pooling for better performance.",
			},
			"pool_max_idle": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     5,
				Description: "Maximum number of idle connections in the pool.",
			},
			"pool_max_active": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     10,
				Description: "Maximum number of active connections (0 = unlimited).",
			},
			"pool_idle_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     300,
				Description: "Maximum time (in seconds) a connection can be idle before being closed.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"windows_feature":          ResourceWindowsFeature(),
			"windows_hostname":         ResourceWindowsHostname(),
			"windows_localuser":        ResourceWindowsLocalUser(),
			"windows_localgroup":       ResourceWindowsLocalGroup(),
			"windows_localgroupmember": ResourceWindowsLocalGroupMember(),
			"windows_registry_key":     ResourceWindowsRegistryKey(),
			"windows_registry_value":   ResourceWindowsRegistryValue(),
			"windows_service":          ResourceWindowsService(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"windows_localuser":         DataSourceWindowsLocalUser(),
			"windows_localgroup":        DataSourceWindowsLocalGroup(),
			"windows_localgroupmembers": DataSourceWindowsLocalGroupMembers(),
			"windows_service":           DataSourceWindowsService(),
			"windows_registry_value":    DataSourceWindowsRegistryValue(),
			"windows_feature":           DataSourceWindowsFeature(),
			"windows_hostname":          DataSourceWindowsHostname(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

// providerConfigure configures the Windows provider with SSH settings and connection pool
func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Info(ctx, "configuring Windows provider",
		map[string]any{
			"host":     d.Get("host").(string),
			"username": d.Get("username").(string),
		})

	// Build SSH configuration
	config := ssh.Config{
		Host:                  d.Get("host").(string),
		Username:              d.Get("username").(string),
		Password:              d.Get("password").(string),
		KeyPath:               d.Get("key_path").(string),
		UseSSHAgent:           d.Get("use_ssh_agent").(bool),
		ConnTimeout:           time.Duration(d.Get("conn_timeout").(int)) * time.Second,
		KnownHostsPath:        d.Get("known_hosts_path").(string),
		StrictHostKeyChecking: d.Get("strict_host_key_checking").(bool),
	}

	// Process host key fingerprints
	if fingerprints, ok := d.GetOk("host_key_fingerprints"); ok {
		fpList := fingerprints.([]interface{})
		config.HostKeyFingerprints = make([]string, len(fpList))
		for i, fp := range fpList {
			config.HostKeyFingerprints[i] = fp.(string)
		}
		tflog.Debug(ctx, "host key fingerprints configured",
			map[string]any{"count": len(config.HostKeyFingerprints)})
	}

	// Security validation
	securityDiags := validateSecurityConfig(d)
	diags = append(diags, securityDiags...)

	// Check if connection pooling is enabled
	enablePool := d.Get("enable_connection_pool").(bool)

	if enablePool {
		// Create connection pool
		poolConfig := ssh.PoolConfig{
			MaxIdle:      d.Get("pool_max_idle").(int),
			MaxActive:    d.Get("pool_max_active").(int),
			IdleTimeout:  time.Duration(d.Get("pool_idle_timeout").(int)) * time.Second,
			WaitTimeout:  30 * time.Second,
			TestOnBorrow: true,
			TestInterval: 30 * time.Second,
		}

		pool := ssh.NewConnectionPool(config, poolConfig)

		tflog.Info(ctx, "connection pool created",
			map[string]any{
				"max_idle":     poolConfig.MaxIdle,
				"max_active":   poolConfig.MaxActive,
				"idle_timeout": poolConfig.IdleTimeout,
			})

		meta := &ProviderMeta{
			connectionPool: pool,
			sshConfig:      config,
		}

		return meta, diags
	}

	// Fallback to single SSH client (legacy mode)
	tflog.Info(ctx, "connection pooling disabled, using single connection mode")

	sshClient, err := ssh.NewClient(config)
	if err != nil {
		errMsg := fmt.Sprintf("failed to create SSH client: %v", err)
		tflog.Error(ctx, errMsg)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Failed to configure SSH client",
			Detail:   errMsg,
		})
		return nil, diags
	}

	tflog.Debug(ctx, "SSH client created successfully",
		map[string]any{"host": config.Host})

	return sshClient, diags
}

// validateSecurityConfig validates the security configuration
func validateSecurityConfig(d *schema.ResourceData) diag.Diagnostics {
	var diags diag.Diagnostics

	strictHostKey := d.Get("strict_host_key_checking").(bool)
	hasFingerprints := false
	hasKnownHosts := d.Get("known_hosts_path").(string) != ""

	if fingerprints, ok := d.GetOk("host_key_fingerprints"); ok {
		hasFingerprints = len(fingerprints.([]interface{})) > 0
	}

	if !strictHostKey && !hasFingerprints && !hasKnownHosts {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Insecure SSH configuration",
			Detail: "Host key verification is disabled without fingerprints or known_hosts. " +
				"This configuration is insecure and should only be used in development environments. " +
				"For production, enable strict_host_key_checking or provide host_key_fingerprints.",
		})
	}

	// Validate that authentication method is provided
	hasPassword := d.Get("password").(string) != ""
	hasKeyPath := d.Get("key_path").(string) != ""
	useSSHAgent := d.Get("use_ssh_agent").(bool)

	if !hasPassword && !hasKeyPath && !useSSHAgent {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "No authentication method provided",
			Detail:   "You must provide at least one authentication method: password, key_path, or use_ssh_agent.",
		})
	}

	return diags
}

// GetSSHClient gets an SSH client from the provider meta
// This helper function abstracts the connection pool vs single client logic
func GetSSHClient(ctx context.Context, m interface{}) (*ssh.Client, func(), error) {
	switch meta := m.(type) {
	case *ProviderMeta:
		// Connection pool mode
		client, err := meta.connectionPool.Get(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get connection from pool: %w", err)
		}

		// Return client and cleanup function
		cleanup := func() {
			meta.connectionPool.Put(client)
		}

		return client, cleanup, nil

	case *ssh.Client:
		// Single client mode (legacy)
		// No cleanup needed as the connection is reused
		cleanup := func() {}
		return meta, cleanup, nil

	default:
		return nil, nil, fmt.Errorf("invalid provider meta type")
	}
}

// GetPoolStats returns connection pool statistics if pooling is enabled
func GetPoolStats(m interface{}) (ssh.PoolStats, bool) {
	if meta, ok := m.(*ProviderMeta); ok {
		return meta.connectionPool.Stats(), true
	}
	return ssh.PoolStats{}, false
}
