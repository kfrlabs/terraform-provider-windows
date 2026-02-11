package provider

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/common"
	"github.com/kfrlabs/terraform-provider-windows/internal/datasources"
	"github.com/kfrlabs/terraform-provider-windows/internal/resources"
	"github.com/kfrlabs/terraform-provider-windows/internal/ssh"
)

// Ensure the implementation satisfies the provider.Provider interface
var _ provider.Provider = &windowsProvider{}

// windowsProvider defines the provider implementation
type windowsProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance tests
	version string
}

// windowsProviderModel describes the provider configuration data model
type windowsProviderModel struct {
	Host                  types.String `tfsdk:"host"`
	Username              types.String `tfsdk:"username"`
	Password              types.String `tfsdk:"password"`
	KeyPath               types.String `tfsdk:"key_path"`
	UseSSHAgent           types.Bool   `tfsdk:"use_ssh_agent"`
	ConnTimeout           types.Int64  `tfsdk:"conn_timeout"`
	KnownHostsPath        types.String `tfsdk:"known_hosts_path"`
	HostKeyFingerprints   types.List   `tfsdk:"host_key_fingerprints"`
	StrictHostKeyChecking types.Bool   `tfsdk:"strict_host_key_checking"`

	// Connection Pool Settings
	EnableConnectionPool types.Bool  `tfsdk:"enable_connection_pool"`
	PoolMaxIdle          types.Int64 `tfsdk:"pool_max_idle"`
	PoolMaxActive        types.Int64 `tfsdk:"pool_max_active"`
	PoolIdleTimeout      types.Int64 `tfsdk:"pool_idle_timeout"`
}

// New creates a new provider instance
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &windowsProvider{
			version: version,
		}
	}
}

// Metadata returns the provider type name
func (p *windowsProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "windows"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data
func (p *windowsProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provider for managing Windows Server resources via SSH/PowerShell",
		MarkdownDescription: `
The Windows provider allows you to manage Windows Server resources using SSH and PowerShell.

## Example Usage

` + "```terraform" + `
provider "windows" {
  host     = "windows-server.example.com"
  username = "Administrator"
  password = var.windows_password
  
  # Connection pool settings for better performance
  enable_connection_pool = true
  pool_max_idle          = 5
  pool_max_active        = 10
  
  # Security settings
  strict_host_key_checking = true
  host_key_fingerprints = [
    "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  ]
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			// Connection Settings
			"host": schema.StringAttribute{
				Description: "The hostname or IP address of the Windows server",
				Required:    true,
			},
			"username": schema.StringAttribute{
				Description: "The username for SSH authentication",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description:         "The password for SSH authentication. Can also be set via WINDOWS_PASSWORD environment variable",
				MarkdownDescription: "The password for SSH authentication. Can also be set via `WINDOWS_PASSWORD` environment variable",
				Optional:            true,
				Sensitive:           true,
			},
			"key_path": schema.StringAttribute{
				Description: "The path to the private key for SSH authentication (PEM format)",
				Optional:    true,
			},
			"use_ssh_agent": schema.BoolAttribute{
				Description: "Whether to use the SSH agent for authentication",
				Optional:    true,
			},
			"conn_timeout": schema.Int64Attribute{
				Description: "Timeout in seconds for SSH connection (default: 30)",
				Optional:    true,
			},

			// Security Settings
			"known_hosts_path": schema.StringAttribute{
				Description: "Path to the SSH known_hosts file for host key verification (e.g., ~/.ssh/known_hosts)",
				Optional:    true,
			},
			"host_key_fingerprints": schema.ListAttribute{
				Description: "List of expected SSH host key fingerprints (SHA256 format: 'SHA256:xxxxxx...'). If provided, the host key will be verified against these fingerprints",
				ElementType: types.StringType,
				Optional:    true,
			},
			"strict_host_key_checking": schema.BoolAttribute{
				Description: "If true, fail if host key is not found in known_hosts or fingerprints don't match. Default is true for security",
				Optional:    true,
			},

			// Connection Pool Settings
			"enable_connection_pool": schema.BoolAttribute{
				Description: "Enable SSH connection pooling for better performance (default: true)",
				Optional:    true,
			},
			"pool_max_idle": schema.Int64Attribute{
				Description: "Maximum number of idle connections in the pool (default: 5)",
				Optional:    true,
			},
			"pool_max_active": schema.Int64Attribute{
				Description: "Maximum number of active connections (0 = unlimited, default: 10)",
				Optional:    true,
			},
			"pool_idle_timeout": schema.Int64Attribute{
				Description: "Maximum time (in seconds) a connection can be idle before being closed (default: 300)",
				Optional:    true,
			},
		},
	}
}

// Configure prepares the provider with SSH client and connection pool
func (p *windowsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config windowsProviderModel

	// Read configuration data into model
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Allow configuration via environment variables
	if config.Password.IsNull() {
		if password := os.Getenv("WINDOWS_PASSWORD"); password != "" {
			config.Password = types.StringValue(password)
		}
	}

	// Set defaults
	if config.ConnTimeout.IsNull() {
		config.ConnTimeout = types.Int64Value(30)
	}
	if config.StrictHostKeyChecking.IsNull() {
		config.StrictHostKeyChecking = types.BoolValue(true)
	}
	if config.EnableConnectionPool.IsNull() {
		config.EnableConnectionPool = types.BoolValue(true)
	}
	if config.PoolMaxIdle.IsNull() {
		config.PoolMaxIdle = types.Int64Value(5)
	}
	if config.PoolMaxActive.IsNull() {
		config.PoolMaxActive = types.Int64Value(10)
	}
	if config.PoolIdleTimeout.IsNull() {
		config.PoolIdleTimeout = types.Int64Value(300)
	}

	tflog.Info(ctx, "Configuring Windows provider", map[string]any{
		"host":                   config.Host.ValueString(),
		"username":               config.Username.ValueString(),
		"enable_connection_pool": config.EnableConnectionPool.ValueBool(),
	})

	// Build SSH configuration
	sshConfig := ssh.Config{
		Host:                  config.Host.ValueString(),
		Username:              config.Username.ValueString(),
		Password:              config.Password.ValueString(),
		KeyPath:               config.KeyPath.ValueString(),
		UseSSHAgent:           config.UseSSHAgent.ValueBool(),
		ConnTimeout:           time.Duration(config.ConnTimeout.ValueInt64()) * time.Second,
		KnownHostsPath:        config.KnownHostsPath.ValueString(),
		StrictHostKeyChecking: config.StrictHostKeyChecking.ValueBool(),
	}

	// Process host key fingerprints
	if !config.HostKeyFingerprints.IsNull() {
		var fingerprints []string
		resp.Diagnostics.Append(config.HostKeyFingerprints.ElementsAs(ctx, &fingerprints, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		sshConfig.HostKeyFingerprints = fingerprints
		tflog.Debug(ctx, "Host key fingerprints configured", map[string]any{
			"count": len(fingerprints),
		})
	}

	// Validate security configuration
	p.validateSecurityConfig(ctx, config, resp)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate authentication method
	hasPassword := !config.Password.IsNull() && config.Password.ValueString() != ""
	hasKeyPath := !config.KeyPath.IsNull() && config.KeyPath.ValueString() != ""
	useSSHAgent := !config.UseSSHAgent.IsNull() && config.UseSSHAgent.ValueBool()

	if !hasPassword && !hasKeyPath && !useSSHAgent {
		resp.Diagnostics.AddError(
			"No authentication method provided",
			"You must provide at least one authentication method: password, key_path, or use_ssh_agent",
		)
		return
	}

	// Initialize provider data - use setters instead of direct field access
	providerData := &common.ProviderData{}
	providerData.SetSSHConfig(sshConfig)

	// Setup connection pool or single client
	if config.EnableConnectionPool.ValueBool() {
		poolConfig := ssh.PoolConfig{
			MaxIdle:      int(config.PoolMaxIdle.ValueInt64()),
			MaxActive:    int(config.PoolMaxActive.ValueInt64()),
			IdleTimeout:  time.Duration(config.PoolIdleTimeout.ValueInt64()) * time.Second,
			WaitTimeout:  30 * time.Second,
			TestOnBorrow: true,
			TestInterval: 30 * time.Second,
		}

		// Use setter method instead of direct field access
		providerData.SetConnectionPool(ssh.NewConnectionPool(sshConfig, poolConfig))

		tflog.Info(ctx, "Connection pool created", map[string]any{
			"max_idle":     poolConfig.MaxIdle,
			"max_active":   poolConfig.MaxActive,
			"idle_timeout": poolConfig.IdleTimeout.String(),
		})
	} else {
		// Legacy single connection mode
		tflog.Info(ctx, "Connection pooling disabled, using single connection mode")

		sshClient, err := ssh.NewClient(sshConfig)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to create SSH client",
				fmt.Sprintf("Failed to configure SSH client: %v", err),
			)
			return
		}

		// Use setter method instead of direct field access
		providerData.SetSSHClient(sshClient)
		tflog.Debug(ctx, "SSH client created successfully", map[string]any{
			"host": sshConfig.Host,
		})
	}

	// Make provider data available to resources and data sources
	resp.DataSourceData = providerData
	resp.ResourceData = providerData

	tflog.Info(ctx, "Windows provider configured successfully")
}

// validateSecurityConfig validates the security configuration
func (p *windowsProvider) validateSecurityConfig(ctx context.Context, config windowsProviderModel, resp *provider.ConfigureResponse) {
	strictHostKey := config.StrictHostKeyChecking.ValueBool()
	hasFingerprints := !config.HostKeyFingerprints.IsNull()
	hasKnownHosts := !config.KnownHostsPath.IsNull() && config.KnownHostsPath.ValueString() != ""

	if !strictHostKey && !hasFingerprints && !hasKnownHosts {
		resp.Diagnostics.AddWarning(
			"Insecure SSH configuration",
			"Host key verification is disabled without fingerprints or known_hosts. "+
				"This configuration is insecure and should only be used in development environments. "+
				"For production, enable strict_host_key_checking or provide host_key_fingerprints.",
		)
	}
}

// Resources returns the list of resources supported by this provider
func (p *windowsProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewFeatureResource,
		resources.NewHostnameResource,
		resources.NewLocalUserResource,
		// resources.NewLocalGroupResource,
		// resources.NewLocalGroupMemberResource,
		// resources.NewRegistryKeyResource,
		// resources.NewRegistryValueResource,
		// resources.NewServiceResource,
	}
}

// DataSources returns the list of data sources supported by this provider
func (p *windowsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		datasources.NewFeatureDataSource,
		datasources.NewHostnameDataSource,
		datasources.NewLocalUserDataSource,
		// datasources.NewLocalGroupDataSource,
		// datasources.NewLocalGroupMembersDataSource,
		// datasources.NewServiceDataSource,
		// datasources.NewRegistryValueDataSource,
	}
}
