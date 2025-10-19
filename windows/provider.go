package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

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
				Description: "Path to the SSH known_hosts file for host key verification (e.g., ~/.ssh/known_hosts). If not specified, ~/.ssh/known_hosts will be used.",
			},
			"host_key_fingerprints": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of expected SSH host key fingerprints (SHA256 format: 'SHA256:xxxxxx...'). If provided, the host key will be verified against these fingerprints instead of known_hosts.",
			},
			"strict_host_key_checking": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, fail if host key is not found in known_hosts or fingerprints don't match. If false, log a warning but proceed (not recommended for production).",
			},
			"skip_host_key_verification": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "⚠️ DEPRECATED and INSECURE: Skip SSH host key verification entirely. Use known_hosts_path or host_key_fingerprints instead. This option is provided only for backward compatibility and testing.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"windows_feature":        ResourceWindowsFeature(),
			"windows_hostname":       ResourceWindowsHostname(),
			"windows_localuser":      ResourceWindowsLocalUser(),
			"windows_localgroup":     ResourceWindowsLocalGroup(),
			"windows_registry_key":   ResourceWindowsRegistryKey(),
			"windows_registry_value": ResourceWindowsRegistryValue(),
			"windows_service":        ResourceWindowsService(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, error) {
	tflog.Info(ctx, "configuring Windows provider",
		map[string]any{
			"host":     d.Get("host").(string),
			"username": d.Get("username").(string),
		})

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

	// Traiter les empreintes digitales host key
	if fingerprints, ok := d.GetOk("host_key_fingerprints"); ok {
		fpList := fingerprints.([]interface{})
		config.HostKeyFingerprints = make([]string, len(fpList))
		for i, fp := range fpList {
			config.HostKeyFingerprints[i] = fp.(string)
		}

		tflog.Debug(ctx, "host key fingerprints configured",
			map[string]any{"count": len(config.HostKeyFingerprints)})
	}

	// ⚠️ Vérifier l'option dépréciée
	if d.Get("skip_host_key_verification").(bool) {
		tflog.Warn(ctx,
			"⚠️  DEPRECATED: skip_host_key_verification is deprecated and INSECURE. "+
				"Use known_hosts_path or host_key_fingerprints instead for production environments.",
		)
	}

	sshClient, err := ssh.NewClient(config)
	if err != nil {
		tflog.Error(ctx, "failed to create SSH client",
			map[string]any{"error": err.Error()})
		return nil, fmt.Errorf("failed to create SSH client: %v", err)
	}

	tflog.Debug(ctx, "SSH client created successfully",
		map[string]any{"host": config.Host})

	return sshClient, nil
}
