package resources

import (
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/k9fr4n/tf-windows/windows/internal/ssh"
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
				Description: "The password for SSH authentication. Required if use_ssh_agent is false.",
			},
			"key_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The path to the private key for SSH authentication.",
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
		},
		ResourcesMap: map[string]*schema.Resource{
			"windows_feature": ResourceWindowsFeature(),
			"registry_key":    ResourceWindowsRegistryKey(),
			"registry_value":  ResourceWindowsRegistryValue(),
		},
		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := ssh.Config{
		Host:        d.Get("host").(string),
		Username:    d.Get("username").(string),
		Password:    d.Get("password").(string),
		KeyPath:     d.Get("key_path").(string),
		UseSSHAgent: d.Get("use_ssh_agent").(bool),
		ConnTimeout: time.Duration(d.Get("conn_timeout").(int)) * time.Second,
	}

	sshClient, err := ssh.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client: %v", err)
	}

	return sshClient, nil
}
