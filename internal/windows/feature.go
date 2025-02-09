package windows

import (
	"github.com/FranckSallet/tf-windows/internal/powershell"
	"github.com/FranckSallet/tf-windows/internal/ssh"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func ResourceWindowsFeature() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsFeatureCreate,
		Read:   resourceWindowsFeatureRead,
		Update: resourceWindowsFeatureUpdate,
		Delete: resourceWindowsFeatureDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the Windows feature to install or remove.",
			},
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
				Required:    true,
				Sensitive:   true,
				Description: "The password for SSH authentication.",
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
			"output": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The output of the PowerShell command.",
			},
		},
	}
}

func resourceWindowsFeatureCreate(d *schema.ResourceData, m interface{}) error {
	name := d.Get("name").(string)
	host := d.Get("host").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	keyPath := d.Get("key_path").(string)
	useSSHAgent := d.Get("use_ssh_agent").(bool)

	sshClient, err := ssh.CreateSSHClient(host, username, password, keyPath, useSSHAgent)
	if err != nil {
		return err
	}
	defer sshClient.Close()

	command := "Install-WindowsFeature -Name " + name
	output, err := powershell.ExecutePowerShellCommand(sshClient, command)
	if err != nil {
		return err
	}

	d.SetId(name)
	d.Set("output", output)
	return nil
}

func resourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	// Implement reading logic if needed
	// For example, you might want to check if the feature is installed
	return nil
}

func resourceWindowsFeatureUpdate(d *schema.ResourceData, m interface{}) error {
	// Implement update logic if needed
	// For example, you might want to handle changes to the feature configuration
	return nil
}

func resourceWindowsFeatureDelete(d *schema.ResourceData, m interface{}) error {
	name := d.Get("name").(string)
	host := d.Get("host").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	keyPath := d.Get("key_path").(string)
	useSSHAgent := d.Get("use_ssh_agent").(bool)

	sshClient, err := ssh.CreateSSHClient(host, username, password, keyPath, useSSHAgent)
	if err != nil {
		return err
	}
	defer sshClient.Close()

	command := "Remove-WindowsFeature -Name " + name
	_, err = powershell.ExecutePowerShellCommand(sshClient, command)
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}
