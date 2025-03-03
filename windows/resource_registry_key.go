package resources

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/k9fr4n/tf-windows/windows/internal/ssh"
)

func ResourceWindowsRegistryKey() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsRegistryKeyCreate,
		Read:   resourceWindowsRegistryKeyRead,
		Update: resourceWindowsRegistryKeyUpdate,
		Delete: resourceWindowsRegistryKeyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path to the registry key (e.g., 'HKLM:\\Software\\MyApp').",
				ForceNew:    true,
			},
			"force": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to force the creation of parent keys if they do not exist.",
			},
			"command_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     300,
				Description: "Timeout in seconds for PowerShell commands.",
			},
		},
	}
}

func resourceWindowsRegistryKeyCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	force := d.Get("force").(bool)
	timeout := d.Get("command_timeout").(int)

	command := fmt.Sprintf("New-Item -Path '%s' %s", path, map[bool]string{true: "-Force", false: ""}[force])
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to create registry key: %w", err)
	}

	d.SetId(path)
	return resourceWindowsRegistryKeyRead(d, m)
}

func resourceWindowsRegistryKeyRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	timeout := d.Get("command_timeout").(int)

	command := fmt.Sprintf("Test-Path -Path '%s'", path)
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		d.SetId("")
		return nil
	}

	return nil
}

func resourceWindowsRegistryKeyUpdate(d *schema.ResourceData, m interface{}) error {
	// Update logic for registry keys if needed
	return resourceWindowsRegistryKeyRead(d, m)
}

func resourceWindowsRegistryKeyDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	timeout := d.Get("command_timeout").(int)

	command := fmt.Sprintf("Remove-Item -Path '%s' -Recurse -Force", path)
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to delete registry key: %w", err)
	}

	d.SetId("")
	return nil
}
