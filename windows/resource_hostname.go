package resources

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

func ResourceWindowsHostname() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsHostnameCreate,
		Read:   resourceWindowsHostnameRead,
		Update: resourceWindowsHostnameUpdate,
		Delete: resourceWindowsHostnameDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The new hostname to apply to the Windows machine.",
			},
			"restart": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Restart the computer after renaming.",
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

func resourceWindowsHostnameCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	hostname := d.Get("hostname").(string)
	timeout := d.Get("command_timeout").(int)
	restart := d.Get("restart").(bool)

	command := fmt.Sprintf("Rename-Computer -NewName '%s' -Force -ErrorAction Stop", hostname)
	if restart {
		command += " -Restart"
	}
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to set hostname: %w", err)
	}

	d.SetId(hostname)
	return resourceWindowsHostnameRead(d, m)
}

func resourceWindowsHostnameRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	timeout, ok := d.GetOk("command_timeout")
	if !ok {
		timeout = 300
	}

	command := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(command, timeout.(int))
	if err != nil || stdout != d.Get("hostname").(string) {
		d.SetId("")
		return nil
	}
	return nil
}

func resourceWindowsHostnameUpdate(d *schema.ResourceData, m interface{}) error {
	return resourceWindowsHostnameCreate(d, m)
}

func resourceWindowsHostnameDelete(d *schema.ResourceData, m interface{}) error {
	// Optional: restore the previous hostname if needed
	d.SetId("")
	return nil
}
