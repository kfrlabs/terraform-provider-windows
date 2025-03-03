package resources

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/k9fr4n/terraform-provider-windows/windows/internal/ssh"
)

func ResourceWindowsRegistryValue() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsRegistryValueCreate,
		Read:   resourceWindowsRegistryValueRead,
		Update: resourceWindowsRegistryValueUpdate,
		Delete: resourceWindowsRegistryValueDelete,
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
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the registry value (optional).",
				ForceNew:    true,
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "String",
				Description:  "The type of the registry value (e.g., 'String', 'DWord', 'Binary').",
				ValidateFunc: validation.StringInSlice([]string{"String", "ExpandString", "Binary", "DWord", "MultiString", "Qword", "Unknown"}, false),
				ForceNew:     true,
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value to set in the registry.",
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

func resourceWindowsRegistryValueCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	valueType := d.Get("type").(string)
	value := d.Get("value").(string)
	timeout := d.Get("command_timeout").(int)

	// Check if the registry key exists
	command := fmt.Sprintf("Get-Item -Path '%s'", path)
	_, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to check registry key: %w\nStderr: %s", err, stderr)
	}

	// Create the registry value
	command = fmt.Sprintf("New-ItemProperty -Path '%s' -Name '%s' -Value '%s' -PropertyType '%s'", path, name, value, valueType)
	_, stderr, err = sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to create registry value: %w\nStderr: %s", err, stderr)
	}

	d.SetId(fmt.Sprintf("%s\\%s", path, name))
	return resourceWindowsRegistryValueRead(d, m)
}

func resourceWindowsRegistryValueRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Commande pour obtenir la valeur actuelle du registre
	command := fmt.Sprintf("Get-ItemPropertyValue -Path '%s' -Name '%s'", path, name)
	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("failed to read registry value: %w\nStderr: %s", err, stderr)
	}

	// Mettre à jour l'état de Terraform avec la valeur récupérée
	if err := d.Set("value", stdout); err != nil {
		return fmt.Errorf("failed to set value in state: %w", err)
	}

	return nil
}

func resourceWindowsRegistryValueUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	value := d.Get("value").(string)
	timeout := d.Get("command_timeout").(int)

	command := fmt.Sprintf("Set-ItemProperty -Path '%s' -Name '%s' -Value '%s'", path, name, value)
	_, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to update registry value: %w\nStderr: %s", err, stderr)
	}

	return resourceWindowsRegistryValueRead(d, m)
}

func resourceWindowsRegistryValueDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	command := fmt.Sprintf("Remove-ItemProperty -Path '%s' -Name '%s' -Force", path, name)
	_, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to delete registry value: %w\nStderr: %s", err, stderr)
	}

	d.SetId("")
	return nil
}
