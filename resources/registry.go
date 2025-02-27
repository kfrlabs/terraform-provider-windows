package resources

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/k9fr4n/tf-windows/resources/internal/ssh"
)

func ResourceWindowsRegistry() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsRegistryCreate,
		Read:   resourceWindowsRegistryRead,
		Update: resourceWindowsRegistryUpdate,
		Delete: resourceWindowsRegistryDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path to the registry key (e.g., 'HKLM:\\Software\\MyApp').",
			},
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the registry value (optional).",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "String",
				Description: "The type of the registry value (e.g., 'String', 'DWord', 'Binary').",
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value to set in the registry.",
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

func resourceWindowsRegistryCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	valueType := d.Get("type").(string)
	value := d.Get("value").(string)
	force := d.Get("force").(bool)
	timeout := d.Get("command_timeout").(int)

	command := ""
	if name != "" {
		command = fmt.Sprintf("New-Item -Path '%s' -Name '%s' -Value '%s' -Type '%s' %s", path, name, value, valueType, map[bool]string{true: "-Force", false: ""}[force])
	} else {
		command = fmt.Sprintf("New-Item -Path '%s' %s", path, map[bool]string{true: "-Force", false: ""}[force])
	}
	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to create registry key: %w", err)
	}

	d.SetId(path)
	return resourceWindowsRegistryRead(d, m)
}

func resourceWindowsRegistryRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Vérifier si la clé existe
	command := fmt.Sprintf("Test-Path -Path '%s'", path)
	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		d.SetId("")
		return nil
	}

	// Si un nom de valeur est spécifié, vérifier la valeur
	if name != "" {
		command = fmt.Sprintf("Get-ItemProperty -Path '%s' -Name '%s' -ErrorAction SilentlyContinue", path, name)
		if err := sshClient.ExecuteCommand(command, timeout); err != nil {
			d.SetId("")
			return nil
		}
	}

	return nil
}

func resourceWindowsRegistryUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	value := d.Get("value").(string)
	valueType := d.Get("type").(string)
	timeout := d.Get("command_timeout").(int)

	if name != "" {
		command := fmt.Sprintf("Set-ItemProperty -Path '%s' -Name '%s' -Value '%s' -Type '%s'", path, name, value, valueType)
		if err := sshClient.ExecuteCommand(command, timeout); err != nil {
			return fmt.Errorf("failed to update registry value: %w", err)
		}
	}

	return resourceWindowsRegistryRead(d, m)
}

func resourceWindowsRegistryDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	var command string
	if name == "" {
		// Supprimer la clé de registre
		command = fmt.Sprintf("Remove-Item -Path '%s' -Recurse -Force", path)
	} else {
		// Supprimer une valeur spécifique
		command = fmt.Sprintf("Remove-ItemProperty -Path '%s' -Name '%s' -Force", path, name)
	}

	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to delete registry key/value: %w", err)
	}

	d.SetId("")
	return nil
}
