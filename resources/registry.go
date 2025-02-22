package resources

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/k9fr4n/tf-windows/resources/internal/ssh"
)

func ResourceWindowsRegistry() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsRegistryCreate,
		Read:   resourceWindowsRegistryRead,
		Update: resourceWindowsRegistryUpdate,
		Delete: resourceWindowsRegistryDelete,

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

	// Construire la commande PowerShell pour créer la clé ou la valeur
	command := fmt.Sprintf("New-Item -Path '%s' -Force:$%t", path, force)
	if name != "" {
		command += fmt.Sprintf("; Set-ItemProperty -Path '%s' -Name '%s' -Value '%s' -Type '%s'", path, name, value, valueType)
	}

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to create registry key or value: %v", err)
	}

	// Définir l'ID de la ressource comme le chemin de la clé
	d.SetId(path)
	return nil
}

func resourceWindowsRegistryRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Construire la commande PowerShell pour vérifier si la clé ou la valeur existe
	command := fmt.Sprintf("Test-Path -Path '%s'", path)
	if name != "" {
		command += fmt.Sprintf("; Get-ItemProperty -Path '%s' -Name '%s' -ErrorAction SilentlyContinue", path, name)
	}

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		// Si la commande échoue, la clé ou la valeur n'existe pas
		d.SetId("")
		return nil
	}

	// Si la commande réussit, la clé ou la valeur existe
	return nil
}

func resourceWindowsRegistryUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	value := d.Get("value").(string)
	valueType := d.Get("type").(string)
	timeout := d.Get("command_timeout").(int)

	// Construire la commande PowerShell pour mettre à jour la valeur
	command := fmt.Sprintf("Set-ItemProperty -Path '%s' -Name '%s' -Value '%s' -Type '%s'", path, name, value, valueType)

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to update registry value: %v", err)
	}

	return nil
}

func resourceWindowsRegistryDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Construire la commande PowerShell pour supprimer la clé ou la valeur
	command := fmt.Sprintf("Remove-ItemProperty -Path '%s'", path)
	if name != "" {
		command += fmt.Sprintf(" -Name '%s'", name)
	}

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to delete registry key or value: %v", err)
	}

	// Supprimer l'ID de la ressource
	d.SetId("")
	return nil
}
