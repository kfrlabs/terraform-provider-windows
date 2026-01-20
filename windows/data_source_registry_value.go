package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

func DataSourceWindowsRegistryValue() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsRegistryValueRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path to the registry key (e.g., 'HKLM:\\Software\\MyApp').",
			},
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "The name of the registry value. Empty string for default value.",
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The value stored in the registry.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of the registry value (String, DWord, Binary, etc.).",
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

func dataSourceWindowsRegistryValueRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Reading registry value: %s", resourceID))

	// Valider les paramètres pour sécurité
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return utils.HandleResourceError("validate", resourceID, "path", err)
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return utils.HandleResourceError("validate", resourceID, "name", err)
		}
	}

	// Vérifier que la clé de registre existe
	checkKeyCommand := fmt.Sprintf("Test-Path -Path %s -ErrorAction Stop",
		powershell.QuotePowerShellString(path))

	keyStdout, keyStderr, keyErr := sshClient.ExecuteCommand(checkKeyCommand, timeout)
	if keyErr != nil || keyStdout != "True" {
		return utils.HandleCommandError(
			"check_key",
			resourceID,
			"state",
			checkKeyCommand,
			keyStdout,
			keyStderr,
			fmt.Errorf("registry key does not exist: %s", path),
		)
	}

	// Récupérer la valeur du registre
	exists, currentValue, err := checkRegistryValueExists(ctx, sshClient, path, name, timeout)
	if err != nil {
		return utils.HandleResourceError("read", resourceID, "state", err)
	}

	if !exists {
		return utils.HandleResourceError("read", resourceID, "state",
			fmt.Errorf("registry value does not exist: %s", resourceID))
	}

	// Récupérer le type de la valeur
	var typeCommand string
	if name == "" {
		typeCommand = fmt.Sprintf(
			"(Get-Item -Path %s -ErrorAction Stop).GetValueKind('(default)')",
			powershell.QuotePowerShellString(path),
		)
	} else {
		typeCommand = fmt.Sprintf(
			"(Get-Item -Path %s -ErrorAction Stop).GetValueKind(%s)",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name),
		)
	}

	typeStdout, _, typeErr := sshClient.ExecuteCommand(typeCommand, timeout)
	if typeErr != nil {
		// Si on ne peut pas obtenir le type, on met "Unknown"
		typeStdout = "Unknown"
	}

	// Nettoyer la sortie du type
	valueType := strings.TrimSpace(typeStdout)

	// Set all attributes
	d.SetId(resourceID)
	if err := d.Set("path", path); err != nil {
		return utils.HandleResourceError("read", resourceID, "path", err)
	}
	if err := d.Set("name", name); err != nil {
		return utils.HandleResourceError("read", resourceID, "name", err)
	}
	if err := d.Set("value", currentValue); err != nil {
		return utils.HandleResourceError("read", resourceID, "value", err)
	}
	if err := d.Set("type", valueType); err != nil {
		return utils.HandleResourceError("read", resourceID, "type", err)
	}

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Successfully read registry value: %s (type=%s)", resourceID, valueType))
	return nil
}
