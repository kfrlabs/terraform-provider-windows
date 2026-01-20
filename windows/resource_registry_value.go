package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
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
				Description: "The name of the registry value (optional, empty string for default value).",
				ForceNew:    true,
			},
			"type": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "String",
				Description:  "The type of the registry value (e.g., 'String', 'DWord', 'Binary').",
				ValidateFunc: validation.StringInSlice([]string{"String", "ExpandString", "Binary", "DWord", "MultiString", "QWord", "Unknown"}, false),
				ForceNew:     true,
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value to set in the registry.",
			},
			"allow_existing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, adopt existing registry value instead of failing. If false, fail if value already exists.",
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

// checkRegistryValueExists vérifie si une valeur de registre existe
func checkRegistryValueExists(ctx context.Context, sshClient *ssh.Client, path, name string, timeout int) (bool, string, error) {
	// Validate inputs for security
	resourceID := fmt.Sprintf("%s\\%s", path, name)
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return false, "", err
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return false, "", err
		}
	}

	// Build secure PowerShell command
	var command string
	if name == "" {
		// Check default value: (Get-ItemProperty -Path 'path').'(default)'
		command = fmt.Sprintf("(Get-ItemProperty -Path %s -ErrorAction Stop).'(default)'",
			powershell.QuotePowerShellString(path))
	} else {
		command = fmt.Sprintf("Get-ItemPropertyValue -Path %s -Name %s -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name))
	}

	tflog.Debug(ctx, fmt.Sprintf("Checking registry value existence: %s\\%s", path, name))

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return false, "", nil // Si erreur, la valeur n'existe pas
	}

	return true, strings.TrimSpace(stdout), nil
}

func resourceWindowsRegistryValueCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	valueType := d.Get("type").(string)
	value := d.Get("value").(string)
	allowExisting := d.Get("allow_existing").(bool)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// Validate inputs for security
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return err
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return err
		}
	}
	if err := utils.ValidateField(valueType, resourceID, "type"); err != nil {
		return err
	}

	// Check if the registry key exists
	checkKeyCommand := fmt.Sprintf("Test-Path -Path %s -ErrorAction Stop",
		powershell.QuotePowerShellString(path))

	tflog.Debug(ctx, fmt.Sprintf("Checking if registry key exists: %s", path))

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

	// Check if registry value already exists
	exists, currentValue, err := checkRegistryValueExists(ctx, sshClient, path, name, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", resourceID, "state", err)
	}

	if exists {
		if allowExisting {
			// Adopt the existing registry value
			tflog.Info(ctx, fmt.Sprintf("Registry value %s already exists with value '%s', adopting it (allow_existing=true)", resourceID, currentValue))
			d.SetId(resourceID)
			return resourceWindowsRegistryValueRead(d, m)
		} else {
			// Fail with clear error
			resourceName := "registry_value"
			return utils.HandleResourceError(
				"create",
				resourceID,
				"state",
				fmt.Errorf("registry value already exists with value '%s'. "+
					"To manage this existing registry value, either:\n"+
					"  1. Import it: terraform import windows_registry_value.%s '%s'\n"+
					"  2. Set allow_existing = true in your configuration\n"+
					"  3. Remove it first: Remove-ItemProperty -Path '%s' -Name '%s' -Force",
					currentValue, resourceName, resourceID, path, name),
			)
		}
	}

	// Build secure PowerShell command to create the value
	var command string
	if name == "" {
		// Set default value: Set-ItemProperty -Path 'path' -Name '(default)' -Value 'value'
		command = fmt.Sprintf("Set-ItemProperty -Path %s -Name '(default)' -Value %s -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(value))
	} else {
		command = fmt.Sprintf("New-ItemProperty -Path %s -Name %s -Value %s -PropertyType %s -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(value),
			powershell.QuotePowerShellString(valueType))
	}

	tflog.Info(ctx, fmt.Sprintf("Creating registry value: %s", resourceID))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"create",
			resourceID,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId(resourceID)
	return resourceWindowsRegistryValueRead(d, m)
}

func resourceWindowsRegistryValueRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	// Parse ID or get from schema
	var path, name string
	if d.Id() != "" {
		// L'ID est au format "path\name"
		// Il faut trouver le DERNIER backslash pour séparer correctement
		// car le path contient déjà des backslashes
		lastBackslash := strings.LastIndex(d.Id(), "\\")
		if lastBackslash > 0 {
			path = d.Id()[:lastBackslash]
			name = d.Id()[lastBackslash+1:]
		} else {
			// Fallback si pas de backslash trouvé
			path = d.Get("path").(string)
			name = d.Get("name").(string)
		}
	} else {
		path = d.Get("path").(string)
		name = d.Get("name").(string)
	}

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// Get timeout from schema
	timeout, ok := d.GetOk("command_timeout")
	if !ok {
		timeout = 300 // Default value from schema
	}

	// Validate inputs for security
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return utils.HandleResourceError("validate", resourceID, "path", err)
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return utils.HandleResourceError("validate", resourceID, "name", err)
		}
	}

	// Check if registry value exists and get its current value
	exists, currentValue, err := checkRegistryValueExists(ctx, sshClient, path, name, timeout.(int))
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to read registry value %s: %v", resourceID, err))
		d.SetId("")
		return nil
	}

	if !exists {
		tflog.Debug(ctx, fmt.Sprintf("Registry value %s does not exist, removing from state", resourceID))
		d.SetId("")
		return nil
	}

	// Update state
	if err := d.Set("path", path); err != nil {
		return utils.HandleResourceError("read", resourceID, "path", err)
	}
	if err := d.Set("name", name); err != nil {
		return utils.HandleResourceError("read", resourceID, "name", err)
	}
	if err := d.Set("value", currentValue); err != nil {
		return utils.HandleResourceError("read", resourceID, "value", err)
	}

	d.SetId(resourceID)
	return nil
}

func resourceWindowsRegistryValueUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	value := d.Get("value").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// If only non-destructive options changed, skip update
	if d.HasChange("command_timeout") || d.HasChange("allow_existing") {
		tflog.Debug(ctx, "Non-destructive change detected, skipping update")
		return resourceWindowsRegistryValueRead(d, m)
	}

	// Validate inputs for security
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return err
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return err
		}
	}

	// Update the registry value
	var command string
	if name == "" {
		command = fmt.Sprintf("Set-ItemProperty -Path %s -Name '(default)' -Value %s -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(value))
	} else {
		command = fmt.Sprintf("Set-ItemProperty -Path %s -Name %s -Value %s -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(value))
	}

	tflog.Info(ctx, fmt.Sprintf("Updating registry value: %s", resourceID))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"update",
			resourceID,
			"value",
			command,
			stdout,
			stderr,
			err,
		)
	}

	return resourceWindowsRegistryValueRead(d, m)
}

func resourceWindowsRegistryValueDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// Validate inputs for security
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return err
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return err
		}
	}

	// Build secure PowerShell command
	var command string
	if name == "" {
		// Cannot remove default value, just clear it
		command = fmt.Sprintf("Set-ItemProperty -Path %s -Name '(default)' -Value '' -ErrorAction Stop",
			powershell.QuotePowerShellString(path))
	} else {
		command = fmt.Sprintf("Remove-ItemProperty -Path %s -Name %s -Force -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name))
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting registry value: %s", resourceID))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"delete",
			resourceID,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId("")
	return nil
}
