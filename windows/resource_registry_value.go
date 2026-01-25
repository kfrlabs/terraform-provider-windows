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

// checkRegistryValueExists checks if a registry value exists (using batch for efficiency)
func checkRegistryValueExists(ctx context.Context, sshClient *ssh.Client, path, name string, timeout int) (bool, string, error) {
	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// Validate inputs
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return false, "", err
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return false, "", err
		}
	}

	// ✨ CORRECTION : Utiliser OutputSeparator pour gérer les types mixtes
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputSeparator)

	// Add commands to check key existence and get value
	batch.Add(fmt.Sprintf("Test-Path -Path %s", powershell.QuotePowerShellString(path)))

	if name == "" {
		batch.Add(fmt.Sprintf("(Get-ItemProperty -Path %s -ErrorAction SilentlyContinue).'(default)'",
			powershell.QuotePowerShellString(path)))
	} else {
		batch.Add(fmt.Sprintf("Get-ItemPropertyValue -Path %s -Name %s -ErrorAction SilentlyContinue",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name)))
	}

	command := batch.Build()
	tflog.Debug(ctx, "Checking registry value existence with batch command")

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		// Erreur SSH, pas une erreur d'existence
		tflog.Debug(ctx, "SSH error while checking registry value", map[string]any{"error": err.Error()})
		return false, "", nil
	}

	// ✨ CORRECTION : Parse avec OutputSeparator
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputSeparator)
	if err != nil {
		tflog.Debug(ctx, "Failed to parse batch result", map[string]any{"error": err.Error()})
		return false, "", nil
	}

	if result.Count() < 2 {
		tflog.Debug(ctx, "Incomplete batch result", map[string]any{"count": result.Count()})
		return false, "", nil
	}

	// Check if key exists
	keyExists, err := result.GetStringResult(0)
	if err != nil {
		tflog.Debug(ctx, "Failed to get key existence result", map[string]any{"error": err.Error()})
		return false, "", nil
	}

	if keyExists != "True" {
		tflog.Debug(ctx, "Registry key does not exist", map[string]any{"path": path})
		return false, "", nil
	}

	// Get value
	value, err := result.GetStringResult(1)
	if err != nil {
		tflog.Debug(ctx, "Failed to get value result", map[string]any{"error": err.Error()})
		return false, "", nil
	}

	// Si la valeur est vide, elle n'existe probablement pas
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		tflog.Debug(ctx, "Registry value is empty, considering as non-existent")
		return false, "", nil
	}

	tflog.Debug(ctx, "Registry value exists", map[string]any{
		"path":  path,
		"name":  name,
		"value": trimmedValue,
	})

	return true, trimmedValue, nil
}

func resourceWindowsRegistryValueCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// Get SSH client from pool or single connection
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	valueType := d.Get("type").(string)
	value := d.Get("value").(string)
	allowExisting := d.Get("allow_existing").(bool)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// Validate inputs
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

	tflog.Info(ctx, "Creating registry value", map[string]any{"resource_id": resourceID})

	// ✨ CORRECTION : Pas de batch pour une seule commande simple
	// Check if registry key exists
	checkKeyCommand := fmt.Sprintf("Test-Path -Path %s", powershell.QuotePowerShellString(path))

	stdout, stderr, err := sshClient.ExecuteCommand(checkKeyCommand, timeout)
	if err != nil || stdout != "True" {
		return utils.HandleCommandError(
			"check_key",
			resourceID,
			"state",
			checkKeyCommand,
			stdout,
			stderr,
			fmt.Errorf("registry key does not exist: %s (create it first with windows_registry_key)", path),
		)
	}

	// Check if value already exists
	exists, currentValue, err := checkRegistryValueExists(ctx, sshClient, path, name, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", resourceID, "state", err)
	}

	if exists {
		if allowExisting {
			tflog.Info(ctx, "Registry value already exists, adopting it",
				map[string]any{
					"resource_id":   resourceID,
					"current_value": currentValue,
				})
			d.SetId(resourceID)
			return resourceWindowsRegistryValueRead(d, m)
		}

		return utils.HandleResourceError(
			"create",
			resourceID,
			"state",
			fmt.Errorf("registry value already exists with value '%s'. "+
				"To manage this existing registry value, either:\n"+
				"  1. Import it: terraform import windows_registry_value.example '%s'\n"+
				"  2. Set allow_existing = true in your configuration",
				currentValue, resourceID),
		)
	}

	// Create the registry value
	var createCmd string
	if name == "" {
		createCmd = fmt.Sprintf("Set-ItemProperty -Path %s -Name '(default)' -Value %s -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(value))
	} else {
		createCmd = fmt.Sprintf("New-ItemProperty -Path %s -Name %s -Value %s -PropertyType %s -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(value),
			powershell.QuotePowerShellString(valueType))
	}

	tflog.Debug(ctx, "Creating registry value", map[string]any{"resource_id": resourceID})

	stdout, stderr, err = sshClient.ExecuteCommand(createCmd, timeout)
	if err != nil {
		return utils.HandleCommandError("create", resourceID, "state", createCmd, stdout, stderr, err)
	}

	d.SetId(resourceID)

	// Log pool statistics if available
	if stats, ok := GetPoolStats(m); ok {
		tflog.Debug(ctx, "Pool statistics after create", map[string]any{"stats": stats.String()})
	}

	return resourceWindowsRegistryValueRead(d, m)
}

func resourceWindowsRegistryValueRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	var path, name string
	if d.Id() != "" {
		lastBackslash := strings.LastIndex(d.Id(), "\\")
		if lastBackslash > 0 {
			path = d.Id()[:lastBackslash]
			name = d.Id()[lastBackslash+1:]
		} else {
			path = d.Get("path").(string)
			name = d.Get("name").(string)
		}
	} else {
		path = d.Get("path").(string)
		name = d.Get("name").(string)
	}

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	timeout, ok := d.GetOk("command_timeout")
	if !ok {
		timeout = 300
	}

	// Validate inputs
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return utils.HandleResourceError("validate", resourceID, "path", err)
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return utils.HandleResourceError("validate", resourceID, "name", err)
		}
	}

	// Check existence using batch (more efficient)
	exists, currentValue, err := checkRegistryValueExists(ctx, sshClient, path, name, timeout.(int))
	if err != nil {
		tflog.Warn(ctx, "Failed to read registry value", map[string]any{
			"resource_id": resourceID,
			"error":       err.Error(),
		})
		d.SetId("")
		return nil
	}

	if !exists {
		tflog.Debug(ctx, "Registry value does not exist, removing from state",
			map[string]any{"resource_id": resourceID})
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

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	value := d.Get("value").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// Only update if value changed
	if d.HasChange("command_timeout") || d.HasChange("allow_existing") {
		tflog.Debug(ctx, "Non-destructive change detected, skipping update")
		return resourceWindowsRegistryValueRead(d, m)
	}

	// Validate inputs
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

	tflog.Info(ctx, "Updating registry value", map[string]any{"resource_id": resourceID})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("update", resourceID, "value", command, stdout, stderr, err)
	}

	return resourceWindowsRegistryValueRead(d, m)
}

func resourceWindowsRegistryValueDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	// Validate inputs
	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return err
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return err
		}
	}

	// Build command
	var command string
	if name == "" {
		command = fmt.Sprintf("Set-ItemProperty -Path %s -Name '(default)' -Value '' -ErrorAction Stop",
			powershell.QuotePowerShellString(path))
	} else {
		command = fmt.Sprintf("Remove-ItemProperty -Path %s -Name %s -Force -ErrorAction Stop",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name))
	}

	tflog.Info(ctx, "Deleting registry value", map[string]any{"resource_id": resourceID})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("delete", resourceID, "state", command, stdout, stderr, err)
	}

	d.SetId("")
	return nil
}

// ============================================================================
// BATCH OPERATIONS FOR MULTIPLE REGISTRY VALUES
// ============================================================================

// CreateMultipleRegistryValues creates multiple registry values in a single batch
// This is useful when creating many values at once (e.g., initial app configuration)
func CreateMultipleRegistryValues(
	ctx context.Context,
	sshClient *ssh.Client,
	values []RegistryValueConfig,
	timeout int,
) error {
	if len(values) == 0 {
		return nil
	}

	tflog.Info(ctx, "Creating multiple registry values in batch",
		map[string]any{"count": len(values)})

	// Build batch command
	batch := powershell.NewRegistryBatchBuilder()

	for _, v := range values {
		batch.AddCreateValue(v.Path, v.Name, v.Value, v.Type)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch registry creation",
		map[string]any{"command_count": batch.Count()})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_create",
			"multiple_values",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	tflog.Info(ctx, "Successfully created registry values in batch",
		map[string]any{"count": len(values)})

	return nil
}

// RegistryValueConfig represents a registry value configuration for batch operations
type RegistryValueConfig struct {
	Path  string
	Name  string
	Value string
	Type  string
}
