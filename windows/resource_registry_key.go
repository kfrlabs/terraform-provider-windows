package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
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
			"allow_existing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, adopt existing registry key instead of failing. If false, fail if key already exists.",
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

// checkRegistryKeyExists checks if a registry key exists
func checkRegistryKeyExists(ctx context.Context, sshClient *ssh.Client, path string, timeout int) (bool, error) {
	// Validate path for security
	if err := utils.ValidateField(path, path, "path"); err != nil {
		return false, err
	}

	// Build secure PowerShell command
	command := fmt.Sprintf("Test-Path -Path %s -ErrorAction SilentlyContinue",
		powershell.QuotePowerShellString(path))

	tflog.Debug(ctx, "Checking registry key existence", map[string]any{"path": path})

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return false, nil // If error, consider it doesn't exist
	}

	return stdout == "True", nil
}

func resourceWindowsRegistryKeyCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	path := d.Get("path").(string)
	force := d.Get("force").(bool)
	allowExisting := d.Get("allow_existing").(bool)
	timeout := d.Get("command_timeout").(int)

	// Validate path for security
	if err := utils.ValidateField(path, path, "path"); err != nil {
		return err
	}

	tflog.Info(ctx, "Creating registry key", map[string]any{
		"path":  path,
		"force": force,
	})

	// Check if registry key already exists
	exists, err := checkRegistryKeyExists(ctx, sshClient, path, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", path, "state", err)
	}

	if exists {
		if allowExisting {
			tflog.Info(ctx, "Registry key already exists, adopting it",
				map[string]any{"path": path})
			d.SetId(path)
			return resourceWindowsRegistryKeyRead(d, m)
		}

		return utils.HandleResourceError(
			"create",
			path,
			"state",
			fmt.Errorf("registry key already exists. "+
				"To manage this existing registry key, either:\n"+
				"  1. Import it: terraform import windows_registry_key.example '%s'\n"+
				"  2. Set allow_existing = true in your configuration",
				path),
		)
	}

	// Build secure PowerShell command
	forceFlag := ""
	if force {
		forceFlag = "-Force"
	}

	command := fmt.Sprintf("New-Item -Path %s %s -ErrorAction Stop",
		powershell.QuotePowerShellString(path),
		forceFlag)

	tflog.Debug(ctx, "Executing registry key creation", map[string]any{"path": path})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("create", path, "state", command, stdout, stderr, err)
	}

	d.SetId(path)

	// Log pool statistics if available
	if stats, ok := GetPoolStats(m); ok {
		tflog.Debug(ctx, "Pool statistics after create", map[string]any{"stats": stats.String()})
	}

	return resourceWindowsRegistryKeyRead(d, m)
}

func resourceWindowsRegistryKeyRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	path := d.Id()
	if path == "" {
		path = d.Get("path").(string)
	}

	// Validate path for security
	if err := utils.ValidateField(path, path, "path"); err != nil {
		return utils.HandleResourceError("validate", path, "path", err)
	}

	// Get timeout from schema
	timeout, ok := d.GetOk("command_timeout")
	if !ok {
		timeout = 300 // Default value from schema
	}

	// Check if registry key exists
	exists, err := checkRegistryKeyExists(ctx, sshClient, path, timeout.(int))
	if err != nil {
		tflog.Warn(ctx, "Failed to read registry key", map[string]any{
			"path":  path,
			"error": err.Error(),
		})
		d.SetId("")
		return nil
	}

	if !exists {
		tflog.Debug(ctx, "Registry key does not exist, removing from state",
			map[string]any{"path": path})
		d.SetId("")
		return nil
	}

	// Update state
	if err := d.Set("path", path); err != nil {
		return utils.HandleResourceError("read", path, "path", err)
	}

	d.SetId(path)
	return nil
}

func resourceWindowsRegistryKeyUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// If only non-destructive options changed, skip recreate
	if d.HasChange("command_timeout") || d.HasChange("allow_existing") {
		tflog.Debug(ctx, "Non-destructive change detected, skipping recreate")
		return resourceWindowsRegistryKeyRead(d, m)
	}

	// For path or force changes, recreate is handled by ForceNew
	return resourceWindowsRegistryKeyRead(d, m)
}

func resourceWindowsRegistryKeyDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	path := d.Get("path").(string)
	timeout := d.Get("command_timeout").(int)

	// Validate path for security
	if err := utils.ValidateField(path, path, "path"); err != nil {
		return err
	}

	// Build secure PowerShell command
	command := fmt.Sprintf("Remove-Item -Path %s -Recurse -Force -ErrorAction Stop",
		powershell.QuotePowerShellString(path))

	tflog.Info(ctx, "Deleting registry key", map[string]any{"path": path})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("delete", path, "state", command, stdout, stderr, err)
	}

	tflog.Info(ctx, "Successfully deleted registry key", map[string]any{"path": path})

	d.SetId("")
	return nil
}

// ============================================================================
// BATCH OPERATIONS FOR MULTIPLE REGISTRY KEYS
// ============================================================================

// RegistryKeyConfig represents a registry key configuration for batch operations
type RegistryKeyConfig struct {
	Path  string
	Force bool
}

// CreateMultipleRegistryKeys creates multiple registry keys in a single batch
// This is useful when creating a complete registry structure at once
func CreateMultipleRegistryKeys(
	ctx context.Context,
	sshClient *ssh.Client,
	keys []RegistryKeyConfig,
	timeout int,
) error {
	if len(keys) == 0 {
		return nil
	}

	tflog.Info(ctx, "Creating multiple registry keys in batch",
		map[string]any{"count": len(keys)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, k := range keys {
		forceFlag := ""
		if k.Force {
			forceFlag = "-Force"
		}

		command := fmt.Sprintf("New-Item -Path %s %s -ErrorAction SilentlyContinue; Test-Path -Path %s",
			powershell.QuotePowerShellString(k.Path),
			forceFlag,
			powershell.QuotePowerShellString(k.Path))

		batch.Add(command)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch registry key creation",
		map[string]any{"key_count": len(keys)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_create",
			"multiple_keys",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse batch results to verify creation
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Check results
	failedKeys := []string{}
	for i, key := range keys {
		created, _ := result.GetStringResult(i)
		if created != "True" {
			failedKeys = append(failedKeys, key.Path)
		}
	}

	if len(failedKeys) > 0 {
		tflog.Warn(ctx, "Some registry keys failed to create",
			map[string]any{
				"failed_count": len(failedKeys),
				"failed_keys":  failedKeys,
			})
	}

	tflog.Info(ctx, "Successfully created registry keys in batch",
		map[string]any{
			"total":   len(keys),
			"failed":  len(failedKeys),
			"success": len(keys) - len(failedKeys),
		})

	return nil
}

// CheckMultipleRegistryKeysExist checks if multiple registry keys exist
// Returns a map of key path to existence status
func CheckMultipleRegistryKeysExist(
	ctx context.Context,
	sshClient *ssh.Client,
	paths []string,
	timeout int,
) (map[string]bool, error) {
	if len(paths) == 0 {
		return make(map[string]bool), nil
	}

	tflog.Debug(ctx, "Checking multiple registry keys existence",
		map[string]any{"count": len(paths)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, path := range paths {
		command := fmt.Sprintf("Test-Path -Path %s -ErrorAction SilentlyContinue",
			powershell.QuotePowerShellString(path))
		batch.Add(command)
	}

	command := batch.Build()
	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, utils.HandleCommandError(
			"batch_check",
			"multiple_keys",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return nil, fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Build result map
	existsMap := make(map[string]bool)
	for i, path := range paths {
		exists, _ := result.GetStringResult(i)
		existsMap[path] = (exists == "True")
	}

	tflog.Debug(ctx, "Registry key existence status retrieved",
		map[string]any{"count": len(existsMap)})

	return existsMap, nil
}

// DeleteMultipleRegistryKeys deletes multiple registry keys in a single batch
func DeleteMultipleRegistryKeys(
	ctx context.Context,
	sshClient *ssh.Client,
	paths []string,
	timeout int,
) error {
	if len(paths) == 0 {
		return nil
	}

	tflog.Info(ctx, "Deleting multiple registry keys in batch",
		map[string]any{"count": len(paths)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, path := range paths {
		command := fmt.Sprintf("Remove-Item -Path %s -Recurse -Force -ErrorAction SilentlyContinue; Test-Path -Path %s",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(path))
		batch.Add(command)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch registry key deletion",
		map[string]any{"key_count": len(paths)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_delete",
			"multiple_keys",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse batch results to verify deletion
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Check results (keys should NOT exist after deletion)
	notDeletedKeys := []string{}
	for i, path := range paths {
		stillExists, _ := result.GetStringResult(i)
		if stillExists == "True" {
			notDeletedKeys = append(notDeletedKeys, path)
		}
	}

	if len(notDeletedKeys) > 0 {
		tflog.Warn(ctx, "Some registry keys failed to delete",
			map[string]any{
				"failed_count": len(notDeletedKeys),
				"failed_keys":  notDeletedKeys,
			})
	}

	tflog.Info(ctx, "Successfully deleted registry keys in batch",
		map[string]any{
			"total":   len(paths),
			"failed":  len(notDeletedKeys),
			"success": len(paths) - len(notDeletedKeys),
		})

	return nil
}

// CreateRegistryStructure creates a complete registry structure with keys and values
// This is a high-level helper that combines key and value creation
type RegistryStructure struct {
	Keys   []RegistryKeyConfig
	Values []RegistryValueConfig
}

// CreateRegistryStructure creates keys first, then values
func CreateCompleteRegistryStructure(
	ctx context.Context,
	sshClient *ssh.Client,
	structure RegistryStructure,
	timeout int,
) error {
	tflog.Info(ctx, "Creating complete registry structure",
		map[string]any{
			"key_count":   len(structure.Keys),
			"value_count": len(structure.Values),
		})

	// Step 1: Create all keys
	if len(structure.Keys) > 0 {
		if err := CreateMultipleRegistryKeys(ctx, sshClient, structure.Keys, timeout); err != nil {
			return fmt.Errorf("failed to create registry keys: %w", err)
		}
	}

	// Step 2: Create all values
	if len(structure.Values) > 0 {
		if err := CreateMultipleRegistryValues(ctx, sshClient, structure.Values, timeout); err != nil {
			return fmt.Errorf("failed to create registry values: %w", err)
		}
	}

	tflog.Info(ctx, "Successfully created complete registry structure",
		map[string]any{
			"keys_created":   len(structure.Keys),
			"values_created": len(structure.Values),
		})

	return nil
}
