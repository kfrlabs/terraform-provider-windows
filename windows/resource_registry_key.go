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

// checkRegistryKeyExists vérifie si une clé de registre existe
func checkRegistryKeyExists(ctx context.Context, sshClient *ssh.Client, path string, timeout int) (bool, error) {
	// Validate path for security
	if err := powershell.ValidatePowerShellArgument(path); err != nil {
		return false, err
	}

	// Build secure PowerShell command
	command := fmt.Sprintf("Test-Path -Path %s -ErrorAction Stop",
		powershell.QuotePowerShellString(path))

	tflog.Debug(ctx, fmt.Sprintf("Checking registry key existence: %s", path))

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return false, nil // Si erreur, on considère que ça n'existe pas
	}

	return stdout == "True", nil
}

func resourceWindowsRegistryKeyCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	path := d.Get("path").(string)
	force := d.Get("force").(bool)
	allowExisting := d.Get("allow_existing").(bool)
	timeout := d.Get("command_timeout").(int)

	// Validate path for security
	if err := powershell.ValidatePowerShellArgument(path); err != nil {
		return utils.HandleResourceError("validate", path, "path", err)
	}

	// Check if registry key already exists
	exists, err := checkRegistryKeyExists(ctx, sshClient, path, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", path, "state", err)
	}

	if exists {
		if allowExisting {
			// Adopt the existing registry key
			tflog.Info(ctx, fmt.Sprintf("Registry key %s already exists, adopting it (allow_existing=true)", path))
			d.SetId(path)
			return resourceWindowsRegistryKeyRead(d, m)
		} else {
			// Fail with clear error
			// Extract a clean resource name from path for the import command
			resourceName := "registry_key"
			return utils.HandleResourceError(
				"create",
				path,
				"state",
				fmt.Errorf("registry key already exists. "+
					"To manage this existing registry key, either:\n"+
					"  1. Import it: terraform import windows_registry_key.%s '%s'\n"+
					"  2. Set allow_existing = true in your configuration\n"+
					"  3. Remove it first: Remove-Item -Path '%s' -Force",
					resourceName, path, path),
			)
		}
	}

	// Build secure PowerShell command
	forceFlag := ""
	if force {
		forceFlag = "-Force"
	}

	command := fmt.Sprintf("New-Item -Path %s %s -ErrorAction Stop",
		powershell.QuotePowerShellString(path),
		forceFlag)

	tflog.Info(ctx, fmt.Sprintf("Creating registry key: %s", path))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"create",
			path,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId(path)
	return resourceWindowsRegistryKeyRead(d, m)
}

func resourceWindowsRegistryKeyRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	path := d.Id()
	if path == "" {
		path = d.Get("path").(string)
	}

	// Validate path for security
	if err := powershell.ValidatePowerShellArgument(path); err != nil {
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
		tflog.Warn(ctx, fmt.Sprintf("Failed to read registry key %s: %v", path, err))
		d.SetId("")
		return nil
	}

	if !exists {
		tflog.Debug(ctx, fmt.Sprintf("Registry key %s does not exist, removing from state", path))
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
	sshClient := m.(*ssh.Client)

	path := d.Get("path").(string)
	timeout := d.Get("command_timeout").(int)

	// Validate path for security
	if err := powershell.ValidatePowerShellArgument(path); err != nil {
		return utils.HandleResourceError("validate", path, "path", err)
	}

	// Build secure PowerShell command
	command := fmt.Sprintf("Remove-Item -Path %s -Recurse -Force -ErrorAction Stop",
		powershell.QuotePowerShellString(path))

	tflog.Info(ctx, fmt.Sprintf("Deleting registry key: %s", path))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"delete",
			path,
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
