package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// LocalUserInfo represents information about a local user
type LocalUserInfo struct {
	Exists                   bool   `json:"Exists"`
	FullName                 string `json:"FullName"`
	Description              string `json:"Description"`
	PasswordNeverExpires     bool   `json:"PasswordNeverExpires"`
	UserMayNotChangePassword bool   `json:"UserMayNotChangePassword"`
	Enabled                  bool   `json:"Enabled"`
}

func ResourceWindowsLocalUser() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsLocalUserCreate,
		Read:   resourceWindowsLocalUserRead,
		Update: resourceWindowsLocalUserUpdate,
		Delete: resourceWindowsLocalUserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the local user account. Cannot be changed after creation.",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "The password for the local user account.",
			},
			"full_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The full name of the user.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A description for the user account.",
			},
			"password_never_expires": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, the password will never expire.",
			},
			"user_cannot_change_password": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, the user cannot change their password.",
			},
			"account_disabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, the account will be disabled.",
			},
			"allow_existing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, adopt existing user instead of failing. If false, fail if user already exists.",
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

// checkLocalUserExists checks if a local user exists and returns its information
func checkLocalUserExists(ctx context.Context, sshClient *ssh.Client, username string, timeout int) (*LocalUserInfo, error) {
	// Validate username for security
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return nil, err
	}

	tflog.Debug(ctx, "Checking if local user exists", map[string]any{"username": username})

	// PowerShell command that returns structured JSON
	command := fmt.Sprintf(`
$user = Get-LocalUser -Name %s -ErrorAction SilentlyContinue
if ($user) {
    @{
        'Exists' = $true
        'FullName' = $user.FullName
        'Description' = $user.Description
        'PasswordNeverExpires' = $user.PasswordNeverExpires
        'UserMayNotChangePassword' = -not $user.UserMayChangePassword
        'Enabled' = $user.Enabled
    } | ConvertTo-Json -Compress
} else {
    @{ 'Exists' = $false } | ConvertTo-Json -Compress
}
`,
		powershell.QuotePowerShellString(username),
	)

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to check user: %w", err)
	}

	var info LocalUserInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w; output: %s", err, stdout)
	}

	return &info, nil
}

func resourceWindowsLocalUserCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	username := d.Get("username").(string)
	password := d.Get("password").(string)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	tflog.Info(ctx, "Creating local user", map[string]any{"username": username})

	// Validate username for security
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return err
	}

	// Check if user already exists
	info, err := checkLocalUserExists(ctx, sshClient, username, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", username, "state", err)
	}

	if info.Exists {
		if allowExisting {
			tflog.Info(ctx, "User already exists, adopting it",
				map[string]any{"username": username})
			d.SetId(username)
			return resourceWindowsLocalUserRead(d, m)
		}

		return utils.HandleResourceError(
			"create",
			username,
			"state",
			fmt.Errorf("local user already exists. "+
				"To manage this existing user, either:\n"+
				"  1. Import it: terraform import windows_localuser.example '%s'\n"+
				"  2. Set allow_existing = true in your configuration",
				username),
		)
	}

	// Build command securely
	command := fmt.Sprintf(
		"New-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
		powershell.QuotePowerShellString(username),
		powershell.QuotePowerShellString(password),
	)

	// Add optional parameters
	if fullName, ok := d.GetOk("full_name"); ok {
		fullNameStr := fullName.(string)
		if err := utils.ValidateField(fullNameStr, username, "full_name"); err != nil {
			return err
		}
		command += fmt.Sprintf(" -FullName %s", powershell.QuotePowerShellString(fullNameStr))
	}

	if description, ok := d.GetOk("description"); ok {
		descriptionStr := description.(string)
		if err := utils.ValidateField(descriptionStr, username, "description"); err != nil {
			return err
		}
		command += fmt.Sprintf(" -Description %s", powershell.QuotePowerShellString(descriptionStr))
	}

	if d.Get("password_never_expires").(bool) {
		command += " -PasswordNeverExpires"
	}

	if d.Get("user_cannot_change_password").(bool) {
		command += " -UserMayNotChangePassword"
	}

	command += " -ErrorAction Stop"

	tflog.Debug(ctx, "Creating local user with command (password hidden)")

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"create",
			username,
			"state",
			"New-LocalUser (password hidden)",
			stdout,
			stderr,
			err,
		)
	}

	tflog.Info(ctx, "Local user created successfully", map[string]any{"username": username})

	// Disable account if necessary
	if d.Get("account_disabled").(bool) {
		disableCmd := fmt.Sprintf("Disable-LocalUser -Name %s -ErrorAction Stop",
			powershell.QuotePowerShellString(username))

		tflog.Debug(ctx, "Disabling user account", map[string]any{"username": username})

		stdout, stderr, err := sshClient.ExecuteCommand(disableCmd, timeout)
		if err != nil {
			return utils.HandleCommandError("create", username, "account_disabled", disableCmd, stdout, stderr, err)
		}
	}

	d.SetId(username)

	// Log pool statistics if available
	if stats, ok := GetPoolStats(m); ok {
		tflog.Debug(ctx, "Pool statistics after create", map[string]any{"stats": stats.String()})
	}

	return resourceWindowsLocalUserRead(d, m)
}

func resourceWindowsLocalUserRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	username := d.Id()
	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	// Validate username
	if err := utils.ValidateField(username, username, "username"); err != nil {
		tflog.Warn(ctx, "Invalid username format", map[string]any{
			"username": username,
			"error":    err.Error(),
		})
		d.SetId("")
		return nil
	}

	tflog.Debug(ctx, "Reading local user", map[string]any{"username": username})

	info, err := checkLocalUserExists(ctx, sshClient, username, timeout)
	if err != nil {
		tflog.Warn(ctx, "Failed to read local user", map[string]any{
			"username": username,
			"error":    err.Error(),
		})
		d.SetId("")
		return nil
	}

	if !info.Exists {
		tflog.Debug(ctx, "Local user does not exist, removing from state",
			map[string]any{"username": username})
		d.SetId("")
		return nil
	}

	// Update state
	if err := d.Set("username", username); err != nil {
		return utils.HandleResourceError("read", username, "username", err)
	}
	if err := d.Set("full_name", info.FullName); err != nil {
		return utils.HandleResourceError("read", username, "full_name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", username, "description", err)
	}
	if err := d.Set("password_never_expires", info.PasswordNeverExpires); err != nil {
		return utils.HandleResourceError("read", username, "password_never_expires", err)
	}
	if err := d.Set("user_cannot_change_password", info.UserMayNotChangePassword); err != nil {
		return utils.HandleResourceError("read", username, "user_cannot_change_password", err)
	}
	if err := d.Set("account_disabled", !info.Enabled); err != nil {
		return utils.HandleResourceError("read", username, "account_disabled", err)
	}

	tflog.Debug(ctx, "Local user read successfully",
		map[string]any{
			"username": username,
			"enabled":  info.Enabled,
		})

	return nil
}

func resourceWindowsLocalUserUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Updating local user", map[string]any{"username": username})

	// Validate username for security
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return err
	}

	// Update password
	if d.HasChange("password") {
		password := d.Get("password").(string)
		command := fmt.Sprintf(
			"Set-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force) -ErrorAction Stop",
			powershell.QuotePowerShellString(username),
			powershell.QuotePowerShellString(password),
		)

		tflog.Debug(ctx, "Updating password (password hidden)")

		stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"update",
				username,
				"password",
				"Set-LocalUser -Password (password hidden)",
				stdout,
				stderr,
				err,
			)
		}
	}

	// Build update command for other attributes
	needsUpdate := false
	command := fmt.Sprintf("Set-LocalUser -Name %s", powershell.QuotePowerShellString(username))

	if d.HasChange("full_name") {
		fullName := d.Get("full_name").(string)
		if err := utils.ValidateField(fullName, username, "full_name"); err != nil {
			return err
		}
		command += fmt.Sprintf(" -FullName %s", powershell.QuotePowerShellString(fullName))
		needsUpdate = true
	}

	if d.HasChange("description") {
		description := d.Get("description").(string)
		if err := utils.ValidateField(description, username, "description"); err != nil {
			return err
		}
		command += fmt.Sprintf(" -Description %s", powershell.QuotePowerShellString(description))
		needsUpdate = true
	}

	if d.HasChange("password_never_expires") {
		command += fmt.Sprintf(" -PasswordNeverExpires $%t", d.Get("password_never_expires").(bool))
		needsUpdate = true
	}

	if d.HasChange("user_cannot_change_password") {
		command += fmt.Sprintf(" -UserMayChangePassword $%t", !d.Get("user_cannot_change_password").(bool))
		needsUpdate = true
	}

	if needsUpdate {
		command += " -ErrorAction Stop"

		tflog.Debug(ctx, "Executing user update", map[string]any{"username": username})

		stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return utils.HandleCommandError("update", username, "properties", command, stdout, stderr, err)
		}
	}

	// Handle account enable/disable
	if d.HasChange("account_disabled") {
		disabled := d.Get("account_disabled").(bool)
		var cmd string
		var action string

		if disabled {
			cmd = fmt.Sprintf("Disable-LocalUser -Name %s -ErrorAction Stop",
				powershell.QuotePowerShellString(username))
			action = "Disabling"
		} else {
			cmd = fmt.Sprintf("Enable-LocalUser -Name %s -ErrorAction Stop",
				powershell.QuotePowerShellString(username))
			action = "Enabling"
		}

		tflog.Debug(ctx, action+" user account", map[string]any{"username": username})

		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError("update", username, "account_disabled", cmd, stdout, stderr, err)
		}
	}

	tflog.Info(ctx, "Local user updated successfully", map[string]any{"username": username})

	return resourceWindowsLocalUserRead(d, m)
}

func resourceWindowsLocalUserDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Deleting local user", map[string]any{"username": username})

	// Validate username for security
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return err
	}

	command := fmt.Sprintf("Remove-LocalUser -Name %s -ErrorAction Stop",
		powershell.QuotePowerShellString(username))

	tflog.Debug(ctx, "Executing user deletion", map[string]any{"username": username})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("delete", username, "state", command, stdout, stderr, err)
	}

	d.SetId("")

	tflog.Info(ctx, "Local user deleted successfully", map[string]any{"username": username})

	return nil
}

// ============================================================================
// BATCH OPERATIONS FOR MULTIPLE LOCAL USERS
// ============================================================================

// LocalUserConfig represents a local user configuration for batch operations
type LocalUserConfig struct {
	Username                 string
	Password                 string
	FullName                 string
	Description              string
	PasswordNeverExpires     bool
	UserCannotChangePassword bool
	AccountDisabled          bool
}

// CreateMultipleLocalUsers creates multiple local users in a batch
func CreateMultipleLocalUsers(
	ctx context.Context,
	sshClient *ssh.Client,
	users []LocalUserConfig,
	timeout int,
) error {
	if len(users) == 0 {
		return nil
	}

	tflog.Info(ctx, "Creating multiple local users in batch",
		map[string]any{"count": len(users)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, user := range users {
		// Build creation command
		cmd := fmt.Sprintf(
			"New-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
			powershell.QuotePowerShellString(user.Username),
			powershell.QuotePowerShellString(user.Password),
		)

		if user.FullName != "" {
			cmd += fmt.Sprintf(" -FullName %s", powershell.QuotePowerShellString(user.FullName))
		}

		if user.Description != "" {
			cmd += fmt.Sprintf(" -Description %s", powershell.QuotePowerShellString(user.Description))
		}

		if user.PasswordNeverExpires {
			cmd += " -PasswordNeverExpires"
		}

		if user.UserCannotChangePassword {
			cmd += " -UserMayNotChangePassword"
		}

		cmd += " -ErrorAction SilentlyContinue; "

		// Disable if needed
		if user.AccountDisabled {
			cmd += fmt.Sprintf("Disable-LocalUser -Name %s -ErrorAction SilentlyContinue; ",
				powershell.QuotePowerShellString(user.Username))
		}

		// Check if created
		cmd += fmt.Sprintf("(Get-LocalUser -Name %s -ErrorAction SilentlyContinue) -ne $null",
			powershell.QuotePowerShellString(user.Username))

		batch.Add(cmd)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch user creation (passwords hidden)",
		map[string]any{"user_count": len(users)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_create",
			"multiple_users",
			"state",
			"batch user creation (passwords hidden)",
			stdout,
			stderr,
			err,
		)
	}

	// Parse results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Check results
	failedUsers := []string{}
	for i, user := range users {
		created, _ := result.GetStringResult(i)
		if created != "True" {
			failedUsers = append(failedUsers, user.Username)
		}
	}

	if len(failedUsers) > 0 {
		tflog.Warn(ctx, "Some users failed to create",
			map[string]any{
				"failed_count": len(failedUsers),
				"failed_users": failedUsers,
			})
	}

	tflog.Info(ctx, "Successfully created local users in batch",
		map[string]any{
			"total":   len(users),
			"failed":  len(failedUsers),
			"success": len(users) - len(failedUsers),
		})

	return nil
}

// CheckMultipleLocalUsersExist checks if multiple local users exist
func CheckMultipleLocalUsersExist(
	ctx context.Context,
	sshClient *ssh.Client,
	usernames []string,
	timeout int,
) (map[string]*LocalUserInfo, error) {
	if len(usernames) == 0 {
		return make(map[string]*LocalUserInfo), nil
	}

	tflog.Debug(ctx, "Checking multiple local users existence",
		map[string]any{"count": len(usernames)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, username := range usernames {
		command := fmt.Sprintf(`
$user = Get-LocalUser -Name %s -ErrorAction SilentlyContinue
if ($user) {
    @{
        'Exists' = $true
        'FullName' = $user.FullName
        'Description' = $user.Description
        'PasswordNeverExpires' = $user.PasswordNeverExpires
        'UserMayNotChangePassword' = -not $user.UserMayChangePassword
        'Enabled' = $user.Enabled
    } | ConvertTo-Json -Compress
} else {
    @{ 'Exists' = $false } | ConvertTo-Json -Compress
}`,
			powershell.QuotePowerShellString(username))

		batch.Add(command)
	}

	cmd := batch.Build()
	stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
	if err != nil {
		return nil, utils.HandleCommandError(
			"batch_check",
			"multiple_users",
			"state",
			cmd,
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
	infoMap := make(map[string]*LocalUserInfo)
	for i, username := range usernames {
		infoStr, _ := result.GetStringResult(i)

		var info LocalUserInfo
		if err := json.Unmarshal([]byte(infoStr), &info); err != nil {
			tflog.Warn(ctx, "Failed to parse user info",
				map[string]any{
					"username": username,
					"error":    err.Error(),
				})
			continue
		}

		infoMap[username] = &info
	}

	tflog.Debug(ctx, "Local user existence status retrieved",
		map[string]any{"count": len(infoMap)})

	return infoMap, nil
}

// DeleteMultipleLocalUsers deletes multiple local users in a batch
func DeleteMultipleLocalUsers(
	ctx context.Context,
	sshClient *ssh.Client,
	usernames []string,
	timeout int,
) error {
	if len(usernames) == 0 {
		return nil
	}

	tflog.Info(ctx, "Deleting multiple local users in batch",
		map[string]any{"count": len(usernames)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, username := range usernames {
		command := fmt.Sprintf("Remove-LocalUser -Name %s -ErrorAction SilentlyContinue; (Get-LocalUser -Name %s -ErrorAction SilentlyContinue) -eq $null",
			powershell.QuotePowerShellString(username),
			powershell.QuotePowerShellString(username))
		batch.Add(command)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch user deletion",
		map[string]any{"user_count": len(usernames)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_delete",
			"multiple_users",
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
		return fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Check results (users should NOT exist after deletion)
	notDeletedUsers := []string{}
	for i, username := range usernames {
		deleted, _ := result.GetStringResult(i)
		if deleted != "True" {
			notDeletedUsers = append(notDeletedUsers, username)
		}
	}

	if len(notDeletedUsers) > 0 {
		tflog.Warn(ctx, "Some users failed to delete",
			map[string]any{
				"failed_count": len(notDeletedUsers),
				"failed_users": notDeletedUsers,
			})
	}

	tflog.Info(ctx, "Successfully deleted local users in batch",
		map[string]any{
			"total":   len(usernames),
			"failed":  len(notDeletedUsers),
			"success": len(usernames) - len(notDeletedUsers),
		})

	return nil
}
