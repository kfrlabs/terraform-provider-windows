package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/kfrlabs/terraform-provider-windows/internal/ssh"
)

// LocalUserInfo represents comprehensive information about a local user retrieved from Windows
type LocalUserInfo struct {
	Exists                   bool   `json:"Exists"`
	Name                     string `json:"Name"`
	SID                      string `json:"SID"`
	FullName                 string `json:"FullName"`
	Description              string `json:"Description"`
	Enabled                  bool   `json:"Enabled"`
	PasswordNeverExpires     bool   `json:"PasswordNeverExpires"`
	UserMayNotChangePassword bool   `json:"UserMayNotChangePassword"`
	PasswordRequired         bool   `json:"PasswordRequired"`
	PasswordLastSet          string `json:"PasswordLastSet"`
	PasswordExpires          string `json:"PasswordExpires"`
	PasswordChangeableDate   string `json:"PasswordChangeableDate"`
	AccountExpires           string `json:"AccountExpires"`
	LastLogon                string `json:"LastLogon"`
	PrincipalSource          string `json:"PrincipalSource"`
	ObjectClass              string `json:"ObjectClass"`
}

// LocalUserCreateParams contains parameters for creating a new local user
type LocalUserCreateParams struct {
	Username                 string
	Password                 string
	FullName                 string
	Description              string
	PasswordNeverExpires     bool
	UserCannotChangePassword bool
}

// LocalUserUpdateParams contains parameters for updating a local user
// All fields except Username are optional (nil means no change)
type LocalUserUpdateParams struct {
	Username                 string
	FullName                 *string
	Description              *string
	PasswordNeverExpires     *bool
	UserCannotChangePassword *bool
}

// quotePowerShellString escapes a string for safe use in PowerShell commands
// This prevents command injection by properly escaping single quotes
func quotePowerShellString(s string) string {
	// Replace single quotes with two single quotes (PowerShell escaping)
	escaped := strings.ReplaceAll(s, "'", "''")
	// Wrap in single quotes
	return fmt.Sprintf("'%s'", escaped)
}

// formatDateTimeForJson converts PowerShell DateTime to ISO string, returns empty if null
func formatDateTimeForJson(fieldName string) string {
	return fmt.Sprintf("if ($user.%s) { $user.%s.ToString('o') } else { '' }", fieldName, fieldName)
}

// GetLocalUserInfo retrieves comprehensive information about a local user
// Returns LocalUserInfo with Exists=false if the user doesn't exist
func GetLocalUserInfo(ctx context.Context, client *ssh.Client, username string) (*LocalUserInfo, error) {
	tflog.Debug(ctx, "Getting local user information", map[string]interface{}{
		"username": username,
	})

	// PowerShell command that returns comprehensive structured JSON
	command := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$user = Get-LocalUser -Name %s -ErrorAction SilentlyContinue
if ($user) {
    @{
        'Exists' = $true
        'Name' = $user.Name
        'SID' = $user.SID.Value
        'FullName' = if ($user.FullName) { $user.FullName } else { '' }
        'Description' = if ($user.Description) { $user.Description } else { '' }
        'Enabled' = $user.Enabled
        'PasswordNeverExpires' = if ($user.PasswordExpires -eq $null) { $true } else { $false }
        'UserMayNotChangePassword' = -not $user.UserMayChangePassword
        'PasswordRequired' = $user.PasswordRequired
        'PasswordLastSet' = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') } else { '' }
        'PasswordExpires' = if ($user.PasswordExpires) { $user.PasswordExpires.ToString('o') } else { '' }
        'PasswordChangeableDate' = if ($user.PasswordChangeableDate) { $user.PasswordChangeableDate.ToString('o') } else { '' }
        'AccountExpires' = if ($user.AccountExpires) { $user.AccountExpires.ToString('o') } else { '' }
        'LastLogon' = if ($user.LastLogon) { $user.LastLogon.ToString('o') } else { '' }
        'PrincipalSource' = $user.PrincipalSource.ToString()
        'ObjectClass' = $user.ObjectClass
    } | ConvertTo-Json -Compress
} else {
    @{ 'Exists' = $false } | ConvertTo-Json -Compress
}
`, quotePowerShellString(username))

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w; stderr: %s", err, stderr)
	}

	var info LocalUserInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w; output: %s", err, stdout)
	}

	return &info, nil
}

// CreateLocalUser creates a new local user with the specified parameters
func CreateLocalUser(ctx context.Context, client *ssh.Client, params LocalUserCreateParams) error {
	tflog.Debug(ctx, "Creating local user", map[string]interface{}{
		"username": params.Username,
	})

	// Build PowerShell command securely
	command := fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'; New-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
		quotePowerShellString(params.Username),
		quotePowerShellString(params.Password),
	)

	// Add optional parameters
	if params.FullName != "" {
		command += fmt.Sprintf(" -FullName %s", quotePowerShellString(params.FullName))
	}

	if params.Description != "" {
		command += fmt.Sprintf(" -Description %s", quotePowerShellString(params.Description))
	}

	if params.PasswordNeverExpires {
		command += " -PasswordNeverExpires"
	}

	if params.UserCannotChangePassword {
		command += " -UserMayNotChangePassword"
	}

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to create user '%s': %w; stdout: %s; stderr: %s", params.Username, err, stdout, stderr)
	}

	tflog.Info(ctx, "Local user created successfully", map[string]interface{}{
		"username": params.Username,
	})

	return nil
}

// UpdateLocalUser updates properties of an existing local user
func UpdateLocalUser(ctx context.Context, client *ssh.Client, params LocalUserUpdateParams) error {
	tflog.Debug(ctx, "Updating local user", map[string]interface{}{
		"username": params.Username,
	})

	needsUpdate := false
	command := fmt.Sprintf("$ErrorActionPreference = 'Stop'; Set-LocalUser -Name %s", quotePowerShellString(params.Username))

	// Add optional parameters only if they are set (not nil)
	if params.FullName != nil {
		command += fmt.Sprintf(" -FullName %s", quotePowerShellString(*params.FullName))
		needsUpdate = true
	}

	if params.Description != nil {
		command += fmt.Sprintf(" -Description %s", quotePowerShellString(*params.Description))
		needsUpdate = true
	}

	if params.PasswordNeverExpires != nil {
		command += fmt.Sprintf(" -PasswordNeverExpires $%t", *params.PasswordNeverExpires)
		needsUpdate = true
	}

	if params.UserCannotChangePassword != nil {
		// Note: PowerShell uses UserMayChangePassword (opposite of UserCannotChangePassword)
		command += fmt.Sprintf(" -UserMayChangePassword $%t", !*params.UserCannotChangePassword)
		needsUpdate = true
	}

	// Only execute if there are changes
	if !needsUpdate {
		tflog.Debug(ctx, "No user properties to update", map[string]interface{}{
			"username": params.Username,
		})
		return nil
	}

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to update user '%s': %w; stdout: %s; stderr: %s", params.Username, err, stdout, stderr)
	}

	tflog.Info(ctx, "Local user updated successfully", map[string]interface{}{
		"username": params.Username,
	})

	return nil
}

// SetLocalUserPassword updates the password for a local user
func SetLocalUserPassword(ctx context.Context, client *ssh.Client, username, password string) error {
	tflog.Debug(ctx, "Updating user password", map[string]interface{}{
		"username": username,
	})

	command := fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'; Set-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
		quotePowerShellString(username),
		quotePowerShellString(password),
	)

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to update password for user '%s': %w; stdout: %s; stderr: %s", username, err, stdout, stderr)
	}

	tflog.Info(ctx, "User password updated successfully", map[string]interface{}{
		"username": username,
	})

	return nil
}

// SetLocalUserEnabled enables or disables a local user account
func SetLocalUserEnabled(ctx context.Context, client *ssh.Client, username string, enabled bool) error {
	var command string
	var action string

	if enabled {
		command = fmt.Sprintf("$ErrorActionPreference = 'Stop'; Enable-LocalUser -Name %s", quotePowerShellString(username))
		action = "enable"
	} else {
		command = fmt.Sprintf("$ErrorActionPreference = 'Stop'; Disable-LocalUser -Name %s", quotePowerShellString(username))
		action = "disable"
	}

	tflog.Debug(ctx, "Updating user enabled status", map[string]interface{}{
		"username": username,
		"action":   action,
	})

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to %s user '%s': %w; stdout: %s; stderr: %s", action, username, err, stdout, stderr)
	}

	tflog.Info(ctx, "User enabled status updated successfully", map[string]interface{}{
		"username": username,
		"enabled":  enabled,
	})

	return nil
}

// DeleteLocalUser removes a local user account
func DeleteLocalUser(ctx context.Context, client *ssh.Client, username string) error {
	tflog.Debug(ctx, "Deleting local user", map[string]interface{}{
		"username": username,
	})

	command := fmt.Sprintf("$ErrorActionPreference = 'Stop'; Remove-LocalUser -Name %s", quotePowerShellString(username))

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to delete user '%s': %w; stdout: %s; stderr: %s", username, err, stdout, stderr)
	}

	tflog.Info(ctx, "Local user deleted successfully", map[string]interface{}{
		"username": username,
	})

	return nil
}
