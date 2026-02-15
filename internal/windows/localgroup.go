package windows

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/kfrlabs/terraform-provider-windows/internal/ssh"
)

// LocalGroupInfo represents comprehensive information about a local group retrieved from Windows
type LocalGroupInfo struct {
	Exists          bool   `json:"Exists"`
	Name            string `json:"Name"`
	SID             string `json:"SID"`
	Description     string `json:"Description"`
	PrincipalSource string `json:"PrincipalSource"`
	ObjectClass     string `json:"ObjectClass"`
}

// LocalGroupCreateParams contains parameters for creating a new local group
type LocalGroupCreateParams struct {
	Name        string
	Description string
}

// LocalGroupUpdateParams contains parameters for updating a local group
// All fields except Name are optional (nil means no change)
type LocalGroupUpdateParams struct {
	Name        string
	Description *string
}

// GetLocalGroupInfo retrieves comprehensive information about a local group
// Returns LocalGroupInfo with Exists=false if the group doesn't exist
func GetLocalGroupInfo(ctx context.Context, client *ssh.Client, groupname string) (*LocalGroupInfo, error) {
	tflog.Debug(ctx, "Getting local group information", map[string]interface{}{
		"groupname": groupname,
	})

	// PowerShell command that returns comprehensive structured JSON
	command := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$group = Get-LocalGroup -Name %s -ErrorAction SilentlyContinue
if ($group) {
    @{
        'Exists' = $true
        'Name' = $group.Name
        'SID' = $group.SID.Value
        'Description' = if ($group.Description) { $group.Description } else { '' }
        'PrincipalSource' = $group.PrincipalSource.ToString()
        'ObjectClass' = $group.ObjectClass
    } | ConvertTo-Json -Compress
} else {
    @{ 'Exists' = $false } | ConvertTo-Json -Compress
}
`, quotePowerShellString(groupname))

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("failed to get group info: %w; stderr: %s", err, stderr)
	}

	var info LocalGroupInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse group info: %w; output: %s", err, stdout)
	}

	return &info, nil
}

// CreateLocalGroup creates a new local group with the specified parameters
func CreateLocalGroup(ctx context.Context, client *ssh.Client, params LocalGroupCreateParams) error {
	tflog.Debug(ctx, "Creating local group", map[string]interface{}{
		"groupname": params.Name,
	})

	// Build PowerShell command securely
	command := fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'; New-LocalGroup -Name %s",
		quotePowerShellString(params.Name),
	)

	// Add optional parameters
	if params.Description != "" {
		command += fmt.Sprintf(" -Description %s", quotePowerShellString(params.Description))
	}

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to create group '%s': %w; stdout: %s; stderr: %s", params.Name, err, stdout, stderr)
	}

	tflog.Info(ctx, "Local group created successfully", map[string]interface{}{
		"groupname": params.Name,
	})

	return nil
}

// UpdateLocalGroup updates properties of an existing local group
func UpdateLocalGroup(ctx context.Context, client *ssh.Client, params LocalGroupUpdateParams) error {
	tflog.Debug(ctx, "Updating local group", map[string]interface{}{
		"groupname": params.Name,
	})

	needsUpdate := false
	command := fmt.Sprintf("$ErrorActionPreference = 'Stop'; Set-LocalGroup -Name %s", quotePowerShellString(params.Name))

	// Add optional parameters only if they are set (not nil)
	if params.Description != nil {
		command += fmt.Sprintf(" -Description %s", quotePowerShellString(*params.Description))
		needsUpdate = true
	}

	// Only execute if there are changes
	if !needsUpdate {
		tflog.Debug(ctx, "No group properties to update", map[string]interface{}{
			"groupname": params.Name,
		})
		return nil
	}

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to update group '%s': %w; stdout: %s; stderr: %s", params.Name, err, stdout, stderr)
	}

	tflog.Info(ctx, "Local group updated successfully", map[string]interface{}{
		"groupname": params.Name,
	})

	return nil
}

// DeleteLocalGroup removes a local group
func DeleteLocalGroup(ctx context.Context, client *ssh.Client, groupname string) error {
	tflog.Debug(ctx, "Deleting local group", map[string]interface{}{
		"groupname": groupname,
	})

	command := fmt.Sprintf("$ErrorActionPreference = 'Stop'; Remove-LocalGroup -Name %s", quotePowerShellString(groupname))

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to delete group '%s': %w; stdout: %s; stderr: %s", groupname, err, stdout, stderr)
	}

	tflog.Info(ctx, "Local group deleted successfully", map[string]interface{}{
		"groupname": groupname,
	})

	return nil
}
