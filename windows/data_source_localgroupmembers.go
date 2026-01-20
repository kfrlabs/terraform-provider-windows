package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// GroupMemberInfo represents information about a group member
type GroupMemberInfo struct {
	Name            string `json:"Name"`
	ObjectClass     string `json:"ObjectClass"`
	SID             string `json:"SID"`
	PrincipalSource string `json:"PrincipalSource"`
}

func DataSourceWindowsLocalGroupMembers() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsLocalGroupMembersRead,

		Schema: map[string]*schema.Schema{
			"group_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the local group to retrieve members from.",
			},
			"members": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of group members.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Name of the member.",
						},
						"object_class": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Object class (User, Group, etc.).",
						},
						"sid": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Security Identifier (SID) of the member.",
						},
						"principal_source": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Source of the principal (Local, ActiveDirectory, etc.).",
						},
					},
				},
			},
			"member_count": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Number of members in the group.",
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

// isNoMembersError checks if an error message indicates that a group has no members
// This is more robust than simple substring matching
func isNoMembersError(stderr string) bool {
	if stderr == "" {
		return false
	}

	// Convert to lowercase for case-insensitive matching
	lowerStderr := strings.ToLower(stderr)

	// Common patterns that indicate no members or group not found
	noMemberPatterns := []string{
		"no members",
		"does not have any members",
		"cannot find",
		"no matching",
		"member count is 0",
		"the group has no members",
		"no results found",
	}

	for _, pattern := range noMemberPatterns {
		if strings.Contains(lowerStderr, pattern) {
			return true
		}
	}

	return false
}

// parseGroupMembers parses the JSON output from PowerShell into GroupMemberInfo structs
// It handles both single member objects and arrays of members
func parseGroupMembers(output string) ([]GroupMemberInfo, error) {
	trimmed := strings.TrimSpace(output)

	// Empty output means no members
	if trimmed == "" {
		return []GroupMemberInfo{}, nil
	}

	var members []GroupMemberInfo

	// Try to parse as array first
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &members); err != nil {
			return nil, fmt.Errorf("failed to parse members array: %w; output: %s", err, trimmed)
		}
		return members, nil
	}

	// Try to parse as single object
	var singleMember GroupMemberInfo
	if err := json.Unmarshal([]byte(trimmed), &singleMember); err != nil {
		return nil, fmt.Errorf("failed to parse single member: %w; output: %s", err, trimmed)
	}

	return []GroupMemberInfo{singleMember}, nil
}

// convertMembersToTerraformList converts GroupMemberInfo structs to Terraform-compatible map format
func convertMembersToTerraformList(members []GroupMemberInfo) []interface{} {
	membersList := make([]interface{}, len(members))
	for i, member := range members {
		membersList[i] = map[string]interface{}{
			"name":             member.Name,
			"object_class":     member.ObjectClass,
			"sid":              member.SID,
			"principal_source": member.PrincipalSource,
		}
	}
	return membersList
}

func dataSourceWindowsLocalGroupMembersRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	groupName := d.Get("group_name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Reading members of local group: %s", groupName))

	// Validate group name for security
	if err := utils.ValidateField(groupName, groupName, "group_name"); err != nil {
		return utils.HandleResourceError("validate", groupName, "group_name", err)
	}

	// First, verify that the group exists
	checkGroupInfo, err := checkLocalGroupExists(ctx, sshClient, groupName, timeout)
	if err != nil {
		return utils.HandleResourceError("check_group", groupName, "state", err)
	}

	if !checkGroupInfo.Exists {
		return utils.HandleResourceError("check_group", groupName, "state",
			fmt.Errorf("local group %s does not exist", groupName))
	}

	// PowerShell command to retrieve group members
	// Using -ErrorAction Stop ensures we catch errors properly
	command := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
try {
    $members = Get-LocalGroupMember -Group %s -ErrorAction Stop
    if ($members) {
        $members | ForEach-Object {
            @{
                'Name' = $_.Name
                'ObjectClass' = $_.ObjectClass
                'SID' = $_.SID.Value
                'PrincipalSource' = $_.PrincipalSource.ToString()
            }
        } | ConvertTo-Json -Compress
    } else {
        # Group exists but has no members
        Write-Output ''
    }
} catch {
    # Check if it's a "no members" error
    if ($_.Exception.Message -match 'no members|does not have any members') {
        Write-Output ''
    } else {
        throw
    }
}
`,
		powershell.QuotePowerShellString(groupName),
	)

	tflog.Debug(ctx, fmt.Sprintf("[DATA SOURCE] Executing command to retrieve group members"))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)

	// Handle different error scenarios
	if err != nil {
		// Check if this is a "no members" scenario
		if isNoMembersError(stderr) {
			tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Group %s has no members", groupName))
			return setEmptyMembersList(d, groupName)
		}

		// Check if output suggests no members despite error
		if isNoMembersError(stdout) {
			tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Group %s has no members (detected from stdout)", groupName))
			return setEmptyMembersList(d, groupName)
		}

		// Genuine error - return it
		return utils.HandleCommandError(
			"get_members",
			groupName,
			"members",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse the JSON output
	members, err := parseGroupMembers(stdout)
	if err != nil {
		return utils.HandleResourceError("parse_members", groupName, "members", err)
	}

	// If no members found, handle gracefully
	if len(members) == 0 {
		tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Group %s has no members", groupName))
		return setEmptyMembersList(d, groupName)
	}

	// Convert members to Terraform format
	membersList := convertMembersToTerraformList(members)

	// Set all attributes
	d.SetId(groupName)
	if err := d.Set("group_name", groupName); err != nil {
		return utils.HandleResourceError("read", groupName, "group_name", err)
	}
	if err := d.Set("members", membersList); err != nil {
		return utils.HandleResourceError("read", groupName, "members", err)
	}
	if err := d.Set("member_count", len(members)); err != nil {
		return utils.HandleResourceError("read", groupName, "member_count", err)
	}

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Successfully read %d members from group: %s", len(members), groupName))
	return nil
}

// setEmptyMembersList sets the data source state for a group with no members
func setEmptyMembersList(d *schema.ResourceData, groupName string) error {
	d.SetId(groupName)

	if err := d.Set("group_name", groupName); err != nil {
		return utils.HandleResourceError("read", groupName, "group_name", err)
	}
	if err := d.Set("members", []interface{}{}); err != nil {
		return utils.HandleResourceError("read", groupName, "members", err)
	}
	if err := d.Set("member_count", 0); err != nil {
		return utils.HandleResourceError("read", groupName, "member_count", err)
	}

	return nil
}
