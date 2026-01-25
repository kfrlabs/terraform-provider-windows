package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
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
func isNoMembersError(stderr string) bool {
	if stderr == "" {
		return false
	}

	lowerStderr := strings.ToLower(stderr)
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
func parseGroupMembers(output string) ([]GroupMemberInfo, error) {
	trimmed := strings.TrimSpace(output)
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

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	groupName := d.Get("group_name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Reading local group members data source",
		map[string]any{"group_name": groupName})

	if err := utils.ValidateField(groupName, groupName, "group_name"); err != nil {
		return utils.HandleResourceError("validate", groupName, "group_name", err)
	}

	// Use batch with OutputSeparator
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputSeparator) // ← CHANGE ICI : OutputRaw → OutputSeparator

	// Command 1: Check if group exists
	batch.Add(fmt.Sprintf("(Get-LocalGroup -Name %s -ErrorAction SilentlyContinue) -ne $null",
		powershell.QuotePowerShellString(groupName)))

	// Command 2: Get group members
	membersCommand := fmt.Sprintf(`
$members = Get-LocalGroupMember -Group %s -ErrorAction SilentlyContinue
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
    ''
}`,
		powershell.QuotePowerShellString(groupName))

	batch.Add(membersCommand)

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch command to check group and get members")

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		if isNoMembersError(stderr) || isNoMembersError(stdout) {
			tflog.Info(ctx, "Group has no members", map[string]any{"group_name": groupName})
			return setEmptyMembersList(d, groupName)
		}
		return utils.HandleCommandError("get_members_batch", groupName, "members", command, stdout, stderr, err)
	}

	// Parse batch results with OutputSeparator
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputSeparator) // ← CHANGE ICI : OutputRaw → OutputSeparator
	if err != nil {
		return utils.HandleResourceError("read", groupName, "parse_result",
			fmt.Errorf("failed to parse batch result: %w", err))
	}

	if result.Count() < 2 {
		return utils.HandleResourceError("read", groupName, "state",
			fmt.Errorf("incomplete batch result"))
	}

	// Result 1: Group existence
	groupExists, _ := result.GetStringResult(0)
	if groupExists != "True" {
		return utils.HandleResourceError("check_group", groupName, "state",
			fmt.Errorf("local group %s does not exist", groupName))
	}

	// Result 2: Members
	membersOutput, _ := result.GetStringResult(1)

	// Parse the JSON output
	members, err := parseGroupMembers(membersOutput)
	if err != nil {
		return utils.HandleResourceError("parse_members", groupName, "members", err)
	}

	// If no members found, handle gracefully
	if len(members) == 0 {
		tflog.Info(ctx, "Group has no members", map[string]any{"group_name": groupName})
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

	tflog.Info(ctx, "Successfully read group members data source",
		map[string]any{
			"group_name":   groupName,
			"member_count": len(members),
		})

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
