package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

// GroupMemberInfo représente les informations d'un membre de groupe
type GroupMemberInfo struct {
	Name         string `json:"Name"`
	ObjectClass  string `json:"ObjectClass"`
	SID          string `json:"SID"`
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

func dataSourceWindowsLocalGroupMembersRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	groupName := d.Get("group_name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Reading members of local group: %s", groupName))

	// Valider le nom du groupe pour sécurité
	if err := powershell.ValidatePowerShellArgument(groupName); err != nil {
		return fmt.Errorf("invalid group name: %w", err)
	}

	// Vérifier d'abord que le groupe existe
	checkGroupInfo, err := checkLocalGroupExists(ctx, sshClient, groupName, timeout)
	if err != nil {
		return fmt.Errorf("failed to check group existence: %w", err)
	}

	if !checkGroupInfo.Exists {
		return fmt.Errorf("local group %s does not exist", groupName)
	}

	// Commande PowerShell pour récupérer les membres du groupe
	command := fmt.Sprintf(`
$members = Get-LocalGroupMember -Group %s -ErrorAction Stop
$members | ForEach-Object {
    @{
        'Name' = $_.Name
        'ObjectClass' = $_.ObjectClass
        'SID' = $_.SID.Value
        'PrincipalSource' = $_.PrincipalSource.ToString()
    }
} | ConvertTo-Json -Compress
`,
		powershell.QuotePowerShellString(groupName),
	)

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		// Si le groupe n'a pas de membres, Get-LocalGroupMember peut retourner une erreur
		if stderr != "" && (contains(stderr, "no members") || contains(stderr, "Cannot find")) {
			tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Group %s has no members", groupName))
			d.SetId(groupName)
			if err := d.Set("group_name", groupName); err != nil {
				return fmt.Errorf("failed to set group_name: %w", err)
			}
			if err := d.Set("members", []interface{}{}); err != nil {
				return fmt.Errorf("failed to set members: %w", err)
			}
			if err := d.Set("member_count", 0); err != nil {
				return fmt.Errorf("failed to set member_count: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to get group members: %w; stderr: %s", err, stderr)
	}

	// Parser le JSON retourné
	var members []GroupMemberInfo
	
	// Le résultat peut être un objet unique ou un tableau
	stdout = trimOutput(stdout)
	if stdout == "" {
		members = []GroupMemberInfo{}
	} else if stdout[0] == '[' {
		// Tableau de membres
		if err := json.Unmarshal([]byte(stdout), &members); err != nil {
			return fmt.Errorf("failed to parse group members: %w; output: %s", err, stdout)
		}
	} else {
		// Un seul membre
		var singleMember GroupMemberInfo
		if err := json.Unmarshal([]byte(stdout), &singleMember); err != nil {
			return fmt.Errorf("failed to parse group member: %w; output: %s", err, stdout)
		}
		members = []GroupMemberInfo{singleMember}
	}

	// Convertir en format Terraform
	membersList := make([]interface{}, len(members))
	for i, member := range members {
		membersList[i] = map[string]interface{}{
			"name":             member.Name,
			"object_class":     member.ObjectClass,
			"sid":              member.SID,
			"principal_source": member.PrincipalSource,
		}
	}

	// Set all attributes
	d.SetId(groupName)
	if err := d.Set("group_name", groupName); err != nil {
		return fmt.Errorf("failed to set group_name: %w", err)
	}
	if err := d.Set("members", membersList); err != nil {
		return fmt.Errorf("failed to set members: %w", err)
	}
	if err := d.Set("member_count", len(members)); err != nil {
		return fmt.Errorf("failed to set member_count: %w", err)
	}

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Successfully read %d members from group: %s", len(members), groupName))
	return nil
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || 
		   len(s) > len(substr) && contains(s[1:], substr)
}

func trimOutput(s string) string {
	// Simple trim implementation
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
