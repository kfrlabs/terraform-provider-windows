package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

// LocalGroupInfo represents the information of a local group
type LocalGroupInfo struct {
	Exists      bool     `json:"Exists"`
	Name        string   `json:"Name"`
	Description string   `json:"Description"`
	Members     []string `json:"Members"`
}

func ResourceWindowsLocalGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsLocalGroupCreate,
		Read:   resourceWindowsLocalGroupRead,
		Update: resourceWindowsLocalGroupUpdate,
		Delete: resourceWindowsLocalGroupDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceWindowsLocalGroupImport,
		},

		Schema: map[string]*schema.Schema{
			"group": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The local group name.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A description for the local group.",
			},
			"members": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Members to ensure are part of the group (local accounts or DOMAIN\\User).",
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

func resourceWindowsLocalGroupCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	group := d.Get("group").(string)
	timeout := d.Get("command_timeout").(int)

	// Validate group name
	if err := powershell.ValidatePowerShellArgument(group); err != nil {
		return fmt.Errorf("invalid group name: %w", err)
	}

	// Create group
	command := fmt.Sprintf("New-LocalGroup -Name %s -ErrorAction Stop", powershell.QuotePowerShellString(group))
	log.Printf("[DEBUG] Creating local group: %s", group)
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to create local group: %w", err)
	}

	// Add members if provided
	if members, ok := d.GetOk("members"); ok {
		memberList := members.(*schema.Set).List()
		for _, mbr := range memberList {
			member := mbr.(string)

			if err := powershell.ValidatePowerShellArgument(member); err != nil {
				return fmt.Errorf("invalid member name '%s': %w", member, err)
			}

			addCmd := fmt.Sprintf("Add-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
				powershell.QuotePowerShellString(group),
				powershell.QuotePowerShellString(member),
			)
			log.Printf("[DEBUG] Adding member '%s' to group '%s'", member, group)
			_, _, err := sshClient.ExecuteCommand(addCmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to add member %s to group %s: %w", member, group, err)
			}
		}
	}

	d.SetId(group)
	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	group := d.Id()
	if group == "" {
		group = d.Get("group").(string)
	}
	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	// Validate group name
	if err := powershell.ValidatePowerShellArgument(group); err != nil {
		d.SetId("")
		return fmt.Errorf("invalid group name: %w", err)
	}

	// Build PowerShell to return JSON about group existence and members
	command := fmt.Sprintf(`
$g = Get-LocalGroup -Name %s -ErrorAction SilentlyContinue
if ($g) {
    $members = @()
    try {
        $members = @(Get-LocalGroupMember -Group %s -ErrorAction SilentlyContinue | ForEach-Object {
            # Format member name as "Domain\User" or "COMPUTERNAME\User"
            if ($_.ObjectClass -eq 'User' -or $_.ObjectClass -eq 'Group') {
                $_.Name
            } else {
                $_.Name
            }
        })
    } catch {}
    @{ 'Exists' = $true; 'Members' = $members } | ConvertTo-Json
} else {
    @{ 'Exists' = $false } | ConvertTo-Json
}
`, powershell.QuotePowerShellString(group), powershell.QuotePowerShellString(group))

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		// If we can't read, clear id to force re-create/import
		log.Printf("[DEBUG] failed to read local group '%s': %v", group, err)
		d.SetId("")
		return nil
	}

	var info LocalGroupInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return fmt.Errorf("failed to parse local group info: %w; output: %s", err, stdout)
	}

	if !info.Exists {
		d.SetId("")
		return nil
	}

	// Update state
	d.Set("group", group)
	d.Set("members", info.Members)

	return nil
}

func resourceWindowsLocalGroupUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	group := d.Get("group").(string)
	timeout := d.Get("command_timeout").(int)

	// Validate group
	if err := powershell.ValidatePowerShellArgument(group); err != nil {
		return fmt.Errorf("invalid group name: %w", err)
	}

	// Handle members changes
	if d.HasChange("members") {
		o, n := d.GetChange("members")
		oldSet := o.(*schema.Set)
		newSet := n.(*schema.Set)

		// Remove members that are no longer present
		for _, rm := range oldSet.Difference(newSet).List() {
			member := rm.(string)

			if err := powershell.ValidatePowerShellArgument(member); err != nil {
				return fmt.Errorf("invalid member name '%s': %w", member, err)
			}

			removeCmd := fmt.Sprintf("Remove-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
				powershell.QuotePowerShellString(group),
				powershell.QuotePowerShellString(member),
			)
			log.Printf("[DEBUG] Removing member '%s' from group '%s'", member, group)
			_, _, err := sshClient.ExecuteCommand(removeCmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to remove member %s from group %s: %w", member, group, err)
			}
		}

		// Add new members
		for _, am := range newSet.Difference(oldSet).List() {
			member := am.(string)

			if err := powershell.ValidatePowerShellArgument(member); err != nil {
				return fmt.Errorf("invalid member name '%s': %w", member, err)
			}

			addCmd := fmt.Sprintf("Add-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
				powershell.QuotePowerShellString(group),
				powershell.QuotePowerShellString(member),
			)
			log.Printf("[DEBUG] Adding member '%s' to group '%s'", member, group)
			_, _, err := sshClient.ExecuteCommand(addCmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to add member %s to group %s: %w", member, group, err)
			}
		}
	}

	// Nothing else to update for group itself (name is ForceNew)
	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	group := d.Get("group").(string)
	timeout := d.Get("command_timeout").(int)

	// Validate group
	if err := powershell.ValidatePowerShellArgument(group); err != nil {
		return fmt.Errorf("invalid group name: %w", err)
	}

	command := fmt.Sprintf("Remove-LocalGroup -Name %s -ErrorAction Stop", powershell.QuotePowerShellString(group))
	log.Printf("[DEBUG] Removing local group: %s", group)
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to remove local group: %w", err)
	}

	d.SetId("")
	return nil
}

func resourceWindowsLocalGroupImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient := m.(*ssh.Client)
	group := d.Id()

	// Validate group
	if err := powershell.ValidatePowerShellArgument(group); err != nil {
		return nil, fmt.Errorf("invalid group name: %w", err)
	}

	// Set the group attribute and defaults
	d.Set("group", group)
	d.Set("command_timeout", 300)

	// Try to fetch members, but allow import even if we can't verify
	if stdout, _, err := sshClient.ExecuteCommand(fmt.Sprintf("Get-LocalGroupMember -Group %s | Select-Object -ExpandProperty Name | ConvertTo-Json", powershell.QuotePowerShellString(group)), 300); err == nil {
		var members []string
		if err := json.Unmarshal([]byte(stdout), &members); err == nil {
			d.Set("members", members)
		} else {
			// If single member returned as string, try that
			var single string
			if err2 := json.Unmarshal([]byte(stdout), &single); err2 == nil && single != "" {
				d.Set("members", []string{single})
			}
		}
	} else {
		log.Printf("[DEBUG] could not list members for group '%s' during import: %v", group, err)
	}

	return []*schema.ResourceData{d}, nil
}
