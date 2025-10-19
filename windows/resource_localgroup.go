package resources

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

type localGroupInfo struct {
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
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the local group.",
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
				Description: "List of members (users or groups) to add to this local group.",
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
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Create group command
	command := fmt.Sprintf("New-LocalGroup -Name '%s'", name)
	if desc, ok := d.GetOk("description"); ok {
		command += fmt.Sprintf(" -Description '%s'", desc.(string))
	}
	command += " -ErrorAction Stop"

	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to create local group: %w", err)
	}

	// Add members if any
	if members, ok := d.GetOk("members"); ok {
		memberList := members.(*schema.Set).List()
		for _, mbr := range memberList {
			addCmd := fmt.Sprintf("Add-LocalGroupMember -Group '%s' -Member '%s' -ErrorAction Stop", name, mbr.(string))
			_, _, err := sshClient.ExecuteCommand(addCmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to add member '%s' to group '%s': %w", mbr.(string), name, err)
			}
		}
	}

	d.SetId(name)
	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	name := d.Id()
	timeout := d.Get("command_timeout").(int)

	// PowerShell: return JSON with Exists, Name, Description, Members
	command := fmt.Sprintf(`
$group = Get-LocalGroup -Name '%s' -ErrorAction SilentlyContinue
if ($group) {
    $members = @()
    try { $members = (Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) } catch {}
    @{ Exists = $true; Name = $group.Name; Description = $group.Description; Members = $members } | ConvertTo-Json
} else {
    @{ Exists = $false } | ConvertTo-Json
}
`, name)

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to read local group: %w", err)
	}

	var info localGroupInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		// Try to be helpful with raw output
		return fmt.Errorf("failed to parse group info JSON: %w; output: %s", err, stdout)
	}

	if !info.Exists {
		d.SetId("")
		return nil
	}

	d.Set("name", info.Name)
	d.Set("description", info.Description)
	if err := d.Set("members", schema.NewSet(schema.HashString, stringSliceToInterfaceSlice(info.Members))); err != nil {
		return fmt.Errorf("failed to set members in state: %w", err)
	}

	return nil
}

func resourceWindowsLocalGroupUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	if d.HasChange("description") {
		desc := d.Get("description").(string)
		cmd := fmt.Sprintf("Set-LocalGroup -Name '%s' -Description '%s' -ErrorAction Stop", name, desc)
		_, _, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return fmt.Errorf("failed to update group description: %w", err)
		}
	}

	// Handle members update
	if d.HasChange("members") {
		o, n := d.GetChange("members")
		oldSet := o.(*schema.Set)
		newSet := n.(*schema.Set)

		// Remove members that were removed
		for _, member := range oldSet.Difference(newSet).List() {
			cmd := fmt.Sprintf("Remove-LocalGroupMember -Group '%s' -Member '%s' -ErrorAction Stop", name, member.(string))
			_, _, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to remove member '%s' from group '%s': %w", member.(string), name, err)
			}
		}

		// Add new members
		for _, member := range newSet.Difference(oldSet).List() {
			cmd := fmt.Sprintf("Add-LocalGroupMember -Group '%s' -Member '%s' -ErrorAction Stop", name, member.(string))
			_, _, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to add member '%s' to group '%s': %w", member.(string), name, err)
			}
		}
	}

	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	cmd := fmt.Sprintf("Remove-LocalGroup -Name '%s' -ErrorAction Stop", name)
	_, _, err := sshClient.ExecuteCommand(cmd, timeout)
	if err != nil {
		return fmt.Errorf("failed to delete local group: %w", err)
	}

	d.SetId("")
	return nil
}

// helper: convert []string to []interface{} for schema.Set
func stringSliceToInterfaceSlice(in []string) []interface{} {
	out := make([]interface{}, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}
