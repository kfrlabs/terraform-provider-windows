package resources

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

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
				Description: "The name of the local user account.",
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
				Description: "If true, the account will be created in a disabled state.",
			},
			"groups": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of local groups this user should be a member of.",
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

func resourceWindowsLocalUserCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	timeout := d.Get("command_timeout").(int)

	// Base command for creating user
	command := fmt.Sprintf("New-LocalUser -Name '%s' -Password (ConvertTo-SecureString -AsPlainText '%s' -Force)",
		username, password)

	// Add optional parameters
	if fullName, ok := d.GetOk("full_name"); ok {
		command += fmt.Sprintf(" -FullName '%s'", fullName.(string))
	}
	if description, ok := d.GetOk("description"); ok {
		command += fmt.Sprintf(" -Description '%s'", description.(string))
	}
	if d.Get("password_never_expires").(bool) {
		command += " -PasswordNeverExpires $true"
	}
	if d.Get("user_cannot_change_password").(bool) {
		command += " -UserMayNotChangePassword $true"
	}
	if d.Get("account_disabled").(bool) {
		command += " -Disabled $true"
	}

	command += " -ErrorAction Stop"

	// Create the user
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to create local user: %w", err)
	}

	// Handle group memberships if specified
	if groups, ok := d.GetOk("groups"); ok {
		groupList := groups.(*schema.Set).List()
		for _, group := range groupList {
			addToGroupCmd := fmt.Sprintf("Add-LocalGroupMember -Group '%s' -Member '%s' -ErrorAction Stop",
				group.(string), username)
			_, _, err := sshClient.ExecuteCommand(addToGroupCmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to add user to group %s: %w", group.(string), err)
			}
		}
	}

	d.SetId(username)
	return resourceWindowsLocalUserRead(d, m)
}

func resourceWindowsLocalUserRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	username := d.Id()
	timeout := d.Get("command_timeout").(int)

	// Check if user exists and get properties
	command := fmt.Sprintf(`
        $user = Get-LocalUser -Name '%s' -ErrorAction SilentlyContinue
        if ($user) {
            @{
                'Exists' = $true
                'FullName' = $user.FullName
                'Description' = $user.Description
                'PasswordNeverExpires' = $user.PasswordNeverExpires
                'UserMayNotChangePassword' = !$user.UserMayChangePassword
                'Enabled' = $user.Enabled
                'Groups' = (Get-LocalGroup | Where-Object { $_.Members -contains $user }).Name
            } | ConvertTo-Json
        } else {
            @{ 'Exists' = $false } | ConvertTo-Json
        }
    `, username)

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to read local user: %w", err)
	}

	// Parse the JSON output
	if strings.Contains(stdout, `"Exists": false`) {
		d.SetId("")
		return nil
	}

	// Update the state with the current values
	d.Set("username", username)
	d.Set("full_name", strings.TrimSpace(strings.Split(stdout, "FullName")[1]))
	d.Set("description", strings.TrimSpace(strings.Split(stdout, "Description")[1]))
	d.Set("password_never_expires", strings.Contains(stdout, `"PasswordNeverExpires": true`))
	d.Set("user_cannot_change_password", strings.Contains(stdout, `"UserMayNotChangePassword": true`))
	d.Set("account_disabled", !strings.Contains(stdout, `"Enabled": true`))

	// Update groups
	if strings.Contains(stdout, "Groups") {
		groups := strings.Split(strings.Split(stdout, "Groups")[1], "]")[0]
		d.Set("groups", strings.Split(groups, ","))
	}

	return nil
}

func resourceWindowsLocalUserUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	if d.HasChange("password") {
		password := d.Get("password").(string)
		command := fmt.Sprintf("Set-LocalUser -Name '%s' -Password (ConvertTo-SecureString -AsPlainText '%s' -Force)",
			username, password)
		_, _, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}
	}

	// Update other properties
	command := fmt.Sprintf("Set-LocalUser -Name '%s'", username)
	if d.HasChange("full_name") {
		command += fmt.Sprintf(" -FullName '%s'", d.Get("full_name").(string))
	}
	if d.HasChange("description") {
		command += fmt.Sprintf(" -Description '%s'", d.Get("description").(string))
	}
	if d.HasChange("password_never_expires") {
		command += fmt.Sprintf(" -PasswordNeverExpires $%t", d.Get("password_never_expires").(bool))
	}
	if d.HasChange("user_cannot_change_password") {
		command += fmt.Sprintf(" -UserMayChangePassword $%t", !d.Get("user_cannot_change_password").(bool))
	}
	if d.HasChange("account_disabled") {
		if d.Get("account_disabled").(bool) {
			command += " -Disabled $true"
		} else {
			command += " -Enabled $true"
		}
	}

	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to update local user: %w", err)
	}

	// Handle group membership changes
	if d.HasChange("groups") {
		o, n := d.GetChange("groups")
		oldSet := o.(*schema.Set)
		newSet := n.(*schema.Set)

		// Remove from old groups that are not in new groups
		for _, group := range oldSet.Difference(newSet).List() {
			command := fmt.Sprintf("Remove-LocalGroupMember -Group '%s' -Member '%s' -ErrorAction Stop",
				group.(string), username)
			_, _, err := sshClient.ExecuteCommand(command, timeout)
			if err != nil {
				return fmt.Errorf("failed to remove user from group %s: %w", group.(string), err)
			}
		}

		// Add to new groups that were not in old groups
		for _, group := range newSet.Difference(oldSet).List() {
			command := fmt.Sprintf("Add-LocalGroupMember -Group '%s' -Member '%s' -ErrorAction Stop",
				group.(string), username)
			_, _, err := sshClient.ExecuteCommand(command, timeout)
			if err != nil {
				return fmt.Errorf("failed to add user to group %s: %w", group.(string), err)
			}
		}
	}

	return resourceWindowsLocalUserRead(d, m)
}

func resourceWindowsLocalUserDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	command := fmt.Sprintf("Remove-LocalUser -Name '%s' -ErrorAction Stop", username)
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to delete local user: %w", err)
	}

	d.SetId("")
	return nil
}
