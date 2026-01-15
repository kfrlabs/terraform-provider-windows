package resources

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

// LocalUserInfo représente les informations d'un utilisateur local
type LocalUserInfo struct {
	Exists                   bool     `json:"Exists"`
	FullName                 string   `json:"FullName"`
	Description              string   `json:"Description"`
	PasswordNeverExpires     bool     `json:"PasswordNeverExpires"`
	UserMayNotChangePassword bool     `json:"UserMayNotChangePassword"`
	Enabled                  bool     `json:"Enabled"`
	Groups                   []string `json:"Groups"`
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

	// ✅ Valider les inputs
	if err := powershell.ValidatePowerShellArgument(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// ✅ Construire la commande de manière sécurisée avec quoting
	command := fmt.Sprintf(
		"New-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
		powershell.QuotePowerShellString(username),
		powershell.QuotePowerShellString(password),
	)

	// Ajouter les paramètres optionnels
	if fullName, ok := d.GetOk("full_name"); ok {
		command += fmt.Sprintf(" -FullName %s", powershell.QuotePowerShellString(fullName.(string)))
	}
	if description, ok := d.GetOk("description"); ok {
		command += fmt.Sprintf(" -Description %s", powershell.QuotePowerShellString(description.(string)))
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

	// Créer l'utilisateur
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to create local user: %w", err)
	}

	// Ajouter aux groupes si spécifiés
	if groups, ok := d.GetOk("groups"); ok {
		groupList := groups.(*schema.Set).List()
		for _, group := range groupList {
			groupName := group.(string)

			// ✅ Valider le nom du groupe
			if err := powershell.ValidatePowerShellArgument(groupName); err != nil {
				return fmt.Errorf("invalid group name '%s': %w", groupName, err)
			}

			addToGroupCmd := fmt.Sprintf(
				"Add-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
				powershell.QuotePowerShellString(groupName),
				powershell.QuotePowerShellString(username),
			)
			_, _, err := sshClient.ExecuteCommand(addToGroupCmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to add user to group %s: %w", groupName, err)
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

	// ✅ Valider le username avant utilisation
	if err := powershell.ValidatePowerShellArgument(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// Commande PowerShell qui retourne du JSON structuré
	command := fmt.Sprintf(`
$user = Get-LocalUser -Name %s -ErrorAction SilentlyContinue
if ($user) {
    $groups = @()
    try { 
        $groups = @(Get-LocalGroup | Where-Object { 
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | 
             Where-Object { $_.Name -eq "$env:COMPUTERNAME\$($user.Name)" }) -ne $null 
        } | Select-Object -ExpandProperty Name)
    } catch {}
    
    @{
        'Exists' = $true
        'FullName' = $user.FullName
        'Description' = $user.Description
        'PasswordNeverExpires' = $user.PasswordNeverExpires
        'UserMayNotChangePassword' = -not $user.UserMayChangePassword
        'Enabled' = $user.Enabled
        'Groups' = $groups
    } | ConvertTo-Json
} else {
    @{ 'Exists' = $false } | ConvertTo-Json
}
`,
		powershell.QuotePowerShellString(username),
	)

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to read local user: %w", err)
	}

	// ✅ Parser le JSON de manière structurée
	var info LocalUserInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return fmt.Errorf("failed to parse user info: %w; output: %s", err, stdout)
	}

	if !info.Exists {
		d.SetId("")
		return nil
	}

	// Mettre à jour l'état
	d.Set("username", username)
	d.Set("full_name", info.FullName)
	d.Set("description", info.Description)
	d.Set("password_never_expires", info.PasswordNeverExpires)
	d.Set("user_cannot_change_password", info.UserMayNotChangePassword)
	d.Set("account_disabled", !info.Enabled)
	d.Set("groups", info.Groups)

	return nil
}

func resourceWindowsLocalUserUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	// ✅ Valider le username
	if err := powershell.ValidatePowerShellArgument(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// Mettre à jour le mot de passe
	if d.HasChange("password") {
		password := d.Get("password").(string)
		command := fmt.Sprintf(
			"Set-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
			powershell.QuotePowerShellString(username),
			powershell.QuotePowerShellString(password),
		)
		_, _, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}
	}

	// Construire la commande de mise à jour
	command := fmt.Sprintf("Set-LocalUser -Name %s", powershell.QuotePowerShellString(username))

	if d.HasChange("full_name") {
		command += fmt.Sprintf(" -FullName %s", powershell.QuotePowerShellString(d.Get("full_name").(string)))
	}
	if d.HasChange("description") {
		command += fmt.Sprintf(" -Description %s", powershell.QuotePowerShellString(d.Get("description").(string)))
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

	if d.HasChange("full_name") || d.HasChange("description") || d.HasChange("password_never_expires") ||
		d.HasChange("user_cannot_change_password") || d.HasChange("account_disabled") {
		_, _, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return fmt.Errorf("failed to update local user: %w", err)
		}
	}

	// Gérer les modifications d'adhésion aux groupes
	if d.HasChange("groups") {
		o, n := d.GetChange("groups")
		oldSet := o.(*schema.Set)
		newSet := n.(*schema.Set)

		// Retirer des anciens groupes
		for _, group := range oldSet.Difference(newSet).List() {
			groupName := group.(string)

			// ✅ Valider le nom du groupe
			if err := powershell.ValidatePowerShellArgument(groupName); err != nil {
				return fmt.Errorf("invalid group name '%s': %w", groupName, err)
			}

			command := fmt.Sprintf(
				"Remove-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
				powershell.QuotePowerShellString(groupName),
				powershell.QuotePowerShellString(username),
			)
			_, _, err := sshClient.ExecuteCommand(command, timeout)
			if err != nil {
				return fmt.Errorf("failed to remove user from group %s: %w", groupName, err)
			}
		}

		// Ajouter aux nouveaux groupes
		for _, group := range newSet.Difference(oldSet).List() {
			groupName := group.(string)

			// ✅ Valider le nom du groupe
			if err := powershell.ValidatePowerShellArgument(groupName); err != nil {
				return fmt.Errorf("invalid group name '%s': %w", groupName, err)
			}

			command := fmt.Sprintf(
				"Add-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
				powershell.QuotePowerShellString(groupName),
				powershell.QuotePowerShellString(username),
			)
			_, _, err := sshClient.ExecuteCommand(command, timeout)
			if err != nil {
				return fmt.Errorf("failed to add user to group %s: %w", groupName, err)
			}
		}
	}

	return resourceWindowsLocalUserRead(d, m)
}

func resourceWindowsLocalUserDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	// ✅ Valider le username
	if err := powershell.ValidatePowerShellArgument(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	command := fmt.Sprintf("Remove-LocalUser -Name %s -ErrorAction Stop", powershell.QuotePowerShellString(username))
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to delete local user: %w", err)
	}

	d.SetId("")
	return nil
}
