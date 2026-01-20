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

// LocalUserInfo représente les informations d'un utilisateur local
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

// checkLocalUserExists vérifie si un utilisateur local existe et retourne ses informations
func checkLocalUserExists(ctx context.Context, sshClient *ssh.Client, username string, timeout int) (*LocalUserInfo, error) {
	// Valider le username pour sécurité
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return nil, err
	}

	tflog.Debug(ctx, fmt.Sprintf("Checking if local user exists: %s", username))

	// Commande PowerShell qui retourne du JSON structuré
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
	sshClient := m.(*ssh.Client)

	username := d.Get("username").(string)
	password := d.Get("password").(string)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Starting local user creation for: %s", username))

	// Valider le username pour sécurité
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return err
	}

	// Vérifier si l'utilisateur existe déjà
	info, err := checkLocalUserExists(ctx, sshClient, username, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", username, "state", err)
	}

	if info.Exists {
		if allowExisting {
			tflog.Info(ctx, fmt.Sprintf("[CREATE] User %s already exists, adopting it (allow_existing=true)", username))
			d.SetId(username)
			return resourceWindowsLocalUserRead(d, m)
		} else {
			resourceName := "localuser"
			return utils.HandleResourceError(
				"create",
				username,
				"state",
				fmt.Errorf("local user already exists. "+
					"To manage this existing user, either:\n"+
					"  1. Import it: terraform import windows_localuser.%s '%s'\n"+
					"  2. Set allow_existing = true in your configuration\n"+
					"  3. Remove it first (WARNING): Remove-LocalUser -Name '%s' -Force",
					resourceName, username, username),
			)
		}
	}

	// Construire la commande de manière sécurisée
	command := fmt.Sprintf(
		"New-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force)",
		powershell.QuotePowerShellString(username),
		powershell.QuotePowerShellString(password),
	)

	// Ajouter les paramètres optionnels
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

	if d.Get("account_disabled").(bool) {
		command += " -AccountNeverExpires"
	}

	command += " -ErrorAction Stop"

	tflog.Info(ctx, "[CREATE] Creating local user (password hidden)")
	tflog.Debug(ctx, fmt.Sprintf("[CREATE] Executing: %s", strings.ReplaceAll(command, password, "***REDACTED***")))

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

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Local user created successfully: %s", username))

	// Désactiver le compte si nécessaire
	if d.Get("account_disabled").(bool) {
		disableCmd := fmt.Sprintf("Disable-LocalUser -Name %s -ErrorAction Stop",
			powershell.QuotePowerShellString(username))

		tflog.Debug(ctx, "[CREATE] Disabling user account")
		stdout, stderr, err := sshClient.ExecuteCommand(disableCmd, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"create",
				username,
				"account_disabled",
				disableCmd,
				stdout,
				stderr,
				err,
			)
		}
	}

	d.SetId(username)
	tflog.Info(ctx, fmt.Sprintf("[CREATE] Local user resource created successfully with ID: %s", username))

	return resourceWindowsLocalUserRead(d, m)
}

func resourceWindowsLocalUserRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	username := d.Id()
	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	// Valider le username
	if err := utils.ValidateField(username, username, "username"); err != nil {
		tflog.Warn(ctx, fmt.Sprintf("[READ] Invalid username format: %v", err))
		d.SetId("")
		return nil
	}

	tflog.Debug(ctx, fmt.Sprintf("[READ] Reading local user: %s", username))

	info, err := checkLocalUserExists(ctx, sshClient, username, timeout)
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("[READ] Failed to read local user %s: %v", username, err))
		d.SetId("")
		return nil
	}

	if !info.Exists {
		tflog.Debug(ctx, fmt.Sprintf("[READ] Local user %s does not exist, removing from state", username))
		d.SetId("")
		return nil
	}

	// Mettre à jour le state
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

	tflog.Debug(ctx, fmt.Sprintf("[READ] Local user read successfully: %s (enabled=%v)", username, info.Enabled))
	return nil
}

func resourceWindowsLocalUserUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[UPDATE] Updating local user: %s", username))

	// Valider le username pour sécurité
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return err
	}

	// Mettre à jour le mot de passe
	if d.HasChange("password") {
		password := d.Get("password").(string)
		command := fmt.Sprintf(
			"Set-LocalUser -Name %s -Password (ConvertTo-SecureString -AsPlainText %s -Force) -ErrorAction Stop",
			powershell.QuotePowerShellString(username),
			powershell.QuotePowerShellString(password),
		)

		tflog.Info(ctx, "[UPDATE] Updating password")
		tflog.Debug(ctx, "[UPDATE] Executing: Set-LocalUser -Password (password hidden)")

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

	// Construire la commande de mise à jour pour les autres attributs
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
		tflog.Debug(ctx, fmt.Sprintf("[UPDATE] Executing: %s", command))

		stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"update",
				username,
				"properties",
				command,
				stdout,
				stderr,
				err,
			)
		}
	}

	// Gérer l'activation/désactivation du compte
	if d.HasChange("account_disabled") {
		disabled := d.Get("account_disabled").(bool)
		var cmd string
		if disabled {
			cmd = fmt.Sprintf("Disable-LocalUser -Name %s -ErrorAction Stop",
				powershell.QuotePowerShellString(username))
			tflog.Info(ctx, "[UPDATE] Disabling user account")
		} else {
			cmd = fmt.Sprintf("Enable-LocalUser -Name %s -ErrorAction Stop",
				powershell.QuotePowerShellString(username))
			tflog.Info(ctx, "[UPDATE] Enabling user account")
		}

		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"update",
				username,
				"account_disabled",
				cmd,
				stdout,
				stderr,
				err,
			)
		}
	}

	tflog.Info(ctx, fmt.Sprintf("[UPDATE] Local user updated successfully: %s", username))
	return resourceWindowsLocalUserRead(d, m)
}

func resourceWindowsLocalUserDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DELETE] Deleting local user: %s", username))

	// Valider le username pour sécurité
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return err
	}

	command := fmt.Sprintf("Remove-LocalUser -Name %s -ErrorAction Stop",
		powershell.QuotePowerShellString(username))

	tflog.Debug(ctx, fmt.Sprintf("[DELETE] Executing: %s", command))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"delete",
			username,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId("")
	tflog.Info(ctx, fmt.Sprintf("[DELETE] Local user deleted successfully: %s", username))
	return nil
}
