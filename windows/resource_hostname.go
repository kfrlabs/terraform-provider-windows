package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// validateHostname vérifie qu'un hostname est conforme (labels 1-63 chars, letters/digits/hyphen,
// ne commence/termine pas par '-', labels séparés par '.', longueur totale <=255).
// Cette validation est volontairement stricte sur la forme (pas sur NetBIOS vs FQDN).
func validateHostname(name string) error {
	if name == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("hostname exceeds maximum length of 255 characters")
	}

	// label regex : start/end with alnum, can contain hyphens inside, length 1..63
	labelRe := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$`)

	labels := strings.Split(name, ".")
	for _, lbl := range labels {
		if lbl == "" {
			return fmt.Errorf("hostname contains empty label")
		}
		if len(lbl) > 63 {
			return fmt.Errorf("hostname label '%s' exceeds 63 characters", lbl)
		}
		if !labelRe.MatchString(lbl) {
			return fmt.Errorf("hostname label '%s' contains invalid characters (allowed: letters, digits, hyphen; cannot start or end with hyphen)", lbl)
		}
	}
	return nil
}

func ResourceWindowsHostname() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsHostnameCreate,
		Read:   resourceWindowsHostnameRead,
		Update: resourceWindowsHostnameUpdate,
		Delete: resourceWindowsHostnameDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceWindowsHostnameImport,
		},
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The new hostname to apply to the Windows machine.",
			},
			"restart": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Restart the computer after renaming.",
			},
			"pending_reboot": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates if a reboot is pending for the hostname change to take effect.",
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

func resourceWindowsHostnameCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	hostname := d.Get("hostname").(string)
	timeout := d.Get("command_timeout").(int)
	restart := d.Get("restart").(bool)

	// Valider le hostname (forme)
	if err := validateHostname(hostname); err != nil {
		return utils.HandleResourceError("validate", hostname, "hostname", err)
	}

	// Valider pour sécurité PowerShell
	if err := utils.ValidateField(hostname, hostname, "hostname"); err != nil {
		return err
	}

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Starting hostname creation/verification for: %s", hostname))

	// Récupérer le hostname actuel
	checkCommand := "hostname"
	tflog.Debug(ctx, fmt.Sprintf("[CREATE] Executing: %s", checkCommand))

	stdout, _, err := sshClient.ExecuteCommand(checkCommand, timeout)
	currentHostname := strings.TrimSpace(stdout)

	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("[CREATE] Could not retrieve current hostname: %v", err))
	} else {
		tflog.Info(ctx, fmt.Sprintf("[CREATE] Current hostname: '%s', Target: '%s'", currentHostname, hostname))

		// Vérifier si le hostname est déjà le bon
		if strings.EqualFold(currentHostname, hostname) {
			tflog.Info(ctx, fmt.Sprintf("[CREATE] Hostname is already set to '%s', no change needed", hostname))
			d.SetId(hostname)
			if err := d.Set("pending_reboot", false); err != nil {
				return utils.HandleResourceError("create", hostname, "pending_reboot", err)
			}
			return nil
		}

		tflog.Info(ctx, fmt.Sprintf("[CREATE] Changing hostname from '%s' to '%s'", currentHostname, hostname))
	}

	// Construire la commande de manière sûre
	command := fmt.Sprintf("Rename-Computer -NewName %s -Force -ErrorAction Stop",
		powershell.QuotePowerShellString(hostname))
	if restart {
		command += " -Restart"
	}

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Executing: %s", command))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("[CREATE] Command failed - stdout: '%s', stderr: '%s'", stdout, stderr))
		return utils.HandleCommandError(
			"create",
			hostname,
			"hostname",
			command,
			stdout,
			stderr,
			err,
		)
	}

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Command succeeded - stdout: '%s'", stdout))

	d.SetId(hostname)

	if restart {
		tflog.Warn(ctx, "[CREATE] Computer is restarting. Hostname change will be effective after reboot.")
		if err := d.Set("pending_reboot", false); err != nil {
			return utils.HandleResourceError("create", hostname, "pending_reboot", err)
		}
	} else {
		tflog.Warn(ctx, "[CREATE] Hostname change requires a reboot to take effect. Set restart=true or reboot manually.")
		if err := d.Set("pending_reboot", true); err != nil {
			return utils.HandleResourceError("create", hostname, "pending_reboot", err)
		}
	}

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Hostname resource created successfully with ID: %s", hostname))
	return nil
}

func resourceWindowsHostnameRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	expected := d.Id()
	if expected == "" {
		expected = d.Get("hostname").(string)
	}

	// Vérifier si un redémarrage est en attente
	pendingReboot, _ := d.Get("pending_reboot").(bool)

	tflog.Info(ctx, fmt.Sprintf("[READ] Starting hostname verification for: %s (pending_reboot=%v)", expected, pendingReboot))

	// Valider pour sécurité PowerShell
	if err := utils.ValidateField(expected, expected, "hostname"); err != nil {
		return utils.HandleResourceError("validate", expected, "hostname", err)
	}

	// Récupérer le nom courant sur la machine distante
	command := "hostname"

	tflog.Debug(ctx, fmt.Sprintf("[READ] Executing: %s", command))

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("[READ] Command failed: %v", err))
		if pendingReboot {
			// Si redémarrage en attente, la machine peut être en train de rebooter
			tflog.Warn(ctx, "[READ] Could not verify hostname (machine may be rebooting), keeping resource in state")
			return nil
		}
		tflog.Warn(ctx, "[READ] Could not verify hostname, keeping resource in state")
		return nil
	}

	currentHostname := strings.TrimSpace(stdout)

	tflog.Info(ctx, fmt.Sprintf("[READ] Current='%s' (len=%d), Expected='%s' (len=%d)",
		currentHostname, len(currentHostname), expected, len(expected)))

	// Comparaison insensible à la casse
	if !strings.EqualFold(currentHostname, expected) {
		if pendingReboot {
			// C'est normal que le hostname soit différent si un redémarrage est en attente
			tflog.Info(ctx, fmt.Sprintf("[READ] Hostname not yet changed (pending reboot): current='%s', expected='%s'", currentHostname, expected))
			return nil
		}

		tflog.Warn(ctx, fmt.Sprintf("[READ] Hostname mismatch: expected '%s', got '%s'", expected, currentHostname))
		tflog.Warn(ctx, "[READ] Removing resource from state due to mismatch")
		d.SetId("")
		return nil
	}

	// Le hostname correspond : le redémarrage a été effectué ou n'était pas nécessaire
	tflog.Info(ctx, fmt.Sprintf("[READ] Hostname verified successfully: %s", expected))
	if pendingReboot {
		tflog.Info(ctx, "[READ] Hostname change is now effective, clearing pending_reboot flag")
		if err := d.Set("pending_reboot", false); err != nil {
			return utils.HandleResourceError("read", expected, "pending_reboot", err)
		}
	}

	return nil
}

func resourceWindowsHostnameUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// Si seul command_timeout change, pas besoin de renommer
	if d.HasChange("command_timeout") && !d.HasChange("hostname") && !d.HasChange("restart") {
		tflog.Debug(ctx, "Only command_timeout changed, skipping hostname update")
		return resourceWindowsHostnameRead(d, m)
	}

	// Pour tout autre changement, on réutilise create qui rename et gère le restart
	return resourceWindowsHostnameCreate(d, m)
}

func resourceWindowsHostnameDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// Optionnel : restaurer l'ancien nom si on a stocké le précédent (non implémenté)
	// Pour le hostname, on ne fait généralement rien lors du delete
	tflog.Info(ctx, fmt.Sprintf("Deleting hostname resource (no action taken on remote host), id=%s", d.Id()))
	d.SetId("")
	return nil
}

func resourceWindowsHostnameImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient := m.(*ssh.Client)
	hostname := d.Id()

	// Valider la forme du hostname
	if err := validateHostname(hostname); err != nil {
		return nil, utils.HandleResourceError("validate", hostname, "hostname", err)
	}

	// Valider pour sécurité PowerShell
	if err := utils.ValidateField(hostname, hostname, "hostname"); err != nil {
		return nil, utils.HandleResourceError("validate", hostname, "hostname", err)
	}

	// Définir l'attribut et defaults cohérents
	if err := d.Set("hostname", hostname); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "hostname", err)
	}
	if err := d.Set("restart", false); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "restart", err)
	}
	if err := d.Set("pending_reboot", false); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "pending_reboot", err)
	}
	if err := d.Set("command_timeout", 300); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "command_timeout", err)
	}

	// Vérifier que le hostname correspond à la machine distante
	checkCommand := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(checkCommand, 300)
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Could not verify remote hostname during import: %v", err))
	} else {
		currentHostname := strings.TrimSpace(stdout)
		if !strings.EqualFold(currentHostname, hostname) {
			tflog.Warn(ctx, fmt.Sprintf("Imported hostname '%s' does not match remote host actual hostname '%s'", hostname, currentHostname))
			return nil, fmt.Errorf("imported hostname '%s' does not match remote host actual hostname '%s'. "+
				"Use the actual hostname or run 'Rename-Computer -NewName %s' on the remote host first",
				hostname, currentHostname, hostname)
		}
		tflog.Info(ctx, fmt.Sprintf("Successfully verified hostname: %s", hostname))
	}

	return []*schema.ResourceData{d}, nil
}
