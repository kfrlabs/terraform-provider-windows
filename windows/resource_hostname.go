package resources

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
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
	sshClient := m.(*ssh.Client)
	hostname := d.Get("hostname").(string)
	timeout := d.Get("command_timeout").(int)
	restart := d.Get("restart").(bool)

	// Valider le hostname (forme)
	if err := validateHostname(hostname); err != nil {
		return fmt.Errorf("invalid hostname: %w", err)
	}

	// Construire la commande de manière sûre
	command := fmt.Sprintf("Rename-Computer -NewName %s -Force -ErrorAction Stop",
		powershell.QuotePowerShellString(hostname))
	if restart {
		command += " -Restart"
	}

	log.Printf("[DEBUG] Setting hostname to: %s (restart=%v)", hostname, restart)
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to set hostname: %w", err)
	}

	d.SetId(hostname)
	return resourceWindowsHostnameRead(d, m)
}

func resourceWindowsHostnameRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	expected := d.Get("hostname").(string)

	// Récupérer le nom courant sur la machine distante
	command := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		// Si on ne peut pas vérifier l'état, retirer l'id pour forcer recreate/import
		log.Printf("[DEBUG] Failed to read hostname: %v", err)
		d.SetId("")
		return nil
	}

	current := strings.TrimSpace(stdout)
	// Comparaison insensible à la casse (hostnames Windows ne sont pas case-sensitive)
	if !strings.EqualFold(current, expected) {
		log.Printf("[DEBUG] Hostname mismatch: expected '%s', got '%s'", expected, current)
		d.SetId("")
		return nil
	}

	// Tout est ok
	d.SetId(expected)
	return nil
}

func resourceWindowsHostnameUpdate(d *schema.ResourceData, m interface{}) error {
	// On peut réutiliser create qui rename et gère le restart
	return resourceWindowsHostnameCreate(d, m)
}

func resourceWindowsHostnameDelete(d *schema.ResourceData, m interface{}) error {
	// Optionnel : restaurer l'ancien nom si on a stocké le précédent (non implémenté)
	log.Printf("[DEBUG] Deleting hostname resource (no action taken on remote host), id=%s", d.Id())
	d.SetId("")
	return nil
}

func resourceWindowsHostnameImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient := m.(*ssh.Client)
	hostname := d.Id()

	// Valider la forme du hostname
	if err := validateHostname(hostname); err != nil {
		return nil, fmt.Errorf("invalid hostname: %w", err)
	}

	// Définir l'attribut et defaults cohérents
	d.Set("hostname", hostname)
	d.Set("restart", false)
	d.Set("command_timeout", 300)

	// Optionnel : vérifier que le hostname correspond à la machine distante
	// mais laisser l'import fonctionner même si la vérification échoue.
	if stdout, _, err := sshClient.ExecuteCommand("hostname", 300); err == nil {
		if !strings.EqualFold(strings.TrimSpace(stdout), hostname) {
			log.Printf("[WARN] imported hostname '%s' does not match remote host actual hostname '%s'", hostname, strings.TrimSpace(stdout))
		}
	} else {
		log.Printf("[DEBUG] could not verify remote hostname during import: %v", err)
	}

	return []*schema.ResourceData{d}, nil
}
