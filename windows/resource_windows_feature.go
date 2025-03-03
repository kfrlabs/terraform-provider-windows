package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/k9fr4n/terraform-provider-windows/windows/internal/ssh"
)

func ResourceWindowsFeature() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsFeatureCreate,
		Read:   resourceWindowsFeatureRead,
		Update: resourceWindowsFeatureUpdate,
		Delete: resourceWindowsFeatureDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceWindowsFeatureImport,
		},

		Schema: map[string]*schema.Schema{
			"feature": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Windows feature to install or remove.",
			},
			"restart": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to restart the server automatically if needed.",
			},
			"include_all_sub_features": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to include all sub-features of the specified feature.",
			},
			"include_management_tools": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to include management tools for the specified feature.",
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

func resourceWindowsFeatureCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	feature := d.Get("feature").(string)
	restart := d.Get("restart").(bool)
	includeAllSubFeatures := d.Get("include_all_sub_features").(bool)
	includeManagementTools := d.Get("include_management_tools").(bool)
	timeout := d.Get("command_timeout").(int)

	// Vérifier si la fonctionnalité est déjà installée
	checkCommand := "Get-WindowsFeature -Name " + feature + " -ErrorAction Stop | Select-Object -ExpandProperty Installed"
	checkOutput, _, err := sshClient.ExecuteCommand(checkCommand, timeout)
	if err != nil {
		return fmt.Errorf("error checking if feature is installed: %s", err)
	}

	// Si la fonctionnalité est déjà installée, retourner une erreur
	if strings.TrimSpace(checkOutput) == "True" {
		return fmt.Errorf("feature %s is already installed. Please use 'terraform import' to manage this resource", feature)
	}

	command := "Install-WindowsFeature -Name " + feature + " -ErrorAction Stop"
	if restart {
		command += " -Restart"
	}
	if includeAllSubFeatures {
		command += " -IncludeAllSubFeature"
	}
	if includeManagementTools {
		command += " -IncludeManagementTools"
	}

	log.Printf("[DEBUG] Installing Windows feature: %s", feature)
	_, _, err = sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to install Windows feature.")
	}

	d.SetId(feature)
	return resourceWindowsFeatureRead(d, m)
}

func resourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	feature := d.Id()
	if feature == "" {
		feature = d.Get("feature").(string)
	}

	// Récupérer le timeout du schéma si non défini
	timeout, ok := d.GetOk("command_timeout")
	if !ok {
		timeout = 300 // Valeur par défaut définie dans le schéma
	}

	checkCommand := "Get-WindowsFeature -Name " + feature + " -ErrorAction Stop | Select-Object -ExpandProperty Installed"
	checkOutput, _, err := sshClient.ExecuteCommand(checkCommand, timeout.(int))
	if err != nil {
		d.SetId("")
		return fmt.Errorf("failed to check Windows feature status: %s", err)
	}

	if strings.TrimSpace(checkOutput) != "True" {
		// La fonctionnalité n'est pas installée
		d.SetId("")
		return nil
	}

	d.SetId(feature)
	return nil
}

func resourceWindowsFeatureUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	timeout := d.Get("command_timeout").(int)

	if d.HasChange("feature") || d.HasChange("restart") ||
		d.HasChange("include_all_sub_features") || d.HasChange("include_management_tools") {
		oldFeature, newFeature := d.GetChange("feature")

		// Remove old feature
		if oldFeature != "" {
			if err := removeFeature(sshClient, oldFeature.(string), timeout); err != nil {
				return fmt.Errorf("failed to remove Windows feature: %w", err)
			}
		}

		// Add new feature
		d.Set("feature", newFeature)
		return resourceWindowsFeatureCreate(d, m)
	}

	return resourceWindowsFeatureRead(d, m)
}

func removeFeature(sshClient *ssh.Client, featureToRemove string, timeout int) error {
	command := "Remove-WindowsFeature -Name " + featureToRemove + " -ErrorAction Stop"
	log.Printf("[DEBUG] Removing Windows feature: %s", featureToRemove)

	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to remove Windows feature: %w", err)
	}

	return nil
}

func resourceWindowsFeatureDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	feature := d.Get("feature").(string)
	timeout := d.Get("command_timeout").(int)

	command := "Remove-WindowsFeature -Name " + feature + " -ErrorAction Stop"
	log.Printf("[DEBUG] Removing Windows feature: %s", feature)

	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to remove Windows feature: %w", err)
	}

	d.SetId("")
	return nil
}

func resourceWindowsFeatureImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient := m.(*ssh.Client)
	feature := d.Id()

	// Définir le nom de la fonctionnalité
	d.Set("feature", feature)

	// Commande PowerShell pour obtenir les détails de la fonctionnalité
	command := fmt.Sprintf(`
		$feature = Get-WindowsFeature -Name %s
		$hasSubFeatures = $feature.SubFeatures.Count -gt 0
		$subFeaturesInstalled = $false
		if ($hasSubFeatures) {
			$subFeaturesInstalled = $true
			foreach ($subFeature in $feature.SubFeatures) {
				$subFeatureState = Get-WindowsFeature -Name $subFeature
				if (-not $subFeatureState.Installed) {
					$subFeaturesInstalled = $false
					break
				}
			}
		}
		@{
			'Installed' = $feature.Installed
			'InstallState' = $feature.InstallState
			'HasSubFeatures' = $hasSubFeatures
			'SubFeatures' = ($feature.SubFeatures -join ',')
			'AllSubFeaturesInstalled' = $subFeaturesInstalled
			'ManagementTools' = ($feature.InstallState -eq 'Available')
		} | ConvertTo-Json
	`, feature)

	output, _, err := sshClient.ExecuteCommand(command, 300)
	if err != nil {
		return nil, fmt.Errorf("failed to get Windows feature details during import: %s", err)
	}

	// Analyser la sortie JSON
	var featureDetails map[string]interface{}
	if err := json.Unmarshal([]byte(output), &featureDetails); err != nil {
		return nil, fmt.Errorf("failed to parse feature details: %s", err)
	}

	// Définir les valeurs par défaut
	d.Set("restart", false)
	d.Set("command_timeout", 300)

	// Vérifier d'abord si la feature a des sous-fonctionnalités
	hasSubFeatures, ok := featureDetails["HasSubFeatures"].(bool)
	if !ok || !hasSubFeatures {
		d.Set("include_all_sub_features", false)
	} else {
		// Si elle a des sous-fonctionnalités, vérifier si elles sont toutes installées
		if allSubFeaturesInstalled, ok := featureDetails["AllSubFeaturesInstalled"].(bool); ok {
			d.Set("include_all_sub_features", allSubFeaturesInstalled)
		} else {
			d.Set("include_all_sub_features", false)
		}
	}

	if managementTools, ok := featureDetails["ManagementTools"].(bool); ok {
		d.Set("include_management_tools", managementTools)
	} else {
		d.Set("include_management_tools", false)
	}

	return []*schema.ResourceData{d}, nil
}
