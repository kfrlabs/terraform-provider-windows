package windows

import (
	"log"
	"strings"

	"github.com/FranckSallet/tf-windows/tf-windows/internal/powershell"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func ResourceWindowsFeature() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsFeatureCreate,
		Read:   resourceWindowsFeatureRead,
		Update: resourceWindowsFeatureUpdate,
		Delete: resourceWindowsFeatureDelete,

		Schema: map[string]*schema.Schema{
			"features": {
				Type:        schema.TypeList,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "A list of Windows features to install or remove.",
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
				Description: "Whether to include all sub-features of the specified features.",
			},
			"include_management_tools": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to include management tools for the specified features.",
			},
			"output": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The output of the PowerShell command.",
			},
		},
	}
}

func resourceWindowsFeatureCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	features := d.Get("features").([]interface{})
	restart := d.Get("restart").(bool)
	includeAllSubFeatures := d.Get("include_all_sub_features").(bool)
	includeManagementTools := d.Get("include_management_tools").(bool)

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}

	// Construire la commande PowerShell avec les paramètres optionnels
	command := "Install-WindowsFeature -Name " + strings.Join(featuresList, ",")
	if restart {
		command += " -Restart"
	}
	if includeAllSubFeatures {
		command += " -IncludeAllSubFeature"
	}
	if includeManagementTools {
		command += " -IncludeManagementTools"
	}

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	output, err := powershell.ExecutePowerShellCommand(sshClient, command)
	if err != nil {
		log.Printf("[ERROR] Failed to execute PowerShell command: %v", err)
		return err
	}

	log.Printf("[DEBUG] Command output: %s", output)
	d.SetId(strings.Join(featuresList, ","))
	d.Set("output", output)
	return nil
}

func resourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	features := d.Get("features").([]interface{})

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}
	command := "Get-WindowsFeature -Name " + strings.Join(featuresList, ",")

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	output, err := powershell.ExecutePowerShellCommand(sshClient, command)
	if err != nil {
		log.Printf("[ERROR] Failed to execute PowerShell command: %v", err)
		return err
	}

	log.Printf("[DEBUG] Command output: %s", output)
	d.Set("output", output)
	return nil
}

func resourceWindowsFeatureUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	if d.HasChange("features") || d.HasChange("restart") || d.HasChange("include_all_sub_features") || d.HasChange("include_management_tools") {
		oldFeatures, newFeatures := d.GetChange("features")
		oldFeaturesSet := make(map[string]struct{})
		newFeaturesSet := make(map[string]struct{})

		for _, feature := range oldFeatures.([]interface{}) {
			oldFeaturesSet[feature.(string)] = struct{}{}
		}

		for _, feature := range newFeatures.([]interface{}) {
			newFeaturesSet[feature.(string)] = struct{}{}
		}

		// Determine features to remove
		toRemove := []string{}
		for feature := range oldFeaturesSet {
			if _, found := newFeaturesSet[feature]; !found {
				toRemove = append(toRemove, feature)
			}
		}

		// Determine features to add
		toAdd := []string{}
		for feature := range newFeaturesSet {
			if _, found := oldFeaturesSet[feature]; !found {
				toAdd = append(toAdd, feature)
			}
		}

		if len(toRemove) > 0 {
			err := removeFeatures(sshClient, toRemove)
			if err != nil {
				return err
			}
		}

		if len(toAdd) > 0 {
			d.Set("features", newFeatures)
			return resourceWindowsFeatureCreate(d, m)
		}
	}

	return nil
}

func removeFeatures(sshClient *ssh.Client, featuresToRemove []string) error {
	for _, feature := range featuresToRemove {
		command := "Remove-WindowsFeature -Name " + feature
		log.Printf("[DEBUG] Executing PowerShell command: %s", command)
		_, err := powershell.ExecutePowerShellCommand(sshClient, command)
		if err != nil {
			log.Printf("[ERROR] Failed to execute PowerShell command: %v", err)
			return err
		}
	}

	return nil
}

func resourceWindowsFeatureDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	features := d.Get("features").([]interface{})

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}
	command := "Remove-WindowsFeature -Name " + strings.Join(featuresList, ",")

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	_, err := powershell.ExecutePowerShellCommand(sshClient, command)
	if err != nil {
		log.Printf("[ERROR] Failed to execute PowerShell command: %v", err)
		return err
	}

	d.SetId("")
	return nil
}
