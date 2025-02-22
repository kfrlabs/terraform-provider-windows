package resources

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/k9fr4n/tf-windows/resources/internal/ssh"
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
	features := d.Get("features").([]interface{})
	restart := d.Get("restart").(bool)
	includeAllSubFeatures := d.Get("include_all_sub_features").(bool)
	includeManagementTools := d.Get("include_management_tools").(bool)
	timeout := d.Get("command_timeout").(int)

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}

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
	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to install Windows features: %v", err)
	}

	d.SetId(strings.Join(featuresList, ","))
	return nil
}

func resourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	features := d.Get("features").([]interface{})
	timeout := d.Get("command_timeout").(int)

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}

	command := "Get-WindowsFeature -Name " + strings.Join(featuresList, ",")

	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to read Windows features: %v", err)
	}

	return nil
}

func resourceWindowsFeatureUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	timeout := d.Get("command_timeout").(int)

	if d.HasChange("features") || d.HasChange("restart") ||
		d.HasChange("include_all_sub_features") || d.HasChange("include_management_tools") {

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
			if err := removeFeatures(sshClient, toRemove, timeout); err != nil {
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

func removeFeatures(sshClient *ssh.Client, featuresToRemove []string, timeout int) error {
	for _, feature := range featuresToRemove {
		command := "Remove-WindowsFeature -Name " + feature

		if err := sshClient.ExecuteCommand(command, timeout); err != nil {
			return fmt.Errorf("failed to remove Windows feature %s: %v", feature, err)
		}
	}

	return nil
}

func resourceWindowsFeatureDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	features := d.Get("features").([]interface{})
	timeout := d.Get("command_timeout").(int)

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}

	command := "Remove-WindowsFeature -Name " + strings.Join(featuresList, ",")

	if err := sshClient.ExecuteCommand(command, timeout); err != nil {
		return fmt.Errorf("failed to remove Windows features: %v", err)
	}

	d.SetId("")
	return nil
}
