package resources

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/k9fr4n/tf-windows/resources/internal/ssh"
)

func ResourceWindowsFeature() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsFeatureCreate,
		Read:   resourceWindowsFeatureRead,
		Update: resourceWindowsFeatureUpdate,
		Delete: resourceWindowsFeatureDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
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

	command := "Install-WindowsFeature -Name " + feature
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
	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to install Windows feature.")
	}

	d.SetId(feature)
	return resourceWindowsFeatureRead(d, m)
}

func resourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	feature := d.Get("feature").(string)
	timeout := d.Get("command_timeout").(int)

	command := "Get-WindowsFeature -Name " + feature
	log.Printf("[DEBUG] Checking Windows feature status: %s", feature)

	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		fmt.Errorf("failed to remove Windows feature: %w", err)
		d.SetId("")
		return nil
	}

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
	command := "Remove-WindowsFeature -Name " + featureToRemove
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

	command := "Remove-WindowsFeature -Name " + feature
	log.Printf("[DEBUG] Removing Windows feature: %s", feature)

	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to remove Windows feature: %w", err)
	}

	d.SetId("")
	return nil
}
