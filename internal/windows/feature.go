package windows

import (
	"fmt"
	"log"
	"strings"

	"github.com/FranckSallet/tf-windows/internal/powershell"
	"github.com/FranckSallet/tf-windows/internal/ssh"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
			"host": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The hostname or IP address of the Windows server.",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The username for SSH authentication.",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The password for SSH authentication. Required if use_ssh_agent is false.",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					log.Printf("[DEBUG] Validating password for key: %s", key)
					useSSHAgent := val.(bool)
					if !useSSHAgent && val.(string) == "" {
						errs = append(errs, fmt.Errorf("password is required when use_ssh_agent is false"))
					}
					return
				},
			},
			"key_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The path to the private key for SSH authentication.",
			},
			"use_ssh_agent": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to use the SSH agent for authentication.",
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
	features := d.Get("features").([]interface{})
	host := d.Get("host").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	keyPath := d.Get("key_path").(string)
	useSSHAgent := d.Get("use_ssh_agent").(bool)

	log.Printf("[DEBUG] Creating SSH client for host: %s", host)
	sshClient, err := ssh.CreateSSHClient(host, username, password, keyPath, useSSHAgent)
	if err != nil {
		log.Printf("[ERROR] Failed to create SSH client: %v", err)
		return err
	}
	defer sshClient.Close()

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}
	command := "Install-WindowsFeature -Name " + strings.Join(featuresList, ",")

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
	features := d.Get("features").([]interface{})
	host := d.Get("host").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	keyPath := d.Get("key_path").(string)
	useSSHAgent := d.Get("use_ssh_agent").(bool)

	log.Printf("[DEBUG] Creating SSH client for host: %s", host)
	sshClient, err := ssh.CreateSSHClient(host, username, password, keyPath, useSSHAgent)
	if err != nil {
		log.Printf("[ERROR] Failed to create SSH client: %v", err)
		return err
	}
	defer sshClient.Close()

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
	if d.HasChange("features") {
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
			err := removeFeatures(d, toRemove)
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

func removeFeatures(d *schema.ResourceData, featuresToRemove []string) error {
	host := d.Get("host").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	keyPath := d.Get("key_path").(string)
	useSSHAgent := d.Get("use_ssh_agent").(bool)

	log.Printf("[DEBUG] Creating SSH client for host: %s", host)
	sshClient, err := ssh.CreateSSHClient(host, username, password, keyPath, useSSHAgent)
	if err != nil {
		log.Printf("[ERROR] Failed to create SSH client: %v", err)
		return err
	}
	defer sshClient.Close()

	for _, feature := range featuresToRemove {
		command := "Remove-WindowsFeature -Name " + feature
		log.Printf("[DEBUG] Executing PowerShell command: %s", command)
		_, err = powershell.ExecutePowerShellCommand(sshClient, command)
		if err != nil {
			log.Printf("[ERROR] Failed to execute PowerShell command: %v", err)
			return err
		}
	}

	return nil
}

func resourceWindowsFeatureDelete(d *schema.ResourceData, m interface{}) error {
	features := d.Get("features").([]interface{})
	host := d.Get("host").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	keyPath := d.Get("key_path").(string)
	useSSHAgent := d.Get("use_ssh_agent").(bool)

	log.Printf("[DEBUG] Creating SSH client for host: %s", host)
	sshClient, err := ssh.CreateSSHClient(host, username, password, keyPath, useSSHAgent)
	if err != nil {
		log.Printf("[ERROR] Failed to create SSH client: %v", err)
		return err
	}
	defer sshClient.Close()

	featuresList := make([]string, len(features))
	for i, feature := range features {
		featuresList[i] = feature.(string)
	}
	command := "Remove-WindowsFeature -Name " + strings.Join(featuresList, ",")

	log.Printf("[DEBUG] Executing PowerShell command: %s", command)
	_, err = powershell.ExecutePowerShellCommand(sshClient, command)
	if err != nil {
		log.Printf("[ERROR] Failed to execute PowerShell command: %v", err)
		return err
	}

	d.SetId("")
	return nil
}
