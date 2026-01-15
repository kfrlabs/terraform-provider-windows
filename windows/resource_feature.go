package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

// Structure de description détaillée de la feature Windows
type FeatureInfo struct {
	Installed               bool   `json:"Installed"`
	InstallState            string `json:"InstallState"`
	HasSubFeatures          bool   `json:"HasSubFeatures"`
	SubFeatures             string `json:"SubFeatures"`
	AllSubFeaturesInstalled bool   `json:"AllSubFeaturesInstalled"`
	ManagementTools         bool   `json:"ManagementTools"`
}

func ResourceWindowsFeature() *schema.Resource {
	return &schema.Resource{
		Create:   resourceWindowsFeatureCreate,
		Read:     resourceWindowsFeatureRead,
		Update:   resourceWindowsFeatureUpdate,
		Delete:   resourceWindowsFeatureDelete,
		Importer: &schema.ResourceImporter{StateContext: resourceWindowsFeatureImport},

		Schema: map[string]*schema.Schema{
			"feature": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
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
				Computed:    true,
				Default:     false,
				Description: "Whether to include all sub-features of the specified feature.",
			},
			"include_management_tools": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Default:     false,
				Description: "Whether to include management tools for the specified feature.",
			},
			"install_state": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current installation state of the Windows feature.",
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

// --- Fonctions principales ---

func resourceWindowsFeatureCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	feature := d.Get("feature").(string)
	restart := d.Get("restart").(bool)
	includeAllSubFeatures := d.Get("include_all_sub_features").(bool)
	includeManagementTools := d.Get("include_management_tools").(bool)
	timeout := d.Get("command_timeout").(int)

	if err := powershell.ValidatePowerShellArgument(feature); err != nil {
		return fmt.Errorf("invalid feature name: %w", err)
	}

	// Vérifie si la fonctionnalité est déjà installée
	info, err := getFeatureDetails(ctx, sshClient, feature, timeout)
	if err != nil {
		return fmt.Errorf("error checking Windows feature: %w", err)
	}
	if info.Installed {
		d.SetId(feature)
		tflog.Debug(ctx, fmt.Sprintf("Feature %s already installed", feature))
		return resourceWindowsFeatureRead(d, m)
	}

	// Construction sécurisée de la commande PowerShell
	command := fmt.Sprintf("Install-WindowsFeature -Name %s -ErrorAction Stop",
		powershell.QuotePowerShellString(feature))

	if restart {
		command += " -Restart"
	}
	if includeAllSubFeatures {
		command += " -IncludeAllSubFeatures"
	}
	if includeManagementTools {
		command += " -IncludeManagementTools"
	}

	tflog.Info(ctx, fmt.Sprintf("Installing Windows feature: %s", feature))
	_, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to install Windows feature %s: %s (%w)", feature, stderr, err)
	}

	d.SetId(feature)
	return resourceWindowsFeatureRead(d, m)
}

func resourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	feature := d.Id()
	if feature == "" {
		feature = d.Get("feature").(string)
	}
	timeout := d.Get("command_timeout").(int)

	info, err := getFeatureDetails(ctx, sshClient, feature, timeout)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("failed to read feature %s: %w", feature, err)
	}

	if !info.Installed {
		d.SetId("")
		return nil
	}

	// Mise à jour du state Terraform
	_ = d.Set("feature", feature)
	_ = d.Set("install_state", info.InstallState)
	_ = d.Set("include_all_sub_features", info.AllSubFeaturesInstalled)
	_ = d.Set("include_management_tools", info.ManagementTools)

	d.SetId(feature)
	return nil
}

func resourceWindowsFeatureUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)
	timeout := d.Get("command_timeout").(int)

	// Si seule une option non destructive a changé → pas de réinstallation
	if d.HasChange("restart") || d.HasChange("command_timeout") {
		tflog.Debug(ctx, "Non-destructive change detected, skipping reinstall")
		return resourceWindowsFeatureRead(d, m)
	}

	if d.HasChange("feature") || d.HasChange("include_all_sub_features") || d.HasChange("include_management_tools") {
		oldFeature, newFeature := d.GetChange("feature")

		if oldFeature != "" {
			if err := removeFeature(ctx, sshClient, oldFeature.(string), timeout); err != nil {
				return fmt.Errorf("failed to remove feature %s: %w", oldFeature, err)
			}
		}

		d.Set("feature", newFeature)
		return resourceWindowsFeatureCreate(d, m)
	}

	return resourceWindowsFeatureRead(d, m)
}

func resourceWindowsFeatureDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)
	feature := d.Get("feature").(string)
	timeout := d.Get("command_timeout").(int)

	if err := removeFeature(ctx, sshClient, feature, timeout); err != nil {
		return err
	}

	d.SetId("")
	return nil
}

func resourceWindowsFeatureImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient := m.(*ssh.Client)
	feature := d.Id()

	info, err := getFeatureDetails(ctx, sshClient, feature, 300)
	if err != nil {
		return nil, fmt.Errorf("failed to import feature %s: %w", feature, err)
	}

	_ = d.Set("feature", feature)
	_ = d.Set("install_state", info.InstallState)
	_ = d.Set("include_all_sub_features", info.AllSubFeaturesInstalled)
	_ = d.Set("include_management_tools", info.ManagementTools)
	_ = d.Set("restart", false)
	_ = d.Set("command_timeout", 300)

	d.SetId(feature)
	return []*schema.ResourceData{d}, nil
}

// --- Fonctions utilitaires ---

func getFeatureDetails(ctx context.Context, sshClient *ssh.Client, feature string, timeout int) (*FeatureInfo, error) {
	if err := powershell.ValidatePowerShellArgument(feature); err != nil {
		return nil, fmt.Errorf("invalid feature name: %w", err)
	}

	command := fmt.Sprintf(`
$feature = Get-WindowsFeature -Name %s
if (-not $feature) { exit 1 }
$hasSubFeatures = $feature.SubFeatures.Count -gt 0
$subFeaturesInstalled = $true
if ($hasSubFeatures) {
	foreach ($sf in $feature.SubFeatures) {
		if (-not (Get-WindowsFeature -Name $sf).Installed) {
			$subFeaturesInstalled = $false
			break
		}
	}
}
@{
	Installed = $feature.Installed
	InstallState = $feature.InstallState
	HasSubFeatures = $hasSubFeatures
	SubFeatures = ($feature.SubFeatures -join ',')
	AllSubFeaturesInstalled = $subFeaturesInstalled
	ManagementTools = $feature.Installed -and ($feature.InstallState -eq 'Installed')
} | ConvertTo-Json -Compress
`, powershell.QuotePowerShellString(feature))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, fmt.Errorf("PowerShell error: %s (%w)", stderr, err)
	}

	var info FeatureInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse feature details JSON: %w", err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Feature %s state: %+v", feature, info))
	return &info, nil
}

func removeFeature(ctx context.Context, sshClient *ssh.Client, feature string, timeout int) error {
	if err := powershell.ValidatePowerShellArgument(feature); err != nil {
		return fmt.Errorf("invalid feature name: %w", err)
	}

	command := fmt.Sprintf("Remove-WindowsFeature -Name %s -ErrorAction Stop",
		powershell.QuotePowerShellString(feature))
	tflog.Info(ctx, fmt.Sprintf("Removing Windows feature: %s", feature))

	_, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to remove Windows feature %s: %s (%w)", feature, stderr, err)
	}

	return nil
}
