package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

const (
	defaultCommandTimeout = 300
)

// Detailed description structure of Windows feature
type FeatureInfo struct {
	Installed                bool   `json:"Installed"`
	InstallState             string `json:"InstallState"`
	HasSubFeatures           bool   `json:"HasSubFeatures"`
	SubFeatures              string `json:"SubFeatures"`
	AllSubFeaturesInstalled  bool   `json:"AllSubFeaturesInstalled"`
	ManagementToolsInstalled bool   `json:"ManagementToolsInstalled"`
}

// Installation result structure
type InstallResult struct {
	Success       bool   `json:"Success"`
	RestartNeeded string `json:"RestartNeeded"`
	ExitCode      int    `json:"ExitCode"`
	FeatureResult string `json:"FeatureResult"`
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
				Description: "Whether to include all sub-features of the specified feature.",
			},
			"include_management_tools": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
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
				Default:     defaultCommandTimeout,
				Description: "Timeout in seconds for PowerShell commands.",
			},
			"allow_existing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, adopt existing feature instead of failing. If false, fail if feature already installed.",
			},
		},
	}
}

// --- Main functions ---

func resourceWindowsFeatureCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	feature := d.Get("feature").(string)
	restart := d.Get("restart").(bool)
	includeAllSubFeatures := d.Get("include_all_sub_features").(bool)
	includeManagementTools := d.Get("include_management_tools").(bool)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	// Validate feature name for security
	if err := powershell.ValidatePowerShellArgument(feature); err != nil {
		return utils.HandleResourceError("validate", feature, "name", err)
	}

	// Check if feature is already installed
	info, err := getFeatureDetails(ctx, sshClient, feature, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", feature, "state", err)
	}

	if info.Installed {
		if allowExisting {
			// Adopt the existing feature
			tflog.Info(ctx, fmt.Sprintf("Feature %s already installed, adopting it (allow_existing=true)", feature))
			d.SetId(feature)
			return resourceWindowsFeatureRead(d, m)
		} else {
			// Fail with clear error
			return utils.HandleResourceError(
				"create",
				feature,
				"state",
				fmt.Errorf("feature is already installed (InstallState: %s). "+
					"To manage this existing feature, either:\n"+
					"  1. Import it: terraform import windows_feature.%s %s\n"+
					"  2. Set allow_existing = true in your configuration\n"+
					"  3. Remove it first: Remove-WindowsFeature -Name '%s'",
					info.InstallState, feature, feature, feature),
			)
		}
	}

	// Build secure PowerShell command with result capture
	command := fmt.Sprintf(`
$result = Install-WindowsFeature -Name %s -ErrorAction Stop`,
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

	command += `
@{
	Success = $result.Success
	RestartNeeded = $result.RestartNeeded
	ExitCode = $result.ExitCode.value__
	FeatureResult = $result.FeatureResult
} | ConvertTo-Json -Compress`

	tflog.Info(ctx, fmt.Sprintf("Installing Windows feature: %s", feature))
	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"install",
			feature,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse installation result
	var installResult InstallResult
	if err := json.Unmarshal([]byte(stdout), &installResult); err != nil {
		return utils.HandleCommandError(
			"parse_result",
			feature,
			"installation_output",
			command,
			stdout,
			stderr,
			fmt.Errorf("failed to parse JSON output: %w", err),
		)
	}

	if !installResult.Success {
		return utils.HandleCommandError(
			"install",
			feature,
			"state",
			command,
			stdout,
			stderr,
			fmt.Errorf("installation failed with exit code %d", installResult.ExitCode),
		)
	}

	if installResult.RestartNeeded == "Yes" && !restart {
		tflog.Warn(ctx, fmt.Sprintf("Feature %s installed but requires restart", feature))
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
		tflog.Warn(ctx, fmt.Sprintf("Failed to read feature %s: %v", feature, err))
		d.SetId("")
		return nil
	}

	if !info.Installed {
		tflog.Debug(ctx, fmt.Sprintf("Feature %s is not installed, removing from state", feature))
		d.SetId("")
		return nil
	}

	// Update Terraform state
	if err := d.Set("feature", feature); err != nil {
		return utils.HandleResourceError("read", feature, "feature", err)
	}
	if err := d.Set("install_state", info.InstallState); err != nil {
		return utils.HandleResourceError("read", feature, "install_state", err)
	}
	if err := d.Set("include_all_sub_features", info.AllSubFeaturesInstalled); err != nil {
		return utils.HandleResourceError("read", feature, "include_all_sub_features", err)
	}
	if err := d.Set("include_management_tools", info.ManagementToolsInstalled); err != nil {
		return utils.HandleResourceError("read", feature, "include_management_tools", err)
	}

	d.SetId(feature)
	return nil
}

func resourceWindowsFeatureUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)
	timeout := d.Get("command_timeout").(int)

	// If only non-destructive options changed, skip reinstall
	if d.HasChange("restart") || d.HasChange("command_timeout") || d.HasChange("allow_existing") {
		tflog.Debug(ctx, "Non-destructive change detected, skipping reinstall")
		return resourceWindowsFeatureRead(d, m)
	}

	if d.HasChange("feature") || d.HasChange("include_all_sub_features") || d.HasChange("include_management_tools") {
		oldFeature, newFeature := d.GetChange("feature")

		if oldFeature != "" && oldFeature.(string) != "" {
			if err := removeFeature(ctx, sshClient, oldFeature.(string), timeout); err != nil {
				return utils.HandleResourceError("update_remove_old", oldFeature.(string), "state", err)
			}
		}

		if err := d.Set("feature", newFeature); err != nil {
			return utils.HandleResourceError("update", newFeature.(string), "feature", err)
		}
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
		return err // Already wrapped by removeFeature
	}

	d.SetId("")
	return nil
}

func resourceWindowsFeatureImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient := m.(*ssh.Client)
	feature := d.Id()

	info, err := getFeatureDetails(ctx, sshClient, feature, defaultCommandTimeout)
	if err != nil {
		return nil, utils.HandleResourceError("import", feature, "state", err)
	}

	if !info.Installed {
		return nil, utils.HandleResourceError(
			"import",
			feature,
			"state",
			fmt.Errorf("feature is not installed, cannot import"),
		)
	}

	// Set all attributes
	attrs := map[string]interface{}{
		"feature":                  feature,
		"install_state":            info.InstallState,
		"include_all_sub_features": info.AllSubFeaturesInstalled,
		"include_management_tools": info.ManagementToolsInstalled,
		"restart":                  false,
		"command_timeout":          defaultCommandTimeout,
		"allow_existing":           false,
	}

	for key, value := range attrs {
		if err := d.Set(key, value); err != nil {
			return nil, utils.HandleResourceError("import", feature, key, err)
		}
	}

	d.SetId(feature)
	return []*schema.ResourceData{d}, nil
}

// --- Utility functions ---

func getFeatureDetails(ctx context.Context, sshClient *ssh.Client, feature string, timeout int) (*FeatureInfo, error) {
	if err := powershell.ValidatePowerShellArgument(feature); err != nil {
		return nil, utils.HandleResourceError("validate", feature, "name", err)
	}

	command := fmt.Sprintf(`
$feature = Get-WindowsFeature -Name %s
if (-not $feature) { 
	Write-Error "Feature not found"
	exit 1 
}

$hasSubFeatures = $feature.SubFeatures.Count -gt 0
$subFeaturesInstalled = $true

if ($hasSubFeatures) {
	foreach ($sf in $feature.SubFeatures) {
		$subFeature = Get-WindowsFeature -Name $sf
		if (-not $subFeature.Installed) {
			$subFeaturesInstalled = $false
			break
		}
	}
}

# Check if management tools are installed by looking for related features
$mgmtToolsInstalled = $false
if ($feature.Installed) {
	$mgmtFeatureName = "$($feature.Name)-MGMT"
	$mgmtFeature = Get-WindowsFeature -Name $mgmtFeatureName -ErrorAction SilentlyContinue
	if ($mgmtFeature) {
		$mgmtToolsInstalled = $mgmtFeature.Installed
	} else {
		# If no specific management feature exists, consider it as installed with the main feature
		$mgmtToolsInstalled = $true
	}
}

@{
	Installed = $feature.Installed
	InstallState = $feature.InstallState.ToString()
	HasSubFeatures = $hasSubFeatures
	SubFeatures = ($feature.SubFeatures -join ',')
	AllSubFeaturesInstalled = $subFeaturesInstalled
	ManagementToolsInstalled = $mgmtToolsInstalled
} | ConvertTo-Json -Compress
`, powershell.QuotePowerShellString(feature))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, utils.HandleCommandError(
			"get_details",
			feature,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	var info FeatureInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, utils.HandleCommandError(
			"parse_details",
			feature,
			"json_output",
			command,
			stdout,
			stderr,
			fmt.Errorf("failed to parse JSON: %w", err),
		)
	}

	tflog.Debug(ctx, fmt.Sprintf("Feature %s state: %+v", feature, info))
	return &info, nil
}

func removeFeature(ctx context.Context, sshClient *ssh.Client, feature string, timeout int) error {
	if err := powershell.ValidatePowerShellArgument(feature); err != nil {
		return utils.HandleResourceError("validate", feature, "name", err)
	}

	command := fmt.Sprintf(`
$result = Remove-WindowsFeature -Name %s -ErrorAction Stop
@{
	Success = $result.Success
	ExitCode = $result.ExitCode.value__
} | ConvertTo-Json -Compress
`, powershell.QuotePowerShellString(feature))

	tflog.Info(ctx, fmt.Sprintf("Removing Windows feature: %s", feature))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"remove",
			feature,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	var result InstallResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		// If parsing fails, log but don't fail the operation
		tflog.Warn(ctx, fmt.Sprintf("Could not parse removal result: %v", err))
		return nil
	}

	if !result.Success {
		return utils.HandleCommandError(
			"remove",
			feature,
			"state",
			command,
			stdout,
			stderr,
			fmt.Errorf("removal failed with exit code %d", result.ExitCode),
		)
	}

	return nil
}
