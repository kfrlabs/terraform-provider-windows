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

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	feature := d.Get("feature").(string)
	restart := d.Get("restart").(bool)
	includeAllSubFeatures := d.Get("include_all_sub_features").(bool)
	includeManagementTools := d.Get("include_management_tools").(bool)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	// Validate feature name for security
	if err := utils.ValidateField(feature, feature, "feature"); err != nil {
		return err
	}

	tflog.Info(ctx, "Creating Windows feature", map[string]any{
		"feature":                  feature,
		"include_all_sub_features": includeAllSubFeatures,
		"include_management_tools": includeManagementTools,
		"restart":                  restart,
	})

	// Check if feature is already installed
	info, err := getFeatureDetails(ctx, sshClient, feature, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", feature, "state", err)
	}

	if info.Installed {
		if allowExisting {
			tflog.Info(ctx, "Feature already installed, adopting it",
				map[string]any{
					"feature":       feature,
					"install_state": info.InstallState,
				})
			d.SetId(feature)
			return resourceWindowsFeatureRead(d, m)
		}

		return utils.HandleResourceError(
			"create",
			feature,
			"state",
			fmt.Errorf("feature is already installed (InstallState: %s). "+
				"To manage this existing feature, either:\n"+
				"  1. Import it: terraform import windows_feature.example %s\n"+
				"  2. Set allow_existing = true in your configuration",
				info.InstallState, feature),
		)
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

	tflog.Debug(ctx, "Installing Windows feature", map[string]any{"feature": feature})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("install", feature, "state", command, stdout, stderr, err)
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
		tflog.Warn(ctx, "Feature installed but requires restart",
			map[string]any{"feature": feature})
	}

	d.SetId(feature)

	// Log pool statistics if available
	if stats, ok := GetPoolStats(m); ok {
		tflog.Debug(ctx, "Pool statistics after create", map[string]any{"stats": stats.String()})
	}

	return resourceWindowsFeatureRead(d, m)
}

func resourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	feature := d.Id()
	if feature == "" {
		feature = d.Get("feature").(string)
	}

	timeout, ok := d.GetOk("command_timeout")
	if !ok {
		timeout = defaultCommandTimeout
	}

	info, err := getFeatureDetails(ctx, sshClient, feature, timeout.(int))
	if err != nil {
		tflog.Warn(ctx, "Failed to read feature", map[string]any{
			"feature": feature,
			"error":   err.Error(),
		})
		d.SetId("")
		return nil
	}

	if !info.Installed {
		tflog.Debug(ctx, "Feature is not installed, removing from state",
			map[string]any{"feature": feature})
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

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	timeout := d.Get("command_timeout").(int)

	// If only non-destructive options changed, skip reinstall
	if d.HasChange("restart") || d.HasChange("command_timeout") || d.HasChange("allow_existing") {
		tflog.Debug(ctx, "Non-destructive change detected, skipping reinstall")
		return resourceWindowsFeatureRead(d, m)
	}

	if d.HasChange("feature") || d.HasChange("include_all_sub_features") || d.HasChange("include_management_tools") {
		oldFeature, newFeature := d.GetChange("feature")

		if oldFeature != "" && oldFeature.(string) != "" {
			tflog.Info(ctx, "Removing old feature before update",
				map[string]any{"old_feature": oldFeature.(string)})

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

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	feature := d.Get("feature").(string)
	timeout := d.Get("command_timeout").(int)

	if err := removeFeature(ctx, sshClient, feature, timeout); err != nil {
		return err // Already wrapped by removeFeature
	}

	d.SetId("")
	return nil
}

func resourceWindowsFeatureImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	feature := d.Id()

	tflog.Info(ctx, "Importing Windows feature", map[string]any{"feature": feature})

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

	tflog.Info(ctx, "Successfully imported Windows feature",
		map[string]any{
			"feature":       feature,
			"install_state": info.InstallState,
		})

	return []*schema.ResourceData{d}, nil
}

// --- Helper functions ---

func getFeatureDetails(ctx context.Context, sshClient *ssh.Client, feature string, timeout int) (*FeatureInfo, error) {
	// Validate feature name for security
	if err := utils.ValidateField(feature, feature, "feature"); err != nil {
		return nil, err
	}

	command := fmt.Sprintf(`
$feature = Get-WindowsFeature -Name %s -ErrorAction Stop
$info = @{
    Installed = $feature.Installed
    InstallState = $feature.InstallState.ToString()
    HasSubFeatures = ($feature.SubFeatures.Count -gt 0)
    SubFeatures = ($feature.SubFeatures -join ',')
    AllSubFeaturesInstalled = ($feature.SubFeatures.Count -eq 0) -or ($feature.SubFeatures | Where-Object { (Get-WindowsFeature -Name $_).Installed -eq $false } | Measure-Object).Count -eq 0
    ManagementToolsInstalled = $feature.AdditionalInfo.MgmtToolsInstalled
}
$info | ConvertTo-Json -Compress
`, powershell.QuotePowerShellString(feature))

	tflog.Debug(ctx, "Getting feature details", map[string]any{"feature": feature})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, utils.HandleCommandError("get_details", feature, "state", command, stdout, stderr, err)
	}

	var info FeatureInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse feature info: %w; output: %s", err, stdout)
	}

	return &info, nil
}

func removeFeature(ctx context.Context, sshClient *ssh.Client, feature string, timeout int) error {
	// Validate feature name for security
	if err := utils.ValidateField(feature, feature, "feature"); err != nil {
		return err
	}

	command := fmt.Sprintf("Uninstall-WindowsFeature -Name %s -ErrorAction Stop",
		powershell.QuotePowerShellString(feature))

	tflog.Info(ctx, "Removing Windows feature", map[string]any{"feature": feature})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("remove", feature, "state", command, stdout, stderr, err)
	}

	tflog.Info(ctx, "Successfully removed Windows feature", map[string]any{"feature": feature})

	return nil
}

// ============================================================================
// BATCH OPERATIONS FOR MULTIPLE FEATURES
// ============================================================================

// FeatureConfig represents a feature configuration for batch operations
type FeatureConfig struct {
	Name                   string
	IncludeAllSubFeatures  bool
	IncludeManagementTools bool
	Restart                bool
}

// InstallMultipleFeatures installs multiple Windows features in a single batch
// This is useful when setting up a server with many features at once
func InstallMultipleFeatures(
	ctx context.Context,
	sshClient *ssh.Client,
	features []FeatureConfig,
	timeout int,
) ([]InstallResult, error) {
	if len(features) == 0 {
		return nil, nil
	}

	tflog.Info(ctx, "Installing multiple Windows features in batch",
		map[string]any{"count": len(features)})

	// Build batch command for all features
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, f := range features {
		command := fmt.Sprintf("Install-WindowsFeature -Name %s -ErrorAction Stop",
			powershell.QuotePowerShellString(f.Name))

		if f.IncludeAllSubFeatures {
			command += " -IncludeAllSubFeatures"
		}
		if f.IncludeManagementTools {
			command += " -IncludeManagementTools"
		}
		if f.Restart {
			command += " -Restart"
		}

		// Add command that returns JSON result
		fullCommand := fmt.Sprintf(`
$result = %s
@{
    Success = $result.Success
    RestartNeeded = $result.RestartNeeded
    ExitCode = $result.ExitCode.value__
    FeatureResult = $result.FeatureResult
} | ConvertTo-Json -Compress`, command)

		batch.Add(fullCommand)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch feature installation",
		map[string]any{"feature_count": len(features)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, utils.HandleCommandError(
			"batch_install",
			"multiple_features",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse batch results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return nil, fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Parse each feature result
	results := make([]InstallResult, 0, len(features))
	for i := 0; i < len(features); i++ {
		resultStr, err := result.GetStringResult(i)
		if err != nil {
			tflog.Warn(ctx, "Failed to get result for feature",
				map[string]any{
					"feature": features[i].Name,
					"index":   i,
					"error":   err.Error(),
				})
			continue
		}

		var installResult InstallResult
		if err := json.Unmarshal([]byte(resultStr), &installResult); err != nil {
			tflog.Warn(ctx, "Failed to parse result for feature",
				map[string]any{
					"feature": features[i].Name,
					"error":   err.Error(),
				})
			continue
		}

		results = append(results, installResult)
	}

	tflog.Info(ctx, "Successfully installed features in batch",
		map[string]any{
			"requested": len(features),
			"installed": len(results),
		})

	return results, nil
}

// CheckMultipleFeaturesInstalled checks if multiple features are installed
// Returns a map of feature name to installation status
func CheckMultipleFeaturesInstalled(
	ctx context.Context,
	sshClient *ssh.Client,
	features []string,
	timeout int,
) (map[string]bool, error) {
	if len(features) == 0 {
		return make(map[string]bool), nil
	}

	tflog.Debug(ctx, "Checking multiple features installation status",
		map[string]any{"count": len(features)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, feature := range features {
		command := fmt.Sprintf("(Get-WindowsFeature -Name %s -ErrorAction SilentlyContinue).Installed",
			powershell.QuotePowerShellString(feature))
		batch.Add(command)
	}

	command := batch.Build()
	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, utils.HandleCommandError(
			"batch_check",
			"multiple_features",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return nil, fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Build result map
	statusMap := make(map[string]bool)
	for i, feature := range features {
		installed, _ := result.GetStringResult(i)
		statusMap[feature] = (installed == "True")
	}

	tflog.Debug(ctx, "Feature installation status retrieved",
		map[string]any{"count": len(statusMap)})

	return statusMap, nil
}
