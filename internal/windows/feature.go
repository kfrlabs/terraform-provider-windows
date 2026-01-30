package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/kfrlabs/terraform-provider-windows/internal/validators"
)

// SSHExecutor defines the interface for executing commands via SSH.
// This interface allows for easy mocking in unit tests.
type SSHExecutor interface {
	ExecuteCommand(context.Context, string) (string, string, error)
}

// FeatureInfo represents detailed information about a Windows feature.
// This structure maps directly to the output of Get-WindowsFeature PowerShell cmdlet.
//
// Note on field types:
//   - InstallState is an integer enum in PowerShell:
//     0 = Unknown, 1 = Installed, 2 = Available, 3 = Removed
type FeatureInfo struct {
	Name                      string            `json:"Name"`
	DisplayName               string            `json:"DisplayName"`
	Description               string            `json:"Description"`
	Installed                 bool              `json:"Installed"`
	InstallState              int               `json:"InstallState"` // Changed from string to int
	FeatureType               string            `json:"FeatureType"`
	Path                      string            `json:"Path"`
	SubFeatures               []string          `json:"SubFeatures"`
	ServerComponentDescriptor any               `json:"ServerComponentDescriptor"` // Complex object, use any
	Dependencies              []string          `json:"DependsOn"`                 // Note: JSON field is still "DependsOn" from PowerShell
	Parent                    *string           `json:"Parent"`                    // Changed to pointer to handle null values
	Depth                     int               `json:"Depth"`
	SystemService             []string          `json:"SystemService"`
	Notification              []string          `json:"Notification"`
	BestPracticesModelId      string            `json:"BestPracticesModelId"`
	EventQuery                string            `json:"EventQuery"`
	PostConfigurationNeeded   bool              `json:"PostConfigurationNeeded"`
	AdditionalInfo            map[string]string `json:"AdditionalInfo"` // MajorVersion, MinorVersion, NumericId, InstallName
}

// GetInstallStateString returns a human-readable string representation of the install state.
// This helps with logging and debugging.
func (f *FeatureInfo) GetInstallStateString() string {
	switch f.InstallState {
	case 0:
		return "Unknown"
	case 1:
		return "Installed"
	case 2:
		return "Available"
	case 3:
		return "Removed"
	default:
		return fmt.Sprintf("Unknown(%d)", f.InstallState)
	}
}

// InstallResult represents the result of a Windows feature installation operation.
// This structure maps to the output of Install-WindowsFeature PowerShell cmdlet.
//
// Note on field types:
//   - RestartNeeded is an integer enum in PowerShell:
//     0 = No restart needed
//     1 = Restart needed
//     2 = Restart is automatic (when -Restart flag is used)
type InstallResult struct {
	Success       bool  `json:"Success"`
	RestartNeeded int   `json:"RestartNeeded"` // Changed from string to int
	ExitCode      int   `json:"ExitCode"`
	FeatureResult []any `json:"FeatureResult"` // Changed from string to array
}

// IsRestartNeeded returns whether a restart is required after installation.
// This is a convenience method for cleaner code.
func (r *InstallResult) IsRestartNeeded() bool {
	return r.RestartNeeded == 1 || r.RestartNeeded == 2
}

// GetRestartNeededString returns a human-readable string representation of the restart status.
func (r *InstallResult) GetRestartNeededString() string {
	switch r.RestartNeeded {
	case 0:
		return "No"
	case 1:
		return "Yes"
	case 2:
		return "Automatic"
	default:
		return fmt.Sprintf("Unknown(%d)", r.RestartNeeded)
	}
}

// GetFeatureInfo retrieves detailed information about a Windows feature using PowerShell.
// It executes the Get-WindowsFeature cmdlet and returns structured feature information.
//
// The function will return an error if:
// - The SSH command execution fails
// - The PowerShell command returns an error
// - The JSON parsing fails
// - The feature name is invalid
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - client: SSH client implementing the SSHExecutor interface
//   - featureName: The name of the Windows feature to query
//
// Returns:
//   - *FeatureInfo: Detailed information about the feature
//   - error: Any error that occurred during the operation
func GetFeatureInfo(ctx context.Context, client SSHExecutor, featureName string) (*FeatureInfo, error) {
	quotedName := validators.QuotePowerShellString(featureName)

	// Build PowerShell command to retrieve ALL feature information
	// 🆕 Updated to include new fields
	command := fmt.Sprintf(`
$feature = Get-WindowsFeature -Name %s -ErrorAction Stop
if ($null -eq $feature) {
	Write-Error "Feature not found: %s"
	exit 1
}

# Extract AdditionalInfo as string key-value pairs
$additionalInfoMap = @{}
if ($feature.AdditionalInfo) {
	foreach ($key in $feature.AdditionalInfo.Keys) {
		$additionalInfoMap[$key] = $feature.AdditionalInfo[$key].ToString()
	}
}

# Build output object with ALL properties
$output = @{
	Name                      = $feature.Name
	DisplayName               = $feature.DisplayName
	Description               = $feature.Description
	Installed                 = $feature.Installed
	InstallState              = $feature.InstallState.value__
	FeatureType               = $feature.FeatureType
	Path                      = $feature.Path
	SubFeatures               = @($feature.SubFeatures)
	ServerComponentDescriptor = if ($feature.ServerComponentDescriptor) { $feature.ServerComponentDescriptor.ToString() } else { $null }
	DependsOn                 = @($feature.DependsOn)
	Parent                    = $feature.Parent
	Depth                     = $feature.Depth
	SystemService             = @($feature.SystemService)
	Notification              = @($feature.Notification)
	BestPracticesModelId      = if ($feature.BestPracticesModelId) { $feature.BestPracticesModelId } else { "" }
	EventQuery                = if ($feature.EventQuery) { $feature.EventQuery } else { "" }
	PostConfigurationNeeded   = $feature.PostConfigurationNeeded
	AdditionalInfo            = $additionalInfoMap
}

$output | ConvertTo-Json -Depth 3 -Compress
`, quotedName, quotedName)

	tflog.Trace(ctx, "Getting feature information", map[string]interface{}{
		"feature": featureName,
		"command": command,
	})

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		tflog.Error(ctx, "Get-WindowsFeature command failed", map[string]interface{}{
			"error":   err.Error(),
			"stderr":  stderr,
			"stdout":  stdout,
			"feature": featureName,
		})
		return nil, fmt.Errorf("command execution failed: %w\nStderr: %s", err, stderr)
	}

	// Check for feature not found errors in stderr or stdout
	if strings.Contains(stderr, "Feature not found") ||
		strings.Contains(stdout, "Feature not found") ||
		strings.Contains(stderr, "does not exist") {
		return nil, fmt.Errorf("feature '%s' not found on the system", featureName)
	}

	// Parse JSON output
	var info FeatureInfo
	stdout = strings.TrimSpace(stdout)

	if stdout == "" {
		return nil, fmt.Errorf("empty response from Get-WindowsFeature command")
	}

	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		tflog.Error(ctx, "Failed to parse feature information", map[string]interface{}{
			"error":   err.Error(),
			"stdout":  stdout,
			"feature": featureName,
		})
		return nil, fmt.Errorf("failed to parse feature info: %w\nOutput: %s", err, stdout)
	}

	tflog.Debug(ctx, "Feature information retrieved successfully", map[string]interface{}{
		"feature":                   featureName,
		"installed":                 info.Installed,
		"install_state":             info.GetInstallStateString(),
		"feature_type":              info.FeatureType,
		"depth":                     info.Depth,
		"post_configuration_needed": info.PostConfigurationNeeded,
	})

	return &info, nil
}

// InstallFeature installs a Windows feature with the specified configuration.
// It executes the Install-WindowsFeature PowerShell cmdlet with appropriate parameters.
//
// The function supports:
// - Installing all sub-features
// - Installing management tools (RSAT)
// - Automatic server restart if required
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - client: SSH client implementing the SSHExecutor interface
//   - featureName: The name of the Windows feature to install
//   - includeAllSubFeatures: Whether to install all sub-features
//   - includeManagementTools: Whether to install management tools
//   - restart: Whether to automatically restart if needed
//
// Returns:
//   - *InstallResult: The result of the installation operation
//   - error: Any error that occurred during the operation
func InstallFeature(ctx context.Context, client SSHExecutor, featureName string,
	includeAllSubFeatures, includeManagementTools, restart bool) (*InstallResult, error) {

	quotedName := validators.QuotePowerShellString(featureName)

	// Build Install-WindowsFeature command with appropriate parameters
	cmdParts := []string{"Install-WindowsFeature", "-Name", quotedName}

	if includeAllSubFeatures {
		cmdParts = append(cmdParts, "-IncludeAllSubFeature")
	}

	if includeManagementTools {
		cmdParts = append(cmdParts, "-IncludeManagementTools")
	}

	if restart {
		cmdParts = append(cmdParts, "-Restart")
	}

	// Add JSON output for structured parsing
	cmdParts = append(cmdParts, "| ConvertTo-Json -Compress")

	command := strings.Join(cmdParts, " ")

	tflog.Info(ctx, "Installing Windows feature", map[string]interface{}{
		"feature":                  featureName,
		"include_all_sub_features": includeAllSubFeatures,
		"include_management_tools": includeManagementTools,
		"restart":                  restart,
	})

	tflog.Debug(ctx, "Executing Install-WindowsFeature command", map[string]interface{}{
		"command": command,
	})

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		tflog.Error(ctx, "Install-WindowsFeature command failed", map[string]interface{}{
			"error":   err.Error(),
			"stderr":  stderr,
			"stdout":  stdout,
			"feature": featureName,
		})
		return nil, fmt.Errorf("command execution failed: %w\nStderr: %s", err, stderr)
	}

	// Parse JSON result
	var result InstallResult
	stdout = strings.TrimSpace(stdout)

	if stdout == "" {
		return nil, fmt.Errorf("empty response from Install-WindowsFeature command")
	}

	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		tflog.Error(ctx, "Failed to parse installation result", map[string]interface{}{
			"error":   err.Error(),
			"stdout":  stdout,
			"feature": featureName,
		})
		return nil, fmt.Errorf("failed to parse installation result: %w\nOutput: %s", err, stdout)
	}

	tflog.Info(ctx, "Feature installation completed", map[string]interface{}{
		"feature":        featureName,
		"success":        result.Success,
		"restart_needed": result.GetRestartNeededString(),
		"exit_code":      result.ExitCode,
	})

	return &result, nil
}

// UninstallFeature uninstalls a Windows feature.
// It executes the Uninstall-WindowsFeature PowerShell cmdlet with the -Remove flag
// to completely remove the feature binaries from the system.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - client: SSH client implementing the SSHExecutor interface
//   - featureName: The name of the Windows feature to uninstall
//   - restart: Whether to automatically restart if needed
//
// Returns:
//   - error: Any error that occurred during the operation
func UninstallFeature(ctx context.Context, client SSHExecutor, featureName string, restart bool) error {
	quotedName := validators.QuotePowerShellString(featureName)

	// Build Uninstall-WindowsFeature command
	// The -Remove flag ensures feature binaries are removed from disk
	cmdParts := []string{"Uninstall-WindowsFeature", "-Name", quotedName, "-Remove"}

	if restart {
		cmdParts = append(cmdParts, "-Restart")
	}

	command := strings.Join(cmdParts, " ")

	tflog.Info(ctx, "Uninstalling Windows feature", map[string]interface{}{
		"feature": featureName,
		"restart": restart,
	})

	tflog.Debug(ctx, "Executing Uninstall-WindowsFeature command", map[string]interface{}{
		"command": command,
	})

	stdout, stderr, err := client.ExecuteCommand(ctx, command)
	if err != nil {
		tflog.Error(ctx, "Uninstall-WindowsFeature command failed", map[string]interface{}{
			"error":   err.Error(),
			"stderr":  stderr,
			"stdout":  stdout,
			"feature": featureName,
		})
		return fmt.Errorf("command execution failed: %w\nStderr: %s", err, stderr)
	}

	tflog.Info(ctx, "Feature uninstalled successfully", map[string]interface{}{
		"feature": featureName,
	})

	return nil
}
