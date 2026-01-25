package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// FeatureDataSourceInfo represents information about a Windows feature
type FeatureDataSourceInfo struct {
	Exists                    bool   `json:"Exists"`
	Name                      string `json:"Name"`
	DisplayName               string `json:"DisplayName"`
	Description               string `json:"Description"`
	Installed                 bool   `json:"Installed"`
	InstallState              string `json:"InstallState"`
	FeatureType               string `json:"FeatureType"`
	Path                      string `json:"Path"`
	SubFeatures               string `json:"SubFeatures"`
	ServerComponentDescriptor string `json:"ServerComponentDescriptor"`
}

func DataSourceWindowsFeature() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsFeatureRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the Windows feature to retrieve (e.g., 'Web-Server', 'RSAT-AD-Tools').",
			},
			"display_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The display name of the feature.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A description of the feature.",
			},
			"installed": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the feature is currently installed.",
			},
			"install_state": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The installation state of the feature (Installed, Available, Removed, etc.).",
			},
			"feature_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of feature (Role, Role Service, Feature).",
			},
			"path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The path of the feature in the feature tree.",
			},
			"sub_features": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Comma-separated list of sub-features.",
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

func dataSourceWindowsFeatureRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Reading Windows feature data source",
		map[string]any{"feature_name": name})

	// Validate feature name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return utils.HandleResourceError("validate", name, "name", err)
	}

	// PowerShell command to retrieve feature information
	command := fmt.Sprintf(`
$feature = Get-WindowsFeature -Name %s -ErrorAction SilentlyContinue
if ($feature) {
    @{
        'Exists' = $true
        'Name' = $feature.Name
        'DisplayName' = $feature.DisplayName
        'Description' = $feature.Description
        'Installed' = $feature.Installed
        'InstallState' = $feature.InstallState.ToString()
        'FeatureType' = $feature.FeatureType.ToString()
        'Path' = $feature.Path
        'SubFeatures' = ($feature.SubFeatures -join ',')
        'ServerComponentDescriptor' = $feature.ServerComponentDescriptor
    } | ConvertTo-Json -Compress
} else {
    @{ 'Exists' = $false } | ConvertTo-Json -Compress
}
`,
		powershell.QuotePowerShellString(name),
	)

	tflog.Debug(ctx, "Executing command to retrieve feature information")

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"get_feature",
			name,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	var info FeatureDataSourceInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return utils.HandleResourceError("parse_feature", name, "output",
			fmt.Errorf("failed to parse feature info: %w; output: %s", err, stdout))
	}

	if !info.Exists {
		return utils.HandleResourceError("read", name, "state",
			fmt.Errorf("Windows feature %s does not exist", name))
	}

	// Set all attributes
	d.SetId(name)
	if err := d.Set("name", info.Name); err != nil {
		return utils.HandleResourceError("read", name, "name", err)
	}
	if err := d.Set("display_name", info.DisplayName); err != nil {
		return utils.HandleResourceError("read", name, "display_name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", name, "description", err)
	}
	if err := d.Set("installed", info.Installed); err != nil {
		return utils.HandleResourceError("read", name, "installed", err)
	}
	if err := d.Set("install_state", info.InstallState); err != nil {
		return utils.HandleResourceError("read", name, "install_state", err)
	}
	if err := d.Set("feature_type", info.FeatureType); err != nil {
		return utils.HandleResourceError("read", name, "feature_type", err)
	}
	if err := d.Set("path", info.Path); err != nil {
		return utils.HandleResourceError("read", name, "path", err)
	}
	if err := d.Set("sub_features", info.SubFeatures); err != nil {
		return utils.HandleResourceError("read", name, "sub_features", err)
	}

	tflog.Info(ctx, "Successfully read feature data source",
		map[string]any{
			"feature_name":  name,
			"installed":     info.Installed,
			"install_state": info.InstallState,
		})

	return nil
}
