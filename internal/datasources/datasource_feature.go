package datasources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/common"
	"github.com/kfrlabs/terraform-provider-windows/internal/validators"
	"github.com/kfrlabs/terraform-provider-windows/internal/windows"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &featureDataSource{}
	_ datasource.DataSourceWithConfigure = &featureDataSource{}
)

// NewFeatureDataSource is a helper function to simplify the provider implementation.
func NewFeatureDataSource() datasource.DataSource {
	return &featureDataSource{}
}

// featureDataSource is the data source implementation for reading Windows feature information.
// It provides read-only access to Windows Server feature metadata and installation status.
type featureDataSource struct {
	providerData *common.ProviderData
}

// featureDataSourceModel maps the Terraform data source schema to Go struct.
// It includes the feature name as input and all feature metadata as computed outputs.
type featureDataSourceModel struct {
	// Input
	Name types.String `tfsdk:"name"`

	// Computed outputs
	ID                        types.String `tfsdk:"id"`
	DisplayName               types.String `tfsdk:"display_name"`
	Description               types.String `tfsdk:"description"`
	Installed                 types.Bool   `tfsdk:"installed"`
	InstallState              types.String `tfsdk:"install_state"`
	FeatureType               types.String `tfsdk:"feature_type"`
	Path                      types.String `tfsdk:"path"`
	SubFeatures               types.List   `tfsdk:"sub_features"`
	ServerComponentDescriptor types.String `tfsdk:"server_component_descriptor"`
	Dependencies              types.List   `tfsdk:"dependencies"` // Renamed from depends_on (reserved keyword)
	Parent                    types.String `tfsdk:"parent"`

	// 🆕 New attributes
	Depth                   types.Int64  `tfsdk:"depth"`
	SystemService           types.List   `tfsdk:"system_service"`
	Notification            types.List   `tfsdk:"notification"`
	BestPracticesModelId    types.String `tfsdk:"best_practices_model_id"`
	EventQuery              types.String `tfsdk:"event_query"`
	PostConfigurationNeeded types.Bool   `tfsdk:"post_configuration_needed"`
	AdditionalInfo          types.Map    `tfsdk:"additional_info"`
}

// Metadata returns the data source type name.
func (d *featureDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_feature"
}

// Schema defines the schema for the data source.
func (d *featureDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves information about a Windows Server feature.",
		MarkdownDescription: `Retrieves detailed information about a Windows Server feature using the PowerShell Get-WindowsFeature cmdlet.

This data source provides comprehensive information about Windows features including their installation state, dependencies, and sub-features.

## Example Usage

` + "```terraform" + `
data "windows_feature" "web_server" {
  name = "Web-Server"
}

output "web_server_installed" {
  value = data.windows_feature.web_server.installed
}

output "web_server_subfeatures" {
  value = data.windows_feature.web_server.sub_features
}

output "web_server_dependencies" {
  value = data.windows_feature.web_server.dependencies
}

# Conditional resource creation based on feature state
resource "windows_feature" "web_management" {
  count                    = data.windows_feature.web_server.installed ? 1 : 0
  feature                  = "Web-Mgmt-Console"
  include_management_tools = true
}
` + "```",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "The name of the Windows feature to query (e.g., 'Web-Server', 'RSAT-ADDS').",
				Required:    true,
			},
			"id": schema.StringAttribute{
				Description: "Unique identifier for the data source (same as feature name).",
				Computed:    true,
			},
			"display_name": schema.StringAttribute{
				Description: "The display name of the Windows feature.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the Windows feature.",
				Computed:    true,
			},
			"installed": schema.BoolAttribute{
				Description: "Whether the feature is currently installed.",
				Computed:    true,
			},
			"install_state": schema.StringAttribute{
				Description: "The current installation state of the feature. Possible values: 'Installed', 'Available', 'Removed', 'Unknown'.",
				Computed:    true,
			},
			"feature_type": schema.StringAttribute{
				Description: "The type of the feature (e.g., 'Role', 'Role Service', 'Feature').",
				Computed:    true,
			},
			"path": schema.StringAttribute{
				Description: "The hierarchical path of the feature in the Windows Server feature tree.",
				Computed:    true,
			},
			"sub_features": schema.ListAttribute{
				Description: "List of sub-features that can be installed with this feature.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"server_component_descriptor": schema.StringAttribute{
				Description: "The server component descriptor for the feature (JSON string).",
				Computed:    true,
			},
			"dependencies": schema.ListAttribute{
				Description: "List of features that this feature depends on. These are the prerequisite features required for installation.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"parent": schema.StringAttribute{
				Description: "The parent feature name if this is a sub-feature.",
				Computed:    true,
			},
			// 🆕 New attributes
			"depth": schema.Int64Attribute{
				Description: "The depth level of the feature in the hierarchy tree.",
				Computed:    true,
			},
			"system_service": schema.ListAttribute{
				Description: "List of system services associated with this feature.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"notification": schema.ListAttribute{
				Description: "List of notifications related to the feature.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"best_practices_model_id": schema.StringAttribute{
				Description: "The Best Practices Analyzer model ID for this feature.",
				Computed:    true,
			},
			"event_query": schema.StringAttribute{
				Description: "The event query string associated with the feature.",
				Computed:    true,
			},
			"post_configuration_needed": schema.BoolAttribute{
				Description: "Indicates whether post-installation configuration is required.",
				Computed:    true,
			},
			"additional_info": schema.MapAttribute{
				Description: "Additional metadata about the feature (MajorVersion, MinorVersion, NumericId, InstallName).",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *featureDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*common.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *common.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.providerData = providerData
}

// Read refreshes the Terraform state with the latest data.
func (d *featureDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config featureDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	featureName := config.Name.ValueString()

	// Validate feature name format before making SSH connection
	if err := validators.ValidateFeatureName(featureName); err != nil {
		resp.Diagnostics.AddError(
			"Invalid Feature Name",
			fmt.Sprintf("The feature name '%s' is not valid: %s", featureName, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Reading Windows feature information", map[string]interface{}{
		"feature": featureName,
	})

	// Get SSH client
	client, cleanup, err := d.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Use default timeout of 60 seconds for data source operations (typically faster than resource operations)
	execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Get feature information using shared package function
	featureInfo, err := windows.GetFeatureInfo(execCtx, client, featureName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Read Feature",
			fmt.Sprintf("Failed to read Windows feature '%s': %s\n\nEnsure the feature name is correct and the Windows Server has the Server Manager module available.", featureName, err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Feature information retrieved", map[string]interface{}{
		"feature":       featureName,
		"installed":     featureInfo.Installed,
		"install_state": featureInfo.GetInstallStateString(),
		"feature_type":  featureInfo.FeatureType,
	})

	// Convert sub-features slice to types.List
	subFeaturesList, diags := types.ListValueFrom(ctx, types.StringType, featureInfo.SubFeatures)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert dependencies slice to types.List
	dependenciesList, diags := types.ListValueFrom(ctx, types.StringType, featureInfo.Dependencies)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 🆕 Convert SystemService to types.List
	systemServiceList, diags := types.ListValueFrom(ctx, types.StringType, featureInfo.SystemService)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 🆕 Convert Notification to types.List
	notificationList, diags := types.ListValueFrom(ctx, types.StringType, featureInfo.Notification)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 🆕 Convert AdditionalInfo to types.Map
	additionalInfoMap, diags := types.MapValueFrom(ctx, types.StringType, featureInfo.AdditionalInfo)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert ServerComponentDescriptor to JSON string
	var serverComponentStr string
	if featureInfo.ServerComponentDescriptor != nil {
		if jsonBytes, err := json.Marshal(featureInfo.ServerComponentDescriptor); err == nil {
			serverComponentStr = string(jsonBytes)
		} else {
			serverComponentStr = ""
		}
	} else {
		serverComponentStr = ""
	}

	// Handle Parent pointer
	var parentStr string
	if featureInfo.Parent != nil {
		parentStr = *featureInfo.Parent
	} else {
		parentStr = ""
	}

	// Map feature information to data source model
	state := featureDataSourceModel{
		Name:                      types.StringValue(featureInfo.Name),
		ID:                        types.StringValue(featureInfo.Name),
		DisplayName:               types.StringValue(featureInfo.DisplayName),
		Description:               types.StringValue(featureInfo.Description),
		Installed:                 types.BoolValue(featureInfo.Installed),
		InstallState:              types.StringValue(featureInfo.GetInstallStateString()),
		FeatureType:               types.StringValue(featureInfo.FeatureType),
		Path:                      types.StringValue(featureInfo.Path),
		SubFeatures:               subFeaturesList,
		ServerComponentDescriptor: types.StringValue(serverComponentStr),
		Dependencies:              dependenciesList,
		Parent:                    types.StringValue(parentStr),

		// 🆕 New fields
		Depth:                   types.Int64Value(int64(featureInfo.Depth)),
		SystemService:           systemServiceList,
		Notification:            notificationList,
		BestPracticesModelId:    types.StringValue(featureInfo.BestPracticesModelId),
		EventQuery:              types.StringValue(featureInfo.EventQuery),
		PostConfigurationNeeded: types.BoolValue(featureInfo.PostConfigurationNeeded),
		AdditionalInfo:          additionalInfoMap,
	}

	// Set state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

	tflog.Info(ctx, "Feature information read successfully", map[string]interface{}{
		"feature":                   featureName,
		"installed":                 featureInfo.Installed,
		"install_state":             featureInfo.GetInstallStateString(),
		"sub_features":              len(featureInfo.SubFeatures),
		"dependencies":              len(featureInfo.Dependencies),
		"depth":                     featureInfo.Depth,
		"post_configuration_needed": featureInfo.PostConfigurationNeeded,
	})
}
