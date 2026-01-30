package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/common"
	"github.com/kfrlabs/terraform-provider-windows/internal/validators"
	"github.com/kfrlabs/terraform-provider-windows/internal/windows"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &featureResource{}
	_ resource.ResourceWithConfigure   = &featureResource{}
	_ resource.ResourceWithImportState = &featureResource{}
)

// NewFeatureResource is a helper function to simplify the provider implementation.
func NewFeatureResource() resource.Resource {
	return &featureResource{}
}

// featureResource is the resource implementation for managing Windows features.
// It provides full lifecycle management (CRUD) for Windows Server features and roles
// using PowerShell cmdlets executed over SSH.
type featureResource struct {
	providerData *common.ProviderData
}

// featureResourceModel maps the Terraform schema to Go struct for state management.
// It includes both user-configurable attributes and computed values retrieved from Windows.
type featureResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	Feature                types.String `tfsdk:"feature"`
	IncludeAllSubFeatures  types.Bool   `tfsdk:"include_all_sub_features"`
	IncludeManagementTools types.Bool   `tfsdk:"include_management_tools"`
	Restart                types.Bool   `tfsdk:"restart"`
	AllowExisting          types.Bool   `tfsdk:"allow_existing"`
	CommandTimeout         types.Int64  `tfsdk:"command_timeout"`
	InstallState           types.String `tfsdk:"install_state"`
	DisplayName            types.String `tfsdk:"display_name"`
	Description            types.String `tfsdk:"description"`
	RestartNeeded          types.Bool   `tfsdk:"restart_needed"`

	// 🆕 New computed attributes
	Depth                   types.Int64 `tfsdk:"depth"`
	PostConfigurationNeeded types.Bool  `tfsdk:"post_configuration_needed"`
	AdditionalInfo          types.Map   `tfsdk:"additional_info"`
}

// Metadata returns the resource type name.
func (r *featureResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_feature"
}

// Schema defines the schema for the resource.
func (r *featureResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Windows Server feature installation.",
		MarkdownDescription: `Manages a Windows Server feature using the PowerShell Install-WindowsFeature cmdlet.

This resource allows you to install, configure, and remove Windows Server features and roles.

## Example Usage

` + "```terraform" + `
resource "windows_feature" "web_server" {
  feature                    = "Web-Server"
  include_all_sub_features   = true
  include_management_tools   = true
  restart                    = false
}

resource "windows_feature" "ad_domain_services" {
  feature                    = "AD-Domain-Services"
  include_management_tools   = true
  allow_existing             = true
}
` + "```",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the resource (same as feature name).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"feature": schema.StringAttribute{
				Description: "The name of the Windows feature to install. Must be a valid Windows feature name (e.g., 'Web-Server', 'RSAT-ADDS').",
				Required:    true,
				Validators: []validator.String{
					validators.WindowsFeatureName(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"include_all_sub_features": schema.BoolAttribute{
				Description: "If true, installs all sub-features of the specified feature.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"include_management_tools": schema.BoolAttribute{
				Description: "If true, installs the management tools for the feature (RSAT tools).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"restart": schema.BoolAttribute{
				Description: "If true, restarts the server after installation if required. Use with caution.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"allow_existing": schema.BoolAttribute{
				Description: "If true, allows adopting an already installed feature. If false, fails if the feature is already installed.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"command_timeout": schema.Int64Attribute{
				Description: "Timeout in seconds for PowerShell commands. Default is 300 seconds (5 minutes).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(300),
			},
			"install_state": schema.StringAttribute{
				Description: "The current installation state of the feature (e.g., 'Installed', 'Available', 'Removed').",
				Computed:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("Installed", "Available", "Removed", "Unknown"),
				},
			},
			"display_name": schema.StringAttribute{
				Description: "The display name of the Windows feature.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the Windows feature.",
				Computed:    true,
			},
			"restart_needed": schema.BoolAttribute{
				Description: "Indicates whether a restart is needed after the operation.",
				Computed:    true,
			},
			// 🆕 New computed attributes
			"depth": schema.Int64Attribute{
				Description: "The depth level of the feature in the hierarchy tree.",
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

// Configure adds the provider configured client to the resource.
func (r *featureResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*common.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *common.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.providerData = providerData
}

// Create creates the resource and sets the initial Terraform state.
func (r *featureResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan featureResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	featureName := plan.Feature.ValueString()

	tflog.Info(ctx, "Creating Windows feature", map[string]interface{}{
		"feature":                  featureName,
		"include_all_sub_features": plan.IncludeAllSubFeatures.ValueBool(),
		"include_management_tools": plan.IncludeManagementTools.ValueBool(),
		"restart":                  plan.Restart.ValueBool(),
		"allow_existing":           plan.AllowExisting.ValueBool(),
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context for all operations
	timeout := time.Duration(plan.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Check if feature already exists when allow_existing is enabled
	if plan.AllowExisting.ValueBool() {
		tflog.Debug(ctx, "Checking if feature already exists", map[string]interface{}{
			"feature": featureName,
		})

		featureInfo, err := windows.GetFeatureInfo(execCtx, client, featureName)
		if err == nil && featureInfo.Installed {
			tflog.Info(ctx, "Feature already installed, adopting existing installation", map[string]interface{}{
				"feature":       featureName,
				"install_state": featureInfo.GetInstallStateString(),
			})

			// 🆕 Convert AdditionalInfo to types.Map
			additionalInfoMap, diags := types.MapValueFrom(ctx, types.StringType, featureInfo.AdditionalInfo)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			// Populate state from existing feature
			plan.ID = types.StringValue(featureName)
			plan.InstallState = types.StringValue(featureInfo.GetInstallStateString())
			plan.DisplayName = types.StringValue(featureInfo.DisplayName)
			plan.Description = types.StringValue(featureInfo.Description)
			plan.RestartNeeded = types.BoolValue(false)

			// 🆕 Populate new fields
			plan.Depth = types.Int64Value(int64(featureInfo.Depth))
			plan.PostConfigurationNeeded = types.BoolValue(featureInfo.PostConfigurationNeeded)
			plan.AdditionalInfo = additionalInfoMap

			resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
			return
		}
	}

	// Install the feature using the shared package function
	installResult, err := windows.InstallFeature(
		execCtx,
		client,
		featureName,
		plan.IncludeAllSubFeatures.ValueBool(),
		plan.IncludeManagementTools.ValueBool(),
		plan.Restart.ValueBool(),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Feature Installation Failed",
			fmt.Sprintf("Failed to install Windows feature '%s': %s", featureName, err.Error()),
		)
		return
	}

	if !installResult.Success {
		resp.Diagnostics.AddError(
			"Feature Installation Failed",
			fmt.Sprintf("Windows feature installation completed with errors.\nFeature: %s\nExit Code: %d",
				featureName, installResult.ExitCode),
		)
		return
	}

	tflog.Info(ctx, "Feature installed successfully", map[string]interface{}{
		"feature":        featureName,
		"restart_needed": installResult.GetRestartNeededString(),
	})

	// Get updated feature information
	featureInfo, err := windows.GetFeatureInfo(execCtx, client, featureName)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Failed to Read Feature Info",
			fmt.Sprintf("Feature was installed but failed to read its current state: %s", err.Error()),
		)

		// Set minimal state on warning
		plan.ID = types.StringValue(featureName)
		plan.InstallState = types.StringValue("Installed")
		plan.DisplayName = types.StringValue("")
		plan.Description = types.StringValue("")
		plan.RestartNeeded = types.BoolValue(installResult.IsRestartNeeded())

		// 🆕 Set empty values for new fields
		plan.Depth = types.Int64Value(0)
		plan.PostConfigurationNeeded = types.BoolValue(false)
		plan.AdditionalInfo, _ = types.MapValue(types.StringType, map[string]attr.Value{})
	} else {
		// 🆕 Convert AdditionalInfo to types.Map
		additionalInfoMap, diags := types.MapValueFrom(ctx, types.StringType, featureInfo.AdditionalInfo)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Set complete state from feature info
		plan.ID = types.StringValue(featureName)
		plan.InstallState = types.StringValue(featureInfo.GetInstallStateString())
		plan.DisplayName = types.StringValue(featureInfo.DisplayName)
		plan.Description = types.StringValue(featureInfo.Description)
		plan.RestartNeeded = types.BoolValue(installResult.IsRestartNeeded())

		// 🆕 Set new fields
		plan.Depth = types.Int64Value(int64(featureInfo.Depth))
		plan.PostConfigurationNeeded = types.BoolValue(featureInfo.PostConfigurationNeeded)
		plan.AdditionalInfo = additionalInfoMap
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *featureResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state featureResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	featureName := state.Feature.ValueString()

	tflog.Debug(ctx, "Reading Windows feature state", map[string]interface{}{
		"feature": featureName,
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context
	timeout := time.Duration(state.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Get feature information using shared package function
	featureInfo, err := windows.GetFeatureInfo(execCtx, client, featureName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Read Feature",
			fmt.Sprintf("Failed to read Windows feature '%s': %s", featureName, err.Error()),
		)
		return
	}

	// If feature is not installed, remove from state
	if !featureInfo.Installed {
		tflog.Warn(ctx, "Feature is not installed, removing from state", map[string]interface{}{
			"feature": featureName,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// 🆕 Convert AdditionalInfo to types.Map
	additionalInfoMap, diags := types.MapValueFrom(ctx, types.StringType, featureInfo.AdditionalInfo)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update state with current feature information
	state.InstallState = types.StringValue(featureInfo.GetInstallStateString())
	state.DisplayName = types.StringValue(featureInfo.DisplayName)
	state.Description = types.StringValue(featureInfo.Description)

	// 🆕 Update new fields
	state.Depth = types.Int64Value(int64(featureInfo.Depth))
	state.PostConfigurationNeeded = types.BoolValue(featureInfo.PostConfigurationNeeded)
	state.AdditionalInfo = additionalInfoMap

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *featureResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan featureResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	featureName := plan.Feature.ValueString()

	tflog.Info(ctx, "Update called for Windows feature - reinstalling with new configuration", map[string]interface{}{
		"feature": featureName,
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context
	timeout := time.Duration(plan.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Reinstall with new configuration using shared package function
	installResult, err := windows.InstallFeature(
		execCtx,
		client,
		featureName,
		plan.IncludeAllSubFeatures.ValueBool(),
		plan.IncludeManagementTools.ValueBool(),
		plan.Restart.ValueBool(),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Feature Update Failed",
			fmt.Sprintf("Failed to update Windows feature: %s", err.Error()),
		)
		return
	}

	if !installResult.Success {
		resp.Diagnostics.AddError(
			"Feature Update Failed",
			fmt.Sprintf("Windows feature update completed with errors.\nExit Code: %d",
				installResult.ExitCode),
		)
		return
	}

	// Get updated feature information
	featureInfo, err := windows.GetFeatureInfo(execCtx, client, featureName)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Failed to Read Feature Info",
			fmt.Sprintf("Feature was updated but failed to read its current state: %s", err.Error()),
		)

		// Set minimal state on warning
		plan.InstallState = types.StringValue("Installed")
		plan.DisplayName = types.StringValue("")
		plan.Description = types.StringValue("")
		plan.RestartNeeded = types.BoolValue(installResult.IsRestartNeeded())

		// 🆕 Set empty values for new fields
		plan.Depth = types.Int64Value(0)
		plan.PostConfigurationNeeded = types.BoolValue(false)
		plan.AdditionalInfo, _ = types.MapValue(types.StringType, map[string]attr.Value{})
	} else {
		// 🆕 Convert AdditionalInfo to types.Map
		additionalInfoMap, diags := types.MapValueFrom(ctx, types.StringType, featureInfo.AdditionalInfo)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Update state with current feature information
		plan.InstallState = types.StringValue(featureInfo.GetInstallStateString())
		plan.DisplayName = types.StringValue(featureInfo.DisplayName)
		plan.Description = types.StringValue(featureInfo.Description)
		plan.RestartNeeded = types.BoolValue(installResult.IsRestartNeeded())

		// 🆕 Update new fields
		plan.Depth = types.Int64Value(int64(featureInfo.Depth))
		plan.PostConfigurationNeeded = types.BoolValue(featureInfo.PostConfigurationNeeded)
		plan.AdditionalInfo = additionalInfoMap
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *featureResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state featureResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	featureName := state.Feature.ValueString()

	tflog.Info(ctx, "Deleting Windows feature", map[string]interface{}{
		"feature": featureName,
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context
	timeout := time.Duration(state.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Uninstall the feature using shared package function
	err = windows.UninstallFeature(execCtx, client, featureName, state.Restart.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError(
			"Feature Uninstallation Failed",
			fmt.Sprintf("Failed to uninstall Windows feature '%s': %s", featureName, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Feature uninstalled successfully", map[string]interface{}{
		"feature": featureName,
	})
}

// ImportState imports an existing resource into Terraform state.
func (r *featureResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	featureName := req.ID

	tflog.Info(ctx, "Importing Windows feature", map[string]interface{}{
		"feature": featureName,
	})

	// Validate feature name format
	if err := validators.ValidateFeatureName(featureName); err != nil {
		resp.Diagnostics.AddError(
			"Invalid Feature Name",
			fmt.Sprintf("The feature name '%s' is not valid: %s", featureName, err.Error()),
		)
		return
	}

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Use default timeout for import operations
	execCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()

	// Get feature information to verify it exists using shared package function
	featureInfo, err := windows.GetFeatureInfo(execCtx, client, featureName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Feature Not Found",
			fmt.Sprintf("Failed to find Windows feature '%s': %s", featureName, err.Error()),
		)
		return
	}

	if !featureInfo.Installed {
		resp.Diagnostics.AddError(
			"Feature Not Installed",
			fmt.Sprintf("Windows feature '%s' is not currently installed and cannot be imported.", featureName),
		)
		return
	}

	// 🆕 Convert AdditionalInfo to types.Map
	additionalInfoMap, diags := types.MapValueFrom(ctx, types.StringType, featureInfo.AdditionalInfo)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set imported state with default values for configuration attributes
	state := featureResourceModel{
		ID:                     types.StringValue(featureName),
		Feature:                types.StringValue(featureName),
		IncludeAllSubFeatures:  types.BoolValue(false),
		IncludeManagementTools: types.BoolValue(false),
		Restart:                types.BoolValue(false),
		AllowExisting:          types.BoolValue(true),
		CommandTimeout:         types.Int64Value(300),
		InstallState:           types.StringValue(featureInfo.GetInstallStateString()),
		DisplayName:            types.StringValue(featureInfo.DisplayName),
		Description:            types.StringValue(featureInfo.Description),
		RestartNeeded:          types.BoolValue(false),

		// 🆕 New fields
		Depth:                   types.Int64Value(int64(featureInfo.Depth)),
		PostConfigurationNeeded: types.BoolValue(featureInfo.PostConfigurationNeeded),
		AdditionalInfo:          additionalInfoMap,
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

	tflog.Info(ctx, "Feature imported successfully", map[string]interface{}{
		"feature":       featureName,
		"install_state": featureInfo.GetInstallStateString(),
	})
}
