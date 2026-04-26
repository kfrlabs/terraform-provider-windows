// Package provider: windows_feature data source implementation.
//
// Reads the observed state of a Windows Server role or feature without
// managing its lifecycle. All write-only input attributes of the resource
// (include_sub_features, include_management_tools, source, restart) are
// absent from this data source.
package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsFeatureDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsFeatureDataSource)(nil)
)

// NewWindowsFeatureDataSource is the constructor registered in provider.go.
func NewWindowsFeatureDataSource() datasource.DataSource {
	return &windowsFeatureDataSource{}
}

// windowsFeatureDataSource is the TPF data source type for windows_feature.
type windowsFeatureDataSource struct {
	client *winclient.Client
	feat   winclient.WindowsFeatureClient
}

// windowsFeatureDataSourceModel is the Terraform state model for the
// windows_feature data source.
type windowsFeatureDataSourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	DisplayName    types.String `tfsdk:"display_name"`
	Description    types.String `tfsdk:"description"`
	Installed      types.Bool   `tfsdk:"installed"`
	RestartPending types.Bool   `tfsdk:"restart_pending"`
	InstallState   types.String `tfsdk:"install_state"`
}

// Metadata sets the data source type name ("windows_feature").
func (d *windowsFeatureDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_feature"
}

// Schema returns the TPF schema for the windows_feature data source.
func (d *windowsFeatureDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a Windows Server role or feature without " +
			"managing its lifecycle. Backed by `Get-WindowsFeature` (ServerManager module).\n\n" +
			"Returns an error when the named feature does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier; equal to the feature short name.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				Description:         "Technical name of the Windows feature to look up (e.g. Web-Server, DNS, RSAT-AD-PowerShell).",
				MarkdownDescription: "Technical name of the Windows feature to look up (e.g. `Web-Server`, `DNS`, `RSAT-AD-PowerShell`).",
			},
			"display_name": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable display name reported by Get-WindowsFeature.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description string returned by Get-WindowsFeature.",
			},
			"installed": schema.BoolAttribute{
				Computed:    true,
				Description: "True when InstallState=Installed.",
			},
			"restart_pending": schema.BoolAttribute{
				Computed:    true,
				Description: "True if the OS reports a pending reboot flag related to this feature.",
			},
			"install_state": schema.StringAttribute{
				Computed:    true,
				Description: "Current install state: Installed, Available, or Removed.",
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsFeatureDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	d.client = c
	d.feat = winclient.NewFeatureClient(c)
}

// Read fetches the feature state from the remote Windows host.
func (d *windowsFeatureDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsFeatureDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := config.Name.ValueString()
	tflog.Debug(ctx, "windows_feature data source Read start", map[string]interface{}{"name": name})

	info, err := d.feat.Read(ctx, name)
	if err != nil {
		var fe *winclient.FeatureError
		if errors.As(err, &fe) && fe.Kind == winclient.FeatureErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_feature %q", name),
				fmt.Sprintf("No Windows feature named %q was found on the target host. "+
					"Verify the name with Get-WindowsFeature on the target.", name),
			)
			return
		}
		addFeatureDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_feature %q failed", name), err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_feature %q", name),
			fmt.Sprintf("No Windows feature named %q was found on the target host.", name),
		)
		return
	}

	state := windowsFeatureDataSourceModel{
		ID:             types.StringValue(info.Name),
		Name:           types.StringValue(info.Name),
		DisplayName:    types.StringValue(info.DisplayName),
		Description:    types.StringValue(info.Description),
		Installed:      types.BoolValue(info.Installed),
		RestartPending: types.BoolValue(info.RestartPending),
		InstallState:   types.StringValue(info.InstallState),
	}

	tflog.Debug(ctx, "windows_feature data source Read end", map[string]interface{}{
		"name":          state.Name.ValueString(),
		"install_state": state.InstallState.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
