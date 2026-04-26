// Package provider: windows_local_group data source implementation.
//
// Reads the observed state of a Windows local group by name OR SID (exactly
// one of the two must be provided). The write-only attributes of the resource
// are absent; all returned attributes are Computed.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource                     = (*windowsLocalGroupDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*windowsLocalGroupDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*windowsLocalGroupDataSource)(nil)
)

// NewWindowsLocalGroupDataSource is the constructor registered in provider.go.
func NewWindowsLocalGroupDataSource() datasource.DataSource {
	return &windowsLocalGroupDataSource{}
}

// windowsLocalGroupDataSource is the TPF data source type for windows_local_group.
type windowsLocalGroupDataSource struct {
	client *winclient.Client
	grp    winclient.WindowsLocalGroupClient
}

// windowsLocalGroupDataSourceModel is the Terraform state model for the
// windows_local_group data source.
type windowsLocalGroupDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	SID         types.String `tfsdk:"sid"`
	Description types.String `tfsdk:"description"`
}

// Metadata sets the data source type name ("windows_local_group").
func (d *windowsLocalGroupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_group"
}

// Schema returns the TPF schema for the windows_local_group data source.
func (d *windowsLocalGroupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a Windows local group without managing its lifecycle.\n\n" +
			"Exactly one of `name` or `sid` must be provided as the lookup key. " +
			"The other attribute is populated from the resolved group state.\n\n" +
			"Returns an error when no matching group is found on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; equal to the group SID.",
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name of the local group. Exactly one of name or sid must be specified.",
			},
			"sid": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Security Identifier of the group (e.g. \"S-1-5-21-...-1001\"). Exactly one of name or sid must be specified.",
				MarkdownDescription: "Security Identifier (SID) of the group (e.g. `S-1-5-21-...-1001`). Exactly one of `name` or `sid` must be specified.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Free-text description of the group as returned by Windows.",
			},
		},
	}
}

// ConfigValidators enforces ExactlyOneOf(name, sid).
func (d *windowsLocalGroupDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("name"),
			path.MatchRoot("sid"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsLocalGroupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.grp = winclient.NewLocalGroupClient(c)
}

// Read fetches the local group state from the remote Windows host.
func (d *windowsLocalGroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsLocalGroupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_local_group data source Read start", map[string]interface{}{
		"name": config.Name.ValueString(),
		"sid":  config.SID.ValueString(),
	})

	var gs *winclient.GroupState
	var err error

	if !config.Name.IsNull() && config.Name.ValueString() != "" {
		gs, err = d.grp.ImportByName(ctx, config.Name.ValueString())
	} else {
		gs, err = d.grp.ImportBySID(ctx, config.SID.ValueString())
	}

	if err != nil {
		if winclient.IsLocalGroupError(err, winclient.LocalGroupErrorNotFound) {
			key := config.Name.ValueString()
			if key == "" {
				key = config.SID.ValueString()
			}
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_local_group %q", key),
				fmt.Sprintf("No local group with name/SID %q was found on the target host.", key),
			)
			return
		}
		addLocalGroupDiag(&resp.Diagnostics, "Read windows_local_group data source failed", err)
		return
	}
	if gs == nil {
		key := config.Name.ValueString()
		if key == "" {
			key = config.SID.ValueString()
		}
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_local_group %q", key),
			fmt.Sprintf("No local group with name/SID %q was found on the target host.", key),
		)
		return
	}

	state := windowsLocalGroupDataSourceModel{
		ID:          types.StringValue(gs.SID),
		Name:        types.StringValue(gs.Name),
		SID:         types.StringValue(gs.SID),
		Description: types.StringValue(gs.Description),
	}

	tflog.Debug(ctx, "windows_local_group data source Read end", map[string]interface{}{
		"name": state.Name.ValueString(),
		"sid":  state.SID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
