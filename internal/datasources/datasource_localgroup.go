package datasources

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/common"
	"github.com/kfrlabs/terraform-provider-windows/internal/validators"
	"github.com/kfrlabs/terraform-provider-windows/internal/windows"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &localGroupDataSource{}
	_ datasource.DataSourceWithConfigure = &localGroupDataSource{}
)

// NewLocalGroupDataSource is a helper function to simplify the provider implementation.
func NewLocalGroupDataSource() datasource.DataSource {
	return &localGroupDataSource{}
}

// localGroupDataSource is the data source implementation for reading Windows local group information.
type localGroupDataSource struct {
	providerData *common.ProviderData
}

// localGroupDataSourceModel describes the data source data model
type localGroupDataSourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	SID             types.String `tfsdk:"sid"`
	Description     types.String `tfsdk:"description"`
	PrincipalSource types.String `tfsdk:"principal_source"`
	ObjectClass     types.String `tfsdk:"object_class"`
	CommandTimeout  types.Int64  `tfsdk:"command_timeout"`
}

// Metadata returns the data source type name.
func (d *localGroupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_localgroup"
}

// Schema defines the schema for the data source.
func (d *localGroupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads information about a Windows local group.",
		MarkdownDescription: `Reads information about a Windows local group.

This data source retrieves detailed information about an existing local group on a Windows system,
including security identifiers and group properties.

## Example Usage

` + "```terraform" + `
data "windows_localgroup" "administrators" {
  name = "Administrators"
}

output "admin_group_info" {
  value = {
    sid              = data.windows_localgroup.administrators.sid
    description      = data.windows_localgroup.administrators.description
    principal_source = data.windows_localgroup.administrators.principal_source
  }
}

data "windows_localgroup" "custom_group" {
  name = "CustomGroup"
}

output "custom_group_sid" {
  value = data.windows_localgroup.custom_group.sid
}
` + "```",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the data source (same as name).",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the local group to look up.",
				Required:    true,
				Validators: []validator.String{
					validators.WindowsGroupName(),
				},
			},
			"sid": schema.StringAttribute{
				Description: "The Security Identifier (SID) of the group. This is a unique identifier in the format S-1-5-...",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the group.",
				Computed:    true,
			},
			"principal_source": schema.StringAttribute{
				Description: "The source of the group. Typically 'Local' for local groups.",
				Computed:    true,
			},
			"object_class": schema.StringAttribute{
				Description: "The object class type. Typically 'Group' for group objects.",
				Computed:    true,
			},
			"command_timeout": schema.Int64Attribute{
				Description: "Timeout in seconds for PowerShell commands. Default is 300 seconds (5 minutes).",
				Optional:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *localGroupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *localGroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config localGroupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupname := config.Name.ValueString()

	tflog.Info(ctx, "Reading local group information", map[string]interface{}{
		"groupname": groupname,
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

	// Determine timeout (default to 300 seconds if not specified)
	timeout := int64(300)
	if !config.CommandTimeout.IsNull() {
		timeout = config.CommandTimeout.ValueInt64()
	}

	// Create timeout context
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Get group information using shared package function
	groupInfo, err := windows.GetLocalGroupInfo(execCtx, client, groupname)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Read Group",
			fmt.Sprintf("Failed to read local group '%s': %s", groupname, err.Error()),
		)
		return
	}

	// Check if group exists
	if !groupInfo.Exists {
		resp.Diagnostics.AddError(
			"Group Not Found",
			fmt.Sprintf("Local group '%s' does not exist on the Windows system.", groupname),
		)
		return
	}

	// Map all attributes to state
	config.ID = types.StringValue(groupname)
	config.SID = types.StringValue(groupInfo.SID)
	config.Description = types.StringValue(groupInfo.Description)
	config.PrincipalSource = types.StringValue(groupInfo.PrincipalSource)
	config.ObjectClass = types.StringValue(groupInfo.ObjectClass)

	tflog.Debug(ctx, "Successfully read local group information", map[string]interface{}{
		"groupname":        groupname,
		"sid":              groupInfo.SID,
		"principal_source": groupInfo.PrincipalSource,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
