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
	_ datasource.DataSource              = &localUserDataSource{}
	_ datasource.DataSourceWithConfigure = &localUserDataSource{}
)

// NewLocalUserDataSource is a helper function to simplify the provider implementation.
func NewLocalUserDataSource() datasource.DataSource {
	return &localUserDataSource{}
}

// localUserDataSource is the data source implementation for reading Windows local user information.
type localUserDataSource struct {
	providerData *common.ProviderData
}

// localUserDataSourceModel describes the data source data model with all available attributes
type localUserDataSourceModel struct {
	ID                       types.String `tfsdk:"id"`
	Username                 types.String `tfsdk:"username"`
	SID                      types.String `tfsdk:"sid"`
	FullName                 types.String `tfsdk:"full_name"`
	Description              types.String `tfsdk:"description"`
	Enabled                  types.Bool   `tfsdk:"enabled"`
	PasswordNeverExpires     types.Bool   `tfsdk:"password_never_expires"`
	UserCannotChangePassword types.Bool   `tfsdk:"user_cannot_change_password"`
	PasswordRequired         types.Bool   `tfsdk:"password_required"`
	PasswordLastSet          types.String `tfsdk:"password_last_set"`
	PasswordExpires          types.String `tfsdk:"password_expires"`
	PasswordChangeableDate   types.String `tfsdk:"password_changeable_date"`
	AccountExpires           types.String `tfsdk:"account_expires"`
	LastLogon                types.String `tfsdk:"last_logon"`
	PrincipalSource          types.String `tfsdk:"principal_source"`
	ObjectClass              types.String `tfsdk:"object_class"`
	CommandTimeout           types.Int64  `tfsdk:"command_timeout"`
}

// Metadata returns the data source type name.
func (d *localUserDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_localuser"
}

// Schema defines the schema for the data source.
func (d *localUserDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads comprehensive information about a Windows local user account.",
		MarkdownDescription: `Reads comprehensive information about a Windows local user account.

This data source retrieves detailed information about an existing local user on a Windows system,
including security identifiers, password policies, and activity timestamps.

## Example Usage

` + "```terraform" + `
data "windows_localuser" "admin" {
  username = "Administrator"
}

output "admin_info" {
  value = {
    sid                  = data.windows_localuser.admin.sid
    enabled              = data.windows_localuser.admin.enabled
    password_last_set    = data.windows_localuser.admin.password_last_set
    last_logon           = data.windows_localuser.admin.last_logon
    password_expires     = data.windows_localuser.admin.password_expires
  }
}

data "windows_localuser" "service_account" {
  username = "svc_account"
}

output "service_account_description" {
  value = data.windows_localuser.service_account.description
}
` + "```",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the data source (same as username).",
				Computed:    true,
			},
			"username": schema.StringAttribute{
				Description: "The name of the local user account to look up.",
				Required:    true,
				Validators: []validator.String{
					validators.WindowsUsername(),
				},
			},
			"sid": schema.StringAttribute{
				Description: "The Security Identifier (SID) of the user account. This is a unique identifier in the format S-1-5-21-...",
				Computed:    true,
			},
			"full_name": schema.StringAttribute{
				Description: "The full name of the user.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the user account.",
				Computed:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Indicates whether the user account is enabled.",
				Computed:    true,
			},
			"password_never_expires": schema.BoolAttribute{
				Description: "Indicates whether the password never expires.",
				Computed:    true,
			},
			"user_cannot_change_password": schema.BoolAttribute{
				Description: "Indicates whether the user can change their password.",
				Computed:    true,
			},
			"password_required": schema.BoolAttribute{
				Description: "Indicates whether a password is required for the account.",
				Computed:    true,
			},
			"password_last_set": schema.StringAttribute{
				Description: "The date and time when the password was last set, in ISO 8601 format (e.g., '2026-02-11T20:38:36+01:00'). Empty if never set.",
				Computed:    true,
			},
			"password_expires": schema.StringAttribute{
				Description: "The date and time when the password will expire, in ISO 8601 format. Empty if password never expires.",
				Computed:    true,
			},
			"password_changeable_date": schema.StringAttribute{
				Description: "The date and time when the password can be changed, in ISO 8601 format. Empty if not applicable.",
				Computed:    true,
			},
			"account_expires": schema.StringAttribute{
				Description: "The date and time when the account will expire, in ISO 8601 format. Empty if account never expires.",
				Computed:    true,
			},
			"last_logon": schema.StringAttribute{
				Description: "The date and time of the last logon, in ISO 8601 format. Empty if user has never logged on.",
				Computed:    true,
			},
			"principal_source": schema.StringAttribute{
				Description: "The source of the account. Typically 'Local' for local accounts.",
				Computed:    true,
			},
			"object_class": schema.StringAttribute{
				Description: "The object class type. Typically 'User' for user accounts.",
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
func (d *localUserDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *localUserDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config localUserDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	username := config.Username.ValueString()

	tflog.Info(ctx, "Reading local user information", map[string]interface{}{
		"username": username,
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

	// Get user information using shared package function
	userInfo, err := windows.GetLocalUserInfo(execCtx, client, username)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Read User",
			fmt.Sprintf("Failed to read local user '%s': %s", username, err.Error()),
		)
		return
	}

	// Check if user exists
	if !userInfo.Exists {
		resp.Diagnostics.AddError(
			"User Not Found",
			fmt.Sprintf("Local user '%s' does not exist on the Windows system.", username),
		)
		return
	}

	// Map all attributes to state
	config.ID = types.StringValue(username)
	config.SID = types.StringValue(userInfo.SID)
	config.FullName = types.StringValue(userInfo.FullName)
	config.Description = types.StringValue(userInfo.Description)
	config.Enabled = types.BoolValue(userInfo.Enabled)
	config.PasswordNeverExpires = types.BoolValue(userInfo.PasswordNeverExpires)
	config.UserCannotChangePassword = types.BoolValue(userInfo.UserMayNotChangePassword)
	config.PasswordRequired = types.BoolValue(userInfo.PasswordRequired)
	config.PasswordLastSet = types.StringValue(userInfo.PasswordLastSet)
	config.PasswordExpires = types.StringValue(userInfo.PasswordExpires)
	config.PasswordChangeableDate = types.StringValue(userInfo.PasswordChangeableDate)
	config.AccountExpires = types.StringValue(userInfo.AccountExpires)
	config.LastLogon = types.StringValue(userInfo.LastLogon)
	config.PrincipalSource = types.StringValue(userInfo.PrincipalSource)
	config.ObjectClass = types.StringValue(userInfo.ObjectClass)

	tflog.Debug(ctx, "Successfully read local user information", map[string]interface{}{
		"username":         username,
		"sid":              userInfo.SID,
		"enabled":          userInfo.Enabled,
		"last_logon":       userInfo.LastLogon,
		"password_expires": userInfo.PasswordExpires,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
