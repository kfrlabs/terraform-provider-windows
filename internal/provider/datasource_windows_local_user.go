// Package provider: windows_local_user data source implementation.
//
// Reads the observed state of a Windows local user account by name OR SID
// (exactly one must be provided). Write-only resource attributes (password,
// password_wo_version) are absent. Sensitive attributes (if any) are preserved.
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
	_ datasource.DataSource                     = (*windowsLocalUserDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*windowsLocalUserDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*windowsLocalUserDataSource)(nil)
)

// NewWindowsLocalUserDataSource is the constructor registered in provider.go.
func NewWindowsLocalUserDataSource() datasource.DataSource {
	return &windowsLocalUserDataSource{}
}

// windowsLocalUserDataSource is the TPF data source type for windows_local_user.
type windowsLocalUserDataSource struct {
	client *winclient.Client
	user   winclient.LocalUserClient
}

// windowsLocalUserDataSourceModel is the Terraform state model for the
// windows_local_user data source.
type windowsLocalUserDataSourceModel struct {
	ID                       types.String `tfsdk:"id"`
	SID                      types.String `tfsdk:"sid"`
	Name                     types.String `tfsdk:"name"`
	FullName                 types.String `tfsdk:"full_name"`
	Description              types.String `tfsdk:"description"`
	Enabled                  types.Bool   `tfsdk:"enabled"`
	PasswordNeverExpires     types.Bool   `tfsdk:"password_never_expires"`
	UserMayNotChangePassword types.Bool   `tfsdk:"user_may_not_change_password"`
	AccountNeverExpires      types.Bool   `tfsdk:"account_never_expires"`
	AccountExpires           types.String `tfsdk:"account_expires"`
	LastLogon                types.String `tfsdk:"last_logon"`
	PasswordLastSet          types.String `tfsdk:"password_last_set"`
	PrincipalSource          types.String `tfsdk:"principal_source"`
}

// Metadata sets the data source type name ("windows_local_user").
func (d *windowsLocalUserDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_user"
}

// Schema returns the TPF schema for the windows_local_user data source.
func (d *windowsLocalUserDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a Windows local user account without managing " +
			"its lifecycle. Exactly one of `name` or `sid` must be provided as the lookup key.\n\n" +
			"Write-only attributes (`password`, `password_wo_version`) are intentionally absent — " +
			"Windows cannot return plaintext passwords.\n\n" +
			"Returns an error when no matching account is found on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; equal to the user SID.",
			},
			"sid": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Security Identifier of the user (e.g. \"S-1-5-21-...-1001\"). Exactly one of name or sid must be specified.",
				MarkdownDescription: "Security Identifier (SID) of the user. Exactly one of `name` or `sid` must be specified.",
			},
			"name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "SAM account name of the user. Exactly one of name or sid must be specified.",
				MarkdownDescription: "SAM account name of the user. Exactly one of `name` or `sid` must be specified.",
			},
			"full_name": schema.StringAttribute{
				Computed:    true,
				Description: "Display name of the user account.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Free-text description of the user account.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the account is active and not disabled.",
			},
			"password_never_expires": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the account password has no expiry policy.",
			},
			"user_may_not_change_password": schema.BoolAttribute{
				Computed:    true,
				Description: "True when self-service password change is blocked for this account.",
			},
			"account_never_expires": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the account has no expiry date set.",
			},
			"account_expires": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp of the account expiry date, or empty string when the account never expires.",
			},
			"last_logon": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp of the last logon, or empty string if the account has never been used.",
			},
			"password_last_set": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp of the last password change, or empty string if not yet set.",
			},
			"principal_source": schema.StringAttribute{
				Computed:    true,
				Description: "Origin of the account: Local, ActiveDirectory, AzureAD, MicrosoftAccount, or Unknown.",
			},
		},
	}
}

// ConfigValidators enforces ExactlyOneOf(name, sid).
func (d *windowsLocalUserDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("name"),
			path.MatchRoot("sid"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsLocalUserDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.user = winclient.NewLocalUserClient(c)
}

// Read fetches the local user state from the remote Windows host.
func (d *windowsLocalUserDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsLocalUserDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_local_user data source Read start", map[string]interface{}{
		"name": config.Name.ValueString(),
		"sid":  config.SID.ValueString(),
	})

	var us *winclient.UserState
	var err error

	if !config.Name.IsNull() && config.Name.ValueString() != "" {
		us, err = d.user.ImportByName(ctx, config.Name.ValueString())
	} else {
		us, err = d.user.ImportBySID(ctx, config.SID.ValueString())
	}

	if err != nil {
		if winclient.IsLocalUserError(err, winclient.LocalUserErrorNotFound) {
			key := config.Name.ValueString()
			if key == "" {
				key = config.SID.ValueString()
			}
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_local_user %q", key),
				fmt.Sprintf("No local user account with name/SID %q was found on the target host.", key),
			)
			return
		}
		addLocalUserDiag(&resp.Diagnostics, "Read windows_local_user data source failed", err)
		return
	}
	if us == nil {
		key := config.Name.ValueString()
		if key == "" {
			key = config.SID.ValueString()
		}
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_local_user %q", key),
			fmt.Sprintf("No local user account with name/SID %q was found on the target host.", key),
		)
		return
	}

	state := windowsLocalUserDataSourceModel{
		ID:                       types.StringValue(us.SID),
		SID:                      types.StringValue(us.SID),
		Name:                     types.StringValue(us.Name),
		FullName:                 types.StringValue(us.FullName),
		Description:              types.StringValue(us.Description),
		Enabled:                  types.BoolValue(us.Enabled),
		PasswordNeverExpires:     types.BoolValue(us.PasswordNeverExpires),
		UserMayNotChangePassword: types.BoolValue(us.UserMayNotChangePassword),
		AccountNeverExpires:      types.BoolValue(us.AccountNeverExpires),
		AccountExpires:           types.StringValue(us.AccountExpires),
		LastLogon:                types.StringValue(us.LastLogon),
		PasswordLastSet:          types.StringValue(us.PasswordLastSet),
		PrincipalSource:          types.StringValue(us.PrincipalSource),
	}

	tflog.Debug(ctx, "windows_local_user data source Read end", map[string]interface{}{
		"sid":  state.SID.ValueString(),
		"name": state.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Helper addLocalUserDiag is reused from resource_windows_local_user.go (same package).
