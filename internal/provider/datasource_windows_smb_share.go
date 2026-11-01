// Package provider: windows_smb_share data source implementation.
//
// Reads the observed state of an existing SMB share without managing it.
// Declarative input attributes of the resource (description,
// folder_enumeration_mode, caching_mode, concurrent_user_limit, encrypt_data)
// are exposed read-only instead, alongside the observed access lists and the
// special flag.
package provider

import (
	"context"
	"errors"
	"fmt"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsSmbShareDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsSmbShareDataSource)(nil)
)

// NewWindowsSmbShareDataSource is the constructor registered in provider.go.
func NewWindowsSmbShareDataSource() datasource.DataSource {
	return &windowsSmbShareDataSource{}
}

// windowsSmbShareDataSource is the TPF data source type for windows_smb_share.
type windowsSmbShareDataSource struct {
	client winclient.SmbShareClient
}

// smbShareDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block. It reuses the sibling resource default
// (smbShareDefaultTimeout) so a stalled session surfaces a timeout diagnostic
// instead of blocking plan forever (issue #197).
const smbShareDSDefaultTimeout = smbShareDefaultTimeout

// windowsSmbShareDataSourceModel is the Terraform state model for the
// windows_smb_share data source.
type windowsSmbShareDataSourceModel struct {
	ID                    types.String     `tfsdk:"id"`
	Name                  types.String     `tfsdk:"name"`
	Path                  types.String     `tfsdk:"path"`
	Description           types.String     `tfsdk:"description"`
	FolderEnumerationMode types.String     `tfsdk:"folder_enumeration_mode"`
	CachingMode           types.String     `tfsdk:"caching_mode"`
	ConcurrentUserLimit   types.Int64      `tfsdk:"concurrent_user_limit"`
	EncryptData           types.Bool       `tfsdk:"encrypt_data"`
	FullAccess            types.Set        `tfsdk:"full_access"`
	ChangeAccess          types.Set        `tfsdk:"change_access"`
	ReadAccess            types.Set        `tfsdk:"read_access"`
	NoAccess              types.Set        `tfsdk:"no_access"`
	Special               types.Bool       `tfsdk:"special"`
	Timeouts              dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_smb_share").
func (d *windowsSmbShareDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_smb_share"
}

// Schema returns the TPF schema for the windows_smb_share data source.
func (d *windowsSmbShareDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of an existing SMB share on a remote " +
			"Windows host without managing it.\n\n" +
			"Declarative attributes of the sibling resource (except the lookup key `name`) are intentionally absent " +
			"as inputs: the observed values are exposed read-only instead, including the full share access lists and " +
			"the `special` flag that marks administrative shares (`ADMIN$`, `C$`, `IPC$`).\n\n" +
			"Returns an error when the share does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the SMB share name.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "SMB share name on the target host. The share must already exist.",
			},
			"path": schema.StringAttribute{
				Computed:    true,
				Description: "Local absolute path of the shared directory, as observed on the host.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Share description, as observed on the host.",
			},
			"folder_enumeration_mode": schema.StringAttribute{
				Computed:    true,
				Description: "Folder enumeration mode, as observed on the host: Unrestricted or AccessBased.",
			},
			"caching_mode": schema.StringAttribute{
				Computed:    true,
				Description: "Offline file caching mode, as observed on the host: None, Manual, Programs, Documents or BranchCache.",
			},
			"concurrent_user_limit": schema.Int64Attribute{
				Computed:    true,
				Description: "Maximum number of concurrent users (0 means no limit), as observed on the host.",
			},
			"encrypt_data": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether SMB encryption is required for the share, as observed on the host.",
			},
			"full_access": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Trustees granted full share access, as observed on the host.",
			},
			"change_access": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Trustees granted change share access, as observed on the host.",
			},
			"read_access": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Trustees granted read share access, as observed on the host.",
			},
			"no_access": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Trustees explicitly denied share access, as observed on the host.",
			},
			"special": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the share is administrative (owned by Windows).",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to smbShareDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsSmbShareDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewSmbShareClient(c)
}

// smbShareTrusteeNames renders observed trustees as their display names.
// The data source reports what Windows reports; SID comparison belongs to
// the resource's drift reconciliation.
func smbShareTrusteeNames(trustees []winclient.SmbShareTrustee) []string {
	out := make([]string, 0, len(trustees))
	for _, t := range trustees {
		out = append(out, t.Name)
	}
	return out
}

// Read fetches the observed share state from the remote Windows host by
// calling the sibling resource's SmbShareClient.Read with the configured
// name. A nil result triggers a `not found` diagnostic (data sources never
// silently clear state). Other typed *winclient.SmbShareError values are
// surfaced via addSmbShareDiag, mirroring the resource Read path.
func (d *windowsSmbShareDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsSmbShareDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, smbShareDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Name.ValueString()
	tflog.Debug(ctx, "windows_smb_share data source Read start", map[string]interface{}{"name": target})

	observed, err := d.client.Read(ctx, target)
	if err != nil {
		var se *winclient.SmbShareError
		if errors.As(err, &se) && se.Kind == winclient.SmbShareErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_smb_share %q", target),
				fmt.Sprintf("No SMB share %q was found on the target host.", target),
			)
			return
		}
		addSmbShareDiag(&resp.Diagnostics, "Read data source", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_smb_share %q", target),
			fmt.Sprintf("No SMB share %q was found on the target host.", target),
		)
		return
	}

	full, dgs := types.SetValueFrom(ctx, types.StringType, smbShareTrusteeNames(observed.FullAccess))
	resp.Diagnostics.Append(dgs...)
	change, dgs := types.SetValueFrom(ctx, types.StringType, smbShareTrusteeNames(observed.ChangeAccess))
	resp.Diagnostics.Append(dgs...)
	read, dgs := types.SetValueFrom(ctx, types.StringType, smbShareTrusteeNames(observed.ReadAccess))
	resp.Diagnostics.Append(dgs...)
	no, dgs := types.SetValueFrom(ctx, types.StringType, smbShareTrusteeNames(observed.NoAccess))
	resp.Diagnostics.Append(dgs...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsSmbShareDataSourceModel{
		ID:                    types.StringValue(observed.Name),
		Name:                  types.StringValue(observed.Name),
		Path:                  types.StringValue(observed.Path),
		Description:           types.StringValue(observed.Description),
		FolderEnumerationMode: types.StringValue(observed.FolderEnumerationMode),
		CachingMode:           types.StringValue(observed.CachingMode),
		ConcurrentUserLimit:   types.Int64Value(observed.ConcurrentUserLimit),
		EncryptData:           types.BoolValue(observed.EncryptData),
		FullAccess:            full,
		ChangeAccess:          change,
		ReadAccess:            read,
		NoAccess:              no,
		Special:               types.BoolValue(observed.Special),
		Timeouts:              config.Timeouts,
	}

	tflog.Debug(ctx, "windows_smb_share data source Read end", map[string]interface{}{
		"name": state.Name.ValueString(),
		"path": state.Path.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
