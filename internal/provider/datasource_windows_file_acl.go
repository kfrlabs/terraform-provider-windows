// Package provider: windows_file_acl data source implementation.
//
// Reads the observed security descriptor of an existing file or directory
// without managing it. All declarative input attributes of the resource
// (mode, access_rule, preserve_inherited_on_protect) are absent from this
// data source: the observed DACL is exposed read-only through
// effective_access_rules instead.
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
	_ datasource.DataSource              = (*windowsFileACLDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsFileACLDataSource)(nil)
)

// NewWindowsFileACLDataSource is the constructor registered in provider.go.
func NewWindowsFileACLDataSource() datasource.DataSource {
	return &windowsFileACLDataSource{}
}

// windowsFileACLDataSource is the TPF data source type for windows_file_acl.
type windowsFileACLDataSource struct {
	client winclient.FileACLClient
}

// fileACLDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block. It reuses the sibling resource default
// (fileACLDefaultTimeout) so a stalled session surfaces a timeout diagnostic
// instead of blocking plan forever (issue #197).
const fileACLDSDefaultTimeout = fileACLDefaultTimeout

// windowsFileACLDataSourceModel is the Terraform state model for the
// windows_file_acl data source.
type windowsFileACLDataSourceModel struct {
	ID                 types.String     `tfsdk:"id"`
	Path               types.String     `tfsdk:"path"`
	Owner              types.String     `tfsdk:"owner"`
	OwnerSID           types.String     `tfsdk:"owner_sid"`
	TargetType         types.String     `tfsdk:"target_type"`
	InheritanceEnabled types.Bool       `tfsdk:"inheritance_enabled"`
	SDDL               types.String     `tfsdk:"sddl"`
	EffectiveRules     types.List       `tfsdk:"effective_access_rules"`
	Timeouts           dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_file_acl").
func (d *windowsFileACLDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file_acl"
}

// Schema returns the TPF schema for the windows_file_acl data source.
func (d *windowsFileACLDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed NTFS security descriptor of an existing file or directory " +
			"without managing it.\n\n" +
			"Declarative attributes of the sibling resource (`mode`, `access_rule`, " +
			"`preserve_inherited_on_protect`) are intentionally absent: the observed DACL is exposed " +
			"read-only through `effective_access_rules` instead.\n\n" +
			"Returns an error when the target does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the normalised absolute path of the secured target.",
			},
			"path": schema.StringAttribute{
				Required:    true,
				Description: "Absolute path of the file or directory whose security descriptor is read. The target must already exist.",
			},
			"owner": schema.StringAttribute{
				Computed:    true,
				Description: "Owner of the target as reported by the host (display name form).",
			},
			"owner_sid": schema.StringAttribute{
				Computed:    true,
				Description: "Canonical SID of the observed owner.",
			},
			"target_type": schema.StringAttribute{
				Computed:    true,
				Description: "Whether the target is a file or a directory, as observed on the host.",
			},
			"inheritance_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the target inherits permissions from its parent, as observed on the host.",
			},
			"sddl": schema.StringAttribute{
				Computed:    true,
				Description: "Security descriptor of the target in SDDL form, as observed on the host.",
			},
			"effective_access_rules": schema.ListAttribute{
				Computed:    true,
				ElementType: fileACLEffectiveRuleObjectType,
				MarkdownDescription: "Every entry of the observed DACL, inherited ones included, in the order " +
					"Windows returns them. Each element carries `identity`, `identity_sid`, `rights`, " +
					"`access_mask`, `type`, `inheritance`, `propagation` and `inherited`.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to fileACLDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsFileACLDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewFileACLClient(c)
}

// Read fetches the security descriptor from the remote Windows host by calling
// the sibling resource's FileACLClient.Read with the configured path. A nil
// result from the client triggers a `not found` diagnostic (data sources never
// silently clear state). Other typed *winclient.FileACLError values are surfaced
// via addFileACLDiag, mirroring the resource Read path.
func (d *windowsFileACLDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsFileACLDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, fileACLDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Path.ValueString()
	tflog.Debug(ctx, "windows_file_acl data source Read start", map[string]interface{}{"path": target})

	observed, err := d.client.Read(ctx, target)
	if err != nil {
		var fe *winclient.FileACLError
		if errors.As(err, &fe) && fe.Kind == winclient.FileACLErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_file_acl %q", target),
				fmt.Sprintf("No file or directory %q was found on the target host.", target),
			)
			return
		}
		addFileACLDiag(&resp.Diagnostics, "Read data source", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_file_acl %q", target),
			fmt.Sprintf("No file or directory %q was found on the target host.", target),
		)
		return
	}

	rules, dgs := fileACLEffectiveList(ctx, observed.AccessRules)
	resp.Diagnostics.Append(dgs...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsFileACLDataSourceModel{
		ID:                 types.StringValue(observed.Path),
		Path:               types.StringValue(observed.Path),
		Owner:              types.StringValue(observed.Owner),
		OwnerSID:           types.StringValue(observed.OwnerSID),
		TargetType:         types.StringValue(observed.TargetType),
		InheritanceEnabled: types.BoolValue(observed.InheritanceEnabled),
		SDDL:               types.StringValue(observed.SDDL),
		EffectiveRules:     rules,
		Timeouts:           config.Timeouts,
	}

	tflog.Debug(ctx, "windows_file_acl data source Read end", map[string]interface{}{
		"path":        state.Path.ValueString(),
		"target_type": state.TargetType.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
