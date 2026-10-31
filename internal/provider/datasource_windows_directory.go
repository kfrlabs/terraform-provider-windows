// Package provider: windows_directory data source implementation.
//
// Reads the observed state of an existing directory without managing it.
// All declarative input attributes of the resource (ensure,
// recursive_delete, create_parent_directories) are absent from this data
// source: the observed state (attributes included) is exposed read-only
// instead.
package provider

import (
	"context"
	"errors"
	"fmt"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsDirectoryDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsDirectoryDataSource)(nil)
)

// NewWindowsDirectoryDataSource is the constructor registered in provider.go.
func NewWindowsDirectoryDataSource() datasource.DataSource {
	return &windowsDirectoryDataSource{}
}

// windowsDirectoryDataSource is the TPF data source type for windows_directory.
type windowsDirectoryDataSource struct {
	client winclient.DirectoryClient
}

// directoryDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block. It reuses the sibling resource default
// (directoryDefaultTimeout) so a stalled session surfaces a timeout diagnostic
// instead of blocking plan forever (issue #197).
const directoryDSDefaultTimeout = directoryDefaultTimeout

// windowsDirectoryDataSourceModel is the Terraform state model for the
// windows_directory data source.
type windowsDirectoryDataSourceModel struct {
	ID             types.String     `tfsdk:"id"`
	Path           types.String     `tfsdk:"path"`
	ExistsChildren types.Bool       `tfsdk:"exists_children"`
	ItemCount      types.Int64      `tfsdk:"item_count"`
	LastWriteTime  types.String     `tfsdk:"last_write_time"`
	Attributes     types.List       `tfsdk:"attributes"`
	Timeouts       dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_directory").
func (d *windowsDirectoryDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_directory"
}

// Schema returns the TPF schema for the windows_directory data source.
func (d *windowsDirectoryDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of an existing directory on a remote " +
			"Windows host without managing it.\n\n" +
			"Declarative attributes of the sibling resource (`ensure`, `recursive_delete`, " +
			"`create_parent_directories`) are intentionally absent: the observed state is exposed " +
			"read-only instead.\n\n" +
			"Returns an error when the directory does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the normalised absolute path of the directory.",
			},
			"path": schema.StringAttribute{
				Required:    true,
				Description: "Absolute path of the directory on the target host. The directory must already exist.",
			},
			"exists_children": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the directory directly contains at least one file or sub-directory, as observed on the host.",
			},
			"item_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of items (files and sub-directories) directly contained in the directory (non-recursive), as observed on the host.",
			},
			"last_write_time": schema.StringAttribute{
				Computed:    true,
				Description: "Last write timestamp of the directory, ISO 8601 UTC, as observed on the host.",
			},
			"attributes": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Directory attributes observed on the host: hidden, readonly, system.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to directoryDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsDirectoryDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewDirectoryClient(c)
}

// Read fetches the observed directory state from the remote Windows host by
// calling the sibling resource's DirectoryClient.Read with the configured
// path. A nil result from the client triggers a `not found` diagnostic (data
// sources never silently clear state). Other typed *winclient.DirectoryError
// values are surfaced via addDirectoryDiag, mirroring the resource Read path.
func (d *windowsDirectoryDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsDirectoryDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, directoryDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Path.ValueString()
	tflog.Debug(ctx, "windows_directory data source Read start", map[string]interface{}{"path": target})

	observed, err := d.client.Read(ctx, target)
	if err != nil {
		var de *winclient.DirectoryError
		if errors.As(err, &de) && de.Kind == winclient.DirectoryErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_directory %q", target),
				fmt.Sprintf("No directory %q was found on the target host.", target),
			)
			return
		}
		addDirectoryDiag(&resp.Diagnostics, "Read data source", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_directory %q", target),
			fmt.Sprintf("No directory %q was found on the target host.", target),
		)
		return
	}

	attrs := observed.Attributes
	if attrs == nil {
		attrs = []string{}
	}
	elems := make([]attr.Value, len(attrs))
	for i, a := range attrs {
		elems[i] = types.StringValue(a)
	}
	attrList, dgs := types.ListValue(types.StringType, elems)
	resp.Diagnostics.Append(dgs...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsDirectoryDataSourceModel{
		ID:             types.StringValue(observed.Path),
		Path:           types.StringValue(observed.Path),
		ExistsChildren: types.BoolValue(observed.ExistsChildren),
		ItemCount:      types.Int64Value(observed.ItemCount),
		LastWriteTime:  types.StringValue(observed.LastWriteTime),
		Attributes:     attrList,
		Timeouts:       config.Timeouts,
	}

	tflog.Debug(ctx, "windows_directory data source Read end", map[string]interface{}{
		"path":       state.Path.ValueString(),
		"item_count": state.ItemCount.ValueInt64(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
