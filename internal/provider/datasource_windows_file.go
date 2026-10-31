// Package provider: windows_file data source implementation.
//
// Reads the observed metadata of an existing file without managing it.
// All declarative input attributes of the resource (content,
// content_base64, write-only content, source, source_url, encoding,
// overwrite, create_parent_directories, attributes) are absent from this
// data source: the observed metadata is exposed read-only instead.
//
// DESIGN DECISION (issue #206, final quarter of the file/data-source
// campaign): this data source is METADATA-ONLY by explicit decision — it
// exposes id/path plus content_sha256/size_bytes/last_write_time and NOT
// content/content_base64. Rationale: returning file content from a data
// source would persist arbitrary host file bytes (frequently secrets, keys,
// configs) into terraform state on every read/plan, and winclient caps
// content with truncation anyway; metadata + digest covers the stated use
// cases (existence check, hash for triggers block, pre-deploy read). This
// matches the issue's first option ("expose metadata plus content_sha256
// only").
//
// How the digest is obtained without content: the data source reuses the
// sibling resource's FileClient.Read metadata path, which never transfers
// file bytes. The host computes the SHA-256 itself (Get-FileSha256 over a
// ReadWrite-shared open, via Build-FileData) and returns only the hex
// digest, size and timestamp. The byte-transferring ReadContent path stays
// reserved for the resource ImportState flow and is deliberately not used
// here; content fields are never mapped into state.
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
	_ datasource.DataSource              = (*windowsFileDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsFileDataSource)(nil)
)

// NewWindowsFileDataSource is the constructor registered in provider.go.
func NewWindowsFileDataSource() datasource.DataSource {
	return &windowsFileDataSource{}
}

// windowsFileDataSource is the TPF data source type for windows_file.
type windowsFileDataSource struct {
	client winclient.FileClient
}

// fileDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block. It reuses the sibling resource default
// (fileDefaultTimeout) so a stalled session surfaces a timeout diagnostic
// instead of blocking plan forever (issue #197).
const fileDSDefaultTimeout = fileDefaultTimeout

// windowsFileDataSourceModel is the Terraform state model for the
// windows_file data source.
type windowsFileDataSourceModel struct {
	ID            types.String     `tfsdk:"id"`
	Path          types.String     `tfsdk:"path"`
	ContentSHA256 types.String     `tfsdk:"content_sha256"`
	SizeBytes     types.Int64      `tfsdk:"size_bytes"`
	LastWriteTime types.String     `tfsdk:"last_write_time"`
	Timeouts      dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_file").
func (d *windowsFileDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

// Schema returns the TPF schema for the windows_file data source.
func (d *windowsFileDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed metadata of an existing file on a remote " +
			"Windows host without managing it.\n\n" +
			"Metadata only by design: the data source exposes the file digest " +
			"(`content_sha256`), size and last write time, never the file " +
			"content itself, so host secrets are not persisted into Terraform " +
			"state. Use the digest for existence checks, `triggers` blocks and " +
			"pre-deploy reads.\n\n" +
			"Declarative attributes of the sibling resource (`content`, " +
			"`source`, `source_url`, `encoding`, `overwrite`, " +
			"`create_parent_directories`, `attributes`) are intentionally absent: " +
			"the observed metadata is exposed read-only instead.\n\n" +
			"Returns an error when the file does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the normalised absolute path of the file.",
			},
			"path": schema.StringAttribute{
				Required:    true,
				Description: "Absolute path of the file on the target host. The file must already exist.",
			},
			"content_sha256": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 digest of the file content in lowercase hex, as observed on the host.",
			},
			"size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Size of the file in bytes, as observed on the host.",
			},
			"last_write_time": schema.StringAttribute{
				Computed:    true,
				Description: "Last write timestamp of the file, ISO 8601 UTC, as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to fileDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsFileDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewFileClient(c)
}

// Read fetches the observed file metadata from the remote Windows host by
// calling the sibling resource's FileClient.Read with the configured path.
// The metadata path never transfers file bytes: the host returns the digest,
// size and timestamp only (see the package design note). A nil result from
// the client triggers a `not found` diagnostic (data sources never silently
// clear state). Other typed *winclient.FileError values are surfaced via
// addFileDiag, mirroring the resource Read path.
func (d *windowsFileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsFileDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, fileDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Path.ValueString()
	tflog.Debug(ctx, "windows_file data source Read start", map[string]interface{}{"path": target})

	observed, err := d.client.Read(ctx, target)
	if err != nil {
		var fe *winclient.FileError
		if errors.As(err, &fe) && fe.Kind == winclient.FileErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_file %q", target),
				fmt.Sprintf("No file %q was found on the target host.", target),
			)
			return
		}
		addFileDiag(&resp.Diagnostics, "Read data source", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_file %q", target),
			fmt.Sprintf("No file %q was found on the target host.", target),
		)
		return
	}

	state := windowsFileDataSourceModel{
		ID:            types.StringValue(observed.Path),
		Path:          types.StringValue(observed.Path),
		ContentSHA256: types.StringValue(observed.SHA256),
		SizeBytes:     types.Int64Value(observed.SizeBytes),
		LastWriteTime: types.StringValue(observed.LastWriteTime),
		Timeouts:      config.Timeouts,
	}

	tflog.Debug(ctx, "windows_file data source Read end", map[string]interface{}{
		"path":       state.Path.ValueString(),
		"size_bytes": state.SizeBytes.ValueInt64(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
