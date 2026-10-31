// Package provider: windows_legacy_package data source implementation.
//
// Reads the observed state of a legacy Windows package (MSI ProductCode or
// EXE DisplayName) without managing its lifecycle. All install-only input
// attributes of the resource (installer_type, source_path, source_url,
// checksum, install_args, uninstall_args, uninstall_command, valid_exit_codes,
// working_directory, timeout_seconds, log_path, environment, name) are absent
// from this data source.
package provider

import (
	"context"
	"fmt"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
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
	_ datasource.DataSource                     = (*windowsLegacyPackageDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*windowsLegacyPackageDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*windowsLegacyPackageDataSource)(nil)
)

// NewWindowsLegacyPackageDataSource is the constructor registered in provider.go.
func NewWindowsLegacyPackageDataSource() datasource.DataSource {
	return &windowsLegacyPackageDataSource{}
}

// windowsLegacyPackageDataSource is the TPF data source type for windows_legacy_package.
type windowsLegacyPackageDataSource struct {
	lp winclient.LegacyPackageClient
}

// legacyPackageDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (lpDefaultTimeout) so a stalled session surfaces a timeout
// diagnostic instead of blocking plan forever (issue #197).
const legacyPackageDSDefaultTimeout = lpDefaultTimeout

// windowsLegacyPackageDataSourceModel is the Terraform state model for the
// windows_legacy_package data source.
type windowsLegacyPackageDataSourceModel struct {
	ID               types.String     `tfsdk:"id"`
	ProductID        types.String     `tfsdk:"product_id"`
	DisplayName      types.String     `tfsdk:"display_name"`
	Installed        types.Bool       `tfsdk:"installed"`
	InstalledVersion types.String     `tfsdk:"installed_version"`
	InstallDate      types.String     `tfsdk:"install_date"`
	Timeouts         dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_legacy_package").
func (d *windowsLegacyPackageDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_legacy_package"
}

// Schema returns the TPF schema for the windows_legacy_package data source.
func (d *windowsLegacyPackageDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a legacy Windows package (MSI or EXE installer) " +
			"without managing its lifecycle. Exactly one of `product_id` (MSI ProductCode GUID) or " +
			"`display_name` (exact EXE `DisplayName`) must be provided as the lookup key.\n\n" +
			"Install-only attributes of the sibling resource (`installer_type`, `source_path`, `source_url`, " +
			"`checksum`, `install_args`, ...) are intentionally absent.\n\n" +
			"Returns an error when no matching package is found in the Uninstall registry hives.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: ProductCode GUID for MSI, resolved exact DisplayName for EXE.",
			},
			"product_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "MSI ProductCode GUID (e.g. \"{01234567-89AB-CDEF-0123-456789ABCDEF}\"). Exactly one of product_id or display_name must be specified.",
				MarkdownDescription: "MSI **ProductCode** GUID. Exactly one of `product_id` or `display_name` must be specified.",
			},
			"display_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Exact DisplayName of an EXE install as recorded in the Uninstall registry hive (verbatim, case-sensitive match). Exactly one of product_id or display_name must be specified.",
				MarkdownDescription: "Exact `DisplayName` of an EXE install as recorded in the Uninstall registry hive (verbatim, case-sensitive match). Exactly one of `product_id` or `display_name` must be specified.",
			},
			"installed": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the package is currently detected on the host (always true when the lookup succeeds).",
			},
			"installed_version": schema.StringAttribute{
				Computed:    true,
				Description: "DisplayVersion read from the Uninstall registry entry.",
			},
			"install_date": schema.StringAttribute{
				Computed:    true,
				Description: "Install date from registry InstallDate, normalized to ISO-8601 when parseable.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to legacyPackageDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// ConfigValidators enforces ExactlyOneOf(product_id, display_name).
func (d *windowsLegacyPackageDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("product_id"),
			path.MatchRoot("display_name"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsLegacyPackageDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.lp = winclient.NewLegacyPackageClient(c)
}

// Read fetches the package state from the remote Windows host by calling the
// sibling resource's LegacyPackageClient.Read with the configured lookup key
// (a GUID-in-braces resolves as an MSI ProductCode, anything else as an exact
// DisplayName, exactly as the resource Read does). A nil result from the
// client triggers a `not found` diagnostic (data sources never silently
// clear state). Typed *winclient.LegacyPackageError values are surfaced via
// addLPDiag, mirroring the resource Read path.
func (d *windowsLegacyPackageDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsLegacyPackageDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, legacyPackageDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	key := config.ProductID.ValueString()
	if config.ProductID.IsNull() || key == "" {
		key = config.DisplayName.ValueString()
	}
	tflog.Debug(ctx, "windows_legacy_package data source Read start", map[string]interface{}{"key": key})

	remote, err := d.lp.Read(ctx, key)
	if err != nil {
		addLPDiag(&resp.Diagnostics, err, "Read data source")
		return
	}
	if remote == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_legacy_package %q", key),
			fmt.Sprintf("No legacy package %q was found in the Uninstall registry hives on the target host.", key),
		)
		return
	}

	state := windowsLegacyPackageDataSourceModel{
		ID:               types.StringValue(remote.ID),
		ProductID:        types.StringValue(remote.ProductID),
		DisplayName:      config.DisplayName,
		Installed:        types.BoolValue(remote.Installed),
		InstalledVersion: types.StringValue(remote.InstalledVersion),
		InstallDate:      types.StringValue(remote.InstallDate),
		Timeouts:         config.Timeouts,
	}

	tflog.Debug(ctx, "windows_legacy_package data source Read end", map[string]interface{}{
		"id":                state.ID.ValueString(),
		"installed":         state.Installed.ValueBool(),
		"installed_version": state.InstalledVersion.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
