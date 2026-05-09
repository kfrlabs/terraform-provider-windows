// Package provider: windows_winget_package data source implementation.
//
// Read-only data source returning the state of a single winget-managed
// package on a remote Windows host. Mirrors the windows_winget_package
// resource Read path via PowerShell Remoting (WinRM) using the
// Microsoft.WinGet.Client module.
//
// REUSES the existing winclient.WingetPackageClient interface from the
// twin resource — no new winclient files, no new client interface, no new
// State type.
//
// Spec alignment: windows_winget_package data source spec v1 (2026-05-09).
package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsWingetPackageDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsWingetPackageDataSource)(nil)
)

// NewWindowsWingetPackageDataSource is the constructor registered in provider.go.
func NewWindowsWingetPackageDataSource() datasource.DataSource {
	return &windowsWingetPackageDataSource{}
}

// windowsWingetPackageDataSource is the TPF data source type for
// windows_winget_package. The client field reuses the twin resource's
// WingetPackageClient interface as-is (no dedicated DS interface).
type windowsWingetPackageDataSource struct {
	client winclient.WingetPackageClient
}

// windowsWingetPackageDataSourceModel is the Terraform state model for the
// data source. Field tags match attribute keys in the schema below.
type windowsWingetPackageDataSourceModel struct {
	ID                types.String `tfsdk:"id"`
	PackageID         types.String `tfsdk:"package_id"`
	Source            types.String `tfsdk:"source"`
	Name              types.String `tfsdk:"name"`
	InstalledVersion  types.String `tfsdk:"installed_version"`
	AvailableVersion  types.String `tfsdk:"available_version"`
	IsInstalled       types.Bool   `tfsdk:"is_installed"`
	IsUpdateAvailable types.Bool   `tfsdk:"is_update_available"`
}

// Metadata sets the data source type name ("windows_winget_package").
func (d *windowsWingetPackageDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_winget_package"
}

// Schema returns the TPF schema for the windows_winget_package data source.
func (d *windowsWingetPackageDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = datasourceschema.Schema{
		MarkdownDescription: "Reads the state of a single winget-managed package on a remote Windows host " +
			"via WinRM + the `Microsoft.WinGet.Client` PowerShell module. " +
			"Returns a Terraform error if the package is absent from both the winget catalog and ARP.",

		Attributes: map[string]datasourceschema.Attribute{
			"id": datasourceschema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Synthesized data source id formatted as `\"<source>:<package_id>\"`. " +
					"Recomputed on every Read.",
			},

			"package_id": datasourceschema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]*(\.[A-Za-z0-9][A-Za-z0-9._+\-]*)*$`),
						"must be a valid winget package id (alphanumerics, dots, underscores, plus, hyphens)",
					),
				},
				MarkdownDescription: "Winget package identifier (e.g. `Microsoft.PowerShell`). " +
					"Exact-match lookup key; case-insensitive `Equals` comparison applied client-side.",
			},

			"source": datasourceschema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf("winget", "msstore", ""),
				},
				MarkdownDescription: "Winget source to query. One of `winget`, `msstore`, or `\"\"` (ARP-only entries). " +
					"Optional input; defaults to `winget` when not set. Echoed back as computed so users can read " +
					"the effective value (set to `\"\"` when the match is detected as ARP-only).",
			},

			"name": datasourceschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`DisplayName` as reported by winget for the matched package.",
			},

			"installed_version": datasourceschema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Currently installed version on the target host. " +
					"Empty string when the package is present in the catalog but not installed.",
			},

			"available_version": datasourceschema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Latest version available from the source catalog. " +
					"Empty when the entry is ARP-only (legacy MSI/EXE visible to winget without a source).",
			},

			"is_installed": datasourceschema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "`true` when `installed_version` is non-empty.",
			},

			"is_update_available": datasourceschema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "`true` when both `installed_version` and `available_version` are " +
					"non-empty and differ.",
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the WingetPackageClient (reusing the resource's client).
func (d *windowsWingetPackageDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewWingetPackageClient(c)
}

// Read fetches the winget package state from the remote Windows host.
// STUB — to be implemented by the provider-coder follow-up task.
func (d *windowsWingetPackageDataSource) Read(_ context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	resp.Diagnostics.AddError(
		"not implemented",
		"windows_winget_package data source Read is not implemented yet.",
	)
}
