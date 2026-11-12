// Package provider: windows_os_info data source implementation.
//
// Standalone singleton data source — no lookup keys and no sibling
// resource. Reads the OS inventory of the remote Windows host (product,
// build, edition, SKU, server role, architecture, dates, paths, language,
// PowerShell version, machine ID).
package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsOSInfoDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsOSInfoDataSource)(nil)
)

// NewWindowsOSInfoDataSource is the constructor registered in provider.go.
func NewWindowsOSInfoDataSource() datasource.DataSource {
	return &windowsOSInfoDataSource{}
}

// windowsOSInfoDataSource is the TPF data source type for windows_os_info.
type windowsOSInfoDataSource struct {
	osinfo winclient.WindowsOSInfoClient
}

// osInfoDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block, so a stalled session surfaces a timeout
// diagnostic instead of blocking plan forever (issue #197).
const osInfoDSDefaultTimeout = 1 * time.Minute

// windowsOSInfoDataSourceModel is the Terraform state model for the
// windows_os_info data source.
type windowsOSInfoDataSourceModel struct {
	ID                types.String     `tfsdk:"id"`
	ProductName       types.String     `tfsdk:"product_name"`
	Version           types.String     `tfsdk:"version"`
	BuildNumber       types.Int64      `tfsdk:"build_number"`
	UBR               types.Int64      `tfsdk:"ubr"`
	FullBuild         types.String     `tfsdk:"full_build"`
	DisplayVersion    types.String     `tfsdk:"display_version"`
	EditionID         types.String     `tfsdk:"edition_id"`
	SKU               types.Int64      `tfsdk:"sku"`
	SKUName           types.String     `tfsdk:"sku_name"`
	InstallationType  types.String     `tfsdk:"installation_type"`
	IsServer          types.Bool       `tfsdk:"is_server"`
	IsServerCore      types.Bool       `tfsdk:"is_server_core"`
	ProductType       types.String     `tfsdk:"product_type"`
	Architecture      types.String     `tfsdk:"architecture"`
	InstallDate       types.String     `tfsdk:"install_date"`
	LastBootTime      types.String     `tfsdk:"last_boot_time"`
	SystemDrive       types.String     `tfsdk:"system_drive"`
	WindowsDirectory  types.String     `tfsdk:"windows_directory"`
	OSLanguage        types.String     `tfsdk:"os_language"`
	PowerShellVersion types.String     `tfsdk:"powershell_version"`
	Timeouts          dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_os_info").
func (d *windowsOSInfoDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_os_info"
}

// Schema returns the TPF schema for the windows_os_info data source.
func (d *windowsOSInfoDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the OS inventory of the remote Windows host without " +
			"managing it. This is a **singleton** data source — no lookup keys are required.\n\n" +
			"Exposes `product_name`, `version`, `build_number` / `ubr` (combined as `full_build`), " +
			"`display_version`, `edition_id`, the numeric `sku` with its `sku_name`, `installation_type`, " +
			"`is_server` / `is_server_core`, `product_type`, `architecture`, `install_date`, " +
			"`last_boot_time`, `system_drive`, `windows_directory`, `os_language`, `powershell_version`, " +
			"and the stable machine ID (HKLM MachineGuid), exposed as the resource `id`.\n\n" +
			"The Terraform data source ID is the stable machine ID (HKLM MachineGuid).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; the stable machine ID (HKLM MachineGuid).",
			},
			"product_name": schema.StringAttribute{
				Computed:    true,
				Description: "OS caption (Win32_OperatingSystem.Caption).",
			},
			"version": schema.StringAttribute{
				Computed:    true,
				Description: "OS version (Win32_OperatingSystem.Version).",
			},
			"build_number": schema.Int64Attribute{
				Computed:    true,
				Description: "OS build (HKLM CurrentVersion CurrentBuild).",
			},
			"ubr": schema.Int64Attribute{
				Computed:    true,
				Description: "Update build revision (HKLM CurrentVersion UBR).",
			},
			"full_build": schema.StringAttribute{
				Computed:    true,
				Description: "Build number, or build.ubr when UBR is greater than zero.",
			},
			"display_version": schema.StringAttribute{
				Computed:    true,
				Description: "Friendly version (CurrentVersion DisplayVersion, ReleaseId on older hosts).",
			},
			"edition_id": schema.StringAttribute{
				Computed:    true,
				Description: "OS edition (CurrentVersion EditionID).",
			},
			"sku": schema.Int64Attribute{
				Computed:    true,
				Description: "Numeric OS SKU (Win32_OperatingSystem.OperatingSystemSKU).",
			},
			"sku_name": schema.StringAttribute{
				Computed:    true,
				Description: "SKU mapped to its documented product name; empty when unknown.",
			},
			"installation_type": schema.StringAttribute{
				Computed:    true,
				Description: "Installation type (CurrentVersion InstallationType).",
			},
			"is_server": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the product type is DomainController or Server; false otherwise, including unknown values.",
			},
			"is_server_core": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the installation type is Server Core.",
			},
			"product_type": schema.StringAttribute{
				Computed:    true,
				Description: "Product type name: Workstation, DomainController or Server; empty when unknown.",
			},
			"architecture": schema.StringAttribute{
				Computed:    true,
				Description: "Processor architecture name: x86, arm, x64 or arm64; empty when unknown.",
			},
			"install_date": schema.StringAttribute{
				Computed:    true,
				Description: "OS install time in UTC RFC 3339; empty when unavailable.",
			},
			"last_boot_time": schema.StringAttribute{
				Computed:    true,
				Description: "Last boot time in UTC RFC 3339; empty when unavailable.",
			},
			"system_drive": schema.StringAttribute{
				Computed:    true,
				Description: "System drive (Win32_OperatingSystem.SystemDrive).",
			},
			"windows_directory": schema.StringAttribute{
				Computed:    true,
				Description: "Windows directory (Win32_OperatingSystem.WindowsDirectory).",
			},
			"os_language": schema.StringAttribute{
				Computed:    true,
				Description: "OS culture name; empty when unavailable.",
			},
			"powershell_version": schema.StringAttribute{
				Computed:    true,
				Description: "Responding PowerShell engine version.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to osInfoDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsOSInfoDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.osinfo = winclient.NewOSInfoClient(c)
}

// Read fetches the current OS inventory from the remote Windows host.
func (d *windowsOSInfoDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsOSInfoDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, osInfoDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_os_info data source Read start")

	live, err := d.osinfo.Read(ctx)
	if err != nil {
		addOSInfoDiag(&resp.Diagnostics, "Read windows_os_info data source failed", err)
		return
	}
	if live == nil {
		resp.Diagnostics.AddError(
			"Read windows_os_info data source failed",
			"The host returned an empty OS inventory.",
		)
		return
	}

	// The ID is the stable machine ID. MachineGuid should always be
	// present; fall back to the singleton literal instead of an empty ID,
	// which Terraform forbids.
	id := live.MachineID
	if id == "" {
		id = "current"
	}

	state := windowsOSInfoDataSourceModel{
		ID:                types.StringValue(id),
		ProductName:       types.StringValue(live.ProductName),
		Version:           types.StringValue(live.Version),
		BuildNumber:       types.Int64Value(live.BuildNumber),
		UBR:               types.Int64Value(live.UBR),
		FullBuild:         types.StringValue(live.FullBuild),
		DisplayVersion:    types.StringValue(live.DisplayVersion),
		EditionID:         types.StringValue(live.EditionID),
		SKU:               types.Int64Value(live.SKU),
		SKUName:           types.StringValue(live.SKUName),
		InstallationType:  types.StringValue(live.InstallationType),
		IsServer:          types.BoolValue(live.IsServer),
		IsServerCore:      types.BoolValue(live.IsServerCore),
		ProductType:       types.StringValue(live.ProductType),
		Architecture:      types.StringValue(live.Architecture),
		InstallDate:       types.StringValue(live.InstallDate),
		LastBootTime:      types.StringValue(live.LastBootTime),
		SystemDrive:       types.StringValue(live.SystemDrive),
		WindowsDirectory:  types.StringValue(live.WindowsDirectory),
		OSLanguage:        types.StringValue(live.OSLanguage),
		PowerShellVersion: types.StringValue(live.PowerShellVersion),
		Timeouts:          config.Timeouts,
	}

	tflog.Debug(ctx, "windows_os_info data source Read end", map[string]interface{}{
		"product_name": state.ProductName.ValueString(),
		"full_build":   state.FullBuild.ValueString(),
		"machine_id":   state.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// addOSInfoDiag converts a *winclient.OSInfoError into a TPF diagnostic.
func addOSInfoDiag(diags *diag.Diagnostics, summary string, err error) {
	var oe *winclient.OSInfoError
	if errors.As(err, &oe) {
		detail := oe.Message
		if len(oe.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range oe.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if oe.Cause != nil {
			detail += "\n\nCause: " + oe.Cause.Error()
		}
		if oe.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", oe.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
