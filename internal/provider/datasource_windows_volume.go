// Package provider: windows_volume data source implementation.
//
// Reads the observed state of a formatted volume on a remote Windows host
// without managing it. Lookup is by exactly one of drive_letter, unique_id
// or file_system_label, and reuses the sibling resource's
// winclient.WindowsVolumeClient (no new winclient code).
package provider

import (
	"context"
	"fmt"
	"strings"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource                     = (*windowsVolumeDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*windowsVolumeDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*windowsVolumeDataSource)(nil)
)

// NewWindowsVolumeDataSource is the constructor registered in provider.go.
func NewWindowsVolumeDataSource() datasource.DataSource {
	return &windowsVolumeDataSource{}
}

// windowsVolumeDataSource is the TPF data source type for windows_volume.
type windowsVolumeDataSource struct {
	volumes winclient.WindowsVolumeClient
}

// volumeDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block. It reuses the sibling resource default
// (volumeDefaultTimeout) so a stalled session surfaces a timeout diagnostic
// instead of blocking plan forever.
const volumeDSDefaultTimeout = volumeDefaultTimeout

// windowsVolumeDataSourceModel is the Terraform state model for the
// windows_volume data source.
type windowsVolumeDataSourceModel struct {
	ID                 types.String     `tfsdk:"id"`
	DriveLetter        types.String     `tfsdk:"drive_letter"`
	UniqueID           types.String     `tfsdk:"unique_id"`
	FileSystemLabel    types.String     `tfsdk:"file_system_label"`
	PartitionID        types.String     `tfsdk:"partition_id"`
	FileSystem         types.String     `tfsdk:"file_system"`
	AllocationUnitSize types.Int64      `tfsdk:"allocation_unit_size"`
	Path               types.String     `tfsdk:"path"`
	SizeBytes          types.Int64      `tfsdk:"size_bytes"`
	SizeRemainingBytes types.Int64      `tfsdk:"size_remaining_bytes"`
	HealthStatus       types.String     `tfsdk:"health_status"`
	OperationalStatus  types.String     `tfsdk:"operational_status"`
	DriveType          types.String     `tfsdk:"drive_type"`
	Timeouts           dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_volume", the same
// Terraform type name as the sibling resource per ADR-0009).
func (d *windowsVolumeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_volume"
}

// Schema returns the TPF schema for the windows_volume data source.
func (d *windowsVolumeDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a formatted volume on a remote Windows host via SSH and " +
			"PowerShell (`Get-Volume`) without managing it.\n\n" +
			"Lookup is by exactly one of `drive_letter` (a single letter, `C` allowed: reads never change " +
			"the volume), `unique_id` (the stable `\\\\?\\Volume{...}\\` identity, preferred) or " +
			"`file_system_label` (exact, case-insensitive; several matches are an error). Zero matches are " +
			"an error, as is an unformatted (null/RAW file system) match.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier; the stable Get-Volume UniqueId of the observed volume.",
			},
			"drive_letter": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Single drive letter A-Z (an optional trailing colon is allowed; `C` is allowed) of the volume to look up. Exactly one of drive_letter, unique_id and file_system_label must be specified.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"unique_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Stable Get-Volume UniqueId of the volume to look up. Exactly one of drive_letter, unique_id and file_system_label must be specified.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"file_system_label": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Exact Get-Volume FileSystemLabel of the volume to look up, matched case-insensitively. Exactly one of drive_letter, unique_id and file_system_label must be specified; several matches are an error.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"partition_id": schema.StringAttribute{
				Computed:    true,
				Description: "Hosting partition in `<disk_unique_id>|<guid_or_offset>` form, as observed on the host (the `partition_id` a sibling `windows_volume` resource would manage).",
			},
			"file_system": schema.StringAttribute{
				Computed:    true,
				Description: "File system of the volume (NTFS, ReFS, exFAT, FAT32), as observed on the host.",
			},
			"allocation_unit_size": schema.Int64Attribute{
				Computed:    true,
				Description: "Allocation unit (cluster) size in bytes, as observed on the host.",
			},
			"path": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume Path, as observed on the host.",
			},
			"size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Get-Volume Size in bytes, as observed on the host.",
			},
			"size_remaining_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Get-Volume SizeRemaining in bytes, as observed on the host.",
			},
			"health_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume HealthStatus (e.g. Healthy), as observed on the host.",
			},
			"operational_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume OperationalStatus (e.g. OK), as observed on the host.",
			},
			"drive_type": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume DriveType (e.g. Fixed), as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to volumeDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// ConfigValidators enforces ExactlyOneOf over the three lookups.
func (d *windowsVolumeDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("drive_letter"),
			path.MatchRoot("unique_id"),
			path.MatchRoot("file_system_label"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsVolumeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.volumes = winclient.NewVolumeClient(c)
}

// Read fetches the observed volume state from the remote Windows host by
// calling the sibling resource's WindowsVolumeClient. A nil result or a
// typed error surfaces as a diagnostic (data sources never silently clear
// state).
func (d *windowsVolumeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsVolumeDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, volumeDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	lookup, ok := volumeLookupFromTF(config.DriveLetter, config.UniqueID, config.FileSystemLabel)
	if !ok {
		resp.Diagnostics.AddError(
			"Missing volume lookup",
			"Exactly one of drive_letter, unique_id and file_system_label must be set.",
		)
		return
	}

	tflog.Debug(ctx, "windows_volume data source Read start", map[string]interface{}{"lookup": lookup.Describe()})

	info, err := d.volumes.Lookup(ctx, lookup)
	if err != nil {
		addVolumeDiag(&resp.Diagnostics, fmt.Sprintf("Read data source windows_volume (%s) failed", lookup.Describe()), err)
		return
	}

	state := windowsVolumeDataSourceModel{
		ID:                 types.StringValue(info.UniqueID),
		DriveLetter:        volumeStringOrNull(info.DriveLetter),
		UniqueID:           types.StringValue(info.UniqueID),
		FileSystemLabel:    volumeStringOrNull(info.FileSystemLabel),
		PartitionID:        volumeStringOrNull(info.PartitionID),
		FileSystem:         types.StringValue(info.FileSystem),
		AllocationUnitSize: volumeInt64OrNull(info.AllocationUnitSize),
		Path:               types.StringValue(info.Path),
		SizeBytes:          types.Int64Value(info.SizeBytes),
		SizeRemainingBytes: types.Int64Value(info.SizeRemainingBytes),
		HealthStatus:       types.StringValue(info.HealthStatus),
		OperationalStatus:  types.StringValue(info.OperationalStatus),
		DriveType:          types.StringValue(info.DriveType),
		Timeouts:           config.Timeouts,
	}

	tflog.Debug(ctx, "windows_volume data source Read end", map[string]interface{}{
		"unique_id": state.UniqueID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// volumeLookupFromTF builds a winclient.VolumeLookup from the three Terraform
// lookup values. The second return is false when the values do not carry
// exactly one lookup (the schema ExactlyOneOf validator normally prevents
// this; the check is defence in depth for direct API use). Unknown values
// count as unset so a still-unknown lookup surfaces as "none set" rather
// than a comparison against garbage.
func volumeLookupFromTF(letter, uniqueID, label types.String) (winclient.VolumeLookup, bool) {
	set := 0
	var lookup winclient.VolumeLookup
	if !letter.IsNull() && !letter.IsUnknown() && strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(letter.ValueString()), ":")) != "" {
		set++
		lookup.DriveLetter = letter.ValueString()
	}
	if !uniqueID.IsNull() && !uniqueID.IsUnknown() && strings.TrimSpace(uniqueID.ValueString()) != "" {
		set++
		lookup.UniqueID = uniqueID.ValueString()
	}
	if !label.IsNull() && !label.IsUnknown() && strings.TrimSpace(label.ValueString()) != "" {
		set++
		lookup.FileSystemLabel = label.ValueString()
	}
	if set != 1 {
		return winclient.VolumeLookup{}, false
	}
	return lookup, true
}
