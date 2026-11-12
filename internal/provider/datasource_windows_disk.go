// Package provider: windows_disk data source implementation.
//
// Reads the observed state of a disk on a remote Windows host without
// managing it. Lookup is by exactly one of unique_id, serial_number,
// location or number, and reuses the sibling resource's
// winclient.WindowsDiskClient (no new winclient code).
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
	_ datasource.DataSource                     = (*windowsDiskDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*windowsDiskDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*windowsDiskDataSource)(nil)
)

// NewWindowsDiskDataSource is the constructor registered in provider.go.
func NewWindowsDiskDataSource() datasource.DataSource {
	return &windowsDiskDataSource{}
}

// windowsDiskDataSource is the TPF data source type for windows_disk.
type windowsDiskDataSource struct {
	disks winclient.WindowsDiskClient
}

// diskDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block. It reuses the sibling resource default
// (diskDefaultTimeout) so a stalled session surfaces a timeout diagnostic
// instead of blocking plan forever.
const diskDSDefaultTimeout = diskDefaultTimeout

// windowsDiskDataSourceModel is the Terraform state model for the
// windows_disk data source.
type windowsDiskDataSourceModel struct {
	ID                types.String     `tfsdk:"id"`
	UniqueID          types.String     `tfsdk:"unique_id"`
	SerialNumber      types.String     `tfsdk:"serial_number"`
	Location          types.String     `tfsdk:"location"`
	Number            types.Int64      `tfsdk:"number"`
	IsOffline         types.Bool       `tfsdk:"is_offline"`
	IsReadOnly        types.Bool       `tfsdk:"is_read_only"`
	PartitionStyle    types.String     `tfsdk:"partition_style"`
	FriendlyName      types.String     `tfsdk:"friendly_name"`
	BusType           types.String     `tfsdk:"bus_type"`
	HealthStatus      types.String     `tfsdk:"health_status"`
	OperationalStatus types.String     `tfsdk:"operational_status"`
	SizeBytes         types.Int64      `tfsdk:"size_bytes"`
	IsBoot            types.Bool       `tfsdk:"is_boot"`
	IsSystem          types.Bool       `tfsdk:"is_system"`
	IsClustered       types.Bool       `tfsdk:"is_clustered"`
	Timeouts          dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_disk", the same
// Terraform type name as the sibling resource per ADR-0009).
func (d *windowsDiskDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_disk"
}

// Schema returns the TPF schema for the windows_disk data source.
func (d *windowsDiskDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a disk on a remote Windows host via SSH and " +
			"PowerShell (`Get-Disk`) without managing it.\n\n" +
			"Lookup is by exactly one of `unique_id` (the stable identity, preferred), `serial_number`, " +
			"`location` or `number`. Zero matches are an error, several matches are an `ambiguous_disk` " +
			"error. Disks hosting the OS, the active pagefile, the crash-dump target, or clustered disks " +
			"are refused fail-closed with `protected_storage`, as is a disk whose placement cannot be " +
			"determined. Selecting by `number` emits a warning: Windows assigns numbers at scan time and " +
			"they can shift across reboots.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier; the stable Get-Disk UniqueId of the observed disk.",
			},
			"unique_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Stable Get-Disk UniqueId of the disk to look up. Exactly one of unique_id, serial_number, location and number must be specified.",
			},
			"serial_number": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Get-Disk SerialNumber of the disk to look up, matched case-insensitively after trimming whitespace. Exactly one of unique_id, serial_number, location and number must be specified.",
			},
			"location": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Get-Disk Location (adapter path) of the disk to look up, matched case-insensitively after trimming whitespace. Exactly one of unique_id, serial_number, location and number must be specified.",
			},
			"number": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Get-Disk Number of the disk to look up. Exactly one of unique_id, serial_number, location and number must be specified. Disk numbers are assigned by Windows at scan time and can shift across reboots: using number emits a warning, prefer unique_id.",
			},
			"is_offline": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is offline, as observed on the host.",
			},
			"is_read_only": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is read-only, as observed on the host.",
			},
			"partition_style": schema.StringAttribute{
				Computed:    true,
				Description: "Partition style of the disk (RAW, MBR or GPT), as observed on the host.",
			},
			"friendly_name": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk FriendlyName, as observed on the host.",
			},
			"bus_type": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk BusType (e.g. SATA, NVMe, RAID, USB, Virtual), as observed on the host.",
			},
			"health_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk HealthStatus (e.g. Healthy), as observed on the host.",
			},
			"operational_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk OperationalStatus (e.g. Online, Offline), as observed on the host.",
			},
			"size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Get-Disk Size in bytes, as observed on the host.",
			},
			"is_boot": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is the boot disk, as observed on the host.",
			},
			"is_system": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is the system disk, as observed on the host.",
			},
			"is_clustered": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is clustered, as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to diskDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// ConfigValidators enforces ExactlyOneOf over the four selectors.
func (d *windowsDiskDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("unique_id"),
			path.MatchRoot("serial_number"),
			path.MatchRoot("location"),
			path.MatchRoot("number"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsDiskDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.disks = winclient.NewDiskClient(c)
}

// Read fetches the observed disk state from the remote Windows host by
// calling the sibling resource's WindowsDiskClient. A nil result or a typed
// error surfaces as a diagnostic (data sources never silently clear state).
func (d *windowsDiskDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsDiskDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, diskDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	sel, ok := diskSelectorFromTF(config.UniqueID, config.SerialNumber, config.Location, config.Number)
	if !ok {
		resp.Diagnostics.AddError(
			"Missing disk selector",
			"Exactly one of unique_id, serial_number, location and number must be set.",
		)
		return
	}
	warnOnNumberSelector(&resp.Diagnostics, config.Number)

	tflog.Debug(ctx, "windows_disk data source Read start", map[string]interface{}{"selector": sel.Describe()})

	info, err := d.disks.Read(ctx, sel)
	if err != nil {
		addDiskDiag(&resp.Diagnostics, fmt.Sprintf("Read data source windows_disk (%s) failed", sel.Describe()), err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_disk (%s)", sel.Describe()),
			fmt.Sprintf("No disk matching %s was found on the target host.", sel.Describe()),
		)
		return
	}

	state := windowsDiskDataSourceModel{
		ID:                types.StringValue(info.UniqueID),
		UniqueID:          types.StringValue(info.UniqueID),
		SerialNumber:      diskStringOrNull(info.SerialNumber),
		Location:          diskStringOrNull(info.Location),
		Number:            types.Int64Value(int64(info.Number)),
		IsOffline:         types.BoolValue(info.IsOffline),
		IsReadOnly:        types.BoolValue(info.IsReadOnly),
		PartitionStyle:    types.StringValue(info.PartitionStyle),
		FriendlyName:      types.StringValue(info.FriendlyName),
		BusType:           types.StringValue(info.BusType),
		HealthStatus:      types.StringValue(info.HealthStatus),
		OperationalStatus: types.StringValue(info.OperationalStatus),
		SizeBytes:         types.Int64Value(info.SizeBytes),
		IsBoot:            types.BoolValue(info.IsBoot),
		IsSystem:          types.BoolValue(info.IsSystem),
		IsClustered:       types.BoolValue(info.IsClustered),
		Timeouts:          config.Timeouts,
	}

	tflog.Debug(ctx, "windows_disk data source Read end", map[string]interface{}{
		"unique_id": state.UniqueID.ValueString(),
		"number":    state.Number.ValueInt64(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
