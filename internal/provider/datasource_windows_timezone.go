// Package provider: windows_timezone data source implementation.
//
// Singleton data source — no lookup keys. Reads the current system time zone
// state of the remote Windows host (zone ID, display name, offsets,
// DST-disabled flag, tzautoupdate flag, machine ID). Input-only resource
// attributes (restore_on_destroy) are absent from this data source.
package provider

import (
	"context"
	"fmt"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsTimezoneDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsTimezoneDataSource)(nil)
)

// NewWindowsTimezoneDataSource is the constructor registered in provider.go.
func NewWindowsTimezoneDataSource() datasource.DataSource {
	return &windowsTimezoneDataSource{}
}

// windowsTimezoneDataSource is the TPF data source type for windows_timezone.
type windowsTimezoneDataSource struct {
	tz winclient.WindowsTimezoneClient
}

// timezoneDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block, matching the sibling resource default so a
// stalled session surfaces a timeout diagnostic instead of blocking plan
// forever.
const timezoneDSDefaultTimeout = 5 * time.Minute

// windowsTimezoneDataSourceModel is the Terraform state model for the
// windows_timezone data source.
type windowsTimezoneDataSourceModel struct {
	ID                     types.String     `tfsdk:"id"`
	TimezoneID             types.String     `tfsdk:"timezone_id"`
	DisplayName            types.String     `tfsdk:"display_name"`
	BaseUTCOffset          types.String     `tfsdk:"base_utc_offset"`
	SupportsDST            types.Bool       `tfsdk:"supports_daylight_saving_time"`
	CurrentUTCOffset       types.String     `tfsdk:"current_utc_offset"`
	DaylightSavingDisabled types.Bool       `tfsdk:"daylight_saving_disabled"`
	TzautoupdateEnabled    types.Bool       `tfsdk:"tzautoupdate_enabled"`
	Timeouts               dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_timezone").
func (d *windowsTimezoneDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_timezone"
}

// Schema returns the TPF schema for the windows_timezone data source.
func (d *windowsTimezoneDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the current system time zone state of the remote Windows host without " +
			"managing it. This is a **singleton** data source — no lookup keys are required.\n\n" +
			"Exposes `timezone_id`, `display_name`, `base_utc_offset` (standard offset), " +
			"`supports_daylight_saving_time`, `current_utc_offset` (live effective offset), " +
			"`daylight_saving_disabled` and `tzautoupdate_enabled`.\n\n" +
			"The Terraform data source ID is the stable `machine_id` (HKLM MachineGuid).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; the stable machine ID (HKLM MachineGuid).",
			},
			"timezone_id": schema.StringAttribute{
				Computed:            true,
				Description:         "Configured Windows time zone ID (e.g. Romance Standard Time).",
				MarkdownDescription: "Configured Windows time zone ID (e.g. `Romance Standard Time`).",
			},
			"display_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Localized display name of the configured time zone.",
				MarkdownDescription: "Localized display name of the configured time zone.",
			},
			"base_utc_offset": schema.StringAttribute{
				Computed:            true,
				Description:         "Standard (non-DST) UTC offset of the zone, formatted as +HH:mm.",
				MarkdownDescription: "Standard (non-DST) UTC offset of the zone, formatted as `+HH:mm`.",
			},
			"supports_daylight_saving_time": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the zone definition includes daylight saving time.",
				MarkdownDescription: "Whether the zone definition includes daylight saving time.",
			},
			"current_utc_offset": schema.StringAttribute{
				Computed:            true,
				Description:         "Live effective UTC offset (base plus the active DST delta, if any), formatted as +HH:mm.",
				MarkdownDescription: "Live effective UTC offset (base plus the active DST delta, if any), formatted as `+HH:mm`.",
			},
			"daylight_saving_disabled": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether daylight saving time is disabled for the zone (tzutil <id>_dstoff).",
				MarkdownDescription: "Whether daylight saving time is disabled for the zone (`tzutil <id>_dstoff`).",
			},
			"tzautoupdate_enabled": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the tzautoupdate service may change the time zone automatically.",
				MarkdownDescription: "Whether the `tzautoupdate` service may change the time zone automatically.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever. Absent
			// configuration falls back to timezoneDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsTimezoneDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.tz = winclient.NewTimezoneClient(c)
}

// Read fetches the current time zone state from the remote Windows host.
func (d *windowsTimezoneDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsTimezoneDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, timezoneDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_timezone data source Read start")

	live, err := d.tz.Read(ctx)
	if err != nil {
		addTimezoneDiag(&resp.Diagnostics, "Read windows_timezone data source failed", err)
		return
	}

	// The ID is the stable machine ID. MachineGuid should always be
	// present; fall back to the singleton literal instead of an empty ID,
	// which Terraform forbids.
	id := live.MachineID
	if id == "" {
		id = "current"
	}

	state := windowsTimezoneDataSourceModel{
		ID:                     types.StringValue(id),
		TimezoneID:             types.StringValue(live.TimezoneID),
		DisplayName:            types.StringValue(live.DisplayName),
		BaseUTCOffset:          types.StringValue(live.BaseUTCOffset),
		SupportsDST:            types.BoolValue(live.SupportsDaylightSavingTime),
		CurrentUTCOffset:       types.StringValue(live.CurrentUTCOffset),
		DaylightSavingDisabled: types.BoolValue(live.DaylightSavingDisabled),
		TzautoupdateEnabled:    types.BoolValue(live.TzautoupdateEnabled),
		Timeouts:               config.Timeouts,
	}

	tflog.Debug(ctx, "windows_timezone data source Read end", map[string]interface{}{
		"timezone_id": state.TimezoneID.ValueString(),
		"id":          state.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
