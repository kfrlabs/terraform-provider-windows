// Package provider: windows_eventlog data source implementation.
//
// Reads the observed state of an existing event log (classic or modern
// channel) without managing it. Every sibling-resource setting is exposed
// read-only instead, including the informational record_count /
// file_size_bytes counters and the GPO-managed policy_override flag, plus
// the read-only timeouts{read} block.
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
	_ datasource.DataSource              = (*windowsEventLogDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsEventLogDataSource)(nil)
)

// NewWindowsEventLogDataSource is the constructor registered in provider.go.
func NewWindowsEventLogDataSource() datasource.DataSource {
	return &windowsEventLogDataSource{}
}

// windowsEventLogDataSource is the TPF data source type for windows_eventlog.
type windowsEventLogDataSource struct {
	el winclient.WindowsEventLogClient
}

// eventLogDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (eventLogDefaultTimeout) so a stalled session surfaces a timeout
// diagnostic instead of blocking plan forever.
const eventLogDSDefaultTimeout = eventLogDefaultTimeout

// windowsEventLogDataSourceModel is the Terraform state model for the
// windows_eventlog data source.
type windowsEventLogDataSourceModel struct {
	ID               types.String     `tfsdk:"id"`
	Name             types.String     `tfsdk:"name"`
	MaximumSizeBytes types.Int64      `tfsdk:"maximum_size_bytes"`
	Retention        types.String     `tfsdk:"retention"`
	Enabled          types.Bool       `tfsdk:"enabled"`
	LogFilePath      types.String     `tfsdk:"log_file_path"`
	LogType          types.String     `tfsdk:"log_type"`
	IsClassicLog     types.Bool       `tfsdk:"is_classic_log"`
	RecordCount      types.Int64      `tfsdk:"record_count"`
	FileSizeBytes    types.Int64      `tfsdk:"file_size_bytes"`
	PolicyOverride   types.Bool       `tfsdk:"policy_override"`
	Timeouts         dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_eventlog").
func (d *windowsEventLogDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_eventlog"
}

// Schema returns the TPF schema for the windows_eventlog data source.
func (d *windowsEventLogDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of an existing Windows event log (classic log or " +
			"modern channel) on a remote Windows host without managing it.\n\n" +
			"The log is matched by exact name (`LogName`, matched literally — a `/` in a channel name " +
			"such as `Microsoft-Windows-PowerShell/Operational` is part of the name). `record_count` and " +
			"`file_size_bytes` are informational counters. `policy_override` reports whether Group Policy " +
			"carries `MaxSize`, `Retention` or `AutoBackupLogFiles` for the log " +
			"(`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\<log>`).\n\n" +
			"Returns an error when the log does not exist on the target host (for example a feature log " +
			"whose role was uninstalled).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the exact event log name.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Exact event log name (`LogName`) on the target host, e.g. `Application` or `Microsoft-Windows-PowerShell/Operational`.",
			},
			"maximum_size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Maximum size of the event log file in bytes, as observed on the host.",
			},
			"retention": schema.StringAttribute{
				Computed:    true,
				Description: "Retention policy as observed on the host: `overwrite` (`Circular`), `archive` (`AutoBackup`) or `retain` (`Retain`).",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the log is enabled, as observed on the host.",
			},
			"log_file_path": schema.StringAttribute{
				Computed:    true,
				Description: "Path of the event log file, as observed on the host.",
			},
			"log_type": schema.StringAttribute{
				Computed:    true,
				Description: "Log type as observed on the host (`Administrative`, `Operational`, `Analytic` or `Debug`).",
			},
			"is_classic_log": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the log is a classic log, as observed on the host.",
			},
			"record_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of records currently in the log, as observed on the host.",
			},
			"file_size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Current size of the log file on disk in bytes, as observed on the host.",
			},
			"policy_override": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether Group Policy carries `MaxSize`, `Retention` or `AutoBackupLogFiles` for this log, as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to eventLogDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsEventLogDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.el = winclient.NewEventLogClient(c)
}

// Read fetches the observed event log state from the remote Windows host by
// calling the sibling resource's EventLogClient.Read with the configured
// name. A nil result (or a typed not_found) triggers a `not found`
// diagnostic (data sources never silently clear state). Other typed
// *winclient.EventLogError values surface via addEventLogDiag, mirroring
// the resource Read path.
func (d *windowsEventLogDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsEventLogDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, eventLogDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Name.ValueString()
	tflog.Debug(ctx, "windows_eventlog data source Read start", map[string]interface{}{"name": target})

	observed, err := d.el.Read(ctx, target)
	if err != nil {
		var ee *winclient.EventLogError
		if errors.As(err, &ee) && ee.Kind == winclient.EventLogErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_eventlog %q", target),
				fmt.Sprintf("No event log %q was found on the target host.", target),
			)
			return
		}
		addEventLogDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_eventlog %q failed", target), err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_eventlog %q", target),
			fmt.Sprintf("No event log %q was found on the target host.", target),
		)
		return
	}

	state := windowsEventLogDataSourceModel{
		ID:               types.StringValue(observed.Name),
		Name:             types.StringValue(observed.Name),
		MaximumSizeBytes: types.Int64Value(observed.MaximumSizeBytes),
		Retention:        types.StringValue(winclient.EventLogLogModeToRetention(observed.LogMode)),
		Enabled:          types.BoolValue(observed.IsEnabled),
		LogFilePath:      types.StringValue(observed.LogFilePath),
		LogType:          types.StringValue(observed.LogType),
		IsClassicLog:     types.BoolValue(observed.IsClassic),
		RecordCount:      types.Int64Value(observed.RecordCount),
		FileSizeBytes:    types.Int64Value(observed.FileSizeBytes),
		PolicyOverride:   types.BoolValue(observed.PolicyOverride),
		Timeouts:         config.Timeouts,
	}

	tflog.Debug(ctx, "windows_eventlog data source Read end", map[string]interface{}{
		"name":    state.Name.ValueString(),
		"enabled": state.Enabled.ValueBool(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
