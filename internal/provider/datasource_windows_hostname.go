// Package provider: windows_hostname data source implementation.
//
// Singleton data source — no lookup keys. Reads the current hostname state
// of the remote Windows host (active name, pending name, reboot flag, machine ID).
// Input-only resource attributes (name, force) are absent from this data source.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsHostnameDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsHostnameDataSource)(nil)
)

// NewWindowsHostnameDataSource is the constructor registered in provider.go.
func NewWindowsHostnameDataSource() datasource.DataSource {
	return &windowsHostnameDataSource{}
}

// windowsHostnameDataSource is the TPF data source type for windows_hostname.
type windowsHostnameDataSource struct {
	client *winclient.Client
	hn     winclient.WindowsHostnameClient
}

// windowsHostnameDataSourceModel is the Terraform state model for the
// windows_hostname data source.
type windowsHostnameDataSourceModel struct {
	ID            types.String `tfsdk:"id"`
	CurrentName   types.String `tfsdk:"current_name"`
	PendingName   types.String `tfsdk:"pending_name"`
	RebootPending types.Bool   `tfsdk:"reboot_pending"`
	MachineID     types.String `tfsdk:"machine_id"`
}

// Metadata sets the data source type name ("windows_hostname").
func (d *windowsHostnameDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hostname"
}

// Schema returns the TPF schema for the windows_hostname data source.
func (d *windowsHostnameDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the current hostname state of the remote Windows host without " +
			"managing it. This is a **singleton** data source — no lookup keys are required.\n\n" +
			"Exposes `current_name` (active name), `pending_name` (effective after next reboot), " +
			"`reboot_pending`, and the stable `machine_id` (HKLM MachineGuid).\n\n" +
			"The Terraform data source ID is always `\"current\"`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; always \"current\" (singleton).",
			},
			"current_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Active computer name (Win32_ComputerSystem.Name == HKLM ActiveComputerName).",
				MarkdownDescription: "Active computer name as exposed by `Win32_ComputerSystem.Name`.",
			},
			"pending_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Hostname queued to take effect on next reboot (HKLM ComputerName/ComputerName). Equal to current_name when no rename is pending.",
				MarkdownDescription: "Hostname queued to take effect on next reboot. Equal to `current_name` when no rename is pending.",
			},
			"reboot_pending": schema.BoolAttribute{
				Computed:            true,
				Description:         "True when pending_name (case-insensitive) differs from current_name.",
				MarkdownDescription: "True when `pending_name` differs from `current_name` (case-insensitive).",
			},
			"machine_id": schema.StringAttribute{
				Computed:            true,
				Description:         "Stable per-machine identifier (HKLM Cryptography MachineGuid).",
				MarkdownDescription: "Stable per-machine identifier read from `HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`.",
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsHostnameDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = c
	d.hn = winclient.NewHostnameClient(c)
}

// Read fetches the current hostname state from the remote Windows host.
// Passing an empty machine ID means no ID-match check is performed.
func (d *windowsHostnameDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsHostnameDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_hostname data source Read start")

	live, err := d.hn.Read(ctx, "")
	if err != nil {
		addHostnameDiag(&resp.Diagnostics, "Read windows_hostname data source failed", err)
		return
	}

	state := windowsHostnameDataSourceModel{
		ID:            types.StringValue("current"),
		CurrentName:   types.StringValue(live.CurrentName),
		PendingName:   types.StringValue(live.PendingName),
		RebootPending: types.BoolValue(live.RebootPending),
		MachineID:     types.StringValue(live.MachineID),
	}

	tflog.Debug(ctx, "windows_hostname data source Read end", map[string]interface{}{
		"current_name": state.CurrentName.ValueString(),
		"machine_id":   state.MachineID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
