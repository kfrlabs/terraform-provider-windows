// Package provider: windows_ntp data source implementation.
//
// Singleton data source — no lookup keys. Reads the current W32Time
// time-source state of the remote Windows host (sync type, NTP peers, poll
// interval, reliable flag, NTP server role, phase corrections, current
// source, policy/domain signals, machine ID). Input-only resource
// attributes (manage_service, resync_on_apply, restore_on_destroy) are
// absent from this data source.
package provider

import (
	"context"
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
	_ datasource.DataSource              = (*windowsNTPDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsNTPDataSource)(nil)
)

// NewWindowsNTPDataSource is the constructor registered in provider.go.
func NewWindowsNTPDataSource() datasource.DataSource {
	return &windowsNTPDataSource{}
}

// windowsNTPDataSource is the TPF data source type for windows_ntp.
type windowsNTPDataSource struct {
	ntp winclient.WindowsNTPClient
}

// ntpDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block, matching the sibling resource default so a
// stalled session surfaces a timeout diagnostic instead of blocking plan
// forever.
const ntpDSDefaultTimeout = ntpDefaultTimeout

// windowsNTPDataSourceModel is the Terraform state model for the
// windows_ntp data source.
type windowsNTPDataSourceModel struct {
	ID                           types.String     `tfsdk:"id"`
	Type                         types.String     `tfsdk:"type"`
	Servers                      types.List       `tfsdk:"servers"`
	SpecialPollIntervalSeconds   types.Int64      `tfsdk:"special_poll_interval_seconds"`
	Reliable                     types.Bool       `tfsdk:"reliable"`
	NtpServerEnabled             types.Bool       `tfsdk:"ntp_server_enabled"`
	MaxPosPhaseCorrectionSeconds types.Int64      `tfsdk:"max_pos_phase_correction_seconds"`
	MaxNegPhaseCorrectionSeconds types.Int64      `tfsdk:"max_neg_phase_correction_seconds"`
	CurrentSource                types.String     `tfsdk:"current_source"`
	PolicyOverride               types.Bool       `tfsdk:"policy_override"`
	DomainJoined                 types.Bool       `tfsdk:"domain_joined"`
	Timeouts                     dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_ntp").
func (d *windowsNTPDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ntp"
}

// Schema returns the TPF schema for the windows_ntp data source.
func (d *windowsNTPDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the current Windows Time service (W32Time) time-source state of the remote Windows host without " +
			"managing it. This is a **singleton** data source — no lookup keys are required.\n\n" +
			"Exposes `type` (`NTP`/`NT5DS`/`AllSync`/`NoSync`), the ordered `servers` peer list (`address` plus `flags`), " +
			"`special_poll_interval_seconds`, `reliable` (`AnnounceFlags` `5`), `ntp_server_enabled`, " +
			"`max_pos_phase_correction_seconds` / `max_neg_phase_correction_seconds`, the informational `current_source` " +
			"(`w32tm /query /source`, opaque peer name), `policy_override` and `domain_joined`.\n\n" +
			"The Terraform data source ID is the stable `machine_id` (HKLM MachineGuid).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; the stable machine ID (HKLM MachineGuid).",
			},
			"type": schema.StringAttribute{
				Computed:            true,
				Description:         "W32Time sync type as observed on the host (NTP, NT5DS, AllSync or NoSync).",
				MarkdownDescription: "W32Time sync type as observed on the host (`NTP`, `NT5DS`, `AllSync` or `NoSync`).",
			},
			"servers": schema.ListNestedAttribute{
				Computed:            true,
				Description:         "NTP peers as observed on the host, in order (address plus flags).",
				MarkdownDescription: "NTP peers as observed on the host, in order (`address` plus `flags`).",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"address": schema.StringAttribute{
							Computed:            true,
							Description:         "Peer hostname or address as observed on the host.",
							MarkdownDescription: "Peer hostname or address as observed on the host.",
						},
						"flags": schema.StringAttribute{
							Computed:            true,
							Description:         "Per-peer flags as observed on the host (canonical lower-case hex, e.g. 0x9).",
							MarkdownDescription: "Per-peer flags as observed on the host (canonical lower-case hex, e.g. `0x9`).",
						},
					},
				},
			},
			"special_poll_interval_seconds": schema.Int64Attribute{
				Computed:            true,
				Description:         "Poll interval in seconds as observed on the host.",
				MarkdownDescription: "Poll interval in seconds as observed on the host.",
			},
			"reliable": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the host is a reliable time source as observed on the host (AnnounceFlags 5).",
				MarkdownDescription: "Whether the host is a reliable time source as observed on the host (`AnnounceFlags` `5`).",
			},
			"ntp_server_enabled": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the host answers NTP requests as observed on the host.",
				MarkdownDescription: "Whether the host answers NTP requests as observed on the host.",
			},
			"max_pos_phase_correction_seconds": schema.Int64Attribute{
				Computed:            true,
				Description:         "Largest forward clock correction the service may apply, in seconds, as observed on the host.",
				MarkdownDescription: "Largest forward clock correction the service may apply, in seconds, as observed on the host.",
			},
			"max_neg_phase_correction_seconds": schema.Int64Attribute{
				Computed:            true,
				Description:         "Largest backward clock correction the service may apply, in seconds, as observed on the host.",
				MarkdownDescription: "Largest backward clock correction the service may apply, in seconds, as observed on the host.",
			},
			"current_source": schema.StringAttribute{
				Computed:            true,
				Description:         "Current time source as reported by w32tm /query /source (opaque peer name). Empty when the query fails.",
				MarkdownDescription: "Current time source as reported by `w32tm /query /source` (opaque peer name). Empty when the query fails.",
			},
			"policy_override": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether Group Policy carries Type or NtpServer for W32Time as observed on the host.",
				MarkdownDescription: "Whether Group Policy carries `Type` or `NtpServer` for W32Time as observed on the host.",
			},
			"domain_joined": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the host is joined to an Active Directory domain as observed on the host.",
				MarkdownDescription: "Whether the host is joined to an Active Directory domain as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever. Absent
			// configuration falls back to ntpDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsNTPDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.ntp = winclient.NewNTPClient(c)
}

// Read fetches the current W32Time time-source state from the remote
// Windows host.
func (d *windowsNTPDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsNTPDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, ntpDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_ntp data source Read start")

	live, err := d.ntp.Read(ctx)
	if err != nil {
		addNTPDiag(&resp.Diagnostics, "Read windows_ntp data source failed", err)
		return
	}

	// The ID is the stable machine ID. MachineGuid should always be
	// present; fall back to the singleton literal instead of an empty ID,
	// which Terraform forbids.
	id := live.MachineID
	if id == "" {
		id = "current"
	}

	servers, diags := ntpServersToListValue(live.Servers)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsNTPDataSourceModel{
		ID:                           types.StringValue(id),
		Type:                         types.StringValue(live.Type),
		Servers:                      servers,
		SpecialPollIntervalSeconds:   types.Int64Value(live.SpecialPollIntervalSeconds),
		Reliable:                     types.BoolValue(live.Reliable),
		NtpServerEnabled:             types.BoolValue(live.NtpServerEnabled),
		MaxPosPhaseCorrectionSeconds: types.Int64Value(live.MaxPosPhaseCorrectionSeconds),
		MaxNegPhaseCorrectionSeconds: types.Int64Value(live.MaxNegPhaseCorrectionSeconds),
		CurrentSource:                types.StringValue(live.CurrentSource),
		PolicyOverride:               types.BoolValue(live.PolicyOverride),
		DomainJoined:                 types.BoolValue(live.DomainJoined),
		Timeouts:                     config.Timeouts,
	}

	tflog.Debug(ctx, "windows_ntp data source Read end", map[string]interface{}{
		"type": state.Type.ValueString(),
		"id":   state.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
