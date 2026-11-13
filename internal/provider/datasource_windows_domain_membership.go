// Package provider: windows_domain_membership data source implementation.
//
// Singleton data source — no lookup keys. Reads the current domain-membership
// state of the remote Windows host (join state, DNS/NetBIOS domain names,
// workgroup, computer/DNS-host names, domain role, reboot flag,
// secure-channel result, machine ID). Write-only resource attributes (the
// join credential) are absent from this data source.
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
	_ datasource.DataSource              = (*windowsDomainMembershipDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsDomainMembershipDataSource)(nil)
)

// NewWindowsDomainMembershipDataSource is the constructor registered in
// provider.go.
func NewWindowsDomainMembershipDataSource() datasource.DataSource {
	return &windowsDomainMembershipDataSource{}
}

// windowsDomainMembershipDataSource is the TPF data source type for
// windows_domain_membership.
type windowsDomainMembershipDataSource struct {
	dm winclient.WindowsDomainMembershipClient
}

// domainMembershipDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block, so a stalled session surfaces a
// timeout diagnostic instead of blocking plan forever (issue #197).
const domainMembershipDSDefaultTimeout = 2 * time.Minute

// windowsDomainMembershipDataSourceModel is the Terraform state model for
// the windows_domain_membership data source.
type windowsDomainMembershipDataSourceModel struct {
	ID                 types.String     `tfsdk:"id"`
	PartOfDomain       types.Bool       `tfsdk:"part_of_domain"`
	Domain             types.String     `tfsdk:"domain"`
	Workgroup          types.String     `tfsdk:"workgroup"`
	ComputerName       types.String     `tfsdk:"computer_name"`
	DNSHostName        types.String     `tfsdk:"dns_host_name"`
	FQDN               types.String     `tfsdk:"fqdn"`
	NetBIOSDomain      types.String     `tfsdk:"netbios_domain"`
	DomainRole         types.String     `tfsdk:"domain_role"`
	PendingReboot      types.Bool       `tfsdk:"pending_reboot"`
	SecureChannelOk    types.Bool       `tfsdk:"secure_channel_ok"`
	CheckSecureChannel types.Bool       `tfsdk:"check_secure_channel"`
	Timeouts           dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_domain_membership").
func (d *windowsDomainMembershipDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain_membership"
}

// Schema returns the TPF schema for the windows_domain_membership data
// source.
func (d *windowsDomainMembershipDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the current domain-membership state of the remote Windows host without " +
			"managing it. This is a **singleton** data source — no lookup keys are required.\n\n" +
			"Exposes `part_of_domain`, the DNS `domain` (empty when workgroup-joined), the `workgroup` " +
			"(empty when domain-joined), `computer_name`, `dns_host_name` (with `fqdn` as its alias), " +
			"the NetBIOS `netbios_domain`, the `domain_role`, `pending_reboot`, the `secure_channel_ok` " +
			"result (`null` when the host is not joined or when `check_secure_channel` is `false`), and " +
			"the stable `machine_id` (HKLM MachineGuid).\n\n" +
			"The Terraform data source ID is the `machine_id`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; the stable machine ID (HKLM MachineGuid).",
			},
			"part_of_domain": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the host is joined to an Active Directory domain.",
			},
			"domain": schema.StringAttribute{
				Computed:    true,
				Description: "DNS name of the joined domain. Empty when the host is workgroup-joined (never the workgroup name).",
			},
			"workgroup": schema.StringAttribute{
				Computed:    true,
				Description: "Workgroup name. Empty when the host is domain-joined.",
			},
			"computer_name": schema.StringAttribute{
				Computed:    true,
				Description: "Active computer name (Win32_ComputerSystem.Name).",
			},
			"dns_host_name": schema.StringAttribute{
				Computed:    true,
				Description: "Fully qualified host name (Win32_ComputerSystem.DNSHostName).",
			},
			"fqdn": schema.StringAttribute{
				Computed:    true,
				Description: "Alias of dns_host_name.",
			},
			"netbios_domain": schema.StringAttribute{
				Computed:    true,
				Description: "NetBIOS (short) domain name. Empty when the host is workgroup-joined.",
			},
			"domain_role": schema.StringAttribute{
				Computed:    true,
				Description: "Win32_ComputerSystem.DomainRole mapped to its name: StandaloneWorkstation, MemberWorkstation, StandaloneServer, MemberServer, BackupDomainController or PrimaryDomainController.",
			},
			"pending_reboot": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the OS exposes a pending reboot flag.",
			},
			"secure_channel_ok": schema.BoolAttribute{
				Computed:    true,
				Description: "Test-ComputerSecureChannel result. Null when the host is workgroup-joined or when check_secure_channel is false.",
			},
			"check_secure_channel": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether to probe the domain secure channel (Test-ComputerSecureChannel). Defaults to true when unset; set to false for inventory-only reads to avoid the domain-controller round-trip (secure_channel_ok is then null).",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to
			// domainMembershipDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsDomainMembershipDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.dm = winclient.NewDomainMembershipClient(c)
}

// Read fetches the current domain-membership state from the remote Windows
// host. A null or unknown check_secure_channel falls back to the schema
// default (true).
func (d *windowsDomainMembershipDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsDomainMembershipDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, domainMembershipDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	checkSecure := true
	if !config.CheckSecureChannel.IsNull() && !config.CheckSecureChannel.IsUnknown() {
		checkSecure = config.CheckSecureChannel.ValueBool()
	}

	tflog.Debug(ctx, "windows_domain_membership data source Read start", map[string]interface{}{
		"check_secure_channel": checkSecure,
	})

	live, err := d.dm.ReadWithOptions(ctx, winclient.DomainMembershipReadOptions{CheckSecureChannel: checkSecure})
	if err != nil {
		addDomainMembershipDiag(&resp.Diagnostics, "Read windows_domain_membership data source failed", err)
		return
	}
	if live == nil {
		resp.Diagnostics.AddError(
			"Read windows_domain_membership data source failed",
			"The host returned an empty domain-membership state.",
		)
		return
	}

	// The ID is the stable machine ID. MachineGuid should always be
	// present; an unreadable value is an error, never a placeholder ID.
	if live.MachineID == "" {
		resp.Diagnostics.AddError(
			"Read windows_domain_membership data source failed",
			"The host did not report a MachineGuid (HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid), so the stable singleton ID cannot be determined. Verify the host is reachable and the MachineGuid value is readable, then retry.",
		)
		return
	}
	id := live.MachineID

	secureChannelOk := types.BoolNull()
	if !live.SecureChannelNull {
		secureChannelOk = types.BoolValue(live.SecureChannelOk)
	}

	state := windowsDomainMembershipDataSourceModel{
		ID:                 types.StringValue(id),
		PartOfDomain:       types.BoolValue(live.PartOfDomain),
		Domain:             types.StringValue(live.Domain),
		Workgroup:          types.StringValue(live.Workgroup),
		ComputerName:       types.StringValue(live.ComputerName),
		DNSHostName:        types.StringValue(live.DNSHostName),
		FQDN:               types.StringValue(live.DNSHostName),
		NetBIOSDomain:      types.StringValue(live.NetBIOSDomain),
		DomainRole:         types.StringValue(live.DomainRole),
		PendingReboot:      types.BoolValue(live.PendingReboot),
		SecureChannelOk:    secureChannelOk,
		CheckSecureChannel: types.BoolValue(checkSecure),
		Timeouts:           config.Timeouts,
	}

	tflog.Debug(ctx, "windows_domain_membership data source Read end", map[string]interface{}{
		"part_of_domain": state.PartOfDomain.ValueBool(),
		"domain":         state.Domain.ValueString(),
		"machine_id":     state.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
