// Package provider: windows_net_ip_address data source implementation.
//
// Reads the observed state of an existing static IP address without managing
// it. Lookup is by ip_address alone or together with interface_alias, and
// reuses the sibling resource's winclient.NetIPAddressClient (no new
// winclient code).
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsNetIPAddressDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsNetIPAddressDataSource)(nil)
)

// NewWindowsNetIPAddressDataSource is the constructor registered in provider.go.
func NewWindowsNetIPAddressDataSource() datasource.DataSource {
	return &windowsNetIPAddressDataSource{}
}

// windowsNetIPAddressDataSource is the TPF data source type for windows_net_ip_address.
type windowsNetIPAddressDataSource struct {
	ip winclient.NetIPAddressClient
}

// netIPAddressDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (netIPAddressDefaultTimeout) so a stalled session surfaces a
// timeout diagnostic instead of blocking plan forever.
const netIPAddressDSDefaultTimeout = netIPAddressDefaultTimeout

// windowsNetIPAddressDataSourceModel is the Terraform state model for the
// windows_net_ip_address data source.
type windowsNetIPAddressDataSourceModel struct {
	ID             types.String     `tfsdk:"id"`
	IPAddress      types.String     `tfsdk:"ip_address"`
	InterfaceAlias types.String     `tfsdk:"interface_alias"`
	InterfaceIndex types.Int64      `tfsdk:"interface_index"`
	PrefixLength   types.Int64      `tfsdk:"prefix_length"`
	PrefixOrigin   types.String     `tfsdk:"prefix_origin"`
	AddressState   types.String     `tfsdk:"address_state"`
	AddressFamily  types.String     `tfsdk:"address_family"`
	SkipAsSource   types.Bool       `tfsdk:"skip_as_source"`
	Timeouts       dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_net_ip_address", the
// same Terraform type name as the sibling resource per ADR-0009).
func (d *windowsNetIPAddressDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_net_ip_address"
}

// Schema returns the TPF schema for the windows_net_ip_address data source.
func (d *windowsNetIPAddressDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of an existing static IP address on a remote Windows host " +
			"without managing it.\n\n" +
			"Lookup is by `ip_address` alone or together with `interface_alias`. Zero matches, or several " +
			"matches (the same address present on more than one interface), is an error listing the " +
			"candidates — refine the lookup with `interface_alias`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: `<interface_alias>|<canonical ip_address>`.",
			},
			"ip_address": schema.StringAttribute{
				Required:    true,
				Description: "IP address to look up, in canonical or any parseable spelling.",
			},
			"interface_alias": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the lookup to one interface alias (exact, case-insensitive match).",
			},
			"interface_index": schema.Int64Attribute{
				Computed:    true,
				Description: "Numeric interface index owning the address, as observed on the host.",
			},
			"prefix_length": schema.Int64Attribute{
				Computed:    true,
				Description: "Subnet prefix length, as observed on the host.",
			},
			"prefix_origin": schema.StringAttribute{
				Computed:    true,
				Description: "How the address was provisioned, as observed on the host (`Manual`, `Dhcp`, `WellKnown`, `RouterAdvertisement`, `Other`).",
			},
			"address_state": schema.StringAttribute{
				Computed:    true,
				Description: "Duplicate-detection state, as observed on the host (`Preferred`, `Tentative`, `Duplicate`, `Deprecated`).",
			},
			"address_family": schema.StringAttribute{
				Computed:    true,
				Description: "Address family, as observed on the host (`IPv4` or `IPv6`).",
			},
			"skip_as_source": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the address is excluded from outbound source selection, as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to netIPAddressDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsNetIPAddressDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.ip = winclient.NewNetIPAddressClient(c)
}

// Read looks the address up via the sibling resource's
// NetIPAddressClient.Lookup. Zero or several matches surface as a `not
// found` diagnostic (never a silently cleared state); other typed
// *winclient.NetIPAddressError values surface via addNetIPAddressDiag,
// mirroring the resource Read path.
func (d *windowsNetIPAddressDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsNetIPAddressDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, netIPAddressDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	canonical, err := canonicalNetIPAddress(config.IPAddress.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid ip_address",
			fmt.Sprintf("ip_address must be a valid IPv4 or IPv6 address; got %q.", config.IPAddress.ValueString()),
		)
		return
	}
	alias := ""
	if !config.InterfaceAlias.IsNull() && !config.InterfaceAlias.IsUnknown() {
		// A whitespace-only alias is rejected instead of widening the
		// lookup to all interfaces.
		raw := config.InterfaceAlias.ValueString()
		alias = strings.TrimSpace(raw)
		if raw != "" && alias == "" {
			resp.Diagnostics.AddError(
				"Invalid interface_alias",
				"interface_alias must not be blank; omit it to search all interfaces.",
			)
			return
		}
	}

	tflog.Debug(ctx, "windows_net_ip_address data source Read start", map[string]interface{}{
		"ip_address": canonical, "interface_alias": alias,
	})

	observed, err := d.ip.Lookup(ctx, canonical, alias)
	if err != nil {
		var ne *winclient.NetIPAddressError
		if errors.As(err, &ne) && ne.Kind == winclient.NetIPAddressErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_net_ip_address %q", canonical),
				fmt.Sprintf("No address %q was found on the target host.", canonical),
			)
			return
		}
		addNetIPAddressDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_net_ip_address %q failed", canonical), err)
		return
	}
	if len(observed) != 1 {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_net_ip_address %q", canonical),
			fmt.Sprintf("Expected exactly one match for address %q, got %d. Refine the lookup with interface_alias.", canonical, len(observed)),
		)
		return
	}
	info := observed[0]

	state := windowsNetIPAddressDataSourceModel{
		ID:             types.StringValue(netIPAddressID(info.InterfaceAlias, info.IPAddress)),
		IPAddress:      types.StringValue(info.IPAddress),
		InterfaceAlias: types.StringValue(info.InterfaceAlias),
		InterfaceIndex: types.Int64Value(int64(info.InterfaceIndex)),
		PrefixLength:   types.Int64Value(int64(info.PrefixLength)),
		PrefixOrigin:   types.StringValue(info.PrefixOrigin),
		AddressState:   types.StringValue(info.AddressState),
		AddressFamily:  types.StringValue(info.AddressFamily),
		SkipAsSource:   types.BoolValue(info.SkipAsSource),
		Timeouts:       config.Timeouts,
	}

	tflog.Debug(ctx, "windows_net_ip_address data source Read end", map[string]interface{}{
		"ip_address": state.IPAddress.ValueString(),
		"id":         state.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
