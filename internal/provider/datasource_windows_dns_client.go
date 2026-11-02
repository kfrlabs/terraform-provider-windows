// Package provider: windows_dns_client data source implementation.
//
// Reads the observed DNS client settings of one network interface without
// managing them. Every sibling-resource setting is exposed read-only,
// including the DHCP-inclusive effective server lists.
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
	_ datasource.DataSource              = (*windowsDNSClientDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsDNSClientDataSource)(nil)
)

// NewWindowsDNSClientDataSource is the constructor registered in provider.go.
func NewWindowsDNSClientDataSource() datasource.DataSource {
	return &windowsDNSClientDataSource{}
}

// windowsDNSClientDataSource is the TPF data source type for windows_dns_client.
type windowsDNSClientDataSource struct {
	dns winclient.DnsClientClient
}

// dnsClientDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (dnsClientDefaultTimeout) so a stalled session surfaces a timeout
// diagnostic instead of blocking plan forever.
const dnsClientDSDefaultTimeout = dnsClientDefaultTimeout

// windowsDNSClientDataSourceModel is the Terraform state model for the
// windows_dns_client data source.
type windowsDNSClientDataSourceModel struct {
	ID                            types.String     `tfsdk:"id"`
	InterfaceAlias                types.String     `tfsdk:"interface_alias"`
	IPv4ServerAddresses           types.List       `tfsdk:"ipv4_server_addresses"`
	IPv6ServerAddresses           types.List       `tfsdk:"ipv6_server_addresses"`
	ConnectionSpecificSuffix      types.String     `tfsdk:"connection_specific_suffix"`
	RegisterThisConnectionAddress types.Bool       `tfsdk:"register_this_connection_address"`
	UseSuffixWhenRegistering      types.Bool       `tfsdk:"use_suffix_when_registering"`
	InterfaceIndex                types.Int64      `tfsdk:"interface_index"`
	InterfaceGUID                 types.String     `tfsdk:"interface_guid"`
	EffectiveIPv4                 types.List       `tfsdk:"effective_ipv4"`
	EffectiveIPv6                 types.List       `tfsdk:"effective_ipv6"`
	Timeouts                      dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_dns_client").
func (d *windowsDNSClientDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns_client"
}

// Schema returns the TPF schema for the windows_dns_client data source.
func (d *windowsDNSClientDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed DNS client settings of one network interface on a " +
			"remote Windows host without managing them.\n\n" +
			"`ipv4_server_addresses` / `ipv6_server_addresses` report the statically configured " +
			"servers (automatic families report `[]`); `effective_ipv4` / `effective_ipv6` are " +
			"DHCP-inclusive and report the live servers.\n\n" +
			"Returns an error when no interface matches the alias.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the canonical (trimmed) interface alias.",
			},
			"interface_alias": schema.StringAttribute{
				Required:    true,
				Description: "Network interface alias on the target host. Matched exactly and case-insensitively, never as a wildcard.",
			},
			"ipv4_server_addresses": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Static IPv4 DNS servers in order, as observed on the host (`[]` when the family is automatic).",
			},
			"ipv6_server_addresses": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Static IPv6 DNS servers in order, as observed on the host (`[]` when the family is automatic).",
			},
			"connection_specific_suffix": schema.StringAttribute{
				Computed:    true,
				Description: "Connection-specific DNS suffix, as observed on the host (`\"\"` when unset).",
			},
			"register_this_connection_address": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether this connection's address is registered in DNS, as observed on the host.",
			},
			"use_suffix_when_registering": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the connection-specific suffix is used when registering in DNS, as observed on the host.",
			},
			"interface_index": schema.Int64Attribute{
				Computed:    true,
				Description: "Numeric interface index, as observed on the host.",
			},
			"interface_guid": schema.StringAttribute{
				Computed:    true,
				Description: "Interface GUID (braces included), as observed on the host.",
			},
			"effective_ipv4": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Live IPv4 DNS servers, as observed on the host (static plus DHCP-provided).",
			},
			"effective_ipv6": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Live IPv6 DNS servers, as observed on the host (static plus DHCP-provided).",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to dnsClientDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsDNSClientDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.dns = winclient.NewDnsClientClient(c)
}

// Read fetches the observed DNS client state of the configured interface by
// reusing the sibling resource's DnsClientClient.Read. A missing interface
// surfaces a `not found` diagnostic (data sources never silently clear
// state).
func (d *windowsDNSClientDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsDNSClientDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, dnsClientDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := canonicalDNSClientAlias(config.InterfaceAlias.ValueString())
	tflog.Debug(ctx, "windows_dns_client data source Read start", map[string]interface{}{"interface_alias": target})

	if err := winclient.ValidateDnsClientAlias(target); err != nil {
		addDNSClientDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_dns_client %q failed", target), err)
		return
	}

	observed, err := d.dns.Read(ctx, target)
	if err != nil {
		addDNSClientDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_dns_client %q failed", target), err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_dns_client %q", target),
			fmt.Sprintf("No interface matching alias %q was found on the target host.", target),
		)
		return
	}

	state := windowsDNSClientDataSourceModel{
		ID:                            types.StringValue(canonicalDNSClientAlias(observed.InterfaceAlias)),
		InterfaceAlias:                types.StringValue(observed.InterfaceAlias),
		IPv4ServerAddresses:           dnsClientMustList(observed.StaticIPv4),
		IPv6ServerAddresses:           dnsClientMustList(observed.StaticIPv6),
		ConnectionSpecificSuffix:      types.StringValue(observed.ConnectionSpecificSuffix),
		RegisterThisConnectionAddress: types.BoolValue(observed.RegisterThisConnectionAddress),
		UseSuffixWhenRegistering:      types.BoolValue(observed.UseSuffixWhenRegistering),
		InterfaceIndex:                types.Int64Value(int64(observed.InterfaceIndex)),
		InterfaceGUID:                 types.StringValue(observed.InterfaceGUID),
		EffectiveIPv4:                 dnsClientMustList(observed.EffectiveIPv4),
		EffectiveIPv6:                 dnsClientMustList(observed.EffectiveIPv6),
		Timeouts:                      config.Timeouts,
	}

	tflog.Debug(ctx, "windows_dns_client data source Read end", map[string]interface{}{
		"interface_alias": state.InterfaceAlias.ValueString(),
		"interface_index": state.InterfaceIndex.ValueInt64(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
