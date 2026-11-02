// Package provider: windows_net_route data source implementation.
//
// Reads the observed state of an existing persistent route without managing
// it. Lookup is by destination_prefix, optionally narrowed by
// interface_alias and next_hop, and reuses the sibling resource's
// winclient.NetRouteClient (no new winclient code). Several matches resolve
// deterministically to the one with the lowest effective metric; match_count
// reports how many matched.
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
	_ datasource.DataSource              = (*windowsNetRouteDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsNetRouteDataSource)(nil)
)

// NewWindowsNetRouteDataSource is the constructor registered in provider.go.
func NewWindowsNetRouteDataSource() datasource.DataSource {
	return &windowsNetRouteDataSource{}
}

// windowsNetRouteDataSource is the TPF data source type for windows_net_route.
type windowsNetRouteDataSource struct {
	routes winclient.NetRouteClient
}

// netRouteDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (netRouteDefaultTimeout) so a stalled session surfaces a timeout
// diagnostic instead of blocking plan forever.
const netRouteDSDefaultTimeout = netRouteDefaultTimeout

// windowsNetRouteDataSourceModel is the Terraform state model for the
// windows_net_route data source.
type windowsNetRouteDataSourceModel struct {
	ID                types.String     `tfsdk:"id"`
	DestinationPrefix types.String     `tfsdk:"destination_prefix"`
	InterfaceAlias    types.String     `tfsdk:"interface_alias"`
	NextHop           types.String     `tfsdk:"next_hop"`
	InterfaceIndex    types.Int64      `tfsdk:"interface_index"`
	AddressFamily     types.String     `tfsdk:"address_family"`
	RouteMetric       types.Int64      `tfsdk:"route_metric"`
	InterfaceMetric   types.Int64      `tfsdk:"interface_metric"`
	EffectiveMetric   types.Int64      `tfsdk:"effective_metric"`
	Protocol          types.String     `tfsdk:"protocol"`
	MatchCount        types.Int64      `tfsdk:"match_count"`
	Timeouts          dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_net_route", the same
// Terraform type name as the sibling resource per ADR-0009).
func (d *windowsNetRouteDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_net_route"
}

// Schema returns the TPF schema for the windows_net_route data source.
func (d *windowsNetRouteDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of an existing persistent route on a remote Windows host " +
			"without managing it. Typical use: `data.windows_net_route.default_v4.next_hop` as the gateway address, " +
			"e.g. in a `precondition` guarding a default-gateway change.\n\n" +
			"Lookup is by `destination_prefix`, optionally narrowed by `interface_alias` and `next_hop`. " +
			"Several matches resolve deterministically to the one with the lowest `effective_metric` " +
			"(`match_count` tells how many matched); zero matches is an error.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: `<interface_alias>|<destination_prefix>|<next_hop>` of the winning route.",
			},
			"destination_prefix": schema.StringAttribute{
				Required:    true,
				Description: "Route destination in CIDR form (e.g. `\"198.51.100.0/24\"`, `\"0.0.0.0/0\"` for the IPv4 default route).",
			},
			"interface_alias": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the lookup to one interface alias (exact, case-insensitive match).",
			},
			"next_hop": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Gateway address. As a query input it narrows the lookup; the observed value of the winning route is stored.",
			},
			"interface_index": schema.Int64Attribute{
				Computed:    true,
				Description: "Numeric interface index owning the winning route, as observed on the host.",
			},
			"address_family": schema.StringAttribute{
				Computed:    true,
				Description: "Address family, as observed on the host (`IPv4` or `IPv6`).",
			},
			"route_metric": schema.Int64Attribute{
				Computed:    true,
				Description: "Route metric of the winning route, as observed on the host.",
			},
			"interface_metric": schema.Int64Attribute{
				Computed:    true,
				Description: "Interface metric from `Get-NetIPInterface`, as observed on the host.",
			},
			"effective_metric": schema.Int64Attribute{
				Computed:    true,
				Description: "Effective metric Windows uses for route selection (`route_metric` + `interface_metric`), as observed on the host.",
			},
			"protocol": schema.StringAttribute{
				Computed:    true,
				Description: "Route protocol, as observed on the host (`NetMgmt`, `Dhcp`, `Local`, ...).",
			},
			"match_count": schema.Int64Attribute{
				Computed:    true,
				Description: "How many routes matched the lookup before the lowest-effective-metric winner was picked.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to netRouteDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsNetRouteDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.routes = winclient.NewNetRouteClient(c)
}

// Read looks the route up via the sibling resource's NetRouteClient.Lookup.
// Zero matches surface as a `not found` diagnostic (never a silently
// cleared state); several matches resolve to the lowest effective metric
// winner. Other typed *winclient.NetRouteError values surface via
// addNetRouteDiag, mirroring the resource Read path.
func (d *windowsNetRouteDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsNetRouteDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, netRouteDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	prefix, err := canonicalNetRoutePrefix(config.DestinationPrefix.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid destination_prefix",
			fmt.Sprintf("destination_prefix must be a valid CIDR prefix; got %q.", config.DestinationPrefix.ValueString()),
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
	nextHop := ""
	if !config.NextHop.IsNull() && !config.NextHop.IsUnknown() && strings.TrimSpace(config.NextHop.ValueString()) != "" {
		nextHop, err = canonicalNetRouteNextHop(config.NextHop.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid next_hop",
				fmt.Sprintf("next_hop must be a valid IPv4 or IPv6 address; got %q.", config.NextHop.ValueString()),
			)
			return
		}
	}

	tflog.Debug(ctx, "windows_net_route data source Read start", map[string]interface{}{
		"destination_prefix": prefix, "interface_alias": alias, "next_hop": nextHop,
	})

	observed, err := d.routes.Lookup(ctx, prefix, alias, nextHop)
	if err != nil {
		var ne *winclient.NetRouteError
		if errors.As(err, &ne) && ne.Kind == winclient.NetRouteErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_net_route %q", prefix),
				fmt.Sprintf("No route %q was found on the target host.", prefix),
			)
			return
		}
		addNetRouteDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_net_route %q failed", prefix), err)
		return
	}
	if len(observed) == 0 {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_net_route %q", prefix),
			fmt.Sprintf("No route %q was found on the target host.", prefix),
		)
		return
	}
	winner := pickLowestEffectiveMetric(observed)

	state := windowsNetRouteDataSourceModel{
		ID:                types.StringValue(netRouteID(winner.InterfaceAlias, winner.DestinationPrefix, winner.NextHop)),
		DestinationPrefix: types.StringValue(winner.DestinationPrefix),
		InterfaceAlias:    types.StringValue(winner.InterfaceAlias),
		NextHop:           types.StringValue(winner.NextHop),
		InterfaceIndex:    types.Int64Value(int64(winner.InterfaceIndex)),
		AddressFamily:     types.StringValue(winner.AddressFamily),
		RouteMetric:       types.Int64Value(int64(winner.RouteMetric)),
		InterfaceMetric:   types.Int64Value(int64(winner.InterfaceMetric)),
		EffectiveMetric:   types.Int64Value(int64(winner.EffectiveMetric)),
		Protocol:          types.StringValue(winner.Protocol),
		MatchCount:        types.Int64Value(int64(len(observed))),
		Timeouts:          config.Timeouts,
	}

	tflog.Debug(ctx, "windows_net_route data source Read end", map[string]interface{}{
		"destination_prefix": state.DestinationPrefix.ValueString(),
		"id":                 state.ID.ValueString(),
		"match_count":        len(observed),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// pickLowestEffectiveMetric returns the route with the lowest effective
// metric, breaking ties deterministically by destination prefix, next hop,
// interface alias and interface index so plans stay stable.
func pickLowestEffectiveMetric(routes []*winclient.NetRouteInfo) *winclient.NetRouteInfo {
	winner := routes[0]
	for _, r := range routes[1:] {
		if routeLess(r, winner) {
			winner = r
		}
	}
	return winner
}

// routeLess orders routes by effective metric, then by identity fields for
// a deterministic winner.
func routeLess(a, b *winclient.NetRouteInfo) bool {
	if a.EffectiveMetric != b.EffectiveMetric {
		return a.EffectiveMetric < b.EffectiveMetric
	}
	if a.DestinationPrefix != b.DestinationPrefix {
		return a.DestinationPrefix < b.DestinationPrefix
	}
	if a.NextHop != b.NextHop {
		return a.NextHop < b.NextHop
	}
	if a.InterfaceAlias != b.InterfaceAlias {
		return a.InterfaceAlias < b.InterfaceAlias
	}
	return a.InterfaceIndex < b.InterfaceIndex
}
