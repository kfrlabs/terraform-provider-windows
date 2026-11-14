// Package provider: windows_network_adapters data source implementation.
//
// Standalone collection data source — no sibling resource exists. Reads the
// network adapter inventory of the remote Windows host in a single
// round-trip, narrowed by optional filters (names, name_regex, mac_address,
// status, physical_only, include_hidden). The result is a sorted `adapters`
// list; an empty inventory match is valid (empty list, never an error).
//
// Filter inputs are Optional only (null means unfiltered; there is no
// framework bool default, so a null bool reads as false). `timeouts.read`
// defaults to 10m like the other net-family data sources.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsNetworkAdaptersDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsNetworkAdaptersDataSource)(nil)
)

// NewWindowsNetworkAdaptersDataSource is the constructor registered in
// provider.go.
func NewWindowsNetworkAdaptersDataSource() datasource.DataSource {
	return &windowsNetworkAdaptersDataSource{}
}

// windowsNetworkAdaptersDataSource is the TPF data source type for
// windows_network_adapters.
type windowsNetworkAdaptersDataSource struct {
	client winclient.WindowsNetworkAdaptersClient
}

// networkAdaptersDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. There is no sibling resource to
// reuse a default from, so it uses 10m like the other net-family
// (net_ip_address, net_route, dns_client) data sources, so a stalled
// session surfaces a timeout diagnostic instead of blocking plan forever.
const networkAdaptersDSDefaultTimeout = 10 * time.Minute

// windowsNetworkAdaptersDataSourceModel is the Terraform state model for
// the windows_network_adapters data source.
type windowsNetworkAdaptersDataSourceModel struct {
	ID            types.String     `tfsdk:"id"`
	Names         types.Set        `tfsdk:"names"`
	NameRegex     types.String     `tfsdk:"name_regex"`
	MACAddress    types.String     `tfsdk:"mac_address"`
	Status        types.String     `tfsdk:"status"`
	PhysicalOnly  types.Bool       `tfsdk:"physical_only"`
	IncludeHidden types.Bool       `tfsdk:"include_hidden"`
	Adapters      types.List       `tfsdk:"adapters"`
	Timeouts      dstimeouts.Value `tfsdk:"timeouts"`
}

// windowsNetworkAdaptersObjectType is the element type of the adapters
// list: one object per matching adapter.
func windowsNetworkAdaptersObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":                  types.StringType,
		"interface_index":       types.Int64Type,
		"interface_description": types.StringType,
		"mac_address":           types.StringType,
		"status":                types.StringType,
		"admin_enabled":         types.BoolType,
		"link_speed_bps":        types.Int64Type,
		"media_type":            types.StringType,
		"physical_media_type":   types.StringType,
		"is_physical":           types.BoolType,
		"is_virtual":            types.BoolType,
		"vlan_id":               types.Int64Type,
		"driver_description":    types.StringType,
		"driver_version":        types.StringType,
		"driver_provider":       types.StringType,
		"mtu_ipv4":              types.Int64Type,
		"mtu_ipv6":              types.Int64Type,
		"dhcp_enabled":          types.BoolType,
		"ipv4_addresses":        types.ListType{ElemType: types.StringType},
		"ipv6_addresses":        types.ListType{ElemType: types.StringType},
		"default_gateways":      types.ListType{ElemType: types.StringType},
		"dns_servers":           types.ListType{ElemType: types.StringType},
		"network_category":      types.StringType,
		"is_management":         types.BoolType,
	}}
}

// Metadata sets the data source type name ("windows_network_adapters").
func (d *windowsNetworkAdaptersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_adapters"
}

// Schema returns the TPF schema for the windows_network_adapters data
// source.
func (d *windowsNetworkAdaptersDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the network adapter inventory of the remote Windows host without " +
			"managing it. This is a **standalone collection** data source — no sibling resource exists.\n\n" +
			"Optional filters narrow the result: `names` (exact, case-insensitive), `name_regex` (RE2 " +
			"match on the adapter name), `mac_address` (any common spelling), `status` (`Up`, " +
			"`Disconnected`, `Disabled` or `NotPresent`, case-insensitive), `physical_only` (pass " +
			"`-Physical` to `Get-NetAdapter`) and `include_hidden` (pass `-IncludeHidden`). " +
			"Omitted filters match everything.\n\n" +
			"`adapters` carries one object per matching adapter, sorted by `interface_index`; an " +
			"empty match is a valid empty list, never an error. `is_management` marks the adapter " +
			"owning the address of the current SSH session (advisory inventory; never asserted in " +
			"automation because it is host-dependent). Unbound MTUs report `null` (the host has no " +
			"family address to size); unreported strings report `\"\"`.\n\n" +
			"The Terraform data source ID is a query-ID: the hex SHA-256 of the normalised filter set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID (query-ID); hex SHA-256 of the normalised filter set (sorted lower-case names, regex, normalised MAC, upper-case status, bools).",
			},
			"names": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Restrict the result to these adapter names (exact, case-insensitive). Omit to match every name.",
			},
			"name_regex": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to adapter names matching this RE2 regular expression.",
			},
			"mac_address": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to the adapter with this MAC address, in any common spelling (colons, dashes, dots, any case).",
			},
			"status": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to one adapter status: Up, Disconnected, Disabled or NotPresent (case-insensitive).",
			},
			"physical_only": schema.BoolAttribute{
				Optional:    true,
				Description: "Pass -Physical to Get-NetAdapter. Omit (null) means false.",
			},
			"include_hidden": schema.BoolAttribute{
				Optional:    true,
				Description: "Pass -IncludeHidden to Get-NetAdapter. Omit (null) means false.",
			},
			"adapters": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Adapter friendly name, as observed on the host.",
						},
						"interface_index": schema.Int64Attribute{
							Computed:    true,
							Description: "Numeric interface index, as observed on the host.",
						},
						"interface_description": schema.StringAttribute{
							Computed:    true,
							Description: "Driver description string, as observed on the host.",
						},
						"mac_address": schema.StringAttribute{
							Computed:    true,
							Description: "Adapter MAC in lower aa:bb:cc:dd:ee:ff form; empty when the host reports none.",
						},
						"status": schema.StringAttribute{
							Computed:    true,
							Description: "Derived adapter status: Up, Disconnected, Disabled or NotPresent.",
						},
						"admin_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "True unless the adapter AdminStatus is Down.",
						},
						"link_speed_bps": schema.Int64Attribute{
							Computed:    true,
							Description: "Receive link speed in bits per second; 0 when unknown or disconnected.",
						},
						"media_type": schema.StringAttribute{
							Computed:    true,
							Description: "NdisMedium mapped to its documented name (e.g. 802.3); empty when unknown.",
						},
						"physical_media_type": schema.StringAttribute{
							Computed:    true,
							Description: "NdisPhysicalMedium mapped to its documented name (e.g. 802.3); empty when unknown.",
						},
						"is_physical": schema.BoolAttribute{
							Computed:    true,
							Description: "True for physical adapters (negation of the host Virtual flag).",
						},
						"is_virtual": schema.BoolAttribute{
							Computed:    true,
							Description: "Host-reported Virtual flag.",
						},
						"vlan_id": schema.Int64Attribute{
							Computed:    true,
							Description: "Adapter VLAN ID; 0 when untagged or unreported.",
						},
						"driver_description": schema.StringAttribute{
							Computed:    true,
							Description: "Driver description; empty when unreported.",
						},
						"driver_version": schema.StringAttribute{
							Computed:    true,
							Description: "Driver version; empty when unreported.",
						},
						"driver_provider": schema.StringAttribute{
							Computed:    true,
							Description: "Driver provider; empty when unreported.",
						},
						"mtu_ipv4": schema.Int64Attribute{
							Computed:    true,
							Description: "IPv4 NlMtu; null when the family is unbound on the interface.",
						},
						"mtu_ipv6": schema.Int64Attribute{
							Computed:    true,
							Description: "IPv6 NlMtu; null when the family is unbound on the interface.",
						},
						"dhcp_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "True when DHCP is enabled on the IPv4 interface.",
						},
						"ipv4_addresses": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Bound IPv4 addresses in canonical CIDR form, sorted.",
						},
						"ipv6_addresses": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Bound IPv6 addresses in canonical CIDR form (link-local kept), sorted.",
						},
						"default_gateways": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Default-route next hops covering this interface, sorted.",
						},
						"dns_servers": schema.ListAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "Effective DNS servers for this interface, sorted.",
						},
						"network_category": schema.StringAttribute{
							Computed:    true,
							Description: "Connection-profile category; empty when the interface has no profile.",
						},
						"is_management": schema.BoolAttribute{
							Computed:    true,
							Description: "True when this adapter owns the address of the current SSH session (advisory; never assert it in automation).",
						},
					},
				},
				Description: "Matching adapters, sorted by interface_index. Empty when no adapter matches the filters.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to
			// networkAdaptersDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the NetworkAdaptersClient.
func (d *windowsNetworkAdaptersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewNetworkAdaptersClient(c)
}

// networkAdaptersFilterID builds the data source ID: the hex SHA-256 of the
// normalised filter set (sorted lower-case names, raw regex, normalised
// MAC, upper-case status, bools), so identical filters share an ID and any
// filter change moves it.
func networkAdaptersFilterID(names []string, regex, mac, status string, physical, hidden bool) string {
	lower := make([]string, 0, len(names))
	for _, n := range names {
		if strings.TrimSpace(n) != "" {
			lower = append(lower, strings.ToLower(strings.TrimSpace(n)))
		}
	}
	sort.Strings(lower)
	// Normalise the MAC through the same canonicaliser the List path
	// uses, so every spelling of one address hashes to the same ID. An
	// invalid MAC never reaches the host (List fails validation first),
	// so fall back to the lower/trimmed raw value for hashing.
	macCanon := strings.ToLower(strings.TrimSpace(mac))
	if strings.TrimSpace(mac) != "" {
		if norm, merr := winclient.NormalizeNetworkAdapterMAC(mac); merr == nil {
			macCanon = norm
		}
	}
	canonical := strings.Join(lower, ",") + "|" + regex + "|" +
		macCanon + "|" +
		strings.ToUpper(strings.TrimSpace(status)) + "|" +
		strconv.FormatBool(physical) + "|" + strconv.FormatBool(hidden)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// Read lists the adapters matching the configured filters.
func (d *windowsNetworkAdaptersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsNetworkAdaptersDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, networkAdaptersDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	var names []string
	if !config.Names.IsNull() && !config.Names.IsUnknown() {
		resp.Diagnostics.Append(config.Names.ElementsAs(ctx, &names, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	regex := ""
	if !config.NameRegex.IsNull() && !config.NameRegex.IsUnknown() {
		regex = config.NameRegex.ValueString()
	}
	mac := ""
	if !config.MACAddress.IsNull() && !config.MACAddress.IsUnknown() {
		mac = config.MACAddress.ValueString()
	}
	status := ""
	if !config.Status.IsNull() && !config.Status.IsUnknown() {
		status = config.Status.ValueString()
	}
	physical := false
	if !config.PhysicalOnly.IsNull() && !config.PhysicalOnly.IsUnknown() {
		physical = config.PhysicalOnly.ValueBool()
	}
	hidden := false
	if !config.IncludeHidden.IsNull() && !config.IncludeHidden.IsUnknown() {
		hidden = config.IncludeHidden.ValueBool()
	}

	tflog.Debug(ctx, "windows_network_adapters data source Read start", map[string]interface{}{
		"names": names, "name_regex": regex, "mac_address": mac, "status": status,
		"physical_only": physical, "include_hidden": hidden,
	})

	adapters, err := d.client.List(ctx, winclient.NetworkAdapterFilter{
		Names:         names,
		NameRegex:     regex,
		MACAddress:    mac,
		Status:        status,
		PhysicalOnly:  physical,
		IncludeHidden: hidden,
	})
	if err != nil {
		addNetworkAdaptersDiag(&resp.Diagnostics, "Read windows_network_adapters failed", err)
		return
	}

	state := windowsNetworkAdaptersDataSourceModel{
		ID:            types.StringValue(networkAdaptersFilterID(names, regex, mac, status, physical, hidden)),
		Names:         config.Names,
		NameRegex:     config.NameRegex,
		MACAddress:    config.MACAddress,
		Status:        config.Status,
		PhysicalOnly:  config.PhysicalOnly,
		IncludeHidden: config.IncludeHidden,
		Timeouts:      config.Timeouts,
	}

	objType := windowsNetworkAdaptersObjectType()
	objs := make([]attr.Value, 0, len(adapters))
	for _, a := range adapters {
		obj, d := networkAdapterToObject(ctx, objType, a)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		objs = append(objs, obj)
	}
	adaptersList, diags := types.ListValue(objType, objs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Adapters = adaptersList

	tflog.Debug(ctx, "windows_network_adapters data source Read end", map[string]interface{}{
		"id":            state.ID.ValueString(),
		"adapter_count": len(adapters),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// networkAdapterStringList projects a Go string slice onto a Terraform list
// value. A nil or empty slice becomes an empty (non-null) list so plans stay
// stable.
func networkAdapterStringList(ctx context.Context, diags *diag.Diagnostics, in []string) types.List {
	if in == nil {
		in = []string{}
	}
	list, d := types.ListValueFrom(ctx, types.StringType, in)
	diags.Append(d...)
	return list
}

// networkAdapterMTU projects a winclient MTU (0 means unbound) onto a
// Terraform int: 0 renders null, anything else its value.
func networkAdapterMTU(mtu int64) types.Int64 {
	if mtu == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(mtu)
}

// networkAdapterToObject projects one winclient.NetworkAdapter onto the
// adapters element object type.
func networkAdapterToObject(ctx context.Context, objType types.ObjectType, a winclient.NetworkAdapter) (attr.Value, diag.Diagnostics) {
	var diags diag.Diagnostics
	return types.ObjectValue(objType.AttrTypes, map[string]attr.Value{
		"name":                  types.StringValue(a.Name),
		"interface_index":       types.Int64Value(a.InterfaceIndex),
		"interface_description": types.StringValue(a.InterfaceDescription),
		"mac_address":           types.StringValue(a.MACAddress),
		"status":                types.StringValue(a.Status),
		"admin_enabled":         types.BoolValue(a.AdminEnabled),
		"link_speed_bps":        types.Int64Value(a.LinkSpeedBps),
		"media_type":            types.StringValue(a.MediaType),
		"physical_media_type":   types.StringValue(a.PhysicalMediaType),
		"is_physical":           types.BoolValue(a.IsPhysical),
		"is_virtual":            types.BoolValue(a.IsVirtual),
		"vlan_id":               types.Int64Value(a.VlanID),
		"driver_description":    types.StringValue(a.DriverDescription),
		"driver_version":        types.StringValue(a.DriverVersion),
		"driver_provider":       types.StringValue(a.DriverProvider),
		"mtu_ipv4":              networkAdapterMTU(a.MTUIPv4),
		"mtu_ipv6":              networkAdapterMTU(a.MTUIPv6),
		"dhcp_enabled":          types.BoolValue(a.DHCPEnabled),
		"ipv4_addresses":        networkAdapterStringList(ctx, &diags, a.IPv4Addresses),
		"ipv6_addresses":        networkAdapterStringList(ctx, &diags, a.IPv6Addresses),
		"default_gateways":      networkAdapterStringList(ctx, &diags, a.DefaultGateways),
		"dns_servers":           networkAdapterStringList(ctx, &diags, a.DNSServers),
		"network_category":      types.StringValue(a.NetworkCategory),
		"is_management":         types.BoolValue(a.IsManagement),
	})
}

// addNetworkAdaptersDiag converts a *winclient.NetworkAdapterError into a
// TPF diagnostic.
func addNetworkAdaptersDiag(diags *diag.Diagnostics, summary string, err error) {
	var ne *winclient.NetworkAdapterError
	if errors.As(err, &ne) {
		detail := ne.Message
		if len(ne.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range ne.Context {
				detail += "\n  " + k + " = " + v
			}
		}
		if ne.Cause != nil {
			detail += "\n\nCause: " + ne.Cause.Error()
		}
		if ne.Kind != "" {
			detail += "\n\nKind: " + string(ne.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
