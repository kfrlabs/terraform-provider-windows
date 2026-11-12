// Package provider — unit tests for the windows_network_adapters data
// source.
//
// windows_network_adapters is a standalone collection: optional filters,
// sorted `adapters` ListNested output, empty match is valid. Tests cover:
// Metadata, Schema, Configure, Read happy-path mapping (MTU null, empty
// lists non-null), filter passing, Read error, empty result, ID stability
// and timeout bounding.
package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeNetworkAdaptersClientDS struct {
	gotFilter winclient.NetworkAdapterFilter
	listOut   []winclient.NetworkAdapter
	listErr   error

	deadline time.Time
	ok       bool
}

func (f *fakeNetworkAdaptersClientDS) List(ctx context.Context, filter winclient.NetworkAdapterFilter) ([]winclient.NetworkAdapter, error) {
	f.gotFilter = filter
	f.deadline, f.ok = ctx.Deadline()
	return f.listOut, f.listErr
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func naDSAdapterElemType() tftypes.Object {
	strList := func() tftypes.Type { return tftypes.List{ElementType: tftypes.String} }
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"name":                  tftypes.String,
		"interface_index":       tftypes.Number,
		"interface_description": tftypes.String,
		"mac_address":           tftypes.String,
		"status":                tftypes.String,
		"admin_enabled":         tftypes.Bool,
		"link_speed_bps":        tftypes.Number,
		"media_type":            tftypes.String,
		"physical_media_type":   tftypes.String,
		"is_physical":           tftypes.Bool,
		"is_virtual":            tftypes.Bool,
		"vlan_id":               tftypes.Number,
		"driver_description":    tftypes.String,
		"driver_version":        tftypes.String,
		"driver_provider":       tftypes.String,
		"mtu_ipv4":              tftypes.Number,
		"mtu_ipv6":              tftypes.Number,
		"dhcp_enabled":          tftypes.Bool,
		"ipv4_addresses":        strList(),
		"ipv6_addresses":        strList(),
		"default_gateways":      strList(),
		"dns_servers":           strList(),
		"network_category":      tftypes.String,
		"is_management":         tftypes.Bool,
	}}
}

func naDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":             tftypes.String,
		"names":          tftypes.Set{ElementType: tftypes.String},
		"name_regex":     tftypes.String,
		"mac_address":    tftypes.String,
		"status":         tftypes.String,
		"physical_only":  tftypes.Bool,
		"include_hidden": tftypes.Bool,
		"adapters":       tftypes.List{ElementType: naDSAdapterElemType()},
		"timeouts":       dsTimeoutsObjType(),
	}}
}

func naDSBaseVals() map[string]tftypes.Value {
	obj := naDSObjType()
	vals := map[string]tftypes.Value{}
	for name, typ := range obj.AttributeTypes {
		if name == "timeouts" {
			vals[name] = dsNullTimeoutsValue()
			continue
		}
		vals[name] = tftypes.NewValue(typ, nil)
	}
	return vals
}

// naDSConfig builds a config with the given filters; nil names means a null
// set, "" strings mean null, nil bools mean null.
func naDSConfig(names []string, regex, mac, status string, physical, hidden *bool) tfsdk.Config {
	d := &windowsNetworkAdaptersDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := naDSBaseVals()
	if names != nil {
		elems := make([]tftypes.Value, len(names))
		for i, n := range names {
			elems[i] = tftypes.NewValue(tftypes.String, n)
		}
		vals["names"] = tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, elems)
	}
	if regex != "" {
		vals["name_regex"] = tftypes.NewValue(tftypes.String, regex)
	}
	if mac != "" {
		vals["mac_address"] = tftypes.NewValue(tftypes.String, mac)
	}
	if status != "" {
		vals["status"] = tftypes.NewValue(tftypes.String, status)
	}
	if physical != nil {
		vals["physical_only"] = tftypes.NewValue(tftypes.Bool, *physical)
	}
	if hidden != nil {
		vals["include_hidden"] = tftypes.NewValue(tftypes.Bool, *hidden)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(naDSObjType(), vals),
	}
}

func naBool(b bool) *bool { return &b }

func fakeNetworkAdapterFull() winclient.NetworkAdapter {
	return winclient.NetworkAdapter{
		Name:                 "Ethernet",
		InterfaceIndex:       7,
		InterfaceDescription: "Test Adapter",
		MACAddress:           "aa:bb:cc:dd:ee:ff",
		Status:               "Up",
		AdminEnabled:         true,
		LinkSpeedBps:         1000000000,
		MediaType:            "802.3",
		PhysicalMediaType:    "802.3",
		IsPhysical:           true,
		IsVirtual:            false,
		VlanID:               0,
		DriverDescription:    "Test Driver",
		DriverVersion:        "1.0",
		DriverProvider:       "Test",
		MTUIPv4:              1500,
		MTUIPv6:              1500,
		DHCPEnabled:          true,
		IPv4Addresses:        []string{"192.168.1.10/24"},
		IPv6Addresses:        []string{"fe80::1/64"},
		DefaultGateways:      []string{"192.168.1.1"},
		DNSServers:           []string{"192.168.1.1"},
		NetworkCategory:      "Private",
		IsManagement:         true,
	}
}

func fakeNetworkAdapterSparse() winclient.NetworkAdapter {
	return winclient.NetworkAdapter{
		Name:           "Ethernet 2",
		InterfaceIndex: 9,
		Status:         "Disconnected",
		AdminEnabled:   true,
		// MTUIPv4/MTUIPv6 0 (unbound), empty slices, empty strings.
	}
}

// naAdapterAttr extracts one adapters element as an attribute map.
func naAttrString(t *testing.T, m map[string]attr.Value, key string) types.String {
	t.Helper()
	v, ok := m[key].(types.String)
	if !ok {
		t.Fatalf("%s is %T, want types.String", key, m[key])
	}
	return v
}

func naAttrInt64(t *testing.T, m map[string]attr.Value, key string) types.Int64 {
	t.Helper()
	v, ok := m[key].(types.Int64)
	if !ok {
		t.Fatalf("%s is %T, want types.Int64", key, m[key])
	}
	return v
}

func naAttrBool(t *testing.T, m map[string]attr.Value, key string) types.Bool {
	t.Helper()
	v, ok := m[key].(types.Bool)
	if !ok {
		t.Fatalf("%s is %T, want types.Bool", key, m[key])
	}
	return v
}

func naAttrList(t *testing.T, m map[string]attr.Value, key string) types.List {
	t.Helper()
	v, ok := m[key].(types.List)
	if !ok {
		t.Fatalf("%s is %T, want types.List", key, m[key])
	}
	return v
}

func naAdapterAttr(t *testing.T, state windowsNetworkAdaptersDataSourceModel, i int) map[string]attr.Value {
	t.Helper()
	elems := state.Adapters.Elements()
	if len(elems) <= i {
		t.Fatalf("adapters has %d elements, want index %d", len(elems), i)
	}
	obj, ok := elems[i].(interface{ Attributes() map[string]attr.Value })
	if !ok {
		t.Fatalf("element %d is %T, want an object", i, elems[i])
	}
	return obj.Attributes()
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

func TestNetworkAdaptersDSMetadata(t *testing.T) {
	d := &windowsNetworkAdaptersDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_network_adapters" {
		t.Errorf("TypeName = %q, want windows_network_adapters", resp.TypeName)
	}
}

func TestNewWindowsNetworkAdaptersDataSource_NotNil(t *testing.T) {
	if NewWindowsNetworkAdaptersDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

func TestNetworkAdaptersDSSchema(t *testing.T) {
	d := &windowsNetworkAdaptersDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "names", "name_regex", "mac_address", "status",
		"physical_only", "include_hidden", "adapters", "timeouts",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(resp.Schema.Attributes) != len(want) {
		t.Errorf("schema has %d attributes, want %d", len(resp.Schema.Attributes), len(want))
	}
}

func TestNetworkAdaptersDSConfigure(t *testing.T) {
	d := &windowsNetworkAdaptersDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}

	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}

	d2 := &windowsNetworkAdaptersDataSource{}
	resp2 := &datasource.ConfigureResponse{}
	d2.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp2.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestNetworkAdaptersDSRead_HappyPath(t *testing.T) {
	fc := &fakeNetworkAdaptersClientDS{listOut: []winclient.NetworkAdapter{
		fakeNetworkAdapterFull(),
		fakeNetworkAdapterSparse(),
	}}
	d := &windowsNetworkAdaptersDataSource{client: fc}
	cfg := naDSConfig(nil, "", "", "", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var state windowsNetworkAdaptersDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must be set (filter hash)")
	}
	if len(state.Adapters.Elements()) != 2 {
		t.Fatalf("adapters has %d elements, want 2", len(state.Adapters.Elements()))
	}

	full := naAdapterAttr(t, state, 0)
	if naAttrString(t, full, "name").ValueString() != "Ethernet" {
		t.Errorf("name = %v", full["name"])
	}
	if naAttrInt64(t, full, "interface_index").ValueInt64() != 7 {
		t.Errorf("interface_index = %v", full["interface_index"])
	}
	if naAttrString(t, full, "mac_address").ValueString() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac_address = %v", full["mac_address"])
	}
	if naAttrInt64(t, full, "mtu_ipv4").ValueInt64() != 1500 {
		t.Errorf("mtu_ipv4 = %v, want 1500", full["mtu_ipv4"])
	}
	if !naAttrBool(t, full, "is_management").ValueBool() {
		t.Error("is_management should be true")
	}
	v4 := naAttrList(t, full, "ipv4_addresses")
	if v4.IsNull() || len(v4.Elements()) != 1 {
		t.Errorf("ipv4_addresses should hold 1 element, got %v", v4)
	}

	// Sparse adapter: unbound MTUs are null, empty lists are non-null.
	sparse := naAdapterAttr(t, state, 1)
	if !naAttrInt64(t, sparse, "mtu_ipv4").IsNull() {
		t.Errorf("unbound mtu_ipv4 must be null, got %v", sparse["mtu_ipv4"])
	}
	if !naAttrInt64(t, sparse, "mtu_ipv6").IsNull() {
		t.Errorf("unbound mtu_ipv6 must be null, got %v", sparse["mtu_ipv6"])
	}
	for _, k := range []string{"ipv4_addresses", "ipv6_addresses", "default_gateways", "dns_servers"} {
		l := naAttrList(t, sparse, k)
		if l.IsNull() {
			t.Errorf("%s must be an empty list, not null", k)
		}
		if len(l.Elements()) != 0 {
			t.Errorf("%s must be empty, got %v", k, l)
		}
	}
	if naAttrString(t, sparse, "mac_address").IsNull() {
		t.Error("empty mac_address must be empty, not null")
	}
}

func TestNetworkAdaptersDSRead_FiltersPassed(t *testing.T) {
	fc := &fakeNetworkAdaptersClientDS{listOut: []winclient.NetworkAdapter{}}
	d := &windowsNetworkAdaptersDataSource{client: fc}
	cfg := naDSConfig([]string{"Ethernet", "ethernet 2"}, `vEth.*`, "AA-BB-CC-DD-EE-FF", "Up", naBool(true), naBool(false))
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if len(fc.gotFilter.Names) != 2 || fc.gotFilter.Names[0] != "Ethernet" || fc.gotFilter.Names[1] != "ethernet 2" {
		t.Errorf("names not passed through: %v", fc.gotFilter.Names)
	}
	if fc.gotFilter.NameRegex != `vEth.*` || fc.gotFilter.MACAddress != "AA-BB-CC-DD-EE-FF" || fc.gotFilter.Status != "Up" {
		t.Errorf("scalar filters not passed through: %+v", fc.gotFilter)
	}
	if !fc.gotFilter.PhysicalOnly || fc.gotFilter.IncludeHidden {
		t.Errorf("bool filters not passed through: %+v", fc.gotFilter)
	}
}

func TestNetworkAdaptersDSRead_Error(t *testing.T) {
	fc := &fakeNetworkAdaptersClientDS{listErr: winclient.NewNetworkAdapterError(
		winclient.NetworkAdapterErrorCIMUnavailable, "cim down", nil, nil)}
	d := &windowsNetworkAdaptersDataSource{client: fc}
	cfg := naDSConfig(nil, "", "", "", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from list failure")
	}
}

func TestNetworkAdaptersDSRead_EmptyResultNoError(t *testing.T) {
	fc := &fakeNetworkAdaptersClientDS{listOut: []winclient.NetworkAdapter{}}
	d := &windowsNetworkAdaptersDataSource{client: fc}
	cfg := naDSConfig(nil, "", "", "Disabled", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("empty match must not error: %v", resp.Diagnostics)
	}
	var state windowsNetworkAdaptersDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.Adapters.IsNull() {
		t.Error("adapters must be an empty list, not null")
	}
	if len(state.Adapters.Elements()) != 0 {
		t.Errorf("adapters must be empty, got %d elements", len(state.Adapters.Elements()))
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must still be set for an empty match")
	}
}

func naDSReadID(t *testing.T, cfg tfsdk.Config) string {
	t.Helper()
	fc := &fakeNetworkAdaptersClientDS{listOut: []winclient.NetworkAdapter{}}
	d := &windowsNetworkAdaptersDataSource{client: fc}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", resp.Diagnostics)
	}
	var state windowsNetworkAdaptersDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	return state.ID.ValueString()
}

func TestNetworkAdaptersDSRead_IDStability(t *testing.T) {
	a := naDSReadID(t, naDSConfig(nil, "", "", "Up", nil, nil))
	b := naDSReadID(t, naDSConfig(nil, "", "", "up", nil, nil))
	if a != b {
		t.Errorf("same filter, different ID: %q vs %q", a, b)
	}
	c := naDSReadID(t, naDSConfig([]string{"b", "a"}, "", "", "Up", nil, nil))
	d := naDSReadID(t, naDSConfig([]string{"a", "b"}, "", "", "Up", nil, nil))
	if c != d {
		t.Errorf("name order must not move the ID: %q vs %q", c, d)
	}
	if a == c {
		t.Error("adding names must change the ID")
	}
	e := naDSReadID(t, naDSConfig(nil, "", "", "Disconnected", nil, nil))
	if a == e {
		t.Error("changing status must change the ID")
	}
	f := naDSReadID(t, naDSConfig(nil, "", "", "Up", naBool(true), nil))
	if a == f {
		t.Error("changing physical_only must change the ID")
	}
}

func TestNetworkAdaptersDSRead_IDMACNormalization(t *testing.T) {
	// Every spelling of one MAC hashes to the same ID; a different MAC
	// moves it.
	a := naDSReadID(t, naDSConfig(nil, "", "AA-BB-CC-DD-EE-FF", "", nil, nil))
	b := naDSReadID(t, naDSConfig(nil, "", "aa:bb:cc:dd:ee:ff", "", nil, nil))
	c := naDSReadID(t, naDSConfig(nil, "", "aabb.ccdd.eeff", "", nil, nil))
	if a != b || a != c {
		t.Errorf("same MAC, different spellings must share an ID: %q vs %q vs %q", a, b, c)
	}
	d := naDSReadID(t, naDSConfig(nil, "", "11-22-33-44-55-66", "", nil, nil))
	if a == d {
		t.Error("a different MAC must change the ID")
	}
}

// TestNetworkAdaptersDSRead_BoundedByTimeouts verifies the data source Read
// runs under a deadline derived from `timeouts.read` (issue #197):
// networkAdaptersDSDefaultTimeout when the block is absent, the configured
// value when set.
func TestNetworkAdaptersDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", networkAdaptersDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeNetworkAdaptersClientDS{listOut: []winclient.NetworkAdapter{}}
			d := &windowsNetworkAdaptersDataSource{client: fake}
			cfg := naDSConfig(nil, "", "", "", nil, nil)
			if tc.customRead != "" {
				cfg = dsConfigWithReadTimeout(t, cfg, tc.customRead)
			}
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
			d.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound (issue #197)")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
	}
}

func TestNetworkAdaptersDSConfigure_WrongType(t *testing.T) {
	d := &windowsNetworkAdaptersDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 42}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}
