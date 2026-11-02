// Package provider — unit tests for the windows_net_route data source.
//
// Tests cover: Metadata (same Terraform type name as the sibling resource),
// Schema (query keys, computed attributes), Configure, Read happy path (by
// prefix alone and with interface_alias/next_hop), lowest-effective-metric
// winner with match_count, not-found, generic errors, and blank-alias
// rejection.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeNetRouteClientDS struct {
	lookupPrefix string
	lookupAlias  string
	lookupNext   string
	lookupOut    []*winclient.NetRouteInfo
	lookupErr    error
}

func (f *fakeNetRouteClientDS) Read(_ context.Context, _, _, _ string) (*winclient.NetRouteInfo, error) {
	panic("Read not used in data source")
}

func (f *fakeNetRouteClientDS) Lookup(_ context.Context, prefix, alias, next string) ([]*winclient.NetRouteInfo, error) {
	f.lookupPrefix, f.lookupAlias, f.lookupNext = prefix, alias, next
	return f.lookupOut, f.lookupErr
}

func (f *fakeNetRouteClientDS) Create(_ context.Context, _ winclient.NetRouteInput) (*winclient.NetRouteInfo, error) {
	panic("Create not used in data source")
}

func (f *fakeNetRouteClientDS) Update(_ context.Context, _, _, _ string, _ int, _ bool) (*winclient.NetRouteInfo, error) {
	panic("Update not used in data source")
}

func (f *fakeNetRouteClientDS) Delete(_ context.Context, _, _, _ string, _ bool) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// Config helper
// ---------------------------------------------------------------------------

func nrDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"destination_prefix": tftypes.String,
		"interface_alias":    tftypes.String,
		"next_hop":           tftypes.String,
		"interface_index":    tftypes.Number,
		"address_family":     tftypes.String,
		"route_metric":       tftypes.Number,
		"interface_metric":   tftypes.Number,
		"effective_metric":   tftypes.Number,
		"protocol":           tftypes.String,
		"match_count":        tftypes.Number,
		"timeouts":           dsTimeoutsObjType(),
	}}
}

func nrDSConfig(prefix, alias, next string) tfsdk.Config {
	d := &windowsNetRouteDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	aliasVal := tftypes.NewValue(tftypes.String, nil)
	if alias != "" {
		aliasVal = tftypes.NewValue(tftypes.String, alias)
	}
	nextVal := tftypes.NewValue(tftypes.String, nil)
	if next != "" {
		nextVal = tftypes.NewValue(tftypes.String, next)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(nrDSObjType(), map[string]tftypes.Value{
			"id":                 tftypes.NewValue(tftypes.String, nil),
			"destination_prefix": tftypes.NewValue(tftypes.String, prefix),
			"interface_alias":    aliasVal,
			"next_hop":           nextVal,
			"interface_index":    tftypes.NewValue(tftypes.Number, nil),
			"address_family":     tftypes.NewValue(tftypes.String, nil),
			"route_metric":       tftypes.NewValue(tftypes.Number, nil),
			"interface_metric":   tftypes.NewValue(tftypes.Number, nil),
			"effective_metric":   tftypes.NewValue(tftypes.Number, nil),
			"protocol":           tftypes.NewValue(tftypes.String, nil),
			"match_count":        tftypes.NewValue(tftypes.Number, nil),
			"timeouts":           dsNullTimeoutsValue(),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

func TestNetRouteDSMetadata(t *testing.T) {
	d := &windowsNetRouteDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_net_route" {
		t.Errorf("TypeName = %q, want windows_net_route (same as the resource)", resp.TypeName)
	}
}

func TestNewWindowsNetRouteDataSource_NotNil(t *testing.T) {
	if NewWindowsNetRouteDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

func TestNetRouteDSSchema(t *testing.T) {
	d := &windowsNetRouteDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "destination_prefix", "interface_alias", "next_hop",
		"interface_index", "address_family", "route_metric", "interface_metric",
		"effective_metric", "protocol", "match_count", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestWindowsNetRouteDataSource_Configure(t *testing.T) {
	d := &windowsNetRouteDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func nrDSRoute(alias string, metric, ifMetric int) *winclient.NetRouteInfo {
	return &winclient.NetRouteInfo{
		InterfaceAlias:    alias,
		InterfaceIndex:    7,
		DestinationPrefix: "0.0.0.0/0",
		NextHop:           "192.0.2.1",
		RouteMetric:       metric,
		InterfaceMetric:   ifMetric,
		EffectiveMetric:   metric + ifMetric,
		AddressFamily:     "IPv4",
		Protocol:          "NetMgmt",
	}
}

func TestNetRouteDSRead_PicksLowestEffectiveMetric(t *testing.T) {
	fc := &fakeNetRouteClientDS{lookupOut: []*winclient.NetRouteInfo{
		nrDSRoute("Ethernet 3", 500, 25),
		nrDSRoute("Ethernet 2", 10, 25),
	}}
	d := &windowsNetRouteDataSource{routes: fc}
	req := datasource.ReadRequest{Config: nrDSConfig("0.0.0.0/0", "", "")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if fc.lookupPrefix != "0.0.0.0/0" || fc.lookupAlias != "" || fc.lookupNext != "" {
		t.Errorf("unexpected lookup args: %q %q %q", fc.lookupPrefix, fc.lookupAlias, fc.lookupNext)
	}
	var model windowsNetRouteDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	// The lowest effective metric (10+25) wins over 500+25.
	if model.InterfaceAlias.ValueString() != "Ethernet 2" {
		t.Errorf("winner = %q, want Ethernet 2", model.InterfaceAlias.ValueString())
	}
	if model.EffectiveMetric.ValueInt64() != 35 {
		t.Errorf("effective = %d, want 35", model.EffectiveMetric.ValueInt64())
	}
	if model.MatchCount.ValueInt64() != 2 {
		t.Errorf("match_count = %d, want 2", model.MatchCount.ValueInt64())
	}
	if model.ID.ValueString() != "Ethernet 2|0.0.0.0/0|192.0.2.1" {
		t.Errorf("id = %q", model.ID.ValueString())
	}
	if model.NextHop.ValueString() != "192.0.2.1" || model.Protocol.ValueString() != "NetMgmt" {
		t.Errorf("winner not projected: %+v", model)
	}
}

func TestNetRouteDSRead_NarrowedLookup(t *testing.T) {
	fc := &fakeNetRouteClientDS{lookupOut: []*winclient.NetRouteInfo{nrDSRoute("Ethernet 2", 10, 25)}}
	d := &windowsNetRouteDataSource{routes: fc}
	req := datasource.ReadRequest{Config: nrDSConfig("0.0.0.0/0", "Ethernet 2", "192.0.2.1")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if fc.lookupAlias != "Ethernet 2" || fc.lookupNext != "192.0.2.1" {
		t.Errorf("lookup must forward the qualifiers, got %q %q", fc.lookupAlias, fc.lookupNext)
	}
}

func TestNetRouteDSRead_NotFound(t *testing.T) {
	fc := &fakeNetRouteClientDS{lookupErr: winclient.NewNetRouteError(
		winclient.NetRouteErrorNotFound, "no route 198.51.100.0/24", nil, nil)}
	d := &windowsNetRouteDataSource{routes: fc}
	req := datasource.ReadRequest{Config: nrDSConfig("198.51.100.0/24", "", "")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("zero matches must error")
	}
	var found bool
	for _, dg := range resp.Diagnostics {
		if strings.Contains(dg.Summary()+dg.Detail(), "not found") {
			found = true
		}
	}
	if !found {
		t.Errorf("diagnostic must say not found, got %v", resp.Diagnostics)
	}
}

func TestNetRouteDSRead_BlankAliasRejected(t *testing.T) {
	fc := &fakeNetRouteClientDS{lookupOut: []*winclient.NetRouteInfo{nrDSRoute("Ethernet 2", 10, 25)}}
	d := &windowsNetRouteDataSource{routes: fc}
	req := datasource.ReadRequest{Config: nrDSConfig("0.0.0.0/0", "   ", "")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("whitespace-only alias must error instead of widening the lookup")
	}
	if fc.lookupPrefix != "" {
		t.Error("lookup must not run for a blank alias")
	}
}

func TestPickLowestEffectiveMetric_DeterministicTie(t *testing.T) {
	a := nrDSRoute("Ethernet 3", 10, 25)
	b := nrDSRoute("Ethernet 2", 10, 25)
	if pickLowestEffectiveMetric([]*winclient.NetRouteInfo{a, b}) != b {
		t.Error("tied effective metrics must break deterministically by alias")
	}
	if pickLowestEffectiveMetric([]*winclient.NetRouteInfo{b, a}) != b {
		t.Error("tie-break must be order-independent")
	}
}
