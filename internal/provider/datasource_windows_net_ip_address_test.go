// Package provider — unit tests for the windows_net_ip_address data source.
//
// Tests cover: Metadata (same Terraform type name as the sibling resource),
// Schema (query keys, computed attributes), Configure, Read happy path (by
// address alone and with interface_alias), not-found, ambiguous matches,
// generic errors, and blank-alias rejection.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeNetIPAddressClientDS struct {
	lookupIP    string
	lookupAlias string
	lookupOut   []*winclient.NetIPAddressInfo
	lookupErr   error
}

func (f *fakeNetIPAddressClientDS) Read(_ context.Context, _, _ string) (*winclient.NetIPAddressInfo, error) {
	panic("Read not used in data source")
}

func (f *fakeNetIPAddressClientDS) Lookup(_ context.Context, ip, alias string) ([]*winclient.NetIPAddressInfo, error) {
	f.lookupIP, f.lookupAlias = ip, alias
	return f.lookupOut, f.lookupErr
}

func (f *fakeNetIPAddressClientDS) Create(_ context.Context, _ winclient.NetIPAddressInput) (*winclient.NetIPAddressInfo, bool, error) {
	panic("Create not used in data source")
}

func (f *fakeNetIPAddressClientDS) Update(_ context.Context, _ string, _ string, _ int, _, _, _ bool) (*winclient.NetIPAddressInfo, bool, error) {
	panic("Update not used in data source")
}

func (f *fakeNetIPAddressClientDS) Delete(_ context.Context, _ string, _ string, _ bool) error {
	panic("Delete not used in data source")
}

func (f *fakeNetIPAddressClientDS) RestoreDHCP(_ context.Context, _ string) error {
	panic("RestoreDHCP not used in data source")
}

// ---------------------------------------------------------------------------
// Config helper
// ---------------------------------------------------------------------------

func niDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":              tftypes.String,
		"ip_address":      tftypes.String,
		"interface_alias": tftypes.String,
		"interface_index": tftypes.Number,
		"prefix_length":   tftypes.Number,
		"prefix_origin":   tftypes.String,
		"address_state":   tftypes.String,
		"address_family":  tftypes.String,
		"skip_as_source":  tftypes.Bool,
		"timeouts":        dsTimeoutsObjType(),
	}}
}

func niDSConfig(ip, alias string) tfsdk.Config {
	d := &windowsNetIPAddressDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	aliasVal := tftypes.NewValue(tftypes.String, nil)
	if alias != "" {
		aliasVal = tftypes.NewValue(tftypes.String, alias)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(niDSObjType(), map[string]tftypes.Value{
			"id":              tftypes.NewValue(tftypes.String, nil),
			"ip_address":      tftypes.NewValue(tftypes.String, ip),
			"interface_alias": aliasVal,
			"interface_index": tftypes.NewValue(tftypes.Number, nil),
			"prefix_length":   tftypes.NewValue(tftypes.Number, nil),
			"prefix_origin":   tftypes.NewValue(tftypes.String, nil),
			"address_state":   tftypes.NewValue(tftypes.String, nil),
			"address_family":  tftypes.NewValue(tftypes.String, nil),
			"skip_as_source":  tftypes.NewValue(tftypes.Bool, nil),
			"timeouts":        dsNullTimeoutsValue(),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

func TestNetIPAddressDSMetadata(t *testing.T) {
	d := &windowsNetIPAddressDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_net_ip_address" {
		t.Errorf("TypeName = %q, want windows_net_ip_address (same as the resource)", resp.TypeName)
	}
}

func TestNewWindowsNetIPAddressDataSource_NotNil(t *testing.T) {
	if NewWindowsNetIPAddressDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

func TestNetIPAddressDSSchema(t *testing.T) {
	d := &windowsNetIPAddressDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "ip_address", "interface_alias", "interface_index",
		"prefix_length", "prefix_origin", "address_state", "address_family",
		"skip_as_source", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestWindowsNetIPAddressDataSource_Configure(t *testing.T) {
	d := &windowsNetIPAddressDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressDataSource_Read_HappyPath(t *testing.T) {
	fc := &fakeNetIPAddressClientDS{lookupOut: []*winclient.NetIPAddressInfo{okNetAddressInfo()}}
	d := &windowsNetIPAddressDataSource{ip: fc}

	req := datasource.ReadRequest{Config: niDSConfig("192.0.2.10", "")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.lookupIP != "192.0.2.10" || fc.lookupAlias != "" {
		t.Errorf("lookup args = %q, %q", fc.lookupIP, fc.lookupAlias)
	}
	var model windowsNetIPAddressDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Ethernet 2|192.0.2.10" {
		t.Errorf("id = %q, want Ethernet 2|192.0.2.10", model.ID.ValueString())
	}
	if model.InterfaceIndex.ValueInt64() != 7 || model.PrefixLength.ValueInt64() != 24 {
		t.Errorf("unexpected state: %+v", model)
	}
}

func TestWindowsNetIPAddressDataSource_Read_WithAlias(t *testing.T) {
	fc := &fakeNetIPAddressClientDS{lookupOut: []*winclient.NetIPAddressInfo{okNetAddressInfo()}}
	d := &windowsNetIPAddressDataSource{ip: fc}

	req := datasource.ReadRequest{Config: niDSConfig("2001:DB8::0010", "Ethernet 2")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	// The lookup key is canonicalised before reaching the client.
	if fc.lookupIP != "2001:db8::10" || fc.lookupAlias != "Ethernet 2" {
		t.Errorf("lookup args = %q, %q", fc.lookupIP, fc.lookupAlias)
	}
}

func TestWindowsNetIPAddressDataSource_Read_NotFound(t *testing.T) {
	fc := &fakeNetIPAddressClientDS{lookupErr: winclient.NewNetIPAddressError(
		winclient.NetIPAddressErrorNotFound, "none", nil, nil)}
	d := &windowsNetIPAddressDataSource{ip: fc}

	req := datasource.ReadRequest{Config: niDSConfig("192.0.2.99", "")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("zero matches must error")
	}
}

func TestWindowsNetIPAddressDataSource_Read_Ambiguous(t *testing.T) {
	fc := &fakeNetIPAddressClientDS{lookupErr: winclient.NewNetIPAddressError(
		winclient.NetIPAddressErrorInUseElsewhere, "matches several", nil, nil)}
	d := &windowsNetIPAddressDataSource{ip: fc}

	req := datasource.ReadRequest{Config: niDSConfig("192.0.2.10", "")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("several matches must error")
	}
}

func TestWindowsNetIPAddressDataSource_Read_InvalidAddress(t *testing.T) {
	fc := &fakeNetIPAddressClientDS{lookupOut: []*winclient.NetIPAddressInfo{okNetAddressInfo()}}
	d := &windowsNetIPAddressDataSource{ip: fc}

	req := datasource.ReadRequest{Config: niDSConfig("not-an-ip", "")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("unparsable address must error before any lookup")
	}
	if fc.lookupIP != "" {
		t.Error("unparsable address must not reach the client")
	}
}

func TestWindowsNetIPAddressDataSource_Read_BlankAliasRejected(t *testing.T) {
	// A whitespace-only alias is rejected instead of widening the lookup
	// to all interfaces — and before any lookup runs.
	fc := &fakeNetIPAddressClientDS{lookupOut: []*winclient.NetIPAddressInfo{okNetAddressInfo()}}
	d := &windowsNetIPAddressDataSource{ip: fc}

	req := datasource.ReadRequest{Config: niDSConfig("192.0.2.10", "   ")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: req.Config.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("whitespace-only alias must error")
	}
	if fc.lookupIP != "" {
		t.Error("whitespace-only alias must not reach the client")
	}
}
