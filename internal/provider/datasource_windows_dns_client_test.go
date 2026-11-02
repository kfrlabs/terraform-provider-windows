// Package provider — unit tests for the windows_dns_client data source.
//
// These tests exercise the schema and Read handler without touching SSH by
// reusing the fakeDNSClient from the sibling resource tests.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func TestDNSClientDataSourceMetadata(t *testing.T) {
	d := &windowsDNSClientDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_dns_client" {
		t.Errorf("TypeName = %q, want windows_dns_client", resp.TypeName)
	}
}

func TestNewWindowsDNSClientDataSource_NotNil(t *testing.T) {
	if NewWindowsDNSClientDataSource() == nil {
		t.Fatal("NewWindowsDNSClientDataSource must not return nil")
	}
}

func TestDNSClientDataSourceConfigure(t *testing.T) {
	d := &windowsDNSClientDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op: %v", resp.Diagnostics)
	}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "bad-type"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should produce an error diagnostic")
	}
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	d2 := &windowsDNSClientDataSource{}
	resp2 := &datasource.ConfigureResponse{}
	d2.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: c}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp2.Diagnostics)
	}
	if d2.dns == nil {
		t.Error("Configure must populate dns field")
	}
}

func TestDNSClientDataSourceSchema_HasRequiredAttributes(t *testing.T) {
	d := &windowsDNSClientDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{"id", "interface_alias", "ipv4_server_addresses", "ipv6_server_addresses",
		"connection_specific_suffix", "register_this_connection_address", "use_suffix_when_registering",
		"interface_index", "interface_guid", "effective_ipv4", "effective_ipv6", "timeouts"}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

// dnsDSObj builds a data source config value carrying only the alias.
func dnsDSObj(alias string) tftypes.Value {
	strList := tftypes.List{ElementType: tftypes.String}
	nullList := tftypes.NewValue(strList, nil)
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                               tftypes.String,
		"interface_alias":                  tftypes.String,
		"ipv4_server_addresses":            strList,
		"ipv6_server_addresses":            strList,
		"connection_specific_suffix":       tftypes.String,
		"register_this_connection_address": tftypes.Bool,
		"use_suffix_when_registering":      tftypes.Bool,
		"interface_index":                  tftypes.Number,
		"interface_guid":                   tftypes.String,
		"effective_ipv4":                   strList,
		"effective_ipv6":                   strList,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"read": tftypes.String,
		}},
	}}, map[string]tftypes.Value{
		"id":                               tftypes.NewValue(tftypes.String, nil),
		"interface_alias":                  tftypes.NewValue(tftypes.String, alias),
		"ipv4_server_addresses":            nullList,
		"ipv6_server_addresses":            nullList,
		"connection_specific_suffix":       tftypes.NewValue(tftypes.String, nil),
		"register_this_connection_address": tftypes.NewValue(tftypes.Bool, nil),
		"use_suffix_when_registering":      tftypes.NewValue(tftypes.Bool, nil),
		"interface_index":                  tftypes.NewValue(tftypes.Number, nil),
		"interface_guid":                   tftypes.NewValue(tftypes.String, nil),
		"effective_ipv4":                   nullList,
		"effective_ipv6":                   nullList,
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"read": tftypes.String,
		}}, nil),
	})
}

func TestDNSClientDataSourceRead_HappyPath(t *testing.T) {
	fake := &fakeDNSClient{readOut: fakeDNSState()}
	d := &windowsDNSClientDataSource{dns: fake}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	full := tfsdk.Config{Schema: schemaResp.Schema, Raw: dnsDSObj("Ethernet 2")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: full}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	var got windowsDNSClientDataSourceModel
	resp.State.Get(context.Background(), &got)
	if got.ID.ValueString() != "Ethernet 2" {
		t.Errorf("ID = %q, want Ethernet 2", got.ID.ValueString())
	}
	if got.InterfaceIndex.ValueInt64() != 14 {
		t.Errorf("InterfaceIndex = %d, want 14", got.InterfaceIndex.ValueInt64())
	}
	if len(got.EffectiveIPv4.Elements()) != 2 {
		t.Errorf("EffectiveIPv4 must be DHCP-inclusive: %v", got.EffectiveIPv4)
	}
	if got.ConnectionSpecificSuffix.ValueString() != "corp.example.com" {
		t.Errorf("Suffix = %q", got.ConnectionSpecificSuffix.ValueString())
	}
}

func TestDNSClientDataSourceRead_NotFound(t *testing.T) {
	fake := &fakeDNSClient{readOut: nil}
	d := &windowsDNSClientDataSource{dns: fake}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	full := tfsdk.Config{Schema: schemaResp.Schema, Raw: dnsDSObj("Ethernet 9")}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: full}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("missing interface must error for data sources")
	}
}
