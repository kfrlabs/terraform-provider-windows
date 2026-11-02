// Package provider — unit tests for the windows_dns_client resource.
//
// These tests exercise the schema, validators, helpers and CRUD handlers
// without touching SSH. They use a fakeDnsClient injected into
// windowsDNSClientResource.dns.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// -----------------------------------------------------------------------------
// Fake DnsClientClient
// -----------------------------------------------------------------------------

type fakeDNSClient struct {
	readOut   *winclient.DnsClientState
	readErr   error
	applyOut  *winclient.DnsClientState
	applyErr  error
	applyGot  *winclient.DnsClientSettings
	applyName string
	resetOut  *winclient.DnsClientState
	resetErr  error
	resetV4   bool
	resetV6   bool
	resetSfx  bool
	resetName string
	resetSeen bool
	readSeen  bool
}

func (f *fakeDNSClient) Read(_ context.Context, alias string) (*winclient.DnsClientState, error) {
	f.readSeen = true
	return f.readOut, f.readErr
}

func (f *fakeDNSClient) Apply(_ context.Context, alias string, s winclient.DnsClientSettings) (*winclient.DnsClientState, error) {
	cp := s
	f.applyGot = &cp
	f.applyName = alias
	return f.applyOut, f.applyErr
}

func (f *fakeDNSClient) Reset(_ context.Context, alias string, v4, v6, sfx bool) (*winclient.DnsClientState, error) {
	f.resetSeen = true
	f.resetName, f.resetV4, f.resetV6, f.resetSfx = alias, v4, v6, sfx
	return f.resetOut, f.resetErr
}

// fakeDNSState builds a realistic DnsClientState for tests.
func fakeDNSState() *winclient.DnsClientState {
	return &winclient.DnsClientState{
		InterfaceAlias:                "Ethernet 2",
		InterfaceIndex:                14,
		InterfaceGUID:                 "{11111111-2222-3333-4444-555555555555}",
		StaticIPv4:                    []string{"192.0.2.53"},
		StaticIPv6:                    []string{},
		EffectiveIPv4:                 []string{"192.0.2.53", "198.51.100.53"},
		EffectiveIPv6:                 []string{},
		ConnectionSpecificSuffix:      "corp.example.com",
		RegisterThisConnectionAddress: true,
		UseSuffixWhenRegistering:      true,
	}
}

// -----------------------------------------------------------------------------
// tftypes helpers — mirrors the dns_client schema attribute set
// -----------------------------------------------------------------------------

func dnsObjectType() tftypes.Object {
	strList := tftypes.List{ElementType: tftypes.String}
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                               tftypes.String,
		"interface_alias":                  tftypes.String,
		"ipv4_server_addresses":            strList,
		"ipv6_server_addresses":            strList,
		"connection_specific_suffix":       tftypes.String,
		"register_this_connection_address": tftypes.Bool,
		"use_suffix_when_registering":      tftypes.Bool,
		"reset_on_destroy":                 tftypes.Bool,
		"interface_index":                  tftypes.Number,
		"interface_guid":                   tftypes.String,
		"effective_ipv4":                   strList,
		"effective_ipv6":                   strList,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func dnsNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func dnsStrList(vals []string) tftypes.Value {
	typ := tftypes.List{ElementType: tftypes.String}
	if vals == nil {
		return tftypes.NewValue(typ, nil)
	}
	elems := make([]tftypes.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, tftypes.NewValue(tftypes.String, v))
	}
	return tftypes.NewValue(typ, elems)
}

func dnsObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":                               tftypes.NewValue(tftypes.String, nil),
		"interface_alias":                  tftypes.NewValue(tftypes.String, nil),
		"ipv4_server_addresses":            dnsStrList(nil),
		"ipv6_server_addresses":            dnsStrList(nil),
		"connection_specific_suffix":       tftypes.NewValue(tftypes.String, nil),
		"register_this_connection_address": tftypes.NewValue(tftypes.Bool, nil),
		"use_suffix_when_registering":      tftypes.NewValue(tftypes.Bool, nil),
		"reset_on_destroy":                 tftypes.NewValue(tftypes.Bool, false),
		"interface_index":                  tftypes.NewValue(tftypes.Number, nil),
		"interface_guid":                   tftypes.NewValue(tftypes.String, nil),
		"effective_ipv4":                   dnsStrList(nil),
		"effective_ipv6":                   dnsStrList(nil),
		"timeouts":                         dnsNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(dnsObjectType(), base)
}

// -----------------------------------------------------------------------------
// Metadata + Schema
// -----------------------------------------------------------------------------

func TestDNSClientMetadata(t *testing.T) {
	r := &windowsDNSClientResource{}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_dns_client" {
		t.Errorf("TypeName = %q, want windows_dns_client", resp.TypeName)
	}
}

func TestDNSClientSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsDNSClientSchemaDefinition(context.Background())
	want := []string{"id", "interface_alias", "ipv4_server_addresses", "ipv6_server_addresses",
		"connection_specific_suffix", "register_this_connection_address", "use_suffix_when_registering",
		"reset_on_destroy", "interface_index", "interface_guid", "effective_ipv4", "effective_ipv6", "timeouts"}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestNewWindowsDNSClientResource_NotNil(t *testing.T) {
	if NewWindowsDNSClientResource() == nil {
		t.Fatal("NewWindowsDNSClientResource must not return nil")
	}
}

func TestDNSClientConfigure(t *testing.T) {
	r := &windowsDNSClientResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op: %v", resp.Diagnostics)
	}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "bad-type"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should produce an error diagnostic")
	}
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r2 := &windowsDNSClientResource{}
	resp2 := &resource.ConfigureResponse{}
	r2.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp2.Diagnostics)
	}
	if r2.dns == nil {
		t.Error("Configure must populate dns field")
	}
}

// -----------------------------------------------------------------------------
// Validators
// -----------------------------------------------------------------------------

func TestDNSClientAliasValidator(t *testing.T) {
	v := dnsClientAliasValidator{}
	for _, tc := range []struct {
		name    string
		val     types.String
		wantErr bool
	}{
		{"null skipped", types.StringNull(), false},
		{"unknown skipped", types.StringUnknown(), false},
		{"valid", types.StringValue("Ethernet 2"), false},
		{"blank", types.StringValue("   "), true},
		{"empty", types.StringValue(""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &validator.StringResponse{}
			v.ValidateString(context.Background(), validator.StringRequest{
				Path:        path.Root("interface_alias"),
				ConfigValue: tc.val,
			}, resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("HasError = %v, want %v", resp.Diagnostics.HasError(), tc.wantErr)
			}
		})
	}
}

func TestDNSClientServerAddressesValidator(t *testing.T) {
	ctx := context.Background()
	newReq := func(vals []string) validator.ListRequest {
		if vals == nil {
			return validator.ListRequest{Path: path.Root("ipv4_server_addresses"), ConfigValue: types.ListNull(types.StringType)}
		}
		v, d := types.ListValueFrom(ctx, types.StringType, vals)
		if d.HasError() {
			t.Fatalf("ListValueFrom: %v", d)
		}
		return validator.ListRequest{Path: path.Root("ipv4_server_addresses"), ConfigValue: v}
	}
	v4 := dnsClientServerAddressesValidator{wantV6: false}
	for _, tc := range []struct {
		name    string
		vals    []string
		wantErr bool
	}{
		{"null skipped", nil, false},
		{"empty ok (reset)", []string{}, false},
		{"valid", []string{"192.0.2.53", "198.51.100.53"}, false},
		{"loopback allowed", []string{"127.0.0.1"}, false},
		{"v6 rejected", []string{"2001:db8::53"}, true},
		{"duplicate", []string{"192.0.2.53", "192.0.2.53"}, true},
		{"broadcast", []string{"255.255.255.255"}, true},
		{"multicast", []string{"224.0.0.251"}, true},
		{"garbage", []string{"nope"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &validator.ListResponse{}
			v4.ValidateList(ctx, newReq(tc.vals), resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("HasError = %v, want %v", resp.Diagnostics.HasError(), tc.wantErr)
			}
		})
	}
	v6 := dnsClientServerAddressesValidator{wantV6: true}
	resp := &validator.ListResponse{}
	vals, _ := types.ListValueFrom(ctx, types.StringType, []string{"192.0.2.53"})
	v6.ValidateList(ctx, validator.ListRequest{Path: path.Root("ipv6_server_addresses"), ConfigValue: vals}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("IPv4 address in the IPv6 list must fail validation")
	}
	resp2 := &validator.ListResponse{}
	vals2, _ := types.ListValueFrom(ctx, types.StringType, []string{"2001:DB8::53"})
	v6.ValidateList(ctx, validator.ListRequest{Path: path.Root("ipv6_server_addresses"), ConfigValue: vals2}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Errorf("canonical IPv6 must pass: %v", resp2.Diagnostics)
	}
}

func TestDNSClientServerAddressesNormalizeModifier(t *testing.T) {
	ctx := context.Background()
	// Upper-case IPv6 with padding whitespace plans as the canonical form
	// the state carries, so no perpetual diff is proposed.
	v6 := dnsClientServerAddressesNormalizeModifier{wantV6: true}
	plan, d := types.ListValueFrom(ctx, types.StringType, []string{"2001:DB8::53", " 2001:db8::1 "})
	if d.HasError() {
		t.Fatalf("ListValueFrom: %v", d)
	}
	resp := &planmodifier.ListResponse{}
	v6.PlanModifyList(ctx, planmodifier.ListRequest{
		Path:      path.Root("ipv6_server_addresses"),
		PlanValue: plan,
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	var got []string
	resp.Diagnostics.Append(resp.PlanValue.ElementsAs(ctx, &got, false)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if len(got) != 2 || got[0] != "2001:db8::53" || got[1] != "2001:db8::1" {
		t.Errorf("IPv6 not canonicalised at plan time: %v", got)
	}

	// IPv4-mapped IPv6 unmaps to the IPv4 form.
	v4 := dnsClientServerAddressesNormalizeModifier{wantV6: false}
	plan, d = types.ListValueFrom(ctx, types.StringType, []string{"::ffff:192.0.2.53"})
	if d.HasError() {
		t.Fatalf("ListValueFrom: %v", d)
	}
	resp = &planmodifier.ListResponse{}
	v4.PlanModifyList(ctx, planmodifier.ListRequest{
		Path:      path.Root("ipv4_server_addresses"),
		PlanValue: plan,
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	got = nil
	resp.Diagnostics.Append(resp.PlanValue.ElementsAs(ctx, &got, false)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if len(got) != 1 || got[0] != "192.0.2.53" {
		t.Errorf("IPv4-mapped address not unmapped at plan time: %v", got)
	}

	// Null and unknown plans pass through untouched.
	resp = &planmodifier.ListResponse{}
	v4.PlanModifyList(ctx, planmodifier.ListRequest{
		Path:      path.Root("ipv4_server_addresses"),
		PlanValue: types.ListNull(types.StringType),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("null plan must pass through without diags: %v", resp.Diagnostics)
	}

	// Invalid input is left for the attribute validator to report.
	bad, d := types.ListValueFrom(ctx, types.StringType, []string{"nope"})
	if d.HasError() {
		t.Fatalf("ListValueFrom: %v", d)
	}
	resp = &planmodifier.ListResponse{}
	v4.PlanModifyList(ctx, planmodifier.ListRequest{
		Path:      path.Root("ipv4_server_addresses"),
		PlanValue: bad,
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("invalid input must not error in the modifier: %v", resp.Diagnostics)
	}
}

func TestDNSClientSuffixValidator(t *testing.T) {
	v := dnsClientSuffixValidator{}
	for _, tc := range []struct {
		name    string
		val     types.String
		wantErr bool
	}{
		{"null skipped", types.StringNull(), false},
		{"unknown skipped", types.StringUnknown(), false},
		{"valid", types.StringValue("corp.example.com"), false},
		{"single label", types.StringValue("corp"), false},
		{"empty rejected", types.StringValue(""), true},
		{"underscore", types.StringValue("bad_name.example.com"), true},
		{"empty label", types.StringValue("a..b"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &validator.StringResponse{}
			v.ValidateString(context.Background(), validator.StringRequest{
				Path:        path.Root("connection_specific_suffix"),
				ConfigValue: tc.val,
			}, resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("HasError = %v, want %v", resp.Diagnostics.HasError(), tc.wantErr)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Settings + state projection helpers
// -----------------------------------------------------------------------------

func TestModelToDNSClientSettings_NullMeansUnmanaged(t *testing.T) {
	var plan windowsDNSClientModel
	plan.InterfaceAlias = types.StringValue("Ethernet 2")
	plan.IPv4ServerAddresses = types.ListNull(types.StringType)
	plan.IPv6ServerAddresses = types.ListNull(types.StringType)
	plan.ConnectionSpecificSuffix = types.StringNull()
	plan.RegisterThisConnectionAddress = types.BoolNull()
	plan.UseSuffixWhenRegistering = types.BoolNull()
	s, diags := modelToDnsClientSettings(context.Background(), plan)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if s.DnsClientConfigured() {
		t.Errorf("all-null plan must be unconfigured, got %+v", s)
	}
}

func TestModelToDNSClientSettings_Managed(t *testing.T) {
	ctx := context.Background()
	plan := windowsDNSClientModel{
		InterfaceAlias:                types.StringValue("Ethernet 2"),
		IPv4ServerAddresses:           dnsClientMustList([]string{"192.0.2.53"}),
		IPv6ServerAddresses:           dnsClientMustList([]string{}),
		ConnectionSpecificSuffix:      types.StringValue("corp.example.com"),
		RegisterThisConnectionAddress: types.BoolValue(true),
		UseSuffixWhenRegistering:      types.BoolValue(false),
	}
	// Convert tftypes lists back through the model via ListValueFrom types.
	v4, d := types.ListValueFrom(ctx, types.StringType, []string{"192.0.2.53"})
	if d.HasError() {
		t.Fatalf("ListValueFrom: %v", d)
	}
	plan.IPv4ServerAddresses = v4
	s, diags := modelToDnsClientSettings(ctx, plan)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if !s.IPv4Set || len(s.IPv4Addresses) != 1 || s.IPv4Addresses[0] != "192.0.2.53" {
		t.Errorf("IPv4 not projected: %+v", s)
	}
	if !s.IPv6Set || len(s.IPv6Addresses) != 0 {
		t.Errorf("empty IPv6 list must be managed-but-empty: %+v", s)
	}
	if !s.SuffixSet || *s.ConnectionSpecificSuffix != "corp.example.com" {
		t.Errorf("suffix not projected: %+v", s)
	}
	if s.RegisterThisConnectionAddress == nil || !*s.RegisterThisConnectionAddress {
		t.Errorf("register flag not projected: %+v", s)
	}
}

func TestDNSClientSettingsForUpdate_DropsUnchanged(t *testing.T) {
	ctx := context.Background()
	mkList := func(vals []string) types.List {
		v, d := types.ListValueFrom(ctx, types.StringType, vals)
		if d.HasError() {
			t.Fatalf("ListValueFrom: %v", d)
		}
		return v
	}
	plan := windowsDNSClientModel{
		InterfaceAlias:                types.StringValue("Ethernet 2"),
		IPv4ServerAddresses:           mkList([]string{"192.0.2.53"}),
		IPv6ServerAddresses:           mkList([]string{"2001:db8::53"}),
		ConnectionSpecificSuffix:      types.StringValue("corp.example.com"),
		RegisterThisConnectionAddress: types.BoolValue(true),
		UseSuffixWhenRegistering:      types.BoolValue(true),
	}
	prior := plan
	s, diags := dnsClientSettingsForUpdate(ctx, plan, prior)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if s.DnsClientConfigured() {
		t.Errorf("identical plan/prior must yield no changes, got %+v", s)
	}
	plan.IPv4ServerAddresses = mkList([]string{"198.51.100.53"})
	s, diags = dnsClientSettingsForUpdate(ctx, plan, prior)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if !s.IPv4Set || s.IPv6Set || s.SuffixSet {
		t.Errorf("only the changed family must be set, got %+v", s)
	}
}

func TestDNSClientStateToModel_PartialManagement(t *testing.T) {
	ctx := context.Background()
	plan := windowsDNSClientModel{
		InterfaceAlias:                types.StringValue("Ethernet 2"),
		IPv4ServerAddresses:           dnsClientMustList([]string{"192.0.2.53"}),
		IPv6ServerAddresses:           types.ListNull(types.StringType),
		ConnectionSpecificSuffix:      types.StringNull(),
		RegisterThisConnectionAddress: types.BoolNull(),
		UseSuffixWhenRegistering:      types.BoolValue(true),
		ResetOnDestroy:                types.BoolValue(false),
		Timeouts:                      dnsClientNullTimeouts(),
	}
	m, diags := dnsClientStateToModel(ctx, plan, fakeDNSState())
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if m.ID.ValueString() != "Ethernet 2" {
		t.Errorf("ID = %q, want canonical alias", m.ID.ValueString())
	}
	if m.IPv4ServerAddresses.IsNull() {
		t.Error("managed IPv4 must be filled from observed state")
	}
	if !m.IPv6ServerAddresses.IsNull() {
		t.Error("unmanaged IPv6 must stay null")
	}
	if !m.ConnectionSpecificSuffix.IsNull() {
		t.Error("unmanaged suffix must stay null")
	}
	if !m.RegisterThisConnectionAddress.IsNull() {
		t.Error("unmanaged register flag must stay null")
	}
	if m.EffectiveIPv4.IsNull() || len(m.EffectiveIPv4.Elements()) != 2 {
		t.Errorf("effective IPv4 must always reflect the host: %v", m.EffectiveIPv4)
	}
	if m.InterfaceIndex.ValueInt64() != 14 {
		t.Errorf("InterfaceIndex = %d, want 14", m.InterfaceIndex.ValueInt64())
	}
}

// -----------------------------------------------------------------------------
// Create / Read / Update / Delete
// -----------------------------------------------------------------------------

func TestDNSClientCreate_HappyPath(t *testing.T) {
	fake := &fakeDNSClient{applyOut: fakeDNSState()}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"interface_alias":       tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"ipv4_server_addresses": dnsStrList([]string{"192.0.2.53"}),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: dnsObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	var m windowsDNSClientModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "Ethernet 2" {
		t.Errorf("ID = %q, want canonical alias", m.ID.ValueString())
	}
	if fake.applyName != "Ethernet 2" {
		t.Errorf("Apply alias = %q", fake.applyName)
	}
	if fake.applyGot == nil || !fake.applyGot.IPv4Set {
		t.Error("Apply must receive the managed IPv4 family")
	}
}

func TestDNSClientCreate_NothingManagedReads(t *testing.T) {
	fake := &fakeDNSClient{readOut: fakeDNSState()}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"interface_alias": tftypes.NewValue(tftypes.String, "Ethernet 2"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: dnsObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if !fake.readSeen || fake.applyGot != nil {
		t.Error("a fully unmanaged plan must Read, not Apply")
	}
}

func TestDNSClientCreate_PermissionDenied(t *testing.T) {
	fake := &fakeDNSClient{
		applyErr: winclient.NewDnsClientError(winclient.DnsClientErrorPermission, "Access is denied", nil, nil),
	}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"interface_alias":       tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"ipv4_server_addresses": dnsStrList([]string{"192.0.2.53"}),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: dnsObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected permission_denied error")
	}
}

func TestDNSClientRead_HappyPath(t *testing.T) {
	fake := &fakeDNSClient{readOut: fakeDNSState()}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"id":              tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"interface_alias": tftypes.NewValue(tftypes.String, "Ethernet 2"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should not be removed on happy read")
	}
}

func TestDNSClientRead_InterfaceGoneRemovesResource(t *testing.T) {
	fake := &fakeDNSClient{readOut: nil}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"id":              tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"interface_alias": tftypes.NewValue(tftypes.String, "Ethernet 2"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("missing interface must RemoveResource, not error: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state must be removed when the interface is gone")
	}
}

func TestDNSClientUpdate_OnlyChangedSent(t *testing.T) {
	fake := &fakeDNSClient{applyOut: fakeDNSState()}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	priorRaw := dnsObj(map[string]tftypes.Value{
		"id":                    tftypes.NewValue(tftypes.String, "Ethernet 2"),
		"interface_alias":       tftypes.NewValue(tftypes.String, "Ethernet 2"),
		"ipv4_server_addresses": dnsStrList([]string{"192.0.2.53"}),
		"ipv6_server_addresses": dnsStrList([]string{}),
	})
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"id":                    tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"interface_alias":       tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"ipv4_server_addresses": dnsStrList([]string{"198.51.100.53"}),
			"ipv6_server_addresses": dnsStrList([]string{}),
		}),
	}
	prior := tfsdk.State{Schema: schemaDef, Raw: priorRaw}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorRaw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if fake.applyGot == nil {
		t.Fatal("Update must Apply when something changed")
	}
	if !fake.applyGot.IPv4Set || fake.applyGot.IPv6Set {
		t.Errorf("only the changed family must be sent, got %+v", fake.applyGot)
	}
}

func TestDNSClientDelete_NoResetIsNoop(t *testing.T) {
	fake := &fakeDNSClient{}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	state := tfsdk.State{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"id":                    tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"interface_alias":       tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"ipv4_server_addresses": dnsStrList([]string{"192.0.2.53"}),
			"reset_on_destroy":      tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("no-op delete must not error: %v", resp.Diagnostics)
	}
	if fake.resetSeen {
		t.Error("Reset must not run without reset_on_destroy")
	}
}

func TestDNSClientDelete_ResetManagedOnly(t *testing.T) {
	fake := &fakeDNSClient{resetOut: fakeDNSState()}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	state := tfsdk.State{
		Schema: schemaDef,
		Raw: dnsObj(map[string]tftypes.Value{
			"id":                         tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"interface_alias":            tftypes.NewValue(tftypes.String, "Ethernet 2"),
			"ipv4_server_addresses":      dnsStrList([]string{"192.0.2.53"}),
			"connection_specific_suffix": tftypes.NewValue(tftypes.String, "corp.example.com"),
			"reset_on_destroy":           tftypes.NewValue(tftypes.Bool, true),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if !fake.resetSeen {
		t.Fatal("Reset must run with reset_on_destroy")
	}
	if fake.resetName != "Ethernet 2" || !fake.resetV4 || fake.resetV6 || !fake.resetSfx {
		t.Errorf("Reset flags wrong: name=%q v4=%v v6=%v sfx=%v",
			fake.resetName, fake.resetV4, fake.resetV6, fake.resetSfx)
	}
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestDNSClientImportState(t *testing.T) {
	fake := &fakeDNSClient{readOut: fakeDNSState()}
	r := &windowsDNSClientResource{dns: fake}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: dnsObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "Ethernet 2"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	var m windowsDNSClientModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "Ethernet 2" {
		t.Errorf("ID = %q, want Ethernet 2", m.ID.ValueString())
	}
	if m.IPv4ServerAddresses.IsNull() || m.IPv6ServerAddresses.IsNull() {
		t.Error("import must manage both families (DHCP imports as [])")
	}
	if len(m.IPv6ServerAddresses.Elements()) != 0 {
		t.Errorf("automatic IPv6 must import as [], got %v", m.IPv6ServerAddresses)
	}
	if m.ConnectionSpecificSuffix.ValueString() != "corp.example.com" {
		t.Errorf("import must adopt the observed suffix as managed, got %v", m.ConnectionSpecificSuffix)
	}

	// An unset suffix imports as unmanaged (null), not as an empty string.
	bare := fakeDNSState()
	bare.ConnectionSpecificSuffix = ""
	fake.readOut = bare
	resp = &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: dnsObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "Ethernet 2"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	var m2 windowsDNSClientModel
	resp.State.Get(context.Background(), &m2)
	if !m2.ConnectionSpecificSuffix.IsNull() {
		t.Errorf("unset suffix must import as null, got %v", m2.ConnectionSpecificSuffix)
	}
}

func TestDNSClientImportState_BlankID(t *testing.T) {
	r := &windowsDNSClientResource{dns: &fakeDNSClient{}}
	schemaDef := windowsDNSClientSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: dnsObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "  "}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("blank import ID must error")
	}
}

// -----------------------------------------------------------------------------
// addDNSClientDiag
// -----------------------------------------------------------------------------

func TestAddDNSClientDiag(t *testing.T) {
	var diags diag.Diagnostics
	he := winclient.NewDnsClientError(
		winclient.DnsClientErrorInterfaceNotFound,
		"No interface matches alias",
		errors.New("cause"),
		map[string]string{"interface_alias": "Ethernet 9"},
	)
	addDNSClientDiag(&diags, "Read failed", he)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags.Errors()[0].Detail()
	summary := diags.Errors()[0].Summary()
	if !strings.Contains(detail, "Ethernet 9") {
		t.Errorf("detail should contain context: %s", detail)
	}
	if !strings.Contains(summary, "interface_not_found") {
		t.Errorf("summary should contain kind: %s", summary)
	}

	var plain diag.Diagnostics
	addDNSClientDiag(&plain, "Read failed", errors.New("plain error"))
	if !plain.HasError() {
		t.Fatal("expected error diagnostic for plain errors")
	}
}
