// Package provider — unit tests for the windows_net_ip_address resource.
//
// These tests exercise the schema, validators, helpers and CRUD handlers
// without SSH. A fakeNetIPAddressClient is injected into
// windowsNetIPAddressResource.ip.
//
// Edge cases covered (issue #230):
//
//	Metadata                 — returns "windows_net_ip_address"
//	Schema                   — interface_alias/ip_address Required+ForceNew,
//	                           prefix_length Required, flags Optional+Computed
//	                           default false, timeouts block
//	Alias validator          — rejects '|' (import-ID separator)
//	Address validator        — rejects unspecified/loopback/multicast/
//	                           broadcast/zone IDs, warns link-local
//	Config validator         — prefix vs family, disable_dhcp IPv4-only
//	ID helpers               — canonicalisation, split (trims parts), bad IDs
//	Private-state flag       — dhcp_disabled round-trip
//	Create (happy)           — canonical ID, Tentative warns
//	Create (refusals)       — management_path_at_risk/unknown diagnostics,
//	                           unsafe_skip bypass, residual-DHCP warning
//	Read (happy/missing)     — refresh computed, missing removes from state
//	Update/Delete            — forwards delta, guard enforced, DHCP restore,
//	                           residual-DHCP flag accumulation on error
//	ImportState              — Manual only, bad IDs, non-manual refused
package provider

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeNetIPAddressClient
// ---------------------------------------------------------------------------

type fakeNetIPAddressClient struct {
	createIn   winclient.NetIPAddressInput
	createOut  *winclient.NetIPAddressInfo
	createDHCP bool
	createErr  error

	readAlias string
	readIP    string
	readOut   *winclient.NetIPAddressInfo
	readErr   error

	lookupIP    string
	lookupAlias string
	lookupOut   []*winclient.NetIPAddressInfo
	lookupErr   error

	updateAlias  string
	updateIP     string
	updatePrefix int
	updateSkip   bool
	updateDHCPIn bool
	updateUnsafe bool
	updateOut    *winclient.NetIPAddressInfo
	updateDHCP   bool
	updateErr    error

	deleteAlias  string
	deleteIP     string
	deleteUnsafe bool
	deleteErr    error

	restoreAlias string
	restoreErr   error
}

func (f *fakeNetIPAddressClient) Create(_ context.Context, in winclient.NetIPAddressInput) (*winclient.NetIPAddressInfo, bool, error) {
	f.createIn = in
	return f.createOut, f.createDHCP, f.createErr
}

func (f *fakeNetIPAddressClient) Read(_ context.Context, alias, ip string) (*winclient.NetIPAddressInfo, error) {
	f.readAlias, f.readIP = alias, ip
	return f.readOut, f.readErr
}

func (f *fakeNetIPAddressClient) Lookup(_ context.Context, ip, alias string) ([]*winclient.NetIPAddressInfo, error) {
	f.lookupIP, f.lookupAlias = ip, alias
	return f.lookupOut, f.lookupErr
}

func (f *fakeNetIPAddressClient) Update(_ context.Context, alias, ip string, prefix int, skip, dhcp, unsafe bool) (*winclient.NetIPAddressInfo, bool, error) {
	f.updateAlias, f.updateIP, f.updatePrefix = alias, ip, prefix
	f.updateSkip, f.updateDHCPIn, f.updateUnsafe = skip, dhcp, unsafe
	return f.updateOut, f.updateDHCP, f.updateErr
}

func (f *fakeNetIPAddressClient) Delete(_ context.Context, alias, ip string, unsafe bool) error {
	f.deleteAlias, f.deleteIP, f.deleteUnsafe = alias, ip, unsafe
	return f.deleteErr
}

func (f *fakeNetIPAddressClient) RestoreDHCP(_ context.Context, alias string) error {
	f.restoreAlias = alias
	return f.restoreErr
}

// okNetAddressInfo builds a realistic NetIPAddressInfo for tests.
func okNetAddressInfo() *winclient.NetIPAddressInfo {
	return &winclient.NetIPAddressInfo{
		InterfaceAlias: "Ethernet 2",
		InterfaceIndex: 7,
		IPAddress:      "192.0.2.10",
		PrefixLength:   24,
		AddressFamily:  "IPv4",
		AddressState:   "Preferred",
		PrefixOrigin:   "Manual",
		SkipAsSource:   false,
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_net_ip_address schema
// ---------------------------------------------------------------------------

func niObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                           tftypes.String,
		"interface_alias":              tftypes.String,
		"ip_address":                   tftypes.String,
		"prefix_length":                tftypes.Number,
		"skip_as_source":               tftypes.Bool,
		"disable_dhcp":                 tftypes.Bool,
		"restore_dhcp_on_destroy":      tftypes.Bool,
		"unsafe_skip_management_check": tftypes.Bool,
		"interface_index":              tftypes.Number,
		"address_family":               tftypes.String,
		"address_state":                tftypes.String,
		"prefix_origin":                tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func niNullStr() tftypes.Value { return tftypes.NewValue(tftypes.String, nil) }
func niNullNum() tftypes.Value { return tftypes.NewValue(tftypes.Number, nil) }

func niNullTimeouts() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func niObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                           niNullStr(),
		"interface_alias":              tftypes.NewValue(tftypes.String, "Ethernet 2"),
		"ip_address":                   tftypes.NewValue(tftypes.String, "192.0.2.10"),
		"prefix_length":                tftypes.NewValue(tftypes.Number, 24),
		"skip_as_source":               tftypes.NewValue(tftypes.Bool, false),
		"disable_dhcp":                 tftypes.NewValue(tftypes.Bool, false),
		"restore_dhcp_on_destroy":      tftypes.NewValue(tftypes.Bool, false),
		"unsafe_skip_management_check": tftypes.NewValue(tftypes.Bool, false),
		"interface_index":              niNullNum(),
		"address_family":               niNullStr(),
		"address_state":                niNullStr(),
		"prefix_origin":                niNullStr(),
		"timeouts":                     niNullTimeouts(),
	}
}

func niObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := niObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(niObjType(), base)
}

func niState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsNetIPAddressSchemaDefinition(context.Background())
	return tfsdk.State{Raw: niObj(overrides), Schema: s}
}

func niPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsNetIPAddressSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: niObj(overrides), Schema: s}
}

func niConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsNetIPAddressSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: niObj(overrides), Schema: s}
}

func niDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// niAllocPrivate allocates the framework private-state value on a response
// or request (same technique as the firewall-profile suite: reflection over
// the unnameable internal *privatestate.ProviderData type).
func niAllocPrivate(t *testing.T, holder any) {
	t.Helper()
	v := reflect.ValueOf(holder).Elem().FieldByName("Private")
	if !v.IsValid() || v.Type().Kind() != reflect.Pointer || !v.CanSet() {
		t.Fatalf("holder %T has no settable Private pointer field", holder)
	}
	v.Set(reflect.New(v.Type().Elem()))
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressResource_Metadata(t *testing.T) {
	r := &windowsNetIPAddressResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_net_ip_address" {
		t.Errorf("TypeName = %q, want windows_net_ip_address", resp.TypeName)
	}
}

func TestWindowsNetIPAddressResource_Schema(t *testing.T) {
	r := &windowsNetIPAddressResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics: %v", niDiagSummaries(schemaResp.Diagnostics))
	}
	s := schemaResp.Schema

	get := func(name string) schema.Attribute {
		a, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("schema missing attribute %q", name)
		}
		return a
	}

	// interface_alias / ip_address: Required + ForceNew.
	for _, name := range []string{"interface_alias", "ip_address"} {
		a, ok := get(name).(schema.StringAttribute)
		if !ok {
			t.Fatalf("expected schema.StringAttribute, got %T", a)
		}
		if !a.Required || a.Computed || a.Optional {
			t.Errorf("%s must be Required-only", name)
		}
		if len(a.PlanModifiers) == 0 {
			t.Errorf("%s must be ForceNew (RequiresReplace)", name)
		}
	}
	// prefix_length: Required.
	prefixAttr, ok := get("prefix_length").(schema.Int64Attribute)
	if !ok {
		t.Fatalf("expected schema.Int64Attribute, got %T", prefixAttr)
	}
	if !prefixAttr.Required {
		t.Error("prefix_length must be Required")
	}
	// Flags: Optional+Computed with false defaults.
	for _, name := range []string{"skip_as_source", "disable_dhcp", "restore_dhcp_on_destroy", "unsafe_skip_management_check"} {
		a, ok := get(name).(schema.BoolAttribute)
		if !ok {
			t.Fatalf("expected schema.BoolAttribute, got %T", a)
		}
		if !a.Optional || !a.Computed {
			t.Errorf("%s must be Optional+Computed", name)
		}
		if a.Default == nil {
			t.Errorf("%s must carry a default", name)
		}
	}
	// Computed-only.
	for _, name := range []string{"id", "interface_index", "address_family", "address_state", "prefix_origin"} {
		a := get(name)
		switch v := a.(type) {
		case schema.StringAttribute:
			if !v.Computed || v.Required || v.Optional {
				t.Errorf("%s must be Computed-only", name)
			}
		case schema.Int64Attribute:
			if !v.Computed || v.Required || v.Optional {
				t.Errorf("%s must be Computed-only", name)
			}
		default:
			t.Errorf("%s has unexpected attribute type %T", name, a)
		}
	}
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Error("schema must expose a timeouts block")
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestNetIPAddressAliasValidator(t *testing.T) {
	v := netIPAddressAliasValidator{}
	run := func(val string) diag.Diagnostics {
		var diags diag.Diagnostics
		req := validator.StringRequest{
			Path:        path.Root("interface_alias"),
			ConfigValue: types.StringValue(val),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		diags.Append(resp.Diagnostics...)
		return diags
	}
	if d := run("Ethernet 2"); d.HasError() {
		t.Errorf("plain alias must pass, got %v", niDiagSummaries(d))
	}
	if d := run("Ethernet|2"); !d.HasError() {
		t.Error("alias with '|' must fail")
	}
	// Null/unknown skip.
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("interface_alias"), ConfigValue: types.StringNull()}, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null alias must skip")
	}
}

func TestNetIPAddressStringValidator(t *testing.T) {
	v := netIPAddressStringValidator{}
	run := func(val string) diag.Diagnostics {
		req := validator.StringRequest{
			Path:        path.Root("ip_address"),
			ConfigValue: types.StringValue(val),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		return resp.Diagnostics
	}
	for _, good := range []string{"192.0.2.10", "2001:db8::10", "::ffff:192.0.2.10"} {
		if d := run(good); d.HasError() {
			t.Errorf("address %q must pass, got %v", good, niDiagSummaries(d))
		}
	}
	for _, bad := range []string{"999.1.1.1", "0.0.0.0", "::", "127.0.0.1", "::1", "224.0.0.1", "ff02::1", "255.255.255.255", "fe80::1%12", "not-an-ip"} {
		if d := run(bad); !d.HasError() {
			t.Errorf("address %q must fail", bad)
		}
	}
	// Link-local warns, not errors.
	d := run("169.254.10.20")
	if d.HasError() {
		t.Errorf("link-local must not error, got %v", niDiagSummaries(d))
	}
	if len(d) == 0 {
		t.Error("link-local must warn")
	}
}

func TestNetIPAddressConfigValidator(t *testing.T) {
	v := netIPAddressConfigValidator{}
	run := func(ip string, prefix int64, dhcp bool) diag.Diagnostics {
		over := map[string]tftypes.Value{
			"ip_address":    tftypes.NewValue(tftypes.String, ip),
			"prefix_length": tftypes.NewValue(tftypes.Number, float64(prefix)),
			"disable_dhcp":  tftypes.NewValue(tftypes.Bool, dhcp),
		}
		req := resource.ValidateConfigRequest{Config: niConfig(t, over)}
		resp := &resource.ValidateConfigResponse{}
		v.ValidateResource(context.Background(), req, resp)
		return resp.Diagnostics
	}
	if d := run("192.0.2.10", 24, false); d.HasError() {
		t.Errorf("v4/24 must pass, got %v", niDiagSummaries(d))
	}
	if d := run("2001:db8::10", 64, false); d.HasError() {
		t.Errorf("v6/64 must pass, got %v", niDiagSummaries(d))
	}
	if d := run("192.0.2.10", 33, false); !d.HasError() {
		t.Error("v4/33 must fail")
	}
	if d := run("192.0.2.10", 0, false); !d.HasError() {
		t.Error("v4/0 must fail")
	}
	if d := run("2001:db8::10", 129, false); !d.HasError() {
		t.Error("v6/129 must fail")
	}
	if d := run("2001:db8::10", 64, true); !d.HasError() {
		t.Error("disable_dhcp on IPv6 must fail")
	}
}

// ---------------------------------------------------------------------------
// ID + canonicalisation helpers
// ---------------------------------------------------------------------------

func TestCanonicalNetIPAddress(t *testing.T) {
	// Uppercase + leading zeros collapse (ID canonicalisation).
	got, err := canonicalNetIPAddress("2001:DB8::0010")
	if err != nil || got != "2001:db8::10" {
		t.Errorf("canonicalise = %q, %v; want 2001:db8::10, nil", got, err)
	}
	if got, err := canonicalNetIPAddress(" 192.0.2.10 "); err != nil || got != "192.0.2.10" {
		t.Errorf("canonicalise = %q, %v; want 192.0.2.10, nil", got, err)
	}
	if _, err := canonicalNetIPAddress("fe80::1%eth0"); err == nil {
		t.Error("zone ID must fail")
	}
	if _, err := canonicalNetIPAddress("nope"); err == nil {
		t.Error("garbage must fail")
	}
	if id := netIPAddressID("Ethernet 2", "2001:db8::10"); id != "Ethernet 2|2001:db8::10" {
		t.Errorf("id = %q", id)
	}
	alias, ip, err := splitNetIPAddressID("Ethernet 2|2001:db8::10")
	if err != nil || alias != "Ethernet 2" || ip != "2001:db8::10" {
		t.Errorf("split = %q, %q, %v", alias, ip, err)
	}
	// Surrounding whitespace on both parts is trimmed.
	alias, ip, err = splitNetIPAddressID(" Ethernet 2 | 192.0.2.10 ")
	if err != nil || alias != "Ethernet 2" || ip != "192.0.2.10" {
		t.Errorf("spaced split = %q, %q, %v", alias, ip, err)
	}
	for _, bad := range []string{"", "no-separator", "a|b|c", "|192.0.2.10", "Ethernet 2|"} {
		if _, _, err := splitNetIPAddressID(bad); err == nil {
			t.Errorf("ID %q must fail", bad)
		}
	}
}

func TestNetIPAddressDHCPFlagRoundTrip(t *testing.T) {
	resp := &resource.CreateResponse{}
	niAllocPrivate(t, resp)
	if err := setNetIPAddressDHCPFlag(context.Background(), resp.Private.SetKey, true); err != nil {
		t.Fatalf("set: %v", err)
	}
	req := &resource.UpdateRequest{}
	niAllocPrivate(t, req)
	raw, diags := resp.Private.GetKey(context.Background(), netIPAddressPrivateKeyDHCP)
	if diags.HasError() {
		t.Fatalf("get: %v", diags)
	}
	if diags := req.Private.SetKey(context.Background(), netIPAddressPrivateKeyDHCP, raw); diags.HasError() {
		t.Fatalf("reseed: %v", diags)
	}
	if !getNetIPAddressDHCPFlag(context.Background(), req.Private.GetKey) {
		t.Error("flag must round-trip as true")
	}
	// Absent flag reads as false.
	req2 := &resource.DeleteRequest{}
	if getNetIPAddressDHCPFlag(context.Background(), req2.Private.GetKey) {
		t.Error("absent flag must read as false")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressResource_Configure(t *testing.T) {
	r := &windowsNetIPAddressResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressResource_Create_HappyPath(t *testing.T) {
	fc := &fakeNetIPAddressClient{createOut: okNetAddressInfo()}
	r := &windowsNetIPAddressResource{ip: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
	niAllocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: niPlan(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.InterfaceAlias != "Ethernet 2" || fc.createIn.IPAddress != "192.0.2.10" || fc.createIn.PrefixLength != 24 {
		t.Errorf("unexpected client input: %+v", fc.createIn)
	}
	var model windowsNetIPAddressModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Ethernet 2|192.0.2.10" {
		t.Errorf("id = %q, want Ethernet 2|192.0.2.10", model.ID.ValueString())
	}
	if model.InterfaceIndex.ValueInt64() != 7 || model.AddressFamily.ValueString() != "IPv4" {
		t.Errorf("computed not refreshed: %+v", model)
	}
}

func TestWindowsNetIPAddressResource_Create_CanonicalisesV6(t *testing.T) {
	out := okNetAddressInfo()
	out.IPAddress = "2001:db8::10"
	out.AddressFamily = "IPv6"
	out.PrefixLength = 64
	fc := &fakeNetIPAddressClient{createOut: out}
	r := &windowsNetIPAddressResource{ip: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
	niAllocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: niPlan(t, map[string]tftypes.Value{
		"ip_address":    tftypes.NewValue(tftypes.String, "2001:DB8::0010"),
		"prefix_length": tftypes.NewValue(tftypes.Number, 64),
	})}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.IPAddress != "2001:db8::10" {
		t.Errorf("client must receive the canonical address, got %q", fc.createIn.IPAddress)
	}
	var model windowsNetIPAddressModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Ethernet 2|2001:db8::10" {
		t.Errorf("id = %q, want canonical", model.ID.ValueString())
	}
}

func TestWindowsNetIPAddressResource_Create_TentativeWarns(t *testing.T) {
	out := okNetAddressInfo()
	out.AddressState = "Tentative"
	fc := &fakeNetIPAddressClient{createOut: out}
	r := &windowsNetIPAddressResource{ip: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
	niAllocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: niPlan(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("tentative must warn, not error: %v", niDiagSummaries(resp.Diagnostics))
	}
	if len(resp.Diagnostics) == 0 {
		t.Fatal("tentative must produce a warning")
	}
}

func TestWindowsNetIPAddressResource_Create_GuardRefusal(t *testing.T) {
	fc := &fakeNetIPAddressClient{createErr: winclient.NewNetIPAddressError(
		winclient.NetIPAddressErrorMgmtAtRisk,
		"refusing delete of 172.18.122.203 on interface \"Ethernet\": it is the management address this SSH session arrived on (SSH_CONNECTION server_ip 172.18.122.203 via ssh_connection). Set unsafe_skip_management_check = true to proceed anyway.",
		nil, nil)}
	r := &windowsNetIPAddressResource{ip: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
	niAllocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: niPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected a management_path_at_risk diagnostic")
	}
	joined := strings.Join(niDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "management_path_at_risk") || !strings.Contains(joined, "unsafe_skip_management_check") {
		t.Errorf("refusal diagnostic must name the kind and the escape hatch, got:\n%s", joined)
	}
}

func TestWindowsNetIPAddressResource_Create_FailedCreateWithResidualDHCPWarns(t *testing.T) {
	// The client best-effort restores DHCP after a post-disable failure; a
	// residual disable surfaces as a warning naming the manual step (no
	// state — and no private flag — is saved on a failed create).
	fc := &fakeNetIPAddressClient{
		createErr: winclient.NewNetIPAddressError(
			winclient.NetIPAddressErrorAlreadyExists, "already there", nil, nil),
		createDHCP: true,
	}
	r := &windowsNetIPAddressResource{ip: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
	niAllocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: niPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected the create error diagnostic")
	}
	var warnings []string
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			warnings = append(warnings, d.Summary()+": "+d.Detail())
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "DHCP remains disabled") {
		t.Errorf("expected one residual-DHCP warning, got: %v", niDiagSummaries(resp.Diagnostics))
	}
}

func TestWindowsNetIPAddressResource_Create_FailedCreateWithoutResidualDHCPNoWarning(t *testing.T) {
	// No residual disable (restore succeeded or nothing was disabled): no
	// warning beyond the error itself.
	fc := &fakeNetIPAddressClient{
		createErr: winclient.NewNetIPAddressError(
			winclient.NetIPAddressErrorAlreadyExists, "already there", nil, nil),
	}
	r := &windowsNetIPAddressResource{ip: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
	niAllocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: niPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected the create error diagnostic")
	}
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			t.Errorf("unexpected warning without a residual disable: %v", niDiagSummaries(resp.Diagnostics))
		}
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressResource_Read_HappyPath(t *testing.T) {
	fc := &fakeNetIPAddressClient{readOut: okNetAddressInfo()}
	r := &windowsNetIPAddressResource{ip: fc}

	state := niState(t, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "Ethernet 2|192.0.2.10")})
	req := resource.ReadRequest{State: state}
	resp := &resource.ReadResponse{State: state}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.readAlias != "Ethernet 2" || fc.readIP != "192.0.2.10" {
		t.Errorf("read args = %q, %q", fc.readAlias, fc.readIP)
	}
	var model windowsNetIPAddressModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.PrefixLength.ValueInt64() != 24 || model.AddressState.ValueString() != "Preferred" {
		t.Errorf("computed not refreshed: %+v", model)
	}
}

func TestWindowsNetIPAddressResource_Read_MissingRemoves(t *testing.T) {
	fc := &fakeNetIPAddressClient{readOut: nil}
	r := &windowsNetIPAddressResource{ip: fc}

	state := niState(t, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "Ethernet 2|192.0.2.10")})
	req := resource.ReadRequest{State: state}
	resp := &resource.ReadResponse{State: state}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing must not error: %v", niDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("missing address must remove the resource from state")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressResource_Update_HappyPath(t *testing.T) {
	out := okNetAddressInfo()
	out.PrefixLength = 25
	out.SkipAsSource = true
	fc := &fakeNetIPAddressClient{updateOut: out}
	r := &windowsNetIPAddressResource{ip: fc}

	prior := niState(t, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "Ethernet 2|192.0.2.10")})
	plan := niPlan(t, map[string]tftypes.Value{
		"prefix_length":  tftypes.NewValue(tftypes.Number, 25),
		"skip_as_source": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.UpdateRequest{State: prior, Plan: plan}
	resp := &resource.UpdateResponse{State: prior}
	niAllocPrivate(t, resp)
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.updatePrefix != 25 || !fc.updateSkip {
		t.Errorf("update args wrong: prefix=%d skip=%v", fc.updatePrefix, fc.updateSkip)
	}
	var model windowsNetIPAddressModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.PrefixLength.ValueInt64() != 25 || !model.SkipAsSource.ValueBool() {
		t.Errorf("state not refreshed: %+v", model)
	}
	if model.ID.ValueString() != "Ethernet 2|192.0.2.10" {
		t.Errorf("update must keep the id, got %q", model.ID.ValueString())
	}
}

func TestWindowsNetIPAddressResource_Update_FailedUpdateKeepsDHCPFlag(t *testing.T) {
	// A residual DHCP disable on update error is accumulated into private
	// state best-effort and surfaces as a warning naming the manual step.
	fc := &fakeNetIPAddressClient{
		updateErr: winclient.NewNetIPAddressError(
			winclient.NetIPAddressErrorInvalidAddress, "bad prefix", nil, nil),
		updateDHCP: true,
	}
	r := &windowsNetIPAddressResource{ip: fc}

	prior := niState(t, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "Ethernet 2|192.0.2.10")})
	plan := niPlan(t, map[string]tftypes.Value{
		"prefix_length": tftypes.NewValue(tftypes.Number, 25),
	})
	req := resource.UpdateRequest{State: prior, Plan: plan}
	niAllocPrivate(t, &req)
	resp := &resource.UpdateResponse{State: prior}
	niAllocPrivate(t, resp)
	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected the update error diagnostic")
	}
	var warnings []string
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			warnings = append(warnings, d.Summary()+": "+d.Detail())
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "DHCP remains disabled") {
		t.Errorf("expected one residual-DHCP warning, got: %v", niDiagSummaries(resp.Diagnostics))
	}
	if !getNetIPAddressDHCPFlag(context.Background(), resp.Private.GetKey) {
		t.Error("a residual DHCP disable must be accumulated into private state even on update error")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressResource_Delete_HappyPath(t *testing.T) {
	fc := &fakeNetIPAddressClient{}
	r := &windowsNetIPAddressResource{ip: fc}

	state := niState(t, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "Ethernet 2|192.0.2.10")})
	req := resource.DeleteRequest{State: state}
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.deleteAlias != "Ethernet 2" || fc.deleteIP != "192.0.2.10" || fc.deleteUnsafe {
		t.Errorf("delete args wrong: %+v unsafe=%v", fc, fc.deleteUnsafe)
	}
	if fc.restoreAlias != "" {
		t.Errorf("without the restore flag nothing may be restored, got %q", fc.restoreAlias)
	}
}

func TestWindowsNetIPAddressResource_Delete_RestoresDHCP(t *testing.T) {
	fc := &fakeNetIPAddressClient{}
	r := &windowsNetIPAddressResource{ip: fc}

	state := niState(t, map[string]tftypes.Value{
		"id":                           tftypes.NewValue(tftypes.String, "Ethernet 2|192.0.2.10"),
		"restore_dhcp_on_destroy":      tftypes.NewValue(tftypes.Bool, true),
		"unsafe_skip_management_check": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	niAllocPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), netIPAddressPrivateKeyDHCP, []byte("true")); diags.HasError() {
		t.Fatalf("seed flag: %v", diags)
	}
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreAlias != "Ethernet 2" {
		t.Errorf("restore expected on Ethernet 2, got %q", fc.restoreAlias)
	}
	if !fc.deleteUnsafe {
		t.Error("unsafe_skip_management_check must flow to Delete")
	}
}

func TestWindowsNetIPAddressResource_Delete_NoRestoreWithoutFlag(t *testing.T) {
	fc := &fakeNetIPAddressClient{}
	r := &windowsNetIPAddressResource{ip: fc}

	state := niState(t, map[string]tftypes.Value{
		"id":                      tftypes.NewValue(tftypes.String, "Ethernet 2|192.0.2.10"),
		"restore_dhcp_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreAlias != "" {
		t.Errorf("without a recorded DHCP disable nothing may be restored, got %q", fc.restoreAlias)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsNetIPAddressResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakeNetIPAddressClient{readOut: okNetAddressInfo()}
	r := &windowsNetIPAddressResource{ip: fc}

	req := resource.ImportStateRequest{ID: "Ethernet 2|192.0.2.10"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", niDiagSummaries(resp.Diagnostics))
	}
	var model windowsNetIPAddressModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Ethernet 2|192.0.2.10" || model.PrefixOrigin.ValueString() != "Manual" {
		t.Errorf("unexpected imported state: id=%q origin=%q", model.ID.ValueString(), model.PrefixOrigin.ValueString())
	}
}

func TestWindowsNetIPAddressResource_ImportState_Refusals(t *testing.T) {
	// Non-manual origins are refused.
	for _, origin := range []string{"Dhcp", "WellKnown", "RouterAdvertisement", "Other"} {
		t.Run(origin, func(t *testing.T) {
			out := okNetAddressInfo()
			out.PrefixOrigin = origin
			r := &windowsNetIPAddressResource{ip: &fakeNetIPAddressClient{readOut: out}}
			resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
			r.ImportState(context.Background(), resource.ImportStateRequest{ID: "Ethernet 2|192.0.2.10"}, resp)
			if !resp.Diagnostics.HasError() {
				t.Fatalf("origin %s must be refused", origin)
			}
			if !strings.Contains(strings.Join(niDiagSummaries(resp.Diagnostics), "\n"), "Manual") {
				t.Errorf("refusal must name Manual as the only importable origin")
			}
		})
	}
	// Bad IDs and missing addresses.
	r := &windowsNetIPAddressResource{ip: &fakeNetIPAddressClient{readOut: nil}}
	for _, id := range []string{"", "no-separator", "a|b|c", "Ethernet 2|999.1.1.1"} {
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsNetIPAddressSchemaDefinition(context.Background())}}
		r.ImportState(context.Background(), resource.ImportStateRequest{ID: id}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("ID %q must fail", id)
		}
	}
}

// TestNetIPAddressPrefixLengthSchemaRange pins the #324 attribute-level
// Between(1,128) gate on prefix_length. The IPv4 refinement (1-32) stays in
// netIPAddressConfigValidator, which keeps the family-aware diagnostics.
func TestNetIPAddressPrefixLengthSchemaRange(t *testing.T) {
	s := windowsNetIPAddressSchemaDefinition(context.Background())
	a, ok := s.Attributes["prefix_length"].(schema.Int64Attribute)
	if !ok {
		t.Fatalf("prefix_length: expected schema.Int64Attribute, got %T", s.Attributes["prefix_length"])
	}
	if len(a.Validators) == 0 {
		t.Fatal("prefix_length must carry a range validator (#324)")
	}
	for _, v := range []int64{1, 24, 32, 64, 128} {
		resp := &validator.Int64Response{}
		a.Validators[0].ValidateInt64(context.Background(), validator.Int64Request{
			Path: path.Root("prefix_length"), ConfigValue: types.Int64Value(v),
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("prefix_length %d should pass, got %v", v, resp.Diagnostics)
		}
	}
	for _, v := range []int64{-1, 0, 129, 255} {
		resp := &validator.Int64Response{}
		a.Validators[0].ValidateInt64(context.Background(), validator.Int64Request{
			Path: path.Root("prefix_length"), ConfigValue: types.Int64Value(v),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("prefix_length %d should be rejected", v)
		}
	}
}
