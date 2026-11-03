// Package provider — unit tests for the windows_net_route resource.
//
// These tests exercise the schema, validators, helpers and CRUD handlers
// without SSH. A fakeNetRouteClient is injected into
// windowsNetRouteResource.routes.
//
// Edge cases covered (issue #231):
//
//	Metadata                 — returns "windows_net_route"
//	Schema                   — identity attributes Required+ForceNew,
//	                           route_metric Optional+Computed default 256,
//	                           timeouts block
//	Alias validator          — rejects '|' (import-ID separator)
//	Prefix validator         — canonical masked form, host bits name canonical
//	Next-hop validator       — rejects multicast/loopback/broadcast/zone IDs
//	Config validator         — family agreement
//	ID helpers               — canonicalisation, split (trims parts), bad IDs
//	Create (happy)           — canonical ID, computed refresh
//	Create (refusals)       — management_path_at_risk/unknown diagnostics,
//	                           unsafe_skip bypass forwards
//	Read (happy/missing)     — refresh computed, missing removes from state
//	Update/Delete            — forwards metric delta, guard enforced
//	ImportState              — NetMgmt only, bad IDs, non-NetMgmt refused
package provider

import (
	"context"
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
// fakeNetRouteClient
// ---------------------------------------------------------------------------

type fakeNetRouteClient struct {
	createIn  winclient.NetRouteInput
	createOut *winclient.NetRouteInfo
	createErr error

	readAlias  string
	readPrefix string
	readNext   string
	readOut    *winclient.NetRouteInfo
	readErr    error

	lookupPrefix string
	lookupAlias  string
	lookupNext   string
	lookupOut    []*winclient.NetRouteInfo
	lookupErr    error

	updateAlias  string
	updatePrefix string
	updateNext   string
	updateMetric int
	updateUnsafe bool
	updateOut    *winclient.NetRouteInfo
	updateErr    error

	deleteAlias  string
	deletePrefix string
	deleteNext   string
	deleteUnsafe bool
	deleteErr    error
}

func (f *fakeNetRouteClient) Create(_ context.Context, in winclient.NetRouteInput) (*winclient.NetRouteInfo, error) {
	f.createIn = in
	return f.createOut, f.createErr
}

func (f *fakeNetRouteClient) Read(_ context.Context, alias, prefix, next string) (*winclient.NetRouteInfo, error) {
	f.readAlias, f.readPrefix, f.readNext = alias, prefix, next
	return f.readOut, f.readErr
}

func (f *fakeNetRouteClient) Lookup(_ context.Context, prefix, alias, next string) ([]*winclient.NetRouteInfo, error) {
	f.lookupPrefix, f.lookupAlias, f.lookupNext = prefix, alias, next
	return f.lookupOut, f.lookupErr
}

func (f *fakeNetRouteClient) Update(_ context.Context, alias, prefix, next string, metric int, unsafe bool) (*winclient.NetRouteInfo, error) {
	f.updateAlias, f.updatePrefix, f.updateNext, f.updateMetric, f.updateUnsafe = alias, prefix, next, metric, unsafe
	return f.updateOut, f.updateErr
}

func (f *fakeNetRouteClient) Delete(_ context.Context, alias, prefix, next string, unsafe bool) error {
	f.deleteAlias, f.deletePrefix, f.deleteNext, f.deleteUnsafe = alias, prefix, next, unsafe
	return f.deleteErr
}

// okNetRouteInfo builds a realistic NetRouteInfo for tests.
func okNetRouteInfo() *winclient.NetRouteInfo {
	return &winclient.NetRouteInfo{
		InterfaceAlias:    "Ethernet 2",
		InterfaceIndex:    7,
		DestinationPrefix: "198.51.100.0/24",
		NextHop:           "192.0.2.1",
		RouteMetric:       10,
		InterfaceMetric:   25,
		EffectiveMetric:   35,
		AddressFamily:     "IPv4",
		Protocol:          "NetMgmt",
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_net_route schema
// ---------------------------------------------------------------------------

func nrObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                           tftypes.String,
		"interface_alias":              tftypes.String,
		"destination_prefix":           tftypes.String,
		"next_hop":                     tftypes.String,
		"route_metric":                 tftypes.Number,
		"unsafe_skip_management_check": tftypes.Bool,
		"interface_index":              tftypes.Number,
		"address_family":               tftypes.String,
		"interface_metric":             tftypes.Number,
		"effective_metric":             tftypes.Number,
		"protocol":                     tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func nrNullStr() tftypes.Value { return tftypes.NewValue(tftypes.String, nil) }
func nrNullNum() tftypes.Value { return tftypes.NewValue(tftypes.Number, nil) }

func nrNullTimeoutsVal() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func nrObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                           nrNullStr(),
		"interface_alias":              tftypes.NewValue(tftypes.String, "Ethernet 2"),
		"destination_prefix":           tftypes.NewValue(tftypes.String, "198.51.100.0/24"),
		"next_hop":                     tftypes.NewValue(tftypes.String, "192.0.2.1"),
		"route_metric":                 tftypes.NewValue(tftypes.Number, 10),
		"unsafe_skip_management_check": tftypes.NewValue(tftypes.Bool, false),
		"interface_index":              nrNullNum(),
		"address_family":               nrNullStr(),
		"interface_metric":             nrNullNum(),
		"effective_metric":             nrNullNum(),
		"protocol":                     nrNullStr(),
		"timeouts":                     nrNullTimeoutsVal(),
	}
}

func nrObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := nrObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(nrObjType(), base)
}

func nrState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsNetRouteSchemaDefinition(context.Background())
	return tfsdk.State{Raw: nrObj(overrides), Schema: s}
}

func nrPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsNetRouteSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: nrObj(overrides), Schema: s}
}

func nrConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsNetRouteSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: nrObj(overrides), Schema: s}
}

func nrDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsNetRouteResource_Metadata(t *testing.T) {
	r := &windowsNetRouteResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_net_route" {
		t.Errorf("TypeName = %q, want windows_net_route", resp.TypeName)
	}
}

func TestWindowsNetRouteResource_Schema(t *testing.T) {
	r := &windowsNetRouteResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics: %v", nrDiagSummaries(schemaResp.Diagnostics))
	}
	s := schemaResp.Schema

	get := func(name string) schema.Attribute {
		a, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("schema missing attribute %q", name)
		}
		return a
	}

	// Identity attributes: Required + ForceNew.
	for _, name := range []string{"interface_alias", "destination_prefix", "next_hop"} {
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
	// route_metric: Optional+Computed with the Windows default.
	a, ok := get("route_metric").(schema.Int64Attribute)
	if !ok {
		t.Fatalf("expected schema.Int64Attribute, got %T", a)
	}
	if !a.Optional || !a.Computed {
		t.Error("route_metric must be Optional+Computed")
	}
	if a.Default == nil {
		t.Error("route_metric must carry a default (256)")
	}
	// unsafe_skip_management_check: Optional+Computed with false default.
	b, ok := get("unsafe_skip_management_check").(schema.BoolAttribute)
	if !ok {
		t.Fatalf("expected schema.BoolAttribute, got %T", b)
	}
	if !b.Optional || !b.Computed || b.Default == nil {
		t.Error("unsafe_skip_management_check must be Optional+Computed with a default")
	}
	// Computed-only.
	for _, name := range []string{"id", "interface_index", "address_family", "interface_metric", "effective_metric", "protocol"} {
		attr := get(name)
		switch v := attr.(type) {
		case schema.StringAttribute:
			if !v.Computed || v.Required || v.Optional {
				t.Errorf("%s must be Computed-only", name)
			}
		case schema.Int64Attribute:
			if !v.Computed || v.Required || v.Optional {
				t.Errorf("%s must be Computed-only", name)
			}
		default:
			t.Errorf("%s has unexpected attribute type %T", name, attr)
		}
	}
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Error("schema must expose a timeouts block")
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestNetRouteAliasValidator(t *testing.T) {
	v := netRouteAliasValidator{}
	run := func(val string) diag.Diagnostics {
		req := validator.StringRequest{
			Path:        path.Root("interface_alias"),
			ConfigValue: types.StringValue(val),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		return resp.Diagnostics
	}
	if d := run("Ethernet 2"); d.HasError() {
		t.Errorf("plain alias must pass, got %v", nrDiagSummaries(d))
	}
	if d := run("Ethernet|2"); !d.HasError() {
		t.Error("alias with '|' must fail")
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("interface_alias"), ConfigValue: types.StringNull()}, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null alias must skip")
	}
}

func TestNetRoutePrefixValidator(t *testing.T) {
	v := netRoutePrefixValidator{}
	run := func(val string) diag.Diagnostics {
		req := validator.StringRequest{
			Path:        path.Root("destination_prefix"),
			ConfigValue: types.StringValue(val),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		return resp.Diagnostics
	}
	for _, good := range []string{"198.51.100.0/24", "0.0.0.0/0", "::/0", "2001:db8::/32", "192.0.2.1/32", "2001:db8::1/128"} {
		if d := run(good); d.HasError() {
			t.Errorf("prefix %q must pass, got %v", good, nrDiagSummaries(d))
		}
	}
	for _, bad := range []string{"not-a-prefix", "10.0.0.1", "198.51.100.0/33"} {
		if d := run(bad); !d.HasError() {
			t.Errorf("prefix %q must fail", bad)
		}
	}
	// Host bits set: plan-time error naming the canonical form.
	d := run("198.51.100.7/24")
	if !d.HasError() {
		t.Fatal("host-bits prefix must fail")
	}
	if joined := strings.Join(nrDiagSummaries(d), "\n"); !strings.Contains(joined, "198.51.100.0/24") {
		t.Errorf("host-bits error must name 198.51.100.0/24, got:\n%s", joined)
	}
	d = run("2001:db8::1/32")
	if !d.HasError() || !strings.Contains(strings.Join(nrDiagSummaries(d), "\n"), "2001:db8::/32") {
		t.Errorf("ipv6 host-bits error must name 2001:db8::/32, got:\n%s", strings.Join(nrDiagSummaries(d), "\n"))
	}
}

func TestNetRouteNextHopValidator(t *testing.T) {
	v := netRouteNextHopValidator{}
	run := func(val string) diag.Diagnostics {
		req := validator.StringRequest{
			Path:        path.Root("next_hop"),
			ConfigValue: types.StringValue(val),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		return resp.Diagnostics
	}
	// Unspecified (on-link) spellings are allowed.
	for _, good := range []string{"192.0.2.1", "0.0.0.0", "::", "fe80::1", "::ffff:192.0.2.1"} {
		if d := run(good); d.HasError() {
			t.Errorf("next hop %q must pass, got %v", good, nrDiagSummaries(d))
		}
	}
	for _, bad := range []string{"999.1.1.1", "224.0.0.1", "ff02::1", "127.0.0.1", "::1", "255.255.255.255", "fe80::1%12", "not-an-ip"} {
		if d := run(bad); !d.HasError() {
			t.Errorf("next hop %q must fail", bad)
		}
	}
}

func TestNetRouteConfigValidator(t *testing.T) {
	v := netRouteConfigValidator{}
	run := func(prefix, next string) diag.Diagnostics {
		over := map[string]tftypes.Value{
			"destination_prefix": tftypes.NewValue(tftypes.String, prefix),
			"next_hop":           tftypes.NewValue(tftypes.String, next),
		}
		req := resource.ValidateConfigRequest{Config: nrConfig(t, over)}
		resp := &resource.ValidateConfigResponse{}
		v.ValidateResource(context.Background(), req, resp)
		return resp.Diagnostics
	}
	if d := run("198.51.100.0/24", "192.0.2.1"); d.HasError() {
		t.Errorf("v4 pair must pass, got %v", nrDiagSummaries(d))
	}
	if d := run("2001:db8::/32", "fe80::1"); d.HasError() {
		t.Errorf("v6 pair must pass, got %v", nrDiagSummaries(d))
	}
	if d := run("0.0.0.0/0", "0.0.0.0"); d.HasError() {
		t.Errorf("on-link default must pass, got %v", nrDiagSummaries(d))
	}
	if d := run("198.51.100.0/24", "fe80::1"); !d.HasError() {
		t.Error("v4 prefix with v6 next hop must fail")
	}
	if d := run("2001:db8::/32", "192.0.2.1"); !d.HasError() {
		t.Error("v6 prefix with v4 next hop must fail")
	}
}

// ---------------------------------------------------------------------------
// ID + canonicalisation helpers
// ---------------------------------------------------------------------------

func TestNetRouteIDHelpers(t *testing.T) {
	prefix, err := canonicalNetRoutePrefix("198.51.100.0/24")
	if err != nil || prefix != "198.51.100.0/24" {
		t.Errorf("prefix = %q, %v", prefix, err)
	}
	if prefix, err := canonicalNetRoutePrefix("2001:DB8::/32"); err != nil || prefix != "2001:db8::/32" {
		t.Errorf("v6 prefix = %q, %v", prefix, err)
	}
	if _, err := canonicalNetRoutePrefix("nope"); err == nil {
		t.Error("garbage prefix must fail")
	}
	nextHop, err := canonicalNetRouteNextHop("::FFFF:192.0.2.1")
	if err != nil || nextHop != "192.0.2.1" {
		t.Errorf("next hop = %q, %v", nextHop, err)
	}
	if _, err := canonicalNetRouteNextHop("fe80::1%eth0"); err == nil {
		t.Error("zone ID must fail")
	}
	if id := netRouteID("Ethernet 2", "198.51.100.0/24", "192.0.2.1"); id != "Ethernet 2|198.51.100.0/24|192.0.2.1" {
		t.Errorf("id = %q", id)
	}
	alias, prefix, nextHop, err := splitNetRouteID("Ethernet 2|198.51.100.0/24|192.0.2.1")
	if err != nil || alias != "Ethernet 2" || prefix != "198.51.100.0/24" || nextHop != "192.0.2.1" {
		t.Errorf("split = %q, %q, %q, %v", alias, prefix, nextHop, err)
	}
	alias, prefix, nextHop, err = splitNetRouteID(" Ethernet 2 | 198.51.100.0/24 | 192.0.2.1 ")
	if err != nil || alias != "Ethernet 2" || prefix != "198.51.100.0/24" || nextHop != "192.0.2.1" {
		t.Errorf("spaced split = %q, %q, %q, %v", alias, prefix, nextHop, err)
	}
	for _, bad := range []string{"", "no-separator", "a|b", "a|b|c|d", "|198.51.100.0/24|192.0.2.1", "Ethernet 2||192.0.2.1", "Ethernet 2|198.51.100.0/24|"} {
		if _, _, _, err := splitNetRouteID(bad); err == nil {
			t.Errorf("ID %q must fail", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestWindowsNetRouteResource_Configure(t *testing.T) {
	r := &windowsNetRouteResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsNetRouteResource_Create_HappyPath(t *testing.T) {
	fc := &fakeNetRouteClient{createOut: okNetRouteInfo()}
	r := &windowsNetRouteResource{routes: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: nrPlan(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", nrDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.InterfaceAlias != "Ethernet 2" || fc.createIn.DestinationPrefix != "198.51.100.0/24" ||
		fc.createIn.NextHop != "192.0.2.1" || fc.createIn.RouteMetric != 10 {
		t.Errorf("unexpected client input: %+v", fc.createIn)
	}
	var model windowsNetRouteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Ethernet 2|198.51.100.0/24|192.0.2.1" {
		t.Errorf("id = %q, want Ethernet 2|198.51.100.0/24|192.0.2.1", model.ID.ValueString())
	}
	if model.InterfaceIndex.ValueInt64() != 7 || model.AddressFamily.ValueString() != "IPv4" ||
		model.EffectiveMetric.ValueInt64() != 35 || model.Protocol.ValueString() != "NetMgmt" {
		t.Errorf("computed not refreshed: %+v", model)
	}
}

func TestWindowsNetRouteResource_Create_Canonicalises(t *testing.T) {
	out := okNetRouteInfo()
	out.DestinationPrefix = "2001:db8::/32"
	out.NextHop = "fe80::1"
	out.AddressFamily = "IPv6"
	fc := &fakeNetRouteClient{createOut: out}
	r := &windowsNetRouteResource{routes: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: nrPlan(t, map[string]tftypes.Value{
		"destination_prefix": tftypes.NewValue(tftypes.String, "2001:DB8::/32"),
		"next_hop":           tftypes.NewValue(tftypes.String, "FE80::1"),
	})}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", nrDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.DestinationPrefix != "2001:db8::/32" || fc.createIn.NextHop != "fe80::1" {
		t.Errorf("client must receive canonical values, got %+v", fc.createIn)
	}
}

func TestWindowsNetRouteResource_Create_GuardRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  winclient.NetRouteErrorKind
		msg   string
		check string
	}{
		{"at risk", winclient.NetRouteErrorMgmtAtRisk,
			"refusing create of route 198.51.100.0/24 via 192.0.2.1 on interface \"Ethernet 2\": it would hijack the return path of this SSH session. Set unsafe_skip_management_check = true to proceed anyway.",
			"management_path_at_risk"},
		{"unknown", winclient.NetRouteErrorMgmtUnknown,
			"cannot determine the management path for this SSH session. Set unsafe_skip_management_check = true to proceed anyway.",
			"management_path_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeNetRouteClient{createErr: winclient.NewNetRouteError(tc.kind, tc.msg, nil, nil)}
			r := &windowsNetRouteResource{routes: fc}
			resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
			r.Create(context.Background(), resource.CreateRequest{Plan: nrPlan(t, nil)}, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatal("expected a guard diagnostic")
			}
			joined := strings.Join(nrDiagSummaries(resp.Diagnostics), "\n")
			if !strings.Contains(joined, tc.check) || !strings.Contains(joined, "unsafe_skip_management_check") {
				t.Errorf("refusal diagnostic must name %q and the escape hatch, got:\n%s", tc.check, joined)
			}
		})
	}
}

func TestWindowsNetRouteResource_Create_AlreadyExists(t *testing.T) {
	fc := &fakeNetRouteClient{createErr: winclient.NewNetRouteError(
		winclient.NetRouteErrorAlreadyExists, "already exists; terraform import", nil, nil)}
	r := &windowsNetRouteResource{routes: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: nrPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an already_exists diagnostic")
	}
	if joined := strings.Join(nrDiagSummaries(resp.Diagnostics), "\n"); !strings.Contains(joined, "already_exists") {
		t.Errorf("diagnostic must name already_exists, got:\n%s", joined)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsNetRouteResource_Read(t *testing.T) {
	fc := &fakeNetRouteClient{readOut: okNetRouteInfo()}
	r := &windowsNetRouteResource{routes: fc}
	state := nrState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "Ethernet 2|198.51.100.0/24|192.0.2.1"),
	})
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", nrDiagSummaries(resp.Diagnostics))
	}
	if fc.readAlias != "Ethernet 2" || fc.readPrefix != "198.51.100.0/24" || fc.readNext != "192.0.2.1" {
		t.Errorf("unexpected read args: %q %q %q", fc.readAlias, fc.readPrefix, fc.readNext)
	}
	var model windowsNetRouteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.EffectiveMetric.ValueInt64() != 35 {
		t.Errorf("computed not refreshed: %+v", model)
	}
}

func TestWindowsNetRouteResource_Read_MissingRemoves(t *testing.T) {
	fc := &fakeNetRouteClient{readOut: nil}
	r := &windowsNetRouteResource{routes: fc}

	state := nrState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "Ethernet 2|198.51.100.0/24|192.0.2.1"),
	})
	req := resource.ReadRequest{State: state}
	resp := &resource.ReadResponse{State: state}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing must not error: %v", nrDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("missing route must remove the resource from state")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestWindowsNetRouteResource_Update_MetricInPlace(t *testing.T) {
	out := okNetRouteInfo()
	out.RouteMetric = 99
	out.EffectiveMetric = 124
	fc := &fakeNetRouteClient{updateOut: out}
	r := &windowsNetRouteResource{routes: fc}
	prior := nrState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "Ethernet 2|198.51.100.0/24|192.0.2.1"),
	})
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan: nrPlan(t, map[string]tftypes.Value{
			"route_metric": tftypes.NewValue(tftypes.Number, 99),
		}),
		State: prior,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", nrDiagSummaries(resp.Diagnostics))
	}
	if fc.updateAlias != "Ethernet 2" || fc.updatePrefix != "198.51.100.0/24" || fc.updateNext != "192.0.2.1" || fc.updateMetric != 99 {
		t.Errorf("unexpected update args: %+v", fc)
	}
	var model windowsNetRouteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Ethernet 2|198.51.100.0/24|192.0.2.1" {
		t.Errorf("update must preserve the ID, got %q", model.ID.ValueString())
	}
	if model.RouteMetric.ValueInt64() != 99 || model.EffectiveMetric.ValueInt64() != 124 {
		t.Errorf("metric not refreshed: %+v", model)
	}
}

func TestWindowsNetRouteResource_Update_GuardRefusal(t *testing.T) {
	fc := &fakeNetRouteClient{updateErr: winclient.NewNetRouteError(
		winclient.NetRouteErrorMgmtAtRisk, "refusing update: it is the management route. Set unsafe_skip_management_check = true.", nil, nil)}
	r := &windowsNetRouteResource{routes: fc}
	prior := nrState(t, nil)
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Update(context.Background(), resource.UpdateRequest{Plan: nrPlan(t, nil), State: prior}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected a guard diagnostic")
	}
}

func TestWindowsNetRouteResource_Delete(t *testing.T) {
	fc := &fakeNetRouteClient{}
	r := &windowsNetRouteResource{routes: fc}
	state := nrState(t, map[string]tftypes.Value{
		"id":                           tftypes.NewValue(tftypes.String, "Ethernet 2|198.51.100.0/24|192.0.2.1"),
		"unsafe_skip_management_check": tftypes.NewValue(tftypes.Bool, true),
	})
	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", nrDiagSummaries(resp.Diagnostics))
	}
	if fc.deleteAlias != "Ethernet 2" || fc.deletePrefix != "198.51.100.0/24" || fc.deleteNext != "192.0.2.1" || !fc.deleteUnsafe {
		t.Errorf("unexpected delete args: %+v", fc)
	}
}

func TestWindowsNetRouteResource_Delete_InvalidID(t *testing.T) {
	fc := &fakeNetRouteClient{}
	r := &windowsNetRouteResource{routes: fc}
	state := nrState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "not-an-id"),
	})
	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("invalid ID must error")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsNetRouteResource_ImportState(t *testing.T) {
	fc := &fakeNetRouteClient{readOut: okNetRouteInfo()}
	r := &windowsNetRouteResource{routes: fc}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), resource.ImportStateRequest{
		ID: "Ethernet 2|198.51.100.0/24|192.0.2.1",
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", nrDiagSummaries(resp.Diagnostics))
	}
	var model windowsNetRouteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Ethernet 2|198.51.100.0/24|192.0.2.1" {
		t.Errorf("id = %q", model.ID.ValueString())
	}
	if model.Protocol.ValueString() != "NetMgmt" || model.RouteMetric.ValueInt64() != 10 {
		t.Errorf("imported state not projected: %+v", model)
	}
}

func TestWindowsNetRouteResource_ImportState_Refusals(t *testing.T) {
	// Non-NetMgmt protocol refused.
	dhcp := okNetRouteInfo()
	dhcp.Protocol = "Dhcp"
	fc := &fakeNetRouteClient{readOut: dhcp}
	r := &windowsNetRouteResource{routes: fc}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), resource.ImportStateRequest{
		ID: "Ethernet 2|0.0.0.0/0|192.0.2.1",
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Dhcp route import must fail")
	}
	if joined := strings.Join(nrDiagSummaries(resp.Diagnostics), "\n"); !strings.Contains(joined, "NetMgmt") {
		t.Errorf("refusal must name NetMgmt, got:\n%s", joined)
	}

	// Missing route refused.
	fc2 := &fakeNetRouteClient{readOut: nil}
	r2 := &windowsNetRouteResource{routes: fc2}
	resp2 := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
	r2.ImportState(context.Background(), resource.ImportStateRequest{
		ID: "Ethernet 2|198.51.100.0/24|192.0.2.1",
	}, resp2)
	if !resp2.Diagnostics.HasError() {
		t.Error("missing route import must fail")
	}

	// Bad IDs refused.
	for _, bad := range []string{"no-separator", "a|b", "Ethernet 2|nope|192.0.2.1", "Ethernet 2|198.51.100.0/24|nope"} {
		resp3 := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsNetRouteSchemaDefinition(context.Background())}}
		r2.ImportState(context.Background(), resource.ImportStateRequest{ID: bad}, resp3)
		if !resp3.Diagnostics.HasError() {
			t.Errorf("import ID %q must fail", bad)
		}
	}
}
