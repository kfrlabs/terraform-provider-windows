// Package provider — unit tests for the windows_iis_binding resource.
//
// These tests exercise the schema, validators, ValidateConfig matrix,
// canonicalisation, input projection and CRUD handlers without SSH. A
// fakeIISBindingClient is injected into windowsIISBindingResource.binding.
//
// Edge cases covered (issue #285):
//
//	Metadata                 — returns "windows_iis_binding"
//	Schema                   — identity attrs Required/ForceNew, port range,
//	                           ip/host/thumbprint/store validators,
//	                           require_sni/store defaults,
//	                           binding_information Computed, timeouts block
//	Attribute validators     — "*" + IP canonical shapes pass, zones fail;
//	                           host pipes/colons/whitespace fail;
//	                           thumbprint 40-hex normalisation
//	Config matrix            — thumbprint/SNI need https; SNI needs a host
//	Canonicalisation         — protocol/IP/host/port shapes
//	Create input             — only configured in-place attrs sent
//	In-place delta           — require_sni/thumbprint/store change
//	                           detection; untouched cert round-trips prior
//	Create (happy)           — timeouts kept, id + binding_information set
//	Create (would_lock_out / — diagnostics
//	site_not_found / conflict)
//	Read (happy/missing)     — missing removes from state, timeouts kept
//	Update (happy)           — input forwarded; no-op refreshes via Read
//	Delete (happy)           — host called with parsed identity
//	ImportState (happy)      — id parsed, thumbprint/store projected
//	ImportState (invalid)    — diagnostic error
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeIISBindingClient
// ---------------------------------------------------------------------------

type fakeIISBindingClient struct {
	createIn  winclient.IISBindingInput
	createOut *winclient.IISBindingState
	createErr error

	readSite, readProto, readBI string
	readOut                     *winclient.IISBindingState
	readErr                     error

	updateIn  winclient.IISBindingInput
	updateOut *winclient.IISBindingState
	updateErr error

	deleteSite, deleteProto, deleteBI string
	deleteErr                         error
}

func (f *fakeIISBindingClient) Create(_ context.Context, in winclient.IISBindingInput) (*winclient.IISBindingState, error) {
	f.createIn = in
	return f.createOut, f.createErr
}

func (f *fakeIISBindingClient) Read(_ context.Context, site, protocol, bindingInformation string) (*winclient.IISBindingState, error) {
	f.readSite, f.readProto, f.readBI = site, protocol, bindingInformation
	return f.readOut, f.readErr
}

func (f *fakeIISBindingClient) Update(_ context.Context, in winclient.IISBindingInput) (*winclient.IISBindingState, error) {
	f.updateIn = in
	return f.updateOut, f.updateErr
}

func (f *fakeIISBindingClient) Delete(_ context.Context, site, protocol, bindingInformation string) error {
	f.deleteSite, f.deleteProto, f.deleteBI = site, protocol, bindingInformation
	return f.deleteErr
}

func okIISBindingState() *winclient.IISBindingState {
	return &winclient.IISBindingState{
		SiteName: "web", Protocol: "https", IPAddress: "*",
		Port: 443, HostHeader: "example.com", RequireSNI: true,
		CertificateThumbprint: strings.Repeat("A", 40),
		CertificateStoreName:  "My",
		BindingInformation:    "*:443:example.com", SslFlags: 1,
	}
}

func okIISBindingHTTPState() *winclient.IISBindingState {
	return &winclient.IISBindingState{
		SiteName: "web", Protocol: "http", IPAddress: "*",
		Port: 80, HostHeader: "", RequireSNI: false,
		CertificateThumbprint: "",
		CertificateStoreName:  "",
		BindingInformation:    "*:80:", SslFlags: 0,
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_iis_binding schema
// ---------------------------------------------------------------------------

func bindingObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                     tftypes.String,
		"site_name":              tftypes.String,
		"protocol":               tftypes.String,
		"ip_address":             tftypes.String,
		"port":                   tftypes.Number,
		"host_header":            tftypes.String,
		"require_sni":            tftypes.Bool,
		"certificate_thumbprint": tftypes.String,
		"certificate_store_name": tftypes.String,
		"binding_information":    tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func bindingNullStr() tftypes.Value { return tftypes.NewValue(tftypes.String, nil) }

func bindingNullTimeouts() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func bindingObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                     tftypes.NewValue(tftypes.String, "web|https|*:443:example.com"),
		"site_name":              tftypes.NewValue(tftypes.String, "web"),
		"protocol":               tftypes.NewValue(tftypes.String, "https"),
		"ip_address":             tftypes.NewValue(tftypes.String, "*"),
		"port":                   tftypes.NewValue(tftypes.Number, 443),
		"host_header":            tftypes.NewValue(tftypes.String, "example.com"),
		"require_sni":            tftypes.NewValue(tftypes.Bool, true),
		"certificate_thumbprint": tftypes.NewValue(tftypes.String, strings.Repeat("A", 40)),
		"certificate_store_name": tftypes.NewValue(tftypes.String, "My"),
		"binding_information":    bindingNullStr(),
		"timeouts":               bindingNullTimeouts(),
	}
}

func bindingObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := bindingObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(bindingObjType(), base)
}

func bindingState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsIISBindingSchemaDefinition(context.Background())
	return tfsdk.State{Raw: bindingObj(overrides), Schema: s}
}

func bindingPlan(t *testing.T) tfsdk.Plan {
	t.Helper()
	s := windowsIISBindingSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: bindingObj(nil), Schema: s}
}

func bindingConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsIISBindingSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: bindingObj(overrides), Schema: s}
}

func bindingDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsIISBindingResource_Metadata(t *testing.T) {
	r := &windowsIISBindingResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_iis_binding" {
		t.Errorf("TypeName = %q, want windows_iis_binding", resp.TypeName)
	}
}

func TestWindowsIISBindingResource_Schema(t *testing.T) {
	s := windowsIISBindingSchemaDefinition(context.Background())
	get := func(name string) schema.Attribute {
		a, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("schema missing attribute %q", name)
		}
		return a
	}
	strAttr := func(name string) schema.StringAttribute {
		a, ok := get(name).(schema.StringAttribute)
		if !ok {
			t.Fatalf("attribute %q is %T, want StringAttribute", name, get(name))
		}
		return a
	}
	if a := strAttr("site_name"); !a.Required || a.Computed {
		t.Error("site_name must be Required (not Computed)")
	}
	if a := strAttr("protocol"); !a.Required || a.Computed {
		t.Error("protocol must be Required (not Computed)")
	}
	intAttr, ok := get("port").(schema.Int64Attribute)
	if !ok {
		t.Fatalf("port is %T, want Int64Attribute", get("port"))
	}
	if !intAttr.Required || intAttr.Computed {
		t.Error("port must be Required (not Computed)")
	}
	// Defaults: "*" / "" / false / "My".
	if a := strAttr("ip_address"); !a.Optional || !a.Computed {
		t.Error("ip_address must be Optional+Computed")
	}
	if a := strAttr("host_header"); !a.Optional || !a.Computed {
		t.Error("host_header must be Optional+Computed")
	}
	boolAttr, ok := get("require_sni").(schema.BoolAttribute)
	if !ok {
		t.Fatalf("require_sni is %T, want BoolAttribute", get("require_sni"))
	}
	if !boolAttr.Optional || !boolAttr.Computed {
		t.Error("require_sni must be Optional+Computed")
	}
	if a := strAttr("certificate_thumbprint"); a.Computed || !a.Optional {
		t.Error("certificate_thumbprint must be Optional without Computed (null = no certificate)")
	}
	if a := strAttr("certificate_store_name"); !a.Optional || !a.Computed {
		t.Error("certificate_store_name must be Optional+Computed")
	}
	if a := strAttr("binding_information"); !a.Computed || a.Optional || a.Required {
		t.Error("binding_information must be Computed-only")
	}
	if a := strAttr("id"); !a.Computed || a.Optional || a.Required {
		t.Error("id must be Computed-only")
	}
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Error("schema must expose timeouts")
	}
}

// ---------------------------------------------------------------------------
// Attribute validators
// ---------------------------------------------------------------------------

func TestIISBindingIPAddressValidator(t *testing.T) {
	v := iisBindingIPAddressValidator{}
	run := func(raw string) diag.Diagnostics {
		req := validator.StringRequest{
			Path:        path.Root("ip_address"),
			ConfigValue: types.StringValue(raw),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		return resp.Diagnostics
	}
	for _, good := range []string{"*", "192.0.2.10", "2001:db8::10", "::1", "0.0.0.0"} {
		if d := run(good); d.HasError() {
			t.Errorf("ip %q must pass, got %v", good, bindingDiagSummaries(d))
		}
	}
	for _, bad := range []string{"nope", "fe80::1%eth0", "1.2.3.4/24", "[::1]"} {
		if d := run(bad); !d.HasError() {
			t.Errorf("ip %q must fail", bad)
		}
	}
}

func TestIISBindingHostHeaderValidator(t *testing.T) {
	v := iisBindingHostHeaderValidator{}
	run := func(raw string) diag.Diagnostics {
		req := validator.StringRequest{
			Path:        path.Root("host_header"),
			ConfigValue: types.StringValue(raw),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		return resp.Diagnostics
	}
	for _, good := range []string{"", "example.com", "EXAMPLE.com", "a-b.c_d"} {
		if d := run(good); d.HasError() {
			t.Errorf("host %q must pass, got %v", good, bindingDiagSummaries(d))
		}
	}
	for _, bad := range []string{"a|b", "a:b", "has space"} {
		if d := run(bad); !d.HasError() {
			t.Errorf("host %q must fail", bad)
		}
	}
}

func TestIISBindingThumbprintValidator(t *testing.T) {
	v := iisBindingThumbprintValidator{}
	run := func(raw string) diag.Diagnostics {
		req := validator.StringRequest{
			Path:        path.Root("certificate_thumbprint"),
			ConfigValue: types.StringValue(raw),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		return resp.Diagnostics
	}
	if d := run(strings.ToLower(strings.Repeat("A", 40))); d.HasError() {
		t.Errorf("lower-case thumbprint must pass, got %v", bindingDiagSummaries(d))
	}
	if d := run("ab cd " + strings.Repeat("0", 36)); d.HasError() {
		t.Errorf("spaced thumbprint must pass, got %v", bindingDiagSummaries(d))
	}
	for _, bad := range []string{"abc", strings.Repeat("G", 40), strings.Repeat("A", 39)} {
		if d := run(bad); !d.HasError() {
			t.Errorf("thumbprint %q must fail", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Config matrix
// ---------------------------------------------------------------------------

func TestIISBindingCanonicalPlanModifiers(t *testing.T) {
	ctx := context.Background()
	run := func(m planmodifier.String, v types.String) (types.String, diag.Diagnostics) {
		resp := &planmodifier.StringResponse{PlanValue: v}
		m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: v}, resp)
		return resp.PlanValue, resp.Diagnostics
	}

	ipMod := iisBindingIPAddressCanonicalModifier{}
	if got, d := run(ipMod, types.StringValue("2001:DB8::1")); d.HasError() || got.ValueString() != "2001:db8::1" {
		t.Errorf("IP modifier = %q (%v), want 2001:db8::1", got.ValueString(), bindingDiagSummaries(d))
	}
	if got, d := run(ipMod, types.StringValue("::ffff:192.168.1.1")); d.HasError() || got.ValueString() != "192.168.1.1" {
		t.Errorf("IP modifier = %q (%v), want 192.168.1.1", got.ValueString(), bindingDiagSummaries(d))
	}
	if got, _ := run(ipMod, types.StringNull()); !got.IsNull() {
		t.Error("IP modifier must leave null alone")
	}
	if got, _ := run(ipMod, types.StringUnknown()); !got.IsUnknown() {
		t.Error("IP modifier must leave unknown alone")
	}
	if got, d := run(ipMod, types.StringValue("nope")); d.HasError() || got.ValueString() != "nope" {
		t.Errorf("IP modifier must leave invalid input for the validator, got %q (%v)", got.ValueString(), bindingDiagSummaries(d))
	}

	hostMod := iisBindingHostHeaderCanonicalModifier{}
	if got, d := run(hostMod, types.StringValue("Example.COM")); d.HasError() || got.ValueString() != "example.com" {
		t.Errorf("host modifier = %q (%v), want example.com", got.ValueString(), bindingDiagSummaries(d))
	}
	if got, _ := run(hostMod, types.StringNull()); !got.IsNull() {
		t.Error("host modifier must leave null alone")
	}

	thumbMod := iisBindingThumbprintCanonicalModifier{}
	if got, d := run(thumbMod, types.StringValue(strings.ToLower(strings.Repeat("D", 40)))); d.HasError() || got.ValueString() != strings.Repeat("D", 40) {
		t.Errorf("thumbprint modifier = %q (%v), want upper-case", got.ValueString(), bindingDiagSummaries(d))
	}
	if got, d := run(thumbMod, types.StringValue("ab cd "+strings.Repeat("0", 36))); d.HasError() || got.ValueString() != "ABCD"+strings.Repeat("0", 36) {
		t.Errorf("thumbprint modifier = %q (%v), want spaces stripped", got.ValueString(), bindingDiagSummaries(d))
	}
	if got, _ := run(thumbMod, types.StringValue("")); got.ValueString() != "" {
		t.Error("thumbprint modifier must leave empty alone (null and empty both mean no certificate)")
	}
	if got, _ := run(thumbMod, types.StringNull()); !got.IsNull() {
		t.Error("thumbprint modifier must leave null alone")
	}
	if got, d := run(thumbMod, types.StringValue("zzz")); d.HasError() || got.ValueString() != "zzz" {
		t.Errorf("thumbprint modifier must leave invalid input for the validator, got %q (%v)", got.ValueString(), bindingDiagSummaries(d))
	}
}

func TestIISBindingConfigValidator(t *testing.T) {
	v := iisBindingConfigValidator{}
	run := func(proto string, sni bool, host, thumb string) diag.Diagnostics {
		over := map[string]tftypes.Value{
			"protocol":               tftypes.NewValue(tftypes.String, proto),
			"require_sni":            tftypes.NewValue(tftypes.Bool, sni),
			"host_header":            tftypes.NewValue(tftypes.String, host),
			"certificate_thumbprint": tftypes.NewValue(tftypes.String, thumb),
		}
		if thumb == "" {
			over["certificate_thumbprint"] = bindingNullStr()
		}
		req := resource.ValidateConfigRequest{Config: bindingConfig(t, over)}
		resp := &resource.ValidateConfigResponse{}
		v.ValidateResource(context.Background(), req, resp)
		return resp.Diagnostics
	}
	thumb := strings.Repeat("A", 40)
	if d := run("https", true, "example.com", thumb); d.HasError() {
		t.Errorf("full https config must pass, got %v", bindingDiagSummaries(d))
	}
	if d := run("http", false, "", ""); d.HasError() {
		t.Errorf("plain http config must pass, got %v", bindingDiagSummaries(d))
	}
	if d := run("http", false, "", thumb); !d.HasError() {
		t.Error("thumbprint on http must fail")
	}
	if d := run("http", true, "example.com", ""); !d.HasError() {
		t.Error("require_sni on http must fail")
	}
	if d := run("https", true, "", ""); !d.HasError() {
		t.Error("require_sni without a host must fail")
	}
}

func TestIISBindingConfigValidator_StoreWithoutThumbprint(t *testing.T) {
	v := iisBindingConfigValidator{}
	run := func(thumb, store string) diag.Diagnostics {
		thumbVal := bindingNullStr()
		if thumb != "" {
			thumbVal = tftypes.NewValue(tftypes.String, thumb)
		}
		over := map[string]tftypes.Value{
			"protocol":               tftypes.NewValue(tftypes.String, "https"),
			"require_sni":            tftypes.NewValue(tftypes.Bool, false),
			"host_header":            tftypes.NewValue(tftypes.String, "example.com"),
			"certificate_thumbprint": thumbVal,
			"certificate_store_name": tftypes.NewValue(tftypes.String, store),
		}
		req := resource.ValidateConfigRequest{Config: bindingConfig(t, over)}
		resp := &resource.ValidateConfigResponse{}
		v.ValidateResource(context.Background(), req, resp)
		return resp.Diagnostics
	}
	thumb := strings.Repeat("A", 40)
	if d := run(thumb, "WebHosting"); d.HasError() {
		t.Errorf("store with a certificate must pass, got %v", bindingDiagSummaries(d))
	}
	if d := run("", "My"); d.HasError() {
		t.Errorf("default store without a certificate must pass, got %v", bindingDiagSummaries(d))
	}
	d := run("", "WebHosting")
	if d.HasError() {
		t.Errorf("non-default store without a certificate must warn, not error, got %v", bindingDiagSummaries(d))
	}
	if len(d.Warnings()) == 0 {
		t.Error("non-default store without a certificate must warn that the store is ignored")
	}
}

// ---------------------------------------------------------------------------
// Canonicalisation + input projection
// ---------------------------------------------------------------------------

func TestCanonicalIISBindingPlan(t *testing.T) {
	m := windowsIISBindingModel{
		Protocol:   types.StringValue("HTTPS"),
		IPAddress:  types.StringValue("2001:DB8::1"),
		HostHeader: types.StringValue("Example.COM"),
		Port:       types.Int64Value(443),
	}
	proto, ip, host, port, diags := canonicalIISBindingPlan(m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(diags))
	}
	if proto != "https" || ip != "2001:db8::1" || host != "example.com" || port != 443 {
		t.Errorf("got (%q, %q, %q, %d)", proto, ip, host, port)
	}
	bad := m
	bad.Port = types.Int64Value(0)
	if _, _, _, _, diags := canonicalIISBindingPlan(bad); !diags.HasError() {
		t.Error("port 0 must fail canonicalisation")
	}
}

func TestModelToIISBindingCreateInput_OnlyConfigured(t *testing.T) {
	m := windowsIISBindingModel{
		SiteName:              types.StringValue("web"),
		RequireSNI:            types.BoolNull(),
		CertificateThumbprint: types.StringNull(),
		CertificateStoreName:  types.StringNull(),
	}
	in := modelToIISBindingCreateInput(m, "http", "*", "", 80)
	if in.RequireSNI != nil {
		t.Error("null require_sni must stay nil (never sent)")
	}
	if in.CertificateThumbprint != nil {
		t.Error("null thumbprint must stay nil (never sent)")
	}
	full := windowsIISBindingModel{
		SiteName:              types.StringValue("web"),
		RequireSNI:            types.BoolValue(true),
		CertificateThumbprint: types.StringValue(strings.ToLower(strings.Repeat("B", 40))),
		CertificateStoreName:  types.StringValue("webhosting"),
	}
	in = modelToIISBindingCreateInput(full, "https", "*", "example.com", 443)
	if in.RequireSNI == nil || !*in.RequireSNI {
		t.Errorf("configured require_sni must be forwarded, got %+v", in.RequireSNI)
	}
	if in.CertificateThumbprint == nil || *in.CertificateThumbprint != strings.Repeat("B", 40) {
		t.Errorf("thumbprint must be normalised to upper-case, got %+v", in.CertificateThumbprint)
	}
	if in.CertificateStoreName != "WebHosting" {
		t.Errorf("store must be canonicalised, got %q", in.CertificateStoreName)
	}
}

func TestIISBindingInPlaceChanged(t *testing.T) {
	base := windowsIISBindingModel{
		RequireSNI:            types.BoolValue(false),
		CertificateThumbprint: types.StringNull(),
		CertificateStoreName:  types.StringValue("My"),
	}
	same := base
	if iisBindingInPlaceChanged(same, base) {
		t.Error("identical models must not report a change")
	}
	changed := base
	changed.RequireSNI = types.BoolValue(true)
	if !iisBindingInPlaceChanged(changed, base) {
		t.Error("require_sni flip must report a change")
	}
	changed = base
	changed.CertificateThumbprint = types.StringValue(strings.Repeat("C", 40))
	if !iisBindingInPlaceChanged(changed, base) {
		t.Error("added thumbprint must report a change")
	}
	// Store-only drift with no certificate bound carries no host meaning.
	changed = base
	changed.CertificateStoreName = types.StringValue("WebHosting")
	if iisBindingInPlaceChanged(changed, base) {
		t.Error("store drift without a certificate must not report a change")
	}
	// Case-only thumbprint drift is the same certificate.
	changed = base
	changed.CertificateThumbprint = types.StringValue(strings.ToLower(strings.Repeat("C", 40)))
	prior := base
	prior.CertificateThumbprint = types.StringValue(strings.Repeat("C", 40))
	if iisBindingInPlaceChanged(changed, prior) {
		t.Error("case-only thumbprint drift must not report a change")
	}
}

// ---------------------------------------------------------------------------
// CRUD handlers
// ---------------------------------------------------------------------------

func TestWindowsIISBindingResource_Create_HappyPath(t *testing.T) {
	fc := &fakeIISBindingClient{createOut: okIISBindingState()}
	r := &windowsIISBindingResource{binding: fc}

	req := resource.CreateRequest{Plan: bindingPlan(t)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.SiteName != "web" || fc.createIn.Protocol != "https" || fc.createIn.Port != 443 {
		t.Errorf("create identity not forwarded, got %+v", fc.createIn)
	}
	if fc.createIn.HostHeader != "example.com" {
		t.Errorf("host must be lower-cased, got %q", fc.createIn.HostHeader)
	}
	var model windowsIISBindingModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "web|https|*:443:example.com" {
		t.Errorf("id = %q, want web|https|*:443:example.com", model.ID.ValueString())
	}
	if model.BindingInformation.ValueString() != "*:443:example.com" {
		t.Errorf("binding_information = %q", model.BindingInformation.ValueString())
	}
	if model.CertificateThumbprint.ValueString() != strings.Repeat("A", 40) {
		t.Errorf("thumbprint = %q", model.CertificateThumbprint.ValueString())
	}
}

func TestWindowsIISBindingResource_Create_TypedErrors(t *testing.T) {
	for _, tc := range []struct {
		kind winclient.IISBindingErrorKind
		want string
	}{
		{winclient.IISBindingErrorWouldLockOut, "would_lock_out"},
		{winclient.IISBindingErrorSiteNotFound, "site_not_found"},
		{winclient.IISBindingErrorConflict, "conflict"},
		{winclient.IISBindingErrorCertificateNoPrivateKey, "certificate_no_private_key"},
	} {
		fc := &fakeIISBindingClient{
			createErr: winclient.NewIISBindingError(tc.kind, "refused", nil, nil),
		}
		r := &windowsIISBindingResource{binding: fc}
		req := resource.CreateRequest{Plan: bindingPlan(t)}
		resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
		r.Create(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("kind %q must error", tc.kind)
			continue
		}
		joined := strings.Join(bindingDiagSummaries(resp.Diagnostics), "\n")
		if !strings.Contains(joined, tc.want) {
			t.Errorf("diagnostic must name kind %q, got:\n%s", tc.want, joined)
		}
	}
}

func TestWindowsIISBindingResource_Create_NilReadback(t *testing.T) {
	fc := &fakeIISBindingClient{createOut: nil}
	r := &windowsIISBindingResource{binding: fc}
	req := resource.CreateRequest{Plan: bindingPlan(t)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("nil readback must error")
	}
}

func TestWindowsIISBindingResource_Read_HappyPath(t *testing.T) {
	fc := &fakeIISBindingClient{readOut: okIISBindingState()}
	r := &windowsIISBindingResource{binding: fc}
	req := resource.ReadRequest{State: bindingState(t, nil)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	if fc.readSite != "web" || fc.readProto != "https" || fc.readBI != "*:443:example.com" {
		t.Errorf("read identity = (%q, %q, %q)", fc.readSite, fc.readProto, fc.readBI)
	}
	var model windowsIISBindingModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.BindingInformation.ValueString() != "*:443:example.com" {
		t.Errorf("binding_information = %q", model.BindingInformation.ValueString())
	}
	if model.ID.ValueString() != "web|https|*:443:example.com" {
		t.Errorf("id must be preserved, got %q", model.ID.ValueString())
	}
}

func TestWindowsIISBindingResource_Read_MissingRemovesResource(t *testing.T) {
	fc := &fakeIISBindingClient{readOut: nil}
	r := &windowsIISBindingResource{binding: fc}
	req := resource.ReadRequest{State: bindingState(t, nil)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background()), Raw: bindingObj(nil)}}
	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("missing binding must remove the resource from state")
	}
}

func TestWindowsIISBindingResource_Read_HTTPProjectsNullThumbprint(t *testing.T) {
	fc := &fakeIISBindingClient{readOut: okIISBindingHTTPState()}
	r := &windowsIISBindingResource{binding: fc}
	over := map[string]tftypes.Value{
		"id":                     tftypes.NewValue(tftypes.String, "web|http|*:80:"),
		"protocol":               tftypes.NewValue(tftypes.String, "http"),
		"port":                   tftypes.NewValue(tftypes.Number, 80),
		"host_header":            tftypes.NewValue(tftypes.String, ""),
		"require_sni":            tftypes.NewValue(tftypes.Bool, false),
		"certificate_thumbprint": bindingNullStr(),
		"binding_information":    bindingNullStr(),
	}
	req := resource.ReadRequest{State: bindingState(t, over)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	var model windowsIISBindingModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if !model.CertificateThumbprint.IsNull() {
		t.Errorf("http binding thumbprint must stay null, got %q", model.CertificateThumbprint.ValueString())
	}
	if model.CertificateStoreName.ValueString() != "My" {
		t.Errorf("empty observed store must fall back to My, got %q", model.CertificateStoreName.ValueString())
	}
}

func TestWindowsIISBindingResource_Update_OnlyChanged(t *testing.T) {
	fc := &fakeIISBindingClient{updateOut: okIISBindingState()}
	r := &windowsIISBindingResource{binding: fc}
	prior := bindingState(t, map[string]tftypes.Value{
		"require_sni": tftypes.NewValue(tftypes.Bool, false),
	})
	plan := bindingPlan(t) // require_sni true
	req := resource.UpdateRequest{Plan: plan, State: prior}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	if fc.updateIn.RequireSNI == nil || !*fc.updateIn.RequireSNI {
		t.Errorf("update must forward the flipped require_sni, got %+v", fc.updateIn.RequireSNI)
	}
	if fc.updateIn.HostHeader != "example.com" {
		t.Errorf("update keeps the identity host, got %q", fc.updateIn.HostHeader)
	}
	var model windowsIISBindingModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "web|https|*:443:example.com" {
		t.Errorf("id must be preserved across update, got %q", model.ID.ValueString())
	}
}

func TestWindowsIISBindingResource_Update_NoChangesRefreshes(t *testing.T) {
	fc := &fakeIISBindingClient{readOut: okIISBindingState()}
	r := &windowsIISBindingResource{binding: fc}
	st := bindingState(t, nil)
	req := resource.UpdateRequest{Plan: bindingPlan(t), State: st}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	if fc.readSite != "web" {
		t.Errorf("no-op update must refresh via Read, got site %q", fc.readSite)
	}
	if fc.updateOut != nil {
		t.Error("no-op update must not call Update")
	}
}

func TestWindowsIISBindingResource_Delete_HappyPath(t *testing.T) {
	fc := &fakeIISBindingClient{}
	r := &windowsIISBindingResource{binding: fc}
	req := resource.DeleteRequest{State: bindingState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	if fc.deleteSite != "web" || fc.deleteProto != "https" || fc.deleteBI != "*:443:example.com" {
		t.Errorf("delete identity = (%q, %q, %q)", fc.deleteSite, fc.deleteProto, fc.deleteBI)
	}
}

func TestWindowsIISBindingResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakeIISBindingClient{readOut: okIISBindingState()}
	r := &windowsIISBindingResource{binding: fc}
	req := resource.ImportStateRequest{ID: "web|https|*:443:example.com"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", bindingDiagSummaries(resp.Diagnostics))
	}
	if fc.readSite != "web" || fc.readProto != "https" || fc.readBI != "*:443:example.com" {
		t.Errorf("import read identity = (%q, %q, %q)", fc.readSite, fc.readProto, fc.readBI)
	}
	var model windowsIISBindingModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "web|https|*:443:example.com" {
		t.Errorf("import id = %q", model.ID.ValueString())
	}
	if model.SiteName.ValueString() != "web" || model.Port.ValueInt64() != 443 {
		t.Errorf("import must project identity, got %+v", model)
	}
}

func TestWindowsIISBindingResource_ImportState_Invalid(t *testing.T) {
	fc := &fakeIISBindingClient{}
	r := &windowsIISBindingResource{binding: fc}
	for _, bad := range []string{"", "web", "web|https", "web|ftp|*:21:x"} {
		req := resource.ImportStateRequest{ID: bad}
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISBindingSchemaDefinition(context.Background())}}
		r.ImportState(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("import ID %q must fail", bad)
		}
	}
}
