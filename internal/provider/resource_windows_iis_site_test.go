// Package provider — unit tests for the windows_iis_site resource.
//
// These tests exercise the schema, validators, plan modifier, settings
// projection and CRUD handlers without SSH. A fakeIISSiteClient is
// injected into windowsIISSiteResource.site.
//
// Edge cases covered (issue #284):
//
//	Metadata                 — returns "windows_iis_site"
//	Schema                   — name Required/ForceNew/length, site_id
//	                           Optional+Computed/ForceNew/range,
//	                           physical_path Required,
//	                           all other settings Optional+Computed,
//	                           bindings Computed-only (UseStateForUnknown),
//	                           state Optional+Computed + suppression
//	                           modifier, timeouts block
//	Name validator           — forbidden chars + padding rejected,
//	                           null/unknown skip
//	State modifier           — Started + empty bindings plans Stopped;
//	                           Started + bindings, Stopped, null, unknown
//	                           and null/unknown bindings pass through
//	Settings projection      — only configured attrs sent, unknown
//	                           skipped (never sent)
//	Delta                    — only changed configured attrs sent,
//	                           site_id stripped (ForceNew)
//	Create (happy)           — timeouts kept, id = name
//	Create (Started, no       — warning diagnostic, host state kept
//	bindings)
//	Create (already_exists / — diagnostics, import hint
//	id_conflict / app_pool_not_found / path_not_found)
//	Read (happy/missing)     — missing removes from state, timeouts kept
//	Update (happy)           — delta forwarded; no-op refreshes via Read
//	Delete (happy)           — host called with the site name
//	ImportState (happy)      — id = name, site_id managed
//	ImportState (invalid)    — diagnostic error
package provider

import (
	"context"
	"strings"
	"testing"
	"time"

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
// fakeIISSiteClient
// ---------------------------------------------------------------------------

type fakeIISSiteClient struct {
	createIn  winclient.IISSiteInput
	createOut *winclient.IISSiteState
	createErr error

	readName string
	readOut  *winclient.IISSiteState
	readErr  error

	updateIn  winclient.IISSiteInput
	updateOut *winclient.IISSiteState
	updateErr error

	deleteName string
	deleteErr  error
}

func (f *fakeIISSiteClient) Create(_ context.Context, in winclient.IISSiteInput) (*winclient.IISSiteState, error) {
	f.createIn = in
	return f.createOut, f.createErr
}

func (f *fakeIISSiteClient) Read(_ context.Context, name string) (*winclient.IISSiteState, error) {
	f.readName = name
	return f.readOut, f.readErr
}

func (f *fakeIISSiteClient) Update(_ context.Context, in winclient.IISSiteInput) (*winclient.IISSiteState, error) {
	f.updateIn = in
	return f.updateOut, f.updateErr
}

func (f *fakeIISSiteClient) Delete(_ context.Context, name string) error {
	f.deleteName = name
	return f.deleteErr
}

func okIISSiteState() *winclient.IISSiteState {
	return &winclient.IISSiteState{
		Name: "web", SiteID: 2, PhysicalPath: `C:\inetpub\wwwroot`,
		ApplicationPool: "DefaultAppPool", AutoStart: true,
		PreloadEnabled: false, EnabledProtocols: "http",
		LogEnabled: true, LogDirectory: `%SystemDrive%\inetpub\logs\LogFiles`,
		LogFormat: "W3C", ConnectionTimeoutSeconds: 120, MaxConnections: 0,
		Bindings: []winclient.IISSiteBinding{}, State: "Stopped",
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_iis_site schema
// ---------------------------------------------------------------------------

func siteBindingObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"protocol":            tftypes.String,
		"binding_information": tftypes.String,
	}}
}

func siteBindingsListType() tftypes.List {
	return tftypes.List{ElementType: siteBindingObjType()}
}

func siteObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                         tftypes.String,
		"name":                       tftypes.String,
		"site_id":                    tftypes.Number,
		"physical_path":              tftypes.String,
		"application_pool":           tftypes.String,
		"auto_start":                 tftypes.Bool,
		"preload_enabled":            tftypes.Bool,
		"enabled_protocols":          tftypes.String,
		"log_enabled":                tftypes.Bool,
		"log_directory":              tftypes.String,
		"log_format":                 tftypes.String,
		"connection_timeout_seconds": tftypes.Number,
		"max_connections":            tftypes.Number,
		"bindings":                   siteBindingsListType(),
		"state":                      tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func siteNullStr() tftypes.Value  { return tftypes.NewValue(tftypes.String, nil) }
func siteNullBool() tftypes.Value { return tftypes.NewValue(tftypes.Bool, nil) }
func siteNullNum() tftypes.Value  { return tftypes.NewValue(tftypes.Number, nil) }

func siteNullTimeouts() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func siteNullBindings() tftypes.Value {
	return tftypes.NewValue(siteBindingsListType(), nil)
}

func siteObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                         tftypes.NewValue(tftypes.String, "web"),
		"name":                       tftypes.NewValue(tftypes.String, "web"),
		"site_id":                    siteNullNum(),
		"physical_path":              tftypes.NewValue(tftypes.String, `C:\inetpub\wwwroot`),
		"application_pool":           siteNullStr(),
		"auto_start":                 siteNullBool(),
		"preload_enabled":            siteNullBool(),
		"enabled_protocols":          siteNullStr(),
		"log_enabled":                siteNullBool(),
		"log_directory":              siteNullStr(),
		"log_format":                 siteNullStr(),
		"connection_timeout_seconds": siteNullNum(),
		"max_connections":            siteNullNum(),
		"bindings":                   siteNullBindings(),
		"state":                      siteNullStr(),
		"timeouts":                   siteNullTimeouts(),
	}
}

func siteObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := siteObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(siteObjType(), base)
}

func siteState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsIISSiteSchemaDefinition(context.Background())
	return tfsdk.State{Raw: siteObj(overrides), Schema: s}
}

func sitePlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsIISSiteSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: siteObj(overrides), Schema: s}
}

func siteDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsIISSiteResource_Metadata(t *testing.T) {
	r := &windowsIISSiteResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_iis_site" {
		t.Errorf("TypeName = %q, want windows_iis_site", resp.TypeName)
	}
}

func TestWindowsIISSiteResource_Schema(t *testing.T) {
	s := windowsIISSiteSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "name", "site_id", "physical_path", "application_pool",
		"auto_start", "preload_enabled", "enabled_protocols",
		"log_enabled", "log_directory", "log_format",
		"connection_timeout_seconds", "max_connections",
		"bindings", "state", "timeouts",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	// name is Required + ForceNew.
	nameAttr, ok := s.Attributes["name"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", nameAttr)
	}
	if !nameAttr.Required {
		t.Error("name must be Required")
	}
	if len(nameAttr.PlanModifiers) == 0 {
		t.Error("name must be ForceNew (RequiresReplace)")
	}
	// site_id is Optional+Computed + ForceNew.
	siteIDAttr, ok := s.Attributes["site_id"].(schema.Int64Attribute)
	if !ok {
		t.Fatalf("site_id: expected schema.Int64Attribute, got %T", siteIDAttr)
	}
	if !siteIDAttr.Optional || !siteIDAttr.Computed {
		t.Error("site_id must be Optional+Computed")
	}
	if len(siteIDAttr.PlanModifiers) == 0 {
		t.Error("site_id must be ForceNew (RequiresReplace)")
	}
	if len(siteIDAttr.Validators) == 0 {
		t.Error("site_id must carry a range validator (1-4294967295)")
	}
	// physical_path is Required (in place).
	pathAttr, ok := s.Attributes["physical_path"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("physical_path: expected schema.StringAttribute, got %T", pathAttr)
	}
	if !pathAttr.Required {
		t.Error("physical_path must be Required")
	}
	// Every other setting is Optional+Computed: only configured attrs are sent.
	for _, n := range []string{"application_pool", "auto_start", "preload_enabled",
		"enabled_protocols", "log_enabled", "log_directory", "log_format",
		"connection_timeout_seconds", "max_connections", "state"} {
		a := s.Attributes[n]
		if !isOptionalComputedAttr(a) {
			t.Errorf("%s must be Optional+Computed (partial management)", n)
		}
	}
	// bindings is Computed-only: never declarative.
	bindingsAttr, ok := s.Attributes["bindings"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("bindings: expected schema.ListNestedAttribute, got %T", bindingsAttr)
	}
	if !bindingsAttr.Computed || bindingsAttr.Optional || bindingsAttr.Required {
		t.Error("bindings must be Computed-only (owned by windows_iis_binding)")
	}
	idAttr, ok := s.Attributes["id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", idAttr)
	}
	if !idAttr.Computed || idAttr.Optional || idAttr.Required {
		t.Error("id must be computed only")
	}
}

func TestWindowsIISSiteResource_SchemaEnumValidators(t *testing.T) {
	s := windowsIISSiteSchemaDefinition(context.Background())
	for name, valid := range map[string][]string{
		"log_format": {"W3C", "IIS", "NCSA"},
		"state":      {"Started", "Stopped"},
	} {
		a, ok := s.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected schema.StringAttribute, got %T", name, a)
		}
		if len(a.Validators) == 0 {
			t.Fatalf("%s must carry a OneOf validator", name)
		}
		for _, v := range valid {
			resp := &validator.StringResponse{}
			a.Validators[0].ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root(name), ConfigValue: types.StringValue(v),
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Errorf("%s %q should pass, got %v", name, v, resp.Diagnostics)
			}
		}
		for _, v := range []string{"nope", "running"} {
			resp := &validator.StringResponse{}
			a.Validators[0].ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root(name), ConfigValue: types.StringValue(v),
			}, resp)
			if !resp.Diagnostics.HasError() {
				t.Errorf("%s %q should be rejected", name, v)
			}
		}
	}
	for name, valid := range map[string][]int64{
		"connection_timeout_seconds": {0, 120, 3600},
		"max_connections":            {0, 100, 1000000},
	} {
		a, ok := s.Attributes[name].(schema.Int64Attribute)
		if !ok {
			t.Fatalf("%s: expected schema.Int64Attribute, got %T", name, a)
		}
		if len(a.Validators) == 0 {
			t.Fatalf("%s must carry a range validator", name)
		}
		for _, v := range valid {
			resp := &validator.Int64Response{}
			a.Validators[0].ValidateInt64(context.Background(), validator.Int64Request{
				Path: path.Root(name), ConfigValue: types.Int64Value(v),
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Errorf("%s %d should pass, got %v", name, v, resp.Diagnostics)
			}
		}
		resp := &validator.Int64Response{}
		a.Validators[0].ValidateInt64(context.Background(), validator.Int64Request{
			Path: path.Root(name), ConfigValue: types.Int64Value(-1),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("%s -1 should be rejected", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestIISSiteNameValidator(t *testing.T) {
	v := iisSiteNameValidator{}
	for _, p := range []string{"web", "Default Web Site", "a", "site-1_name.test"} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("name"), ConfigValue: types.StringValue(p),
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("name %q should pass, got %v", p, resp.Diagnostics)
		}
	}
	for _, p := range []string{" leading", "trailing ", "a/b", `a\b`, "a[b", "a:b", "a,b", "a?b", "a*b", `a"b`, "a<b", "a|b"} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("name"), ConfigValue: types.StringValue(p),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("name %q should be rejected", p)
		}
	}
	for _, cv := range []types.String{types.StringNull(), types.StringUnknown()} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("name"), ConfigValue: cv,
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("null/unknown should skip validation, got %v", resp.Diagnostics)
		}
	}
}

// ---------------------------------------------------------------------------
// State suppression plan modifier
// ---------------------------------------------------------------------------

func siteBindingsList(t *testing.T, entries ...map[string]string) tftypes.Value {
	t.Helper()
	elem := siteBindingObjType()
	if len(entries) == 0 {
		return tftypes.NewValue(siteBindingsListType(), []tftypes.Value{})
	}
	vals := make([]tftypes.Value, 0, len(entries))
	for _, e := range entries {
		vals = append(vals, tftypes.NewValue(elem, map[string]tftypes.Value{
			"protocol":            tftypes.NewValue(tftypes.String, e["protocol"]),
			"binding_information": tftypes.NewValue(tftypes.String, e["binding_information"]),
		}))
	}
	return tftypes.NewValue(siteBindingsListType(), vals)
}

func TestIISSiteStateSuppressUnboundModifier(t *testing.T) {
	s := windowsIISSiteSchemaDefinition(context.Background())
	stateAttr, ok := s.Attributes["state"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("state: expected schema.StringAttribute, got %T", stateAttr)
	}
	if len(stateAttr.PlanModifiers) == 0 {
		t.Fatal("state must carry the unbound-suppression plan modifier")
	}
	mod := stateAttr.PlanModifiers[0]
	ctx := context.Background()

	run := func(state string, bindings tftypes.Value) types.String {
		plan := tfsdk.Plan{Raw: siteObj(map[string]tftypes.Value{
			"state":    tftypes.NewValue(tftypes.String, state),
			"bindings": bindings,
		}), Schema: s}
		var planState types.String
		if d := plan.GetAttribute(ctx, path.Root("state"), &planState); d.HasError() {
			t.Fatalf("GetAttribute: %v", d)
		}
		resp := &planmodifier.StringResponse{PlanValue: planState}
		mod.PlanModifyString(ctx, planmodifier.StringRequest{
			Path:      path.Root("state"),
			Plan:      plan,
			PlanValue: planState,
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("modifier diagnostics: %v", resp.Diagnostics)
		}
		return resp.PlanValue
	}

	// Exercise through the plan: build plans and read back the modifier
	// result via PlanModifyString with a real response value.
	cases := []struct {
		name     string
		state    string
		bindings tftypes.Value
		want     string
	}{
		{"started unbound suppresses", "Started", siteBindingsList(t), "Stopped"},
		{"started bound stays", "Started", siteBindingsList(t, map[string]string{"protocol": "http", "binding_information": "*:80:web"}), "Started"},
		{"stopped unbound stays", "Stopped", siteBindingsList(t), "Stopped"},
		{"stopped bound stays", "Stopped", siteBindingsList(t, map[string]string{"protocol": "http", "binding_information": "*:80:web"}), "Stopped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.state, tc.bindings); got.ValueString() != tc.want {
				t.Errorf("modifier result = %q, want %q", got.ValueString(), tc.want)
			}
		})
	}

	// Null, unknown and unknown-bindings plans pass through untouched.
	for _, tc := range []struct {
		name     string
		state    tftypes.Value
		bindings tftypes.Value
	}{
		{"null state", siteNullStr(), siteBindingsList(t)},
		{"unknown state", tftypes.NewValue(tftypes.String, tftypes.UnknownValue), siteBindingsList(t)},
		{"unknown bindings", tftypes.NewValue(tftypes.String, "Started"), tftypes.NewValue(siteBindingsListType(), tftypes.UnknownValue)},
		{"null bindings", tftypes.NewValue(tftypes.String, "Started"), siteNullBindings()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := tfsdk.Plan{Raw: siteObj(map[string]tftypes.Value{
				"state":    tc.state,
				"bindings": tc.bindings,
			}), Schema: s}
			var planState types.String
			if d := plan.GetAttribute(ctx, path.Root("state"), &planState); d.HasError() {
				t.Fatalf("GetAttribute: %v", d)
			}
			resp := &planmodifier.StringResponse{PlanValue: planState}
			mod.PlanModifyString(ctx, planmodifier.StringRequest{
				Path:      path.Root("state"),
				Plan:      plan,
				PlanValue: planState,
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("modifier diagnostics: %v", resp.Diagnostics)
			}
			if !resp.PlanValue.Equal(planState) {
				t.Errorf("modifier must pass through, got %v want %v", resp.PlanValue, planState)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Settings projection: only configured attrs sent
// ---------------------------------------------------------------------------

func TestModelToIISSiteSettings_OnlyConfigured(t *testing.T) {
	ctx := context.Background()
	var m windowsIISSiteModel
	if diags := sitePlan(t, map[string]tftypes.Value{
		"physical_path": tftypes.NewValue(tftypes.String, `C:\inetpub\wwwroot`),
	}).Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	s := modelToIISSiteSettings(m)
	if s.PhysicalPath == nil || *s.PhysicalPath != `C:\inetpub\wwwroot` {
		t.Error("physical_path must be forwarded")
	}
	if s.ApplicationPool != nil || s.AutoStart != nil || s.State != nil {
		t.Error("null attributes must stay nil (never sent)")
	}
	if s.SiteID != nil {
		t.Error("null site_id must stay nil (IIS allocates the lowest free ID)")
	}
	if s.IISSiteConfigured() != true {
		t.Error("configured physical_path must count as configured")
	}
}

func TestModelToIISSiteSettings_UnknownDefers(t *testing.T) {
	m := windowsIISSiteModel{
		PhysicalPath:    types.StringValue(`C:\inetpub\wwwroot`),
		AutoStart:       types.BoolUnknown(),
		ApplicationPool: types.StringUnknown(),
		SiteID:          types.Int64Unknown(),
	}
	s := modelToIISSiteSettings(m)
	if s.AutoStart != nil || s.ApplicationPool != nil || s.SiteID != nil {
		t.Error("unknown attributes must stay nil (never sent)")
	}
	if s.PhysicalPath == nil {
		t.Error("known physical_path must be forwarded")
	}
}

func TestIISSiteConfigured_Empty(t *testing.T) {
	if (winclient.IISSiteSettings{}).IISSiteConfigured() {
		t.Error("empty settings must not count as configured")
	}
}

// ---------------------------------------------------------------------------
// Delta: only changed configured attrs sent, site_id stripped
// ---------------------------------------------------------------------------

func TestPlanToIISSiteDelta_OnlyChanged(t *testing.T) {
	ctx := context.Background()
	var prior windowsIISSiteModel
	if diags := sitePlan(t, map[string]tftypes.Value{
		"physical_path":    tftypes.NewValue(tftypes.String, `C:\inetpub\wwwroot`),
		"application_pool": tftypes.NewValue(tftypes.String, "pool1"),
		"site_id":          tftypes.NewValue(tftypes.Number, 2),
	}).Get(ctx, &prior); diags.HasError() {
		t.Fatalf("prior.Get: %v", diags)
	}
	var plan windowsIISSiteModel
	if diags := sitePlan(t, map[string]tftypes.Value{
		"physical_path":    tftypes.NewValue(tftypes.String, `C:\inetpub\wwwroot`),
		"application_pool": tftypes.NewValue(tftypes.String, "pool2"),
		"site_id":          tftypes.NewValue(tftypes.Number, 2),
	}).Get(ctx, &plan); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	s := planToIISSiteDelta(plan, prior)
	if s.ApplicationPool == nil || *s.ApplicationPool != "pool2" {
		t.Errorf("changed attribute must be forwarded, got %+v", s)
	}
	if s.PhysicalPath != nil {
		t.Errorf("unchanged attribute must not be re-sent, got %+v", s)
	}
	if s.SiteID != nil {
		t.Errorf("site_id must never be re-sent on update (ForceNew), got %+v", s)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsIISSiteResource_Create_HappyPath(t *testing.T) {
	fc := &fakeIISSiteClient{createOut: okIISSiteState()}
	r := &windowsIISSiteResource{site: fc}

	req := resource.CreateRequest{Plan: sitePlan(t, map[string]tftypes.Value{
		"application_pool": tftypes.NewValue(tftypes.String, "pool2"),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", siteDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.Name != "web" {
		t.Errorf("create name = %q, want web", fc.createIn.Name)
	}
	if fc.createIn.Settings.ApplicationPool == nil || *fc.createIn.Settings.ApplicationPool != "pool2" {
		t.Errorf("create must forward configured attrs, got %+v", fc.createIn.Settings)
	}
	if fc.createIn.Settings.AutoStart != nil {
		t.Errorf("create must not send unconfigured attrs, got %+v", fc.createIn.Settings)
	}
	var model windowsIISSiteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "web" {
		t.Errorf("id = %q, want web (site name)", model.ID.ValueString())
	}
	if model.SiteID.ValueInt64() != 2 {
		t.Errorf("site_id = %v, want observed 2", model.SiteID)
	}
}

func TestWindowsIISSiteResource_Create_StartedWithoutBindingsWarns(t *testing.T) {
	st := okIISSiteState() // State Stopped, no bindings.
	fc := &fakeIISSiteClient{createOut: st}
	r := &windowsIISSiteResource{site: fc}

	req := resource.CreateRequest{Plan: sitePlan(t, map[string]tftypes.Value{
		"state": tftypes.NewValue(tftypes.String, "Started"),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("warning must not be an error, got %v", siteDiagSummaries(resp.Diagnostics))
	}
	if len(resp.Diagnostics.Warnings()) == 0 {
		t.Fatal("expected a warning when Started cannot be enforced without bindings")
	}
	joined := strings.Join(siteDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "no bindings") {
		t.Errorf("warning must explain the unbound site, got:\n%s", joined)
	}
	var model windowsIISSiteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.State.ValueString() != "Stopped" {
		t.Errorf("state = %q, want observed Stopped", model.State.ValueString())
	}
}

func TestWindowsIISSiteResource_Create_AlreadyExists(t *testing.T) {
	fc := &fakeIISSiteClient{
		createErr: winclient.NewIISSiteError(winclient.IISSiteErrorAlreadyExists,
			"IIS site 'web' already exists on this host (use 'terraform import' to bring it under management).", nil, nil),
	}
	r := &windowsIISSiteResource{site: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: sitePlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an already_exists diagnostic")
	}
	joined := strings.Join(siteDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "already_exists") || !strings.Contains(joined, "terraform import") {
		t.Errorf("diagnostic must name the kind and hint at import, got:\n%s", joined)
	}
}

func TestWindowsIISSiteResource_Create_TypedErrors(t *testing.T) {
	for kind, summary := range map[winclient.IISSiteErrorKind]string{
		winclient.IISSiteErrorIDConflict:      "id_conflict",
		winclient.IISSiteErrorAppPoolNotFound: "app_pool_not_found",
		winclient.IISSiteErrorPathNotFound:    "path_not_found",
	} {
		t.Run(summary, func(t *testing.T) {
			fc := &fakeIISSiteClient{
				createErr: winclient.NewIISSiteError(kind, "boom "+summary, nil, nil),
			}
			r := &windowsIISSiteResource{site: fc}
			resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
			r.Create(context.Background(), resource.CreateRequest{Plan: sitePlan(t, nil)}, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatal("expected a diagnostic")
			}
			joined := strings.Join(siteDiagSummaries(resp.Diagnostics), "\n")
			if !strings.Contains(joined, summary) {
				t.Errorf("diagnostic must name the kind %q, got:\n%s", summary, joined)
			}
		})
	}
}

func TestWindowsIISSiteResource_Create_NilReadback(t *testing.T) {
	fc := &fakeIISSiteClient{createOut: nil, createErr: nil}
	r := &windowsIISSiteResource{site: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: sitePlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("nil readback after create must produce an error diagnostic")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsIISSiteResource_Read_HappyPath(t *testing.T) {
	fc := &fakeIISSiteClient{readOut: okIISSiteState()}
	r := &windowsIISSiteResource{site: fc}

	req := resource.ReadRequest{State: siteState(t, nil)}
	resp := &resource.ReadResponse{State: siteState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", siteDiagSummaries(resp.Diagnostics))
	}
	if fc.readName != "web" {
		t.Errorf("read name = %q, want web", fc.readName)
	}
	var model windowsIISSiteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.PhysicalPath.ValueString() != `C:\inetpub\wwwroot` || model.SiteID.ValueInt64() != 2 {
		t.Errorf("unexpected state: %+v", model)
	}
}

func TestWindowsIISSiteResource_Read_MissingRemovesResource(t *testing.T) {
	fc := &fakeIISSiteClient{readOut: nil}
	r := &windowsIISSiteResource{site: fc}

	req := resource.ReadRequest{State: siteState(t, nil)}
	resp := &resource.ReadResponse{State: siteState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing site must remove from state without error, got %v", siteDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("missing site must remove the resource from state")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestWindowsIISSiteResource_Update_OnlyChanged(t *testing.T) {
	st := okIISSiteState()
	st.ApplicationPool = "pool2"
	fc := &fakeIISSiteClient{updateOut: st}
	r := &windowsIISSiteResource{site: fc}

	req := resource.UpdateRequest{
		Plan: sitePlan(t, map[string]tftypes.Value{
			"physical_path":    tftypes.NewValue(tftypes.String, `C:\inetpub\wwwroot`),
			"application_pool": tftypes.NewValue(tftypes.String, "pool2"),
		}),
		State: siteState(t, map[string]tftypes.Value{
			"physical_path":    tftypes.NewValue(tftypes.String, `C:\inetpub\wwwroot`),
			"application_pool": tftypes.NewValue(tftypes.String, "pool1"),
		}),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", siteDiagSummaries(resp.Diagnostics))
	}
	if fc.updateIn.Settings.ApplicationPool == nil || *fc.updateIn.Settings.ApplicationPool != "pool2" {
		t.Errorf("update must forward the changed attr, got %+v", fc.updateIn.Settings)
	}
	if fc.updateIn.Settings.PhysicalPath != nil {
		t.Errorf("update must not re-send unchanged attrs, got %+v", fc.updateIn.Settings)
	}
}

func TestWindowsIISSiteResource_Update_NilReadback(t *testing.T) {
	fc := &fakeIISSiteClient{updateOut: nil, updateErr: nil}
	r := &windowsIISSiteResource{site: fc}

	req := resource.UpdateRequest{
		Plan: sitePlan(t, map[string]tftypes.Value{
			"application_pool": tftypes.NewValue(tftypes.String, "pool2"),
		}),
		State: siteState(t, map[string]tftypes.Value{
			"application_pool": tftypes.NewValue(tftypes.String, "pool1"),
		}),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("nil readback after update must produce an error diagnostic")
	}
}

func TestWindowsIISSiteResource_Update_NoChangesRefreshes(t *testing.T) {
	st := okIISSiteState()
	fc := &fakeIISSiteClient{updateOut: st, readOut: st}
	r := &windowsIISSiteResource{site: fc}

	same := map[string]tftypes.Value{
		"physical_path": tftypes.NewValue(tftypes.String, `C:\inetpub\wwwroot`),
	}
	req := resource.UpdateRequest{
		Plan:  sitePlan(t, same),
		State: siteState(t, same),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", siteDiagSummaries(resp.Diagnostics))
	}
	if fc.updateIn.Name != "" {
		t.Errorf("no changes must refresh via Read, not Update (update got %+v)", fc.updateIn)
	}
	if fc.readName != "web" {
		t.Errorf("expected a refresh Read, got readName=%q", fc.readName)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestWindowsIISSiteResource_Delete_HappyPath(t *testing.T) {
	fc := &fakeIISSiteClient{}
	r := &windowsIISSiteResource{site: fc}

	req := resource.DeleteRequest{State: siteState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", siteDiagSummaries(resp.Diagnostics))
	}
	if fc.deleteName != "web" {
		t.Errorf("delete name = %q, want web", fc.deleteName)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsIISSiteResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakeIISSiteClient{readOut: okIISSiteState()}
	r := &windowsIISSiteResource{site: fc}

	req := resource.ImportStateRequest{ID: "web"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", siteDiagSummaries(resp.Diagnostics))
	}
	var model windowsIISSiteModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Name.ValueString() != "web" || model.ID.ValueString() != "web" {
		t.Errorf("unexpected imported state: name=%q id=%q", model.Name.ValueString(), model.ID.ValueString())
	}
	if model.SiteID.ValueInt64() != 2 {
		t.Errorf("imported site_id = %v, want observed 2", model.SiteID)
	}
}

func TestWindowsIISSiteResource_ImportState_InvalidID(t *testing.T) {
	for _, id := range []string{"", "a/b", "a*b"} {
		r := &windowsIISSiteResource{site: &fakeIISSiteClient{readOut: okIISSiteState()}}
		req := resource.ImportStateRequest{ID: id}
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
		r.ImportState(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("expected diagnostic error for import ID %q", id)
		}
	}
	// Leading/trailing spaces trim to a valid name and are accepted.
	r := &windowsIISSiteResource{site: &fakeIISSiteClient{readOut: okIISSiteState()}}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: " web "}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("import ID %q trims to a valid name and should be accepted: %v", " web ", siteDiagSummaries(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// Timeouts / Configure
// ---------------------------------------------------------------------------

func TestWindowsIISSiteSchema_HasTimeoutsBlock(t *testing.T) {
	s := windowsIISSiteSchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block: CRUD must be time-bounded")
	}
}

// hangIISSiteClient simulates a stalled transport: Create blocks until
// the passed context is done, then returns the context error.
type hangIISSiteClient struct {
	fakeIISSiteClient
}

func (f *hangIISSiteClient) Create(ctx context.Context, _ winclient.IISSiteInput) (*winclient.IISSiteState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// siteTimeoutsRaw builds the raw tftypes value for a timeouts block
// carrying the given per-operation durations.
func siteTimeoutsRaw(durations map[string]string) tftypes.Value {
	vals := map[string]tftypes.Value{
		"create": tftypes.NewValue(tftypes.String, nil),
		"read":   tftypes.NewValue(tftypes.String, nil),
		"update": tftypes.NewValue(tftypes.String, nil),
		"delete": tftypes.NewValue(tftypes.String, nil),
	}
	for op, d := range durations {
		vals[op] = tftypes.NewValue(tftypes.String, d)
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, vals)
}

func TestWindowsIISSiteResource_Create_StalledTransportIsBounded(t *testing.T) {
	r := &windowsIISSiteResource{site: &hangIISSiteClient{}}

	req := resource.CreateRequest{
		Plan: sitePlan(t, map[string]tftypes.Value{
			"timeouts": siteTimeoutsRaw(map[string]string{"create": "200ms"}),
		}),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}

	start := time.Now()
	r.Create(context.Background(), req, resp)
	elapsed := time.Since(start)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag when the transport stalls past the create timeout")
	}
	if elapsed > 30*time.Second {
		t.Errorf("Create blocked for %v with a 200ms timeout", elapsed)
	}
}

func TestWindowsIISSiteResource_Configure(t *testing.T) {
	r := &windowsIISSiteResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}

	resp = &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}

	resp = &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

func TestIISSiteErrorDiag_TypedKinds(t *testing.T) {
	for kind, msg := range map[winclient.IISSiteErrorKind]string{
		winclient.IISSiteErrorIDConflict:      "site1",
		winclient.IISSiteErrorAppPoolNotFound: "pool1",
		winclient.IISSiteErrorPathNotFound:    `C:\gone`,
	} {
		var diags diag.Diagnostics
		addIISSiteDiag(&diags, "Error creating Windows IIS site",
			winclient.NewIISSiteError(kind, msg, nil, nil))
		if !diags.HasError() {
			t.Fatalf("expected an error diagnostic for %q", kind)
		}
		joined := strings.Join(siteDiagSummaries(diags), "\n")
		if !strings.Contains(joined, string(kind)) || !strings.Contains(joined, msg) {
			t.Errorf("diag must keep kind + guidance, got:\n%s", joined)
		}
	}
}

// ---------------------------------------------------------------------------
// Partial state on failure (ADR-0012): a (state, error) return persists the
// observed state before the error diagnostic (tainted); a nil state stays
// error-only.
// ---------------------------------------------------------------------------

func TestWindowsIISSiteResource_Create_PartialStateOnError(t *testing.T) {
	fc := &fakeIISSiteClient{
		createOut: okIISSiteState(),
		createErr: winclient.NewIISSiteError(winclient.IISSiteErrorUnknown, "reconcile failed", nil, nil),
	}
	r := &windowsIISSiteResource{site: fc}

	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISSiteSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: sitePlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag from reconcile failure")
	}
	var model windowsIISSiteModel
	if d := resp.State.Get(context.Background(), &model); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if model.ID.ValueString() != "web" {
		t.Errorf("partial state must be persisted (tainted), got id=%q", model.ID.ValueString())
	}
	if model.SiteID.ValueInt64() != 2 {
		t.Errorf("partial state must carry the observed site_id, got %v", model.SiteID)
	}
}

func TestWindowsIISSiteResource_Create_NilStateOnError_StaysStateless(t *testing.T) {
	fc := &fakeIISSiteClient{
		createErr: winclient.NewIISSiteError(winclient.IISSiteErrorAlreadyExists,
			"IIS site 'web' already exists on this host (use 'terraform import' to bring it under management).", nil, nil),
	}
	r := &windowsIISSiteResource{site: fc}

	schemaDef := windowsIISSiteSchemaDefinition(context.Background())
	resp := &resource.CreateResponse{State: tfsdk.State{
		Schema: schemaDef,
		Raw:    tftypes.NewValue(siteObjType(), nil),
	}}
	r.Create(context.Background(), resource.CreateRequest{Plan: sitePlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag from already_exists")
	}
	// The handler never touches state on a nil-state error: the raw value
	// is still the null object it was seeded with (State.Get cannot decode
	// a null object into the model struct, so assert on Raw directly).
	if !resp.State.Raw.IsNull() {
		t.Errorf("nil-state error must stay stateless, got raw=%v", resp.State.Raw)
	}
}

func TestWindowsIISSiteResource_Update_PartialStateOnError(t *testing.T) {
	observed := okIISSiteState()
	observed.ApplicationPool = "pool2"
	fc := &fakeIISSiteClient{
		updateOut: observed,
		updateErr: winclient.NewIISSiteError(winclient.IISSiteErrorUnknown, "reconcile failed", nil, nil),
	}
	r := &windowsIISSiteResource{site: fc}

	schemaDef := windowsIISSiteSchemaDefinition(context.Background())
	prior := siteState(t, nil)
	plan := sitePlan(t, map[string]tftypes.Value{
		"application_pool": tftypes.NewValue(tftypes.String, "pool2"),
	})
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw}}

	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag from reconcile failure")
	}
	var model windowsIISSiteModel
	if d := resp.State.Get(context.Background(), &model); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if model.ID.ValueString() != "web" {
		t.Errorf("partial state must be persisted on update failure, got id=%q", model.ID.ValueString())
	}
	if model.ApplicationPool.ValueString() != "pool2" {
		t.Errorf("partial state must carry the observed application_pool, got %q", model.ApplicationPool.ValueString())
	}
}
