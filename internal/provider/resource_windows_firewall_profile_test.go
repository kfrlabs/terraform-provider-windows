// Package provider — unit tests for the windows_firewall_profile resource.
//
// These tests exercise the schema, validators, settings projection and
// CRUD handlers without SSH. A fakeFirewallProfileClient is injected into
// windowsFirewallProfileResource.fp.
//
// Edge cases covered (issue #223):
//
//	Metadata                 — returns "windows_firewall_profile"
//	Schema                   — name Required/ForceNew/OneOf, all others
//	                           Optional+Computed, restore_on_destroy default,
//	                           timeouts block
//	Name validator           — OneOf Domain/Private/Public at plan time
//	Log path validator       — absolute, UNC, %systemroot% (+case), reject
//	                           relative, null/unknown skip
//	Enabled validator        — false warns, true/null clean
//	Settings projection      — only configured attrs sent, empty-vs-null
//	                           alias set, unknown defers, alias dedup
//	Create (happy)           — snapshot captured when restore_on_destroy,
//	                           skipped otherwise; Apply only configured
//	Create (would_lock_out)  — diagnostic, nothing half-written
//	Read (happy)             — tri-state NotConfigured -> null, unmanaged
//	                           aliases stay null, restore/timeouts kept
//	Read (missing)           — error, never RemoveResource
//	Update (happy)           — forwards delta, keeps snapshot intent
//	Delete (default)         — no remote change
//	Delete (restore)         — re-applies snapshot; missing snapshot warns
//	ImportState (happy)      — snapshot captured, aliases start unmanaged
//	ImportState (invalid)    — diagnostic error
package provider

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeFirewallProfileClient
// ---------------------------------------------------------------------------

type fakeFirewallProfileClient struct {
	readOut  *winclient.FirewallProfileState
	readErr  error
	readName string

	applyIn   winclient.FirewallProfileSettings
	applyName string
	applyOut  *winclient.FirewallProfileState
	applyErr  error

	restoreIn  winclient.FirewallProfileState
	restoreOut *winclient.FirewallProfileState
	restoreErr error
}

func (f *fakeFirewallProfileClient) Read(_ context.Context, name string) (*winclient.FirewallProfileState, error) {
	f.readName = name
	return f.readOut, f.readErr
}

func (f *fakeFirewallProfileClient) Apply(_ context.Context, name string, s winclient.FirewallProfileSettings) (*winclient.FirewallProfileState, error) {
	f.applyName = name
	f.applyIn = s
	return f.applyOut, f.applyErr
}

func (f *fakeFirewallProfileClient) Restore(_ context.Context, snap winclient.FirewallProfileState) (*winclient.FirewallProfileState, error) {
	f.restoreIn = snap
	return f.restoreOut, f.restoreErr
}

func (f *fakeFirewallProfileClient) SSHProfile(_ context.Context) (string, error) {
	panic("SSHProfile not used in resource unit tests")
}

func okFirewallProfileState(name string) *winclient.FirewallProfileState {
	return &winclient.FirewallProfileState{
		Name:                            name,
		Enabled:                         true,
		DefaultInboundAction:            "Allow",
		DefaultOutboundAction:           "Allow",
		AllowInboundRules:               "True",
		AllowLocalFirewallRules:         "NotConfigured",
		AllowLocalIPsecRules:            "NotConfigured",
		AllowUnicastResponseToMulticast: "NotConfigured",
		NotifyOnListen:                  false,
		LogFileName:                     `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`,
		LogMaxSizeKilobytes:             4096,
		LogAllowed:                      "False",
		LogBlocked:                      "False",
		LogIgnored:                      "False",
		DisabledInterfaceAliases:        []string{},
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_firewall_profile schema
// ---------------------------------------------------------------------------

func fpSetType() tftypes.Set { return tftypes.Set{ElementType: tftypes.String} }

func fpObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                                  tftypes.String,
		"name":                                tftypes.String,
		"enabled":                             tftypes.Bool,
		"default_inbound_action":              tftypes.String,
		"default_outbound_action":             tftypes.String,
		"allow_inbound_rules":                 tftypes.Bool,
		"allow_local_firewall_rules":          tftypes.Bool,
		"allow_local_ipsec_rules":             tftypes.Bool,
		"allow_unicast_response_to_multicast": tftypes.Bool,
		"notify_on_listen":                    tftypes.Bool,
		"log_file_name":                       tftypes.String,
		"log_max_size_kilobytes":              tftypes.Number,
		"log_allowed":                         tftypes.Bool,
		"log_blocked":                         tftypes.Bool,
		"log_ignored":                         tftypes.Bool,
		"disabled_interface_aliases":          fpSetType(),
		"restore_on_destroy":                  tftypes.Bool,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func fpNullStr() tftypes.Value  { return tftypes.NewValue(tftypes.String, nil) }
func fpNullBool() tftypes.Value { return tftypes.NewValue(tftypes.Bool, nil) }
func fpNullNum() tftypes.Value  { return tftypes.NewValue(tftypes.Number, nil) }
func fpNullSet() tftypes.Value  { return tftypes.NewValue(fpSetType(), nil) }

func fpNullTimeouts() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func fpObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                                  tftypes.NewValue(tftypes.String, "Public"),
		"name":                                tftypes.NewValue(tftypes.String, "Public"),
		"enabled":                             fpNullBool(),
		"default_inbound_action":              fpNullStr(),
		"default_outbound_action":             fpNullStr(),
		"allow_inbound_rules":                 fpNullBool(),
		"allow_local_firewall_rules":          fpNullBool(),
		"allow_local_ipsec_rules":             fpNullBool(),
		"allow_unicast_response_to_multicast": fpNullBool(),
		"notify_on_listen":                    fpNullBool(),
		"log_file_name":                       fpNullStr(),
		"log_max_size_kilobytes":              fpNullNum(),
		"log_allowed":                         fpNullBool(),
		"log_blocked":                         fpNullBool(),
		"log_ignored":                         fpNullBool(),
		"disabled_interface_aliases":          fpNullSet(),
		"restore_on_destroy":                  tftypes.NewValue(tftypes.Bool, false),
		"timeouts":                            fpNullTimeouts(),
	}
}

func fpObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := fpObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(fpObjType(), base)
}

func fpState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	return tfsdk.State{Raw: fpObj(overrides), Schema: s}
}

func fpPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: fpObj(overrides), Schema: s}
}

func fpConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: fpObj(overrides), Schema: s}
}

func fpDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// allocPrivate allocates the framework private-state value on a response or
// request so handler tests can capture snapshots without the framework
// server. The *privatestate.ProviderData type lives in an internal framework
// package and cannot be named here; reflection allocates the zero value,
// which SetKey lazily initializes (mirroring EmptyProviderData). Method
// calls on the allocated value compile without naming the type.
func allocPrivate(t *testing.T, holder any) {
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

func TestWindowsFirewallProfileResource_Metadata(t *testing.T) {
	r := &windowsFirewallProfileResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_firewall_profile" {
		t.Errorf("TypeName = %q, want windows_firewall_profile", resp.TypeName)
	}
}

func TestWindowsFirewallProfileResource_Schema(t *testing.T) {
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "name", "enabled", "default_inbound_action", "default_outbound_action",
		"allow_inbound_rules", "allow_local_firewall_rules", "allow_local_ipsec_rules",
		"allow_unicast_response_to_multicast", "notify_on_listen",
		"log_file_name", "log_max_size_kilobytes", "log_allowed", "log_blocked", "log_ignored",
		"disabled_interface_aliases", "restore_on_destroy", "timeouts",
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
	// Every setting is Optional+Computed: only configured attrs are sent.
	for _, n := range []string{"enabled", "default_inbound_action", "default_outbound_action",
		"allow_inbound_rules", "allow_local_firewall_rules", "allow_local_ipsec_rules",
		"allow_unicast_response_to_multicast", "notify_on_listen",
		"log_file_name", "log_max_size_kilobytes", "log_allowed", "log_blocked", "log_ignored"} {
		a := s.Attributes[n]
		if !isOptionalComputedAttr(a) {
			t.Errorf("%s must be Optional+Computed (partial management)", n)
		}
	}
	setAttr, ok := s.Attributes["disabled_interface_aliases"].(schema.SetAttribute)
	if !ok {
		t.Fatalf("expected schema.SetAttribute, got %T", setAttr)
	}
	if !setAttr.Optional || !setAttr.Computed {
		t.Error("disabled_interface_aliases must be Optional+Computed")
	}
	restoreAttr, ok := s.Attributes["restore_on_destroy"].(schema.BoolAttribute)
	if !ok {
		t.Fatalf("expected schema.BoolAttribute, got %T", restoreAttr)
	}
	if !restoreAttr.Optional || !restoreAttr.Computed {
		t.Error("restore_on_destroy must be Optional+Computed (default false)")
	}
	idAttr, ok := s.Attributes["id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", idAttr)
	}
	if !idAttr.Computed || idAttr.Optional || idAttr.Required {
		t.Error("id must be computed only")
	}
}

func isOptionalComputedAttr(a any) bool {
	type optionalChecker interface{ IsOptional() bool }
	type computedChecker interface{ IsComputed() bool }
	oc, ok1 := a.(optionalChecker)
	cc, ok2 := a.(computedChecker)
	return ok1 && ok2 && oc.IsOptional() && cc.IsComputed()
}

// TestFirewallProfileResource_SettingsUseStateForUnknown (issue #322):
// every Optional+Computed profile setting is observed from the host
// (Get-NetFirewallProfile, tri-states project to null) and must carry
// UseStateForUnknown so an unconfigured attribute keeps its prior state
// instead of planning an unknown value that fails with
// "inconsistent result after apply". The bespoke Read keeps the
// disabled_interface_aliases null-when-unmanaged projection; the plan
// modifier only affects unknown values, never null.
func TestFirewallProfileResource_SettingsUseStateForUnknown(t *testing.T) {
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	for _, n := range []string{
		"enabled", "allow_inbound_rules", "allow_local_firewall_rules",
		"allow_local_ipsec_rules", "allow_unicast_response_to_multicast",
		"notify_on_listen", "log_allowed", "log_blocked", "log_ignored",
	} {
		a, ok := s.Attributes[n].(schema.BoolAttribute)
		if !ok {
			t.Fatalf("%s: expected schema.BoolAttribute, got %T", n, s.Attributes[n])
		}
		if len(a.PlanModifiers) != 1 || !reflect.DeepEqual(a.PlanModifiers[0], boolplanmodifier.UseStateForUnknown()) {
			t.Errorf("%s must carry exactly UseStateForUnknown, got %v", n, a.PlanModifiers)
		}
	}
	for _, n := range []string{
		"default_inbound_action", "default_outbound_action", "log_file_name",
	} {
		a, ok := s.Attributes[n].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected schema.StringAttribute, got %T", n, s.Attributes[n])
		}
		if len(a.PlanModifiers) != 1 || !reflect.DeepEqual(a.PlanModifiers[0], stringplanmodifier.UseStateForUnknown()) {
			t.Errorf("%s must carry exactly UseStateForUnknown, got %v", n, a.PlanModifiers)
		}
	}
	intAttr, ok := s.Attributes["log_max_size_kilobytes"].(schema.Int64Attribute)
	if !ok {
		t.Fatalf("log_max_size_kilobytes: expected schema.Int64Attribute, got %T", s.Attributes["log_max_size_kilobytes"])
	}
	if len(intAttr.PlanModifiers) != 1 || !reflect.DeepEqual(intAttr.PlanModifiers[0], int64planmodifier.UseStateForUnknown()) {
		t.Errorf("log_max_size_kilobytes must carry exactly UseStateForUnknown, got %v", intAttr.PlanModifiers)
	}
	setAttr, ok := s.Attributes["disabled_interface_aliases"].(schema.SetAttribute)
	if !ok {
		t.Fatalf("disabled_interface_aliases: expected schema.SetAttribute, got %T", s.Attributes["disabled_interface_aliases"])
	}
	if len(setAttr.PlanModifiers) != 1 || !reflect.DeepEqual(setAttr.PlanModifiers[0], setplanmodifier.UseStateForUnknown()) {
		t.Errorf("disabled_interface_aliases must carry exactly UseStateForUnknown, got %v", setAttr.PlanModifiers)
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestFirewallProfileNameValidator(t *testing.T) {
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	nameAttr, ok := s.Attributes["name"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", nameAttr)
	}
	if len(nameAttr.Validators) == 0 {
		t.Fatal("name must carry a OneOf validator")
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue("Domain"), false},
		{types.StringValue("Private"), false},
		{types.StringValue("Public"), false},
		{types.StringValue("Any"), true},
		{types.StringValue("domain"), true},
		{types.StringNull(), false},
		{types.StringUnknown(), false},
	} {
		resp := &validator.StringResponse{}
		nameAttr.Validators[0].ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("name"), ConfigValue: tc.val,
		}, resp)
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("name %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestFirewallProfileActionValidators(t *testing.T) {
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	for _, n := range []string{"default_inbound_action", "default_outbound_action"} {
		a, ok := s.Attributes[n].(schema.StringAttribute)
		if !ok {
			t.Fatalf("expected schema.StringAttribute, got %T", a)
		}
		if len(a.Validators) == 0 {
			t.Fatalf("%s must carry a OneOf validator", n)
		}
		for _, tc := range []struct {
			val     types.String
			wantErr bool
		}{
			{types.StringValue("Allow"), false},
			{types.StringValue("Block"), false},
			{types.StringValue("NotConfigured"), true},
			{types.StringValue("allow"), true},
			{types.StringNull(), false},
		} {
			resp := &validator.StringResponse{}
			a.Validators[0].ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root(n), ConfigValue: tc.val,
			}, resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("%s %v: wantErr=%v, got %v", n, tc.val, tc.wantErr, resp.Diagnostics)
			}
		}
	}
}

func TestFirewallProfileLogSizeValidator(t *testing.T) {
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	sizeAttr, ok := s.Attributes["log_max_size_kilobytes"].(schema.Int64Attribute)
	if !ok {
		t.Fatalf("expected schema.Int64Attribute, got %T", sizeAttr)
	}
	if len(sizeAttr.Validators) == 0 {
		t.Fatal("log_max_size_kilobytes must carry a range validator")
	}
	// Between(1,32767) is expressed through the framework int64 validator.
	ctx := context.Background()
	for _, tc := range []struct {
		val     types.Int64
		wantErr bool
	}{
		{types.Int64Value(1), false},
		{types.Int64Value(4096), false},
		{types.Int64Value(32767), false},
		{types.Int64Value(0), true},
		{types.Int64Value(-1), true},
		{types.Int64Value(32768), true},
		{types.Int64Null(), false},
		{types.Int64Unknown(), false},
	} {
		resp := &validator.Int64Response{}
		sizeAttr.Validators[0].ValidateInt64(ctx, validator.Int64Request{
			Path: path.Root("log_max_size_kilobytes"), ConfigValue: tc.val,
		}, resp)
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("log size %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestFirewallProfileLogPathValidator(t *testing.T) {
	v := firewallProfileLogPathValidator{}
	valid := []string{
		`C:\Logs\pfirewall.log`,
		`D:/Logs/pfirewall.log`,
		`\\server\share\pfirewall.log`,
		`%systemroot%\system32\LogFiles\Firewall\pfirewall.log`,
		`%SystemRoot%\system32\LogFiles\Firewall\pfirewall.log`,
		`%SYSTEMROOT%\a.log`,
	}
	for _, p := range valid {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("log_file_name"), ConfigValue: types.StringValue(p),
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("log path %q should pass, got %v", p, resp.Diagnostics)
		}
	}
	invalid := []string{
		`Logs\pfirewall.log`,
		`C:Logs\pfirewall.log`,
		`/var/log/fw.log`,
		`%windir%\a.log`,
		``,
	}
	for _, p := range invalid {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("log_file_name"), ConfigValue: types.StringValue(p),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("log path %q should be rejected", p)
		}
	}
	for _, cv := range []types.String{types.StringNull(), types.StringUnknown()} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("log_file_name"), ConfigValue: cv,
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("null/unknown should skip validation, got %v", resp.Diagnostics)
		}
	}
}

func TestFirewallProfileEnabledValidator(t *testing.T) {
	r, ok := NewWindowsFirewallProfileResource().(*windowsFirewallProfileResource)
	if !ok {
		t.Fatalf("expected *windowsFirewallProfileResource, got %T", r)
	}
	var v firewallProfileEnabledValidator
	for _, cv := range r.ConfigValidators(context.Background()) {
		if ev, ok := cv.(firewallProfileEnabledValidator); ok {
			v = ev
		}
	}
	cases := []struct {
		name      string
		overrides map[string]tftypes.Value
		wantWarn  bool
	}{
		{"disabled warns", map[string]tftypes.Value{"enabled": tftypes.NewValue(tftypes.Bool, false)}, true},
		{"enabled clean", map[string]tftypes.Value{"enabled": tftypes.NewValue(tftypes.Bool, true)}, false},
		{"unset clean", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &resource.ValidateConfigResponse{}
			v.ValidateResource(context.Background(), resource.ValidateConfigRequest{
				Config: fpConfig(t, tc.overrides),
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("validator must warn, never error: %v", resp.Diagnostics)
			}
			gotWarn := false
			for _, d := range resp.Diagnostics {
				if d.Severity() == diag.SeverityWarning {
					gotWarn = true
				}
			}
			if gotWarn != tc.wantWarn {
				t.Errorf("wantWarn=%v, diagnostics: %v", tc.wantWarn, fpDiagSummaries(resp.Diagnostics))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Settings projection: only configured attrs sent
// ---------------------------------------------------------------------------

func TestModelToFirewallProfileSettings_OnlyConfigured(t *testing.T) {
	ctx := context.Background()
	var m windowsFirewallProfileModel
	if diags := fpPlan(t, nil).Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	s, diags := modelToFirewallProfileSettings(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(diags))
	}
	if s.FirewallProfileConfigured() {
		t.Errorf("all-null plan must produce no configured settings: %+v", s)
	}
	if s.DisabledInterfaceAliasesSet {
		t.Error("null alias set must stay unmanaged")
	}
}

func TestModelToFirewallProfileSettings_ConfiguredAndAliases(t *testing.T) {
	ctx := context.Background()
	empty, d := types.SetValue(types.StringType, []attr.Value{})
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	m := windowsFirewallProfileModel{
		Enabled:                         types.BoolValue(false),
		DisabledInterfaceAliases:        empty,
		LogMaxSizeKilobytes:             types.Int64Value(8192),
		DefaultInboundAction:            types.StringValue("Block"),
		AllowInboundRules:               types.BoolValue(false),
		LogFileName:                     types.StringNull(),
		AllowLocalFirewallRules:         types.BoolNull(),
		AllowLocalIPsecRules:            types.BoolNull(),
		AllowUnicastResponseToMulticast: types.BoolNull(),
		NotifyOnListen:                  types.BoolNull(),
		LogAllowed:                      types.BoolNull(),
		LogBlocked:                      types.BoolNull(),
		LogIgnored:                      types.BoolNull(),
		DefaultOutboundAction:           types.StringNull(),
	}
	s, diags := modelToFirewallProfileSettings(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(diags))
	}
	if s.Enabled == nil || *s.Enabled {
		t.Error("enabled=false must be forwarded (with plan warning, never dropped)")
	}
	if s.DefaultInboundAction == nil || *s.DefaultInboundAction != "Block" {
		t.Error("default_inbound_action must be forwarded")
	}
	if s.LogMaxSizeKilobytes == nil || *s.LogMaxSizeKilobytes != 8192 {
		t.Error("log_max_size_kilobytes must be forwarded")
	}
	if !s.DisabledInterfaceAliasesSet || s.DisabledInterfaceAliases == nil || len(s.DisabledInterfaceAliases) != 0 {
		t.Errorf("configured empty alias set must be authoritative-empty, got %+v", s.DisabledInterfaceAliases)
	}
	if s.LogFileName != nil || s.NotifyOnListen != nil {
		t.Error("null attributes must stay nil (never sent)")
	}
}

func TestModelToFirewallProfileSettings_UnknownDefers(t *testing.T) {
	ctx := context.Background()
	m := windowsFirewallProfileModel{
		Enabled:                         types.BoolUnknown(),
		DisabledInterfaceAliases:        types.SetNull(types.StringType),
		AllowInboundRules:               types.BoolNull(),
		AllowLocalFirewallRules:         types.BoolNull(),
		AllowLocalIPsecRules:            types.BoolNull(),
		AllowUnicastResponseToMulticast: types.BoolNull(),
		NotifyOnListen:                  types.BoolNull(),
		LogAllowed:                      types.BoolNull(),
		LogBlocked:                      types.BoolNull(),
		LogIgnored:                      types.BoolNull(),
		DefaultInboundAction:            types.StringNull(),
		DefaultOutboundAction:           types.StringNull(),
		LogFileName:                     types.StringNull(),
		LogMaxSizeKilobytes:             types.Int64Null(),
	}
	if _, diags := modelToFirewallProfileSettings(ctx, m); !diags.HasError() {
		t.Error("unknown attributes must abort with a deferring diagnostic")
	}
	// Unknown alias set defers too.
	m2 := m
	m2.Enabled = types.BoolNull()
	m2.DisabledInterfaceAliases = types.SetUnknown(types.StringType)
	if _, diags := modelToFirewallProfileSettings(ctx, m2); !diags.HasError() {
		t.Error("unknown alias set must abort with a deferring diagnostic")
	}
}

func TestDedupeFirewallAliases(t *testing.T) {
	got := dedupeFirewallAliases([]string{"Ethernet 2", "ETHERNET 2", "Wi-Fi", "Ethernet 2"})
	if len(got) != 2 || got[0] != "Ethernet 2" || got[1] != "Wi-Fi" {
		t.Errorf("dedupe = %v, want [Ethernet 2 Wi-Fi] (first spelling wins)", got)
	}
	if got := dedupeFirewallAliases(nil); len(got) != 0 {
		t.Errorf("dedupe(nil) = %v, want empty", got)
	}
	// Whitespace variants collapse to the trimmed first-wins spelling.
	got = dedupeFirewallAliases([]string{"  Ethernet 2  ", "ethernet 2", " Wi-Fi "})
	if len(got) != 2 || got[0] != "Ethernet 2" || got[1] != "Wi-Fi" {
		t.Errorf("dedupe whitespace = %q, want trimmed [Ethernet 2 Wi-Fi]", got)
	}
}

// ---------------------------------------------------------------------------
// State projection: tri-states, aliases, id
// ---------------------------------------------------------------------------

func TestFirewallProfileStateToModel_TriStates(t *testing.T) {
	ctx := context.Background()
	m, diags := firewallProfileStateToModel(ctx, types.SetNull(types.StringType), okFirewallProfileState("Public"))
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(diags))
	}
	if m.ID.ValueString() != "Public" || m.Name.ValueString() != "Public" {
		t.Errorf("id/name = %q/%q, want Public/Public", m.ID.ValueString(), m.Name.ValueString())
	}
	// Host NotConfigured tri-states (lab evidence) surface as null, never exposed.
	for _, b := range []types.Bool{m.AllowLocalFirewallRules, m.AllowLocalIPsecRules,
		m.AllowUnicastResponseToMulticast, m.LogIgnored} {
		_ = b
	}
	if !m.AllowLocalFirewallRules.IsNull() || !m.AllowLocalIPsecRules.IsNull() ||
		!m.AllowUnicastResponseToMulticast.IsNull() {
		t.Error("NotConfigured inbound/local rules must project to null")
	}
	if m.AllowInboundRules.ValueBool() != true {
		t.Error("AllowInboundRules True must project to true")
	}
	// GPO-managed NotConfigured actions (lab: observed on ActiveStore) are
	// observed as unset (null), consistent with the bool tri-states and the
	// schema OneOf Allow/Block.
	stNotConfigured := okFirewallProfileState("Public")
	stNotConfigured.DefaultInboundAction = "NotConfigured"
	stNotConfigured.DefaultOutboundAction = "NotConfigured"
	mNC, diags := firewallProfileStateToModel(ctx, types.SetNull(types.StringType), stNotConfigured)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(diags))
	}
	if !mNC.DefaultInboundAction.IsNull() || !mNC.DefaultOutboundAction.IsNull() {
		t.Errorf("NotConfigured actions must project to null, got %v/%v",
			mNC.DefaultInboundAction, mNC.DefaultOutboundAction)
	}
	if m.LogAllowed.ValueBool() != false {
		t.Error("LogAllowed False must project to false")
	}
	if !m.DisabledInterfaceAliases.IsNull() {
		t.Error("null declared aliases must stay null (unmanaged, never diffed)")
	}

	// Declared aliases reconcile verbatim.
	declared, d := types.SetValue(types.StringType, []attr.Value{types.StringValue("Ethernet 2")})
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	st := okFirewallProfileState("Public")
	st.DisabledInterfaceAliases = []string{"Ethernet 2", "Wi-Fi"}
	m2, diags := firewallProfileStateToModel(ctx, declared, st)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(diags))
	}
	var got []string
	if d := m2.DisabledInterfaceAliases.ElementsAs(ctx, &got, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	if len(got) != 2 {
		t.Errorf("declared aliases must reconcile observed drift, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsFirewallProfileResource_Create_HappyPath(t *testing.T) {
	fc := &fakeFirewallProfileClient{
		readOut:  okFirewallProfileState("Public"),
		applyOut: okFirewallProfileState("Public"),
	}
	r := &windowsFirewallProfileResource{fp: fc}

	req := resource.CreateRequest{Plan: fpPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.applyName != "Public" {
		t.Errorf("apply name = %q, want Public", fc.applyName)
	}
	if fc.applyIn.FirewallProfileConfigured() {
		t.Errorf("all-null plan must Apply no settings, got %+v", fc.applyIn)
	}
	var model windowsFirewallProfileModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Public" {
		t.Errorf("id = %q, want Public", model.ID.ValueString())
	}
}

func TestWindowsFirewallProfileResource_Create_SnapshotOnlyWhenRestore(t *testing.T) {
	// restore_on_destroy = true: pre-existing values are captured.
	fc := &fakeFirewallProfileClient{
		readOut:  okFirewallProfileState("Public"),
		applyOut: okFirewallProfileState("Public"),
	}
	r := &windowsFirewallProfileResource{fp: fc}
	req := resource.CreateRequest{Plan: fpPlan(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}
	allocPrivate(t, resp)
	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.readName != "Public" {
		t.Errorf("expected a pre-existing Read for the snapshot, got readName=%q", fc.readName)
	}
	raw, diags := resp.Private.GetKey(context.Background(), firewallProfilePrivateKey)
	if diags.HasError() {
		t.Fatalf("GetKey: %v", diags)
	}
	if len(raw) == 0 {
		t.Fatal("expected a snapshot in private state")
	}
	var snap winclient.FirewallProfileState
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.Name != "Public" || snap.LogMaxSizeKilobytes != 4096 {
		t.Errorf("snapshot content wrong: %+v", snap)
	}

	// Default (false): no pre-read, no snapshot.
	fc2 := &fakeFirewallProfileClient{applyOut: okFirewallProfileState("Public")}
	r2 := &windowsFirewallProfileResource{fp: fc2}
	resp2 := &resource.CreateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}
	r2.Create(context.Background(), resource.CreateRequest{Plan: fpPlan(t, nil)}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp2.Diagnostics))
	}
	if fc2.readName != "" {
		t.Errorf("restore disabled: no pre-read expected, got %q", fc2.readName)
	}
	if raw, _ := resp2.Private.GetKey(context.Background(), firewallProfilePrivateKey); len(raw) != 0 {
		t.Error("restore disabled: no snapshot expected in private state")
	}
}

func TestWindowsFirewallProfileResource_Create_WouldLockOut(t *testing.T) {
	fc := &fakeFirewallProfileClient{
		readOut: okFirewallProfileState("Public"),
		applyErr: winclient.NewFirewallProfileError(
			winclient.FirewallProfileErrorWouldLockOut,
			"Refusing to tighten firewall profile Public: no enabled inbound Allow TCP rule for port 22 covers that profile. Add one with windows_firewall_rule first, then re-apply. Nothing was applied.",
			nil, nil),
	}
	r := &windowsFirewallProfileResource{fp: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: fpPlan(t, map[string]tftypes.Value{
		"default_inbound_action": tftypes.NewValue(tftypes.String, "Block"),
		"allow_inbound_rules":    tftypes.NewValue(tftypes.Bool, false),
	})}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected a would_lock_out diagnostic")
	}
	joined := strings.Join(fpDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "would_lock_out") || !strings.Contains(joined, "windows_firewall_rule") {
		t.Errorf("lockout diagnostic must name the kind and point at windows_firewall_rule, got:\n%s", joined)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsFirewallProfileResource_Read_HappyPath(t *testing.T) {
	fc := &fakeFirewallProfileClient{readOut: okFirewallProfileState("Public")}
	r := &windowsFirewallProfileResource{fp: fc}

	req := resource.ReadRequest{State: fpState(t, nil)}
	resp := &resource.ReadResponse{State: fpState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var model windowsFirewallProfileModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Public" || !model.Enabled.ValueBool() {
		t.Errorf("unexpected state: id=%q enabled=%v", model.ID.ValueString(), model.Enabled.ValueBool())
	}
}

func TestWindowsFirewallProfileResource_Read_MissingIsError(t *testing.T) {
	fc := &fakeFirewallProfileClient{readOut: nil}
	r := &windowsFirewallProfileResource{fp: fc}

	req := resource.ReadRequest{State: fpState(t, nil)}
	resp := &resource.ReadResponse{State: fpState(t, nil)}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a missing profile must error, never silently drop from state")
	}
	if !resp.State.Raw.IsNull() {
		// State untouched: profiles always exist, so absence is a host defect.
		t.Log("state preserved alongside the error diagnostic")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestWindowsFirewallProfileResource_Update_HappyPath(t *testing.T) {
	st := okFirewallProfileState("Public")
	st.DefaultInboundAction = "Block"
	fc := &fakeFirewallProfileClient{applyOut: st}
	r := &windowsFirewallProfileResource{fp: fc}

	req := resource.UpdateRequest{
		Plan:  fpPlan(t, map[string]tftypes.Value{"default_inbound_action": tftypes.NewValue(tftypes.String, "Block")}),
		State: fpState(t, nil),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.applyIn.DefaultInboundAction == nil || *fc.applyIn.DefaultInboundAction != "Block" {
		t.Errorf("update must forward the delta, got %+v", fc.applyIn)
	}
	var model windowsFirewallProfileModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.DefaultInboundAction.ValueString() != "Block" {
		t.Errorf("state action = %q, want Block", model.DefaultInboundAction.ValueString())
	}
}

func TestWindowsFirewallProfileResource_Delete_DefaultNoRemoteChange(t *testing.T) {
	fc := &fakeFirewallProfileClient{restoreOut: okFirewallProfileState("Public")}
	r := &windowsFirewallProfileResource{fp: fc}

	req := resource.DeleteRequest{State: fpState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.Name != "" {
		t.Errorf("default delete must make no remote change, got restore of %+v", fc.restoreIn)
	}
}

func TestWindowsFirewallProfileResource_Delete_Restore(t *testing.T) {
	fc := &fakeFirewallProfileClient{restoreOut: okFirewallProfileState("Public")}
	r := &windowsFirewallProfileResource{fp: fc}

	want := okFirewallProfileState("Public")
	want.Enabled = false // snapshot differs from live state: restore must win
	want.LogMaxSizeKilobytes = 8192
	snap, _ := json.Marshal(want)

	state := fpState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	allocPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), firewallProfilePrivateKey, snap); diags.HasError() {
		t.Fatalf("seed snapshot: %v", diags)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.Name != "Public" || fc.restoreIn.Enabled != false || fc.restoreIn.LogMaxSizeKilobytes != 8192 {
		t.Errorf("restore must re-apply the captured snapshot verbatim, got %+v", fc.restoreIn)
	}
}

func TestWindowsFirewallProfileResource_Delete_RestoreMissingSnapshotWarns(t *testing.T) {
	fc := &fakeFirewallProfileClient{restoreOut: okFirewallProfileState("Public")}
	r := &windowsFirewallProfileResource{fp: fc}

	state := fpState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	// No snapshot seeded on this DeleteRequest (Private is nil, which
	// GetKey tolerates as "no snapshot"): warn, don't error or restore.
	req := resource.DeleteRequest{State: state}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing snapshot must warn, not error: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.Name != "" {
		t.Errorf("without a snapshot nothing may be re-applied, got %+v", fc.restoreIn)
	}
	foundWarn := false
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Error("missing snapshot with restore_on_destroy must warn")
	}
}

func TestWindowsFirewallProfileResource_Delete_CorruptSnapshotWarns(t *testing.T) {
	fc := &fakeFirewallProfileClient{restoreOut: okFirewallProfileState("Public")}
	r := &windowsFirewallProfileResource{fp: fc}

	state := fpState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	allocPrivate(t, &req)
	// Unreadable snapshot: valid JSON that cannot unmarshal into
	// FirewallProfileState reports !ok via getFirewallProfileSnapshot —
	// Delete must warn (same as the missing-snapshot path) and leave the
	// host untouched. (A bare "{corrupt" cannot be seeded here: the
	// framework's Private.SetKey validates JSON and rejects it with
	// diagnostics before Delete ever runs.)
	if diags := req.Private.SetKey(context.Background(), firewallProfilePrivateKey, []byte(`"corrupt"`)); diags.HasError() {
		t.Fatalf("seed corrupt snapshot: %v", diags)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("corrupt snapshot must warn, not error: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.Name != "" {
		t.Errorf("with an unreadable snapshot nothing may be re-applied, got %+v", fc.restoreIn)
	}
	foundWarn := false
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Error("corrupt snapshot with restore_on_destroy must warn")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsFirewallProfileResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakeFirewallProfileClient{readOut: okFirewallProfileState("Private")}
	r := &windowsFirewallProfileResource{fp: fc}

	req := resource.ImportStateRequest{ID: "Private"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}
	allocPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var model windowsFirewallProfileModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Name.ValueString() != "Private" || model.ID.ValueString() != "Private" {
		t.Errorf("unexpected imported state: name=%q id=%q", model.Name.ValueString(), model.ID.ValueString())
	}
	// Import starts with the alias list unmanaged (null).
	if !model.DisabledInterfaceAliases.IsNull() {
		t.Error("imported alias set must start null (unmanaged)")
	}
	if model.RestoreOnDestroy.ValueBool() {
		t.Error("imported restore_on_destroy must default to false")
	}
	// The observed values become the restore snapshot.
	raw, diags := resp.Private.GetKey(context.Background(), firewallProfilePrivateKey)
	if diags.HasError() || len(raw) == 0 {
		t.Fatalf("import must capture the restore snapshot: %v", diags)
	}
}

func TestWindowsFirewallProfileResource_ImportState_InvalidID(t *testing.T) {
	for _, id := range []string{"", "Any", "Domainx", " Private "} {
		// Note: " Private " trims to a valid name and is accepted.
		r := &windowsFirewallProfileResource{fp: &fakeFirewallProfileClient{readOut: okFirewallProfileState("Private")}}
		req := resource.ImportStateRequest{ID: id}
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}
		allocPrivate(t, resp)
		r.ImportState(context.Background(), req, resp)
		if id == " Private " {
			if resp.Diagnostics.HasError() {
				t.Errorf("import ID %q trims to a valid name and should be accepted: %v", id, fpDiagSummaries(resp.Diagnostics))
			}
			continue
		}
		if !resp.Diagnostics.HasError() {
			t.Errorf("expected diagnostic error for import ID %q", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Timeouts: a stalled remote command must surface a bounded diagnostic
// ---------------------------------------------------------------------------

func TestWindowsFirewallProfileSchema_HasTimeoutsBlock(t *testing.T) {
	s := windowsFirewallProfileSchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block: CRUD must be time-bounded")
	}
}

// hangFirewallProfileClient simulates a stalled transport: Apply blocks until
// the passed context is done, then returns the context error.
type hangFirewallProfileClient struct {
	fakeFirewallProfileClient
}

func (f *hangFirewallProfileClient) Apply(ctx context.Context, _ string, _ winclient.FirewallProfileSettings) (*winclient.FirewallProfileState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// fpTimeoutsRaw builds the raw tftypes value for a timeouts block carrying
// the given per-operation durations.
func fpTimeoutsRaw(durations map[string]string) tftypes.Value {
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

func TestWindowsFirewallProfileResource_Create_StalledTransportIsBounded(t *testing.T) {
	r := &windowsFirewallProfileResource{fp: &hangFirewallProfileClient{}}

	req := resource.CreateRequest{Plan: fpPlan(t, map[string]tftypes.Value{
		"timeouts": fpTimeoutsRaw(map[string]string{"create": "200ms"}),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsFirewallProfileSchemaDefinition(context.Background())}}

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

func TestWindowsFirewallProfileModel_PreservesTimeouts(t *testing.T) {
	ctx := context.Background()
	prior := windowsFirewallProfileModel{
		Timeouts: mustFPTimeouts(t, map[string]string{"create": "5m"}),
	}
	m := prior
	st := okFirewallProfileState("Public")
	projected, diags := firewallProfileStateToModel(ctx, types.SetNull(types.StringType), st)
	if diags.HasError() {
		t.Fatalf("projection: %v", diags)
	}
	projected.Timeouts = m.Timeouts
	got, diags := projected.Timeouts.Create(ctx, firewallProfileDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("Timeouts.Create: %v", diags)
	}
	if got != 5*time.Minute {
		t.Errorf("Timeouts not preserved through projection: create = %v, want 5m", got)
	}
}

// mustFPTimeouts decodes fpTimeoutsRaw through the resource schema, the same
// path the framework takes for real plans.
func mustFPTimeouts(t *testing.T, durations map[string]string) timeouts.Value {
	t.Helper()
	ctx := context.Background()
	plan := tfsdk.Plan{
		Schema: windowsFirewallProfileSchemaDefinition(ctx),
		Raw: fpObj(map[string]tftypes.Value{
			"timeouts": fpTimeoutsRaw(durations),
		}),
	}
	var m windowsFirewallProfileModel
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get timeouts: %v", diags)
	}
	return m.Timeouts
}

func TestFirewallProfileErrorDiag_WouldLockOut(t *testing.T) {
	var diags diag.Diagnostics
	addFirewallProfileDiag(&diags, "Error creating Windows Firewall profile",
		winclient.NewFirewallProfileError(winclient.FirewallProfileErrorWouldLockOut, "Refusing: add one with windows_firewall_rule.", nil, nil))
	if !diags.HasError() {
		t.Fatal("expected an error diagnostic")
	}
	joined := strings.Join(fpDiagSummaries(diags), "\n")
	if !strings.Contains(joined, "would_lock_out") || !strings.Contains(joined, "windows_firewall_rule") {
		t.Errorf("lockout diag must keep kind + guidance, got:\n%s", joined)
	}
}

func TestFirewallProfileSnapshot_RoundTrip(t *testing.T) {
	ctx := context.Background()
	// setFirewallProfileSnapshot/getFirewallProfileSnapshot round-trip through
	// injectable closures so the JSON private-state format is pinned.
	store := map[string][]byte{}
	setKey := func(_ context.Context, k string, v []byte) diag.Diagnostics {
		store[k] = v
		return nil
	}
	getKey := func(_ context.Context, k string) ([]byte, diag.Diagnostics) {
		return store[k], nil
	}
	want := okFirewallProfileState("Domain")
	want.DisabledInterfaceAliases = []string{"Ethernet 2"}
	if err := setFirewallProfileSnapshot(ctx, setKey, want); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := getFirewallProfileSnapshot(ctx, getKey)
	if !ok || got == nil {
		t.Fatal("expected a snapshot back")
	}
	if got.Name != "Domain" || len(got.DisabledInterfaceAliases) != 1 || got.DisabledInterfaceAliases[0] != "Ethernet 2" {
		t.Errorf("snapshot round-trip lost data: %+v", got)
	}
	// Empty store: no snapshot, still ok.
	got, ok = getFirewallProfileSnapshot(ctx, func(_ context.Context, _ string) ([]byte, diag.Diagnostics) {
		return nil, nil
	})
	if !ok || got != nil {
		t.Errorf("empty store must be (nil, true), got (%+v, %v)", got, ok)
	}
	// Corrupt JSON: not ok.
	got, ok = getFirewallProfileSnapshot(ctx, func(_ context.Context, _ string) ([]byte, diag.Diagnostics) {
		return []byte("{nope"), nil
	})
	if ok {
		t.Errorf("corrupt snapshot must not be ok, got %+v", got)
	}
}

func TestWindowsFirewallProfileResource_Configure(t *testing.T) {
	r := &windowsFirewallProfileResource{}
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
