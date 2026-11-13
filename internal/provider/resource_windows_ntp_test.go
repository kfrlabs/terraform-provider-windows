// Package provider — unit tests for the windows_ntp resource.
//
// These tests exercise the schema, validators, model projection and CRUD
// handlers without SSH. A fakeNTPClient is injected into
// windowsNTPResource.ntp.
//
// Edge cases covered (issue #287):
//
//	Metadata              — returns "windows_ntp"
//	Schema                — type Required + OneOf, servers Optional+Computed
//	                        (address Required + no-space/comma validator,
//	                        flags default 0x9 + hex validator + lower-case
//	                        modifier), poll 16-86400, phase corrections >= 0,
//	                        manage_service/resync defaults true,
//	                        restore_on_destroy default false, timeouts 5m
//	Flags modifier        — "0X9" normalises to "0x9", null/unknown skipped
//	Config matrix         — peers required for NTP/AllSync, forbidden for
//	                        NT5DS/NoSync; poll-without-0x1 warns
//	Create (happy)        — snapshot captured when restore_on_destroy,
//	                        Set input forwarded, computed mapped, ID anchored
//	Create (no restore)   — snapshot skipped
//	Create (set error)    — service_unavailable diagnostic
//	Create (resync warn)  — resync failure warns, never errors
//	Create (domain/GPO)   — warnings surface
//	Read (happy)          — refreshes all computed, never removed
//	Read (error)          — diagnostic
//	Update (happy)        — forwards delta, keeps snapshot intent
//	Delete (default)      — no remote change
//	Delete (restore)      — re-applies snapshot verbatim (AnnounceFlags,
//	                        no resync, manage_service honoured); missing
//	                        snapshot warns; restore failure errors
//	ImportState (happy)   — any ID accepted, snapshot captured
//	ImportState (empty)   — diagnostic error
package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

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
// fakeNTPClient
// ---------------------------------------------------------------------------

type fakeNTPClient struct {
	readOut *winclient.NTPState
	readErr error

	setIn    winclient.NTPInput
	setCalls int
	setOut   *winclient.NTPState
	setErr   error
}

func (f *fakeNTPClient) Read(_ context.Context) (*winclient.NTPState, error) {
	return f.readOut, f.readErr
}

func (f *fakeNTPClient) Set(_ context.Context, in winclient.NTPInput) (*winclient.NTPState, error) {
	f.setIn = in
	f.setCalls++
	return f.setOut, f.setErr
}

func okNTPState() *winclient.NTPState {
	return &winclient.NTPState{
		MachineID:                    "11111111-2222-3333-4444-555555555555",
		Type:                         "NTP",
		Servers:                      []winclient.NTPPeer{{Address: "0.fr.pool.ntp.org", Flags: "0x9"}},
		SpecialPollIntervalSeconds:   900,
		Reliable:                     false,
		AnnounceFlags:                10,
		NtpServerEnabled:             false,
		MaxPosPhaseCorrectionSeconds: 54000,
		MaxNegPhaseCorrectionSeconds: 54000,
		CurrentSource:                "0.fr.pool.ntp.org,0x9",
		PolicyOverride:               false,
		DomainJoined:                 false,
		VmICEnabled:                  false,
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_ntp schema
// ---------------------------------------------------------------------------

func ntpServerElemObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"address": tftypes.String,
		"flags":   tftypes.String,
	}}
}

func ntpServerListType() tftypes.List {
	return tftypes.List{ElementType: ntpServerElemObjType()}
}

func ntpServersTFTypesValue(peers ...[2]string) tftypes.Value {
	vals := make([]tftypes.Value, 0, len(peers))
	for _, p := range peers {
		vals = append(vals, tftypes.NewValue(ntpServerElemObjType(), map[string]tftypes.Value{
			"address": tftypes.NewValue(tftypes.String, p[0]),
			"flags":   tftypes.NewValue(tftypes.String, p[1]),
		}))
	}
	return tftypes.NewValue(ntpServerListType(), vals)
}

func ntpObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                               tftypes.String,
		"type":                             tftypes.String,
		"servers":                          ntpServerListType(),
		"special_poll_interval_seconds":    tftypes.Number,
		"reliable":                         tftypes.Bool,
		"ntp_server_enabled":               tftypes.Bool,
		"max_pos_phase_correction_seconds": tftypes.Number,
		"max_neg_phase_correction_seconds": tftypes.Number,
		"manage_service":                   tftypes.Bool,
		"resync_on_apply":                  tftypes.Bool,
		"restore_on_destroy":               tftypes.Bool,
		"current_source":                   tftypes.String,
		"policy_override":                  tftypes.Bool,
		"domain_joined":                    tftypes.Bool,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func ntpNullTimeoutsTFTypesValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func ntpObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                               tftypes.NewValue(tftypes.String, nil),
		"type":                             tftypes.NewValue(tftypes.String, "NTP"),
		"servers":                          ntpServersTFTypesValue([2]string{"0.fr.pool.ntp.org", "0x9"}),
		"special_poll_interval_seconds":    tftypes.NewValue(tftypes.Number, nil),
		"reliable":                         tftypes.NewValue(tftypes.Bool, nil),
		"ntp_server_enabled":               tftypes.NewValue(tftypes.Bool, nil),
		"max_pos_phase_correction_seconds": tftypes.NewValue(tftypes.Number, nil),
		"max_neg_phase_correction_seconds": tftypes.NewValue(tftypes.Number, nil),
		"manage_service":                   tftypes.NewValue(tftypes.Bool, true),
		"resync_on_apply":                  tftypes.NewValue(tftypes.Bool, true),
		"restore_on_destroy":               tftypes.NewValue(tftypes.Bool, false),
		"current_source":                   tftypes.NewValue(tftypes.String, nil),
		"policy_override":                  tftypes.NewValue(tftypes.Bool, nil),
		"domain_joined":                    tftypes.NewValue(tftypes.Bool, nil),
		"timeouts":                         ntpNullTimeoutsTFTypesValue(),
	}
}

func ntpObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := ntpObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(ntpObjType(), base)
}

func ntpState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsNTPSchemaDefinition(context.Background())
	return tfsdk.State{Raw: ntpObj(overrides), Schema: s}
}

func ntpPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsNTPSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: ntpObj(overrides), Schema: s}
}

func ntpConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsNTPSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: ntpObj(overrides), Schema: s}
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsNTPResource_Metadata(t *testing.T) {
	r := &windowsNTPResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_ntp" {
		t.Errorf("TypeName = %q, want windows_ntp", resp.TypeName)
	}
}

func TestWindowsNTPResource_Schema(t *testing.T) {
	s := windowsNTPSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "type", "servers", "special_poll_interval_seconds", "reliable",
		"ntp_server_enabled", "max_pos_phase_correction_seconds",
		"max_neg_phase_correction_seconds", "manage_service", "resync_on_apply",
		"restore_on_destroy", "current_source", "policy_override",
		"domain_joined", "timeouts",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	typAttr, ok := s.Attributes["type"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", s.Attributes["type"])
	}
	if !typAttr.Required {
		t.Error("type must be Required")
	}
	if len(typAttr.Validators) == 0 {
		t.Error("type must carry the OneOf validator")
	}
	serversAttr, ok := s.Attributes["servers"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("expected schema.ListNestedAttribute, got %T", s.Attributes["servers"])
	}
	if !serversAttr.Optional || !serversAttr.Computed {
		t.Error("servers must be Optional+Computed")
	}
	addrAttr, ok := serversAttr.NestedObject.Attributes["address"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute for address, got %T", serversAttr.NestedObject.Attributes["address"])
	}
	if !addrAttr.Required || len(addrAttr.Validators) == 0 {
		t.Error("servers[].address must be Required with validators")
	}
	flagsAttr, ok := serversAttr.NestedObject.Attributes["flags"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute for flags, got %T", serversAttr.NestedObject.Attributes["flags"])
	}
	if !flagsAttr.Optional || !flagsAttr.Computed {
		t.Error("servers[].flags must be Optional+Computed")
	}
	if len(flagsAttr.Validators) == 0 {
		t.Error("servers[].flags must carry the hex validator")
	}
	if len(flagsAttr.PlanModifiers) == 0 {
		t.Error("servers[].flags must carry the lower-case plan modifier")
	}
	for _, n := range []string{"manage_service", "resync_on_apply", "restore_on_destroy"} {
		a, ok := s.Attributes[n].(schema.BoolAttribute)
		if !ok {
			t.Fatalf("expected schema.BoolAttribute, got %T", s.Attributes[n])
		}
		if !a.Optional || !a.Computed {
			t.Errorf("%s must be Optional+Computed", n)
		}
	}
	idAttr, ok := s.Attributes["id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", s.Attributes["id"])
	}
	if !idAttr.Computed || idAttr.Optional || idAttr.Required {
		t.Error("id must be computed only")
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestNTPTypeValidator(t *testing.T) {
	s := windowsNTPSchemaDefinition(context.Background())
	typAttr, ok := s.Attributes["type"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", s.Attributes["type"])
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue("NTP"), false},
		{types.StringValue("NT5DS"), false},
		{types.StringValue("AllSync"), false},
		{types.StringValue("NoSync"), false},
		{types.StringValue("ntp"), true},
		{types.StringValue("PDC"), true},
		{types.StringNull(), false},
		{types.StringUnknown(), false},
	} {
		resp := &validator.StringResponse{}
		for _, v := range typAttr.Validators {
			v.ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root("type"), ConfigValue: tc.val,
			}, resp)
			if resp.Diagnostics.HasError() {
				break
			}
		}
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("type %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestNTPServerElementValidators(t *testing.T) {
	s := windowsNTPSchemaDefinition(context.Background())
	serversAttr, ok := s.Attributes["servers"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("expected schema.ListNestedAttribute, got %T", s.Attributes["servers"])
	}
	addrAttr, ok := serversAttr.NestedObject.Attributes["address"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", serversAttr.NestedObject.Attributes["address"])
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue("0.fr.pool.ntp.org"), false},
		{types.StringValue("192.0.2.1"), false},
		{types.StringValue("has space.example"), true},
		{types.StringValue("a,b"), true},
		{types.StringNull(), false},
		{types.StringUnknown(), false},
	} {
		resp := &validator.StringResponse{}
		for _, v := range addrAttr.Validators {
			v.ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root("address"), ConfigValue: tc.val,
			}, resp)
			if resp.Diagnostics.HasError() {
				break
			}
		}
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("address %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
	flagsAttr, ok := serversAttr.NestedObject.Attributes["flags"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", serversAttr.NestedObject.Attributes["flags"])
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue("0x9"), false},
		{types.StringValue("0x1"), false},
		{types.StringValue("0Xf"), false},
		{types.StringValue("0x0"), true},
		{types.StringValue("0x10"), true},
		{types.StringValue("9"), true},
		{types.StringNull(), false},
		{types.StringUnknown(), false},
	} {
		resp := &validator.StringResponse{}
		for _, v := range flagsAttr.Validators {
			v.ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root("flags"), ConfigValue: tc.val,
			}, resp)
			if resp.Diagnostics.HasError() {
				break
			}
		}
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("flags %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestNTPLowercaseFlagsModifier(t *testing.T) {
	m := ntpLowercaseFlagsModifier{}
	if m.Description(context.Background()) == "" || m.MarkdownDescription(context.Background()) == "" {
		t.Error("modifier descriptions must not be empty")
	}
	resp := &planmodifier.StringResponse{PlanValue: types.StringValue("0X9")}
	m.PlanModifyString(context.Background(), planmodifier.StringRequest{PlanValue: types.StringValue("0X9")}, resp)
	if resp.PlanValue.ValueString() != "0x9" {
		t.Errorf("flags should normalise to lower-case, got %q", resp.PlanValue.ValueString())
	}
	nullResp := &planmodifier.StringResponse{PlanValue: types.StringNull()}
	m.PlanModifyString(context.Background(), planmodifier.StringRequest{PlanValue: types.StringNull()}, nullResp)
	if !nullResp.PlanValue.IsNull() {
		t.Error("null flags must stay null")
	}
}

// ---------------------------------------------------------------------------
// ConfigValidator matrix
// ---------------------------------------------------------------------------

func TestNTPConfigValidator_Matrix(t *testing.T) {
	v := windowsNTPConfigValidator{}
	nullServers := tftypes.NewValue(ntpServerListType(), nil)
	unknownServers := tftypes.NewValue(ntpServerListType(), tftypes.UnknownValue)
	for _, tc := range []struct {
		name      string
		typ       string
		servers   tftypes.Value
		wantErr   bool
		wantWarn  bool
		pollUnset bool
	}{
		{"ntp with peers", "NTP", ntpServersTFTypesValue([2]string{"h.example", "0x9"}), false, true, false},
		{"ntp without peers", "NTP", nullServers, true, false, true},
		{"allsync with peers", "AllSync", ntpServersTFTypesValue([2]string{"h.example", "0x1"}), false, false, false},
		{"nt5ds without peers", "NT5DS", nullServers, false, false, true},
		{"nt5ds with peers", "NT5DS", ntpServersTFTypesValue([2]string{"h.example", "0x9"}), true, false, true},
		{"nosync with peers", "NoSync", ntpServersTFTypesValue([2]string{"h.example", "0x9"}), true, false, true},
		{"unknown servers defers", "NTP", unknownServers, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poll := tftypes.NewValue(tftypes.Number, 900)
			if tc.pollUnset {
				poll = tftypes.NewValue(tftypes.Number, nil)
			}
			cfg := ntpConfig(t, map[string]tftypes.Value{
				"type":                          tftypes.NewValue(tftypes.String, tc.typ),
				"servers":                       tc.servers,
				"special_poll_interval_seconds": poll,
				"manage_service":                tftypes.NewValue(tftypes.Bool, true),
				"resync_on_apply":               tftypes.NewValue(tftypes.Bool, true),
				"restore_on_destroy":            tftypes.NewValue(tftypes.Bool, false),
			})
			req := resource.ValidateConfigRequest{Config: cfg}
			resp := &resource.ValidateConfigResponse{}
			v.ValidateResource(context.Background(), req, resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("wantErr=%v, got %v (%v)", tc.wantErr, resp.Diagnostics.HasError(), fpDiagSummaries(resp.Diagnostics))
			}
			if (resp.Diagnostics.WarningsCount() > 0) != tc.wantWarn {
				t.Errorf("wantWarn=%v, got %d warnings (%v)", tc.wantWarn, resp.Diagnostics.WarningsCount(), fpDiagSummaries(resp.Diagnostics))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsNTPResource_CreateHappy(t *testing.T) {
	live := okNTPState()
	fc := &fakeNTPClient{readOut: live, setOut: live}
	r := &windowsNTPResource{ntp: fc}

	req := resource.CreateRequest{Plan: ntpPlan(t, map[string]tftypes.Value{
		"restore_on_destroy":            tftypes.NewValue(tftypes.Bool, true),
		"special_poll_interval_seconds": tftypes.NewValue(tftypes.Number, 900),
		"reliable":                      tftypes.NewValue(tftypes.Bool, false),
	})}
	resp := &resource.CreateResponse{
		State: ntpState(t, nil),
	}
	allocPrivate(t, resp)

	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setIn.Type != "NTP" {
		t.Errorf("Set type = %q, want NTP", fc.setIn.Type)
	}
	if len(fc.setIn.Servers) != 1 || fc.setIn.Servers[0].Flags != "0x9" {
		t.Errorf("Set servers = %+v", fc.setIn.Servers)
	}
	if fc.setIn.SpecialPollIntervalSeconds == nil || *fc.setIn.SpecialPollIntervalSeconds != 900 {
		t.Errorf("Set poll = %+v", fc.setIn.SpecialPollIntervalSeconds)
	}
	if !fc.setIn.ManageService || !fc.setIn.ResyncOnApply {
		t.Errorf("manage_service/resync_on_apply must default true, got %+v", fc.setIn)
	}
	raw, diags := resp.Private.GetKey(context.Background(), ntpPrivateKey)
	if diags.HasError() {
		t.Fatalf("GetKey: %v", diags)
	}
	if len(raw) == 0 {
		t.Fatal("expected a snapshot in private state")
	}
	var m windowsNTPModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.ID.ValueString() != live.MachineID {
		t.Errorf("id = %q, want machine %q", m.ID.ValueString(), live.MachineID)
	}
	if m.CurrentSource.ValueString() != live.CurrentSource {
		t.Errorf("current_source = %q", m.CurrentSource.ValueString())
	}
	if m.ManageService.ValueBool() != true || m.ResyncOnApply.ValueBool() != true {
		t.Error("input-only intent must be preserved in state")
	}
}

func TestWindowsNTPResource_CreateNoRestoreSkipsSnapshot(t *testing.T) {
	live := okNTPState()
	fc := &fakeNTPClient{readOut: live, setOut: live}
	r := &windowsNTPResource{ntp: fc}

	resp := &resource.CreateResponse{
		State: ntpState(t, nil),
	}
	allocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: ntpPlan(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if raw, _ := resp.Private.GetKey(context.Background(), ntpPrivateKey); len(raw) != 0 {
		t.Error("restore disabled: no snapshot expected in private state")
	}
}

func TestWindowsNTPResource_CreateSetError(t *testing.T) {
	fc := &fakeNTPClient{
		readOut: okNTPState(),
		setErr:  winclient.NewNTPError(winclient.NTPErrorServiceUnavailable, "no W32Time", nil, nil),
	}
	r := &windowsNTPResource{ntp: fc}

	resp := &resource.CreateResponse{
		State: ntpState(t, nil),
	}
	allocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: ntpPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when Set fails")
	}
	if !strings.Contains(strings.Join(fpDiagSummaries(resp.Diagnostics), " "), "service_unavailable") {
		t.Errorf("diagnostic must carry the kind, got %v", fpDiagSummaries(resp.Diagnostics))
	}
}

func TestWindowsNTPResource_CreateResyncFailureWarns(t *testing.T) {
	live := okNTPState()
	live.ResyncWarning = "w32tm /resync /rediscover exited 1: No time data was available"
	fc := &fakeNTPClient{readOut: okNTPState(), setOut: live}
	r := &windowsNTPResource{ntp: fc}

	resp := &resource.CreateResponse{
		State: ntpState(t, nil),
	}
	allocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: ntpPlan(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("resync failure must warn, not error: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Fatal("resync failure must emit a warning")
	}
}

func TestWindowsNTPResource_CreateWarningsTable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*winclient.NTPState)
		want   string
	}{
		{"domain joined non-NT5DS", func(s *winclient.NTPState) { s.DomainJoined = true }, "Domain-joined"},
		{"policy override", func(s *winclient.NTPState) { s.PolicyOverride = true }, "Group Policy"},
		{"ntp server enabled", func(s *winclient.NTPState) { s.NtpServerEnabled = true }, "UDP/123"},
		{"hyper-v time sync", func(s *winclient.NTPState) { s.VmICEnabled = true }, "Hyper-V"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			live := okNTPState()
			tc.mutate(live)
			fc := &fakeNTPClient{readOut: okNTPState(), setOut: live}
			r := &windowsNTPResource{ntp: fc}
			resp := &resource.CreateResponse{State: ntpState(t, nil)}
			allocPrivate(t, resp)
			r.Create(context.Background(), resource.CreateRequest{Plan: ntpPlan(t, nil)}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Create diags: %v", fpDiagSummaries(resp.Diagnostics))
			}
			if resp.Diagnostics.WarningsCount() == 0 {
				t.Fatalf("expected a %q warning", tc.want)
			}
			if !strings.Contains(strings.Join(fpDiagSummaries(resp.Diagnostics), " "), tc.want) {
				t.Errorf("warning must mention %q, got %v", tc.want, fpDiagSummaries(resp.Diagnostics))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsNTPResource_ReadHappy(t *testing.T) {
	live := okNTPState()
	live.Type = "NT5DS"
	live.Servers = nil
	fc := &fakeNTPClient{readOut: live}
	r := &windowsNTPResource{ntp: fc}

	req := resource.ReadRequest{State: ntpState(t, nil)}
	resp := &resource.ReadResponse{
		State: ntpState(t, nil),
	}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var m windowsNTPModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.Type.ValueString() != "NT5DS" {
		t.Errorf("type = %q, want drifted live value NT5DS", m.Type.ValueString())
	}
	if !m.Servers.IsNull() && len(m.Servers.Elements()) != 0 {
		t.Errorf("empty host peer list must project to an empty list, got %v", m.Servers)
	}
}

func TestWindowsNTPResource_ReadError(t *testing.T) {
	fc := &fakeNTPClient{
		readErr: winclient.NewNTPError(winclient.NTPErrorUnknown, "boom", nil, nil),
	}
	r := &windowsNTPResource{ntp: fc}

	req := resource.ReadRequest{State: ntpState(t, nil)}
	resp := &resource.ReadResponse{
		State: ntpState(t, nil),
	}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when Read fails")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestWindowsNTPResource_UpdateHappy(t *testing.T) {
	live := okNTPState()
	live.SpecialPollIntervalSeconds = 3600
	fc := &fakeNTPClient{setOut: live}
	r := &windowsNTPResource{ntp: fc}

	req := resource.UpdateRequest{
		Plan: ntpPlan(t, map[string]tftypes.Value{
			"special_poll_interval_seconds": tftypes.NewValue(tftypes.Number, 3600),
		}),
		State: ntpState(t, nil),
	}
	resp := &resource.UpdateResponse{
		State: ntpState(t, nil),
	}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setIn.SpecialPollIntervalSeconds == nil || *fc.setIn.SpecialPollIntervalSeconds != 3600 {
		t.Errorf("Set poll = %+v, want 3600", fc.setIn.SpecialPollIntervalSeconds)
	}
	if resp.Private != nil {
		if raw, diags := resp.Private.GetKey(context.Background(), ntpPrivateKey); !diags.HasError() && len(raw) != 0 {
			t.Error("Update must not overwrite the restore snapshot")
		}
	}
	var m windowsNTPModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.SpecialPollIntervalSeconds.ValueInt64() != 3600 {
		t.Errorf("poll = %d", m.SpecialPollIntervalSeconds.ValueInt64())
	}
}

func TestWindowsNTPResource_UpdateError(t *testing.T) {
	fc := &fakeNTPClient{
		setErr: winclient.NewNTPError(winclient.NTPErrorAccessDenied, "denied", nil, nil),
	}
	r := &windowsNTPResource{ntp: fc}

	req := resource.UpdateRequest{Plan: ntpPlan(t, nil), State: ntpState(t, nil)}
	resp := &resource.UpdateResponse{
		State: ntpState(t, nil),
	}
	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when Set fails")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestWindowsNTPResource_DeleteDefaultIsNoop(t *testing.T) {
	fc := &fakeNTPClient{setOut: okNTPState()}
	r := &windowsNTPResource{ntp: fc}

	req := resource.DeleteRequest{State: ntpState(t, nil)}
	resp := &resource.DeleteResponse{
		State: ntpState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setCalls != 0 {
		t.Error("default destroy must make no remote change")
	}
}

func TestWindowsNTPResource_DeleteRestore(t *testing.T) {
	prior := okNTPState()
	prior.Type = "NT5DS"
	prior.Servers = nil
	prior.AnnounceFlags = 5
	prior.Reliable = true
	restored := okNTPState()
	restored.Type = "NT5DS"
	fc := &fakeNTPClient{setOut: restored}
	r := &windowsNTPResource{ntp: fc}

	req := resource.DeleteRequest{State: ntpState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
		"manage_service":     tftypes.NewValue(tftypes.Bool, false),
	})}
	allocPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), ntpPrivateKey, mustMarshalNTP(t, prior)); diags.HasError() {
		t.Fatalf("SetKey: %v", diags)
	}
	resp := &resource.DeleteResponse{
		State: ntpState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setCalls != 1 {
		t.Fatalf("restore destroy must re-apply the snapshot, got %d Set calls", fc.setCalls)
	}
	if fc.setIn.Type != "NT5DS" {
		t.Errorf("restore type = %q, want snapshot NT5DS", fc.setIn.Type)
	}
	if fc.setIn.AnnounceFlags == nil || *fc.setIn.AnnounceFlags != 5 {
		t.Errorf("restore must carry the verbatim AnnounceFlags, got %+v", fc.setIn.AnnounceFlags)
	}
	if fc.setIn.ResyncOnApply {
		t.Error("delete-time restore must not resync")
	}
	if fc.setIn.ManageService {
		t.Error("restore must honour manage_service=false and leave the service untouched")
	}
	if len(fc.setIn.Servers) != 0 {
		t.Errorf("empty snapshot peer list must stay unmanaged, got %+v", fc.setIn.Servers)
	}
}

func TestWindowsNTPResource_DeleteRestoreMissingSnapshotWarns(t *testing.T) {
	fc := &fakeNTPClient{setOut: okNTPState()}
	r := &windowsNTPResource{ntp: fc}

	req := resource.DeleteRequest{State: ntpState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp := &resource.DeleteResponse{
		State: ntpState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing snapshot must warn, not error: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Fatal("missing snapshot must warn")
	}
	if fc.setCalls != 0 {
		t.Error("missing snapshot: host must be left untouched")
	}
}

func TestWindowsNTPResource_DeleteRestoreFailureErrors(t *testing.T) {
	prior := okNTPState()
	fc := &fakeNTPClient{
		setErr: winclient.NewNTPError(winclient.NTPErrorAccessDenied, "denied", nil, nil),
	}
	r := &windowsNTPResource{ntp: fc}

	req := resource.DeleteRequest{State: ntpState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	allocPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), ntpPrivateKey, mustMarshalNTP(t, prior)); diags.HasError() {
		t.Fatalf("SetKey: %v", diags)
	}
	resp := &resource.DeleteResponse{
		State: ntpState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("restore failure must surface an error diagnostic")
	}
}

func mustMarshalNTP(t *testing.T, st *winclient.NTPState) []byte {
	t.Helper()
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsNTPResource_ImportState(t *testing.T) {
	live := okNTPState()
	fc := &fakeNTPClient{readOut: live}
	r := &windowsNTPResource{ntp: fc}

	req := resource.ImportStateRequest{ID: "current"}
	resp := &resource.ImportStateResponse{
		State: ntpState(t, nil),
	}
	allocPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Import diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var m windowsNTPModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.ID.ValueString() != live.MachineID {
		t.Errorf("id = %q, want live machine %q", m.ID.ValueString(), live.MachineID)
	}
	if m.Type.ValueString() != live.Type {
		t.Errorf("type = %q", m.Type.ValueString())
	}
	if m.RestoreOnDestroy.ValueBool() {
		t.Error("imported restore_on_destroy must start false")
	}
	if !m.ManageService.ValueBool() || !m.ResyncOnApply.ValueBool() {
		t.Error("imported manage_service/resync_on_apply must default true")
	}
	raw, diags := resp.Private.GetKey(context.Background(), ntpPrivateKey)
	if diags.HasError() {
		t.Fatalf("GetKey: %v", diags)
	}
	if len(raw) == 0 {
		t.Fatal("import must capture the snapshot for a later restore")
	}
}

func TestWindowsNTPResource_ImportStateEmptyID(t *testing.T) {
	r := &windowsNTPResource{ntp: &fakeNTPClient{}}

	req := resource.ImportStateRequest{ID: "  "}
	resp := &resource.ImportStateResponse{
		State: ntpState(t, nil),
	}
	allocPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("empty import ID must error")
	}
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

func TestNTPStateToModel_EmptyPeersAndIDFallback(t *testing.T) {
	live := okNTPState()
	live.Servers = nil
	live.MachineID = ""
	prior := windowsNTPModel{
		ID:               types.StringValue("anchored-id"),
		ManageService:    types.BoolNull(),
		ResyncOnApply:    types.BoolUnknown(),
		RestoreOnDestroy: types.BoolNull(),
		Timeouts:         ntpNullTimeouts(),
	}
	m, diags := ntpStateToModel(live, prior)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if m.ID.ValueString() != "anchored-id" {
		t.Errorf("missing MachineGuid must keep the anchored ID, got %q", m.ID.ValueString())
	}
	if len(m.Servers.Elements()) != 0 {
		t.Errorf("nil peers must project to an empty list, got %v", m.Servers)
	}
	if !m.ManageService.ValueBool() || !m.ResyncOnApply.ValueBool() || m.RestoreOnDestroy.ValueBool() {
		t.Error("null/unknown intent must fall back to the schema defaults")
	}
}

func TestNTPModelToInput_NullAndUnknownSkip(t *testing.T) {
	m := windowsNTPModel{
		Type:                         types.StringValue("NT5DS"),
		Servers:                      types.ListNull(ntpServerElementObjectType()),
		SpecialPollIntervalSeconds:   types.Int64Unknown(),
		Reliable:                     types.BoolNull(),
		NtpServerEnabled:             types.BoolNull(),
		MaxPosPhaseCorrectionSeconds: types.Int64Null(),
		MaxNegPhaseCorrectionSeconds: types.Int64Null(),
		ManageService:                types.BoolValue(false),
		ResyncOnApply:                types.BoolValue(false),
	}
	in, diags := ntpModelToInput(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if in.Servers != nil || in.SpecialPollIntervalSeconds != nil || in.Reliable != nil ||
		in.NtpServerEnabled != nil || in.MaxPosPhaseCorrectionSeconds != nil || in.MaxNegPhaseCorrectionSeconds != nil {
		t.Errorf("null/unknown attributes must stay unmanaged, got %+v", in)
	}
	if in.ManageService || in.ResyncOnApply {
		t.Errorf("manage/resync flags must pass through, got %+v", in)
	}
}

func TestNTPSnapshotToInput_Verbatim(t *testing.T) {
	snap := okNTPState()
	snap.AnnounceFlags = 11
	snap.Reliable = false
	in, diags := ntpSnapshotToInput(snap, true)
	if diags.HasError() {
		t.Fatalf("snapshot diags: %v", diags)
	}
	if in.AnnounceFlags == nil || *in.AnnounceFlags != 11 {
		t.Errorf("restore must carry the verbatim AnnounceFlags, got %+v", in.AnnounceFlags)
	}
	if in.ResyncOnApply {
		t.Error("restore must not resync")
	}
	if !in.ManageService {
		t.Error("restore must honour manage_service=true")
	}
	if in.SpecialPollIntervalSeconds == nil || *in.SpecialPollIntervalSeconds != 900 {
		t.Errorf("restore must carry the snapshot poll interval, got %+v", in.SpecialPollIntervalSeconds)
	}
}
