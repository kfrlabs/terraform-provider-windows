// Package provider — unit tests for the windows_iis_app_pool resource.
//
// These tests exercise the schema, validators, settings projection and CRUD
// handlers without SSH. A fakeIISAppPoolClient is injected into
// windowsIISAppPoolResource.pool.
//
// Edge cases covered (issue #283):
//
//	Metadata                 — returns "windows_iis_app_pool"
//	Schema                   — name Required/ForceNew/length, all non-identity
//	                           Optional+Computed, identity_password_wo
//	                           Optional+Sensitive+WriteOnly, version AtLeast(1),
//	                           timeouts block
//	Name validator           — forbidden chars + padding rejected, null/unknown skip
//	Schedule validator       — HH:MM:SS accepted, bad shapes rejected
//	Identity validator       — SpecificUser requires username+password;
//	                           LocalSystem warns; credential without
//	                           SpecificUser warns
//	Settings projection      — only configured attrs sent, empty-vs-null
//	                           schedule, unknown skipped (never sent)
//	Delta                    — only changed configured attrs sent
//	Create (happy)           — password forwarded from config, version kept,
//	                           WO never in state
//	Create (SpecificUser)    — missing username/password fail closed
//	Read (happy/missing)     — missing removes from state, version preserved
//	Update (happy)           — delta forwarded; password re-sent only on
//	                           version bump; identity change without bump fails
//	Delete (in_use)          — diagnostic, kind preserved
//	ImportState (happy)      — schedule starts unmanaged, version null
//	ImportState (invalid)    — diagnostic error
package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
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
// fakeIISAppPoolClient
// ---------------------------------------------------------------------------

type fakeIISAppPoolClient struct {
	createIn  winclient.IISAppPoolInput
	createOut *winclient.IISAppPoolState
	createErr error

	readName string
	readOut  *winclient.IISAppPoolState
	readErr  error

	updateIn  winclient.IISAppPoolInput
	updateOut *winclient.IISAppPoolState
	updateErr error

	deleteName string
	deleteErr  error
}

func (f *fakeIISAppPoolClient) Create(_ context.Context, in winclient.IISAppPoolInput) (*winclient.IISAppPoolState, error) {
	f.createIn = in
	return f.createOut, f.createErr
}

func (f *fakeIISAppPoolClient) Read(_ context.Context, name string) (*winclient.IISAppPoolState, error) {
	f.readName = name
	return f.readOut, f.readErr
}

func (f *fakeIISAppPoolClient) Update(_ context.Context, in winclient.IISAppPoolInput) (*winclient.IISAppPoolState, error) {
	f.updateIn = in
	return f.updateOut, f.updateErr
}

func (f *fakeIISAppPoolClient) Delete(_ context.Context, name string) error {
	f.deleteName = name
	return f.deleteErr
}

func okIISAppPoolState(name string) *winclient.IISAppPoolState {
	return &winclient.IISAppPoolState{
		Name: name, ManagedRuntimeVersion: "v4.0", ManagedPipelineMode: "Integrated",
		Enable32BitAppOnWin64: false, StartMode: "OnDemand", AutoStart: true,
		QueueLength: 1000, IdentityType: "ApplicationPoolIdentity", IdentityUsername: "",
		LoadUserProfile: true, IdleTimeoutMinutes: 20, IdleTimeoutAction: "Terminate",
		MaxProcesses: 1, RecyclingPeriodicRestartMinutes: 1740,
		RecyclingSchedule: []string{}, RecyclingPrivateMemoryKB: 0,
		RapidFailProtection: true, CPULimitPercent: 0, CPUAction: "NoAction",
		State: "Started",
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_iis_app_pool schema
// ---------------------------------------------------------------------------

func apSetType() tftypes.Set { return tftypes.Set{ElementType: tftypes.String} }

func apObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                                 tftypes.String,
		"name":                               tftypes.String,
		"managed_runtime_version":            tftypes.String,
		"managed_pipeline_mode":              tftypes.String,
		"enable_32bit_app_on_win64":          tftypes.Bool,
		"start_mode":                         tftypes.String,
		"auto_start":                         tftypes.Bool,
		"queue_length":                       tftypes.Number,
		"identity_type":                      tftypes.String,
		"identity_username":                  tftypes.String,
		"identity_password_wo":               tftypes.String,
		"identity_password_wo_version":       tftypes.Number,
		"load_user_profile":                  tftypes.Bool,
		"idle_timeout_minutes":               tftypes.Number,
		"idle_timeout_action":                tftypes.String,
		"max_processes":                      tftypes.Number,
		"recycling_periodic_restart_minutes": tftypes.Number,
		"recycling_schedule":                 apSetType(),
		"recycling_private_memory_kb":        tftypes.Number,
		"rapid_fail_protection":              tftypes.Bool,
		"cpu_limit_percent":                  tftypes.Number,
		"cpu_action":                         tftypes.String,
		"state":                              tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func apNullStr() tftypes.Value  { return tftypes.NewValue(tftypes.String, nil) }
func apNullBool() tftypes.Value { return tftypes.NewValue(tftypes.Bool, nil) }
func apNullNum() tftypes.Value  { return tftypes.NewValue(tftypes.Number, nil) }
func apNullSet() tftypes.Value  { return tftypes.NewValue(apSetType(), nil) }

func apNullTimeouts() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func apObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                                 tftypes.NewValue(tftypes.String, "api"),
		"name":                               tftypes.NewValue(tftypes.String, "api"),
		"managed_runtime_version":            apNullStr(),
		"managed_pipeline_mode":              apNullStr(),
		"enable_32bit_app_on_win64":          apNullBool(),
		"start_mode":                         apNullStr(),
		"auto_start":                         apNullBool(),
		"queue_length":                       apNullNum(),
		"identity_type":                      apNullStr(),
		"identity_username":                  apNullStr(),
		"identity_password_wo":               apNullStr(),
		"identity_password_wo_version":       apNullNum(),
		"load_user_profile":                  apNullBool(),
		"idle_timeout_minutes":               apNullNum(),
		"idle_timeout_action":                apNullStr(),
		"max_processes":                      apNullNum(),
		"recycling_periodic_restart_minutes": apNullNum(),
		"recycling_schedule":                 apNullSet(),
		"recycling_private_memory_kb":        apNullNum(),
		"rapid_fail_protection":              apNullBool(),
		"cpu_limit_percent":                  apNullNum(),
		"cpu_action":                         apNullStr(),
		"state":                              apNullStr(),
		"timeouts":                           apNullTimeouts(),
	}
}

func apObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := apObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(apObjType(), base)
}

func apState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsIISAppPoolSchemaDefinition(context.Background())
	return tfsdk.State{Raw: apObj(overrides), Schema: s}
}

func apPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsIISAppPoolSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: apObj(overrides), Schema: s}
}

func apConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsIISAppPoolSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: apObj(overrides), Schema: s}
}

func apDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsIISAppPoolResource_Metadata(t *testing.T) {
	r := &windowsIISAppPoolResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_iis_app_pool" {
		t.Errorf("TypeName = %q, want windows_iis_app_pool", resp.TypeName)
	}
}

func TestWindowsIISAppPoolResource_Schema(t *testing.T) {
	s := windowsIISAppPoolSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "name", "managed_runtime_version", "managed_pipeline_mode",
		"enable_32bit_app_on_win64", "start_mode", "auto_start", "queue_length",
		"identity_type", "identity_username", "identity_password_wo",
		"identity_password_wo_version", "load_user_profile", "idle_timeout_minutes",
		"idle_timeout_action", "max_processes", "recycling_periodic_restart_minutes",
		"recycling_schedule", "recycling_private_memory_kb", "rapid_fail_protection",
		"cpu_limit_percent", "cpu_action", "state", "timeouts",
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
	// Every non-identity setting is Optional+Computed: only configured attrs are sent.
	for _, n := range []string{"managed_runtime_version", "managed_pipeline_mode",
		"enable_32bit_app_on_win64", "start_mode", "auto_start", "queue_length",
		"identity_type", "identity_username", "load_user_profile", "idle_timeout_minutes",
		"idle_timeout_action", "max_processes", "recycling_periodic_restart_minutes",
		"recycling_private_memory_kb", "rapid_fail_protection",
		"cpu_limit_percent", "cpu_action", "state"} {
		a := s.Attributes[n]
		if !isOptionalComputedAttr(a) {
			t.Errorf("%s must be Optional+Computed (partial management)", n)
		}
	}
	setAttr, ok := s.Attributes["recycling_schedule"].(schema.SetAttribute)
	if !ok {
		t.Fatalf("expected schema.SetAttribute, got %T", setAttr)
	}
	if !setAttr.Optional || !setAttr.Computed {
		t.Error("recycling_schedule must be Optional+Computed")
	}
	// WriteOnly + Sensitive password.
	woAttr, ok := s.Attributes["identity_password_wo"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", woAttr)
	}
	if !woAttr.WriteOnly || !woAttr.Sensitive || !woAttr.Optional {
		t.Error("identity_password_wo must be Optional+Sensitive+WriteOnly")
	}
	idAttr, ok := s.Attributes["id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", idAttr)
	}
	if !idAttr.Computed || idAttr.Optional || idAttr.Required {
		t.Error("id must be computed only")
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestIISAppPoolNameValidator(t *testing.T) {
	v := iisAppPoolNameValidator{}
	for _, p := range []string{"api", "DefaultAppPool", "a", "pool-1_name.test"} {
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

func TestIISAppPoolScheduleValidator(t *testing.T) {
	v := iisAppPoolScheduleValidator{}
	ctx := context.Background()
	mkSet := func(entries ...string) types.Set {
		vals := make([]attr.Value, 0, len(entries))
		for _, e := range entries {
			vals = append(vals, types.StringValue(e))
		}
		set, d := types.SetValue(types.StringType, vals)
		if d.HasError() {
			t.Fatalf("SetValue: %v", d)
		}
		return set
	}
	for _, set := range []types.Set{mkSet("03:00:00"), mkSet("00:00:00", "23:59:59"), types.SetNull(types.StringType), types.SetUnknown(types.StringType)} {
		resp := &validator.SetResponse{}
		v.ValidateSet(ctx, validator.SetRequest{Path: path.Root("recycling_schedule"), ConfigValue: set}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("schedule %v should pass, got %v", set, resp.Diagnostics)
		}
	}
	for _, set := range []types.Set{mkSet("3:00:00"), mkSet("24:00:00"), mkSet("03:00"), mkSet("nope"), mkSet("03:00:60")} {
		resp := &validator.SetResponse{}
		v.ValidateSet(ctx, validator.SetRequest{Path: path.Root("recycling_schedule"), ConfigValue: set}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("schedule %v should be rejected", set)
		}
	}
}

func TestIISAppPoolEnumValidators(t *testing.T) {
	s := windowsIISAppPoolSchemaDefinition(context.Background())
	strCases := map[string]struct {
		valid   []string
		invalid []string
	}{
		"managed_runtime_version": {[]string{"", "v2.0", "v4.0"}, []string{"v1.1", "V4.0"}},
		"managed_pipeline_mode":   {[]string{"Integrated", "Classic"}, []string{"integrated"}},
		"start_mode":              {[]string{"OnDemand", "AlwaysRunning"}, []string{"ondemand"}},
		"identity_type":           {[]string{"ApplicationPoolIdentity", "LocalSystem", "LocalService", "NetworkService", "SpecificUser"}, []string{"system"}},
		"idle_timeout_action":     {[]string{"Terminate", "Suspend"}, []string{"Kill"}},
		"cpu_action":              {[]string{"NoAction", "KillW3wp", "Throttle", "ThrottleUnderLoad"}, []string{"Kill"}},
		"state":                   {[]string{"Started", "Stopped"}, []string{"Running"}},
	}
	for name, tc := range strCases {
		a, ok := s.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected schema.StringAttribute, got %T", name, a)
		}
		if len(a.Validators) == 0 {
			t.Fatalf("%s must carry a OneOf validator", name)
		}
		for _, v := range tc.valid {
			resp := &validator.StringResponse{}
			a.Validators[0].ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root(name), ConfigValue: types.StringValue(v),
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Errorf("%s %q should pass, got %v", name, v, resp.Diagnostics)
			}
		}
		for _, v := range tc.invalid {
			resp := &validator.StringResponse{}
			a.Validators[0].ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root(name), ConfigValue: types.StringValue(v),
			}, resp)
			if !resp.Diagnostics.HasError() {
				t.Errorf("%s %q should be rejected", name, v)
			}
		}
	}
	intCases := map[string]struct {
		valid   []int64
		invalid []int64
	}{
		"queue_length":         {[]int64{10, 1000, 65535}, []int64{9, 65536, 0}},
		"idle_timeout_minutes": {[]int64{0, 20, 43200}, []int64{-1, 43201}},
		"max_processes":        {[]int64{0, 1, 2147483647}, []int64{-1}},
		"cpu_limit_percent":    {[]int64{0, 50, 100}, []int64{-1, 101}},
	}
	for name, tc := range intCases {
		a, ok := s.Attributes[name].(schema.Int64Attribute)
		if !ok {
			t.Fatalf("%s: expected schema.Int64Attribute, got %T", name, a)
		}
		if len(a.Validators) == 0 {
			t.Fatalf("%s must carry a range validator", name)
		}
		for _, v := range tc.valid {
			resp := &validator.Int64Response{}
			a.Validators[0].ValidateInt64(context.Background(), validator.Int64Request{
				Path: path.Root(name), ConfigValue: types.Int64Value(v),
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Errorf("%s %d should pass, got %v", name, v, resp.Diagnostics)
			}
		}
		for _, v := range tc.invalid {
			resp := &validator.Int64Response{}
			a.Validators[0].ValidateInt64(context.Background(), validator.Int64Request{
				Path: path.Root(name), ConfigValue: types.Int64Value(v),
			}, resp)
			if !resp.Diagnostics.HasError() {
				t.Errorf("%s %d should be rejected", name, v)
			}
		}
	}
}

func TestIISAppPoolIdentityValidator(t *testing.T) {
	var v iisAppPoolIdentityValidator
	cases := []struct {
		name      string
		overrides map[string]tftypes.Value
		wantErr   bool
		wantWarn  bool
	}{
		{"specificuser complete", map[string]tftypes.Value{
			"identity_type":        tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_username":    tftypes.NewValue(tftypes.String, `CONTOSO\svc`),
			"identity_password_wo": tftypes.NewValue(tftypes.String, "pw"),
		}, false, false},
		{"specificuser missing username", map[string]tftypes.Value{
			"identity_type":        tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_password_wo": tftypes.NewValue(tftypes.String, "pw"),
		}, true, false},
		{"specificuser missing password", map[string]tftypes.Value{
			"identity_type":     tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_username": tftypes.NewValue(tftypes.String, `CONTOSO\svc`),
		}, true, false},
		{"localsystem warns", map[string]tftypes.Value{
			"identity_type": tftypes.NewValue(tftypes.String, "LocalSystem"),
		}, false, true},
		{"credential without specificuser warns", map[string]tftypes.Value{
			"identity_type":     tftypes.NewValue(tftypes.String, "ApplicationPoolIdentity"),
			"identity_username": tftypes.NewValue(tftypes.String, `CONTOSO\svc`),
		}, false, true},
		{"unset clean", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &resource.ValidateConfigResponse{}
			v.ValidateResource(context.Background(), resource.ValidateConfigRequest{
				Config: apConfig(t, tc.overrides),
			}, resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("wantErr=%v, got %v", tc.wantErr, apDiagSummaries(resp.Diagnostics))
			}
			gotWarn := false
			for _, d := range resp.Diagnostics {
				if d.Severity() == diag.SeverityWarning {
					gotWarn = true
				}
			}
			if gotWarn != tc.wantWarn {
				t.Errorf("wantWarn=%v, diagnostics: %v", tc.wantWarn, apDiagSummaries(resp.Diagnostics))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Settings projection: only configured attrs sent
// ---------------------------------------------------------------------------

func TestModelToIISAppPoolSettings_OnlyConfigured(t *testing.T) {
	ctx := context.Background()
	var m windowsIISAppPoolModel
	if diags := apPlan(t, nil).Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	s, diags := modelToIISAppPoolSettings(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(diags))
	}
	if s.IISAppPoolConfigured() {
		t.Errorf("all-null plan must produce no configured settings: %+v", s)
	}
	if s.RecyclingScheduleSet {
		t.Error("null schedule must stay unmanaged")
	}
}

func TestModelToIISAppPoolSettings_ConfiguredAndSchedule(t *testing.T) {
	ctx := context.Background()
	sched, d := types.SetValue(types.StringType, []attr.Value{types.StringValue("03:00:00")})
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	m := windowsIISAppPoolModel{
		ManagedPipelineMode:   types.StringValue("Classic"),
		QueueLength:           types.Int64Value(2000),
		RecyclingSchedule:     sched,
		ManagedRuntimeVersion: types.StringNull(),
		StartMode:             types.StringNull(),
		IdentityType:          types.StringNull(),
		State:                 types.StringNull(),
	}
	s, diags := modelToIISAppPoolSettings(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(diags))
	}
	if s.ManagedPipelineMode == nil || *s.ManagedPipelineMode != "Classic" {
		t.Error("managed_pipeline_mode must be forwarded")
	}
	if s.QueueLength == nil || *s.QueueLength != 2000 {
		t.Error("queue_length must be forwarded")
	}
	if !s.RecyclingScheduleSet || len(s.RecyclingSchedule) != 1 || s.RecyclingSchedule[0] != "03:00:00" {
		t.Errorf("configured schedule must be authoritative, got %+v", s.RecyclingSchedule)
	}
	if s.ManagedRuntimeVersion != nil || s.State != nil {
		t.Error("null attributes must stay nil (never sent)")
	}
}

func TestModelToIISAppPoolSettings_EmptyScheduleAuthoritative(t *testing.T) {
	ctx := context.Background()
	empty, d := types.SetValue(types.StringType, []attr.Value{})
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	m := windowsIISAppPoolModel{RecyclingSchedule: empty}
	s, diags := modelToIISAppPoolSettings(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(diags))
	}
	if !s.RecyclingScheduleSet || s.RecyclingSchedule == nil || len(s.RecyclingSchedule) != 0 {
		t.Errorf("configured empty schedule must clear the collection, got %+v", s.RecyclingSchedule)
	}
}

func TestModelToIISAppPoolSettings_UnknownDefers(t *testing.T) {
	ctx := context.Background()
	m := windowsIISAppPoolModel{
		ManagedPipelineMode:   types.StringUnknown(),
		QueueLength:           types.Int64Unknown(),
		Enable32BitAppOnWin64: types.BoolUnknown(),
		RecyclingSchedule:     types.SetNull(types.StringType),
	}
	s, diags := modelToIISAppPoolSettings(ctx, m)
	if diags.HasError() {
		t.Fatalf("unknown attributes must be skipped without error, got: %v", apDiagSummaries(diags))
	}
	if s.ManagedPipelineMode != nil || s.QueueLength != nil || s.Enable32BitAppOnWin64 != nil {
		t.Error("unknown attributes must stay nil (never sent)")
	}
	if s.RecyclingScheduleSet {
		t.Error("null schedule must stay unset")
	}
	m2 := windowsIISAppPoolModel{RecyclingSchedule: types.SetUnknown(types.StringType)}
	s2, diags := modelToIISAppPoolSettings(ctx, m2)
	if diags.HasError() {
		t.Fatalf("unknown schedule must be skipped without error, got: %v", apDiagSummaries(diags))
	}
	if s2.RecyclingScheduleSet || s2.RecyclingSchedule != nil {
		t.Error("unknown schedule must stay unset (never sent)")
	}
}

// ---------------------------------------------------------------------------
// Delta: only changed configured attrs sent
// ---------------------------------------------------------------------------

func TestPlanToIISAppPoolDelta_OnlyChanged(t *testing.T) {
	ctx := context.Background()
	var prior windowsIISAppPoolModel
	if diags := apPlan(t, map[string]tftypes.Value{
		"managed_pipeline_mode": tftypes.NewValue(tftypes.String, "Integrated"),
		"queue_length":          tftypes.NewValue(tftypes.Number, 1000),
	}).Get(ctx, &prior); diags.HasError() {
		t.Fatalf("prior.Get: %v", diags)
	}
	var plan windowsIISAppPoolModel
	if diags := apPlan(t, map[string]tftypes.Value{
		"managed_pipeline_mode": tftypes.NewValue(tftypes.String, "Classic"),
		"queue_length":          tftypes.NewValue(tftypes.Number, 1000),
	}).Get(ctx, &plan); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	s, diags := planToIISAppPoolDelta(ctx, plan, prior)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(diags))
	}
	if s.ManagedPipelineMode == nil || *s.ManagedPipelineMode != "Classic" {
		t.Error("changed attribute must be forwarded")
	}
	if s.QueueLength != nil {
		t.Error("unchanged attribute must not be re-sent")
	}
}

func TestIISAppPoolPasswordVersionChanged(t *testing.T) {
	mk := func(v *int64) types.Int64 {
		if v == nil {
			return types.Int64Null()
		}
		return types.Int64Value(*v)
	}
	one, two := int64(1), int64(2)
	cases := []struct {
		name  string
		plan  types.Int64
		prior types.Int64
		want  bool
	}{
		{"bump", mk(&two), mk(&one), true},
		{"same", mk(&one), mk(&one), false},
		{"both null", mk(nil), mk(nil), false},
		{"unknown plan", types.Int64Unknown(), mk(&one), false},
	}
	for _, tc := range cases {
		if got := iisAppPoolPasswordVersionChanged(
			windowsIISAppPoolModel{IdentityPasswordWOVersion: tc.plan},
			windowsIISAppPoolModel{IdentityPasswordWOVersion: tc.prior},
		); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsIISAppPoolResource_Create_HappyPath(t *testing.T) {
	fc := &fakeIISAppPoolClient{createOut: okIISAppPoolState("api")}
	r := &windowsIISAppPoolResource{pool: fc}

	req := resource.CreateRequest{Plan: apPlan(t, map[string]tftypes.Value{
		"managed_pipeline_mode": tftypes.NewValue(tftypes.String, "Classic"),
	}), Config: apConfig(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.Name != "api" {
		t.Errorf("create name = %q, want api", fc.createIn.Name)
	}
	if fc.createIn.Settings.ManagedPipelineMode == nil || *fc.createIn.Settings.ManagedPipelineMode != "Classic" {
		t.Errorf("create must forward configured attrs, got %+v", fc.createIn.Settings)
	}
	if fc.createIn.Settings.ManagedRuntimeVersion != nil {
		t.Errorf("create must not send unconfigured attrs, got %+v", fc.createIn.Settings)
	}
	var model windowsIISAppPoolModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "api" {
		t.Errorf("id = %q, want api (pool name)", model.ID.ValueString())
	}
	if !model.IdentityPasswordWO.IsNull() {
		t.Error("WriteOnly password must never reach state")
	}
}

func TestWindowsIISAppPoolResource_Create_SpecificUserPasswordFromConfig(t *testing.T) {
	st := okIISAppPoolState("svc")
	st.IdentityType = "SpecificUser"
	st.IdentityUsername = `CONTOSO\svc-web`
	fc := &fakeIISAppPoolClient{createOut: st}
	r := &windowsIISAppPoolResource{pool: fc}

	plan := apPlan(t, map[string]tftypes.Value{
		"identity_type":                tftypes.NewValue(tftypes.String, "SpecificUser"),
		"identity_username":            tftypes.NewValue(tftypes.String, `CONTOSO\svc-web`),
		"identity_password_wo_version": tftypes.NewValue(tftypes.Number, 1),
	})
	// The WriteOnly value is null in the plan handed to ApplyResourceChange:
	// it must be read from config.
	config := apConfig(t, map[string]tftypes.Value{
		"identity_type":                tftypes.NewValue(tftypes.String, "SpecificUser"),
		"identity_username":            tftypes.NewValue(tftypes.String, `CONTOSO\svc-web`),
		"identity_password_wo":         tftypes.NewValue(tftypes.String, "s3cret!"),
		"identity_password_wo_version": tftypes.NewValue(tftypes.Number, 1),
	})
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: config}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.Password != "s3cret!" {
		t.Errorf("password must be forwarded from config, got %q", fc.createIn.Password)
	}
	var model windowsIISAppPoolModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.IdentityPasswordWOVersion.ValueInt64() != 1 {
		t.Errorf("version = %v, want 1", model.IdentityPasswordWOVersion)
	}
	if !model.IdentityPasswordWO.IsNull() {
		t.Error("WriteOnly password must never reach state")
	}
}

func TestWindowsIISAppPoolResource_Create_SpecificUserRequiresCredential(t *testing.T) {
	for name, overrides := range map[string]map[string]tftypes.Value{
		"missing username": {
			"identity_type":                tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_password_wo":         tftypes.NewValue(tftypes.String, "pw"),
			"identity_password_wo_version": tftypes.NewValue(tftypes.Number, 1),
		},
		"missing password": {
			"identity_type":     tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_username": tftypes.NewValue(tftypes.String, `CONTOSO\svc`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			fc := &fakeIISAppPoolClient{createOut: okIISAppPoolState("api")}
			r := &windowsIISAppPoolResource{pool: fc}
			resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
			r.Create(context.Background(), resource.CreateRequest{
				Plan:   apPlan(t, overrides),
				Config: apConfig(t, overrides),
			}, resp)
			if !resp.Diagnostics.HasError() {
				t.Fatal("expected a fail-closed diagnostic")
			}
			if fc.createIn.Name != "" {
				t.Error("failed validation must not reach the host")
			}
		})
	}
}

func TestWindowsIISAppPoolResource_Create_AlreadyExists(t *testing.T) {
	fc := &fakeIISAppPoolClient{
		createErr: winclient.NewIISAppPoolError(winclient.IISAppPoolErrorAlreadyExists,
			"IIS application pool 'api' already exists on this host (use 'terraform import' to bring it under management).", nil, nil),
	}
	r := &windowsIISAppPoolResource{pool: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: apPlan(t, nil), Config: apConfig(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an already_exists diagnostic")
	}
	joined := strings.Join(apDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "already_exists") || !strings.Contains(joined, "terraform import") {
		t.Errorf("diagnostic must name the kind and hint at import, got:\n%s", joined)
	}
}

func TestWindowsIISAppPoolResource_Create_NilReadback(t *testing.T) {
	fc := &fakeIISAppPoolClient{createOut: nil, createErr: nil}
	r := &windowsIISAppPoolResource{pool: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: apPlan(t, nil), Config: apConfig(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("nil readback after create must produce an error diagnostic")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsIISAppPoolResource_Read_HappyPath(t *testing.T) {
	fc := &fakeIISAppPoolClient{readOut: okIISAppPoolState("api")}
	r := &windowsIISAppPoolResource{pool: fc}

	req := resource.ReadRequest{State: apState(t, map[string]tftypes.Value{
		"identity_password_wo_version": tftypes.NewValue(tftypes.Number, 2),
	})}
	resp := &resource.ReadResponse{State: apState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp.Diagnostics))
	}
	if fc.readName != "api" {
		t.Errorf("read name = %q, want api", fc.readName)
	}
	var model windowsIISAppPoolModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ManagedRuntimeVersion.ValueString() != "v4.0" || model.QueueLength.ValueInt64() != 1000 {
		t.Errorf("unexpected state: %+v", model)
	}
	if model.IdentityPasswordWOVersion.ValueInt64() != 2 {
		t.Error("read must preserve the rotation counter from prior state")
	}
	if !model.IdentityPasswordWO.IsNull() {
		t.Error("password stays null after read (never returned)")
	}
	// Null declared schedule stays null (unmanaged, never diffed).
	if !model.RecyclingSchedule.IsNull() {
		t.Error("null declared schedule must stay null")
	}
}

func TestWindowsIISAppPoolResource_Read_MissingRemovesResource(t *testing.T) {
	fc := &fakeIISAppPoolClient{readOut: nil}
	r := &windowsIISAppPoolResource{pool: fc}

	req := resource.ReadRequest{State: apState(t, nil)}
	resp := &resource.ReadResponse{State: apState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing pool must remove from state without error, got %v", apDiagSummaries(resp.Diagnostics))
	}
	var model windowsIISAppPoolModel
	diags := resp.State.Get(context.Background(), &model)
	_ = diags
	if !resp.State.Raw.IsNull() {
		t.Error("missing pool must remove the resource from state")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestWindowsIISAppPoolResource_Update_OnlyChanged(t *testing.T) {
	st := okIISAppPoolState("api")
	st.ManagedPipelineMode = "Classic"
	fc := &fakeIISAppPoolClient{updateOut: st}
	r := &windowsIISAppPoolResource{pool: fc}

	req := resource.UpdateRequest{
		Plan: apPlan(t, map[string]tftypes.Value{
			"managed_pipeline_mode": tftypes.NewValue(tftypes.String, "Classic"),
			"queue_length":          tftypes.NewValue(tftypes.Number, 1000),
		}),
		State: apState(t, map[string]tftypes.Value{
			"managed_pipeline_mode": tftypes.NewValue(tftypes.String, "Integrated"),
			"queue_length":          tftypes.NewValue(tftypes.Number, 1000),
		}),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp.Diagnostics))
	}
	if fc.updateIn.Settings.ManagedPipelineMode == nil || *fc.updateIn.Settings.ManagedPipelineMode != "Classic" {
		t.Errorf("update must forward the changed attr, got %+v", fc.updateIn.Settings)
	}
	if fc.updateIn.Settings.QueueLength != nil {
		t.Errorf("update must not re-send unchanged attrs, got %+v", fc.updateIn.Settings)
	}
	if fc.updateIn.Password != "" {
		t.Errorf("password must not be re-sent without a version bump, got %q", fc.updateIn.Password)
	}
}

func TestWindowsIISAppPoolResource_Update_NilReadback(t *testing.T) {
	fc := &fakeIISAppPoolClient{updateOut: nil, updateErr: nil}
	r := &windowsIISAppPoolResource{pool: fc}

	req := resource.UpdateRequest{
		Plan: apPlan(t, map[string]tftypes.Value{
			"managed_pipeline_mode": tftypes.NewValue(tftypes.String, "Classic"),
			"queue_length":          tftypes.NewValue(tftypes.Number, 1000),
		}),
		State: apState(t, map[string]tftypes.Value{
			"managed_pipeline_mode": tftypes.NewValue(tftypes.String, "Integrated"),
			"queue_length":          tftypes.NewValue(tftypes.Number, 1000),
		}),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("nil readback after update must produce an error diagnostic")
	}
}

func TestWindowsIISAppPoolResource_Update_PasswordGatedByVersion(t *testing.T) {
	st := okIISAppPoolState("svc")
	st.IdentityType = "SpecificUser"
	newVersion := func(n int) map[string]tftypes.Value {
		return map[string]tftypes.Value{
			"identity_type":                tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_username":            tftypes.NewValue(tftypes.String, `CONTOSO\svc`),
			"identity_password_wo_version": tftypes.NewValue(tftypes.Number, float64(n)),
		}
	}
	// Version bump: password re-sent from config.
	fc := &fakeIISAppPoolClient{updateOut: st, readOut: st}
	r := &windowsIISAppPoolResource{pool: fc}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  apPlan(t, newVersion(2)),
		State: apState(t, newVersion(1)),
		Config: apConfig(t, map[string]tftypes.Value{
			"identity_type":                tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_username":            tftypes.NewValue(tftypes.String, `CONTOSO\svc`),
			"identity_password_wo":         tftypes.NewValue(tftypes.String, "new-pw"),
			"identity_password_wo_version": tftypes.NewValue(tftypes.Number, 2),
		}),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp.Diagnostics))
	}
	if fc.updateIn.Password != "new-pw" {
		t.Errorf("version bump must re-send the password, got %q", fc.updateIn.Password)
	}

	// Same version: password never re-sent, refresh path only.
	fc2 := &fakeIISAppPoolClient{updateOut: st, readOut: st}
	r2 := &windowsIISAppPoolResource{pool: fc2}
	resp2 := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r2.Update(context.Background(), resource.UpdateRequest{
		Plan:   apPlan(t, newVersion(1)),
		State:  apState(t, newVersion(1)),
		Config: apConfig(t, newVersion(1)),
	}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp2.Diagnostics))
	}
	if fc2.updateIn.Name != "" {
		t.Errorf("no changes and no bump must refresh via Read, not Update (update got %+v)", fc2.updateIn)
	}
	if fc2.readName != "api" {
		t.Errorf("expected a refresh Read, got readName=%q", fc2.readName)
	}
}

func TestWindowsIISAppPoolResource_Update_IdentityChangeWithoutBumpFails(t *testing.T) {
	fc := &fakeIISAppPoolClient{updateOut: okIISAppPoolState("api")}
	r := &windowsIISAppPoolResource{pool: fc}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan: apPlan(t, map[string]tftypes.Value{
			"identity_type":     tftypes.NewValue(tftypes.String, "SpecificUser"),
			"identity_username": tftypes.NewValue(tftypes.String, `CONTOSO\svc`),
		}),
		State:  apState(t, nil),
		Config: apConfig(t, nil),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("adopting SpecificUser without a version bump must fail closed")
	}
	if fc.updateIn.Name != "" {
		t.Error("failed validation must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestWindowsIISAppPoolResource_Delete_HappyPath(t *testing.T) {
	fc := &fakeIISAppPoolClient{}
	r := &windowsIISAppPoolResource{pool: fc}

	req := resource.DeleteRequest{State: apState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp.Diagnostics))
	}
	if fc.deleteName != "api" {
		t.Errorf("delete name = %q, want api", fc.deleteName)
	}
}

func TestWindowsIISAppPoolResource_Delete_InUse(t *testing.T) {
	fc := &fakeIISAppPoolClient{
		deleteErr: winclient.NewIISAppPoolError(winclient.IISAppPoolErrorInUse,
			"Cannot delete IIS application pool 'api': it is still referenced by site:Default Web Site. Move those sites or applications to another pool first.", nil, nil),
	}
	r := &windowsIISAppPoolResource{pool: fc}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: apState(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an in_use diagnostic")
	}
	joined := strings.Join(apDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "in_use") || !strings.Contains(joined, "Default Web Site") {
		t.Errorf("in_use diagnostic must name the kind and the referencing site, got:\n%s", joined)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsIISAppPoolResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakeIISAppPoolClient{readOut: okIISAppPoolState("api")}
	r := &windowsIISAppPoolResource{pool: fc}

	req := resource.ImportStateRequest{ID: "api"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", apDiagSummaries(resp.Diagnostics))
	}
	var model windowsIISAppPoolModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Name.ValueString() != "api" || model.ID.ValueString() != "api" {
		t.Errorf("unexpected imported state: name=%q id=%q", model.Name.ValueString(), model.ID.ValueString())
	}
	if !model.RecyclingSchedule.IsNull() {
		t.Error("imported schedule must start null (unmanaged)")
	}
	if !model.IdentityPasswordWO.IsNull() || !model.IdentityPasswordWOVersion.IsNull() {
		t.Error("imported password material must be null (cannot be imported)")
	}
}

func TestWindowsIISAppPoolResource_ImportState_InvalidID(t *testing.T) {
	for _, id := range []string{"", "a/b", "a*b"} {
		r := &windowsIISAppPoolResource{pool: &fakeIISAppPoolClient{readOut: okIISAppPoolState("api")}}
		req := resource.ImportStateRequest{ID: id}
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
		r.ImportState(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("expected diagnostic error for import ID %q", id)
		}
	}
	// Leading/trailing spaces trim to a valid name and are accepted.
	r := &windowsIISAppPoolResource{pool: &fakeIISAppPoolClient{readOut: okIISAppPoolState("api")}}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: " api "}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("import ID %q trims to a valid name and should be accepted: %v", " api ", apDiagSummaries(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// Timeouts / Configure
// ---------------------------------------------------------------------------

func TestWindowsIISAppPoolSchema_HasTimeoutsBlock(t *testing.T) {
	s := windowsIISAppPoolSchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block: CRUD must be time-bounded")
	}
}

// hangIISAppPoolClient simulates a stalled transport: Create blocks until
// the passed context is done, then returns the context error.
type hangIISAppPoolClient struct {
	fakeIISAppPoolClient
}

func (f *hangIISAppPoolClient) Create(ctx context.Context, _ winclient.IISAppPoolInput) (*winclient.IISAppPoolState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// apTimeoutsRaw builds the raw tftypes value for a timeouts block carrying
// the given per-operation durations.
func apTimeoutsRaw(durations map[string]string) tftypes.Value {
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

func TestWindowsIISAppPoolResource_Create_StalledTransportIsBounded(t *testing.T) {
	r := &windowsIISAppPoolResource{pool: &hangIISAppPoolClient{}}

	req := resource.CreateRequest{
		Plan: apPlan(t, map[string]tftypes.Value{
			"timeouts": apTimeoutsRaw(map[string]string{"create": "200ms"}),
		}),
		Config: apConfig(t, nil),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsIISAppPoolSchemaDefinition(context.Background())}}

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

func TestWindowsIISAppPoolResource_Configure(t *testing.T) {
	r := &windowsIISAppPoolResource{}
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

func TestIISAppPoolErrorDiag_InUse(t *testing.T) {
	var diags diag.Diagnostics
	addIISAppPoolDiag(&diags, "Error deleting Windows IIS application pool",
		winclient.NewIISAppPoolError(winclient.IISAppPoolErrorInUse, "still referenced by site:X.", nil, nil))
	if !diags.HasError() {
		t.Fatal("expected an error diagnostic")
	}
	joined := strings.Join(apDiagSummaries(diags), "\n")
	if !strings.Contains(joined, "in_use") || !strings.Contains(joined, "site:X") {
		t.Errorf("in_use diag must keep kind + guidance, got:\n%s", joined)
	}
}
