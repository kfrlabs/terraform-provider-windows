// Package provider — unit tests for the windows_power_plan resource.
//
// These tests exercise the schema, validators, settings projection and
// CRUD handlers without SSH. A fakePowerPlanClient is injected into
// windowsPowerPlanResource.pp.
//
// Edge cases covered (issue #288):
//
//	Metadata                 — returns "windows_power_plan"
//	Schema                   — plan Required (GUID or alias), settings
//	                           Optional+Computed, create_if_missing /
//	                           restore_on_destroy defaults, timeouts block,
//	                           computed plan_guid/plan_name
//	Plan validator           — GUID (any case) or alias; names rejected
//	No canonical modifier    — the configured plan spelling is preserved
//	                           in state when it resolves to the observed
//	                           active GUID (genuine drift surfaces the GUID)
//	Config validator        — each setting needs ac_value or dc_value
//	Settings projection      — only configured values sent, unknown defers
//	State projection        — plan canonicalised, intent preserved, id
//	                           fallback
//	Create (happy)           — snapshot captured when restore_on_destroy,
//	                           owned duplicated plan recorded
//	Create (plan_not_found)  — diagnostic error
//	Create (unsupported)     — diagnostic error (e.g. containers)
//	Read (happy)             — state refreshed, intent preserved
//	Read (error)             — diagnostic error (singleton never removed)
//	Update (happy)           — forwards delta, leaves snapshot untouched
//	Delete (default)         — no remote change
//	Delete (restore)         — re-applies snapshot; missing snapshot warns
//	Delete (owned cleanup)   — inactive duplicated plan deleted, active
//	                           owned plan warns and stays
//	ImportState (happy)      — snapshot captured, any non-empty ID
//	ImportState (invalid)    — empty ID diagnostic error
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
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakePowerPlanClient
// ---------------------------------------------------------------------------

type fakePowerPlanClient struct {
	readOut  *winclient.PowerPlanState
	readErr  error
	readKeys []winclient.PowerPlanSettingKey

	applyIn  winclient.PowerPlanInput
	applyOut *winclient.PowerPlanState
	applyErr error

	listOut *winclient.PowerPlanListState
	listErr error

	restoreIn  winclient.PowerPlanSnapshot
	restoreOut *winclient.PowerPlanState
	restoreErr error

	deleted   []string
	deleteErr error
}

func (f *fakePowerPlanClient) Read(_ context.Context, keys []winclient.PowerPlanSettingKey) (*winclient.PowerPlanState, error) {
	f.readKeys = keys
	return f.readOut, f.readErr
}

func (f *fakePowerPlanClient) Apply(_ context.Context, in winclient.PowerPlanInput) (*winclient.PowerPlanState, error) {
	f.applyIn = in
	return f.applyOut, f.applyErr
}

func (f *fakePowerPlanClient) List(_ context.Context) (*winclient.PowerPlanListState, error) {
	return f.listOut, f.listErr
}

func (f *fakePowerPlanClient) Restore(_ context.Context, snap winclient.PowerPlanSnapshot) (*winclient.PowerPlanState, error) {
	f.restoreIn = snap
	return f.restoreOut, f.restoreErr
}

func (f *fakePowerPlanClient) DeletePlan(_ context.Context, guid string) error {
	f.deleted = append(f.deleted, guid)
	return f.deleteErr
}

func ppInt64(v int64) *int64 { return &v }

func okPowerPlanState() *winclient.PowerPlanState {
	return &winclient.PowerPlanState{
		MachineID: "11111111-2222-3333-4444-555555555555",
		PlanGUID:  winclient.PowerPlanHighPerformanceGUID,
		PlanName:  "High performance",
		Settings: []winclient.PowerPlanSettingState{{
			SubgroupGUID: "238c9fa8-0aad-41ed-83f4-97be242c8f20",
			SettingGUID:  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
			ACValue:      ppInt64(0),
			DCValue:      ppInt64(0),
		}},
	}
}

func okPowerPlanList() *winclient.PowerPlanListState {
	return &winclient.PowerPlanListState{
		MachineID:      "11111111-2222-3333-4444-555555555555",
		ActivePlanGUID: winclient.PowerPlanHighPerformanceGUID,
		ActivePlanName: "High performance",
		Plans: []winclient.PowerPlanInfo{
			{GUID: winclient.PowerPlanBalancedGUID, Name: "Balanced"},
			{GUID: winclient.PowerPlanHighPerformanceGUID, Name: "High performance", IsActive: true},
		},
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_power_plan schema
// ---------------------------------------------------------------------------

func ppSettingObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"subgroup": tftypes.String,
		"setting":  tftypes.String,
		"ac_value": tftypes.Number,
		"dc_value": tftypes.Number,
	}}
}

func ppObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"plan":               tftypes.String,
		"settings":           tftypes.List{ElementType: ppSettingObjType()},
		"create_if_missing":  tftypes.Bool,
		"restore_on_destroy": tftypes.Bool,
		"plan_guid":          tftypes.String,
		"plan_name":          tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func ppNullStr() tftypes.Value { return tftypes.NewValue(tftypes.String, nil) }

func ppNullList() tftypes.Value {
	return tftypes.NewValue(tftypes.List{ElementType: ppSettingObjType()}, nil)
}

func ppNullTimeouts() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func ppSettingVal(subgroup, setting string, ac, dc any) tftypes.Value {
	acV := tftypes.NewValue(tftypes.Number, nil)
	if ac != nil {
		acV = tftypes.NewValue(tftypes.Number, ac)
	}
	dcV := tftypes.NewValue(tftypes.Number, nil)
	if dc != nil {
		dcV = tftypes.NewValue(tftypes.Number, dc)
	}
	return tftypes.NewValue(ppSettingObjType(), map[string]tftypes.Value{
		"subgroup": tftypes.NewValue(tftypes.String, subgroup),
		"setting":  tftypes.NewValue(tftypes.String, setting),
		"ac_value": acV,
		"dc_value": dcV,
	})
}

func ppObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                 ppNullStr(),
		"plan":               tftypes.NewValue(tftypes.String, winclient.PowerPlanHighPerformanceGUID),
		"settings":           ppNullList(),
		"create_if_missing":  tftypes.NewValue(tftypes.Bool, false),
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, false),
		"plan_guid":          ppNullStr(),
		"plan_name":          ppNullStr(),
		"timeouts":           ppNullTimeouts(),
	}
}

func ppObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := ppObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(ppObjType(), base)
}

func ppState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsPowerPlanSchemaDefinition(context.Background())
	return tfsdk.State{Raw: ppObj(overrides), Schema: s}
}

func ppPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsPowerPlanSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: ppObj(overrides), Schema: s}
}

func ppConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsPowerPlanSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: ppObj(overrides), Schema: s}
}

func ppDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// allocPowerPlanPrivate allocates the framework private-state value on a
// response or request so handler tests can capture snapshots without the
// framework server.
func allocPowerPlanPrivate(t *testing.T, holder any) {
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

func TestWindowsPowerPlanResource_Metadata(t *testing.T) {
	r := &windowsPowerPlanResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_power_plan" {
		t.Errorf("TypeName = %q, want windows_power_plan", resp.TypeName)
	}
}

func TestWindowsPowerPlanResource_Schema(t *testing.T) {
	s := windowsPowerPlanSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "plan", "settings", "create_if_missing", "restore_on_destroy",
		"plan_guid", "plan_name", "timeouts",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	planAttr, ok := s.Attributes["plan"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", planAttr)
	}
	if !planAttr.Required {
		t.Error("plan must be Required")
	}
	if len(planAttr.Validators) == 0 {
		t.Error("plan must carry the GUID-or-alias validator")
	}
	settingsAttr, ok := s.Attributes["settings"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("expected schema.ListNestedAttribute, got %T", settingsAttr)
	}
	if !settingsAttr.Optional || !settingsAttr.Computed {
		t.Error("settings must be Optional+Computed (only listed settings are managed)")
	}
	for _, n := range []string{"create_if_missing", "restore_on_destroy"} {
		a, ok := s.Attributes[n].(schema.BoolAttribute)
		if !ok {
			t.Fatalf("expected schema.BoolAttribute, got %T", a)
		}
		if !a.Optional || !a.Computed {
			t.Errorf("%s must be Optional+Computed (default false)", n)
		}
	}
	for _, n := range []string{"plan_guid", "plan_name"} {
		a, ok := s.Attributes[n].(schema.StringAttribute)
		if !ok {
			t.Fatalf("expected schema.StringAttribute, got %T", a)
		}
		if !a.Computed || a.Optional || a.Required {
			t.Errorf("%s must be Computed-only", n)
		}
	}
}

// ---------------------------------------------------------------------------
// Plan validator and canonical modifier
// ---------------------------------------------------------------------------

func TestPowerPlanReferenceValidator(t *testing.T) {
	s := windowsPowerPlanSchemaDefinition(context.Background())
	planAttr, ok := s.Attributes["plan"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", planAttr)
	}
	if len(planAttr.Validators) == 0 {
		t.Fatal("plan must carry a validator")
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue(winclient.PowerPlanHighPerformanceGUID), false},
		{types.StringValue("8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C"), false},
		{types.StringValue("high_performance"), false},
		{types.StringValue("High_Performance"), false},
		{types.StringValue("ultimate_performance"), false},
		{types.StringValue("High performance"), true},
		{types.StringValue("Power saver (recommended)"), true},
		{types.StringValue(""), true},
		{types.StringNull(), false},
		{types.StringUnknown(), false},
	} {
		resp := &validator.StringResponse{}
		planAttr.Validators[0].ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("plan"), ConfigValue: tc.val,
		}, resp)
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("plan %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestPowerPlanNoCanonicalModifier(t *testing.T) {
	s := windowsPowerPlanSchemaDefinition(context.Background())
	planAttr, ok := s.Attributes["plan"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", planAttr)
	}
	if len(planAttr.PlanModifiers) != 0 {
		t.Errorf("plan must carry no plan modifiers (the configured spelling is preserved in state at apply time), got %d", len(planAttr.PlanModifiers))
	}
}

func TestPowerPlanStateToModel_PreservesPlanSpelling(t *testing.T) {
	newPrior := func(plan string) windowsPowerPlanModel {
		return windowsPowerPlanModel{
			Plan:             types.StringValue(plan),
			CreateIfMissing:  types.BoolValue(false),
			RestoreOnDestroy: types.BoolValue(false),
		}
	}
	for _, tc := range []struct {
		name     string
		prior    string
		observed string
		want     string
	}{
		{"alias preserved", "high_performance", winclient.PowerPlanHighPerformanceGUID, "high_performance"},
		{"alias case preserved", "High_Performance", winclient.PowerPlanHighPerformanceGUID, "High_Performance"},
		{"guid case preserved", "8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C", winclient.PowerPlanHighPerformanceGUID, "8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C"},
		{"genuine drift surfaces observed guid", "high_performance", winclient.PowerPlanBalancedGUID, winclient.PowerPlanBalancedGUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := okPowerPlanState()
			st.PlanGUID = tc.observed
			m, diags := powerPlanStateToModel(st, newPrior(tc.prior))
			if diags.HasError() {
				t.Fatalf("stateToModel: %v", diags)
			}
			if m.Plan.ValueString() != tc.want {
				t.Errorf("plan = %q, want %q", m.Plan.ValueString(), tc.want)
			}
			if m.PlanGUID.ValueString() != tc.observed {
				t.Errorf("plan_guid = %q, want observed %q", m.PlanGUID.ValueString(), tc.observed)
			}
		})
	}
	// No usable prior ref (e.g. import): the observed GUID is surfaced.
	st := okPowerPlanState()
	m, diags := powerPlanStateToModel(st, windowsPowerPlanModel{})
	if diags.HasError() {
		t.Fatalf("stateToModel: %v", diags)
	}
	if m.Plan.ValueString() != st.PlanGUID {
		t.Errorf("plan without prior = %q, want observed %q", m.Plan.ValueString(), st.PlanGUID)
	}
}

// ---------------------------------------------------------------------------
// Config validator
// ---------------------------------------------------------------------------

func TestWindowsPowerPlanConfigValidator(t *testing.T) {
	r, ok := NewWindowsPowerPlanResource().(*windowsPowerPlanResource)
	if !ok {
		t.Fatalf("expected *windowsPowerPlanResource, got %T", r)
	}
	var v windowsPowerPlanConfigValidator
	for _, cv := range r.ConfigValidators(context.Background()) {
		if ev, ok := cv.(windowsPowerPlanConfigValidator); ok {
			v = ev
		}
	}
	settingsList := func(vals ...tftypes.Value) tftypes.Value {
		return tftypes.NewValue(tftypes.List{ElementType: ppSettingObjType()}, vals)
	}
	cases := []struct {
		name      string
		overrides map[string]tftypes.Value
		wantErr   bool
	}{
		{"ac only ok", map[string]tftypes.Value{
			"settings": settingsList(ppSettingVal("SUB_DISK", "DISKIDLE", 0, nil)),
		}, false},
		{"dc only ok", map[string]tftypes.Value{
			"settings": settingsList(ppSettingVal("SUB_SLEEP", "STANDBYIDLE", nil, 0)),
		}, false},
		{"both ok", map[string]tftypes.Value{
			"settings": settingsList(ppSettingVal("SUB_DISK", "DISKIDLE", 0, 0)),
		}, false},
		{"neither errors", map[string]tftypes.Value{
			"settings": settingsList(ppSettingVal("SUB_DISK", "DISKIDLE", nil, nil)),
		}, true},
		{"unset clean", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &resource.ValidateConfigResponse{}
			v.ValidateResource(context.Background(), resource.ValidateConfigRequest{
				Config: ppConfig(t, tc.overrides),
			}, resp)
			if resp.Diagnostics.HasError() != tc.wantErr {
				t.Errorf("wantErr=%v, diagnostics: %v", tc.wantErr, ppDiagSummaries(resp.Diagnostics))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Settings projection: only configured values sent
// ---------------------------------------------------------------------------

func TestPowerPlanModelToInput_OnlyConfigured(t *testing.T) {
	ctx := context.Background()
	var m windowsPowerPlanModel
	if diags := ppPlan(t, nil).Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	in, diags := powerPlanModelToInput(ctx, m)
	if diags.HasError() {
		t.Fatalf("modelToInput: %v", diags)
	}
	if len(in.Settings) != 0 {
		t.Errorf("null settings must produce no inputs, got %+v", in.Settings)
	}
}

func TestPowerPlanModelToInput_Forwards(t *testing.T) {
	ctx := context.Background()
	var m windowsPowerPlanModel
	plan := ppPlan(t, map[string]tftypes.Value{
		"plan": tftypes.NewValue(tftypes.String, "high_performance"),
		"settings": tftypes.NewValue(tftypes.List{ElementType: ppSettingObjType()}, []tftypes.Value{
			ppSettingVal("SUB_DISK", "DISKIDLE", 0, nil),
		}),
		"create_if_missing": tftypes.NewValue(tftypes.Bool, true),
	})
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	in, diags := powerPlanModelToInput(ctx, m)
	if diags.HasError() {
		t.Fatalf("modelToInput: %v", diags)
	}
	if in.Plan != "high_performance" || !in.CreateIfMissing {
		t.Errorf("plan/flag not forwarded: %+v", in)
	}
	if len(in.Settings) != 1 {
		t.Fatalf("want 1 setting, got %+v", in.Settings)
	}
	s := in.Settings[0]
	if s.Subgroup != "SUB_DISK" || s.Setting != "DISKIDLE" {
		t.Errorf("setting refs not forwarded: %+v", s)
	}
	if s.ACValue == nil || *s.ACValue != 0 || s.DCValue != nil {
		t.Errorf("AC/DC not forwarded (DC must stay nil): %+v", s)
	}
}

func TestPowerPlanModelToInput_UnknownDefers(t *testing.T) {
	m := windowsPowerPlanModel{
		Plan:     types.StringValue("balanced"),
		Settings: types.ListUnknown(powerPlanSettingElementObjectType()),
	}
	in, diags := powerPlanModelToInput(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("modelToInput: %v", diags)
	}
	if len(in.Settings) != 0 {
		t.Errorf("unknown settings must stay unmanaged, got %+v", in.Settings)
	}
}

// ---------------------------------------------------------------------------
// State projection
// ---------------------------------------------------------------------------

func TestPowerPlanStateToModel(t *testing.T) {
	m, diags := powerPlanStateToModel(okPowerPlanState(), windowsPowerPlanModel{})
	if diags.HasError() {
		t.Fatalf("stateToModel: %v", diags)
	}
	if m.ID.ValueString() != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("id = %q, want machine ID", m.ID.ValueString())
	}
	if m.Plan.ValueString() != winclient.PowerPlanHighPerformanceGUID || m.PlanGUID.ValueString() != winclient.PowerPlanHighPerformanceGUID {
		t.Errorf("plan/plan_guid = %q/%q, want canonical GUID", m.Plan.ValueString(), m.PlanGUID.ValueString())
	}
	if m.PlanName.ValueString() != "High performance" {
		t.Errorf("plan_name = %q", m.PlanName.ValueString())
	}
	var elems []windowsPowerPlanSettingModel
	if d := m.Settings.ElementsAs(context.Background(), &elems, false); d.HasError() {
		t.Fatalf("settings ElementsAs: %v", d)
	}
	if len(elems) != 1 || elems[0].Subgroup.ValueString() != "238c9fa8-0aad-41ed-83f4-97be242c8f20" {
		t.Errorf("settings not projected: %+v", elems)
	}
	if m.RestoreOnDestroy.ValueBool() || m.CreateIfMissing.ValueBool() {
		t.Error("intent flags must default to false without prior state")
	}
}

func TestPowerPlanStateToModel_PreservesIntentAndIDFallback(t *testing.T) {
	prior := windowsPowerPlanModel{
		ID:               types.StringValue("prior-id"),
		CreateIfMissing:  types.BoolValue(true),
		RestoreOnDestroy: types.BoolValue(true),
		Timeouts:         mustPowerPlanTimeouts(t, map[string]string{"create": "5m"}),
	}
	st := okPowerPlanState()
	st.MachineID = ""
	m, diags := powerPlanStateToModel(st, prior)
	if diags.HasError() {
		t.Fatalf("stateToModel: %v", diags)
	}
	if m.ID.ValueString() != "prior-id" {
		t.Errorf("empty MachineGuid must keep the anchored ID, got %q", m.ID.ValueString())
	}
	if !m.CreateIfMissing.ValueBool() || !m.RestoreOnDestroy.ValueBool() {
		t.Error("intent flags must be preserved across the projection")
	}
	got, d := m.Timeouts.Create(context.Background(), powerPlanDefaultTimeout)
	if d.HasError() {
		t.Fatalf("Timeouts.Create: %v", d)
	}
	if got != 5*time.Minute {
		t.Errorf("Timeouts not preserved: create = %v", got)
	}
}

func TestPowerPlanStateToModel_EmptyMachineIDNoPriorErrors(t *testing.T) {
	st := okPowerPlanState()
	st.MachineID = ""
	_, diags := powerPlanStateToModel(st, windowsPowerPlanModel{})
	if !diags.HasError() {
		t.Fatal("expected error diagnostic when MachineGuid is missing with no prior ID")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsPowerPlanResource_Create_HappyPath(t *testing.T) {
	fc := &fakePowerPlanClient{
		readOut:  okPowerPlanState(),
		applyOut: okPowerPlanState(),
	}
	r := &windowsPowerPlanResource{pp: fc}

	req := resource.CreateRequest{Plan: ppPlan(t, map[string]tftypes.Value{
		"settings": tftypes.NewValue(tftypes.List{ElementType: ppSettingObjType()}, []tftypes.Value{
			ppSettingVal("SUB_DISK", "DISKIDLE", 0, 0),
		}),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if fc.applyIn.Plan != winclient.PowerPlanHighPerformanceGUID {
		t.Errorf("apply plan = %q, want canonical GUID", fc.applyIn.Plan)
	}
	if len(fc.applyIn.Settings) != 1 || fc.applyIn.Settings[0].Setting != "DISKIDLE" {
		t.Errorf("apply settings wrong: %+v", fc.applyIn.Settings)
	}
	if len(fc.readKeys) != 0 {
		t.Errorf("restore disabled: no pre-read expected, got %+v", fc.readKeys)
	}
	var model windowsPowerPlanModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("id = %q, want machine ID", model.ID.ValueString())
	}
	if model.PlanGUID.ValueString() != winclient.PowerPlanHighPerformanceGUID {
		t.Errorf("plan_guid = %q", model.PlanGUID.ValueString())
	}
}

func TestWindowsPowerPlanResource_Create_SnapshotOnlyWhenRestore(t *testing.T) {
	fc := &fakePowerPlanClient{
		readOut:  okPowerPlanState(),
		applyOut: okPowerPlanState(),
	}
	r := &windowsPowerPlanResource{pp: fc}
	req := resource.CreateRequest{Plan: ppPlan(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	allocPowerPlanPrivate(t, resp)
	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	raw, diags := resp.Private.GetKey(context.Background(), powerPlanPrivateKey)
	if diags.HasError() {
		t.Fatalf("GetKey: %v", diags)
	}
	if len(raw) == 0 {
		t.Fatal("expected a snapshot in private state")
	}
	var snap winclient.PowerPlanSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.PlanGUID != winclient.PowerPlanHighPerformanceGUID {
		t.Errorf("snapshot plan wrong: %+v", snap)
	}

	// Default (false): no snapshot.
	fc2 := &fakePowerPlanClient{applyOut: okPowerPlanState()}
	r2 := &windowsPowerPlanResource{pp: fc2}
	resp2 := &resource.CreateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	r2.Create(context.Background(), resource.CreateRequest{Plan: ppPlan(t, nil)}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp2.Diagnostics))
	}
	if raw, _ := resp2.Private.GetKey(context.Background(), powerPlanPrivateKey); len(raw) != 0 {
		t.Error("restore disabled: no snapshot expected in private state")
	}
}

func TestWindowsPowerPlanResource_Create_RecordsDuplicatedPlan(t *testing.T) {
	duped := okPowerPlanState()
	duped.DuplicatedPlanGUID = "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6"
	fc := &fakePowerPlanClient{applyOut: duped}
	r := &windowsPowerPlanResource{pp: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	allocPowerPlanPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: ppPlan(t, map[string]tftypes.Value{
		"plan":              tftypes.NewValue(tftypes.String, "ultimate_performance"),
		"create_if_missing": tftypes.NewValue(tftypes.Bool, true),
	})}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	raw, diags := resp.Private.GetKey(context.Background(), powerPlanPrivateKey)
	if diags.HasError() || len(raw) == 0 {
		t.Fatalf("expected owned-plan record in private state: %v", diags)
	}
	var snap winclient.PowerPlanSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.OwnedPlanGUID != "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6" {
		t.Errorf("owned plan not recorded: %+v", snap)
	}
}

func TestWindowsPowerPlanResource_Create_PlanNotFound(t *testing.T) {
	fc := &fakePowerPlanClient{
		applyErr: winclient.NewPowerPlanError(winclient.PowerPlanErrorPlanNotFound, "power plan missing was not found", nil, nil),
	}
	r := &windowsPowerPlanResource{pp: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: ppPlan(t, nil)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("missing plan must error, not converge")
	}
	joined := strings.Join(ppDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "plan_not_found") {
		t.Errorf("diagnostic must name the kind, got:\n%s", joined)
	}
}

func TestWindowsPowerPlanResource_Create_Unsupported(t *testing.T) {
	fc := &fakePowerPlanClient{
		applyErr: winclient.NewPowerPlanError(winclient.PowerPlanErrorUnsupported,
			"powercfg.exe is not available on the target host", nil, nil),
	}
	r := &windowsPowerPlanResource{pp: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: ppPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an unsupported diagnostic")
	}
	joined := strings.Join(ppDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "unsupported") {
		t.Errorf("diagnostic must name the kind, got:\n%s", joined)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsPowerPlanResource_Read_HappyPath(t *testing.T) {
	live := okPowerPlanState()
	live.PlanGUID = winclient.PowerPlanBalancedGUID
	live.PlanName = "Balanced"
	fc := &fakePowerPlanClient{readOut: live}
	r := &windowsPowerPlanResource{pp: fc}

	req := resource.ReadRequest{State: ppState(t, nil)}
	resp := &resource.ReadResponse{State: ppState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if len(fc.readKeys) != 0 {
		// Base state carries null settings: no keys to refresh.
		t.Errorf("unexpected read keys: %+v", fc.readKeys)
	}
	var model windowsPowerPlanModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	// Drift surfaces: the observed balanced plan replaces the
	// high_performance state plan.
	if model.Plan.ValueString() != winclient.PowerPlanBalancedGUID || model.PlanGUID.ValueString() != winclient.PowerPlanBalancedGUID {
		t.Errorf("drift not surfaced: plan=%q plan_guid=%q", model.Plan.ValueString(), model.PlanGUID.ValueString())
	}
	if model.PlanName.ValueString() != "Balanced" {
		t.Errorf("plan_name = %q", model.PlanName.ValueString())
	}
}

func TestWindowsPowerPlanResource_Read_ErrorIsDiagnostic(t *testing.T) {
	fc := &fakePowerPlanClient{
		readErr: winclient.NewPowerPlanError(winclient.PowerPlanErrorAccessDenied, "denied", nil, nil),
	}
	r := &windowsPowerPlanResource{pp: fc}

	req := resource.ReadRequest{State: ppState(t, nil)}
	resp := &resource.ReadResponse{State: ppState(t, nil)}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("access_denied must surface a diagnostic, not remove the singleton")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestWindowsPowerPlanResource_Update_HappyPath(t *testing.T) {
	st := okPowerPlanState()
	fc := &fakePowerPlanClient{applyOut: st}
	r := &windowsPowerPlanResource{pp: fc}

	req := resource.UpdateRequest{
		Plan: ppPlan(t, map[string]tftypes.Value{
			"settings": tftypes.NewValue(tftypes.List{ElementType: ppSettingObjType()}, []tftypes.Value{
				ppSettingVal("SUB_DISK", "DISKIDLE", 0, 0),
			}),
		}),
		State: ppState(t, nil),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if len(fc.applyIn.Settings) != 1 || fc.applyIn.Settings[0].DCValue == nil {
		t.Errorf("update must forward the delta, got %+v", fc.applyIn.Settings)
	}
}

func TestWindowsPowerPlanResource_Delete_DefaultNoRemoteChange(t *testing.T) {
	fc := &fakePowerPlanClient{restoreOut: okPowerPlanState()}
	r := &windowsPowerPlanResource{pp: fc}

	req := resource.DeleteRequest{State: ppState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.PlanGUID != "" {
		t.Errorf("default delete must make no remote change, got restore of %+v", fc.restoreIn)
	}
	if len(fc.deleted) != 0 {
		t.Errorf("default delete must not delete plans, got %v", fc.deleted)
	}
}

func seedPowerPlanSnapshot(t *testing.T, req *resource.DeleteRequest, snap winclient.PowerPlanSnapshot) {
	t.Helper()
	allocPowerPlanPrivate(t, req)
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if diags := req.Private.SetKey(context.Background(), powerPlanPrivateKey, raw); diags.HasError() {
		t.Fatalf("seed snapshot: %v", diags)
	}
}

func TestWindowsPowerPlanResource_Delete_Restore(t *testing.T) {
	restored := okPowerPlanState()
	restored.PlanGUID = winclient.PowerPlanBalancedGUID
	fc := &fakePowerPlanClient{restoreOut: restored, readOut: restored}
	r := &windowsPowerPlanResource{pp: fc}

	state := ppState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	seedPowerPlanSnapshot(t, &req, winclient.PowerPlanSnapshot{
		PlanGUID: winclient.PowerPlanBalancedGUID,
		Settings: okPowerPlanState().Settings,
	})
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.PlanGUID != winclient.PowerPlanBalancedGUID {
		t.Errorf("restore must re-apply the captured snapshot verbatim, got %+v", fc.restoreIn)
	}
}

func TestWindowsPowerPlanResource_Delete_RestoreMissingSnapshotWarns(t *testing.T) {
	fc := &fakePowerPlanClient{restoreOut: okPowerPlanState()}
	r := &windowsPowerPlanResource{pp: fc}

	state := ppState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	// No snapshot seeded (Private is nil, which GetKey tolerates as "no
	// snapshot"): warn, don't error or restore.
	req := resource.DeleteRequest{State: state}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing snapshot must warn, not error: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.PlanGUID != "" {
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

func TestWindowsPowerPlanResource_Delete_CorruptSnapshotWarns(t *testing.T) {
	fc := &fakePowerPlanClient{restoreOut: okPowerPlanState()}
	r := &windowsPowerPlanResource{pp: fc}

	state := ppState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	allocPowerPlanPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), powerPlanPrivateKey, []byte(`"corrupt"`)); diags.HasError() {
		t.Fatalf("seed corrupt snapshot: %v", diags)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("corrupt snapshot must warn, not error: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.PlanGUID != "" {
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

func TestWindowsPowerPlanResource_Delete_OwnedPlanInactiveDeleted(t *testing.T) {
	// Snapshot plan restored (balanced); the owned duplicated plan is
	// inactive afterwards and must be deleted.
	restored := okPowerPlanState()
	restored.PlanGUID = winclient.PowerPlanBalancedGUID
	fc := &fakePowerPlanClient{restoreOut: restored, readOut: restored}
	r := &windowsPowerPlanResource{pp: fc}

	state := ppState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	seedPowerPlanSnapshot(t, &req, winclient.PowerPlanSnapshot{
		PlanGUID:      winclient.PowerPlanBalancedGUID,
		OwnedPlanGUID: "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6",
	})
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if len(fc.deleted) != 1 || fc.deleted[0] != "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6" {
		t.Errorf("inactive owned plan must be deleted, got %v", fc.deleted)
	}
}

func TestWindowsPowerPlanResource_Delete_OwnedPlanActiveWarns(t *testing.T) {
	// The owned duplicated plan is still active: it cannot be deleted
	// while active, so Delete warns and leaves it in place.
	active := okPowerPlanState()
	active.PlanGUID = "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6"
	fc := &fakePowerPlanClient{readOut: active}
	r := &windowsPowerPlanResource{pp: fc}

	state := ppState(t, nil)
	req := resource.DeleteRequest{State: state}
	seedPowerPlanSnapshot(t, &req, winclient.PowerPlanSnapshot{
		OwnedPlanGUID: "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6",
	})
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("active owned plan must warn, not error: %v", ppDiagSummaries(resp.Diagnostics))
	}
	if len(fc.deleted) != 0 {
		t.Errorf("active owned plan must not be deleted, got %v", fc.deleted)
	}
	foundWarn := false
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Error("active owned plan must warn")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsPowerPlanResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakePowerPlanClient{readOut: okPowerPlanState()}
	r := &windowsPowerPlanResource{pp: fc}

	req := resource.ImportStateRequest{ID: "current"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	allocPowerPlanPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	var model windowsPowerPlanModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Plan.ValueString() != winclient.PowerPlanHighPerformanceGUID || model.ID.ValueString() != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("unexpected imported state: plan=%q id=%q", model.Plan.ValueString(), model.ID.ValueString())
	}
	if model.RestoreOnDestroy.ValueBool() || model.CreateIfMissing.ValueBool() {
		t.Error("imported intents must default to false")
	}
	raw, diags := resp.Private.GetKey(context.Background(), powerPlanPrivateKey)
	if diags.HasError() || len(raw) == 0 {
		t.Fatalf("import must capture the restore snapshot: %v", diags)
	}
}

func TestWindowsPowerPlanResource_ImportState_InvalidID(t *testing.T) {
	r := &windowsPowerPlanResource{pp: &fakePowerPlanClient{readOut: okPowerPlanState()}}
	req := resource.ImportStateRequest{ID: "   "}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	allocPowerPlanPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error for an empty import ID")
	}
}

// ---------------------------------------------------------------------------
// Timeouts: a stalled remote command must surface a bounded diagnostic
// ---------------------------------------------------------------------------

func TestWindowsPowerPlanSchema_HasTimeoutsBlock(t *testing.T) {
	s := windowsPowerPlanSchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block: CRUD must be time-bounded")
	}
}

// hangPowerPlanClient simulates a stalled transport: Apply blocks until the
// passed context is done, then returns the context error.
type hangPowerPlanClient struct {
	fakePowerPlanClient
}

func (f *hangPowerPlanClient) Apply(ctx context.Context, _ winclient.PowerPlanInput) (*winclient.PowerPlanState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// ppTimeoutsRaw builds the raw tftypes value for a timeouts block carrying
// the given per-operation durations.
func ppTimeoutsRaw(durations map[string]string) tftypes.Value {
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

func TestWindowsPowerPlanResource_Create_StalledTransportIsBounded(t *testing.T) {
	r := &windowsPowerPlanResource{pp: &hangPowerPlanClient{}}

	req := resource.CreateRequest{Plan: ppPlan(t, map[string]tftypes.Value{
		"timeouts": ppTimeoutsRaw(map[string]string{"create": "200ms"}),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}

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

func TestWindowsPowerPlanModel_PreservesTimeouts(t *testing.T) {
	ctx := context.Background()
	prior := windowsPowerPlanModel{
		Timeouts: mustPowerPlanTimeouts(t, map[string]string{"create": "5m"}),
	}
	m := prior
	got, diags := m.Timeouts.Create(ctx, powerPlanDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("Timeouts.Create: %v", diags)
	}
	if got != 5*time.Minute {
		t.Errorf("Timeouts not preserved through projection: create = %v, want 5m", got)
	}
}

// mustPowerPlanTimeouts decodes ppTimeoutsRaw through the resource schema,
// the same path the framework takes for real plans.
func mustPowerPlanTimeouts(t *testing.T, durations map[string]string) timeouts.Value {
	t.Helper()
	ctx := context.Background()
	plan := tfsdk.Plan{
		Schema: windowsPowerPlanSchemaDefinition(ctx),
		Raw: ppObj(map[string]tftypes.Value{
			"timeouts": ppTimeoutsRaw(durations),
		}),
	}
	var m windowsPowerPlanModel
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get timeouts: %v", diags)
	}
	return m.Timeouts
}

func TestPowerPlanErrorDiag_Kinds(t *testing.T) {
	for _, kind := range []winclient.PowerPlanErrorKind{
		winclient.PowerPlanErrorPlanNotFound,
		winclient.PowerPlanErrorSettingNotFound,
		winclient.PowerPlanErrorInvalidValue,
		winclient.PowerPlanErrorUnsupported,
		winclient.PowerPlanErrorAccessDenied,
		winclient.PowerPlanErrorUnknown,
	} {
		var diags diag.Diagnostics
		addPowerPlanDiag(&diags, "Error creating Windows power plan",
			winclient.NewPowerPlanError(kind, "boom", nil, map[string]string{"plan": "balanced"}))
		if !diags.HasError() {
			t.Fatalf("kind %q: expected an error diagnostic", kind)
		}
		joined := strings.Join(ppDiagSummaries(diags), "\n")
		if !strings.Contains(joined, string(kind)) {
			t.Errorf("kind %q: diagnostic must name the kind, got:\n%s", kind, joined)
		}
	}
}

func TestPowerPlanSnapshot_RoundTrip(t *testing.T) {
	ctx := context.Background()
	// setPowerPlanSnapshot/getPowerPlanSnapshot round-trip through
	// injectable closures so the JSON private-state format is pinned.
	store := map[string][]byte{}
	setKey := func(_ context.Context, k string, v []byte) diag.Diagnostics {
		store[k] = v
		return nil
	}
	getKey := func(_ context.Context, k string) ([]byte, diag.Diagnostics) {
		return store[k], nil
	}
	want := &winclient.PowerPlanSnapshot{
		PlanGUID:      winclient.PowerPlanBalancedGUID,
		Settings:      okPowerPlanState().Settings,
		OwnedPlanGUID: "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6",
	}
	if err := setPowerPlanSnapshot(ctx, setKey, want); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := getPowerPlanSnapshot(ctx, getKey)
	if !ok || got == nil {
		t.Fatal("expected a snapshot back")
	}
	if got.PlanGUID != winclient.PowerPlanBalancedGUID || got.OwnedPlanGUID != want.OwnedPlanGUID || len(got.Settings) != 1 {
		t.Errorf("snapshot round-trip lost data: %+v", got)
	}
	// Empty store: no snapshot, still ok.
	got, ok = getPowerPlanSnapshot(ctx, func(_ context.Context, _ string) ([]byte, diag.Diagnostics) {
		return nil, nil
	})
	if !ok || got != nil {
		t.Errorf("empty store must be (nil, true), got (%+v, %v)", got, ok)
	}
	// Corrupt JSON: not ok.
	got, ok = getPowerPlanSnapshot(ctx, func(_ context.Context, _ string) ([]byte, diag.Diagnostics) {
		return []byte("{nope"), nil
	})
	if ok {
		t.Errorf("corrupt snapshot must not be ok, got %+v", got)
	}
}

func TestPowerPlanStateToModel_PreservesConfiguredRefs(t *testing.T) {
	ctx := context.Background()
	// Prior (configured) refs use aliases; observed state carries GUIDs.
	// The projection must keep the aliases and only refresh AC/DC.
	prior := windowsPowerPlanModel{
		Settings: mustPowerPlanSettingsValue(t, []powerPlanSettingInput{
			{Subgroup: "SUB_DISK", Setting: "DISKIDLE", AC: 0},
		}),
	}
	observed := okPowerPlanState()
	// Simulate host reporting canonical GUIDs with a changed value.
	observed.Settings[0].SubgroupGUID = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
	observed.Settings[0].SettingGUID = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
	observed.Settings[0].ACValue = ppInt64(600)
	m, diags := powerPlanStateToModel(observed, prior)
	if diags.HasError() {
		t.Fatalf("stateToModel: %v", diags)
	}
	var elems []windowsPowerPlanSettingModel
	if d := m.Settings.ElementsAs(ctx, &elems, false); d.HasError() {
		t.Fatalf("settings ElementsAs: %v", d)
	}
	if len(elems) != 1 {
		t.Fatalf("want 1 setting, got %+v", elems)
	}
	if elems[0].Subgroup.ValueString() != "SUB_DISK" || elems[0].Setting.ValueString() != "DISKIDLE" {
		t.Errorf("configured refs not preserved: %+v", elems[0])
	}
	if elems[0].ACValue.ValueInt64() != 600 {
		t.Errorf("observed value not applied: %+v", elems[0])
	}
}

// powerPlanSettingInput is a test-only helper for building settings values.
type powerPlanSettingInput struct {
	Subgroup string
	Setting  string
	AC       any
	DC       any
}

func mustPowerPlanSettingsValue(t *testing.T, in []powerPlanSettingInput) types.List {
	t.Helper()
	vals := make([]attr.Value, 0, len(in))
	for _, s := range in {
		ac := types.Int64Null()
		if v, ok := s.AC.(int); ok {
			ac = types.Int64Value(int64(v))
		}
		dc := types.Int64Null()
		if v, ok := s.DC.(int); ok {
			dc = types.Int64Value(int64(v))
		}
		obj, d := types.ObjectValue(powerPlanSettingElementAttrTypes(), map[string]attr.Value{
			"subgroup": types.StringValue(s.Subgroup),
			"setting":  types.StringValue(s.Setting),
			"ac_value": ac,
			"dc_value": dc,
		})
		if d.HasError() {
			t.Fatalf("ObjectValue: %v", d)
		}
		vals = append(vals, obj)
	}
	lv, d := types.ListValue(powerPlanSettingElementObjectType(), vals)
	if d.HasError() {
		t.Fatalf("ListValue: %v", d)
	}
	return lv
}

func TestWindowsPowerPlanResource_Update_StaleOwnedCleaned(t *testing.T) {
	oldOwned := "11111111-2222-3333-4444-555555555555"
	newOwned := "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6"
	// Live host is on the new plan: the stale owned plan is inactive and
	// must be deleted before overwriting.
	live := okPowerPlanState()
	live.PlanGUID = newOwned
	live.DuplicatedPlanGUID = newOwned
	stale := okPowerPlanState()
	stale.PlanGUID = newOwned
	fc := &fakePowerPlanClient{readOut: stale, applyOut: live}
	r := &windowsPowerPlanResource{pp: fc}

	req := resource.UpdateRequest{
		Plan:  ppPlan(t, nil),
		State: ppState(t, nil),
	}
	allocPowerPlanPrivate(t, &req)
	seedSnapshot := winclient.PowerPlanSnapshot{
		PlanGUID:      winclient.PowerPlanBalancedGUID,
		OwnedPlanGUID: oldOwned,
	}
	rawSeed, err := json.Marshal(seedSnapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if diags := req.Private.SetKey(context.Background(), powerPlanPrivateKey, rawSeed); diags.HasError() {
		t.Fatalf("seed snapshot: %v", diags)
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	allocPowerPlanPrivate(t, resp)
	// Seed the response store with the same prior snapshot (Update reads
	// the snapshot from the response store after extension copies it
	// forward).
	seedPowerPlanSnapshotResp(t, resp, winclient.PowerPlanSnapshot{
		PlanGUID:      winclient.PowerPlanBalancedGUID,
		OwnedPlanGUID: oldOwned,
	})
	// The fake's pre-update read returns stale (active=new), so the stale
	// oldOwned is deletable.
	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	found := false
	for _, g := range fc.deleted {
		if strings.EqualFold(g, oldOwned) {
			found = true
		}
	}
	if !found {
		t.Errorf("stale owned plan %q must be deleted, got %v", oldOwned, fc.deleted)
	}
	raw, diags := resp.Private.GetKey(context.Background(), powerPlanPrivateKey)
	if diags.HasError() || len(raw) == 0 {
		t.Fatalf("expected snapshot in private state: %v", diags)
	}
	var snap winclient.PowerPlanSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot JSON: %v", err)
	}
	if !strings.EqualFold(snap.OwnedPlanGUID, newOwned) {
		t.Errorf("owned plan not overwritten with %q: %+v", newOwned, snap)
	}
}

func TestWindowsPowerPlanResource_Delete_ReadFailureWarns(t *testing.T) {
	fc := &fakePowerPlanClient{
		readErr: winclient.NewPowerPlanError(winclient.PowerPlanErrorUnknown, "ssh boom", nil, nil),
	}
	r := &windowsPowerPlanResource{pp: fc}
	req := resource.DeleteRequest{State: ppState(t, nil)}
	seedPowerPlanSnapshot(t, &req, winclient.PowerPlanSnapshot{
		OwnedPlanGUID: "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6",
	})
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("read failure must warn, not error: %v", ppDiagSummaries(resp.Diagnostics))
	}
	foundWarn := false
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Error("read failure during owned cleanup must warn")
	}
	if len(fc.deleted) != 0 {
		t.Errorf("no delete without a verified inactive plan, got %v", fc.deleted)
	}
}

func TestWindowsPowerPlanResource_Delete_RestoreErrorStillCleansUp(t *testing.T) {
	restored := okPowerPlanState()
	restored.PlanGUID = winclient.PowerPlanBalancedGUID
	fc := &fakePowerPlanClient{
		restoreErr: winclient.NewPowerPlanError(winclient.PowerPlanErrorUnknown, "restore boom", nil, nil),
		readOut:    restored,
	}
	r := &windowsPowerPlanResource{pp: fc}
	state := ppState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	seedPowerPlanSnapshot(t, &req, winclient.PowerPlanSnapshot{
		PlanGUID:      winclient.PowerPlanBalancedGUID,
		OwnedPlanGUID: "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6",
	})
	resp := &resource.DeleteResponse{}
	// Point the restored read at a non-owned active plan so cleanup runs.
	fc.readOut = restored
	r.Delete(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("restore failure must still error")
	}
	if len(fc.deleted) != 1 || fc.deleted[0] != "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6" {
		t.Errorf("cleanup must run after restore error, got %v", fc.deleted)
	}
}

func seedPowerPlanSnapshotResp(t *testing.T, resp *resource.UpdateResponse, snap winclient.PowerPlanSnapshot) {
	t.Helper()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if diags := resp.Private.SetKey(context.Background(), powerPlanPrivateKey, raw); diags.HasError() {
		t.Fatalf("seed snapshot: %v", diags)
	}
}

func TestWindowsPowerPlanResource_Update_ExtendsSnapshot(t *testing.T) {
	// Prior snapshot covers DISKIDLE only; the plan adds VIDEOIDLE. The
	// pre-Update read returns both values and the merged snapshot must
	// contain both keys.
	diskGUID := "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
	videoGUID := "7516b95f-f776-4464-8c53-06167f40cc99"
	pre := okPowerPlanState()
	pre.Settings = []winclient.PowerPlanSettingState{
		{SubgroupGUID: "238c9fa8-0aad-41ed-83f4-97be242c8f20", SettingGUID: diskGUID, ACValue: ppInt64(0)},
		{SubgroupGUID: "7516b95f-f776-4464-8c53-06167f40cc99", SettingGUID: videoGUID, ACValue: ppInt64(300)},
	}
	fc := &fakePowerPlanClient{readOut: pre, applyOut: okPowerPlanState()}
	r := &windowsPowerPlanResource{pp: fc}

	plan := ppPlan(t, map[string]tftypes.Value{
		"settings": tftypes.NewValue(tftypes.List{ElementType: ppSettingObjType()}, []tftypes.Value{
			ppSettingVal("SUB_DISK", "DISKIDLE", 0, nil),
			ppSettingVal("SUB_VIDEO", "VIDEOIDLE", 300, nil),
		}),
	})
	req := resource.UpdateRequest{Plan: plan, State: ppState(t, nil)}
	allocPowerPlanPrivate(t, &req)
	priorSnap := winclient.PowerPlanSnapshot{
		PlanGUID: winclient.PowerPlanBalancedGUID,
		Settings: []winclient.PowerPlanSettingState{
			{SubgroupGUID: "238c9fa8-0aad-41ed-83f4-97be242c8f20", SettingGUID: diskGUID, ACValue: ppInt64(0)},
		},
	}
	rawSeed, err := json.Marshal(priorSnap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if diags := req.Private.SetKey(context.Background(), powerPlanPrivateKey, rawSeed); diags.HasError() {
		t.Fatalf("seed snapshot: %v", diags)
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsPowerPlanSchemaDefinition(context.Background())}}
	allocPowerPlanPrivate(t, resp)
	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", ppDiagSummaries(resp.Diagnostics))
	}
	raw, diags := resp.Private.GetKey(context.Background(), powerPlanPrivateKey)
	if diags.HasError() || len(raw) == 0 {
		t.Fatalf("expected extended snapshot: %v", diags)
	}
	var snap winclient.PowerPlanSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot JSON: %v", err)
	}
	if len(snap.Settings) != 2 {
		t.Fatalf("extended snapshot must merge missing keys, got %+v", snap.Settings)
	}
}

func TestWindowsPowerPlanResource_Configure(t *testing.T) {
	r := &windowsPowerPlanResource{}
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
