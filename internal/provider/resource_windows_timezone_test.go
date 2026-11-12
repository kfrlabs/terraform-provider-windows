// Package provider — unit tests for the windows_timezone resource.
//
// These tests exercise the schema, validator, model projection and CRUD
// handlers without SSH. A fakeTimezoneClient is injected into
// windowsTimezoneResource.tz.
//
// Edge cases covered (issue #286):
//
//	Metadata                 — returns "windows_timezone"
//	Schema                   — timezone_id Required + "/" validator, in-place
//	                           (no RequiresReplace), restore default, timeouts
//	ID validator             — rejects "Europe/Paris" with an IANA hint,
//	                           accepts Windows IDs, skips null/unknown
//	Create (happy)           — snapshot captured when restore_on_destroy,
//	                           Set input forwarded, computed mapped
//	Create (no restore)      — snapshot skipped
//	Create (set error)       — diagnostic, nothing half-written
//	Create (mismatch)        — defensive post-Set mismatch errors
//	Create (tzautoupdate)    — warns when the service may move the zone
//	Read (happy)             — refreshes all computed, preserves intent,
//	                           machine change updates id (never removed)
//	Read (error)             — diagnostic
//	Update (happy)           — forwards delta, keeps snapshot intent
//	Delete (default)         — no remote change
//	Delete (restore)         — re-applies snapshot; missing snapshot warns;
//	                           restore failure errors
//	ImportState (happy)      — any ID accepted, snapshot captured
//	ImportState (empty)      — diagnostic error
package provider

import (
	"context"
	"encoding/json"
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
// fakeTimezoneClient
// ---------------------------------------------------------------------------

type fakeTimezoneClient struct {
	readOut *winclient.TimezoneState
	readErr error

	setIn    winclient.TimezoneInput
	setCalls int
	setOut   *winclient.TimezoneState
	setErr   error
}

func (f *fakeTimezoneClient) Read(_ context.Context) (*winclient.TimezoneState, error) {
	return f.readOut, f.readErr
}

func (f *fakeTimezoneClient) Set(_ context.Context, in winclient.TimezoneInput) (*winclient.TimezoneState, error) {
	f.setIn = in
	f.setCalls++
	return f.setOut, f.setErr
}

func okTimezoneState() *winclient.TimezoneState {
	return &winclient.TimezoneState{
		MachineID:                  "11111111-2222-3333-4444-555555555555",
		TimezoneID:                 "Romance Standard Time",
		DisplayName:                "(UTC+01:00) Brussels, Copenhagen, Madrid, Paris",
		BaseUTCOffset:              "+01:00",
		SupportsDaylightSavingTime: true,
		CurrentUTCOffset:           "+02:00",
		DaylightSavingDisabled:     false,
		TzautoupdateEnabled:        false,
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_timezone schema
// ---------------------------------------------------------------------------

func tzObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                            tftypes.String,
		"timezone_id":                   tftypes.String,
		"daylight_saving_disabled":      tftypes.Bool,
		"display_name":                  tftypes.String,
		"base_utc_offset":               tftypes.String,
		"supports_daylight_saving_time": tftypes.Bool,
		"current_utc_offset":            tftypes.String,
		"tzautoupdate_enabled":          tftypes.Bool,
		"restore_on_destroy":            tftypes.Bool,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func tzNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func tzObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                            tftypes.NewValue(tftypes.String, nil),
		"timezone_id":                   tftypes.NewValue(tftypes.String, "Romance Standard Time"),
		"daylight_saving_disabled":      tftypes.NewValue(tftypes.Bool, false),
		"display_name":                  tftypes.NewValue(tftypes.String, nil),
		"base_utc_offset":               tftypes.NewValue(tftypes.String, nil),
		"supports_daylight_saving_time": tftypes.NewValue(tftypes.Bool, nil),
		"current_utc_offset":            tftypes.NewValue(tftypes.String, nil),
		"tzautoupdate_enabled":          tftypes.NewValue(tftypes.Bool, nil),
		"restore_on_destroy":            tftypes.NewValue(tftypes.Bool, false),
		"timeouts":                      tzNullTimeoutsValue(),
	}
}

func tzObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := tzObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(tzObjType(), base)
}

func tzState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsTimezoneSchemaDefinition(context.Background())
	return tfsdk.State{Raw: tzObj(overrides), Schema: s}
}

func tzPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsTimezoneSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: tzObj(overrides), Schema: s}
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsTimezoneResource_Metadata(t *testing.T) {
	r := &windowsTimezoneResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_timezone" {
		t.Errorf("TypeName = %q, want windows_timezone", resp.TypeName)
	}
}

func TestWindowsTimezoneResource_Schema(t *testing.T) {
	s := windowsTimezoneSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "timezone_id", "daylight_saving_disabled", "display_name",
		"base_utc_offset", "supports_daylight_saving_time", "current_utc_offset",
		"tzautoupdate_enabled", "restore_on_destroy", "timeouts",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	// timezone_id is Required and updated in place (no RequiresReplace).
	tzAttr, ok := s.Attributes["timezone_id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", s.Attributes["timezone_id"])
	}
	if !tzAttr.Required {
		t.Error("timezone_id must be Required")
	}
	if len(tzAttr.PlanModifiers) != 0 {
		t.Error("timezone_id must update in place (no RequiresReplace)")
	}
	if len(tzAttr.Validators) == 0 {
		t.Error("timezone_id must carry the IANA-rejection validator")
	}
	// Optional+Computed knobs.
	for _, n := range []string{"daylight_saving_disabled", "restore_on_destroy"} {
		a, ok := s.Attributes[n].(schema.BoolAttribute)
		if !ok {
			t.Fatalf("expected schema.BoolAttribute, got %T", s.Attributes[n])
		}
		if !a.Optional || !a.Computed {
			t.Errorf("%s must be Optional+Computed", n)
		}
	}
	// Every observed field is computed only.
	for _, n := range []string{"display_name", "base_utc_offset", "supports_daylight_saving_time",
		"current_utc_offset", "tzautoupdate_enabled"} {
		a := s.Attributes[n]
		if !isOptionalComputedAttr(a) && !isComputedOnlyAttr(a) {
			t.Errorf("%s must be computed", n)
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

func isComputedOnlyAttr(a any) bool {
	type optionalChecker interface{ IsOptional() bool }
	type computedChecker interface{ IsComputed() bool }
	type requiredChecker interface{ IsRequired() bool }
	oc, ok1 := a.(optionalChecker)
	cc, ok2 := a.(computedChecker)
	rc, ok3 := a.(requiredChecker)
	return ok1 && ok2 && ok3 && !oc.IsOptional() && cc.IsComputed() && !rc.IsRequired()
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

func TestTimezoneIDValidator(t *testing.T) {
	s := windowsTimezoneSchemaDefinition(context.Background())
	tzAttr, ok := s.Attributes["timezone_id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", s.Attributes["timezone_id"])
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue("Romance Standard Time"), false},
		{types.StringValue("UTC"), false},
		{types.StringValue("GMT Standard Time"), false},
		{types.StringValue("Europe/Paris"), true},
		{types.StringValue("America/New_York"), true},
		{types.StringNull(), false},
		{types.StringUnknown(), false},
	} {
		resp := &validator.StringResponse{}
		for _, v := range tzAttr.Validators {
			v.ValidateString(context.Background(), validator.StringRequest{
				Path: path.Root("timezone_id"), ConfigValue: tc.val,
			}, resp)
			if resp.Diagnostics.HasError() {
				break
			}
		}
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("timezone_id %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestTimezoneIDValidator_IANAMessage(t *testing.T) {
	v := timezoneIDValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		Path:        path.Root("timezone_id"),
		ConfigValue: types.StringValue("Europe/Paris"),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for IANA ID")
	}
	detail := resp.Diagnostics[0].Detail()
	if !strings.Contains(detail, "IANA") {
		t.Errorf("diagnostic must hint IANA IDs are unsupported, got: %q", detail)
	}
	if !strings.Contains(detail, "Romance Standard Time") {
		t.Errorf("diagnostic must suggest a Windows ID, got: %q", detail)
	}
	if v.Description(context.Background()) == "" || v.MarkdownDescription(context.Background()) == "" {
		t.Error("validator descriptions must not be empty")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsTimezoneResource_CreateHappy(t *testing.T) {
	live := okTimezoneState()
	fc := &fakeTimezoneClient{readOut: live, setOut: live}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.CreateRequest{Plan: tzPlan(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp := &resource.CreateResponse{
		State: tzState(t, nil),
	}
	allocPrivate(t, resp)

	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setIn.TimezoneID != "Romance Standard Time" || fc.setIn.DaylightSavingDisabled {
		t.Errorf("Set input = %+v, want Romance Standard Time/dst-enabled", fc.setIn)
	}
	// Snapshot captured because restore_on_destroy is set.
	raw, diags := resp.Private.GetKey(context.Background(), timezonePrivateKey)
	if diags.HasError() {
		t.Fatalf("GetKey: %v", diags)
	}
	if len(raw) == 0 {
		t.Fatal("expected a snapshot in private state")
	}
	var m windowsTimezoneModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.ID.ValueString() != live.MachineID {
		t.Errorf("id = %q, want machine %q", m.ID.ValueString(), live.MachineID)
	}
	if m.DisplayName.ValueString() != live.DisplayName {
		t.Errorf("display_name = %q", m.DisplayName.ValueString())
	}
	if m.BaseUTCOffset.ValueString() != "+01:00" || m.CurrentUTCOffset.ValueString() != "+02:00" {
		t.Errorf("offsets = %q/%q", m.BaseUTCOffset.ValueString(), m.CurrentUTCOffset.ValueString())
	}
	if !m.SupportsDST.ValueBool() {
		t.Error("supports_daylight_saving_time must be true")
	}
	if m.RestoreOnDestroy.ValueBool() != true {
		t.Error("restore_on_destroy intent must be preserved")
	}
}

func TestWindowsTimezoneResource_CreateNoRestoreSkipsSnapshot(t *testing.T) {
	live := okTimezoneState()
	fc := &fakeTimezoneClient{readOut: live, setOut: live}
	r := &windowsTimezoneResource{tz: fc}

	resp := &resource.CreateResponse{
		State: tzState(t, nil),
	}
	allocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: tzPlan(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if raw, _ := resp.Private.GetKey(context.Background(), timezonePrivateKey); len(raw) != 0 {
		t.Error("restore disabled: no snapshot expected in private state")
	}
}

func TestWindowsTimezoneResource_CreateSetError(t *testing.T) {
	fc := &fakeTimezoneClient{
		readOut: okTimezoneState(),
		setErr:  winclient.NewTimezoneError(winclient.TimezoneErrorInvalidTimezone, "no such zone", nil, nil),
	}
	r := &windowsTimezoneResource{tz: fc}

	resp := &resource.CreateResponse{
		State: tzState(t, nil),
	}
	allocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: tzPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when Set fails")
	}
}

func TestWindowsTimezoneResource_CreateMismatchErrors(t *testing.T) {
	fc := &fakeTimezoneClient{
		readOut: okTimezoneState(),
		setOut: func() *winclient.TimezoneState {
			st := okTimezoneState()
			st.TimezoneID = "UTC" // host silently kept another zone
			return st
		}(),
	}
	r := &windowsTimezoneResource{tz: fc}

	resp := &resource.CreateResponse{
		State: tzState(t, nil),
	}
	allocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: tzPlan(t, nil)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic on post-Set zone mismatch")
	}
}

func TestWindowsTimezoneResource_CreateTzautoupdateWarns(t *testing.T) {
	live := okTimezoneState()
	live.TzautoupdateEnabled = true
	fc := &fakeTimezoneClient{readOut: live, setOut: live}
	r := &windowsTimezoneResource{tz: fc}

	resp := &resource.CreateResponse{
		State: tzState(t, nil),
	}
	allocPrivate(t, resp)
	r.Create(context.Background(), resource.CreateRequest{Plan: tzPlan(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Fatal("tzautoupdate enabled must emit a warning")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsTimezoneResource_ReadHappy(t *testing.T) {
	live := okTimezoneState()
	live.TimezoneID = "UTC" // drifted out of band
	live.DaylightSavingDisabled = true
	fc := &fakeTimezoneClient{readOut: live}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.ReadRequest{State: tzState(t, nil)}
	resp := &resource.ReadResponse{
		State: tzState(t, nil),
	}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var m windowsTimezoneModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.TimezoneID.ValueString() != "UTC" {
		t.Errorf("timezone_id = %q, want drifted live value UTC", m.TimezoneID.ValueString())
	}
	if !m.DaylightSavingDisabled.ValueBool() {
		t.Error("daylight_saving_disabled must reflect the live value")
	}
}

func TestWindowsTimezoneResource_ReadMachineChangeUpdatesID(t *testing.T) {
	live := okTimezoneState()
	live.MachineID = "99999999-2222-3333-4444-555555555555"
	fc := &fakeTimezoneClient{readOut: live}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.ReadRequest{State: tzState(t, nil)}
	resp := &resource.ReadResponse{
		State: tzState(t, nil),
	}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var m windowsTimezoneModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	// The singleton zone always exists: a machine change refreshes the ID,
	// the resource is never removed from state.
	if m.ID.ValueString() != live.MachineID {
		t.Errorf("id = %q, want refreshed live machine %q", m.ID.ValueString(), live.MachineID)
	}
}

func TestWindowsTimezoneResource_ReadError(t *testing.T) {
	fc := &fakeTimezoneClient{
		readErr: winclient.NewTimezoneError(winclient.TimezoneErrorUnknown, "boom", nil, nil),
	}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.ReadRequest{State: tzState(t, nil)}
	resp := &resource.ReadResponse{
		State: tzState(t, nil),
	}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when Read fails")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestWindowsTimezoneResource_UpdateHappy(t *testing.T) {
	live := okTimezoneState()
	live.TimezoneID = "UTC"
	live.DaylightSavingDisabled = true
	fc := &fakeTimezoneClient{readOut: okTimezoneState(), setOut: live}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.UpdateRequest{
		Plan: tzPlan(t, map[string]tftypes.Value{
			"timezone_id":              tftypes.NewValue(tftypes.String, "UTC"),
			"daylight_saving_disabled": tftypes.NewValue(tftypes.Bool, true),
		}),
		State: tzState(t, nil),
	}
	resp := &resource.UpdateResponse{
		State: tzState(t, nil),
	}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setIn.TimezoneID != "UTC" || !fc.setIn.DaylightSavingDisabled {
		t.Errorf("Set input = %+v, want UTC/dst-disabled", fc.setIn)
	}
	// Update never overwrites the Create-time restore snapshot.
	if resp.Private != nil {
		if raw, diags := resp.Private.GetKey(context.Background(), timezonePrivateKey); !diags.HasError() && len(raw) != 0 {
			t.Error("Update must not overwrite the restore snapshot")
		}
	}
	var m windowsTimezoneModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.TimezoneID.ValueString() != "UTC" {
		t.Errorf("timezone_id = %q", m.TimezoneID.ValueString())
	}
}

func TestWindowsTimezoneResource_UpdateError(t *testing.T) {
	fc := &fakeTimezoneClient{
		setErr: winclient.NewTimezoneError(winclient.TimezoneErrorAccessDenied, "denied", nil, nil),
	}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.UpdateRequest{Plan: tzPlan(t, nil), State: tzState(t, nil)}
	resp := &resource.UpdateResponse{
		State: tzState(t, nil),
	}
	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when Set fails")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestWindowsTimezoneResource_DeleteDefaultIsNoop(t *testing.T) {
	fc := &fakeTimezoneClient{setOut: okTimezoneState()}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.DeleteRequest{State: tzState(t, nil)}
	resp := &resource.DeleteResponse{
		State: tzState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setCalls != 0 {
		t.Error("default destroy must make no remote change")
	}
}

func TestWindowsTimezoneResource_DeleteRestore(t *testing.T) {
	prior := okTimezoneState()
	restored := okTimezoneState()
	restored.TimezoneID = "W. Europe Standard Time"
	fc := &fakeTimezoneClient{setOut: restored}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.DeleteRequest{State: tzState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	allocPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), timezonePrivateKey, mustMarshalTz(t, prior)); diags.HasError() {
		t.Fatalf("SetKey: %v", diags)
	}
	resp := &resource.DeleteResponse{
		State: tzState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if fc.setCalls != 1 {
		t.Fatalf("restore destroy must re-apply the snapshot, got %d Set calls", fc.setCalls)
	}
	if fc.setIn.TimezoneID != prior.TimezoneID || fc.setIn.DaylightSavingDisabled != prior.DaylightSavingDisabled {
		t.Errorf("restore Set input = %+v, want snapshot %+v", fc.setIn, prior)
	}
}

func TestWindowsTimezoneResource_DeleteRestoreMissingSnapshotWarns(t *testing.T) {
	fc := &fakeTimezoneClient{setOut: okTimezoneState()}
	r := &windowsTimezoneResource{tz: fc}

	// No snapshot seeded on this DeleteRequest (Private is nil, which
	// GetKey tolerates as "no snapshot"): warn, don't error or restore.
	req := resource.DeleteRequest{State: tzState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp := &resource.DeleteResponse{
		State: tzState(t, nil),
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

func TestWindowsTimezoneResource_DeleteRestoreCorruptSnapshotWarns(t *testing.T) {
	fc := &fakeTimezoneClient{setOut: okTimezoneState()}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.DeleteRequest{State: tzState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	allocPrivate(t, &req)
	// Unreadable snapshot: valid JSON that cannot unmarshal into a
	// TimezoneState reports !ok via getTimezoneSnapshot — Delete must warn
	// (same as the missing-snapshot path) and leave the host untouched.
	// (A bare "{corrupt" cannot be seeded here: the framework's
	// Private.SetKey validates JSON and rejects it before Delete runs.)
	if diags := req.Private.SetKey(context.Background(), timezonePrivateKey, []byte(`"corrupt"`)); diags.HasError() {
		t.Fatalf("seed corrupt snapshot: %v", diags)
	}
	resp := &resource.DeleteResponse{
		State: tzState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("corrupt snapshot must warn, not error: %v", fpDiagSummaries(resp.Diagnostics))
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Fatal("corrupt snapshot must warn")
	}
	if fc.setCalls != 0 {
		t.Error("corrupt snapshot: host must be left untouched")
	}
}

func TestWindowsTimezoneResource_DeleteRestoreFailureErrors(t *testing.T) {
	prior := okTimezoneState()
	fc := &fakeTimezoneClient{
		setErr: winclient.NewTimezoneError(winclient.TimezoneErrorAccessDenied, "denied", nil, nil),
	}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.DeleteRequest{State: tzState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	allocPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), timezonePrivateKey, mustMarshalTz(t, prior)); diags.HasError() {
		t.Fatalf("SetKey: %v", diags)
	}
	resp := &resource.DeleteResponse{
		State: tzState(t, nil),
	}
	r.Delete(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("restore failure must surface an error diagnostic")
	}
}

func mustMarshalTz(t *testing.T, st *winclient.TimezoneState) []byte {
	t.Helper()
	// Snapshot payloads are produced with encoding/json in the handler; the
	// same encoding here keeps the round-trip faithful.
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsTimezoneResource_ImportState(t *testing.T) {
	live := okTimezoneState()
	fc := &fakeTimezoneClient{readOut: live}
	r := &windowsTimezoneResource{tz: fc}

	req := resource.ImportStateRequest{ID: "current"}
	resp := &resource.ImportStateResponse{
		State: tzState(t, nil),
	}
	allocPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Import diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var m windowsTimezoneModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	// Any ID is accepted and ignored; the live zone is adopted.
	if m.ID.ValueString() != live.MachineID {
		t.Errorf("id = %q, want live machine %q", m.ID.ValueString(), live.MachineID)
	}
	if m.TimezoneID.ValueString() != live.TimezoneID {
		t.Errorf("timezone_id = %q", m.TimezoneID.ValueString())
	}
	if m.RestoreOnDestroy.ValueBool() {
		t.Error("imported restore_on_destroy must start false")
	}
	raw, diags := resp.Private.GetKey(context.Background(), timezonePrivateKey)
	if diags.HasError() {
		t.Fatalf("GetKey: %v", diags)
	}
	if len(raw) == 0 {
		t.Fatal("import must capture the snapshot for a later restore")
	}
}

func TestWindowsTimezoneResource_ImportStateEmptyID(t *testing.T) {
	r := &windowsTimezoneResource{tz: &fakeTimezoneClient{}}

	req := resource.ImportStateRequest{ID: "  "}
	resp := &resource.ImportStateResponse{
		State: tzState(t, nil),
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

func TestTimezoneIDsEqual(t *testing.T) {
	for _, tc := range []struct {
		live, desired string
		want          bool
	}{
		{"Romance Standard Time", "Romance Standard Time", true},
		{"romance standard time", "Romance Standard Time", true},
		{"Romance Standard Time_dstoff", "Romance Standard Time", true},
		{"ROMANCE STANDARD TIME_DSTOFF", "romance standard time", true},
		{"UTC", "Romance Standard Time", false},
		{"Romance Standard Time", "UTC", false},
	} {
		if got := timezoneIDsEqual(tc.live, tc.desired); got != tc.want {
			t.Errorf("timezoneIDsEqual(%q, %q) = %v, want %v", tc.live, tc.desired, got, tc.want)
		}
	}
}

func TestMaybeWarnTzautoupdate(t *testing.T) {
	var quiet diag.Diagnostics
	maybeWarnTzautoupdate(&quiet, windowsTimezoneModel{TzautoupdateEnabled: types.BoolValue(false)})
	if quiet.WarningsCount() != 0 {
		t.Error("disabled tzautoupdate must not warn")
	}
	var loud diag.Diagnostics
	maybeWarnTzautoupdate(&loud, windowsTimezoneModel{TzautoupdateEnabled: types.BoolValue(true)})
	if loud.WarningsCount() == 0 {
		t.Error("enabled tzautoupdate must warn")
	}
}
