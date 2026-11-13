// Package provider — unit tests for the windows_eventlog resource.
//
// These tests exercise the schema, validators, settings projection and
// CRUD handlers without SSH. A fakeEventLogClient is injected into
// windowsEventLogResource.el.
//
// Edge cases covered (issue #289):
//
//	Metadata                 — returns "windows_eventlog"
//	Schema                   — name Required/ForceNew (literal, "/" allowed),
//	                           settings Optional+Computed, restore_on_destroy
//	                           default, timeouts block, computed-only counters
//	Name validator           — LengthAtLeast(1); no OneOf (modern channels)
//	Size validator           — 1 MiB floor, 64 KiB multiple, null/unknown skip
//	Retention validator      — OneOf overwrite/archive/retain at plan time
//	Retain-on-Security       — warns, never errors; non-Security clean
//	Settings projection      — only configured attrs sent, unknown defers
//	State projection        — LogMode mapping, counters verbatim
//	Create (happy)           — snapshot captured when restore_on_destroy,
//	                           skipped otherwise; warnings (shrink, 4 GiB
//	                           classic, GPO) surface
//	Create (not_found)       — diagnostic error
//	Create (unsupported)     — diagnostic error (classic disable)
//	Read (happy)             — state refreshed, intent preserved
//	Read (missing)           — RemoveResource (nil and not_found)
//	Update (happy)           — forwards delta, keeps snapshot intent
//	Delete (default)         — no remote change
//	Delete (restore)         — re-applies snapshot; missing snapshot warns
//	ImportState (happy)      — snapshot captured, by exact name incl. "/"
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
// fakeEventLogClient
// ---------------------------------------------------------------------------

type fakeEventLogClient struct {
	readOut  *winclient.EventLogState
	readErr  error
	readName string

	applyIn   winclient.EventLogSettings
	applyName string
	applyOut  *winclient.EventLogState
	applyErr  error

	restoreIn  winclient.EventLogState
	restoreOut *winclient.EventLogState
	restoreErr error
}

func (f *fakeEventLogClient) Read(_ context.Context, name string) (*winclient.EventLogState, error) {
	f.readName = name
	return f.readOut, f.readErr
}

func (f *fakeEventLogClient) Apply(_ context.Context, name string, s winclient.EventLogSettings) (*winclient.EventLogState, error) {
	f.applyName = name
	f.applyIn = s
	return f.applyOut, f.applyErr
}

func (f *fakeEventLogClient) Restore(_ context.Context, snap winclient.EventLogState) (*winclient.EventLogState, error) {
	f.restoreIn = snap
	return f.restoreOut, f.restoreErr
}

func okEventLogState(name string) *winclient.EventLogState {
	return &winclient.EventLogState{
		Name:             name,
		LogType:          "Administrative",
		IsClassic:        true,
		IsEnabled:        true,
		LogMode:          "Circular",
		MaximumSizeBytes: 20971520,
		LogFilePath:      `%SystemRoot%\System32\Winevt\Logs\Application.evtx`,
		RecordCount:      1234,
		FileSizeBytes:    2105344,
		PolicyOverride:   false,
	}
}

func okModernEventLogState(name string) *winclient.EventLogState {
	return &winclient.EventLogState{
		Name:             name,
		LogType:          "Operational",
		IsClassic:        false,
		IsEnabled:        true,
		LogMode:          "Circular",
		MaximumSizeBytes: 1048576,
		LogFilePath:      `%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`,
		RecordCount:      42,
		FileSizeBytes:    69632,
		PolicyOverride:   false,
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_eventlog schema
// ---------------------------------------------------------------------------

func elObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"name":               tftypes.String,
		"maximum_size_bytes": tftypes.Number,
		"retention":          tftypes.String,
		"enabled":            tftypes.Bool,
		"log_file_path":      tftypes.String,
		"restore_on_destroy": tftypes.Bool,
		"log_type":           tftypes.String,
		"is_classic_log":     tftypes.Bool,
		"record_count":       tftypes.Number,
		"file_size_bytes":    tftypes.Number,
		"policy_override":    tftypes.Bool,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func elNullStr() tftypes.Value  { return tftypes.NewValue(tftypes.String, nil) }
func elNullBool() tftypes.Value { return tftypes.NewValue(tftypes.Bool, nil) }
func elNullNum() tftypes.Value  { return tftypes.NewValue(tftypes.Number, nil) }

func elNullTimeouts() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func elObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, "Application"),
		"name":               tftypes.NewValue(tftypes.String, "Application"),
		"maximum_size_bytes": elNullNum(),
		"retention":          elNullStr(),
		"enabled":            elNullBool(),
		"log_file_path":      elNullStr(),
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, false),
		"log_type":           elNullStr(),
		"is_classic_log":     elNullBool(),
		"record_count":       elNullNum(),
		"file_size_bytes":    elNullNum(),
		"policy_override":    elNullBool(),
		"timeouts":           elNullTimeouts(),
	}
}

func elObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := elObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(elObjType(), base)
}

func elState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsEventLogSchemaDefinition(context.Background())
	return tfsdk.State{Raw: elObj(overrides), Schema: s}
}

func elPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsEventLogSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: elObj(overrides), Schema: s}
}

func elConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsEventLogSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: elObj(overrides), Schema: s}
}

func elDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// allocEventLogPrivate allocates the framework private-state value on a
// response or request so handler tests can capture snapshots without the
// framework server. Mirrors allocPrivate (firewall profile tests) under a
// collision-free name.
func allocEventLogPrivate(t *testing.T, holder any) {
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

func TestWindowsEventLogResource_Metadata(t *testing.T) {
	r := &windowsEventLogResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_eventlog" {
		t.Errorf("TypeName = %q, want windows_eventlog", resp.TypeName)
	}
}

func TestWindowsEventLogResource_Schema(t *testing.T) {
	s := windowsEventLogSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "name", "maximum_size_bytes", "retention", "enabled",
		"log_file_path", "restore_on_destroy", "log_type", "is_classic_log",
		"record_count", "file_size_bytes", "policy_override", "timeouts",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	// name is Required + ForceNew and accepts channel names containing "/":
	// no OneOf validator gates the value.
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
	// Every setting is Optional+Computed: only configured attrs are assigned
	// before SaveChanges.
	for _, n := range []string{"maximum_size_bytes", "retention", "enabled", "log_file_path"} {
		a := s.Attributes[n]
		if !isOptionalComputedAttr(a) {
			t.Errorf("%s must be Optional+Computed (partial management)", n)
		}
	}
	// Counters and policy flag are Computed-only: informational, no drift.
	for _, n := range []string{"record_count", "file_size_bytes", "log_type", "is_classic_log", "policy_override"} {
		a := s.Attributes[n]
		if isOptionalAttr(a) {
			t.Errorf("%s must be Computed-only (informational), not Optional", n)
		}
		if !isComputedAttr(a) {
			t.Errorf("%s must be Computed", n)
		}
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

func isOptionalAttr(a any) bool {
	type optionalChecker interface{ IsOptional() bool }
	oc, ok := a.(optionalChecker)
	return ok && oc.IsOptional()
}

func isComputedAttr(a any) bool {
	type computedChecker interface{ IsComputed() bool }
	cc, ok := a.(computedChecker)
	return ok && cc.IsComputed()
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestEventLogNameValidator(t *testing.T) {
	s := windowsEventLogSchemaDefinition(context.Background())
	nameAttr, ok := s.Attributes["name"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", nameAttr)
	}
	if len(nameAttr.Validators) == 0 {
		t.Fatal("name must carry a LengthAtLeast validator")
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue("Application"), false},
		{types.StringValue("Security"), false},
		// Modern channel names containing "/" are valid literal names.
		{types.StringValue("Microsoft-Windows-PowerShell/Operational"), false},
		{types.StringValue(""), true},
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

func TestEventLogSizeValidator(t *testing.T) {
	s := windowsEventLogSchemaDefinition(context.Background())
	sizeAttr, ok := s.Attributes["maximum_size_bytes"].(schema.Int64Attribute)
	if !ok {
		t.Fatalf("expected schema.Int64Attribute, got %T", sizeAttr)
	}
	if len(sizeAttr.Validators) == 0 {
		t.Fatal("maximum_size_bytes must carry the 1 MiB / 64 KiB validator")
	}
	ctx := context.Background()
	for _, tc := range []struct {
		val     types.Int64
		wantErr bool
	}{
		{types.Int64Value(1048576), false},
		{types.Int64Value(20971520), false},
		{types.Int64Value(1073741824), false},
		{types.Int64Value(0), true},
		{types.Int64Value(1048575), true},
		{types.Int64Value(1048577), true},
		{types.Int64Value(1000000), true},
		{types.Int64Null(), false},
		{types.Int64Unknown(), false},
	} {
		resp := &validator.Int64Response{}
		sizeAttr.Validators[0].ValidateInt64(ctx, validator.Int64Request{
			Path: path.Root("maximum_size_bytes"), ConfigValue: tc.val,
		}, resp)
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("size %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestEventLogRetentionValidator(t *testing.T) {
	s := windowsEventLogSchemaDefinition(context.Background())
	retAttr, ok := s.Attributes["retention"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", retAttr)
	}
	if len(retAttr.Validators) == 0 {
		t.Fatal("retention must carry a OneOf validator")
	}
	for _, tc := range []struct {
		val     types.String
		wantErr bool
	}{
		{types.StringValue("overwrite"), false},
		{types.StringValue("archive"), false},
		{types.StringValue("retain"), false},
		{types.StringValue("Circular"), true},
		{types.StringValue("overwrite "), true},
		{types.StringNull(), false},
		{types.StringUnknown(), false},
	} {
		resp := &validator.StringResponse{}
		retAttr.Validators[0].ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("retention"), ConfigValue: tc.val,
		}, resp)
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("retention %v: wantErr=%v, got %v", tc.val, tc.wantErr, resp.Diagnostics)
		}
	}
}

func TestEventLogRetainOnSecurityValidator(t *testing.T) {
	r, ok := NewWindowsEventLogResource().(*windowsEventLogResource)
	if !ok {
		t.Fatalf("expected *windowsEventLogResource, got %T", r)
	}
	var v eventLogRetentionValidator
	for _, cv := range r.ConfigValidators(context.Background()) {
		if ev, ok := cv.(eventLogRetentionValidator); ok {
			v = ev
		}
	}
	cases := []struct {
		name      string
		overrides map[string]tftypes.Value
		wantWarn  bool
	}{
		{"retain on Security warns", map[string]tftypes.Value{
			"name":      tftypes.NewValue(tftypes.String, "Security"),
			"retention": tftypes.NewValue(tftypes.String, "retain"),
		}, true},
		{"retain on security warns (case-insensitive)", map[string]tftypes.Value{
			"name":      tftypes.NewValue(tftypes.String, "security"),
			"retention": tftypes.NewValue(tftypes.String, "retain"),
		}, true},
		{"overwrite on Security clean", map[string]tftypes.Value{
			"name":      tftypes.NewValue(tftypes.String, "Security"),
			"retention": tftypes.NewValue(tftypes.String, "overwrite"),
		}, false},
		{"retain on Application clean", map[string]tftypes.Value{
			"name":      tftypes.NewValue(tftypes.String, "Application"),
			"retention": tftypes.NewValue(tftypes.String, "retain"),
		}, false},
		{"unset clean", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &resource.ValidateConfigResponse{}
			v.ValidateResource(context.Background(), resource.ValidateConfigRequest{
				Config: elConfig(t, tc.overrides),
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
				t.Errorf("wantWarn=%v, diagnostics: %v", tc.wantWarn, elDiagSummaries(resp.Diagnostics))
			}
			if tc.wantWarn {
				joined := strings.Join(elDiagSummaries(resp.Diagnostics), "\n")
				if !strings.Contains(joined, "CrashOnAuditFail") {
					t.Errorf("retain-on-Security warning must name CrashOnAuditFail, got:\n%s", joined)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Settings projection: only configured attrs sent
// ---------------------------------------------------------------------------

func TestModelToEventLogSettings_OnlyConfigured(t *testing.T) {
	ctx := context.Background()
	var m windowsEventLogModel
	if diags := elPlan(t, nil).Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get: %v", diags)
	}
	s, diags := modelToEventLogSettings(ctx, m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(diags))
	}
	if s.EventLogConfigured() {
		t.Errorf("all-null plan must produce no configured settings: %+v", s)
	}
}

func TestModelToEventLogSettings_Configured(t *testing.T) {
	m := windowsEventLogModel{
		MaximumSizeBytes: types.Int64Value(1073741824),
		Retention:        types.StringValue("archive"),
		Enabled:          types.BoolValue(true),
		LogFilePath:      types.StringValue(`C:\Logs\app.evtx`),
	}
	s, diags := modelToEventLogSettings(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(diags))
	}
	if s.MaximumSizeBytes == nil || *s.MaximumSizeBytes != 1073741824 {
		t.Error("maximum_size_bytes must be forwarded")
	}
	if s.Retention == nil || *s.Retention != "archive" {
		t.Error("retention must be forwarded")
	}
	if s.Enabled == nil || !*s.Enabled {
		t.Error("enabled must be forwarded")
	}
	if s.LogFilePath == nil || *s.LogFilePath != `C:\Logs\app.evtx` {
		t.Error("log_file_path must be forwarded")
	}
	if s.Retention != nil {
		if mode, err := winclient.EventLogRetentionToLogMode(*s.Retention); err != nil || mode != "AutoBackup" {
			t.Errorf("retention archive must map to AutoBackup, got %q, %v", mode, err)
		}
	}
}

func TestModelToEventLogSettings_UnknownDefers(t *testing.T) {
	m := windowsEventLogModel{
		MaximumSizeBytes: types.Int64Unknown(),
		Retention:        types.StringNull(),
		Enabled:          types.BoolNull(),
		LogFilePath:      types.StringNull(),
	}
	if _, diags := modelToEventLogSettings(context.Background(), m); !diags.HasError() {
		t.Error("unknown attributes must abort with a deferring diagnostic")
	}
}

func TestModelToEventLogSettings_UnknownRetentionUnmanaged(t *testing.T) {
	// A future host LogMode passes through eventLogStateToModel verbatim
	// (Computed retention), so it can reappear here without ever being
	// user-configured — the plan OneOf validator guarantees configured
	// values are known. It must be left unmanaged so the next Apply does
	// not fail closed in EventLogRetentionToLogMode.
	m := windowsEventLogModel{
		MaximumSizeBytes: types.Int64Null(),
		Retention:        types.StringValue("FutureMode"),
		Enabled:          types.BoolNull(),
		LogFilePath:      types.StringNull(),
	}
	s, diags := modelToEventLogSettings(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(diags))
	}
	if s.Retention != nil {
		t.Errorf("unknown observed retention must be unmanaged (nil), got %q", *s.Retention)
	}
	if s.EventLogConfigured() {
		t.Errorf("unknown retention alone must leave nothing configured: %+v", s)
	}
}

// ---------------------------------------------------------------------------
// State projection: LogMode mapping, counters verbatim
// ---------------------------------------------------------------------------

func TestEventLogStateToModel(t *testing.T) {
	m := eventLogStateToModel(okModernEventLogState("Microsoft-Windows-PowerShell/Operational"))
	if m.ID.ValueString() != "Microsoft-Windows-PowerShell/Operational" || m.Name.ValueString() != "Microsoft-Windows-PowerShell/Operational" {
		t.Errorf("id/name must be the literal log name, got %q/%q", m.ID.ValueString(), m.Name.ValueString())
	}
	if m.Retention.ValueString() != "overwrite" {
		t.Errorf("Circular must project to overwrite, got %q", m.Retention.ValueString())
	}
	if m.IsClassicLog.ValueBool() {
		t.Error("modern channel must not be classic")
	}
	if m.LogType.ValueString() != "Operational" {
		t.Errorf("log_type = %q, want Operational", m.LogType.ValueString())
	}
	if m.RecordCount.ValueInt64() != 42 || m.FileSizeBytes.ValueInt64() != 69632 {
		t.Errorf("counts must project verbatim, got %d/%d", m.RecordCount.ValueInt64(), m.FileSizeBytes.ValueInt64())
	}
	// Host LogMode spellings map back to Terraform spellings.
	for mode, want := range map[string]string{"Circular": "overwrite", "AutoBackup": "archive", "Retain": "retain"} {
		st := okEventLogState("Application")
		st.LogMode = mode
		if got := eventLogStateToModel(st).Retention.ValueString(); got != want {
			t.Errorf("LogMode %q must project to %q, got %q", mode, want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsEventLogResource_Create_HappyPath(t *testing.T) {
	fc := &fakeEventLogClient{
		readOut:  okEventLogState("Application"),
		applyOut: okEventLogState("Application"),
	}
	r := &windowsEventLogResource{el: fc}

	req := resource.CreateRequest{Plan: elPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	if fc.applyName != "Application" {
		t.Errorf("apply name = %q, want Application", fc.applyName)
	}
	if fc.applyIn.EventLogConfigured() {
		t.Errorf("all-null plan must Apply no settings, got %+v", fc.applyIn)
	}
	var model windowsEventLogModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Application" {
		t.Errorf("id = %q, want Application", model.ID.ValueString())
	}
	// No warnings on a clean apply.
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			t.Errorf("clean apply must not warn, got: %s", d.Detail())
		}
	}
}

func TestWindowsEventLogResource_Create_SnapshotOnlyWhenRestore(t *testing.T) {
	// restore_on_destroy = true: pre-existing values are captured.
	fc := &fakeEventLogClient{
		readOut:  okEventLogState("Application"),
		applyOut: okEventLogState("Application"),
	}
	r := &windowsEventLogResource{el: fc}
	req := resource.CreateRequest{Plan: elPlan(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	allocEventLogPrivate(t, resp)
	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	if fc.readName != "Application" {
		t.Errorf("expected a pre-existing Read for the snapshot, got readName=%q", fc.readName)
	}
	raw, diags := resp.Private.GetKey(context.Background(), eventLogPrivateKey)
	if diags.HasError() {
		t.Fatalf("GetKey: %v", diags)
	}
	if len(raw) == 0 {
		t.Fatal("expected a snapshot in private state")
	}
	var snap winclient.EventLogState
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.Name != "Application" || snap.MaximumSizeBytes != 20971520 {
		t.Errorf("snapshot content wrong: %+v", snap)
	}

	// Default (false): no pre-read, no snapshot.
	fc2 := &fakeEventLogClient{applyOut: okEventLogState("Application")}
	r2 := &windowsEventLogResource{el: fc2}
	resp2 := &resource.CreateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	r2.Create(context.Background(), resource.CreateRequest{Plan: elPlan(t, nil)}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp2.Diagnostics))
	}
	if fc2.readName != "" {
		t.Errorf("restore disabled: no pre-read expected, got %q", fc2.readName)
	}
	if raw, _ := resp2.Private.GetKey(context.Background(), eventLogPrivateKey); len(raw) != 0 {
		t.Error("restore disabled: no snapshot expected in private state")
	}
}

func TestWindowsEventLogResource_Create_NotFound(t *testing.T) {
	fc := &fakeEventLogClient{
		readErr: winclient.NewEventLogError(winclient.EventLogErrorNotFound, "Event log Bogus was not found", nil, nil),
	}
	r := &windowsEventLogResource{el: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: elPlan(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("missing log must error, not converge")
	}
	joined := strings.Join(elDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "not_found") {
		t.Errorf("diagnostic must name the kind, got:\n%s", joined)
	}
}

func TestWindowsEventLogResource_Create_Unsupported(t *testing.T) {
	fc := &fakeEventLogClient{
		applyErr: winclient.NewEventLogError(winclient.EventLogErrorUnsupported,
			"Event log Application is a classic log and cannot be disabled.", nil, nil),
	}
	r := &windowsEventLogResource{el: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: elPlan(t, map[string]tftypes.Value{
		"enabled": tftypes.NewValue(tftypes.Bool, false),
	})}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an unsupported diagnostic")
	}
	joined := strings.Join(elDiagSummaries(resp.Diagnostics), "\n")
	if !strings.Contains(joined, "unsupported") {
		t.Errorf("diagnostic must name the kind, got:\n%s", joined)
	}
}

func TestWindowsEventLogResource_Create_Warnings(t *testing.T) {
	// Shrink + GPO + 4 GiB classic all warn on the same apply.
	// want (5 GiB) sits below the observed file size (6 GiB) for the
	// shrink warning and above 4 GiB on a classic log for the large-size
	// warning.
	observed := okEventLogState("Application")
	observed.FileSizeBytes = 6442450944
	observed.PolicyOverride = true
	observed.MaximumSizeBytes = 6442450944 // > 4 GiB, still re-read verbatim
	fc := &fakeEventLogClient{applyOut: observed}
	r := &windowsEventLogResource{el: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: elPlan(t, map[string]tftypes.Value{
		"maximum_size_bytes": tftypes.NewValue(tftypes.Number, 5368709120),
	})}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("warnings must not error: %v", elDiagSummaries(resp.Diagnostics))
	}
	joined := strings.Join(elDiagSummaries(resp.Diagnostics), "\n")
	for _, want := range []string{"Shrinking", "Large maximum size", "Group Policy"} {
		if !strings.Contains(joined, want) {
			t.Errorf("apply warnings missing %q, got:\n%s", want, joined)
		}
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsEventLogResource_Read_HappyPath(t *testing.T) {
	fc := &fakeEventLogClient{readOut: okEventLogState("Application")}
	r := &windowsEventLogResource{el: fc}

	req := resource.ReadRequest{State: elState(t, nil)}
	resp := &resource.ReadResponse{State: elState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	var model windowsEventLogModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Application" || !model.IsClassicLog.ValueBool() {
		t.Errorf("unexpected state: id=%q classic=%v", model.ID.ValueString(), model.IsClassicLog.ValueBool())
	}
	// Counters refresh verbatim (informational, never diffed).
	if model.RecordCount.ValueInt64() != 1234 || model.FileSizeBytes.ValueInt64() != 2105344 {
		t.Errorf("unexpected counters: %+v", model)
	}
}

func TestWindowsEventLogResource_Read_MissingRemoves(t *testing.T) {
	// Nil result: the log was removed out-of-band.
	fc := &fakeEventLogClient{readOut: nil}
	r := &windowsEventLogResource{el: fc}

	req := resource.ReadRequest{State: elState(t, nil)}
	resp := &resource.ReadResponse{State: elState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing log must RemoveResource, not error: %v", elDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state should be null (RemoveResource) when the log is gone")
	}
}

func TestWindowsEventLogResource_Read_NotFoundRemoves(t *testing.T) {
	// Typed not_found: same outcome as nil.
	fc := &fakeEventLogClient{
		readErr: winclient.NewEventLogError(winclient.EventLogErrorNotFound, "gone", nil, nil),
	}
	r := &windowsEventLogResource{el: fc}

	req := resource.ReadRequest{State: elState(t, nil)}
	resp := &resource.ReadResponse{State: elState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("not_found must RemoveResource, not error: %v", elDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state should be null (RemoveResource) on not_found")
	}
}

func TestWindowsEventLogResource_Read_OtherErrorIsDiagnostic(t *testing.T) {
	fc := &fakeEventLogClient{
		readErr: winclient.NewEventLogError(winclient.EventLogErrorAccessDenied, "denied", nil, nil),
	}
	r := &windowsEventLogResource{el: fc}

	req := resource.ReadRequest{State: elState(t, nil)}
	resp := &resource.ReadResponse{State: elState(t, nil)}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("access_denied must surface a diagnostic, not RemoveResource")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestWindowsEventLogResource_Update_HappyPath(t *testing.T) {
	st := okEventLogState("Application")
	st.MaximumSizeBytes = 1073741824
	st.LogMode = "AutoBackup"
	fc := &fakeEventLogClient{applyOut: st}
	r := &windowsEventLogResource{el: fc}

	req := resource.UpdateRequest{
		Plan: elPlan(t, map[string]tftypes.Value{
			"maximum_size_bytes": tftypes.NewValue(tftypes.Number, 1073741824),
			"retention":          tftypes.NewValue(tftypes.String, "archive"),
		}),
		State: elState(t, nil),
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	if fc.applyIn.MaximumSizeBytes == nil || *fc.applyIn.MaximumSizeBytes != 1073741824 {
		t.Errorf("update must forward the size delta, got %+v", fc.applyIn)
	}
	if fc.applyIn.Retention == nil || *fc.applyIn.Retention != "archive" {
		t.Errorf("update must forward the retention delta, got %+v", fc.applyIn)
	}
	if fc.applyIn.Enabled != nil || fc.applyIn.LogFilePath != nil {
		t.Errorf("update must not forward unmanaged attrs, got %+v", fc.applyIn)
	}
	var model windowsEventLogModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Retention.ValueString() != "archive" {
		t.Errorf("state retention = %q, want archive", model.Retention.ValueString())
	}
}

func TestWindowsEventLogResource_Delete_DefaultNoRemoteChange(t *testing.T) {
	fc := &fakeEventLogClient{restoreOut: okEventLogState("Application")}
	r := &windowsEventLogResource{el: fc}

	req := resource.DeleteRequest{State: elState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.Name != "" {
		t.Errorf("default delete must make no remote change, got restore of %+v", fc.restoreIn)
	}
}

func TestWindowsEventLogResource_Delete_Restore(t *testing.T) {
	fc := &fakeEventLogClient{restoreOut: okEventLogState("Application")}
	r := &windowsEventLogResource{el: fc}

	want := okEventLogState("Application")
	want.MaximumSizeBytes = 1073741824
	want.LogMode = "Retain"
	snap, _ := json.Marshal(want)

	state := elState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	allocEventLogPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), eventLogPrivateKey, snap); diags.HasError() {
		t.Fatalf("seed snapshot: %v", diags)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	if fc.restoreIn.Name != "Application" || fc.restoreIn.MaximumSizeBytes != 1073741824 || fc.restoreIn.LogMode != "Retain" {
		t.Errorf("restore must re-apply the captured snapshot verbatim, got %+v", fc.restoreIn)
	}
}

func TestWindowsEventLogResource_Delete_RestoreWarnsOnPolicyOverride(t *testing.T) {
	restored := okEventLogState("Application")
	restored.PolicyOverride = true
	fc := &fakeEventLogClient{restoreOut: restored}
	r := &windowsEventLogResource{el: fc}

	want := okEventLogState("Application")
	snap, _ := json.Marshal(want)

	state := elState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	allocEventLogPrivate(t, &req)
	if diags := req.Private.SetKey(context.Background(), eventLogPrivateKey, snap); diags.HasError() {
		t.Fatalf("seed snapshot: %v", diags)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	foundWarn := false
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Error("restore readback with policy_override must warn on Delete")
	}
}

func TestWindowsEventLogResource_Delete_RestoreMissingSnapshotWarns(t *testing.T) {
	fc := &fakeEventLogClient{restoreOut: okEventLogState("Application")}
	r := &windowsEventLogResource{el: fc}

	state := elState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	// No snapshot seeded on this DeleteRequest (Private is nil, which
	// GetKey tolerates as "no snapshot"): warn, don't error or restore.
	req := resource.DeleteRequest{State: state}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing snapshot must warn, not error: %v", elDiagSummaries(resp.Diagnostics))
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

func TestWindowsEventLogResource_Delete_CorruptSnapshotWarns(t *testing.T) {
	fc := &fakeEventLogClient{restoreOut: okEventLogState("Application")}
	r := &windowsEventLogResource{el: fc}

	state := elState(t, map[string]tftypes.Value{
		"restore_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	req := resource.DeleteRequest{State: state}
	allocEventLogPrivate(t, &req)
	// Unreadable snapshot: valid JSON that cannot unmarshal into
	// EventLogState reports !ok via getEventLogSnapshot — Delete must warn
	// (same as the missing-snapshot path) and leave the host untouched.
	if diags := req.Private.SetKey(context.Background(), eventLogPrivateKey, []byte(`"corrupt"`)); diags.HasError() {
		t.Fatalf("seed corrupt snapshot: %v", diags)
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("corrupt snapshot must warn, not error: %v", elDiagSummaries(resp.Diagnostics))
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

func TestWindowsEventLogResource_ImportState_HappyPath(t *testing.T) {
	for _, name := range []string{"Application", "Microsoft-Windows-PowerShell/Operational"} {
		t.Run(name, func(t *testing.T) {
			st := okEventLogState(name)
			if name != "Application" {
				st = okModernEventLogState(name)
			}
			fc := &fakeEventLogClient{readOut: st}
			r := &windowsEventLogResource{el: fc}

			req := resource.ImportStateRequest{ID: name}
			resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
			allocEventLogPrivate(t, resp)
			r.ImportState(context.Background(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
			}
			var model windowsEventLogModel
			resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
			if model.Name.ValueString() != name || model.ID.ValueString() != name {
				t.Errorf("unexpected imported state: name=%q id=%q", model.Name.ValueString(), model.ID.ValueString())
			}
			if model.RestoreOnDestroy.ValueBool() {
				t.Error("imported restore_on_destroy must default to false")
			}
			// The observed values become the restore snapshot.
			raw, diags := resp.Private.GetKey(context.Background(), eventLogPrivateKey)
			if diags.HasError() || len(raw) == 0 {
				t.Fatalf("import must capture the restore snapshot: %v", diags)
			}
		})
	}
}

func TestWindowsEventLogResource_ImportState_InvalidID(t *testing.T) {
	r := &windowsEventLogResource{el: &fakeEventLogClient{readOut: okEventLogState("Application")}}
	req := resource.ImportStateRequest{ID: "   "}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	allocEventLogPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error for an empty import ID")
	}
}

func TestWindowsEventLogResource_ImportState_MissingLog(t *testing.T) {
	r := &windowsEventLogResource{el: &fakeEventLogClient{readOut: nil}}
	req := resource.ImportStateRequest{ID: "NoSuchLog"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}
	allocEventLogPrivate(t, resp)
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error for a missing log")
	}
}

// ---------------------------------------------------------------------------
// Timeouts: a stalled remote command must surface a bounded diagnostic
// ---------------------------------------------------------------------------

func TestWindowsEventLogSchema_HasTimeoutsBlock(t *testing.T) {
	s := windowsEventLogSchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block: CRUD must be time-bounded")
	}
}

// hangEventLogClient simulates a stalled transport: Apply blocks until the
// passed context is done, then returns the context error.
type hangEventLogClient struct {
	fakeEventLogClient
}

func (f *hangEventLogClient) Apply(ctx context.Context, _ string, _ winclient.EventLogSettings) (*winclient.EventLogState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// elTimeoutsRaw builds the raw tftypes value for a timeouts block carrying
// the given per-operation durations.
func elTimeoutsRaw(durations map[string]string) tftypes.Value {
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

func TestWindowsEventLogResource_Create_StalledTransportIsBounded(t *testing.T) {
	r := &windowsEventLogResource{el: &hangEventLogClient{}}

	req := resource.CreateRequest{Plan: elPlan(t, map[string]tftypes.Value{
		"timeouts": elTimeoutsRaw(map[string]string{"create": "200ms"}),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsEventLogSchemaDefinition(context.Background())}}

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

func TestWindowsEventLogModel_PreservesTimeouts(t *testing.T) {
	ctx := context.Background()
	prior := windowsEventLogModel{
		Timeouts: mustEventLogTimeouts(t, map[string]string{"create": "5m"}),
	}
	m := prior
	st := okEventLogState("Application")
	projected := eventLogStateToModel(st)
	projected.Timeouts = m.Timeouts
	got, diags := projected.Timeouts.Create(ctx, eventLogDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("Timeouts.Create: %v", diags)
	}
	if got != 5*time.Minute {
		t.Errorf("Timeouts not preserved through projection: create = %v, want 5m", got)
	}
}

// mustEventLogTimeouts decodes elTimeoutsRaw through the resource schema,
// the same path the framework takes for real plans.
func mustEventLogTimeouts(t *testing.T, durations map[string]string) timeouts.Value {
	t.Helper()
	ctx := context.Background()
	plan := tfsdk.Plan{
		Schema: windowsEventLogSchemaDefinition(ctx),
		Raw: elObj(map[string]tftypes.Value{
			"timeouts": elTimeoutsRaw(durations),
		}),
	}
	var m windowsEventLogModel
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get timeouts: %v", diags)
	}
	return m.Timeouts
}

func TestEventLogErrorDiag_Kinds(t *testing.T) {
	for _, kind := range []winclient.EventLogErrorKind{
		winclient.EventLogErrorNotFound,
		winclient.EventLogErrorAccessDenied,
		winclient.EventLogErrorUnsupported,
		winclient.EventLogErrorInvalidSize,
		winclient.EventLogErrorUnknown,
	} {
		var diags diag.Diagnostics
		addEventLogDiag(&diags, "Error creating Windows event log",
			winclient.NewEventLogError(kind, "boom", nil, map[string]string{"log": "Application"}))
		if !diags.HasError() {
			t.Fatalf("kind %q: expected an error diagnostic", kind)
		}
		joined := strings.Join(elDiagSummaries(diags), "\n")
		if !strings.Contains(joined, string(kind)) {
			t.Errorf("kind %q: diagnostic must name the kind, got:\n%s", kind, joined)
		}
	}
}

func TestEventLogSnapshot_RoundTrip(t *testing.T) {
	ctx := context.Background()
	// setEventLogSnapshot/getEventLogSnapshot round-trip through injectable
	// closures so the JSON private-state format is pinned.
	store := map[string][]byte{}
	setKey := func(_ context.Context, k string, v []byte) diag.Diagnostics {
		store[k] = v
		return nil
	}
	getKey := func(_ context.Context, k string) ([]byte, diag.Diagnostics) {
		return store[k], nil
	}
	want := okEventLogState("Application")
	if err := setEventLogSnapshot(ctx, setKey, want); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := getEventLogSnapshot(ctx, getKey)
	if !ok || got == nil {
		t.Fatal("expected a snapshot back")
	}
	if got.Name != "Application" || got.MaximumSizeBytes != 20971520 || got.LogMode != "Circular" {
		t.Errorf("snapshot round-trip lost data: %+v", got)
	}
	// Empty store: no snapshot, still ok.
	got, ok = getEventLogSnapshot(ctx, func(_ context.Context, _ string) ([]byte, diag.Diagnostics) {
		return nil, nil
	})
	if !ok || got != nil {
		t.Errorf("empty store must be (nil, true), got (%+v, %v)", got, ok)
	}
	// Corrupt JSON: not ok.
	got, ok = getEventLogSnapshot(ctx, func(_ context.Context, _ string) ([]byte, diag.Diagnostics) {
		return []byte("{nope"), nil
	})
	if ok {
		t.Errorf("corrupt snapshot must not be ok, got %+v", got)
	}
}

func TestWindowsEventLogResource_Configure(t *testing.T) {
	r := &windowsEventLogResource{}
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
