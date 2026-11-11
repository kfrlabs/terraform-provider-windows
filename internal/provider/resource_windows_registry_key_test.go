// Package provider — unit tests for windows_registry_key resource.
//
// These tests exercise the schema, helpers, and CRUD handlers without SSH.
// A fakeRegistryKeyClient is injected into windowsRegistryKeyResource.client.
//
// Edge cases covered:
//
//	purge=false leaves unknown values in place (no DeleteValues call)
//	purge=true deletes only live-minus-managed names, then re-lists
//	(Default) value ("") handled in managed/unknown computation
//	unknown comparison is case-insensitive (registry lookups are)
//	Create on missing key materialises it via EnsureKey
//	Read on missing key removes the resource from state
//	Delete defaults to leaving the key in place; delete_key_on_destroy
//	  removes it, passing recursive through
//	rkID composite ID format
//	ImportState: valid, lowercase hive, malformed IDs
//	applyRKState list mapping, addRKDiag kinds
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeRegistryKeyClient
// ---------------------------------------------------------------------------

type fakeRegistryKeyClient struct {
	ensureOut *winclient.RegistryKeyState
	ensureErr error
	listOut   *winclient.RegistryKeyState
	listErr   error

	deleteValuesErr error
	deleteKeyErr    error

	ensureCalls int
	listCalls   int

	deletedValueNames [][]string
	deleteKeyCalls    []bool
	deleteCalled      bool
}

func (f *fakeRegistryKeyClient) EnsureKey(_ context.Context, hive, regPath string) (*winclient.RegistryKeyState, error) {
	f.ensureCalls++
	return f.ensureOut, f.ensureErr
}

func (f *fakeRegistryKeyClient) List(_ context.Context, hive, regPath string) (*winclient.RegistryKeyState, error) {
	f.listCalls++
	return f.listOut, f.listErr
}

func (f *fakeRegistryKeyClient) DeleteValues(_ context.Context, _, _ string, names []string) error {
	f.deletedValueNames = append(f.deletedValueNames, names)
	return f.deleteValuesErr
}

func (f *fakeRegistryKeyClient) DeleteKey(_ context.Context, _, _ string, recursive bool) error {
	f.deleteCalled = true
	f.deleteKeyCalls = append(f.deleteKeyCalls, recursive)
	return f.deleteKeyErr
}

// sequenceListKeyClient returns a canned List sequence (pre-purge, then
// post-purge re-list) while delegating everything else to the inner fake.
type sequenceListKeyClient struct {
	fake  *fakeRegistryKeyClient
	lists []*winclient.RegistryKeyState
}

func (s *sequenceListKeyClient) EnsureKey(ctx context.Context, hive, regPath string) (*winclient.RegistryKeyState, error) {
	return s.fake.EnsureKey(ctx, hive, regPath)
}

func (s *sequenceListKeyClient) List(ctx context.Context, hive, regPath string) (*winclient.RegistryKeyState, error) {
	s.fake.listCalls++
	if len(s.lists) == 0 {
		return nil, errors.New("sequenceListKeyClient: no more canned List responses")
	}
	out := s.lists[0]
	s.lists = s.lists[1:]
	return out, nil
}

func (s *sequenceListKeyClient) DeleteValues(ctx context.Context, hive, regPath string, names []string) error {
	return s.fake.DeleteValues(ctx, hive, regPath, names)
}

func (s *sequenceListKeyClient) DeleteKey(ctx context.Context, hive, regPath string, recursive bool) error {
	return s.fake.DeleteKey(ctx, hive, regPath, recursive)
}

// okRKState returns a RegistryKeyState with two values for mocking.
func okRKState(names ...string) *winclient.RegistryKeyState {
	if names == nil {
		names = []string{}
	}
	summaries := make([]winclient.RegistryKeyValueSummary, len(names))
	for i, n := range names {
		summaries[i] = winclient.RegistryKeyValueSummary{Name: n, Kind: winclient.RegistryValueKindString}
	}
	return &winclient.RegistryKeyState{
		Hive:       "HKLM",
		Path:       `SOFTWARE\MyApp`,
		Found:      true,
		ValueNames: names,
		Values:     summaries,
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for registry key schema
// ---------------------------------------------------------------------------

func registryKeyObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                    tftypes.String,
		"hive":                  tftypes.String,
		"path":                  tftypes.String,
		"purge_unknown_values":  tftypes.Bool,
		"managed_value_names":   tftypes.List{ElementType: tftypes.String},
		"delete_key_on_destroy": tftypes.Bool,
		"recursive":             tftypes.Bool,
		"value_names":           tftypes.List{ElementType: tftypes.String},
		"unknown_value_names":   tftypes.List{ElementType: tftypes.String},
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

// rkObjBase returns the base tftypes.Value map with purge disabled.
func rkObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                   tftypes.NewValue(tftypes.String, nil),
		"hive":                 tftypes.NewValue(tftypes.String, "HKLM"),
		"path":                 tftypes.NewValue(tftypes.String, `SOFTWARE\MyApp`),
		"purge_unknown_values": tftypes.NewValue(tftypes.Bool, false),
		"managed_value_names": tftypes.NewValue(tftypes.List{ElementType: tftypes.String},
			[]tftypes.Value{tftypes.NewValue(tftypes.String, "Version")}),
		"delete_key_on_destroy": tftypes.NewValue(tftypes.Bool, false),
		"recursive":             tftypes.NewValue(tftypes.Bool, false),
		"value_names":           tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
		"unknown_value_names":   tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}}, nil),
	}
}

// rkObj builds a tftypes.Value with defaults overridden by the given map.
func rkObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := rkObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(registryKeyObjectType(), base)
}

// rkStrList builds a tftypes list-of-string value.
func rkStrList(ss ...string) tftypes.Value {
	vals := make([]tftypes.Value, len(ss))
	for i, s := range ss {
		vals[i] = tftypes.NewValue(tftypes.String, s)
	}
	return tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, vals)
}

// rkDiagSummaries extracts diagnostic summaries for assertion helpers.
func rkDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata + Schema
// ---------------------------------------------------------------------------

func TestRegistryKeyMetadata(t *testing.T) {
	r := &windowsRegistryKeyResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_registry_key" {
		t.Errorf("TypeName = %q, want windows_registry_key", resp.TypeName)
	}
}

func TestRegistryKeySchema_HasRequiredAttributes(t *testing.T) {
	s := windowsRegistryKeySchemaDefinition(context.Background())
	for _, k := range []string{
		"id", "hive", "path",
		"purge_unknown_values", "managed_value_names",
		"delete_key_on_destroy", "recursive",
		"value_names", "unknown_value_names",
		"timeouts",
	} {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestRegistryKeySchema_ResourceLevelCall(t *testing.T) {
	r := &windowsRegistryKeyResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

func TestRegistryKeySchema_DescriptionsMentionCoexistence(t *testing.T) {
	s := windowsRegistryKeySchemaDefinition(context.Background())
	md := s.MarkdownDescription
	for _, want := range []string{"windows_registry_value", "managed_value_names", "terraform import"} {
		if !strings.Contains(md, want) {
			t.Errorf("resource description must mention %q", want)
		}
	}
	purge, ok := s.Attributes["purge_unknown_values"]
	if !ok {
		t.Fatal("schema missing purge_unknown_values")
	}
	type describer interface{ GetDescription() string }
	if d, ok := purge.(describer); ok {
		if !strings.Contains(d.GetDescription(), "managed_value_names") {
			t.Error("purge_unknown_values description must reference managed_value_names")
		}
	}
	pathAttr, ok := s.Attributes["path"]
	if !ok {
		t.Fatal("schema missing path")
	}
	if d, ok := pathAttr.(describer); ok {
		if !strings.Contains(d.GetDescription(), "Policies") {
			t.Error("path description must carry the Group Policy warning")
		}
	}
}

// ---------------------------------------------------------------------------
// rkID / rkUnknownNames / rkManagedNames / applyRKState
// ---------------------------------------------------------------------------

func TestRkID(t *testing.T) {
	if got := rkID("HKLM", `SOFTWARE\MyApp`); got != `HKLM\SOFTWARE\MyApp` {
		t.Errorf("rkID = %q", got)
	}
}

func TestRkUnknownNames(t *testing.T) {
	unknown := rkUnknownNames([]string{"Version", "OOB", ""}, []string{"Version", ""})
	if len(unknown) != 1 || unknown[0] != "OOB" {
		t.Errorf("rkUnknownNames = %q, want [OOB]", unknown)
	}
}

func TestRkUnknownNames_CaseInsensitive(t *testing.T) {
	// Registry value lookups are case-insensitive: a live "version" covered
	// by managed "Version" must not be purged.
	if unknown := rkUnknownNames([]string{"version"}, []string{"Version"}); len(unknown) != 0 {
		t.Errorf("rkUnknownNames = %q, want empty (case-insensitive match)", unknown)
	}
}

func TestRkUnknownNames_Empty(t *testing.T) {
	if unknown := rkUnknownNames([]string{"A"}, []string{"A", "B"}); len(unknown) != 0 {
		t.Errorf("rkUnknownNames = %q, want empty", unknown)
	}
}

func TestApplyRKState_Lists(t *testing.T) {
	m := &windowsRegistryKeyModel{}
	var diags diag.Diagnostics
	applyRKState(m, okRKState("Version", "OOB", ""), []string{"Version", ""}, &diags)
	if diags.HasError() {
		t.Fatalf("applyRKState: %v", diags)
	}
	var names []string
	if d := m.ValueNames.ElementsAs(context.Background(), &names, false); d.HasError() {
		t.Fatalf("ValueNames ElementsAs: %v", d)
	}
	if len(names) != 3 {
		t.Errorf("ValueNames = %q, want 3 entries", names)
	}
	var unknown []string
	if d := m.UnknownValueNames.ElementsAs(context.Background(), &unknown, false); d.HasError() {
		t.Fatalf("UnknownValueNames ElementsAs: %v", d)
	}
	if len(unknown) != 1 || unknown[0] != "OOB" {
		t.Errorf("UnknownValueNames = %q, want [OOB]", unknown)
	}
}

func TestAddRKDiag_Kinds(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{winclient.NewRegistryKeyError(winclient.RegistryKeyErrorPermission, "denied", nil, nil), "permission denied"},
		{winclient.NewRegistryKeyError(winclient.RegistryKeyErrorInvalidInput, "bad", nil, nil), "invalid input"},
		{winclient.NewRegistryKeyError(winclient.RegistryKeyErrorNotFound, "gone", nil, nil), "not found"},
		{errors.New("plain error"), "plain error"},
	}
	for _, tc := range cases {
		var diags diag.Diagnostics
		addRKDiag(&diags, "Create", tc.err)
		if !diags.HasError() {
			t.Errorf("expected error diagnostic for %v", tc.err)
			continue
		}
		if !strings.Contains(rkDiagSummaries(diags)[0], tc.want) {
			t.Errorf("expected %q in diag: %v", tc.want, rkDiagSummaries(diags))
		}
	}
}

// ---------------------------------------------------------------------------
// Create handler
// ---------------------------------------------------------------------------

func TestRegistryKeyCreate_PurgeDisabledLeavesUnknown(t *testing.T) {
	fake := &fakeRegistryKeyClient{ensureOut: okRKState("Version", "OOB")}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rkObj(nil)}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", rkDiagSummaries(resp.Diagnostics))
	}
	if len(fake.deletedValueNames) != 0 {
		t.Errorf("purge=false must not delete values, got %v", fake.deletedValueNames)
	}
	var m windowsRegistryKeyModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != `HKLM\SOFTWARE\MyApp` {
		t.Errorf("ID = %q", m.ID.ValueString())
	}
	var unknown []string
	if d := m.UnknownValueNames.ElementsAs(context.Background(), &unknown, false); d.HasError() {
		t.Fatalf("UnknownValueNames ElementsAs: %v", d)
	}
	if len(unknown) != 1 || unknown[0] != "OOB" {
		t.Errorf("UnknownValueNames = %q, want [OOB] as purge preview", unknown)
	}
}

func TestRegistryKeyCreate_PurgeDeletesOnlyUnknown(t *testing.T) {
	after := okRKState("Version")
	fake := &fakeRegistryKeyClient{
		ensureOut: okRKState("Version", "OOB", "Stale"),
		listOut:   after,
	}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rkObj(map[string]tftypes.Value{
		"purge_unknown_values": tftypes.NewValue(tftypes.Bool, true),
	})}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create purge: %v", rkDiagSummaries(resp.Diagnostics))
	}
	if len(fake.deletedValueNames) != 1 {
		t.Fatalf("expected one DeleteValues call, got %v", fake.deletedValueNames)
	}
	got := fake.deletedValueNames[0]
	if len(got) != 2 || got[0] != "OOB" || got[1] != "Stale" {
		t.Errorf("deleted names = %q, want [OOB Stale]", got)
	}
	var m windowsRegistryKeyModel
	resp.State.Get(context.Background(), &m)
	var unknown []string
	if d := m.UnknownValueNames.ElementsAs(context.Background(), &unknown, false); d.HasError() {
		t.Fatalf("UnknownValueNames ElementsAs: %v", d)
	}
	if len(unknown) != 0 {
		t.Errorf("UnknownValueNames = %q, want empty after purge", unknown)
	}
}

func TestRegistryKeyCreate_PurgeKeepsDefaultWhenManaged(t *testing.T) {
	fake := &fakeRegistryKeyClient{
		ensureOut: okRKState("Version", ""),
		listOut:   okRKState("Version", ""),
	}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rkObj(map[string]tftypes.Value{
		"purge_unknown_values": tftypes.NewValue(tftypes.Bool, true),
		"managed_value_names":  rkStrList("Version", ""),
	})}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create purge: %v", rkDiagSummaries(resp.Diagnostics))
	}
	if len(fake.deletedValueNames) != 0 {
		t.Errorf("Default value listed in managed must not be purged, got %v", fake.deletedValueNames)
	}
}

func TestRegistryKeyCreate_EnsureError(t *testing.T) {
	fake := &fakeRegistryKeyClient{
		ensureErr: winclient.NewRegistryKeyError(winclient.RegistryKeyErrorPermission, "denied", nil, nil),
	}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rkObj(nil)}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic when EnsureKey fails")
	}
}

func TestRegistryKeyCreate_NilStateReturned(t *testing.T) {
	// EnsureKey returns (nil, nil) — should produce diagnostic.
	fake := &fakeRegistryKeyClient{ensureOut: nil, ensureErr: nil}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rkObj(nil)}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic when EnsureKey returns nil state")
	}
}

// ---------------------------------------------------------------------------
// Read handler
// ---------------------------------------------------------------------------

func TestRegistryKeyRead_HappyPath(t *testing.T) {
	fake := &fakeRegistryKeyClient{listOut: okRKState("Version", "OOB")}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	st := tfsdk.State{Schema: s, Raw: rkObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp`),
	})}
	req := resource.ReadRequest{State: st}
	resp := &resource.ReadResponse{State: st}

	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", rkDiagSummaries(resp.Diagnostics))
	}
	if len(fake.deletedValueNames) != 0 {
		t.Error("Read must never purge; it only previews unknown_value_names")
	}
}

func TestRegistryKeyRead_NotFound(t *testing.T) {
	fake := &fakeRegistryKeyClient{listOut: &winclient.RegistryKeyState{
		Hive: "HKLM", Path: `SOFTWARE\Ghost`, Found: false,
		ValueNames: []string{}, Values: []winclient.RegistryKeyValueSummary{},
	}}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	st := tfsdk.State{Schema: s, Raw: rkObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\Ghost`),
	})}
	req := resource.ReadRequest{State: st}
	resp := &resource.ReadResponse{State: st}

	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read on missing key must not error: %v", rkDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state must be removed when key not found")
	}
}

// ---------------------------------------------------------------------------
// Update handler
// ---------------------------------------------------------------------------

func TestRegistryKeyUpdate_PurgeOnUpdate(t *testing.T) {
	fake := &fakeRegistryKeyClient{}
	// First List (pre-purge) sees the unmanaged value; the re-list after
	// the purge sees only the managed one.
	lists := []*winclient.RegistryKeyState{okRKState("Version", "OOB"), okRKState("Version")}
	r := &windowsRegistryKeyResource{client: &sequenceListKeyClient{fake: fake, lists: lists}}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	rawPlan := rkObj(map[string]tftypes.Value{
		"id":                   tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp`),
		"purge_unknown_values": tftypes.NewValue(tftypes.Bool, true),
	})
	rawState := rkObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp`),
	})
	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s}}

	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", rkDiagSummaries(resp.Diagnostics))
	}
	if len(fake.deletedValueNames) != 1 || len(fake.deletedValueNames[0]) != 1 || fake.deletedValueNames[0][0] != "OOB" {
		t.Errorf("Update must purge [OOB], got %v", fake.deletedValueNames)
	}
}

func TestRegistryKeyUpdate_MissingKey(t *testing.T) {
	fake := &fakeRegistryKeyClient{listOut: &winclient.RegistryKeyState{
		Hive: "HKLM", Path: `SOFTWARE\MyApp`, Found: false,
		ValueNames: []string{}, Values: []winclient.RegistryKeyValueSummary{},
	}}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	rawPlan := rkObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp`),
	})
	rawState := rkObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp`),
	})
	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s}}

	r.Update(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("Update on a missing key must produce an error")
	}
}

// ---------------------------------------------------------------------------
// Delete handler
// ---------------------------------------------------------------------------

func TestRegistryKeyDelete_DefaultLeavesKeyInPlace(t *testing.T) {
	fake := &fakeRegistryKeyClient{}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	st := tfsdk.State{Schema: s, Raw: rkObj(nil)}
	req := resource.DeleteRequest{State: st}
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete: %v", rkDiagSummaries(resp.Diagnostics))
	}
	if fake.deleteCalled {
		t.Error("default Delete must leave the key in place (no DeleteKey call)")
	}
}

func TestRegistryKeyDelete_RemovesKey(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		fake := &fakeRegistryKeyClient{}
		r := &windowsRegistryKeyResource{client: fake}
		s := windowsRegistryKeySchemaDefinition(context.Background())

		st := tfsdk.State{Schema: s, Raw: rkObj(map[string]tftypes.Value{
			"delete_key_on_destroy": tftypes.NewValue(tftypes.Bool, true),
			"recursive":             tftypes.NewValue(tftypes.Bool, recursive),
		})}
		req := resource.DeleteRequest{State: st}
		resp := &resource.DeleteResponse{}

		r.Delete(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("Delete recursive=%v: %v", recursive, rkDiagSummaries(resp.Diagnostics))
		}
		if !fake.deleteCalled {
			t.Fatalf("recursive=%v: expected DeleteKey call", recursive)
		}
		if fake.deleteKeyCalls[0] != recursive {
			t.Errorf("recursive=%v: DeleteKey got recursive=%v", recursive, fake.deleteKeyCalls[0])
		}
	}
}

func TestRegistryKeyDelete_KeyError(t *testing.T) {
	fake := &fakeRegistryKeyClient{
		deleteKeyErr: winclient.NewRegistryKeyError(winclient.RegistryKeyErrorUnknown, "boom", nil, nil),
	}
	r := &windowsRegistryKeyResource{client: fake}
	s := windowsRegistryKeySchemaDefinition(context.Background())

	st := tfsdk.State{Schema: s, Raw: rkObj(map[string]tftypes.Value{
		"delete_key_on_destroy": tftypes.NewValue(tftypes.Bool, true),
		"recursive":             tftypes.NewValue(tftypes.Bool, true),
	})}
	req := resource.DeleteRequest{State: st}
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic when DeleteKey fails")
	}
}

// ---------------------------------------------------------------------------
// ImportState handler
// ---------------------------------------------------------------------------

func TestRegistryKeyImportState_Valid(t *testing.T) {
	r := &windowsRegistryKeyResource{}
	s := windowsRegistryKeySchemaDefinition(context.Background())
	req := resource.ImportStateRequest{ID: `HKLM\SOFTWARE\MyApp`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(registryKeyObjectType(), nil)}}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState valid: %v", rkDiagSummaries(resp.Diagnostics))
	}
	var m windowsRegistryKeyModel
	resp.State.Get(context.Background(), &m)
	if m.Hive.ValueString() != "HKLM" {
		t.Errorf("Hive = %q", m.Hive.ValueString())
	}
	if m.Path.ValueString() != `SOFTWARE\MyApp` {
		t.Errorf("Path = %q", m.Path.ValueString())
	}
	if m.ID.ValueString() != `HKLM\SOFTWARE\MyApp` {
		t.Errorf("ID = %q", m.ID.ValueString())
	}
	if m.ManagedValueNames.IsNull() {
		t.Error("managed_value_names must default to an empty list on import")
	}
}

func TestRegistryKeyImportState_LowercaseHiveNormalized(t *testing.T) {
	r := &windowsRegistryKeyResource{}
	s := windowsRegistryKeySchemaDefinition(context.Background())
	req := resource.ImportStateRequest{ID: `hklm\SOFTWARE\Test`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(registryKeyObjectType(), nil)}}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState lowercase hive: %v", rkDiagSummaries(resp.Diagnostics))
	}
	var m windowsRegistryKeyModel
	resp.State.Get(context.Background(), &m)
	if m.Hive.ValueString() != "HKLM" {
		t.Errorf("Hive should be normalised to HKLM, got %q", m.Hive.ValueString())
	}
}

func TestRegistryKeyImportState_Errors(t *testing.T) {
	s := windowsRegistryKeySchemaDefinition(context.Background())
	for name, id := range map[string]string{
		"no backslash": "HKLM",
		"unknown hive": `BADH\SOFTWARE\Test`,
		"empty path":   `HKLM\`,
	} {
		r := &windowsRegistryKeyResource{}
		req := resource.ImportStateRequest{ID: id}
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}
		r.ImportState(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("%s (%q): expected error", name, id)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestRegistryKeyConfigure(t *testing.T) {
	r := &windowsRegistryKeyResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil must not error: %v", resp.Diagnostics)
	}

	r2 := &windowsRegistryKeyResource{}
	resp2 := &resource.ConfigureResponse{}
	r2.Configure(context.Background(), resource.ConfigureRequest{ProviderData: true}, resp2)
	if !resp2.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp2.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp2.Diagnostics[0].Detail())
	}

	r3 := &windowsRegistryKeyResource{}
	resp3 := &resource.ConfigureResponse{}
	r3.Configure(context.Background(), resource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp3)
	if resp3.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp3.Diagnostics)
	}
	if r3.client == nil {
		t.Error("client must be set after Configure")
	}
}

// ---------------------------------------------------------------------------
// Misc: constructor + plan-level details
// ---------------------------------------------------------------------------

func TestNewWindowsRegistryKeyResource_NotNil(t *testing.T) {
	if NewWindowsRegistryKeyResource() == nil {
		t.Fatal("constructor must not return nil")
	}
}
