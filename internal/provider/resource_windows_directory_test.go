// Package provider — unit tests for windows_directory resource.
//
// These tests exercise the schema, helpers, and CRUD handlers without SSH. A
// fakeDirectoryClient is injected into windowsDirectoryResource.client.
//
// Edge cases covered (aligned with spec EC-* identifiers):
//
//	Metadata                 — returns "windows_directory"
//	Schema                   — required/computed attributes present, no ensure
//	Create (happy, present)  — directory created, state populated
//	Create (error)           — client error produces diagnostic
//	Read (happy path)        — state refreshed from client
//	Read (EC-1 not found)    — always RemoveResource
//	Read (error)             — client error produces diagnostic
//	Update (attributes)      — in-place update via client.Update
//	Update (not_found drift) — falls back to Create
//	Delete (happy path)      — Delete called with recursive flag
//	Delete (error)           — client error produces diagnostic
//	ImportState (happy)      — full model populated from client
//	ImportState (not found)  — diagnostic error, not RemoveResource
//	UpgradeState (v0 -> v1)  — drops ensure, preserves other fields
package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeDirectoryClient
// ---------------------------------------------------------------------------

type fakeDirectoryClient struct {
	createOut *winclient.DirectoryState
	createErr error
	readOut   *winclient.DirectoryState
	readErr   error
	updateOut *winclient.DirectoryState
	updateErr error
	deleteErr error

	lastCreateInput winclient.DirectoryInput
	lastReadPath    string
	lastUpdatePath  string
	lastUpdateAttrs []string
	lastDeletePath  string
	lastDeleteRec   bool
	deleteCalled    bool
	createCalled    bool
}

func (f *fakeDirectoryClient) Create(_ context.Context, input winclient.DirectoryInput) (*winclient.DirectoryState, error) {
	f.createCalled = true
	f.lastCreateInput = input
	return f.createOut, f.createErr
}

func (f *fakeDirectoryClient) Read(_ context.Context, path string) (*winclient.DirectoryState, error) {
	f.lastReadPath = path
	return f.readOut, f.readErr
}

func (f *fakeDirectoryClient) Update(_ context.Context, path string, attrs []string) (*winclient.DirectoryState, error) {
	f.lastUpdatePath = path
	f.lastUpdateAttrs = attrs
	return f.updateOut, f.updateErr
}

func (f *fakeDirectoryClient) Delete(_ context.Context, path string, recursive bool) error {
	f.deleteCalled = true
	f.lastDeletePath = path
	f.lastDeleteRec = recursive
	return f.deleteErr
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_directory schema
// ---------------------------------------------------------------------------

func dirObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                        tftypes.String,
		"path":                      tftypes.String,
		"recursive_delete":          tftypes.Bool,
		"create_parent_directories": tftypes.Bool,
		"attributes":                tftypes.List{ElementType: tftypes.String},
		"exists_children":           tftypes.Bool,
		"item_count":                tftypes.Number,
		"last_write_time":           tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

// dirNullTimeoutsValue is the zero (absent) value for the `timeouts {}`
// nested attribute, matching the shape in dirObjectType.
func dirNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func dirObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                        tftypes.NewValue(tftypes.String, `C:\app\logs`),
		"path":                      tftypes.NewValue(tftypes.String, `C:\app\logs`),
		"recursive_delete":          tftypes.NewValue(tftypes.Bool, false),
		"create_parent_directories": tftypes.NewValue(tftypes.Bool, true),
		"attributes":                tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
		"exists_children":           tftypes.NewValue(tftypes.Bool, false),
		"item_count":                tftypes.NewValue(tftypes.Number, 0),
		"last_write_time":           tftypes.NewValue(tftypes.String, "2026-10-01T12:00:00Z"),
		"timeouts":                  dirNullTimeoutsValue(),
	}
}

func dirObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := dirObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(dirObjectType(), base)
}

func dirState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsDirectorySchemaDefinition(context.Background())
	return tfsdk.State{Raw: dirObj(overrides), Schema: s}
}

func dirPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsDirectorySchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: dirObj(overrides), Schema: s}
}

func okDirState() *winclient.DirectoryState {
	return &winclient.DirectoryState{
		Path:           `C:\app\logs`,
		ExistsChildren: false,
		ItemCount:      0,
		LastWriteTime:  "2026-10-01T12:00:00Z",
		Attributes:     []string{},
	}
}

func dirDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_Metadata(t *testing.T) {
	r := &windowsDirectoryResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_directory" {
		t.Errorf("TypeName = %q, want windows_directory", resp.TypeName)
	}
}

func TestWindowsDirectorySchemaDefinition(t *testing.T) {
	s := windowsDirectorySchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "path", "recursive_delete", "create_parent_directories",
		"attributes", "exists_children", "item_count", "last_write_time",
		"timeouts",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	if _, ok := s.Attributes["ensure"]; ok {
		t.Error("schema must not contain ensure (removed in #319)")
	}
	pathAttr := s.Attributes["path"]
	if !pathAttr.IsRequired() {
		t.Error("path must be Required")
	}
}

// ---------------------------------------------------------------------------
// addDirectoryDiag
// ---------------------------------------------------------------------------

func TestAddDirectoryDiag_Kinds(t *testing.T) {
	cases := []winclient.DirectoryErrorKind{
		winclient.DirectoryErrorPermission,
		winclient.DirectoryErrorTypeConflict,
		winclient.DirectoryErrorNotEmpty,
		winclient.DirectoryErrorInvalidInput,
		winclient.DirectoryErrorNotFound,
		winclient.DirectoryErrorUnknown,
	}
	for _, kind := range cases {
		var diags diag.Diagnostics
		addDirectoryDiag(&diags, "Create", winclient.NewDirectoryError(kind, "boom", nil, nil))
		if !diags.HasError() {
			t.Errorf("kind %q should produce a diagnostic", kind)
		}
	}

	var diags diag.Diagnostics
	addDirectoryDiag(&diags, "Create", errors.New("plain error"))
	if !diags.HasError() {
		t.Error("plain error should also produce a diagnostic")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_Create_HappyPath(t *testing.T) {
	fc := &fakeDirectoryClient{createOut: okDirState()}
	r := &windowsDirectoryResource{client: fc}

	req := resource.CreateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if !fc.createCalled {
		t.Error("expected client.Create to be called")
	}
	if fc.lastCreateInput.Path != `C:\app\logs` {
		t.Errorf("unexpected create input: %+v", fc.lastCreateInput)
	}
}

func TestWindowsDirectoryResource_Create_Error(t *testing.T) {
	fc := &fakeDirectoryClient{createErr: winclient.NewDirectoryError(winclient.DirectoryErrorTypeConflict, "is a file", nil, nil)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.CreateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on client error")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_Read_HappyPath(t *testing.T) {
	fc := &fakeDirectoryClient{readOut: okDirState()}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ReadRequest{State: dirState(t, nil)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if fc.lastReadPath != `C:\app\logs` {
		t.Errorf("unexpected read path: %q", fc.lastReadPath)
	}
}

func TestWindowsDirectoryResource_Read_NotFound_RemovesResource(t *testing.T) {
	fc := &fakeDirectoryClient{readOut: nil}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ReadRequest{State: dirState(t, nil)}
	resp := &resource.ReadResponse{State: dirState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("expected state to be removed (null) when the directory is absent")
	}
}

func TestWindowsDirectoryResource_Read_Error(t *testing.T) {
	fc := &fakeDirectoryClient{readErr: winclient.NewDirectoryError(winclient.DirectoryErrorPermission, "denied", nil, nil)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ReadRequest{State: dirState(t, nil)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on client error")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_Update_Attributes(t *testing.T) {
	fc := &fakeDirectoryClient{updateOut: okDirState()}
	r := &windowsDirectoryResource{client: fc}

	req := resource.UpdateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if fc.lastUpdatePath != `C:\app\logs` {
		t.Errorf("unexpected update path: %q", fc.lastUpdatePath)
	}
}

func TestWindowsDirectoryResource_Update_DriftRecreate(t *testing.T) {
	fc := &fakeDirectoryClient{
		updateErr: winclient.NewDirectoryError(winclient.DirectoryErrorNotFound, "gone", nil, nil),
		createOut: okDirState(),
	}
	r := &windowsDirectoryResource{client: fc}

	req := resource.UpdateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if !fc.createCalled {
		t.Error("expected fallback to client.Create when Update reports not_found")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_Delete_HappyPath(t *testing.T) {
	fc := &fakeDirectoryClient{}
	r := &windowsDirectoryResource{client: fc}

	req := resource.DeleteRequest{State: dirState(t, map[string]tftypes.Value{
		"recursive_delete": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if !fc.deleteCalled || !fc.lastDeleteRec {
		t.Errorf("expected recursive delete call, got called=%v recursive=%v", fc.deleteCalled, fc.lastDeleteRec)
	}
}

func TestWindowsDirectoryResource_Delete_Error(t *testing.T) {
	fc := &fakeDirectoryClient{deleteErr: winclient.NewDirectoryError(winclient.DirectoryErrorNotEmpty, "not empty", nil, nil)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.DeleteRequest{State: dirState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on client error")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakeDirectoryClient{readOut: okDirState()}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ImportStateRequest{ID: `C:\app\logs`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}

	var model windowsDirectoryModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Path.ValueString() != `C:\app\logs` {
		t.Errorf("unexpected path in imported state: %q", model.Path.ValueString())
	}
}

func TestWindowsDirectoryResource_ImportState_NotFound(t *testing.T) {
	fc := &fakeDirectoryClient{readOut: nil}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ImportStateRequest{ID: `C:\missing`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error when importing a non-existent directory")
	}
}

func TestWindowsDirectoryResource_ImportState_EmptyID(t *testing.T) {
	r := &windowsDirectoryResource{client: &fakeDirectoryClient{}}

	req := resource.ImportStateRequest{ID: ""}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error for empty import ID")
	}
}

// -----------------------------------------------------------------------------
// Timeouts (issue #154): a stalled remote command must surface a bounded
// diagnostic instead of blocking Terraform indefinitely.
// -----------------------------------------------------------------------------

func TestWindowsDirectorySchema_HasTimeoutsBlock(t *testing.T) {
	s := windowsDirectorySchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block (issue #154: CRUD must be time-bounded)")
	}
}

// hangDirectoryClient simulates a stalled transport: Create blocks until the
// passed context is done, then returns the context error.
type hangDirectoryClient struct {
	fakeDirectoryClient
}

func (f *hangDirectoryClient) Create(ctx context.Context, in winclient.DirectoryInput) (*winclient.DirectoryState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// dirTimeoutsRaw builds the raw tftypes value for a timeouts block carrying
// the given per-operation durations.
func dirTimeoutsRaw(durations map[string]string) tftypes.Value {
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

// mustDirTimeouts decodes dirTimeoutsRaw through the resource schema, the
// same path the framework takes for real plans.
func mustDirTimeouts(t *testing.T, durations map[string]string) timeouts.Value {
	t.Helper()
	ctx := context.Background()
	plan := tfsdk.Plan{
		Schema: windowsDirectorySchemaDefinition(ctx),
		Raw: dirObj(map[string]tftypes.Value{
			"timeouts": dirTimeoutsRaw(durations),
		}),
	}
	var m windowsDirectoryModel
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get timeouts: %v", diags)
	}
	return m.Timeouts
}

func TestWindowsDirectoryModelFromState_PreservesTimeouts(t *testing.T) {
	prior := windowsDirectoryModel{
		Timeouts: mustDirTimeouts(t, map[string]string{"create": "5m"}),
	}
	// applyDirectoryState projects onto the caller's model; timeouts configured
	// by the operator must survive the projection.
	m := prior
	applyDirectoryState(&m, okDirState(), &diag.Diagnostics{})
	got, diags := m.Timeouts.Create(context.Background(), directoryDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("Timeouts.Create: %v", diags)
	}
	if got != 5*time.Minute {
		t.Errorf("Timeouts not preserved through applyDirectoryState: create = %v, want 5m", got)
	}
}

func TestWindowsDirectoryResource_Create_StalledTransportIsBounded(t *testing.T) {
	r := &windowsDirectoryResource{client: &hangDirectoryClient{}}

	req := resource.CreateRequest{Plan: dirPlan(t, map[string]tftypes.Value{
		"timeouts": dirTimeoutsRaw(map[string]string{"create": "200ms"}),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition(context.Background())}}

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

// -----------------------------------------------------------------------------
// State upgrade (issue #319: ensure removed)
// -----------------------------------------------------------------------------

func TestWindowsDirectoryResource_UpgradeState_V0ToV1_DropsEnsure(t *testing.T) {
	ctx := context.Background()
	r := &windowsDirectoryResource{}

	upgraders := r.UpgradeState(ctx)
	upgrader, ok := upgraders[0]
	if !ok {
		t.Fatal("expected state upgrader for prior version 0")
	}
	if upgrader.PriorSchema == nil {
		t.Fatal("expected prior schema for version 0")
	}
	if _, ok := upgrader.PriorSchema.Attributes["ensure"]; !ok {
		t.Fatal("prior schema must contain the removed ensure attribute")
	}

	currentSchema := windowsDirectorySchemaDefinition(ctx)
	if currentSchema.Version != 1 {
		t.Errorf("current schema Version = %d, want 1", currentSchema.Version)
	}

	priorObjectType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                        tftypes.String,
		"path":                      tftypes.String,
		"ensure":                    tftypes.String,
		"recursive_delete":          tftypes.Bool,
		"create_parent_directories": tftypes.Bool,
		"attributes":                tftypes.List{ElementType: tftypes.String},
		"exists_children":           tftypes.Bool,
		"item_count":                tftypes.Number,
		"last_write_time":           tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}

	// Both historical ensure values must upgrade to the schema without it.
	for _, ensure := range []string{"present", "absent"} {
		priorRaw := tftypes.NewValue(priorObjectType, map[string]tftypes.Value{
			"id":                        tftypes.NewValue(tftypes.String, `C:\app\logs`),
			"path":                      tftypes.NewValue(tftypes.String, `C:\app\logs`),
			"ensure":                    tftypes.NewValue(tftypes.String, ensure),
			"recursive_delete":          tftypes.NewValue(tftypes.Bool, true),
			"create_parent_directories": tftypes.NewValue(tftypes.Bool, true),
			"attributes": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
				tftypes.NewValue(tftypes.String, "hidden"),
			}),
			"exists_children": tftypes.NewValue(tftypes.Bool, true),
			"item_count":      tftypes.NewValue(tftypes.Number, 3),
			"last_write_time": tftypes.NewValue(tftypes.String, "2026-11-02T15:04:05Z"),
			"timeouts":        dirTimeoutsRaw(map[string]string{"create": "5m"}),
		})

		req := resource.UpgradeStateRequest{State: &tfsdk.State{Schema: *upgrader.PriorSchema, Raw: priorRaw}}
		resp := &resource.UpgradeStateResponse{State: tfsdk.State{Schema: currentSchema}}

		upgrader.StateUpgrader(ctx, req, resp)

		if resp.Diagnostics.HasError() {
			t.Fatalf("ensure=%q: unexpected diagnostics: %v", ensure, dirDiagSummaries(resp.Diagnostics))
		}

		var upgraded windowsDirectoryModel
		resp.Diagnostics.Append(resp.State.Get(ctx, &upgraded)...)
		if resp.Diagnostics.HasError() {
			t.Fatalf("ensure=%q: upgraded state Get: %v", ensure, dirDiagSummaries(resp.Diagnostics))
		}
		if upgraded.Path.ValueString() != `C:\app\logs` {
			t.Errorf("ensure=%q: path = %q, want %q", ensure, upgraded.Path.ValueString(), `C:\app\logs`)
		}
		if upgraded.ID.ValueString() != `C:\app\logs` {
			t.Errorf("ensure=%q: id = %q, want %q", ensure, upgraded.ID.ValueString(), `C:\app\logs`)
		}
		if !upgraded.RecursiveDelete.ValueBool() {
			t.Errorf("ensure=%q: recursive_delete = false, want true", ensure)
		}
		var attrs []string
		resp.Diagnostics.Append(upgraded.Attributes.ElementsAs(ctx, &attrs, false)...)
		if resp.Diagnostics.HasError() {
			t.Fatalf("ensure=%q: attributes ElementsAs: %v", ensure, dirDiagSummaries(resp.Diagnostics))
		}
		if len(attrs) != 1 || attrs[0] != "hidden" {
			t.Errorf("ensure=%q: attributes = %q, want [hidden]", ensure, attrs)
		}
		if !upgraded.ExistsChildren.ValueBool() {
			t.Errorf("ensure=%q: exists_children = false, want true", ensure)
		}
		if upgraded.ItemCount.ValueInt64() != 3 {
			t.Errorf("ensure=%q: item_count = %d, want 3", ensure, upgraded.ItemCount.ValueInt64())
		}
		if upgraded.LastWriteTime.ValueString() != "2026-11-02T15:04:05Z" {
			t.Errorf("ensure=%q: last_write_time = %q, want %q", ensure, upgraded.LastWriteTime.ValueString(), "2026-11-02T15:04:05Z")
		}
		got, diags := upgraded.Timeouts.Create(ctx, directoryDefaultTimeout)
		if diags.HasError() {
			t.Fatalf("ensure=%q: Timeouts.Create: %v", ensure, diags)
		}
		if got != 5*time.Minute {
			t.Errorf("ensure=%q: timeouts.create = %v, want 5m", ensure, got)
		}

		objType, ok := resp.State.Raw.Type().(tftypes.Object)
		if !ok {
			t.Fatalf("ensure=%q: upgraded raw type is %T, want tftypes.Object", ensure, resp.State.Raw.Type())
		}
		if _, ok := objType.AttributeTypes["ensure"]; ok {
			t.Errorf("ensure=%q: upgraded state must not contain ensure", ensure)
		}
	}
}
