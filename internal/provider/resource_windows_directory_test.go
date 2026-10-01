// Package provider — unit tests for windows_directory resource.
//
// These tests exercise the schema, helpers, and CRUD handlers without SSH. A
// fakeDirectoryClient is injected into windowsDirectoryResource.client.
//
// Edge cases covered (aligned with spec EC-* identifiers):
//
//	Metadata                 — returns "windows_directory"
//	Schema                   — required/computed attributes present, defaults
//	Create (happy, present)  — directory created, state populated
//	Create (ensure=absent)   — no client call, empty computed state
//	Create (error)           — client error produces diagnostic
//	Read (happy path)        — state refreshed from client
//	Read (EC-1 not found)    — RemoveResource when ensure=present
//	Read (converged absent)  — ensure=absent + (nil,nil) does not RemoveResource
//	Read (error)             — client error produces diagnostic
//	Update (attributes)      — in-place update via client.Update
//	Update (ensure->absent)  — calls client.Delete
//	Update (not_found drift) — falls back to Create
//	Delete (happy path)      — Delete called with recursive flag
//	Delete (error)           — client error produces diagnostic
//	ImportState (happy)      — full model populated from client
//	ImportState (not found)  — diagnostic error, not RemoveResource
package provider

import (
	"context"
	"errors"
	"testing"

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
		"ensure":                    tftypes.String,
		"recursive_delete":          tftypes.Bool,
		"create_parent_directories": tftypes.Bool,
		"attributes":                tftypes.List{ElementType: tftypes.String},
		"exists_children":           tftypes.Bool,
		"item_count":                tftypes.Number,
		"last_write_time":           tftypes.String,
	}}
}

func dirObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                        tftypes.NewValue(tftypes.String, `C:\app\logs`),
		"path":                      tftypes.NewValue(tftypes.String, `C:\app\logs`),
		"ensure":                    tftypes.NewValue(tftypes.String, "present"),
		"recursive_delete":          tftypes.NewValue(tftypes.Bool, false),
		"create_parent_directories": tftypes.NewValue(tftypes.Bool, true),
		"attributes":                tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
		"exists_children":           tftypes.NewValue(tftypes.Bool, false),
		"item_count":                tftypes.NewValue(tftypes.Number, 0),
		"last_write_time":           tftypes.NewValue(tftypes.String, "2026-10-01T12:00:00Z"),
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
	s := windowsDirectorySchemaDefinition()
	return tfsdk.State{Raw: dirObj(overrides), Schema: s}
}

func dirPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsDirectorySchemaDefinition()
	return tfsdk.Plan{Raw: dirObj(overrides), Schema: s}
}

func okDirState(path string) *winclient.DirectoryState {
	return &winclient.DirectoryState{
		Path:           path,
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
	s := windowsDirectorySchemaDefinition()
	for _, name := range []string{
		"id", "path", "ensure", "recursive_delete", "create_parent_directories",
		"attributes", "exists_children", "item_count", "last_write_time",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	pathAttr := s.Attributes["path"]
	if !pathAttr.IsRequired() {
		t.Error("path must be Required")
	}
	ensureAttr := s.Attributes["ensure"]
	if ensureAttr.IsRequired() {
		t.Error("ensure must be Optional, not Required")
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
	fc := &fakeDirectoryClient{createOut: okDirState(`C:\app\logs`)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.CreateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
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

func TestWindowsDirectoryResource_Create_EnsureAbsent_NoClientCall(t *testing.T) {
	fc := &fakeDirectoryClient{}
	r := &windowsDirectoryResource{client: fc}

	req := resource.CreateRequest{Plan: dirPlan(t, map[string]tftypes.Value{
		"ensure": tftypes.NewValue(tftypes.String, "absent"),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if fc.createCalled {
		t.Error("client.Create should not be called when ensure=absent")
	}
}

func TestWindowsDirectoryResource_Create_Error(t *testing.T) {
	fc := &fakeDirectoryClient{createErr: winclient.NewDirectoryError(winclient.DirectoryErrorTypeConflict, "is a file", nil, nil)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.CreateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on client error")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_Read_HappyPath(t *testing.T) {
	fc := &fakeDirectoryClient{readOut: okDirState(`C:\app\logs`)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ReadRequest{State: dirState(t, nil)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
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
		t.Error("expected state to be removed (null) when directory is absent and ensure=present")
	}
}

func TestWindowsDirectoryResource_Read_ConvergedAbsent_NoRemove(t *testing.T) {
	fc := &fakeDirectoryClient{readOut: nil}
	r := &windowsDirectoryResource{client: fc}

	overrides := map[string]tftypes.Value{"ensure": tftypes.NewValue(tftypes.String, "absent")}
	req := resource.ReadRequest{State: dirState(t, overrides)}
	resp := &resource.ReadResponse{State: dirState(t, overrides)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should not be removed when ensure=absent and directory is absent (converged)")
	}
}

func TestWindowsDirectoryResource_Read_Error(t *testing.T) {
	fc := &fakeDirectoryClient{readErr: winclient.NewDirectoryError(winclient.DirectoryErrorPermission, "denied", nil, nil)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ReadRequest{State: dirState(t, nil)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on client error")
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestWindowsDirectoryResource_Update_Attributes(t *testing.T) {
	fc := &fakeDirectoryClient{updateOut: okDirState(`C:\app\logs`)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.UpdateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if fc.lastUpdatePath != `C:\app\logs` {
		t.Errorf("unexpected update path: %q", fc.lastUpdatePath)
	}
}

func TestWindowsDirectoryResource_Update_EnsureToAbsent_CallsDelete(t *testing.T) {
	fc := &fakeDirectoryClient{}
	r := &windowsDirectoryResource{client: fc}

	req := resource.UpdateRequest{Plan: dirPlan(t, map[string]tftypes.Value{
		"ensure": tftypes.NewValue(tftypes.String, "absent"),
	})}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}
	if !fc.deleteCalled {
		t.Error("expected client.Delete to be called when ensure flips to absent")
	}
}

func TestWindowsDirectoryResource_Update_DriftRecreate(t *testing.T) {
	fc := &fakeDirectoryClient{
		updateErr: winclient.NewDirectoryError(winclient.DirectoryErrorNotFound, "gone", nil, nil),
		createOut: okDirState(`C:\app\logs`),
	}
	r := &windowsDirectoryResource{client: fc}

	req := resource.UpdateRequest{Plan: dirPlan(t, nil)}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
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
	fc := &fakeDirectoryClient{readOut: okDirState(`C:\app\logs`)}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ImportStateRequest{ID: `C:\app\logs`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", dirDiagSummaries(resp.Diagnostics))
	}

	var model windowsDirectoryModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Path.ValueString() != `C:\app\logs` {
		t.Errorf("unexpected path in imported state: %q", model.Path.ValueString())
	}
	if model.Ensure.ValueString() != directoryEnsurePresent {
		t.Errorf("imported ensure should default to present, got %q", model.Ensure.ValueString())
	}
}

func TestWindowsDirectoryResource_ImportState_NotFound(t *testing.T) {
	fc := &fakeDirectoryClient{readOut: nil}
	r := &windowsDirectoryResource{client: fc}

	req := resource.ImportStateRequest{ID: `C:\missing`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.ImportState(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error when importing a non-existent directory")
	}
}

func TestWindowsDirectoryResource_ImportState_EmptyID(t *testing.T) {
	r := &windowsDirectoryResource{client: &fakeDirectoryClient{}}

	req := resource.ImportStateRequest{ID: ""}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsDirectorySchemaDefinition()}}
	r.ImportState(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error for empty import ID")
	}
}
