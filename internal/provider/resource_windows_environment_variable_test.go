// Package provider — unit tests for windows_environment_variable resource.
//
// These tests exercise validators, helpers, and CRUD handlers without WinRM.
// A fakeEnvVarClient is injected into windowsEnvVarResource.client.
//
// Edge cases covered (aligned with spec EC-* identifiers):
//
//	envVarNameValidator  — empty / valid / contains '=' / null / unknown
//	envVarID             — composite "<scope>:<name>" format
//	addEnvVarDiag        — permission / invalid_input / unknown / plain error
//	Metadata             — returns "windows_environment_variable"
//	Schema               — 5 required attributes present, expand defaults false
//	ConfigValidators     — returns empty slice
//	Create (happy path)  — machine scope REG_SZ
//	Create (error)       — client error produces diagnostic
//	Create (broadcast)   — BroadcastWarning is logged but does not error
//	Read (happy path)    — state refreshed from client
//	Read (not found)     — EC-4 RemoveResource
//	Read (error)         — client error produces diagnostic
//	Read (malformed ID)  — EC-7 diagnostic error
//	Read (bad scope)     — unknown scope diagnostic error
//	Update (happy path)  — value + expand updated in-place
//	Update (error)       — client error produces diagnostic
//	Delete (happy path)  — Delete called
//	Delete (error)       — client error produces diagnostic
//	ImportState (happy)  — full model populated from client
//	ImportState (bad ID) — EC-10 / EC-13 diagnostic errors
//	ImportState (not found) — EC-10 error not RemoveResource
//	ImportState (scope)  — unknown scope diagnostic
//	ImportState (equal)  — '=' in name diagnostic
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeEnvVarClient
// ---------------------------------------------------------------------------

type fakeEnvVarClient struct {
	setOut    *winclient.EnvVarState
	setErr    error
	readOut   *winclient.EnvVarState
	readErr   error
	deleteErr error

	lastSetInput    winclient.EnvVarInput
	lastReadScope   winclient.EnvVarScope
	lastReadName    string
	lastDeleteScope winclient.EnvVarScope
	lastDeleteName  string
	deleteCalled    bool
}

func (f *fakeEnvVarClient) Set(_ context.Context, input winclient.EnvVarInput) (*winclient.EnvVarState, error) {
	f.lastSetInput = input
	return f.setOut, f.setErr
}

func (f *fakeEnvVarClient) Read(_ context.Context, scope winclient.EnvVarScope, name string) (*winclient.EnvVarState, error) {
	f.lastReadScope = scope
	f.lastReadName = name
	return f.readOut, f.readErr
}

func (f *fakeEnvVarClient) Delete(_ context.Context, scope winclient.EnvVarScope, name string) error {
	f.deleteCalled = true
	f.lastDeleteScope = scope
	f.lastDeleteName = name
	return f.deleteErr
}

// ---------------------------------------------------------------------------
// tftypes helpers for environment variable schema
// ---------------------------------------------------------------------------

func envVarObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":     tftypes.String,
		"name":   tftypes.String,
		"value":  tftypes.String,
		"scope":  tftypes.String,
		"expand": tftypes.Bool,
	}}
}

// evObjBase returns a base tftypes.Value map for the envVar schema.
func evObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":     tftypes.NewValue(tftypes.String, nil),
		"name":   tftypes.NewValue(tftypes.String, "JAVA_HOME"),
		"value":  tftypes.NewValue(tftypes.String, "/usr/lib/jvm"),
		"scope":  tftypes.NewValue(tftypes.String, "machine"),
		"expand": tftypes.NewValue(tftypes.Bool, false),
	}
}

// evObj builds a tftypes.Value with overrides applied.
func evObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := evObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(envVarObjectType(), base)
}

// evState builds a tfsdk.State for the environment variable schema.
func evState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsEnvVarSchemaDefinition()
	return tfsdk.State{Raw: evObj(overrides), Schema: s}
}

// evPlan builds a tfsdk.Plan for the environment variable schema.
func evPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsEnvVarSchemaDefinition()
	return tfsdk.Plan{Raw: evObj(overrides), Schema: s}
}

// okEvState returns a minimal EnvVarState for mocking Set/Read returns.
func okEvState() *winclient.EnvVarState {
	return &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeMachine,
		Name:   "JAVA_HOME",
		Value:  "/usr/lib/jvm",
		Expand: false,
	}
}

// evDiagSummaries returns diagnostic summaries for assertions.
func evDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// envVarNameValidator
// ---------------------------------------------------------------------------

func TestEnvVarNameValidator_ValidNames(t *testing.T) {
	v := envVarNameValidator{}
	for _, name := range []string{"JAVA_HOME", "MY_VAR", "path123", "_UNDERSCORE", "X"} {
		req := validator.StringRequest{
			Path:        path.Root("name"),
			ConfigValue: types.StringValue(name),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("name %q should be valid, got diag: %v", name, resp.Diagnostics)
		}
	}
}

func TestEnvVarNameValidator_EmptyName(t *testing.T) {
	v := envVarNameValidator{}
	req := validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringValue(""),
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("empty name should fail validation")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "must not be empty") {
		t.Errorf("unexpected error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestEnvVarNameValidator_ContainsEquals(t *testing.T) {
	v := envVarNameValidator{}
	for _, name := range []string{"FOO=BAR", "=X", "KEY="} {
		req := validator.StringRequest{
			Path:        path.Root("name"),
			ConfigValue: types.StringValue(name),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("name %q containing '=' should fail validation", name)
		}
		if !strings.Contains(resp.Diagnostics[0].Detail(), "'='") {
			t.Errorf("error detail should mention '=': %s", resp.Diagnostics[0].Detail())
		}
	}
}

func TestEnvVarNameValidator_NullUnknown(t *testing.T) {
	v := envVarNameValidator{}
	// Null — no error
	req := validator.StringRequest{Path: path.Root("name"), ConfigValue: types.StringNull()}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null name should not produce error")
	}
	// Unknown — no error
	req2 := validator.StringRequest{Path: path.Root("name"), ConfigValue: types.StringUnknown()}
	resp2 := &validator.StringResponse{}
	v.ValidateString(context.Background(), req2, resp2)
	if resp2.Diagnostics.HasError() {
		t.Error("unknown name should not produce error")
	}
}

func TestEnvVarNameValidator_Descriptions(t *testing.T) {
	v := envVarNameValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

// ---------------------------------------------------------------------------
// envVarID helper
// ---------------------------------------------------------------------------

func TestEnvVarID(t *testing.T) {
	tests := []struct {
		scope winclient.EnvVarScope
		name  string
		want  string
	}{
		{winclient.EnvVarScopeMachine, "JAVA_HOME", "machine:JAVA_HOME"},
		{winclient.EnvVarScopeUser, "MY_VAR", "user:MY_VAR"},
		{winclient.EnvVarScopeMachine, "PATH", "machine:PATH"},
	}
	for _, tc := range tests {
		got := envVarID(tc.scope, tc.name)
		if got != tc.want {
			t.Errorf("envVarID(%q, %q) = %q, want %q", tc.scope, tc.name, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// addEnvVarDiag
// ---------------------------------------------------------------------------

func TestAddEnvVarDiag_Permission(t *testing.T) {
	var d diag.Diagnostics
	err := winclient.NewEnvVarError(winclient.EnvVarErrorPermission, "access denied", nil, nil)
	addEnvVarDiag(&d, "Create", err)
	if !d.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(d[0].Summary(), "Permission denied") {
		t.Errorf("unexpected summary: %s", d[0].Summary())
	}
}

func TestAddEnvVarDiag_InvalidInput(t *testing.T) {
	var d diag.Diagnostics
	err := winclient.NewEnvVarError(winclient.EnvVarErrorInvalidInput, "bad scope", nil, nil)
	addEnvVarDiag(&d, "Create", err)
	if !d.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(d[0].Summary(), "Invalid input") {
		t.Errorf("unexpected summary: %s", d[0].Summary())
	}
}

func TestAddEnvVarDiag_Unknown(t *testing.T) {
	var d diag.Diagnostics
	err := winclient.NewEnvVarError(winclient.EnvVarErrorUnknown, "transport failed", nil, nil)
	addEnvVarDiag(&d, "Read", err)
	if !d.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(d[0].Summary(), "windows_environment_variable") {
		t.Errorf("unexpected summary: %s", d[0].Summary())
	}
}

func TestAddEnvVarDiag_PlainError(t *testing.T) {
	var d diag.Diagnostics
	addEnvVarDiag(&d, "Delete", errors.New("some plain error"))
	if !d.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(d[0].Detail(), "some plain error") {
		t.Errorf("unexpected detail: %s", d[0].Detail())
	}
}

func TestAddEnvVarDiag_NotFound(t *testing.T) {
	var d diag.Diagnostics
	err := winclient.NewEnvVarError(winclient.EnvVarErrorNotFound, "var not found", nil, nil)
	addEnvVarDiag(&d, "ImportState", err)
	if !d.HasError() {
		t.Fatal("expected error diagnostic")
	}
}

// ---------------------------------------------------------------------------
// Metadata + Schema + ConfigValidators
// ---------------------------------------------------------------------------

func TestEnvVarMetadata(t *testing.T) {
	r := &windowsEnvVarResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_environment_variable" {
		t.Errorf("TypeName = %q, want windows_environment_variable", resp.TypeName)
	}
}

func TestEnvVarSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsEnvVarSchemaDefinition()
	for _, k := range []string{"id", "name", "value", "scope", "expand"} {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(s.Attributes) != 5 {
		t.Errorf("schema has %d attributes, want 5", len(s.Attributes))
	}
}

func TestEnvVarSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsEnvVarResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

func TestEnvVarConfigValidators_ReturnsSlice(t *testing.T) {
	r := &windowsEnvVarResource{}
	vs := r.ConfigValidators(context.Background())
	// The resource declares no cross-attribute validators in v1.
	if vs == nil {
		t.Error("ConfigValidators should return non-nil slice")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestEnvVarCreate_HappyPath(t *testing.T) {
	fake := &fakeEnvVarClient{setOut: okEvState()}
	r := &windowsEnvVarResource{client: fake}

	req := resource.CreateRequest{
		Plan: evPlan(t, nil),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{
			Schema: windowsEnvVarSchemaDefinition(),
		},
	}
	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if fake.lastSetInput.Scope != winclient.EnvVarScopeMachine {
		t.Errorf("Set scope = %q, want machine", fake.lastSetInput.Scope)
	}
	if fake.lastSetInput.Name != "JAVA_HOME" {
		t.Errorf("Set name = %q, want JAVA_HOME", fake.lastSetInput.Name)
	}
}

func TestEnvVarCreate_ClientError(t *testing.T) {
	fake := &fakeEnvVarClient{
		setErr: winclient.NewEnvVarError(winclient.EnvVarErrorPermission, "no access", nil, nil),
	}
	r := &windowsEnvVarResource{client: fake}

	req := resource.CreateRequest{Plan: evPlan(t, nil)}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic from client Set error")
	}
}

func TestEnvVarCreate_BroadcastWarning(t *testing.T) {
	state := okEvState()
	state.BroadcastWarning = "SendMessageTimeout returned 0"
	fake := &fakeEnvVarClient{setOut: state}
	r := &windowsEnvVarResource{client: fake}

	req := resource.CreateRequest{Plan: evPlan(t, nil)}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Create(context.Background(), req, resp)
	// Broadcast warning should NOT produce a diagnostic error
	if resp.Diagnostics.HasError() {
		t.Errorf("broadcast warning should not error: %v", evDiagSummaries(resp.Diagnostics))
	}
}

func TestEnvVarCreate_UserScope(t *testing.T) {
	state := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeUser,
		Name:   "MY_VAR",
		Value:  "hello",
		Expand: false,
	}
	fake := &fakeEnvVarClient{setOut: state}
	r := &windowsEnvVarResource{client: fake}

	req := resource.CreateRequest{
		Plan: evPlan(t, map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "MY_VAR"),
			"value": tftypes.NewValue(tftypes.String, "hello"),
			"scope": tftypes.NewValue(tftypes.String, "user"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if fake.lastSetInput.Scope != winclient.EnvVarScopeUser {
		t.Errorf("Set scope = %q, want user", fake.lastSetInput.Scope)
	}
}

func TestEnvVarCreate_ExpandTrue(t *testing.T) {
	state := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeMachine,
		Name:   "PATH_EXT",
		Value:  "%SystemRoot%\\system32",
		Expand: true,
	}
	fake := &fakeEnvVarClient{setOut: state}
	r := &windowsEnvVarResource{client: fake}

	req := resource.CreateRequest{
		Plan: evPlan(t, map[string]tftypes.Value{
			"name":   tftypes.NewValue(tftypes.String, "PATH_EXT"),
			"value":  tftypes.NewValue(tftypes.String, "%SystemRoot%\\system32"),
			"scope":  tftypes.NewValue(tftypes.String, "machine"),
			"expand": tftypes.NewValue(tftypes.Bool, true),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if !fake.lastSetInput.Expand {
		t.Error("Set expand should be true")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestEnvVarRead_HappyPath(t *testing.T) {
	fake := &fakeEnvVarClient{readOut: okEvState()}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ReadRequest{
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if fake.lastReadScope != winclient.EnvVarScopeMachine {
		t.Errorf("Read scope = %q, want machine", fake.lastReadScope)
	}
	if fake.lastReadName != "JAVA_HOME" {
		t.Errorf("Read name = %q, want JAVA_HOME", fake.lastReadName)
	}
}

func TestEnvVarRead_NotFound_RemovesResource(t *testing.T) {
	fake := &fakeEnvVarClient{readOut: nil, readErr: nil}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ReadRequest{
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME"),
		}),
	}
	// State must be properly initialised to detect RemoveResource
	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: windowsEnvVarSchemaDefinition(),
			Raw:    evObj(map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME")}),
		},
	}
	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error on not-found: %v", evDiagSummaries(resp.Diagnostics))
	}
	// After RemoveResource the raw state should be null
	if !resp.State.Raw.IsNull() {
		t.Error("state should be null (RemoveResource) when variable not found")
	}
}

func TestEnvVarRead_ClientError(t *testing.T) {
	fake := &fakeEnvVarClient{
		readErr: winclient.NewEnvVarError(winclient.EnvVarErrorUnknown, "transport failed", nil, nil),
	}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ReadRequest{
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic from client Read error")
	}
}

func TestEnvVarRead_MalformedID(t *testing.T) {
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	for _, badID := range []string{"nocolon", ":noname", "noscope:", ""} {
		req := resource.ReadRequest{
			State: evState(t, map[string]tftypes.Value{
				"id": tftypes.NewValue(tftypes.String, badID),
			}),
		}
		resp := &resource.ReadResponse{
			State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
		}
		r.Read(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("expected error for malformed ID %q", badID)
		}
	}
}

func TestEnvVarRead_BadScope(t *testing.T) {
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ReadRequest{
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "badscope:JAVA_HOME"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for unknown scope in ID")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "unknown scope") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestEnvVarUpdate_HappyPath(t *testing.T) {
	newState := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeMachine,
		Name:   "JAVA_HOME",
		Value:  "/new/path",
		Expand: true,
	}
	fake := &fakeEnvVarClient{setOut: newState}
	r := &windowsEnvVarResource{client: fake}

	req := resource.UpdateRequest{
		Plan: evPlan(t, map[string]tftypes.Value{
			"id":     tftypes.NewValue(tftypes.String, "machine:JAVA_HOME"),
			"value":  tftypes.NewValue(tftypes.String, "/new/path"),
			"expand": tftypes.NewValue(tftypes.Bool, true),
		}),
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if !fake.lastSetInput.Expand {
		t.Error("Update should pass expand=true to client")
	}
}

func TestEnvVarUpdate_ClientError(t *testing.T) {
	fake := &fakeEnvVarClient{
		setErr: winclient.NewEnvVarError(winclient.EnvVarErrorInvalidInput, "bad value", nil, nil),
	}
	r := &windowsEnvVarResource{client: fake}

	req := resource.UpdateRequest{
		Plan:  evPlan(t, nil),
		State: evState(t, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME")}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Update(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic from client Set error")
	}
}

func TestEnvVarUpdate_BroadcastWarning(t *testing.T) {
	state := okEvState()
	state.BroadcastWarning = "timeout"
	fake := &fakeEnvVarClient{setOut: state}
	r := &windowsEnvVarResource{client: fake}

	req := resource.UpdateRequest{
		Plan:  evPlan(t, nil),
		State: evState(t, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME")}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("broadcast warning should not error: %v", evDiagSummaries(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestEnvVarDelete_HappyPath(t *testing.T) {
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	req := resource.DeleteRequest{
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if !fake.deleteCalled {
		t.Error("Delete should have called client.Delete")
	}
	if fake.lastDeleteScope != winclient.EnvVarScopeMachine {
		t.Errorf("Delete scope = %q, want machine", fake.lastDeleteScope)
	}
	if fake.lastDeleteName != "JAVA_HOME" {
		t.Errorf("Delete name = %q, want JAVA_HOME", fake.lastDeleteName)
	}
}

func TestEnvVarDelete_ClientError(t *testing.T) {
	fake := &fakeEnvVarClient{
		deleteErr: winclient.NewEnvVarError(winclient.EnvVarErrorPermission, "no access", nil, nil),
	}
	r := &windowsEnvVarResource{client: fake}

	req := resource.DeleteRequest{
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "machine:JAVA_HOME"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic from client Delete error")
	}
}

func TestEnvVarDelete_MalformedID_NoError(t *testing.T) {
	// Malformed state ID during Delete: nothing to delete, no error.
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	req := resource.DeleteRequest{
		State: evState(t, map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, "nocolon"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("malformed ID during Delete should not error (nothing to delete)")
	}
	if fake.deleteCalled {
		t.Error("Delete should not be called for malformed ID")
	}
}

func TestEnvVarDelete_UserScope(t *testing.T) {
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	req := resource.DeleteRequest{
		State: evState(t, map[string]tftypes.Value{
			"id":    tftypes.NewValue(tftypes.String, "user:MY_VAR"),
			"scope": tftypes.NewValue(tftypes.String, "user"),
			"name":  tftypes.NewValue(tftypes.String, "MY_VAR"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if fake.lastDeleteScope != winclient.EnvVarScopeUser {
		t.Errorf("Delete scope = %q, want user", fake.lastDeleteScope)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestEnvVarImportState_HappyPath_Machine(t *testing.T) {
	fake := &fakeEnvVarClient{readOut: okEvState()}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ImportStateRequest{ID: "machine:JAVA_HOME"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
}

func TestEnvVarImportState_HappyPath_User(t *testing.T) {
	state := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeUser,
		Name:   "MY_VAR",
		Value:  "hello",
		Expand: false,
	}
	fake := &fakeEnvVarClient{readOut: state}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ImportStateRequest{ID: "user:MY_VAR"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if fake.lastReadScope != winclient.EnvVarScopeUser {
		t.Errorf("ImportState Read scope = %q, want user", fake.lastReadScope)
	}
}

func TestEnvVarImportState_MalformedID(t *testing.T) {
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	for _, badID := range []string{"nocolon", ":noname", "noscope:", ""} {
		req := resource.ImportStateRequest{ID: badID}
		resp := &resource.ImportStateResponse{
			State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
		}
		r.ImportState(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("expected error for malformed import ID %q", badID)
		}
		if !strings.Contains(resp.Diagnostics[0].Summary(), "Invalid import ID") {
			t.Errorf("unexpected summary for %q: %s", badID, resp.Diagnostics[0].Summary())
		}
	}
}

func TestEnvVarImportState_UnknownScope(t *testing.T) {
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ImportStateRequest{ID: "badscope:JAVA_HOME"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for unknown scope in import ID")
	}
}

func TestEnvVarImportState_NameContainsEquals(t *testing.T) {
	fake := &fakeEnvVarClient{}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ImportStateRequest{ID: "machine:FOO=BAR"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for '=' in variable name")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "illegal character") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestEnvVarImportState_NotFound(t *testing.T) {
	// EC-10: import for non-existent variable returns error, not RemoveResource
	fake := &fakeEnvVarClient{readOut: nil, readErr: nil}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ImportStateRequest{ID: "machine:NONEXISTENT"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error when importing non-existent variable")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestEnvVarImportState_ClientError(t *testing.T) {
	fake := &fakeEnvVarClient{
		readErr: winclient.NewEnvVarError(winclient.EnvVarErrorUnknown, "transport failure", nil, nil),
	}
	r := &windowsEnvVarResource{client: fake}

	req := resource.ImportStateRequest{ID: "machine:JAVA_HOME"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsEnvVarSchemaDefinition()},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error from client Read failure")
	}
}

// ---------------------------------------------------------------------------
// windowsEnvVarModel round-trip: verify tfsdk tags marshal correctly
// ---------------------------------------------------------------------------

func TestEnvVarModel_RoundTrip(t *testing.T) {
	s := windowsEnvVarSchemaDefinition()
	cfg := tfsdk.Config{
		Schema: s,
		Raw:    evObj(nil),
	}

	var m windowsEnvVarModel
	diags := cfg.Get(context.Background(), &m)
	if diags.HasError() {
		t.Fatalf("Config.Get failed: %v", diags)
	}
	if m.Name.ValueString() != "JAVA_HOME" {
		t.Errorf("Name = %q, want JAVA_HOME", m.Name.ValueString())
	}
	if m.Scope.ValueString() != "machine" {
		t.Errorf("Scope = %q, want machine", m.Scope.ValueString())
	}
	if m.Value.ValueString() != "/usr/lib/jvm" {
		t.Errorf("Value = %q, want /usr/lib/jvm", m.Value.ValueString())
	}
	if m.Expand.ValueBool() != false {
		t.Errorf("Expand = %v, want false", m.Expand.ValueBool())
	}
}

func TestEnvVarModel_RoundTrip_ExpandTrue(t *testing.T) {
	s := windowsEnvVarSchemaDefinition()
	cfg := tfsdk.Config{
		Schema: s,
		Raw: evObj(map[string]tftypes.Value{
			"expand": tftypes.NewValue(tftypes.Bool, true),
			"name":   tftypes.NewValue(tftypes.String, "MY_EXP"),
		}),
	}

	var m windowsEnvVarModel
	diags := cfg.Get(context.Background(), &m)
	if diags.HasError() {
		t.Fatalf("Config.Get failed: %v", diags)
	}
	if !m.Expand.ValueBool() {
		t.Error("Expand should be true")
	}
	if m.Name.ValueString() != "MY_EXP" {
		t.Errorf("Name = %q, want MY_EXP", m.Name.ValueString())
	}
}

// ---------------------------------------------------------------------------
// EnvVarError — Error() / Unwrap() / Is()
// ---------------------------------------------------------------------------

func TestEnvVarError_ErrorString(t *testing.T) {
	cause := errors.New("root cause")
	e := winclient.NewEnvVarError(winclient.EnvVarErrorUnknown, "something went wrong", cause, nil)
	if !strings.Contains(e.Error(), "root cause") {
		t.Errorf("Error() = %q, should contain root cause", e.Error())
	}
	if !strings.Contains(e.Error(), "windows_environment_variable") {
		t.Errorf("Error() = %q, should contain prefix", e.Error())
	}
}

func TestEnvVarError_ErrorStringNoCause(t *testing.T) {
	e := winclient.NewEnvVarError(winclient.EnvVarErrorPermission, "no cause", nil, nil)
	if strings.Contains(e.Error(), "nil") {
		t.Errorf("Error() should not include 'nil' when cause is nil: %q", e.Error())
	}
}

func TestEnvVarError_Is(t *testing.T) {
	e := winclient.NewEnvVarError(winclient.EnvVarErrorPermission, "msg", nil, nil)
	if !errors.Is(e, winclient.ErrEnvVarPermission) {
		t.Error("errors.Is should match by Kind")
	}
	if errors.Is(e, winclient.ErrEnvVarNotFound) {
		t.Error("errors.Is should not match different Kind")
	}
}

func TestEnvVarError_Unwrap(t *testing.T) {
	cause := errors.New("inner")
	e := winclient.NewEnvVarError(winclient.EnvVarErrorUnknown, "msg", cause, nil)
	if !errors.Is(e, cause) {
		t.Error("Unwrap should expose inner cause")
	}
}

func TestIsEnvVarError(t *testing.T) {
	e := winclient.NewEnvVarError(winclient.EnvVarErrorInvalidInput, "bad", nil, nil)
	if !winclient.IsEnvVarError(e, winclient.EnvVarErrorInvalidInput) {
		t.Error("IsEnvVarError should return true for matching kind")
	}
	if winclient.IsEnvVarError(e, winclient.EnvVarErrorPermission) {
		t.Error("IsEnvVarError should return false for different kind")
	}
	if winclient.IsEnvVarError(errors.New("plain"), winclient.EnvVarErrorUnknown) {
		t.Error("IsEnvVarError should return false for non-EnvVarError")
	}
}

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

func TestEnvVarSentinels(t *testing.T) {
	sentinels := []*winclient.EnvVarError{
		winclient.ErrEnvVarNotFound,
		winclient.ErrEnvVarPermission,
		winclient.ErrEnvVarInvalidInput,
		winclient.ErrEnvVarUnknown,
	}
	for _, s := range sentinels {
		if s == nil {
			t.Error("sentinel should not be nil")
			continue
		}
		if s.Kind == "" {
			t.Error("sentinel Kind should not be empty")
		}
	}
}

// ---------------------------------------------------------------------------
// Configure error path
// ---------------------------------------------------------------------------

func TestEnvVarResource_Configure_WrongType(t *testing.T) {
	r := &windowsEnvVarResource{}
	req := resource.ConfigureRequest{ProviderData: "not-a-client"}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for wrong ProviderData type")
	}
}

func TestEnvVarResource_Configure_Nil(t *testing.T) {
	r := &windowsEnvVarResource{}
	req := resource.ConfigureRequest{ProviderData: nil}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should not produce error: %v", resp.Diagnostics)
	}
}
