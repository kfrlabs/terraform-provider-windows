// Package provider — unit tests for windows_environment_variable data source.
//
// These tests exercise the data source schema, Metadata, Configure, and Read
// handlers without WinRM. The fakeEnvVarClient defined in the resource test
// file is reused (same package).
//
// Edge cases covered:
//
//	Metadata     — returns "windows_environment_variable"
//	Schema       — 5 attributes present (id/name/value/scope/expand)
//	Configure    — nil ProviderData / wrong type
//	Read (happy) — machine scope, found=true, state populated
//	Read (user)  — user scope, found=true
//	Read (expand true) — expand=true reflected in state
//	Read (not found) — nil result → Terraform error (not RemoveResource)
//	Read (client error) — permission / transport → diagnostic error
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// dsEvObjectType — tftypes.Object matching the datasource schema
// ---------------------------------------------------------------------------

func dsEvObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":     tftypes.String,
		"name":   tftypes.String,
		"value":  tftypes.String,
		"scope":  tftypes.String,
		"expand": tftypes.Bool,
	}}
}

// dsEvObjBase returns a base tftypes.Value map for the datasource config.
func dsEvObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":     tftypes.NewValue(tftypes.String, nil),
		"name":   tftypes.NewValue(tftypes.String, "JAVA_HOME"),
		"value":  tftypes.NewValue(tftypes.String, nil),
		"scope":  tftypes.NewValue(tftypes.String, "machine"),
		"expand": tftypes.NewValue(tftypes.Bool, nil),
	}
}

// dsEvObj builds a tftypes.Value for the datasource with overrides applied.
func dsEvObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := dsEvObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(dsEvObjectType(), base)
}

// dsEvSchema returns the datasource schema (extracted from the real datasource).
func dsEvSchema() datasourceschema.Schema {
	ds := &windowsEnvVarDataSource{}
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	return resp.Schema
}

// dsEvConfig builds a tfsdk.Config for the datasource.
func dsEvConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	return tfsdk.Config{
		Schema: dsEvSchema(),
		Raw:    dsEvObj(overrides),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Metadata(t *testing.T) {
	ds := &windowsEnvVarDataSource{}
	req := datasource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_environment_variable" {
		t.Errorf("TypeName = %q, want windows_environment_variable", resp.TypeName)
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Schema_HasAttributes(t *testing.T) {
	s := dsEvSchema()
	for _, k := range []string{"id", "name", "value", "scope", "expand"} {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("datasource schema missing attribute %q", k)
		}
	}
	if len(s.Attributes) != 5 {
		t.Errorf("datasource schema has %d attributes, want 5", len(s.Attributes))
	}
}

func TestEnvVarDataSource_Schema_NameRequired(t *testing.T) {
	s := dsEvSchema()
	attr, ok := s.Attributes["name"]
	if !ok {
		t.Fatal("missing name attribute")
	}
	type requiredAttr interface{ IsRequired() bool }
	if ra, ok := attr.(requiredAttr); ok {
		if !ra.IsRequired() {
			t.Error("name attribute should be Required")
		}
	}
}

func TestEnvVarDataSource_Schema_ScopeRequired(t *testing.T) {
	s := dsEvSchema()
	attr, ok := s.Attributes["scope"]
	if !ok {
		t.Fatal("missing scope attribute")
	}
	type requiredAttr interface{ IsRequired() bool }
	if ra, ok := attr.(requiredAttr); ok {
		if !ra.IsRequired() {
			t.Error("scope attribute should be Required")
		}
	}
}

func TestEnvVarDataSource_Schema_ValueComputed(t *testing.T) {
	s := dsEvSchema()
	attr, ok := s.Attributes["value"]
	if !ok {
		t.Fatal("missing value attribute")
	}
	type computedAttr interface{ IsComputed() bool }
	if ca, ok := attr.(computedAttr); ok {
		if !ca.IsComputed() {
			t.Error("value attribute should be Computed")
		}
	}
}

func TestEnvVarDataSource_Schema_ExpandComputed(t *testing.T) {
	s := dsEvSchema()
	attr, ok := s.Attributes["expand"]
	if !ok {
		t.Fatal("missing expand attribute")
	}
	type computedAttr interface{ IsComputed() bool }
	if ca, ok := attr.(computedAttr); ok {
		if !ca.IsComputed() {
			t.Error("expand attribute should be Computed")
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Configure_Nil(t *testing.T) {
	ds := &windowsEnvVarDataSource{}
	req := datasource.ConfigureRequest{ProviderData: nil}
	resp := &datasource.ConfigureResponse{}
	ds.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should not produce error: %v", resp.Diagnostics)
	}
}

func TestEnvVarDataSource_Configure_WrongType(t *testing.T) {
	ds := &windowsEnvVarDataSource{}
	req := datasource.ConfigureRequest{ProviderData: "not-a-client"}
	resp := &datasource.ConfigureResponse{}
	ds.Configure(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for wrong ProviderData type")
	}
}

// ---------------------------------------------------------------------------
// Read — happy path (machine scope, found)
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Read_HappyPath_Machine(t *testing.T) {
	evs := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeMachine,
		Name:   "JAVA_HOME",
		Value:  "C:\\jdk17",
		Expand: false,
	}
	fake := &fakeEnvVarClient{readOut: evs}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "JAVA_HOME"),
			"scope": tftypes.NewValue(tftypes.String, "machine"),
		}),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
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

// ---------------------------------------------------------------------------
// Read — user scope
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Read_UserScope(t *testing.T) {
	evs := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeUser,
		Name:   "MY_VAR",
		Value:  "user_value",
		Expand: false,
	}
	fake := &fakeEnvVarClient{readOut: evs}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "MY_VAR"),
			"scope": tftypes.NewValue(tftypes.String, "user"),
		}),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	if fake.lastReadScope != winclient.EnvVarScopeUser {
		t.Errorf("Read scope = %q, want user", fake.lastReadScope)
	}
}

// ---------------------------------------------------------------------------
// Read — expand=true reflected in state
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Read_ExpandTrue(t *testing.T) {
	evs := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeMachine,
		Name:   "EXPAND_VAR",
		Value:  "%SystemRoot%\\system32",
		Expand: true,
	}
	fake := &fakeEnvVarClient{readOut: evs}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "EXPAND_VAR"),
			"scope": tftypes.NewValue(tftypes.String, "machine"),
		}),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}
	// Verify expand is written to state
	var m windowsEnvVarModel
	if diags := resp.State.Get(context.Background(), &m); diags.HasError() {
		t.Fatalf("Get state failed: %v", diags)
	}
	if !m.Expand.ValueBool() {
		t.Error("expand should be true in state")
	}
}

// ---------------------------------------------------------------------------
// Read — not found → Terraform error (not RemoveResource)
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Read_NotFound(t *testing.T) {
	fake := &fakeEnvVarClient{readOut: nil, readErr: nil}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, nil),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error when variable not found in data source")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

// ---------------------------------------------------------------------------
// Read — client error → diagnostic error
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Read_PermissionError(t *testing.T) {
	fake := &fakeEnvVarClient{
		readErr: winclient.NewEnvVarError(winclient.EnvVarErrorPermission, "access denied", nil, nil),
	}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, nil),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic from permission error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "Permission denied") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestEnvVarDataSource_Read_TransportError(t *testing.T) {
	fake := &fakeEnvVarClient{
		readErr: winclient.NewEnvVarError(winclient.EnvVarErrorUnknown, "WinRM timeout", nil, nil),
	}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, nil),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic from transport error")
	}
}

func TestEnvVarDataSource_Read_InvalidInputError(t *testing.T) {
	fake := &fakeEnvVarClient{
		readErr: winclient.NewEnvVarError(winclient.EnvVarErrorInvalidInput, "bad scope key", nil, nil),
	}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, nil),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic from invalid input error")
	}
}

// ---------------------------------------------------------------------------
// Read — composite ID format validation
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_Read_IDFormat(t *testing.T) {
	evs := &winclient.EnvVarState{
		Scope:  winclient.EnvVarScopeMachine,
		Name:   "JAVA_HOME",
		Value:  "C:\\jdk17",
		Expand: false,
	}
	fake := &fakeEnvVarClient{readOut: evs}
	ds := &windowsEnvVarDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsEvConfig(t, nil),
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: dsEvSchema()},
	}
	ds.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", evDiagSummaries(resp.Diagnostics))
	}

	var m windowsEnvVarModel
	if diags := resp.State.Get(context.Background(), &m); diags.HasError() {
		t.Fatalf("Get state failed: %v", diags)
	}
	// ID should follow "<scope>:<name>" format
	wantID := "machine:JAVA_HOME"
	if m.ID.ValueString() != wantID {
		t.Errorf("state ID = %q, want %q", m.ID.ValueString(), wantID)
	}
}

// ---------------------------------------------------------------------------
// Verify datasource satisfies interface assertions
// ---------------------------------------------------------------------------

func TestEnvVarDataSource_InterfaceAssertions(t *testing.T) {
	// Compile-time interface checks; this test just ensures the code compiles.
	var _ datasource.DataSource = (*windowsEnvVarDataSource)(nil)
	var _ datasource.DataSourceWithConfigure = (*windowsEnvVarDataSource)(nil)
}
