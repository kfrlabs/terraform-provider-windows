// Package provider — unit tests for the windows_service data source.
//
// Tests cover: Metadata, Schema, Configure, Read happy path (with and
// without dependencies), not-found, nil result, generic error.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeServiceClientDS struct {
	readOut *winclient.ServiceState
	readErr error
}

func (f *fakeServiceClientDS) Create(_ context.Context, _ winclient.ServiceInput) (*winclient.ServiceState, error) {
	panic("Create not used in data source")
}
func (f *fakeServiceClientDS) Read(_ context.Context, _ string) (*winclient.ServiceState, error) {
	return f.readOut, f.readErr
}
func (f *fakeServiceClientDS) Update(_ context.Context, _ string, _ winclient.ServiceInput) (*winclient.ServiceState, error) {
	panic("Update not used in data source")
}
func (f *fakeServiceClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}
func (f *fakeServiceClientDS) StartService(_ context.Context, _ string) error {
	panic("StartService not used in data source")
}
func (f *fakeServiceClientDS) StopService(_ context.Context, _ string) error {
	panic("StopService not used in data source")
}
func (f *fakeServiceClientDS) PauseService(_ context.Context, _ string) error {
	panic("PauseService not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func serviceDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":              tftypes.String,
		"name":            tftypes.String,
		"display_name":    tftypes.String,
		"description":     tftypes.String,
		"binary_path":     tftypes.String,
		"start_type":      tftypes.String,
		"current_status":  tftypes.String,
		"service_account": tftypes.String,
		"dependencies":    tftypes.List{ElementType: tftypes.String},
	}}
}

func serviceDSConfig(name string) tfsdk.Config {
	d := &windowsServiceDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(serviceDSObjType(), map[string]tftypes.Value{
			"id":              tftypes.NewValue(tftypes.String, nil),
			"name":            tftypes.NewValue(tftypes.String, name),
			"display_name":    tftypes.NewValue(tftypes.String, nil),
			"description":     tftypes.NewValue(tftypes.String, nil),
			"binary_path":     tftypes.NewValue(tftypes.String, nil),
			"start_type":      tftypes.NewValue(tftypes.String, nil),
			"current_status":  tftypes.NewValue(tftypes.String, nil),
			"service_account": tftypes.NewValue(tftypes.String, nil),
			"dependencies":    tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestServiceDSMetadata(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_service" {
		t.Errorf("TypeName = %q, want windows_service", resp.TypeName)
	}
}

func TestNewWindowsServiceDataSource_NotNil(t *testing.T) {
	if NewWindowsServiceDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestServiceDSSchema_AllAttributes(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "name", "display_name", "description",
		"binary_path", "start_type", "current_status",
		"service_account", "dependencies",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestServiceDSSchema_NameRequired(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type requiredChecker interface{ IsRequired() bool }
	attr := resp.Schema.Attributes["name"]
	rc, ok := attr.(requiredChecker)
	if !ok || !rc.IsRequired() {
		t.Error("name attribute must be Required")
	}
}

func TestServiceDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	for _, k := range []string{"id", "display_name", "description", "binary_path", "start_type", "current_status", "service_account", "dependencies"} {
		attr := resp.Schema.Attributes[k]
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

func TestServiceDSSchema_NoWriteOnlyAttributes(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"service_password", "status"} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("data source must NOT expose write-only attribute %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestServiceDSConfigure_Nil(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil must not error: %v", resp.Diagnostics)
	}
}

func TestServiceDSConfigure_WrongType(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 3.14}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestServiceDSConfigure_OK(t *testing.T) {
	d := &windowsServiceDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path (no dependencies)
// ---------------------------------------------------------------------------

func TestServiceDSRead_HappyPath_NoDeps(t *testing.T) {
	d := &windowsServiceDataSource{
		svc: &fakeServiceClientDS{
			readOut: &winclient.ServiceState{
				Name:           "Spooler",
				DisplayName:    "Print Spooler",
				Description:    "Manages print jobs",
				BinaryPath:     "C:\\Windows\\System32\\spoolsv.exe",
				StartType:      "Automatic",
				CurrentStatus:  "Running",
				ServiceAccount: "LocalSystem",
				Dependencies:   []string{},
			},
		},
	}
	cfg := serviceDSConfig("Spooler")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsServiceDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Name.ValueString() != "Spooler" {
		t.Errorf("Name = %q", state.Name.ValueString())
	}
	if state.ID.ValueString() != "Spooler" {
		t.Errorf("ID = %q, want Spooler", state.ID.ValueString())
	}
	if state.StartType.ValueString() != "Automatic" {
		t.Errorf("StartType = %q", state.StartType.ValueString())
	}
	if state.CurrentStatus.ValueString() != "Running" {
		t.Errorf("CurrentStatus = %q", state.CurrentStatus.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — happy path with dependencies
// ---------------------------------------------------------------------------

func TestServiceDSRead_HappyPath_WithDeps(t *testing.T) {
	d := &windowsServiceDataSource{
		svc: &fakeServiceClientDS{
			readOut: &winclient.ServiceState{
				Name:         "MySvc",
				Dependencies: []string{"RpcSs", "NTDS"},
			},
		},
	}
	cfg := serviceDSConfig("MySvc")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsServiceDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Dependencies.IsNull() || state.Dependencies.IsUnknown() {
		t.Error("Dependencies should be populated")
	}
	elems := state.Dependencies.Elements()
	if len(elems) != 2 {
		t.Errorf("Dependencies len = %d, want 2", len(elems))
	}
}

// ---------------------------------------------------------------------------
// Read — not found
// ---------------------------------------------------------------------------

func TestServiceDSRead_NotFound(t *testing.T) {
	d := &windowsServiceDataSource{
		svc: &fakeServiceClientDS{
			readErr: winclient.NewServiceError(winclient.ServiceErrorNotFound, "service not found", nil, nil),
		},
	}
	cfg := serviceDSConfig("NoSuchService")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for not-found service")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestServiceDSRead_NilResult(t *testing.T) {
	d := &windowsServiceDataSource{
		svc: &fakeServiceClientDS{readOut: nil, readErr: nil},
	}
	cfg := serviceDSConfig("GhostSvc")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("nil result must produce error")
	}
}

// ---------------------------------------------------------------------------
// Read — generic error
// ---------------------------------------------------------------------------

func TestServiceDSRead_GenericError(t *testing.T) {
	d := &windowsServiceDataSource{
		svc: &fakeServiceClientDS{
			readErr: errors.New("SCM unavailable"),
		},
	}
	cfg := serviceDSConfig("Spooler")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic failure")
	}
}
