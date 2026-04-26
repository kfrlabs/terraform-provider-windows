// Package provider — unit tests for the windows_feature data source.
//
// Tests cover: Metadata, Schema, Configure (nil/wrong/correct), Read happy
// path, Read not-found, Read generic error, and model-mapping edge cases.
// All tests run without WinRM via a fake WindowsFeatureClient injected into
// windowsFeatureDataSource.feat.
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

type fakeFeatureClientDS struct {
	readOut *winclient.FeatureInfo
	readErr error
}

func (f *fakeFeatureClientDS) Read(_ context.Context, _ string) (*winclient.FeatureInfo, error) {
	return f.readOut, f.readErr
}
func (f *fakeFeatureClientDS) Install(_ context.Context, _ winclient.FeatureInput) (*winclient.FeatureInfo, *winclient.InstallResult, error) {
	panic("Install must not be called on a data source")
}
func (f *fakeFeatureClientDS) Uninstall(_ context.Context, _ winclient.FeatureInput) (*winclient.FeatureInfo, *winclient.InstallResult, error) {
	panic("Uninstall must not be called on a data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func featureDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":              tftypes.String,
		"name":            tftypes.String,
		"display_name":    tftypes.String,
		"description":     tftypes.String,
		"installed":       tftypes.Bool,
		"restart_pending": tftypes.Bool,
		"install_state":   tftypes.String,
	}}
}

func featureDSConfig(name string) tfsdk.Config {
	d := &windowsFeatureDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(featureDSObjType(), map[string]tftypes.Value{
			"id":              tftypes.NewValue(tftypes.String, nil),
			"name":            tftypes.NewValue(tftypes.String, name),
			"display_name":    tftypes.NewValue(tftypes.String, nil),
			"description":     tftypes.NewValue(tftypes.String, nil),
			"installed":       tftypes.NewValue(tftypes.Bool, nil),
			"restart_pending": tftypes.NewValue(tftypes.Bool, nil),
			"install_state":   tftypes.NewValue(tftypes.String, nil),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestFeatureDSMetadata(t *testing.T) {
	d := &windowsFeatureDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_feature" {
		t.Errorf("TypeName = %q, want windows_feature", resp.TypeName)
	}
}

func TestNewWindowsFeatureDataSource_NotNil(t *testing.T) {
	if NewWindowsFeatureDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestFeatureDSSchema_AllAttributes(t *testing.T) {
	d := &windowsFeatureDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	s := resp.Schema
	want := []string{"id", "name", "display_name", "description", "installed", "restart_pending", "install_state"}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestFeatureDSSchema_NameIsRequired(t *testing.T) {
	d := &windowsFeatureDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	attr := resp.Schema.Attributes["name"]
	if attr == nil {
		t.Fatal("name attribute not found")
	}
	type requiredChecker interface{ IsRequired() bool }
	rc, ok := attr.(requiredChecker)
	if !ok || !rc.IsRequired() {
		t.Error("name attribute must be Required")
	}
}

func TestFeatureDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsFeatureDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	computedOnly := []string{"id", "display_name", "description", "installed", "restart_pending", "install_state"}
	for _, k := range computedOnly {
		attr := resp.Schema.Attributes[k]
		if attr == nil {
			t.Errorf("attribute %q not found", k)
			continue
		}
		type computedChecker interface{ IsComputed() bool }
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestFeatureDSConfigure_Nil(t *testing.T) {
	d := &windowsFeatureDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestFeatureDSConfigure_WrongType(t *testing.T) {
	d := &windowsFeatureDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestFeatureDSConfigure_CorrectType(t *testing.T) {
	d := &windowsFeatureDataSource{}
	resp := &datasource.ConfigureResponse{}
	c := &winclient.Client{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path
// ---------------------------------------------------------------------------

func TestFeatureDSRead_HappyPath(t *testing.T) {
	d := &windowsFeatureDataSource{
		feat: &fakeFeatureClientDS{
			readOut: &winclient.FeatureInfo{
				Name:           "DNS",
				DisplayName:    "DNS Server",
				Description:    "Provides DNS resolution",
				Installed:      true,
				InstallState:   "Installed",
				RestartPending: false,
			},
		},
	}
	cfg := featureDSConfig("DNS")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsFeatureDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Name.ValueString() != "DNS" {
		t.Errorf("Name = %q, want DNS", state.Name.ValueString())
	}
	if !state.Installed.ValueBool() {
		t.Error("Installed should be true")
	}
	if state.ID.ValueString() != "DNS" {
		t.Errorf("ID = %q, want DNS", state.ID.ValueString())
	}
	if state.InstallState.ValueString() != "Installed" {
		t.Errorf("InstallState = %q, want Installed", state.InstallState.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — not found
// ---------------------------------------------------------------------------

func TestFeatureDSRead_NotFoundError(t *testing.T) {
	d := &windowsFeatureDataSource{
		feat: &fakeFeatureClientDS{
			readErr: winclient.NewFeatureError(winclient.FeatureErrorNotFound, "no such feature", nil, nil),
		},
	}
	cfg := featureDSConfig("Missing-Feature")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for not-found feature")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestFeatureDSRead_NilResult(t *testing.T) {
	d := &windowsFeatureDataSource{
		feat: &fakeFeatureClientDS{readOut: nil, readErr: nil},
	}
	cfg := featureDSConfig("Ghost")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for nil feature result")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

// ---------------------------------------------------------------------------
// Read — generic error
// ---------------------------------------------------------------------------

func TestFeatureDSRead_GenericError(t *testing.T) {
	d := &windowsFeatureDataSource{
		feat: &fakeFeatureClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := featureDSConfig("Web-Server")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}

// ---------------------------------------------------------------------------
// Read — model field mapping
// ---------------------------------------------------------------------------

func TestFeatureDSRead_ModelMapping_RestartPending(t *testing.T) {
	d := &windowsFeatureDataSource{
		feat: &fakeFeatureClientDS{
			readOut: &winclient.FeatureInfo{
				Name:           "Telnet-Client",
				DisplayName:    "Telnet Client",
				Description:    "Telnet",
				Installed:      false,
				InstallState:   "Available",
				RestartPending: true,
			},
		},
	}
	cfg := featureDSConfig("Telnet-Client")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	var state windowsFeatureDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.InstallState.ValueString() != "Available" {
		t.Errorf("InstallState = %q, want Available", state.InstallState.ValueString())
	}
	if state.Installed.ValueBool() {
		t.Error("Installed should be false")
	}
	if !state.RestartPending.ValueBool() {
		t.Error("RestartPending should be true")
	}
	if state.DisplayName.ValueString() != "Telnet Client" {
		t.Errorf("DisplayName = %q, want 'Telnet Client'", state.DisplayName.ValueString())
	}
}
