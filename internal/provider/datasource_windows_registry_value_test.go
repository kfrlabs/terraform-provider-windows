// Package provider — unit tests for the windows_registry_value data source.
//
// Tests cover: Metadata, Schema, Configure, Read happy path (REG_SZ,
// REG_MULTI_SZ, REG_BINARY), not-found, nil result, generic error,
// and applyRVStateDS field mapping.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeRegistryValueClientDS struct {
	readOut *winclient.RegistryValueState
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeRegistryValueClientDS) Set(_ context.Context, _ winclient.RegistryValueInput) (*winclient.RegistryValueState, error) {
	panic("Set not used in data source")
}
func (f *fakeRegistryValueClientDS) Read(ctx context.Context, _, _, _ string, _ bool) (*winclient.RegistryValueState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}
func (f *fakeRegistryValueClientDS) Delete(_ context.Context, _, _, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func regValueDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                           tftypes.String,
		"hive":                         tftypes.String,
		"path":                         tftypes.String,
		"name":                         tftypes.String,
		"expand_environment_variables": tftypes.Bool,
		"type":                         tftypes.String,
		"value_string":                 tftypes.String,
		"value_strings":                tftypes.List{ElementType: tftypes.String},
		"value_binary":                 tftypes.String,
		"timeouts":                     dsTimeoutsObjType(),
	}}
}

func regValueDSConfig(hive, path, name string) tfsdk.Config {
	d := &windowsRegistryValueDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(regValueDSObjType(), map[string]tftypes.Value{
			"id":                           tftypes.NewValue(tftypes.String, nil),
			"hive":                         tftypes.NewValue(tftypes.String, hive),
			"path":                         tftypes.NewValue(tftypes.String, path),
			"name":                         tftypes.NewValue(tftypes.String, name),
			"expand_environment_variables": tftypes.NewValue(tftypes.Bool, nil),
			"type":                         tftypes.NewValue(tftypes.String, nil),
			"value_string":                 tftypes.NewValue(tftypes.String, nil),
			"value_strings":                tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
			"value_binary":                 tftypes.NewValue(tftypes.String, nil),
			"timeouts":                     dsNullTimeoutsValue(),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestRegistryValueDSMetadata(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_registry_value" {
		t.Errorf("TypeName = %q, want windows_registry_value", resp.TypeName)
	}
}

func TestNewWindowsRegistryValueDataSource_NotNil(t *testing.T) {
	if NewWindowsRegistryValueDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestRegistryValueDSSchema_AllAttributes(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "hive", "path", "name",
		"expand_environment_variables",
		"type", "value_string", "value_strings", "value_binary",
		"timeouts",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestRegistryValueDSSchema_RequiredLookupKeys(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type requiredChecker interface{ IsRequired() bool }
	for _, k := range []string{"hive", "path", "name"} {
		attr := resp.Schema.Attributes[k]
		rc, ok := attr.(requiredChecker)
		if !ok || !rc.IsRequired() {
			t.Errorf("attribute %q must be Required", k)
		}
	}
}

func TestRegistryValueDSSchema_ComputedValueFields(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	for _, k := range []string{"id", "type", "value_string", "value_strings", "value_binary"} {
		attr := resp.Schema.Attributes[k]
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

func TestRegistryValueDSSchema_ExpandEnvVarsOptional(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type optionalChecker interface{ IsOptional() bool }
	attr := resp.Schema.Attributes["expand_environment_variables"]
	oc, ok := attr.(optionalChecker)
	if !ok || !oc.IsOptional() {
		t.Error("expand_environment_variables must be Optional")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestRegistryValueDSConfigure_Nil(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil must not error: %v", resp.Diagnostics)
	}
}

func TestRegistryValueDSConfigure_WrongType(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: true}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestRegistryValueDSConfigure_OK(t *testing.T) {
	d := &windowsRegistryValueDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path REG_SZ
// ---------------------------------------------------------------------------

func TestRegistryValueDSRead_REGSZ(t *testing.T) {
	val := "C:\\Windows"
	d := &windowsRegistryValueDataSource{
		client: &fakeRegistryValueClientDS{
			readOut: &winclient.RegistryValueState{
				Hive:        "HKLM",
				Path:        "SOFTWARE\\MyApp",
				Name:        "InstallDir",
				Kind:        winclient.RegistryValueKindString,
				ValueString: &val,
			},
		},
	}
	cfg := regValueDSConfig("HKLM", "SOFTWARE\\MyApp", "InstallDir")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsRegistryValueDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Type.ValueString() != "REG_SZ" {
		t.Errorf("Type = %q, want REG_SZ", state.Type.ValueString())
	}
	if state.ValueString.ValueString() != "C:\\Windows" {
		t.Errorf("ValueString = %q", state.ValueString.ValueString())
	}
	if !state.ValueStrings.IsNull() {
		t.Error("ValueStrings should be null for REG_SZ")
	}
}

// ---------------------------------------------------------------------------
// Read — REG_MULTI_SZ
// ---------------------------------------------------------------------------

func TestRegistryValueDSRead_REGMULTISZ(t *testing.T) {
	d := &windowsRegistryValueDataSource{
		client: &fakeRegistryValueClientDS{
			readOut: &winclient.RegistryValueState{
				Hive:         "HKLM",
				Path:         "SOFTWARE\\MyApp",
				Name:         "MultiVal",
				Kind:         winclient.RegistryValueKindMultiString,
				ValueStrings: []string{"alpha", "beta"},
			},
		},
	}
	cfg := regValueDSConfig("HKLM", "SOFTWARE\\MyApp", "MultiVal")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsRegistryValueDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Type.ValueString() != "REG_MULTI_SZ" {
		t.Errorf("Type = %q", state.Type.ValueString())
	}
	if state.ValueStrings.IsNull() || state.ValueStrings.IsUnknown() {
		t.Error("ValueStrings should be populated")
	}
}

// ---------------------------------------------------------------------------
// Read — REG_BINARY
// ---------------------------------------------------------------------------

func TestRegistryValueDSRead_REGBINARY(t *testing.T) {
	hex := "deadbeef"
	d := &windowsRegistryValueDataSource{
		client: &fakeRegistryValueClientDS{
			readOut: &winclient.RegistryValueState{
				Hive:        "HKLM",
				Path:        "SOFTWARE\\MyApp",
				Name:        "BinVal",
				Kind:        winclient.RegistryValueKindBinary,
				ValueBinary: &hex,
			},
		},
	}
	cfg := regValueDSConfig("HKLM", "SOFTWARE\\MyApp", "BinVal")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	var state windowsRegistryValueDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ValueBinary.ValueString() != "deadbeef" {
		t.Errorf("ValueBinary = %q", state.ValueBinary.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — not found
// ---------------------------------------------------------------------------

func TestRegistryValueDSRead_NotFound(t *testing.T) {
	d := &windowsRegistryValueDataSource{
		client: &fakeRegistryValueClientDS{
			readErr: winclient.NewRegistryValueError(winclient.RegistryValueErrorNotFound, "not found", nil, nil),
		},
	}
	cfg := regValueDSConfig("HKLM", "SOFTWARE\\Missing", "Val")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for not-found registry value")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestRegistryValueDSRead_NilResult(t *testing.T) {
	d := &windowsRegistryValueDataSource{
		client: &fakeRegistryValueClientDS{readOut: nil, readErr: nil},
	}
	cfg := regValueDSConfig("HKLM", "SOFTWARE\\Ghost", "Val")
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

func TestRegistryValueDSRead_GenericError(t *testing.T) {
	d := &windowsRegistryValueDataSource{
		client: &fakeRegistryValueClientDS{readErr: errors.New("transport error")},
	}
	cfg := regValueDSConfig("HKLM", "SOFTWARE\\MyApp", "Val")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

// TestRegistryValueDSRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read` (issue #197):
// registryValueDSDefaultTimeout when the block is absent, the configured value
// when set.
func TestRegistryValueDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()
	val := "C:\\Windows"

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", registryValueDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRegistryValueClientDS{
				readOut: &winclient.RegistryValueState{
					Hive:        "HKLM",
					Path:        "SOFTWARE\\MyApp",
					Name:        "InstallDir",
					Kind:        winclient.RegistryValueKindString,
					ValueString: &val,
				},
			}
			d := &windowsRegistryValueDataSource{client: fake}
			cfg := regValueDSConfig("HKLM", "SOFTWARE\\MyApp", "InstallDir")
			if tc.customRead != "" {
				cfg = dsConfigWithReadTimeout(t, cfg, tc.customRead)
			}
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
			d.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound (issue #197)")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
	}
}
