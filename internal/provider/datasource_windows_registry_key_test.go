// Package provider — unit tests for the windows_registry_key data source.
//
// Tests cover: Metadata, Schema, Configure, Read happy path (value_names +
// values name/kind summary), Default ("") value, not-found, nil result,
// generic error, and the timeouts.read deadline bound.
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

type fakeRegistryKeyClientDS struct {
	listOut *winclient.RegistryKeyState
	listErr error

	deadline time.Time
	ok       bool
}

func (f *fakeRegistryKeyClientDS) EnsureKey(_ context.Context, _, _ string) (*winclient.RegistryKeyState, error) {
	panic("EnsureKey not used in data source")
}

func (f *fakeRegistryKeyClientDS) List(ctx context.Context, _, _ string) (*winclient.RegistryKeyState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.listOut, f.listErr
}

func (f *fakeRegistryKeyClientDS) DeleteValues(_ context.Context, _, _ string, _ []string) error {
	panic("DeleteValues not used in data source")
}

func (f *fakeRegistryKeyClientDS) DeleteKey(_ context.Context, _, _ string, _ bool) error {
	panic("DeleteKey not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func regKeyDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":          tftypes.String,
		"hive":        tftypes.String,
		"path":        tftypes.String,
		"value_names": tftypes.List{ElementType: tftypes.String},
		"values": tftypes.List{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"name": tftypes.String,
			"type": tftypes.String,
		}}},
		"timeouts": dsTimeoutsObjType(),
	}}
}

func regKeyDSConfig(regPath string) tfsdk.Config {
	d := &windowsRegistryKeyDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	emptyStrList := tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil)
	emptyObjList := tftypes.NewValue(tftypes.List{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"name": tftypes.String,
		"type": tftypes.String,
	}}}, nil)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(regKeyDSObjType(), map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, nil),
			"hive":        tftypes.NewValue(tftypes.String, "HKLM"),
			"path":        tftypes.NewValue(tftypes.String, regPath),
			"value_names": emptyStrList,
			"values":      emptyObjList,
			"timeouts":    dsNullTimeoutsValue(),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestRegistryKeyDSMetadata(t *testing.T) {
	d := &windowsRegistryKeyDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_registry_key" {
		t.Errorf("TypeName = %q, want windows_registry_key", resp.TypeName)
	}
}

func TestNewWindowsRegistryKeyDataSource_NotNil(t *testing.T) {
	if NewWindowsRegistryKeyDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestRegistryKeyDSSchema_AllAttributes(t *testing.T) {
	d := &windowsRegistryKeyDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{
		"id", "hive", "path", "value_names", "values", "timeouts",
	} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestRegistryKeyDSSchema_RequiredLookupKeys(t *testing.T) {
	d := &windowsRegistryKeyDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type requiredChecker interface{ IsRequired() bool }
	for _, k := range []string{"hive", "path"} {
		attr := resp.Schema.Attributes[k]
		rc, ok := attr.(requiredChecker)
		if !ok || !rc.IsRequired() {
			t.Errorf("attribute %q must be Required", k)
		}
	}
}

func TestRegistryKeyDSSchema_ComputedFields(t *testing.T) {
	d := &windowsRegistryKeyDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	for _, k := range []string{"id", "value_names", "values"} {
		attr := resp.Schema.Attributes[k]
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestRegistryKeyDSConfigure_Nil(t *testing.T) {
	d := &windowsRegistryKeyDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil must not error: %v", resp.Diagnostics)
	}
}

func TestRegistryKeyDSConfigure_WrongType(t *testing.T) {
	d := &windowsRegistryKeyDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: true}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestRegistryKeyDSConfigure_OK(t *testing.T) {
	d := &windowsRegistryKeyDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path
// ---------------------------------------------------------------------------

func TestRegistryKeyDSRead_HappyPath(t *testing.T) {
	d := &windowsRegistryKeyDataSource{
		client: &fakeRegistryKeyClientDS{
			listOut: &winclient.RegistryKeyState{
				Hive:       "HKLM",
				Path:       `SOFTWARE\MyApp`,
				Found:      true,
				ValueNames: []string{"Version", ""},
				Values: []winclient.RegistryKeyValueSummary{
					{Name: "Version", Kind: winclient.RegistryValueKindString},
					{Name: "", Kind: winclient.RegistryValueKindDWord},
				},
			},
		},
	}
	cfg := regKeyDSConfig(`SOFTWARE\MyApp`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsRegistryKeyDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != `HKLM\SOFTWARE\MyApp` {
		t.Errorf("ID = %q", state.ID.ValueString())
	}
	var names []string
	if diags := state.ValueNames.ElementsAs(context.Background(), &names, false); diags.HasError() {
		t.Fatalf("ValueNames ElementsAs: %v", diags)
	}
	if len(names) != 2 || names[0] != "Version" || names[1] != "" {
		t.Errorf("ValueNames = %q, want [Version \"\"]", names)
	}
	if len(state.Values.Elements()) != 2 {
		t.Fatalf("Values should hold 2 summaries, got %d", len(state.Values.Elements()))
	}
}

// ---------------------------------------------------------------------------
// Read — not found / nil / generic error
// ---------------------------------------------------------------------------

func TestRegistryKeyDSRead_NotFound(t *testing.T) {
	d := &windowsRegistryKeyDataSource{
		client: &fakeRegistryKeyClientDS{
			listOut: &winclient.RegistryKeyState{Found: false},
		},
	}
	cfg := regKeyDSConfig(`SOFTWARE\Missing`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for missing registry key")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestRegistryKeyDSRead_NilResult(t *testing.T) {
	d := &windowsRegistryKeyDataSource{
		client: &fakeRegistryKeyClientDS{listOut: nil, listErr: nil},
	}
	cfg := regKeyDSConfig(`SOFTWARE\Ghost`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("nil result must produce error")
	}
}

func TestRegistryKeyDSRead_GenericError(t *testing.T) {
	d := &windowsRegistryKeyDataSource{
		client: &fakeRegistryKeyClientDS{listErr: errors.New("transport error")},
	}
	cfg := regKeyDSConfig(`SOFTWARE\MyApp`)
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

func TestRegistryKeyDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", registryKeyDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRegistryKeyClientDS{
				listOut: &winclient.RegistryKeyState{
					Hive:       "HKLM",
					Path:       `SOFTWARE\MyApp`,
					Found:      true,
					ValueNames: []string{"Version"},
					Values: []winclient.RegistryKeyValueSummary{
						{Name: "Version", Kind: winclient.RegistryValueKindString},
					},
				},
			}
			d := &windowsRegistryKeyDataSource{client: fake}
			cfg := regKeyDSConfig(`SOFTWARE\MyApp`)
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
