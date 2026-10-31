// Package provider — unit tests for the windows_local_group data source.
//
// Tests cover: Metadata, Schema (ExactlyOneOf, Optional+Computed name/sid),
// Configure, Read by name, Read by SID, not-found, nil result, generic error.
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

type fakeLocalGroupClientDS struct {
	importByNameOut *winclient.GroupState
	importByNameErr error
	importBySIDOut  *winclient.GroupState
	importBySIDErr  error

	deadline time.Time
	ok       bool
}

func (f *fakeLocalGroupClientDS) Create(_ context.Context, _ winclient.GroupInput) (*winclient.GroupState, error) {
	panic("Create not used in data source")
}
func (f *fakeLocalGroupClientDS) Read(_ context.Context, _ string) (*winclient.GroupState, error) {
	panic("Read not used in data source")
}
func (f *fakeLocalGroupClientDS) Update(_ context.Context, _ string, _ winclient.GroupInput) (*winclient.GroupState, error) {
	panic("Update not used in data source")
}
func (f *fakeLocalGroupClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}
func (f *fakeLocalGroupClientDS) ImportByName(ctx context.Context, _ string) (*winclient.GroupState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.importByNameOut, f.importByNameErr
}
func (f *fakeLocalGroupClientDS) ImportBySID(ctx context.Context, _ string) (*winclient.GroupState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.importBySIDOut, f.importBySIDErr
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func localGroupDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":          tftypes.String,
		"name":        tftypes.String,
		"sid":         tftypes.String,
		"description": tftypes.String,
		"timeouts":    dsTimeoutsObjType(),
	}}
}

func localGroupDSConfigByName(name string) tfsdk.Config {
	d := &windowsLocalGroupDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(localGroupDSObjType(), map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, nil),
			"name":        tftypes.NewValue(tftypes.String, name),
			"sid":         tftypes.NewValue(tftypes.String, nil),
			"description": tftypes.NewValue(tftypes.String, nil),
			"timeouts":    dsNullTimeoutsValue(),
		}),
	}
}

func localGroupDSConfigBySID(sid string) tfsdk.Config {
	d := &windowsLocalGroupDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(localGroupDSObjType(), map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, nil),
			"name":        tftypes.NewValue(tftypes.String, nil),
			"sid":         tftypes.NewValue(tftypes.String, sid),
			"description": tftypes.NewValue(tftypes.String, nil),
			"timeouts":    dsNullTimeoutsValue(),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestLocalGroupDSMetadata(t *testing.T) {
	d := &windowsLocalGroupDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_local_group" {
		t.Errorf("TypeName = %q, want windows_local_group", resp.TypeName)
	}
}

func TestNewWindowsLocalGroupDataSource_NotNil(t *testing.T) {
	if NewWindowsLocalGroupDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestLocalGroupDSSchema_AllAttributes(t *testing.T) {
	d := &windowsLocalGroupDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "name", "sid", "description", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestLocalGroupDSSchema_NameAndSIDOptional(t *testing.T) {
	d := &windowsLocalGroupDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"name", "sid"} {
		attr := resp.Schema.Attributes[k]
		oc, ok := attr.(optionalChecker)
		if !ok || !oc.IsOptional() {
			t.Errorf("attribute %q must be Optional", k)
		}
	}
}

func TestLocalGroupDSSchema_DescriptionComputed(t *testing.T) {
	d := &windowsLocalGroupDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	type computedChecker interface{ IsComputed() bool }
	for _, k := range []string{"id", "description"} {
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

func TestLocalGroupDSConfigure_Nil(t *testing.T) {
	d := &windowsLocalGroupDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not error: %v", resp.Diagnostics)
	}
}

func TestLocalGroupDSConfigure_WrongType(t *testing.T) {
	d := &windowsLocalGroupDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "bad"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
}

func TestLocalGroupDSConfigure_OK(t *testing.T) {
	d := &windowsLocalGroupDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — by name
// ---------------------------------------------------------------------------

func TestLocalGroupDSRead_ByName_HappyPath(t *testing.T) {
	d := &windowsLocalGroupDataSource{
		grp: &fakeLocalGroupClientDS{
			importByNameOut: &winclient.GroupState{
				Name:        "Administrators",
				SID:         "S-1-5-32-544",
				Description: "Built-in Administrators",
			},
		},
	}
	cfg := localGroupDSConfigByName("Administrators")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsLocalGroupDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Name.ValueString() != "Administrators" {
		t.Errorf("Name = %q", state.Name.ValueString())
	}
	if state.SID.ValueString() != "S-1-5-32-544" {
		t.Errorf("SID = %q", state.SID.ValueString())
	}
	if state.ID.ValueString() != "S-1-5-32-544" {
		t.Errorf("ID = %q, want SID", state.ID.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

// TestLocalGroupDSRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read` (issue #197):
// localGroupDSDefaultTimeout when the block is absent, the configured value
// when set.
func TestLocalGroupDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", localGroupDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeLocalGroupClientDS{
				importByNameOut: &winclient.GroupState{
					Name: "Administrators",
					SID:  "S-1-5-32-544",
				},
			}
			d := &windowsLocalGroupDataSource{grp: fake}
			cfg := localGroupDSConfigByName("Administrators")
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

// ---------------------------------------------------------------------------
// Read — by SID
// ---------------------------------------------------------------------------

func TestLocalGroupDSRead_BySID_HappyPath(t *testing.T) {
	d := &windowsLocalGroupDataSource{
		grp: &fakeLocalGroupClientDS{
			importBySIDOut: &winclient.GroupState{
				Name:        "Users",
				SID:         "S-1-5-32-545",
				Description: "All users",
			},
		},
	}
	cfg := localGroupDSConfigBySID("S-1-5-32-545")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsLocalGroupDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Name.ValueString() != "Users" {
		t.Errorf("Name = %q", state.Name.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — not found
// ---------------------------------------------------------------------------

func TestLocalGroupDSRead_NotFound(t *testing.T) {
	d := &windowsLocalGroupDataSource{
		grp: &fakeLocalGroupClientDS{
			importByNameErr: winclient.NewLocalGroupError(winclient.LocalGroupErrorNotFound, "not found", nil, nil),
		},
	}
	cfg := localGroupDSConfigByName("NoSuchGroup")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for not-found group")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestLocalGroupDSRead_NilResult(t *testing.T) {
	d := &windowsLocalGroupDataSource{
		grp: &fakeLocalGroupClientDS{
			importByNameOut: nil, importByNameErr: nil,
		},
	}
	cfg := localGroupDSConfigByName("GhostGroup")
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

func TestLocalGroupDSRead_GenericError(t *testing.T) {
	d := &windowsLocalGroupDataSource{
		grp: &fakeLocalGroupClientDS{
			importByNameErr: errors.New("SSH gone"),
		},
	}
	cfg := localGroupDSConfigByName("SomeGroup")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic failure")
	}
}
