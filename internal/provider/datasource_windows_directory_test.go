// Package provider — unit tests for the windows_directory data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative input attributes), Configure, Read happy path, not-found
// (typed and nil, with a single-line detail so Terraform does not wrap it
// and break ExpectError regexes), generic error, timeouts.read deadline
// propagation (issue #197) and null-config default resolution.
package provider

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeDirectoryClientDS struct {
	readOut *winclient.DirectoryState
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeDirectoryClientDS) Create(_ context.Context, _ winclient.DirectoryInput) (*winclient.DirectoryState, error) {
	panic("Create not used in data source")
}
func (f *fakeDirectoryClientDS) Read(ctx context.Context, _ string) (*winclient.DirectoryState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}
func (f *fakeDirectoryClientDS) Update(_ context.Context, _ string, _ []string) (*winclient.DirectoryState, error) {
	panic("Update not used in data source")
}
func (f *fakeDirectoryClientDS) Delete(_ context.Context, _ string, _ bool) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func directoryDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":              tftypes.String,
		"path":            tftypes.String,
		"exists_children": tftypes.Bool,
		"item_count":      tftypes.Number,
		"last_write_time": tftypes.String,
		"attributes":      tftypes.List{ElementType: tftypes.String},
		"timeouts":        dsTimeoutsObjType(),
	}}
}

func directoryDSConfig(path string) tfsdk.Config {
	d := &windowsDirectoryDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(directoryDSObjType(), map[string]tftypes.Value{
			"id":              tftypes.NewValue(tftypes.String, nil),
			"path":            tftypes.NewValue(tftypes.String, path),
			"exists_children": tftypes.NewValue(tftypes.Bool, nil),
			"item_count":      tftypes.NewValue(tftypes.Number, nil),
			"last_write_time": tftypes.NewValue(tftypes.String, nil),
			"attributes": tftypes.NewValue(
				tftypes.List{ElementType: tftypes.String}, nil),
			"timeouts": dsNullTimeoutsValue(),
		}),
	}
}

func directoryDSState() *winclient.DirectoryState {
	return &winclient.DirectoryState{
		Path:           `C:\acc\lookup`,
		ExistsChildren: true,
		ItemCount:      2,
		LastWriteTime:  "2026-10-01T00:00:00Z",
		Attributes:     []string{"hidden"},
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestDirectoryDSMetadata(t *testing.T) {
	d := &windowsDirectoryDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_directory" {
		t.Errorf("TypeName = %q, want windows_directory", resp.TypeName)
	}
}

func TestNewWindowsDirectoryDataSource_NotNil(t *testing.T) {
	if NewWindowsDirectoryDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestDirectoryDSSchema_AllAttributes(t *testing.T) {
	d := &windowsDirectoryDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "path", "exists_children", "item_count",
		"last_write_time", "attributes", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestDirectoryDSSchema_QueryKeyRequired(t *testing.T) {
	d := &windowsDirectoryDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type requiredChecker interface{ IsRequired() bool }
	type computedChecker interface{ IsComputed() bool }
	attr := resp.Schema.Attributes["path"]
	if attr == nil {
		t.Fatal("attribute path not found")
	}
	rc, ok := attr.(requiredChecker)
	if !ok || !rc.IsRequired() {
		t.Error("attribute path must be Required")
	}
	cc, ok := attr.(computedChecker)
	if !ok || cc.IsComputed() {
		t.Error("attribute path must not be Computed: it is the lookup key")
	}
}

func TestDirectoryDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsDirectoryDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"id", "exists_children", "item_count",
		"last_write_time", "attributes"} {
		attr := resp.Schema.Attributes[k]
		if attr == nil {
			t.Errorf("attribute %q not found", k)
			continue
		}
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
		if oc, ok := attr.(optionalChecker); ok && oc.IsOptional() {
			t.Errorf("attribute %q must not be Optional: observed state is read-only", k)
		}
	}
}

func TestDirectoryDSSchema_NoDeclarativeInputs(t *testing.T) {
	d := &windowsDirectoryDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{
		"ensure", "recursive_delete", "create_parent_directories",
	} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("data source must NOT expose declarative input attribute %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestDirectoryDSConfigure_Nil(t *testing.T) {
	d := &windowsDirectoryDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestDirectoryDSConfigure_WrongType(t *testing.T) {
	d := &windowsDirectoryDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestDirectoryDSConfigure_CorrectType(t *testing.T) {
	d := &windowsDirectoryDataSource{}
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

func TestDirectoryDSRead_HappyPath(t *testing.T) {
	d := &windowsDirectoryDataSource{
		client: &fakeDirectoryClientDS{readOut: directoryDSState()},
	}
	cfg := directoryDSConfig(`C:\acc\lookup`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsDirectoryDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != `C:\acc\lookup` {
		t.Errorf("ID = %q, want the normalised target path", state.ID.ValueString())
	}
	if state.Path.ValueString() != `C:\acc\lookup` {
		t.Errorf("Path = %q, want the queried path echoed back", state.Path.ValueString())
	}
	if !state.ExistsChildren.ValueBool() {
		t.Error("ExistsChildren should be true")
	}
	if state.ItemCount.ValueInt64() != 2 {
		t.Errorf("ItemCount = %d, want 2", state.ItemCount.ValueInt64())
	}
	if state.LastWriteTime.ValueString() != "2026-10-01T00:00:00Z" {
		t.Errorf("LastWriteTime = %q, want the observed timestamp", state.LastWriteTime.ValueString())
	}
	if len(state.Attributes.Elements()) != 1 {
		t.Errorf("attributes has %d elements, want 1", len(state.Attributes.Elements()))
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

// TestDirectoryDSRead_BoundedByTimeouts verifies the data source Read runs under
// a deadline derived from `timeouts.read` (issue #197): directoryDSDefaultTimeout
// when the block is absent, the configured value when set.
func TestDirectoryDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", directoryDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeDirectoryClientDS{readOut: directoryDSState()}
			d := &windowsDirectoryDataSource{client: fake}
			cfg := directoryDSConfig(`C:\acc\lookup`)
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
// Timeouts — null-config default resolution (issue #197)
// ---------------------------------------------------------------------------

// directoryDSnTimeouts builds a datasource timeouts.Value for resolution tests,
// reusing the schema's attribute types so the value matches what the framework
// decodes. A nil read yields the absent-block (null) value.
func directoryDSnTimeouts(t *testing.T, read *string) dstimeouts.Value {
	t.Helper()
	var v attr.Value = types.StringNull()
	if read != nil {
		v = types.StringValue(*read)
	}
	obj, diags := types.ObjectValue(
		map[string]attr.Type{"read": types.StringType},
		map[string]attr.Value{"read": v},
	)
	if diags.HasError() {
		t.Fatalf("ObjectValue: %v", diags)
	}
	return dstimeouts.Value{Object: obj}
}

// TestDirectoryDSnTimeouts_NullConfigDefault verifies `timeouts.read` resolution
// for the data source (issue #197): directoryDSDefaultTimeout when the block is
// absent, the configured value when set. The full Read path needs a live host,
// so resolution is asserted at the model level; BoundedByTimeouts covers
// deadline propagation end to end.
func TestDirectoryDSnTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := directoryDSnTimeouts(t, nil).Read(ctx, directoryDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != directoryDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, directoryDSDefaultTimeout)
	}
	if directoryDSDefaultTimeout != directoryDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", directoryDSDefaultTimeout, directoryDefaultTimeout)
	}

	custom := "45s"
	got, diags = directoryDSnTimeouts(t, &custom).Read(ctx, directoryDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("custom timeouts diags: %v", diags)
	}
	if got != 45*time.Second {
		t.Errorf("custom timeouts resolved to %v, want 45s", got)
	}
}

// ---------------------------------------------------------------------------
// Read — not found (typed and nil) / generic error
// ---------------------------------------------------------------------------

func TestDirectoryDSRead_TypedNotFound(t *testing.T) {
	d := &windowsDirectoryDataSource{
		client: &fakeDirectoryClientDS{
			readErr: &winclient.DirectoryError{Kind: winclient.DirectoryErrorNotFound, Message: "directory not found"},
		},
	}
	cfg := directoryDSConfig(`C:\acc\missing`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for typed not_found")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestDirectoryDSRead_NilResult(t *testing.T) {
	d := &windowsDirectoryDataSource{
		client: &fakeDirectoryClientDS{readOut: nil, readErr: nil},
	}
	cfg := directoryDSConfig(`C:\acc\missing`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for nil state result")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

// TestDirectoryDSRead_NotFoundDetailSingleLine pins the not-found detail to one
// line (lesson from PR #214): Terraform wraps multi-line details, which breaks
// ExpectError regexes in the acceptance suite.
func TestDirectoryDSRead_NotFoundDetailSingleLine(t *testing.T) {
	want := regexp.MustCompile(`No directory .* was found on the target host\.`)

	cases := []struct {
		name   string
		client *fakeDirectoryClientDS
	}{
		{"typed", &fakeDirectoryClientDS{
			readErr: &winclient.DirectoryError{Kind: winclient.DirectoryErrorNotFound, Message: "directory not found"},
		}},
		{"nil", &fakeDirectoryClientDS{readOut: nil, readErr: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &windowsDirectoryDataSource{client: tc.client}
			cfg := directoryDSConfig(`C:\acc\missing`)
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

			d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatal("expected not-found error")
			}
			detail := resp.Diagnostics[0].Detail()
			if strings.Contains(detail, "\n") {
				t.Errorf("not-found detail must be a single line, got: %q", detail)
			}
			if !want.MatchString(detail) {
				t.Errorf("not-found detail %q does not match %v", detail, want)
			}
		})
	}
}

func TestDirectoryDSRead_TypedError(t *testing.T) {
	d := &windowsDirectoryDataSource{
		client: &fakeDirectoryClientDS{
			readErr: &winclient.DirectoryError{Kind: winclient.DirectoryErrorTypeConflict, Message: "path is a file"},
		},
	}
	cfg := directoryDSConfig(`C:\acc\lookup`)
	// A typed client error surfaces through the shared addDirectoryDiag helper,
	// mirroring the resource Read path.
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "conflict") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestDirectoryDSRead_GenericError(t *testing.T) {
	d := &windowsDirectoryDataSource{
		client: &fakeDirectoryClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := directoryDSConfig(`C:\acc\lookup`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}
