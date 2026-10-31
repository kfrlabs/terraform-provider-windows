// Package provider — unit tests for the windows_file data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative input attributes and no content attributes), Configure, Read
// happy path, not-found (typed and nil, with a single-line detail so
// Terraform does not wrap it and break ExpectError regexes), generic error,
// timeouts.read deadline propagation (issue #197) and null-config default
// resolution.
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

type fakeFileClientDS struct {
	readOut *winclient.FileState
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeFileClientDS) Set(_ context.Context, _ winclient.FileInput) (*winclient.FileState, error) {
	panic("Set not used in data source")
}
func (f *fakeFileClientDS) Read(ctx context.Context, _ string) (*winclient.FileState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}
func (f *fakeFileClientDS) ReadContent(_ context.Context, _ string, _ int64) (*winclient.FileContent, error) {
	panic("ReadContent not used in data source")
}
func (f *fakeFileClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func fileDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":              tftypes.String,
		"path":            tftypes.String,
		"content_sha256":  tftypes.String,
		"size_bytes":      tftypes.Number,
		"last_write_time": tftypes.String,
		"timeouts":        dsTimeoutsObjType(),
	}}
}

func fileDSConfig(path string) tfsdk.Config {
	d := &windowsFileDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(fileDSObjType(), map[string]tftypes.Value{
			"id":              tftypes.NewValue(tftypes.String, nil),
			"path":            tftypes.NewValue(tftypes.String, path),
			"content_sha256":  tftypes.NewValue(tftypes.String, nil),
			"size_bytes":      tftypes.NewValue(tftypes.Number, nil),
			"last_write_time": tftypes.NewValue(tftypes.String, nil),
			"timeouts":        dsNullTimeoutsValue(),
		}),
	}
}

func fileDSState() *winclient.FileState {
	return &winclient.FileState{
		Path:          `C:\acc\lookup.conf`,
		SHA256:        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		SizeBytes:     4,
		LastWriteTime: "2026-10-01T00:00:00Z",
		Attributes:    []string{"archive"},
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestFileDSMetadata(t *testing.T) {
	d := &windowsFileDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_file" {
		t.Errorf("TypeName = %q, want windows_file", resp.TypeName)
	}
}

func TestNewWindowsFileDataSource_NotNil(t *testing.T) {
	if NewWindowsFileDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestFileDSSchema_AllAttributes(t *testing.T) {
	d := &windowsFileDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "path", "content_sha256", "size_bytes",
		"last_write_time", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestFileDSSchema_QueryKeyRequired(t *testing.T) {
	d := &windowsFileDataSource{}
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

func TestFileDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsFileDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"id", "content_sha256", "size_bytes",
		"last_write_time"} {
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

func TestFileDSSchema_NoDeclarativeInputs(t *testing.T) {
	d := &windowsFileDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{
		"content", "content_base64", "content_wo", "content_base64_wo",
		"content_wo_version", "source", "source_url", "encoding",
		"overwrite", "create_parent_directories", "attributes",
	} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("data source must NOT expose declarative input attribute %q", k)
		}
	}
	for _, k := range []string{"content", "content_base64"} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("metadata-only data source must NOT expose content attribute %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestFileDSConfigure_Nil(t *testing.T) {
	d := &windowsFileDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestFileDSConfigure_WrongType(t *testing.T) {
	d := &windowsFileDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestFileDSConfigure_CorrectType(t *testing.T) {
	d := &windowsFileDataSource{}
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

func TestFileDSRead_HappyPath(t *testing.T) {
	d := &windowsFileDataSource{
		client: &fakeFileClientDS{readOut: fileDSState()},
	}
	cfg := fileDSConfig(`C:\acc\lookup.conf`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsFileDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != `C:\acc\lookup.conf` {
		t.Errorf("ID = %q, want the normalised target path", state.ID.ValueString())
	}
	if state.Path.ValueString() != `C:\acc\lookup.conf` {
		t.Errorf("Path = %q, want the queried path echoed back", state.Path.ValueString())
	}
	if state.ContentSHA256.ValueString() != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("ContentSHA256 = %q, want the observed digest", state.ContentSHA256.ValueString())
	}
	if state.SizeBytes.ValueInt64() != 4 {
		t.Errorf("SizeBytes = %d, want 4", state.SizeBytes.ValueInt64())
	}
	if state.LastWriteTime.ValueString() != "2026-10-01T00:00:00Z" {
		t.Errorf("LastWriteTime = %q, want the observed timestamp", state.LastWriteTime.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

// TestFileDSRead_BoundedByTimeouts verifies the data source Read runs under
// a deadline derived from `timeouts.read` (issue #197): fileDSDefaultTimeout
// when the block is absent, the configured value when set.
func TestFileDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", fileDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeFileClientDS{readOut: fileDSState()}
			d := &windowsFileDataSource{client: fake}
			cfg := fileDSConfig(`C:\acc\lookup.conf`)
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

// fileDSnTimeouts builds a datasource timeouts.Value for resolution tests,
// reusing the schema's attribute types so the value matches what the framework
// decodes. A nil read yields the absent-block (null) value.
func fileDSnTimeouts(t *testing.T, read *string) dstimeouts.Value {
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

// TestFileDSnTimeouts_NullConfigDefault verifies `timeouts.read` resolution
// for the data source (issue #197): fileDSDefaultTimeout when the block is
// absent, the configured value when set. The full Read path needs a live host,
// so resolution is asserted at the model level; BoundedByTimeouts covers
// deadline propagation end to end.
func TestFileDSnTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := fileDSnTimeouts(t, nil).Read(ctx, fileDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != fileDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, fileDSDefaultTimeout)
	}
	if fileDSDefaultTimeout != fileDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", fileDSDefaultTimeout, fileDefaultTimeout)
	}

	custom := "45s"
	got, diags = fileDSnTimeouts(t, &custom).Read(ctx, fileDSDefaultTimeout)
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

func TestFileDSRead_TypedNotFound(t *testing.T) {
	d := &windowsFileDataSource{
		client: &fakeFileClientDS{
			readErr: &winclient.FileError{Kind: winclient.FileErrorNotFound, Message: "file not found"},
		},
	}
	cfg := fileDSConfig(`C:\acc\missing.conf`)
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

func TestFileDSRead_NilResult(t *testing.T) {
	d := &windowsFileDataSource{
		client: &fakeFileClientDS{readOut: nil, readErr: nil},
	}
	cfg := fileDSConfig(`C:\acc\missing.conf`)
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

// TestFileDSRead_NotFoundDetailSingleLine pins the not-found detail to one
// line (lesson from PR #214): Terraform wraps multi-line details, which breaks
// ExpectError regexes in the acceptance suite.
func TestFileDSRead_NotFoundDetailSingleLine(t *testing.T) {
	want := regexp.MustCompile(`No file .* was found on the target host\.`)

	cases := []struct {
		name   string
		client *fakeFileClientDS
	}{
		{"typed", &fakeFileClientDS{
			readErr: &winclient.FileError{Kind: winclient.FileErrorNotFound, Message: "file not found"},
		}},
		{"nil", &fakeFileClientDS{readOut: nil, readErr: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &windowsFileDataSource{client: tc.client}
			cfg := fileDSConfig(`C:\acc\missing.conf`)
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

func TestFileDSRead_TypedError(t *testing.T) {
	d := &windowsFileDataSource{
		client: &fakeFileClientDS{
			readErr: &winclient.FileError{Kind: winclient.FileErrorTypeConflict, Message: "path is a directory"},
		},
	}
	cfg := fileDSConfig(`C:\acc\lookup.conf`)
	// A typed client error surfaces through the shared addFileDiag helper,
	// mirroring the resource Read path.
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "directory") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestFileDSRead_GenericError(t *testing.T) {
	d := &windowsFileDataSource{
		client: &fakeFileClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := fileDSConfig(`C:\acc\lookup.conf`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}
