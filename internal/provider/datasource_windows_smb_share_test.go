// Package provider — unit tests for the windows_smb_share data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative inputs), Configure, Read happy path (incl. the special flag),
// not-found (typed and nil, with a single-line detail so Terraform does not
// wrap it and break ExpectError regexes), generic error, timeouts.read
// deadline propagation (issue #197) and null-config default resolution.
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

type fakeSmbShareClientDS struct {
	readOut *winclient.SmbShareInfo
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeSmbShareClientDS) Create(_ context.Context, _ winclient.SmbShareInput) (*winclient.SmbShareInfo, error) {
	panic("Create not used in data source")
}
func (f *fakeSmbShareClientDS) Read(ctx context.Context, _ string) (*winclient.SmbShareInfo, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}
func (f *fakeSmbShareClientDS) Update(_ context.Context, _ winclient.SmbShareUpdateInput) (*winclient.SmbShareInfo, error) {
	panic("Update not used in data source")
}
func (f *fakeSmbShareClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func smbShareDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                      tftypes.String,
		"name":                    tftypes.String,
		"path":                    tftypes.String,
		"description":             tftypes.String,
		"folder_enumeration_mode": tftypes.String,
		"caching_mode":            tftypes.String,
		"concurrent_user_limit":   tftypes.Number,
		"encrypt_data":            tftypes.Bool,
		"full_access":             tftypes.Set{ElementType: tftypes.String},
		"change_access":           tftypes.Set{ElementType: tftypes.String},
		"read_access":             tftypes.Set{ElementType: tftypes.String},
		"no_access":               tftypes.Set{ElementType: tftypes.String},
		"special":                 tftypes.Bool,
		"timeouts":                dsTimeoutsObjType(),
	}}
}

func smbShareDSConfig(name string) tfsdk.Config {
	d := &windowsSmbShareDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(smbShareDSObjType(), map[string]tftypes.Value{
			"id":                      tftypes.NewValue(tftypes.String, nil),
			"name":                    tftypes.NewValue(tftypes.String, name),
			"path":                    tftypes.NewValue(tftypes.String, nil),
			"description":             tftypes.NewValue(tftypes.String, nil),
			"folder_enumeration_mode": tftypes.NewValue(tftypes.String, nil),
			"caching_mode":            tftypes.NewValue(tftypes.String, nil),
			"concurrent_user_limit":   tftypes.NewValue(tftypes.Number, nil),
			"encrypt_data":            tftypes.NewValue(tftypes.Bool, nil),
			"full_access":             tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil),
			"change_access":           tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil),
			"read_access":             tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil),
			"no_access":               tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil),
			"special":                 tftypes.NewValue(tftypes.Bool, nil),
			"timeouts":                dsNullTimeoutsValue(),
		}),
	}
}

func smbShareDSState() *winclient.SmbShareInfo {
	return &winclient.SmbShareInfo{
		Name:                  "Finance",
		Path:                  `D:\Shares\Finance`,
		Description:           "Finance share",
		FolderEnumerationMode: "AccessBased",
		CachingMode:           "None",
		EncryptData:           true,
		Special:               false,
		FullAccess:            []winclient.SmbShareTrustee{{Name: `BUILTIN\Administrators`, SID: "S-1-5-32-544"}},
		ReadAccess:            []winclient.SmbShareTrustee{{Name: "Everyone", SID: "S-1-1-1"}},
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestSmbShareDSMetadata(t *testing.T) {
	d := &windowsSmbShareDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_smb_share" {
		t.Errorf("TypeName = %q, want windows_smb_share", resp.TypeName)
	}
}

func TestNewWindowsSmbShareDataSource_NotNil(t *testing.T) {
	if NewWindowsSmbShareDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestSmbShareDSSchema_AllAttributes(t *testing.T) {
	d := &windowsSmbShareDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "name", "path", "description",
		"folder_enumeration_mode", "caching_mode", "concurrent_user_limit",
		"encrypt_data", "full_access", "change_access", "read_access",
		"no_access", "special", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestSmbShareDSSchema_QueryKeyRequired(t *testing.T) {
	d := &windowsSmbShareDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type requiredChecker interface{ IsRequired() bool }
	type computedChecker interface{ IsComputed() bool }
	attr := resp.Schema.Attributes["name"]
	if attr == nil {
		t.Fatal("attribute name not found")
	}
	rc, ok := attr.(requiredChecker)
	if !ok || !rc.IsRequired() {
		t.Error("attribute name must be Required")
	}
	cc, ok := attr.(computedChecker)
	if !ok || cc.IsComputed() {
		t.Error("attribute name must not be Computed: it is the lookup key")
	}
}

func TestSmbShareDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsSmbShareDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"id", "path", "description",
		"folder_enumeration_mode", "caching_mode", "concurrent_user_limit",
		"encrypt_data", "full_access", "change_access", "read_access",
		"no_access", "special"} {
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

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestSmbShareDSConfigure_Nil(t *testing.T) {
	d := &windowsSmbShareDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestSmbShareDSConfigure_WrongType(t *testing.T) {
	d := &windowsSmbShareDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestSmbShareDSConfigure_CorrectType(t *testing.T) {
	d := &windowsSmbShareDataSource{}
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

func TestSmbShareDSRead_HappyPath(t *testing.T) {
	d := &windowsSmbShareDataSource{
		client: &fakeSmbShareClientDS{readOut: smbShareDSState()},
	}
	cfg := smbShareDSConfig("Finance")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsSmbShareDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "Finance" {
		t.Errorf("ID = %q, want the share name", state.ID.ValueString())
	}
	if state.Path.ValueString() != `D:\Shares\Finance` {
		t.Errorf("Path = %q, want the observed path", state.Path.ValueString())
	}
	if state.Description.ValueString() != "Finance share" {
		t.Errorf("Description = %q, want the observed description", state.Description.ValueString())
	}
	if state.FolderEnumerationMode.ValueString() != "AccessBased" {
		t.Errorf("FolderEnumerationMode = %q", state.FolderEnumerationMode.ValueString())
	}
	if state.ConcurrentUserLimit.ValueInt64() != 0 {
		t.Errorf("ConcurrentUserLimit = %d, want 0", state.ConcurrentUserLimit.ValueInt64())
	}
	if !state.EncryptData.ValueBool() {
		t.Error("EncryptData should be true")
	}
	if state.Special.ValueBool() {
		t.Error("Special should be false for a regular share")
	}
	var full []string
	state.FullAccess.ElementsAs(context.Background(), &full, false)
	if len(full) != 1 || full[0] != `BUILTIN\Administrators` {
		t.Errorf("full_access = %v, want [BUILTIN\\Administrators]", full)
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

func TestSmbShareDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", smbShareDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSmbShareClientDS{readOut: smbShareDSState()}
			d := &windowsSmbShareDataSource{client: fake}
			cfg := smbShareDSConfig("Finance")
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

// smbShareDSnTimeouts builds a datasource timeouts.Value for resolution tests,
// reusing the schema's attribute types so the value matches what the framework
// decodes. A nil read yields the absent-block (null) value.
func smbShareDSnTimeouts(t *testing.T, read *string) dstimeouts.Value {
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

func TestSmbShareDSnTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := smbShareDSnTimeouts(t, nil).Read(ctx, smbShareDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != smbShareDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, smbShareDSDefaultTimeout)
	}
	if smbShareDSDefaultTimeout != smbShareDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", smbShareDSDefaultTimeout, smbShareDefaultTimeout)
	}

	custom := "45s"
	got, diags = smbShareDSnTimeouts(t, &custom).Read(ctx, smbShareDSDefaultTimeout)
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

func TestSmbShareDSRead_TypedNotFound(t *testing.T) {
	d := &windowsSmbShareDataSource{
		client: &fakeSmbShareClientDS{
			readErr: &winclient.SmbShareError{Kind: winclient.SmbShareErrorNotFound, Message: "share not found"},
		},
	}
	cfg := smbShareDSConfig("Finance")
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

func TestSmbShareDSRead_NilResult(t *testing.T) {
	d := &windowsSmbShareDataSource{
		client: &fakeSmbShareClientDS{readOut: nil, readErr: nil},
	}
	cfg := smbShareDSConfig("Finance")
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

// TestSmbShareDSRead_NotFoundDetailSingleLine pins the not-found detail to one
// line (lesson from PR #214): Terraform wraps multi-line details, which breaks
// ExpectError regexes in the acceptance suite.
func TestSmbShareDSRead_NotFoundDetailSingleLine(t *testing.T) {
	want := regexp.MustCompile(`No SMB share .* was found on the target host\.`)

	cases := []struct {
		name   string
		client *fakeSmbShareClientDS
	}{
		{"typed", &fakeSmbShareClientDS{
			readErr: &winclient.SmbShareError{Kind: winclient.SmbShareErrorNotFound, Message: "share not found"},
		}},
		{"nil", &fakeSmbShareClientDS{readOut: nil, readErr: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &windowsSmbShareDataSource{client: tc.client}
			cfg := smbShareDSConfig("Finance")
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

func TestSmbShareDSRead_TypedError(t *testing.T) {
	d := &windowsSmbShareDataSource{
		client: &fakeSmbShareClientDS{
			readErr: &winclient.SmbShareError{Kind: winclient.SmbShareErrorAccessDenied, Message: "denied"},
		},
	}
	cfg := smbShareDSConfig("Finance")
	// A typed client error surfaces through the shared addSmbShareDiag helper,
	// mirroring the resource Read path.
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "denied") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestSmbShareDSRead_GenericError(t *testing.T) {
	d := &windowsSmbShareDataSource{
		client: &fakeSmbShareClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := smbShareDSConfig("Finance")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}
