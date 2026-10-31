// Package provider — unit tests for the windows_file_acl data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative input attributes or blocks), Configure, Read happy path,
// not-found (typed and nil), generic error, timeouts.read deadline
// propagation (issue #197) and null-config default resolution.
package provider

import (
	"context"
	"errors"
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

type fakeFileACLClientDS struct {
	readOut *winclient.FileACLState
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeFileACLClientDS) Set(_ context.Context, _ winclient.FileACLInput) (*winclient.FileACLState, error) {
	panic("Set not used in data source")
}
func (f *fakeFileACLClientDS) Read(ctx context.Context, _ string) (*winclient.FileACLState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}
func (f *fakeFileACLClientDS) Reset(_ context.Context, _ string, _ []winclient.FileACLAccessRule) error {
	panic("Reset not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func fileACLDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                     tftypes.String,
		"path":                   tftypes.String,
		"owner":                  tftypes.String,
		"owner_sid":              tftypes.String,
		"target_type":            tftypes.String,
		"inheritance_enabled":    tftypes.Bool,
		"sddl":                   tftypes.String,
		"effective_access_rules": tftypes.List{ElementType: fileACLEffectiveRulesTFTypesType()},
		"timeouts":               dsTimeoutsObjType(),
	}}
}

// fileACLEffectiveRulesTFTypesType mirrors fileACLEffectiveRuleObjectType in
// tftypes form for the test config scaffolding.
func fileACLEffectiveRulesTFTypesType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"identity":     tftypes.String,
		"identity_sid": tftypes.String,
		"rights":       tftypes.List{ElementType: tftypes.String},
		"access_mask":  tftypes.Number,
		"type":         tftypes.String,
		"inheritance":  tftypes.String,
		"propagation":  tftypes.String,
		"inherited":    tftypes.Bool,
	}}
}

func fileACLDSConfig(path string) tfsdk.Config {
	d := &windowsFileACLDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(fileACLDSObjType(), map[string]tftypes.Value{
			"id":                  tftypes.NewValue(tftypes.String, nil),
			"path":                tftypes.NewValue(tftypes.String, path),
			"owner":               tftypes.NewValue(tftypes.String, nil),
			"owner_sid":           tftypes.NewValue(tftypes.String, nil),
			"target_type":         tftypes.NewValue(tftypes.String, nil),
			"inheritance_enabled": tftypes.NewValue(tftypes.Bool, nil),
			"sddl":                tftypes.NewValue(tftypes.String, nil),
			"effective_access_rules": tftypes.NewValue(
				tftypes.List{ElementType: fileACLEffectiveRulesTFTypesType()}, nil),
			"timeouts": dsNullTimeoutsValue(),
		}),
	}
}

func fileACLDSState() *winclient.FileACLState {
	return &winclient.FileACLState{
		Path:               `C:\acc\lookup.conf`,
		TargetType:         winclient.FileACLTargetFile,
		Owner:              `BUILTIN\Administrators`,
		OwnerSID:           "S-1-5-32-544",
		InheritanceEnabled: false,
		SDDL:               "O:S-1-5-32-544D:PAI(A;;FA;;;SY)",
		AccessRules: []winclient.FileACLAccessRule{
			{
				Identity:    `NT AUTHORITY\SYSTEM`,
				IdentitySID: "S-1-5-18",
				Rights:      []string{"FullControl"},
				AccessMask:  0x1F01FF,
				Type:        winclient.FileACLTypeAllow,
				Inheritance: winclient.FileACLInheritanceNone,
				Propagation: winclient.FileACLPropagationNone,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestFileACLDSMetadata(t *testing.T) {
	d := &windowsFileACLDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_file_acl" {
		t.Errorf("TypeName = %q, want windows_file_acl", resp.TypeName)
	}
}

func TestNewWindowsFileACLDataSource_NotNil(t *testing.T) {
	if NewWindowsFileACLDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestFileACLDSSchema_AllAttributes(t *testing.T) {
	d := &windowsFileACLDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "path", "owner", "owner_sid", "target_type",
		"inheritance_enabled", "sddl", "effective_access_rules", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestFileACLDSSchema_QueryKeyRequired(t *testing.T) {
	d := &windowsFileACLDataSource{}
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

func TestFileACLDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsFileACLDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"id", "owner", "owner_sid", "target_type",
		"inheritance_enabled", "sddl", "effective_access_rules"} {
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

func TestFileACLDSSchema_NoDeclarativeInputs(t *testing.T) {
	d := &windowsFileACLDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{
		"mode", "preserve_inherited_on_protect",
	} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("data source must NOT expose declarative input attribute %q", k)
		}
	}
	if _, ok := resp.Schema.Blocks["access_rule"]; ok {
		t.Error("data source must NOT expose the access_rule block: the observed DACL belongs in effective_access_rules")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestFileACLDSConfigure_Nil(t *testing.T) {
	d := &windowsFileACLDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestFileACLDSConfigure_WrongType(t *testing.T) {
	d := &windowsFileACLDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestFileACLDSConfigure_CorrectType(t *testing.T) {
	d := &windowsFileACLDataSource{}
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

func TestFileACLDSRead_HappyPath(t *testing.T) {
	d := &windowsFileACLDataSource{
		client: &fakeFileACLClientDS{readOut: fileACLDSState()},
	}
	cfg := fileACLDSConfig(`C:\acc\lookup.conf`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsFileACLDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != `C:\acc\lookup.conf` {
		t.Errorf("ID = %q, want the normalised target path", state.ID.ValueString())
	}
	if state.Path.ValueString() != `C:\acc\lookup.conf` {
		t.Errorf("Path = %q, want the queried path echoed back", state.Path.ValueString())
	}
	if state.OwnerSID.ValueString() != "S-1-5-32-544" {
		t.Errorf("OwnerSID = %q, want S-1-5-32-544", state.OwnerSID.ValueString())
	}
	if state.TargetType.ValueString() != winclient.FileACLTargetFile {
		t.Errorf("TargetType = %q, want file", state.TargetType.ValueString())
	}
	if state.InheritanceEnabled.ValueBool() {
		t.Error("InheritanceEnabled should be false")
	}
	if state.SDDL.ValueString() == "" {
		t.Error("SDDL should be populated")
	}
	if len(state.EffectiveRules.Elements()) != 1 {
		t.Errorf("effective_access_rules has %d elements, want 1", len(state.EffectiveRules.Elements()))
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

// TestFileACLDSRead_BoundedByTimeouts verifies the data source Read runs under
// a deadline derived from `timeouts.read` (issue #197): fileACLDSDefaultTimeout
// when the block is absent, the configured value when set.
func TestFileACLDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", fileACLDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeFileACLClientDS{readOut: fileACLDSState()}
			d := &windowsFileACLDataSource{client: fake}
			cfg := fileACLDSConfig(`C:\acc\lookup.conf`)
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

// fileACLDSnTimeouts builds a datasource timeouts.Value for resolution tests,
// reusing the schema's attribute types so the value matches what the framework
// decodes. A nil read yields the absent-block (null) value.
func fileACLDSnTimeouts(t *testing.T, read *string) dstimeouts.Value {
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

// TestFileACLDSnTimeouts_NullConfigDefault verifies `timeouts.read` resolution
// for the data source (issue #197): fileACLDSDefaultTimeout when the block is
// absent, the configured value when set. The full Read path needs a live host,
// so resolution is asserted at the model level; BoundedByTimeouts covers
// deadline propagation end to end.
func TestFileACLDSnTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := fileACLDSnTimeouts(t, nil).Read(ctx, fileACLDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != fileACLDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, fileACLDSDefaultTimeout)
	}
	if fileACLDSDefaultTimeout != fileACLDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", fileACLDSDefaultTimeout, fileACLDefaultTimeout)
	}

	custom := "45s"
	got, diags = fileACLDSnTimeouts(t, &custom).Read(ctx, fileACLDSDefaultTimeout)
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

func TestFileACLDSRead_TypedNotFound(t *testing.T) {
	d := &windowsFileACLDataSource{
		client: &fakeFileACLClientDS{
			readErr: &winclient.FileACLError{Kind: winclient.FileACLErrorNotFound, Message: "target not found"},
		},
	}
	cfg := fileACLDSConfig(`C:\acc\missing.conf`)
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

func TestFileACLDSRead_NilResult(t *testing.T) {
	d := &windowsFileACLDataSource{
		client: &fakeFileACLClientDS{readOut: nil, readErr: nil},
	}
	cfg := fileACLDSConfig(`C:\acc\missing.conf`)
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

func TestFileACLDSRead_TypedError(t *testing.T) {
	d := &windowsFileACLDataSource{
		client: &fakeFileACLClientDS{
			readErr: &winclient.FileACLError{Kind: winclient.FileACLErrorPermission, Message: "access denied"},
		},
	}
	cfg := fileACLDSConfig(`C:\acc\lookup.conf`)
	// A typed client error surfaces through the shared addFileACLDiag helper,
	// mirroring the resource Read path.
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "ACL") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestFileACLDSRead_GenericError(t *testing.T) {
	d := &windowsFileACLDataSource{
		client: &fakeFileACLClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := fileACLDSConfig(`C:\acc\lookup.conf`)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}
