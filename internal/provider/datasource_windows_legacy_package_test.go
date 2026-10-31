// Package provider — unit tests for the windows_legacy_package data source.
//
// Tests cover: Metadata, Schema (query keys, computed attributes, no
// install-only attributes), ConfigValidators, Configure, Read by product_id,
// Read by display_name, not-found, nil result, generic error, timeouts.read
// deadline propagation (issue #197) and null-config default resolution.
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

type fakeLegacyPackageClientDS struct {
	readOut *winclient.LegacyPackageState
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeLegacyPackageClientDS) Create(_ context.Context, _ winclient.LegacyPackageInput) (*winclient.LegacyPackageState, error) {
	panic("Create not used in data source")
}
func (f *fakeLegacyPackageClientDS) Read(ctx context.Context, _ string) (*winclient.LegacyPackageState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}
func (f *fakeLegacyPackageClientDS) Update(_ context.Context, _ string, _ winclient.LegacyPackageInput) (*winclient.LegacyPackageState, error) {
	panic("Update not used in data source")
}
func (f *fakeLegacyPackageClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func legacyPackageDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                tftypes.String,
		"product_id":        tftypes.String,
		"display_name":      tftypes.String,
		"installed":         tftypes.Bool,
		"installed_version": tftypes.String,
		"install_date":      tftypes.String,
		"timeouts":          dsTimeoutsObjType(),
	}}
}

func legacyPackageDSConfigByProductID(productID string) tfsdk.Config {
	d := &windowsLegacyPackageDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(legacyPackageDSObjType(), map[string]tftypes.Value{
			"id":                tftypes.NewValue(tftypes.String, nil),
			"product_id":        tftypes.NewValue(tftypes.String, productID),
			"display_name":      tftypes.NewValue(tftypes.String, nil),
			"installed":         tftypes.NewValue(tftypes.Bool, nil),
			"installed_version": tftypes.NewValue(tftypes.String, nil),
			"install_date":      tftypes.NewValue(tftypes.String, nil),
			"timeouts":          dsNullTimeoutsValue(),
		}),
	}
}

func legacyPackageDSConfigByDisplayName(displayName string) tfsdk.Config {
	d := &windowsLegacyPackageDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(legacyPackageDSObjType(), map[string]tftypes.Value{
			"id":                tftypes.NewValue(tftypes.String, nil),
			"product_id":        tftypes.NewValue(tftypes.String, nil),
			"display_name":      tftypes.NewValue(tftypes.String, displayName),
			"installed":         tftypes.NewValue(tftypes.Bool, nil),
			"installed_version": tftypes.NewValue(tftypes.String, nil),
			"install_date":      tftypes.NewValue(tftypes.String, nil),
			"timeouts":          dsNullTimeoutsValue(),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestLegacyPackageDSMetadata(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_legacy_package" {
		t.Errorf("TypeName = %q, want windows_legacy_package", resp.TypeName)
	}
}

func TestNewWindowsLegacyPackageDataSource_NotNil(t *testing.T) {
	if NewWindowsLegacyPackageDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestLegacyPackageDSSchema_AllAttributes(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "product_id", "display_name", "installed", "installed_version", "install_date", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestLegacyPackageDSSchema_QueryKeysOptionalComputed(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type optionalChecker interface{ IsOptional() bool }
	type computedChecker interface{ IsComputed() bool }
	for _, k := range []string{"product_id", "display_name"} {
		attr := resp.Schema.Attributes[k]
		if attr == nil {
			t.Errorf("attribute %q not found", k)
			continue
		}
		oc, ok := attr.(optionalChecker)
		if !ok || !oc.IsOptional() {
			t.Errorf("attribute %q must be Optional", k)
		}
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

func TestLegacyPackageDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	for _, k := range []string{"id", "installed", "installed_version", "install_date"} {
		attr := resp.Schema.Attributes[k]
		if attr == nil {
			t.Errorf("attribute %q not found", k)
			continue
		}
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

func TestLegacyPackageDSSchema_NoInstallOnlyAttributes(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{
		"name", "installer_type", "source_path", "source_url", "checksum",
		"insecure_skip_verify", "display_name_pattern", "install_args",
		"uninstall_args", "uninstall_command", "valid_exit_codes",
		"working_directory", "timeout_seconds", "log_path", "environment",
	} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("data source must NOT expose install-only attribute %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

func TestLegacyPackageDSConfigValidators_ExactlyOneOf(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	vs := d.ConfigValidators(context.Background())
	if len(vs) != 1 {
		t.Fatalf("expected exactly 1 ConfigValidator (ExactlyOneOf product_id/display_name), got %d", len(vs))
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestLegacyPackageDSConfigure_Nil(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestLegacyPackageDSConfigure_WrongType(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestLegacyPackageDSConfigure_CorrectType(t *testing.T) {
	d := &windowsLegacyPackageDataSource{}
	resp := &datasource.ConfigureResponse{}
	c := &winclient.Client{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path by product_id (MSI)
// ---------------------------------------------------------------------------

func TestLegacyPackageDSRead_ByProductID(t *testing.T) {
	const guid = "{01234567-89AB-CDEF-0123-456789ABCDEF}"
	d := &windowsLegacyPackageDataSource{
		lp: &fakeLegacyPackageClientDS{
			readOut: &winclient.LegacyPackageState{
				ID:               guid,
				ProductID:        guid,
				Installed:        true,
				InstalledVersion: "9.9",
				InstallDate:      "2026-10-01",
			},
		},
	}
	cfg := legacyPackageDSConfigByProductID(guid)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsLegacyPackageDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != guid {
		t.Errorf("ID = %q, want %q", state.ID.ValueString(), guid)
	}
	if state.ProductID.ValueString() != guid {
		t.Errorf("ProductID = %q, want %q", state.ProductID.ValueString(), guid)
	}
	if !state.Installed.ValueBool() {
		t.Error("Installed should be true")
	}
	if state.InstalledVersion.ValueString() != "9.9" {
		t.Errorf("InstalledVersion = %q, want 9.9", state.InstalledVersion.ValueString())
	}
	if state.InstallDate.ValueString() != "2026-10-01" {
		t.Errorf("InstallDate = %q, want 2026-10-01", state.InstallDate.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — happy path by display_name (EXE)
// ---------------------------------------------------------------------------

func TestLegacyPackageDSRead_ByDisplayName(t *testing.T) {
	d := &windowsLegacyPackageDataSource{
		lp: &fakeLegacyPackageClientDS{
			readOut: &winclient.LegacyPackageState{
				ID:               "Acme App",
				ProductID:        "",
				Installed:        true,
				InstalledVersion: "1.0",
				InstallDate:      "",
			},
		},
	}
	cfg := legacyPackageDSConfigByDisplayName("Acme App")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsLegacyPackageDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "Acme App" {
		t.Errorf("ID = %q, want Acme App", state.ID.ValueString())
	}
	if state.DisplayName.ValueString() != "Acme App" {
		t.Errorf("DisplayName = %q, want Acme App echoed back", state.DisplayName.ValueString())
	}
	if state.InstalledVersion.ValueString() != "1.0" {
		t.Errorf("InstalledVersion = %q, want 1.0", state.InstalledVersion.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read (issue #197)
// ---------------------------------------------------------------------------

// TestLegacyPackageDSRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read` (issue #197):
// legacyPackageDSDefaultTimeout when the block is absent, the configured value
// when set.
func TestLegacyPackageDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", legacyPackageDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeLegacyPackageClientDS{
				readOut: &winclient.LegacyPackageState{ID: "Acme App", Installed: true},
			}
			d := &windowsLegacyPackageDataSource{lp: fake}
			cfg := legacyPackageDSConfigByDisplayName("Acme App")
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

// legacyPackageDSTimeouts builds a datasource timeouts.Value for resolution
// tests, reusing the schema's attribute types so the value matches what the
// framework decodes. A nil read yields the absent-block (null) value.
func legacyPackageDSTimeouts(t *testing.T, read *string) dstimeouts.Value {
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

// TestLegacyPackageDSTimeouts_NullConfigDefault verifies `timeouts.read`
// resolution for the data source (issue #197):
// legacyPackageDSDefaultTimeout when the block is absent, the configured
// value when set. The full Read path needs a live host, so resolution is
// asserted at the model level; BoundedByTimeouts covers deadline propagation
// end to end.
func TestLegacyPackageDSTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := legacyPackageDSTimeouts(t, nil).Read(ctx, legacyPackageDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != legacyPackageDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, legacyPackageDSDefaultTimeout)
	}
	if legacyPackageDSDefaultTimeout != lpDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", legacyPackageDSDefaultTimeout, lpDefaultTimeout)
	}

	custom := "45s"
	got, diags = legacyPackageDSTimeouts(t, &custom).Read(ctx, legacyPackageDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("custom timeouts diags: %v", diags)
	}
	if got != 45*time.Second {
		t.Errorf("custom timeouts resolved to %v, want 45s", got)
	}
}

// ---------------------------------------------------------------------------
// Read — not found / nil result
// ---------------------------------------------------------------------------

func TestLegacyPackageDSRead_TypedError(t *testing.T) {
	d := &windowsLegacyPackageDataSource{
		lp: &fakeLegacyPackageClientDS{
			readErr: &winclient.LegacyPackageError{Kind: "msi_inspect_failed", Message: "boom"},
		},
	}
	cfg := legacyPackageDSConfigByProductID("{00000000-0000-0000-0000-000000000000}")
	// A typed client error surfaces through the shared addLPDiag helper,
	// mirroring the resource Read path.
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "windows_legacy_package") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestLegacyPackageDSRead_NilResult(t *testing.T) {
	d := &windowsLegacyPackageDataSource{
		lp: &fakeLegacyPackageClientDS{readOut: nil, readErr: nil},
	}
	cfg := legacyPackageDSConfigByProductID("{00000000-0000-0000-0000-000000000000}")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for nil package result")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

// ---------------------------------------------------------------------------
// Read — generic error
// ---------------------------------------------------------------------------

func TestLegacyPackageDSRead_GenericError(t *testing.T) {
	d := &windowsLegacyPackageDataSource{
		lp: &fakeLegacyPackageClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := legacyPackageDSConfigByDisplayName("Acme App")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}
