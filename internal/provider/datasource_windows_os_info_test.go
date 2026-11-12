// Package provider — unit tests for the windows_os_info data source.
//
// windows_os_info is a standalone singleton: no Required lookup keys, no
// sibling resource. Tests cover: Metadata, Schema, Configure, Read happy
// path mapping (incl FullBuild/IsServerCore), Read error, Read nil-state
// error and timeout bounding.
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

type fakeOSInfoClientDS struct {
	readOut *winclient.OSInfo
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeOSInfoClientDS) Read(ctx context.Context) (*winclient.OSInfo, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func osInfoDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"product_name":       tftypes.String,
		"version":            tftypes.String,
		"build_number":       tftypes.Number,
		"ubr":                tftypes.Number,
		"full_build":         tftypes.String,
		"display_version":    tftypes.String,
		"edition_id":         tftypes.String,
		"sku":                tftypes.Number,
		"sku_name":           tftypes.String,
		"installation_type":  tftypes.String,
		"is_server":          tftypes.Bool,
		"is_server_core":     tftypes.Bool,
		"product_type":       tftypes.String,
		"architecture":       tftypes.String,
		"install_date":       tftypes.String,
		"last_boot_time":     tftypes.String,
		"system_drive":       tftypes.String,
		"windows_directory":  tftypes.String,
		"os_language":        tftypes.String,
		"powershell_version": tftypes.String,
		"timeouts":           dsTimeoutsObjType(),
	}}
}

func osInfoDSConfig() tfsdk.Config {
	d := &windowsOSInfoDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := map[string]tftypes.Value{
		"timeouts": dsNullTimeoutsValue(),
	}
	for name, typ := range osInfoDSObjType().AttributeTypes {
		if name == "timeouts" {
			continue
		}
		vals[name] = tftypes.NewValue(typ, nil)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(osInfoDSObjType(), vals),
	}
}

func fakeOSInfoState() *winclient.OSInfo {
	return &winclient.OSInfo{
		MachineID:         "abc-123-def",
		ProductName:       "Microsoft Windows Server 2025 Standard",
		Version:           "10.0.26100",
		BuildNumber:       26100,
		UBR:               1,
		FullBuild:         "26100.1",
		DisplayVersion:    "24H2",
		EditionID:         "ServerStandard",
		SKU:               7,
		SKUName:           "Server Standard",
		InstallationType:  "Server",
		IsServer:          true,
		IsServerCore:      false,
		ProductType:       "Server",
		Architecture:      "x64",
		InstallDate:       "2024-11-01T00:00:00Z",
		LastBootTime:      "2026-11-12T08:00:00Z",
		SystemDrive:       "C:",
		WindowsDirectory:  `C:\Windows`,
		OSLanguage:        "en-US",
		PowerShellVersion: "5.1.26100.1",
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestOSInfoDSMetadata(t *testing.T) {
	d := &windowsOSInfoDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_os_info" {
		t.Errorf("TypeName = %q, want windows_os_info", resp.TypeName)
	}
}

func TestNewWindowsOSInfoDataSource_NotNil(t *testing.T) {
	if NewWindowsOSInfoDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestOSInfoDSSchema_AllAttributes(t *testing.T) {
	d := &windowsOSInfoDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "product_name", "version", "build_number", "ubr",
		"full_build", "display_version", "edition_id", "sku", "sku_name",
		"installation_type", "is_server", "is_server_core", "product_type",
		"architecture", "install_date", "last_boot_time", "system_drive",
		"windows_directory", "os_language", "powershell_version", "timeouts",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(resp.Schema.Attributes) != len(want) {
		t.Errorf("schema has %d attributes, want %d", len(resp.Schema.Attributes), len(want))
	}
}

func TestOSInfoDSSchema_NoRequired(t *testing.T) {
	d := &windowsOSInfoDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for k, attr := range resp.Schema.Attributes {
		type requiredChecker interface{ IsRequired() bool }
		rc, ok := attr.(requiredChecker)
		if ok && rc.IsRequired() {
			t.Errorf("os_info DS attribute %q is Required, but singleton DS should have no required keys", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestOSInfoDSConfigure_Nil(t *testing.T) {
	d := &windowsOSInfoDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestOSInfoDSConfigure_WrongType(t *testing.T) {
	d := &windowsOSInfoDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 42}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestOSInfoDSConfigure_CorrectType(t *testing.T) {
	d := &windowsOSInfoDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path
// ---------------------------------------------------------------------------

func TestOSInfoDSRead_HappyPath(t *testing.T) {
	d := &windowsOSInfoDataSource{
		osinfo: &fakeOSInfoClientDS{readOut: fakeOSInfoState()},
	}
	cfg := osInfoDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsOSInfoDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "abc-123-def" {
		t.Errorf("ID = %q, want machine_id", state.ID.ValueString())
	}
	if state.ProductName.ValueString() != "Microsoft Windows Server 2025 Standard" {
		t.Errorf("ProductName = %q", state.ProductName.ValueString())
	}
	if state.Version.ValueString() != "10.0.26100" {
		t.Errorf("Version = %q", state.Version.ValueString())
	}
	if state.BuildNumber.ValueInt64() != 26100 {
		t.Errorf("BuildNumber = %d, want 26100", state.BuildNumber.ValueInt64())
	}
	if state.UBR.ValueInt64() != 1 {
		t.Errorf("UBR = %d, want 1", state.UBR.ValueInt64())
	}
	if state.FullBuild.ValueString() != "26100.1" {
		t.Errorf("FullBuild = %q, want 26100.1", state.FullBuild.ValueString())
	}
	if state.SKU.ValueInt64() != 7 || state.SKUName.ValueString() != "Server Standard" {
		t.Errorf("SKU/SKUName = %d/%q", state.SKU.ValueInt64(), state.SKUName.ValueString())
	}
	if !state.IsServer.ValueBool() {
		t.Error("IsServer should be true")
	}
	if state.IsServerCore.ValueBool() {
		t.Error("IsServerCore should be false")
	}
	if state.ProductType.ValueString() != "Server" {
		t.Errorf("ProductType = %q", state.ProductType.ValueString())
	}
	if state.Architecture.ValueString() != "x64" {
		t.Errorf("Architecture = %q", state.Architecture.ValueString())
	}
}

func TestOSInfoDSRead_ServerCore(t *testing.T) {
	live := fakeOSInfoState()
	live.InstallationType = "Server Core"
	live.IsServerCore = true
	d := &windowsOSInfoDataSource{
		osinfo: &fakeOSInfoClientDS{readOut: live},
	}
	cfg := osInfoDSConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsOSInfoDataSourceModel
	resp.State.Get(context.Background(), &state)
	if !state.IsServerCore.ValueBool() {
		t.Error("IsServerCore should be true")
	}
	if state.InstallationType.ValueString() != "Server Core" {
		t.Errorf("InstallationType = %q", state.InstallationType.ValueString())
	}
}

func TestOSInfoDSRead_EmptyMachineIDFallsBack(t *testing.T) {
	live := fakeOSInfoState()
	live.MachineID = ""
	d := &windowsOSInfoDataSource{
		osinfo: &fakeOSInfoClientDS{readOut: live},
	}
	cfg := osInfoDSConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsOSInfoDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "current" {
		t.Errorf("ID = %q, want current fallback", state.ID.ValueString())
	}
}

// TestOSInfoDSRead_NullSafety verifies unknown codes degrading to "" still
// land as non-null (empty) state values rather than nulls.
func TestOSInfoDSRead_NullSafety(t *testing.T) {
	live := fakeOSInfoState()
	live.SKUName = ""
	live.ProductType = ""
	live.Architecture = ""
	live.DisplayVersion = ""
	d := &windowsOSInfoDataSource{
		osinfo: &fakeOSInfoClientDS{readOut: live},
	}
	cfg := osInfoDSConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsOSInfoDataSourceModel
	resp.State.Get(context.Background(), &state)
	for name, v := range map[string]interface{ IsNull() bool }{
		"sku_name":        state.SKUName,
		"product_type":    state.ProductType,
		"architecture":    state.Architecture,
		"display_version": state.DisplayVersion,
	} {
		if v.IsNull() {
			t.Errorf("%s should be empty, not null", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Read — error paths
// ---------------------------------------------------------------------------

func TestOSInfoDSRead_Error(t *testing.T) {
	d := &windowsOSInfoDataSource{
		osinfo: &fakeOSInfoClientDS{
			readErr: errors.New("SSH unreachable"),
		},
	}
	cfg := osInfoDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from read failure")
	}
}

func TestOSInfoDSRead_NilState(t *testing.T) {
	d := &windowsOSInfoDataSource{osinfo: &fakeOSInfoClientDS{}}
	cfg := osInfoDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from nil state")
	}
}

// TestOSInfoDSRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read` (issue #197):
// osInfoDSDefaultTimeout when the block is absent, the configured value
// when set.
func TestOSInfoDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", osInfoDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeOSInfoClientDS{readOut: fakeOSInfoState()}
			d := &windowsOSInfoDataSource{osinfo: fake}
			cfg := osInfoDSConfig()
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
