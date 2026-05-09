// Package provider — unit tests for windows_winget_package data source.
//
// These tests exercise the data source schema, Metadata, Configure, and Read
// handlers without WinRM. A package-local fakeWingetPackageClient implements
// the winclient.WingetPackageClient interface; only Read is meaningfully
// exercised here (the other methods are present to satisfy the interface).
//
// Edge cases covered (per spec.yaml):
//
//	Metadata     — returns "windows_winget_package"
//	Schema       — 8 attributes present, package_id Required, source Optional+Computed
//	Configure    — nil ProviderData / wrong type
//	Read (happy) — winget source, found → state populated, id synthesized
//	Read (default source) — source unset → client called with "winget"
//	Read (not_found)      — client returns (nil,nil) → diagnostic "not_found"
//	Read (transport err)  — client returns error → diagnostic surfaced
//	Read (module_missing) — typed error → surfaced
//	Read (source_unreachable) — typed error → surfaced (no swallow as not_found)
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeWingetPackageClient — in-memory mock satisfying winclient.WingetPackageClient
// ---------------------------------------------------------------------------

type fakeWingetPackageClient struct {
	readOut *winclient.WingetPackageState
	readErr error

	lastReadPackageID string
	lastReadSource    string
	readCalls         int

	installOut   *winclient.WingetPackageState
	installErr   error
	updateOut    *winclient.WingetPackageState
	updateErr    error
	uninstallOut *winclient.WingetPackageState
	uninstallErr error
}

func (f *fakeWingetPackageClient) Install(_ context.Context, _ winclient.WingetPackageInput) (*winclient.WingetPackageState, error) {
	return f.installOut, f.installErr
}

func (f *fakeWingetPackageClient) Read(_ context.Context, packageID, source string) (*winclient.WingetPackageState, error) {
	f.readCalls++
	f.lastReadPackageID = packageID
	f.lastReadSource = source
	return f.readOut, f.readErr
}

func (f *fakeWingetPackageClient) Update(_ context.Context, _ winclient.WingetPackageInput) (*winclient.WingetPackageState, error) {
	return f.updateOut, f.updateErr
}

func (f *fakeWingetPackageClient) Uninstall(_ context.Context, _, _ string) (*winclient.WingetPackageState, error) {
	return f.uninstallOut, f.uninstallErr
}

// Compile-time assertion.
var _ winclient.WingetPackageClient = (*fakeWingetPackageClient)(nil)

// ---------------------------------------------------------------------------
// tftypes helpers — windows_winget_package data source schema
// ---------------------------------------------------------------------------

func dsWPObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                  tftypes.String,
		"package_id":          tftypes.String,
		"source":              tftypes.String,
		"name":                tftypes.String,
		"installed_version":   tftypes.String,
		"available_version":   tftypes.String,
		"is_installed":        tftypes.Bool,
		"is_update_available": tftypes.Bool,
	}}
}

func dsWPObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                  tftypes.NewValue(tftypes.String, nil),
		"package_id":          tftypes.NewValue(tftypes.String, "Microsoft.PowerShell"),
		"source":              tftypes.NewValue(tftypes.String, "winget"),
		"name":                tftypes.NewValue(tftypes.String, nil),
		"installed_version":   tftypes.NewValue(tftypes.String, nil),
		"available_version":   tftypes.NewValue(tftypes.String, nil),
		"is_installed":        tftypes.NewValue(tftypes.Bool, nil),
		"is_update_available": tftypes.NewValue(tftypes.Bool, nil),
	}
}

func dsWPObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := dsWPObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(dsWPObjectType(), base)
}

func dsWPSchema() datasourceschema.Schema {
	ds := &windowsWingetPackageDataSource{}
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	return resp.Schema
}

func dsWPConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	return tfsdk.Config{
		Schema: dsWPSchema(),
		Raw:    dsWPObj(overrides),
	}
}

func dsWPState(t *testing.T) tfsdk.State {
	t.Helper()
	return tfsdk.State{Schema: dsWPSchema()}
}

func dsWPDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Metadata(t *testing.T) {
	ds := &windowsWingetPackageDataSource{}
	req := datasource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_winget_package" {
		t.Errorf("TypeName = %q, want windows_winget_package", resp.TypeName)
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Schema_HasAllAttributes(t *testing.T) {
	s := dsWPSchema()
	want := []string{
		"id", "package_id", "source",
		"name", "installed_version", "available_version",
		"is_installed", "is_update_available",
	}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(s.Attributes) != len(want) {
		t.Errorf("schema attribute count = %d, want %d", len(s.Attributes), len(want))
	}
}

func TestWingetPackageDataSource_Schema_PackageIDRequired(t *testing.T) {
	s := dsWPSchema()
	a, ok := s.Attributes["package_id"]
	if !ok {
		t.Fatal("missing package_id")
	}
	type req interface{ IsRequired() bool }
	if r, ok := a.(req); ok && !r.IsRequired() {
		t.Error("package_id must be Required")
	}
}

func TestWingetPackageDataSource_Schema_SourceOptionalAndComputed(t *testing.T) {
	s := dsWPSchema()
	a, ok := s.Attributes["source"]
	if !ok {
		t.Fatal("missing source")
	}
	type opt interface{ IsOptional() bool }
	type cmp interface{ IsComputed() bool }
	if o, ok := a.(opt); ok && !o.IsOptional() {
		t.Error("source must be Optional")
	}
	if c, ok := a.(cmp); ok && !c.IsComputed() {
		t.Error("source must be Computed")
	}
}

func TestWingetPackageDataSource_Schema_ComputedAttributes(t *testing.T) {
	s := dsWPSchema()
	for _, k := range []string{"id", "name", "installed_version", "available_version", "is_installed", "is_update_available"} {
		a, ok := s.Attributes[k]
		if !ok {
			t.Errorf("missing %q", k)
			continue
		}
		type cmp interface{ IsComputed() bool }
		if c, ok := a.(cmp); ok && !c.IsComputed() {
			t.Errorf("%q must be Computed", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Configure_NilProviderData(t *testing.T) {
	ds := &windowsWingetPackageDataSource{}
	resp := &datasource.ConfigureResponse{}
	ds.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should not error: %v", resp.Diagnostics)
	}
}

func TestWingetPackageDataSource_Configure_WrongType(t *testing.T) {
	ds := &windowsWingetPackageDataSource{}
	resp := &datasource.ConfigureResponse{}
	ds.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error for wrong ProviderData type")
	}
}

func TestWingetPackageDataSource_Configure_HappyPath(t *testing.T) {
	ds := &windowsWingetPackageDataSource{}
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	resp := &datasource.ConfigureResponse{}
	ds.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	if ds.client == nil {
		t.Error("client should be set after Configure")
	}
}

// ---------------------------------------------------------------------------
// Read — happy path (winget source, package found)
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Read_HappyPath_Winget(t *testing.T) {
	fake := &fakeWingetPackageClient{
		readOut: &winclient.WingetPackageState{
			PackageID:        "Microsoft.PowerShell",
			Source:           "winget",
			InstalledVersion: "7.4.1",
			Name:             "PowerShell",
		},
	}
	ds := &windowsWingetPackageDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsWPConfig(t, map[string]tftypes.Value{
			"package_id": tftypes.NewValue(tftypes.String, "Microsoft.PowerShell"),
			"source":     tftypes.NewValue(tftypes.String, "winget"),
		}),
	}
	resp := &datasource.ReadResponse{State: dsWPState(t)}
	ds.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", dsWPDiagSummaries(resp.Diagnostics))
	}
	if fake.readCalls != 1 {
		t.Errorf("Read calls = %d, want 1", fake.readCalls)
	}
	if fake.lastReadPackageID != "Microsoft.PowerShell" {
		t.Errorf("Read package_id = %q, want Microsoft.PowerShell", fake.lastReadPackageID)
	}
	if fake.lastReadSource != "winget" {
		t.Errorf("Read source = %q, want winget", fake.lastReadSource)
	}

	var m windowsWingetPackageDataSourceModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("state.Get: %v", d)
	}
	if m.ID.ValueString() != "winget:Microsoft.PowerShell" {
		t.Errorf("id = %q, want winget:Microsoft.PowerShell", m.ID.ValueString())
	}
	if m.PackageID.ValueString() != "Microsoft.PowerShell" {
		t.Errorf("package_id = %q", m.PackageID.ValueString())
	}
	if m.InstalledVersion.ValueString() != "7.4.1" {
		t.Errorf("installed_version = %q, want 7.4.1", m.InstalledVersion.ValueString())
	}
	if m.Name.ValueString() != "PowerShell" {
		t.Errorf("name = %q, want PowerShell", m.Name.ValueString())
	}
	if !m.IsInstalled.ValueBool() {
		t.Error("is_installed must be true when installed_version is non-empty")
	}
}

// ---------------------------------------------------------------------------
// Read — source unset → client called with default "winget"
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Read_DefaultSource(t *testing.T) {
	fake := &fakeWingetPackageClient{
		readOut: &winclient.WingetPackageState{
			PackageID:        "Microsoft.PowerShell",
			Source:           "winget",
			InstalledVersion: "7.4.1",
			Name:             "PowerShell",
		},
	}
	ds := &windowsWingetPackageDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsWPConfig(t, map[string]tftypes.Value{
			"package_id": tftypes.NewValue(tftypes.String, "Microsoft.PowerShell"),
			"source":     tftypes.NewValue(tftypes.String, nil),
		}),
	}
	resp := &datasource.ReadResponse{State: dsWPState(t)}
	ds.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", dsWPDiagSummaries(resp.Diagnostics))
	}
	if fake.lastReadSource != "winget" {
		t.Errorf("default source must be 'winget', got %q", fake.lastReadSource)
	}

	var m windowsWingetPackageDataSourceModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("state.Get: %v", d)
	}
	if m.ID.ValueString() != "winget:Microsoft.PowerShell" {
		t.Errorf("id = %q, want winget:Microsoft.PowerShell", m.ID.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — package not found → diagnostic error
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Read_NotFound(t *testing.T) {
	fake := &fakeWingetPackageClient{readOut: nil, readErr: nil}
	ds := &windowsWingetPackageDataSource{client: fake}

	req := datasource.ReadRequest{
		Config: dsWPConfig(t, map[string]tftypes.Value{
			"package_id": tftypes.NewValue(tftypes.String, "Does.Not.Exist"),
			"source":     tftypes.NewValue(tftypes.String, "winget"),
		}),
	}
	resp := &datasource.ReadResponse{State: dsWPState(t)}
	ds.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic error when client returns (nil, nil)")
	}
	combined := strings.ToLower(strings.Join(dsWPDiagSummaries(resp.Diagnostics), " | "))
	if !strings.Contains(combined, "not found") && !strings.Contains(combined, "not_found") {
		t.Errorf("expected 'not found' / 'not_found' in diagnostics: %v", dsWPDiagSummaries(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// Read — module_missing → diagnostic error surfaced
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Read_ModuleMissing(t *testing.T) {
	fake := &fakeWingetPackageClient{
		readErr: winclient.NewWingetPackageError(
			winclient.WingetPackageErrorModuleMissing,
			"Microsoft.WinGet.Client module is not available", nil, nil,
		),
	}
	ds := &windowsWingetPackageDataSource{client: fake}

	req := datasource.ReadRequest{Config: dsWPConfig(t, nil)}
	resp := &datasource.ReadResponse{State: dsWPState(t)}
	ds.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic for module_missing error")
	}
	combined := strings.Join(dsWPDiagSummaries(resp.Diagnostics), " | ")
	if !strings.Contains(combined, "module_missing") && !strings.Contains(combined, "Microsoft.WinGet.Client") {
		t.Errorf("expected module_missing context in diagnostics: %v", combined)
	}
}

// ---------------------------------------------------------------------------
// Read — source_unreachable must NOT be swallowed as not_found
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Read_SourceUnreachable(t *testing.T) {
	fake := &fakeWingetPackageClient{
		readErr: winclient.NewWingetPackageError(
			winclient.WingetPackageErrorSourceUnreachable,
			"network error contacting winget source", nil, nil,
		),
	}
	ds := &windowsWingetPackageDataSource{client: fake}

	req := datasource.ReadRequest{Config: dsWPConfig(t, nil)}
	resp := &datasource.ReadResponse{State: dsWPState(t)}
	ds.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic error for source_unreachable")
	}
	combined := strings.ToLower(strings.Join(dsWPDiagSummaries(resp.Diagnostics), " | "))
	if strings.Contains(combined, "not found") || strings.Contains(combined, "not_found") {
		t.Errorf("source_unreachable must not be reported as not_found: %v", combined)
	}
}

// ---------------------------------------------------------------------------
// Read — unknown / transport error
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_Read_TransportError(t *testing.T) {
	fake := &fakeWingetPackageClient{readErr: errors.New("WinRM connection refused")}
	ds := &windowsWingetPackageDataSource{client: fake}

	req := datasource.ReadRequest{Config: dsWPConfig(t, nil)}
	resp := &datasource.ReadResponse{State: dsWPState(t)}
	ds.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic error for transport failure")
	}
}

// ---------------------------------------------------------------------------
// Compile-time interface assertions
// ---------------------------------------------------------------------------

func TestWingetPackageDataSource_InterfaceAssertions(t *testing.T) {
	var _ datasource.DataSource = (*windowsWingetPackageDataSource)(nil)
	var _ datasource.DataSourceWithConfigure = (*windowsWingetPackageDataSource)(nil)
}
