// Package provider — unit tests for the windows_installed_software data
// source.
//
// windows_installed_software is a standalone collection: optional filters,
// sorted `packages` ListNested output plus `skipped_entries`, empty match
// is valid. Tests cover: Metadata, Schema, Configure, Read happy-path
// mapping (incl skipped_entries and sparse entries), filter passing, Read
// error (incl filter validation errors with no host call), empty result,
// ID stability (incl product code spelling variants) and timeout bounding.
package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeInstalledSoftwareClientDS struct {
	gotFilter winclient.InstalledSoftwareFilter
	listOut   *winclient.InstalledSoftwareResult
	listErr   error

	deadline time.Time
	ok       bool
}

func (f *fakeInstalledSoftwareClientDS) List(ctx context.Context, filter winclient.InstalledSoftwareFilter) (*winclient.InstalledSoftwareResult, error) {
	f.gotFilter = filter
	f.deadline, f.ok = ctx.Deadline()
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listOut != nil {
		return f.listOut, nil
	}
	return &winclient.InstalledSoftwareResult{Packages: []winclient.InstalledSoftware{}}, nil
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func isDSAdapterElemType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"name":                   tftypes.String,
		"version":                tftypes.String,
		"publisher":              tftypes.String,
		"install_date":           tftypes.String,
		"install_location":       tftypes.String,
		"product_code":           tftypes.String,
		"is_msi":                 tftypes.Bool,
		"architecture":           tftypes.String,
		"scope":                  tftypes.String,
		"user_sid":               tftypes.String,
		"estimated_size_kb":      tftypes.Number,
		"uninstall_string":       tftypes.String,
		"quiet_uninstall_string": tftypes.String,
		"registry_key":           tftypes.String,
	}}
}

func isDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                        tftypes.String,
		"name_regex":                tftypes.String,
		"publisher_regex":           tftypes.String,
		"product_code":              tftypes.String,
		"include_system_components": tftypes.Bool,
		"include_updates":           tftypes.Bool,
		"include_user_installs":     tftypes.Bool,
		"packages":                  tftypes.List{ElementType: isDSAdapterElemType()},
		"skipped_entries":           tftypes.Number,
		"timeouts":                  dsTimeoutsObjType(),
	}}
}

func isDSBaseVals() map[string]tftypes.Value {
	obj := isDSObjType()
	vals := map[string]tftypes.Value{}
	for name, typ := range obj.AttributeTypes {
		if name == "timeouts" {
			vals[name] = dsNullTimeoutsValue()
			continue
		}
		vals[name] = tftypes.NewValue(typ, nil)
	}
	return vals
}

// isDSConfig builds a config with the given filters; "" strings mean null,
// nil bools mean null.
func isDSConfig(nameRegex, publisherRegex, productCode string, system, updates, user *bool) tfsdk.Config {
	d := &windowsInstalledSoftwareDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := isDSBaseVals()
	if nameRegex != "" {
		vals["name_regex"] = tftypes.NewValue(tftypes.String, nameRegex)
	}
	if publisherRegex != "" {
		vals["publisher_regex"] = tftypes.NewValue(tftypes.String, publisherRegex)
	}
	if productCode != "" {
		vals["product_code"] = tftypes.NewValue(tftypes.String, productCode)
	}
	if system != nil {
		vals["include_system_components"] = tftypes.NewValue(tftypes.Bool, *system)
	}
	if updates != nil {
		vals["include_updates"] = tftypes.NewValue(tftypes.Bool, *updates)
	}
	if user != nil {
		vals["include_user_installs"] = tftypes.NewValue(tftypes.Bool, *user)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(isDSObjType(), vals),
	}
}

func isBool(b bool) *bool { return &b }

func fakeInstalledSoftwareFull() winclient.InstalledSoftware {
	return winclient.InstalledSoftware{
		Name:                 "Microsoft .NET Runtime 8",
		Version:              "8.0.0",
		Publisher:            "Microsoft Corporation",
		InstallDate:          "2024-01-15",
		InstallLocation:      `C:\Program Files\dotnet`,
		ProductCode:          "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
		IsMSI:                true,
		Architecture:         "x64",
		Scope:                "machine",
		UserSID:              "",
		EstimatedSizeKB:      1234,
		UninstallString:      `"C:\Program Files\dotnet\uninstall.exe"`,
		QuietUninstallString: `"C:\Program Files\dotnet\uninstall.exe" /quiet`,
		RegistryKey:          `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}`,
	}
}

func fakeInstalledSoftwareSparse() winclient.InstalledSoftware {
	return winclient.InstalledSoftware{
		Name:         "7-Zip 23.01 (x64)",
		Version:      "23.01",
		Publisher:    "Igor Pavlov",
		Architecture: "x64",
		Scope:        "machine",
		RegistryKey:  `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip 23.01 (x64)`,
		// InstallDate, InstallLocation, ProductCode, UserSID and the
		// uninstall strings stay empty; EstimatedSizeKB stays 0.
	}
}

// isAttrString extracts one packages element attribute.
func isAttrString(t *testing.T, m map[string]attr.Value, key string) types.String {
	t.Helper()
	v, ok := m[key].(types.String)
	if !ok {
		t.Fatalf("%s is %T, want types.String", key, m[key])
	}
	return v
}

func isAttrInt64(t *testing.T, m map[string]attr.Value, key string) types.Int64 {
	t.Helper()
	v, ok := m[key].(types.Int64)
	if !ok {
		t.Fatalf("%s is %T, want types.Int64", key, m[key])
	}
	return v
}

func isAttrBool(t *testing.T, m map[string]attr.Value, key string) types.Bool {
	t.Helper()
	v, ok := m[key].(types.Bool)
	if !ok {
		t.Fatalf("%s is %T, want types.Bool", key, m[key])
	}
	return v
}

func isPackageAttr(t *testing.T, state windowsInstalledSoftwareDataSourceModel, i int) map[string]attr.Value {
	t.Helper()
	elems := state.Packages.Elements()
	if len(elems) <= i {
		t.Fatalf("packages has %d elements, want index %d", len(elems), i)
	}
	obj, ok := elems[i].(interface{ Attributes() map[string]attr.Value })
	if !ok {
		t.Fatalf("element %d is %T, want an object", i, elems[i])
	}
	return obj.Attributes()
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

func TestInstalledSoftwareDSMetadata(t *testing.T) {
	d := &windowsInstalledSoftwareDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_installed_software" {
		t.Errorf("TypeName = %q, want windows_installed_software", resp.TypeName)
	}
}

func TestNewWindowsInstalledSoftwareDataSource_NotNil(t *testing.T) {
	if NewWindowsInstalledSoftwareDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

func TestInstalledSoftwareDSSchema(t *testing.T) {
	d := &windowsInstalledSoftwareDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "name_regex", "publisher_regex", "product_code",
		"include_system_components", "include_updates", "include_user_installs",
		"packages", "skipped_entries", "timeouts",
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

func TestInstalledSoftwareDSConfigure(t *testing.T) {
	d := &windowsInstalledSoftwareDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}

	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}

	d2 := &windowsInstalledSoftwareDataSource{}
	resp2 := &datasource.ConfigureResponse{}
	d2.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp2.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestInstalledSoftwareDSRead_HappyPath(t *testing.T) {
	fc := &fakeInstalledSoftwareClientDS{listOut: &winclient.InstalledSoftwareResult{
		Packages: []winclient.InstalledSoftware{
			fakeInstalledSoftwareFull(),
			fakeInstalledSoftwareSparse(),
		},
		SkippedEntries: 2,
	}}
	d := &windowsInstalledSoftwareDataSource{client: fc}
	cfg := isDSConfig("", "", "", nil, nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var state windowsInstalledSoftwareDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must be set (filter hash)")
	}
	if len(state.Packages.Elements()) != 2 {
		t.Fatalf("packages has %d elements, want 2", len(state.Packages.Elements()))
	}
	if state.SkippedEntries.ValueInt64() != 2 {
		t.Errorf("skipped_entries = %d, want 2", state.SkippedEntries.ValueInt64())
	}

	full := isPackageAttr(t, state, 0)
	if isAttrString(t, full, "name").ValueString() != "Microsoft .NET Runtime 8" {
		t.Errorf("name = %v", full["name"])
	}
	if isAttrString(t, full, "product_code").ValueString() != "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}" {
		t.Errorf("product_code = %v", full["product_code"])
	}
	if isAttrString(t, full, "install_date").ValueString() != "2024-01-15" {
		t.Errorf("install_date = %v", full["install_date"])
	}
	if !isAttrBool(t, full, "is_msi").ValueBool() {
		t.Error("is_msi should be true")
	}
	if isAttrInt64(t, full, "estimated_size_kb").ValueInt64() != 1234 {
		t.Errorf("estimated_size_kb = %v, want 1234", full["estimated_size_kb"])
	}

	// Sparse entry: empty strings stay empty (not null), size stays 0.
	sparse := isPackageAttr(t, state, 1)
	if isAttrString(t, sparse, "install_date").ValueString() != "" {
		t.Errorf("empty install_date must be empty, not null: %v", sparse["install_date"])
	}
	if isAttrString(t, sparse, "product_code").IsNull() {
		t.Error("empty product_code must be empty, not null")
	}
	if isAttrInt64(t, sparse, "estimated_size_kb").ValueInt64() != 0 {
		t.Errorf("estimated_size_kb = %v, want 0", sparse["estimated_size_kb"])
	}
	if isAttrBool(t, sparse, "is_msi").ValueBool() {
		t.Error("is_msi should be false for the sparse entry")
	}
}

func TestInstalledSoftwareDSRead_FiltersPassed(t *testing.T) {
	fc := &fakeInstalledSoftwareClientDS{}
	d := &windowsInstalledSoftwareDataSource{client: fc}
	cfg := isDSConfig(`\.NET.*`, `^Microsoft`, "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", isBool(true), isBool(false), isBool(true))
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if fc.gotFilter.NameRegex != `\.NET.*` || fc.gotFilter.PublisherRegex != `^Microsoft` ||
		fc.gotFilter.ProductCode != "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}" {
		t.Errorf("scalar filters not passed through: %+v", fc.gotFilter)
	}
	if !fc.gotFilter.IncludeSystemComponents || fc.gotFilter.IncludeUpdates || !fc.gotFilter.IncludeUserInstalls {
		t.Errorf("bool filters not passed through: %+v", fc.gotFilter)
	}
}

func TestInstalledSoftwareDSRead_Error(t *testing.T) {
	fc := &fakeInstalledSoftwareClientDS{listErr: winclient.NewInstalledSoftwareError(
		winclient.InstalledSoftwareErrorAccessDenied, "denied", nil, nil)}
	d := &windowsInstalledSoftwareDataSource{client: fc}
	cfg := isDSConfig("", "", "", nil, nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from list failure")
	}
}

func TestInstalledSoftwareDSRead_InvalidFilterError(t *testing.T) {
	// Filter validation lives in winclient (see
	// TestInstalledSoftwareList_InvalidFiltersNoHostCall for the
	// no-host-call contract); the provider surfaces the resulting
	// invalid_parameter error as a diagnostic.
	fc := &fakeInstalledSoftwareClientDS{listErr: winclient.NewInstalledSoftwareError(
		winclient.InstalledSoftwareErrorInvalidParameter, `name_regex "(unclosed" is not a valid regular expression`, nil, nil)}
	d := &windowsInstalledSoftwareDataSource{client: fc}
	cfg := isDSConfig("(unclosed", "", "", nil, nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for an invalid filter")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "invalid_parameter") &&
		!strings.Contains(resp.Diagnostics[0].Detail(), "not a valid regular expression") {
		t.Errorf("diagnostic should name the filter failure, got: %s", resp.Diagnostics[0].Detail())
	}
}

func TestInstalledSoftwareDSRead_EmptyResultNoError(t *testing.T) {
	fc := &fakeInstalledSoftwareClientDS{listOut: &winclient.InstalledSoftwareResult{}}
	d := &windowsInstalledSoftwareDataSource{client: fc}
	cfg := isDSConfig(`NoSuchSoftware.*`, "", "", nil, nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("empty match must not error: %v", resp.Diagnostics)
	}
	var state windowsInstalledSoftwareDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.Packages.IsNull() {
		t.Error("packages must be an empty list, not null")
	}
	if len(state.Packages.Elements()) != 0 {
		t.Errorf("packages must be empty, got %d elements", len(state.Packages.Elements()))
	}
	if state.SkippedEntries.ValueInt64() != 0 {
		t.Errorf("skipped_entries = %d, want 0", state.SkippedEntries.ValueInt64())
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must still be set for an empty match")
	}
}

func isDSReadID(t *testing.T, cfg tfsdk.Config) string {
	t.Helper()
	fc := &fakeInstalledSoftwareClientDS{}
	d := &windowsInstalledSoftwareDataSource{client: fc}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", resp.Diagnostics)
	}
	var state windowsInstalledSoftwareDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	return state.ID.ValueString()
}

func TestInstalledSoftwareDSRead_IDStability(t *testing.T) {
	a := isDSReadID(t, isDSConfig(`\.NET.*`, "", "", nil, nil, nil))
	b := isDSReadID(t, isDSConfig(`\.NET.*`, "", "", nil, nil, nil))
	if a != b {
		t.Errorf("same filter, different ID: %q vs %q", a, b)
	}
	c := isDSReadID(t, isDSConfig(`\.NET.*`, "", "", isBool(true), nil, nil))
	if a == c {
		t.Error("toggling include_system_components must change the ID")
	}
	d := isDSReadID(t, isDSConfig(`^7-Zip`, "", "", nil, nil, nil))
	if a == d {
		t.Error("changing name_regex must change the ID")
	}
	e := isDSReadID(t, isDSConfig("", "", "", nil, isBool(true), nil))
	if a == e {
		t.Error("toggling include_updates must change the ID")
	}
}

func TestInstalledSoftwareDSRead_IDProductCodeNormalization(t *testing.T) {
	// Every spelling of one GUID hashes to the same ID; a different GUID
	// moves it.
	a := isDSReadID(t, isDSConfig("", "", "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", nil, nil, nil))
	b := isDSReadID(t, isDSConfig("", "", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", nil, nil, nil))
	c := isDSReadID(t, isDSConfig("", "", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", nil, nil, nil))
	if a != b || a != c {
		t.Errorf("same GUID, different spellings must share an ID: %q vs %q vs %q", a, b, c)
	}
	d := isDSReadID(t, isDSConfig("", "", "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}", nil, nil, nil))
	if a == d {
		t.Error("a different product code must change the ID")
	}
}

func TestInstalledSoftwareDSRead_IDPipeAmbiguity(t *testing.T) {
	// The "|" join would hash ("a|b", "c") and ("a", "b|c") identically;
	// the JSON preimage must tell them apart.
	a := isDSReadID(t, isDSConfig("a|b", "c", "", nil, nil, nil))
	b := isDSReadID(t, isDSConfig("a", "b|c", "", nil, nil, nil))
	if a == b {
		t.Error("pipe-adjacent filter pairs must hash to different IDs")
	}
}

func TestInstalledSoftwareDSRead_RegexTrimmed(t *testing.T) {
	// Surrounding whitespace is trimmed before both List and the ID, so a
	// padded config behaves like (and hashes like) the trimmed one.
	fc := &fakeInstalledSoftwareClientDS{}
	d := &windowsInstalledSoftwareDataSource{client: fc}
	cfg := isDSConfig("  foo.*  ", "  ^Bar  ", "", nil, nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if fc.gotFilter.NameRegex != "foo.*" || fc.gotFilter.PublisherRegex != "^Bar" {
		t.Errorf("regexes must be trimmed before List, got %+v", fc.gotFilter)
	}
	a := isDSReadID(t, isDSConfig("  foo.*  ", "  ^Bar  ", "", nil, nil, nil))
	b := isDSReadID(t, isDSConfig("foo.*", "^Bar", "", nil, nil, nil))
	if a != b {
		t.Errorf("padded and trimmed regexes must share an ID: %q vs %q", a, b)
	}
}

func TestInstalledSoftwareDSSchema_UserInstallsDescription(t *testing.T) {
	d := &windowsInstalledSoftwareDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	attr, ok := resp.Schema.Attributes["include_user_installs"]
	if !ok {
		t.Fatal("schema missing attribute include_user_installs")
	}
	boolAttr, ok := attr.(schema.BoolAttribute)
	if !ok {
		t.Fatalf("include_user_installs is %T, want schema.BoolAttribute", attr)
	}
	desc := boolAttr.Description
	for _, want := range []string{"S-1-5-21", "excluded", "not scanned"} {
		if !strings.Contains(desc, want) {
			t.Errorf("include_user_installs description must mention %q, got: %s", want, desc)
		}
	}
}

// TestInstalledSoftwareDSRead_BoundedByTimeouts verifies the data source
// Read runs under a deadline derived from `timeouts.read` (issue #197):
// installedSoftwareDSDefaultTimeout when the block is absent, the configured
// value when set.
func TestInstalledSoftwareDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", installedSoftwareDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeInstalledSoftwareClientDS{}
			d := &windowsInstalledSoftwareDataSource{client: fake}
			cfg := isDSConfig("", "", "", nil, nil, nil)
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

func TestInstalledSoftwareDSConfigure_WrongType(t *testing.T) {
	d := &windowsInstalledSoftwareDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 42}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}
