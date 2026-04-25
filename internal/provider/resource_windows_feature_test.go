// Package provider — unit tests for windows_feature.
//
// These tests exercise schema, CRUD handlers, ImportState, helpers and
// addFeatureDiag without touching WinRM. CRUD handlers are driven via a
// fakeFeatureClient injected into windowsFeatureResource.feat.
//
// The 9 spec edge cases are covered:
//
//	EC-1 unknown feature   -> Create returns not_found error diag
//	EC-2 drift removal     -> Read sees nil info, RemoveResource called
//	EC-3 source missing    -> Create returns source_missing diag
//	EC-4 reboot warning    -> Install reports RestartNeeded -> warning diag
//	EC-5 permission denied -> Read returns permission_denied diag
//	EC-6 ForceNew on include_* -> schema-level RequiresReplace asserted
//	EC-7 dependency missing -> Create returns dependency_missing diag
//	EC-8 timeout           -> Install returns timeout diag
//	EC-9 unsupported SKU   -> Read returns unsupported_sku diag
package provider

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/ecritel/terraform-provider-windows/internal/winclient"
)

// -----------------------------------------------------------------------------
// Metadata + Schema
// -----------------------------------------------------------------------------

func TestFeatureMetadata(t *testing.T) {
	r := &windowsFeatureResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_feature" {
		t.Errorf("TypeName = %q, want windows_feature", resp.TypeName)
	}
}

func TestFeatureSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsFeatureSchemaDefinition()
	want := []string{
		"id", "name", "display_name", "description", "installed",
		"include_sub_features", "include_management_tools", "source",
		"restart", "restart_pending", "install_state",
	}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestFeatureSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsFeatureResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

// EC-6: name / include_sub_features / include_management_tools must use
// RequiresReplace plan modifiers.
func TestFeatureSchema_ForceNewAttributes_EC6(t *testing.T) {
	s := windowsFeatureSchemaDefinition()

	matchesReplace := func(desc string) bool {
		l := strings.ToLower(desc)
		return strings.Contains(l, "replace") || strings.Contains(l, "recreate")
	}

	// name -> StringAttribute
	nameAttr, ok := s.Attributes["name"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("name attr type = %T", s.Attributes["name"])
	}
	foundName := false
	for _, m := range nameAttr.PlanModifiers {
		if matchesReplace(m.Description(context.Background())) ||
			matchesReplace(m.MarkdownDescription(context.Background())) {
			foundName = true
		}
	}
	if !foundName {
		t.Error("EC-6: name must have RequiresReplace plan modifier")
	}

	for _, name := range []string{"include_sub_features", "include_management_tools"} {
		boolAttr, ok := s.Attributes[name].(rschema.BoolAttribute)
		if !ok {
			t.Fatalf("%s attr type = %T", name, s.Attributes[name])
		}
		found := false
		for _, m := range boolAttr.PlanModifiers {
			if matchesReplace(m.Description(context.Background())) ||
				matchesReplace(m.MarkdownDescription(context.Background())) {
				found = true
			}
		}
		if !found {
			t.Errorf("EC-6: %s must have RequiresReplace plan modifier", name)
		}
	}
}

// Name regex sanity, mirrors the spec validation.
func TestFeatureNameRegex(t *testing.T) {
	re := regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]*$")
	ok := []string{"Web-Server", "DNS", "RSAT-AD-PowerShell", "a", "Foo.Bar", "X_Y"}
	ko := []string{"", "-Web", ".dot", "with space", "with/slash", "%pc"}
	for _, s := range ok {
		if !re.MatchString(s) {
			t.Errorf("expected %q to match", s)
		}
	}
	for _, s := range ko {
		if re.MatchString(s) {
			t.Errorf("expected %q NOT to match", s)
		}
	}
}

// -----------------------------------------------------------------------------
// addFeatureDiag
// -----------------------------------------------------------------------------

func TestAddFeatureDiag_StructuredError(t *testing.T) {
	diags := &diag.Diagnostics{}
	fe := winclient.NewFeatureError(
		winclient.FeatureErrorPermission,
		"access denied", nil,
		map[string]string{"name": "Web-Server", "host": "WIN01"},
	)
	addFeatureDiag(diags, "Read failed", fe)
	if !diags.HasError() {
		t.Fatal("expected error diag")
	}
	detail := (*diags)[0].Detail()
	if !strings.Contains(detail, "permission_denied") {
		t.Errorf("missing kind in detail: %s", detail)
	}
	if !strings.Contains(detail, "access denied") {
		t.Errorf("missing message in detail: %s", detail)
	}
	if !strings.Contains(detail, "Web-Server") {
		t.Errorf("missing context name: %s", detail)
	}
}

func TestAddFeatureDiag_PlainError(t *testing.T) {
	diags := &diag.Diagnostics{}
	addFeatureDiag(diags, "Generic", errors.New("boom"))
	if !diags.HasError() {
		t.Fatal("expected error diag")
	}
	if !strings.Contains((*diags)[0].Detail(), "boom") {
		t.Errorf("missing underlying text: %s", (*diags)[0].Detail())
	}
}

// -----------------------------------------------------------------------------
// modelFromFeature + applyInstallResult
// -----------------------------------------------------------------------------

func TestModelFromFeature_AllFields(t *testing.T) {
	info := &winclient.FeatureInfo{
		Name: "Web-Server", DisplayName: "Web Server", Description: "IIS",
		Installed: true, InstallState: "Installed", RestartPending: false,
	}
	prior := windowsFeatureModel{
		IncludeSubFeatures:     types.BoolValue(true),
		IncludeManagementTools: types.BoolValue(false),
		Source:                 types.StringValue(`\\srv\share`),
		Restart:                types.BoolValue(true),
	}
	got := modelFromFeature(info, prior)
	if got.ID.ValueString() != "Web-Server" || got.Name.ValueString() != "Web-Server" {
		t.Errorf("ID/Name mismatch: %+v", got)
	}
	if !got.Installed.ValueBool() || got.InstallState.ValueString() != "Installed" {
		t.Errorf("Installed/InstallState mismatch")
	}
	if !got.IncludeSubFeatures.ValueBool() || got.Source.ValueString() != `\\srv\share` || !got.Restart.ValueBool() {
		t.Errorf("desired-input fields not preserved: %+v", got)
	}
}

func TestModelFromFeature_NullDefaults(t *testing.T) {
	info := &winclient.FeatureInfo{Name: "X", InstallState: "Available"}
	prior := windowsFeatureModel{
		IncludeSubFeatures:     types.BoolNull(),
		IncludeManagementTools: types.BoolUnknown(),
		Restart:                types.BoolNull(),
	}
	got := modelFromFeature(info, prior)
	if got.IncludeSubFeatures.ValueBool() {
		t.Error("IncludeSubFeatures default should be false")
	}
	if got.IncludeManagementTools.ValueBool() {
		t.Error("IncludeManagementTools default should be false")
	}
	if got.Restart.ValueBool() {
		t.Error("Restart default should be false")
	}
}

func TestApplyInstallResult_RestartWarning_EC4(t *testing.T) {
	d := &diag.Diagnostics{}
	m := &windowsFeatureModel{
		Name:           types.StringValue("Web-Server"),
		RestartPending: types.BoolValue(false),
	}
	plan := windowsFeatureModel{Restart: types.BoolValue(false)}
	r := &winclient.InstallResult{RestartNeeded: true, ExitCode: "SuccessRestartRequired"}
	applyInstallResult(d, m, plan, r)
	if !m.RestartPending.ValueBool() {
		t.Error("EC-4: RestartPending should be set true")
	}
	if d.WarningsCount() == 0 {
		t.Error("EC-4: a warning diagnostic must be emitted")
	}
}

func TestApplyInstallResult_NoWarningWhenRestartTrue(t *testing.T) {
	d := &diag.Diagnostics{}
	m := &windowsFeatureModel{Name: types.StringValue("X")}
	plan := windowsFeatureModel{Restart: types.BoolValue(true)}
	r := &winclient.InstallResult{RestartNeeded: true, ExitCode: "SuccessRestartRequired"}
	applyInstallResult(d, m, plan, r)
	if d.WarningsCount() != 0 {
		t.Errorf("no warning expected when restart=true; got %d", d.WarningsCount())
	}
}

func TestApplyInstallResult_NilResult(t *testing.T) {
	d := &diag.Diagnostics{}
	m := &windowsFeatureModel{}
	applyInstallResult(d, m, windowsFeatureModel{}, nil)
	if d.HasError() || d.WarningsCount() != 0 {
		t.Error("nil result must be a no-op")
	}
}

// -----------------------------------------------------------------------------
// Configure
// -----------------------------------------------------------------------------

func TestFeatureConfigure_NilProviderData(t *testing.T) {
	r := &windowsFeatureResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
}

func TestFeatureConfigure_WrongType(t *testing.T) {
	r := &windowsFeatureResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should error")
	}
}

func TestFeatureConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsFeatureResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.client != c || r.feat == nil {
		t.Error("Configure must populate client and feat")
	}
}

func TestNewWindowsFeatureResource_NotNil(t *testing.T) {
	if NewWindowsFeatureResource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// -----------------------------------------------------------------------------
// Fake WindowsFeatureClient
// -----------------------------------------------------------------------------

type fakeFeatureClient struct {
	readOut    *winclient.FeatureInfo
	readErr    error
	installIn  winclient.FeatureInput
	installOut *winclient.FeatureInfo
	installRes *winclient.InstallResult
	installErr error
	uninstIn   winclient.FeatureInput
	uninstOut  *winclient.FeatureInfo
	uninstRes  *winclient.InstallResult
	uninstErr  error
}

func (f *fakeFeatureClient) Read(_ context.Context, _ string) (*winclient.FeatureInfo, error) {
	return f.readOut, f.readErr
}
func (f *fakeFeatureClient) Install(_ context.Context, in winclient.FeatureInput) (*winclient.FeatureInfo, *winclient.InstallResult, error) {
	f.installIn = in
	return f.installOut, f.installRes, f.installErr
}
func (f *fakeFeatureClient) Uninstall(_ context.Context, in winclient.FeatureInput) (*winclient.FeatureInfo, *winclient.InstallResult, error) {
	f.uninstIn = in
	return f.uninstOut, f.uninstRes, f.uninstErr
}

// -----------------------------------------------------------------------------
// Schema-shaped tftypes object helpers
// -----------------------------------------------------------------------------

func featureObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                       tftypes.String,
		"name":                     tftypes.String,
		"display_name":             tftypes.String,
		"description":              tftypes.String,
		"installed":                tftypes.Bool,
		"include_sub_features":     tftypes.Bool,
		"include_management_tools": tftypes.Bool,
		"source":                   tftypes.String,
		"restart":                  tftypes.Bool,
		"restart_pending":          tftypes.Bool,
		"install_state":            tftypes.String,
	}}
}

func featObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":                       tftypes.NewValue(tftypes.String, nil),
		"name":                     tftypes.NewValue(tftypes.String, nil),
		"display_name":             tftypes.NewValue(tftypes.String, nil),
		"description":              tftypes.NewValue(tftypes.String, nil),
		"installed":                tftypes.NewValue(tftypes.Bool, nil),
		"include_sub_features":     tftypes.NewValue(tftypes.Bool, false),
		"include_management_tools": tftypes.NewValue(tftypes.Bool, false),
		"source":                   tftypes.NewValue(tftypes.String, nil),
		"restart":                  tftypes.NewValue(tftypes.Bool, false),
		"restart_pending":          tftypes.NewValue(tftypes.Bool, nil),
		"install_state":            tftypes.NewValue(tftypes.String, nil),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(featureObjectType(), base)
}

func okFeatureInfo() *winclient.FeatureInfo {
	return &winclient.FeatureInfo{
		Name: "Web-Server", DisplayName: "Web Server", Description: "IIS",
		Installed: true, InstallState: "Installed", RestartPending: false,
	}
}

// -----------------------------------------------------------------------------
// CRUD handler tests
// -----------------------------------------------------------------------------

func TestFeatureCreate_Handler_HappyPath(t *testing.T) {
	fake := &fakeFeatureClient{
		installOut: okFeatureInfo(),
		installRes: &winclient.InstallResult{Success: true, ExitCode: "Success"},
	}
	r := &windowsFeatureResource{feat: fake}

	schemaDef := windowsFeatureSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"name":                     tftypes.NewValue(tftypes.String, "Web-Server"),
			"include_sub_features":     tftypes.NewValue(tftypes.Bool, true),
			"include_management_tools": tftypes.NewValue(tftypes.Bool, true),
			"source":                   tftypes.NewValue(tftypes.String, `\\srv\sxs`),
			"restart":                  tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: featObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.installIn.Name != "Web-Server" {
		t.Errorf("Install input Name = %q", fake.installIn.Name)
	}
	if !fake.installIn.IncludeSubFeatures || !fake.installIn.IncludeManagementTools {
		t.Errorf("include_* not propagated: %+v", fake.installIn)
	}
	if fake.installIn.Source != `\\srv\sxs` {
		t.Errorf("Source not propagated: %q", fake.installIn.Source)
	}
}

func TestFeatureCreate_Handler_RestartWarning_EC4(t *testing.T) {
	fake := &fakeFeatureClient{
		installOut: okFeatureInfo(),
		installRes: &winclient.InstallResult{Success: true, RestartNeeded: true, ExitCode: "SuccessRestartRequired"},
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"name":    tftypes.NewValue(tftypes.String, "Web-Server"),
			"restart": tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: featObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Error("EC-4: expected a reboot warning when RestartNeeded && restart=false")
	}
}

func TestFeatureCreate_Handler_NotFound_EC1(t *testing.T) {
	fake := &fakeFeatureClient{
		installErr: winclient.NewFeatureError(winclient.FeatureErrorNotFound,
			"Feature 'Bogus' was not found", nil, map[string]string{"name": "Bogus"}),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"name": tftypes.NewValue(tftypes.String, "Bogus"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: featObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-1 expected error diag")
	}
}

func TestFeatureCreate_Handler_SourceMissing_EC3(t *testing.T) {
	fake := &fakeFeatureClient{
		installErr: winclient.NewFeatureError(winclient.FeatureErrorSourceMissing,
			"install_state=Removed; provide source", nil, nil),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: featObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-3 expected error diag")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "source_missing") {
		t.Errorf("EC-3 expected source_missing kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

func TestFeatureCreate_Handler_DependencyMissing_EC7(t *testing.T) {
	fake := &fakeFeatureClient{
		installErr: winclient.NewFeatureError(winclient.FeatureErrorDependencyMissing,
			"depends on Web-Server", nil, nil),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"name": tftypes.NewValue(tftypes.String, "Web-Mgmt-Service"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: featObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-7 expected error diag")
	}
}

func TestFeatureCreate_Handler_Timeout_EC8(t *testing.T) {
	fake := &fakeFeatureClient{
		installErr: winclient.NewFeatureError(winclient.FeatureErrorTimeout,
			"timed out installing Web-Server", context.DeadlineExceeded, nil),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: featObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-8 expected error diag for timeout")
	}
}

func TestFeatureRead_Handler_HappyPath(t *testing.T) {
	fake := &fakeFeatureClient{readOut: okFeatureInfo()}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should NOT be removed on happy read")
	}
}

func TestFeatureRead_Handler_DriftRemoved_EC2(t *testing.T) {
	fake := &fakeFeatureClient{readOut: nil, readErr: nil}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("EC-2: state should be removed when feature is gone")
	}
}

func TestFeatureRead_Handler_PermissionDenied_EC5(t *testing.T) {
	fake := &fakeFeatureClient{
		readErr: winclient.NewFeatureError(winclient.FeatureErrorPermission,
			"Access is denied (Local Administrator on the target host is required.)", nil, nil),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-5 expected permission_denied error")
	}
}

func TestFeatureRead_Handler_UnsupportedSKU_EC9(t *testing.T) {
	fake := &fakeFeatureClient{
		readErr: winclient.NewFeatureError(winclient.FeatureErrorUnsupportedSKU,
			"ServerManager not available; use Enable-WindowsOptionalFeature", nil, nil),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-9 expected unsupported_sku error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "Enable-WindowsOptionalFeature") {
		t.Errorf("EC-9 should hint at Enable-WindowsOptionalFeature: %v", diagDetails(resp.Diagnostics))
	}
}

func TestFeatureUpdate_Handler_HappyPath(t *testing.T) {
	fake := &fakeFeatureClient{
		installOut: okFeatureInfo(),
		installRes: &winclient.InstallResult{Success: true},
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"name":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"source": tftypes.NewValue(tftypes.String, `\\new\sxs`),
		}),
	}
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(),
		resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.installIn.Source != `\\new\sxs` {
		t.Errorf("source not propagated to Update: %q", fake.installIn.Source)
	}
}

func TestFeatureDelete_Handler_HappyPath(t *testing.T) {
	fake := &fakeFeatureClient{
		uninstOut: nil,
		uninstRes: &winclient.InstallResult{Success: true, ExitCode: "Success"},
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":      tftypes.NewValue(tftypes.String, "Web-Server"),
			"name":    tftypes.NewValue(tftypes.String, "Web-Server"),
			"restart": tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.uninstIn.Name != "Web-Server" {
		t.Errorf("Uninstall called with %q", fake.uninstIn.Name)
	}
}

func TestFeatureDelete_Handler_AlreadyAbsent_NotFound(t *testing.T) {
	// not_found from Uninstall must be swallowed (idempotent).
	fake := &fakeFeatureClient{
		uninstErr: winclient.NewFeatureError(winclient.FeatureErrorNotFound, "gone", nil, nil),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete should be idempotent for not_found, got %v", resp.Diagnostics)
	}
}

func TestFeatureDelete_Handler_RestartWarning(t *testing.T) {
	fake := &fakeFeatureClient{
		uninstRes: &winclient.InstallResult{Success: true, RestartNeeded: true, ExitCode: "SuccessRestartRequired"},
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":      tftypes.NewValue(tftypes.String, "Web-Server"),
			"name":    tftypes.NewValue(tftypes.String, "Web-Server"),
			"restart": tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Error("expected a reboot warning when uninstall reports RestartNeeded && restart=false")
	}
}

func TestFeatureDelete_Handler_PermissionDenied(t *testing.T) {
	fake := &fakeFeatureClient{
		uninstErr: winclient.NewFeatureError(winclient.FeatureErrorPermission, "denied", nil, nil),
	}
	r := &windowsFeatureResource{feat: fake}
	schemaDef := windowsFeatureSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: featObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "Web-Server"),
			"name": tftypes.NewValue(tftypes.String, "Web-Server"),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("permission_denied during Delete must surface as error")
	}
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestFeatureImportState_Handler(t *testing.T) {
	r := &windowsFeatureResource{}
	schemaDef := windowsFeatureSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: featObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "Web-Server"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	var m windowsFeatureModel
	d := resp.State.Get(context.Background(), &m)
	if d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != "Web-Server" || m.Name.ValueString() != "Web-Server" {
		t.Errorf("import state = id=%q name=%q", m.ID.ValueString(), m.Name.ValueString())
	}
}

// -----------------------------------------------------------------------------
// Utility used by detail assertions
// -----------------------------------------------------------------------------

func diagDetails(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+" / "+x.Detail())
	}
	return out
}
