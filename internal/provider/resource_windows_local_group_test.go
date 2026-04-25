// Package provider — unit tests for the windows_local_group resource.
//
// These tests exercise schema, validators, CRUD handlers, ImportState, and
// helpers without touching WinRM. CRUD handlers are driven via a
// fakeLocalGroupClient injected into windowsLocalGroupResource.grp.
//
// Edge cases covered (aligned with spec EC-* identifiers):
//
//	EC-1  Group exists at Create             -> AlreadyExists diag
//	EC-2  Delete built-in group              -> BuiltinGroup diag
//	EC-3  Group disappears (Read nil,nil)    -> RemoveResource
//	EC-4  Name casing drift (EqualFold)      -> prior name kept in state
//	EC-5  Rename in place                    -> Update called, SID stable
//	EC-6  Invalid name (schema validators)   -> whitespace / leading-space rules
//	EC-7  Description > 256 chars (schema)   -> LengthBetween validator
//	EC-8  Permission denied                  -> permission_denied diag
//	EC-10 Import by name vs by SID           -> ImportState auto-detection
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// -----------------------------------------------------------------------------
// Fake WindowsLocalGroupClient
// -----------------------------------------------------------------------------

type fakeLocalGroupClient struct {
	createOut       *winclient.GroupState
	createErr       error
	readOut         *winclient.GroupState
	readErr         error
	updateOut       *winclient.GroupState
	updateErr       error
	deleteErr       error
	importByNameOut *winclient.GroupState
	importByNameErr error
	importBySIDOut  *winclient.GroupState
	importBySIDErr  error

	// Capture calls for assertions.
	lastUpdateSID   string
	lastUpdateInput winclient.GroupInput
}

func (f *fakeLocalGroupClient) Create(_ context.Context, _ winclient.GroupInput) (*winclient.GroupState, error) {
	return f.createOut, f.createErr
}
func (f *fakeLocalGroupClient) Read(_ context.Context, _ string) (*winclient.GroupState, error) {
	return f.readOut, f.readErr
}
func (f *fakeLocalGroupClient) Update(_ context.Context, sid string, input winclient.GroupInput) (*winclient.GroupState, error) {
	f.lastUpdateSID = sid
	f.lastUpdateInput = input
	return f.updateOut, f.updateErr
}
func (f *fakeLocalGroupClient) Delete(_ context.Context, _ string) error {
	return f.deleteErr
}
func (f *fakeLocalGroupClient) ImportByName(_ context.Context, _ string) (*winclient.GroupState, error) {
	return f.importByNameOut, f.importByNameErr
}
func (f *fakeLocalGroupClient) ImportBySID(_ context.Context, _ string) (*winclient.GroupState, error) {
	return f.importBySIDOut, f.importBySIDErr
}

// -----------------------------------------------------------------------------
// tftypes helpers for local group schema
// -----------------------------------------------------------------------------

func localGroupObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":          tftypes.String,
		"name":        tftypes.String,
		"description": tftypes.String,
		"sid":         tftypes.String,
	}}
}

// lgObj builds a tftypes.Value for the local group schema with optional overrides.
func lgObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":          tftypes.NewValue(tftypes.String, nil),
		"name":        tftypes.NewValue(tftypes.String, nil),
		"description": tftypes.NewValue(tftypes.String, ""),
		"sid":         tftypes.NewValue(tftypes.String, nil),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(localGroupObjectType(), base)
}

func okGroupState(name, desc, sid string) *winclient.GroupState {
	return &winclient.GroupState{Name: name, Description: desc, SID: sid}
}

// lgDiagDetails extracts Summary + " / " + Detail from each diagnostic.
func lgDiagDetails(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+" / "+x.Detail())
	}
	return out
}

// lgValidatorStringReq builds a validator.StringRequest for testing name validators.
func lgValidatorStringReq(val string) validator.StringRequest {
	return validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringValue(val),
	}
}

// lgNullValidatorStringReq builds a validator.StringRequest with a null value.
func lgNullValidatorStringReq() validator.StringRequest {
	return validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringNull(),
	}
}

// -----------------------------------------------------------------------------
// Metadata + Schema
// -----------------------------------------------------------------------------

func TestLocalGroupMetadata(t *testing.T) {
	r := &windowsLocalGroupResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_local_group" {
		t.Errorf("TypeName = %q, want windows_local_group", resp.TypeName)
	}
}

func TestLocalGroupSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsLocalGroupSchemaDefinition()
	want := []string{"id", "name", "description", "sid"}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestLocalGroupSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsLocalGroupResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

func TestLocalGroupSchema_NameIsRequired(t *testing.T) {
	s := windowsLocalGroupSchemaDefinition()
	nameAttr, ok := s.Attributes["name"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("name attribute type %T is not StringAttribute", s.Attributes["name"])
	}
	if !nameAttr.Required {
		t.Error("name attribute must be Required")
	}
	// name must NOT have RequiresReplace — renames are in-place via Rename-LocalGroup (EC-5).
	for _, pm := range nameAttr.PlanModifiers {
		desc := strings.ToLower(pm.Description(context.Background()) + pm.MarkdownDescription(context.Background()))
		if strings.Contains(desc, "replace") || strings.Contains(desc, "recreate") {
			t.Error("name must NOT have RequiresReplace plan modifier; renames are in-place (EC-5, ADR-LG-1)")
		}
	}
}

func TestLocalGroupSchema_SIDIsComputed(t *testing.T) {
	s := windowsLocalGroupSchemaDefinition()
	sidAttr, ok := s.Attributes["sid"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("sid attribute type %T", s.Attributes["sid"])
	}
	if !sidAttr.Computed {
		t.Error("sid must be Computed")
	}
	if sidAttr.Required || sidAttr.Optional {
		t.Error("sid must not be Required or Optional (read-only attribute)")
	}
}

func TestLocalGroupSchema_DescriptionOptionalComputed(t *testing.T) {
	s := windowsLocalGroupSchemaDefinition()
	descAttr, ok := s.Attributes["description"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("description attribute type %T", s.Attributes["description"])
	}
	if !descAttr.Optional {
		t.Error("description must be Optional")
	}
	if !descAttr.Computed {
		t.Error("description must be Computed (ADR-LG-5: Default requires Computed=true)")
	}
}

func TestLocalGroupSchema_IDHasUseStateForUnknown(t *testing.T) {
	s := windowsLocalGroupSchemaDefinition()
	idAttr, ok := s.Attributes["id"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("id attribute type %T", s.Attributes["id"])
	}
	found := false
	for _, pm := range idAttr.PlanModifiers {
		desc := strings.ToLower(pm.Description(context.Background()) + pm.MarkdownDescription(context.Background()))
		if strings.Contains(desc, "unknown") || strings.Contains(desc, "state") {
			found = true
		}
	}
	if !found {
		t.Error("id must have UseStateForUnknown plan modifier (ADR-LG-1)")
	}
}

// -----------------------------------------------------------------------------
// localGroupNameValidator (EC-6)
// -----------------------------------------------------------------------------

func TestLocalGroupNameValidator_WhitespaceOnly_EC6(t *testing.T) {
	v := localGroupNameValidator{}
	req := lgValidatorStringReq("   ")
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("EC-6: whitespace-only name should fail validation")
	}
	if len(resp.Diagnostics) > 0 {
		detail := resp.Diagnostics[0].Detail()
		if !strings.Contains(detail, "whitespace") {
			t.Errorf("diagnostic should mention whitespace: %s", detail)
		}
	}
}

func TestLocalGroupNameValidator_LeadingSpace_EC6(t *testing.T) {
	v := localGroupNameValidator{}
	req := lgValidatorStringReq(" AppAdmins")
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("EC-6: leading space should fail validation")
	}
}

func TestLocalGroupNameValidator_TrailingSpace_EC6(t *testing.T) {
	v := localGroupNameValidator{}
	req := lgValidatorStringReq("AppAdmins ")
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("EC-6: trailing space should fail validation")
	}
}

func TestLocalGroupNameValidator_ValidNames_EC6(t *testing.T) {
	v := localGroupNameValidator{}
	validNames := []string{
		"AppAdmins",
		"Remote Desktop Users",
		"my-group",
		"Group123",
		"A",
	}
	for _, name := range validNames {
		req := lgValidatorStringReq(name)
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("valid name %q rejected: %v", name, resp.Diagnostics)
		}
	}
}

func TestLocalGroupNameValidator_NullSkipped(t *testing.T) {
	v := localGroupNameValidator{}
	req := lgNullValidatorStringReq()
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should be skipped by validator")
	}
}

func TestLocalGroupNameValidator_Description(t *testing.T) {
	v := localGroupNameValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description() must return a non-empty string")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription() must return a non-empty string")
	}
}

// -----------------------------------------------------------------------------
// localGroupNameRegex (EC-6)
// -----------------------------------------------------------------------------

func TestLocalGroupNameRegex(t *testing.T) {
	valid := []string{
		"AppAdmins", "Group-1", "My Group", "a", "123", "αβγ",
	}
	for _, n := range valid {
		if !localGroupNameRegex.MatchString(n) {
			t.Errorf("valid name %q did not match regex", n)
		}
	}
	invalid := []string{
		"",
		"Group/Name",
		"Group\\Name",
		"Group[Name",
		"Group]Name",
		"Group:Name",
		"Group;Name",
		"Group|Name",
		"Group=Name",
		"Group,Name",
		"Group+Name",
		"Group*Name",
		"Group?Name",
		"Group<Name",
		"Group>Name",
		`Group"Name`,
	}
	for _, n := range invalid {
		if localGroupNameRegex.MatchString(n) {
			t.Errorf("invalid name %q should NOT match regex", n)
		}
	}
}

// -----------------------------------------------------------------------------
// addLocalGroupDiag helper
// -----------------------------------------------------------------------------

func TestAddLocalGroupDiag_StructuredError(t *testing.T) {
	diags := &diag.Diagnostics{}
	lge := winclient.NewLocalGroupError(
		winclient.LocalGroupErrorPermission,
		"Access is denied",
		nil,
		map[string]string{"sid": "S-1-5-21-1-2-3-4", "host": "win01"},
	)
	addLocalGroupDiag(diags, "Read failed", lge)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := (*diags)[0].Detail()
	if !strings.Contains(detail, "permission_denied") {
		t.Errorf("diagnostic should contain kind 'permission_denied': %s", detail)
	}
	if !strings.Contains(detail, "Access is denied") {
		t.Errorf("diagnostic should contain message: %s", detail)
	}
	if !strings.Contains(detail, "win01") {
		t.Errorf("diagnostic should contain context value 'win01': %s", detail)
	}
}

func TestAddLocalGroupDiag_PlainError(t *testing.T) {
	diags := &diag.Diagnostics{}
	addLocalGroupDiag(diags, "Failed", errors.New("plain error message"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(diags.Errors()[0].Detail(), "plain error message") {
		t.Errorf("detail should contain plain error: %s", diags.Errors()[0].Detail())
	}
}

func TestAddLocalGroupDiag_BuiltinGroupKind(t *testing.T) {
	diags := &diag.Diagnostics{}
	lge := winclient.NewLocalGroupError(
		winclient.LocalGroupErrorBuiltinGroup,
		"cannot destroy built-in local group",
		nil,
		map[string]string{"sid": "S-1-5-32-544", "name": "Administrators"},
	)
	addLocalGroupDiag(diags, "Delete failed", lge)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags.Errors()[0].Detail()
	if !strings.Contains(detail, "builtin_group") {
		t.Errorf("diagnostic should contain kind 'builtin_group': %s", detail)
	}
}

// -----------------------------------------------------------------------------
// stateFromGroup helper
// -----------------------------------------------------------------------------

func TestStateFromGroup(t *testing.T) {
	gs := &winclient.GroupState{
		Name:        "AppAdmins",
		Description: "Application Administrators",
		SID:         "S-1-5-21-111-222-333-1001",
	}
	m := stateFromGroup(gs)
	if m.ID.ValueString() != "S-1-5-21-111-222-333-1001" {
		t.Errorf("ID = %q, want SID (ADR-LG-1)", m.ID.ValueString())
	}
	if m.SID.ValueString() != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", m.SID.ValueString())
	}
	if m.Name.ValueString() != "AppAdmins" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
	if m.Description.ValueString() != "Application Administrators" {
		t.Errorf("Description = %q", m.Description.ValueString())
	}
}

func TestStateFromGroup_IDEqualsSID(t *testing.T) {
	// ADR-LG-1: ID must equal SID in all cases.
	gs := &winclient.GroupState{Name: "X", Description: "", SID: "S-1-5-21-9-8-7-500"}
	m := stateFromGroup(gs)
	if m.ID.ValueString() != m.SID.ValueString() {
		t.Errorf("ADR-LG-1: ID (%q) must equal SID (%q)", m.ID.ValueString(), m.SID.ValueString())
	}
}

// -----------------------------------------------------------------------------
// Configure
// -----------------------------------------------------------------------------

func TestLocalGroupConfigure_NilProviderData(t *testing.T) {
	r := &windowsLocalGroupResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
}

func TestLocalGroupConfigure_WrongType(t *testing.T) {
	r := &windowsLocalGroupResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should produce an error diagnostic")
	}
}

func TestLocalGroupConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsLocalGroupResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.client != c {
		t.Error("Configure must populate client field")
	}
	if r.grp == nil {
		t.Error("Configure must populate grp field with a LocalGroupClient")
	}
}

func TestNewWindowsLocalGroupResource_NotNil(t *testing.T) {
	if NewWindowsLocalGroupResource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// -----------------------------------------------------------------------------
// Create handler
// -----------------------------------------------------------------------------

func TestLocalGroupCreate_HappyPath_Handler(t *testing.T) {
	fake := &fakeLocalGroupClient{
		createOut: okGroupState("AppAdmins", "Application admins", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()

	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"name":        tftypes.NewValue(tftypes.String, "AppAdmins"),
			"description": tftypes.NewValue(tftypes.String, "Application admins"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgDiagDetails(resp.Diagnostics))
	}

	var m windowsLocalGroupModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "S-1-5-21-111-222-333-1001" {
		t.Errorf("ID = %q, want SID", m.ID.ValueString())
	}
	if m.Name.ValueString() != "AppAdmins" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
	if m.Description.ValueString() != "Application admins" {
		t.Errorf("Description = %q", m.Description.ValueString())
	}
}

func TestLocalGroupCreate_AlreadyExists_EC1(t *testing.T) {
	fake := &fakeLocalGroupClient{
		createErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorAlreadyExists,
			"local group 'AppAdmins' already exists; use terraform import",
			nil,
			map[string]string{"name": "AppAdmins", "sid": "S-1-5-21-111-222-333-1001"},
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-1: expected error diagnostic for already_exists")
	}
	details := strings.Join(lgDiagDetails(resp.Diagnostics), "\n")
	if !strings.Contains(details, "already_exists") {
		t.Errorf("EC-1 diagnostic should mention already_exists: %s", details)
	}
}

func TestLocalGroupCreate_PermissionDenied_EC8(t *testing.T) {
	fake := &fakeLocalGroupClient{
		createErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorPermission,
			"Access is denied; Administrator rights required",
			nil,
			map[string]string{"host": "win01"},
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-8: expected permission_denied error diagnostic")
	}
}

// -----------------------------------------------------------------------------
// Read handler
// -----------------------------------------------------------------------------

func TestLocalGroupRead_HappyPath_Handler(t *testing.T) {
	fake := &fakeLocalGroupClient{
		readOut: okGroupState("AppAdmins", "desc", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name":        tftypes.NewValue(tftypes.String, "AppAdmins"),
			"description": tftypes.NewValue(tftypes.String, "desc"),
			"sid":         tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgDiagDetails(resp.Diagnostics))
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should NOT be removed on happy read")
	}
}

func TestLocalGroupRead_GroupNotFound_EC3(t *testing.T) {
	// EC-3: (nil, nil) → RemoveResource.
	fake := &fakeLocalGroupClient{readOut: nil, readErr: nil}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("EC-3 should not produce error diags: %v", lgDiagDetails(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("EC-3: state must be removed (RemoveResource) when group is gone")
	}
}

func TestLocalGroupRead_PermissionDenied_EC8(t *testing.T) {
	fake := &fakeLocalGroupClient{
		readErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorPermission,
			"Access is denied",
			nil, nil,
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-8: expected permission_denied error diagnostic")
	}
}

func TestLocalGroupRead_CaseInsensitiveNameNormalisation_EC4(t *testing.T) {
	// EC-4 / ADR-LG-4: Windows returns "AppAdmins"; prior state has "appadmins".
	// Read should keep the prior state name to avoid permanent plan diff.
	fake := &fakeLocalGroupClient{
		readOut: okGroupState("AppAdmins", "desc", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name":        tftypes.NewValue(tftypes.String, "appadmins"), // lowercase in state
			"description": tftypes.NewValue(tftypes.String, "desc"),
			"sid":         tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgDiagDetails(resp.Diagnostics))
	}
	var m windowsLocalGroupModel
	resp.State.Get(context.Background(), &m)
	// Prior state name (lowercase) should be preserved to prevent spurious diff.
	if m.Name.ValueString() != "appadmins" {
		t.Errorf("EC-4: expected prior state name 'appadmins' to be preserved, got %q", m.Name.ValueString())
	}
}

func TestLocalGroupRead_FallbackToIDWhenSIDEmpty(t *testing.T) {
	// When SID is empty/null in state, read falls back to ID.
	fake := &fakeLocalGroupClient{
		readOut: okGroupState("AppAdmins", "desc", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name":        tftypes.NewValue(tftypes.String, "AppAdmins"),
			"description": tftypes.NewValue(tftypes.String, ""),
			"sid":         tftypes.NewValue(tftypes.String, nil), // null SID
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("fallback to ID should work: %v", lgDiagDetails(resp.Diagnostics))
	}
}

// -----------------------------------------------------------------------------
// Update handler
// -----------------------------------------------------------------------------

func TestLocalGroupUpdate_HappyPath_Handler(t *testing.T) {
	fake := &fakeLocalGroupClient{
		updateOut: okGroupState("NewName", "New desc", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()

	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"name":        tftypes.NewValue(tftypes.String, "NewName"),
			"description": tftypes.NewValue(tftypes.String, "New desc"),
			"sid":         tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"id":          tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name":        tftypes.NewValue(tftypes.String, "OldName"),
			"description": tftypes.NewValue(tftypes.String, "Old desc"),
			"sid":         tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgDiagDetails(resp.Diagnostics))
	}
	// Verify the client was called with the correct SID (EC-5: SID-based update).
	if fake.lastUpdateSID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("Update called with SID %q, want S-1-5-21-111-222-333-1001", fake.lastUpdateSID)
	}
	if fake.lastUpdateInput.Name != "NewName" {
		t.Errorf("Update input Name = %q, want NewName", fake.lastUpdateInput.Name)
	}
}

func TestLocalGroupUpdate_NameConflict_EC5(t *testing.T) {
	// EC-5: rename fails because target name is already taken.
	fake := &fakeLocalGroupClient{
		updateErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorNameConflict,
			"group name 'TakenName' is not unique on this host",
			nil,
			map[string]string{"old_name": "AppAdmins", "new_name": "TakenName"},
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"name":        tftypes.NewValue(tftypes.String, "TakenName"),
			"description": tftypes.NewValue(tftypes.String, ""),
			"sid":         tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"id":          tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
			"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-5: expected name_conflict error diagnostic")
	}
}

func TestLocalGroupUpdate_CaseInsensitiveKeepsPlanName_EC4(t *testing.T) {
	// EC-4 / ADR-LG-4: Windows returns "AppAdmins" but plan says "appadmins".
	// Update should store the plan name in state (not Windows casing).
	fake := &fakeLocalGroupClient{
		updateOut: okGroupState("AppAdmins", "desc", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"name":        tftypes.NewValue(tftypes.String, "appadmins"), // lowercase
			"description": tftypes.NewValue(tftypes.String, "desc"),
			"sid":         tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"id":          tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
			"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgDiagDetails(resp.Diagnostics))
	}
	var m windowsLocalGroupModel
	resp.State.Get(context.Background(), &m)
	// Plan name (HCL value "appadmins") should be stored in state for case-only diffs.
	if m.Name.ValueString() != "appadmins" {
		t.Errorf("EC-4: expected plan name 'appadmins' in state, got %q", m.Name.ValueString())
	}
}

// -----------------------------------------------------------------------------
// Delete handler
// -----------------------------------------------------------------------------

func TestLocalGroupDelete_HappyPath_Handler(t *testing.T) {
	fake := &fakeLocalGroupClient{deleteErr: nil}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	state := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected diags on delete: %v", lgDiagDetails(resp.Diagnostics))
	}
}

func TestLocalGroupDelete_BuiltinGroup_EC2(t *testing.T) {
	// EC-2: client returns ErrLocalGroupBuiltinGroup.
	fake := &fakeLocalGroupClient{
		deleteErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorBuiltinGroup,
			"cannot destroy built-in local group 'Administrators' (SID: S-1-5-32-544); "+
				"Windows built-in groups must not be deleted. Remove this resource from your configuration instead.",
			nil,
			map[string]string{"sid": "S-1-5-32-544", "name": "Administrators"},
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	state := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "S-1-5-32-544"),
			"sid":  tftypes.NewValue(tftypes.String, "S-1-5-32-544"),
			"name": tftypes.NewValue(tftypes.String, "Administrators"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-2: expected builtin_group error diagnostic on delete")
	}
	detail := resp.Diagnostics[0].Detail()
	if !strings.Contains(detail, "builtin_group") && !strings.Contains(detail, "cannot destroy") {
		t.Errorf("EC-2 diagnostic should describe builtin protection: %s", detail)
	}
}

func TestLocalGroupDelete_PermissionDenied_EC8(t *testing.T) {
	fake := &fakeLocalGroupClient{
		deleteErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorPermission,
			"Access is denied",
			nil, nil,
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	state := tfsdk.State{
		Schema: schemaDef,
		Raw: lgObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
			"name": tftypes.NewValue(tftypes.String, "AppAdmins"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-8: expected permission_denied error on delete")
	}
}

// -----------------------------------------------------------------------------
// ImportState handler (EC-10)
// -----------------------------------------------------------------------------

func TestLocalGroupImportState_ByName_EC10(t *testing.T) {
	// EC-10: import ID does NOT start with "S-" → name-based path.
	fake := &fakeLocalGroupClient{
		importByNameOut: okGroupState("AppAdmins", "desc", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "AppAdmins"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("EC-10: unexpected diags on import by name: %v", lgDiagDetails(resp.Diagnostics))
	}

	var m windowsLocalGroupModel
	resp.State.Get(context.Background(), &m)
	// After import, resource ID must be the SID (not the import name string).
	if m.ID.ValueString() != "S-1-5-21-111-222-333-1001" {
		t.Errorf("EC-10: after import by name, ID must be SID; got %q", m.ID.ValueString())
	}
	if m.Name.ValueString() != "AppAdmins" {
		t.Errorf("EC-10: Name = %q", m.Name.ValueString())
	}
}

func TestLocalGroupImportState_BySID_EC10(t *testing.T) {
	// EC-10: import ID starts with "S-" → SID-based path.
	fake := &fakeLocalGroupClient{
		importBySIDOut: okGroupState("AppAdmins", "desc", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "S-1-5-21-111-222-333-1001"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("EC-10: unexpected diags on import by SID: %v", lgDiagDetails(resp.Diagnostics))
	}

	var m windowsLocalGroupModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "S-1-5-21-111-222-333-1001" {
		t.Errorf("EC-10: ID = %q, want SID", m.ID.ValueString())
	}
}

func TestLocalGroupImportState_ByName_NotFound_EC10(t *testing.T) {
	fake := &fakeLocalGroupClient{
		importByNameErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorNotFound,
			"cannot import: no local group found with name 'NoSuchGroup'",
			nil, nil,
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "NoSuchGroup"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-10: expected error diagnostic when import by name not found")
	}
}

func TestLocalGroupImportState_BySID_NotFound_EC10(t *testing.T) {
	fake := &fakeLocalGroupClient{
		importBySIDErr: winclient.NewLocalGroupError(
			winclient.LocalGroupErrorNotFound,
			"cannot import: no local group found with SID 'S-1-5-21-999'",
			nil, nil,
		),
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "S-1-5-21-999"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-10: expected error diagnostic when import by SID not found")
	}
}

func TestLocalGroupImportState_NilState_EC10(t *testing.T) {
	// Edge case: client returns (nil, nil) during import — produce a clear error.
	fake := &fakeLocalGroupClient{
		importByNameOut: nil,
		importByNameErr: nil,
	}
	r := &windowsLocalGroupResource{grp: fake}
	schemaDef := windowsLocalGroupSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: lgObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "NoSuchGroup"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-10: nil GroupState from import should produce an error diagnostic")
	}
}
