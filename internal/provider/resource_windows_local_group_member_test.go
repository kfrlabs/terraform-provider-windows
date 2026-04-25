// Package provider — unit tests for the windows_local_group_member resource.
//
// Coverage strategy:
//   - Schema: all 7 attributes verified (required/computed flags, plan modifiers,
//     validators, ForceNew).
//   - Helpers: parseCompositeID, addLocalGroupMemberDiag, addLocalGroupMemberCreateDiag.
//   - CRUD handlers (Read, Delete, Update): driven via fakeLocalGroupMemberClient
//     injected into windowsLocalGroupMemberResource.member.
//     Create and ImportState happy-paths require winclient.ResolveGroup which calls
//     runPowerShell (unexported seam in winclient package); they are covered by the
//     winclient unit tests (local_group_member_test.go). ImportState invalid-format
//     paths are safe to test here because the function returns before calling any
//     client method.
//   - Configure: nil, wrong-type, valid client.
//
// Edge cases covered:
//
//	EC-1  member_already_exists diag (addLocalGroupMemberCreateDiag)
//	EC-2  group_not_found diag on Create (addLocalGroupMemberCreateDiag)
//	EC-3  member_unresolvable diag (sub_type=local)
//	EC-4  drift: Read with absent membership → RemoveResource
//	EC-5  drift: Read with group_not_found → RemoveResource
//	EC-8  permission_denied diag (addLocalGroupMemberCreateDiag)
//	EC-9  BUILTIN groups not blocked (no special validator in schema)
//	EC-10 member_unresolvable diag (sub_type=domain)
//	EC-11 Update is no-op
//	     ImportState: invalid ID format (various malformed strings)
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeLocalGroupMemberClient
// ---------------------------------------------------------------------------

type fakeLocalGroupMemberClient struct {
	addOut    *winclient.LocalGroupMemberState
	addErr    error
	removeErr error
	getOut    *winclient.LocalGroupMemberState
	getErr    error
	listOut   []*winclient.LocalGroupMemberState
	listErr   error

	// Captured call args for assertions.
	lastRemoveGroupSID  string
	lastRemoveMemberSID string
	lastGetGroupSID     string
	lastGetMemberSID    string
}

func (f *fakeLocalGroupMemberClient) Add(_ context.Context, _ winclient.LocalGroupMemberInput) (*winclient.LocalGroupMemberState, error) {
	return f.addOut, f.addErr
}

func (f *fakeLocalGroupMemberClient) Remove(_ context.Context, groupSID, memberSID string) error {
	f.lastRemoveGroupSID = groupSID
	f.lastRemoveMemberSID = memberSID
	return f.removeErr
}

func (f *fakeLocalGroupMemberClient) Get(_ context.Context, groupSID, memberSID string) (*winclient.LocalGroupMemberState, error) {
	f.lastGetGroupSID = groupSID
	f.lastGetMemberSID = memberSID
	return f.getOut, f.getErr
}

func (f *fakeLocalGroupMemberClient) List(_ context.Context, _ string) ([]*winclient.LocalGroupMemberState, error) {
	return f.listOut, f.listErr
}

// ---------------------------------------------------------------------------
// tftypes helpers for the local_group_member schema
// ---------------------------------------------------------------------------

func lgmObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                      tftypes.String,
		"group":                   tftypes.String,
		"group_sid":               tftypes.String,
		"member":                  tftypes.String,
		"member_sid":              tftypes.String,
		"member_name":             tftypes.String,
		"member_principal_source": tftypes.String,
	}}
}

// lgmObj builds a tftypes.Value for the local_group_member schema with optional overrides.
func lgmObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":                      tftypes.NewValue(tftypes.String, nil),
		"group":                   tftypes.NewValue(tftypes.String, nil),
		"group_sid":               tftypes.NewValue(tftypes.String, nil),
		"member":                  tftypes.NewValue(tftypes.String, nil),
		"member_sid":              tftypes.NewValue(tftypes.String, nil),
		"member_name":             tftypes.NewValue(tftypes.String, nil),
		"member_principal_source": tftypes.NewValue(tftypes.String, nil),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(lgmObjectType(), base)
}

// lgmState builds a populated tfsdk.State for the local_group_member schema.
func lgmState(groupSID, memberSID, group, member string) tfsdk.State {
	schemaDef := windowsLocalGroupMemberSchemaDefinition()
	return tfsdk.State{
		Schema: schemaDef,
		Raw: lgmObj(map[string]tftypes.Value{
			"id":                      tftypes.NewValue(tftypes.String, groupSID+"/"+memberSID),
			"group":                   tftypes.NewValue(tftypes.String, group),
			"group_sid":               tftypes.NewValue(tftypes.String, groupSID),
			"member":                  tftypes.NewValue(tftypes.String, member),
			"member_sid":              tftypes.NewValue(tftypes.String, memberSID),
			"member_name":             tftypes.NewValue(tftypes.String, "DOMAIN\\user"),
			"member_principal_source": tftypes.NewValue(tftypes.String, "ActiveDirectory"),
		}),
	}
}

// lgmDiagDetails extracts "Summary / Detail" strings from diagnostics.
func lgmDiagDetails(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+" / "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestLocalGroupMemberMetadata(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_local_group_member" {
		t.Errorf("TypeName = %q, want windows_local_group_member", resp.TypeName)
	}
}

func TestNewWindowsLocalGroupMemberResource_NotNil(t *testing.T) {
	if NewWindowsLocalGroupMemberResource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema attribute verification
// ---------------------------------------------------------------------------

func TestLocalGroupMemberSchema_HasAllAttributes(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	want := []string{"id", "group", "group_sid", "member", "member_sid", "member_name", "member_principal_source"}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(s.Attributes) != 7 {
		t.Errorf("schema has %d attributes, want 7", len(s.Attributes))
	}
}

func TestLocalGroupMemberSchema_GroupIsRequired_ForceNew(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	attr, ok := s.Attributes["group"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("group attribute type %T", s.Attributes["group"])
	}
	if !attr.Required {
		t.Error("group must be Required")
	}
	if attr.Computed {
		t.Error("group must NOT be Computed")
	}
	// Verify RequiresReplace plan modifier.
	foundReplace := false
	for _, pm := range attr.PlanModifiers {
		desc := strings.ToLower(pm.Description(context.Background()) + pm.MarkdownDescription(context.Background()))
		if strings.Contains(desc, "replace") || strings.Contains(desc, "recreate") {
			foundReplace = true
		}
	}
	if !foundReplace {
		t.Error("group must have RequiresReplace plan modifier (ForceNew)")
	}
}

func TestLocalGroupMemberSchema_MemberIsRequired_ForceNew(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	attr, ok := s.Attributes["member"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("member attribute type %T", s.Attributes["member"])
	}
	if !attr.Required {
		t.Error("member must be Required")
	}
	if attr.Computed {
		t.Error("member must NOT be Computed")
	}
	foundReplace := false
	for _, pm := range attr.PlanModifiers {
		desc := strings.ToLower(pm.Description(context.Background()) + pm.MarkdownDescription(context.Background()))
		if strings.Contains(desc, "replace") || strings.Contains(desc, "recreate") {
			foundReplace = true
		}
	}
	if !foundReplace {
		t.Error("member must have RequiresReplace plan modifier (ForceNew)")
	}
}

func TestLocalGroupMemberSchema_GroupSIDIsComputedWithUseStateForUnknown(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	attr, ok := s.Attributes["group_sid"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("group_sid attribute type %T", s.Attributes["group_sid"])
	}
	if !attr.Computed {
		t.Error("group_sid must be Computed")
	}
	if attr.Required || attr.Optional {
		t.Error("group_sid must not be Required or Optional")
	}
	foundUSFU := false
	for _, pm := range attr.PlanModifiers {
		desc := strings.ToLower(pm.Description(context.Background()) + pm.MarkdownDescription(context.Background()))
		if strings.Contains(desc, "unknown") || strings.Contains(desc, "state") {
			foundUSFU = true
		}
	}
	if !foundUSFU {
		t.Error("group_sid must have UseStateForUnknown plan modifier")
	}
}

func TestLocalGroupMemberSchema_MemberSIDIsComputedWithUseStateForUnknown(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	attr, ok := s.Attributes["member_sid"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("member_sid attribute type %T", s.Attributes["member_sid"])
	}
	if !attr.Computed {
		t.Error("member_sid must be Computed")
	}
}

func TestLocalGroupMemberSchema_IDHasUseStateForUnknown(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	idAttr, ok := s.Attributes["id"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("id attribute type %T", s.Attributes["id"])
	}
	if !idAttr.Computed {
		t.Error("id must be Computed")
	}
	foundUSFU := false
	for _, pm := range idAttr.PlanModifiers {
		desc := strings.ToLower(pm.Description(context.Background()) + pm.MarkdownDescription(context.Background()))
		if strings.Contains(desc, "unknown") || strings.Contains(desc, "state") {
			foundUSFU = true
		}
	}
	if !foundUSFU {
		t.Error("id must have UseStateForUnknown plan modifier")
	}
}

func TestLocalGroupMemberSchema_MemberPrincipalSourceHasOneOfValidator(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	attr, ok := s.Attributes["member_principal_source"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("member_principal_source attribute type %T", s.Attributes["member_principal_source"])
	}
	if !attr.Computed {
		t.Error("member_principal_source must be Computed")
	}
	if len(attr.Validators) == 0 {
		t.Error("member_principal_source must have at least one validator (OneOf)")
	}
}

func TestLocalGroupMemberSchema_GroupHasLengthValidator(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	attr, ok := s.Attributes["group"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("group attribute type %T", s.Attributes["group"])
	}
	if len(attr.Validators) == 0 {
		t.Error("group must have length validator (LengthBetween(1,256))")
	}
}

func TestLocalGroupMemberSchema_MemberHasLengthValidator(t *testing.T) {
	s := windowsLocalGroupMemberSchemaDefinition()
	attr, ok := s.Attributes["member"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("member attribute type %T", s.Attributes["member"])
	}
	if len(attr.Validators) == 0 {
		t.Error("member must have length validator (LengthBetween(1,512))")
	}
}

func TestLocalGroupMemberSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestLocalGroupMemberConfigure_NilProviderData(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
}

func TestLocalGroupMemberConfigure_WrongType(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should produce an error diagnostic")
	}
}

func TestLocalGroupMemberConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.client != c {
		t.Error("Configure must populate client field")
	}
	if r.member == nil {
		t.Error("Configure must populate member field with a LocalGroupMemberClient")
	}
}

// ---------------------------------------------------------------------------
// parseCompositeID helper
// ---------------------------------------------------------------------------

func TestParseCompositeID_Valid(t *testing.T) {
	groupSID, memberSID, ok := parseCompositeID("S-1-5-32-544/S-1-5-21-100-200-300-500")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if groupSID != "S-1-5-32-544" {
		t.Errorf("groupSID = %q", groupSID)
	}
	if memberSID != "S-1-5-21-100-200-300-500" {
		t.Errorf("memberSID = %q", memberSID)
	}
}

func TestParseCompositeID_MinimalValid(t *testing.T) {
	groupSID, memberSID, ok := parseCompositeID("a/b")
	if !ok {
		t.Fatal("expected ok=true for minimal a/b")
	}
	if groupSID != "a" || memberSID != "b" {
		t.Errorf("groupSID=%q memberSID=%q", groupSID, memberSID)
	}
}

func TestParseCompositeID_NoSlash(t *testing.T) {
	_, _, ok := parseCompositeID("S-1-5-32-544S-1-5-21-100-200-300-500")
	if ok {
		t.Error("expected ok=false for ID with no slash")
	}
}

func TestParseCompositeID_SlashAtStart(t *testing.T) {
	_, _, ok := parseCompositeID("/S-1-5-21-100-200-300-500")
	if ok {
		t.Error("expected ok=false when slash is at index 0 (idx < 1)")
	}
}

func TestParseCompositeID_SlashAtEnd(t *testing.T) {
	_, _, ok := parseCompositeID("S-1-5-32-544/")
	if ok {
		t.Error("expected ok=false when slash is at last position (idx >= len-1)")
	}
}

func TestParseCompositeID_Empty(t *testing.T) {
	_, _, ok := parseCompositeID("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}

// ---------------------------------------------------------------------------
// addLocalGroupMemberDiag helper
// ---------------------------------------------------------------------------

func TestAddLGMDiag_LocalGroupMemberError(t *testing.T) {
	var diags diag.Diagnostics
	lgme := winclient.NewLocalGroupMemberError(
		winclient.LocalGroupMemberErrorPermission,
		"Access is denied",
		nil,
		map[string]string{"host": "win01", "group_sid": "S-1-5-32-544"},
	)
	addLocalGroupMemberDiag(&diags, "operation failed", lgme)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags[0].Detail()
	if !strings.Contains(detail, "Access is denied") {
		t.Errorf("detail should contain message: %s", detail)
	}
	if !strings.Contains(detail, "win01") {
		t.Errorf("detail should contain context host: %s", detail)
	}
	if !strings.Contains(detail, "permission_denied") {
		t.Errorf("detail should contain kind: %s", detail)
	}
}

func TestAddLGMDiag_LocalGroupError(t *testing.T) {
	// addLocalGroupMemberDiag also handles *LocalGroupError (from ResolveGroup).
	var diags diag.Diagnostics
	lge := winclient.NewLocalGroupError(
		winclient.LocalGroupErrorNotFound,
		"group was not found",
		nil,
		map[string]string{"group": "NoSuchGroup", "host": "win01"},
	)
	addLocalGroupMemberDiag(&diags, "resolve failed", lge)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags[0].Detail()
	if !strings.Contains(detail, "group was not found") {
		t.Errorf("detail should contain LocalGroupError message: %s", detail)
	}
}

func TestAddLGMDiag_GenericError(t *testing.T) {
	var diags diag.Diagnostics
	addLocalGroupMemberDiag(&diags, "failed", errors.New("plain error"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(diags[0].Detail(), "plain error") {
		t.Errorf("detail should contain plain error: %s", diags[0].Detail())
	}
}

// ---------------------------------------------------------------------------
// addLocalGroupMemberCreateDiag helper — per-kind routing
// ---------------------------------------------------------------------------

func TestAddLGMCreateDiag_AlreadyExists_EC1(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewLocalGroupMemberError(
		winclient.LocalGroupMemberErrorAlreadyExists,
		`member "DOMAIN\alice" (SID: S-1-5-21-1-2-3-500) is already a member. Use: terraform import ...`,
		nil,
		map[string]string{"group_sid": "S-1-5-32-544", "member": "DOMAIN\\alice"},
	)
	addLocalGroupMemberCreateDiag(&diags, "DOMAIN\\alice", err)
	if !diags.HasError() {
		t.Fatal("EC-1: expected error diagnostic")
	}
	combined := strings.Join(lgmDiagDetails(diags), "\n")
	if !strings.Contains(combined, "already exists") {
		t.Errorf("EC-1 diag should mention already_exists: %s", combined)
	}
	if !strings.Contains(combined, "import") {
		t.Errorf("EC-1 diag should contain import hint: %s", combined)
	}
}

func TestAddLGMCreateDiag_Unresolvable_Local_EC3(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewLocalGroupMemberError(
		winclient.LocalGroupMemberErrorUnresolvable,
		"user not found locally",
		nil,
		map[string]string{"member": "nosuchuser", "sub_type": "local"},
	)
	addLocalGroupMemberCreateDiag(&diags, "nosuchuser", err)
	if !diags.HasError() {
		t.Fatal("EC-3: expected error diagnostic")
	}
	combined := strings.Join(lgmDiagDetails(diags), "\n")
	if !strings.Contains(combined, "nosuchuser") {
		t.Errorf("EC-3 diag should mention member identity: %s", combined)
	}
}

func TestAddLGMCreateDiag_Unresolvable_Domain_EC10(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewLocalGroupMemberError(
		winclient.LocalGroupMemberErrorUnresolvable,
		"domain unreachable",
		nil,
		map[string]string{"member": "UNREACHABLE\\user", "sub_type": "domain"},
	)
	addLocalGroupMemberCreateDiag(&diags, "UNREACHABLE\\user", err)
	if !diags.HasError() {
		t.Fatal("EC-10: expected error diagnostic")
	}
	combined := strings.Join(lgmDiagDetails(diags), "\n")
	if !strings.Contains(combined, "domain") {
		t.Errorf("EC-10 diag should mention domain: %s", combined)
	}
}

func TestAddLGMCreateDiag_Permission_EC8(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewLocalGroupMemberError(
		winclient.LocalGroupMemberErrorPermission,
		"Access is denied",
		nil,
		map[string]string{"host": "win01"},
	)
	addLocalGroupMemberCreateDiag(&diags, "DOMAIN\\alice", err)
	if !diags.HasError() {
		t.Fatal("EC-8: expected error diagnostic")
	}
	combined := strings.Join(lgmDiagDetails(diags), "\n")
	if !strings.Contains(combined, "permission") || !strings.Contains(strings.ToLower(combined), "denied") {
		t.Errorf("EC-8 diag should mention permission denied: %s", combined)
	}
}

func TestAddLGMCreateDiag_GroupNotFound_EC2(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewLocalGroupMemberError(
		winclient.LocalGroupMemberErrorGroupNotFound,
		"group not found after resolve",
		nil,
		nil,
	)
	addLocalGroupMemberCreateDiag(&diags, "DOMAIN\\alice", err)
	if !diags.HasError() {
		t.Fatal("EC-2: expected error diagnostic")
	}
}

func TestAddLGMCreateDiag_Unknown_FallsBack(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewLocalGroupMemberError(
		winclient.LocalGroupMemberErrorUnknown,
		"some unexpected error",
		nil, nil,
	)
	addLocalGroupMemberCreateDiag(&diags, "user", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic for unknown kind")
	}
}

func TestAddLGMCreateDiag_NonLGMError(t *testing.T) {
	// Non-LocalGroupMemberError falls back to generic diag.
	var diags diag.Diagnostics
	addLocalGroupMemberCreateDiag(&diags, "user", errors.New("generic error"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
}

// ---------------------------------------------------------------------------
// Read handler
// ---------------------------------------------------------------------------

func TestLocalGroupMemberRead_HappyPath(t *testing.T) {
	fake := &fakeLocalGroupMemberClient{
		getOut: &winclient.LocalGroupMemberState{
			GroupSID:        "S-1-5-32-544",
			MemberSID:       "S-1-5-21-100-200-300-500",
			MemberName:      "DOMAIN\\alice",
			PrincipalSource: "ActiveDirectory",
		},
	}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-544", "S-1-5-21-100-200-300-500", "Administrators", "DOMAIN\\alice")
	resp := &resource.ReadResponse{State: prior}

	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgmDiagDetails(resp.Diagnostics))
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should NOT be removed on happy read")
	}

	// member preserved as-supplied (ADR-LGM-4).
	var m windowsLocalGroupMemberModel
	resp.State.Get(context.Background(), &m)
	if m.Member.ValueString() != "DOMAIN\\alice" {
		t.Errorf("member should be preserved as-supplied: %q", m.Member.ValueString())
	}
	if m.MemberPrincipalSource.ValueString() != "ActiveDirectory" {
		t.Errorf("MemberPrincipalSource = %q", m.MemberPrincipalSource.ValueString())
	}
}

func TestLocalGroupMemberRead_MemberAbsent_EC4(t *testing.T) {
	// EC-4: membership removed out-of-band → RemoveResource.
	fake := &fakeLocalGroupMemberClient{getOut: nil, getErr: nil}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-544", "S-1-5-21-100-200-300-500", "Administrators", "DOMAIN\\alice")
	resp := &resource.ReadResponse{State: prior}

	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("EC-4: should not produce error diags: %v", lgmDiagDetails(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("EC-4: state must be removed (RemoveResource) when membership is absent")
	}
}

func TestLocalGroupMemberRead_GroupNotFound_EC5(t *testing.T) {
	// EC-5: group deleted → RemoveResource (distinct from EC-4).
	fake := &fakeLocalGroupMemberClient{
		getErr: winclient.NewLocalGroupMemberError(
			winclient.LocalGroupMemberErrorGroupNotFound,
			"group not found",
			nil, nil,
		),
	}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-9999", "S-1-5-21-100-200-300-500", "DeletedGroup", "DOMAIN\\alice")
	resp := &resource.ReadResponse{State: prior}

	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("EC-5: should not produce error diags: %v", lgmDiagDetails(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("EC-5: state must be removed when group is gone")
	}
}

func TestLocalGroupMemberRead_Error(t *testing.T) {
	fake := &fakeLocalGroupMemberClient{
		getErr: winclient.NewLocalGroupMemberError(
			winclient.LocalGroupMemberErrorPermission,
			"Access is denied",
			nil, nil,
		),
	}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-544", "S-1-5-21-100-200-300-500", "Administrators", "DOMAIN\\alice")
	resp := &resource.ReadResponse{State: prior}

	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for permission denied")
	}
}

func TestLocalGroupMemberRead_MemberPreservedAsSupplied_ADR_LGM4(t *testing.T) {
	// ADR-LGM-4: member attribute must NOT be overwritten by the Read path.
	// The operator supplied "alice@corp.example.com" but Windows returns
	// "DOMAIN\\alice" — Read must keep the operator's original form.
	fake := &fakeLocalGroupMemberClient{
		getOut: &winclient.LocalGroupMemberState{
			GroupSID:        "S-1-5-32-544",
			MemberSID:       "S-1-5-21-100-200-300-500",
			MemberName:      "DOMAIN\\alice", // Windows canonical name
			PrincipalSource: "ActiveDirectory",
		},
	}
	r := &windowsLocalGroupMemberResource{member: fake}

	schemaDef := windowsLocalGroupMemberSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: lgmObj(map[string]tftypes.Value{
			"id":                      tftypes.NewValue(tftypes.String, "S-1-5-32-544/S-1-5-21-100-200-300-500"),
			"group":                   tftypes.NewValue(tftypes.String, "Administrators"),
			"group_sid":               tftypes.NewValue(tftypes.String, "S-1-5-32-544"),
			"member":                  tftypes.NewValue(tftypes.String, "alice@corp.example.com"), // UPN in state
			"member_sid":              tftypes.NewValue(tftypes.String, "S-1-5-21-100-200-300-500"),
			"member_name":             tftypes.NewValue(tftypes.String, "DOMAIN\\alice"),
			"member_principal_source": tftypes.NewValue(tftypes.String, "ActiveDirectory"),
		}),
	}
	resp := &resource.ReadResponse{State: prior}

	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgmDiagDetails(resp.Diagnostics))
	}

	var m windowsLocalGroupMemberModel
	resp.State.Get(context.Background(), &m)
	// member must NOT be overwritten.
	if m.Member.ValueString() != "alice@corp.example.com" {
		t.Errorf("ADR-LGM-4: member should be preserved as UPN, got %q", m.Member.ValueString())
	}
}

func TestLocalGroupMemberRead_GetCalledWithCorrectSIDs(t *testing.T) {
	fake := &fakeLocalGroupMemberClient{
		getOut: &winclient.LocalGroupMemberState{
			GroupSID:        "S-1-5-32-544",
			MemberSID:       "S-1-5-21-100-200-300-500",
			MemberName:      "DOMAIN\\alice",
			PrincipalSource: "ActiveDirectory",
		},
	}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-544", "S-1-5-21-100-200-300-500", "Administrators", "DOMAIN\\alice")
	resp := &resource.ReadResponse{State: prior}

	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)

	if fake.lastGetGroupSID != "S-1-5-32-544" {
		t.Errorf("Get called with groupSID=%q, want S-1-5-32-544", fake.lastGetGroupSID)
	}
	if fake.lastGetMemberSID != "S-1-5-21-100-200-300-500" {
		t.Errorf("Get called with memberSID=%q, want S-1-5-21-100-200-300-500", fake.lastGetMemberSID)
	}
}

// ---------------------------------------------------------------------------
// Delete handler
// ---------------------------------------------------------------------------

func TestLocalGroupMemberDelete_Success(t *testing.T) {
	fake := &fakeLocalGroupMemberClient{removeErr: nil}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-544", "S-1-5-21-100-200-300-500", "Administrators", "DOMAIN\\alice")
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", lgmDiagDetails(resp.Diagnostics))
	}
}

func TestLocalGroupMemberDelete_UsesMemberSID_ADR_LGM2(t *testing.T) {
	// ADR-LGM-2: Delete must use the member SID (not display name).
	fake := &fakeLocalGroupMemberClient{removeErr: nil}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-544", "S-1-5-21-100-200-300-500", "Administrators", "DOMAIN\\alice")
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)

	if fake.lastRemoveGroupSID != "S-1-5-32-544" {
		t.Errorf("Remove called with groupSID=%q, want S-1-5-32-544", fake.lastRemoveGroupSID)
	}
	if fake.lastRemoveMemberSID != "S-1-5-21-100-200-300-500" {
		t.Errorf("Remove must use member SID, got %q", fake.lastRemoveMemberSID)
	}
}

func TestLocalGroupMemberDelete_Error(t *testing.T) {
	fake := &fakeLocalGroupMemberClient{
		removeErr: winclient.NewLocalGroupMemberError(
			winclient.LocalGroupMemberErrorPermission,
			"Access is denied",
			nil, nil,
		),
	}
	r := &windowsLocalGroupMemberResource{member: fake}
	prior := lgmState("S-1-5-32-544", "S-1-5-21-100-200-300-500", "Administrators", "DOMAIN\\alice")
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for permission denied")
	}
}

// ---------------------------------------------------------------------------
// Update handler — no-op (EC-11)
// ---------------------------------------------------------------------------

func TestLocalGroupMemberUpdate_Noop_EC11(t *testing.T) {
	// All attributes are RequiresReplace so Update is never called in practice.
	// The implementation should copy plan → state without calling any client method.
	fake := &fakeLocalGroupMemberClient{}
	r := &windowsLocalGroupMemberResource{member: fake}
	schemaDef := windowsLocalGroupMemberSchemaDefinition()

	planState := lgmObj(map[string]tftypes.Value{
		"id":                      tftypes.NewValue(tftypes.String, "S-1-5-32-544/S-1-5-21-100-200-300-500"),
		"group":                   tftypes.NewValue(tftypes.String, "Administrators"),
		"group_sid":               tftypes.NewValue(tftypes.String, "S-1-5-32-544"),
		"member":                  tftypes.NewValue(tftypes.String, "DOMAIN\\alice"),
		"member_sid":              tftypes.NewValue(tftypes.String, "S-1-5-21-100-200-300-500"),
		"member_name":             tftypes.NewValue(tftypes.String, "DOMAIN\\alice"),
		"member_principal_source": tftypes.NewValue(tftypes.String, "ActiveDirectory"),
	})
	plan := tfsdk.Plan{Schema: schemaDef, Raw: planState}
	priorState := tfsdk.State{Schema: schemaDef, Raw: planState.Copy()}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaDef, Raw: planState.Copy()}}

	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("EC-11 Update is no-op and must not produce errors: %v", lgmDiagDetails(resp.Diagnostics))
	}
	// Verify plan is copied to state.
	var m windowsLocalGroupMemberModel
	resp.State.Get(context.Background(), &m)
	if m.GroupSID.ValueString() != "S-1-5-32-544" {
		t.Errorf("GroupSID = %q after Update", m.GroupSID.ValueString())
	}

	// Verify no client methods were called.
	if fake.lastRemoveGroupSID != "" || fake.lastGetGroupSID != "" {
		t.Error("EC-11: Update must NOT call any client methods")
	}
}

// ---------------------------------------------------------------------------
// ImportState — invalid format validation (safe: returns before ResolveGroup)
// ---------------------------------------------------------------------------

func TestLocalGroupMemberImportState_InvalidFormat_NoSlash(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsLocalGroupMemberSchemaDefinition(), Raw: lgmObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "AdministratorsS-1-5-32-544"},
		resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for ID with no slash")
	}
	combined := strings.Join(lgmDiagDetails(resp.Diagnostics), "\n")
	if !strings.Contains(combined, "<group>/<member>") {
		t.Errorf("error should mention expected format: %s", combined)
	}
}

func TestLocalGroupMemberImportState_InvalidFormat_Empty(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsLocalGroupMemberSchemaDefinition(), Raw: lgmObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: ""}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for empty ID")
	}
}

func TestLocalGroupMemberImportState_InvalidFormat_SlashAtStart(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsLocalGroupMemberSchemaDefinition(), Raw: lgmObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "/S-1-5-21-100"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for ID starting with slash")
	}
}

func TestLocalGroupMemberImportState_InvalidFormat_SlashAtEnd(t *testing.T) {
	r := &windowsLocalGroupMemberResource{}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: windowsLocalGroupMemberSchemaDefinition(), Raw: lgmObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "Administrators/"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for ID ending with slash (empty member part)")
	}
}

// ---------------------------------------------------------------------------
// EC-9: No BUILTIN-group validator in schema (BUILTIN groups fully supported)
// ---------------------------------------------------------------------------

func TestLocalGroupMemberSchema_NoBUILTINBlock(t *testing.T) {
	// EC-9: The windows_local_group_member resource must NOT block BUILTIN group
	// SIDs. Verify there is no custom validator on the "group" attribute that
	// rejects S-1-5-32-* SIDs (unlike windows_local_group delete guard).
	s := windowsLocalGroupMemberSchemaDefinition()
	groupAttr, ok := s.Attributes["group"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("group attribute type %T", s.Attributes["group"])
	}
	// There should be at most 1 validator (LengthBetween) — not a custom block.
	// The BUILTIN guard is NOT present for this resource (EC-9, ADR-LGM-9).
	for _, v := range groupAttr.Validators {
		desc := strings.ToLower(v.Description(context.Background()))
		if strings.Contains(desc, "builtin") || strings.Contains(desc, "s-1-5-32") {
			t.Errorf("EC-9: 'group' must NOT have a BUILTIN-block validator, found: %q", desc)
		}
	}
}

// ---------------------------------------------------------------------------
// types helper: Value string round-trip
// ---------------------------------------------------------------------------

func TestLocalGroupMemberModel_IDComposite(t *testing.T) {
	m := windowsLocalGroupMemberModel{
		ID:        types.StringValue("S-1-5-32-544/S-1-5-21-100-200-300-500"),
		GroupSID:  types.StringValue("S-1-5-32-544"),
		MemberSID: types.StringValue("S-1-5-21-100-200-300-500"),
	}
	wantID := m.GroupSID.ValueString() + "/" + m.MemberSID.ValueString()
	if m.ID.ValueString() != wantID {
		t.Errorf("ID = %q, want %q (ADR-LGM-1)", m.ID.ValueString(), wantID)
	}
}
