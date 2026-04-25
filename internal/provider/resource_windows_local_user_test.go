// Package provider — unit tests for windows_local_user resource.
//
// These tests exercise validators, helpers, and CRUD handlers without WinRM.
// A fakeLocalUserClient is injected into windowsLocalUserResource.user.
//
// Edge cases covered (aligned with spec EC-* identifiers):
//
//	EC-1  Create: name collision                    -> AlreadyExists diag
//	EC-2  Delete: builtin_account                   -> hard error diag
//	EC-3  Read: user disappears                     -> RemoveResource
//	EC-4  Read: case-fold name normalisation         -> prior name preserved
//	EC-5  Update: rename in place                   -> Rename called, SID stable
//	EC-6  Update: password rotation via wo_version  -> SetPassword called
//	EC-10 Validator: localUserNameValidator rules    -> whitespace / leading-space
//	EC-11 ImportState: SID vs name detection        -> ImportBySID / ImportByName
//	EC-13 Create: account_expires in the past        -> diagnostic error
//	EC-14 Validator: accountExpiresConflictValidator -> mutual exclusion
//	rfc3339Validator: invalid/valid timestamps
//	planToUserInput: field mapping
//	scalarAttrsChanged: changed / unchanged
//	addLocalUserDiag: both error paths
//	Schema: password sensitive, name required, sid computed
package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/ecritel/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeLocalUserClient
// ---------------------------------------------------------------------------

type fakeLocalUserClient struct {
	createOut       *winclient.UserState
	createErr       error
	readOut         *winclient.UserState
	readErr         error
	updateOut       *winclient.UserState
	updateErr       error
	renameErr       error
	setPasswordErr  error
	enableErr       error
	disableErr      error
	deleteErr       error
	importByNameOut *winclient.UserState
	importByNameErr error
	importBySIDOut  *winclient.UserState
	importBySIDErr  error

	// Call capture
	lastRenameNewName  string
	lastSetPasswordSID string
	enableCalled       bool
	disableCalled      bool
}

func (f *fakeLocalUserClient) Create(_ context.Context, _ winclient.UserInput, _ string) (*winclient.UserState, error) {
	return f.createOut, f.createErr
}
func (f *fakeLocalUserClient) Read(_ context.Context, _ string) (*winclient.UserState, error) {
	return f.readOut, f.readErr
}
func (f *fakeLocalUserClient) Update(_ context.Context, _ string, _ winclient.UserInput) (*winclient.UserState, error) {
	return f.updateOut, f.updateErr
}
func (f *fakeLocalUserClient) Rename(_ context.Context, _ string, newName string) error {
	f.lastRenameNewName = newName
	return f.renameErr
}
func (f *fakeLocalUserClient) SetPassword(_ context.Context, sid string, _ string) error {
	f.lastSetPasswordSID = sid
	return f.setPasswordErr
}
func (f *fakeLocalUserClient) Enable(_ context.Context, _ string) error {
	f.enableCalled = true
	return f.enableErr
}
func (f *fakeLocalUserClient) Disable(_ context.Context, _ string) error {
	f.disableCalled = true
	return f.disableErr
}
func (f *fakeLocalUserClient) Delete(_ context.Context, _ string) error {
	return f.deleteErr
}
func (f *fakeLocalUserClient) ImportByName(_ context.Context, _ string) (*winclient.UserState, error) {
	return f.importByNameOut, f.importByNameErr
}
func (f *fakeLocalUserClient) ImportBySID(_ context.Context, _ string) (*winclient.UserState, error) {
	return f.importBySIDOut, f.importBySIDErr
}

// ---------------------------------------------------------------------------
// tftypes helpers for local_user schema
// ---------------------------------------------------------------------------

func localUserObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                         tftypes.String,
		"sid":                        tftypes.String,
		"name":                       tftypes.String,
		"full_name":                  tftypes.String,
		"description":                tftypes.String,
		"password":                   tftypes.String,
		"password_wo_version":        tftypes.Number,
		"enabled":                    tftypes.Bool,
		"password_never_expires":     tftypes.Bool,
		"user_may_not_change_password": tftypes.Bool,
		"account_never_expires":      tftypes.Bool,
		"account_expires":            tftypes.String,
		"last_logon":                 tftypes.String,
		"password_last_set":          tftypes.String,
		"principal_source":           tftypes.String,
	}}
}

// luObj builds a complete tftypes.Value with sensible defaults and optional overrides.
func luObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":                          tftypes.NewValue(tftypes.String, nil),
		"sid":                         tftypes.NewValue(tftypes.String, nil),
		"name":                        tftypes.NewValue(tftypes.String, "alice"),
		"full_name":                   tftypes.NewValue(tftypes.String, ""),
		"description":                 tftypes.NewValue(tftypes.String, ""),
		"password":                    tftypes.NewValue(tftypes.String, "P@ssw0rd!"),
		"password_wo_version":         tftypes.NewValue(tftypes.Number, nil),
		"enabled":                     tftypes.NewValue(tftypes.Bool, true),
		"password_never_expires":      tftypes.NewValue(tftypes.Bool, false),
		"user_may_not_change_password": tftypes.NewValue(tftypes.Bool, false),
		"account_never_expires":       tftypes.NewValue(tftypes.Bool, true),
		"account_expires":             tftypes.NewValue(tftypes.String, nil),
		"last_logon":                  tftypes.NewValue(tftypes.String, nil),
		"password_last_set":           tftypes.NewValue(tftypes.String, nil),
		"principal_source":            tftypes.NewValue(tftypes.String, nil),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(localUserObjectType(), base)
}

func okUserState(name, sid string) *winclient.UserState {
	return &winclient.UserState{
		Name:                     name,
		SID:                      sid,
		FullName:                 "",
		Description:              "",
		Enabled:                  true,
		PasswordNeverExpires:     false,
		UserMayNotChangePassword: false,
		AccountNeverExpires:      true,
		AccountExpires:           "",
		LastLogon:                "",
		PasswordLastSet:          "",
		PrincipalSource:          "Local",
	}
}

func luDiagDetails(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+" / "+x.Detail())
	}
	return out
}

func luValidatorStringReq(val string) validator.StringRequest {
	return validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringValue(val),
	}
}

func luNullValidatorStringReq() validator.StringRequest {
	return validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringNull(),
	}
}

// ---------------------------------------------------------------------------
// Metadata + Schema
// ---------------------------------------------------------------------------

func TestLocalUserMetadata(t *testing.T) {
	r := &windowsLocalUserResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_local_user" {
		t.Errorf("TypeName = %q, want windows_local_user", resp.TypeName)
	}
}

func TestLocalUserSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsLocalUserSchemaDefinition()
	want := []string{
		"id", "sid", "name", "full_name", "description", "password",
		"password_wo_version", "enabled", "password_never_expires",
		"user_may_not_change_password", "account_never_expires",
		"account_expires", "last_logon", "password_last_set", "principal_source",
	}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestLocalUserSchema_PasswordIsSensitive(t *testing.T) {
	s := windowsLocalUserSchemaDefinition()
	pwAttr, ok := s.Attributes["password"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("password attr is not StringAttribute")
	}
	if !pwAttr.Sensitive {
		t.Error("password attribute must be Sensitive (ADR-LU-3)")
	}
}

func TestLocalUserSchema_NameIsRequired(t *testing.T) {
	s := windowsLocalUserSchemaDefinition()
	nameAttr, ok := s.Attributes["name"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("name attr is not StringAttribute")
	}
	if !nameAttr.Required {
		t.Error("name must be Required")
	}
	// name must NOT have RequiresReplace (renames are in-place, EC-5)
	for _, pm := range nameAttr.PlanModifiers {
		desc := strings.ToLower(pm.Description(context.Background()) + pm.MarkdownDescription(context.Background()))
		if strings.Contains(desc, "replace") || strings.Contains(desc, "recreate") {
			t.Error("name must NOT have RequiresReplace modifier (EC-5)")
		}
	}
}

func TestLocalUserSchema_SIDIsComputed(t *testing.T) {
	s := windowsLocalUserSchemaDefinition()
	sidAttr, ok := s.Attributes["sid"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("sid attr is not StringAttribute")
	}
	if !sidAttr.Computed {
		t.Error("sid must be Computed")
	}
	if sidAttr.Required || sidAttr.Optional {
		t.Error("sid must not be Required or Optional")
	}
}

func TestLocalUserSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsLocalUserResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

// ---------------------------------------------------------------------------
// localUserNameValidator
// ---------------------------------------------------------------------------

func TestLocalUserNameValidator_Description(t *testing.T) {
	v := localUserNameValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must not be empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription must not be empty")
	}
}

func TestLocalUserNameValidator_Null_Skipped(t *testing.T) {
	v := localUserNameValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), luNullValidatorStringReq(), resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should not produce errors")
	}
}

func TestLocalUserNameValidator_WhitespaceOnly(t *testing.T) {
	v := localUserNameValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), luValidatorStringReq("   "), resp)
	if !resp.Diagnostics.HasError() {
		t.Error("whitespace-only name must produce error (EC-10)")
	}
}

func TestLocalUserNameValidator_LeadingSpace(t *testing.T) {
	v := localUserNameValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), luValidatorStringReq(" alice"), resp)
	if !resp.Diagnostics.HasError() {
		t.Error("leading-space name must produce error (EC-10)")
	}
}

func TestLocalUserNameValidator_TrailingSpace(t *testing.T) {
	v := localUserNameValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), luValidatorStringReq("alice "), resp)
	if !resp.Diagnostics.HasError() {
		t.Error("trailing-space name must produce error (EC-10)")
	}
}

func TestLocalUserNameValidator_ValidName(t *testing.T) {
	v := localUserNameValidator{}
	for _, name := range []string{"alice", "svc-backup", "JDoe", "user123"} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), luValidatorStringReq(name), resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("valid name %q should not produce error: %v", name, luDiagDetails(resp.Diagnostics))
		}
	}
}

// ---------------------------------------------------------------------------
// rfc3339Validator
// ---------------------------------------------------------------------------

func TestRFC3339Validator_Description(t *testing.T) {
	v := rfc3339Validator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must not be empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription must not be empty")
	}
}

func TestRFC3339Validator_Null_Skipped(t *testing.T) {
	v := rfc3339Validator{}
	req := validator.StringRequest{
		Path:        path.Root("account_expires"),
		ConfigValue: types.StringNull(),
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should not produce error")
	}
}

func TestRFC3339Validator_EmptyString_Skipped(t *testing.T) {
	v := rfc3339Validator{}
	req := validator.StringRequest{
		Path:        path.Root("account_expires"),
		ConfigValue: types.StringValue(""),
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("empty string should not produce error")
	}
}

func TestRFC3339Validator_ValidTimestamp(t *testing.T) {
	v := rfc3339Validator{}
	for _, ts := range []string{
		"2027-12-31T23:59:59Z",
		"2028-01-01T00:00:00+02:00",
		"2030-06-15T12:00:00-05:00",
	} {
		req := validator.StringRequest{
			Path:        path.Root("account_expires"),
			ConfigValue: types.StringValue(ts),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("valid RFC3339 %q should not produce error", ts)
		}
	}
}

func TestRFC3339Validator_InvalidTimestamp(t *testing.T) {
	v := rfc3339Validator{}
	for _, ts := range []string{
		"not-a-date",
		"2027/12/31",
		"2027-13-01T00:00:00Z",
	} {
		req := validator.StringRequest{
			Path:        path.Root("account_expires"),
			ConfigValue: types.StringValue(ts),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("invalid timestamp %q should produce error", ts)
		}
	}
}

// ---------------------------------------------------------------------------
// accountExpiresConflictValidator
// ---------------------------------------------------------------------------

func TestAccountExpiresConflictValidator_Description(t *testing.T) {
	v := accountExpiresConflictValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must not be empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription must not be empty")
	}
}

func TestAccountExpiresConflictValidator_NullValue_Skipped(t *testing.T) {
	v := accountExpiresConflictValidator{}
	s := windowsLocalUserSchemaDefinition()
	rawCfg := luObj(nil)
	cfg := tfsdk.Config{Schema: s, Raw: rawCfg}
	req := validator.StringRequest{
		Path:        path.Root("account_expires"),
		ConfigValue: types.StringNull(),
		Config:      cfg,
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null account_expires must not produce error")
	}
}

func TestAccountExpiresConflictValidator_NeverExpiresTrue_WithExpires_Fails(t *testing.T) {
	v := accountExpiresConflictValidator{}
	s := windowsLocalUserSchemaDefinition()
	rawCfg := luObj(map[string]tftypes.Value{
		"account_never_expires": tftypes.NewValue(tftypes.Bool, true),
		"account_expires":       tftypes.NewValue(tftypes.String, "2027-12-31T23:59:59Z"),
	})
	cfg := tfsdk.Config{Schema: s, Raw: rawCfg}
	req := validator.StringRequest{
		Path:        path.Root("account_expires"),
		ConfigValue: types.StringValue("2027-12-31T23:59:59Z"),
		Config:      cfg,
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("account_expires with account_never_expires=true must produce error (EC-14)")
	}
}

func TestAccountExpiresConflictValidator_NeverExpiresFalse_WithExpires_OK(t *testing.T) {
	v := accountExpiresConflictValidator{}
	s := windowsLocalUserSchemaDefinition()
	rawCfg := luObj(map[string]tftypes.Value{
		"account_never_expires": tftypes.NewValue(tftypes.Bool, false),
		"account_expires":       tftypes.NewValue(tftypes.String, "2027-12-31T23:59:59Z"),
	})
	cfg := tfsdk.Config{Schema: s, Raw: rawCfg}
	req := validator.StringRequest{
		Path:        path.Root("account_expires"),
		ConfigValue: types.StringValue("2027-12-31T23:59:59Z"),
		Config:      cfg,
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("account_expires with account_never_expires=false must be OK: %v", luDiagDetails(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// planToUserInput
// ---------------------------------------------------------------------------

func TestPlanToUserInput(t *testing.T) {
	m := windowsLocalUserModel{
		Name:                     types.StringValue("alice"),
		FullName:                 types.StringValue("Alice"),
		Description:              types.StringValue("desc"),
		PasswordNeverExpires:     types.BoolValue(true),
		UserMayNotChangePassword: types.BoolValue(true),
		AccountNeverExpires:      types.BoolValue(false),
		AccountExpires:           types.StringValue("2028-01-01T00:00:00Z"),
		Enabled:                  types.BoolValue(true),
	}
	input := planToUserInput(m)
	if input.Name != "alice" {
		t.Errorf("Name = %q", input.Name)
	}
	if input.FullName != "Alice" {
		t.Errorf("FullName = %q", input.FullName)
	}
	if input.Description != "desc" {
		t.Errorf("Description = %q", input.Description)
	}
	if !input.PasswordNeverExpires {
		t.Error("PasswordNeverExpires must be true")
	}
	if !input.UserMayNotChangePassword {
		t.Error("UserMayNotChangePassword must be true")
	}
	if input.AccountNeverExpires {
		t.Error("AccountNeverExpires must be false")
	}
	if input.AccountExpires != "2028-01-01T00:00:00Z" {
		t.Errorf("AccountExpires = %q", input.AccountExpires)
	}
	if !input.Enabled {
		t.Error("Enabled must be true")
	}
}

func TestPlanToUserInput_Defaults(t *testing.T) {
	m := windowsLocalUserModel{
		Name:                     types.StringValue("u"),
		FullName:                 types.StringValue(""),
		Description:              types.StringValue(""),
		PasswordNeverExpires:     types.BoolValue(false),
		UserMayNotChangePassword: types.BoolValue(false),
		AccountNeverExpires:      types.BoolValue(true),
		AccountExpires:           types.StringNull(),
		Enabled:                  types.BoolValue(true),
	}
	input := planToUserInput(m)
	if input.AccountExpires != "" {
		t.Errorf("AccountExpires must be empty for null, got %q", input.AccountExpires)
	}
	if !input.AccountNeverExpires {
		t.Error("AccountNeverExpires must be true")
	}
}

// ---------------------------------------------------------------------------
// scalarAttrsChanged
// ---------------------------------------------------------------------------

func makeModel(desc string, pne, umcp, ane bool, ae string) windowsLocalUserModel {
	m := windowsLocalUserModel{
		Name:                     types.StringValue("u"),
		FullName:                 types.StringValue(""),
		Description:              types.StringValue(desc),
		PasswordNeverExpires:     types.BoolValue(pne),
		UserMayNotChangePassword: types.BoolValue(umcp),
		AccountNeverExpires:      types.BoolValue(ane),
		Enabled:                  types.BoolValue(true),
	}
	if ae != "" {
		m.AccountExpires = types.StringValue(ae)
	} else {
		m.AccountExpires = types.StringNull()
	}
	return m
}

func TestScalarAttrsChanged_Unchanged(t *testing.T) {
	m := makeModel("desc", false, false, true, "")
	if scalarAttrsChanged(m, m) {
		t.Error("identical models must not report scalar change")
	}
}

func TestScalarAttrsChanged_DescriptionChanged(t *testing.T) {
	plan := makeModel("new-desc", false, false, true, "")
	prior := makeModel("old-desc", false, false, true, "")
	if !scalarAttrsChanged(plan, prior) {
		t.Error("description change must be detected")
	}
}

func TestScalarAttrsChanged_PNEChanged(t *testing.T) {
	plan := makeModel("d", true, false, true, "")
	prior := makeModel("d", false, false, true, "")
	if !scalarAttrsChanged(plan, prior) {
		t.Error("password_never_expires change must be detected")
	}
}

func TestScalarAttrsChanged_UMCPChanged(t *testing.T) {
	plan := makeModel("d", false, true, true, "")
	prior := makeModel("d", false, false, true, "")
	if !scalarAttrsChanged(plan, prior) {
		t.Error("user_may_not_change_password change must be detected")
	}
}

func TestScalarAttrsChanged_ANEChanged(t *testing.T) {
	plan := makeModel("d", false, false, false, "2028-01-01T00:00:00Z")
	prior := makeModel("d", false, false, true, "")
	if !scalarAttrsChanged(plan, prior) {
		t.Error("account_never_expires change must be detected")
	}
}

func TestScalarAttrsChanged_AccountExpiresChanged(t *testing.T) {
	plan := makeModel("d", false, false, false, "2029-01-01T00:00:00Z")
	prior := makeModel("d", false, false, false, "2028-01-01T00:00:00Z")
	if !scalarAttrsChanged(plan, prior) {
		t.Error("account_expires change must be detected")
	}
}

// ---------------------------------------------------------------------------
// addLocalUserDiag
// ---------------------------------------------------------------------------

func TestAddLocalUserDiag_LocalUserError(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewLocalUserError(winclient.LocalUserErrorPermission, "access denied", nil,
		map[string]string{"host": "win01"})
	addLocalUserDiag(&diags, "Delete failed", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	found := false
	for _, d := range diags {
		if d.Summary() == "Delete failed" {
			found = true
			if !strings.Contains(d.Detail(), "access denied") {
				t.Errorf("detail missing message: %q", d.Detail())
			}
			if !strings.Contains(d.Detail(), "permission_denied") {
				t.Errorf("detail missing kind: %q", d.Detail())
			}
		}
	}
	if !found {
		t.Error("expected diagnostic with summary 'Delete failed'")
	}
}

func TestAddLocalUserDiag_PlainError(t *testing.T) {
	var diags diag.Diagnostics
	addLocalUserDiag(&diags, "Oops", errSimple("some plain error"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(luDiagDetails(diags)[0], "some plain error") {
		t.Errorf("detail missing message: %v", luDiagDetails(diags))
	}
}

// errSimple implements the error interface for plain errors without winclient.
type errSimple string

func (e errSimple) Error() string { return string(e) }

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestLocalUserResource_Configure_NilData(t *testing.T) {
	r := &windowsLocalUserResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Error("nil ProviderData must not produce error")
	}
}

func TestLocalUserResource_Configure_WrongType(t *testing.T) {
	r := &windowsLocalUserResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong ProviderData type must produce error")
	}
}

// ---------------------------------------------------------------------------
// Create handler — happy path + EC-1 + EC-13 + no password diag
// ---------------------------------------------------------------------------

func TestLocalUserCreate_HappyPath(t *testing.T) {
	fake := &fakeLocalUserClient{
		createOut: okUserState("alice", "S-1-5-21-111-222-333-1001"),
		readOut:   okUserState("alice", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawPlan := luObj(nil)
	plan := tfsdk.Plan{Schema: s, Raw: rawPlan}
	req := resource.CreateRequest{Plan: plan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create() unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}
}

func TestLocalUserCreate_EC1_AlreadyExists(t *testing.T) {
	fake := &fakeLocalUserClient{
		createErr: winclient.NewLocalUserError(winclient.LocalUserErrorAlreadyExists,
			"user already exists", nil, nil),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawPlan := luObj(nil)
	plan := tfsdk.Plan{Schema: s, Raw: rawPlan}
	req := resource.CreateRequest{Plan: plan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected already_exists diagnostic")
	}
}

func TestLocalUserCreate_EC13_PastAccountExpires(t *testing.T) {
	fake := &fakeLocalUserClient{}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	past := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	rawPlan := luObj(map[string]tftypes.Value{
		"account_never_expires": tftypes.NewValue(tftypes.Bool, false),
		"account_expires":       tftypes.NewValue(tftypes.String, past),
	})
	plan := tfsdk.Plan{Schema: s, Raw: rawPlan}
	req := resource.CreateRequest{Plan: plan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for past account_expires (EC-13)")
	}
}

func TestLocalUserCreate_NoPassword_Error(t *testing.T) {
	fake := &fakeLocalUserClient{}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawPlan := luObj(map[string]tftypes.Value{
		"password": tftypes.NewValue(tftypes.String, nil), // null password
	})
	plan := tfsdk.Plan{Schema: s, Raw: rawPlan}
	req := resource.CreateRequest{Plan: plan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for missing password at Create")
	}
}

// ---------------------------------------------------------------------------
// Read handler — EC-3 drift + EC-4 case-fold
// ---------------------------------------------------------------------------

func TestLocalUserRead_EC3_UserDisappeared(t *testing.T) {
	fake := &fakeLocalUserClient{readOut: nil, readErr: nil}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawState := luObj(map[string]tftypes.Value{
		"sid": tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
	})
	st := tfsdk.State{Schema: s, Raw: rawState}
	req := resource.ReadRequest{State: st}
	resp := &resource.ReadResponse{State: st}

	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read EC-3 must not produce error: %v", luDiagDetails(resp.Diagnostics))
	}
	// State should be removed (Raw becomes null)
	if !resp.State.Raw.IsNull() {
		t.Error("state must be removed when user is nil (EC-3)")
	}
}

func TestLocalUserRead_EC4_CaseFoldName(t *testing.T) {
	fake := &fakeLocalUserClient{
		readOut: okUserState("ALICE", "S-1-5-21-111-222-333-1001"), // Windows uppercase
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawState := luObj(map[string]tftypes.Value{
		"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"name": tftypes.NewValue(tftypes.String, "alice"), // prior state lowercase
	})
	st := tfsdk.State{Schema: s, Raw: rawState}
	req := resource.ReadRequest{State: st}
	resp := &resource.ReadResponse{State: st}

	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read EC-4 must not produce error: %v", luDiagDetails(resp.Diagnostics))
	}

	// Extract the name from the new state
	var newState windowsLocalUserModel
	resp.State.Get(context.Background(), &newState)
	// EC-4: prior state name (lowercase) must be preserved
	if newState.Name.ValueString() != "alice" {
		t.Errorf("EC-4: name must be prior state 'alice', got %q", newState.Name.ValueString())
	}
}

func TestLocalUserRead_Error(t *testing.T) {
	fake := &fakeLocalUserClient{
		readErr: winclient.NewLocalUserError(winclient.LocalUserErrorPermission, "access denied", nil, nil),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawState := luObj(map[string]tftypes.Value{
		"sid": tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
	})
	st := tfsdk.State{Schema: s, Raw: rawState}
	req := resource.ReadRequest{State: st}
	resp := &resource.ReadResponse{State: st}

	r.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for read failure")
	}
}

// ---------------------------------------------------------------------------
// Update handler — rename + scalar + password rotation + enable/disable
// ---------------------------------------------------------------------------

func TestLocalUserUpdate_Rename(t *testing.T) {
	fake := &fakeLocalUserClient{
		renameErr: nil,
		readOut:   okUserState("alice-new", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawPlan := luObj(map[string]tftypes.Value{
		"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"name": tftypes.NewValue(tftypes.String, "alice-new"),
	})
	rawState := luObj(map[string]tftypes.Value{
		"sid":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":   tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"name": tftypes.NewValue(tftypes.String, "alice"),
	})

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: rawState}}

	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update Rename unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}
	if fake.lastRenameNewName != "alice-new" {
		t.Errorf("Rename called with %q, want alice-new", fake.lastRenameNewName)
	}
}

func TestLocalUserUpdate_PasswordRotation(t *testing.T) {
	fake := &fakeLocalUserClient{
		readOut: okUserState("alice", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	// wo_version changed from 1 to 2
	rawPlan := luObj(map[string]tftypes.Value{
		"sid":                 tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":                  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"password_wo_version": tftypes.NewValue(tftypes.Number, 2),
	})
	rawState := luObj(map[string]tftypes.Value{
		"sid":                 tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":                  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"name":                tftypes.NewValue(tftypes.String, "alice"),
		"password_wo_version": tftypes.NewValue(tftypes.Number, 1),
	})

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: rawState}}

	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update PasswordRotation unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}
	if fake.lastSetPasswordSID == "" {
		t.Error("SetPassword must have been called")
	}
}

func TestLocalUserUpdate_Enable(t *testing.T) {
	fake := &fakeLocalUserClient{
		readOut: okUserState("alice", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawPlan := luObj(map[string]tftypes.Value{
		"sid":     tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":      tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"enabled": tftypes.NewValue(tftypes.Bool, true),
	})
	rawState := luObj(map[string]tftypes.Value{
		"sid":     tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":      tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"name":    tftypes.NewValue(tftypes.String, "alice"),
		"enabled": tftypes.NewValue(tftypes.Bool, false),
	})

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: rawState}}

	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update Enable unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}
	if !fake.enableCalled {
		t.Error("Enable must have been called")
	}
}

func TestLocalUserUpdate_Disable(t *testing.T) {
	fake := &fakeLocalUserClient{
		readOut: okUserState("alice", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawPlan := luObj(map[string]tftypes.Value{
		"sid":     tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":      tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"enabled": tftypes.NewValue(tftypes.Bool, false),
	})
	rawState := luObj(map[string]tftypes.Value{
		"sid":     tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":      tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"name":    tftypes.NewValue(tftypes.String, "alice"),
		"enabled": tftypes.NewValue(tftypes.Bool, true),
	})

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: rawState}}

	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update Disable unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}
	if !fake.disableCalled {
		t.Error("Disable must have been called")
	}
}

// ---------------------------------------------------------------------------
// Delete handler — EC-2 builtin guard
// ---------------------------------------------------------------------------

func TestLocalUserDelete_HappyPath(t *testing.T) {
	fake := &fakeLocalUserClient{deleteErr: nil}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawState := luObj(map[string]tftypes.Value{
		"sid": tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
		"id":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-1001"),
	})
	st := tfsdk.State{Schema: s, Raw: rawState}
	req := resource.DeleteRequest{State: st}
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete happy path unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}
}

func TestLocalUserDelete_EC2_BuiltinAccount(t *testing.T) {
	fake := &fakeLocalUserClient{
		deleteErr: winclient.NewLocalUserError(winclient.LocalUserErrorBuiltinAccount,
			"cannot destroy built-in account", nil, map[string]string{"rid": "500"}),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	rawState := luObj(map[string]tftypes.Value{
		"sid": tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-500"),
		"id":  tftypes.NewValue(tftypes.String, "S-1-5-21-111-222-333-500"),
	})
	st := tfsdk.State{Schema: s, Raw: rawState}
	req := resource.DeleteRequest{State: st}
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected builtin_account error (EC-2)")
	}
}

// ---------------------------------------------------------------------------
// ImportState — EC-11 SID vs name detection
// ---------------------------------------------------------------------------

func TestLocalUserImportState_BySID(t *testing.T) {
	fake := &fakeLocalUserClient{
		importBySIDOut: okUserState("alice", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	req := resource.ImportStateRequest{ID: "S-1-5-21-111-222-333-1001"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}

	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState BySID unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}

	var m windowsLocalUserModel
	resp.State.Get(context.Background(), &m)
	if m.SID.ValueString() != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", m.SID.ValueString())
	}
	// Password must be null after import (EC-11, ADR-LU-3)
	if !m.Password.IsNull() {
		t.Error("password must be null after import (EC-11)")
	}
}

func TestLocalUserImportState_ByName(t *testing.T) {
	fake := &fakeLocalUserClient{
		importByNameOut: okUserState("alice", "S-1-5-21-111-222-333-1001"),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	// "alice" does not start with "S-" → ImportByName
	req := resource.ImportStateRequest{ID: "alice"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}

	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState ByName unexpected errors: %v", luDiagDetails(resp.Diagnostics))
	}

	var m windowsLocalUserModel
	resp.State.Get(context.Background(), &m)
	if m.Name.ValueString() != "alice" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
}

func TestLocalUserImportState_BySID_NotFound(t *testing.T) {
	fake := &fakeLocalUserClient{
		importBySIDErr: winclient.NewLocalUserError(winclient.LocalUserErrorNotFound,
			"SID not found", nil, nil),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	req := resource.ImportStateRequest{ID: "S-1-5-21-999-999-999-9999"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}

	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for SID not found")
	}
}

func TestLocalUserImportState_ByName_NotFound(t *testing.T) {
	fake := &fakeLocalUserClient{
		importByNameErr: winclient.NewLocalUserError(winclient.LocalUserErrorNotFound,
			"user not found", nil, nil),
	}
	r := &windowsLocalUserResource{user: fake}
	s := windowsLocalUserSchemaDefinition()

	req := resource.ImportStateRequest{ID: "ghost-user"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}

	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for name not found")
	}
}
