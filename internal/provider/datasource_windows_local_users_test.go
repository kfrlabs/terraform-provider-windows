// Package provider — unit tests for the windows_local_users data source.
//
// windows_local_users is the sibling collection of windows_local_user:
// optional filters, sorted `users` ListNested output (the singular
// attribute set plus `is_builtin`) with `names`/`sids` convenience lists in
// the same order, empty match is valid. Tests cover: Metadata, Schema
// (including the shared-attribute parity with the singular data source),
// Configure, Read happy-path mapping, parity with the singular Read path
// for the same fixture, filter pass-through, invalid-filter diagnostics,
// empty result, ID stability and timeout bounding.
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

type fakeLocalUsersClientDS struct {
	gotFilter winclient.LocalUserFilter
	listOut   []winclient.UserState
	listErr   error
	called    bool

	deadline time.Time
	ok       bool
}

func (f *fakeLocalUsersClientDS) List(ctx context.Context, filter winclient.LocalUserFilter) ([]winclient.UserState, error) {
	f.gotFilter = filter
	f.called = true
	f.deadline, f.ok = ctx.Deadline()
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listOut != nil {
		return f.listOut, nil
	}
	return []winclient.UserState{}, nil
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func localUsersDSElemType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"sid":                          tftypes.String,
		"name":                         tftypes.String,
		"full_name":                    tftypes.String,
		"description":                  tftypes.String,
		"enabled":                      tftypes.Bool,
		"password_never_expires":       tftypes.Bool,
		"user_may_not_change_password": tftypes.Bool,
		"account_never_expires":        tftypes.Bool,
		"account_expires":              tftypes.String,
		"last_logon":                   tftypes.String,
		"password_last_set":            tftypes.String,
		"principal_source":             tftypes.String,
		"is_builtin":                   tftypes.Bool,
	}}
}

func localUsersDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":              tftypes.String,
		"name_regex":      tftypes.String,
		"enabled":         tftypes.Bool,
		"include_builtin": tftypes.Bool,
		"users":           tftypes.List{ElementType: localUsersDSElemType()},
		"names":           tftypes.List{ElementType: tftypes.String},
		"sids":            tftypes.List{ElementType: tftypes.String},
		"timeouts":        dsTimeoutsObjType(),
	}}
}

func localUsersDSBaseVals() map[string]tftypes.Value {
	obj := localUsersDSObjType()
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

// localUsersDSConfig builds a config with the given filters; "" strings
// mean null, nil bools mean null.
func localUsersDSConfig(nameRegex string, enabled, includeBuiltin *bool) tfsdk.Config {
	d := &windowsLocalUsersDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := localUsersDSBaseVals()
	if nameRegex != "" {
		vals["name_regex"] = tftypes.NewValue(tftypes.String, nameRegex)
	}
	if enabled != nil {
		vals["enabled"] = tftypes.NewValue(tftypes.Bool, *enabled)
	}
	if includeBuiltin != nil {
		vals["include_builtin"] = tftypes.NewValue(tftypes.Bool, *includeBuiltin)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(localUsersDSObjType(), vals),
	}
}

func localUsersBool(b bool) *bool { return &b }

func fakeLocalUsersList() []winclient.UserState {
	return []winclient.UserState{
		{
			SID:                      "S-1-5-21-123-456-789-500",
			Name:                     "Administrator",
			FullName:                 "",
			Description:              "Built-in account",
			Enabled:                  false,
			PasswordNeverExpires:     true,
			UserMayNotChangePassword: false,
			AccountNeverExpires:      true,
			AccountExpires:           "",
			LastLogon:                "",
			PasswordLastSet:          "2025-12-01T00:00:00Z",
			PrincipalSource:          "Local",
		},
		{
			SID:                      "S-1-5-21-123-456-789-1001",
			Name:                     "jdoe",
			FullName:                 "John Doe",
			Description:              "Test user",
			Enabled:                  true,
			PasswordNeverExpires:     true,
			UserMayNotChangePassword: false,
			AccountNeverExpires:      true,
			AccountExpires:           "",
			LastLogon:                "2026-01-01T00:00:00Z",
			PasswordLastSet:          "2025-12-01T00:00:00Z",
			PrincipalSource:          "Local",
		},
	}
}

// localUsersAttr extracts one users element from a read state.
func localUsersAttr(t *testing.T, state windowsLocalUsersDataSourceModel, i int) map[string]attr.Value {
	t.Helper()
	elems := state.Users.Elements()
	if len(elems) <= i {
		t.Fatalf("users has %d elements, want index %d", len(elems), i)
	}
	obj, ok := elems[i].(interface{ Attributes() map[string]attr.Value })
	if !ok {
		t.Fatalf("element %d is %T, want an object", i, elems[i])
	}
	return obj.Attributes()
}

func localUsersStr(t *testing.T, m map[string]attr.Value, key string) types.String {
	t.Helper()
	v, ok := m[key].(types.String)
	if !ok {
		t.Fatalf("%s is %T, want types.String", key, m[key])
	}
	return v
}

func localUsersBoolAttr(t *testing.T, m map[string]attr.Value, key string) types.Bool {
	t.Helper()
	v, ok := m[key].(types.Bool)
	if !ok {
		t.Fatalf("%s is %T, want types.Bool", key, m[key])
	}
	return v
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

func TestLocalUsersDSMetadata(t *testing.T) {
	d := &windowsLocalUsersDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_local_users" {
		t.Errorf("TypeName = %q, want windows_local_users", resp.TypeName)
	}
}

func TestNewWindowsLocalUsersDataSource_NotNil(t *testing.T) {
	if NewWindowsLocalUsersDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

func TestLocalUsersDSSchema(t *testing.T) {
	d := &windowsLocalUsersDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "name_regex", "enabled", "include_builtin",
		"users", "names", "sids", "timeouts",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(resp.Schema.Attributes) != len(want) {
		t.Errorf("schema has %d attributes, want %d", len(resp.Schema.Attributes), len(want))
	}

	// The users elements carry exactly the singular data source attribute
	// set plus is_builtin (see local_user_ds_shared.go).
	usersAttr, ok := resp.Schema.Attributes["users"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("users is %T, want schema.ListNestedAttribute", resp.Schema.Attributes["users"])
	}
	nestedNames := map[string]bool{}
	for n := range usersAttr.NestedObject.Attributes {
		nestedNames[n] = true
	}
	for _, n := range localUserNestedAttrNames() {
		if !nestedNames[n] {
			t.Errorf("users nested object missing attribute %q", n)
		}
	}
	if len(usersAttr.NestedObject.Attributes) != len(localUserNestedAttrNames()) {
		t.Errorf("users nested object has %d attributes, want %d",
			len(usersAttr.NestedObject.Attributes), len(localUserNestedAttrNames()))
	}
	if len(localUserNestedAttrNames()) != 13 {
		t.Fatalf("shared per-user attribute set has %d names, want 13 (12 singular + is_builtin)",
			len(localUserNestedAttrNames()))
	}
}

// TestLocalUsersSchema_ParityWithSingular requires the shared per-user
// attribute set to match the singular windows_local_user data source in
// type and description. sid/name are excluded from the description check:
// their singular descriptions carry the ExactlyOneOf lookup-key sentences,
// which the shared helper intentionally drops for collection elements.
func TestLocalUsersSchema_ParityWithSingular(t *testing.T) {
	ctx := context.Background()
	single := &windowsLocalUserDataSource{}
	sResp := &datasource.SchemaResponse{}
	single.Schema(ctx, datasource.SchemaRequest{}, sResp)
	nested := localUserNestedAttributes()
	for name, collectionAttr := range nested {
		singularAttr, ok := sResp.Schema.Attributes[name]
		if !ok {
			if name == "is_builtin" {
				continue
			}
			t.Errorf("collection attribute %q missing from singular schema", name)
			continue
		}
		if name == "sid" || name == "name" {
			continue
		}
		wantDesc := ""
		switch want := singularAttr.(type) {
		case schema.StringAttribute:
			wantDesc = want.Description
			if _, ok := collectionAttr.(schema.StringAttribute); !ok {
				t.Errorf("attribute %q: collection is %T, want schema.StringAttribute", name, collectionAttr)
			}
		case schema.BoolAttribute:
			wantDesc = want.Description
			if _, ok := collectionAttr.(schema.BoolAttribute); !ok {
				t.Errorf("attribute %q: collection is %T, want schema.BoolAttribute", name, collectionAttr)
			}
		default:
			t.Errorf("attribute %q: singular is %T, parity check only knows String/Bool", name, singularAttr)
			continue
		}
		gotDesc := ""
		switch got := collectionAttr.(type) {
		case schema.StringAttribute:
			gotDesc = got.Description
		case schema.BoolAttribute:
			gotDesc = got.Description
		}
		if gotDesc != wantDesc {
			t.Errorf("attribute %q description drift:\n collection: %q\n singular:   %q", name, gotDesc, wantDesc)
		}
	}
}

func TestLocalUsersDSConfigure(t *testing.T) {
	d := &windowsLocalUsersDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}

	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}

	d2 := &windowsLocalUsersDataSource{}
	resp2 := &datasource.ConfigureResponse{}
	d2.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp2.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestLocalUsersDSRead_HappyPath(t *testing.T) {
	fc := &fakeLocalUsersClientDS{listOut: fakeLocalUsersList()}
	d := &windowsLocalUsersDataSource{lister: fc}
	cfg := localUsersDSConfig("", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var state windowsLocalUsersDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must be set (filter hash)")
	}
	if len(state.Users.Elements()) != 2 {
		t.Fatalf("users has %d elements, want 2", len(state.Users.Elements()))
	}

	admin := localUsersAttr(t, state, 0)
	if localUsersStr(t, admin, "name").ValueString() != "Administrator" {
		t.Errorf("name = %v", admin["name"])
	}
	if localUsersStr(t, admin, "sid").ValueString() != "S-1-5-21-123-456-789-500" {
		t.Errorf("sid = %v", admin["sid"])
	}
	if !localUsersBoolAttr(t, admin, "is_builtin").ValueBool() {
		t.Error("Administrator (RID 500) must be is_builtin")
	}
	if localUsersBoolAttr(t, admin, "enabled").ValueBool() {
		t.Error("Administrator fixture must be disabled")
	}

	jdoe := localUsersAttr(t, state, 1)
	if localUsersStr(t, jdoe, "full_name").ValueString() != "John Doe" {
		t.Errorf("full_name = %v", jdoe["full_name"])
	}
	if localUsersBoolAttr(t, jdoe, "is_builtin").ValueBool() {
		t.Error("jdoe (RID 1001) must not be is_builtin")
	}
	if !localUsersBoolAttr(t, jdoe, "enabled").ValueBool() {
		t.Error("jdoe must be enabled")
	}

	// names/sids convenience lists mirror users order.
	if len(state.Names.Elements()) != 2 || len(state.SIDs.Elements()) != 2 {
		t.Fatalf("names/sids must each have 2 elements")
	}
	var names, sids []string
	resp.Diagnostics.Append(state.Names.ElementsAs(context.Background(), &names, false)...)
	resp.Diagnostics.Append(state.SIDs.ElementsAs(context.Background(), &sids, false)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("elements as: %v", resp.Diagnostics)
	}
	if names[0] != "Administrator" || names[1] != "jdoe" {
		t.Errorf("names = %v, want [Administrator jdoe]", names)
	}
	if sids[0] != "S-1-5-21-123-456-789-500" || sids[1] != "S-1-5-21-123-456-789-1001" {
		t.Errorf("sids = %v", sids)
	}
}

// TestLocalUsersDSRead_ParityWithSingularDS feeds the same UserState fixture
// through the singular windows_local_user Read mapping and the collection
// projection and requires identical per-user values. The singular data
// source is deliberately not refactored to share helpers (see
// local_user_ds_shared.go); this test pins the two paths together instead.
func TestLocalUsersDSRead_ParityWithSingularDS(t *testing.T) {
	us := fakeUserState()

	singular := &windowsLocalUserDataSource{
		user: &fakeLocalUserClientDS{importByNameOut: us},
	}
	sCfg := localUserDSConfigByName(us.Name)
	sResp := &datasource.ReadResponse{State: tfsdk.State{Schema: sCfg.Schema}}
	singular.Read(context.Background(), datasource.ReadRequest{Config: sCfg}, sResp)
	if sResp.Diagnostics.HasError() {
		t.Fatalf("singular read: %v", sResp.Diagnostics)
	}
	var single windowsLocalUserDataSourceModel
	sResp.Diagnostics.Append(sResp.State.Get(context.Background(), &single)...)
	if sResp.Diagnostics.HasError() {
		t.Fatalf("singular state: %v", sResp.Diagnostics)
	}

	collection := &windowsLocalUsersDataSource{
		lister: &fakeLocalUsersClientDS{listOut: []winclient.UserState{*us}},
	}
	cCfg := localUsersDSConfig("", nil, nil)
	cResp := &datasource.ReadResponse{State: tfsdk.State{Schema: cCfg.Schema}}
	collection.Read(context.Background(), datasource.ReadRequest{Config: cCfg}, cResp)
	if cResp.Diagnostics.HasError() {
		t.Fatalf("collection read: %v", cResp.Diagnostics)
	}
	var coll windowsLocalUsersDataSourceModel
	cResp.Diagnostics.Append(cResp.State.Get(context.Background(), &coll)...)
	if cResp.Diagnostics.HasError() {
		t.Fatalf("collection state: %v", cResp.Diagnostics)
	}
	if len(coll.Users.Elements()) != 1 {
		t.Fatalf("users has %d elements, want 1", len(coll.Users.Elements()))
	}
	elem := localUsersAttr(t, coll, 0)

	if got := localUsersStr(t, elem, "sid").ValueString(); got != single.SID.ValueString() {
		t.Errorf("sid: collection %q != singular %q", got, single.SID.ValueString())
	}
	if got := localUsersStr(t, elem, "name").ValueString(); got != single.Name.ValueString() {
		t.Errorf("name: collection %q != singular %q", got, single.Name.ValueString())
	}
	if got := localUsersStr(t, elem, "full_name").ValueString(); got != single.FullName.ValueString() {
		t.Errorf("full_name: collection %q != singular %q", got, single.FullName.ValueString())
	}
	if got := localUsersStr(t, elem, "description").ValueString(); got != single.Description.ValueString() {
		t.Errorf("description: collection %q != singular %q", got, single.Description.ValueString())
	}
	if got := localUsersBoolAttr(t, elem, "enabled").ValueBool(); got != single.Enabled.ValueBool() {
		t.Errorf("enabled: collection %v != singular %v", got, single.Enabled.ValueBool())
	}
	if got := localUsersBoolAttr(t, elem, "password_never_expires").ValueBool(); got != single.PasswordNeverExpires.ValueBool() {
		t.Errorf("password_never_expires mismatch: %v != %v", got, single.PasswordNeverExpires.ValueBool())
	}
	if got := localUsersBoolAttr(t, elem, "user_may_not_change_password").ValueBool(); got != single.UserMayNotChangePassword.ValueBool() {
		t.Errorf("user_may_not_change_password mismatch")
	}
	if got := localUsersBoolAttr(t, elem, "account_never_expires").ValueBool(); got != single.AccountNeverExpires.ValueBool() {
		t.Errorf("account_never_expires mismatch")
	}
	if got := localUsersStr(t, elem, "account_expires").ValueString(); got != single.AccountExpires.ValueString() {
		t.Errorf("account_expires mismatch")
	}
	if got := localUsersStr(t, elem, "last_logon").ValueString(); got != single.LastLogon.ValueString() {
		t.Errorf("last_logon mismatch")
	}
	if got := localUsersStr(t, elem, "password_last_set").ValueString(); got != single.PasswordLastSet.ValueString() {
		t.Errorf("password_last_set mismatch")
	}
	if got := localUsersStr(t, elem, "principal_source").ValueString(); got != single.PrincipalSource.ValueString() {
		t.Errorf("principal_source mismatch")
	}
}

func TestLocalUsersDSRead_FiltersPassed(t *testing.T) {
	fc := &fakeLocalUsersClientDS{}
	d := &windowsLocalUsersDataSource{lister: fc}
	cfg := localUsersDSConfig(`^svc-`, localUsersBool(true), localUsersBool(false))
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if fc.gotFilter.NameRegex != `^svc-` {
		t.Errorf("name_regex not passed through: %+v", fc.gotFilter)
	}
	if fc.gotFilter.Enabled == nil || !*fc.gotFilter.Enabled {
		t.Errorf("enabled not passed through: %+v", fc.gotFilter)
	}
	if fc.gotFilter.IncludeBuiltin {
		t.Errorf("include_builtin not passed through: %+v", fc.gotFilter)
	}
}

func TestLocalUsersDSRead_NullFilterDefaults(t *testing.T) {
	fc := &fakeLocalUsersClientDS{}
	d := &windowsLocalUsersDataSource{lister: fc}
	cfg := localUsersDSConfig("", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if fc.gotFilter.NameRegex != "" {
		t.Errorf("null name_regex must read as empty: %+v", fc.gotFilter)
	}
	if fc.gotFilter.Enabled != nil {
		t.Errorf("null enabled must read as nil (match all): %+v", fc.gotFilter)
	}
	if !fc.gotFilter.IncludeBuiltin {
		t.Errorf("null include_builtin must default to true: %+v", fc.gotFilter)
	}
}

func TestLocalUsersDSRead_Error(t *testing.T) {
	fc := &fakeLocalUsersClientDS{listErr: winclient.NewLocalUserError(
		winclient.LocalUserErrorPermission, "access denied", nil, nil)}
	d := &windowsLocalUsersDataSource{lister: fc}
	cfg := localUsersDSConfig("", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from list failure")
	}
}

func TestLocalUsersDSRead_InvalidFilterError(t *testing.T) {
	// Filter validation lives in winclient (see
	// TestLocalUserList_InvalidRegexNoHostCall for the no-host-call
	// contract); the provider surfaces the resulting invalid_parameter
	// error as a diagnostic.
	fc := &fakeLocalUsersClientDS{listErr: winclient.NewLocalUserError(
		winclient.LocalUserErrorInvalidParameter, `name_regex "(unclosed" is not a valid regular expression`, nil, nil)}
	d := &windowsLocalUsersDataSource{lister: fc}
	cfg := localUsersDSConfig("(unclosed", nil, nil)
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

func TestLocalUsersDSRead_EmptyResultNoError(t *testing.T) {
	fc := &fakeLocalUsersClientDS{listOut: []winclient.UserState{}}
	d := &windowsLocalUsersDataSource{lister: fc}
	cfg := localUsersDSConfig(`NoSuchUser.*`, nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("empty match must not error: %v", resp.Diagnostics)
	}
	var state windowsLocalUsersDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.Users.IsNull() {
		t.Error("users must be an empty list, not null")
	}
	if len(state.Users.Elements()) != 0 {
		t.Errorf("users must be empty, got %d elements", len(state.Users.Elements()))
	}
	if state.Names.IsNull() || len(state.Names.Elements()) != 0 {
		t.Error("names must be an empty non-null list")
	}
	if state.SIDs.IsNull() || len(state.SIDs.Elements()) != 0 {
		t.Error("sids must be an empty non-null list")
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must be set even for an empty match")
	}
}

func TestLocalUsersDSRead_IDStability(t *testing.T) {
	readID := func(cfg tfsdk.Config) string {
		t.Helper()
		d := &windowsLocalUsersDataSource{lister: &fakeLocalUsersClientDS{}}
		resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
		d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
		}
		var state windowsLocalUsersDataSourceModel
		resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
		if resp.Diagnostics.HasError() {
			t.Fatalf("state read: %v", resp.Diagnostics)
		}
		return state.ID.ValueString()
	}
	id1 := readID(localUsersDSConfig(`^svc-`, localUsersBool(true), nil))
	id2 := readID(localUsersDSConfig(`^svc-`, localUsersBool(true), nil))
	if id1 != id2 {
		t.Errorf("identical filters must share an ID: %q != %q", id1, id2)
	}
	id3 := readID(localUsersDSConfig(`^other-`, localUsersBool(true), nil))
	if id1 == id3 {
		t.Error("different filters must move the ID")
	}
	id4 := readID(localUsersDSConfig(`^svc-`, nil, nil))
	if id1 == id4 {
		t.Error("enabled true vs null must move the ID")
	}
}

// TestLocalUsersDSRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read`: localUserDSDefaultTimeout
// when the block is absent, the configured value when set.
func TestLocalUsersDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", localUserDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeLocalUsersClientDS{}
			d := &windowsLocalUsersDataSource{lister: fake}
			cfg := localUsersDSConfig("", nil, nil)
			if tc.customRead != "" {
				cfg = dsConfigWithReadTimeout(t, cfg, tc.customRead)
			}
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
			d.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
	}
}
