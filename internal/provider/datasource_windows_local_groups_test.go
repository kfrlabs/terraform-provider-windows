// Package provider — unit tests for the windows_local_groups data source.
//
// windows_local_groups is the sibling collection of windows_local_group:
// optional filters, sorted `groups` ListNested output (the singular
// attribute set plus `is_builtin` and `members`) with `names`/`sids` dual
// filter/output sets in the same order, empty match is valid. Tests cover:
// Metadata, Schema (including the shared-attribute parity with the singular
// data source), Configure, Read happy-path mapping, parity with the singular
// Read path for the same fixture, filter pass-through, invalid-filter
// diagnostics, empty result, ID stability, and timeout bounding.
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

type fakeLocalGroupsClientDS struct {
	gotFilter winclient.LocalGroupFilter
	listOut   []winclient.GroupState
	listErr   error
	called    bool

	deadline time.Time
	ok       bool
}

func (f *fakeLocalGroupsClientDS) List(ctx context.Context, filter winclient.LocalGroupFilter) ([]winclient.GroupState, error) {
	f.gotFilter = filter
	f.called = true
	f.deadline, f.ok = ctx.Deadline()
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listOut != nil {
		return f.listOut, nil
	}
	return []winclient.GroupState{}, nil
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func localGroupsDSMemberElemType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"name":             tftypes.String,
		"sid":              tftypes.String,
		"object_class":     tftypes.String,
		"principal_source": tftypes.String,
	}}
}

func localGroupsDSElemType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"sid":         tftypes.String,
		"name":        tftypes.String,
		"description": tftypes.String,
		"is_builtin":  tftypes.Bool,
		"members":     tftypes.List{ElementType: localGroupsDSMemberElemType()},
	}}
}

func localGroupsDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":              tftypes.String,
		"names":           tftypes.Set{ElementType: tftypes.String},
		"sids":            tftypes.Set{ElementType: tftypes.String},
		"name_regex":      tftypes.String,
		"include_builtin": tftypes.Bool,
		"include_members": tftypes.Bool,
		"groups":          tftypes.List{ElementType: localGroupsDSElemType()},
		"timeouts":        dsTimeoutsObjType(),
	}}
}

func localGroupsDSBaseVals() map[string]tftypes.Value {
	obj := localGroupsDSObjType()
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

func localGroupsSet(vals ...string) tftypes.Value {
	if vals == nil {
		return tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil)
	}
	elems := make([]tftypes.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, tftypes.NewValue(tftypes.String, v))
	}
	return tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, elems)
}

// localGroupsDSConfig builds a config with the given filters; nil string
// slices mean null sets, "" regex means null, nil bools mean null.
func localGroupsDSConfig(names, sids []string, nameRegex string, includeBuiltin, includeMembers *bool) tfsdk.Config {
	d := &windowsLocalGroupsDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := localGroupsDSBaseVals()
	if names != nil {
		vals["names"] = localGroupsSet(names...)
	}
	if sids != nil {
		vals["sids"] = localGroupsSet(sids...)
	}
	if nameRegex != "" {
		vals["name_regex"] = tftypes.NewValue(tftypes.String, nameRegex)
	}
	if includeBuiltin != nil {
		vals["include_builtin"] = tftypes.NewValue(tftypes.Bool, *includeBuiltin)
	}
	if includeMembers != nil {
		vals["include_members"] = tftypes.NewValue(tftypes.Bool, *includeMembers)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(localGroupsDSObjType(), vals),
	}
}

func localGroupsBool(b bool) *bool { return &b }

func fakeLocalGroupsList() []winclient.GroupState {
	return []winclient.GroupState{
		{
			SID:         "S-1-5-32-544",
			Name:        "Administrators",
			Description: "Built-in administrators",
			Members: []winclient.LocalGroupMemberState{
				{
					GroupSID:        "S-1-5-32-544",
					MemberSID:       "S-1-5-21-123-456-789-500",
					MemberName:      "Administrator",
					PrincipalSource: "Local",
					ObjectClass:     "User",
				},
				{
					GroupSID:        "S-1-5-32-544",
					MemberSID:       "S-1-5-21-orphan-999",
					MemberName:      "",
					PrincipalSource: "Unknown",
					ObjectClass:     "Unknown",
				},
			},
		},
		{
			SID:         "S-1-5-21-123-456-789-1001",
			Name:        "TestGroup",
			Description: "Test group",
		},
	}
}

// localGroupsAttr extracts one groups element from a read state.
func localGroupsAttr(t *testing.T, state windowsLocalGroupsDataSourceModel, i int) map[string]attr.Value {
	t.Helper()
	elems := state.Groups.Elements()
	if len(elems) <= i {
		t.Fatalf("groups has %d elements, want index %d", len(elems), i)
	}
	obj, ok := elems[i].(interface{ Attributes() map[string]attr.Value })
	if !ok {
		t.Fatalf("element %d is %T, want an object", i, elems[i])
	}
	return obj.Attributes()
}

func localGroupsStr(t *testing.T, m map[string]attr.Value, key string) types.String {
	t.Helper()
	v, ok := m[key].(types.String)
	if !ok {
		t.Fatalf("%s is %T, want types.String", key, m[key])
	}
	return v
}

func localGroupsBoolAttr(t *testing.T, m map[string]attr.Value, key string) types.Bool {
	t.Helper()
	v, ok := m[key].(types.Bool)
	if !ok {
		t.Fatalf("%s is %T, want types.Bool", key, m[key])
	}
	return v
}

func localGroupsListAttr(t *testing.T, m map[string]attr.Value, key string) types.List {
	t.Helper()
	v, ok := m[key].(types.List)
	if !ok {
		t.Fatalf("%s is %T, want types.List", key, m[key])
	}
	return v
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

func TestLocalGroupsDSMetadata(t *testing.T) {
	d := &windowsLocalGroupsDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_local_groups" {
		t.Errorf("TypeName = %q, want windows_local_groups", resp.TypeName)
	}
}

func TestNewWindowsLocalGroupsDataSource_NotNil(t *testing.T) {
	if NewWindowsLocalGroupsDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

func TestLocalGroupsDSSchema(t *testing.T) {
	d := &windowsLocalGroupsDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "names", "sids", "name_regex", "include_builtin",
		"include_members", "groups", "timeouts",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(resp.Schema.Attributes) != len(want) {
		t.Errorf("schema has %d attributes, want %d", len(resp.Schema.Attributes), len(want))
	}

	// The groups elements carry exactly the singular data source attribute
	// set plus is_builtin and members (see local_group_ds_shared.go).
	groupsAttr, ok := resp.Schema.Attributes["groups"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("groups is %T, want schema.ListNestedAttribute", resp.Schema.Attributes["groups"])
	}
	nestedNames := map[string]bool{}
	for n := range groupsAttr.NestedObject.Attributes {
		nestedNames[n] = true
	}
	for _, n := range localGroupNestedAttrNames() {
		if !nestedNames[n] {
			t.Errorf("groups nested object missing attribute %q", n)
		}
	}
	if !nestedNames["members"] {
		t.Error("groups nested object missing attribute members")
	}
	if len(groupsAttr.NestedObject.Attributes) != len(localGroupNestedAttrNames())+1 {
		t.Errorf("groups nested object has %d attributes, want %d",
			len(groupsAttr.NestedObject.Attributes), len(localGroupNestedAttrNames())+1)
	}
	if len(localGroupNestedAttrNames()) != 4 {
		t.Fatalf("shared per-group scalar set has %d names, want 4 (sid, name, description, is_builtin)",
			len(localGroupNestedAttrNames()))
	}

	// The members elements carry name/sid/object_class/principal_source.
	membersAttr, ok := groupsAttr.NestedObject.Attributes["members"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("members is %T, want schema.ListNestedAttribute", groupsAttr.NestedObject.Attributes["members"])
	}
	for _, n := range []string{"name", "sid", "object_class", "principal_source"} {
		if _, ok := membersAttr.NestedObject.Attributes[n]; !ok {
			t.Errorf("members nested object missing attribute %q", n)
		}
	}
	if len(membersAttr.NestedObject.Attributes) != 4 {
		t.Errorf("members nested object has %d attributes, want 4",
			len(membersAttr.NestedObject.Attributes))
	}
}

// TestLocalGroupsSchema_ParityWithSingular requires the shared per-group
// attribute set to match the singular windows_local_group data source in
// type and description. sid/name are excluded from the description check:
// their singular descriptions carry the ExactlyOneOf lookup-key sentences,
// which the shared helper intentionally drops for collection elements.
func TestLocalGroupsSchema_ParityWithSingular(t *testing.T) {
	ctx := context.Background()
	single := &windowsLocalGroupDataSource{}
	sResp := &datasource.SchemaResponse{}
	single.Schema(ctx, datasource.SchemaRequest{}, sResp)
	nested := localGroupNestedAttributes()
	for name, collectionAttr := range nested {
		singularAttr, ok := sResp.Schema.Attributes[name]
		if !ok {
			if name == "is_builtin" || name == "members" {
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
		default:
			t.Errorf("attribute %q: singular is %T, parity check only knows String", name, singularAttr)
			continue
		}
		gotDesc := ""
		switch got := collectionAttr.(type) {
		case schema.StringAttribute:
			gotDesc = got.Description
		}
		if gotDesc != wantDesc {
			t.Errorf("attribute %q description drift:\n collection: %q\n singular:   %q", name, gotDesc, wantDesc)
		}
	}
}

func TestLocalGroupsDSConfigure(t *testing.T) {
	d := &windowsLocalGroupsDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}

	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}

	d2 := &windowsLocalGroupsDataSource{}
	resp2 := &datasource.ConfigureResponse{}
	d2.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp2.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestLocalGroupsDSRead_HappyPath(t *testing.T) {
	fc := &fakeLocalGroupsClientDS{listOut: fakeLocalGroupsList()}
	d := &windowsLocalGroupsDataSource{lister: fc}
	cfg := localGroupsDSConfig(nil, nil, "", nil, localGroupsBool(true))
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var state windowsLocalGroupsDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must be set (filter hash)")
	}
	if len(state.Groups.Elements()) != 2 {
		t.Fatalf("groups has %d elements, want 2", len(state.Groups.Elements()))
	}

	admin := localGroupsAttr(t, state, 0)
	if localGroupsStr(t, admin, "name").ValueString() != "Administrators" {
		t.Errorf("name = %v", admin["name"])
	}
	if localGroupsStr(t, admin, "sid").ValueString() != "S-1-5-32-544" {
		t.Errorf("sid = %v", admin["sid"])
	}
	if !localGroupsBoolAttr(t, admin, "is_builtin").ValueBool() {
		t.Error("Administrators (S-1-5-32-*) must be is_builtin")
	}
	members := localGroupsListAttr(t, admin, "members")
	if members.IsNull() {
		t.Fatal("members must not be null when include_members is true")
	}
	if len(members.Elements()) != 2 {
		t.Fatalf("members has %d elements, want 2", len(members.Elements()))
	}
	first, ok := members.Elements()[0].(interface{ Attributes() map[string]attr.Value })
	if !ok {
		t.Fatalf("member element is %T, want an object", members.Elements()[0])
	}
	m0 := first.Attributes()
	if localGroupsStr(t, m0, "sid").ValueString() != "S-1-5-21-123-456-789-500" {
		t.Errorf("member sid = %v", m0["sid"])
	}
	if localGroupsStr(t, m0, "name").ValueString() != "Administrator" {
		t.Errorf("member name = %v", m0["name"])
	}
	if localGroupsStr(t, m0, "object_class").ValueString() != "User" {
		t.Errorf("member object_class = %v", m0["object_class"])
	}
	if localGroupsStr(t, m0, "principal_source").ValueString() != "Local" {
		t.Errorf("member principal_source = %v", m0["principal_source"])
	}
	second, ok := members.Elements()[1].(interface{ Attributes() map[string]attr.Value })
	if !ok {
		t.Fatalf("member element is %T, want an object", members.Elements()[1])
	}
	m1 := second.Attributes()
	if localGroupsStr(t, m1, "name").ValueString() != "" {
		t.Errorf("orphan member name = %v, want empty (mapped as-is)", m1["name"])
	}
	if localGroupsStr(t, m1, "object_class").ValueString() != "Unknown" {
		t.Errorf("orphan member object_class = %v, want Unknown", m1["object_class"])
	}

	testGroup := localGroupsAttr(t, state, 1)
	if localGroupsStr(t, testGroup, "name").ValueString() != "TestGroup" {
		t.Errorf("name = %v", testGroup["name"])
	}
	if localGroupsBoolAttr(t, testGroup, "is_builtin").ValueBool() {
		t.Error("TestGroup (RID 1001) must not be is_builtin")
	}

	// names/sids convenience sets mirror groups order.
	var outNames, outSIDs []string
	resp.Diagnostics.Append(state.Names.ElementsAs(context.Background(), &outNames, false)...)
	resp.Diagnostics.Append(state.SIDs.ElementsAs(context.Background(), &outSIDs, false)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("elements as: %v", resp.Diagnostics)
	}
	if len(outNames) != 2 || len(outSIDs) != 2 {
		t.Fatalf("names/sids must each have 2 elements, got %v / %v", outNames, outSIDs)
	}
}

// TestLocalGroupsDSRead_MembersNullDefault requires members to be null on
// every group element when include_members is null (the default false).
func TestLocalGroupsDSRead_MembersNullDefault(t *testing.T) {
	fc := &fakeLocalGroupsClientDS{listOut: fakeLocalGroupsList()}
	d := &windowsLocalGroupsDataSource{lister: fc}
	cfg := localGroupsDSConfig(nil, nil, "", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if fc.gotFilter.IncludeMembers {
		t.Errorf("null include_members must read as false: %+v", fc.gotFilter)
	}
	var state windowsLocalGroupsDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	for i := range state.Groups.Elements() {
		elem := localGroupsAttr(t, state, i)
		if !localGroupsListAttr(t, elem, "members").IsNull() {
			t.Errorf("groups[%d].members must be null when membership was not requested", i)
		}
	}
}

// TestLocalGroupsDSRead_ParityWithSingularDS feeds the same GroupState
// fixture through the singular windows_local_group Read mapping and the
// collection projection and requires identical per-group values. The singular
// data source is deliberately not refactored to share helpers (see
// local_group_ds_shared.go); this test pins the two paths together instead.
func TestLocalGroupsDSRead_ParityWithSingularDS(t *testing.T) {
	gs := &winclient.GroupState{
		SID:         "S-1-5-21-123-456-789-1001",
		Name:        "TestGroup",
		Description: "Test group",
	}

	singular := &windowsLocalGroupDataSource{
		grp: &fakeLocalGroupClientDS{importByNameOut: gs},
	}
	sCfg := localGroupDSConfigByName(gs.Name)
	sResp := &datasource.ReadResponse{State: tfsdk.State{Schema: sCfg.Schema}}
	singular.Read(context.Background(), datasource.ReadRequest{Config: sCfg}, sResp)
	if sResp.Diagnostics.HasError() {
		t.Fatalf("singular read: %v", sResp.Diagnostics)
	}
	var single windowsLocalGroupDataSourceModel
	sResp.Diagnostics.Append(sResp.State.Get(context.Background(), &single)...)
	if sResp.Diagnostics.HasError() {
		t.Fatalf("singular state: %v", sResp.Diagnostics)
	}

	collection := &windowsLocalGroupsDataSource{
		lister: &fakeLocalGroupsClientDS{listOut: []winclient.GroupState{*gs}},
	}
	cCfg := localGroupsDSConfig(nil, nil, "", nil, nil)
	cResp := &datasource.ReadResponse{State: tfsdk.State{Schema: cCfg.Schema}}
	collection.Read(context.Background(), datasource.ReadRequest{Config: cCfg}, cResp)
	if cResp.Diagnostics.HasError() {
		t.Fatalf("collection read: %v", cResp.Diagnostics)
	}
	var coll windowsLocalGroupsDataSourceModel
	cResp.Diagnostics.Append(cResp.State.Get(context.Background(), &coll)...)
	if cResp.Diagnostics.HasError() {
		t.Fatalf("collection state: %v", cResp.Diagnostics)
	}
	if len(coll.Groups.Elements()) != 1 {
		t.Fatalf("groups has %d elements, want 1", len(coll.Groups.Elements()))
	}
	elem := localGroupsAttr(t, coll, 0)

	if got := localGroupsStr(t, elem, "sid").ValueString(); got != single.SID.ValueString() {
		t.Errorf("sid: collection %q != singular %q", got, single.SID.ValueString())
	}
	if got := localGroupsStr(t, elem, "name").ValueString(); got != single.Name.ValueString() {
		t.Errorf("name: collection %q != singular %q", got, single.Name.ValueString())
	}
	if got := localGroupsStr(t, elem, "description").ValueString(); got != single.Description.ValueString() {
		t.Errorf("description: collection %q != singular %q", got, single.Description.ValueString())
	}
}

func TestLocalGroupsDSRead_FiltersPassed(t *testing.T) {
	fc := &fakeLocalGroupsClientDS{}
	d := &windowsLocalGroupsDataSource{lister: fc}
	cfg := localGroupsDSConfig([]string{"svc-group"}, []string{"S-1-5-21-1-2-3-1001"}, `^svc-`, localGroupsBool(false), localGroupsBool(true))
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if len(fc.gotFilter.Names) != 1 || fc.gotFilter.Names[0] != "svc-group" {
		t.Errorf("names not passed through: %+v", fc.gotFilter)
	}
	if len(fc.gotFilter.SIDs) != 1 || fc.gotFilter.SIDs[0] != "S-1-5-21-1-2-3-1001" {
		t.Errorf("sids not passed through: %+v", fc.gotFilter)
	}
	if fc.gotFilter.NameRegex != `^svc-` {
		t.Errorf("name_regex not passed through: %+v", fc.gotFilter)
	}
	if fc.gotFilter.IncludeBuiltin {
		t.Errorf("include_builtin not passed through: %+v", fc.gotFilter)
	}
	if !fc.gotFilter.IncludeMembers {
		t.Errorf("include_members not passed through: %+v", fc.gotFilter)
	}
}

func TestLocalGroupsDSRead_NullFilterDefaults(t *testing.T) {
	fc := &fakeLocalGroupsClientDS{}
	d := &windowsLocalGroupsDataSource{lister: fc}
	cfg := localGroupsDSConfig(nil, nil, "", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if len(fc.gotFilter.Names) != 0 {
		t.Errorf("null names must read as empty: %+v", fc.gotFilter)
	}
	if len(fc.gotFilter.SIDs) != 0 {
		t.Errorf("null sids must read as empty: %+v", fc.gotFilter)
	}
	if fc.gotFilter.NameRegex != "" {
		t.Errorf("null name_regex must read as empty: %+v", fc.gotFilter)
	}
	if !fc.gotFilter.IncludeBuiltin {
		t.Errorf("null include_builtin must default to true: %+v", fc.gotFilter)
	}
	if fc.gotFilter.IncludeMembers {
		t.Errorf("null include_members must default to false: %+v", fc.gotFilter)
	}
}

func TestLocalGroupsDSRead_Error(t *testing.T) {
	fc := &fakeLocalGroupsClientDS{listErr: winclient.NewLocalGroupError(
		winclient.LocalGroupErrorPermission, "access denied", nil, nil)}
	d := &windowsLocalGroupsDataSource{lister: fc}
	cfg := localGroupsDSConfig(nil, nil, "", nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from list failure")
	}
}

func TestLocalGroupsDSRead_InvalidFilterError(t *testing.T) {
	// Filter validation lives in winclient (see
	// TestLocalGroupList_InvalidRegexNoHostCall for the no-host-call
	// contract); the provider surfaces the resulting invalid_parameter
	// error as a diagnostic.
	fc := &fakeLocalGroupsClientDS{listErr: winclient.NewLocalGroupError(
		winclient.LocalGroupErrorInvalidParameter, `name_regex "(unclosed" is not a valid regular expression`, nil, nil)}
	d := &windowsLocalGroupsDataSource{lister: fc}
	cfg := localGroupsDSConfig(nil, nil, "(unclosed", nil, nil)
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

func TestLocalGroupsDSRead_EmptyResultNoError(t *testing.T) {
	fc := &fakeLocalGroupsClientDS{listOut: []winclient.GroupState{}}
	d := &windowsLocalGroupsDataSource{lister: fc}
	cfg := localGroupsDSConfig(nil, nil, `NoSuchGroup.*`, nil, nil)
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("empty match must not error: %v", resp.Diagnostics)
	}
	var state windowsLocalGroupsDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state read: %v", resp.Diagnostics)
	}
	if state.Groups.IsNull() {
		t.Error("groups must be an empty list, not null")
	}
	if len(state.Groups.Elements()) != 0 {
		t.Errorf("groups must be empty, got %d elements", len(state.Groups.Elements()))
	}
	if state.Names.IsNull() || len(state.Names.Elements()) != 0 {
		t.Error("names must be an empty non-null set")
	}
	if state.SIDs.IsNull() || len(state.SIDs.Elements()) != 0 {
		t.Error("sids must be an empty non-null set")
	}
	if state.ID.IsNull() || state.ID.ValueString() == "" {
		t.Error("ID must be set even for an empty match")
	}
}

func TestLocalGroupsDSRead_IDStability(t *testing.T) {
	readID := func(cfg tfsdk.Config) string {
		t.Helper()
		d := &windowsLocalGroupsDataSource{lister: &fakeLocalGroupsClientDS{}}
		resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
		d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
		}
		var state windowsLocalGroupsDataSourceModel
		resp.Diagnostics.Append(resp.State.Get(context.Background(), &state)...)
		if resp.Diagnostics.HasError() {
			t.Fatalf("state read: %v", resp.Diagnostics)
		}
		return state.ID.ValueString()
	}
	id1 := readID(localGroupsDSConfig([]string{"a", "b"}, nil, `^svc-`, localGroupsBool(true), nil))
	id2 := readID(localGroupsDSConfig([]string{"a", "b"}, nil, `^svc-`, localGroupsBool(true), nil))
	if id1 != id2 {
		t.Errorf("identical filters must share an ID: %q != %q", id1, id2)
	}
	id3 := readID(localGroupsDSConfig([]string{"a", "b"}, nil, `^other-`, localGroupsBool(true), nil))
	if id1 == id3 {
		t.Error("different filters must move the ID")
	}
	id4 := readID(localGroupsDSConfig(nil, nil, `^svc-`, nil, nil))
	if id1 == id4 {
		t.Error("names filter vs null must move the ID")
	}
}

// TestLocalGroupsDSFilterID_SetOrderInsensitive requires the filter ID to be
// stable under set reordering (config sets carry no order).
func TestLocalGroupsDSFilterID_SetOrderInsensitive(t *testing.T) {
	id1 := localGroupsFilterID([]string{"b", "a"}, []string{"S-2", "S-1"}, "", true, false)
	id2 := localGroupsFilterID([]string{"a", "b"}, []string{"S-1", "S-2"}, "", true, false)
	if id1 != id2 {
		t.Errorf("reordered filters must share an ID: %q != %q", id1, id2)
	}
	id3 := localGroupsFilterID([]string{"a", "c"}, []string{"S-1", "S-2"}, "", true, false)
	if id1 == id3 {
		t.Error("different filters must move the ID")
	}
}

// TestLocalGroupsDSRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read`: localGroupDSDefaultTimeout
// when the block is absent, the configured value when set.
func TestLocalGroupsDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", localGroupDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeLocalGroupsClientDS{}
			d := &windowsLocalGroupsDataSource{lister: fake}
			cfg := localGroupsDSConfig(nil, nil, "", nil, nil)
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
