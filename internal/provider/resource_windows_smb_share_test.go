// Package provider — unit tests for the windows_smb_share resource.
//
// These tests exercise the schema, validators, access-set reconciliation and
// CRUD handlers without SSH. A fakeSmbShareClient is injected into
// windowsSmbShareResource.client.
//
// Edge cases covered (aligned with the windows_smb_share spec, issue #221):
//
//	Metadata                 — returns "windows_smb_share"
//	Schema                   — required/ForceNew/computed attributes, access sets
//	Name validator           — reserved administrative names rejected
//	ConfigValidators         — duplicate principal across sets (plan error),
//	                           SID-aware (Everyone vs S-1-1-1),
//	                           Everyone/Authenticated Users in full/change (warning)
//	AccessManaged            — all-null sets unmanaged vs configured authoritative
//	IdentityMatches          — SID-first, bare-name tolerant
//	Create (happy)           — share + access state populated
//	Create (already_exists)  — diagnostic carries the import hint
//	Create (error)           — client error produces diagnostic
//	Read (happy)             — SID no-diff keeps operator spelling, drift appended
//	Read (not found)         — RemoveResource
//	Read (error)             — client error produces diagnostic
//	Update (happy)           — authoritative settings forwarded incl. ManageAccess
//	Update (unmanaged)       — all-null sets forward ManageAccess=false
//	Update (not found)       — diagnostic, no silent recreate
//	Delete (happy / error)
//	ImportState (happy)      — access sets start unmanaged (null)
//	ImportState (not found / special / invalid) — diagnostic errors
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeSmbShareClient
// ---------------------------------------------------------------------------

type fakeSmbShareClient struct {
	createIn  winclient.SmbShareInput
	createOut *winclient.SmbShareInfo
	createErr error

	readOut *winclient.SmbShareInfo
	readErr error

	updateIn  winclient.SmbShareUpdateInput
	updateOut *winclient.SmbShareInfo
	updateErr error

	deleteErr  error
	deleteName string
}

func (f *fakeSmbShareClient) Create(_ context.Context, in winclient.SmbShareInput) (*winclient.SmbShareInfo, error) {
	f.createIn = in
	return f.createOut, f.createErr
}

func (f *fakeSmbShareClient) Read(_ context.Context, name string) (*winclient.SmbShareInfo, error) {
	return f.readOut, f.readErr
}

func (f *fakeSmbShareClient) Update(_ context.Context, in winclient.SmbShareUpdateInput) (*winclient.SmbShareInfo, error) {
	f.updateIn = in
	return f.updateOut, f.updateErr
}

func (f *fakeSmbShareClient) Delete(_ context.Context, name string) error {
	f.deleteName = name
	return f.deleteErr
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_smb_share schema
// ---------------------------------------------------------------------------

func smbSetType() tftypes.Set { return tftypes.Set{ElementType: tftypes.String} }

func smbObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                      tftypes.String,
		"name":                    tftypes.String,
		"path":                    tftypes.String,
		"description":             tftypes.String,
		"folder_enumeration_mode": tftypes.String,
		"caching_mode":            tftypes.String,
		"concurrent_user_limit":   tftypes.Number,
		"encrypt_data":            tftypes.Bool,
		"full_access":             smbSetType(),
		"change_access":           smbSetType(),
		"read_access":             smbSetType(),
		"no_access":               smbSetType(),
		"special":                 tftypes.Bool,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func smbNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func smbStrSet(vals ...string) tftypes.Value {
	elems := make([]tftypes.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, tftypes.NewValue(tftypes.String, v))
	}
	return tftypes.NewValue(smbSetType(), elems)
}

func smbNullSet() tftypes.Value { return tftypes.NewValue(smbSetType(), nil) }

func smbObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                      tftypes.NewValue(tftypes.String, "Finance"),
		"name":                    tftypes.NewValue(tftypes.String, "Finance"),
		"path":                    tftypes.NewValue(tftypes.String, `D:\Shares\Finance`),
		"description":             tftypes.NewValue(tftypes.String, nil),
		"folder_enumeration_mode": tftypes.NewValue(tftypes.String, "AccessBased"),
		"caching_mode":            tftypes.NewValue(tftypes.String, "None"),
		"concurrent_user_limit":   tftypes.NewValue(tftypes.Number, 0),
		"encrypt_data":            tftypes.NewValue(tftypes.Bool, true),
		"full_access":             smbStrSet(`BUILTIN\Administrators`),
		"change_access":           smbNullSet(),
		"read_access":             smbStrSet("Everyone"),
		"no_access":               smbNullSet(),
		"special":                 tftypes.NewValue(tftypes.Bool, false),
		"timeouts":                smbNullTimeoutsValue(),
	}
}

func smbObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := smbObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(smbObjType(), base)
}

func smbState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsSmbShareSchemaDefinition(context.Background())
	return tfsdk.State{Raw: smbObj(overrides), Schema: s}
}

func smbPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsSmbShareSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: smbObj(overrides), Schema: s}
}

func smbConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsSmbShareSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: smbObj(overrides), Schema: s}
}

func okSmbState(name string) *winclient.SmbShareInfo {
	return &winclient.SmbShareInfo{
		Name:                  name,
		Path:                  `D:\Shares\Finance`,
		Description:           "",
		FolderEnumerationMode: "AccessBased",
		CachingMode:           "None",
		EncryptData:           true,
		FullAccess:            []winclient.SmbShareTrustee{{Name: `BUILTIN\Administrators`, SID: "S-1-5-32-544"}},
		ReadAccess:            []winclient.SmbShareTrustee{{Name: "Everyone", SID: "S-1-1-1"}},
	}
}

func smbDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

func smbSetStrings(t *testing.T, s types.Set) []string {
	t.Helper()
	if s.IsNull() {
		return nil
	}
	var out []string
	if d := s.ElementsAs(context.Background(), &out, false); d.HasError() {
		t.Fatalf("ElementsAs: %v", d)
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsSmbShareResource_Metadata(t *testing.T) {
	r := &windowsSmbShareResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_smb_share" {
		t.Errorf("TypeName = %q, want windows_smb_share", resp.TypeName)
	}
}

func TestWindowsSmbShareSchemaDefinition(t *testing.T) {
	s := windowsSmbShareSchemaDefinition(context.Background())
	for _, name := range []string{
		"id", "name", "path", "description", "folder_enumeration_mode",
		"caching_mode", "concurrent_user_limit", "encrypt_data",
		"full_access", "change_access", "read_access", "no_access",
		"special", "timeouts",
	} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
	for _, name := range []string{"name", "path"} {
		a := s.Attributes[name].(schema.StringAttribute)
		if !a.Required {
			t.Errorf("%s must be Required", name)
		}
		if len(a.PlanModifiers) == 0 {
			t.Errorf("%s must be ForceNew", name)
		}
	}
	// Access sets are Optional (null = unmanaged), never Computed.
	for _, name := range []string{"full_access", "change_access", "read_access", "no_access"} {
		a := s.Attributes[name].(schema.SetAttribute)
		if !a.Optional || a.Computed {
			t.Errorf("%s must be Optional-only (null means unmanaged)", name)
		}
	}
	// Observed-only attributes must never be writable.
	idAttr := s.Attributes["id"].(schema.StringAttribute)
	if !idAttr.Computed || idAttr.Optional || idAttr.Required {
		t.Error("id must be computed only")
	}
	specialAttr := s.Attributes["special"].(schema.BoolAttribute)
	if !specialAttr.Computed || specialAttr.Optional || specialAttr.Required {
		t.Error("special must be computed only")
	}
}

// ---------------------------------------------------------------------------
// Name validator
// ---------------------------------------------------------------------------

func TestSmbShareNameValidator(t *testing.T) {
	valid := []string{"Finance", "finance-data_2026", "Share1"}
	for _, n := range valid {
		resp := &validator.StringResponse{}
		smbShareNameValidator{}.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("name"),
			ConfigValue: types.StringValue(n),
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("name %q should pass, got %v", n, resp.Diagnostics)
		}
	}
	invalid := []string{"IPC$", "ADMIN$", "C$", "Z$"}
	for _, n := range invalid {
		resp := &validator.StringResponse{}
		smbShareNameValidator{}.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("name"),
			ConfigValue: types.StringValue(n),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("name %q should be rejected as reserved", n)
		}
	}
	// Null/unknown values are not validated yet.
	for _, v := range []types.String{types.StringNull(), types.StringUnknown()} {
		resp := &validator.StringResponse{}
		smbShareNameValidator{}.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("name"), ConfigValue: v,
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("null/unknown should skip validation, got %v", resp.Diagnostics)
		}
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators: duplicates + broad-grant warnings
// ---------------------------------------------------------------------------

func smbValidatorDiags(t *testing.T, overrides map[string]tftypes.Value) diag.Diagnostics {
	t.Helper()
	r := NewWindowsSmbShareResource().(*windowsSmbShareResource)
	var v smbShareConfigValidator
	for _, cv := range r.ConfigValidators(context.Background()) {
		if sv, ok := cv.(smbShareConfigValidator); ok {
			v = sv
		}
	}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), resource.ValidateConfigRequest{
		Config: smbConfig(t, overrides),
	}, resp)
	return resp.Diagnostics
}

func smbDiagCounts(ds diag.Diagnostics) (errors, warnings int) {
	for _, d := range ds {
		switch d.Severity() {
		case diag.SeverityError:
			errors++
		case diag.SeverityWarning:
			warnings++
		}
	}
	return errors, warnings
}

func TestSmbShareConfigValidator_DuplicateAcrossSets(t *testing.T) {
	// Exact duplicate, case-insensitive.
	diags := smbValidatorDiags(t, map[string]tftypes.Value{
		"full_access": smbStrSet(`BUILTIN\Administrators`),
		"read_access": smbStrSet(`builtin\administrators`),
	})
	if gotErr, _ := smbDiagCounts(diags); gotErr != 1 {
		t.Errorf("expected 1 duplicate error, got %v", smbDiagSummaries(diags))
	}
	// SID-aware duplicate: Everyone vs its canonical SID.
	diags = smbValidatorDiags(t, map[string]tftypes.Value{
		"full_access": smbStrSet("Everyone"),
		"read_access": smbStrSet("S-1-1-1"),
	})
	if gotErr, gotWarn := smbDiagCounts(diags); gotErr != 1 {
		t.Errorf("expected 1 duplicate error (Everyone/S-1-1-1), got errors=%d warnings=%d: %v",
			gotErr, gotWarn, smbDiagSummaries(diags))
	}
}

func TestSmbShareConfigValidator_BroadGrantWarns(t *testing.T) {
	diags := smbValidatorDiags(t, map[string]tftypes.Value{
		"full_access":   smbStrSet("Everyone"),
		"change_access": smbNullSet(),
		"read_access":   smbNullSet(),
	})
	gotErr, gotWarn := smbDiagCounts(diags)
	if gotErr != 0 || gotWarn != 1 {
		t.Errorf("Everyone in full_access should warn once without erroring, got errors=%d warnings=%d: %v",
			gotErr, gotWarn, smbDiagSummaries(diags))
	}
	// Authenticated Users in change_access warns too.
	diags = smbValidatorDiags(t, map[string]tftypes.Value{
		"full_access":   smbNullSet(),
		"change_access": smbStrSet("Authenticated Users"),
		"read_access":   smbNullSet(),
	})
	if gotErr, gotWarn := smbDiagCounts(diags); gotErr != 0 || gotWarn != 1 {
		t.Errorf("Authenticated Users in change_access should warn once, got errors=%d warnings=%d: %v",
			gotErr, gotWarn, smbDiagSummaries(diags))
	}
	// Read access for Everyone is the Windows default shape: no warning.
	diags = smbValidatorDiags(t, map[string]tftypes.Value{
		"full_access":   smbStrSet(`BUILTIN\Administrators`),
		"change_access": smbNullSet(),
		"read_access":   smbStrSet("Everyone"),
	})
	if gotErr, gotWarn := smbDiagCounts(diags); gotErr != 0 || gotWarn != 0 {
		t.Errorf("expected clean config, got errors=%d warnings=%d: %v", gotErr, gotWarn, smbDiagSummaries(diags))
	}
}

func TestWindowsSmbShareResource_ConfigValidatorsPresent(t *testing.T) {
	v := NewWindowsSmbShareResource().(*windowsSmbShareResource).ConfigValidators(context.Background())
	if len(v) == 0 {
		t.Fatal("expected at least one config validator")
	}
}

// ---------------------------------------------------------------------------
// Access-managed helper + identity matching
// ---------------------------------------------------------------------------

func TestSmbShareAccessManaged(t *testing.T) {
	allNull := &windowsSmbShareModel{
		FullAccess: types.SetNull(types.StringType), ChangeAccess: types.SetNull(types.StringType),
		ReadAccess: types.SetNull(types.StringType), NoAccess: types.SetNull(types.StringType),
	}
	if smbShareAccessManaged(allNull) {
		t.Error("all-null sets must be unmanaged")
	}
	// A configured-but-empty set is authoritative, not unmanaged.
	empty, d := types.SetValue(types.StringType, []attr.Value{})
	if d.HasError() {
		t.Fatalf("SetValue: %v", d)
	}
	managed := &windowsSmbShareModel{
		FullAccess: types.SetNull(types.StringType), ChangeAccess: types.SetNull(types.StringType),
		ReadAccess: empty, NoAccess: types.SetNull(types.StringType),
	}
	if !smbShareAccessManaged(managed) {
		t.Error("a configured empty set must be managed (authoritative)")
	}
}

func TestSmbShareIdentityMatches(t *testing.T) {
	tests := []struct {
		name         string
		declared     string
		observedName string
		observedSID  string
		want         bool
	}{
		{"exact sid", "S-1-5-32-544", `BUILTIN\Administrators`, "S-1-5-32-544", true},
		{"exact name", `BUILTIN\Administrators`, `BUILTIN\Administrators`, "S-1-5-32-544", true},
		{"case insensitive", `builtin\administrators`, `BUILTIN\Administrators`, "S-1-5-32-544", true},
		{"bare vs qualified", "tfacc", `HOST01\tfacc`, "S-1-5-21-1-2-3-1001", true},
		{"wrong sid", "S-1-5-32-545", `BUILTIN\Administrators`, "S-1-5-32-544", false},
		{"different account", "svc_app", `HOST01\tfacc`, "S-1-5-21-1-2-3-1001", false},
		{"empty declared", "", "tfacc", "S-1-1", false},
		{"orphaned sid", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1002", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := smbShareIdentityMatches(tc.declared, tc.observedName, tc.observedSID); got != tc.want {
				t.Errorf("smbShareIdentityMatches(%q, %q, %q) = %v, want %v",
					tc.declared, tc.observedName, tc.observedSID, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsSmbShareResource_Create_HappyPath(t *testing.T) {
	fc := &fakeSmbShareClient{createOut: okSmbState("Finance")}
	r := &windowsSmbShareResource{client: fc}

	req := resource.CreateRequest{Plan: smbPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.Name != "Finance" || fc.createIn.Path != `D:\Shares\Finance` {
		t.Errorf("unexpected create input: %+v", fc.createIn)
	}
	if !fc.createIn.ManageAccess {
		t.Error("configured access sets must forward ManageAccess=true")
	}
	var model windowsSmbShareModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Finance" {
		t.Errorf("id = %q, want Finance", model.ID.ValueString())
	}
	if got := smbSetStrings(t, model.FullAccess); len(got) != 1 || got[0] != `BUILTIN\Administrators` {
		t.Errorf("full_access = %v, want operator spelling preserved", got)
	}
}

func TestWindowsSmbShareResource_Create_AlreadyExists(t *testing.T) {
	fc := &fakeSmbShareClient{createErr: winclient.NewSmbShareError(
		winclient.SmbShareErrorAlreadyExists,
		"SMB share Finance already exists. Import it with: terraform import windows_smb_share.finance Finance",
		nil, nil)}
	r := &windowsSmbShareResource{client: fc}

	req := resource.CreateRequest{Plan: smbPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostics on already_exists")
	}
	joined := ""
	for _, d := range smbDiagSummaries(resp.Diagnostics) {
		joined += d
	}
	if !contains(joined, "terraform import") {
		t.Errorf("already_exists diagnostic must suggest import, got: %s", joined)
	}
}

func TestWindowsSmbShareResource_Create_PathNotFound(t *testing.T) {
	fc := &fakeSmbShareClient{createErr: winclient.NewSmbShareError(
		winclient.SmbShareErrorPathNotFound, "share path missing", nil, nil)}
	r := &windowsSmbShareResource{client: fc}

	req := resource.CreateRequest{Plan: smbPlan(t, nil)}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.Create(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on path_not_found")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsSmbShareResource_Read_HappyPath_SIDNoDiff(t *testing.T) {
	observed := okSmbState("Finance")
	observed.ReadAccess = []winclient.SmbShareTrustee{
		{Name: `HOST01\tfacc`, SID: "S-1-5-21-1-2-3-1001"},
		{Name: `HOST01\intruder`, SID: "S-1-5-21-1-2-3-1099"},
	}
	fc := &fakeSmbShareClient{readOut: observed}
	r := &windowsSmbShareResource{client: fc}

	req := resource.ReadRequest{State: smbState(t, map[string]tftypes.Value{
		"read_access": smbStrSet("tfacc"),
	})}
	resp := &resource.ReadResponse{State: smbState(t, map[string]tftypes.Value{
		"read_access": smbStrSet("tfacc"),
	})}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	var model windowsSmbShareModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	got := smbSetStrings(t, model.ReadAccess)
	if len(got) != 2 {
		t.Fatalf("read_access = %v, want [tfacc intruder-drift]", got)
	}
	if got[0] != "tfacc" {
		t.Errorf("operator spelling must survive a SID match, got %v", got)
	}
}

func TestWindowsSmbShareResource_Read_UnmanagedKeepsNull(t *testing.T) {
	fc := &fakeSmbShareClient{readOut: okSmbState("Finance")}
	r := &windowsSmbShareResource{client: fc}

	overrides := map[string]tftypes.Value{
		"full_access": smbNullSet(), "change_access": smbNullSet(),
		"read_access": smbNullSet(), "no_access": smbNullSet(),
	}
	req := resource.ReadRequest{State: smbState(t, overrides)}
	resp := &resource.ReadResponse{State: smbState(t, overrides)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	var model windowsSmbShareModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if !model.FullAccess.IsNull() || !model.ReadAccess.IsNull() {
		t.Error("unmanaged (all-null) sets must stay null after Read")
	}
}

func TestWindowsSmbShareResource_Read_ManagedPartialNull_ShowsDrift(t *testing.T) {
	// Full is configured (managed) while read is omitted (null): the host's
	// Everyone:Read entry — the New-SmbShare default — must surface as drift
	// instead of staying invisible, so the next plan revokes it.
	observed := okSmbState("Finance")
	observed.ReadAccess = []winclient.SmbShareTrustee{{Name: "Everyone", SID: "S-1-1-1"}}
	fc := &fakeSmbShareClient{readOut: observed}
	r := &windowsSmbShareResource{client: fc}

	overrides := map[string]tftypes.Value{
		"full_access": smbStrSet(`BUILTIN\Administrators`), "change_access": smbNullSet(),
		"read_access": smbNullSet(), "no_access": smbNullSet(),
	}
	req := resource.ReadRequest{State: smbState(t, overrides)}
	resp := &resource.ReadResponse{State: smbState(t, overrides)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	var model windowsSmbShareModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ReadAccess.IsNull() {
		t.Fatal("managed null read_access must become non-null when the host carries Everyone:Read (drift invisible otherwise)")
	}
	got := smbSetStrings(t, model.ReadAccess)
	if len(got) != 1 || got[0] != "Everyone" {
		t.Errorf("read_access = %v, want [Everyone] so the plan revokes it", got)
	}
}

func TestWindowsSmbShareResource_Read_ManagedPartialNull_EmptyStaysNull(t *testing.T) {
	// Managed but nothing observed at that level: keep null so a null plan
	// converges instead of perpetual-diffing null vs empty.
	observed := okSmbState("Finance")
	observed.ChangeAccess = []winclient.SmbShareTrustee{}
	fc := &fakeSmbShareClient{readOut: observed}
	r := &windowsSmbShareResource{client: fc}

	overrides := map[string]tftypes.Value{
		"change_access": smbNullSet(),
	}
	req := resource.ReadRequest{State: smbState(t, overrides)}
	resp := &resource.ReadResponse{State: smbState(t, overrides)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	var model windowsSmbShareModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if !model.ChangeAccess.IsNull() {
		t.Errorf("managed null change_access with nothing observed must stay null, got %v", smbSetStrings(t, model.ChangeAccess))
	}
}

func TestSmbShareAccessManaged_UnknownIsNotManaged(t *testing.T) {
	m := &windowsSmbShareModel{
		FullAccess: types.SetUnknown(types.StringType), ChangeAccess: types.SetNull(types.StringType),
		ReadAccess: types.SetNull(types.StringType), NoAccess: types.SetNull(types.StringType),
	}
	if smbShareAccessManaged(m) {
		t.Error("an unknown set must not flip the access list into managed mode")
	}
	var diags diag.Diagnostics
	if _, ok := smbShareSettingsFromModel(context.Background(), m, &diags); ok {
		t.Error("unknown access sets must abort settings with a deferring diagnostic")
	}
	if !diags.HasError() {
		t.Error("expected a deferring diagnostic for unknown access sets")
	}
}

func TestWindowsSmbShareResource_Read_NotFound_RemovesResource(t *testing.T) {
	fc := &fakeSmbShareClient{readOut: nil}
	r := &windowsSmbShareResource{client: fc}

	req := resource.ReadRequest{State: smbState(t, nil)}
	resp := &resource.ReadResponse{State: smbState(t, nil)}
	r.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("expected state to be removed (null) when the share is absent")
	}
}

func TestWindowsSmbShareResource_Read_Error(t *testing.T) {
	fc := &fakeSmbShareClient{readErr: winclient.NewSmbShareError(winclient.SmbShareErrorAccessDenied, "denied", nil, nil)}
	r := &windowsSmbShareResource{client: fc}

	req := resource.ReadRequest{State: smbState(t, nil)}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on client error")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestWindowsSmbShareResource_Update_HappyPath(t *testing.T) {
	updated := okSmbState("Finance")
	updated.EncryptData = true
	fc := &fakeSmbShareClient{updateOut: updated}
	r := &windowsSmbShareResource{client: fc}

	req := resource.UpdateRequest{Plan: smbPlan(t, nil), State: smbState(t, nil)}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	if fc.updateIn.Name != "Finance" {
		t.Errorf("unexpected update input: %+v", fc.updateIn)
	}
	if !fc.updateIn.ManageAccess {
		t.Error("configured access sets must forward ManageAccess=true on update")
	}
}

func TestWindowsSmbShareResource_Update_Unmanaged(t *testing.T) {
	fc := &fakeSmbShareClient{updateOut: okSmbState("Finance")}
	r := &windowsSmbShareResource{client: fc}

	overrides := map[string]tftypes.Value{
		"full_access": smbNullSet(), "change_access": smbNullSet(),
		"read_access": smbNullSet(), "no_access": smbNullSet(),
	}
	req := resource.UpdateRequest{Plan: smbPlan(t, overrides), State: smbState(t, overrides)}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	if fc.updateIn.ManageAccess {
		t.Error("all-null sets must forward ManageAccess=false on update")
	}
}

func TestWindowsSmbShareResource_Update_NotFound(t *testing.T) {
	fc := &fakeSmbShareClient{updateErr: winclient.NewSmbShareError(winclient.SmbShareErrorNotFound, "gone", nil, nil)}
	r := &windowsSmbShareResource{client: fc}

	req := resource.UpdateRequest{Plan: smbPlan(t, nil), State: smbState(t, nil)}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.Update(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics when the share vanished (no silent recreate)")
	}
}

func TestWindowsSmbShareResource_Delete_HappyPath(t *testing.T) {
	fc := &fakeSmbShareClient{}
	r := &windowsSmbShareResource{client: fc}

	req := resource.DeleteRequest{State: smbState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	if fc.deleteName != "Finance" {
		t.Errorf("unexpected delete name: %q", fc.deleteName)
	}
}

func TestWindowsSmbShareResource_Delete_Error(t *testing.T) {
	fc := &fakeSmbShareClient{deleteErr: winclient.NewSmbShareError(winclient.SmbShareErrorAccessDenied, "denied", nil, nil)}
	r := &windowsSmbShareResource{client: fc}

	req := resource.DeleteRequest{State: smbState(t, nil)}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostics on client error")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsSmbShareResource_ImportState_HappyPath(t *testing.T) {
	fc := &fakeSmbShareClient{readOut: okSmbState("Finance")}
	r := &windowsSmbShareResource{client: fc}

	req := resource.ImportStateRequest{ID: "Finance"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", smbDiagSummaries(resp.Diagnostics))
	}
	var model windowsSmbShareModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Name.ValueString() != "Finance" || model.Path.ValueString() != `D:\Shares\Finance` {
		t.Errorf("unexpected imported state: name=%q path=%q", model.Name.ValueString(), model.Path.ValueString())
	}
	// Import starts unmanaged: declaring the sets takes over authoritatively.
	if !model.FullAccess.IsNull() || !model.ReadAccess.IsNull() {
		t.Error("imported access sets must start null (unmanaged)")
	}
	if model.Special.ValueBool() {
		t.Error("imported special must be false for a regular share")
	}
}

func TestWindowsSmbShareResource_ImportState_NotFound(t *testing.T) {
	fc := &fakeSmbShareClient{readOut: nil}
	r := &windowsSmbShareResource{client: fc}

	req := resource.ImportStateRequest{ID: "Finance"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Error("expected diagnostic error when importing a non-existent share")
	}
}

// Special shares that still pass name validation (e.g. the print$ printer
// driver share) are refused with a dedicated diagnostic; reserved names such
// as ADMIN$/C$/IPC$ never reach this guard because ID validation stops them.
func TestWindowsSmbShareResource_ImportState_SpecialRejected(t *testing.T) {
	special := okSmbState("print$")
	special.Special = true
	fc := &fakeSmbShareClient{readOut: special}
	r := &windowsSmbShareResource{client: fc}

	req := resource.ImportStateRequest{ID: "print$"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic error when importing a special share")
	}
	found := false
	for _, d := range smbDiagSummaries(resp.Diagnostics) {
		if contains(d, "special") {
			found = true
		}
	}
	if !found {
		t.Errorf("special-share rejection must say so, got: %v", smbDiagSummaries(resp.Diagnostics))
	}
}

func TestWindowsSmbShareResource_ImportState_InvalidID(t *testing.T) {
	r := &windowsSmbShareResource{client: &fakeSmbShareClient{}}
	for _, id := range []string{"", "IPC$", "C$"} {
		req := resource.ImportStateRequest{ID: id}
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}
		r.ImportState(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("expected diagnostic error for import ID %q", id)
		}
	}
}

// -----------------------------------------------------------------------------
// Timeouts: a stalled remote command must surface a bounded diagnostic
// instead of blocking Terraform indefinitely.
// -----------------------------------------------------------------------------

func TestWindowsSmbShareSchema_HasTimeoutsBlock(t *testing.T) {
	s := windowsSmbShareSchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block: CRUD must be time-bounded")
	}
}

// hangSmbShareClient simulates a stalled transport: Create blocks until the
// passed context is done, then returns the context error.
type hangSmbShareClient struct {
	fakeSmbShareClient
}

func (f *hangSmbShareClient) Create(ctx context.Context, in winclient.SmbShareInput) (*winclient.SmbShareInfo, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// smbTimeoutsRaw builds the raw tftypes value for a timeouts block carrying
// the given per-operation durations.
func smbTimeoutsRaw(durations map[string]string) tftypes.Value {
	vals := map[string]tftypes.Value{
		"create": tftypes.NewValue(tftypes.String, nil),
		"read":   tftypes.NewValue(tftypes.String, nil),
		"update": tftypes.NewValue(tftypes.String, nil),
		"delete": tftypes.NewValue(tftypes.String, nil),
	}
	for op, d := range durations {
		vals[op] = tftypes.NewValue(tftypes.String, d)
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, vals)
}

// mustSmbTimeouts decodes smbTimeoutsRaw through the resource schema, the
// same path the framework takes for real plans.
func mustSmbTimeouts(t *testing.T, durations map[string]string) timeouts.Value {
	t.Helper()
	ctx := context.Background()
	plan := tfsdk.Plan{
		Schema: windowsSmbShareSchemaDefinition(ctx),
		Raw: smbObj(map[string]tftypes.Value{
			"timeouts": smbTimeoutsRaw(durations),
		}),
	}
	var m windowsSmbShareModel
	if diags := plan.Get(ctx, &m); diags.HasError() {
		t.Fatalf("plan.Get timeouts: %v", diags)
	}
	return m.Timeouts
}

func TestWindowsSmbShareModelFromState_PreservesTimeouts(t *testing.T) {
	prior := windowsSmbShareModel{
		Timeouts: mustSmbTimeouts(t, map[string]string{"create": "5m"}),
	}
	// applySmbShareInfo projects onto the caller's model; timeouts configured
	// by the operator must survive the projection.
	m := prior
	applySmbShareInfo(context.Background(), &m, okSmbState("Finance"), &diag.Diagnostics{})
	got, diags := m.Timeouts.Create(context.Background(), smbShareDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("Timeouts.Create: %v", diags)
	}
	if got != 5*time.Minute {
		t.Errorf("Timeouts not preserved through applySmbShareInfo: create = %v, want 5m", got)
	}
}

func TestWindowsSmbShareResource_Create_StalledTransportIsBounded(t *testing.T) {
	r := &windowsSmbShareResource{client: &hangSmbShareClient{}}

	req := resource.CreateRequest{Plan: smbPlan(t, map[string]tftypes.Value{
		"timeouts": smbTimeoutsRaw(map[string]string{"create": "200ms"}),
	})}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsSmbShareSchemaDefinition(context.Background())}}

	start := time.Now()
	r.Create(context.Background(), req, resp)
	elapsed := time.Since(start)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag when the transport stalls past the create timeout")
	}
	if elapsed > 30*time.Second {
		t.Errorf("Create blocked for %v with a 200ms timeout", elapsed)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
