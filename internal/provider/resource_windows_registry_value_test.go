// Package provider — unit tests for windows_registry_value resource.
//
// These tests exercise validators, helpers, and CRUD handlers without WinRM.
// A fakeRegistryValueClient is injected into windowsRegistryValueResource.client.
//
// Edge cases covered (aligned with spec EC-* identifiers):
//
//	CV-1  REG_SZ/REG_EXPAND_SZ: value_string required + no conflict attrs
//	CV-2  REG_DWORD: value_string required, uint32 range
//	CV-3  REG_QWORD: value_string required, uint64 range
//	CV-4  REG_MULTI_SZ: value_strings required (empty [] valid)
//	CV-5  REG_BINARY: value_binary required
//	CV-6  REG_NONE: no value attrs allowed
//	CV-7  expand_environment_variables=true requires REG_EXPAND_SZ
//	EC-3  Create: type_conflict → diagnostic error
//	EC-4  Read: value not found → RemoveResource
//	EC-12 Delete: idempotent (transparent to provider)
//	EC-13 ImportState: malformed ID → diagnostic error
//	hiveEnumValidator: valid/invalid/null/unknown hive
//	registryPathValidator: valid path / hive prefix / regex fail
//	hexEvenLengthValidator: odd/even lengths
//	hiveNormalizePlanModifier: lowercase → uppercase normalisation
//	addRVDiag: type_conflict / permission / invalid_input / unknown / plain error
//	rvID: composite ID format
//	rvModelToInput: model → input conversion for all types
//	applyRVState: state update for all 7 value kinds
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeRegistryValueClient
// ---------------------------------------------------------------------------

type fakeRegistryValueClient struct {
	setOut    *winclient.RegistryValueState
	setErr    error
	readOut   *winclient.RegistryValueState
	readErr   error
	deleteErr error

	lastSetInput   winclient.RegistryValueInput
	lastReadHive   string
	lastReadPath   string
	lastReadName   string
	deleteCalled   bool
}

func (f *fakeRegistryValueClient) Set(_ context.Context, input winclient.RegistryValueInput) (*winclient.RegistryValueState, error) {
	f.lastSetInput = input
	return f.setOut, f.setErr
}
func (f *fakeRegistryValueClient) Read(_ context.Context, hive, path, name string, _ bool) (*winclient.RegistryValueState, error) {
	f.lastReadHive = hive
	f.lastReadPath = path
	f.lastReadName = name
	return f.readOut, f.readErr
}
func (f *fakeRegistryValueClient) Delete(_ context.Context, _, _, _ string) error {
	f.deleteCalled = true
	return f.deleteErr
}

// ---------------------------------------------------------------------------
// tftypes helpers for registry value schema
// ---------------------------------------------------------------------------

func registryValueObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                           tftypes.String,
		"hive":                         tftypes.String,
		"path":                         tftypes.String,
		"name":                         tftypes.String,
		"type":                         tftypes.String,
		"value_string":                 tftypes.String,
		"value_strings":                tftypes.List{ElementType: tftypes.String},
		"value_binary":                 tftypes.String,
		"expand_environment_variables": tftypes.Bool,
	}}
}

// rvObjBase returns the base tftypes.Value map with sensible REG_SZ defaults.
func rvObjBase() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"id":                           tftypes.NewValue(tftypes.String, nil),
		"hive":                         tftypes.NewValue(tftypes.String, "HKLM"),
		"path":                         tftypes.NewValue(tftypes.String, `SOFTWARE\MyApp`),
		"name":                         tftypes.NewValue(tftypes.String, "Version"),
		"type":                         tftypes.NewValue(tftypes.String, "REG_SZ"),
		"value_string":                 tftypes.NewValue(tftypes.String, "1.0.0"),
		"value_strings":                tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
		"value_binary":                 tftypes.NewValue(tftypes.String, nil),
		"expand_environment_variables": tftypes.NewValue(tftypes.Bool, false),
	}
}

// rvObj builds a tftypes.Value with defaults overridden by the given map.
func rvObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := rvObjBase()
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(registryValueObjectType(), base)
}

// rvConfig builds a tfsdk.Config for the registry value schema.
func rvConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsRegistryValueSchemaDefinition()
	return tfsdk.Config{Raw: rvObj(overrides), Schema: s}
}

// okRVState returns a minimal RegistryValueState for mocking Set/Read returns.
func okRVState(kind winclient.RegistryValueKind) *winclient.RegistryValueState {
	s := &winclient.RegistryValueState{
		Hive: "HKLM",
		Path: `SOFTWARE\MyApp`,
		Name: "Version",
		Kind: kind,
	}
	switch kind {
	case winclient.RegistryValueKindMultiString:
		s.ValueStrings = []string{"hello", "world"}
	case winclient.RegistryValueKindBinary, winclient.RegistryValueKindNone:
		empty := "deadbeef"
		s.ValueBinary = &empty
	default:
		v := "1.0.0"
		s.ValueString = &v
	}
	return s
}

// rvDiagSummaries extracts diagnostic summaries for assertion helpers.
func rvDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata + Schema
// ---------------------------------------------------------------------------

func TestRegistryValueMetadata(t *testing.T) {
	r := &windowsRegistryValueResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_registry_value" {
		t.Errorf("TypeName = %q, want windows_registry_value", resp.TypeName)
	}
}

func TestRegistryValueSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsRegistryValueSchemaDefinition()
	for _, k := range []string{
		"id", "hive", "path", "name", "type",
		"value_string", "value_strings", "value_binary",
		"expand_environment_variables",
	} {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestRegistryValueSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsRegistryValueResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

func TestRegistryValueConfigValidators_NotEmpty(t *testing.T) {
	r := &windowsRegistryValueResource{}
	vs := r.ConfigValidators(context.Background())
	if len(vs) == 0 {
		t.Error("ConfigValidators must return at least one validator")
	}
}

// ---------------------------------------------------------------------------
// hiveEnumValidator
// ---------------------------------------------------------------------------

func TestHiveEnumValidator_ValidHives(t *testing.T) {
	v := hiveEnumValidator{}
	for _, hive := range []string{"HKLM", "hklm", "HKCU", "hkcu", "HKCR", "hkcr", "HKU", "hku", "HKCC", "hkcc"} {
		req := validator.StringRequest{
			Path:        path.Root("hive"),
			ConfigValue: types.StringValue(hive),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("hive %q should be valid, got diag: %v", hive, resp.Diagnostics)
		}
	}
}

func TestHiveEnumValidator_InvalidHive(t *testing.T) {
	v := hiveEnumValidator{}
	for _, hive := range []string{"HKEY_LOCAL_MACHINE", "invalid", "", "HKXX"} {
		req := validator.StringRequest{
			Path:        path.Root("hive"),
			ConfigValue: types.StringValue(hive),
		}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("hive %q should be invalid", hive)
		}
	}
}

func TestHiveEnumValidator_NullUnknown(t *testing.T) {
	v := hiveEnumValidator{}
	// Null — no error
	req := validator.StringRequest{Path: path.Root("hive"), ConfigValue: types.StringNull()}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null hive should not produce error")
	}
	// Unknown — no error
	req2 := validator.StringRequest{Path: path.Root("hive"), ConfigValue: types.StringUnknown()}
	resp2 := &validator.StringResponse{}
	v.ValidateString(context.Background(), req2, resp2)
	if resp2.Diagnostics.HasError() {
		t.Error("unknown hive should not produce error")
	}
}

func TestHiveEnumValidator_Descriptions(t *testing.T) {
	v := hiveEnumValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

// ---------------------------------------------------------------------------
// registryPathValidator
// ---------------------------------------------------------------------------

func TestRegistryPathValidator_ValidPaths(t *testing.T) {
	v := registryPathValidator{}
	for _, p := range []string{
		`SOFTWARE\MyApp`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`MyKey`,
		`A\B\C`,
	} {
		req := validator.StringRequest{Path: path.Root("path"), ConfigValue: types.StringValue(p)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("path %q should be valid", p)
		}
	}
}

func TestRegistryPathValidator_HivePrefix(t *testing.T) {
	v := registryPathValidator{}
	for _, p := range []string{
		`HKLM\SOFTWARE\MyApp`,
		`hklm\SOFTWARE`,
		`HKEY_LOCAL_MACHINE\SOFTWARE`,
		`HKCU\SOFTWARE`,
	} {
		req := validator.StringRequest{Path: path.Root("path"), ConfigValue: types.StringValue(p)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("path with hive prefix %q should be invalid (EC-6b)", p)
		}
	}
}

func TestRegistryPathValidator_InvalidPaths(t *testing.T) {
	v := registryPathValidator{}
	// Leading backslash, trailing backslash, empty, double backslash
	for _, p := range []string{`\SOFTWARE`, `SOFTWARE\`, ``, `SOFTWARE\\MyApp`} {
		req := validator.StringRequest{Path: path.Root("path"), ConfigValue: types.StringValue(p)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("path %q should be invalid", p)
		}
	}
}

func TestRegistryPathValidator_NullUnknown(t *testing.T) {
	v := registryPathValidator{}
	req := validator.StringRequest{Path: path.Root("path"), ConfigValue: types.StringNull()}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null path should not produce error")
	}
}

func TestRegistryPathValidator_Descriptions(t *testing.T) {
	v := registryPathValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

// ---------------------------------------------------------------------------
// hexEvenLengthValidator
// ---------------------------------------------------------------------------

func TestHexEvenLengthValidator_EvenLength(t *testing.T) {
	v := hexEvenLengthValidator{}
	for _, hex := range []string{"", "ab", "deadbeef", "0102030405060708"} {
		req := validator.StringRequest{Path: path.Root("value_binary"), ConfigValue: types.StringValue(hex)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("hex %q (len=%d) should be valid", hex, len(hex))
		}
	}
}

func TestHexEvenLengthValidator_OddLength(t *testing.T) {
	v := hexEvenLengthValidator{}
	for _, hex := range []string{"a", "abc", "deadbee"} {
		req := validator.StringRequest{Path: path.Root("value_binary"), ConfigValue: types.StringValue(hex)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("hex %q (len=%d) should be invalid (EC-8)", hex, len(hex))
		}
	}
}

func TestHexEvenLengthValidator_NullValue(t *testing.T) {
	v := hexEvenLengthValidator{}
	req := validator.StringRequest{Path: path.Root("value_binary"), ConfigValue: types.StringNull()}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value_binary should not produce error")
	}
}

func TestHexEvenLengthValidator_Descriptions(t *testing.T) {
	v := hexEvenLengthValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

// ---------------------------------------------------------------------------
// hiveNormalizePlanModifier
// ---------------------------------------------------------------------------

func TestHiveNormalizePlanModifier_LowercaseToUpper(t *testing.T) {
	m := hiveNormalizePlanModifier{}
	req := planmodifier.StringRequest{ConfigValue: types.StringValue("hklm")}
	resp := &planmodifier.StringResponse{PlanValue: req.ConfigValue}
	m.PlanModifyString(context.Background(), req, resp)
	if resp.PlanValue.ValueString() != "HKLM" {
		t.Errorf("PlanValue = %q, want HKLM", resp.PlanValue.ValueString())
	}
}

func TestHiveNormalizePlanModifier_AlreadyUpper(t *testing.T) {
	m := hiveNormalizePlanModifier{}
	req := planmodifier.StringRequest{ConfigValue: types.StringValue("HKCU")}
	resp := &planmodifier.StringResponse{PlanValue: req.ConfigValue}
	m.PlanModifyString(context.Background(), req, resp)
	if resp.PlanValue.ValueString() != "HKCU" {
		t.Errorf("PlanValue = %q, want HKCU", resp.PlanValue.ValueString())
	}
}

func TestHiveNormalizePlanModifier_NullNotModified(t *testing.T) {
	m := hiveNormalizePlanModifier{}
	req := planmodifier.StringRequest{ConfigValue: types.StringNull()}
	resp := &planmodifier.StringResponse{PlanValue: req.ConfigValue}
	m.PlanModifyString(context.Background(), req, resp)
	if !resp.PlanValue.IsNull() {
		t.Error("null config value should not be modified")
	}
}

func TestHiveNormalizePlanModifier_Descriptions(t *testing.T) {
	m := hiveNormalizePlanModifier{}
	if m.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if m.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators — CV-1..CV-7
// ---------------------------------------------------------------------------

// buildRVValidateReq builds a resource.ValidateConfigRequest for the CV tests.
func buildRVValidateReq(t *testing.T, overrides map[string]tftypes.Value) resource.ValidateConfigRequest {
	t.Helper()
	return resource.ValidateConfigRequest{Config: rvConfig(t, overrides)}
}

// CV-1: REG_SZ — value_string required + non-empty
func TestCV1_REG_SZ_Valid(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, nil) // defaults: type=REG_SZ, value_string="1.0.0"
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_SZ with value_string should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV1_REG_SZ_MissingValueString(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"value_string": tftypes.NewValue(tftypes.String, nil),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_SZ without value_string should fail CV-1")
	}
}

func TestCV1_REG_SZ_EmptyValueString(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"value_string": tftypes.NewValue(tftypes.String, ""),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_SZ with empty value_string should fail CV-1")
	}
}

func TestCV1_REG_SZ_ForbiddenValueStrings(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"value_strings": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "x"),
		}),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_SZ with value_strings set should fail CV-1")
	}
}

func TestCV1_REG_SZ_ForbiddenValueBinary(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"value_binary": tftypes.NewValue(tftypes.String, "deadbeef"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_SZ with value_binary set should fail CV-1")
	}
}

func TestCV1_REG_EXPAND_SZ_Valid(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_EXPAND_SZ"),
		"value_string": tftypes.NewValue(tftypes.String, "%PATH%"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_EXPAND_SZ with value_string should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

// CV-2: REG_DWORD
func TestCV2_REG_DWORD_Valid(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_DWORD"),
		"value_string": tftypes.NewValue(tftypes.String, "4294967295"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_DWORD with valid uint32 should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV2_REG_DWORD_MissingValueString(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_DWORD"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_DWORD without value_string should fail CV-2")
	}
}

func TestCV2_REG_DWORD_Overflow(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_DWORD"),
		"value_string": tftypes.NewValue(tftypes.String, "4294967296"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_DWORD overflow should fail CV-2")
	}
}

func TestCV2_REG_DWORD_ForbiddenValueStrings(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_DWORD"),
		"value_string": tftypes.NewValue(tftypes.String, "42"),
		"value_strings": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "x"),
		}),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_DWORD with value_strings should fail CV-2")
	}
}

// CV-3: REG_QWORD
func TestCV3_REG_QWORD_Valid(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_QWORD"),
		"value_string": tftypes.NewValue(tftypes.String, "18446744073709551615"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_QWORD with valid uint64 should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV3_REG_QWORD_Overflow(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_QWORD"),
		"value_string": tftypes.NewValue(tftypes.String, "18446744073709551616"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_QWORD overflow should fail CV-3")
	}
}

func TestCV3_REG_QWORD_ForbiddenValueBinary(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_QWORD"),
		"value_string": tftypes.NewValue(tftypes.String, "42"),
		"value_binary": tftypes.NewValue(tftypes.String, "deadbeef"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_QWORD with value_binary should fail CV-3")
	}
}

// CV-4: REG_MULTI_SZ
func TestCV4_REG_MULTI_SZ_Valid(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_MULTI_SZ"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
		"value_strings": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "line1"),
			tftypes.NewValue(tftypes.String, "line2"),
		}),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_MULTI_SZ with value_strings should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV4_REG_MULTI_SZ_EmptyList(t *testing.T) {
	// EC-10: empty value_strings is valid
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":          tftypes.NewValue(tftypes.String, "REG_MULTI_SZ"),
		"value_string":  tftypes.NewValue(tftypes.String, nil),
		"value_strings": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_MULTI_SZ with empty value_strings should be valid (EC-10): %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV4_REG_MULTI_SZ_MissingValueStrings(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_MULTI_SZ"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
		// value_strings = null (the default)
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_MULTI_SZ without value_strings should fail CV-4")
	}
}

func TestCV4_REG_MULTI_SZ_ForbiddenValueString(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type": tftypes.NewValue(tftypes.String, "REG_MULTI_SZ"),
		// value_string still has default "1.0.0" unless cleared
		"value_strings": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{}),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_MULTI_SZ with value_string set should fail CV-4")
	}
}

// CV-5: REG_BINARY
func TestCV5_REG_BINARY_Valid(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_BINARY"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
		"value_binary": tftypes.NewValue(tftypes.String, "deadbeef"),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_BINARY with value_binary should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV5_REG_BINARY_EmptyHex(t *testing.T) {
	// Empty hex (zero bytes) is valid for REG_BINARY
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_BINARY"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
		"value_binary": tftypes.NewValue(tftypes.String, ""),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_BINARY with empty hex should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV5_REG_BINARY_MissingValueBinary(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_BINARY"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
		// value_binary = null
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_BINARY without value_binary should fail CV-5")
	}
}

func TestCV5_REG_BINARY_ForbiddenValueString(t *testing.T) {
	// value_string still has default "1.0.0" — forbidden for REG_BINARY
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_BINARY"),
		"value_binary": tftypes.NewValue(tftypes.String, "deadbeef"),
		// value_string remains "1.0.0" from defaults
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_BINARY with value_string set should fail CV-5")
	}
}

// CV-6: REG_NONE
func TestCV6_REG_NONE_Valid(t *testing.T) {
	// REG_NONE with no value attrs set is valid
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_NONE"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_NONE with no value attrs should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV6_REG_NONE_WithValueBinary(t *testing.T) {
	// value_binary is permitted for REG_NONE (no restriction in CV-6)
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_NONE"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
		"value_binary": tftypes.NewValue(tftypes.String, ""),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("REG_NONE with value_binary should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV6_REG_NONE_ForbiddenValueString(t *testing.T) {
	// value_string "1.0.0" still in defaults — should fail
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type": tftypes.NewValue(tftypes.String, "REG_NONE"),
		// value_string remains "1.0.0" from default
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_NONE with value_string set should fail CV-6")
	}
}

func TestCV6_REG_NONE_ForbiddenValueStrings(t *testing.T) {
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_NONE"),
		"value_string": tftypes.NewValue(tftypes.String, nil),
		"value_strings": tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "x"),
		}),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("REG_NONE with value_strings set should fail CV-6")
	}
}

func TestCV_TypeNull_NoError(t *testing.T) {
	// type is null — validator should skip
	v := registryValueTypeDataValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, nil),
		"value_string": tftypes.NewValue(tftypes.String, nil),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null type should not produce error")
	}
}

func TestCV_Descriptions(t *testing.T) {
	v := registryValueTypeDataValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

// CV-7: expand_environment_variables
func TestCV7_ExpandEnvVars_ValidWithREG_EXPAND_SZ(t *testing.T) {
	v := registryValueExpandEnvVarsValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"type":                         tftypes.NewValue(tftypes.String, "REG_EXPAND_SZ"),
		"value_string":                 tftypes.NewValue(tftypes.String, "%PATH%"),
		"expand_environment_variables": tftypes.NewValue(tftypes.Bool, true),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("expand=true with REG_EXPAND_SZ should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV7_ExpandEnvVars_InvalidWithREG_SZ(t *testing.T) {
	v := registryValueExpandEnvVarsValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"expand_environment_variables": tftypes.NewValue(tftypes.Bool, true),
		// type remains "REG_SZ" from defaults
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expand=true with REG_SZ should fail CV-7")
	}
}

func TestCV7_ExpandEnvVars_FalseWithREG_SZ_NoError(t *testing.T) {
	v := registryValueExpandEnvVarsValidator{}
	req := buildRVValidateReq(t, nil) // expand=false (default), type=REG_SZ
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("expand=false with REG_SZ should be valid: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestCV7_ExpandEnvVars_NullExpand_NoError(t *testing.T) {
	v := registryValueExpandEnvVarsValidator{}
	req := buildRVValidateReq(t, map[string]tftypes.Value{
		"expand_environment_variables": tftypes.NewValue(tftypes.Bool, nil),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null expand should not produce error")
	}
}

func TestCV7_Descriptions(t *testing.T) {
	v := registryValueExpandEnvVarsValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

// ---------------------------------------------------------------------------
// Configure handler
// ---------------------------------------------------------------------------

func TestRegistryValueConfigure_NilData(t *testing.T) {
	r := &windowsRegistryValueResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Error("nil ProviderData must not produce error")
	}
}

func TestRegistryValueConfigure_WrongType(t *testing.T) {
	r := &windowsRegistryValueResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong ProviderData type must produce error")
	}
}

// ---------------------------------------------------------------------------
// rvID helper
// ---------------------------------------------------------------------------

func TestRvID_NamedValue(t *testing.T) {
	id := rvID("HKLM", `SOFTWARE\MyApp`, "Version")
	want := `HKLM\SOFTWARE\MyApp\Version`
	if id != want {
		t.Errorf("rvID = %q, want %q", id, want)
	}
}

func TestRvID_DefaultValue(t *testing.T) {
	id := rvID("HKCU", `Software\Test`, "")
	want := `HKCU\Software\Test\`
	if id != want {
		t.Errorf("rvID default value = %q, want %q", id, want)
	}
}

// ---------------------------------------------------------------------------
// rvModelToInput — model → input conversion
// ---------------------------------------------------------------------------

func TestRvModelToInput_REG_SZ(t *testing.T) {
	m := &windowsRegistryValueModel{
		Hive:                       types.StringValue("HKLM"),
		Path:                       types.StringValue(`SOFTWARE\MyApp`),
		Name:                       types.StringValue("Version"),
		Type:                       types.StringValue("REG_SZ"),
		ValueString:                types.StringValue("hello"),
		ValueStrings:               types.ListNull(types.StringType),
		ValueBinary:                types.StringNull(),
		ExpandEnvironmentVariables: types.BoolValue(false),
	}
	input, err := rvModelToInput(m)
	if err != nil {
		t.Fatalf("rvModelToInput: %v", err)
	}
	if input.Kind != winclient.RegistryValueKindString {
		t.Errorf("Kind = %q", input.Kind)
	}
	if input.ValueString == nil || *input.ValueString != "hello" {
		t.Errorf("ValueString = %v", input.ValueString)
	}
}

func TestRvModelToInput_REG_MULTI_SZ(t *testing.T) {
	lst, _ := types.ListValue(types.StringType, []attr.Value{
		types.StringValue("a"),
		types.StringValue("b"),
	})
	m := &windowsRegistryValueModel{
		Hive:                       types.StringValue("HKLM"),
		Path:                       types.StringValue(`SOFTWARE\Test`),
		Name:                       types.StringValue("Multi"),
		Type:                       types.StringValue("REG_MULTI_SZ"),
		ValueString:                types.StringNull(),
		ValueStrings:               lst,
		ValueBinary:                types.StringNull(),
		ExpandEnvironmentVariables: types.BoolValue(false),
	}
	input, err := rvModelToInput(m)
	if err != nil {
		t.Fatalf("rvModelToInput: %v", err)
	}
	if input.Kind != winclient.RegistryValueKindMultiString {
		t.Errorf("Kind = %q", input.Kind)
	}
	if len(input.ValueStrings) != 2 || input.ValueStrings[0] != "a" {
		t.Errorf("ValueStrings = %v", input.ValueStrings)
	}
}

func TestRvModelToInput_REG_MULTI_SZ_Null(t *testing.T) {
	m := &windowsRegistryValueModel{
		Hive:                       types.StringValue("HKLM"),
		Path:                       types.StringValue(`SOFTWARE\Test`),
		Name:                       types.StringValue("Multi"),
		Type:                       types.StringValue("REG_MULTI_SZ"),
		ValueString:                types.StringNull(),
		ValueStrings:               types.ListNull(types.StringType),
		ValueBinary:                types.StringNull(),
		ExpandEnvironmentVariables: types.BoolValue(false),
	}
	input, err := rvModelToInput(m)
	if err != nil {
		t.Fatalf("rvModelToInput: %v", err)
	}
	// Null value_strings → empty slice
	if input.ValueStrings == nil || len(input.ValueStrings) != 0 {
		t.Errorf("null ValueStrings should produce empty slice, got %v", input.ValueStrings)
	}
}

func TestRvModelToInput_REG_BINARY(t *testing.T) {
	m := &windowsRegistryValueModel{
		Hive:                       types.StringValue("HKLM"),
		Path:                       types.StringValue(`SOFTWARE\Test`),
		Name:                       types.StringValue("Bin"),
		Type:                       types.StringValue("REG_BINARY"),
		ValueString:                types.StringNull(),
		ValueStrings:               types.ListNull(types.StringType),
		ValueBinary:                types.StringValue("deadbeef"),
		ExpandEnvironmentVariables: types.BoolValue(false),
	}
	input, err := rvModelToInput(m)
	if err != nil {
		t.Fatalf("rvModelToInput: %v", err)
	}
	if input.Kind != winclient.RegistryValueKindBinary {
		t.Errorf("Kind = %q", input.Kind)
	}
	if input.ValueBinary == nil || *input.ValueBinary != "deadbeef" {
		t.Errorf("ValueBinary = %v", input.ValueBinary)
	}
}

func TestRvModelToInput_REG_NONE_NullBinary(t *testing.T) {
	m := &windowsRegistryValueModel{
		Hive:                       types.StringValue("HKLM"),
		Path:                       types.StringValue(`SOFTWARE\Test`),
		Name:                       types.StringValue("None"),
		Type:                       types.StringValue("REG_NONE"),
		ValueString:                types.StringNull(),
		ValueStrings:               types.ListNull(types.StringType),
		ValueBinary:                types.StringNull(),
		ExpandEnvironmentVariables: types.BoolValue(false),
	}
	input, err := rvModelToInput(m)
	if err != nil {
		t.Fatalf("rvModelToInput: %v", err)
	}
	// Null ValueBinary → empty string pointer
	if input.ValueBinary == nil {
		t.Error("null ValueBinary should produce pointer to empty string")
	}
}

// ---------------------------------------------------------------------------
// applyRVState — state update for all 7 value kinds
// ---------------------------------------------------------------------------

func TestApplyRVState_REG_SZ(t *testing.T) {
	v := "hello"
	rv := &winclient.RegistryValueState{Kind: winclient.RegistryValueKindString, ValueString: &v}
	m := &windowsRegistryValueModel{}
	var diags diag.Diagnostics
	applyRVState(m, rv, &diags)
	if diags.HasError() {
		t.Fatalf("applyRVState: %v", diags)
	}
	if m.Type.ValueString() != "REG_SZ" {
		t.Errorf("Type = %q", m.Type.ValueString())
	}
	if m.ValueString.ValueString() != "hello" {
		t.Errorf("ValueString = %q", m.ValueString.ValueString())
	}
	if !m.ValueStrings.IsNull() {
		t.Error("ValueStrings should be null for REG_SZ")
	}
	if !m.ValueBinary.IsNull() {
		t.Error("ValueBinary should be null for REG_SZ")
	}
}

func TestApplyRVState_REG_MULTI_SZ(t *testing.T) {
	rv := &winclient.RegistryValueState{
		Kind:         winclient.RegistryValueKindMultiString,
		ValueStrings: []string{"a", "b", "c"},
	}
	m := &windowsRegistryValueModel{}
	var diags diag.Diagnostics
	applyRVState(m, rv, &diags)
	if diags.HasError() {
		t.Fatalf("applyRVState: %v", diags)
	}
	if m.Type.ValueString() != "REG_MULTI_SZ" {
		t.Errorf("Type = %q", m.Type.ValueString())
	}
	if m.ValueStrings.IsNull() {
		t.Error("ValueStrings should not be null for REG_MULTI_SZ")
	}
	elems := m.ValueStrings.Elements()
	if len(elems) != 3 {
		t.Errorf("ValueStrings len = %d", len(elems))
	}
}

func TestApplyRVState_REG_MULTI_SZ_Nil(t *testing.T) {
	rv := &winclient.RegistryValueState{
		Kind:         winclient.RegistryValueKindMultiString,
		ValueStrings: nil,
	}
	m := &windowsRegistryValueModel{}
	var diags diag.Diagnostics
	applyRVState(m, rv, &diags)
	if diags.HasError() {
		t.Fatalf("applyRVState REG_MULTI_SZ nil: %v", diags)
	}
	if len(m.ValueStrings.Elements()) != 0 {
		t.Errorf("nil ValueStrings should produce empty list, got %v", m.ValueStrings)
	}
}

func TestApplyRVState_REG_BINARY(t *testing.T) {
	hex := "deadbeef"
	rv := &winclient.RegistryValueState{Kind: winclient.RegistryValueKindBinary, ValueBinary: &hex}
	m := &windowsRegistryValueModel{}
	var diags diag.Diagnostics
	applyRVState(m, rv, &diags)
	if diags.HasError() {
		t.Fatalf("applyRVState: %v", diags)
	}
	if m.ValueBinary.ValueString() != "deadbeef" {
		t.Errorf("ValueBinary = %q", m.ValueBinary.ValueString())
	}
}

func TestApplyRVState_REG_NONE_NilBinary(t *testing.T) {
	rv := &winclient.RegistryValueState{Kind: winclient.RegistryValueKindNone, ValueBinary: nil}
	m := &windowsRegistryValueModel{}
	var diags diag.Diagnostics
	applyRVState(m, rv, &diags)
	if diags.HasError() {
		t.Fatalf("applyRVState: %v", diags)
	}
	// nil ValueBinary should produce empty string
	if m.ValueBinary.ValueString() != "" {
		t.Errorf("nil ValueBinary should produce empty string, got %q", m.ValueBinary.ValueString())
	}
}

// ---------------------------------------------------------------------------
// addRVDiag — diagnostic helper
// ---------------------------------------------------------------------------

func TestAddRVDiag_TypeConflict(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewRegistryValueError(winclient.RegistryValueErrorTypeConflict,
		"type_conflict: existing=REG_SZ declared=REG_DWORD", nil,
		map[string]string{"existing_type": "REG_SZ"})
	addRVDiag(&diags, "Create", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Summary(), "type conflict") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'type conflict' in summary, got: %v", rvDiagSummaries(diags))
	}
}

func TestAddRVDiag_Permission(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewRegistryValueError(winclient.RegistryValueErrorPermission,
		"access denied", nil, nil)
	addRVDiag(&diags, "Read", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(rvDiagSummaries(diags)[0], "permission denied") {
		t.Errorf("expected 'permission denied' in summary: %v", rvDiagSummaries(diags))
	}
}

func TestAddRVDiag_InvalidInput(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewRegistryValueError(winclient.RegistryValueErrorInvalidInput,
		"bad value", nil, nil)
	addRVDiag(&diags, "Update", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(rvDiagSummaries(diags)[0], "invalid input") {
		t.Errorf("expected 'invalid input' in summary: %v", rvDiagSummaries(diags))
	}
}

func TestAddRVDiag_Unknown(t *testing.T) {
	var diags diag.Diagnostics
	err := winclient.NewRegistryValueError(winclient.RegistryValueErrorUnknown,
		"something went wrong", nil, nil)
	addRVDiag(&diags, "Delete", err)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
}

func TestAddRVDiag_PlainError(t *testing.T) {
	var diags diag.Diagnostics
	addRVDiag(&diags, "Create", errors.New("plain error"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostic for plain error")
	}
	if !strings.Contains(rvDiagSummaries(diags)[0], "plain error") {
		t.Errorf("expected 'plain error' in diag: %v", rvDiagSummaries(diags))
	}
}

// ---------------------------------------------------------------------------
// ImportState handler — EC-13 edge cases
// ---------------------------------------------------------------------------

func TestImportState_ValidNamedValue(t *testing.T) {
	r := &windowsRegistryValueResource{}
	s := windowsRegistryValueSchemaDefinition()
	req := resource.ImportStateRequest{ID: `HKLM\SOFTWARE\MyApp\Version`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(registryValueObjectType(), nil)}}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState valid named: %v", rvDiagSummaries(resp.Diagnostics))
	}
	var m windowsRegistryValueModel
	resp.State.Get(context.Background(), &m)
	if m.Hive.ValueString() != "HKLM" {
		t.Errorf("Hive = %q", m.Hive.ValueString())
	}
	if m.Path.ValueString() != `SOFTWARE\MyApp` {
		t.Errorf("Path = %q", m.Path.ValueString())
	}
	if m.Name.ValueString() != "Version" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
}

func TestImportState_ValidDefaultValue(t *testing.T) {
	// Trailing backslash → name="" (Default value)
	r := &windowsRegistryValueResource{}
	s := windowsRegistryValueSchemaDefinition()
	req := resource.ImportStateRequest{ID: `HKCU\Software\Test\`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(registryValueObjectType(), nil)}}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState default value: %v", rvDiagSummaries(resp.Diagnostics))
	}
	var m windowsRegistryValueModel
	resp.State.Get(context.Background(), &m)
	if m.Name.ValueString() != "" {
		t.Errorf("Name should be empty for default value, got %q", m.Name.ValueString())
	}
}

func TestImportState_LowercaseHiveNormalized(t *testing.T) {
	r := &windowsRegistryValueResource{}
	s := windowsRegistryValueSchemaDefinition()
	req := resource.ImportStateRequest{ID: `hklm\SOFTWARE\Test\Val`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(registryValueObjectType(), nil)}}
	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState lowercase hive: %v", rvDiagSummaries(resp.Diagnostics))
	}
	var m windowsRegistryValueModel
	resp.State.Get(context.Background(), &m)
	if m.Hive.ValueString() != "HKLM" {
		t.Errorf("Hive should be normalised to HKLM, got %q", m.Hive.ValueString())
	}
}

func TestImportState_EC13_NoBackslash(t *testing.T) {
	// No backslash at all → error
	r := &windowsRegistryValueResource{}
	s := windowsRegistryValueSchemaDefinition()
	req := resource.ImportStateRequest{ID: "HKLM"}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for ID with no backslash (EC-13)")
	}
}

func TestImportState_EC13_UnknownHive(t *testing.T) {
	r := &windowsRegistryValueResource{}
	s := windowsRegistryValueSchemaDefinition()
	req := resource.ImportStateRequest{ID: `BADH\SOFTWARE\Test\Val`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for unknown hive (EC-13)")
	}
}

func TestImportState_EC13_NoPathSeparator(t *testing.T) {
	// Only hive and one component: HKLM\SOFTWARE (no second backslash)
	r := &windowsRegistryValueResource{}
	s := windowsRegistryValueSchemaDefinition()
	req := resource.ImportStateRequest{ID: `HKLM\SOFTWARE`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for ID with no path separator (EC-13)")
	}
}

func TestImportState_EC13_EmptyPath(t *testing.T) {
	// HKLM\\Value → empty path after hive
	r := &windowsRegistryValueResource{}
	s := windowsRegistryValueSchemaDefinition()
	req := resource.ImportStateRequest{ID: `HKLM\\Version`}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s}}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error for empty path (EC-13)")
	}
}

// ---------------------------------------------------------------------------
// Create handler
// ---------------------------------------------------------------------------

func TestRegistryValueCreate_HappyPath_REG_SZ(t *testing.T) {
	fake := &fakeRegistryValueClient{setOut: okRVState(winclient.RegistryValueKindString)}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawPlan := rvObj(nil) // defaults: HKLM, SOFTWARE\MyApp, Version, REG_SZ, "1.0.0"
	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rawPlan}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create REG_SZ: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestRegistryValueCreate_EC3_TypeConflict(t *testing.T) {
	fake := &fakeRegistryValueClient{
		setErr: winclient.NewRegistryValueError(winclient.RegistryValueErrorTypeConflict,
			"type_conflict: existing=REG_SZ declared=REG_DWORD", nil, nil),
	}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawPlan := rvObj(map[string]tftypes.Value{
		"type":         tftypes.NewValue(tftypes.String, "REG_DWORD"),
		"value_string": tftypes.NewValue(tftypes.String, "42"),
	})
	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rawPlan}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected type_conflict diagnostic (EC-3)")
	}
}

func TestRegistryValueCreate_PermissionDenied(t *testing.T) {
	fake := &fakeRegistryValueClient{
		setErr: winclient.NewRegistryValueError(winclient.RegistryValueErrorPermission,
			"access denied", nil, nil),
	}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawPlan := rvObj(nil)
	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rawPlan}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected permission denied diagnostic")
	}
}

func TestRegistryValueCreate_NilStateReturned(t *testing.T) {
	// Set returns (nil, nil) — should produce diagnostic
	fake := &fakeRegistryValueClient{setOut: nil, setErr: nil}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawPlan := rvObj(nil)
	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: rawPlan}}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: s}}

	r.Create(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diagnostic when Set returns nil state")
	}
}

// ---------------------------------------------------------------------------
// Read handler
// ---------------------------------------------------------------------------

func TestRegistryValueRead_HappyPath(t *testing.T) {
	fake := &fakeRegistryValueClient{readOut: okRVState(winclient.RegistryValueKindString)}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawState := rvObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
	})
	st := tfsdk.State{Schema: s, Raw: rawState}
	req := resource.ReadRequest{State: st}
	resp := &resource.ReadResponse{State: st}

	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", rvDiagSummaries(resp.Diagnostics))
	}
}

func TestRegistryValueRead_EC4_NotFound(t *testing.T) {
	// Read returns nil → RemoveResource
	fake := &fakeRegistryValueClient{readOut: nil, readErr: nil}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawState := rvObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
	})
	st := tfsdk.State{Schema: s, Raw: rawState}
	req := resource.ReadRequest{State: st}
	resp := &resource.ReadResponse{State: st}

	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read EC-4 must not produce error: %v", rvDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state must be removed when value not found (EC-4)")
	}
}

func TestRegistryValueRead_Error(t *testing.T) {
	fake := &fakeRegistryValueClient{
		readErr: winclient.NewRegistryValueError(winclient.RegistryValueErrorPermission,
			"access denied", nil, nil),
	}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawState := rvObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
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
// Update handler
// ---------------------------------------------------------------------------

func TestRegistryValueUpdate_HappyPath(t *testing.T) {
	fake := &fakeRegistryValueClient{setOut: okRVState(winclient.RegistryValueKindString)}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawPlan := rvObj(map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
		"value_string": tftypes.NewValue(tftypes.String, "2.0.0"),
	})
	rawState := rvObj(map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
		"value_string": tftypes.NewValue(tftypes.String, "1.0.0"),
	})

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: rawState}}

	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", rvDiagSummaries(resp.Diagnostics))
	}
	if fake.lastSetInput.ValueString == nil || *fake.lastSetInput.ValueString != "2.0.0" {
		t.Errorf("Set should be called with new value_string, got: %v", fake.lastSetInput.ValueString)
	}
}

func TestRegistryValueUpdate_Error(t *testing.T) {
	fake := &fakeRegistryValueClient{
		setErr: winclient.NewRegistryValueError(winclient.RegistryValueErrorUnknown,
			"server error", nil, nil),
	}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawPlan := rvObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
	})
	rawState := rvObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
	})

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: s, Raw: rawPlan},
		State: tfsdk.State{Schema: s, Raw: rawState},
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: rawState}}

	r.Update(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for update failure")
	}
}

// ---------------------------------------------------------------------------
// Delete handler
// ---------------------------------------------------------------------------

func TestRegistryValueDelete_HappyPath(t *testing.T) {
	fake := &fakeRegistryValueClient{deleteErr: nil}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawState := rvObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
	})
	req := resource.DeleteRequest{State: tfsdk.State{Schema: s, Raw: rawState}}
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete: %v", rvDiagSummaries(resp.Diagnostics))
	}
	if !fake.deleteCalled {
		t.Error("Delete should have been called on the client")
	}
}

func TestRegistryValueDelete_Error(t *testing.T) {
	fake := &fakeRegistryValueClient{
		deleteErr: winclient.NewRegistryValueError(winclient.RegistryValueErrorPermission,
			"cannot delete", nil, nil),
	}
	r := &windowsRegistryValueResource{client: fake}
	s := windowsRegistryValueSchemaDefinition()

	rawState := rvObj(map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, `HKLM\SOFTWARE\MyApp\Version`),
	})
	req := resource.DeleteRequest{State: tfsdk.State{Schema: s, Raw: rawState}}
	resp := &resource.DeleteResponse{}

	r.Delete(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for delete failure")
	}
}
