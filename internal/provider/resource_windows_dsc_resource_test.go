// Package provider — unit tests for windows_dsc_resource helpers, schema and
// plan behaviour (issue #293).
//
// These tests do NOT drive the full TPF Create/Read/Update/Delete lifecycle
// (covered by resource_windows_dsc_resource_acc_test.go, which requires
// TF_ACC=1 and a real Windows host). Instead they exercise:
//
//   - Metadata + Schema shape / attribute presence, sensitivity and
//     WriteOnly flags (service/certificate Tier-3 precedent)
//   - ImportState refusal with adoption guidance
//   - The always-true in_desired_state plan modifier
//   - dscDynamicToGo conversion (scalars, nesting, null, unknown, shape)
//   - dscEnsureInputFromPlan credential/version fail-closed guards
//   - dscModelFromResult projection (ID, canonical JSON, timeout carry-over)
//   - addDSCDiag (typed kinds, password-key redaction, plain errors)
//   - Resource.Configure for nil + wrong-type ProviderData
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// -----------------------------------------------------------------------------
// Metadata / Schema
// -----------------------------------------------------------------------------

func TestDSCMetadata(t *testing.T) {
	r := &windowsDSCResourceResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_dsc_resource" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "windows_dsc_resource")
	}
}

func TestDSCSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsDSCResourceSchemaDefinition(context.Background())
	wantAttrs := []string{
		"id", "module_name", "module_version", "resolved_module_version",
		"resource_name", "properties",
		"credential_properties_wo", "credential_properties_wo_version",
		"destroy_properties",
		"in_desired_state", "current_state_json", "reboot_required",
		"timeouts",
	}
	for _, k := range wantAttrs {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	// properties must be Required dynamic.
	props, ok := s.Attributes["properties"].(interface{ IsRequired() bool })
	if !ok {
		t.Fatalf("properties attr does not implement IsRequired()")
	}
	if !props.IsRequired() {
		t.Error("properties must be Required")
	}
	// credential_properties_wo must be WriteOnly + Sensitive (Tier 3).
	woAttr, ok := s.Attributes["credential_properties_wo"].(interface {
		IsSensitive() bool
		IsWriteOnly() bool
	})
	if !ok {
		t.Fatalf("credential_properties_wo attr missing IsSensitive/IsWriteOnly")
	}
	if !woAttr.IsWriteOnly() {
		t.Error("credential_properties_wo must be WriteOnly (never persisted in state)")
	}
	if !woAttr.IsSensitive() {
		t.Error("credential_properties_wo must be Sensitive")
	}
	// destroy_properties must be Optional dynamic.
	destroy, ok := s.Attributes["destroy_properties"].(interface{ IsOptional() bool })
	if !ok {
		t.Fatalf("destroy_properties attr does not implement IsOptional()")
	}
	if !destroy.IsOptional() {
		t.Error("destroy_properties must be Optional (unset means state-only destroy)")
	}
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Error("schema missing timeouts block")
	}
}

// -----------------------------------------------------------------------------
// ImportState — unsupported with guidance
// -----------------------------------------------------------------------------

func TestDSCImportState_Refused(t *testing.T) {
	r := &windowsDSCResourceResource{}
	req := resource.ImportStateRequest{ID: "PSDesiredStateConfiguration|Environment|abc"}
	resp := &resource.ImportStateResponse{}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("ImportState must fail: import is unsupported for windows_dsc_resource")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Detail(), "cannot be imported") {
			found = true
		}
	}
	if !found {
		t.Errorf("import diagnostic lacks adoption guidance: %v", resp.Diagnostics)
	}
}

// -----------------------------------------------------------------------------
// in_desired_state plan modifier — always true
// -----------------------------------------------------------------------------

func TestDSCInDesiredStateModifier_AlwaysTrue(t *testing.T) {
	m := dscInDesiredStateModifier{}
	for _, pv := range []types.Bool{types.BoolValue(false), types.BoolValue(true), types.BoolUnknown()} {
		resp := &planmodifier.BoolResponse{}
		m.PlanModifyBool(context.Background(), planmodifier.BoolRequest{PlanValue: pv}, resp)
		if !resp.PlanValue.Equal(types.BoolValue(true)) {
			t.Errorf("PlanModifyBool(%v) = %v, want true", pv, resp.PlanValue)
		}
	}
}

// -----------------------------------------------------------------------------
// dscDynamicToGo
// -----------------------------------------------------------------------------

func dscTestObject(t *testing.T, attrs map[string]attr.Type, vals map[string]attr.Value) types.Dynamic {
	t.Helper()
	obj, diags := types.ObjectValue(attrs, vals)
	if diags.HasError() {
		t.Fatalf("ObjectValue: %v", diags)
	}
	return types.DynamicValue(obj)
}

func TestDSCDynamicToGo(t *testing.T) {
	ctx := context.Background()

	dv := dscTestObject(t,
		map[string]attr.Type{
			"Name":   types.StringType,
			"Port":   types.NumberType,
			"Path":   types.BoolType,
			"Tags":   types.ListType{ElemType: types.StringType},
			"Nested": types.MapType{ElemType: types.StringType},
			"Gone":   types.StringType,
		},
		map[string]attr.Value{
			"Name":   types.StringValue("X"),
			"Port":   types.NumberValue(big.NewFloat(80)),
			"Path":   types.BoolValue(true),
			"Tags":   mustDSCList(t, "a", "b"),
			"Nested": mustDSCMap(t, map[string]string{"K": "v"}),
			"Gone":   types.StringNull(),
		},
	)
	got, diags := dscDynamicToGo(ctx, dv, path.Root("properties"))
	if diags.HasError() {
		t.Fatalf("dscDynamicToGo: %v", diags)
	}
	if got["Name"] != "X" || got["Port"] != int64(80) || got["Path"] != true {
		t.Errorf("scalar conversion wrong: %v", got)
	}
	tags, ok := got["Tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "a" || tags[1] != "b" {
		t.Errorf("list conversion wrong: %v", got["Tags"])
	}
	nested, ok := got["Nested"].(map[string]any)
	if !ok || nested["K"] != "v" {
		t.Errorf("map conversion wrong: %v", got["Nested"])
	}
	if got["Gone"] != nil {
		t.Errorf("null must convert to nil, got %v", got["Gone"])
	}

	// Null dynamic converts to an empty map.
	got, diags = dscDynamicToGo(ctx, types.DynamicNull(), path.Root("properties"))
	if diags.HasError() {
		t.Fatalf("null dscDynamicToGo: %v", diags)
	}
	if len(got) != 0 {
		t.Errorf("null dynamic = %v, want empty map", got)
	}

	// Unknown dynamic is an error.
	if _, diags := dscDynamicToGo(ctx, types.DynamicUnknown(), path.Root("properties")); !diags.HasError() {
		t.Error("unknown dynamic must be an error")
	}

	// Non-object dynamic is an error.
	if _, diags := dscDynamicToGo(ctx, types.DynamicValue(types.StringValue("x")), path.Root("properties")); !diags.HasError() {
		t.Error("non-object dynamic must be an error")
	}

	// Nested unknown is an error.
	inner := dscTestObject(t,
		map[string]attr.Type{"A": types.StringType},
		map[string]attr.Value{"A": types.StringUnknown()},
	)
	_ = inner
	outer := dscTestObject(t,
		map[string]attr.Type{"Name": types.StringType, "Inner": inner.UnderlyingValue().Type(ctx)},
		map[string]attr.Value{"Name": types.StringValue("X"), "Inner": inner.UnderlyingValue()},
	)
	if _, diags := dscDynamicToGo(ctx, outer, path.Root("properties")); !diags.HasError() {
		t.Error("nested unknown must be an error")
	}
}

func mustDSCList(t *testing.T, elems ...string) attr.Value {
	t.Helper()
	vals := make([]attr.Value, 0, len(elems))
	for _, e := range elems {
		vals = append(vals, types.StringValue(e))
	}
	l, diags := types.ListValue(types.StringType, vals)
	if diags.HasError() {
		t.Fatalf("ListValue: %v", diags)
	}
	return l
}

func mustDSCMap(t *testing.T, m map[string]string) attr.Value {
	t.Helper()
	vals := make(map[string]attr.Value, len(m))
	for k, v := range m {
		vals[k] = types.StringValue(v)
	}
	mv, diags := types.MapValue(types.StringType, vals)
	if diags.HasError() {
		t.Fatalf("MapValue: %v", diags)
	}
	return mv
}

// -----------------------------------------------------------------------------
// dscEnsureInputFromPlan — credential/version guards
// -----------------------------------------------------------------------------

func dscTestPlan(configCreds map[string]dscCredentialModel, versionSet bool) (windowsDSCResourceModel, windowsDSCResourceModel) {
	props := dscTestObjectForPlan(map[string]attr.Value{"Name": types.StringValue("X")})
	plan := windowsDSCResourceModel{
		ModuleName:   types.StringValue("M"),
		ResourceName: types.StringValue("R"),
		Properties:   props,
	}
	config := windowsDSCResourceModel{}
	if configCreds != nil {
		vals := make(map[string]attr.Value, len(configCreds))
		for k, c := range configCreds {
			ov, d := types.ObjectValue(
				map[string]attr.Type{"username": types.StringType, "password": types.StringType},
				map[string]attr.Value{"username": c.Username, "password": c.Password},
			)
			if d.HasError() {
				panic(d)
			}
			vals[k] = ov
		}
		mv, d := types.MapValue(dscCredentialObjectType(), vals)
		if d.HasError() {
			panic(d)
		}
		config.CredentialPropertiesWO = mv
	} else {
		config.CredentialPropertiesWO = types.MapNull(dscCredentialObjectType())
	}
	if versionSet {
		plan.CredentialPropertiesWOVer = types.Int64Value(1)
	} else {
		plan.CredentialPropertiesWOVer = types.Int64Null()
	}
	return plan, config
}

func dscTestObjectForPlan(vals map[string]attr.Value) types.Dynamic {
	attrs := make(map[string]attr.Type, len(vals))
	for k, v := range vals {
		attrs[k] = v.Type(context.Background())
	}
	obj, diags := types.ObjectValue(attrs, vals)
	if diags.HasError() {
		panic(diags)
	}
	return types.DynamicValue(obj)
}

func TestDSCCredentialVersionGuards(t *testing.T) {
	ctx := context.Background()
	cred := map[string]dscCredentialModel{
		"Credential": {Username: types.StringValue("u"), Password: types.StringValue("p")},
	}

	// Credentials with a version pass and forward the secret from config.
	plan, config := dscTestPlan(cred, true)
	input, diags := dscEnsureInputFromPlan(ctx, plan, config)
	if diags.HasError() {
		t.Fatalf("creds+version: %v", diags)
	}
	if input.Credentials["Credential"].Password != "p" {
		t.Errorf("credential not forwarded from config: %v", input.Credentials)
	}

	// Credentials without a version fail closed.
	plan, config = dscTestPlan(cred, false)
	if _, diags := dscEnsureInputFromPlan(ctx, plan, config); !diags.HasError() {
		t.Error("creds without version must fail")
	}

	// A version without credentials fails closed.
	plan, config = dscTestPlan(nil, true)
	if _, diags := dscEnsureInputFromPlan(ctx, plan, config); !diags.HasError() {
		t.Error("version without creds must fail")
	}

	// Neither is the common no-credential path.
	plan, config = dscTestPlan(nil, false)
	input, diags = dscEnsureInputFromPlan(ctx, plan, config)
	if diags.HasError() {
		t.Fatalf("neither: %v", diags)
	}
	if len(input.Credentials) != 0 {
		t.Errorf("expected no credentials, got %v", input.Credentials)
	}
	if input.Properties["Name"] != "X" {
		t.Errorf("properties lost: %v", input.Properties)
	}
}

// -----------------------------------------------------------------------------
// dscModelFromResult
// -----------------------------------------------------------------------------

func TestDSCModelFromResult(t *testing.T) {
	prior := windowsDSCResourceModel{
		ModuleName:                types.StringValue("M"),
		ModuleVersion:             types.StringNull(),
		ResourceName:              types.StringValue("R"),
		Properties:                dscTestObjectForPlan(map[string]attr.Value{"Name": types.StringValue("X")}),
		DestroyProperties:         types.DynamicNull(),
		CredentialPropertiesWOVer: types.Int64Null(),
	}
	result := &winclient.DSCEnsureResult{
		ID:                    "M|R|abc",
		InDesiredState:        true,
		CurrentState:          map[string]any{"Name": "X", "Value": "1"},
		RebootRequired:        true,
		ResolvedModuleVersion: "1.1",
	}
	final, diags := dscModelFromResult(prior, result)
	if diags.HasError() {
		t.Fatalf("dscModelFromResult: %v", diags)
	}
	if final.ID.ValueString() != "M|R|abc" {
		t.Errorf("ID = %q", final.ID.ValueString())
	}
	if !final.InDesiredState.ValueBool() || !final.RebootRequired.ValueBool() {
		t.Errorf("flags lost: desired=%v reboot=%v", final.InDesiredState, final.RebootRequired)
	}
	if final.ResolvedModuleVersion.ValueString() != "1.1" {
		t.Errorf("resolved version = %q", final.ResolvedModuleVersion.ValueString())
	}
	if !final.CredentialPropertiesWO.IsNull() {
		t.Error("credential map must stay null in state")
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(final.CurrentStateJSON.ValueString()), &decoded); err != nil {
		t.Fatalf("current_state_json is not JSON: %v", err)
	}
	if decoded["Name"] != "X" {
		t.Errorf("current_state_json = %s", final.CurrentStateJSON.ValueString())
	}
	// Missing ID is a hard error.
	bad := *result
	bad.ID = ""
	if _, diags := dscModelFromResult(prior, &bad); !diags.HasError() {
		t.Error("missing ID must be an error")
	}
}

// -----------------------------------------------------------------------------
// addDSCDiag
// -----------------------------------------------------------------------------

func TestAddDSCDiag(t *testing.T) {
	var ds diag.Diagnostics
	addDSCDiag(&ds, "summary", winclient.NewDSCResourceError(
		winclient.DSCResourceErrorLCMConflict,
		"RefreshMode is Pull",
		nil,
		map[string]string{"password_hint": "must never surface", "module": "M"},
	))
	if !ds.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := ds.Errors()[0].Detail()
	if !strings.Contains(detail, "lcm_conflict") {
		t.Errorf("detail lacks kind: %q", detail)
	}
	if strings.Contains(detail, "must never surface") {
		t.Errorf("password-carrying context key leaked: %q", detail)
	}
	if !strings.Contains(detail, "module = M") {
		t.Errorf("safe context lost: %q", detail)
	}

	var plain diag.Diagnostics
	addDSCDiag(&plain, "summary", errors.New("boom"))
	if !plain.HasError() || !strings.Contains(plain.Errors()[0].Detail(), "boom") {
		t.Errorf("plain error mishandled: %v", plain)
	}
}

// -----------------------------------------------------------------------------
// Configure
// -----------------------------------------------------------------------------

func TestDSCConfigure(t *testing.T) {
	r := &windowsDSCResourceResource{}
	req := resource.ConfigureRequest{ProviderData: nil}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must be a no-op: %v", resp.Diagnostics)
	}
	if r.dsc != nil {
		t.Error("nil ProviderData must not set a client")
	}

	reqBad := resource.ConfigureRequest{ProviderData: "nope"}
	respBad := &resource.ConfigureResponse{}
	r.Configure(context.Background(), reqBad, respBad)
	if !respBad.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData must error")
	}
}

// Compile-time references so unused-import mistakes surface here rather than
// in the resource file: path is used by the resource for diagnostics.
var _ = path.Root
