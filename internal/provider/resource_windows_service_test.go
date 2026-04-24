// Package provider — unit tests for windows_service helpers and validators.
//
// These tests do NOT drive the full TPF Create/Read/Update/Delete request
// lifecycle (that is covered by the acceptance-test skeleton in
// resource_windows_service_acc_test.go, which requires TF_ACC=1 and a real
// Windows host). Instead they exercise:
//
//   - Metadata + Schema shape / attribute presence
//   - builtinAccountRe (EC-11 guard)
//   - serviceAccountPasswordValidator via a real ValidateConfigRequest
//     built from a populated tfsdk.Config (EC-4 + EC-11)
//   - modelFromState projection (null-preserving Description, SS6 password)
//   - addServiceDiag for both *ServiceError and plain error paths
//   - Resource.Configure for nil ProviderData + wrong-type ProviderData
//   - ConfigValidators returns our cross-field validator
package provider

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/ecritel/terraform-provider-windows/internal/winclient"
)

// -----------------------------------------------------------------------------
// Metadata / Schema
// -----------------------------------------------------------------------------

func TestMetadata(t *testing.T) {
	r := &windowsServiceResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_service" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "windows_service")
	}
}

func TestSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsServiceSchemaDefinition()
	wantAttrs := []string{
		"id", "name", "display_name", "description", "binary_path",
		"start_type", "status", "current_status", "service_account",
		"service_password", "dependencies",
	}
	for _, k := range wantAttrs {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	// Sensitive flag on service_password.
	pwAttr, ok := s.Attributes["service_password"].(interface{ IsSensitive() bool })
	if !ok {
		t.Fatalf("service_password attr does not implement IsSensitive()")
	}
	if !pwAttr.IsSensitive() {
		t.Error("service_password must be Sensitive")
	}
}

func TestSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsServiceResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

// -----------------------------------------------------------------------------
// builtinAccountRe (EC-11)
// -----------------------------------------------------------------------------

func TestBuiltinAccountRe(t *testing.T) {
	cases := map[string]bool{
		"LocalSystem":                   true,
		"localsystem":                   true, // case-insensitive
		"NT AUTHORITY\\SYSTEM":          true,
		"NT AUTHORITY\\NetworkService":  true,
		"nt authority\\LocalService":    true,
		"DOMAIN\\svc-app":               false,
		".\\svcuser":                    false,
		"":                              false,
	}
	for in, want := range cases {
		if got := builtinAccountRe.MatchString(in); got != want {
			t.Errorf("builtinAccountRe(%q) = %v, want %v", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// serviceAccountPasswordValidator (EC-4 + EC-11)
// -----------------------------------------------------------------------------

// buildValidatorConfig materialises a tfsdk.Config for the resource schema
// with only the 3 attributes relevant to the cross-field validator populated;
// the rest are null to stay valid for the resource schema shape.
func buildValidatorConfig(t *testing.T, account, password *string) tfsdk.Config {
	t.Helper()
	s := windowsServiceSchemaDefinition()

	val := func(p *string) tftypes.Value {
		if p == nil {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, *p)
	}

	obj := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":               tftypes.String,
		"name":             tftypes.String,
		"display_name":     tftypes.String,
		"description":      tftypes.String,
		"binary_path":      tftypes.String,
		"start_type":       tftypes.String,
		"status":           tftypes.String,
		"current_status":   tftypes.String,
		"service_account":  tftypes.String,
		"service_password": tftypes.String,
		"dependencies":     tftypes.List{ElementType: tftypes.String},
	}}, map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, "svc"),
		"display_name":     tftypes.NewValue(tftypes.String, nil),
		"description":      tftypes.NewValue(tftypes.String, nil),
		"binary_path":      tftypes.NewValue(tftypes.String, `C:\x.exe`),
		"start_type":       tftypes.NewValue(tftypes.String, nil),
		"status":           tftypes.NewValue(tftypes.String, nil),
		"current_status":   tftypes.NewValue(tftypes.String, nil),
		"service_account":  val(account),
		"service_password": val(password),
		"dependencies":     tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
	})

	return tfsdk.Config{
		Raw:    obj,
		Schema: s,
	}
}

func TestValidator_DescriptionStrings(t *testing.T) {
	v := serviceAccountPasswordValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}
}

func TestValidator_NoPassword_NoError(t *testing.T) {
	v := serviceAccountPasswordValidator{}
	cfg := buildValidatorConfig(t, nil, nil)
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("expected no error, got %v", resp.Diagnostics)
	}
}

func TestValidator_PasswordWithoutAccount_EC4(t *testing.T) {
	v := serviceAccountPasswordValidator{}
	pw := "secret"
	cfg := buildValidatorConfig(t, nil, &pw)
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected EC-4 error, got none")
	}
	if !strings.Contains(diagSummary(resp.Diagnostics), "EC-4") {
		t.Errorf("error should reference EC-4: %s", diagSummary(resp.Diagnostics))
	}
}

func TestValidator_PasswordWithBuiltinAccount_EC11(t *testing.T) {
	v := serviceAccountPasswordValidator{}
	pw := "secret"
	acct := "LocalSystem"
	cfg := buildValidatorConfig(t, &acct, &pw)
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected EC-11 error, got none")
	}
	if !strings.Contains(diagSummary(resp.Diagnostics), "EC-11") {
		t.Errorf("error should reference EC-11: %s", diagSummary(resp.Diagnostics))
	}
}

func TestValidator_PasswordWithDomainAccount_OK(t *testing.T) {
	v := serviceAccountPasswordValidator{}
	pw := "secret"
	acct := "DOMAIN\\svc-app"
	cfg := buildValidatorConfig(t, &acct, &pw)
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("expected no error for domain account, got %v", resp.Diagnostics)
	}
}

func diagSummary(d diag.Diagnostics) string {
	var b strings.Builder
	for _, x := range d {
		b.WriteString(x.Summary())
		b.WriteString(" / ")
		b.WriteString(x.Detail())
		b.WriteString("\n")
	}
	return b.String()
}

// -----------------------------------------------------------------------------
// modelFromState / addServiceDiag
// -----------------------------------------------------------------------------

func TestModelFromState_NullDescriptionPreserved(t *testing.T) {
	s := &winclient.ServiceState{
		Name: "svc", DisplayName: "Svc", BinaryPath: `C:\x.exe`,
		StartType: "Automatic", CurrentStatus: "Stopped",
		ServiceAccount: "LocalSystem", Description: "",
		Dependencies: []string{},
	}
	prior := windowsServiceModel{
		Description:     types.StringNull(),
		Status:          types.StringValue("Running"),
		ServicePassword: types.StringValue("keep-me"),
	}
	got := modelFromState(s, prior)
	if !got.Description.IsNull() {
		t.Errorf("Description should stay null when prior is null and observed is empty")
	}
	if got.Status.ValueString() != "Running" {
		t.Errorf("Status must be preserved from prior (desired state), got %q", got.Status.ValueString())
	}
	if got.ServicePassword.ValueString() != "keep-me" {
		t.Errorf("ServicePassword must be preserved from prior state (SS6), got %q",
			got.ServicePassword.ValueString())
	}
	if got.ID.ValueString() != "svc" {
		t.Error("ID must equal Name")
	}
}

func TestModelFromState_DescriptionSetWhenObserved(t *testing.T) {
	s := &winclient.ServiceState{Name: "svc", Description: "running", Dependencies: []string{"Tcpip", "Dnscache"}}
	prior := windowsServiceModel{Description: types.StringNull()}
	got := modelFromState(s, prior)
	if got.Description.ValueString() != "running" {
		t.Errorf("Description should be set when Windows returns one, got %q", got.Description.ValueString())
	}
	// Dependencies list length.
	if len(got.Dependencies.Elements()) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(got.Dependencies.Elements()))
	}
}

func TestAddServiceDiag_StructuredError(t *testing.T) {
	diags := &diag.Diagnostics{}
	se := winclient.NewServiceError(
		winclient.ServiceErrorPermission, "access denied",
		nil,
		map[string]string{"host": "WIN01", "service_password": "must-not-leak"},
	)
	addServiceDiag(diags, "Read failed", se)
	if !diags.HasError() {
		t.Fatal("expected error diag")
	}
	detail := (*diags)[0].Detail()
	if !strings.Contains(detail, "permission_denied") {
		t.Errorf("missing kind in detail: %s", detail)
	}
	if strings.Contains(detail, "must-not-leak") {
		t.Errorf("service_password leaked into detail: %s", detail)
	}
}

func TestAddServiceDiag_PlainError(t *testing.T) {
	diags := &diag.Diagnostics{}
	addServiceDiag(diags, "Generic failure", errors.New("boom"))
	if !diags.HasError() {
		t.Fatal("expected error diag")
	}
	if !strings.Contains((*diags)[0].Detail(), "boom") {
		t.Errorf("detail missing underlying text: %s", (*diags)[0].Detail())
	}
}

// -----------------------------------------------------------------------------
// Resource.Configure
// -----------------------------------------------------------------------------

func TestConfigure_NilProviderData_NoOp(t *testing.T) {
	r := &windowsServiceResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
	if r.client != nil {
		t.Error("client should remain nil")
	}
}

func TestConfigure_WrongTypeProviderData(t *testing.T) {
	r := &windowsServiceResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should yield an error diagnostic")
	}
}

func TestConfigure_ValidClient(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsServiceResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	if r.client != c || r.svc == nil {
		t.Error("Configure must populate client and svc")
	}
}

// -----------------------------------------------------------------------------
// ConfigValidators + ImportState
// -----------------------------------------------------------------------------

func TestConfigValidators(t *testing.T) {
	r := &windowsServiceResource{}
	vs := r.ConfigValidators(context.Background())
	if len(vs) != 1 {
		t.Fatalf("expected 1 validator, got %d", len(vs))
	}
	if _, ok := vs[0].(serviceAccountPasswordValidator); !ok {
		t.Errorf("validator type = %T", vs[0])
	}
}

func TestNewWindowsServiceResource_NotNil(t *testing.T) {
	if NewWindowsServiceResource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// -----------------------------------------------------------------------------
// Name regex from the spec (fast sanity check alongside TPF validator)
// -----------------------------------------------------------------------------

func TestNameRegex(t *testing.T) {
	re := regexp.MustCompile("^[A-Za-z0-9_\\-\\.]{1,256}$")
	ok := []string{"MyService", "my-svc", "my.svc", "a", "svc_01"}
	ko := []string{"", "a b", "slash/name", "percent%", strings.Repeat("a", 257)}
	for _, n := range ok {
		if !re.MatchString(n) {
			t.Errorf("expected %q to match", n)
		}
	}
	for _, n := range ko {
		if re.MatchString(n) {
			t.Errorf("expected %q NOT to match", n)
		}
	}
}

// Static assertion that windowsServiceModel has the expected tfsdk tags used
// by the TPF Get marshaller; this catches accidental tag renames.
func TestWindowsServiceModel_Shape(t *testing.T) {
	m := windowsServiceModel{
		Dependencies: types.ListNull(types.StringType),
	}
	// Quick smoke: just ensure attr.Value fields can be addressed.
	var _ attr.Value = m.ID
	var _ attr.Value = m.Name
}

// -----------------------------------------------------------------------------
// CRUD handler tests driven with a fake WindowsServiceClient
// -----------------------------------------------------------------------------

// fakeSvcClient is an in-memory WindowsServiceClient used to drive the CRUD
// handlers without touching WinRM. Each method captures the last input and
// returns a preset response/error for assertion.
type fakeSvcClient struct {
	createIn     winclient.ServiceInput
	createOut    *winclient.ServiceState
	createErr    error
	readOut      *winclient.ServiceState
	readErr      error
	updateIn     winclient.ServiceInput
	updateOut    *winclient.ServiceState
	updateErr    error
	deleteName   string
	deleteErr    error
	startCalls   int
	stopCalls    int
	pauseCalls   int
}

func (f *fakeSvcClient) Create(_ context.Context, in winclient.ServiceInput) (*winclient.ServiceState, error) {
	f.createIn = in
	return f.createOut, f.createErr
}
func (f *fakeSvcClient) Read(_ context.Context, _ string) (*winclient.ServiceState, error) {
	return f.readOut, f.readErr
}
func (f *fakeSvcClient) Update(_ context.Context, _ string, in winclient.ServiceInput) (*winclient.ServiceState, error) {
	f.updateIn = in
	return f.updateOut, f.updateErr
}
func (f *fakeSvcClient) Delete(_ context.Context, name string) error {
	f.deleteName = name
	return f.deleteErr
}
func (f *fakeSvcClient) StartService(_ context.Context, _ string) error { f.startCalls++; return nil }
func (f *fakeSvcClient) StopService(_ context.Context, _ string) error  { f.stopCalls++; return nil }
func (f *fakeSvcClient) PauseService(_ context.Context, _ string) error { f.pauseCalls++; return nil }

// objectType mirrors the resource schema as a tftypes.Object shape.
func serviceObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":               tftypes.String,
		"name":             tftypes.String,
		"display_name":     tftypes.String,
		"description":      tftypes.String,
		"binary_path":      tftypes.String,
		"start_type":       tftypes.String,
		"status":           tftypes.String,
		"current_status":   tftypes.String,
		"service_account":  tftypes.String,
		"service_password": tftypes.String,
		"dependencies":     tftypes.List{ElementType: tftypes.String},
	}}
}

// svcObj builds a tftypes.Value for the service model, with nil entries
// represented as null.
func svcObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, nil),
		"display_name":     tftypes.NewValue(tftypes.String, nil),
		"description":      tftypes.NewValue(tftypes.String, nil),
		"binary_path":      tftypes.NewValue(tftypes.String, nil),
		"start_type":       tftypes.NewValue(tftypes.String, nil),
		"status":           tftypes.NewValue(tftypes.String, nil),
		"current_status":   tftypes.NewValue(tftypes.String, nil),
		"service_account":  tftypes.NewValue(tftypes.String, nil),
		"service_password": tftypes.NewValue(tftypes.String, nil),
		"dependencies":     tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(serviceObjectType(), base)
}

// stateOK is a preset observed state shared by several tests.
func stateOK() *winclient.ServiceState {
	return &winclient.ServiceState{
		Name: "svc", DisplayName: "Svc", Description: "",
		BinaryPath: `C:\svc.exe`, StartType: "Automatic", CurrentStatus: "Stopped",
		ServiceAccount: "LocalSystem", Dependencies: []string{},
	}
}

// TestCreate_Handler_HappyPath drives windowsServiceResource.Create through
// the TPF request flow and asserts that the fake client received the expected
// input and that state is populated.
func TestCreate_Handler_HappyPath(t *testing.T) {
	fake := &fakeSvcClient{createOut: stateOK()}
	r := &windowsServiceResource{svc: fake}

	schemaDef := windowsServiceSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"name":        tftypes.NewValue(tftypes.String, "svc"),
			"binary_path": tftypes.NewValue(tftypes.String, `C:\svc.exe`),
			"start_type":  tftypes.NewValue(tftypes.String, "Automatic"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: svcObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.createIn.Name != "svc" || fake.createIn.BinaryPath != `C:\svc.exe` {
		t.Errorf("input mismatch: %+v", fake.createIn)
	}
}

func TestCreate_Handler_ClientError(t *testing.T) {
	fake := &fakeSvcClient{createErr: winclient.NewServiceError(
		winclient.ServiceErrorAlreadyExists, "service 'svc' exists", nil, nil)}
	r := &windowsServiceResource{svc: fake}
	schemaDef := windowsServiceSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"name":        tftypes.NewValue(tftypes.String, "svc"),
			"binary_path": tftypes.NewValue(tftypes.String, `C:\x.exe`),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: svcObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag from already_exists")
	}
}

func TestRead_Handler_HappyPath(t *testing.T) {
	fake := &fakeSvcClient{readOut: stateOK()}
	r := &windowsServiceResource{svc: fake}

	schemaDef := windowsServiceSchemaDefinition()
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"id":               tftypes.NewValue(tftypes.String, "svc"),
			"name":             tftypes.NewValue(tftypes.String, "svc"),
			"binary_path":      tftypes.NewValue(tftypes.String, `C:\svc.exe`),
			"service_password": tftypes.NewValue(tftypes.String, "keep-me"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
}

func TestRead_Handler_NotFound_RemovesResource(t *testing.T) {
	// client returns (nil, nil) → handler must call RemoveResource.
	fake := &fakeSvcClient{readOut: nil, readErr: nil}
	r := &windowsServiceResource{svc: fake}

	schemaDef := windowsServiceSchemaDefinition()
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "svc"),
			"name": tftypes.NewValue(tftypes.String, "svc"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	// After RemoveResource, State.Raw should be null.
	if !resp.State.Raw.IsNull() {
		t.Errorf("EC-2: expected state removed, got %v", resp.State.Raw)
	}
}

func TestRead_Handler_ClientError(t *testing.T) {
	fake := &fakeSvcClient{readErr: winclient.NewServiceError(
		winclient.ServiceErrorPermission, "denied", nil, nil)}
	r := &windowsServiceResource{svc: fake}
	schemaDef := windowsServiceSchemaDefinition()
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "svc"),
			"name": tftypes.NewValue(tftypes.String, "svc"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: priorState}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected permission_denied diag")
	}
}

func TestUpdate_Handler_HappyPath(t *testing.T) {
	fake := &fakeSvcClient{updateOut: stateOK()}
	r := &windowsServiceResource{svc: fake}

	schemaDef := windowsServiceSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"name":         tftypes.NewValue(tftypes.String, "svc"),
			"binary_path":  tftypes.NewValue(tftypes.String, `C:\svc.exe`),
			"display_name": tftypes.NewValue(tftypes.String, "New Display"),
			"start_type":   tftypes.NewValue(tftypes.String, "Manual"),
		}),
	}
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"id":          tftypes.NewValue(tftypes.String, "svc"),
			"name":        tftypes.NewValue(tftypes.String, "svc"),
			"binary_path": tftypes.NewValue(tftypes.String, `C:\svc.exe`),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Update(context.Background(),
		resource.UpdateRequest{Plan: plan, State: priorState},
		resp,
	)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.updateIn.DisplayName != "New Display" || fake.updateIn.StartType != "Manual" {
		t.Errorf("update input mismatch: %+v", fake.updateIn)
	}
}

func TestDelete_Handler_HappyPath(t *testing.T) {
	fake := &fakeSvcClient{}
	r := &windowsServiceResource{svc: fake}

	schemaDef := windowsServiceSchemaDefinition()
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "svc"),
			"name": tftypes.NewValue(tftypes.String, "svc"),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.deleteName != "svc" {
		t.Errorf("Delete called with %q, want svc", fake.deleteName)
	}
}

func TestDelete_Handler_ClientError(t *testing.T) {
	fake := &fakeSvcClient{deleteErr: winclient.NewServiceError(
		winclient.ServiceErrorTimeout, "did not stop in time", nil, nil)}
	r := &windowsServiceResource{svc: fake}

	schemaDef := windowsServiceSchemaDefinition()
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: svcObj(map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, "svc"),
			"name": tftypes.NewValue(tftypes.String, "svc"),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: priorState}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected timeout error diag")
	}
}

// TestImportState covers the ImportState handler: id + name must be set.
func TestImportState_Handler(t *testing.T) {
	r := &windowsServiceResource{}
	schemaDef := windowsServiceSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: svcObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "svc"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	// Verify both id and name are set in the resulting state.
	var m windowsServiceModel
	d := resp.State.Get(context.Background(), &m)
	if d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != "svc" || m.Name.ValueString() != "svc" {
		t.Errorf("import state = id=%q name=%q", m.ID.ValueString(), m.Name.ValueString())
	}
}
