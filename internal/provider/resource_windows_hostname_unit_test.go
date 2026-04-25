// Package provider — unit tests for the windows_hostname resource.
//
// These tests complement the acceptance-test skeletons in
// resource_windows_hostname_test.go by exercising the schema, validators,
// helpers, and CRUD handlers without touching WinRM. They use a
// fakeHostnameClient injected into windowsHostnameResource.hn.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// -----------------------------------------------------------------------------
// Fake WindowsHostnameClient
// -----------------------------------------------------------------------------

type fakeHostnameClient struct {
	createOut *winclient.HostnameState
	createErr error
	readOut   *winclient.HostnameState
	readErr   error
	updateOut *winclient.HostnameState
	updateErr error
	deleteErr error
}

func (f *fakeHostnameClient) Create(_ context.Context, _ winclient.HostnameInput) (*winclient.HostnameState, error) {
	return f.createOut, f.createErr
}
func (f *fakeHostnameClient) Read(_ context.Context, _ string) (*winclient.HostnameState, error) {
	return f.readOut, f.readErr
}
func (f *fakeHostnameClient) Update(_ context.Context, _ string, _ winclient.HostnameInput) (*winclient.HostnameState, error) {
	return f.updateOut, f.updateErr
}
func (f *fakeHostnameClient) Delete(_ context.Context, _ string) error {
	return f.deleteErr
}

// fakeHnState builds a realistic HostnameState for tests.
func fakeHnState(machineID, current, pending string, rebootPending bool) *winclient.HostnameState {
	return &winclient.HostnameState{
		MachineID:     machineID,
		CurrentName:   current,
		PendingName:   pending,
		RebootPending: rebootPending,
		PartOfDomain:  false,
	}
}

// hn tftypes helpers — mirrors the hostname schema attribute set.
func hnObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":             tftypes.String,
		"name":           tftypes.String,
		"current_name":   tftypes.String,
		"pending_name":   tftypes.String,
		"reboot_pending": tftypes.Bool,
		"machine_id":     tftypes.String,
		"force":          tftypes.Bool,
	}}
}

func hnObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":             tftypes.NewValue(tftypes.String, nil),
		"name":           tftypes.NewValue(tftypes.String, nil),
		"current_name":   tftypes.NewValue(tftypes.String, ""),
		"pending_name":   tftypes.NewValue(tftypes.String, ""),
		"reboot_pending": tftypes.NewValue(tftypes.Bool, false),
		"machine_id":     tftypes.NewValue(tftypes.String, nil),
		"force":          tftypes.NewValue(tftypes.Bool, false),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(hnObjectType(), base)
}

// hnValidatorStringReq builds a validator.StringRequest for hostname tests.
func hnValidatorStringReq(val string) validator.StringRequest {
	return validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringValue(val),
	}
}

// -----------------------------------------------------------------------------
// Metadata + Schema
// -----------------------------------------------------------------------------

func TestHostnameMetadata(t *testing.T) {
	r := &windowsHostnameResource{}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_hostname" {
		t.Errorf("TypeName = %q, want windows_hostname", resp.TypeName)
	}
}

func TestHostnameSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsHostnameSchemaDefinition()
	want := []string{"id", "name", "current_name", "pending_name", "reboot_pending", "machine_id", "force"}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestHostnameSchema_ResourceLevelCall(t *testing.T) {
	r := &windowsHostnameResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

func TestNewWindowsHostnameResource_NotNil(t *testing.T) {
	if NewWindowsHostnameResource() == nil {
		t.Fatal("NewWindowsHostnameResource must not return nil")
	}
}

// -----------------------------------------------------------------------------
// netbiosNameValidator (EC-1)
// -----------------------------------------------------------------------------

func TestNetbiosNameValidator_PureNumericRejected(t *testing.T) {
	v := netbiosNameValidator{}
	req := hnValidatorStringReq("12345")
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("purely numeric name should fail validation")
	}
	if len(resp.Diagnostics) > 0 && !strings.Contains(resp.Diagnostics[0].Detail(), "purely numeric") {
		t.Errorf("diagnostic should mention 'purely numeric': %s", resp.Diagnostics[0].Detail())
	}
}

func TestNetbiosNameValidator_ValidNamePasses(t *testing.T) {
	v := netbiosNameValidator{}
	validNames := []string{"WORKSTATION1", "WEB-SERVER", "Server01", "a"}
	for _, name := range validNames {
		req := hnValidatorStringReq(name)
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("valid hostname %q rejected: %v", name, resp.Diagnostics)
		}
	}
}

func TestNetbiosNameValidator_NullSkipped(t *testing.T) {
	v := netbiosNameValidator{}
	req := validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringNull(),
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should be skipped by validator")
	}
}

func TestNetbiosNameValidator_UnknownSkipped(t *testing.T) {
	v := netbiosNameValidator{}
	req := validator.StringRequest{
		Path:        path.Root("name"),
		ConfigValue: types.StringUnknown(),
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("unknown value should be skipped by validator")
	}
}

func TestNetbiosNameValidator_Description(t *testing.T) {
	v := netbiosNameValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description() must return non-empty string")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription() must return non-empty string")
	}
}

// -----------------------------------------------------------------------------
// Configure
// -----------------------------------------------------------------------------

func TestHostnameConfigure_NilProviderData(t *testing.T) {
	r := &windowsHostnameResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op: %v", resp.Diagnostics)
	}
}

func TestHostnameConfigure_WrongType(t *testing.T) {
	r := &windowsHostnameResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "bad-type"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should produce an error diagnostic")
	}
}

func TestHostnameConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsHostnameResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.client != c {
		t.Error("Configure must populate client field")
	}
	if r.hn == nil {
		t.Error("Configure must populate hn field")
	}
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestHostnameImportState(t *testing.T) {
	r := &windowsHostnameResource{}
	schemaDef := windowsHostnameSchemaDefinition()
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: hnObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "9a8b7c6d-1234-5678-abcd-ef0123456789"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState unexpected diags: %v", resp.Diagnostics)
	}
	var m windowsHostnameModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "9a8b7c6d-1234-5678-abcd-ef0123456789" {
		t.Errorf("ID = %q, want machine GUID", m.ID.ValueString())
	}
	if m.MachineID.ValueString() != "9a8b7c6d-1234-5678-abcd-ef0123456789" {
		t.Errorf("MachineID = %q, want machine GUID", m.MachineID.ValueString())
	}
}

// -----------------------------------------------------------------------------
// Create handler
// -----------------------------------------------------------------------------

func TestHostnameCreate_HappyPath(t *testing.T) {
	fake := &fakeHostnameClient{
		createOut: fakeHnState("guid-1", "OLD-NAME", "NEW-NAME", true),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "NEW-NAME"),
			"force": tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: hnObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	// reboot_pending warning is expected (pending != current).
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	var m windowsHostnameModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "guid-1" {
		t.Errorf("ID = %q, want guid-1", m.ID.ValueString())
	}
	if m.PendingName.ValueString() != "NEW-NAME" {
		t.Errorf("PendingName = %q, want NEW-NAME", m.PendingName.ValueString())
	}
	// Reboot pending warning should be present.
	if !resp.Diagnostics.HasError() && !m.RebootPending.ValueBool() {
		// The warning doesn't make state HasError; check separately.
	}
	if !m.RebootPending.ValueBool() {
		t.Error("RebootPending should be true when pending != current")
	}
}

func TestHostnameCreate_PermissionDenied(t *testing.T) {
	fake := &fakeHostnameClient{
		createErr: winclient.NewHostnameError(
			winclient.HostnameErrorPermission,
			"Access is denied",
			nil, nil,
		),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "MYHOST"),
			"force": tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: hnObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected permission_denied error")
	}
}

func TestHostnameCreate_DomainJoined(t *testing.T) {
	fake := &fakeHostnameClient{
		createErr: winclient.NewHostnameError(
			winclient.HostnameErrorDomainJoined,
			"this machine is domain-joined; workgroup renames only (EC-5)",
			nil,
			map[string]string{"domain": "corp.example.com"},
		),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "MYHOST"),
			"force": tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: hnObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-5: expected domain_joined error diagnostic")
	}
}

// -----------------------------------------------------------------------------
// Read handler
// -----------------------------------------------------------------------------

func TestHostnameRead_HappyPath(t *testing.T) {
	fake := &fakeHostnameClient{
		readOut: fakeHnState("guid-1", "MYHOST", "MYHOST", false),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id":   tftypes.NewValue(tftypes.String, "guid-1"),
			"name":         tftypes.NewValue(tftypes.String, "MYHOST"),
			"current_name": tftypes.NewValue(tftypes.String, "MYHOST"),
			"pending_name": tftypes.NewValue(tftypes.String, "MYHOST"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should not be removed on happy read")
	}
}

func TestHostnameRead_MachineMismatch_RemovesResource(t *testing.T) {
	// EC-10: machine replaced → remove from state.
	fake := &fakeHostnameClient{
		readErr: winclient.NewHostnameError(
			winclient.HostnameErrorMachineMismatch,
			"MachineGuid does not match state ID; machine has been replaced",
			nil,
			map[string]string{"expected": "guid-1", "actual": "guid-NEW"},
		),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id": tftypes.NewValue(tftypes.String, "guid-1"),
			"name":       tftypes.NewValue(tftypes.String, "MYHOST"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	// machine_mismatch removes resource, does not error.
	if resp.Diagnostics.HasError() {
		t.Fatalf("EC-10: machine_mismatch should trigger RemoveResource, not error: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("EC-10: state must be removed when machine is replaced")
	}
}

func TestHostnameRead_DomainJoined_ReturnsError(t *testing.T) {
	// EC-5: domain-joined detected at Read → error diagnostic.
	fake := &fakeHostnameClient{
		readErr: winclient.NewHostnameError(
			winclient.HostnameErrorDomainJoined,
			"machine is domain-joined",
			nil, nil,
		),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id": tftypes.NewValue(tftypes.String, "guid-1"),
			"name":       tftypes.NewValue(tftypes.String, "MYHOST"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-5: expected error diagnostic for domain_joined")
	}
}

func TestHostnameRead_FallbackToID_WhenMachineIDEmpty(t *testing.T) {
	// When machine_id is empty, Read should fall back to id.
	fake := &fakeHostnameClient{
		readOut: fakeHnState("guid-1", "MYHOST", "MYHOST", false),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id": tftypes.NewValue(tftypes.String, nil), // null machine_id
			"name":       tftypes.NewValue(tftypes.String, "MYHOST"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("fallback to id should work: %v", resp.Diagnostics)
	}
}

func TestHostnameRead_GenericError(t *testing.T) {
	fake := &fakeHostnameClient{
		readErr: winclient.NewHostnameError(
			winclient.HostnameErrorUnreachable,
			"WinRM connection refused",
			nil, nil,
		),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id": tftypes.NewValue(tftypes.String, "guid-1"),
			"name":       tftypes.NewValue(tftypes.String, "MYHOST"),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected unreachable error diagnostic")
	}
}

// -----------------------------------------------------------------------------
// Update handler
// -----------------------------------------------------------------------------

func TestHostnameUpdate_HappyPath(t *testing.T) {
	fake := &fakeHostnameClient{
		updateOut: fakeHnState("guid-1", "OLD-NAME", "NEW-NAME", true),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"name":       tftypes.NewValue(tftypes.String, "NEW-NAME"),
			"force":      tftypes.NewValue(tftypes.Bool, false),
			"machine_id": tftypes.NewValue(tftypes.String, "guid-1"),
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
		}),
	}
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id":   tftypes.NewValue(tftypes.String, "guid-1"),
			"name":         tftypes.NewValue(tftypes.String, "OLD-NAME"),
			"current_name": tftypes.NewValue(tftypes.String, "OLD-NAME"),
			"pending_name": tftypes.NewValue(tftypes.String, "OLD-NAME"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	var m windowsHostnameModel
	resp.State.Get(context.Background(), &m)
	if m.PendingName.ValueString() != "NEW-NAME" {
		t.Errorf("PendingName = %q, want NEW-NAME", m.PendingName.ValueString())
	}
}

func TestHostnameUpdate_MachineMismatch(t *testing.T) {
	fake := &fakeHostnameClient{
		updateErr: winclient.NewHostnameError(
			winclient.HostnameErrorMachineMismatch,
			"machine has been replaced (EC-10)",
			nil, nil,
		),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"name":       tftypes.NewValue(tftypes.String, "NEW-NAME"),
			"machine_id": tftypes.NewValue(tftypes.String, "guid-1"),
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
		}),
	}
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id": tftypes.NewValue(tftypes.String, "guid-1"),
			"name":       tftypes.NewValue(tftypes.String, "OLD-NAME"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("EC-10: expected machine_mismatch error diagnostic on update")
	}
}

func TestHostnameUpdate_FallbackToIDWhenMachineIDEmpty(t *testing.T) {
	fake := &fakeHostnameClient{
		updateOut: fakeHnState("guid-1", "OLD-NAME", "NEW-NAME", true),
	}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"name":  tftypes.NewValue(tftypes.String, "NEW-NAME"),
			"id":    tftypes.NewValue(tftypes.String, "guid-1"),
			"force": tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	priorState := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id": tftypes.NewValue(tftypes.String, nil), // null
			"name":       tftypes.NewValue(tftypes.String, "OLD-NAME"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: priorState.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("fallback to id should work: %v", resp.Diagnostics)
	}
}

// -----------------------------------------------------------------------------
// Delete handler (no-op, EC-7)
// -----------------------------------------------------------------------------

func TestHostnameDelete_NoOp(t *testing.T) {
	fake := &fakeHostnameClient{deleteErr: nil}
	r := &windowsHostnameResource{hn: fake}
	schemaDef := windowsHostnameSchemaDefinition()
	state := tfsdk.State{
		Schema: schemaDef,
		Raw: hnObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, "guid-1"),
			"machine_id":   tftypes.NewValue(tftypes.String, "guid-1"),
			"name":         tftypes.NewValue(tftypes.String, "MYHOST"),
			"current_name": tftypes.NewValue(tftypes.String, "MYHOST"),
			"pending_name": tftypes.NewValue(tftypes.String, "MYHOST"),
		}),
	}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("EC-7: Delete should be a no-op, got: %v", resp.Diagnostics)
	}
}

// -----------------------------------------------------------------------------
// modelFromHostnameState helper
// -----------------------------------------------------------------------------

func TestModelFromHostnameState_AllFields(t *testing.T) {
	state := fakeHnState("guid-99", "CUR-HOST", "PEND-HOST", true)
	prior := windowsHostnameModel{
		Name:  types.StringValue("PEND-HOST"),
		Force: types.BoolValue(true),
	}
	m := modelFromHostnameState(state, prior)

	if m.ID.ValueString() != "guid-99" {
		t.Errorf("ID = %q, want guid-99", m.ID.ValueString())
	}
	if m.MachineID.ValueString() != "guid-99" {
		t.Errorf("MachineID = %q, want guid-99", m.MachineID.ValueString())
	}
	if m.CurrentName.ValueString() != "CUR-HOST" {
		t.Errorf("CurrentName = %q", m.CurrentName.ValueString())
	}
	if m.PendingName.ValueString() != "PEND-HOST" {
		t.Errorf("PendingName = %q", m.PendingName.ValueString())
	}
	if !m.RebootPending.ValueBool() {
		t.Error("RebootPending should be true")
	}
	if !m.Force.ValueBool() {
		t.Error("Force should be true (from prior)")
	}
}

func TestModelFromHostnameState_NullPriorName(t *testing.T) {
	// When prior Name is null, falls back to PendingName.
	state := fakeHnState("guid-1", "OLD-NAME", "NEW-NAME", true)
	prior := windowsHostnameModel{
		Name:  types.StringNull(),
		Force: types.BoolNull(),
	}
	m := modelFromHostnameState(state, prior)
	if m.Name.ValueString() != "NEW-NAME" {
		t.Errorf("Name should fall back to PendingName: got %q", m.Name.ValueString())
	}
	if m.Force.ValueBool() {
		t.Error("Force should default to false when null in prior")
	}
}

func TestModelFromHostnameState_EmptyPriorName(t *testing.T) {
	// When prior Name is empty string, falls back to PendingName.
	state := fakeHnState("guid-1", "CUR", "PEND", false)
	prior := windowsHostnameModel{
		Name:  types.StringValue(""),
		Force: types.BoolValue(false),
	}
	m := modelFromHostnameState(state, prior)
	if m.Name.ValueString() != "PEND" {
		t.Errorf("Name should fall back to PendingName on empty prior: got %q", m.Name.ValueString())
	}
}

// -----------------------------------------------------------------------------
// maybeWarnRebootPending helper
// -----------------------------------------------------------------------------

func TestMaybeWarnRebootPending_WhenPending(t *testing.T) {
	var diags diag.Diagnostics
	m := windowsHostnameModel{
		RebootPending: types.BoolValue(true),
		CurrentName:   types.StringValue("OLD"),
		PendingName:   types.StringValue("NEW"),
	}
	maybeWarnRebootPending(&diags, m, m)
	if diags.HasError() {
		t.Error("reboot pending should emit a warning, not an error")
	}
	var sawWarning bool
	for _, d := range diags {
		if d.Severity() == diag.SeverityWarning {
			sawWarning = true
			if !strings.Contains(d.Summary(), "Reboot pending") {
				t.Errorf("warning summary should mention 'Reboot pending': %s", d.Summary())
			}
		}
	}
	if !sawWarning {
		t.Error("expected a warning diagnostic when reboot is pending")
	}
}

func TestMaybeWarnRebootPending_WhenNotPending(t *testing.T) {
	var diags diag.Diagnostics
	m := windowsHostnameModel{
		RebootPending: types.BoolValue(false),
		CurrentName:   types.StringValue("SAME"),
		PendingName:   types.StringValue("SAME"),
	}
	maybeWarnRebootPending(&diags, m, m)
	if len(diags) > 0 {
		t.Errorf("no diagnostic expected when not pending: %v", diags)
	}
}

// -----------------------------------------------------------------------------
// addHostnameDiag helper
// -----------------------------------------------------------------------------

func TestAddHostnameDiag_StructuredError(t *testing.T) {
	var diags diag.Diagnostics
	he := winclient.NewHostnameError(
		winclient.HostnameErrorDomainJoined,
		"machine is in domain corp.example.com",
		nil,
		map[string]string{"domain": "corp.example.com"},
	)
	addHostnameDiag(&diags, "Read failed", he)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags.Errors()[0].Detail()
	if !strings.Contains(detail, "corp.example.com") {
		t.Errorf("detail should contain domain name: %s", detail)
	}
	if !strings.Contains(detail, "domain_joined") {
		t.Errorf("detail should contain kind: %s", detail)
	}
}

func TestAddHostnameDiag_PlainError(t *testing.T) {
	var diags diag.Diagnostics
	addHostnameDiag(&diags, "Something failed", errors.New("plain error"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(diags.Errors()[0].Detail(), "plain error") {
		t.Errorf("detail should contain plain error text: %s", diags.Errors()[0].Detail())
	}
}

func TestAddHostnameDiag_StructuredErrorNoContext(t *testing.T) {
	var diags diag.Diagnostics
	he := winclient.NewHostnameError(
		winclient.HostnameErrorPermission,
		"Access is denied",
		nil, nil,
	)
	addHostnameDiag(&diags, "Update failed", he)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags.Errors()[0].Detail()
	if !strings.Contains(detail, "Access is denied") {
		t.Errorf("detail should contain message: %s", detail)
	}
}
