// Package provider — unit tests for the windows_domain_membership resource.
//
// These tests exercise the schema, validators, helpers, and CRUD handlers
// without touching SSH. They use a fakeDomainMembershipClient injected into
// windowsDomainMembershipResource.dm.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

// -----------------------------------------------------------------------------
// Fake WindowsDomainMembershipClient
// -----------------------------------------------------------------------------

type fakeDomainMembershipClient struct {
	readOut     *winclient.DomainMembershipState
	readErr     error
	joinOut     *winclient.DomainMembershipState
	joinRes     *winclient.DomainJoinResult
	joinErr     error
	joinInput   *winclient.DomainJoinInput
	unjoinOut   *winclient.DomainMembershipState
	unjoinRes   *winclient.DomainUnjoinResult
	unjoinErr   error
	unjoinIn    *winclient.DomainUnjoinInput
	readCalls   int
	joinCalls   int
	unjoinCalls int
}

func (f *fakeDomainMembershipClient) Read(_ context.Context) (*winclient.DomainMembershipState, error) {
	f.readCalls++
	return f.readOut, f.readErr
}

func (f *fakeDomainMembershipClient) Join(_ context.Context, in winclient.DomainJoinInput) (*winclient.DomainMembershipState, *winclient.DomainJoinResult, error) {
	f.joinCalls++
	f.joinInput = &in
	return f.joinOut, f.joinRes, f.joinErr
}

func (f *fakeDomainMembershipClient) Unjoin(_ context.Context, in winclient.DomainUnjoinInput) (*winclient.DomainMembershipState, *winclient.DomainUnjoinResult, error) {
	f.unjoinCalls++
	f.unjoinIn = &in
	return f.unjoinOut, f.unjoinRes, f.unjoinErr
}

// fakeDMState builds a realistic DomainMembershipState for tests.
func fakeDMState(domain string, partOfDomain bool, pendingReboot bool) *winclient.DomainMembershipState {
	return &winclient.DomainMembershipState{
		Domain:          domain,
		PartOfDomain:    partOfDomain,
		ComputerName:    "WIN01",
		PendingReboot:   pendingReboot,
		SecureChannelOk: partOfDomain,
	}
}

// dmCredentialObjectType is the tftypes form of the join_credential block.
func dmCredentialObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"username":    tftypes.String,
		"password":    tftypes.String,
		"password_wo": tftypes.String,
	}}
}

// dmObjectType mirrors the domain_membership schema attribute set.
func dmObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                    tftypes.String,
		"domain":                tftypes.String,
		"ou_path":               tftypes.String,
		"server":                tftypes.String,
		"join_credential":       dmCredentialObjectType(),
		"restart":               tftypes.Bool,
		"unjoin_on_destroy":     tftypes.Bool,
		"unjoin_workgroup_name": tftypes.String,
		"computer_name":         tftypes.String,
		"pending_reboot":        tftypes.Bool,
		"secure_channel_ok":     tftypes.Bool,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

// dmNullTimeoutsValue is the absent value for the `timeouts {}` block.
func dmNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

// dmTimeoutsValue builds a `timeouts {}` value carrying a duration for one
// named operation (create/read/update/delete), the rest null.
func dmTimeoutsValue(op, d string) tftypes.Value {
	vals := map[string]tftypes.Value{
		"create": tftypes.NewValue(tftypes.String, nil),
		"read":   tftypes.NewValue(tftypes.String, nil),
		"update": tftypes.NewValue(tftypes.String, nil),
		"delete": tftypes.NewValue(tftypes.String, nil),
	}
	vals[op] = tftypes.NewValue(tftypes.String, d)
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, vals)
}

// dmCredentialValue builds a join_credential tftypes value.
func dmCredentialValue(username, password, passwordWO string) tftypes.Value {
	strOrNil := func(s string) tftypes.Value {
		if s == "" {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, s)
	}
	// passwordWO uses a sentinel: "\x00set" means set-empty-string is not
	// needed — empty string and null are treated the same by the handler.
	return tftypes.NewValue(dmCredentialObjectType(), map[string]tftypes.Value{
		"username":    strOrNil(username),
		"password":    strOrNil(password),
		"password_wo": strOrNil(passwordWO),
	})
}

func dmObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":                    tftypes.NewValue(tftypes.String, nil),
		"domain":                tftypes.NewValue(tftypes.String, nil),
		"ou_path":               tftypes.NewValue(tftypes.String, nil),
		"server":                tftypes.NewValue(tftypes.String, nil),
		"join_credential":       tftypes.NewValue(dmCredentialObjectType(), nil),
		"restart":               tftypes.NewValue(tftypes.Bool, false),
		"unjoin_on_destroy":     tftypes.NewValue(tftypes.Bool, false),
		"unjoin_workgroup_name": tftypes.NewValue(tftypes.String, nil),
		"computer_name":         tftypes.NewValue(tftypes.String, nil),
		"pending_reboot":        tftypes.NewValue(tftypes.Bool, nil),
		"secure_channel_ok":     tftypes.NewValue(tftypes.Bool, nil),
		"timeouts":              dmNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(dmObjectType(), base)
}

// dmConfig wraps a raw value as a tfsdk.Config for Create handlers that read
// WriteOnly values from config.
func dmConfig(t *testing.T, schema resource.SchemaResponse, raw tftypes.Value) tfsdk.Config {
	t.Helper()
	return tfsdk.Config{Schema: schema.Schema, Raw: raw}
}

// -----------------------------------------------------------------------------
// Metadata + Schema
// -----------------------------------------------------------------------------

func TestDomainMembershipMetadata(t *testing.T) {
	r := &windowsDomainMembershipResource{}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_domain_membership" {
		t.Errorf("TypeName = %q, want windows_domain_membership", resp.TypeName)
	}
}

func TestDomainMembershipSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsDomainMembershipSchemaDefinition(context.Background())
	want := []string{"id", "domain", "ou_path", "server", "join_credential", "restart",
		"unjoin_on_destroy", "unjoin_workgroup_name", "computer_name", "pending_reboot", "secure_channel_ok", "timeouts"}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestNewWindowsDomainMembershipResource_NotNil(t *testing.T) {
	if NewWindowsDomainMembershipResource() == nil {
		t.Fatal("NewWindowsDomainMembershipResource must not return nil")
	}
}

func TestDomainMembershipSchema_TimeoutsBlock(t *testing.T) {
	s := windowsDomainMembershipSchemaDefinition(context.Background())
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Fatal("schema missing timeouts block")
	}
}

// -----------------------------------------------------------------------------
// Configure
// -----------------------------------------------------------------------------

func TestDomainMembershipConfigure_NilProviderData(t *testing.T) {
	r := &windowsDomainMembershipResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op: %v", resp.Diagnostics)
	}
}

func TestDomainMembershipConfigure_WrongType(t *testing.T) {
	r := &windowsDomainMembershipResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "bad-type"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should produce an error diagnostic")
	}
}

func TestDomainMembershipConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsDomainMembershipResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.dm == nil {
		t.Error("Configure must populate dm field")
	}
}

// -----------------------------------------------------------------------------
// ConfigValidators
// -----------------------------------------------------------------------------

func TestDomainMembershipConfigValidators_UnjoinRequiresStatePassword(t *testing.T) {
	schemaDef := windowsDomainMembershipSchemaDefinition(context.Background())

	// unjoin_on_destroy=true with password_wo only → error.
	raw := dmObj(map[string]tftypes.Value{
		"domain":            tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential":   dmCredentialValue("joiner", "", "wo-secret"),
		"unjoin_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	var model windowsDomainMembershipModel
	cfg := tfsdk.Config{Schema: schemaDef, Raw: raw}
	if diags := cfg.Get(context.Background(), &model); diags.HasError() {
		t.Fatalf("Config.Get: %v", diags)
	}
	v := domainMembershipUnjoinValidator{}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(),
		resource.ValidateConfigRequest{Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("unjoin_on_destroy=true with password_wo must be rejected")
	} else if !strings.Contains(resp.Diagnostics[0].Detail(), "unavailable at destroy time") {
		t.Errorf("diagnostic should explain destroy-time unavailability: %s", resp.Diagnostics[0].Detail())
	}

	// unjoin_on_destroy=true with password → passes.
	rawOK := dmObj(map[string]tftypes.Value{
		"domain":            tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential":   dmCredentialValue("joiner", "state-secret", ""),
		"unjoin_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	respOK := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(),
		resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: schemaDef, Raw: rawOK}}, respOK)
	if respOK.Diagnostics.HasError() {
		t.Errorf("unjoin with state password should pass: %v", respOK.Diagnostics)
	}

	// unjoin_on_destroy=true with unknown password (plan-time reference) →
	// skipped; Delete fails closed if the password is still absent.
	unknownCred := tftypes.NewValue(dmCredentialObjectType(), map[string]tftypes.Value{
		"username":    tftypes.NewValue(tftypes.String, "joiner"),
		"password":    tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"password_wo": tftypes.NewValue(tftypes.String, nil),
	})
	rawUnknown := dmObj(map[string]tftypes.Value{
		"domain":            tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential":   unknownCred,
		"unjoin_on_destroy": tftypes.NewValue(tftypes.Bool, true),
	})
	respUnknown := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(),
		resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: schemaDef, Raw: rawUnknown}}, respUnknown)
	if respUnknown.Diagnostics.HasError() {
		t.Errorf("unjoin with unknown password should be skipped: %v", respUnknown.Diagnostics)
	}

	// unjoin_on_destroy=false with password_wo → passes.
	rawWO := dmObj(map[string]tftypes.Value{
		"domain":            tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential":   dmCredentialValue("joiner", "", "wo-secret"),
		"unjoin_on_destroy": tftypes.NewValue(tftypes.Bool, false),
	})
	respWO := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(),
		resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: schemaDef, Raw: rawWO}}, respWO)
	if respWO.Diagnostics.HasError() {
		t.Errorf("password_wo without unjoin should pass: %v", respWO.Diagnostics)
	}
}

// -----------------------------------------------------------------------------
// Create handler
// -----------------------------------------------------------------------------

func TestDomainMembershipCreate_HappyPath(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		joinOut: fakeDMState("corp.example.com", true, true),
		joinRes: &winclient.DomainJoinResult{RebootScheduled: false},
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	raw := dmObj(map[string]tftypes.Value{
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential": dmCredentialValue("joiner@corp.example.com", "S3cret!", ""),
	})
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: dmConfig(t, *schemaResp, raw)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	var m windowsDomainMembershipModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "corp.example.com" {
		t.Errorf("ID = %q, want lower-cased domain", m.ID.ValueString())
	}
	if m.ComputerName.ValueString() != "WIN01" {
		t.Errorf("ComputerName = %q, want WIN01", m.ComputerName.ValueString())
	}
	if !m.PendingReboot.ValueBool() {
		t.Error("PendingReboot should be true after join")
	}
	if fake.joinCalls != 1 {
		t.Errorf("Join calls = %d, want 1", fake.joinCalls)
	}
	if fake.joinInput == nil || fake.joinInput.Password != "S3cret!" {
		t.Error("join password must reach the client input")
	}
	// Restart=false with pending reboot → warning, not error.
	if resp.Diagnostics.HasError() {
		t.Errorf("pending reboot must warn, not error: %v", resp.Diagnostics)
	}
}

func TestDomainMembershipCreate_IDLowerCased(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		joinOut: fakeDMState("corp.example.com", true, false),
		joinRes: &winclient.DomainJoinResult{},
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	raw := dmObj(map[string]tftypes.Value{
		"domain":          tftypes.NewValue(tftypes.String, "CORP.EXAMPLE.COM"),
		"join_credential": dmCredentialValue("joiner", "S3cret!", ""),
	})
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: dmConfig(t, *schemaResp, raw)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	var m windowsDomainMembershipModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "corp.example.com" {
		t.Errorf("ID = %q, want lower-cased domain", m.ID.ValueString())
	}
	if fake.joinInput == nil || fake.joinInput.Domain != "corp.example.com" {
		t.Errorf("client must receive lower-cased domain, got %+v", fake.joinInput)
	}
}

func TestDomainMembershipCreate_PasswordWOFromConfig(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		joinOut: fakeDMState("corp.example.com", true, false),
		joinRes: &winclient.DomainJoinResult{},
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	// Plan carries null password_wo (WriteOnly is null in plan at apply);
	// config carries the value.
	planRaw := dmObj(map[string]tftypes.Value{
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential": dmCredentialValue("joiner", "", ""),
	})
	configRaw := dmObj(map[string]tftypes.Value{
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential": dmCredentialValue("joiner", "", "wo-secret"),
	})
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: planRaw}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: dmConfig(t, *schemaResp, configRaw)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if fake.joinInput == nil || fake.joinInput.Password != "wo-secret" {
		t.Errorf("password_wo must be overlaid from config, got %+v", fake.joinInput)
	}
}

func TestDomainMembershipCreate_AlreadyJoined(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		joinErr: winclient.NewDomainMembershipError(
			winclient.DomainMembershipErrorAlreadyJoined,
			"already joined to corp.example.com; use terraform import",
			nil, map[string]string{"domain": "corp.example.com"}),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	raw := dmObj(map[string]tftypes.Value{
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential": dmCredentialValue("joiner", "S3cret!", ""),
	})
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: dmConfig(t, *schemaResp, raw)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected already_joined error diagnostic")
	}
}

func TestDomainMembershipCreate_JoinedToOtherDomain(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		joinErr: winclient.NewDomainMembershipError(
			winclient.DomainMembershipErrorJoinedToOtherDomain,
			"already joined to other.example.com",
			nil, nil),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	raw := dmObj(map[string]tftypes.Value{
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential": dmCredentialValue("joiner", "S3cret!", ""),
	})
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: dmConfig(t, *schemaResp, raw)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected joined_to_other_domain error diagnostic")
	}
	if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "joined_to_other_domain") {
		t.Errorf("detail should contain kind: %s", resp.Diagnostics.Errors()[0].Detail())
	}
}

// -----------------------------------------------------------------------------
// Read handler
// -----------------------------------------------------------------------------

func TestDomainMembershipRead_HappyPath(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		readOut: fakeDMState("corp.example.com", true, false),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	prior := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":              tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential": dmCredentialValue("joiner", "S3cret!", ""),
	})}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: prior.Raw.Copy()}}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should not be removed on happy read")
	}
	var m windowsDomainMembershipModel
	resp.State.Get(context.Background(), &m)
	if m.ComputerName.ValueString() != "WIN01" {
		t.Errorf("ComputerName = %q, want WIN01", m.ComputerName.ValueString())
	}
}

func TestDomainMembershipRead_LeftDomain_RemovesResource(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		readOut: fakeDMState("WORKGROUP", false, false),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	prior := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":     tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain": tftypes.NewValue(tftypes.String, "corp.example.com"),
	})}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: prior.Raw.Copy()}}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("removal must not error: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("workgroup drift must remove the resource from state")
	}
}

func TestDomainMembershipRead_MismatchRemoves_UnlessPendingReboot(t *testing.T) {
	schemaOf := func() resource.SchemaResponse {
		r := &windowsDomainMembershipResource{}
		s := &resource.SchemaResponse{}
		r.Schema(context.Background(), resource.SchemaRequest{}, s)
		return *s
	}

	// Different domain, no pending reboot → removed.
	fake := &fakeDomainMembershipClient{readOut: fakeDMState("other.example.com", true, false)}
	r := &windowsDomainMembershipResource{dm: fake}
	s := schemaOf()
	prior := tfsdk.State{Schema: s.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":             tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":         tftypes.NewValue(tftypes.String, "corp.example.com"),
		"pending_reboot": tftypes.NewValue(tftypes.Bool, false),
	})}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: s.Schema, Raw: prior.Raw.Copy()}}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("removal must not error: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("domain mismatch without pending reboot must remove the resource")
	}

	// Different domain, pending reboot → tolerated.
	fake2 := &fakeDomainMembershipClient{readOut: fakeDMState("other.example.com", true, false)}
	r2 := &windowsDomainMembershipResource{dm: fake2}
	s2 := schemaOf()
	prior2 := tfsdk.State{Schema: s2.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":             tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":         tftypes.NewValue(tftypes.String, "corp.example.com"),
		"pending_reboot": tftypes.NewValue(tftypes.Bool, true),
	})}
	resp2 := &resource.ReadResponse{State: tfsdk.State{Schema: s2.Schema, Raw: prior2.Raw.Copy()}}
	r2.Read(context.Background(), resource.ReadRequest{State: prior2}, resp2)
	if resp2.Diagnostics.HasError() {
		t.Fatalf("tolerated mismatch must not error: %v", resp2.Diagnostics)
	}
	if resp2.State.Raw.IsNull() {
		t.Error("domain mismatch while pending_reboot must be tolerated")
	}
	var m windowsDomainMembershipModel
	resp2.State.Get(context.Background(), &m)
	if m.Domain.ValueString() != "corp.example.com" {
		t.Errorf("tolerated read must preserve state domain, got %q", m.Domain.ValueString())
	}
}

// -----------------------------------------------------------------------------
// Update handler (state-only, no remote action)
// -----------------------------------------------------------------------------

func TestDomainMembershipUpdate_NoRemoteAction(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		// Any remote call would succeed; the assertion is that none happens.
		readOut: fakeDMState("corp.example.com", true, false),
		joinOut: fakeDMState("corp.example.com", true, false),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":              tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"ou_path":         tftypes.NewValue(tftypes.String, "OU=New,DC=corp,DC=example,DC=com"),
		"server":          tftypes.NewValue(tftypes.String, "dc01.corp.example.com"),
		"restart":         tftypes.NewValue(tftypes.Bool, true),
		"join_credential": dmCredentialValue("joiner", "S3cret!", ""),
		"computer_name":   tftypes.NewValue(tftypes.String, nil), // unknown in real plans
	})}
	priorState := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":              tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"ou_path":         tftypes.NewValue(tftypes.String, "OU=Old,DC=corp,DC=example,DC=com"),
		"server":          tftypes.NewValue(tftypes.String, "dc00.corp.example.com"),
		"join_credential": dmCredentialValue("joiner", "S3cret!", ""),
		"computer_name":   tftypes.NewValue(tftypes.String, "WIN01"),
		"pending_reboot":  tftypes.NewValue(tftypes.Bool, false),
	})}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: priorState.Raw.Copy()}}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: priorState}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if fake.readCalls+fake.joinCalls+fake.unjoinCalls != 0 {
		t.Errorf("Update must perform no remote action (read=%d join=%d unjoin=%d)",
			fake.readCalls, fake.joinCalls, fake.unjoinCalls)
	}
	var m windowsDomainMembershipModel
	resp.State.Get(context.Background(), &m)
	if m.ComputerName.ValueString() != "WIN01" {
		t.Errorf("Update must preserve computed computer_name, got %q", m.ComputerName.ValueString())
	}
	if m.Server.ValueString() != "dc00.corp.example.com" {
		t.Errorf("Update must preserve prior server (create-only, no remote action), got %q", m.Server.ValueString())
	}
	if m.OUPath.ValueString() != "OU=Old,DC=corp,DC=example,DC=com" {
		t.Errorf("Update must preserve prior ou_path (create-only, no remote action), got %q", m.OUPath.ValueString())
	}
}

// -----------------------------------------------------------------------------
// Delete handler
// -----------------------------------------------------------------------------

func TestDomainMembershipDelete_NoOpDefault(t *testing.T) {
	fake := &fakeDomainMembershipClient{}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	state := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":                tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":            tftypes.NewValue(tftypes.String, "corp.example.com"),
		"unjoin_on_destroy": tftypes.NewValue(tftypes.Bool, false),
	})}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("default Delete should be a no-op: %v", resp.Diagnostics)
	}
	if fake.unjoinCalls != 0 {
		t.Error("default Delete must not call Unjoin")
	}
}

func TestDomainMembershipDelete_UnjoinHappyPath(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		unjoinOut: fakeDMState("WORKGROUP", false, true),
		unjoinRes: &winclient.DomainUnjoinResult{RebootScheduled: true},
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	state := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":                    tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":                tftypes.NewValue(tftypes.String, "corp.example.com"),
		"unjoin_on_destroy":     tftypes.NewValue(tftypes.Bool, true),
		"unjoin_workgroup_name": tftypes.NewValue(tftypes.String, "WORKGROUP"),
		"restart":               tftypes.NewValue(tftypes.Bool, true),
		"join_credential":       dmCredentialValue("joiner", "S3cret!", ""),
	})}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}
	if fake.unjoinCalls != 1 {
		t.Fatalf("Unjoin calls = %d, want 1", fake.unjoinCalls)
	}
	if fake.unjoinIn == nil || fake.unjoinIn.Password != "S3cret!" || fake.unjoinIn.WorkgroupName != "WORKGROUP" {
		t.Errorf("unjoin input wrong: %+v", fake.unjoinIn)
	}
	// restart=true with pending reboot → warning, not error.
	var sawWarning bool
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Error("expected a deferred-reboot warning")
	}
}

func TestDomainMembershipDelete_UnjoinRequiresStatePassword(t *testing.T) {
	fake := &fakeDomainMembershipClient{}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	// password_wo can never be in state — Delete with only a null credential.
	state := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":                    tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":                tftypes.NewValue(tftypes.String, "corp.example.com"),
		"unjoin_on_destroy":     tftypes.NewValue(tftypes.Bool, true),
		"unjoin_workgroup_name": tftypes.NewValue(tftypes.String, "WORKGROUP"),
		"join_credential":       dmCredentialValue("joiner", "", ""),
	})}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("unjoin without a state password must fail closed")
	}
	if fake.unjoinCalls != 0 {
		t.Error("failed-closed Delete must not call Unjoin")
	}
}

func TestDomainMembershipDelete_AlreadyAbsentWithoutPassword(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		// Host already left the domain out-of-band: Read reports a
		// workgroup host, so Delete must succeed without the secret.
		readOut: fakeDMState("WORKGROUP", false, false),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	state := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"id":                    tftypes.NewValue(tftypes.String, "corp.example.com"),
		"domain":                tftypes.NewValue(tftypes.String, "corp.example.com"),
		"unjoin_on_destroy":     tftypes.NewValue(tftypes.Bool, true),
		"unjoin_workgroup_name": tftypes.NewValue(tftypes.String, "WORKGROUP"),
		"join_credential":       dmCredentialValue("joiner", "", ""),
	})}
	resp := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("already-absent Delete must succeed without a password: %v", resp.Diagnostics)
	}
	if fake.unjoinCalls != 0 {
		t.Error("already-absent Delete must not call Unjoin")
	}
}

// -----------------------------------------------------------------------------
// ImportState
// -----------------------------------------------------------------------------

func TestDomainMembershipImportState(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		readOut: fakeDMState("corp.example.com", true, false),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "corp.example.com"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState unexpected diags: %v", resp.Diagnostics)
	}
	var m windowsDomainMembershipModel
	resp.State.Get(context.Background(), &m)
	if m.ID.ValueString() != "corp.example.com" {
		t.Errorf("ID = %q, want corp.example.com", m.ID.ValueString())
	}
	if m.ComputerName.ValueString() != "WIN01" {
		t.Errorf("ComputerName = %q, want WIN01", m.ComputerName.ValueString())
	}
}

func TestDomainMembershipImportState_NotJoined(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		readOut: fakeDMState("WORKGROUP", false, false),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "corp.example.com"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("importing a workgroup host must fail")
	}
}

func TestDomainMembershipImportState_DomainMismatch(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		readOut: fakeDMState("other.example.com", true, false),
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: "corp.example.com"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("importing a host joined to another domain must fail")
	}
}

// -----------------------------------------------------------------------------
// ModifyPlan (create-only ou_path warning)
// -----------------------------------------------------------------------------

func TestDomainMembershipModifyPlan_OUPathChangeWarns(t *testing.T) {
	r := &windowsDomainMembershipResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"domain":  tftypes.NewValue(tftypes.String, "corp.example.com"),
		"ou_path": tftypes.NewValue(tftypes.String, "OU=New,DC=corp,DC=example,DC=com"),
	})}
	prior := tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(map[string]tftypes.Value{
		"domain":  tftypes.NewValue(tftypes.String, "corp.example.com"),
		"ou_path": tftypes.NewValue(tftypes.String, "OU=Old,DC=corp,DC=example,DC=com"),
	})}
	resp := &resource.ModifyPlanResponse{
		Plan: plan,
	}
	r.ModifyPlan(context.Background(), resource.ModifyPlanRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ou_path change must warn, not error: %v", resp.Diagnostics)
	}
	var sawWarning bool
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning && strings.Contains(d.Summary(), "create-only") {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Error("expected a create-only warning for ou_path change")
	}
}

func TestDomainMembershipModifyPlan_OUPathUnchangedNoWarning(t *testing.T) {
	r := &windowsDomainMembershipResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	raw := dmObj(map[string]tftypes.Value{
		"domain":  tftypes.NewValue(tftypes.String, "corp.example.com"),
		"ou_path": tftypes.NewValue(tftypes.String, "OU=Same,DC=corp,DC=example,DC=com"),
	})
	resp := &resource.ModifyPlanResponse{Plan: tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw}}
	r.ModifyPlan(context.Background(), resource.ModifyPlanRequest{
		Plan:  tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw.Copy()},
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: raw.Copy()},
	}, resp)
	if len(resp.Diagnostics) != 0 {
		t.Errorf("unchanged ou_path must not warn: %v", resp.Diagnostics)
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func TestDomainMembershipAddDiag_StructuredError(t *testing.T) {
	var diags diag.Diagnostics
	de := winclient.NewDomainMembershipError(
		winclient.DomainMembershipErrorBadCredentials,
		"logon failure",
		errors.New("winclient: powershell run: exit 1"),
		map[string]string{"domain": "corp.example.com"},
	)
	addDomainMembershipDiag(&diags, "Create failed", de)
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags.Errors()[0].Detail()
	for _, want := range []string{"logon failure", "bad_credentials", "corp.example.com"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail should contain %q: %s", want, detail)
		}
	}
}

func TestDomainMembershipAddDiag_PlainError(t *testing.T) {
	var diags diag.Diagnostics
	addDomainMembershipDiag(&diags, "Something failed", errors.New("plain error"))
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
}

func TestDomainMembershipCreate_PreservesTimeouts(t *testing.T) {
	fake := &fakeDomainMembershipClient{
		joinOut: fakeDMState("corp.example.com", true, false),
		joinRes: &winclient.DomainJoinResult{},
	}
	r := &windowsDomainMembershipResource{dm: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	raw := dmObj(map[string]tftypes.Value{
		"domain":          tftypes.NewValue(tftypes.String, "corp.example.com"),
		"join_credential": dmCredentialValue("joiner", "S3cret!", ""),
		"timeouts":        dmTimeoutsValue("create", "15m"),
	})
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: dmObj(nil)}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: dmConfig(t, *schemaResp, raw)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create unexpected diags: %v", resp.Diagnostics)
	}
	var m windowsDomainMembershipModel
	if diags := resp.State.Get(context.Background(), &m); diags.HasError() {
		t.Fatalf("State.Get: %v", diags)
	}
	got, diags := m.Timeouts.Create(context.Background(), domainMembershipDefaultCreateTimeout)
	if diags.HasError() {
		t.Fatalf("Timeouts.Create: %v", diags)
	}
	if got != 15*time.Minute {
		t.Errorf("Timeouts not preserved through Create: create = %v, want 15m", got)
	}
}

func TestDomainMembershipCredentialAttrTypes(t *testing.T) {
	if _, ok := domainMembershipCredentialAttrTypes["username"]; !ok {
		t.Error("credential attr types missing username")
	}
	var _ attr.Type = types.StringType
}

// joinCredentialValidators extracts the string validators of a nested
// join_credential attribute from the windows_domain_membership schema.
func joinCredentialValidators(t *testing.T, attrName string) []validator.String {
	t.Helper()
	s := windowsDomainMembershipSchemaDefinition(context.Background())
	nested, ok := s.Attributes["join_credential"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("join_credential is not a SingleNestedAttribute")
	}
	strAttr, ok := nested.Attributes[attrName].(schema.StringAttribute)
	if !ok {
		t.Fatalf("join_credential.%s is not a StringAttribute", attrName)
	}
	return strAttr.Validators
}

func TestDomainMembershipJoinPassword_NoLineBreak(t *testing.T) {
	assertSecretAttrGuarded(t,
		path.Root("join_credential").AtName("password"),
		joinCredentialValidators(t, "password"))
}

func TestDomainMembershipJoinPasswordWo_NoLineBreak(t *testing.T) {
	assertSecretAttrGuarded(t,
		path.Root("join_credential").AtName("password_wo"),
		joinCredentialValidators(t, "password_wo"))
}
