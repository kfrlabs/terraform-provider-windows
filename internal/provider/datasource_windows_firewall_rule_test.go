// Package provider — unit tests for the windows_firewall_rule data source.
//
// Coverage:
//   - Metadata: TypeName == windows_firewall_rule
//   - Constructor: returns non-nil
//   - Schema: 19 attributes, name Required, policy_store Optional+Computed,
//     all others Computed only, no write-only attributes
//   - Configure: nil ProviderData, wrong type, happy path
//   - Read: happy path (empty + populated lists), implicit PersistentStore
//     default, not-found error, nil result, generic error, *FirewallRuleError
//     enrichment
//   - firewallStateToDataSourceModel: full projection
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake FirewallRuleClient
// ---------------------------------------------------------------------------

type fakeFirewallClientDS struct {
	readOut         *winclient.FirewallRuleState
	readErr         error
	lastName        string
	lastPolicyStore string
}

func (f *fakeFirewallClientDS) Create(_ context.Context, _ winclient.FirewallRuleInput) (*winclient.FirewallRuleState, error) {
	panic("Create not used in data source")
}
func (f *fakeFirewallClientDS) Read(_ context.Context, name, policyStore string) (*winclient.FirewallRuleState, error) {
	f.lastName = name
	f.lastPolicyStore = policyStore
	return f.readOut, f.readErr
}
func (f *fakeFirewallClientDS) Update(_ context.Context, _ string, _ string, _ winclient.FirewallRuleInput) (*winclient.FirewallRuleState, error) {
	panic("Update not used in data source")
}
func (f *fakeFirewallClientDS) Delete(_ context.Context, _ string, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers — must mirror the schema exactly.
// ---------------------------------------------------------------------------

func firewallDSObjType() tftypes.Object {
	strList := tftypes.List{ElementType: tftypes.String}
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                    tftypes.String,
		"name":                  tftypes.String,
		"display_name":          tftypes.String,
		"description":           tftypes.String,
		"enabled":               tftypes.Bool,
		"direction":             tftypes.String,
		"action":                tftypes.String,
		"profile":               strList,
		"edge_traversal_policy": tftypes.String,
		"group":                 tftypes.String,
		"policy_store":          tftypes.String,
		"protocol":              tftypes.String,
		"local_port":            strList,
		"remote_port":           strList,
		"local_address":         strList,
		"remote_address":        strList,
		"program":               tftypes.String,
		"service":               tftypes.String,
		"interface_type":        tftypes.String,
	}}
}

// firewallDSConfig builds a tfsdk.Config with the given name and an optional
// policy_store override. A nil policyStore leaves the attribute null,
// exercising the implicit default code path.
func firewallDSConfig(name string, policyStore *string) tfsdk.Config {
	d := &windowsFirewallRuleDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)

	strList := tftypes.List{ElementType: tftypes.String}
	var psVal tftypes.Value
	if policyStore == nil {
		psVal = tftypes.NewValue(tftypes.String, nil)
	} else {
		psVal = tftypes.NewValue(tftypes.String, *policyStore)
	}

	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(firewallDSObjType(), map[string]tftypes.Value{
			"id":                    tftypes.NewValue(tftypes.String, nil),
			"name":                  tftypes.NewValue(tftypes.String, name),
			"display_name":          tftypes.NewValue(tftypes.String, nil),
			"description":           tftypes.NewValue(tftypes.String, nil),
			"enabled":               tftypes.NewValue(tftypes.Bool, nil),
			"direction":             tftypes.NewValue(tftypes.String, nil),
			"action":                tftypes.NewValue(tftypes.String, nil),
			"profile":               tftypes.NewValue(strList, nil),
			"edge_traversal_policy": tftypes.NewValue(tftypes.String, nil),
			"group":                 tftypes.NewValue(tftypes.String, nil),
			"policy_store":          psVal,
			"protocol":              tftypes.NewValue(tftypes.String, nil),
			"local_port":            tftypes.NewValue(strList, nil),
			"remote_port":           tftypes.NewValue(strList, nil),
			"local_address":         tftypes.NewValue(strList, nil),
			"remote_address":        tftypes.NewValue(strList, nil),
			"program":               tftypes.NewValue(tftypes.String, nil),
			"service":               tftypes.NewValue(tftypes.String, nil),
			"interface_type":        tftypes.NewValue(tftypes.String, nil),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata + constructor
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Metadata(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_firewall_rule" {
		t.Errorf("TypeName = %q, want windows_firewall_rule", resp.TypeName)
	}
}

func TestNewWindowsFirewallRuleDataSource_NotNil(t *testing.T) {
	if NewWindowsFirewallRuleDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Schema_AllAttributes(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "name", "display_name", "description",
		"enabled", "direction", "action",
		"profile", "edge_traversal_policy", "group", "policy_store",
		"protocol", "local_port", "remote_port",
		"local_address", "remote_address",
		"program", "service", "interface_type",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(resp.Schema.Attributes) != 19 {
		t.Errorf("expected 19 attributes, got %d", len(resp.Schema.Attributes))
	}
}

func TestFirewallRuleDS_Schema_NameRequired(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type req interface{ IsRequired() bool }
	attr := resp.Schema.Attributes["name"]
	r, ok := attr.(req)
	if !ok || !r.IsRequired() {
		t.Error("name attribute must be Required")
	}
}

func TestFirewallRuleDS_Schema_PolicyStoreOptionalComputed(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type optChk interface{ IsOptional() bool }
	type compChk interface{ IsComputed() bool }
	attr := resp.Schema.Attributes["policy_store"]
	if o, ok := attr.(optChk); !ok || !o.IsOptional() {
		t.Error("policy_store must be Optional")
	}
	if c, ok := attr.(compChk); !ok || !c.IsComputed() {
		t.Error("policy_store must be Computed")
	}
}

func TestFirewallRuleDS_Schema_AllOthersComputed(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type compChk interface{ IsComputed() bool }
	computedKeys := []string{
		"id", "display_name", "description", "enabled", "direction", "action",
		"profile", "edge_traversal_policy", "group", "protocol",
		"local_port", "remote_port", "local_address", "remote_address",
		"program", "service", "interface_type",
	}
	for _, k := range computedKeys {
		attr := resp.Schema.Attributes[k]
		cc, ok := attr.(compChk)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Configure_Nil(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil must not error: %v", resp.Diagnostics)
	}
}

func TestFirewallRuleDS_Configure_WrongType(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 3.14}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("unexpected detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestFirewallRuleDS_Configure_OK(t *testing.T) {
	d := &windowsFirewallRuleDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path (no list filters)
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Read_HappyPath_Empty(t *testing.T) {
	fake := &fakeFirewallClientDS{
		readOut: &winclient.FirewallRuleState{
			Name:                "AllowSSH",
			DisplayName:         "Allow SSH",
			Description:         "Inbound SSH",
			Enabled:             true,
			Direction:           "Inbound",
			Action:              "Allow",
			Profile:             []string{"Domain", "Private"},
			EdgeTraversalPolicy: "Block",
			Group:               "",
			PolicyStore:         "PersistentStore",
			Protocol:            "TCP",
			LocalPort:           []string{"22"},
			RemotePort:          []string{},
			LocalAddress:        []string{},
			RemoteAddress:       []string{},
			Program:             "Any",
			Service:             "Any",
			InterfaceType:       "Any",
		},
	}
	d := &windowsFirewallRuleDataSource{fw: fake}
	cfg := firewallDSConfig("AllowSSH", nil)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	if fake.lastName != "AllowSSH" {
		t.Errorf("client got name=%q", fake.lastName)
	}
	if fake.lastPolicyStore != "PersistentStore" {
		t.Errorf("implicit default not applied: got %q", fake.lastPolicyStore)
	}
	var state windowsFirewallRuleDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "AllowSSH" {
		t.Errorf("ID = %q", state.ID.ValueString())
	}
	if state.Action.ValueString() != "Allow" {
		t.Errorf("Action = %q", state.Action.ValueString())
	}
	if !state.Enabled.ValueBool() {
		t.Error("Enabled should be true")
	}
	if state.LocalPort.IsNull() {
		t.Error("LocalPort should not be null")
	}
}

// ---------------------------------------------------------------------------
// Read — explicit policy_store override
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Read_ExplicitPolicyStore(t *testing.T) {
	fake := &fakeFirewallClientDS{
		readOut: &winclient.FirewallRuleState{
			Name:        "GP-Rule",
			PolicyStore: "GroupPolicy",
			Direction:   "Inbound",
			Action:      "Allow",
		},
	}
	d := &windowsFirewallRuleDataSource{fw: fake}
	ps := "GroupPolicy"
	cfg := firewallDSConfig("GP-Rule", &ps)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	if fake.lastPolicyStore != "GroupPolicy" {
		t.Errorf("explicit policy_store ignored: got %q", fake.lastPolicyStore)
	}
}

// ---------------------------------------------------------------------------
// Read — not found via typed error
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Read_NotFound(t *testing.T) {
	fake := &fakeFirewallClientDS{
		readErr: winclient.NewFirewallRuleError(
			winclient.FirewallRuleErrorNotFound, "missing", nil, nil,
		),
	}
	d := &windowsFirewallRuleDataSource{fw: fake}
	cfg := firewallDSConfig("Ghost", nil)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for not-found rule")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

// ---------------------------------------------------------------------------
// Read — nil result, treat as not found
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Read_NilResult(t *testing.T) {
	d := &windowsFirewallRuleDataSource{fw: &fakeFirewallClientDS{}}
	cfg := firewallDSConfig("Phantom", nil)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("nil result must produce error")
	}
}

// ---------------------------------------------------------------------------
// Read — generic error path (non-FirewallRuleError)
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Read_GenericError(t *testing.T) {
	d := &windowsFirewallRuleDataSource{fw: &fakeFirewallClientDS{
		readErr: errors.New("WinRM transport down"),
	}}
	cfg := firewallDSConfig("X", nil)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic failure")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "WinRM transport down") {
		t.Errorf("detail did not propagate: %s", resp.Diagnostics[0].Detail())
	}
}

// ---------------------------------------------------------------------------
// Read — typed permission error → enriched diagnostic
// ---------------------------------------------------------------------------

func TestFirewallRuleDS_Read_TypedErrorEnriched(t *testing.T) {
	fake := &fakeFirewallClientDS{
		readErr: winclient.NewFirewallRuleError(
			winclient.FirewallRuleErrorPermission,
			"access denied",
			errors.New("WinRM 401"),
			map[string]string{"name": "X"},
		),
	}
	d := &windowsFirewallRuleDataSource{fw: fake}
	cfg := firewallDSConfig("X", nil)
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error")
	}
	detail := resp.Diagnostics[0].Detail()
	if !strings.Contains(detail, string(winclient.FirewallRuleErrorPermission)) {
		t.Errorf("detail missing kind: %s", detail)
	}
	if !strings.Contains(detail, "access denied") {
		t.Errorf("detail missing message: %s", detail)
	}
	if !strings.Contains(detail, "WinRM 401") {
		t.Errorf("detail missing cause: %s", detail)
	}
}

// ---------------------------------------------------------------------------
// firewallStateToDataSourceModel — full projection
// ---------------------------------------------------------------------------

func TestFirewallStateToDataSourceModel_FullProjection(t *testing.T) {
	s := &winclient.FirewallRuleState{
		Name:                "R1",
		DisplayName:         "D1",
		Description:         "desc",
		Enabled:             true,
		Direction:           "Inbound",
		Action:              "Allow",
		Profile:             []string{"Domain"},
		EdgeTraversalPolicy: "Block",
		Group:               "GRP",
		PolicyStore:         "ActiveStore",
		Protocol:            "TCP",
		LocalPort:           []string{"80", "443"},
		RemotePort:          []string{"Any"},
		LocalAddress:        []string{"10.0.0.0/8"},
		RemoteAddress:       []string{"Any"},
		Program:             "C:\\app.exe",
		Service:             "MySvc",
		InterfaceType:       "Wired",
	}
	m := firewallStateToDataSourceModel(s)
	if m.Name.ValueString() != "R1" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
	if m.PolicyStore.ValueString() != "ActiveStore" {
		t.Errorf("PolicyStore = %q", m.PolicyStore.ValueString())
	}
	if m.LocalPort.IsNull() || m.LocalPort.IsUnknown() {
		t.Error("LocalPort must be populated")
	}
	if len(m.LocalPort.Elements()) != 2 {
		t.Errorf("LocalPort len = %d, want 2", len(m.LocalPort.Elements()))
	}
}

// ---------------------------------------------------------------------------
// addFirewallDataSourceDiag — both branches
// ---------------------------------------------------------------------------

func TestAddFirewallDataSourceDiag_TypedError(t *testing.T) {
	var ds diag.Diagnostics
	err := winclient.NewFirewallRuleError(
		winclient.FirewallRuleErrorReadOnlyStore, "read-only", nil,
		map[string]string{"store": "GroupPolicy"},
	)
	addFirewallDataSourceDiag(&ds, "summary", err)
	if !ds.HasError() {
		t.Fatal("expected error")
	}
	detail := ds[0].Detail()
	if !strings.Contains(detail, "read_only_store") || !strings.Contains(detail, "GroupPolicy") {
		t.Errorf("missing enrichment in detail: %s", detail)
	}
}

func TestAddFirewallDataSourceDiag_PlainError(t *testing.T) {
	var ds diag.Diagnostics
	addFirewallDataSourceDiag(&ds, "oops", errors.New("boom"))
	if !ds.HasError() {
		t.Fatal("expected error")
	}
	if ds[0].Detail() != "boom" {
		t.Errorf("detail = %q, want boom", ds[0].Detail())
	}
}
