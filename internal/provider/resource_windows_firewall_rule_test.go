// Package provider — unit tests for resource_windows_firewall_rule.go
//
// These tests do NOT require a real Windows host or TF_ACC. They exercise:
//
//   - Metadata: TypeName correctly set to "windows_firewall_rule"
//   - Schema: all 19 attributes present (id + 18 user-facing)
//   - firewallProtocolValidator: keywords, numeric 0-255, invalid, null/unknown skip
//   - firewallRuleProfileValidator (CV-1): Any alone OK, Any mixed → error, null → skip
//   - firewallRulePortProtocolValidator (CV-2): TCP+ports OK, non-TCP+ports → error
//   - listFromStrings / stringsFromList: nil/empty/non-empty/null/unknown
//   - firewallStateToModel: all fields projected correctly
//   - modelToFirewallInput: all fields extracted correctly
//   - addFirewallDiag: *FirewallRuleError path and plain-error path
//   - Configure: nil ProviderData, wrong type, happy path
//   - ConfigValidators: returns exactly 2 validators
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	schemavalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestFirewallRuleResource_Metadata(t *testing.T) {
	r := &windowsFirewallRuleResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_firewall_rule" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "windows_firewall_rule")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestFirewallRuleResource_Schema_AllAttributes(t *testing.T) {
	s := windowsFirewallRuleSchemaDefinition()
	wantAttrs := []string{
		"id", "name", "display_name", "description",
		"enabled", "direction", "action",
		"profile", "edge_traversal_policy", "group", "policy_store",
		"protocol", "local_port", "remote_port",
		"local_address", "remote_address",
		"program", "service", "interface_type",
	}
	for _, k := range wantAttrs {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(s.Attributes) != 19 {
		t.Errorf("expected 19 attributes (id + 18 user-facing), got %d", len(s.Attributes))
	}
}

func TestFirewallRuleResource_Schema_ResourceLevelCall(t *testing.T) {
	r := &windowsFirewallRuleResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
}

// ---------------------------------------------------------------------------
// firewallProtocolValidator — direct ValidateString calls
// ---------------------------------------------------------------------------

func TestFirewallProtocolValidator_Description(t *testing.T) {
	v := firewallProtocolValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must be non-empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription must be non-empty")
	}
}

func TestFirewallProtocolValidator_ValidKeywords(t *testing.T) {
	v := firewallProtocolValidator{}
	for _, kw := range []string{"TCP", "UDP", "ICMPv4", "ICMPv6", "IGMP", "Any",
		"tcp", "udp", "icmpv4", "icmpv6", "igmp", "any"} {
		req := schemavalidator.StringRequest{ConfigValue: types.StringValue(kw)}
		resp := &schemavalidator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("keyword %q should be valid, got error: %v", kw, resp.Diagnostics)
		}
	}
}

func TestFirewallProtocolValidator_ValidNumeric(t *testing.T) {
	v := firewallProtocolValidator{}
	for _, n := range []string{"0", "1", "47", "255"} {
		req := schemavalidator.StringRequest{ConfigValue: types.StringValue(n)}
		resp := &schemavalidator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("numeric %q should be valid, got error", n)
		}
	}
}

func TestFirewallProtocolValidator_InvalidValues(t *testing.T) {
	v := firewallProtocolValidator{}
	for _, bad := range []string{"256", "-1", "999", "TCP2", "INVALID", "NOTAPROTOCOL"} {
		req := schemavalidator.StringRequest{ConfigValue: types.StringValue(bad)}
		resp := &schemavalidator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("value %q should be invalid but was accepted", bad)
		}
	}
}

func TestFirewallProtocolValidator_NullSkipped(t *testing.T) {
	v := firewallProtocolValidator{}
	req := schemavalidator.StringRequest{ConfigValue: types.StringNull()}
	resp := &schemavalidator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should be skipped without error")
	}
}

func TestFirewallProtocolValidator_UnknownSkipped(t *testing.T) {
	v := firewallProtocolValidator{}
	req := schemavalidator.StringRequest{ConfigValue: types.StringUnknown()}
	resp := &schemavalidator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("unknown value should be skipped without error")
	}
}

// fwSchemaObjectType returns the tftypes.Object type matching the firewall rule schema.
func fwSchemaObjectType() tftypes.Object {
	listStr := tftypes.List{ElementType: tftypes.String}
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                    tftypes.String,
		"name":                  tftypes.String,
		"display_name":          tftypes.String,
		"description":           tftypes.String,
		"enabled":               tftypes.Bool,
		"direction":             tftypes.String,
		"action":                tftypes.String,
		"profile":               listStr,
		"edge_traversal_policy": tftypes.String,
		"group":                 tftypes.String,
		"policy_store":          tftypes.String,
		"protocol":              tftypes.String,
		"local_port":            listStr,
		"remote_port":           listStr,
		"local_address":         listStr,
		"remote_address":        listStr,
		"program":               tftypes.String,
		"service":               tftypes.String,
		"interface_type":        tftypes.String,
	}}
}

// buildFWConfig creates a tfsdk.Config for the firewall rule resource.
// Only the provided map values override defaults; everything else is null.
func buildFWConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsFirewallRuleSchemaDefinition()
	listStr := tftypes.List{ElementType: tftypes.String}
	nullList := tftypes.NewValue(listStr, nil)

	defaults := map[string]tftypes.Value{
		"id":                    tftypes.NewValue(tftypes.String, nil),
		"name":                  tftypes.NewValue(tftypes.String, "TEST-RULE"),
		"display_name":          tftypes.NewValue(tftypes.String, "Test Rule"),
		"description":           tftypes.NewValue(tftypes.String, nil),
		"enabled":               tftypes.NewValue(tftypes.Bool, nil),
		"direction":             tftypes.NewValue(tftypes.String, "Inbound"),
		"action":                tftypes.NewValue(tftypes.String, "Allow"),
		"profile":               nullList,
		"edge_traversal_policy": tftypes.NewValue(tftypes.String, nil),
		"group":                 tftypes.NewValue(tftypes.String, nil),
		"policy_store":          tftypes.NewValue(tftypes.String, nil),
		"protocol":              tftypes.NewValue(tftypes.String, nil),
		"local_port":            nullList,
		"remote_port":           nullList,
		"local_address":         nullList,
		"remote_address":        nullList,
		"program":               tftypes.NewValue(tftypes.String, nil),
		"service":               tftypes.NewValue(tftypes.String, nil),
		"interface_type":        tftypes.NewValue(tftypes.String, nil),
	}
	for k, v := range overrides {
		defaults[k] = v
	}
	return tfsdk.Config{
		Raw:    tftypes.NewValue(fwSchemaObjectType(), defaults),
		Schema: s,
	}
}

// ---------------------------------------------------------------------------
// firewallRuleProfileValidator (CV-1)
// ---------------------------------------------------------------------------

func TestFirewallProfileValidator_Description(t *testing.T) {
	v := firewallRuleProfileValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must be non-empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription must be non-empty")
	}
}

func TestFirewallProfileValidator_Valid_NoAny(t *testing.T) {
	v := firewallRuleProfileValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	profiles := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "Domain"),
		tftypes.NewValue(tftypes.String, "Private"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"profile": profiles})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("Domain+Private should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallProfileValidator_Valid_AnyAlone(t *testing.T) {
	v := firewallRuleProfileValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	profiles := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "Any"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"profile": profiles})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("Any alone should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallProfileValidator_Invalid_AnyMixed(t *testing.T) {
	v := firewallRuleProfileValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	profiles := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "Any"),
		tftypes.NewValue(tftypes.String, "Domain"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"profile": profiles})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("Any mixed with Domain should produce an error (CV-1)")
	}
}

func TestFirewallProfileValidator_Null_Skipped(t *testing.T) {
	v := firewallRuleProfileValidator{}
	// profile is null (default in buildFWConfig)
	cfg := buildFWConfig(t, nil)
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("null profile should be skipped: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// firewallRulePortProtocolValidator (CV-2)
// ---------------------------------------------------------------------------

func TestFirewallPortProtocolValidator_Description(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must be non-empty")
	}
}

func TestFirewallPortProtocolValidator_TCPWithPorts_OK(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "443"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":   tftypes.NewValue(tftypes.String, "TCP"),
		"local_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("TCP + local_port should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallPortProtocolValidator_UDPWithPorts_OK(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "53"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":    tftypes.NewValue(tftypes.String, "UDP"),
		"remote_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("UDP + remote_port should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallPortProtocolValidator_NullProtocol_OK(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "443"),
	})
	// protocol is null (computed): skip validation
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"local_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("null protocol should skip CV-2 validation: %v", resp.Diagnostics)
	}
}

func TestFirewallPortProtocolValidator_ICMPWithLocalPort_Error(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "443"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":   tftypes.NewValue(tftypes.String, "ICMPv4"),
		"local_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("ICMPv4 + local_port should produce an error (CV-2)")
	}
}

func TestFirewallPortProtocolValidator_ICMPWithRemotePort_Error(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "80"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":    tftypes.NewValue(tftypes.String, "ICMPv6"),
		"remote_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("ICMPv6 + remote_port should produce an error (CV-2)")
	}
}

func TestFirewallPortProtocolValidator_AnyWithPorts_Error(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "8080"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":   tftypes.NewValue(tftypes.String, "Any"),
		"local_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("Any protocol + local_port should produce an error (CV-2)")
	}
}

// ---------------------------------------------------------------------------
// listFromStrings / stringsFromList
// ---------------------------------------------------------------------------

func TestListFromStrings_Nil(t *testing.T) {
	l := listFromStrings(nil)
	if len(l.Elements()) != 0 {
		t.Errorf("nil → %d elements, want 0", len(l.Elements()))
	}
	if l.IsNull() || l.IsUnknown() {
		t.Error("listFromStrings(nil) should return empty list, not null/unknown")
	}
}

func TestListFromStrings_Empty(t *testing.T) {
	l := listFromStrings([]string{})
	if len(l.Elements()) != 0 {
		t.Errorf("empty → %d elements, want 0", len(l.Elements()))
	}
}

func TestListFromStrings_NonEmpty(t *testing.T) {
	l := listFromStrings([]string{"a", "b", "c"})
	elems := l.Elements()
	if len(elems) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(elems))
	}
	for i, want := range []string{"a", "b", "c"} {
		got, ok := elems[i].(types.String)
		if !ok {
			t.Fatalf("element %d not types.String", i)
		}
		if got.ValueString() != want {
			t.Errorf("element %d = %q, want %q", i, got.ValueString(), want)
		}
	}
}

func TestStringsFromList_Null(t *testing.T) {
	l := types.ListNull(types.StringType)
	got, diags := stringsFromList(context.Background(), l)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	if got != nil {
		t.Errorf("null list → %v, want nil", got)
	}
}

func TestStringsFromList_NonNull(t *testing.T) {
	vals := []attr.Value{
		types.StringValue("x"),
		types.StringValue("y"),
	}
	l := types.ListValueMust(types.StringType, vals)
	got, diags := stringsFromList(context.Background(), l)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	if len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Errorf("got = %v, want [x y]", got)
	}
}

func TestStringsFromList_Unknown(t *testing.T) {
	l := types.ListUnknown(types.StringType)
	got, diags := stringsFromList(context.Background(), l)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	if got != nil {
		t.Errorf("unknown list → %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// firewallStateToModel
// ---------------------------------------------------------------------------

func TestFirewallStateToModel_Full(t *testing.T) {
	enabled := true
	s := &winclient.FirewallRuleState{
		Name:                "MY-RULE",
		DisplayName:         "My Firewall Rule",
		Description:         "Some description",
		Enabled:             enabled,
		Direction:           "Outbound",
		Action:              "Block",
		Profile:             []string{"Domain", "Private"},
		EdgeTraversalPolicy: "Allow",
		Group:               "MyGroup",
		PolicyStore:         "PersistentStore",
		Protocol:            "TCP",
		LocalPort:           []string{"80", "443"},
		RemotePort:          []string{"Any"},
		LocalAddress:        []string{"192.168.0.0/16"},
		RemoteAddress:       []string{"Any"},
		Program:             `C:\App\app.exe`,
		Service:             "MySvc",
		InterfaceType:       "Wired",
	}

	m, diags := firewallStateToModel(context.Background(), s)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}

	if m.ID.ValueString() != "MY-RULE" {
		t.Errorf("ID = %q", m.ID.ValueString())
	}
	if m.Name.ValueString() != "MY-RULE" {
		t.Errorf("Name = %q", m.Name.ValueString())
	}
	if m.DisplayName.ValueString() != "My Firewall Rule" {
		t.Errorf("DisplayName = %q", m.DisplayName.ValueString())
	}
	if m.Description.ValueString() != "Some description" {
		t.Errorf("Description = %q", m.Description.ValueString())
	}
	if !m.Enabled.ValueBool() {
		t.Error("Enabled should be true")
	}
	if m.Direction.ValueString() != "Outbound" {
		t.Errorf("Direction = %q", m.Direction.ValueString())
	}
	if m.Action.ValueString() != "Block" {
		t.Errorf("Action = %q", m.Action.ValueString())
	}
	if len(m.Profile.Elements()) != 2 {
		t.Errorf("Profile elements = %d, want 2", len(m.Profile.Elements()))
	}
	if m.EdgeTraversalPolicy.ValueString() != "Allow" {
		t.Errorf("EdgeTraversalPolicy = %q", m.EdgeTraversalPolicy.ValueString())
	}
	if m.Group.ValueString() != "MyGroup" {
		t.Errorf("Group = %q", m.Group.ValueString())
	}
	if m.PolicyStore.ValueString() != "PersistentStore" {
		t.Errorf("PolicyStore = %q", m.PolicyStore.ValueString())
	}
	if m.Protocol.ValueString() != "TCP" {
		t.Errorf("Protocol = %q", m.Protocol.ValueString())
	}
	if len(m.LocalPort.Elements()) != 2 {
		t.Errorf("LocalPort elements = %d, want 2", len(m.LocalPort.Elements()))
	}
	if m.Program.ValueString() != `C:\App\app.exe` {
		t.Errorf("Program = %q", m.Program.ValueString())
	}
	if m.Service.ValueString() != "MySvc" {
		t.Errorf("Service = %q", m.Service.ValueString())
	}
	if m.InterfaceType.ValueString() != "Wired" {
		t.Errorf("InterfaceType = %q", m.InterfaceType.ValueString())
	}
}

func TestFirewallStateToModel_EmptyListsNormalised(t *testing.T) {
	// Client normalises empty → ["Any"]; model should preserve it.
	s := &winclient.FirewallRuleState{
		Name:          "R",
		DisplayName:   "R",
		Direction:     "Inbound",
		Action:        "Allow",
		Profile:       []string{"Any"},
		LocalPort:     []string{"Any"},
		RemotePort:    []string{"Any"},
		LocalAddress:  []string{"Any"},
		RemoteAddress: []string{"Any"},
		Program:       "Any",
		Service:       "Any",
		InterfaceType: "Any",
	}
	m, diags := firewallStateToModel(context.Background(), s)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if len(m.Profile.Elements()) != 1 {
		t.Errorf("Profile elements = %d, want 1 ([Any])", len(m.Profile.Elements()))
	}
	if len(m.LocalPort.Elements()) != 1 {
		t.Errorf("LocalPort elements = %d, want 1 ([Any])", len(m.LocalPort.Elements()))
	}
}

// ---------------------------------------------------------------------------
// modelToFirewallInput
// ---------------------------------------------------------------------------

func TestModelToFirewallInput_Full(t *testing.T) {
	profile := listFromStrings([]string{"Domain", "Private"})
	localPort := listFromStrings([]string{"80", "443"})
	remotePort := listFromStrings([]string{"Any"})
	localAddr := listFromStrings([]string{"192.168.0.0/24"})
	remoteAddr := listFromStrings([]string{"Any"})

	m := windowsFirewallRuleModel{
		ID:                  types.StringValue("RULE-01"),
		Name:                types.StringValue("RULE-01"),
		DisplayName:         types.StringValue("My Rule"),
		Description:         types.StringValue("Desc"),
		Enabled:             types.BoolValue(true),
		Direction:           types.StringValue("Inbound"),
		Action:              types.StringValue("Allow"),
		Profile:             profile,
		EdgeTraversalPolicy: types.StringValue("Block"),
		Group:               types.StringValue("GrpA"),
		PolicyStore:         types.StringValue("PersistentStore"),
		Protocol:            types.StringValue("TCP"),
		LocalPort:           localPort,
		RemotePort:          remotePort,
		LocalAddress:        localAddr,
		RemoteAddress:       remoteAddr,
		Program:             types.StringValue(`C:\App\app.exe`),
		Service:             types.StringValue("MySvc"),
		InterfaceType:       types.StringValue("Wired"),
	}

	input, diags := modelToFirewallInput(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}

	if input.Name != "RULE-01" {
		t.Errorf("Name = %q", input.Name)
	}
	if input.DisplayName != "My Rule" {
		t.Errorf("DisplayName = %q", input.DisplayName)
	}
	if input.Description != "Desc" {
		t.Errorf("Description = %q", input.Description)
	}
	if input.Enabled == nil || !*input.Enabled {
		t.Error("Enabled should be true")
	}
	if input.Direction != "Inbound" {
		t.Errorf("Direction = %q", input.Direction)
	}
	if input.Action != "Allow" {
		t.Errorf("Action = %q", input.Action)
	}
	if len(input.Profile) != 2 {
		t.Errorf("Profile = %v", input.Profile)
	}
	if input.EdgeTraversalPolicy != "Block" {
		t.Errorf("EdgeTraversalPolicy = %q", input.EdgeTraversalPolicy)
	}
	if input.Group != "GrpA" {
		t.Errorf("Group = %q", input.Group)
	}
	if input.PolicyStore != "PersistentStore" {
		t.Errorf("PolicyStore = %q", input.PolicyStore)
	}
	if input.Protocol != "TCP" {
		t.Errorf("Protocol = %q", input.Protocol)
	}
	if len(input.LocalPort) != 2 {
		t.Errorf("LocalPort = %v", input.LocalPort)
	}
	if input.Program != `C:\App\app.exe` {
		t.Errorf("Program = %q", input.Program)
	}
	if input.Service != "MySvc" {
		t.Errorf("Service = %q", input.Service)
	}
	if input.InterfaceType != "Wired" {
		t.Errorf("InterfaceType = %q", input.InterfaceType)
	}
}

func TestModelToFirewallInput_NullLists(t *testing.T) {
	m := windowsFirewallRuleModel{
		Name:          types.StringValue("R"),
		DisplayName:   types.StringValue("R"),
		Direction:     types.StringValue("Inbound"),
		Action:        types.StringValue("Allow"),
		Enabled:       types.BoolValue(true),
		PolicyStore:   types.StringValue("PersistentStore"),
		Profile:       types.ListNull(types.StringType),
		LocalPort:     types.ListNull(types.StringType),
		RemotePort:    types.ListNull(types.StringType),
		LocalAddress:  types.ListNull(types.StringType),
		RemoteAddress: types.ListNull(types.StringType),
	}
	input, diags := modelToFirewallInput(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if input.Profile != nil {
		t.Errorf("null Profile should be nil, got %v", input.Profile)
	}
	if input.LocalPort != nil {
		t.Errorf("null LocalPort should be nil, got %v", input.LocalPort)
	}
}

// ---------------------------------------------------------------------------
// addFirewallDiag
// ---------------------------------------------------------------------------

func TestAddFirewallDiag_FirewallRuleError(t *testing.T) {
	var d diag.Diagnostics
	fe := winclient.NewFirewallRuleError(
		winclient.FirewallRuleErrorPermission,
		"access denied to firewall API",
		nil,
		map[string]string{"host": "WIN01", "operation": "Create"},
	)
	addFirewallDiag(&d, "Error creating Windows Firewall rule", fe)
	if !d.HasError() {
		t.Fatal("expected error diag")
	}
	summary := d[0].Summary()
	detail := d[0].Detail()
	if !strings.Contains(summary, "permission_denied") {
		t.Errorf("summary should contain kind: %s", summary)
	}
	if !strings.Contains(detail, "access denied") {
		t.Errorf("detail should contain message: %s", detail)
	}
	if !strings.Contains(detail, "WIN01") {
		t.Errorf("detail should contain context: %s", detail)
	}
}

func TestAddFirewallDiag_FirewallRuleError_WithCause(t *testing.T) {
	var d diag.Diagnostics
	cause := errors.New("WinRM connection lost")
	fe := winclient.NewFirewallRuleError(
		winclient.FirewallRuleErrorUnknown,
		"transport failure",
		cause,
		nil,
	)
	addFirewallDiag(&d, "Read failed", fe)
	if !d.HasError() {
		t.Fatal("expected error diag")
	}
	detail := d[0].Detail()
	if !strings.Contains(detail, "WinRM connection lost") {
		t.Errorf("detail should contain cause: %s", detail)
	}
}

func TestAddFirewallDiag_PlainError(t *testing.T) {
	var d diag.Diagnostics
	addFirewallDiag(&d, "Unexpected failure", errors.New("boom"))
	if !d.HasError() {
		t.Fatal("expected error diag")
	}
	if !strings.Contains(d[0].Detail(), "boom") {
		t.Errorf("detail missing error text: %s", d[0].Detail())
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestFirewallRuleResource_Configure_Nil(t *testing.T) {
	r := &windowsFirewallRuleResource{}
	req := resource.ConfigureRequest{ProviderData: nil}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op: %v", resp.Diagnostics)
	}
	if r.fw != nil {
		t.Error("fw should remain nil when ProviderData is nil")
	}
}

func TestFirewallRuleResource_Configure_WrongType(t *testing.T) {
	r := &windowsFirewallRuleResource{}
	req := resource.ConfigureRequest{ProviderData: "wrong-type"}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong ProviderData type should produce error diag")
	}
}

func TestFirewallRuleResource_Configure_HappyPath(t *testing.T) {
	r := &windowsFirewallRuleResource{}
	c, err := winclient.New(winclient.Config{
		Host:     "10.0.0.1",
		Username: "admin",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	req := resource.ConfigureRequest{ProviderData: c}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.fw == nil {
		t.Error("fw should be set after Configure")
	}
	if r.client != c {
		t.Error("client should be stored")
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

func TestFirewallRuleResource_ConfigValidators(t *testing.T) {
	r := &windowsFirewallRuleResource{}
	validators := r.ConfigValidators(context.Background())
	if len(validators) != 2 {
		t.Errorf("expected 2 ConfigValidators (CV-1 + CV-2), got %d", len(validators))
	}
}
