// Package provider — regression tests for firewall rule validators (campaign).
//
//   - firewallPortValidator: `Any`/0-65535/ranges; rejects garbage, out of
//     range, and reversed ranges at plan time.
//   - firewallAddressValidator: `Any`/IP/CIDR; rejects garbage and shell
//     metacharacters (`;`, `$()`, quotes, backticks).
//   - firewallSafeStringValidator (program/service/group): rejects line
//     breaks, null bytes and shell/PowerShell metacharacters.
package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	schemavalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func validateFWString(t *testing.T, v schemavalidator.String, val string) bool {
	t.Helper()
	req := schemavalidator.StringRequest{
		Path:        path.Root("test"),
		ConfigValue: types.StringValue(val),
	}
	resp := &schemavalidator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	return resp.Diagnostics.HasError()
}

func TestFirewallPortValidator_AcceptsValid(t *testing.T) {
	v := firewallPortValidator{}
	for _, ok := range []string{"Any", "any", "ANY", "0", "80", "443", "65535", "8000-8100", "0-65535", "80-80"} {
		if validateFWString(t, v, ok) {
			t.Errorf("port %q should be accepted", ok)
		}
	}
}

func TestFirewallPortValidator_RejectsOutOfRangeAndReversed(t *testing.T) {
	v := firewallPortValidator{}
	for _, bad := range []string{
		"65536", "99999", "-1", "0-65536", "65536-65537",
		"8100-8000", "443-80",
		"http", "80;", "80$()", `"80"`, "8 0",
	} {
		if !validateFWString(t, v, bad) {
			t.Errorf("port %q should be rejected", bad)
		}
	}
}

func TestFirewallAddressValidator_AcceptsValid(t *testing.T) {
	v := firewallAddressValidator{}
	for _, ok := range []string{
		"Any", "any", "ANY",
		"192.168.1.1", "10.0.0.1", "::1", "2001:db8::1",
		"192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32",
	} {
		if validateFWString(t, v, ok) {
			t.Errorf("address %q should be accepted", ok)
		}
	}
}

func TestFirewallAddressValidator_RejectsGarbageAndInjection(t *testing.T) {
	v := firewallAddressValidator{}
	for _, bad := range []string{
		"garbage", "999.999.999.999", "192.168.1.1/99",
		"192.168.1.1; Remove-NetFirewallRule",
		"$(Get-Process)", "`id`", `"192.168.1.1"`, "'10.0.0.1'",
		"10.0.0.1 && whoami", "10.0.0.1|out",
		"",
		" ",
	} {
		if !validateFWString(t, v, bad) {
			t.Errorf("address %q should be rejected", bad)
		}
	}
}

func TestFirewallSafeStringValidator_RejectsInjection(t *testing.T) {
	v := firewallSafeStringValidator{}
	for _, bad := range []string{
		"a\nb", "a\rb", "a\x00b",
		`C:\app.exe; rm -rf`, `$(whoami)`, "`id`",
		`"quoted"`, "'quoted'", "a&b", "a|b", "a>b", "a<b",
	} {
		if !validateFWString(t, v, bad) {
			t.Errorf("value %q should be rejected", bad)
		}
	}
}

func TestFirewallSafeStringValidator_AcceptsClean(t *testing.T) {
	v := firewallSafeStringValidator{}
	for _, ok := range []string{
		"", "Any", `C:\Program Files\App\app.exe`, "MyService", "My Rule Group-1.2",
	} {
		if validateFWString(t, v, ok) {
			t.Errorf("value %q should be accepted", ok)
		}
	}
}

func TestFirewallRuleSchema_HasAddressAndSafeValidators(t *testing.T) {
	s := windowsFirewallRuleSchemaDefinition(context.Background())
	// Detailed behaviour is covered by the validator unit tests above; here
	// we assert the schema actually wires validators for the previously
	// unguarded attributes.
	for _, n := range []string{"local_address", "remote_address", "local_port", "remote_port"} {
		a, ok := s.Attributes[n].(schema.ListAttribute)
		if !ok {
			t.Fatalf("%s: expected schema.ListAttribute, got %T", n, s.Attributes[n])
		}
		if len(a.Validators) == 0 {
			t.Errorf("%s must carry validators", n)
		}
	}
	for _, n := range []string{"program", "service", "group"} {
		a, ok := s.Attributes[n].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected schema.StringAttribute, got %T", n, s.Attributes[n])
		}
		if len(a.Validators) == 0 {
			t.Errorf("%s must carry validators", n)
		}
	}
}

// ---------------------------------------------------------------------------
// Semantic equality: plan stays identical to config (F01/F02/F03)
//
// The schema must not rewrite planned values: any plan modifier that folds
// "tcp" → "TCP" or "55014-55014" → "55014" makes Terraform core reject the
// plan with "Provider produced invalid plan". Canonicalisation happens
// apply-side (modelToFirewallInput) and state-side (parseFirewallRuleState);
// the custom types below only relax the comparison so the raw plan and the
// canonical state agree.
// ---------------------------------------------------------------------------

func TestFirewallProtocolSemanticEquals(t *testing.T) {
	for _, tc := range []struct{ config, state string }{
		{"tcp", "TCP"}, {"TCP", "TCP"}, {"ANY", "Any"}, {"any", "Any"},
		{"1", "ICMPv4"}, {"6", "TCP"}, {"17", "UDP"}, {"58", "ICMPv6"},
		{"47", "47"},
	} {
		equal, diags := firewallProtocolValueOf(tc.config).StringSemanticEquals(
			context.Background(), firewallProtocolValueOf(tc.state))
		if diags.HasError() {
			t.Fatalf("protocol %q vs %q: unexpected diags: %v", tc.config, tc.state, diags)
		}
		if !equal {
			t.Errorf("protocol %q and state %q should compare equal", tc.config, tc.state)
		}
	}
	for _, tc := range []struct{ config, state string }{
		{"TCP", "UDP"}, {"1", "TCP"}, {"47", "48"},
	} {
		equal, _ := firewallProtocolValueOf(tc.config).StringSemanticEquals(
			context.Background(), firewallProtocolValueOf(tc.state))
		if equal {
			t.Errorf("protocol %q and state %q must not compare equal", tc.config, tc.state)
		}
	}
	// Null/unknown never compare equal: the framework falls back to exact
	// comparison instead of hiding missing values.
	for _, v := range []firewallProtocolValue{
		{StringValue: types.StringNull()},
		{StringValue: types.StringUnknown()},
	} {
		if equal, _ := v.StringSemanticEquals(context.Background(), firewallProtocolValueOf("TCP")); equal {
			t.Errorf("null/unknown protocol must not compare equal to TCP")
		}
		if equal, _ := firewallProtocolValueOf("TCP").StringSemanticEquals(context.Background(), v); equal {
			t.Errorf("TCP must not compare equal to null/unknown protocol")
		}
	}
}

func TestFirewallProtocolSemanticEquals_WrongType(t *testing.T) {
	_, diags := firewallProtocolValueOf("TCP").StringSemanticEquals(
		context.Background(), types.StringValue("TCP"))
	if !diags.HasError() {
		t.Error("semantic equality against a non-custom string value must raise a diagnostic")
	}
}

func TestFirewallCanonicalListSemanticEquals_Port(t *testing.T) {
	// F01: a degenerate range in config matches the collapsed state.
	planned := firewallCanonicalListFromStrings(firewallListKindPort, []string{"80", "55014-55014"})
	state := firewallCanonicalListFromStrings(firewallListKindPort, []string{"55014", "80"})
	if equal, diags := planned.ListSemanticEquals(context.Background(), state); diags.HasError() || !equal {
		t.Errorf("degenerate range config must equal collapsed state (diags=%v equal=%v)", diags, equal)
	}
	// `any` casing folds.
	planned = firewallCanonicalListFromStrings(firewallListKindPort, []string{"any"})
	state = firewallCanonicalListFromStrings(firewallListKindPort, []string{"Any"})
	if equal, _ := planned.ListSemanticEquals(context.Background(), state); !equal {
		t.Error(`port "any" must equal state "Any"`)
	}
	// Order-insensitive: config order matches sorted state.
	planned = firewallCanonicalListFromStrings(firewallListKindPort, []string{"443", "80"})
	state = firewallCanonicalListFromStrings(firewallListKindPort, []string{"80", "443"})
	if equal, _ := planned.ListSemanticEquals(context.Background(), state); !equal {
		t.Error("differently ordered port lists must compare equal")
	}
	// Genuinely different lists stay different.
	planned = firewallCanonicalListFromStrings(firewallListKindPort, []string{"80"})
	state = firewallCanonicalListFromStrings(firewallListKindPort, []string{"81"})
	if equal, _ := planned.ListSemanticEquals(context.Background(), state); equal {
		t.Error("different port lists must not compare equal")
	}
}

func TestFirewallCanonicalListSemanticEquals_Address(t *testing.T) {
	// F03: config order matches sorted state order.
	planned := firewallCanonicalListFromStrings(firewallListKindAddress, []string{"192.168.10.11", "10.0.0.0/8"})
	state := firewallCanonicalListFromStrings(firewallListKindAddress, []string{"10.0.0.0/8", "192.168.10.11"})
	if equal, diags := planned.ListSemanticEquals(context.Background(), state); diags.HasError() || !equal {
		t.Errorf("reordered address config must equal sorted state (diags=%v equal=%v)", diags, equal)
	}
	planned = firewallCanonicalListFromStrings(firewallListKindAddress, []string{"any"})
	state = firewallCanonicalListFromStrings(firewallListKindAddress, []string{"Any"})
	if equal, _ := planned.ListSemanticEquals(context.Background(), state); !equal {
		t.Error(`address "any" must equal state "Any"`)
	}
	// Null/unknown never compare equal.
	if equal, _ := firewallCanonicalListNull(firewallListKindAddress).ListSemanticEquals(context.Background(), state); equal {
		t.Error("null address list must not compare equal")
	}
	if equal, _ := planned.ListSemanticEquals(context.Background(), firewallCanonicalListUnknown(firewallListKindAddress)); equal {
		t.Error("address list must not compare equal to unknown")
	}
}

func TestFirewallSchema_PlanStaysIdenticalToConfig(t *testing.T) {
	// Regression guard for F01/F02/F03: no plan modifier on the
	// canonicalised attributes may rewrite the planned value, otherwise
	// Terraform core rejects the plan ("Provider produced invalid plan").
	// Only UseStateForUnknown (which never rewrites a known config value)
	// is allowed.
	s := windowsFirewallRuleSchemaDefinition(context.Background())
	proto := s.Attributes["protocol"].(schema.StringAttribute)
	for _, pm := range proto.PlanModifiers {
		if !reflect.DeepEqual(pm, stringplanmodifier.UseStateForUnknown()) {
			t.Errorf("protocol plan modifier %T rewrites the plan; only UseStateForUnknown is allowed", pm)
		}
	}
	for _, n := range []string{"local_port", "remote_port", "local_address", "remote_address"} {
		a := s.Attributes[n].(schema.ListAttribute)
		for _, pm := range a.PlanModifiers {
			if !reflect.DeepEqual(pm, listplanmodifier.UseStateForUnknown()) {
				t.Errorf("%s plan modifier %T rewrites the plan; only UseStateForUnknown is allowed", n, pm)
			}
		}
	}
}

func TestFirewallCanonicalListValue_TypeRoundTrip(t *testing.T) {
	// Values decoded from Terraform and re-encoded must keep their kind so
	// port and address attributes never compare with the wrong canonicaliser.
	ctx := context.Background()
	typ := firewallCanonicalListType{kind: firewallListKindPort}
	tfVal := tftypes.NewValue(
		tftypes.List{ElementType: tftypes.String},
		[]tftypes.Value{tftypes.NewValue(tftypes.String, "55014-55014")},
	)
	attrVal, err := typ.ValueFromTerraform(ctx, tfVal)
	if err != nil {
		t.Fatalf("ValueFromTerraform: %v", err)
	}
	got, ok := attrVal.(firewallCanonicalListValue)
	if !ok {
		t.Fatalf("ValueFromTerraform returned %T, want firewallCanonicalListValue", attrVal)
	}
	state := firewallCanonicalListFromStrings(firewallListKindPort, []string{"55014"})
	if equal, diags := got.ListSemanticEquals(ctx, state); diags.HasError() || !equal {
		t.Errorf("decoded degenerate range must equal collapsed state (diags=%v equal=%v)", diags, equal)
	}
	if got.Type(ctx).Equal(firewallCanonicalListType{kind: firewallListKindAddress}) {
		t.Error("port list type must not equal address list type")
	}
}

func TestModelToFirewallInput_Canonicalises(t *testing.T) {
	m := windowsFirewallRuleModel{
		Name:          types.StringValue("R"),
		DisplayName:   types.StringValue("R"),
		Direction:     types.StringValue("Inbound"),
		Action:        types.StringValue("Allow"),
		Enabled:       types.BoolValue(true),
		PolicyStore:   types.StringValue("PersistentStore"),
		Protocol:      firewallProtocolValueOf("tcp"),
		LocalPort:     firewallCanonicalListFromStrings(firewallListKindPort, []string{"80", "55014-55014"}),
		RemotePort:    firewallCanonicalListFromStrings(firewallListKindPort, []string{"any"}),
		LocalAddress:  firewallCanonicalListFromStrings(firewallListKindAddress, []string{"10.0.0.0/8", "any"}),
		RemoteAddress: firewallCanonicalListNull(firewallListKindAddress),
		Profile:       types.ListNull(types.StringType),
	}
	input, diags := modelToFirewallInput(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if input.Protocol != "TCP" {
		t.Errorf("Protocol = %q, want TCP", input.Protocol)
	}
	if len(input.LocalPort) != 2 || input.LocalPort[0] != "55014" || input.LocalPort[1] != "80" {
		t.Errorf("LocalPort = %v, want [55014 80]", input.LocalPort)
	}
	if len(input.RemotePort) != 1 || input.RemotePort[0] != "Any" {
		t.Errorf("RemotePort = %v, want [Any]", input.RemotePort)
	}
	if len(input.LocalAddress) != 2 || input.LocalAddress[0] != "10.0.0.0/8" || input.LocalAddress[1] != "Any" {
		t.Errorf("LocalAddress = %v, want [10.0.0.0/8 Any]", input.LocalAddress)
	}
	if input.RemoteAddress != nil {
		t.Errorf("null RemoteAddress must stay nil, got %v", input.RemoteAddress)
	}
}

// ---------------------------------------------------------------------------
// CV-3: Any must appear alone in address lists (F03)
// ---------------------------------------------------------------------------

func TestFirewallAddressAnyValidator_AnyAlone_OK(t *testing.T) {
	v := firewallRuleAddressAnyValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	any := tftypes.NewValue(listStr, []tftypes.Value{tftypes.NewValue(tftypes.String, "Any")})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"local_address": any, "remote_address": any})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("Any alone should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallAddressAnyValidator_AnyMixed_Error(t *testing.T) {
	v := firewallRuleAddressAnyValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	mixed := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "Any"),
		tftypes.NewValue(tftypes.String, "10.0.0.0/8"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"remote_address": mixed})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("Any mixed with an address should produce an error (CV-3)")
	}
}

func TestFirewallAddressAnyValidator_CaseInsensitive_Error(t *testing.T) {
	v := firewallRuleAddressAnyValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	mixed := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "any"),
		tftypes.NewValue(tftypes.String, "192.168.1.1"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"local_address": mixed})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("lowercase any mixed with an address should produce an error (CV-3)")
	}
}

func TestFirewallAddressAnyValidator_NoAny_OK(t *testing.T) {
	v := firewallRuleAddressAnyValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	addrs := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "10.0.0.0/8"),
		tftypes.NewValue(tftypes.String, "192.168.1.1"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"local_address": addrs})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("addresses without Any should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallAddressAnyValidator_PaddedAnyMixed_Error(t *testing.T) {
	// Review blocker 1: CV-3 must detect "Any" with surrounding whitespace,
	// mirroring firewallAddressValidator and CanonicalFirewallAddress which
	// both TrimSpace. [" Any ", "10.0.0.0/8"] would otherwise pass CV-3 and
	// then be canonicalised to ["10.0.0.0/8", "Any"] which Windows drops.
	v := firewallRuleAddressAnyValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	mixed := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, " Any "),
		tftypes.NewValue(tftypes.String, "10.0.0.0/8"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"remote_address": mixed})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error(`padded " Any " mixed with an address should produce an error (CV-3)`)
	}
}

func TestFirewallAddressAnyValidator_PaddedAnyAlone_OK(t *testing.T) {
	v := firewallRuleAddressAnyValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	any := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, " Any "),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"local_address": any})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf(`padded " Any " alone should be valid: %v`, resp.Diagnostics)
	}
}

func TestFirewallAddressAnyValidator_BlankIgnored(t *testing.T) {
	// Blank elements are firewallAddressValidator's concern (invalid value),
	// not CV-3's: ["Any", " "] must not raise "Invalid address combination".
	v := firewallRuleAddressAnyValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	mixed := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "Any"),
		tftypes.NewValue(tftypes.String, "   "),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{"local_address": mixed})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("blank element must be ignored by CV-3: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// CV-2: numeric TCP/UDP aliases accept ports (F02)
// ---------------------------------------------------------------------------

func TestFirewallPortProtocolValidator_NumericTCPAliasWithPorts_OK(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "443"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":   tftypes.NewValue(tftypes.String, "6"),
		"local_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("numeric TCP alias 6 + local_port should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallPortProtocolValidator_NumericUDPAliasWithPorts_OK(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "53"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":    tftypes.NewValue(tftypes.String, "17"),
		"remote_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("numeric UDP alias 17 + remote_port should be valid: %v", resp.Diagnostics)
	}
}

func TestFirewallPortProtocolValidator_NumericICMPWithPorts_Error(t *testing.T) {
	v := firewallRulePortProtocolValidator{}
	listStr := tftypes.List{ElementType: tftypes.String}
	ports := tftypes.NewValue(listStr, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "80"),
	})
	cfg := buildFWConfig(t, map[string]tftypes.Value{
		"protocol":   tftypes.NewValue(tftypes.String, "1"),
		"local_port": ports,
	})
	req := resource.ValidateConfigRequest{Config: cfg}
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("numeric ICMPv4 alias 1 + local_port should produce an error (CV-2)")
	}
}
