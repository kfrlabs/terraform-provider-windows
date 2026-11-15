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
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	schemavalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
