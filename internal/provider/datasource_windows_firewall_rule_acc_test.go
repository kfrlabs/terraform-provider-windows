//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_firewall_rule
// data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// The host must allow administrative WinRM access since the test creates a
// firewall rule in the resource step before reading it back via the data
// source.
//
// Run with:
//
//	go test -tags acceptance ./internal/provider/ -run TestAccWindowsFirewallRuleDataSource
package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccFirewallRuleDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	for _, v := range []string{"WINDOWS_HOST", "WINDOWS_USERNAME", "WINDOWS_PASSWORD"} {
		if os.Getenv(v) == "" {
			t.Skipf("env %s not set; skipping acceptance test", v)
		}
	}
}

// TestAccWindowsFirewallRuleDataSource_Basic creates a firewall rule via the
// resource and reads it back via the data source in the same configuration,
// verifying that observed attributes match the desired configuration.
func TestAccWindowsFirewallRuleDataSource_Basic(t *testing.T) {
	testAccFirewallRuleDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_firewall_rule" "acc" {
  name         = "tf-acc-fwds-allow-8443"
  display_name = "tf-acc fw datasource allow 8443"
  description  = "Acceptance test rule for windows_firewall_rule data source"
  enabled      = true
  direction    = "Inbound"
  action       = "Allow"
  profile      = ["Domain", "Private"]
  protocol     = "TCP"
  local_port   = ["8443"]
}

data "windows_firewall_rule" "acc" {
  name = windows_firewall_rule.acc.name
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_firewall_rule.acc", "id", "tf-acc-fwds-allow-8443"),
					resource.TestCheckResourceAttr("data.windows_firewall_rule.acc", "display_name", "tf-acc fw datasource allow 8443"),
					resource.TestCheckResourceAttr("data.windows_firewall_rule.acc", "direction", "Inbound"),
					resource.TestCheckResourceAttr("data.windows_firewall_rule.acc", "action", "Allow"),
					resource.TestCheckResourceAttr("data.windows_firewall_rule.acc", "enabled", "true"),
					resource.TestCheckResourceAttr("data.windows_firewall_rule.acc", "protocol", "TCP"),
					resource.TestCheckResourceAttr("data.windows_firewall_rule.acc", "local_port.0", "8443"),
					resource.TestCheckResourceAttrSet("data.windows_firewall_rule.acc", "policy_store"),
				),
			},
		},
	})
}

// TestAccWindowsFirewallRuleDataSource_NotFound verifies that querying a rule
// that does not exist returns an error diagnostic.
func TestAccWindowsFirewallRuleDataSource_NotFound(t *testing.T) {
	testAccFirewallRuleDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_firewall_rule" "missing" {
  name = "tf-acc-firewall-rule-does-not-exist-zzz"
}
`,
				ExpectError: regexp.MustCompile(`not found`),
			},
		},
	})
}
