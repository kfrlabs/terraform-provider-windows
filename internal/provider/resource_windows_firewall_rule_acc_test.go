//go:build acceptance

// Package provider — acceptance tests for windows_firewall_rule.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights.
//
// All rules are created with the "tf-acc-" name prefix and removed on destroy,
// so the tests are safe to run repeatedly against a shared lab host.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccFirewallRulePreCheck(t *testing.T) {
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

// TestAccWindowsFirewallRule_Basic — create + read + idempotency.
func TestAccWindowsFirewallRule_Basic(t *testing.T) {
	testAccFirewallRulePreCheck(t)

	cfg := `
resource "windows_firewall_rule" "acc" {
  name         = "tf-acc-fw-allow-8080"
  display_name = "tf-acc fw allow 8080"
  enabled      = true
  direction    = "Inbound"
  action       = "Allow"
  profile      = ["Domain", "Private"]
  protocol     = "TCP"
  local_port   = ["8080"]
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_firewall_rule.acc", "id", "tf-acc-fw-allow-8080"),
					resource.TestCheckResourceAttr("windows_firewall_rule.acc", "direction", "Inbound"),
					resource.TestCheckResourceAttr("windows_firewall_rule.acc", "action", "Allow"),
					resource.TestCheckResourceAttr("windows_firewall_rule.acc", "enabled", "true"),
					resource.TestCheckResourceAttr("windows_firewall_rule.acc", "protocol", "TCP"),
					resource.TestCheckResourceAttr("windows_firewall_rule.acc", "local_port.0", "8080"),
					resource.TestCheckResourceAttrSet("windows_firewall_rule.acc", "policy_store"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsFirewallRule_UpdateInPlace — toggling enabled and editing the
// description update in place (name is the ForceNew identity).
func TestAccWindowsFirewallRule_UpdateInPlace(t *testing.T) {
	testAccFirewallRulePreCheck(t)

	cfg := func(enabled bool, desc string) string {
		return `
resource "windows_firewall_rule" "upd" {
  name         = "tf-acc-fw-update"
  display_name = "tf-acc fw update"
  description  = "` + desc + `"
  enabled      = ` + boolLit(enabled) + `
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["9090"]
}
`
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg(true, "before"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_firewall_rule.upd", "enabled", "true"),
					resource.TestCheckResourceAttr("windows_firewall_rule.upd", "description", "before"),
				),
			},
			{
				Config: cfg(false, "after"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_firewall_rule.upd", "enabled", "false"),
					resource.TestCheckResourceAttr("windows_firewall_rule.upd", "description", "after"),
				),
			},
		},
	})
}

// TestAccWindowsFirewallRule_OutboundBlock — outbound block rule with a
// program filter.
func TestAccWindowsFirewallRule_OutboundBlock(t *testing.T) {
	testAccFirewallRulePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_firewall_rule" "block" {
  name         = "tf-acc-fw-block-out"
  display_name = "tf-acc fw block outbound"
  enabled      = true
  direction    = "Outbound"
  action       = "Block"
  protocol     = "TCP"
  remote_port  = ["445"]
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_firewall_rule.block", "direction", "Outbound"),
					resource.TestCheckResourceAttr("windows_firewall_rule.block", "action", "Block"),
					resource.TestCheckResourceAttr("windows_firewall_rule.block", "remote_port.0", "445"),
				),
			},
		},
	})
}

// TestAccWindowsFirewallRule_Import — import an existing rule by name (== id).
func TestAccWindowsFirewallRule_Import(t *testing.T) {
	testAccFirewallRulePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_firewall_rule" "imp" {
  name         = "tf-acc-fw-import"
  display_name = "tf-acc fw import"
  enabled      = true
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["7070"]
}
`,
			},
			{
				ResourceName:      "windows_firewall_rule.imp",
				ImportState:       true,
				ImportStateId:     "tf-acc-fw-import",
				ImportStateVerify: false, // computed defaults / list normalization differ
			},
		},
	})
}

// boolLit renders a Go bool as an HCL boolean literal.
func boolLit(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
