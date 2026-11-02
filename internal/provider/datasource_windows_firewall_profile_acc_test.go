//go:build acceptance

// Package provider — acceptance tests for the windows_firewall_profile data
// source.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled and the NetSecurity module.
//
// Profiles always exist, so the basic case reads a live profile without any
// fixture; the not-found case exercises the invalid-name guard.
package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccFirewallProfileDSPRECheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// TestAccWindowsFirewallProfileDataSource_Basic — read the observed state of
// the Public profile (always present) without managing it.
func TestAccWindowsFirewallProfileDataSource_Basic(t *testing.T) {
	testAccFirewallProfileDSPRECheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_firewall_profile" "ds" {
  name = "Public"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_firewall_profile.ds", "id", "Public"),
					resource.TestCheckResourceAttr("data.windows_firewall_profile.ds", "name", "Public"),
					resource.TestCheckResourceAttrSet("data.windows_firewall_profile.ds", "enabled"),
					resource.TestCheckResourceAttrSet("data.windows_firewall_profile.ds", "default_inbound_action"),
					resource.TestCheckResourceAttrSet("data.windows_firewall_profile.ds", "log_file_name"),
				),
			},
		},
	})
}

// TestAccWindowsFirewallProfileDataSource_NotFound — an unknown profile name
// is rejected with a not-found diagnostic.
func TestAccWindowsFirewallProfileDataSource_NotFound(t *testing.T) {
	testAccFirewallProfileDSPRECheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_firewall_profile" "missing" {
  name = "Bogus"
}
`,
				ExpectError: regexp.MustCompile(`(?i)not found|invalid.*profile`),
			},
		},
	})
}
