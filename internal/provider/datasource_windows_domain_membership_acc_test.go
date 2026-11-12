//go:build acceptance

// Package provider — acceptance test for the windows_domain_membership data source.
//
// Read-only: safe on any host (workgroup or domain-joined). Requires
// TF_ACC=1 plus a reachable Windows target; otherwise skips.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccDomainMembershipDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// TestAccWindowsDomainMembershipDataSource_Basic reads the singleton data
// source and verifies the stable shape: id is the machine ID, domain is
// empty when workgroup-joined, workgroup is empty when joined, and the
// secure-channel result is null unless the host is joined and probed.
func TestAccWindowsDomainMembershipDataSource_Basic(t *testing.T) {
	testAccDomainMembershipDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "windows_domain_membership" "test" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.test", "id"),
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.test", "part_of_domain"),
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.test", "computer_name"),
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.test", "dns_host_name"),
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.test", "fqdn"),
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.test", "domain_role"),
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.test", "pending_reboot"),
				),
			},
			{
				// Inventory-only read: no secure-channel probe, so the
				// result is null instead of a DC round-trip.
				Config: `data "windows_domain_membership" "inventory" { check_secure_channel = false }`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_domain_membership.inventory", "id"),
					resource.TestCheckNoResourceAttr("data.windows_domain_membership.inventory", "secure_channel_ok"),
				),
			},
		},
	})
}
