//go:build acceptance

// Package provider — acceptance tests for the windows_net_ip_address data
// source.
//
// Requires TF_ACC=1 plus a reachable Windows target (see
// testAccNetIPAddressPreCheck in resource_windows_net_ip_address_acc_test.go
// for the shared safety rules: documentation addresses only, never the
// management interface).
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccNetIPAddressDSFixture provisions a documentation address via the
// sibling resource and reads it back through the data source with and
// without the interface_alias qualifier.
func testAccNetIPAddressDSFixture(alias string) string {
	return `
resource "windows_net_ip_address" "fixture" {
  interface_alias = "` + alias + `"
  ip_address      = "192.0.2.10"
  prefix_length   = 24
}

data "windows_net_ip_address" "by_address" {
  ip_address = windows_net_ip_address.fixture.ip_address
}

data "windows_net_ip_address" "by_both" {
  ip_address      = windows_net_ip_address.fixture.ip_address
  interface_alias = windows_net_ip_address.fixture.interface_alias
}
`
}

// TestAccWindowsNetIPAddressDataSource_Read looks the fixture address up by
// address alone and by address plus interface.
func TestAccWindowsNetIPAddressDataSource_Read(t *testing.T) {
	testAccNetIPAddressPreCheck(t)
	alias := testAccNetIPAddressTarget(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNetIPAddressDSFixture(alias),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_net_ip_address.by_address", "ip_address", "192.0.2.10"),
					resource.TestCheckResourceAttr("data.windows_net_ip_address.by_address", "address_family", "IPv4"),
					resource.TestCheckResourceAttr("data.windows_net_ip_address.by_address", "prefix_origin", "Manual"),
					resource.TestCheckResourceAttr("data.windows_net_ip_address.by_both", "ip_address", "192.0.2.10"),
					resource.TestCheckResourceAttr("data.windows_net_ip_address.by_both", "interface_alias", alias),
				),
			},
		},
	})
}
