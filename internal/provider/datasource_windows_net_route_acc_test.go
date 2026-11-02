//go:build acceptance

// Package provider — acceptance tests for the windows_net_route data
// source.
//
// Requires TF_ACC=1 plus a reachable Windows target (see
// testAccNetRoutePreCheck in resource_windows_net_route_acc_test.go for the
// shared safety rules: documentation prefixes with on-link next hops only,
// never the management interface).
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccNetRouteDSFixture provisions a documentation route via the sibling
// resource and reads it back through the data source with and without the
// qualifiers.
func testAccNetRouteDSFixture(alias string) string {
	return `
resource "windows_net_route" "fixture" {
  destination_prefix = "198.51.100.0/24"
  interface_alias    = "` + alias + `"
  next_hop           = "0.0.0.0"
}

data "windows_net_route" "by_prefix" {
  destination_prefix = windows_net_route.fixture.destination_prefix
}

data "windows_net_route" "by_all" {
  destination_prefix = windows_net_route.fixture.destination_prefix
  interface_alias    = windows_net_route.fixture.interface_alias
  next_hop           = windows_net_route.fixture.next_hop
}
`
}

// TestAccWindowsNetRouteDataSource_Read looks the fixture route up by
// prefix alone and by the full triplet.
func TestAccWindowsNetRouteDataSource_Read(t *testing.T) {
	testAccNetRoutePreCheck(t)
	alias := testAccNetRouteTarget(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNetRouteDSFixture(alias),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_net_route.by_prefix", "destination_prefix", "198.51.100.0/24"),
					resource.TestCheckResourceAttr("data.windows_net_route.by_prefix", "address_family", "IPv4"),
					resource.TestCheckResourceAttr("data.windows_net_route.by_prefix", "next_hop", "0.0.0.0"),
					resource.TestCheckResourceAttr("data.windows_net_route.by_prefix", "protocol", "NetMgmt"),
					resource.TestCheckResourceAttr("data.windows_net_route.by_all", "destination_prefix", "198.51.100.0/24"),
					resource.TestCheckResourceAttr("data.windows_net_route.by_all", "interface_alias", alias),
					resource.TestCheckResourceAttr("data.windows_net_route.by_all", "match_count", "1"),
				),
			},
		},
	})
}
