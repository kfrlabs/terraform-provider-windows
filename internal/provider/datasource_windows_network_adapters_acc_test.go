//go:build acceptance

// Package provider — acceptance test for the windows_network_adapters data
// source.
//
// Read-only: safe on any host. Requires TF_ACC=1 plus a reachable Windows
// target; otherwise skips. is_management is intentionally not asserted: it
// marks whichever adapter carries the session and is host-dependent.
package provider

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func testAccNetworkAdaptersDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccCheckNetworkAdaptersNonEmpty verifies the adapters list holds at
// least one adapter and every element carries an interface_index.
func testAccCheckNetworkAdaptersNonEmpty(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("resource %q not found in state", name)
		}
		n, err := strconv.Atoi(rs.Primary.Attributes["adapters.#"])
		if err != nil {
			return fmt.Errorf("adapters.# is not a number: %v", err)
		}
		if n == 0 {
			return fmt.Errorf("expected at least one network adapter, got none")
		}
		for i := 0; i < n; i++ {
			if rs.Primary.Attributes[fmt.Sprintf("adapters.%d.interface_index", i)] == "" {
				return fmt.Errorf("adapters.%d is missing interface_index", i)
			}
		}
		return nil
	}
}

// TestAccWindowsNetworkAdaptersDataSource_Basic reads the full inventory
// and the physical-only subset.
func TestAccWindowsNetworkAdaptersDataSource_Basic(t *testing.T) {
	testAccNetworkAdaptersDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "windows_network_adapters" "all" {}` + "\n" +
					`data "windows_network_adapters" "physical" { physical_only = true }` + "\n",
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_network_adapters.all", "id"),
					testAccCheckNetworkAdaptersNonEmpty("data.windows_network_adapters.all"),
					resource.TestCheckResourceAttrSet("data.windows_network_adapters.physical", "id"),
					testAccCheckNetworkAdaptersNonEmpty("data.windows_network_adapters.physical"),
				),
			},
		},
	})
}
