//go:build acceptance

// Package provider — acceptance test for the windows_installed_software
// data source.
//
// Read-only: safe on any host. Requires TF_ACC=1 plus a reachable Windows
// target; otherwise skips. Asserts the inventory is non-empty and every
// element carries a name and registry key. No software is installed: the
// suite only inventories what is already present (installing even a tiny
// MSI would couple the test to the legacy_package lifecycle).
package provider

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func testAccInstalledSoftwareDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccCheckInstalledSoftwareNonEmpty verifies the packages list holds at
// least one entry and every element carries a name and registry key.
func testAccCheckInstalledSoftwareNonEmpty(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("resource %q not found in state", name)
		}
		n, err := strconv.Atoi(rs.Primary.Attributes["packages.#"])
		if err != nil {
			return fmt.Errorf("packages.# is not a number: %v", err)
		}
		if n == 0 {
			return fmt.Errorf("expected at least one installed package, got none")
		}
		for i := 0; i < n; i++ {
			if rs.Primary.Attributes[fmt.Sprintf("packages.%d.name", i)] == "" {
				return fmt.Errorf("packages.%d is missing name", i)
			}
			if rs.Primary.Attributes[fmt.Sprintf("packages.%d.registry_key", i)] == "" {
				return fmt.Errorf("packages.%d is missing registry_key", i)
			}
		}
		return nil
	}
}

// TestAccWindowsInstalledSoftwareDataSource_Basic reads the full inventory
// and the inventory filtered by the first found name.
func TestAccWindowsInstalledSoftwareDataSource_Basic(t *testing.T) {
	testAccInstalledSoftwareDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "windows_installed_software" "all" {}` + "\n" +
					`data "windows_installed_software" "dotnet" { name_regex = "Microsoft .NET" }` + "\n",
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_installed_software.all", "id"),
					testAccCheckInstalledSoftwareNonEmpty("data.windows_installed_software.all"),
					resource.TestCheckResourceAttrSet("data.windows_installed_software.dotnet", "id"),
				),
			},
		},
	})
}
