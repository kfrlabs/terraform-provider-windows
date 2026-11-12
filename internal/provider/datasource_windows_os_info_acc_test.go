//go:build acceptance

// Package provider — acceptance test for the windows_os_info data source.
//
// Read-only: safe on any host. Requires TF_ACC=1 plus a reachable Windows
// target; otherwise skips.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccOSInfoDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// TestAccWindowsOSInfoDataSource_Basic reads the singleton data source and
// verifies the stable shape. is_server_core is intentionally not asserted:
// its value is host-dependent (Server Core vs full installation).
func TestAccWindowsOSInfoDataSource_Basic(t *testing.T) {
	testAccOSInfoDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "windows_os_info" "test" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_os_info.test", "id"),
					resource.TestCheckResourceAttrSet("data.windows_os_info.test", "product_name"),
					resource.TestCheckResourceAttrSet("data.windows_os_info.test", "version"),
					resource.TestCheckResourceAttrSet("data.windows_os_info.test", "build_number"),
					resource.TestCheckResourceAttrSet("data.windows_os_info.test", "edition_id"),
				),
			},
		},
	})
}
