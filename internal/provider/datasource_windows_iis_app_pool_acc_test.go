//go:build acceptance

// Package provider — acceptance tests for the windows_iis_app_pool data
// source.
//
// Requires TF_ACC=1 plus a Windows target with IIS (installed on demand by
// accEnsureIIS in resource_windows_iis_app_pool_acc_test.go).
package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccWindowsIISAppPoolDataSource_Basic — the data source observes a pool
// managed by the sibling resource in the same configuration.
func TestAccWindowsIISAppPoolDataSource_Basic(t *testing.T) {
	testAccIISAppPoolPreCheck(t)
	accEnsureIIS(t)

	const pool = "tf-acc-apppool-ds"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_app_pool" "ds" {
  name                  = %[1]q
  managed_runtime_version = "v4.0"
  queue_length          = 1000
}

data "windows_iis_app_pool" "ds" {
  name = windows_iis_app_pool.ds.name
}
`, pool),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_iis_app_pool.ds", "id", pool),
					resource.TestCheckResourceAttr("data.windows_iis_app_pool.ds", "name", pool),
					resource.TestCheckResourceAttr("data.windows_iis_app_pool.ds", "managed_runtime_version", "v4.0"),
					resource.TestCheckResourceAttr("data.windows_iis_app_pool.ds", "queue_length", "1000"),
				),
			},
		},
	})
}

// TestAccWindowsIISAppPoolDataSource_NotFound — a missing pool is a
// diagnostic error naming the pool.
func TestAccWindowsIISAppPoolDataSource_NotFound(t *testing.T) {
	testAccIISAppPoolPreCheck(t)
	accEnsureIIS(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_iis_app_pool" "missing" {
  name = "tf-acc-apppool-does-not-exist"
}
`,
				ExpectError: regexp.MustCompile("No IIS application pool named .* was found"),
			},
		},
	})
}
