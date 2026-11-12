//go:build acceptance

// Package provider — acceptance tests for the windows_timezone data source.
//
// The data source is read-only, so this suite runs against any reachable
// host without a mutability probe.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccTimezoneDSPPreCheck(t *testing.T) {
	t.Helper()
	testAccTimezonePreCheck(t)
}

// TestAccWindowsTimezoneDataSource_Basic — singleton read returns the full
// computed attribute set.
func TestAccWindowsTimezoneDataSource_Basic(t *testing.T) {
	testAccTimezoneDSPPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_timezone" "current" {}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_timezone.current", "id"),
					resource.TestCheckResourceAttrSet("data.windows_timezone.current", "timezone_id"),
					resource.TestCheckResourceAttrSet("data.windows_timezone.current", "display_name"),
					resource.TestCheckResourceAttrSet("data.windows_timezone.current", "base_utc_offset"),
					resource.TestCheckResourceAttrSet("data.windows_timezone.current", "current_utc_offset"),
				),
			},
		},
	})
}
