//go:build acceptance

// Package provider — acceptance tests for the windows_ntp data source.
//
// Requires TF_ACC=1 plus a Windows target with the W32Time service
// registered (see resource_windows_ntp_acc_test.go). On targets without
// W32Time (containers) the suite skips with a visible reason instead of
// failing; the skip is allow-listed in
// .github/testacc-allowed-skips.json.
package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccWindowsNTPDataSource_Basic — read the singleton time source.
func TestAccWindowsNTPDataSource_Basic(t *testing.T) {
	testAccNTPPreCheck(t)
	accNTPEnsureMutable(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_ntp" "current" {}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_ntp.current", "id"),
					resource.TestCheckResourceAttrSet("data.windows_ntp.current", "type"),
					resource.TestMatchResourceAttr("data.windows_ntp.current", "type", regexp.MustCompile(`^(NTP|NT5DS|AllSync|NoSync)$`)),
				),
			},
		},
	})
}
