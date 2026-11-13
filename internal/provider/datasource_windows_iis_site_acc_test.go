//go:build acceptance

// Package provider — acceptance tests for the windows_iis_site data
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

// TestAccWindowsIISSiteDataSource_Basic — the data source observes a site
// managed by the sibling resource in the same configuration.
func TestAccWindowsIISSiteDataSource_Basic(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-site-ds"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_site" "ds" {
  name          = %[1]q
  physical_path = "C:\\inetpub\\wwwroot"
  auto_start    = true
}

data "windows_iis_site" "ds" {
  name = windows_iis_site.ds.name
}
`, site),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_iis_site.ds", "id", site),
					resource.TestCheckResourceAttr("data.windows_iis_site.ds", "name", site),
					resource.TestCheckResourceAttr("data.windows_iis_site.ds", "physical_path", `C:\inetpub\wwwroot`),
					resource.TestCheckResourceAttr("data.windows_iis_site.ds", "auto_start", "true"),
				),
			},
		},
	})
}

// TestAccWindowsIISSiteDataSource_DefaultWebSite — the data source reads
// the built-in Default Web Site that ships with the Web-Server feature.
func TestAccWindowsIISSiteDataSource_DefaultWebSite(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_iis_site" "def" {
  name = "Default Web Site"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_iis_site.def", "id", "Default Web Site"),
					resource.TestCheckResourceAttr("data.windows_iis_site.def", "name", "Default Web Site"),
					resource.TestCheckResourceAttr("data.windows_iis_site.def", "site_id", "1"),
					resource.TestCheckResourceAttrSet("data.windows_iis_site.def", "physical_path"),
				),
			},
		},
	})
}

// TestAccWindowsIISSiteDataSource_NotFound — a missing site is a
// diagnostic error naming the site.
func TestAccWindowsIISSiteDataSource_NotFound(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_iis_site" "missing" {
  name = "tf-acc-site-does-not-exist"
}
`,
				ExpectError: regexp.MustCompile("No IIS site named .* was found"),
			},
		},
	})
}
