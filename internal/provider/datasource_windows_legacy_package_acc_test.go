//go:build acceptance

// Package provider — acceptance tests for the windows_legacy_package data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsLegacyPackageDataSource
//
// The Basic test provisions a throwaway MSI install via the sibling
// windows_legacy_package resource (needs WINDOWS_LP_MSI_URL and
// WINDOWS_LP_MSI_SHA256, as in the resource acceptance suite) and looks it up
// through the data source by product_id, referencing the fixture's computed
// ProductCode so the test stays host-agnostic. The NotFound test needs no
// fixture: a nil-shaped GUID can never match an Uninstall hive entry.
package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccLegacyPackageDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccLegacyPackageDSFixtureConfig renders a fixture windows_legacy_package
// resource (MSI installed from the env-provided URL) plus a data source that
// looks it up via the fixture's computed product_id. The attribute reference
// gives the data source an implicit dependency, so the package is installed
// at read time. The framework destroys the fixture at the end of each test.
func testAccLegacyPackageDSFixtureConfig(name, msiURL, msiSHA256 string) string {
	return fmt.Sprintf(`
resource "windows_legacy_package" "fixture" {
  name           = %[1]q
  installer_type = "msi"
  source_url     = %[2]q
  checksum       = "sha256:%[3]s"
}

data "windows_legacy_package" "lookup" {
  product_id = windows_legacy_package.fixture.product_id
}
`, name, msiURL, msiSHA256)
}

// TestAccWindowsLegacyPackageDataSource_Basic installs a throwaway MSI package
// and looks it up by product_id through the data source.
func TestAccWindowsLegacyPackageDataSource_Basic(t *testing.T) {
	testAccLegacyPackageDSPreCheck(t)
	msiURL := os.Getenv("WINDOWS_LP_MSI_URL")
	msiSHA256 := os.Getenv("WINDOWS_LP_MSI_SHA256")
	if msiURL == "" || msiSHA256 == "" {
		t.Skip("WINDOWS_LP_MSI_URL / WINDOWS_LP_MSI_SHA256 not set; skipping MSI-backed data source test")
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccLegacyPackageDSFixtureConfig("acc-lp-ds", msiURL, msiSHA256),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_legacy_package.lookup", "id"),
					resource.TestCheckResourceAttr("data.windows_legacy_package.lookup", "installed", "true"),
					resource.TestCheckResourceAttrSet("data.windows_legacy_package.lookup", "product_id"),
					resource.TestCheckResourceAttrSet("data.windows_legacy_package.lookup", "installed_version"),
					resource.TestCheckResourceAttrPair(
						"data.windows_legacy_package.lookup", "product_id",
						"windows_legacy_package.fixture", "product_id"),
				),
			},
		},
	})
}

// TestAccWindowsLegacyPackageDataSource_NotFound verifies that a missing
// package returns an error rather than a silent empty state.
func TestAccWindowsLegacyPackageDataSource_NotFound(t *testing.T) {
	testAccLegacyPackageDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_legacy_package" "missing" {
  product_id = "{00000000-0000-0000-0000-000000000000}"
}
`,
				ExpectError: regexp.MustCompile(`No legacy package .* was found`),
			},
		},
	})
}
