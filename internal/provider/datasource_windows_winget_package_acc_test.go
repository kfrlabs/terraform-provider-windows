// Package provider — acceptance-test skeletons for windows_winget_package data source.
//
// Requires (all must be set to activate acceptance tests):
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Microsoft.WinGet.Client installed
//
// Test scenarios covered:
//
//	DS-AT-1  Basic: lookup an installed package by id (winget source)
//	DS-AT-2  Default source: source attribute omitted → defaults to "winget"
//	DS-AT-3  Not-found: lookup a non-existent package → ExpectError 'not_found'
//
// All tests skip immediately when TF_ACC is not set. Per the prompt's golden
// rule for KIND=datasource, no Update / Drift / Import / CheckDestroy logic.
package provider

import (
	"os"
	"testing"
)

// testAccWingetPackageDSPreCheck guards all winget package data source
// acceptance tests.
func testAccWingetPackageDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	for _, v := range []string{"WINDOWS_HOST", "WINDOWS_USERNAME", "WINDOWS_PASSWORD"} {
		if os.Getenv(v) == "" {
			t.Skipf("env %s not set; skipping acceptance test", v)
		}
	}
}

// ---------------------------------------------------------------------------
// DS-AT-1 — Basic happy-path lookup
// ---------------------------------------------------------------------------

// TestAccWindowsWingetPackageDataSource_Basic verifies that an existing
// winget-managed package can be read by id and that the computed attributes
// (id, name, installed_version, is_installed) are populated.
func TestAccWindowsWingetPackageDataSource_Basic(t *testing.T) {
	testAccWingetPackageDSPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target with Microsoft.PowerShell installed via winget")
	/*
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						// Pre-condition: install the package via the resource first to
						// guarantee a stable lookup target.
						Config: `
		resource "windows_winget_package" "seed" {
		  package_id = "Microsoft.PowerShell"
		  source     = "winget"
		}

		data "windows_winget_package" "test" {
		  package_id = windows_winget_package.seed.package_id
		  source     = "winget"
		  depends_on = [windows_winget_package.seed]
		}`,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("data.windows_winget_package.test", "package_id", "Microsoft.PowerShell"),
							resource.TestCheckResourceAttr("data.windows_winget_package.test", "source", "winget"),
							resource.TestCheckResourceAttr("data.windows_winget_package.test", "is_installed", "true"),
							resource.TestCheckResourceAttrSet("data.windows_winget_package.test", "installed_version"),
							resource.TestCheckResourceAttrSet("data.windows_winget_package.test", "name"),
							resource.TestMatchResourceAttr("data.windows_winget_package.test", "id",
								regexp.MustCompile(`^winget:Microsoft\.PowerShell)),
						),
					},
				},
			})
	*/
}

// ---------------------------------------------------------------------------
// DS-AT-2 — source attribute defaults to "winget" when omitted
// ---------------------------------------------------------------------------

func TestAccWindowsWingetPackageDataSource_BasicDefaultSource(t *testing.T) {
	testAccWingetPackageDSPreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: `
		resource "windows_winget_package" "seed" {
		  package_id = "Microsoft.PowerShell"
		  source     = "winget"
		}

		data "windows_winget_package" "test" {
		  package_id = windows_winget_package.seed.package_id
		  # source omitted on purpose → defaults to "winget"
		  depends_on = [windows_winget_package.seed]
		}`,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("data.windows_winget_package.test", "source", "winget"),
							resource.TestCheckResourceAttr("data.windows_winget_package.test", "is_installed", "true"),
						),
					},
				},
			})
	*/
}

// ---------------------------------------------------------------------------
// DS-AT-3 — Not-found returns a Terraform error (not silent empty state)
// ---------------------------------------------------------------------------

// TestAccWindowsWingetPackageDataSource_NotFound verifies that looking up a
// non-existent winget package id produces a Terraform error matching
// 'not_found' (per spec: "data sources must not produce empty state").
func TestAccWindowsWingetPackageDataSource_NotFound(t *testing.T) {
	testAccWingetPackageDSPreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: `
		data "windows_winget_package" "missing" {
		  package_id = "TF.Definitely.Does.Not.Exist.XYZ123"
		  source     = "winget"
		}`,
						ExpectError: regexp.MustCompile(`not[ _]found`),
					},
				},
			})
	*/
}
