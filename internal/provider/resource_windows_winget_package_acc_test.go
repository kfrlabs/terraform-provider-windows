//go:build acceptance

// Package provider — acceptance-test skeleton for windows_winget_package.
//
// These tests require:
//   - build tag: acceptance  (`go test -tags acceptance ./...`)
//   - TF_ACC=1
//   - A reachable Windows host with WinRM enabled
//   - Env vars: WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD
//   - The target host must have the Microsoft.WinGet.Client PowerShell module
//     installed (Install-Module Microsoft.WinGet.Client -Scope AllUsers)
//   - The calling user must be a local Administrator on the target host
//   - winget source "winget" must be reachable from the target host
//
// The suite covers:
//   - Create + Read + check attributes (package_id, source, installed_version, name, id)
//   - Update in-place (version change triggers Update-WinGetPackage, no destroy)
//   - Update with ForceNew (package_id or source change triggers destroy+recreate)
//   - Import by "<source>:<package_id>"
//   - Drift detection: out-of-band Uninstall-WinGetPackage detected on next plan
//   - Delete + CheckDestroy (Get-WinGetPackage returns nothing after destroy)
//   - RebootRequired warning emitted (hard to test without a reboot-requiring package)
//
// On CI without a Windows host every test skips via testAccWingetPreCheck (same
// guard used by all other windows_* resource acceptance tests).
//
// The file does NOT import terraform-plugin-testing to avoid introducing a
// new module dependency; skeletons are provided as commented resource.Test
// calls so that they can be activated once that dependency is added.
package provider

import (
	"os"
	"testing"
)

// testAccWingetPreCheck is the acceptance-test guard for windows_winget_package.
// It delegates to the shared environment-variable checks.
func testAccWingetPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping windows_winget_package acceptance test")
	}
	for _, v := range []string{"WINDOWS_HOST", "WINDOWS_USERNAME", "WINDOWS_PASSWORD"} {
		if os.Getenv(v) == "" {
			t.Skipf("env %s not set; skipping acceptance test", v)
		}
	}
}

// TestAccWindowsWingetPackage_Basic is the baseline create + read + destroy
// scenario. It verifies:
//   - Install-WinGetPackage succeeds and the state is populated from the Read pipeline
//   - id is set to "<source>:<package_id>"
//   - installed_version and name are populated
//   - Destroy calls Uninstall-WinGetPackage and the package is removed
//
// Skeleton: activate with github.com/hashicorp/terraform-plugin-testing.
func TestAccWindowsWingetPackage_Basic(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows host")
	// resource.Test(t, resource.TestCase{
	//   ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
	//   CheckDestroy: testAccCheckWingetPackageDestroyed("7zip.7zip", "winget"),
	//   Steps: []resource.TestStep{
	//     {
	//       Config: testAccWingetPackageConfig_basic("7zip.7zip", "winget"),
	//       Check: resource.ComposeTestCheckFunc(
	//         resource.TestCheckResourceAttr("windows_winget_package.test", "package_id", "7zip.7zip"),
	//         resource.TestCheckResourceAttr("windows_winget_package.test", "source", "winget"),
	//         resource.TestCheckResourceAttr("windows_winget_package.test", "id", "winget:7zip.7zip"),
	//         resource.TestCheckResourceAttrSet("windows_winget_package.test", "installed_version"),
	//         resource.TestCheckResourceAttrSet("windows_winget_package.test", "name"),
	//       ),
	//     },
	//   },
	// })
}

// TestAccWindowsWingetPackage_PinnedVersion installs a specific pinned version
// and verifies that installed_version matches the requested version.
func TestAccWindowsWingetPackage_PinnedVersion(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
	// resource.Test(t, resource.TestCase{
	//   ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
	//   CheckDestroy: testAccCheckWingetPackageDestroyed("7zip.7zip", "winget"),
	//   Steps: []resource.TestStep{
	//     {
	//       Config: testAccWingetPackageConfig_pinned("7zip.7zip", "winget", "24.8.0"),
	//       Check: resource.ComposeTestCheckFunc(
	//         resource.TestCheckResourceAttr("windows_winget_package.test", "version", "24.8.0"),
	//         resource.TestCheckResourceAttr("windows_winget_package.test", "installed_version", "24.8.0"),
	//       ),
	//     },
	//   },
	// })
}

// TestAccWindowsWingetPackage_UpdateVersion asserts that changing the version
// attribute triggers Update-WinGetPackage in-place (no destroy + recreate).
func TestAccWindowsWingetPackage_UpdateVersion(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
	// resource.Test(t, resource.TestCase{
	//   ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
	//   CheckDestroy: testAccCheckWingetPackageDestroyed("7zip.7zip", "winget"),
	//   Steps: []resource.TestStep{
	//     {
	//       Config: testAccWingetPackageConfig_pinned("7zip.7zip", "winget", "24.7.0"),
	//       Check:  resource.TestCheckResourceAttr("windows_winget_package.test", "version", "24.7.0"),
	//     },
	//     {
	//       Config: testAccWingetPackageConfig_pinned("7zip.7zip", "winget", "24.8.0"),
	//       Check: resource.ComposeTestCheckFunc(
	//         resource.TestCheckResourceAttr("windows_winget_package.test", "version", "24.8.0"),
	//         // ID must be unchanged (no destroy):
	//         resource.TestCheckResourceAttr("windows_winget_package.test", "id", "winget:7zip.7zip"),
	//       ),
	//     },
	//   },
	// })
}

// TestAccWindowsWingetPackage_UpdateForceNew asserts that changing package_id
// or source forces a destroy-recreate cycle (RequiresReplace plan modifier).
func TestAccWindowsWingetPackage_UpdateForceNew(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
	// Changing source from "winget" to "msstore" must trigger ForceNew.
	// resource.Test(t, resource.TestCase{
	//   Steps: []resource.TestStep{
	//     {Config: testAccWingetPackageConfig_basic("7zip.7zip", "winget")},
	//     {
	//       Config:             testAccWingetPackageConfig_basic("7zip.7zip", "msstore"),
	//       ExpectNonEmptyPlan: true,
	//     },
	//   },
	// })
}

// TestAccWindowsWingetPackage_Import covers:
//
//	terraform import windows_winget_package.test winget:7zip.7zip
func TestAccWindowsWingetPackage_Import(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
	// resource.Test(t, resource.TestCase{
	//   ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
	//   Steps: []resource.TestStep{
	//     {Config: testAccWingetPackageConfig_basic("7zip.7zip", "winget")},
	//     {
	//       ResourceName:      "windows_winget_package.test",
	//       ImportState:       true,
	//       ImportStateId:     "winget:7zip.7zip",
	//       ImportStateVerify: true,
	//       // version and override are unknown at import time → null
	//       ImportStateVerifyIgnore: []string{"version", "override"},
	//     },
	//   },
	// })
}

// TestAccWindowsWingetPackage_DriftDetection runs a second plan after
// Uninstall-WinGetPackage is called out-of-band and verifies the next plan
// shows a non-empty diff (Read returns nil → resource removed from state).
func TestAccWindowsWingetPackage_DriftDetection(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
	// Steps:
	// 1. Create the package
	// 2. Run Uninstall-WinGetPackage out-of-band via WinRM exec
	// 3. Refresh-only plan → expect non-empty plan (resource removed from state)
	// 4. Apply → package re-installed
}

// TestAccWindowsWingetPackage_DeleteIdempotent verifies that Destroy is a
// no-op when the package was already removed out-of-band before terraform destroy.
// This exercises the PackageNotInstalled idempotency guarantee.
func TestAccWindowsWingetPackage_DeleteIdempotent(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
}

// TestAccWindowsWingetPackage_AlreadyInstalled verifies that attempting to
// Create a package that is already installed returns the already_installed
// error with the import hint.
func TestAccWindowsWingetPackage_AlreadyInstalled(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
	// resource.Test(t, resource.TestCase{
	//   Steps: []resource.TestStep{
	//     // Pre-condition: package is already installed on the host.
	//     {
	//       Config:      testAccWingetPackageConfig_basic("7zip.7zip", "winget"),
	//       ExpectError: regexp.MustCompile("already_installed"),
	//     },
	//   },
	// })
}

// TestAccWindowsWingetPackage_WithOverride verifies that the -Override
// flag is forwarded to Install-WinGetPackage without errors.
func TestAccWindowsWingetPackage_WithOverride(t *testing.T) {
	testAccWingetPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsWingetPackage_Basic")
}

// ---------------------------------------------------------------------------
// Config helpers (to be used once terraform-plugin-testing is added)
// ---------------------------------------------------------------------------

// testAccWingetPackageConfig_basic returns minimal HCL for a
// windows_winget_package without a pinned version.
//
//nolint:unused
func testAccWingetPackageConfig_basic(packageID, source string) string {
	return `
resource "windows_winget_package" "test" {
  package_id = "` + packageID + `"
  source     = "` + source + `"
}
`
}

// testAccWingetPackageConfig_pinned returns HCL with a pinned version.
//
//nolint:unused
func testAccWingetPackageConfig_pinned(packageID, source, version string) string {
	return `
resource "windows_winget_package" "test" {
  package_id = "` + packageID + `"
  source     = "` + source + `"
  version    = "` + version + `"
}
`
}

// testAccWingetPackageConfig_withOverride returns HCL with an override flag.
//
//nolint:unused
func testAccWingetPackageConfig_withOverride(packageID, source, override string) string {
	return `
resource "windows_winget_package" "test" {
  package_id = "` + packageID + `"
  source     = "` + source + `"
  override   = "` + override + `"
}
`
}

// testAccCheckWingetPackageDestroyed returns a CheckDestroyFunc that verifies
// the package is no longer installed via Get-WinGetPackage.
//
//nolint:unused
func testAccCheckWingetPackageDestroyed(packageID, source string) func() error {
	return func() error {
		// Implementation: connect to the Windows host via WinRM and run
		// Get-WinGetPackage -Id <packageID> -Source <source> -MatchOption Equals
		// Expect empty result.
		return nil
	}
}
