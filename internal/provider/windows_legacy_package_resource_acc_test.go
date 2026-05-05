//go:build acceptance

// Package provider — acceptance-test skeleton for windows_legacy_package.
//
// These tests require:
//   - build tag: acceptance  (`go test -tags acceptance ./...`)
//   - TF_ACC=1
//   - A reachable Windows host with WinRM enabled
//   - Env vars: WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD
//   - WINDOWS_LP_MSI_URL  : URL of a small public MSI (e.g. 7-Zip)
//   - WINDOWS_LP_MSI_SHA256 : sha256 of that MSI
//   - WINDOWS_LP_EXE_URL  : URL of a small public EXE installer
//   - WINDOWS_LP_EXE_PATTERN : DisplayName wildcard for the EXE
//
// Suite covers:
//   - Create + Read (MSI happy path, ProductCode discovered post-install)
//   - Update in place (timeout_seconds, log_path, environment, valid_exit_codes)
//   - Update ForceNew (source_path / source_url / installer_type changes)
//   - Import (ProductCode for MSI, DisplayName for EXE)
//   - Drift detection (manual uninstall on the host → next plan re-creates)
//   - Delete (MSI msiexec /x cleans the Uninstall hive)
//   - EXE happy path detected via display_name_pattern
//
// On CI without a Windows host, every test skips via testAccLegacyPackagePreCheck.
//
// File does NOT import terraform-plugin-testing to avoid pulling a new module
// dependency. Skeletons are commented resource.Test calls activated once the
// dependency is added.
package provider

import (
	"os"
	"testing"
)

// testAccLegacyPackagePreCheck guards every test. Skips when TF_ACC or any
// required env var is missing. MSI/EXE tests skip independently when their
// own env vars are unset.
func testAccLegacyPackagePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping windows_legacy_package acceptance test")
	}
	for _, v := range []string{"WINDOWS_HOST", "WINDOWS_USERNAME", "WINDOWS_PASSWORD"} {
		if os.Getenv(v) == "" {
			t.Skipf("env %s not set; skipping acceptance test", v)
		}
	}
}

// TestAccWindowsLegacyPackage_Basic — Create + Read + Destroy (MSI).
func TestAccWindowsLegacyPackage_Basic(t *testing.T) {
	testAccLegacyPackagePreCheck(t)
	if os.Getenv("WINDOWS_LP_MSI_URL") == "" || os.Getenv("WINDOWS_LP_MSI_SHA256") == "" {
		t.Skip("WINDOWS_LP_MSI_URL / WINDOWS_LP_MSI_SHA256 not set")
	}
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows host")
	// resource.Test(t, resource.TestCase{
	//   ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
	//   CheckDestroy: testAccCheckLegacyPackageDestroyed("acc-7zip"),
	//   Steps: []resource.TestStep{
	//     {
	//       Config: testAccLegacyPackageConfig_msiBasic(
	//         "acc-7zip",
	//         os.Getenv("WINDOWS_LP_MSI_URL"),
	//         os.Getenv("WINDOWS_LP_MSI_SHA256"),
	//       ),
	//       Check: resource.ComposeTestCheckFunc(
	//         resource.TestCheckResourceAttr("windows_legacy_package.test", "name", "acc-7zip"),
	//         resource.TestCheckResourceAttr("windows_legacy_package.test", "installer_type", "msi"),
	//         resource.TestCheckResourceAttr("windows_legacy_package.test", "installed", "true"),
	//         resource.TestCheckResourceAttrSet("windows_legacy_package.test", "id"),
	//         resource.TestCheckResourceAttrSet("windows_legacy_package.test", "product_id"),
	//         resource.TestCheckResourceAttrSet("windows_legacy_package.test", "installed_version"),
	//       ),
	//     },
	//   },
	// })
}

// TestAccWindowsLegacyPackage_UpdateInPlace — only mutable attributes change
// (timeout_seconds, log_path, valid_exit_codes, environment); ID must persist.
func TestAccWindowsLegacyPackage_UpdateInPlace(t *testing.T) {
	testAccLegacyPackagePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLegacyPackage_Basic")
	// resource.Test(t, resource.TestCase{
	//   Steps: []resource.TestStep{
	//     {Config: testAccLegacyPackageConfig_msiBasic(...)},
	//     {
	//       Config: testAccLegacyPackageConfig_msiTimeout("acc-7zip", 600),
	//       Check: resource.ComposeTestCheckFunc(
	//         resource.TestCheckResourceAttr("windows_legacy_package.test", "timeout_seconds", "600"),
	//         // ID unchanged proves no destroy/recreate happened.
	//       ),
	//     },
	//   },
	// })
}

// TestAccWindowsLegacyPackage_ForceNew — changing installer_type (or
// source_path / source_url) triggers destroy + recreate.
func TestAccWindowsLegacyPackage_ForceNew(t *testing.T) {
	testAccLegacyPackagePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLegacyPackage_Basic")
	// Two consecutive Configs with different source_url — expect ID to flip.
}

// TestAccWindowsLegacyPackage_Import — import by ProductCode GUID (MSI).
func TestAccWindowsLegacyPackage_Import(t *testing.T) {
	testAccLegacyPackagePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLegacyPackage_Basic")
	// resource.Test(t, resource.TestCase{
	//   Steps: []resource.TestStep{
	//     {Config: testAccLegacyPackageConfig_msiBasic(...)},
	//     {
	//       ResourceName:            "windows_legacy_package.test",
	//       ImportState:             true,
	//       ImportStateVerify:       true,
	//       ImportStateVerifyIgnore: []string{"source_url", "checksum", "install_args"},
	//     },
	//   },
	// })
}

// TestAccWindowsLegacyPackage_DriftDetection — manual uninstall outside TF
// must surface as a plan-time replacement on the next refresh.
func TestAccWindowsLegacyPackage_DriftDetection(t *testing.T) {
	testAccLegacyPackagePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLegacyPackage_Basic")
	// Step 1: create.
	// Step 2: PreConfig → ssh/winrm and run msiexec /x <ID> /qn /norestart.
	// Step 3: ExpectNonEmptyPlan with replace-required diff.
}

// TestAccWindowsLegacyPackage_EXEByDisplayName — EXE installer detected via
// display_name_pattern in the Uninstall hives.
func TestAccWindowsLegacyPackage_EXEByDisplayName(t *testing.T) {
	testAccLegacyPackagePreCheck(t)
	if os.Getenv("WINDOWS_LP_EXE_URL") == "" || os.Getenv("WINDOWS_LP_EXE_PATTERN") == "" {
		t.Skip("WINDOWS_LP_EXE_URL / WINDOWS_LP_EXE_PATTERN not set")
	}
	t.Skip("SKELETON: see TestAccWindowsLegacyPackage_Basic")
	// resource.Test(t, ... installer_type=exe + display_name_pattern + checksum)
}
