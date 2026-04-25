// Package provider — acceptance-test skeleton for windows_feature.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows Server target with WinRM and Local Administrator rights
//   - A safe feature to install/uninstall (e.g. Telnet-Client or RSAT-AD-PowerShell)
//
// Coverage outline (skeleton; populate when terraform-plugin-testing is added):
//   - Create + Read with installed=true / install_state=Installed
//   - Update in-place: source / restart attribute changes
//   - Update with ForceNew: include_sub_features / include_management_tools
//   - Drift: Uninstall feature out-of-band -> next plan recreates resource
//   - Import: `terraform import windows_feature.x Telnet-Client`
//   - Delete: CheckDestroy verifies Get-WindowsFeature reports not Installed
package provider

import (
	"os"
	"testing"
)

func testAccFeaturePreCheck(t *testing.T) {
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

func TestAccWindowsFeature_Basic(t *testing.T) {
	testAccFeaturePreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows Server host")
}

func TestAccWindowsFeature_UpdateInPlace(t *testing.T) {
	testAccFeaturePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFeature_Basic")
}

// EC-6 ForceNew: changing include_sub_features / include_management_tools must
// trigger a destroy-recreate cycle.
func TestAccWindowsFeature_ForceNew(t *testing.T) {
	testAccFeaturePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFeature_Basic")
}

func TestAccWindowsFeature_Import(t *testing.T) {
	testAccFeaturePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFeature_Basic")
}

// EC-2 drift: out-of-band Uninstall-WindowsFeature must be detected at refresh.
func TestAccWindowsFeature_DriftDetection(t *testing.T) {
	testAccFeaturePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFeature_Basic")
}
