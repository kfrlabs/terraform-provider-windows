//go:build acceptance

// Package provider — acceptance tests for windows_feature.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows *Server* target (Install-WindowsFeature / Get-WindowsFeature)
//     with WinRM enabled and Local Administrator rights. The testacc-windows
//     workflow's windows-latest runner (Server) satisfies this.
//   - WINDOWS_FEATURE_NAME (optional): feature to install/uninstall; defaults
//     to "Telnet-Client" — a lightweight feature whose payload ships on disk
//     (no -Source, no reboot).
//
// Declaring the resource installs the feature; destroy uninstalls it. The
// default feature is intentionally trivial so the create/destroy cycle is fast
// and reversible.
package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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

// featureName returns the feature under test (default: Telnet-Client).
func featureName() string {
	if n := os.Getenv("WINDOWS_FEATURE_NAME"); n != "" {
		return n
	}
	return "Telnet-Client"
}

// TestAccWindowsFeature_Basic — install a feature, read back Installed state,
// and confirm idempotency.
func TestAccWindowsFeature_Basic(t *testing.T) {
	testAccFeaturePreCheck(t)

	name := featureName()
	cfg := fmt.Sprintf(`
resource "windows_feature" "acc" {
  name    = %q
  restart = false
}
`, name)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_feature.acc", "id", name),
					resource.TestCheckResourceAttr("windows_feature.acc", "name", name),
					resource.TestCheckResourceAttr("windows_feature.acc", "installed", "true"),
					resource.TestCheckResourceAttr("windows_feature.acc", "install_state", "Installed"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsFeature_Import — import an installed feature by its name (== id).
func TestAccWindowsFeature_Import(t *testing.T) {
	testAccFeaturePreCheck(t)

	name := featureName()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_feature" "imp" {
  name    = %q
  restart = false
}
`, name),
			},
			{
				ResourceName:      "windows_feature.imp",
				ImportState:       true,
				ImportStateId:     name,
				ImportStateVerify: false, // include_* / restart inputs are not read back
			},
		},
	})
}
