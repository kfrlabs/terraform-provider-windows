//go:build acceptance

// Package provider — acceptance tests for windows_service.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights.
//
// The tests create a DISPOSABLE service named "tf-acc-svc-*" pointing at
// cmd.exe with start_type=Manual/Disabled and no desired `status`
// ("observe-only"), so Windows registers the service in the SCM but never
// tries to start the (non-service) binary. The service is removed on destroy.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccServicePreCheck(t *testing.T) {
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

// TestAccWindowsService_Basic — create a disposable service + read + idempotency.
func TestAccWindowsService_Basic(t *testing.T) {
	testAccServicePreCheck(t)

	cfg := `
resource "windows_service" "acc" {
  name         = "tf-acc-svc-basic"
  display_name = "TF Acc Service Basic"
  description  = "created by acceptance test"
  binary_path  = "C:\\Windows\\System32\\cmd.exe"
  start_type   = "Manual"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_service.acc", "id", "tf-acc-svc-basic"),
					resource.TestCheckResourceAttr("windows_service.acc", "name", "tf-acc-svc-basic"),
					resource.TestCheckResourceAttr("windows_service.acc", "display_name", "TF Acc Service Basic"),
					resource.TestCheckResourceAttr("windows_service.acc", "start_type", "Manual"),
					resource.TestCheckResourceAttrSet("windows_service.acc", "current_status"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsService_UpdateInPlace — display_name, description and
// start_type update in place (name/binary_path are the ForceNew identity).
func TestAccWindowsService_UpdateInPlace(t *testing.T) {
	testAccServicePreCheck(t)

	cfg := func(display, desc, startType string) string {
		return `
resource "windows_service" "upd" {
  name         = "tf-acc-svc-update"
  display_name = "` + display + `"
  description  = "` + desc + `"
  binary_path  = "C:\\Windows\\System32\\cmd.exe"
  start_type   = "` + startType + `"
}
`
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("Before", "before", "Manual"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_service.upd", "display_name", "Before"),
					resource.TestCheckResourceAttr("windows_service.upd", "start_type", "Manual"),
				),
			},
			{
				Config: cfg("After", "after", "Disabled"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_service.upd", "display_name", "After"),
					resource.TestCheckResourceAttr("windows_service.upd", "description", "after"),
					resource.TestCheckResourceAttr("windows_service.upd", "start_type", "Disabled"),
				),
			},
		},
	})
}

// TestAccWindowsService_Import — import an existing service by name (== id).
func TestAccWindowsService_Import(t *testing.T) {
	testAccServicePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_service" "imp" {
  name         = "tf-acc-svc-import"
  display_name = "TF Acc Service Import"
  binary_path  = "C:\\Windows\\System32\\cmd.exe"
  start_type   = "Manual"
}
`,
			},
			{
				ResourceName:      "windows_service.imp",
				ImportState:       true,
				ImportStateId:     "tf-acc-svc-import",
				ImportStateVerify: false, // binary_path / write-only fields differ after import
			},
		},
	})
}
