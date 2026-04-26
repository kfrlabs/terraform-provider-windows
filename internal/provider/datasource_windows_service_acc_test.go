//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_service data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsServiceDataSource
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccServiceDSPreCheck(t *testing.T) {
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

// TestAccWindowsServiceDataSource_Basic reads the WinRM service which must
// be running since the provider uses WinRM to connect.
func TestAccWindowsServiceDataSource_Basic(t *testing.T) {
	testAccServiceDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_service" "winrm" {
  name = "WinRM"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_service.winrm", "id"),
					resource.TestCheckResourceAttr("data.windows_service.winrm", "name", "WinRM"),
					resource.TestCheckResourceAttrSet("data.windows_service.winrm", "display_name"),
					resource.TestCheckResourceAttrSet("data.windows_service.winrm", "start_type"),
					resource.TestCheckResourceAttr("data.windows_service.winrm", "current_status", "Running"),
				),
			},
		},
	})
}

// TestAccWindowsServiceDataSource_NotFound verifies missing service produces error.
func TestAccWindowsServiceDataSource_NotFound(t *testing.T) {
	testAccServiceDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_service" "missing" {
  name = "ServiceThatDoesNotExistZZZ"
}
`,
				ExpectError: nil,
			},
		},
	})
}
