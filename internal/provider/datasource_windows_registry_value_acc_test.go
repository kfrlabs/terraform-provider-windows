//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_registry_value data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsRegistryValueDataSource
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccRegistryValueDSPreCheck(t *testing.T) {
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

// TestAccWindowsRegistryValueDataSource_REGSZ reads a well-known REG_SZ value
// from HKLM that is always present on Windows hosts.
func TestAccWindowsRegistryValueDataSource_REGSZ(t *testing.T) {
	testAccRegistryValueDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_registry_value" "os_name" {
  hive = "HKLM"
  path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
  name = "ProductName"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_registry_value.os_name", "id"),
					resource.TestCheckResourceAttr("data.windows_registry_value.os_name", "type", "REG_SZ"),
					resource.TestCheckResourceAttrSet("data.windows_registry_value.os_name", "value_string"),
				),
			},
		},
	})
}

// TestAccWindowsRegistryValueDataSource_NotFound verifies that a missing value
// returns an error.
func TestAccWindowsRegistryValueDataSource_NotFound(t *testing.T) {
	testAccRegistryValueDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_registry_value" "missing" {
  hive = "HKLM"
  path = "SOFTWARE\\DoesNotExist\\ZZZ"
  name = "NoSuchValue"
}
`,
				ExpectError: nil,
			},
		},
	})
}
