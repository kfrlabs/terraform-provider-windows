//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_hostname data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsHostnameDataSource
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccHostnameDSPreCheck(t *testing.T) {
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

// TestAccWindowsHostnameDataSource_Basic reads the hostname state of the
// target host and verifies computed attributes are populated.
func TestAccWindowsHostnameDataSource_Basic(t *testing.T) {
	testAccHostnameDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "windows_hostname" "test" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_hostname.test", "id", "current"),
					resource.TestCheckResourceAttrSet("data.windows_hostname.test", "current_name"),
					resource.TestCheckResourceAttrSet("data.windows_hostname.test", "pending_name"),
					resource.TestCheckResourceAttrSet("data.windows_hostname.test", "machine_id"),
				),
			},
		},
	})
}
