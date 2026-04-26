//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_local_user data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsLocalUserDataSource
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccLocalUserDSPreCheck(t *testing.T) {
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

// TestAccWindowsLocalUserDataSource_ByName looks up the built-in Administrator
// account by name.
func TestAccWindowsLocalUserDataSource_ByName(t *testing.T) {
	testAccLocalUserDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_local_user" "admin" {
  name = "Administrator"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_user.admin", "id"),
					resource.TestCheckResourceAttr("data.windows_local_user.admin", "name", "Administrator"),
					resource.TestCheckResourceAttrSet("data.windows_local_user.admin", "sid"),
					resource.TestCheckResourceAttrSet("data.windows_local_user.admin", "principal_source"),
				),
			},
		},
	})
}

// TestAccWindowsLocalUserDataSource_BySID looks up a user by SID.
func TestAccWindowsLocalUserDataSource_BySID(t *testing.T) {
	testAccLocalUserDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// S-1-5-21-...-500 is the well-known Administrator RID.
				// The full SID is machine-specific; use a variable in real runs.
				Config: `
variable "admin_sid" { default = "S-1-5-21-0-0-0-500" }
data "windows_local_user" "by_sid" {
  sid = var.admin_sid
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_user.by_sid", "name"),
				),
			},
		},
	})
}
