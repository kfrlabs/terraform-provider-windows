//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_local_group data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsLocalGroupDataSource
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccLocalGroupDSPreCheck(t *testing.T) {
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

// TestAccWindowsLocalGroupDataSource_ByName looks up the built-in
// Administrators group by name.
func TestAccWindowsLocalGroupDataSource_ByName(t *testing.T) {
	testAccLocalGroupDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_local_group" "admins" {
  name = "Administrators"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_group.admins", "id"),
					resource.TestCheckResourceAttr("data.windows_local_group.admins", "name", "Administrators"),
					resource.TestCheckResourceAttrSet("data.windows_local_group.admins", "sid"),
				),
			},
		},
	})
}

// TestAccWindowsLocalGroupDataSource_BySID looks up the built-in
// Administrators group by its well-known SID.
func TestAccWindowsLocalGroupDataSource_BySID(t *testing.T) {
	testAccLocalGroupDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_local_group" "admins_sid" {
  sid = "S-1-5-32-544"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_local_group.admins_sid", "sid", "S-1-5-32-544"),
					resource.TestCheckResourceAttrSet("data.windows_local_group.admins_sid", "name"),
				),
			},
		},
	})
}
