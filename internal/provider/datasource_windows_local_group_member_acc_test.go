//go:build acceptance

// Package provider — acceptance-test skeleton for windows_local_group_member data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsLocalGroupMemberDataSource
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccLocalGroupMemberDSPreCheck(t *testing.T) {
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

// TestAccWindowsLocalGroupMemberDataSource_Basic looks up the Administrator
// account in the Administrators group (always present on a Windows host).
func TestAccWindowsLocalGroupMemberDataSource_Basic(t *testing.T) {
	testAccLocalGroupMemberDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_local_group_member" "test" {
  group_name  = "Administrators"
  member_name = "Administrator"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_group_member.test", "id"),
					resource.TestCheckResourceAttr("data.windows_local_group_member.test", "group_name", "Administrators"),
					resource.TestCheckResourceAttrSet("data.windows_local_group_member.test", "group_sid"),
					resource.TestCheckResourceAttrSet("data.windows_local_group_member.test", "member_sid"),
					resource.TestCheckResourceAttrSet("data.windows_local_group_member.test", "member_principal_source"),
				),
			},
		},
	})
}
