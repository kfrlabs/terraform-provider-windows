//go:build acceptance

// Package provider — acceptance test for the windows_local_groups data
// source.
//
// Read-only: safe on any host. Requires TF_ACC=1 plus a reachable Windows
// target; otherwise skips. Filters to the well-known Administrators SID
// (stable across languages, unlike the display name) and asserts the group
// resolves with its SID; a second block exercises include_members.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccWindowsLocalGroupsDataSource_Basic(t *testing.T) {
	testAccLocalGroupDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_local_groups" "admins" {
  sids = ["S-1-5-32-544"]
}

data "windows_local_groups" "admins_members" {
  sids            = ["S-1-5-32-544"]
  include_members = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_groups.admins", "id"),
					resource.TestCheckResourceAttr("data.windows_local_groups.admins", "groups.#", "1"),
					resource.TestCheckResourceAttr("data.windows_local_groups.admins", "groups.0.sid", "S-1-5-32-544"),
					resource.TestCheckResourceAttrSet("data.windows_local_groups.admins", "groups.0.name"),
					resource.TestCheckResourceAttrSet("data.windows_local_groups.admins_members", "id"),
					resource.TestCheckResourceAttr("data.windows_local_groups.admins_members", "groups.#", "1"),
					resource.TestCheckResourceAttr("data.windows_local_groups.admins_members", "groups.0.sid", "S-1-5-32-544"),
				),
			},
		},
	})
}
