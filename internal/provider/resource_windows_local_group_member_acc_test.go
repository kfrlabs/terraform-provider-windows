//go:build acceptance

// Package provider — acceptance tests for windows_local_group_member.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights.
//
// Each test provisions its own local group and local user, then adds the user
// to the group, so it is fully self-contained and safe to run repeatedly.
// All member attributes are ForceNew (there is no in-place update path).
package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccLocalGroupMemberPreCheck(t *testing.T) {
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

// lgmFixture returns HCL that provisions a group + user and adds the user to
// the group. suffix keeps names unique on shared lab hosts.
func lgmFixture(suffix string) string {
	return fmt.Sprintf(`
resource "windows_local_group" "g" {
  name = "grp-lgm-%[1]s"
}

resource "windows_local_user" "u" {
  name     = "usr-lgm-%[1]s"
  password = "P@ssw0rd-Acc-Lgm-%[1]s!"
}

resource "windows_local_group_member" "m" {
  group  = windows_local_group.g.name
  member = windows_local_user.u.name
}
`, suffix)
}

// TestAccWindowsLocalGroupMember_Basic — add a local user to a local group,
// verify SIDs are resolved, and confirm idempotency.
func TestAccWindowsLocalGroupMember_Basic(t *testing.T) {
	testAccLocalGroupMemberPreCheck(t)

	cfg := lgmFixture(groupSuffix())
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_local_group_member.m", "group", "grp-lgm-"+groupSuffix()),
					resource.TestCheckResourceAttr("windows_local_group_member.m", "member", "usr-lgm-"+groupSuffix()),
					resource.TestCheckResourceAttrSet("windows_local_group_member.m", "group_sid"),
					resource.TestCheckResourceAttrSet("windows_local_group_member.m", "member_sid"),
					resource.TestCheckResourceAttrSet("windows_local_group_member.m", "member_principal_source"),
					// id is the composite "<group_sid>/<member_sid>".
					resource.TestCheckResourceAttrSet("windows_local_group_member.m", "id"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsLocalGroupMember_BuiltinGroup — adding a user to a BUILTIN
// group (Administrators) is supported (no BUILTIN-delete guard here).
func TestAccWindowsLocalGroupMember_BuiltinGroup(t *testing.T) {
	testAccLocalGroupMemberPreCheck(t)

	suffix := groupSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_local_user" "u" {
  name     = "usr-lgm-adm-%[1]s"
  password = "P@ssw0rd-Acc-Adm-%[1]s!"
}

resource "windows_local_group_member" "adm" {
  group  = "Administrators"
  member = windows_local_user.u.name
}
`, suffix),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_local_group_member.adm", "group", "Administrators"),
					resource.TestCheckResourceAttrSet("windows_local_group_member.adm", "member_sid"),
				),
			},
		},
	})
}

// TestAccWindowsLocalGroupMember_Import — import by "<group>/<member>".
func TestAccWindowsLocalGroupMember_Import(t *testing.T) {
	testAccLocalGroupMemberPreCheck(t)

	suffix := groupSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: lgmFixture(suffix),
			},
			{
				ResourceName:      "windows_local_group_member.m",
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("grp-lgm-%[1]s/usr-lgm-%[1]s", suffix),
				ImportStateVerify: false, // member is re-resolved to a SID-backed form on import
			},
		},
	})
}
