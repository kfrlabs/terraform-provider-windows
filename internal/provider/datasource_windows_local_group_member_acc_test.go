//go:build acceptance

// Package provider — acceptance tests for the windows_local_group_member data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsLocalGroupMemberDataSource
//
// The test provisions its own throwaway local group, local user, and group
// membership via the sibling resources, then looks the pair up through the
// data source. This keeps the suite host-agnostic: it must not assume the
// built-in Administrator account exists, since that account is disabled/renamed
// on GitHub-hosted windows-latest runners, and its SID is machine-specific
// anyway. The framework destroys the fixtures at the end of the test.
package provider

import (
	"os"
	"regexp"
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

// testAccLocalGroupMemberDSFixtureConfig renders a fixture group + user and
// adds the user to the group, then a data source that looks the pair up. The
// data source's group_name/member_name reference the membership resource's
// attributes, giving it an implicit dependency so the member always exists at
// read time. The password literal is a dummy complexity-satisfying value; it is
// never asserted.
func testAccLocalGroupMemberDSFixtureConfig(suffix string) string {
	return `
resource "windows_local_group" "fixture" {
  name = "grp-lgmds-` + suffix + `"
}

resource "windows_local_user" "fixture" {
  name     = "usr-lgmds-` + suffix + `"
  password = "P@ssw0rd-Acc-Fixture!"
}

resource "windows_local_group_member" "fixture" {
  group  = windows_local_group.fixture.name
  member = windows_local_user.fixture.name
}

data "windows_local_group_member" "test" {
  group_name  = windows_local_group_member.fixture.group
  member_name = windows_local_group_member.fixture.member
}
`
}

// TestAccWindowsLocalGroupMemberDataSource_Basic provisions a throwaway group,
// user, and membership, then looks the pair up through the data source.
func TestAccWindowsLocalGroupMemberDataSource_Basic(t *testing.T) {
	testAccLocalGroupMemberDSPreCheck(t)
	suffix := groupSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccLocalGroupMemberDSFixtureConfig(suffix),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_group_member.test", "id"),
					resource.TestCheckResourceAttr("data.windows_local_group_member.test", "group_name", "grp-lgmds-"+suffix),
					resource.TestCheckResourceAttr("data.windows_local_group_member.test", "member_name", "usr-lgmds-"+suffix),
					resource.TestMatchResourceAttr("data.windows_local_group_member.test", "group_sid",
						regexp.MustCompile(`^S-1-5-`)),
					resource.TestMatchResourceAttr("data.windows_local_group_member.test", "member_sid",
						regexp.MustCompile(`^S-1-5-`)),
					resource.TestCheckResourceAttr("data.windows_local_group_member.test", "member_principal_source", "Local"),
				),
			},
		},
	})
}
