//go:build acceptance

// Package provider — acceptance tests for the windows_local_user data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsLocalUserDataSource
//
// Both tests provision their own throwaway local user via the sibling
// windows_local_user resource and then look it up through the data source.
// This keeps the suite host-agnostic: it must not assume the built-in
// Administrator account exists, since that account is disabled/renamed on
// GitHub-hosted windows-latest runners, and its SID is machine-specific
// anyway. The framework destroys the fixture at the end of each test.
package provider

import (
	"os"
	"regexp"
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

// testAccLocalUserDSFixtureConfig renders a fixture windows_local_user resource
// plus a data source that looks it up via the given lookup attribute
// (`name = ...` or `sid = ...`). The attribute reference to the resource gives
// the data source an implicit dependency, so the user always exists at read
// time. The password literal is a dummy complexity-satisfying value; it is
// never asserted (ADR-LU-3).
func testAccLocalUserDSFixtureConfig(name, lookup string) string {
	return `
resource "windows_local_user" "fixture" {
  name     = "` + name + `"
  password = "P@ssw0rd-Acc-` + name + `!"
}

data "windows_local_user" "lookup" {
  ` + lookup + `
}
`
}

// TestAccWindowsLocalUserDataSource_ByName creates a throwaway local user and
// looks it up by name through the data source.
func TestAccWindowsLocalUserDataSource_ByName(t *testing.T) {
	testAccLocalUserDSPreCheck(t)
	name := "ds-name-" + userSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccLocalUserDSFixtureConfig(name, "name = windows_local_user.fixture.name"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_user.lookup", "id"),
					resource.TestCheckResourceAttr("data.windows_local_user.lookup", "name", name),
					resource.TestMatchResourceAttr("data.windows_local_user.lookup", "sid",
						regexp.MustCompile(`^S-1-5-`)),
					resource.TestCheckResourceAttr("data.windows_local_user.lookup", "principal_source", "Local"),
				),
			},
		},
	})
}

// TestAccWindowsLocalUserDataSource_BySID creates a throwaway local user and
// looks it up by the SID Windows assigned to it. Referencing the fixture's
// computed sid avoids any machine-specific or well-known-SID assumption.
func TestAccWindowsLocalUserDataSource_BySID(t *testing.T) {
	testAccLocalUserDSPreCheck(t)
	name := "ds-sid-" + userSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccLocalUserDSFixtureConfig(name, "sid = windows_local_user.fixture.sid"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_local_user.lookup", "name", name),
					resource.TestCheckResourceAttrPair(
						"data.windows_local_user.lookup", "sid",
						"windows_local_user.fixture", "sid"),
				),
			},
		},
	})
}
