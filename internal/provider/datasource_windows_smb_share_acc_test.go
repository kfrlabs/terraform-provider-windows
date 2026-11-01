//go:build acceptance

// Package provider — acceptance tests for the windows_smb_share data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME + at least one credential.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsSmbShareDataSource
//
// The Basic test provisions a throwaway share via the sibling
// windows_smb_share resource (itself on a windows_directory fixture) and
// looks it up through the data source by name, referencing the fixture's
// name so the lookup is host-agnostic. The NotFound test needs no fixture.
package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccSmbShareDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccSmbShareDSFixtureConfig renders a fixture share plus a data source
// that looks it up via the fixture's computed name. The attribute reference
// gives the data source an implicit dependency, so the share exists at read
// time. The framework destroys the fixtures at the end of each test.
func testAccSmbShareDSFixtureConfig(shareName, dir string) string {
	return fmt.Sprintf(`
resource "windows_directory" "fixture" {
  path = %[2]q
}

resource "windows_smb_share" "fixture" {
  name        = %[1]q
  path        = windows_directory.fixture.path
  full_access = ["BUILTIN\\Administrators"]
  read_access = ["Everyone"]
}

data "windows_smb_share" "lookup" {
  name = windows_smb_share.fixture.name
}
`, shareName, dir)
}

// TestAccWindowsSmbShareDataSource_Basic creates a throwaway share and looks
// up its observed state through the data source.
func TestAccWindowsSmbShareDataSource_Basic(t *testing.T) {
	testAccSmbShareDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSmbShareDSFixtureConfig("TF-ACC-smb-ds", `C:\TF_ACC_smb_ds`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_smb_share.lookup", "name", "TF-ACC-smb-ds"),
					resource.TestCheckResourceAttr("data.windows_smb_share.lookup", "id", "TF-ACC-smb-ds"),
					resource.TestCheckResourceAttrPair(
						"data.windows_smb_share.lookup", "path",
						"windows_smb_share.fixture", "path"),
					resource.TestCheckResourceAttr("data.windows_smb_share.lookup", "special", "false"),
					resource.TestCheckResourceAttr("data.windows_smb_share.lookup", "full_access.#", "1"),
					resource.TestCheckResourceAttr("data.windows_smb_share.lookup", "read_access.#", "1"),
				),
			},
		},
	})
}

// TestAccWindowsSmbShareDataSource_NotFound verifies that a missing share
// returns an error rather than a silent empty state.
func TestAccWindowsSmbShareDataSource_NotFound(t *testing.T) {
	testAccSmbShareDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_smb_share" "missing" {
  name = "TF-ACC-smb-ds-does-not-exist"
}
`,
				ExpectError: regexp.MustCompile(`No SMB share .* was found`),
			},
		},
	})
}
