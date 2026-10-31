//go:build acceptance

// Package provider — acceptance tests for the windows_file_acl data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsFileACLDataSource
//
// The Basic test provisions a throwaway file via the sibling windows_file
// resource and looks it up through the data source by path, referencing the
// fixture's path so the lookup is host-agnostic. The NotFound test needs no
// fixture: a path under a reserved directory can never exist.
package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccFileACLDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccFileACLDSFixtureConfig renders a fixture windows_file resource plus a
// data source that looks it up via the fixture's computed path. The attribute
// reference gives the data source an implicit dependency, so the file exists
// at read time. The framework destroys the fixture at the end of each test.
func testAccFileACLDSFixtureConfig(path string) string {
	return fmt.Sprintf(`
resource "windows_file" "fixture" {
  path    = %[1]q
  content = "file-acl-ds"
}

data "windows_file_acl" "lookup" {
  path = windows_file.fixture.path
}
`, path)
}

// TestAccWindowsFileACLDataSource_Basic creates a throwaway file and looks up
// its security descriptor through the data source.
func TestAccWindowsFileACLDataSource_Basic(t *testing.T) {
	testAccFileACLDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFileACLDSFixtureConfig(`C:\TF-Acc-FileACL-DS\lookup.conf`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_file_acl.lookup", "id"),
					resource.TestCheckResourceAttrPair(
						"data.windows_file_acl.lookup", "path",
						"windows_file.fixture", "path"),
					resource.TestCheckResourceAttr("data.windows_file_acl.lookup", "target_type", "file"),
					resource.TestCheckResourceAttrSet("data.windows_file_acl.lookup", "owner_sid"),
					resource.TestCheckResourceAttrSet("data.windows_file_acl.lookup", "sddl"),
					resource.TestCheckResourceAttrSet("data.windows_file_acl.lookup", "effective_access_rules.#"),
				),
			},
		},
	})
}

// TestAccWindowsFileACLDataSource_NotFound verifies that a missing target
// returns an error rather than a silent empty state.
func TestAccWindowsFileACLDataSource_NotFound(t *testing.T) {
	testAccFileACLDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_file_acl" "missing" {
  path = "C:\\TF-Acc-FileACL-DS\\does-not-exist.conf"
}
`,
				ExpectError: regexp.MustCompile(`No file or directory .* was found`),
			},
		},
	})
}
