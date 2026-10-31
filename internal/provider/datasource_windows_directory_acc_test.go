//go:build acceptance

// Package provider — acceptance tests for the windows_directory data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsDirectoryDataSource
//
// The Basic test provisions a throwaway directory via the sibling
// windows_directory resource and looks it up through the data source by path,
// referencing the fixture's path so the lookup is host-agnostic. The NotFound
// test needs no fixture: a path under a reserved directory can never exist.
package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccDirectoryDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccDirectoryDSFixtureConfig renders a fixture windows_directory resource
// plus a data source that looks it up via the fixture's computed path. The
// attribute reference gives the data source an implicit dependency, so the
// directory exists at read time. The framework destroys the fixture at the end
// of each test.
func testAccDirectoryDSFixtureConfig(path string) string {
	return fmt.Sprintf(`
resource "windows_directory" "fixture" {
  path = %[1]q
}

data "windows_directory" "lookup" {
  path = windows_directory.fixture.path
}
`, path)
}

// TestAccWindowsDirectoryDataSource_Basic creates a throwaway directory and
// looks up its observed state through the data source.
func TestAccWindowsDirectoryDataSource_Basic(t *testing.T) {
	testAccDirectoryDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDirectoryDSFixtureConfig(`C:\TF-Acc-Directory-DS\lookup`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_directory.lookup", "id"),
					resource.TestCheckResourceAttrPair(
						"data.windows_directory.lookup", "path",
						"windows_directory.fixture", "path"),
					resource.TestCheckResourceAttr("data.windows_directory.lookup", "item_count", "0"),
					resource.TestCheckResourceAttrSet("data.windows_directory.lookup", "last_write_time"),
					resource.TestCheckResourceAttr("data.windows_directory.lookup", "attributes.#", "0"),
				),
			},
		},
	})
}

// TestAccWindowsDirectoryDataSource_NotFound verifies that a missing directory
// returns an error rather than a silent empty state.
func TestAccWindowsDirectoryDataSource_NotFound(t *testing.T) {
	testAccDirectoryDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_directory" "missing" {
  path = "C:\\TF-Acc-Directory-DS\\does-not-exist"
}
`,
				ExpectError: regexp.MustCompile(`No directory .* was found`),
			},
		},
	})
}
