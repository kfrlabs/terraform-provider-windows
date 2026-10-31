//go:build acceptance

// Package provider — acceptance tests for the windows_file data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsFileDataSource
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

func testAccFileDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccFileDSFixtureConfig renders a fixture windows_file resource plus a
// data source that looks it up via the fixture's computed path. The attribute
// reference gives the data source an implicit dependency, so the file exists
// at read time. The framework destroys the fixture at the end of each test.
func testAccFileDSFixtureConfig(path string) string {
	return fmt.Sprintf(`
resource "windows_file" "fixture" {
  path    = %[1]q
  content = "file-ds"
}

data "windows_file" "lookup" {
  path = windows_file.fixture.path
}
`, path)
}

// TestAccWindowsFileDataSource_Basic creates a throwaway file and looks up
// its observed metadata through the data source.
func TestAccWindowsFileDataSource_Basic(t *testing.T) {
	testAccFileDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFileDSFixtureConfig(`C:\TF-Acc-File-DS\lookup.conf`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_file.lookup", "id"),
					resource.TestCheckResourceAttrPair(
						"data.windows_file.lookup", "path",
						"windows_file.fixture", "path"),
					resource.TestCheckResourceAttrPair(
						"data.windows_file.lookup", "content_sha256",
						"windows_file.fixture", "content_sha256"),
					resource.TestCheckResourceAttrPair(
						"data.windows_file.lookup", "size_bytes",
						"windows_file.fixture", "size_bytes"),
					resource.TestCheckResourceAttrSet("data.windows_file.lookup", "last_write_time"),
				),
			},
		},
	})
}

// TestAccWindowsFileDataSource_NotFound verifies that a missing file returns
// an error rather than a silent empty state.
func TestAccWindowsFileDataSource_NotFound(t *testing.T) {
	testAccFileDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_file" "missing" {
  path = "C:\\TF-Acc-File-DS\\does-not-exist.conf"
}
`,
				ExpectError: regexp.MustCompile(`No file .* was found`),
			},
		},
	})
}
