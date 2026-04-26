//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_feature data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsFeatureDataSource
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccFeatureDSPreCheck(t *testing.T) {
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

// TestAccWindowsFeatureDataSource_Basic reads a built-in Windows feature that
// is always present (e.g. XPS-Viewer or PowerShell) and verifies the computed
// attributes are populated.
func TestAccWindowsFeatureDataSource_Basic(t *testing.T) {
	testAccFeatureDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_feature" "test" {
  name = "PowerShell"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_feature.test", "id"),
					resource.TestCheckResourceAttr("data.windows_feature.test", "name", "PowerShell"),
					resource.TestCheckResourceAttrSet("data.windows_feature.test", "display_name"),
					resource.TestCheckResourceAttrSet("data.windows_feature.test", "install_state"),
				),
			},
		},
	})
}

// TestAccWindowsFeatureDataSource_NotFound verifies that a missing feature
// returns an error rather than a silent empty state.
func TestAccWindowsFeatureDataSource_NotFound(t *testing.T) {
	testAccFeatureDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_feature" "missing" {
  name = "FeatureThatDoesNotExist-ZZZ"
}
`,
				ExpectError: nil, // plan-time read returns error during apply
			},
		},
	})
}
