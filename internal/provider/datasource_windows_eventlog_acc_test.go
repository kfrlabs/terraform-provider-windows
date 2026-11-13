//go:build acceptance

// Package provider — acceptance tests for the windows_eventlog data source.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled.
//
// Logs always exist, so the basic case reads a live log without any
// fixture; the not-found case exercises a bogus name.
package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccEventLogDSPRECheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// TestAccWindowsEventLogDataSource_Basic — read the observed state of the
// Application log (always present) without managing it.
func TestAccWindowsEventLogDataSource_Basic(t *testing.T) {
	testAccEventLogDSPRECheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_eventlog" "ds" {
  name = "Application"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_eventlog.ds", "id", "Application"),
					resource.TestCheckResourceAttr("data.windows_eventlog.ds", "name", "Application"),
					resource.TestCheckResourceAttr("data.windows_eventlog.ds", "is_classic_log", "true"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "maximum_size_bytes"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "retention"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "enabled"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "log_file_path"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "log_type"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "record_count"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "file_size_bytes"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ds", "policy_override"),
				),
			},
		},
	})
}

// TestAccWindowsEventLogDataSource_ModernChannel — a "/" channel name reads
// literally.
func TestAccWindowsEventLogDataSource_ModernChannel(t *testing.T) {
	testAccEventLogDSPRECheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_eventlog" "ps" {
  name = "Microsoft-Windows-PowerShell/Operational"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_eventlog.ps", "id", "Microsoft-Windows-PowerShell/Operational"),
					resource.TestCheckResourceAttr("data.windows_eventlog.ps", "is_classic_log", "false"),
					resource.TestCheckResourceAttrSet("data.windows_eventlog.ps", "maximum_size_bytes"),
				),
			},
		},
	})
}

// TestAccWindowsEventLogDataSource_NotFound — a bogus log name is rejected
// with a not-found diagnostic.
func TestAccWindowsEventLogDataSource_NotFound(t *testing.T) {
	testAccEventLogDSPRECheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_eventlog" "missing" {
  name = "NoSuchLog-Definitely-Missing"
}
`,
				ExpectError: regexp.MustCompile(`(?i)not found`),
			},
		},
	})
}
