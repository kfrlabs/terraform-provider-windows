//go:build acceptance

// Package provider — acceptance-test skeleton for the windows_service data source.
//
// Requires: TF_ACC=1, WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD.
// Run with: go test -tags acceptance ./internal/provider/ -run TestAccWindowsServiceDataSource
package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccServiceDSPreCheck(t *testing.T) {
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

// TestAccWindowsServiceDataSource_Basic reads the SSH service which must
// be running since the provider uses SSH to connect.
func TestAccWindowsServiceDataSource_Basic(t *testing.T) {
	testAccServiceDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// sshd, not "SSH": the SCM service name for OpenSSH Server is
				// sshd ("OpenSSH SSH Server" is only its display name). And it
				// is the one service guaranteed to be running here, since the
				// provider reached this host through it.
				Config: `
data "windows_service" "sshd" {
  name = "sshd"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_service.sshd", "id"),
					resource.TestCheckResourceAttr("data.windows_service.sshd", "name", "sshd"),
					resource.TestCheckResourceAttrSet("data.windows_service.sshd", "display_name"),
					resource.TestCheckResourceAttrSet("data.windows_service.sshd", "start_type"),
					resource.TestCheckResourceAttr("data.windows_service.sshd", "current_status", "Running"),
				),
			},
		},
	})
}

// TestAccWindowsServiceDataSource_NotFound verifies missing service produces error.
func TestAccWindowsServiceDataSource_NotFound(t *testing.T) {
	testAccServiceDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_service" "missing" {
  name = "ServiceThatDoesNotExistZZZ"
}
`,
				ExpectError: regexp.MustCompile(`No Windows service named .* was found`),
			},
		},
	})
}
