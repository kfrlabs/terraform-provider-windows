//go:build acceptance

// Package provider — acceptance tests for windows_dsc_resource (issue #293).
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME plus a credential env (see acc_test_helper.go)
//   - A Windows target with SSH enabled and Local Administrator rights
//     (machine-scope environment variables and HKLM keys need admin).
//   - A node whose LCM uses PUSH (or Disabled) refresh mode with an Idle
//     state: the gateway never changes LCM settings and refuses Pull/busy
//     nodes with lcm_conflict (Pull/busy paths are covered by the winclient
//     unit fixtures in dsc_resource_test.go, since CI must not flip the LCM).
//
// Every test confines its writes to dedicated TF_ACC_ names. The Environment
// converge test carries destroy_properties so teardown removes the variable
// through the gateway itself.
package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccDSCResourcePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccDSCEnvironmentFixture returns a config converging one machine-scope
// environment variable through the Environment DSC resource.
func testAccDSCEnvironmentFixture(value string) string {
	return `
resource "windows_dsc_resource" "env" {
  module_name   = "PSDesiredStateConfiguration"
  resource_name = "Environment"

  properties = {
    Ensure = "Present"
    Name   = "TF_ACC_DSC_TEST"
    Value  = "` + value + `"
    Target = ["Machine"]
  }

  destroy_properties = {
    Ensure = "Absent"
    Name   = "TF_ACC_DSC_TEST"
  }
}
`
}

// TestAccWindowsDSCResource_EnvironmentConverge — Test-driven converge of a
// machine environment variable, update-in-place on value change, idempotent
// re-plan, and destroy through Ensure=Absent.
func TestAccWindowsDSCResource_EnvironmentConverge(t *testing.T) {
	testAccDSCResourcePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDSCEnvironmentFixture("one"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_dsc_resource.env", "module_name", "PSDesiredStateConfiguration"),
					resource.TestCheckResourceAttr("windows_dsc_resource.env", "resource_name", "Environment"),
					resource.TestCheckResourceAttr("windows_dsc_resource.env", "in_desired_state", "true"),
					resource.TestCheckResourceAttr("windows_dsc_resource.env", "reboot_required", "false"),
					resource.TestMatchResourceAttr("windows_dsc_resource.env", "id", regexp.MustCompile(`^PSDesiredStateConfiguration\|Environment\|[0-9a-f]{64}$`)),
					resource.TestMatchResourceAttr("windows_dsc_resource.env", "resolved_module_version", regexp.MustCompile(`^\d+\.\d+`)),
					resource.TestMatchResourceAttr("windows_dsc_resource.env", "current_state_json", regexp.MustCompile(`"Value":"one"`)),
				),
			},
			// Drift/update: changing the value re-converges in place.
			{
				Config: testAccDSCEnvironmentFixture("two"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_dsc_resource.env", "in_desired_state", "true"),
					resource.TestMatchResourceAttr("windows_dsc_resource.env", "current_state_json", regexp.MustCompile(`"Value":"two"`)),
				),
			},
			// Idempotency: replanning the same config yields no diff.
			{
				Config:   testAccDSCEnvironmentFixture("two"),
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsDSCResource_RegistryConverge — converge of an HKLM registry
// value through the Registry DSC resource (built into
// PSDesiredStateConfiguration, container-runnable).
func TestAccWindowsDSCResource_RegistryConverge(t *testing.T) {
	testAccDSCResourcePreCheck(t)

	cfg := `
resource "windows_dsc_resource" "reg" {
  module_name   = "PSDesiredStateConfiguration"
  resource_name = "Registry"

  properties = {
    Ensure    = "Present"
    Key       = "HKEY_LOCAL_MACHINE\\SOFTWARE\\TF-Acc-DSC"
    ValueName = "AccTest"
    ValueType = "String"
    ValueData = ["1"]
  }

  destroy_properties = {
    Ensure    = "Absent"
    Key       = "HKEY_LOCAL_MACHINE\\SOFTWARE\\TF-Acc-DSC"
    ValueName = "AccTest"
  }
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_dsc_resource.reg", "in_desired_state", "true"),
					resource.TestMatchResourceAttr("windows_dsc_resource.reg", "id", regexp.MustCompile(`^PSDesiredStateConfiguration\|Registry\|[0-9a-f]{64}$`)),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsDSCResource_FileConverge — converge of a file through the
// File DSC resource under the temp directory (container-runnable, no
// credential involved).
func TestAccWindowsDSCResource_FileConverge(t *testing.T) {
	testAccDSCResourcePreCheck(t)

	cfg := `
resource "windows_dsc_resource" "file" {
  module_name   = "PSDesiredStateConfiguration"
  resource_name = "File"

  properties = {
    Ensure          = "Present"
    DestinationPath = "C:\\Windows\\Temp\\tf-acc-dsc.txt"
    Contents        = "managed by terraform"
  }

  destroy_properties = {
    Ensure          = "Absent"
    DestinationPath = "C:\\Windows\\Temp\\tf-acc-dsc.txt"
  }
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_dsc_resource.file", "in_desired_state", "true"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsDSCResource_MissingModule — an unknown module fails closed
// with module_not_found before any converge is attempted.
func TestAccWindowsDSCResource_MissingModule(t *testing.T) {
	testAccDSCResourcePreCheck(t)

	cfg := `
resource "windows_dsc_resource" "missing" {
  module_name   = "NoSuchModuleTFACC"
  resource_name = "Environment"

  properties = {
    Ensure = "Present"
    Name   = "TF_ACC_DSC_MISSING"
    Value  = "x"
  }
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      cfg,
				ExpectError: regexp.MustCompile(`module_not_found`),
			},
		},
	})
}
