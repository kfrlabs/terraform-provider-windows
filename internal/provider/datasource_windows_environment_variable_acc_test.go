// Package provider — acceptance-test skeletons for windows_environment_variable data source.
//
// Requires (all must be set to activate acceptance tests):
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled
//
// Test scenarios covered:
//
//	DS-AT-1  Lookup machine-scope variable by name
//	DS-AT-2  Lookup user-scope variable by name
//	DS-AT-3  expand=true reflected from REG_EXPAND_SZ registry value
//	DS-AT-4  Missing variable returns a Terraform error
//
// All tests skip immediately when TF_ACC is not set.
package provider

import (
	"os"
	"testing"
)

// testAccEnvVarDSPreCheck guards all environment-variable data source acceptance tests.
func testAccEnvVarDSPreCheck(t *testing.T) {
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

// ---------------------------------------------------------------------------
// DS-AT-1 — Lookup machine-scope variable by name
// ---------------------------------------------------------------------------

// TestAccWindowsEnvironmentVariableDataSource_Machine verifies that an existing
// machine-scope environment variable can be read by the data source and that
// value/expand attributes match the stored values.
func TestAccWindowsEnvironmentVariableDataSource_Machine(t *testing.T) {
	testAccEnvVarDSPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						// Pre-condition: create the variable via the resource first.
						Config: `
		resource "windows_environment_variable" "seed" {
		  name  = "TF_DS_TEST_MACHINE"
		  value = "ds_machine_value"
		  scope = "machine"
		}

		data "windows_environment_variable" "read" {
		  name  = windows_environment_variable.seed.name
		  scope = "machine"
		  depends_on = [windows_environment_variable.seed]
		}`,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("data.windows_environment_variable.read", "value", "ds_machine_value"),
							resource.TestCheckResourceAttr("data.windows_environment_variable.read", "scope", "machine"),
							resource.TestCheckResourceAttr("data.windows_environment_variable.read", "expand", "false"),
							resource.TestMatchResourceAttr("data.windows_environment_variable.read", "id",
								regexp.MustCompile(`^machine:TF_DS_TEST_MACHINE)),
						),
					},
				},
			})
	*/
}

// ---------------------------------------------------------------------------
// DS-AT-2 — Lookup user-scope variable by name
// ---------------------------------------------------------------------------

func TestAccWindowsEnvironmentVariableDataSource_User(t *testing.T) {
	testAccEnvVarDSPreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: `
		resource "windows_environment_variable" "seed" {
		  name  = "TF_DS_TEST_USER"
		  value = "ds_user_value"
		  scope = "user"
		}

		data "windows_environment_variable" "read" {
		  name  = windows_environment_variable.seed.name
		  scope = "user"
		  depends_on = [windows_environment_variable.seed]
		}`,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("data.windows_environment_variable.read", "value", "ds_user_value"),
							resource.TestCheckResourceAttr("data.windows_environment_variable.read", "scope", "user"),
							resource.TestMatchResourceAttr("data.windows_environment_variable.read", "id",
								regexp.MustCompile(`^user:TF_DS_TEST_USER)),
						),
					},
				},
			})
	*/
}

// ---------------------------------------------------------------------------
// DS-AT-3 — expand=true reflected from REG_EXPAND_SZ registry value
// ---------------------------------------------------------------------------

func TestAccWindowsEnvironmentVariableDataSource_ExpandTrue(t *testing.T) {
	testAccEnvVarDSPreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: `
		resource "windows_environment_variable" "seed" {
		  name   = "TF_DS_TEST_EXPAND"
		  value  = "%SystemRoot%\\system32"
		  scope  = "machine"
		  expand = true
		}

		data "windows_environment_variable" "read" {
		  name  = windows_environment_variable.seed.name
		  scope = "machine"
		  depends_on = [windows_environment_variable.seed]
		}`,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("data.windows_environment_variable.read", "expand", "true"),
							resource.TestCheckResourceAttr("data.windows_environment_variable.read", "value", "%SystemRoot%\\system32"),
						),
					},
				},
			})
	*/
}

// ---------------------------------------------------------------------------
// DS-AT-4 — Missing variable returns a Terraform error
// ---------------------------------------------------------------------------

// TestAccWindowsEnvironmentVariableDataSource_Missing verifies that looking up
// a non-existent environment variable produces a Terraform error (not a silent
// empty result).
func TestAccWindowsEnvironmentVariableDataSource_Missing(t *testing.T) {
	testAccEnvVarDSPreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: `
		data "windows_environment_variable" "missing" {
		  name  = "TF_DS_TEST_DEFINITELY_DOES_NOT_EXIST_XYZ123"
		  scope = "machine"
		}`,
						ExpectError: regexp.MustCompile(`not found`),
					},
				},
			})
	*/
}
