//go:build acceptance

// Package provider — acceptance tests for windows_environment_variable.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights
//     (machine-scope variables write to HKLM and need admin).
//
// The variable names below are prefixed with TF_ACC_ and removed on destroy,
// so the tests are safe to run repeatedly against a shared lab host.
package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccEnvVarPreCheck(t *testing.T) {
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

// TestAccWindowsEnvironmentVariable_MachineScope — create + read + idempotency.
func TestAccWindowsEnvironmentVariable_MachineScope(t *testing.T) {
	testAccEnvVarPreCheck(t)

	cfg := `
resource "windows_environment_variable" "test" {
  name   = "TF_ACC_JAVA_HOME"
  value  = "C:\\Program Files\\Java\\jdk-17"
  scope  = "machine"
  expand = false
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_environment_variable.test", "name", "TF_ACC_JAVA_HOME"),
					resource.TestCheckResourceAttr("windows_environment_variable.test", "value", "C:\\Program Files\\Java\\jdk-17"),
					resource.TestCheckResourceAttr("windows_environment_variable.test", "scope", "machine"),
					resource.TestCheckResourceAttr("windows_environment_variable.test", "expand", "false"),
					resource.TestCheckResourceAttr("windows_environment_variable.test", "id", "machine:TF_ACC_JAVA_HOME"),
				),
			},
			// Idempotency: replanning the same config yields no diff.
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsEnvironmentVariable_UserScope — user-scope variable (HKCU).
func TestAccWindowsEnvironmentVariable_UserScope(t *testing.T) {
	testAccEnvVarPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_environment_variable" "user" {
  name  = "TF_ACC_USER_VAR"
  value = "user_value"
  scope = "user"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_environment_variable.user", "scope", "user"),
					resource.TestCheckResourceAttr("windows_environment_variable.user", "value", "user_value"),
					resource.TestCheckResourceAttr("windows_environment_variable.user", "id", "user:TF_ACC_USER_VAR"),
				),
			},
		},
	})
}

// TestAccWindowsEnvironmentVariable_ValueUpdateInPlace — changing value only
// must update in place (value is not ForceNew).
func TestAccWindowsEnvironmentVariable_ValueUpdateInPlace(t *testing.T) {
	testAccEnvVarPreCheck(t)

	base := `
resource "windows_environment_variable" "upd" {
  name  = "TF_ACC_UPDATE_VAR"
  value = %q
  scope = "machine"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(base, "first"),
				Check: resource.TestCheckResourceAttr(
					"windows_environment_variable.upd", "value", "first"),
			},
			{
				Config: fmt.Sprintf(base, "second"),
				Check: resource.TestCheckResourceAttr(
					"windows_environment_variable.upd", "value", "second"),
			},
		},
	})
}

// TestAccWindowsEnvironmentVariable_ExpandSZ — expand=true stores REG_EXPAND_SZ
// and the unexpanded literal is preserved.
func TestAccWindowsEnvironmentVariable_ExpandSZ(t *testing.T) {
	testAccEnvVarPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_environment_variable" "expand" {
  name   = "TF_ACC_EXPAND_VAR"
  value  = "%SystemRoot%\\system32"
  scope  = "machine"
  expand = true
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_environment_variable.expand", "expand", "true"),
					resource.TestCheckResourceAttr("windows_environment_variable.expand", "value", "%SystemRoot%\\system32"),
				),
			},
		},
	})
}

// TestAccWindowsEnvironmentVariable_Import — import by composite "<scope>:<name>" ID.
func TestAccWindowsEnvironmentVariable_Import(t *testing.T) {
	testAccEnvVarPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_environment_variable" "imp" {
  name  = "TF_ACC_IMPORT_VAR"
  value = "importable"
  scope = "machine"
}
`,
			},
			{
				ResourceName:      "windows_environment_variable.imp",
				ImportState:       true,
				ImportStateId:     "machine:TF_ACC_IMPORT_VAR",
				ImportStateVerify: true,
			},
		},
	})
}
