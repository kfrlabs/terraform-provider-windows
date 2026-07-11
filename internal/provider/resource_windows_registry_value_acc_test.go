//go:build acceptance

// Package provider — acceptance tests for windows_registry_value.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights
//     (values are written under HKLM\SOFTWARE\TF-Acc-Test-Registry).
//
// Every test confines its writes to the dedicated test key so they are safe
// to run repeatedly and are removed on destroy.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const regTestPath = `SOFTWARE\\TF-Acc-Test-Registry`

func testAccRegistryValuePreCheck(t *testing.T) {
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

// TestAccWindowsRegistryValue_StringCreateUpdate — REG_SZ create, idempotency,
// and in-place value update (value_string is not ForceNew).
func TestAccWindowsRegistryValue_StringCreateUpdate(t *testing.T) {
	testAccRegistryValuePreCheck(t)

	cfg := func(val string) string {
		return `
resource "windows_registry_value" "sz" {
  hive         = "HKLM"
  path         = "` + regTestPath + `"
  name         = "TestString"
  type         = "REG_SZ"
  value_string = "` + val + `"
}
`
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("hello"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_registry_value.sz", "type", "REG_SZ"),
					resource.TestCheckResourceAttr("windows_registry_value.sz", "value_string", "hello"),
					resource.TestCheckResourceAttr("windows_registry_value.sz", "id", `HKLM\SOFTWARE\TF-Acc-Test-Registry\TestString`),
				),
			},
			{
				Config:   cfg("hello"),
				PlanOnly: true,
			},
			{
				// In-place update of the value.
				Config: cfg("world"),
				Check: resource.TestCheckResourceAttr(
					"windows_registry_value.sz", "value_string", "world"),
			},
		},
	})
}

// TestAccWindowsRegistryValue_Dword — REG_DWORD stored as decimal string.
func TestAccWindowsRegistryValue_Dword(t *testing.T) {
	testAccRegistryValuePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_registry_value" "dword" {
  hive         = "HKLM"
  path         = "` + regTestPath + `"
  name         = "TestDword"
  type         = "REG_DWORD"
  value_string = "4294967295"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_registry_value.dword", "type", "REG_DWORD"),
					resource.TestCheckResourceAttr("windows_registry_value.dword", "value_string", "4294967295"),
				),
			},
		},
	})
}

// TestAccWindowsRegistryValue_MultiString — REG_MULTI_SZ list ordering preserved.
func TestAccWindowsRegistryValue_MultiString(t *testing.T) {
	testAccRegistryValuePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_registry_value" "multi" {
  hive          = "HKLM"
  path          = "` + regTestPath + `"
  name          = "TestMulti"
  type          = "REG_MULTI_SZ"
  value_strings = ["alpha", "beta", "gamma"]
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_registry_value.multi", "value_strings.#", "3"),
					resource.TestCheckResourceAttr("windows_registry_value.multi", "value_strings.0", "alpha"),
					resource.TestCheckResourceAttr("windows_registry_value.multi", "value_strings.2", "gamma"),
				),
			},
		},
	})
}

// TestAccWindowsRegistryValue_Binary — REG_BINARY as lowercase hex.
func TestAccWindowsRegistryValue_Binary(t *testing.T) {
	testAccRegistryValuePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_registry_value" "bin" {
  hive         = "HKLM"
  path         = "` + regTestPath + `"
  name         = "TestBinary"
  type         = "REG_BINARY"
  value_binary = "deadbeef"
}
`,
				Check: resource.TestCheckResourceAttr(
					"windows_registry_value.bin", "value_binary", "deadbeef"),
			},
		},
	})
}

// TestAccWindowsRegistryValue_ExpandSZ — REG_EXPAND_SZ with expansion on read.
func TestAccWindowsRegistryValue_ExpandSZ(t *testing.T) {
	testAccRegistryValuePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_registry_value" "expand" {
  hive         = "HKLM"
  path         = "` + regTestPath + `"
  name         = "TestExpand"
  type         = "REG_EXPAND_SZ"
  value_string = "%SystemRoot%\\notepad.exe"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_registry_value.expand", "type", "REG_EXPAND_SZ"),
					resource.TestCheckResourceAttr("windows_registry_value.expand", "value_string", "%SystemRoot%\\notepad.exe"),
				),
			},
		},
	})
}

// TestAccWindowsRegistryValue_Import — import by composite "HIVE\PATH\NAME" ID.
func TestAccWindowsRegistryValue_Import(t *testing.T) {
	testAccRegistryValuePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_registry_value" "imp" {
  hive         = "HKLM"
  path         = "` + regTestPath + `"
  name         = "TestImport"
  type         = "REG_SZ"
  value_string = "importable"
}
`,
			},
			{
				ResourceName:      "windows_registry_value.imp",
				ImportState:       true,
				ImportStateId:     `HKLM\SOFTWARE\TF-Acc-Test-Registry\TestImport`,
				ImportStateVerify: true,
			},
		},
	})
}
