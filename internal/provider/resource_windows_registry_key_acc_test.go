//go:build acceptance

// Package provider — acceptance tests for windows_registry_key.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME plus a credential env (see acc_test_helper.go)
//   - A Windows target with SSH enabled and Local Administrator rights
//     (keys are written under HKLM\SOFTWARE\TF-Acc-Test-Registry*).
//
// Every test confines its writes to dedicated test keys. The key tests reuse
// windows_registry_value resources for managed values: the purge tests prove
// the key deletes only unmanaged names while managed values survive.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// regKeyTestPath is the dedicated acceptance-test key for windows_registry_key.
const regKeyTestPath = `SOFTWARE\\TF-Acc-Test-Registry-Key`

func testAccRegistryKeyPreCheck(t *testing.T) {
	t.Helper()
	testAccRegistryValuePreCheck(t)
}

// testAccRegistryKeyFixture returns a config with one windows_registry_key
// plus a managed and an out-of-band value on the same key. The oob value is
// deliberately NOT listed in managed_value_names.
func testAccRegistryKeyFixture(purge string) string {
	return `
resource "windows_registry_value" "managed" {
  hive         = "HKLM"
  path         = "` + regKeyTestPath + `"
  name         = "Managed"
  type         = "REG_SZ"
  value_string = "kept"
}

resource "windows_registry_value" "oob" {
  hive         = "HKLM"
  path         = "` + regKeyTestPath + `"
  name         = "OOB"
  type         = "REG_SZ"
  value_string = "unmanaged"
}

resource "windows_registry_key" "key" {
  hive                 = "HKLM"
  path                 = "` + regKeyTestPath + `"
  purge_unknown_values = ` + purge + `
  managed_value_names  = ["Managed"]

  depends_on = [
    windows_registry_value.managed,
    windows_registry_value.oob,
  ]
}
`
}

// TestAccWindowsRegistryKey_PurgeDisabledLeavesUnknown — with purge off the
// key reports the unmanaged value in unknown_value_names and leaves it alone.
func TestAccWindowsRegistryKey_PurgeDisabledLeavesUnknown(t *testing.T) {
	testAccRegistryKeyPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRegistryKeyFixture("false"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_registry_key.key", "id", `HKLM\SOFTWARE\TF-Acc-Test-Registry-Key`),
					resource.TestCheckResourceAttr("windows_registry_key.key", "value_names.#", "2"),
					resource.TestCheckResourceAttr("windows_registry_key.key", "unknown_value_names.#", "1"),
					resource.TestCheckResourceAttr("windows_registry_key.key", "unknown_value_names.0", "OOB"),
					resource.TestCheckResourceAttr("windows_registry_value.oob", "value_string", "unmanaged"),
				),
			},
		},
	})
}

// TestAccWindowsRegistryKey_PurgeRemovesOnlyUnknown — flipping purge on
// deletes the unmanaged value while the managed value survives with its data.
func TestAccWindowsRegistryKey_PurgeRemovesOnlyUnknown(t *testing.T) {
	testAccRegistryKeyPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRegistryKeyFixture("false"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_registry_key.key", "unknown_value_names.#", "1"),
					resource.TestCheckResourceAttr("windows_registry_value.oob", "value_string", "unmanaged"),
				),
			},
			{
				Config: testAccRegistryKeyFixture("true"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_registry_key.key", "value_names.#", "1"),
					resource.TestCheckResourceAttr("windows_registry_key.key", "value_names.0", "Managed"),
					resource.TestCheckResourceAttr("windows_registry_key.key", "unknown_value_names.#", "0"),
					resource.TestCheckResourceAttr("windows_registry_value.managed", "value_string", "kept"),
				),
			},
		},
	})
}

// TestAccWindowsRegistryKey_Import — round-trips a key through import.
func TestAccWindowsRegistryKey_Import(t *testing.T) {
	testAccRegistryKeyPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccRegistryKeyFixture("false"),
			},
			{
				ResourceName:      "windows_registry_key.key",
				ImportState:       true,
				ImportStateId:     `HKLM\SOFTWARE\TF-Acc-Test-Registry-Key`,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					// Purge-related intent is not observable on the host:
					// import records the safe defaults.
					"purge_unknown_values",
					"managed_value_names",
					"delete_key_on_destroy",
					"recursive",
				},
			},
		},
	})
}
