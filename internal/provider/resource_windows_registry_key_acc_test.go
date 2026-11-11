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
//
// The key is ordered after the values (depends_on): the key snapshots
// value_names at Create/Update time, so the values must exist first. This
// matches the documented purge guidance (key after values).
func testAccRegistryKeyFixture(purge string) string {
	return testAccRegistryKeyFixtureWithOOB(purge, true)
}

// testAccRegistryKeyFixtureWithOOB is testAccRegistryKeyFixture with the
// out-of-band value optionally removed from the configuration. Dropping the
// oob resource simulates a module input being removed: the stale live value
// is then exactly what purge_unknown_values is for. Keeping the oob
// resource alongside purge=true would make the two resources fight over the
// same name (key deletes it, value resource recreates it, refresh plan never
// empty), so the purge step must use includeOOB=false.
func testAccRegistryKeyFixtureWithOOB(purge string, includeOOB bool) string {
	oobValue := ""
	oobDep := ""
	if includeOOB {
		oobValue = `
resource "windows_registry_value" "oob" {
  hive         = "HKLM"
  path         = "` + regKeyTestPath + `"
  name         = "OOB"
  type         = "REG_SZ"
  value_string = "unmanaged"
}
`
		oobDep = `
    windows_registry_value.oob,`
	}
	return `
resource "windows_registry_value" "managed" {
  hive         = "HKLM"
  path         = "` + regKeyTestPath + `"
  name         = "Managed"
  type         = "REG_SZ"
  value_string = "kept"
}
` + oobValue + `
resource "windows_registry_key" "key" {
  hive                 = "HKLM"
  path                 = "` + regKeyTestPath + `"
  purge_unknown_values = ` + purge + `
  managed_value_names  = ["Managed"]

  depends_on = [
    windows_registry_value.managed,` + oobDep + `
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
				Config: testAccRegistryKeyFixtureWithOOB("true", false),
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
					// import records the safe defaults. unknown_value_names
					// derives from managed_value_names, so it cannot match
					// once the allow-list is ignored (import sees every
					// live value as unknown).
					"purge_unknown_values",
					"managed_value_names",
					"unknown_value_names",
					"delete_key_on_destroy",
					"recursive",
				},
			},
		},
	})
}
