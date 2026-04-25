// Package provider — acceptance-test skeletons for windows_registry_value.
//
// Requires (all must be set to activate acceptance tests):
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights
//
// Test scenarios covered (AT-1 … AT-17 from spec):
//
//	AT-1   Create + Read: REG_SZ round-trip
//	AT-2   Create + Read: REG_EXPAND_SZ with expand_environment_variables=true
//	AT-3   Create + Read: REG_DWORD (uint32 0 and max)
//	AT-4   Create + Read: REG_QWORD (uint64 0 and max)
//	AT-5   Create + Read: REG_MULTI_SZ (empty + non-empty)
//	AT-6   Create + Read: REG_BINARY (empty hex + non-empty)
//	AT-7   Create + Read: REG_NONE
//	AT-8   Default value name="" (trailing backslash in import ID)
//	AT-9   Deep recursive key (path with 5+ levels)
//	AT-10  Update content without type change (no ForceNew)
//	AT-11  Update REG_MULTI_SZ entries
//	AT-12  ForceNew on type change (REG_SZ → REG_DWORD)
//	AT-13  Import: HKLM\PATH\NAME round-trip
//	AT-14  Import: default value trailing backslash
//	AT-15  Drift detection: value deleted out-of-band → plan non-empty
//	AT-16  Idempotency: two consecutive applies produce empty plan
//	AT-17  Delete: value removed on destroy
//
// All tests skip immediately when TF_ACC is not set.
// Full resource.TestCase bodies are commented out as they require
// github.com/hashicorp/terraform-plugin-testing and a live Windows target.
package provider

import (
	"os"
	"testing"
)

// testAccRegistryValuePreCheck guards all registry-value acceptance tests.
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

// ---------------------------------------------------------------------------
// Helper: registry key prefix used in all tests to avoid polluting real hives.
// ---------------------------------------------------------------------------

// rvTestKeyBase returns the base registry path used for acceptance tests.
// All test values are created under HKCU\Software\TFTest\<suite>\.
//
//nolint:unused
func rvTestKeyBase(suite string) string {
	return `Software\TFTest\` + suite
}

// ---------------------------------------------------------------------------
// AT-1 — REG_SZ round-trip
// ---------------------------------------------------------------------------

// TestAccWindowsRegistryValue_REG_SZ verifies that a REG_SZ value is created,
// read back with the correct value, and removed on destroy.
func TestAccWindowsRegistryValue_REG_SZ(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at1"
  name         = "MySZ"
  type         = "REG_SZ"
  value_string = "hello"
}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_registry_value.test", "type", "REG_SZ"),
						resource.TestCheckResourceAttr("windows_registry_value.test", "value_string", "hello"),
						resource.TestCheckResourceAttr("windows_registry_value.test", "hive", "HKCU"),
						resource.TestMatchResourceAttr("windows_registry_value.test", "id",
							regexp.MustCompile(`^HKCU\\`)),
					),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-2 — REG_EXPAND_SZ with expand_environment_variables=true
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_REG_EXPAND_SZ(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive                        = "HKCU"
  path                        = "Software\\TFTest\\at2"
  name                        = "Expand"
  type                        = "REG_EXPAND_SZ"
  value_string                = "%SystemRoot%\\system32"
  expand_environment_variables = true
}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_registry_value.test", "type", "REG_EXPAND_SZ"),
						resource.TestCheckResourceAttr("windows_registry_value.test", "expand_environment_variables", "true"),
					),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-3 — REG_DWORD (uint32 boundaries)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_REG_DWORD(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		for _, val := range []string{"0", "4294967295"} {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at3"
  name         = "DWord"
  type         = "REG_DWORD"
  value_string = "%s"
}`, val),
						Check: resource.TestCheckResourceAttr(
							"windows_registry_value.test", "value_string", val),
					},
				},
			})
		}
	*/
}

// ---------------------------------------------------------------------------
// AT-4 — REG_QWORD (uint64 boundaries)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_REG_QWORD(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		for _, val := range []string{"0", "18446744073709551615"} {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at4"
  name         = "QWord"
  type         = "REG_QWORD"
  value_string = "%s"
}`, val),
						Check: resource.TestCheckResourceAttr(
							"windows_registry_value.test", "value_string", val),
					},
				},
			})
		}
	*/
}

// ---------------------------------------------------------------------------
// AT-5 — REG_MULTI_SZ (empty + non-empty)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_REG_MULTI_SZ(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive          = "HKCU"
  path          = "Software\\TFTest\\at5"
  name          = "Multi"
  type          = "REG_MULTI_SZ"
  value_strings = ["line1", "line2", "line3"]
}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_registry_value.test", "type", "REG_MULTI_SZ"),
						resource.TestCheckResourceAttr("windows_registry_value.test", "value_strings.#", "3"),
					),
				},
				// Empty list
				{
					Config: `
resource "windows_registry_value" "test" {
  hive          = "HKCU"
  path          = "Software\\TFTest\\at5"
  name          = "Multi"
  type          = "REG_MULTI_SZ"
  value_strings = []
}`,
					Check: resource.TestCheckResourceAttr(
						"windows_registry_value.test", "value_strings.#", "0"),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-6 — REG_BINARY (empty + non-empty hex)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_REG_BINARY(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at6"
  name         = "Bin"
  type         = "REG_BINARY"
  value_binary = "deadbeef01020304"
}`,
					Check: resource.TestCheckResourceAttr(
						"windows_registry_value.test", "value_binary", "deadbeef01020304"),
				},
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at6"
  name         = "Bin"
  type         = "REG_BINARY"
  value_binary = ""
}`,
					Check: resource.TestCheckResourceAttr(
						"windows_registry_value.test", "value_binary", ""),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-7 — REG_NONE
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_REG_NONE(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive = "HKCU"
  path = "Software\\TFTest\\at7"
  name = "None"
  type = "REG_NONE"
}`,
					Check: resource.TestCheckResourceAttr(
						"windows_registry_value.test", "type", "REG_NONE"),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-8 — Default value (name="" → trailing backslash in import ID)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_DefaultValue(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at8"
  name         = ""
  type         = "REG_SZ"
  value_string = "default-value"
}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_registry_value.test", "name", ""),
						// ID ends with trailing backslash for the Default value
						resource.TestMatchResourceAttr("windows_registry_value.test", "id",
							regexp.MustCompile(`\\)),
					),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-9 — Deep recursive key creation (5+ levels)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_DeepKey(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\A\\B\\C\\D\\E"
  name         = "Deep"
  type         = "REG_SZ"
  value_string = "deep"
}`,
					Check: resource.TestCheckResourceAttr(
						"windows_registry_value.test", "path", `Software\TFTest\A\B\C\D\E`),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-10 — Update content without type change (no ForceNew)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_UpdateContent(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at10"
  name         = "Val"
  type         = "REG_SZ"
  value_string = "v1"
}`,
					Check: resource.TestCheckResourceAttr("windows_registry_value.test", "value_string", "v1"),
				},
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at10"
  name         = "Val"
  type         = "REG_SZ"
  value_string = "v2"
}`,
					Check: resource.TestCheckResourceAttr("windows_registry_value.test", "value_string", "v2"),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-11 — Update REG_MULTI_SZ entries (add/remove items)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_UpdateMultiSZ(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive          = "HKCU"
  path          = "Software\\TFTest\\at11"
  name          = "Multi"
  type          = "REG_MULTI_SZ"
  value_strings = ["a", "b"]
}`,
					Check: resource.TestCheckResourceAttr("windows_registry_value.test", "value_strings.#", "2"),
				},
				{
					Config: `
resource "windows_registry_value" "test" {
  hive          = "HKCU"
  path          = "Software\\TFTest\\at11"
  name          = "Multi"
  type          = "REG_MULTI_SZ"
  value_strings = ["a", "b", "c", "d"]
}`,
					Check: resource.TestCheckResourceAttr("windows_registry_value.test", "value_strings.#", "4"),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-12 — ForceNew on type change (REG_SZ → REG_DWORD)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_ForceNew_TypeChange(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at12"
  name         = "Val"
  type         = "REG_SZ"
  value_string = "hello"
}`,
					Check: resource.TestCheckResourceAttr("windows_registry_value.test", "type", "REG_SZ"),
				},
				// Changing type triggers ForceNew: the old resource is destroyed and a new one is created
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at12"
  name         = "Val"
  type         = "REG_DWORD"
  value_string = "42"
}`,
					Check: resource.TestCheckResourceAttr("windows_registry_value.test", "type", "REG_DWORD"),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-13 — Import named value
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_Import(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at13"
  name         = "Val"
  type         = "REG_SZ"
  value_string = "import-me"
}`,
				},
				{
					ResourceName:      "windows_registry_value.test",
					ImportState:       true,
					ImportStateId:     `HKCU\Software\TFTest\at13\Val`,
					ImportStateVerify: true,
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-14 — Import default value (trailing backslash)
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_Import_DefaultValue(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at14"
  name         = ""
  type         = "REG_SZ"
  value_string = "default"
}`,
				},
				{
					ResourceName:      "windows_registry_value.test",
					ImportState:       true,
					ImportStateId:     `HKCU\Software\TFTest\at14\`,
					ImportStateVerify: true,
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-15 — Drift detection: value deleted out-of-band
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_DriftDetection(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		var id string

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at15"
  name         = "Drift"
  type         = "REG_SZ"
  value_string = "before-drift"
}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_registry_value.test", "type", "REG_SZ"),
						testAccExtractID("windows_registry_value.test", &id),
					),
				},
				// Out-of-band: delete the value from the registry
				// (done via a refresh-only step expecting a non-empty plan)
				{
					RefreshState:       true,
					ExpectNonEmptyPlan: true,
					// A WinRM script would remove the value between steps in a real test
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-16 — Idempotency: two consecutive applies produce empty plan
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_Idempotency(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		cfg := `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at16"
  name         = "Idem"
  type         = "REG_SZ"
  value_string = "same"
}`
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{Config: cfg},
				// Second apply must produce no changes
				{Config: cfg, PlanOnly: true, ExpectNonEmptyPlan: false},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// AT-17 — Delete: value removed on destroy
// ---------------------------------------------------------------------------

func TestAccWindowsRegistryValue_Destroy(t *testing.T) {
	testAccRegistryValuePreCheck(t)
	t.Skip("SKELETON: requires a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckRegistryValueDestroyed("HKCU", `Software\TFTest\at17`, "Val"),
			Steps: []resource.TestStep{
				{
					Config: `
resource "windows_registry_value" "test" {
  hive         = "HKCU"
  path         = "Software\\TFTest\\at17"
  name         = "Val"
  type         = "REG_SZ"
  value_string = "destroy-me"
}`,
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Helper stubs (used in commented-out acceptance test bodies)
// ---------------------------------------------------------------------------

// testAccExtractID is a test helper that extracts a resource attribute into a variable.
//
//nolint:unused
func testAccExtractID(resourceName string, target *string) func(s interface{}) error {
	return func(_ interface{}) error {
		// In a real acceptance test:
		// rs := s.(*terraform.State).RootModule().Resources[resourceName]
		// *target = rs.Primary.ID
		_ = resourceName
		return nil
	}
}

// testAccCheckRegistryValueDestroyed verifies that the registry value no longer
// exists on the Windows host after a destroy.
//
//nolint:unused
func testAccCheckRegistryValueDestroyed(hive, path, name string) func(s interface{}) error {
	return func(_ interface{}) error {
		// In a real acceptance test, connect to Windows and check absence.
		_ = hive
		_ = path
		_ = name
		return nil
	}
}
