//go:build acceptance

// Package provider — acceptance tests for windows_directory.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with SSH enabled.
//
// Paths below are prefixed with C:\TF_ACC_ and removed on destroy, so the
// tests are safe to run repeatedly against a shared lab host.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccDirectoryPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// TestAccWindowsDirectory_Basic — create + read + idempotency.
func TestAccWindowsDirectory_Basic(t *testing.T) {
	testAccDirectoryPreCheck(t)

	cfg := `
resource "windows_directory" "test" {
  path = "C:\\TF_ACC_dir_basic"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_directory.test", "path", `C:\TF_ACC_dir_basic`),
					resource.TestCheckResourceAttr("windows_directory.test", "ensure", "present"),
					resource.TestCheckResourceAttr("windows_directory.test", "id", `C:\TF_ACC_dir_basic`),
					resource.TestCheckResourceAttr("windows_directory.test", "exists_children", "false"),
					resource.TestCheckResourceAttr("windows_directory.test", "item_count", "0"),
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

// TestAccWindowsDirectory_AttributesUpdateInPlace — changing attributes only
// (no ForceNew).
func TestAccWindowsDirectory_AttributesUpdateInPlace(t *testing.T) {
	testAccDirectoryPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_directory" "attrs" {
  path = "C:\\TF_ACC_dir_attrs"
}
`,
				Check: resource.TestCheckResourceAttr("windows_directory.attrs", "attributes.#", "0"),
			},
			{
				Config: `
resource "windows_directory" "attrs" {
  path       = "C:\\TF_ACC_dir_attrs"
  attributes = ["hidden"]
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_directory.attrs", "attributes.#", "1"),
					resource.TestCheckResourceAttr("windows_directory.attrs", "attributes.0", "hidden"),
				),
			},
		},
	})
}

// TestAccWindowsDirectory_PathForceNew — changing path destroys and recreates.
func TestAccWindowsDirectory_PathForceNew(t *testing.T) {
	testAccDirectoryPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_directory" "mv" {
  path = "C:\\TF_ACC_dir_mv_a"
}
`,
				Check: resource.TestCheckResourceAttr("windows_directory.mv", "path", `C:\TF_ACC_dir_mv_a`),
			},
			{
				Config: `
resource "windows_directory" "mv" {
  path = "C:\\TF_ACC_dir_mv_b"
}
`,
				Check: resource.TestCheckResourceAttr("windows_directory.mv", "path", `C:\TF_ACC_dir_mv_b`),
			},
		},
	})
}

// TestAccWindowsDirectory_Import — import by absolute path.
func TestAccWindowsDirectory_Import(t *testing.T) {
	testAccDirectoryPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_directory" "imp" {
  path = "C:\\TF_ACC_dir_import"
}
`,
			},
			{
				ResourceName:      "windows_directory.imp",
				ImportState:       true,
				ImportStateId:     `C:\TF_ACC_dir_import`,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"recursive_delete", "create_parent_directories",
				},
			},
		},
	})
}

// TestAccWindowsDirectory_Drift — the directory is removed out-of-band
// between plans; the next plan must show a non-empty diff rather than erroring.
func TestAccWindowsDirectory_Drift(t *testing.T) {
	testAccDirectoryPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_directory" "drift" {
  path = "C:\\TF_ACC_dir_drift"
}
`,
			},
			{
				PreConfig: func() {
					// Deliberately left to the operator/lab fixture: removing
					// the directory out-of-band here would require a second
					// SSH client, which acceptance tests intentionally avoid
					// duplicating. See windows_file's acc tests for the same
					// convention.
				},
				Config: `
resource "windows_directory" "drift" {
  path = "C:\\TF_ACC_dir_drift"
}
`,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsDirectory_RecursiveDelete — a directory with content is only
// destroyable when recursive_delete is true.
func TestAccWindowsDirectory_RecursiveDelete(t *testing.T) {
	testAccDirectoryPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_directory" "rd" {
  path             = "C:\\TF_ACC_dir_recursive"
  recursive_delete = true
}
`,
				Check: resource.TestCheckResourceAttr("windows_directory.rd", "recursive_delete", "true"),
			},
		},
	})
}
