//go:build acceptance

// Package provider — acceptance tests for windows_smb_share.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled and the LanmanServer service running.
//
// The share path is provisioned through a windows_directory fixture so the
// tests never assume a pre-existing directory, and everything the tests write
// lands under C:\TF_ACC_smb_* so it is easy to spot leftovers. Principals
// are limited to Everyone and BUILTIN\Administrators, which resolve on every
// host without a domain.
package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccSmbSharePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccSmbShareFixture renders a windows_directory fixture plus a
// windows_smb_share on top of it. The share references the fixture's path,
// which gives Terraform the implicit dependency so the directory exists at
// share-creation time. Share name and fixture path interpolate through %q so
// Windows backslashes arrive HCL-escaped (a raw "C:\..." would be an invalid
// escape sequence for \T), matching the sibling data source fixture.
func testAccSmbShareFixture(shareName, dir, extra string) string {
	return fmt.Sprintf(`
resource "windows_directory" "fixture" {
  path = %[2]q
}

resource "windows_smb_share" "test" {
  name = %[1]q
  path = windows_directory.fixture.path
%[3]s
}
`, shareName, dir, extra)
}

// TestAccWindowsSmbShare_Basic — create + read + idempotency.
func TestAccWindowsSmbShare_Basic(t *testing.T) {
	testAccSmbSharePreCheck(t)

	cfg := testAccSmbShareFixture("TF-ACC-smb-basic", `C:\TF_ACC_smb_basic`, `
  description             = "acc basic"
  folder_enumeration_mode = "AccessBased"
  caching_mode            = "None"
  encrypt_data            = true
  full_access             = ["BUILTIN\\Administrators"]
  read_access             = ["Everyone"]
`)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_smb_share.test", "name", "TF-ACC-smb-basic"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "id", "TF-ACC-smb-basic"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "path", `C:\TF_ACC_smb_basic`),
					resource.TestCheckResourceAttr("windows_smb_share.test", "description", "acc basic"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "folder_enumeration_mode", "AccessBased"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "caching_mode", "None"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "concurrent_user_limit", "0"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "encrypt_data", "true"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "full_access.#", "1"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "read_access.#", "1"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "special", "false"),
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

// TestAccWindowsSmbShare_UpdateInPlace — mutable properties and the access
// list converge without replacing the share.
func TestAccWindowsSmbShare_UpdateInPlace(t *testing.T) {
	testAccSmbSharePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSmbShareFixture("TF-ACC-smb-update", `C:\TF_ACC_smb_update`, `
  description = "before"
  full_access = ["BUILTIN\\Administrators"]
  read_access = ["Everyone"]
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_smb_share.test", "description", "before"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "read_access.#", "1"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "change_access.#", "0"),
				),
			},
			{
				// Access diff: Everyone moves from read to change, and the
				// description + caching mode change in the same apply.
				Config: testAccSmbShareFixture("TF-ACC-smb-update", `C:\TF_ACC_smb_update`, `
  description  = "after"
  caching_mode = "Documents"
  full_access  = ["BUILTIN\\Administrators"]
  change_access = ["Everyone"]
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_smb_share.test", "description", "after"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "caching_mode", "Documents"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "read_access.#", "0"),
					resource.TestCheckResourceAttr("windows_smb_share.test", "change_access.#", "1"),
				),
			},
		},
	})
}

// TestAccWindowsSmbShare_Import — import by share name.
func TestAccWindowsSmbShare_Import(t *testing.T) {
	testAccSmbSharePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSmbShareFixture("TF-ACC-smb-import", `C:\TF_ACC_smb_import`, `
  full_access = ["BUILTIN\\Administrators"]
`),
			},
			{
				ResourceName:      "windows_smb_share.test",
				ImportState:       true,
				ImportStateId:     "TF-ACC-smb-import",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					// Import starts unmanaged; the access sets verify on the
					// next refresh once declared.
					"full_access", "change_access", "read_access", "no_access",
				},
			},
		},
	})
}

// accSmbShareClient builds a direct winclient for out-of-band manipulation,
// which is the only way to simulate drift (share removed behind Terraform's
// back). ResolveFromEnv is intentional here: the public-key CI leg clears
// WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH instead.
func accSmbShareClient(t *testing.T) *winclient.SmbShareClientImpl {
	t.Helper()
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	return winclient.NewSmbShareClient(c)
}

// TestAccWindowsSmbShare_Drift — the share is removed out-of-band between
// plans; the next plan must show a non-empty diff (re-creation) rather than
// an error.
func TestAccWindowsSmbShare_Drift(t *testing.T) {
	testAccSmbSharePreCheck(t)

	shareName := "TF-ACC-smb-drift"
	cfg := testAccSmbShareFixture(shareName, `C:\TF_ACC_smb_drift`, ``)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
			},
			{
				// Share removed behind Terraform's back.
				PreConfig: func() {
					c := accSmbShareClient(t)
					if err := c.Delete(context.Background(), shareName); err != nil {
						t.Fatalf("out-of-band delete: %v", err)
					}
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Re-apply converges back to the managed share.
				Config: cfg,
			},
		},
	})
}

// TestAccWindowsSmbShare_DuplicateAcrossSetsFails ensures the plan-time
// duplicate rule fires against a live host too (unit tests pin the message;
// this pins the plan path end to end).
func TestAccWindowsSmbShare_DuplicateAcrossSetsFails(t *testing.T) {
	testAccSmbSharePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSmbShareFixture("TF-ACC-smb-dup", `C:\TF_ACC_smb_dup`, `
  full_access = ["Everyone"]
  read_access = ["Everyone"]
`),
				ExpectError: regexp.MustCompile(`at most one access set`),
			},
		},
	})
}
