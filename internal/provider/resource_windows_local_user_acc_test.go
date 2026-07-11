//go:build acceptance

// Package provider — acceptance tests for windows_local_user.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights.
//   - WINDOWS_LOCAL_USER_SUFFIX (optional): suffix appended to test user names
//     to avoid collisions on shared lab hosts; defaults to "tf-test".
//
// The password literals below are dummy complexity-satisfying values; they are
// never asserted on and never logged (ADR-LU-3). `userSuffix` and
// `testAccLocalUserPreCheck` are shared with the local_user data-source suite.
package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccLocalUserPreCheck guards the acceptance-test suite.
func testAccLocalUserPreCheck(t *testing.T) {
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

// userSuffix returns the optional test user name suffix (default: "tf-test").
func userSuffix() string {
	if s := os.Getenv("WINDOWS_LOCAL_USER_SUFFIX"); s != "" {
		return s
	}
	return "tf-test"
}

// TestAccWindowsLocalUser_Basic — create + read + idempotency.
func TestAccWindowsLocalUser_Basic(t *testing.T) {
	testAccLocalUserPreCheck(t)

	name := "usr-" + userSuffix()
	cfg := fmt.Sprintf(`
resource "windows_local_user" "test" {
  name        = %q
  password    = "P@ssw0rd-Acc-%s!"
  full_name   = "TF Acc User"
  description = "created by acceptance test"
}
`, name, name)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_local_user.test", "name", name),
					resource.TestCheckResourceAttr("windows_local_user.test", "enabled", "true"),
					resource.TestCheckResourceAttrSet("windows_local_user.test", "sid"),
					resource.TestMatchResourceAttr("windows_local_user.test", "sid", regexp.MustCompile(`^S-1-5-`)),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsLocalUser_DisabledAndFlags — enabled=false plus flag toggles
// applied in place.
func TestAccWindowsLocalUser_DisabledAndFlags(t *testing.T) {
	testAccLocalUserPreCheck(t)

	name := "usr-flags-" + userSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_local_user" "flags" {
  name                   = %q
  password               = "P@ssw0rd-Acc-%s!"
  enabled                = false
  password_never_expires = true
}
`, name, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_local_user.flags", "enabled", "false"),
					resource.TestCheckResourceAttr("windows_local_user.flags", "password_never_expires", "true"),
				),
			},
		},
	})
}

// TestAccWindowsLocalUser_RenameNoRecreate — renaming keeps the same SID
// (in-place Rename-LocalUser, not ForceNew).
func TestAccWindowsLocalUser_RenameNoRecreate(t *testing.T) {
	testAccLocalUserPreCheck(t)

	var originalSID string
	cfg := func(name string) string {
		return fmt.Sprintf(`
resource "windows_local_user" "rn" {
  name     = %q
  password = "P@ssw0rd-Acc-Rename!"
}
`, name)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("usr-rn-" + userSuffix()),
				Check: resource.TestCheckResourceAttrWith(
					"windows_local_user.rn", "sid",
					func(v string) error { originalSID = v; return nil },
				),
			},
			{
				Config: cfg("usr-rn2-" + userSuffix()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_local_user.rn", "name", "usr-rn2-"+userSuffix()),
					resource.TestCheckResourceAttrWith(
						"windows_local_user.rn", "sid",
						func(v string) error {
							if v != originalSID {
								return fmt.Errorf("SID changed on rename: %q -> %q", originalSID, v)
							}
							return nil
						},
					),
				),
			},
		},
	})
}

// TestAccWindowsLocalUser_ImportByName — import an existing user by SAM name;
// password is null after import so state verification skips it.
func TestAccWindowsLocalUser_ImportByName(t *testing.T) {
	testAccLocalUserPreCheck(t)

	name := "usr-imp-" + userSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_local_user" "imp" {
  name     = %q
  password = "P@ssw0rd-Acc-Import!"
}
`, name),
			},
			{
				ResourceName:            "windows_local_user.imp",
				ImportState:             true,
				ImportStateId:           name,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}
