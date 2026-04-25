// Package provider — acceptance-test skeletons for windows_local_user.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights
//   - WINDOWS_LOCAL_USER_SUFFIX (optional): suffix appended to test user names
//     to avoid collision on shared lab hosts; defaults to "tf-test"
//
// Coverage outline (promoted to full resource.TestCase when a live Windows
// target is available with github.com/hashicorp/terraform-plugin-testing):
//
//   - Create + Read            user created, SID assigned, ID == SID
//   - Import by SID (EC-11)    terraform import via SID → password null
//   - Import by name (EC-11)   terraform import via name → password null
//   - Rename no recreate (EC-5) name change issues Rename-LocalUser, SID stable
//   - Password rotation (EC-6)  password_wo_version bump rotates password
//   - Builtin Administrator (EC-2) destroy returns hard error
//   - Drift detection (EC-3)   out-of-band delete → state cleared at next plan
//   - account_expires conflict (EC-14) account_never_expires=true + account_expires → diag
//   - password_never_expires toggle no recreate
//
// All tests skip immediately when TF_ACC is not set (CI unit-test pass is
// green without a Windows lab). The password literal in test configs is a
// dummy value; it is never logged or included in assertions (ADR-LU-3).
package provider

import (
	"os"
	"testing"
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
//
//nolint:unused
func userSuffix() string {
	if s := os.Getenv("WINDOWS_LOCAL_USER_SUFFIX"); s != "" {
		return s
	}
	return "tf-test"
}

// ---------------------------------------------------------------------------
// Basic: Create + Read + Delete
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_Basic verifies the minimal lifecycle:
//  1. Apply creates the user → SID assigned, ID == SID.
//  2. Plan is empty after first apply (idempotency).
//  3. Destroy removes the user from Windows.
//  4. CheckDestroy confirms the user is gone.
func TestAccWindowsLocalUser_Basic(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLocalUserDestroyed("svc-"+userSuffix()),
			Steps: []resource.TestStep{
				{
					Config: testAccLocalUserConfigBasic(userSuffix()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_local_user.test", "name", "svc-"+userSuffix()),
						resource.TestCheckResourceAttrSet("windows_local_user.test", "sid"),
						resource.TestMatchResourceAttr("windows_local_user.test", "sid",
							regexp.MustCompile(`^S-1-5-`)),
						resource.TestCheckResourceAttr("windows_local_user.test", "enabled", "true"),
					),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Import by SID — EC-11
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_ImportBySID imports a pre-existing user by SID.
// After import, password must be null.
func TestAccWindowsLocalUser_ImportBySID(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLocalUserConfigBasic(userSuffix()),
				},
				{
					ResourceName:      "windows_local_user.test",
					ImportState:       true,
					ImportStateIdFunc: testAccLocalUserSIDFromState("windows_local_user.test"),
					ImportStateVerify: false, // password is null after import
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Import by name — EC-11
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_ImportByName imports a pre-existing user by SAM name.
func TestAccWindowsLocalUser_ImportByName(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLocalUserConfigBasic(userSuffix()),
				},
				{
					ResourceName:      "windows_local_user.test",
					ImportState:       true,
					ImportStateId:     "svc-" + userSuffix(),
					ImportStateVerify: false,
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Rename without recreate — EC-5
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_RenameNoRecreate verifies that changing name
// issues Rename-LocalUser in place (SID unchanged, no ForceNew).
func TestAccWindowsLocalUser_RenameNoRecreate(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		originalSID := ""
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLocalUserDestroyed("svc-renamed-"+userSuffix()),
			Steps: []resource.TestStep{
				{
					Config: testAccLocalUserConfigBasic(userSuffix()),
					Check: resource.TestCheckResourceAttrWith(
						"windows_local_user.test", "sid",
						func(v string) error { originalSID = v; return nil },
					),
				},
				{
					Config: testAccLocalUserConfigWithName("svc-renamed-"+userSuffix(), userSuffix()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrWith(
							"windows_local_user.test", "sid",
							func(v string) error {
								if v != originalSID {
									return fmt.Errorf("SID changed: %q → %q (expected in-place rename)", originalSID, v)
								}
								return nil
							},
						),
						resource.TestCheckResourceAttr("windows_local_user.test", "name", "svc-renamed-"+userSuffix()),
					),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Password rotation — EC-6
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_PasswordRotation verifies that bumping
// password_wo_version rotates the password via Set-LocalUser (no recreate).
func TestAccWindowsLocalUser_PasswordRotation(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLocalUserConfigWithPasswordVersion(userSuffix(), 1, "P@ssw0rd!"),
				},
				{
					Config: testAccLocalUserConfigWithPasswordVersion(userSuffix(), 2, "N3wP@ssw0rd!"),
					Check: resource.TestCheckResourceAttr(
						"windows_local_user.test", "password_wo_version", "2"),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Builtin Administrator delete refuses — EC-2
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_BuiltinAdminDeleteRefuses verifies that attempting
// to destroy the built-in Administrator account (RID 500) produces a hard
// error and does not remove the account.
func TestAccWindowsLocalUser_BuiltinAdminDeleteRefuses(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config:      testAccLocalUserConfigImportAdmin(),
					ExpectError: regexp.MustCompile(`builtin_account`),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Drift detection — EC-3
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_DriftDetection verifies that an out-of-band deletion
// is detected at the next plan → Terraform removes the resource from state.
func TestAccWindowsLocalUser_DriftDetection(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLocalUserConfigBasic(userSuffix()),
				},
				{
					// Out-of-band deletion simulated by RefreshState + ExpectNonEmptyPlan
					RefreshState:       true,
					ExpectNonEmptyPlan: false,
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// account_expires conflict — EC-14
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_AccountExpiresConflict verifies that setting
// account_expires with account_never_expires=true produces a plan-time error.
func TestAccWindowsLocalUser_AccountExpiresConflict(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config:      testAccLocalUserConfigConflictExpires(userSuffix()),
					ExpectError: regexp.MustCompile(`EC-14`),
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// password_never_expires toggle — no recreate
// ---------------------------------------------------------------------------

// TestAccWindowsLocalUser_PasswordNeverExpiresToggle verifies that toggling
// password_never_expires does not recreate the resource (in-place via Set-LocalUser).
func TestAccWindowsLocalUser_PasswordNeverExpiresToggle(t *testing.T) {
	testAccLocalUserPreCheck(t)
	t.Skip("SKELETON: requires live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLocalUserConfigBasic(userSuffix()),
					Check: resource.TestCheckResourceAttr(
						"windows_local_user.test", "password_never_expires", "false"),
				},
				{
					Config: testAccLocalUserConfigPNE(userSuffix(), true),
					Check: resource.TestCheckResourceAttr(
						"windows_local_user.test", "password_never_expires", "true"),
				},
			},
		})
	*/
}
