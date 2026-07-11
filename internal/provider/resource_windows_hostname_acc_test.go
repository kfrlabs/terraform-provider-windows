//go:build acceptance

// Package provider — acceptance tests for windows_hostname.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A workgroup (NOT domain-joined) Windows target with WinRM and Local
//     Administrator rights.
//
// SAFETY: applying windows_hostname renames the machine (Rename-Computer) and
// requires a reboot to take effect. That is destructive on a shared/lab host,
// so the create/update/drift lifecycle scenarios below remain SKELETONS gated
// on WINDOWS_HOSTNAME_ALLOW_RENAME=1 and are left unimplemented. Only the
// plan-time schema-validation tests are executed here — they never mutate the
// host because the error is raised before any WinRM call.
package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccHostnamePreCheck centralises the env-var guard for the hostname suite.
func testAccHostnamePreCheck(t *testing.T) {
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

// hostnameConfig renders a minimal windows_hostname resource with the given name.
func hostnameConfig(name string) string {
	return `
resource "windows_hostname" "this" {
  name = "` + name + `"
}
`
}

// --- Non-destructive plan-time validation (EC-1) -----------------------------
// These assert that invalid NetBIOS names are rejected before any rename is
// attempted, so they are safe to run against any host.

// TestAccWindowsHostname_InvalidTooLong rejects names longer than 15 chars.
func TestAccWindowsHostname_InvalidTooLong(t *testing.T) {
	testAccHostnamePreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      hostnameConfig("THIS-NAME-IS-WAY-TOO-LONG"),
				ExpectError: regexp.MustCompile(`(?i)length|15`),
				PlanOnly:    true,
			},
		},
	})
}

// TestAccWindowsHostname_InvalidNumeric rejects purely numeric names.
func TestAccWindowsHostname_InvalidNumeric(t *testing.T) {
	testAccHostnamePreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      hostnameConfig("123456"),
				ExpectError: regexp.MustCompile(`(?i)numeric|NetBIOS`),
				PlanOnly:    true,
			},
		},
	})
}

// TestAccWindowsHostname_InvalidLeadingHyphen rejects names starting with "-".
func TestAccWindowsHostname_InvalidLeadingHyphen(t *testing.T) {
	testAccHostnamePreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      hostnameConfig("-badname"),
				ExpectError: regexp.MustCompile(`(?i)NetBIOS|hyphen|match`),
				PlanOnly:    true,
			},
		},
	})
}

// --- Destructive lifecycle scenarios (SKELETON) ------------------------------
// Implementing these renames the machine and needs a reboot; they are kept as
// skeletons and only run when an operator explicitly opts in with a disposable
// host via WINDOWS_HOSTNAME_ALLOW_RENAME=1.

func skipUnlessRenameAllowed(t *testing.T) {
	t.Helper()
	if os.Getenv("WINDOWS_HOSTNAME_ALLOW_RENAME") != "1" {
		t.Skip("WINDOWS_HOSTNAME_ALLOW_RENAME != 1 — refusing to rename the host")
	}
}

// TestAccWindowsHostname_Basic — create+read: Rename-Computer queues a pending
// rename and surfaces current_name / pending_name / reboot_pending.
func TestAccWindowsHostname_Basic(t *testing.T) {
	testAccHostnamePreCheck(t)
	skipUnlessRenameAllowed(t)
	t.Skip("SKELETON: destructive rename — implement against a disposable host")
}

// TestAccWindowsHostname_UpdateInPlace — changing name issues an in-place
// Rename-Computer (no destroy-recreate); machine_id stays stable.
func TestAccWindowsHostname_UpdateInPlace(t *testing.T) {
	testAccHostnamePreCheck(t)
	skipUnlessRenameAllowed(t)
	t.Skip("SKELETON: destructive rename — see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_DriftDetection — an out-of-band Rename-Computer is
// detected at the next plan (pending_name changed).
func TestAccWindowsHostname_DriftDetection(t *testing.T) {
	testAccHostnamePreCheck(t)
	skipUnlessRenameAllowed(t)
	t.Skip("SKELETON: destructive rename — see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_DeleteIsNoOp — destroy removes the resource from state
// but does NOT change current_name on the host (EC-7).
func TestAccWindowsHostname_DeleteIsNoOp(t *testing.T) {
	testAccHostnamePreCheck(t)
	skipUnlessRenameAllowed(t)
	t.Skip("SKELETON: destructive rename — see TestAccWindowsHostname_Basic")
}
