// Package provider — acceptance-test skeleton for windows_hostname.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A workgroup (NOT domain-joined) Windows target with WinRM and Local
//     Administrator rights
//   - WINDOWS_HOSTNAME_TARGET (optional): NetBIOS name to rename to;
//     defaults to "TFTEST-RENAME"
//
// Coverage outline (skeleton; promoted to full resource.TestCase suites once
// terraform-plugin-testing is added to the module):
//
//   - Create + Read           windows_hostname.this name=<target>, current_name + pending_name
//   - Read drift              an out-of-band Rename-Computer is detected at next plan
//   - Update in-place         changing `name` issues Rename-Computer (no replace)
//   - Update with ForceNew    n/a — v1 has no ForceNew attributes; renames are in-place
//   - Import                  `terraform import windows_hostname.this <machine_guid>`
//   - Delete                  destroy is a no-op (EC-7); CheckDestroy verifies the
//     host still answers and current_name is unchanged
//
// Every test SKIPS via testAccHostnamePreCheck when prerequisites are missing,
// so CI without a Windows lab still produces a green build.
package provider

import (
	"os"
	"testing"
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

// TestAccWindowsHostname_Basic is the baseline create+read+destroy scenario.
// Verifies that Rename-Computer queues a pending rename and that the
// resource surfaces current_name / pending_name / reboot_pending.
func TestAccWindowsHostname_Basic(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live workgroup Windows host")
}

// TestAccWindowsHostname_UpdateInPlace asserts that changing `name` triggers
// an in-place Update (no destroy-recreate), and that machine_id stays stable.
func TestAccWindowsHostname_UpdateInPlace(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_ToggleForce asserts that toggling `force` alone, when
// already at the desired name, does NOT trigger a Rename-Computer call (EC-2 /
// EC-8). The Update plan should be empty after the first apply.
func TestAccWindowsHostname_ToggleForce(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_Import covers `terraform import windows_hostname.this
// <machine_guid>` followed by a Read that backfills current_name / pending_name.
func TestAccWindowsHostname_Import(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_DriftDetection performs an out-of-band rename via
// Rename-Computer on the host and verifies the next `terraform plan` surfaces
// the drift (pending_name changed) so an apply restores `name`.
func TestAccWindowsHostname_DriftDetection(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_DeleteIsNoOp verifies destroy removes the resource
// from state but does NOT change current_name on the host (EC-7).
func TestAccWindowsHostname_DeleteIsNoOp(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_DomainJoinedRejected asserts that a domain-joined
// host is rejected at runtime (EC-5) with HostnameErrorDomainJoined.
func TestAccWindowsHostname_DomainJoinedRejected(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: requires a domain-joined target; see TestAccWindowsHostname_Basic")
}

// TestAccWindowsHostname_InvalidName asserts schema-level validation (EC-1):
// purely numeric / leading-hyphen / >15-char names are rejected at plan time.
func TestAccWindowsHostname_InvalidName(t *testing.T) {
	testAccHostnamePreCheck(t)
	t.Skip("SKELETON: schema validators are unit-tested elsewhere; this acceptance check requires terraform-plugin-testing")
}
