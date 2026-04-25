// Package provider — acceptance-test skeleton for windows_service.
//
// These tests require:
//   - TF_ACC=1
//   - A reachable Windows host with WinRM enabled
//   - Env vars: WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD,
//     WINDOWS_USE_HTTPS (optional), WINDOWS_AUTH_TYPE (optional)
//   - A harmless binary path to manage a throw-away service
//     (e.g. C:\Windows\System32\svchost.exe)
//
// The suite covers:
//   - Create + Read + check attributes
//   - Update in-place (display_name, description, start_type)
//   - Update with ForceNew (binary_path change triggers replace)
//   - Drift detection: running a second plan after a manual sc.exe config
//     change must detect the drift
//   - Import by name
//   - Delete (CheckDestroy verifies Get-Service fails)
//
// On CI without a Windows host, every test skips via testAccPreCheck. This
// file intentionally depends ONLY on the terraform-plugin-framework test
// helpers that ship transitively with the framework; it does NOT import
// `terraform-plugin-testing` to avoid a new module dependency in this PR.
//
// When the project later adds `terraform-plugin-testing`, this file can be
// promoted to full TestCase-driven acceptance tests using resource.TestCase.
package provider

import (
	"os"
	"testing"
)

// testAccPreCheck centralises the env-var guard used by every acceptance test.
// It SKIPS (does not fail) when prerequisites are missing, so CI environments
// without a Windows lab still produce a green build.
func testAccPreCheck(t *testing.T) {
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

// TestAccWindowsService_Basic is the baseline create+read+destroy scenario.
// Skeleton only: requires terraform-plugin-testing to be fully fleshed out.
func TestAccWindowsService_Basic(t *testing.T) {
	testAccPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows host")
}

// TestAccWindowsService_UpdateInPlace asserts that changing display_name,
// description, start_type or service_account triggers an in-place Update.
func TestAccWindowsService_UpdateInPlace(t *testing.T) {
	testAccPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsService_Basic")
}

// TestAccWindowsService_ForceNew asserts that changing binary_path or name
// forces a destroy-recreate cycle (ForceNew attributes).
func TestAccWindowsService_ForceNew(t *testing.T) {
	testAccPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsService_Basic")
}

// TestAccWindowsService_Import covers `terraform import windows_service.foo bar`.
func TestAccWindowsService_Import(t *testing.T) {
	testAccPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsService_Basic")
}

// TestAccWindowsService_DriftDetection performs a manual sc.exe config change
// out-of-band and verifies the next plan surfaces the drift.
func TestAccWindowsService_DriftDetection(t *testing.T) {
	testAccPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsService_Basic")
}

// TestAccWindowsService_DeleteIdempotent verifies Destroy is a no-op after a
// manual `sc.exe delete` (EC-6 / 1060 idempotency).
func TestAccWindowsService_DeleteIdempotent(t *testing.T) {
	testAccPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsService_Basic")
}
