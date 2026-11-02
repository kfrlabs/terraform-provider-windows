//go:build acceptance

// Package provider — acceptance tests for windows_domain_membership.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - WINDOWS_TEST_DOMAIN set to a disposable Active Directory domain that
//     the target host may join (e.g. a test forest for CI).
//
// SAFETY: applying windows_domain_membership joins the machine to a domain
// (Add-Computer) and a reboot takes effect afterwards. That is destructive
// on a shared/lab host, so every scenario that performs a real join/unjoin
// is gated on WINDOWS_TEST_DOMAIN and left as a SKELETON until run against
// a disposable host. Only the plan-time schema-validation tests execute
// here — they never mutate the host because the error is raised before any
// SSH call. A real join is never asserted on windows-latest or in a
// container: those environments have no test domain.
package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccDomainMembershipPreCheck centralises the env-var guard for the
// domain_membership suite.
func testAccDomainMembershipPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// skipUnlessTestDomain skips unless the operator pointed the suite at a
// disposable domain. Joining any other domain (or the lack of one) must
// never happen as a side effect of the test run.
func skipUnlessTestDomain(t *testing.T) {
	t.Helper()
	if os.Getenv("WINDOWS_TEST_DOMAIN") == "" {
		t.Skip("WINDOWS_TEST_DOMAIN not set; refusing to join a domain")
	}
}

// --- Non-destructive plan-time validation ---------------------------------
// These assert that invalid domains are rejected before any join is
// attempted, so they are safe to run against any host.

// TestAccWindowsDomainMembership_InvalidDomain rejects a malformed domain.
func TestAccWindowsDomainMembership_InvalidDomain(t *testing.T) {
	testAccDomainMembershipPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_domain_membership" "this" {
  domain = "-not-a-domain-"
  join_credential = {
    username = "joiner"
    password = "S3cret!"
  }
}
`,
				ExpectError: regexp.MustCompile(`(?i)domain|DNS|match`),
				PlanOnly:    true,
			},
		},
	})
}

// TestAccWindowsDomainMembership_MissingCredential rejects a missing join
// credential before any SSH call.
func TestAccWindowsDomainMembership_MissingCredential(t *testing.T) {
	testAccDomainMembershipPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_domain_membership" "this" {
  domain = "corp.example.com"
  join_credential = {
    username = "joiner"
  }
}
`,
				ExpectError: regexp.MustCompile(`(?i)password|Exactly one`),
				PlanOnly:    true,
			},
		},
	})
}

// TestAccWindowsDomainMembership_UnjoinNeedsStatePassword rejects
// unjoin_on_destroy with a WriteOnly password before any SSH call.
func TestAccWindowsDomainMembership_UnjoinNeedsStatePassword(t *testing.T) {
	testAccDomainMembershipPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_domain_membership" "this" {
  domain = "corp.example.com"
  join_credential = {
    username    = "joiner"
    password_wo = "S3cret!"
  }
  unjoin_on_destroy = true
}
`,
				ExpectError: regexp.MustCompile(`(?i)unjoin_on_destroy|destroy time`),
				PlanOnly:    true,
			},
		},
	})
}

// --- Destructive lifecycle scenarios (SKELETON) ----------------------------
// Implementing these joins the machine to WINDOWS_TEST_DOMAIN and needs a
// reboot; they are kept as skeletons and only run when an operator
// explicitly opts in with a disposable host + domain.

// TestAccWindowsDomainMembership_Basic — join: Add-Computer queues the join
// and surfaces computer_name / pending_reboot / secure_channel_ok.
func TestAccWindowsDomainMembership_Basic(t *testing.T) {
	testAccDomainMembershipPreCheck(t)
	skipUnlessTestDomain(t)
	t.Skip("SKELETON: destructive domain join — implement against a disposable host")
}

// TestAccWindowsDomainMembership_DriftDetection — an out-of-band
// Remove-Computer is detected at the next plan (PartOfDomain=false removes
// the resource from state).
func TestAccWindowsDomainMembership_DriftDetection(t *testing.T) {
	testAccDomainMembershipPreCheck(t)
	skipUnlessTestDomain(t)
	t.Skip("SKELETON: destructive domain join — see TestAccWindowsDomainMembership_Basic")
}

// TestAccWindowsDomainMembership_UnjoinOnDestroy — destroy with
// unjoin_on_destroy=true moves the host back to the workgroup.
func TestAccWindowsDomainMembership_UnjoinOnDestroy(t *testing.T) {
	testAccDomainMembershipPreCheck(t)
	skipUnlessTestDomain(t)
	t.Skip("SKELETON: destructive domain join — see TestAccWindowsDomainMembership_Basic")
}

// TestAccWindowsDomainMembership_DeleteIsNoOp — destroy with the default
// unjoin_on_destroy=false leaves the host domain-joined.
func TestAccWindowsDomainMembership_DeleteIsNoOp(t *testing.T) {
	testAccDomainMembershipPreCheck(t)
	skipUnlessTestDomain(t)
	t.Skip("SKELETON: destructive domain join — see TestAccWindowsDomainMembership_Basic")
}
