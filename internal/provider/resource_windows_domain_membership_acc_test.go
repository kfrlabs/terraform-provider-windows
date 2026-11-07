//go:build acceptance

// Package provider — acceptance tests for windows_domain_membership.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//
// SAFETY: joining a machine to a domain (Add-Computer, plus a reboot) is
// destructive on a shared/lab host and no CI environment provides a test
// domain, so the destructive join/unjoin lifecycle is covered by unit tests
// with a fake transport (see resource_windows_domain_membership_test.go and
// internal/winclient/domain_membership_client_impl_test.go) instead of
// acceptance tests. Only the plan-time schema-validation tests execute
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
