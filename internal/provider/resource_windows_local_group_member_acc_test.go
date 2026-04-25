// Package provider — acceptance-test skeletons for windows_local_group_member.
//
// Requires (when promoted from skeleton to live test):
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target (>=2016/Win10) with WinRM enabled and local
//     Administrator rights over WinRM.
//   - A pre-existing local user account: WINDOWS_TEST_LOCAL_USER (default: "testlgmuser")
//   - Optionally WINDOWS_TEST_DOMAIN_USER: "DOMAIN\user" for domain-user tests.
//
// Acceptance-test identifiers:
//   TestAccWindowsLocalGroupMember_basic        Create+Read+Delete via Administrators
//   TestAccWindowsLocalGroupMember_importBySID  Import by group SID / member SID
//   TestAccWindowsLocalGroupMember_importByName Import by group name / member name
//   TestAccWindowsLocalGroupMember_groupBySID   group attribute = SID string (EC-9)
//   TestAccWindowsLocalGroupMember_memberByUPN  member attribute = user@domain (UPN)
//   TestAccWindowsLocalGroupMember_duplicate    EC-1: duplicate membership ExpectError
//   TestAccWindowsLocalGroupMember_drift        EC-4: out-of-band delete + re-apply
//
// All tests skip immediately when TF_ACC is not set so the CI unit-test
// pass remains green without a Windows lab.
package provider

import (
	"fmt"
	"os"
	"testing"
)

// testAccLGMPreCheck centralises the env-var guard for the local_group_member suite.
func testAccLGMPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test (requires live Windows host)")
	}
	for _, v := range []string{"WINDOWS_HOST", "WINDOWS_USERNAME", "WINDOWS_PASSWORD"} {
		if os.Getenv(v) == "" {
			t.Skipf("env %s not set; skipping acceptance test", v)
		}
	}
}

// lgmTestLocalUser returns the local user account name for acceptance tests.
func lgmTestLocalUser() string {
	if u := os.Getenv("WINDOWS_TEST_LOCAL_USER"); u != "" {
		return u
	}
	return "testlgmuser"
}

// lgmTestDomainUser returns the domain user for UPN/domain tests (may be empty).
func lgmTestDomainUser() string {
	return os.Getenv("WINDOWS_TEST_DOMAIN_USER")
}

// ---------------------------------------------------------------------------
// Acceptance tests (skeletons)
// ---------------------------------------------------------------------------

// TestAccWindowsLocalGroupMember_basic verifies the minimal lifecycle:
//  1. Apply adds local user to Administrators group.
//  2. Plan after apply is empty (idempotency).
//  3. Destroy removes the membership.
//  4. CheckDestroy confirms membership is gone.
//
// Alignment: EC-9 (BUILTIN group support), EC-12 (non-authoritative).
func TestAccWindowsLocalGroupMember_basic(t *testing.T) {
	testAccLGMPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLGMDestroyed("S-1-5-32-544", lgmTestLocalUser()),
			Steps: []resource.TestStep{
				{
					Config: testAccLGMConfigBasic(lgmTestLocalUser()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_local_group_member.test", "group", "Administrators"),
						resource.TestCheckResourceAttr("windows_local_group_member.test", "member", lgmTestLocalUser()),
						resource.TestCheckResourceAttrSet("windows_local_group_member.test", "group_sid"),
						resource.TestCheckResourceAttrSet("windows_local_group_member.test", "member_sid"),
						resource.TestMatchResourceAttr("windows_local_group_member.test", "group_sid",
							regexp.MustCompile(`^S-1-5-32-544)),
						resource.TestMatchResourceAttr("windows_local_group_member.test", "member_sid",
							regexp.MustCompile(`^S-1-5-21-`)),
						resource.TestCheckResourceAttr("windows_local_group_member.test", "member_principal_source", "Local"),
					),
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroupMember_importBySID verifies terraform import using
// the composite SID/SID import ID format (ADR-LGM-1).
func TestAccWindowsLocalGroupMember_importBySID(t *testing.T) {
	testAccLGMPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLGMConfigBasic(lgmTestLocalUser()),
				},
				{
					ResourceName: "windows_local_group_member.test",
					ImportState:  true,
					ImportStateIdFunc: func(s *terraform.State) (string, error) {
						rs := s.RootModule().Resources["windows_local_group_member.test"]
						if rs == nil {
							return "", fmt.Errorf("resource not found in state")
						}
						return rs.Primary.Attributes["group_sid"] + "/" + rs.Primary.Attributes["member_sid"], nil
					},
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: []string{"member"},
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroupMember_importByName verifies terraform import using
// the human-readable "GroupName/MemberName" import ID format.
func TestAccWindowsLocalGroupMember_importByName(t *testing.T) {
	testAccLGMPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLGMConfigBasic(lgmTestLocalUser()),
				},
				{
					ResourceName:            "windows_local_group_member.test",
					ImportState:             true,
					ImportStateId:           fmt.Sprintf("Administrators/%s", lgmTestLocalUser()),
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: []string{"member"},
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroupMember_groupBySID verifies that the group attribute
// accepts a SID string (EC-9: BUILTIN group by SID).
func TestAccWindowsLocalGroupMember_groupBySID(t *testing.T) {
	testAccLGMPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLGMConfigGroupBySID(lgmTestLocalUser()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_local_group_member.bysid",
							"group_sid", "S-1-5-32-544"),
					),
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroupMember_memberByUPN verifies that the member attribute
// accepts a UPN-format identity (user@domain.tld).
func TestAccWindowsLocalGroupMember_memberByUPN(t *testing.T) {
	testAccLGMPreCheck(t)
	if lgmTestDomainUser() == "" {
		t.Skip("WINDOWS_TEST_DOMAIN_USER not set; skipping UPN test")
	}
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLGMConfigMemberByUPN(lgmTestDomainUser()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_local_group_member.upn",
							"member", lgmTestDomainUser()),
						resource.TestCheckResourceAttr("windows_local_group_member.upn",
							"member_principal_source", "ActiveDirectory"),
					),
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroupMember_duplicate verifies EC-1: attempting to create
// a duplicate membership produces a hard error with an import hint.
func TestAccWindowsLocalGroupMember_duplicate(t *testing.T) {
	testAccLGMPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLGMConfigBasic(lgmTestLocalUser()),
				},
				{
					Config:      testAccLGMConfigDuplicate(lgmTestLocalUser()),
					ExpectError: regexp.MustCompile(`member_already_exists|already a member|EC-1`),
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroupMember_drift verifies EC-4: when the membership is
// deleted outside Terraform, the next plan detects drift and re-creates it on
// apply.
func TestAccWindowsLocalGroupMember_drift(t *testing.T) {
	testAccLGMPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccLGMConfigBasic(lgmTestLocalUser()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet("windows_local_group_member.test", "member_sid"),
					),
				},
				{
					// After manually removing membership out-of-band, the RefreshState
					// step verifies drift is detected (state should report resource absent).
					RefreshState:       true,
					ExpectNonEmptyPlan: true,
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// Config template helpers (used by acceptance tests above when promoted)
// ---------------------------------------------------------------------------

// testAccLGMConfigBasic returns a minimal config adding a local user to
// Administrators.
//
//nolint:unused
func testAccLGMConfigBasic(localUser string) string {
	return fmt.Sprintf(`
resource "windows_local_group_member" "test" {
  group  = "Administrators"
  member = %q
}
`, localUser)
}

// testAccLGMConfigGroupBySID returns a config using the BUILTIN SID for the group.
//
//nolint:unused
func testAccLGMConfigGroupBySID(localUser string) string {
	return fmt.Sprintf(`
resource "windows_local_group_member" "bysid" {
  group  = "S-1-5-32-544"
  member = %q
}
`, localUser)
}

// testAccLGMConfigMemberByUPN returns a config using a UPN as member identity.
//
//nolint:unused
func testAccLGMConfigMemberByUPN(upnUser string) string {
	return fmt.Sprintf(`
resource "windows_local_group_member" "upn" {
  group  = "Administrators"
  member = %q
}
`, upnUser)
}

// testAccLGMConfigDuplicate returns two resource blocks for the same (group, member)
// pair, which should trigger EC-1.
//
//nolint:unused
func testAccLGMConfigDuplicate(localUser string) string {
	return fmt.Sprintf(`
resource "windows_local_group_member" "test" {
  group  = "Administrators"
  member = %q
}

resource "windows_local_group_member" "dup" {
  group      = "Administrators"
  member     = %q
  depends_on = [windows_local_group_member.test]
}
`, localUser, localUser)
}

// testAccCheckLGMDestroyed is a placeholder CheckDestroy function for
// acceptance tests. Real implementation would use winclient to confirm absence.
//
//nolint:unused
func testAccCheckLGMDestroyed(_ string, _ string) func(interface{}) error {
	return func(_ interface{}) error {
		return nil // replaced with real check when promoting from skeleton
	}
}
