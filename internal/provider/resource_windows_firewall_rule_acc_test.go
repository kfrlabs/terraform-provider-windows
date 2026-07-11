//go:build acceptance

// Package provider — acceptance-test skeleton for windows_firewall_rule.
//
// These tests require:
//   - TF_ACC=1
//   - A reachable Windows host with WinRM enabled
//   - Env vars: WINDOWS_HOST, WINDOWS_USERNAME, WINDOWS_PASSWORD
//   - The target host must have NetSecurity module available (Windows Server
//     2012+ or Windows 8+)
//   - The calling user must be a local Administrator on the target host
//
// The suite covers:
//   - Create + Read + check attributes
//   - Update in-place (display_name, description, enabled, action)
//   - Update with ForceNew (name / group change triggers replace)
//   - Import by name (PersistentStore assumed)
//   - Import by store/name (explicit policy_store)
//   - Drift detection: manual Remove-NetFirewallRule detected on next plan
//   - Delete + CheckDestroy (Get-NetFirewallRule fails after destroy)
//   - Read-only store rejection (GroupPolicy store → error)
//
// On CI without a Windows host every test skips via testAccPreCheck (same
// guard used by all other windows_* resource acceptance tests).
// The file does NOT import terraform-plugin-testing to avoid introducing a
// new module dependency; a skeleton for resource.TestCase is provided so that
// it can be activated once that dependency is added.
package provider

import (
	"os"
	"testing"
)

// testAccFirewallPreCheck is the acceptance-test guard for windows_firewall_rule.
// It delegates to the shared testAccPreCheck and adds no extra requirements.
func testAccFirewallPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping windows_firewall_rule acceptance test")
	}
	for _, v := range []string{"WINDOWS_HOST", "WINDOWS_USERNAME", "WINDOWS_PASSWORD"} {
		if os.Getenv(v) == "" {
			t.Skipf("env %s not set; skipping acceptance test", v)
		}
	}
}

// TestAccWindowsFirewallRule_Basic is the baseline create + read + destroy
// scenario. It verifies:
//   - New-NetFirewallRule succeeds and state is populated from Read pipeline
//   - Direction, Action, Profile, Protocol, LocalPort are set correctly
//   - ID equals the technical Name (InstanceID)
//
// Skeleton: activate with github.com/hashicorp/terraform-plugin-testing.
func TestAccWindowsFirewallRule_Basic(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows host")
	// resource.Test(t, resource.TestCase{
	//   ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
	//   CheckDestroy: testAccCheckFirewallRuleDestroyed("tf-acc-fw-basic"),
	//   Steps: []resource.TestStep{
	//     {
	//       Config: testAccFirewallRuleConfig_basic("tf-acc-fw-basic"),
	//       Check: resource.ComposeTestCheckFunc(
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "name", "tf-acc-fw-basic"),
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "direction", "Inbound"),
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "action", "Allow"),
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "enabled", "true"),
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "id", "tf-acc-fw-basic"),
	//       ),
	//     },
	//   },
	// })
}

// TestAccWindowsFirewallRule_UpdateInPlace asserts that changing display_name,
// description, enabled, action, profile, or protocol triggers an in-place
// Update (Set-NetFirewallRule) rather than a destroy-recreate cycle.
func TestAccWindowsFirewallRule_UpdateInPlace(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
	// resource.Test(t, resource.TestCase{
	//   ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
	//   Steps: []resource.TestStep{
	//     {
	//       Config: testAccFirewallRuleConfig_basic("tf-acc-fw-update"),
	//       Check:  resource.TestCheckResourceAttr("windows_firewall_rule.basic", "action", "Allow"),
	//     },
	//     {
	//       Config: testAccFirewallRuleConfig_updated("tf-acc-fw-update"),
	//       Check: resource.ComposeTestCheckFunc(
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "action", "Block"),
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "enabled", "false"),
	//         // ID must be the same (no replace):
	//         resource.TestCheckResourceAttr("windows_firewall_rule.basic", "id", "tf-acc-fw-update"),
	//       ),
	//     },
	//   },
	// })
}

// TestAccWindowsFirewallRule_ForceNew asserts that changing name or group
// forces a destroy-recreate cycle (ForceNew plan modifier).
func TestAccWindowsFirewallRule_ForceNew(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
}

// TestAccWindowsFirewallRule_Import covers:
//   - `terraform import windows_firewall_rule.r <name>` (PersistentStore)
//   - `terraform import windows_firewall_rule.r PersistentStore/<name>`
func TestAccWindowsFirewallRule_Import(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
	// resource.Test(t, resource.TestCase{
	//   Steps: []resource.TestStep{
	//     {Config: testAccFirewallRuleConfig_basic("tf-acc-fw-import")},
	//     {
	//       ResourceName:      "windows_firewall_rule.basic",
	//       ImportState:       true,
	//       ImportStateId:     "tf-acc-fw-import",
	//       ImportStateVerify: true,
	//     },
	//     {
	//       ResourceName:      "windows_firewall_rule.basic",
	//       ImportState:       true,
	//       ImportStateId:     "PersistentStore/tf-acc-fw-import",
	//       ImportStateVerify: true,
	//     },
	//   },
	// })
}

// TestAccWindowsFirewallRule_DriftDetection runs a second plan after
// Remove-NetFirewallRule is called out-of-band and verifies the next apply
// recreates the rule (non-empty plan).
func TestAccWindowsFirewallRule_DriftDetection(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
	// Drift test steps:
	// 1. Create the rule
	// 2. Remove-NetFirewallRule out-of-band via exec.Command (WinRM or local)
	// 3. Refresh-only plan → expect non-empty plan (rule removed from state)
	// 4. Apply → rule re-created
}

// TestAccWindowsFirewallRule_DeleteIdempotent verifies that Destroy is a
// no-op when the rule was already removed out-of-band before terraform destroy.
// This exercises the idempotency guarantee (Delete swallows ItemNotFoundException).
func TestAccWindowsFirewallRule_DeleteIdempotent(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
}

// TestAccWindowsFirewallRule_ReadOnlyStore verifies that attempting to Create
// a rule in the GroupPolicy or RSOP store returns a descriptive error.
func TestAccWindowsFirewallRule_ReadOnlyStore(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
	// resource.Test(t, resource.TestCase{
	//   Steps: []resource.TestStep{
	//     {
	//       Config:      testAccFirewallRuleConfig_groupPolicy("tf-acc-fw-readonly"),
	//       ExpectError: regexp.MustCompile("read_only_store"),
	//     },
	//   },
	// })
}

// TestAccWindowsFirewallRule_WithPortFilter verifies that TCP + local_port +
// remote_port filters are correctly applied and read back.
func TestAccWindowsFirewallRule_WithPortFilter(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
}

// TestAccWindowsFirewallRule_WithAddressFilter verifies that local_address +
// remote_address CIDR filters are applied correctly.
func TestAccWindowsFirewallRule_WithAddressFilter(t *testing.T) {
	testAccFirewallPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsFirewallRule_Basic")
}

// ---------------------------------------------------------------------------
// Config helpers (to be used once terraform-plugin-testing is added)
// ---------------------------------------------------------------------------

// testAccFirewallRuleConfig_basic returns minimal HCL for a windows_firewall_rule.
//
//nolint:unused
func testAccFirewallRuleConfig_basic(name string) string {
	return `
resource "windows_firewall_rule" "basic" {
  name         = "` + name + `"
  display_name = "Terraform Acceptance Test Rule"
  direction    = "Inbound"
  action       = "Allow"
  enabled      = true
  policy_store = "PersistentStore"
}
`
}

// testAccFirewallRuleConfig_updated returns HCL with modified mutable attributes.
//
//nolint:unused
func testAccFirewallRuleConfig_updated(name string) string {
	return `
resource "windows_firewall_rule" "basic" {
  name         = "` + name + `"
  display_name = "Terraform Acceptance Test Rule (Updated)"
  description  = "Updated by acceptance test"
  direction    = "Inbound"
  action       = "Block"
  enabled      = false
  policy_store = "PersistentStore"
}
`
}

// testAccFirewallRuleConfig_withPorts returns HCL with TCP port filters.
//
//nolint:unused
func testAccFirewallRuleConfig_withPorts(name string) string {
	return `
resource "windows_firewall_rule" "with_ports" {
  name         = "` + name + `"
  display_name = "Terraform Port Filter Test"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["80", "443", "8080-8090"]
  remote_port  = ["Any"]
  policy_store = "PersistentStore"
}
`
}

// testAccFirewallRuleConfig_groupPolicy returns HCL targeting the read-only store.
//
//nolint:unused
func testAccFirewallRuleConfig_groupPolicy(name string) string {
	return `
resource "windows_firewall_rule" "gpo" {
  name         = "` + name + `"
  display_name = "GPO Rule (should fail)"
  direction    = "Inbound"
  action       = "Allow"
  policy_store = "GroupPolicy"
}
`
}
