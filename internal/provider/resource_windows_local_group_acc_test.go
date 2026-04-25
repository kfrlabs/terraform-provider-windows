// Package provider — acceptance-test skeletons for windows_local_group.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights
//   - WINDOWS_LOCAL_GROUP_SUFFIX (optional): suffix appended to test group names
//     to avoid collision on shared lab hosts; defaults to "tf-test"
//
// Coverage outline (promoted to full resource.TestCase suites when
// terraform-plugin-testing is available with a live Windows target):
//
//   - Create + Read          groups are created, SID is assigned and stored as ID
//   - Update description     in-place description change, SID unchanged
//   - Update name (EC-5)     Rename-LocalGroup in place, SID unchanged
//   - Delete                 group disappears, CheckDestroy confirms absence
//   - Import by name (EC-10) terraform import via group name → SID becomes ID
//   - Import by SID (EC-10)  terraform import via SID string
//   - Builtin protection     EC-2: destroying a built-in group (S-1-5-32-*) produces a hard error
//   - Drift detection (EC-3) out-of-band deletion detected at next plan → resource removed from state
//   - Drift detection (EC-4) out-of-band rename detected at next plan (EqualFold)
//
// All tests skip immediately when TF_ACC is not set, so the CI unit-test pass
// remains green without a Windows lab.
package provider

import (
	"os"
	"testing"
)

// testAccLocalGroupPreCheck centralises the env-var guard for the local_group suite.
func testAccLocalGroupPreCheck(t *testing.T) {
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

// groupSuffix returns the optional group name suffix from env (default: "tf-test").
// Used by acceptance-test skeletons; suppressed until the test bodies are promoted.
//
//nolint:unused
func groupSuffix() string {
	if s := os.Getenv("WINDOWS_LOCAL_GROUP_SUFFIX"); s != "" {
		return s
	}
	return "tf-test"
}

// ---------------------------------------------------------------------------
// Basic: Create + Read + Delete
// ---------------------------------------------------------------------------

// TestAccWindowsLocalGroup_Basic verifies the minimal lifecycle:
//  1. Apply creates the group → SID assigned, ID == SID.
//  2. Plan is empty after first apply (idempotency).
//  3. Destroy removes the group from Windows.
//  4. CheckDestroy confirms the group is gone.
func TestAccWindowsLocalGroup_Basic(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: requires github.com/hashicorp/terraform-plugin-testing and a live Windows target")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLocalGroupDestroyed("AppAdmins-"+groupSuffix()),
			Steps: []resource.TestStep{
				{
					Config: testAccLocalGroupConfigBasic(groupSuffix()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_local_group.test", "name", "AppAdmins-"+groupSuffix()),
						resource.TestCheckResourceAttr("windows_local_group.test", "description", ""),
						resource.TestCheckResourceAttrSet("windows_local_group.test", "sid"),
						resource.TestMatchResourceAttr("windows_local_group.test", "sid",
							regexp.MustCompile(`^S-1-5-`)),
						// ID must equal SID (ADR-LG-1).
						resource.TestCheckResourceAttrPair(
							"windows_local_group.test", "id",
							"windows_local_group.test", "sid"),
					),
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroup_UpdateDescription verifies that changing `description`
// triggers an in-place Update (no resource replacement) and that SID is stable.
func TestAccWindowsLocalGroup_UpdateDescription(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLocalGroup_Basic")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLocalGroupDestroyed("AppAdmins-"+groupSuffix()),
			Steps: []resource.TestStep{
				{
					Config: testAccLocalGroupConfigWithDesc(groupSuffix(), ""),
					Check: resource.TestCheckResourceAttr("windows_local_group.test", "description", ""),
				},
				{
					Config: testAccLocalGroupConfigWithDesc(groupSuffix(), "Updated description"),
					Check:  resource.TestCheckResourceAttr("windows_local_group.test", "description", "Updated description"),
				},
				// Verify SID did not change (no replace).
				// (Would use TestCheckResourceAttrPair with "before" step SID captured via TestCheckResourceAttrWith)
			},
		})
	*/
}

// TestAccWindowsLocalGroup_RenameInPlace verifies EC-5: a change to `name`
// triggers Rename-LocalGroup in place and the SID remains unchanged.
func TestAccWindowsLocalGroup_RenameInPlace(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLocalGroup_Basic")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLocalGroupDestroyed("NewName-"+groupSuffix()),
			Steps: []resource.TestStep{
				{
					Config: testAccLocalGroupConfigNamed("OldName-"+groupSuffix()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_local_group.test", "name", "OldName-"+groupSuffix()),
						resource.TestCheckResourceAttrSet("windows_local_group.test", "sid"),
					),
				},
				{
					Config: testAccLocalGroupConfigNamed("NewName-"+groupSuffix()),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("windows_local_group.test", "name", "NewName-"+groupSuffix()),
						// SID should be identical (no replace).
						// Verified via id == sid and id unchanged between steps.
					),
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroup_ImportByName verifies EC-10 (name-based import):
// `terraform import windows_local_group.test <name>` resolves to the correct SID.
func TestAccWindowsLocalGroup_ImportByName(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLocalGroup_Basic")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLocalGroupDestroyed("AppAdmins-"+groupSuffix()),
			Steps: []resource.TestStep{
				// Step 1: create the group.
				{Config: testAccLocalGroupConfigBasic(groupSuffix())},
				// Step 2: import by name and verify state.
				{
					ResourceName:      "windows_local_group.test",
					ImportState:       true,
					ImportStateId:     "AppAdmins-" + groupSuffix(), // name-based (EC-10)
					ImportStateVerify: true,
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroup_ImportBySID verifies EC-10 (SID-based import):
// `terraform import windows_local_group.test S-1-5-21-...` resolves correctly.
func TestAccWindowsLocalGroup_ImportBySID(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: see TestAccWindowsLocalGroup_Basic")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			CheckDestroy:             testAccCheckLocalGroupDestroyed("AppAdmins-"+groupSuffix()),
			Steps: []resource.TestStep{
				// Step 1: create the group.
				{Config: testAccLocalGroupConfigBasic(groupSuffix())},
				// Step 2: read the SID from state, then import by SID.
				{
					ResourceName:      "windows_local_group.test",
					ImportState:       true,
					ImportStateIdFunc: testAccLocalGroupImportBySIDFunc("windows_local_group.test"),
					ImportStateVerify: true,
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroup_BuiltinProtection verifies EC-2 / ADR-LG-2:
// attempting to destroy a built-in group (S-1-5-32-*) fails with a hard error.
// This test targets the Guests group (S-1-5-32-546) because it is never
// legitimately used in automation labs, but it must still be listed as a
// known BUILTIN SID to trigger the guard.
func TestAccWindowsLocalGroup_BuiltinProtection(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: requires importing a known BUILTIN SID (e.g. S-1-5-32-546) and verifying destroy fails; see TestAccWindowsLocalGroup_Basic")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				// Import an existing built-in group by SID.
				{
					Config:            testAccLocalGroupConfigBuiltin("S-1-5-32-546"),
					ResourceName:      "windows_local_group.builtin",
					ImportState:       true,
					ImportStateId:     "S-1-5-32-546",
					ImportStateVerify: false, // description may differ
					// This step must succeed (read/import is allowed).
				},
				// Attempt destroy — must produce a hard error (EC-2).
				{
					Config:      testAccEmptyConfig(),
					ExpectError: regexp.MustCompile(`builtin_group`),
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroup_DriftDetection_Deleted verifies EC-3:
// if the group is deleted out-of-band (e.g. via Remove-LocalGroup on the host),
// the next `terraform plan` detects drift and schedules re-creation.
func TestAccWindowsLocalGroup_DriftDetection_Deleted(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: requires out-of-band Remove-LocalGroup between steps; see TestAccWindowsLocalGroup_Basic")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				// Step 1: create the group.
				{Config: testAccLocalGroupConfigBasic(groupSuffix())},
				// Step 2: out-of-band delete (simulated by a custom test step that
				//         runs Remove-LocalGroup via WinRM before the refresh plan).
				{
					RefreshState:       true,
					ExpectNonEmptyPlan: true, // drift detected → plan schedules re-create
				},
			},
		})
	*/
}

// TestAccWindowsLocalGroup_DriftDetection_CaseRename verifies EC-4 / ADR-LG-4:
// an out-of-band case-only rename (e.g. "appadmins" → "AppAdmins") does NOT
// produce a spurious plan diff because Read uses strings.EqualFold.
func TestAccWindowsLocalGroup_DriftDetection_CaseRename(t *testing.T) {
	testAccLocalGroupPreCheck(t)
	t.Skip("SKELETON: requires out-of-band Rename-LocalGroup (case change only) and verifying empty plan; see TestAccWindowsLocalGroup_Basic")
	/*
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				// Step 1: create with lowercase name.
				{
					Config: testAccLocalGroupConfigNamed("appadmins-"+groupSuffix()),
					Check:  resource.TestCheckResourceAttr("windows_local_group.test", "name", "appadmins-"+groupSuffix()),
				},
				// Step 2: out-of-band rename to "AppAdmins-<suffix>" (case-only).
				// Next plan must be empty (EqualFold match prevents spurious rename).
				{
					Config:             testAccLocalGroupConfigNamed("appadmins-"+groupSuffix()),
					PlanOnly:           true,
					ExpectNonEmptyPlan: false,
				},
			},
		})
	*/
}

// ---------------------------------------------------------------------------
// HCL config helpers (used by commented-out acceptance tests above)
// ---------------------------------------------------------------------------

//nolint:unused
func testAccLocalGroupConfigBasic(suffix string) string {
	return `
resource "windows_local_group" "test" {
  name = "AppAdmins-` + suffix + `"
}
`
}

//nolint:unused
func testAccLocalGroupConfigWithDesc(suffix, desc string) string {
	return `
resource "windows_local_group" "test" {
  name        = "AppAdmins-` + suffix + `"
  description = "` + desc + `"
}
`
}

//nolint:unused
func testAccLocalGroupConfigNamed(name string) string {
	return `
resource "windows_local_group" "test" {
  name = "` + name + `"
}
`
}

//nolint:unused
func testAccLocalGroupConfigBuiltin(sid string) string {
	return `
resource "windows_local_group" "builtin" {
  # This is a placeholder — SID is injected via import, not HCL.
  name = "placeholder"
}
`
}

//nolint:unused
func testAccEmptyConfig() string {
	return `# empty`
}

//nolint:unused
func testAccCheckLocalGroupDestroyed(name string) func(interface{}) error {
	return func(_ interface{}) error {
		// SKELETON: verify via WinRM that the group no longer exists.
		return nil
	}
}

//nolint:unused
func testAccLocalGroupImportBySIDFunc(resourceName string) func(interface{}) (string, error) {
	return func(state interface{}) (string, error) {
		// SKELETON: extract the SID from state and return it for import.
		return "", nil
	}
}
