//go:build acceptance

// Package provider — acceptance tests for windows_local_group.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / WINDOWS_PASSWORD env vars
//   - A Windows target with WinRM enabled and Local Administrator rights.
//   - WINDOWS_LOCAL_GROUP_SUFFIX (optional): suffix appended to test group
//     names to avoid collisions on shared lab hosts; defaults to "tf-test".
package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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

// groupSuffix returns the optional test group name suffix (default: "tf-test").
func groupSuffix() string {
	if s := os.Getenv("WINDOWS_LOCAL_GROUP_SUFFIX"); s != "" {
		return s
	}
	return "tf-test"
}

// TestAccWindowsLocalGroup_Basic — create + read + idempotency.
func TestAccWindowsLocalGroup_Basic(t *testing.T) {
	testAccLocalGroupPreCheck(t)

	name := "grp-" + groupSuffix()
	cfg := fmt.Sprintf(`
resource "windows_local_group" "test" {
  name        = %q
  description = "created by acceptance test"
}
`, name)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_local_group.test", "name", name),
					resource.TestCheckResourceAttr("windows_local_group.test", "description", "created by acceptance test"),
					resource.TestCheckResourceAttrSet("windows_local_group.test", "sid"),
					resource.TestMatchResourceAttr("windows_local_group.test", "sid", regexp.MustCompile(`^S-1-5-`)),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsLocalGroup_DescriptionUpdate — changing description updates in
// place (no ForceNew).
func TestAccWindowsLocalGroup_DescriptionUpdate(t *testing.T) {
	testAccLocalGroupPreCheck(t)

	name := "grp-desc-" + groupSuffix()
	base := `
resource "windows_local_group" "upd" {
  name        = "` + name + `"
  description = %q
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(base, "before"),
				Check: resource.TestCheckResourceAttr(
					"windows_local_group.upd", "description", "before"),
			},
			{
				Config: fmt.Sprintf(base, "after"),
				Check: resource.TestCheckResourceAttr(
					"windows_local_group.upd", "description", "after"),
			},
		},
	})
}

// TestAccWindowsLocalGroup_RenameNoRecreate — renaming keeps the same SID
// (in-place Rename-LocalGroup, not ForceNew).
func TestAccWindowsLocalGroup_RenameNoRecreate(t *testing.T) {
	testAccLocalGroupPreCheck(t)

	var originalSID string
	cfg := func(name string) string {
		return fmt.Sprintf(`
resource "windows_local_group" "rn" {
  name        = %q
  description = "rename test"
}
`, name)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("grp-rn-" + groupSuffix()),
				Check: resource.TestCheckResourceAttrWith(
					"windows_local_group.rn", "sid",
					func(v string) error { originalSID = v; return nil },
				),
			},
			{
				Config: cfg("grp-rn2-" + groupSuffix()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_local_group.rn", "name", "grp-rn2-"+groupSuffix()),
					resource.TestCheckResourceAttrWith(
						"windows_local_group.rn", "sid",
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

// TestAccWindowsLocalGroup_Import — import an existing group by name.
func TestAccWindowsLocalGroup_Import(t *testing.T) {
	testAccLocalGroupPreCheck(t)

	name := "grp-imp-" + groupSuffix()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_local_group" "imp" {
  name        = %q
  description = "importable"
}
`, name),
			},
			{
				ResourceName:      "windows_local_group.imp",
				ImportState:       true,
				ImportStateId:     name,
				ImportStateVerify: true,
			},
		},
	})
}
