//go:build acceptance

// Package provider — acceptance test for the windows_local_users data
// source.
//
// Read-only: safe on any host. Requires TF_ACC=1 plus a reachable Windows
// target; otherwise skips. Asserts the inventory is non-empty and every
// element carries a name and SID, with names/sids mirroring users. No users
// are created: the suite only inventories what is already present.
package provider

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func testAccLocalUsersDSPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccCheckLocalUsersNonEmpty verifies the users list holds at least one
// entry, every element carries a name and SID, and names/sids mirror the
// users order.
func testAccCheckLocalUsersNonEmpty(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("resource %q not found in state", name)
		}
		n, err := strconv.Atoi(rs.Primary.Attributes["users.#"])
		if err != nil {
			return fmt.Errorf("users.# is not a number: %v", err)
		}
		if n == 0 {
			return fmt.Errorf("expected at least one local user, got none")
		}
		for i := 0; i < n; i++ {
			if rs.Primary.Attributes[fmt.Sprintf("users.%d.name", i)] == "" {
				return fmt.Errorf("users.%d is missing name", i)
			}
			if rs.Primary.Attributes[fmt.Sprintf("users.%d.sid", i)] == "" {
				return fmt.Errorf("users.%d is missing sid", i)
			}
		}
		if rs.Primary.Attributes["names.#"] != strconv.Itoa(n) {
			return fmt.Errorf("names.# = %q, want %d (must mirror users)", rs.Primary.Attributes["names.#"], n)
		}
		if rs.Primary.Attributes["sids.#"] != strconv.Itoa(n) {
			return fmt.Errorf("sids.# = %q, want %d (must mirror users)", rs.Primary.Attributes["sids.#"], n)
		}
		return nil
	}
}

// TestAccWindowsLocalUsersDataSource_Basic reads the full inventory and the
// inventory filtered to enabled accounts.
func TestAccWindowsLocalUsersDataSource_Basic(t *testing.T) {
	testAccLocalUsersDSPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "windows_local_users" "all" {}` + "\n" +
					`data "windows_local_users" "enabled" { enabled = true }` + "\n",
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_local_users.all", "id"),
					testAccCheckLocalUsersNonEmpty("data.windows_local_users.all"),
					resource.TestCheckResourceAttrSet("data.windows_local_users.enabled", "id"),
				),
			},
		},
	})
}
