//go:build acceptance

// Package provider — acceptance tests for windows_net_ip_address.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled.
//
// SAFETY: these tests only ever assign RFC 5737 (192.0.2.0/24) and RFC 3849
// (2001:db8::/32) documentation addresses, and only on an interface that is
// NOT the management interface. The target interface defaults to the
// loopback pseudo-interface (never the management NIC) and can be
// overridden with WINDOWS_TEST_INTERFACE. Every test first resolves the
// management path via winclient and skips when the target would touch it or
// when the path cannot be determined.
package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccNetIPAddressPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccNetIPAddressTarget returns the interface alias the address tests
// may safely use, or skips when it would touch the management path.
func testAccNetIPAddressTarget(t *testing.T) string {
	t.Helper()
	alias := os.Getenv("WINDOWS_TEST_INTERFACE")
	if alias == "" {
		alias = "Loopback Pseudo-Interface 1"
	}
	cfg := winclient.Config{}
	winclient.ResolveFromEnv(&cfg)
	c, err := winclient.New(cfg)
	if err != nil {
		t.Skipf("cannot build SSH client for safety check: %v", err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	mp, err := c.ManagementPath(ctx)
	if err != nil {
		t.Skipf("cannot determine the management path, refusing to run address tests: %v", err)
	}
	if strings.EqualFold(alias, mp.InterfaceAlias) {
		t.Skipf("test interface %q is the management interface; refusing to run address tests", alias)
	}
	return alias
}

// testAccNetIPAddressFixture renders a windows_net_ip_address resource plus
// a data source reading the same address back.
func testAccNetIPAddressFixture(alias, extra string) string {
	return fmt.Sprintf(`
resource "windows_net_ip_address" "test" {
  interface_alias = %[1]q
  ip_address      = "192.0.2.10"
  prefix_length   = 24
%[2]s
}

data "windows_net_ip_address" "test" {
  ip_address       = windows_net_ip_address.test.ip_address
  interface_alias  = windows_net_ip_address.test.interface_alias
}
`, alias, extra)
}

// TestAccWindowsNetIPAddress_Basic — create + update + import, documentation
// addresses only, never the management address.
func TestAccWindowsNetIPAddress_Basic(t *testing.T) {
	testAccNetIPAddressPreCheck(t)
	alias := testAccNetIPAddressTarget(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNetIPAddressFixture(alias, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "interface_alias", alias),
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "ip_address", "192.0.2.10"),
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "prefix_length", "24"),
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "id", alias+"|192.0.2.10"),
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "address_family", "IPv4"),
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "prefix_origin", "Manual"),
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "skip_as_source", "false"),
					resource.TestCheckResourceAttr("data.windows_net_ip_address.test", "ip_address", "192.0.2.10"),
					resource.TestCheckResourceAttr("data.windows_net_ip_address.test", "address_family", "IPv4"),
				),
			},
			{
				// In-place update: prefix length and skip_as_source.
				Config: testAccNetIPAddressFixture(alias, "  prefix_length   = 25\n  skip_as_source  = true\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "prefix_length", "25"),
					resource.TestCheckResourceAttr("windows_net_ip_address.test", "skip_as_source", "true"),
				),
			},
			{
				// Import round-trip; the address must verify in place.
				ResourceName:      "windows_net_ip_address.test",
				ImportState:       true,
				ImportStateId:     alias + "|192.0.2.10",
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccWindowsNetIPAddress_GuardRefusesManagementAddress asserts the guard
// refuses to delete the management IP without touching it: the apply fails
// with management_path_at_risk before any mutation.
func TestAccWindowsNetIPAddress_GuardRefusesManagementAddress(t *testing.T) {
	testAccNetIPAddressPreCheck(t)

	cfg := winclient.Config{}
	winclient.ResolveFromEnv(&cfg)
	c, err := winclient.New(cfg)
	if err != nil {
		t.Skipf("cannot build SSH client: %v", err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	mp, err := c.ManagementPath(ctx)
	if err != nil {
		t.Skipf("cannot determine the management path: %v", err)
	}

	// Sanity: the probe must have resolved via one of the two known sources.
	if mp.Source != winclient.ManagementPathSourceSSH && mp.Source != winclient.ManagementPathSourceTCP {
		t.Fatalf("unexpected management path source %q", mp.Source)
	}

	config := fmt.Sprintf(`
resource "windows_net_ip_address" "mgmt" {
  interface_alias = %[1]q
  ip_address      = %[2]q
  prefix_length   = 24
}
`, mp.InterfaceAlias, mp.ServerIP.String())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`management_path_at_risk`),
			},
		},
	})
}
