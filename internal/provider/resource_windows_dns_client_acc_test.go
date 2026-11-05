//go:build acceptance

// Package provider — acceptance tests for windows_dns_client.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled.
//
// SAFETY: these tests only ever assign RFC 5737 (192.0.2.0/24), RFC 3849
// (2001:db8::/32) and RFC 2606 (example.com) documentation values, and only
// on an explicit secondary interface given by WINDOWS_TEST_INTERFACE. The
// suite refuses to run without that variable (there is no safe default: the
// management NIC must never be touched by DNS tests), skips when the target
// does not expose the interface, and restores automatic (DHCP) servers on
// destroy via reset_on_destroy.
package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccDNSClientPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccDNSClientTarget returns the secondary interface alias the DNS tests
// may safely use. It requires WINDOWS_TEST_INTERFACE and skips when the
// interface is the management interface or cannot be resolved.
func testAccDNSClientTarget(t *testing.T) string {
	t.Helper()
	alias := os.Getenv("WINDOWS_TEST_INTERFACE")
	if strings.TrimSpace(alias) == "" {
		t.Skip("WINDOWS_TEST_INTERFACE is not set; refusing to run DNS client tests without an explicit secondary interface")
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
		t.Skipf("cannot determine the management path, refusing to run DNS client tests: %v", err)
	}
	if strings.EqualFold(alias, mp.InterfaceAlias) {
		t.Skipf("test interface %q is the management interface; refusing to run DNS client tests", alias)
	}
	dns := winclient.NewDnsClientClient(c)
	state, err := dns.Read(ctx, alias)
	if err != nil {
		t.Skipf("cannot read DNS client state on %q, host may not support it: %v", alias, err)
	}
	if state == nil {
		t.Skipf("interface %q not found on the target host", alias)
	}
	return alias
}

// testAccDNSClientFixture renders a windows_dns_client resource plus a data
// source reading the same interface back. servers is the HCL list literal
// for ipv4_server_addresses (kept as a parameter because HCL forbids
// defining the same argument twice: the update step shrinks the list, so it
// cannot be appended via extra). Documentation ranges only.
func testAccDNSClientFixture(alias, servers, extra string) string {
	return fmt.Sprintf(`
resource "windows_dns_client" "test" {
  interface_alias       = %[1]q
  ipv4_server_addresses = %[2]s
%[3]s
  reset_on_destroy = true
}

data "windows_dns_client" "test" {
  interface_alias = windows_dns_client.test.interface_alias
}
`, alias, servers, extra)
}

// TestAccWindowsDNSClient_Basic — create + update + import, documentation
// values only, never the management NIC.
func TestAccWindowsDNSClient_Basic(t *testing.T) {
	testAccDNSClientPreCheck(t)
	alias := testAccDNSClientTarget(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDNSClientFixture(alias, `["192.0.2.53", "198.51.100.53"]`, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_dns_client.test", "interface_alias", alias),
					resource.TestCheckResourceAttr("windows_dns_client.test", "id", alias),
					resource.TestCheckResourceAttr("windows_dns_client.test", "ipv4_server_addresses.0", "192.0.2.53"),
					resource.TestCheckResourceAttr("windows_dns_client.test", "ipv4_server_addresses.1", "198.51.100.53"),
					resource.TestCheckResourceAttr("data.windows_dns_client.test", "interface_alias", alias),
					resource.TestCheckResourceAttr("data.windows_dns_client.test", "ipv4_server_addresses.0", "192.0.2.53"),
				),
			},
			{
				// In-place update: shrink the list and set the suffix.
				Config: testAccDNSClientFixture(alias, `["192.0.2.53"]`, "  connection_specific_suffix = \"corp.example.com\"\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_dns_client.test", "ipv4_server_addresses.0", "192.0.2.53"),
					resource.TestCheckResourceAttr("windows_dns_client.test", "ipv4_server_addresses.#", "1"),
					resource.TestCheckResourceAttr("windows_dns_client.test", "connection_specific_suffix", "corp.example.com"),
				),
			},
			{
				// Import round-trip; the interface must verify in place.
				// reset_on_destroy is config-only (never read back from the
				// host), so the imported state cannot reproduce it.
				ResourceName:            "windows_dns_client.test",
				ImportState:             true,
				ImportStateId:           alias,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"reset_on_destroy"},
			},
		},
	})
}

// TestAccWindowsDNSClient_ResetOnDestroy asserts that destroying with
// reset_on_destroy returns both families to automatic: after apply with an
// empty IPv6 list and destroy, the live static lists are empty.
func TestAccWindowsDNSClient_ResetOnDestroy(t *testing.T) {
	testAccDNSClientPreCheck(t)
	alias := testAccDNSClientTarget(t)

	config := fmt.Sprintf(`
resource "windows_dns_client" "test" {
  interface_alias       = %[1]q
  ipv4_server_addresses = []
  ipv6_server_addresses = []
  reset_on_destroy      = true
}
`, alias)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_dns_client.test", "ipv4_server_addresses.#", "0"),
					resource.TestCheckResourceAttr("windows_dns_client.test", "ipv6_server_addresses.#", "0"),
				),
			},
		},
	})
}
