//go:build acceptance

// Package provider — acceptance tests for windows_net_route.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled.
//
// SAFETY: these tests only ever create RFC 5737 (198.51.100.0/24,
// 203.0.113.0/24) and RFC 3849 (2001:db8::/32) documentation routes with
// on-link next hops, so no real traffic is affected, and only on an
// interface that is NOT the management interface. The target interface
// defaults to the loopback pseudo-interface (never the management NIC) and
// can be overridden with WINDOWS_TEST_INTERFACE. Every test first resolves
// the management path via winclient and skips when the target would touch
// it or when the path cannot be determined.
package provider

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccNetRoutePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// testAccNetRouteTarget returns the interface alias the route tests may
// safely use, or skips when it would touch the management path.
func testAccNetRouteTarget(t *testing.T) string {
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
		t.Skipf("cannot determine the management path, refusing to run route tests: %v", err)
	}
	if strings.EqualFold(alias, mp.InterfaceAlias) {
		t.Skipf("test interface %q is the management interface; refusing to run route tests", alias)
	}
	return alias
}

// testAccNetRouteFixture renders a windows_net_route resource (on-link
// documentation prefix, no real traffic) plus a data source reading it back.
func testAccNetRouteFixture(alias, extra string) string {
	return fmt.Sprintf(`
resource "windows_net_route" "test" {
  destination_prefix = "198.51.100.0/24"
  interface_alias    = %[1]q
  next_hop           = "0.0.0.0"
%[2]s
}

data "windows_net_route" "test" {
  destination_prefix = windows_net_route.test.destination_prefix
  interface_alias    = windows_net_route.test.interface_alias
}
`, alias, extra)
}

// TestAccWindowsNetRoute_Basic — create + metric update + import,
// documentation prefixes with on-link next hops only, never the management
// route. The update step also asserts persistence in the PersistentStore.
func TestAccWindowsNetRoute_Basic(t *testing.T) {
	testAccNetRoutePreCheck(t)
	alias := testAccNetRouteTarget(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNetRouteFixture(alias, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_net_route.test", "destination_prefix", "198.51.100.0/24"),
					resource.TestCheckResourceAttr("windows_net_route.test", "interface_alias", alias),
					resource.TestCheckResourceAttr("windows_net_route.test", "next_hop", "0.0.0.0"),
					resource.TestCheckResourceAttr("windows_net_route.test", "id", alias+"|198.51.100.0/24|0.0.0.0"),
					resource.TestCheckResourceAttr("windows_net_route.test", "address_family", "IPv4"),
					resource.TestCheckResourceAttr("windows_net_route.test", "protocol", "NetMgmt"),
					resource.TestCheckResourceAttr("windows_net_route.test", "route_metric", "256"),
					resource.TestCheckResourceAttr("data.windows_net_route.test", "destination_prefix", "198.51.100.0/24"),
					resource.TestCheckResourceAttr("data.windows_net_route.test", "protocol", "NetMgmt"),
					testAccNetRoutePersistentStore(alias, "198.51.100.0/24", "0.0.0.0"),
				),
			},
			{
				// In-place update: only route_metric changes.
				Config: testAccNetRouteFixture(alias, "  route_metric = 10\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_net_route.test", "route_metric", "10"),
				),
			},
			{
				// Import round-trip; the route must verify in place.
				ResourceName:      "windows_net_route.test",
				ImportState:       true,
				ImportStateId:     alias + "|198.51.100.0/24|0.0.0.0",
				ImportStateVerify: true,
			},
		},
	})
}

// testAccNetRoutePersistentStore dials the target and asserts the route is
// present in the PersistentStore (reboot-surviving), not just the
// ActiveStore view the resource reads.
func testAccNetRoutePersistentStore(alias, prefix, nextHop string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		cfg := winclient.Config{}
		winclient.ResolveFromEnv(&cfg)
		c, err := winclient.New(cfg)
		if err != nil {
			return fmt.Errorf("cannot build SSH client for persistence check: %w", err)
		}
		defer func() { _ = c.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		script := fmt.Sprintf("$r = Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq '%s' -and $_.NextHop -eq '%s' } | Select-Object -First 1; if ($null -eq $r) { throw 'route %s via %s not in PersistentStore' }; $r.DestinationPrefix",
			prefix, nextHop, prefix, nextHop)
		stdout, _, err := c.RunPowerShell(ctx, script)
		if err != nil {
			return fmt.Errorf("persistence check failed for route %s via %s on %q: %w (output: %s)", prefix, nextHop, alias, err, stdout)
		}
		return nil
	}
}

// TestAccWindowsNetRoute_GuardRefusesManagementRoute asserts the guard
// refuses to manage the live management route without touching it: the
// apply fails with management_path_at_risk before any mutation (the guard
// runs before the create pre-flight, so even the already-present route is
// refused by the guard rather than by already_exists).
func TestAccWindowsNetRoute_GuardRefusesManagementRoute(t *testing.T) {
	testAccNetRoutePreCheck(t)

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

	// A refusal assertion is only meaningful when the management triplet
	// passes plan-time validation: loopback/multicast/broadcast next hops
	// are rejected by the schema validators before the guard runs.
	curPrefix, err := netip.ParsePrefix(mp.RouteDestinationPrefix)
	if err != nil {
		t.Skipf("management route prefix %q is unparsable; skipping", mp.RouteDestinationPrefix)
	}
	curNextHop, err := netip.ParseAddr(mp.RouteNextHop)
	if err != nil {
		t.Skipf("management next hop %q is unparsable; skipping", mp.RouteNextHop)
	}
	nh := curNextHop.Unmap()
	if !nh.IsValid() || nh.IsLoopback() || nh.IsMulticast() ||
		(nh.Is4() && nh == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
		t.Skipf("management next hop %s is not usable for a refusal assertion (plan validators reject it before the guard)", mp.RouteNextHop)
	}

	config := fmt.Sprintf(`
resource "windows_net_route" "mgmt" {
  destination_prefix = %[1]q
  interface_alias    = %[2]q
  next_hop           = %[3]q
}
`, curPrefix.Masked().String(), mp.InterfaceAlias, nh.String())

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
