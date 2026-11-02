//go:build acceptance

// Package provider — acceptance tests for windows_firewall_profile.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled and the NetSecurity module.
//
// Profiles always exist, so every test tunes a profile in place and (by
// default) leaves the host exactly as it found it: CRUD steps only touch
// logging settings on the profile that does NOT carry the SSH session, the
// lockout-guard step only attempts a refused change, and the
// restore_on_destroy step reverts its own change on destroy.
package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccFirewallProfilePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// accFirewallProfileClient builds a direct winclient for out-of-band reads,
// which is the only way to observe pre-existing values and the SSH-carrying
// profile. ResolveFromEnv is intentional here: the public-key CI leg clears
// WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH instead.
func accFirewallProfileClient(t *testing.T) *winclient.FirewallProfileClient {
	t.Helper()
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	return winclient.NewFirewallProfileClient(c)
}

// accFirewallProfileSSH returns the profile carrying the test session, or
// skips the test when it cannot be determined (the guard fails closed on the
// same condition, so there is nothing meaningful to assert).
func accFirewallProfileSSH(t *testing.T) string {
	t.Helper()
	profile, err := accFirewallProfileClient(t).SSHProfile(context.Background())
	if err != nil {
		t.Skipf("cannot determine the SSH session profile; skipping: %v", err)
	}
	return profile
}

// accFirewallProfileOther returns a profile that does not carry the test
// session, so CRUD steps never risk the SSH connection.
func accFirewallProfileOther(t *testing.T, sshProfile string) string {
	t.Helper()
	for _, p := range []string{"Private", "Domain", "Public"} {
		if p != sshProfile {
			return p
		}
	}
	t.Fatalf("no non-SSH profile available (SSH profile %q)", sshProfile)
	return ""
}

// TestAccWindowsFirewallProfile_Basic — tune logging settings on a
// non-SSH-carrying profile + idempotency.
func TestAccWindowsFirewallProfile_Basic(t *testing.T) {
	testAccFirewallProfilePreCheck(t)
	target := accFirewallProfileOther(t, accFirewallProfileSSH(t))

	cfg := fmt.Sprintf(`
resource "windows_firewall_profile" "acc" {
  name                   = %[1]q
  notify_on_listen       = true
  log_max_size_kilobytes = 8192
  log_blocked            = true
}
`, target)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_firewall_profile.acc", "id", target),
					resource.TestCheckResourceAttr("windows_firewall_profile.acc", "name", target),
					resource.TestCheckResourceAttr("windows_firewall_profile.acc", "notify_on_listen", "true"),
					resource.TestCheckResourceAttr("windows_firewall_profile.acc", "log_max_size_kilobytes", "8192"),
					resource.TestCheckResourceAttr("windows_firewall_profile.acc", "log_blocked", "true"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsFirewallProfile_UpdateInPlace — logging settings converge
// without replacing the profile (name is the ForceNew identity).
func TestAccWindowsFirewallProfile_UpdateInPlace(t *testing.T) {
	testAccFirewallProfilePreCheck(t)
	target := accFirewallProfileOther(t, accFirewallProfileSSH(t))

	cfg := func(size, blocked string) string {
		return fmt.Sprintf(`
resource "windows_firewall_profile" "upd" {
  name                   = %[1]q
  log_max_size_kilobytes = %[2]s
  log_blocked            = %[3]s
}
`, target, size, blocked)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("8192", "true"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_firewall_profile.upd", "log_max_size_kilobytes", "8192"),
					resource.TestCheckResourceAttr("windows_firewall_profile.upd", "log_blocked", "true"),
				),
			},
			{
				Config: cfg("16384", "false"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_firewall_profile.upd", "log_max_size_kilobytes", "16384"),
					resource.TestCheckResourceAttr("windows_firewall_profile.upd", "log_blocked", "false"),
				),
			},
		},
	})
}

// TestAccWindowsFirewallProfile_GuardRefusesLockout — tightening the profile
// that carries the SSH session (Block inbound + disable inbound rules) is
// refused fail-closed: the step errors naming the missing rule, and a
// follow-up safe change still applies (nothing half-written).
func TestAccWindowsFirewallProfile_GuardRefusesLockout(t *testing.T) {
	testAccFirewallProfilePreCheck(t)
	sshProfile := accFirewallProfileSSH(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_firewall_profile" "guard" {
  name                   = %[1]q
  default_inbound_action = "Block"
  allow_inbound_rules    = false
}
`, sshProfile),
				ExpectError: regexp.MustCompile(`(?i)would_lock_out|Refusing to tighten`),
			},
			{
				// The refused apply left the profile untouched and manageable.
				Config: fmt.Sprintf(`
resource "windows_firewall_profile" "guard" {
  name        = %[1]q
  log_blocked = true
}
`, sshProfile),
				Check: resource.TestCheckResourceAttr("windows_firewall_profile.guard", "log_blocked", "true"),
			},
		},
	})
}

// TestAccWindowsFirewallProfile_Import — import a tuned profile by name.
func TestAccWindowsFirewallProfile_Import(t *testing.T) {
	testAccFirewallProfilePreCheck(t)
	target := accFirewallProfileOther(t, accFirewallProfileSSH(t))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_firewall_profile" "imp" {
  name        = %[1]q
  log_blocked = true
}
`, target),
			},
			{
				ResourceName:      "windows_firewall_profile.imp",
				ImportState:       true,
				ImportStateId:     target,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccWindowsFirewallProfile_RestoreOnDestroy — a change made with
// restore_on_destroy is reverted when the resource is destroyed: dropping the
// resource from config restores the pre-existing log size, observed through
// the sibling data source.
func TestAccWindowsFirewallProfile_RestoreOnDestroy(t *testing.T) {
	testAccFirewallProfilePreCheck(t)
	target := accFirewallProfileOther(t, accFirewallProfileSSH(t))

	c := accFirewallProfileClient(t)
	pre, err := c.Read(context.Background(), target)
	if err != nil {
		t.Fatalf("pre-existing read: %v", err)
	}
	if pre == nil {
		t.Fatalf("profile %q not found on the target host", target)
	}
	observed := pre.LogMaxSizeKilobytes
	changed := int64(8192)
	if observed == changed {
		changed = 16384
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_firewall_profile" "rst" {
  name                   = %[1]q
  log_max_size_kilobytes = %[2]d
  restore_on_destroy     = true
}
`, target, changed),
				Check: resource.TestCheckResourceAttr("windows_firewall_profile.rst", "log_max_size_kilobytes", fmt.Sprintf("%d", changed)),
			},
			{
				// Removing the resource destroys it: restore_on_destroy
				// re-applies the pre-existing size, which the data source
				// then observes.
				Config: fmt.Sprintf(`
data "windows_firewall_profile" "rst" {
  name = %[1]q
}
`, target),
				Check: resource.TestCheckResourceAttr("data.windows_firewall_profile.rst", "log_max_size_kilobytes", fmt.Sprintf("%d", observed)),
			},
		},
	})
}
