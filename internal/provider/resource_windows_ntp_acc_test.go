//go:build acceptance

// Package provider — acceptance tests for windows_ntp.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME plus a credential (see acc_test_helper.go)
//   - A Windows target with the W32Time service registered.
//
// Changing the time source is low-risk (registry writes plus
// w32tm /config /update, instantly reversible) but containers typically
// ship no W32Time service at all: on targets without one the suite skips
// with a visible reason instead of failing (the skip is allow-listed in
// .github/testacc-allowed-skips.json so the CI gate stays green).
// Every mutating test sets restore_on_destroy so the suite leaves the
// pre-existing time source behind even when a step fails mid-apply.
package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccNTPPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// newAccNTPClient builds a direct winclient for out-of-band reads and the
// mutability probe. ResolveFromEnv is intentional here: the public-key
// CI leg clears WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH
// instead.
func newAccNTPClient() (*winclient.NTPClient, error) {
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		return nil, err
	}
	return winclient.NewNTPClient(c), nil
}

func accNTPClient(t *testing.T) *winclient.NTPClient {
	t.Helper()
	c, err := newAccNTPClient()
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	return c
}

// accNTPEnsureMutable probes whether Set takes effect on the target: it
// reads the live state, writes it back verbatim (a harmless no-op apply
// plus /config /update) and returns the pre-existing state. The probe runs
// with manage_service=false so it never changes the W32Time service
// StartupType or starts the service as a side effect. On targets without
// W32Time (containers share the host clock and ship no time service) it
// skips with a visible reason instead of failing.
func accNTPEnsureMutable(t *testing.T) *winclient.NTPState {
	t.Helper()
	c := accNTPClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	orig, err := c.Read(ctx)
	if err != nil {
		t.Skipf("W32Time unavailable on target (%v); skipping", err)
	}
	probe := winclient.NTPInput{
		Type:                         orig.Type,
		Servers:                      orig.Servers,
		SpecialPollIntervalSeconds:   &orig.SpecialPollIntervalSeconds,
		AnnounceFlags:                &orig.AnnounceFlags,
		NtpServerEnabled:             &orig.NtpServerEnabled,
		MaxPosPhaseCorrectionSeconds: &orig.MaxPosPhaseCorrectionSeconds,
		MaxNegPhaseCorrectionSeconds: &orig.MaxNegPhaseCorrectionSeconds,
		ManageService:                false,
		ResyncOnApply:                false,
	}
	if _, err := c.Set(ctx, probe); err != nil {
		t.Skipf("W32Time not mutable on target (%v); skipping", err)
	}
	return orig
}

// ntpAccConfig renders a windows_ntp resource with restore_on_destroy so
// the suite leaves the pre-existing time source behind.
func ntpAccConfig(typ, serversHCL string, poll int64) string {
	return fmt.Sprintf(`
resource "windows_ntp" "acc" {
  type = %q

  servers = [%s]

  special_poll_interval_seconds = %d
  restore_on_destroy            = true
}
`, typ, serversHCL, poll)
}

const ntpAccServersHCL = `
    { address = "0.fr.pool.ntp.org" },
    { address = "1.fr.pool.ntp.org", flags = "0x1" },
`

// TestAccWindowsNTP_TypeServersMatrix — NT5DS with peers is rejected at
// plan time, before any SSH call, so it is safe to run against any host.
func TestAccWindowsNTP_TypeServersMatrix(t *testing.T) {
	testAccNTPPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_ntp" "acc" {
  type = "NT5DS"

  servers = [
    { address = "0.fr.pool.ntp.org" },
  ]
}
`,
				ExpectError: regexp.MustCompile(`(?i)Servers forbidden`),
				PlanOnly:    true,
			},
			{
				Config: `
resource "windows_ntp" "acc" {
  type = "NTP"
}
`,
				ExpectError: regexp.MustCompile(`(?i)Missing NTP servers`),
				PlanOnly:    true,
			},
		},
	})
}

// TestAccWindowsNTP_Basic — set the time source in place + idempotency.
func TestAccWindowsNTP_Basic(t *testing.T) {
	testAccNTPPreCheck(t)
	accNTPEnsureMutable(t)

	cfg := ntpAccConfig("NTP", ntpAccServersHCL, 900)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_ntp.acc", "type", "NTP"),
					resource.TestCheckResourceAttr("windows_ntp.acc", "servers.0.address", "0.fr.pool.ntp.org"),
					resource.TestCheckResourceAttr("windows_ntp.acc", "servers.0.flags", "0x9"),
					resource.TestCheckResourceAttr("windows_ntp.acc", "servers.1.flags", "0x1"),
					resource.TestCheckResourceAttr("windows_ntp.acc", "special_poll_interval_seconds", "900"),
					resource.TestCheckResourceAttrSet("windows_ntp.acc", "id"),
					resource.TestCheckResourceAttrSet("windows_ntp.acc", "current_source"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsNTP_UpdatePollInterval — changing the poll interval
// converges without replacing the singleton (id stays the machine GUID).
func TestAccWindowsNTP_UpdatePollInterval(t *testing.T) {
	testAccNTPPreCheck(t)
	accNTPEnsureMutable(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: ntpAccConfig("NTP", ntpAccServersHCL, 900),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_ntp.acc", "special_poll_interval_seconds", "900"),
				),
			},
			{
				Config: ntpAccConfig("NTP", ntpAccServersHCL, 3600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_ntp.acc", "special_poll_interval_seconds", "3600"),
					resource.TestCheckResourceAttrSet("windows_ntp.acc", "id"),
				),
			},
		},
	})
}

// TestAccWindowsNTP_ServerToggle — toggling the NTP server role writes
// TimeProviders\NtpServer\Enabled in place.
func TestAccWindowsNTP_ServerToggle(t *testing.T) {
	testAccNTPPreCheck(t)
	accNTPEnsureMutable(t)

	render := func(enabled bool) string {
		return fmt.Sprintf(`
resource "windows_ntp" "acc" {
  type = "NTP"

  servers = [
    { address = "0.fr.pool.ntp.org" },
  ]

  ntp_server_enabled = %t
  restore_on_destroy = true
}
`, enabled)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: render(false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_ntp.acc", "ntp_server_enabled", "false"),
				),
			},
			{
				Config: render(true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_ntp.acc", "ntp_server_enabled", "true"),
				),
			},
		},
	})
}

// TestAccWindowsNTP_RestoreOnDestroy — destroy re-applies the pre-existing
// time source captured at creation time.
func TestAccWindowsNTP_RestoreOnDestroy(t *testing.T) {
	testAccNTPPreCheck(t)
	orig := accNTPEnsureMutable(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			c, err := newAccNTPClient()
			if err != nil {
				return fmt.Errorf("winclient.New: %w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			live, err := c.Read(ctx)
			if err != nil {
				return fmt.Errorf("post-destroy read: %w", err)
			}
			if live.Type != orig.Type {
				return fmt.Errorf("restore_on_destroy did not re-apply the pre-existing type: want %q, live %q", orig.Type, live.Type)
			}
			if !winclient.NTPPeersEqual(live.Servers, orig.Servers) {
				return fmt.Errorf("restore_on_destroy did not re-apply the pre-existing peers: want %+v, live %+v", orig.Servers, live.Servers)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: ntpAccConfig("NTP", ntpAccServersHCL, 900),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_ntp.acc", "type", "NTP"),
				),
			},
		},
	})
}
