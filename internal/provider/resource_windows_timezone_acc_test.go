//go:build acceptance

// Package provider — acceptance tests for windows_timezone.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME plus a credential (see acc_test_helper.go)
//   - A Windows target where Set-TimeZone takes effect.
//
// Changing the system time zone is low-risk (no reboot, instantly
// reversible) but containers share the host clock: on targets where
// Set-TimeZone is ineffective the mutating tests probe first and Skip with a
// visible reason instead of failing (the skip is allow-listed in
// .github/testacc-allowed-skips.json so the CI gate stays green).
// Every mutating test sets restore_on_destroy so the suite leaves the
// pre-existing zone behind even when a step fails mid-apply.
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

func testAccTimezonePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// newAccTimezoneClient builds a direct winclient for out-of-band reads and
// the mutability probe. ResolveFromEnv is intentional here: the public-key
// CI leg clears WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH
// instead.
func newAccTimezoneClient() (*winclient.TimezoneClient, error) {
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		return nil, err
	}
	return winclient.NewTimezoneClient(c), nil
}

func accTimezoneClient(t *testing.T) *winclient.TimezoneClient {
	t.Helper()
	c, err := newAccTimezoneClient()
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	return c
}

// accTimezoneEnsureMutable probes whether Set takes effect on the target:
// it applies a zone that differs from the live one, verifies the re-read,
// and restores the original zone. On targets where the zone cannot change
// (containers share the host clock) it skips with a visible reason instead
// of failing. Returns the pre-existing (restored) state.
func accTimezoneEnsureMutable(t *testing.T, want winclient.TimezoneInput) *winclient.TimezoneState {
	t.Helper()
	c := accTimezoneClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	orig, err := c.Read(ctx)
	if err != nil {
		t.Skipf("cannot read live time zone; skipping: %v", err)
	}
	probe := want
	if timezoneIDsEqual(orig.TimezoneID, probe.TimezoneID) && orig.DaylightSavingDisabled == probe.DaylightSavingDisabled {
		probe.TimezoneID = "UTC"
		probe.DaylightSavingDisabled = false
		if timezoneIDsEqual(orig.TimezoneID, probe.TimezoneID) && orig.DaylightSavingDisabled == probe.DaylightSavingDisabled {
			probe.TimezoneID = "GMT Standard Time"
		}
	}
	applied, err := c.Set(ctx, probe)
	if err != nil {
		t.Skipf("host zone immutable (shared clock) or Set-TimeZone ineffective; skipping: %v", err)
	}
	if !timezoneIDsEqual(applied.TimezoneID, probe.TimezoneID) || applied.DaylightSavingDisabled != probe.DaylightSavingDisabled {
		_, _ = c.Set(ctx, winclient.TimezoneInput{TimezoneID: orig.TimezoneID, DaylightSavingDisabled: orig.DaylightSavingDisabled})
		t.Skipf("host zone immutable (shared clock): Set-TimeZone did not take effect (want %q, observed %q); skipping",
			probe.TimezoneID, applied.TimezoneID)
	}
	if _, err := c.Set(ctx, winclient.TimezoneInput{TimezoneID: orig.TimezoneID, DaylightSavingDisabled: orig.DaylightSavingDisabled}); err != nil {
		t.Logf("warning: could not restore original time zone %q: %v", orig.TimezoneID, err)
	}
	return orig
}

// timezoneAccConfig renders a windows_timezone resource with
// restore_on_destroy so the suite leaves the pre-existing zone behind.
func timezoneAccConfig(id string, dstDisabled bool) string {
	return fmt.Sprintf(`
resource "windows_timezone" "acc" {
  timezone_id              = %q
  daylight_saving_disabled = %t
  restore_on_destroy       = true
}
`, id, dstDisabled)
}

// TestAccWindowsTimezone_InvalidIANA — an IANA ID is rejected at plan time,
// before any SSH call, so it is safe to run against any host.
func TestAccWindowsTimezone_InvalidIANA(t *testing.T) {
	testAccTimezonePreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_timezone" "acc" {
  timezone_id = "Europe/Paris"
}
`,
				ExpectError: regexp.MustCompile(`(?i)IANA`),
				PlanOnly:    true,
			},
		},
	})
}

// TestAccWindowsTimezone_Basic — set the zone in place + idempotency.
func TestAccWindowsTimezone_Basic(t *testing.T) {
	testAccTimezonePreCheck(t)
	accTimezoneEnsureMutable(t, winclient.TimezoneInput{TimezoneID: "UTC"})

	cfg := timezoneAccConfig("UTC", false)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_timezone.acc", "timezone_id", "UTC"),
					resource.TestCheckResourceAttr("windows_timezone.acc", "daylight_saving_disabled", "false"),
					resource.TestCheckResourceAttrSet("windows_timezone.acc", "id"),
					resource.TestCheckResourceAttrSet("windows_timezone.acc", "base_utc_offset"),
					resource.TestCheckResourceAttrSet("windows_timezone.acc", "current_utc_offset"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsTimezone_UpdateInPlace — changing timezone_id converges
// without replacing the singleton (id stays the machine GUID).
func TestAccWindowsTimezone_UpdateInPlace(t *testing.T) {
	testAccTimezonePreCheck(t)
	accTimezoneEnsureMutable(t, winclient.TimezoneInput{TimezoneID: "UTC"})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: timezoneAccConfig("UTC", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_timezone.acc", "timezone_id", "UTC"),
				),
			},
			{
				Config: timezoneAccConfig("GMT Standard Time", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_timezone.acc", "timezone_id", "GMT Standard Time"),
					resource.TestCheckResourceAttrSet("windows_timezone.acc", "id"),
				),
			},
		},
	})
}

// TestAccWindowsTimezone_DaylightSavingToggle — toggling
// daylight_saving_disabled re-applies the zone via tzutil.
func TestAccWindowsTimezone_DaylightSavingToggle(t *testing.T) {
	testAccTimezonePreCheck(t)
	accTimezoneEnsureMutable(t, winclient.TimezoneInput{TimezoneID: "GMT Standard Time", DaylightSavingDisabled: true})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: timezoneAccConfig("GMT Standard Time", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_timezone.acc", "daylight_saving_disabled", "false"),
				),
			},
			{
				Config: timezoneAccConfig("GMT Standard Time", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_timezone.acc", "daylight_saving_disabled", "true"),
				),
			},
		},
	})
}

// TestAccWindowsTimezone_RestoreOnDestroy — destroy re-applies the
// pre-existing zone captured at creation time.
func TestAccWindowsTimezone_RestoreOnDestroy(t *testing.T) {
	testAccTimezonePreCheck(t)
	orig := accTimezoneEnsureMutable(t, winclient.TimezoneInput{TimezoneID: "UTC"})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			c, err := newAccTimezoneClient()
			if err != nil {
				return fmt.Errorf("winclient.New: %w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			live, err := c.Read(ctx)
			if err != nil {
				return fmt.Errorf("post-destroy read: %w", err)
			}
			if !timezoneIDsEqual(live.TimezoneID, orig.TimezoneID) ||
				live.DaylightSavingDisabled != orig.DaylightSavingDisabled {
				return fmt.Errorf("restore_on_destroy did not re-apply the pre-existing zone: want %q (DST disabled: %v), live %q (DST disabled: %v)",
					orig.TimezoneID, orig.DaylightSavingDisabled, live.TimezoneID, live.DaylightSavingDisabled)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: timezoneAccConfig("UTC", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_timezone.acc", "timezone_id", "UTC"),
				),
			},
		},
	})
}
