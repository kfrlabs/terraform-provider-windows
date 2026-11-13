//go:build acceptance

// Package provider — acceptance tests for windows_eventlog.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled.
//
// Logs always exist, so every test tunes a log in place and (by default)
// leaves the host exactly as it found it: CRUD steps carry
// restore_on_destroy so destroy re-applies the pre-existing size and
// retention, and the restore_on_destroy step reverts its own change on
// destroy.
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

func testAccEventLogPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// accEventLogClient builds a direct winclient for out-of-band reads, which
// is the only way to observe pre-existing values. ResolveFromEnv is
// intentional here: the public-key CI leg clears WINDOWS_PASSWORD and
// provides WINDOWS_PRIVATE_KEY_PATH instead.
func accEventLogClient(t *testing.T) *winclient.EventLogClient {
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
	return winclient.NewEventLogClient(c)
}

// accEventLogChangedSize returns a valid log size (1 MiB floor, 64 KiB
// multiple) that differs from the observed maximum, so the apply always
// exercises a real change.
func accEventLogChangedSize(t *testing.T, observed int64) int64 {
	t.Helper()
	for _, candidate := range []int64{33554432, 67108864, 20971520} {
		if candidate != observed {
			return candidate
		}
	}
	t.Fatalf("no changed size candidate differs from observed %d", observed)
	return 33554432
}

// TestAccWindowsEventLog_Basic — tune the Application log size + retention
// in place + idempotency.
func TestAccWindowsEventLog_Basic(t *testing.T) {
	testAccEventLogPreCheck(t)

	pre, err := accEventLogClient(t).Read(context.Background(), "Application")
	if err != nil {
		t.Fatalf("pre-existing read: %v", err)
	}
	if pre == nil {
		t.Fatal("Application log not found on the target host")
	}
	changed := accEventLogChangedSize(t, pre.MaximumSizeBytes)

	cfg := fmt.Sprintf(`
resource "windows_eventlog" "acc" {
  name                  = "Application"
  maximum_size_bytes    = %[1]d
  retention             = "archive"
  restore_on_destroy    = true
}
`, changed)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_eventlog.acc", "id", "Application"),
					resource.TestCheckResourceAttr("windows_eventlog.acc", "name", "Application"),
					resource.TestCheckResourceAttr("windows_eventlog.acc", "maximum_size_bytes", fmt.Sprintf("%d", changed)),
					resource.TestCheckResourceAttr("windows_eventlog.acc", "retention", "archive"),
					resource.TestCheckResourceAttr("windows_eventlog.acc", "is_classic_log", "true"),
					resource.TestCheckResourceAttr("windows_eventlog.acc", "log_type", "Administrative"),
					resource.TestCheckResourceAttrSet("windows_eventlog.acc", "record_count"),
					resource.TestCheckResourceAttrSet("windows_eventlog.acc", "file_size_bytes"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsEventLog_ModernChannel — a channel name containing "/" is a
// literal log name, never a path: enable + size the PowerShell Operational
// channel in place.
func TestAccWindowsEventLog_ModernChannel(t *testing.T) {
	testAccEventLogPreCheck(t)
	const channel = "Microsoft-Windows-PowerShell/Operational"

	pre, err := accEventLogClient(t).Read(context.Background(), channel)
	if err != nil {
		t.Fatalf("pre-existing read: %v", err)
	}
	if pre == nil {
		t.Skipf("channel %q not found on the target host; skipping", channel)
	}
	changed := accEventLogChangedSize(t, pre.MaximumSizeBytes)

	cfg := fmt.Sprintf(`
resource "windows_eventlog" "ps" {
  name                  = %[1]q
  enabled               = true
  maximum_size_bytes    = %[2]d
  restore_on_destroy    = true
}
`, channel, changed)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_eventlog.ps", "id", channel),
					resource.TestCheckResourceAttr("windows_eventlog.ps", "name", channel),
					resource.TestCheckResourceAttr("windows_eventlog.ps", "enabled", "true"),
					resource.TestCheckResourceAttr("windows_eventlog.ps", "is_classic_log", "false"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsEventLog_UpdateInPlace — size and retention converge without
// replacing the log (name is the ForceNew identity).
func TestAccWindowsEventLog_UpdateInPlace(t *testing.T) {
	testAccEventLogPreCheck(t)

	pre, err := accEventLogClient(t).Read(context.Background(), "Application")
	if err != nil {
		t.Fatalf("pre-existing read: %v", err)
	}
	if pre == nil {
		t.Fatal("Application log not found on the target host")
	}
	first := accEventLogChangedSize(t, pre.MaximumSizeBytes)
	second := int64(33554432)
	if second == first {
		second = 67108864
	}

	cfg := func(size int64, retention string) string {
		return fmt.Sprintf(`
resource "windows_eventlog" "upd" {
  name                  = "Application"
  maximum_size_bytes    = %[1]d
  retention             = %[2]q
  restore_on_destroy    = true
}
`, size, retention)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg(first, "archive"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_eventlog.upd", "maximum_size_bytes", fmt.Sprintf("%d", first)),
					resource.TestCheckResourceAttr("windows_eventlog.upd", "retention", "archive"),
				),
			},
			{
				Config: cfg(second, "overwrite"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_eventlog.upd", "maximum_size_bytes", fmt.Sprintf("%d", second)),
					resource.TestCheckResourceAttr("windows_eventlog.upd", "retention", "overwrite"),
				),
			},
		},
	})
}

// TestAccWindowsEventLog_RestoreOnDestroy — a change made with
// restore_on_destroy is reverted when the resource is destroyed: dropping
// the resource from config restores the pre-existing size and retention,
// observed through the sibling data source.
func TestAccWindowsEventLog_RestoreOnDestroy(t *testing.T) {
	testAccEventLogPreCheck(t)

	c := accEventLogClient(t)
	pre, err := c.Read(context.Background(), "Application")
	if err != nil {
		t.Fatalf("pre-existing read: %v", err)
	}
	if pre == nil {
		t.Fatal("Application log not found on the target host")
	}
	observedSize := pre.MaximumSizeBytes
	observedRetention := winclient.EventLogLogModeToRetention(pre.LogMode)
	changed := accEventLogChangedSize(t, observedSize)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_eventlog" "rst" {
  name                  = "Application"
  maximum_size_bytes    = %[1]d
  restore_on_destroy    = true
}
`, changed),
				Check: resource.TestCheckResourceAttr("windows_eventlog.rst", "maximum_size_bytes", fmt.Sprintf("%d", changed)),
			},
			{
				// Removing the resource destroys it: restore_on_destroy
				// re-applies the pre-existing values, which the data
				// source then observes.
				Config: `
data "windows_eventlog" "rst" {
  name = "Application"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_eventlog.rst", "maximum_size_bytes", fmt.Sprintf("%d", observedSize)),
					resource.TestCheckResourceAttr("data.windows_eventlog.rst", "retention", observedRetention),
				),
			},
		},
	})
}

// TestAccWindowsEventLog_Import — import the Application log by exact name.
func TestAccWindowsEventLog_Import(t *testing.T) {
	testAccEventLogPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_eventlog" "imp" {
  name               = "Application"
  retention          = "overwrite"
  restore_on_destroy = true
}
`,
			},
			{
				ResourceName:      "windows_eventlog.imp",
				ImportState:       true,
				ImportStateId:     "Application",
				ImportStateVerify: true,
				// Counters move as the live log receives events between
				// the import read and the verify refresh.
				ImportStateVerifyIgnore: []string{"record_count", "file_size_bytes"},
			},
		},
	})
}

// TestAccWindowsEventLog_NotFound — a bogus log name fails closed with a
// not_found diagnostic.
func TestAccWindowsEventLog_NotFound(t *testing.T) {
	testAccEventLogPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_eventlog" "missing" {
  name               = "NoSuchLog-Definitely-Missing"
  maximum_size_bytes = 20971520
}
`,
				ExpectError: regexp.MustCompile(`(?i)not[_\s-]found|was not found`),
			},
		},
	})
}
