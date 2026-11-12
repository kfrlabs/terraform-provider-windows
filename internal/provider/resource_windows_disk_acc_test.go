//go:build acceptance

// Package provider — acceptance tests for windows_disk (resource + data source).
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//     (see acc_test_helper.go)
//   - WINDOWS_ACC_STORAGE=1 (extra gate: these tests attach real — albeit
//     throwaway — virtual disks, so they stay off unless explicitly enabled)
//   - A Windows *Server* target with diskpart available and Local
//     Administrator rights for the SSH user (diskpart attach, Initialize-Disk
//     and Set-Disk all require elevation).
//
// SAFETY: every test creates its own throwaway dynamically-expanding 64 MiB
// VHDX under C:\TF-Acc-Disk, attaches it via diskpart (a RAW data disk —
// never the boot/system disk), and detaches + deletes the VHDX in t.Cleanup.
// windows_disk Delete is state-only (it makes no remote call), so the
// CheckDestroy assertion below verifies the disk is still present after
// destroy and the t.Cleanup detach/delete is what actually releases the
// fixture — even when the test fails.
package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// diskTestDir confines every VHDX fixture to one throwaway directory.
const diskTestDir = `C:\TF-Acc-Disk`

func testAccDiskPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
	if os.Getenv("WINDOWS_ACC_STORAGE") != "1" {
		t.Skip("WINDOWS_ACC_STORAGE != 1; skipping storage acceptance test " +
			"(requires attaching a throwaway VHDX on the target host)")
	}
}

// accDiskClient builds a direct winclient for fixture setup/teardown and
// destroy assertions. ResolveFromEnv is intentional here: the public-key CI
// leg clears WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH instead.
func accDiskClient(t *testing.T) *winclient.Client {
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
	return c
}

// testAccDiskFixture is a throwaway VHDX attached to the target host.
type testAccDiskFixture struct {
	// VHDX is the fixture file path on the target (e.g. C:\TF-Acc-Disk\...).
	VHDX string
	// UniqueID is the Get-Disk UniqueId of the attached disk (the adoption key).
	UniqueID string
}

// testAccDiskCreateVHDX creates a 64 MiB dynamic VHDX on the target, attaches
// it via diskpart (a RAW data disk) and returns its Get-Disk identity.
// Detach + file delete are registered on t.Cleanup first, so the fixture is
// released even when the test fails.
func testAccDiskCreateVHDX(t *testing.T) testAccDiskFixture {
	t.Helper()

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand: %v", err)
	}
	vhdx := diskTestDir + `\tfacc-` + hex.EncodeToString(suffix) + `.vhdx`

	c := accDiskClient(t)
	t.Cleanup(func() { _ = c.Close() })

	// Detach/delete first: cleanup must run even if attach below fails.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		script := fmt.Sprintf(`$ErrorActionPreference = 'Continue'
"select vdisk file=`+"`\"%s`\""+`
detach vdisk" | diskpart | Out-Null
if (Test-Path '%s') { Remove-Item '%s' -Force }`, vhdx, vhdx, vhdx)
		if _, stderr, err := c.RunPowerShell(ctx, script); err != nil {
			t.Logf("cleanup of VHDX fixture %s: %v (stderr: %s)", vhdx, err, stderr)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	attach := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$vhdx = '%s'
New-Item -ItemType Directory -Force -Path (Split-Path $vhdx) | Out-Null
if (Test-Path $vhdx) { Remove-Item $vhdx -Force }
"create vdisk file=`+"`\"$vhdx`\""+` maximum=64 type=expandable
select vdisk file=`+"`\"$vhdx`\""+`
attach vdisk" | diskpart | Out-Null
$base = [IO.Path]::GetFileNameWithoutExtension($vhdx)
$disk = Get-Disk | Where-Object { $_.Location -like ('*' + $base + '*') } | Select-Object -First 1
if (-not $disk) {
  Get-Disk | Format-Table Number, FriendlyName, Location, PartitionStyle, IsBoot, IsSystem -AutoSize | Out-String | Write-Host
  throw "attached VHDX is not visible via Get-Disk: $vhdx"
}
[Console]::Out.WriteLine($disk.UniqueId)
[Console]::Out.WriteLine($disk.Number)
[Console]::Out.WriteLine($disk.PartitionStyle)`, vhdx)
	stdout, stderr, err := c.RunPowerShell(ctx, attach)
	if err != nil {
		t.Fatalf("create/attach VHDX fixture %s: %v (stderr: %s)", vhdx, err, stderr)
	}
	lines := []string{}
	for _, l := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			lines = append(lines, s)
		}
	}
	if len(lines) < 3 {
		t.Fatalf("attach output has %d lines, want UniqueId/Number/PartitionStyle: %q", len(lines), stdout)
	}
	uniqueID, style := lines[len(lines)-3], lines[len(lines)-1]
	if uniqueID == "" {
		t.Fatalf("attached VHDX has an empty UniqueId: %q", stdout)
	}
	if _, err := strconv.Atoi(strings.TrimSpace(lines[len(lines)-2])); err != nil {
		t.Fatalf("attached VHDX disk number is not numeric: %q", stdout)
	}
	if !strings.EqualFold(strings.TrimSpace(style), "RAW") {
		t.Fatalf("freshly attached VHDX should be RAW, got %q (fixture: %s)", style, vhdx)
	}
	return testAccDiskFixture{VHDX: vhdx, UniqueID: uniqueID}
}

// testAccCheckDiskAdoptionReleased returns a CheckDestroy func asserting the
// fixture disk still exists after destroy: windows_disk Delete only drops the
// adoption from state and makes no remote call, so the disk and its data must
// be left untouched (the t.Cleanup detach/delete releases the VHDX after).
func testAccCheckDiskAdoptionReleased(uniqueID string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		cfg := winclient.Config{Timeout: 60 * time.Second}
		winclient.ResolveFromEnv(&cfg)
		if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
			cfg.InsecureIgnoreHostKey = true
		}
		c, err := winclient.New(cfg)
		if err != nil {
			return fmt.Errorf("winclient.New: %w", err)
		}
		defer func() { _ = c.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		info, err := winclient.NewDiskClient(c).Read(ctx, winclient.DiskSelectorByUniqueID(uniqueID))
		if err != nil {
			return fmt.Errorf("re-read of fixture disk after destroy: %w", err)
		}
		if info == nil {
			return fmt.Errorf("fixture disk %q is gone after destroy: Delete must be state-only", uniqueID)
		}
		return nil
	}
}

// testAccDiskFixtureConfig renders a windows_disk adoption of the fixture by
// its stable UniqueId (initializing the RAW disk to GPT, online, with the
// given read-only flag) plus a data source round-trip over the same disk.
func testAccDiskFixtureConfig(uniqueID string, readOnly bool) string {
	return fmt.Sprintf(`
resource "windows_disk" "acc" {
  unique_id       = %q
  partition_style = "GPT"
  is_offline      = false
  is_read_only    = %t
}

data "windows_disk" "ds" {
  unique_id = windows_disk.acc.unique_id
}
`, uniqueID, readOnly)
}

// TestAccWindowsDisk_VHDXLifecycle — attach a throwaway VHDX, adopt it by
// unique_id, initialize the RAW disk to GPT, assert computed attributes and
// the data source round-trip, prove idempotency, toggle is_read_only
// in-place, and assert destroy only releases the adoption (disk untouched).
func TestAccWindowsDisk_VHDXLifecycle(t *testing.T) {
	testAccDiskPreCheck(t)
	fix := testAccDiskCreateVHDX(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDiskAdoptionReleased(fix.UniqueID),
		Steps: []resource.TestStep{
			{
				Config: testAccDiskFixtureConfig(fix.UniqueID, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_disk.acc", "id", fix.UniqueID),
					resource.TestCheckResourceAttr("windows_disk.acc", "unique_id", fix.UniqueID),
					resource.TestCheckResourceAttr("windows_disk.acc", "partition_style", "GPT"),
					resource.TestCheckResourceAttr("windows_disk.acc", "is_offline", "false"),
					resource.TestCheckResourceAttr("windows_disk.acc", "is_read_only", "false"),
					resource.TestCheckResourceAttrWith("windows_disk.acc", "size_bytes",
						func(v string) error {
							n, err := strconv.ParseInt(v, 10, 64)
							if err != nil {
								return fmt.Errorf("size_bytes %q is not numeric: %w", v, err)
							}
							if n <= 0 {
								return fmt.Errorf("size_bytes = %d, want > 0", n)
							}
							return nil
						}),
					resource.TestCheckResourceAttrPair(
						"data.windows_disk.ds", "id", "windows_disk.acc", "id"),
					resource.TestCheckResourceAttrPair(
						"data.windows_disk.ds", "partition_style", "windows_disk.acc", "partition_style"),
				),
			},
			{
				// A re-apply of the same config must be a no-op.
				Config:   testAccDiskFixtureConfig(fix.UniqueID, false),
				PlanOnly: true,
			},
			{
				// In-place update: only is_offline / is_read_only are mutable.
				Config: testAccDiskFixtureConfig(fix.UniqueID, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_disk.acc", "is_read_only", "true"),
					resource.TestCheckResourceAttrPair(
						"data.windows_disk.ds", "is_read_only", "windows_disk.acc", "is_read_only"),
				),
			},
			{
				Config:   testAccDiskFixtureConfig(fix.UniqueID, true),
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsDisk_ImportByUniqueID — import an attached VHDX by its
// UniqueId. ImportStateVerify stays off on purpose: an apply carries null
// serial_number/location/number spellings (only unique_id was configured)
// while import records the observed values, so the states legitimately
// differ; the id check pins the adoption identity instead.
func TestAccWindowsDisk_ImportByUniqueID(t *testing.T) {
	testAccDiskPreCheck(t)
	fix := testAccDiskCreateVHDX(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDiskAdoptionReleased(fix.UniqueID),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_disk" "imp" {
  unique_id       = %q
  partition_style = "GPT"
}
`, fix.UniqueID),
			},
			{
				ResourceName:      "windows_disk.imp",
				ImportState:       true,
				ImportStateId:     fix.UniqueID,
				ImportStateVerify: false,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_disk.imp", "id", fix.UniqueID),
					resource.TestCheckResourceAttr("windows_disk.imp", "unique_id", fix.UniqueID),
					resource.TestCheckResourceAttr("windows_disk.imp", "partition_style", "GPT"),
				),
			},
		},
	})
}
