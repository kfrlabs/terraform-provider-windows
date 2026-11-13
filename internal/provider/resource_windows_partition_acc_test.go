//go:build acceptance

// Package provider — acceptance tests for windows_partition (resource).
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//     (see acc_test_helper.go)
//   - WINDOWS_ACC_STORAGE=1 (extra gate shared with windows_disk: these
//     tests attach real — albeit throwaway — virtual disks, so they stay off
//     unless explicitly enabled)
//   - A Windows *Server* target with diskpart available and Local
//     Administrator rights for the SSH user (diskpart attach, Initialize-Disk
//     and the partition cmdlets all require elevation).
//
// SAFETY: every test creates its own throwaway dynamically-expanding 64 MiB
// VHDX under C:\TF-Acc-Disk (see resource_windows_disk_acc_test.go), attaches
// it via diskpart (a RAW data disk — never the boot/system disk),
// initializes it to GPT or MBR out of band, and detaches + deletes the VHDX
// in t.Cleanup. windows_partition Delete destroys the partition for real, so
// the CheckDestroy assertion below verifies the partition is gone after
// destroy (while the hosting disk is still present; the t.Cleanup
// detach/delete is what actually releases the fixture — even when the test
// fails).
package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// testAccPartitionInitDisk initializes the attached fixture disk to style
// ("GPT" or "MBR") through the public winclient disk client.
func testAccPartitionInitDisk(t *testing.T, uniqueID, style string) {
	t.Helper()
	c := accDiskClient(t)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := winclient.NewDiskClient(c).Initialize(ctx, uniqueID, style); err != nil {
		t.Fatalf("initialize fixture disk %s to %s: %v", uniqueID, style, err)
	}
}

// testAccPartitionFreeLetters returns n drive letters that are currently
// unassigned on the target host, scanning E-Z (C is the system disk, D is
// commonly taken, and A/B are floppy-reserved and rejected anyway).
func testAccPartitionFreeLetters(t *testing.T, n int) []string {
	t.Helper()
	c := accDiskClient(t)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	stdout, _, err := c.RunPowerShell(ctx, `$ErrorActionPreference = 'Stop'
Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object { ([string]$_.DriveLetter).ToUpperInvariant() }`)
	if err != nil {
		t.Fatalf("list volumes for a free drive letter: %v", err)
	}
	used := map[string]bool{}
	for _, l := range strings.Fields(strings.ToUpper(stdout)) {
		used[l] = true
	}
	var free []string
	for ch := 'E'; ch <= 'Z' && len(free) < n; ch++ {
		if !used[string(ch)] {
			free = append(free, string(ch))
		}
	}
	if len(free) < n {
		t.Fatalf("only %d free drive letters on the target, need %d (used: %v)", len(free), n, used)
	}
	return free
}

// testAccPartitionFixtureConfig renders a windows_partition with an explicit
// size and letter; extra carries type lines such as `gpt_type = "basic_data"`.
func testAccPartitionFixtureConfig(uniqueID string, sizeBytes int64, letter, extra string) string {
	return fmt.Sprintf(`
resource "windows_partition" "acc" {
  disk_unique_id = %q
  size_bytes     = %d
  drive_letter   = %q
%s
}
`, uniqueID, sizeBytes, letter, extra)
}

// testAccCheckPartitionDestroyed returns a CheckDestroy func asserting the
// partition recorded in lastID is gone (Delete destroys it for real) while
// the hosting disk is still present (Delete must never touch the disk).
func testAccCheckPartitionDestroyed(uniqueID string, lastID *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if lastID == nil || *lastID == "" {
			return fmt.Errorf("no partition id captured; cannot verify destroy")
		}
		disk, key, err := winclient.ParsePartitionID(*lastID)
		if err != nil {
			return fmt.Errorf("parse captured partition id: %w", err)
		}
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
		info, err := winclient.NewPartitionClient(c).Read(ctx, disk, key)
		if err != nil {
			return fmt.Errorf("re-read of partition after destroy: %w", err)
		}
		if info != nil {
			return fmt.Errorf("partition %q still exists after destroy", *lastID)
		}
		diskInfo, err := winclient.NewDiskClient(c).Read(ctx, winclient.DiskSelectorByUniqueID(uniqueID))
		if err != nil {
			return fmt.Errorf("re-read of fixture disk after destroy: %w", err)
		}
		if diskInfo == nil {
			return fmt.Errorf("fixture disk %q is gone after partition destroy: Delete must not touch the disk", uniqueID)
		}
		return nil
	}
}

// capturePartitionID returns a TestCheckFunc recording the managed resource
// ID into id for the later CheckDestroy closure.
func capturePartitionID(id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources["windows_partition.acc"]
		if !ok {
			return fmt.Errorf("windows_partition.acc not in state")
		}
		*id = rs.Primary.ID
		return nil
	}
}

// TestAccWindowsPartition_GPTLifecycle — attach a throwaway VHDX, initialize
// it to GPT, carve a 16 MiB basic_data partition with a letter, prove
// idempotency, change the letter in place, grow to 32 MiB, import by id, and
// assert destroy removes the partition while the disk survives.
func TestAccWindowsPartition_GPTLifecycle(t *testing.T) {
	testAccDiskPreCheck(t)
	fix := testAccDiskCreateVHDX(t)
	testAccPartitionInitDisk(t, fix.UniqueID, "GPT")
	letters := testAccPartitionFreeLetters(t, 2)

	const size16 = int64(16777216)
	const size32 = int64(33554432)
	var lastID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckPartitionDestroyed(fix.UniqueID, &lastID),
		Steps: []resource.TestStep{
			{
				Config: testAccPartitionFixtureConfig(fix.UniqueID, size16, letters[0], "  gpt_type = \"basic_data\"\n"),
				Check: resource.ComposeTestCheckFunc(
					capturePartitionID(&lastID),
					resource.TestCheckResourceAttrWith("windows_partition.acc", "id",
						func(v string) error {
							if !strings.HasPrefix(v, fix.UniqueID+"|") || len(v) <= len(fix.UniqueID)+1 {
								return fmt.Errorf("id %q must be \"<disk_unique_id>|<guid>\"", v)
							}
							return nil
						}),
					resource.TestCheckResourceAttr("windows_partition.acc", "disk_unique_id", fix.UniqueID),
					resource.TestCheckResourceAttr("windows_partition.acc", "drive_letter", letters[0]),
					resource.TestCheckResourceAttrWith("windows_partition.acc", "size_bytes",
						func(v string) error {
							n, err := strconv.ParseInt(v, 10, 64)
							if err != nil {
								return fmt.Errorf("size_bytes %q is not numeric: %w", v, err)
							}
							if n < size16 {
								return fmt.Errorf("size_bytes = %d, want >= %d", n, size16)
							}
							return nil
						}),
					resource.TestCheckResourceAttrWith("windows_partition.acc", "guid",
						func(v string) error {
							if strings.TrimSpace(v) == "" {
								return fmt.Errorf("GPT partitions must report a guid")
							}
							return nil
						}),
				),
			},
			{
				// A re-apply of the same config must be a no-op.
				Config:   testAccPartitionFixtureConfig(fix.UniqueID, size16, letters[0], "  gpt_type = \"basic_data\"\n"),
				PlanOnly: true,
			},
			{
				// In-place update: drive letter change.
				Config: testAccPartitionFixtureConfig(fix.UniqueID, size16, letters[1], "  gpt_type = \"basic_data\"\n"),
				Check: resource.ComposeTestCheckFunc(
					capturePartitionID(&lastID),
					resource.TestCheckResourceAttr("windows_partition.acc", "drive_letter", letters[1]),
				),
			},
			{
				// In-place update: grow 16 MiB to 32 MiB.
				Config: testAccPartitionFixtureConfig(fix.UniqueID, size32, letters[1], "  gpt_type = \"basic_data\"\n"),
				Check: resource.ComposeTestCheckFunc(
					capturePartitionID(&lastID),
					resource.TestCheckResourceAttrWith("windows_partition.acc", "size_bytes",
						func(v string) error {
							n, err := strconv.ParseInt(v, 10, 64)
							if err != nil {
								return fmt.Errorf("size_bytes %q is not numeric: %w", v, err)
							}
							if n < size32 {
								return fmt.Errorf("size_bytes = %d, want >= %d", n, size32)
							}
							return nil
						}),
				),
			},
			{
				ResourceName: "windows_partition.acc",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources["windows_partition.acc"]
					if !ok {
						return "", fmt.Errorf("windows_partition.acc not in state")
					}
					return rs.Primary.ID, nil
				},
				// ImportStateVerify stays off on purpose: an apply carries
				// configured gpt_type/use_maximum_size spellings while import
				// records only observed values, so the states legitimately
				// differ; the id and letter checks pin the adoption instead.
				ImportStateVerify: false,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("windows_partition.acc", "id",
						func(v string) error {
							if v != lastID {
								return fmt.Errorf("imported id %q != applied id %q", v, lastID)
							}
							return nil
						}),
					resource.TestCheckResourceAttr("windows_partition.acc", "drive_letter", letters[1]),
				),
			},
		},
	})
}

// TestAccWindowsPartition_MBRBasic — attach a throwaway VHDX, initialize it
// to MBR, carve an IFS partition with a letter using an explicit offset-free
// default placement, import by id, and assert destroy removes the partition
// while the disk survives. The MBR identity is the byte offset (no GUID).
func TestAccWindowsPartition_MBRBasic(t *testing.T) {
	testAccDiskPreCheck(t)
	fix := testAccDiskCreateVHDX(t)
	testAccPartitionInitDisk(t, fix.UniqueID, "MBR")
	letters := testAccPartitionFreeLetters(t, 1)

	const size16 = int64(16777216)
	var lastID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckPartitionDestroyed(fix.UniqueID, &lastID),
		Steps: []resource.TestStep{
			{
				Config: testAccPartitionFixtureConfig(fix.UniqueID, size16, letters[0], "  mbr_type = \"IFS\"\n"),
				Check: resource.ComposeTestCheckFunc(
					capturePartitionID(&lastID),
					resource.TestCheckResourceAttrWith("windows_partition.acc", "id",
						func(v string) error {
							rest, ok := strings.CutPrefix(v, fix.UniqueID+"|")
							if !ok || rest == "" {
								return fmt.Errorf("id %q must be \"<disk_unique_id>|<offset>\"", v)
							}
							if _, err := strconv.ParseInt(rest, 10, 64); err != nil {
								return fmt.Errorf("MBR id key %q must be a decimal offset: %w", rest, err)
							}
							return nil
						}),
					resource.TestCheckResourceAttr("windows_partition.acc", "drive_letter", letters[0]),
				),
			},
			{
				ResourceName: "windows_partition.acc",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources["windows_partition.acc"]
					if !ok {
						return "", fmt.Errorf("windows_partition.acc not in state")
					}
					return rs.Primary.ID, nil
				},
				ImportStateVerify: false,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("windows_partition.acc", "id",
						func(v string) error {
							if v != lastID {
								return fmt.Errorf("imported id %q != applied id %q", v, lastID)
							}
							return nil
						}),
				),
			},
		},
	})
}

// TestAccWindowsPartition_UseMaximumSize — attach a throwaway VHDX,
// initialize it to GPT and carve the whole disk with use_maximum_size,
// proving the create-only extent mode converges with no diff on re-apply.
func TestAccWindowsPartition_UseMaximumSize(t *testing.T) {
	testAccDiskPreCheck(t)
	fix := testAccDiskCreateVHDX(t)
	testAccPartitionInitDisk(t, fix.UniqueID, "GPT")
	letters := testAccPartitionFreeLetters(t, 1)
	var lastID string

	cfg := fmt.Sprintf(`
resource "windows_partition" "acc" {
  disk_unique_id    = %q
  use_maximum_size  = true
  drive_letter      = %q
  gpt_type          = "basic_data"
}
`, fix.UniqueID, letters[0])

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckPartitionDestroyed(fix.UniqueID, &lastID),
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					capturePartitionID(&lastID),
					resource.TestCheckResourceAttr("windows_partition.acc", "drive_letter", letters[0]),
					resource.TestCheckResourceAttrWith("windows_partition.acc", "size_bytes",
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
				),
			},
			{
				// Later growth is not automatic: re-applying the same config
				// must be a no-op.
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}
