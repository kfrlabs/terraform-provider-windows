//go:build acceptance

// Package provider — acceptance tests for windows_volume (resource + data
// source).
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//     (see acc_test_helper.go)
//   - WINDOWS_ACC_STORAGE=1 (extra gate shared with windows_disk: these
//     tests attach real — albeit throwaway — virtual disks, so they stay off
//     unless explicitly enabled)
//   - A Windows *Server* target with diskpart available and Local
//     Administrator rights for the SSH user (diskpart attach, Initialize-Disk,
//     the partition cmdlets and Format-Volume all require elevation).
//
// SAFETY: every test creates its own throwaway dynamically-expanding 64 MiB
// VHDX under C:\TF-Acc-Disk (see resource_windows_disk_acc_test.go), attaches
// it via diskpart (a RAW data disk — never the boot/system disk), initializes
// it to GPT and carves a 32 MiB data partition out of band in t.Cleanup-safe
// order. windows_volume Delete is state-only (it makes no remote call), so
// the CheckDestroy assertion below verifies the volume is still present after
// destroy (Delete must never unformat it) while the t.Cleanup detach/delete
// is what actually releases the fixture — even when the test fails.
package provider

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// testAccVolumeCreatePartition carves a 32 MiB data partition with the given
// drive letter on the attached fixture disk (initialized GPT beforehand)
// through the public winclient partition client, and returns its partition
// ID ("<disk_unique_id>|<guid>").
func testAccVolumeCreatePartition(t *testing.T, diskUniqueID, letter string) string {
	t.Helper()
	c := accDiskClient(t)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	info, err := winclient.NewPartitionClient(c).Create(ctx, winclient.PartitionCreateOptions{
		DiskUniqueID: diskUniqueID,
		SizeBytes:    33554432,
		DriveLetter:  letter,
	})
	if err != nil {
		t.Fatalf("carve fixture partition on disk %s: %v", diskUniqueID, err)
	}
	id, err := winclient.BuildPartitionID(info.DiskUniqueID, winclient.PartitionResourceKey(info))
	if err != nil {
		t.Fatalf("build fixture partition id: %v", err)
	}
	return id
}

// testAccVolumeFixtureConfig renders a windows_volume formatting the fixture
// partition plus a data source round-trip over the same volume and a
// read-only lookup of the system volume (drive C).
func testAccVolumeFixtureConfig(partitionID, fileSystem, label string) string {
	return fmt.Sprintf(`
resource "windows_volume" "acc" {
  partition_id      = %q
  file_system       = %q
  file_system_label = %q
}

data "windows_volume" "ds" {
  unique_id = windows_volume.acc.id
}

data "windows_volume" "c" {
  drive_letter = "C"
}
`, partitionID, fileSystem, label)
}

// testAccCheckVolumeAdoptionReleased returns a CheckDestroy func asserting the
// fixture volume still exists after destroy: windows_volume Delete only drops
// the adoption from state and makes no remote call, so the volume and its
// data must be left untouched (the t.Cleanup detach/delete releases the VHDX
// after). It also asserts the hosting disk survived.
func testAccCheckVolumeAdoptionReleased(diskUniqueID string, lastID *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if lastID == nil || *lastID == "" {
			return fmt.Errorf("no volume id captured; cannot verify destroy")
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
		info, err := winclient.NewVolumeClient(c).Read(ctx, *lastID)
		if err != nil {
			return fmt.Errorf("re-read of fixture volume after destroy: %w", err)
		}
		if info == nil {
			return fmt.Errorf("fixture volume %q is gone after destroy: Delete must be state-only", *lastID)
		}
		diskInfo, err := winclient.NewDiskClient(c).Read(ctx, winclient.DiskSelectorByUniqueID(diskUniqueID))
		if err != nil {
			return fmt.Errorf("re-read of fixture disk after destroy: %w", err)
		}
		if diskInfo == nil {
			return fmt.Errorf("fixture disk %q is gone after destroy", diskUniqueID)
		}
		return nil
	}
}

// captureVolumeID returns a TestCheckFunc recording the managed resource ID
// into id for the later CheckDestroy closure.
func captureVolumeID(id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources["windows_volume.acc"]
		if !ok {
			return fmt.Errorf("windows_volume.acc not in state")
		}
		*id = rs.Primary.ID
		return nil
	}
}

// TestAccWindowsVolume_NTFSLifecycle — attach a throwaway VHDX, initialize it
// to GPT, carve a 32 MiB partition with a letter out of band, format it to
// NTFS, prove idempotency, relabel in place, refuse a hostile reformat
// (already_formatted without allow_format_existing), import by UniqueId and
// by drive letter, read the C: system volume via the data source, and assert
// destroy only releases the adoption (volume and disk untouched).
func TestAccWindowsVolume_NTFSLifecycle(t *testing.T) {
	testAccDiskPreCheck(t)
	fix := testAccDiskCreateVHDX(t)
	testAccPartitionInitDisk(t, fix.UniqueID, "GPT")
	letters := testAccPartitionFreeLetters(t, 1)
	partitionID := testAccVolumeCreatePartition(t, fix.UniqueID, letters[0])
	var lastID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckVolumeAdoptionReleased(fix.UniqueID, &lastID),
		Steps: []resource.TestStep{
			{
				Config: testAccVolumeFixtureConfig(partitionID, "NTFS", "TFACC"),
				Check: resource.ComposeTestCheckFunc(
					captureVolumeID(&lastID),
					resource.TestCheckResourceAttrWith("windows_volume.acc", "id",
						func(v string) error {
							if !strings.HasPrefix(v, `\\?\Volume{`) || !strings.HasSuffix(v, `}\`) {
								return fmt.Errorf("id %q must be the Get-Volume UniqueId (\\\\?\\Volume{...}\\)", v)
							}
							return nil
						}),
					resource.TestCheckResourceAttr("windows_volume.acc", "partition_id", partitionID),
					resource.TestCheckResourceAttr("windows_volume.acc", "file_system", "NTFS"),
					resource.TestCheckResourceAttr("windows_volume.acc", "file_system_label", "TFACC"),
					resource.TestCheckResourceAttr("windows_volume.acc", "drive_letter", letters[0]),
					resource.TestCheckResourceAttrWith("windows_volume.acc", "size_bytes",
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
						"data.windows_volume.ds", "id", "windows_volume.acc", "id"),
					resource.TestCheckResourceAttrPair(
						"data.windows_volume.ds", "file_system", "windows_volume.acc", "file_system"),
					// The system volume is readable by drive letter even
					// though it is protected against management.
					resource.TestCheckResourceAttr("data.windows_volume.c", "drive_letter", "C"),
					resource.TestCheckResourceAttrWith("data.windows_volume.c", "file_system",
						func(v string) error {
							if strings.TrimSpace(v) == "" {
								return fmt.Errorf("data.windows_volume.c must report a file system")
							}
							return nil
						}),
				),
			},
			{
				// A re-apply of the same config must be a no-op.
				Config:   testAccVolumeFixtureConfig(partitionID, "NTFS", "TFACC"),
				PlanOnly: true,
			},
			{
				// In-place update: volume label change.
				Config: testAccVolumeFixtureConfig(partitionID, "NTFS", "TFACC2"),
				Check: resource.ComposeTestCheckFunc(
					captureVolumeID(&lastID),
					resource.TestCheckResourceAttr("windows_volume.acc", "file_system_label", "TFACC2"),
				),
			},
			{
				// Hostile reformat refused: changing the file system without
				// allow_format_existing must fail with already_formatted
				// instead of destroying data.
				Config:      testAccVolumeFixtureConfig(partitionID, "ReFS", "TFACC2"),
				ExpectError: regexp.MustCompile("already_formatted"),
			},
			{
				ResourceName: "windows_volume.acc",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources["windows_volume.acc"]
					if !ok {
						return "", fmt.Errorf("windows_volume.acc not in state")
					}
					return rs.Primary.ID, nil
				},
				// ImportStateVerify stays off on purpose: an apply carries
				// configured defaults while import records observed values
				// (label, allocation unit size), so the states legitimately
				// differ; the id and partition checks pin the adoption instead.
				ImportStateVerify: false,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("windows_volume.acc", "id",
						func(v string) error {
							if v != lastID {
								return fmt.Errorf("imported id %q != applied id %q", v, lastID)
							}
							return nil
						}),
					resource.TestCheckResourceAttr("windows_volume.acc", "partition_id", partitionID),
				),
			},
			{
				// Import by drive letter.
				ResourceName:      "windows_volume.acc",
				ImportState:       true,
				ImportStateId:     letters[0] + ":",
				ImportStateVerify: false,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith("windows_volume.acc", "id",
						func(v string) error {
							if v != lastID {
								return fmt.Errorf("letter-imported id %q != applied id %q", v, lastID)
							}
							return nil
						}),
				),
			},
		},
	})
}
