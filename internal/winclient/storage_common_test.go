// Package winclient — unit tests for the shared storage helpers.
//
// Covers the selector validation table (exactly one of unique_id /
// serial_number / location / number), the identity normalization, the
// protected-storage guard decision table, the size helpers and the GPT GUID
// constants. No SSH is involved: every helper under test is pure Go.
package winclient

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// DiskSelector validation
// ---------------------------------------------------------------------------

func TestDiskSelectorValidate_Table(t *testing.T) {
	cases := []struct {
		name    string
		sel     DiskSelector
		wantErr bool
	}{
		{"unique_id", DiskSelector{UniqueID: "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK"}, false},
		{"serial_number", DiskSelector{SerialNumber: "6000c296..."}, false},
		{"location", DiskSelector{Location: "PCI Slot 0"}, false},
		{"number_zero", DiskSelector{Number: 0, HasNumber: true}, false},
		{"number", DiskSelector{Number: 3, HasNumber: true}, false},
		{"none", DiskSelector{}, true},
		{"blank_strings", DiskSelector{UniqueID: "   "}, true},
		{"number_without_flag", DiskSelector{Number: 2}, true},
		{"negative_number", DiskSelector{Number: -1, HasNumber: true}, true},
		{"two_set", DiskSelector{UniqueID: "U", SerialNumber: "S"}, true},
		{"three_set", DiskSelector{UniqueID: "U", Location: "L", Number: 1, HasNumber: true}, true},
		{"all_set", DiskSelector{UniqueID: "U", SerialNumber: "S", Location: "L", Number: 1, HasNumber: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sel.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestDiskSelectorConstructors_Normalize(t *testing.T) {
	sel := DiskSelectorBySerialNumber("  ab12-cd34  ")
	if err := sel.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sel.SerialNumber != "AB12-CD34" {
		t.Errorf("constructor should normalize identity, got %q", sel.SerialNumber)
	}
	if got := DiskSelectorByUniqueID("u").Describe(); !strings.Contains(got, "unique_id") {
		t.Errorf("Describe should name the coordinate, got %q", got)
	}
	if got := (DiskSelector{}).Describe(); got != "no selector" {
		t.Errorf("empty Describe = %q, want %q", got, "no selector")
	}
}

func TestDiskSelectorDescribe_NamesCoordinate(t *testing.T) {
	cases := []struct {
		sel  DiskSelector
		want string
	}{
		{DiskSelectorByUniqueID("U"), "unique_id"},
		{DiskSelectorBySerialNumber("S"), "serial_number"},
		{DiskSelectorByLocation("L"), "location"},
		{DiskSelectorByNumber(2), "number 2"},
	}
	for _, tc := range cases {
		if got := tc.sel.Describe(); !strings.Contains(got, tc.want) {
			t.Errorf("Describe = %q, want it to contain %q", got, tc.want)
		}
	}
}

func TestNormalizeDiskIdentity(t *testing.T) {
	if got := NormalizeDiskIdentity("  ab-12 "); got != "AB-12" {
		t.Errorf("got %q, want %q", got, "AB-12")
	}
	if got := NormalizeDiskIdentity("PCI Slot 0"); got != "PCI SLOT 0" {
		t.Errorf("got %q", got)
	}
}

func TestValidateDiskNumber(t *testing.T) {
	if err := ValidateDiskNumber(0); err != nil {
		t.Errorf("disk 0 is valid, got %v", err)
	}
	if err := ValidateDiskNumber(-1); err == nil {
		t.Error("negative disk number must fail")
	}
}

// ---------------------------------------------------------------------------
// Guard decision table
// ---------------------------------------------------------------------------

func TestDiskGuardInfo_ProtectedStorageReason_Table(t *testing.T) {
	cases := []struct {
		name      string
		guard     DiskGuardInfo
		protected bool
	}{
		{"clean", DiskGuardInfo{}, false},
		{"boot", DiskGuardInfo{IsBoot: true}, true},
		{"system", DiskGuardInfo{IsSystem: true}, true},
		{"pagefile", DiskGuardInfo{HoldsPagefile: true}, true},
		{"crashdump", DiskGuardInfo{HoldsCrashDump: true}, true},
		{"clustered", DiskGuardInfo{IsClustered: true}, true},
		{"placement_unknown_fails_closed", DiskGuardInfo{PlacementUnknown: true}, true},
		{"everything", DiskGuardInfo{IsBoot: true, IsSystem: true, HoldsPagefile: true, HoldsCrashDump: true, IsClustered: true, PlacementUnknown: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := tc.guard.ProtectedStorageReason()
			if tc.protected && reason == "" {
				t.Error("expected a protected-storage reason, got \"\"")
			}
			if !tc.protected && reason != "" {
				t.Errorf("expected no reason, got %q", reason)
			}
		})
	}
}

func TestDiskGuardInfo_BootTakesPrecedence(t *testing.T) {
	g := DiskGuardInfo{IsBoot: true, IsSystem: true, HoldsPagefile: true}
	if reason := g.ProtectedStorageReason(); !strings.Contains(strings.ToLower(reason), "boot") {
		t.Errorf("boot should win, got %q", reason)
	}
}

// TestDiskGuardInfo_PrecedencePinsSharedOrder pins the precedence shared
// with Test-DiskProtected in disk.go: boot, system, clustered, pagefile,
// crash-dump, undeterminable placement. Either side reporting first wins,
// so combined flags must resolve to the earliest reason in that order.
func TestDiskGuardInfo_PrecedencePinsSharedOrder(t *testing.T) {
	cases := []struct {
		name  string
		guard DiskGuardInfo
		want  string
	}{
		{"system_beats_clustered", DiskGuardInfo{IsSystem: true, IsClustered: true}, "system"},
		{"clustered_beats_pagefile", DiskGuardInfo{IsClustered: true, HoldsPagefile: true}, "clustered"},
		{"clustered_beats_crashdump", DiskGuardInfo{IsClustered: true, HoldsCrashDump: true}, "clustered"},
		{"clustered_beats_unknown", DiskGuardInfo{IsClustered: true, PlacementUnknown: true}, "clustered"},
		{"pagefile_beats_crashdump", DiskGuardInfo{HoldsPagefile: true, HoldsCrashDump: true}, "pagefile"},
		{"pagefile_beats_unknown", DiskGuardInfo{HoldsPagefile: true, PlacementUnknown: true}, "pagefile"},
		{"crashdump_beats_unknown", DiskGuardInfo{HoldsCrashDump: true, PlacementUnknown: true}, "crash-dump"},
		{"boot_beats_everything", DiskGuardInfo{IsBoot: true, IsSystem: true, IsClustered: true, HoldsPagefile: true, HoldsCrashDump: true, PlacementUnknown: true}, "boot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := tc.guard.ProtectedStorageReason()
			if !strings.Contains(strings.ToLower(reason), tc.want) {
				t.Errorf("combined guard should resolve to %q, got %q", tc.want, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Size helpers
// ---------------------------------------------------------------------------

func TestParseStorageSizeBytes_Table(t *testing.T) {
	cases := []struct {
		raw  string
		want int64
	}{
		{"1024", 1024},
		{"512MB", 512 * 1024 * 1024},
		{"10 GiB", 10 * 1024 * 1024 * 1024},
		{"1K", 1024},
		{"2tib", 2 * 1024 * 1024 * 1024 * 1024},
		{"1.5GB", 1610612736},
		{"8 B", 8},
		{"1P", 1024 * 1024 * 1024 * 1024 * 1024},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := ParseStorageSizeBytes(tc.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseStorageSizeBytes_Invalid(t *testing.T) {
	for _, raw := range []string{"", "   ", "abc", "10XB", "-5GB", "0", "1.5B", "0x10", "GB", "1.5.2GB"} {
		t.Run("invalid_"+raw, func(t *testing.T) {
			if _, err := ParseStorageSizeBytes(raw); err == nil {
				t.Errorf("expected error for %q", raw)
			}
		})
	}
}

// TestParseStorageSizeBytes_RejectsExplicitSigns pins that sizes are
// magnitudes: a leading "+" or "-" is never an accepted spelling, even
// when the magnitude itself would be valid.
func TestParseStorageSizeBytes_RejectsExplicitSigns(t *testing.T) {
	for _, raw := range []string{"+5GB", "+1024", "+1.5TB", " +10MB ", "+ 5GB", "-5GB", "--5GB"} {
		t.Run("signed_"+raw, func(t *testing.T) {
			if _, err := ParseStorageSizeBytes(raw); err == nil {
				t.Errorf("expected error for signed size %q", raw)
			}
		})
	}
}

// TestParseStorageSizeBytes_ExactBeyondFloat53 pins exact (non-float64)
// arithmetic past 2^53, where float64 silently rounds: 2^53+1 must come
// back exactly, MaxInt64 stays accepted, and MaxInt64+1 overflows.
func TestParseStorageSizeBytes_ExactBeyondFloat53(t *testing.T) {
	const two53plus1 = int64(9007199254740993) // 2^53+1, not representable as float64
	for _, raw := range []string{"9007199254740993", "9007199254740993B"} {
		if got, err := ParseStorageSizeBytes(raw); err != nil {
			t.Errorf("ParseStorageSizeBytes(%q) unexpected error: %v", raw, err)
		} else if got != two53plus1 {
			t.Errorf("ParseStorageSizeBytes(%q) = %d, want exactly %d", raw, got, two53plus1)
		}
	}
	if got, err := ParseStorageSizeBytes("9223372036854775807"); err != nil {
		t.Errorf("MaxInt64 should parse exactly, got error: %v", err)
	} else if got != 9223372036854775807 {
		t.Errorf("MaxInt64 parse = %d, want 9223372036854775807", got)
	}
	for _, raw := range []string{"9223372036854775808", "99999999999999999999999P"} {
		if _, err := ParseStorageSizeBytes(raw); err == nil {
			t.Errorf("expected overflow error for %q", raw)
		}
	}
}

func TestValidateStorageSizeBytes(t *testing.T) {
	if err := ValidateStorageSizeBytes(1); err != nil {
		t.Errorf("1 byte is valid, got %v", err)
	}
	for _, n := range []int64{0, -1, -1024} {
		if err := ValidateStorageSizeBytes(n); err == nil {
			t.Errorf("size %d must fail", n)
		}
	}
}

// ---------------------------------------------------------------------------
// GPT GUID constants
// ---------------------------------------------------------------------------

func TestGPTGUIDs_DistinctAndShaped(t *testing.T) {
	guids := []string{
		GPTBasicDataPartitionGUID,
		GPTEFIPartitionGUID,
		GPTMicrosoftReservedGUID,
		GPTRecoveryPartitionGUID,
		GPTStorageSpacesPartitionGUID,
	}
	seen := map[string]bool{}
	for _, g := range guids {
		if g == "" {
			t.Error("GPT GUID must not be empty")
		}
		if g != strings.ToUpper(g) {
			t.Errorf("GPT GUID %q must be upper-case", g)
		}
		parts := strings.Split(g, "-")
		if len(parts) != 5 {
			t.Errorf("GPT GUID %q must have 5 dash-separated groups", g)
		}
		if seen[g] {
			t.Errorf("duplicate GPT GUID %q", g)
		}
		seen[g] = true
	}
}
