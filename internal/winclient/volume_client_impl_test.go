// Package winclient — unit tests for VolumeClient.
//
// These tests stub the package-level seam runVolumePowerShell to inject
// scripted stdout/stderr/err triples. They cover the envelope mapping for
// every VolumeErrorKind, the pure-Go helpers (file-system canonicalization,
// label limits, allocation-unit validation, import-ID resolution, lookup
// validation, format-option validation), input validation short-circuits (no
// remote call), and the script invariants: quoting, no `exit`, -Confirm:$false,
// -Force, quick-by-default formatting, and the protected-storage guards.
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newVolumeTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:                  "win01",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// stubVolumeRun replaces runVolumePowerShell for the duration of a test.
func stubVolumeRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runVolumePowerShell
	runVolumePowerShell = fn
	return func() { runVolumePowerShell = prev }
}

func volumeOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func volumeErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("marshal err: %v", err)
	}
	return string(b) + "\n"
}

func fakeVolumeData() map[string]any {
	return map[string]any{
		"unique_id":            `\\?\Volume{11111111-2222-3333-4444-555555555555}\`,
		"partition_id":         `SCSI\DISK&VEN_MSFT&PROD_VIRTUAL_DISK|EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`,
		"drive_letter":         "E",
		"path":                 `\\?\Volume{11111111-2222-3333-4444-555555555555}\`,
		"file_system":          "NTFS",
		"file_system_label":    "TFDATA",
		"allocation_unit_size": 4096,
		"size_bytes":           16777216,
		"size_remaining_bytes": 16744448,
		"health_status":        "Healthy",
		"operational_status":   "OK",
		"drive_type":           "Fixed",
	}
}

func okVolumeFormatOpts() VolumeFormatOptions {
	return VolumeFormatOptions{
		PartitionID: `SCSI\DISK&VEN_MSFT&PROD_VIRTUAL_DISK|EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`,
		FileSystem:  VolumeFileSystemNTFS,
	}
}

// ---------------------------------------------------------------------------
// VolumeError type
// ---------------------------------------------------------------------------

func TestVolumeError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	e := NewVolumeError(VolumeErrorUnknown, "timed out", cause, map[string]string{"host": "win01"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "unknown") || !strings.Contains(msg, "timed out") ||
		!strings.Contains(msg, "underlying") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewVolumeError(VolumeErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestVolumeError_Is_And_IsVolumeError(t *testing.T) {
	e := NewVolumeError(VolumeErrorProtected, "x", nil, nil)
	if !errors.Is(e, ErrVolumeProtected) {
		t.Error("errors.Is(ErrVolumeProtected) should match by kind")
	}
	if errors.Is(e, ErrVolumeNotFound) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsVolumeError(e, VolumeErrorProtected) {
		t.Error("IsVolumeError should match")
	}
	if IsVolumeError(errors.New("plain"), VolumeErrorProtected) {
		t.Error("IsVolumeError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-VolumeError should be false")
	}
}

func TestMapVolumeKind(t *testing.T) {
	cases := map[string]VolumeErrorKind{
		"not_found":               VolumeErrorNotFound,
		"partition_not_found":     VolumeErrorPartitionNotFound,
		"already_formatted":       VolumeErrorAlreadyFormatted,
		"protected_storage":       VolumeErrorProtected,
		"unsupported_file_system": VolumeErrorUnsupportedFileSystem,
		"invalid_allocation_unit": VolumeErrorInvalidAllocationUnit,
		"access_denied":           VolumeErrorAccessDenied,
		"unknown":                 VolumeErrorUnknown,
		"":                        VolumeErrorUnknown,
		"weird_kind":              VolumeErrorUnknown,
		"ambiguous_disk":          VolumeErrorUnknown,
		// The disk vocabulary's disk_not_found has no volume counterpart: it
		// surfaces only from the format path (a gone hosting disk) and reads
		// as partition_not_found.
		"disk_not_found": VolumeErrorPartitionNotFound,
	}
	for in, want := range cases {
		if got := mapVolumeKind(in); got != want {
			t.Errorf("mapVolumeKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: file systems
// ---------------------------------------------------------------------------

func TestCanonicalizeVolumeFileSystem_Table(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"NTFS", "NTFS", false},
		{"ntfs", "NTFS", false},
		{"  Ntfs  ", "NTFS", false},
		{"ReFS", "ReFS", false},
		{"refs", "ReFS", false},
		{"REFS", "ReFS", false},
		{"exFAT", "exFAT", false},
		{"exfat", "exFAT", false},
		{"EXFAT", "exFAT", false},
		{"FAT32", "FAT32", false},
		{"fat32", "FAT32", false},
		{"", "", true},
		{"  ", "", true},
		{"FAT", "", true},
		{"FAT16", "", true},
		{"NTFS5", "", true},
		{"ext4", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := CanonicalizeVolumeFileSystem(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("CanonicalizeVolumeFileSystem(%q) = %q, want error", tc.in, got)
				} else if !IsVolumeError(err, VolumeErrorUnsupportedFileSystem) {
					t.Errorf("wrong kind for %q: %v", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalizeVolumeFileSystem(%q) err: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("CanonicalizeVolumeFileSystem(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: labels
// ---------------------------------------------------------------------------

func TestValidateVolumeLabel_Table(t *testing.T) {
	cases := []struct {
		fs      string
		label   string
		wantErr bool
	}{
		{"NTFS", "", false},
		{"NTFS", "TFDATA", false},
		{"NTFS", strings.Repeat("A", 32), false},
		{"NTFS", strings.Repeat("A", 33), true},
		{"ReFS", strings.Repeat("B", 32), false},
		{"ReFS", strings.Repeat("B", 33), true},
		{"exFAT", strings.Repeat("C", 11), false},
		{"exFAT", strings.Repeat("C", 12), true},
		{"FAT32", strings.Repeat("D", 11), false},
		{"FAT32", strings.Repeat("D", 12), true},
		// Multibyte runes count as characters, not bytes.
		{"NTFS", strings.Repeat("é", 32), false},
		{"NTFS", strings.Repeat("é", 33), true},
	}
	for _, tc := range cases {
		t.Run(tc.fs+"/"+tc.label, func(t *testing.T) {
			err := ValidateVolumeLabel(tc.fs, tc.label)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateVolumeLabel(%q, %q) should fail", tc.fs, tc.label)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateVolumeLabel(%q, %q) err: %v", tc.fs, tc.label, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: allocation unit sizes
// ---------------------------------------------------------------------------

func TestValidateVolumeAllocationUnitSize_Table(t *testing.T) {
	cases := []struct {
		fs      string
		size    int64
		wantErr bool
	}{
		{"NTFS", 0, false}, // host default always valid
		{"NTFS", 512, false},
		{"NTFS", 4096, false},
		{"NTFS", 65536, false},
		{"NTFS", 131072, true},
		{"NTFS", 511, true},
		{"NTFS", 3000, true},
		{"NTFS", -512, true},
		{"FAT32", 32768, false},
		{"FAT32", 65536, true},
		{"exFAT", 2097152, false},
		{"exFAT", 4194304, true},
		{"exFAT", 1000, true},
		{"ReFS", 4096, false},
		{"ReFS", 65536, false},
		{"ReFS", 512, true},
		{"ReFS", 8192, true},
	}
	for _, tc := range cases {
		t.Run(tc.fs, func(t *testing.T) {
			err := ValidateVolumeAllocationUnitSize(tc.fs, tc.size)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateVolumeAllocationUnitSize(%q, %d) should fail", tc.fs, tc.size)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateVolumeAllocationUnitSize(%q, %d) err: %v", tc.fs, tc.size, err)
			}
			if tc.wantErr && err != nil && !IsVolumeError(err, VolumeErrorInvalidAllocationUnit) {
				t.Errorf("wrong kind for (%q, %d): %v", tc.fs, tc.size, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: lookups and import IDs
// ---------------------------------------------------------------------------

func TestNormalizeVolumeDriveLetter_Table(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"E", "E", false},
		{"e", "E", false},
		{"E:", "E", false},
		{"  e:  ", "E", false},
		{"C", "C", false}, // C is allowed: reads never change the volume
		{"c:", "C", false},
		{"A", "A", false},
		{"Z", "Z", false},
		{"", "", true},
		{"  ", "", true},
		{"EE", "", true},
		{"1", "", true},
		{"E::", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := NormalizeVolumeDriveLetter(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("NormalizeVolumeDriveLetter(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeVolumeDriveLetter(%q) err: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeVolumeDriveLetter(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestVolumeLookupValidate_Table(t *testing.T) {
	cases := []struct {
		name    string
		lookup  VolumeLookup
		wantErr bool
	}{
		{"unique_id", VolumeLookup{UniqueID: `\\?\Volume{1}\`}, false},
		{"letter", VolumeLookup{DriveLetter: "E"}, false},
		{"letter colon", VolumeLookup{DriveLetter: "e:"}, false},
		{"label", VolumeLookup{FileSystemLabel: "TFDATA"}, false},
		{"none", VolumeLookup{}, true},
		{"blank", VolumeLookup{DriveLetter: "  "}, true},
		{"two set", VolumeLookup{UniqueID: "U", DriveLetter: "E"}, true},
		{"all set", VolumeLookup{UniqueID: "U", DriveLetter: "E", FileSystemLabel: "L"}, true},
		{"bad letter", VolumeLookup{DriveLetter: "EE"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.lookup.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestResolveVolumeImportID_Table(t *testing.T) {
	uid := `\\?\Volume{11111111-2222-3333-4444-555555555555}\`
	cases := []struct {
		in      string
		kind    VolumeImportKind
		value   string
		wantErr bool
	}{
		{uid, VolumeImportByUniqueID, uid, false},
		{"E", VolumeImportByDriveLetter, "E", false},
		{"e", VolumeImportByDriveLetter, "E", false},
		{"E:", VolumeImportByDriveLetter, "E", false},
		{"  e:  ", VolumeImportByDriveLetter, "E", false},
		{"C", VolumeImportByDriveLetter, "C", false},
		{"", "", "", true},
		{"   ", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			kind, value, err := ResolveVolumeImportID(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ResolveVolumeImportID(%q) should fail", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveVolumeImportID(%q) err: %v", tc.in, err)
			}
			if kind != tc.kind || value != tc.value {
				t.Errorf("ResolveVolumeImportID(%q) = (%q, %q), want (%q, %q)",
					tc.in, kind, value, tc.kind, tc.value)
			}
		})
	}
}

func TestValidateVolumeFormatOptions(t *testing.T) {
	if err := ValidateVolumeFormatOptions(okVolumeFormatOpts()); err != nil {
		t.Errorf("valid opts rejected: %v", err)
	}
	full := okVolumeFormatOpts()
	full.FileSystemLabel = "TFDATA"
	full.AllocationUnitSize = 4096
	full.AllowFormatExisting = true
	full.FullFormat = true
	if err := ValidateVolumeFormatOptions(full); err != nil {
		t.Errorf("full opts rejected: %v", err)
	}
	bad := okVolumeFormatOpts()
	bad.PartitionID = "no-separator"
	if err := ValidateVolumeFormatOptions(bad); err == nil {
		t.Error("malformed partition_id must fail")
	}
	bad = okVolumeFormatOpts()
	bad.FileSystem = "ext4"
	if err := ValidateVolumeFormatOptions(bad); err == nil {
		t.Error("unsupported file system must fail")
	} else if !IsVolumeError(err, VolumeErrorUnsupportedFileSystem) {
		t.Errorf("wrong kind: %v", err)
	}
	bad = okVolumeFormatOpts()
	bad.FileSystemLabel = strings.Repeat("A", 33)
	if err := ValidateVolumeFormatOptions(bad); err == nil {
		t.Error("over-long NTFS label must fail")
	}
	bad = okVolumeFormatOpts()
	bad.FileSystem = "FAT32"
	bad.FileSystemLabel = strings.Repeat("A", 12)
	if err := ValidateVolumeFormatOptions(bad); err == nil {
		t.Error("over-long FAT32 label must fail")
	}
	bad = okVolumeFormatOpts()
	bad.AllocationUnitSize = 3000
	if err := ValidateVolumeFormatOptions(bad); err == nil {
		t.Error("non-power-of-two allocation unit must fail")
	} else if !IsVolumeError(err, VolumeErrorInvalidAllocationUnit) {
		t.Errorf("wrong kind: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Script invariants: quoting, no exit, prelude
// ---------------------------------------------------------------------------

func volumeTestScripts(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"format": buildVolumeFormatScript(okVolumeFormatOpts()),
		"read":   buildVolumeReadScript(`\\?\Volume{1}\`),
		"label":  buildVolumeLabelScript(`\\?\Volume{1}\`, "TFDATA"),
		"lookup": buildVolumeLookupScript(VolumeLookup{DriveLetter: "E"}),
		"lib":    psStorageHeader + "\n" + psDiskFunctions + "\n" + psPartitionFunctions + "\n" + psVolumeFunctions,
	}
}

func TestVolumeScripts_NeverUseExit(t *testing.T) {
	scripts := volumeTestScripts(t)
	for name, s := range scripts {
		t.Run(name, func(t *testing.T) {
			if exitWord.MatchString(s) {
				t.Error("script must never use `exit` (it would kill the persistent session)")
			}
			if !strings.Contains(s, "$ErrorActionPreference = 'Stop'") {
				t.Error("script must pin $ErrorActionPreference")
			}
			if !strings.Contains(s, "Update-HostStorageCache") {
				t.Error("script must refresh the storage cache")
			}
		})
	}
}

func TestVolumeScripts_MutationsCarryNoConfirm(t *testing.T) {
	for name, s := range map[string]string{
		"format": buildVolumeFormatScript(okVolumeFormatOpts()),
		"label":  buildVolumeLabelScript("U", "TFDATA"),
	} {
		if !strings.Contains(s, "-Confirm:$false") {
			t.Errorf("%s: mutating cmdlet must carry -Confirm:$false", name)
		}
	}
}

// Format defaults to a quick format: the Full switch is gated behind
// $fullFmt (which renders $false unless full_format is set) and the script
// carries the file system, label and allocation unit size explicitly.
func TestVolumeFormatScript_QuickByDefault(t *testing.T) {
	s := buildVolumeFormatScript(okVolumeFormatOpts())
	if !strings.Contains(s, "Format-Volume") {
		t.Error("format script must call Format-Volume")
	}
	if !strings.Contains(s, "Force = $true") && !strings.Contains(s, "-Force") {
		t.Error("format script must pass -Force")
	}
	if !strings.Contains(s, "if ($fullFmt) { $params['Full'] = $true }") {
		t.Error("format script must gate the Full switch behind $fullFmt")
	}
	if !strings.Contains(s, "$fullFmt = $false") {
		t.Error("default format must render $fullFmt = $false (quick format)")
	}
	full := okVolumeFormatOpts()
	full.FullFormat = true
	full.FileSystemLabel = "TFDATA"
	full.AllocationUnitSize = 4096
	fs := buildVolumeFormatScript(full)
	for _, want := range []string{"$fullFmt = $true", "NewFileSystemLabel", "AllocationUnitSize", "'NTFS'", "'TFDATA'"} {
		if !strings.Contains(fs, want) {
			t.Errorf("full format script must contain %q", want)
		}
	}
}

func TestVolumeFormatScript_Guards(t *testing.T) {
	s := buildVolumeFormatScript(okVolumeFormatOpts())
	for _, want := range []string{
		"Test-DiskProtected",
		"Test-PartitionProtected",
		"already_formatted",
		"partition_not_found",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("format script must contain %q", want)
		}
	}
}

func TestVolumeScripts_QuoteInputs(t *testing.T) {
	var captured string
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return volumeOK(t, fakeVolumeData()), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	// A hostile label must land in the script only as a quoted literal.
	if _, err := f.SetLabel(context.Background(), `\\?\Volume{1}\`, "x'; $evil; '"); err != nil {
		t.Fatalf("SetLabel err: %v", err)
	}
	if !strings.Contains(captured, "'x''; $evil; '''") {
		t.Errorf("script must carry the quoted doubled label, got: %s", captured)
	}
	if strings.Contains(captured, "x'; $evil; '") {
		t.Errorf("unquoted hostile value must not appear in the script: %s", captured)
	}
}

// ---------------------------------------------------------------------------
// Input validation short-circuits (no remote call)
// ---------------------------------------------------------------------------

func TestVolumeRead_EmptyID_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	if _, err := f.Read(context.Background(), "  "); err == nil {
		t.Error("empty UniqueId should fail validation")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestVolumeFormat_InvalidOpts_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	bad := okVolumeFormatOpts()
	bad.FileSystem = "ext4"
	if _, err := f.Format(context.Background(), bad); err == nil {
		t.Error("unsupported file system should fail validation")
	}
	bad = okVolumeFormatOpts()
	bad.PartitionID = "bogus"
	if _, err := f.Format(context.Background(), bad); err == nil {
		t.Error("malformed partition_id should fail validation")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestVolumeLookup_Invalid_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	if _, err := f.Lookup(context.Background(), VolumeLookup{}); err == nil {
		t.Error("empty lookup should fail validation")
	}
	if _, err := f.Lookup(context.Background(), VolumeLookup{UniqueID: "U", DriveLetter: "E"}); err == nil {
		t.Error("two-coordinate lookup should fail validation")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// runVolumeEnvelope mapping
// ---------------------------------------------------------------------------

func TestRunVolumeEnvelope_Timeout(t *testing.T) {
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := NewVolumeClient(newVolumeTestClient(t))
	_, err := f.Read(ctx, "U")
	if !IsVolumeError(err, VolumeErrorUnknown) {
		t.Errorf("timeout should map to unknown (no dedicated timeout kind), got %v", err)
	}
}

func TestRunVolumeEnvelope_TransportError(t *testing.T) {
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "stdout-junk", "stderr-junk", errors.New("ssh: tcp reset")
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	_, err := f.Read(context.Background(), "U")
	if !IsVolumeError(err, VolumeErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Format
// ---------------------------------------------------------------------------

func TestVolumeFormat_HappyPath(t *testing.T) {
	var captured string
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return volumeOK(t, fakeVolumeData()), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	info, err := f.Format(context.Background(), okVolumeFormatOpts())
	if err != nil {
		t.Fatalf("Format err: %v", err)
	}
	if info == nil || info.FileSystem != "NTFS" || info.SizeBytes != 16777216 {
		t.Errorf("unexpected info: %+v", info)
	}
	if info.PartitionID == "" {
		t.Error("format must resolve the hosting partition_id host-side")
	}
	for _, want := range []string{"Format-Volume", "already_formatted", "partition_not_found", "Test-DiskProtected", "Test-PartitionProtected"} {
		if !strings.Contains(captured, want) {
			t.Errorf("format script must contain %q", want)
		}
	}
}

func TestVolumeFormat_CanonicalizesFileSystem(t *testing.T) {
	var captured string
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return volumeOK(t, fakeVolumeData()), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	opts := okVolumeFormatOpts()
	opts.FileSystem = "ntfs"
	if _, err := f.Format(context.Background(), opts); err != nil {
		t.Fatalf("Format err: %v", err)
	}
	if !strings.Contains(captured, "'NTFS'") {
		t.Errorf("format script must carry the canonical file system, got: %s", captured)
	}
	if strings.Contains(captured, "'ntfs'") {
		t.Errorf("format script must not carry the raw spelling, got: %s", captured)
	}
}

func TestVolumeFormat_AlreadyFormatted(t *testing.T) {
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return volumeErr(t, "already_formatted", "already carries a formatted NTFS volume"), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	_, err := f.Format(context.Background(), okVolumeFormatOpts())
	if !IsVolumeError(err, VolumeErrorAlreadyFormatted) {
		t.Errorf("expected already_formatted, got %v", err)
	}
}

func TestVolumeFormat_Protected(t *testing.T) {
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return volumeErr(t, "protected_storage", "Refusing to manage protected storage: the disk is the boot disk."), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	_, err := f.Format(context.Background(), okVolumeFormatOpts())
	if !IsVolumeError(err, VolumeErrorProtected) {
		t.Errorf("expected protected_storage, got %v", err)
	}
}

func TestVolumeFormat_PartitionNotFound(t *testing.T) {
	for _, kind := range []string{"partition_not_found", "disk_not_found"} {
		restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
			return volumeErr(t, kind, "gone"), "", nil
		})
		f := NewVolumeClient(newVolumeTestClient(t))
		_, err := f.Format(context.Background(), okVolumeFormatOpts())
		restore()
		if !IsVolumeError(err, VolumeErrorPartitionNotFound) {
			t.Errorf("%s should map to partition_not_found, got %v", kind, err)
		}
	}
}

func TestVolumeFormat_UnparseablePayload(t *testing.T) {
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":"not-an-object"}` + "\n", "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	_, err := f.Format(context.Background(), okVolumeFormatOpts())
	if !IsVolumeError(err, VolumeErrorUnknown) {
		t.Errorf("expected unknown for unparseable payload, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestVolumeRead_HappyPath(t *testing.T) {
	var captured string
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return volumeOK(t, fakeVolumeData()), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	info, err := f.Read(context.Background(), `\\?\Volume{11111111-2222-3333-4444-555555555555}\`)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if info == nil {
		t.Fatal("expected info, got nil")
	}
	if info.DriveLetter != "E" || info.FileSystemLabel != "TFDATA" || info.AllocationUnitSize != 4096 {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "Get-Volume -UniqueId") {
		t.Errorf("read script must query by UniqueId, got: %s", captured)
	}
}

func TestVolumeRead_NotFound_NilNil(t *testing.T) {
	for _, kind := range []string{"not_found", "partition_not_found"} {
		restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
			return volumeErr(t, kind, "gone"), "", nil
		})
		f := NewVolumeClient(newVolumeTestClient(t))
		info, err := f.Read(context.Background(), "U")
		restore()
		if err != nil {
			t.Errorf("%s should be swallowed by Read, got %v", kind, err)
		}
		if info != nil {
			t.Errorf("%s: expected nil info, got %+v", kind, info)
		}
	}
}

// ---------------------------------------------------------------------------
// SetLabel
// ---------------------------------------------------------------------------

func TestVolumeSetLabel_HappyPath(t *testing.T) {
	var captured string
	data := fakeVolumeData()
	data["file_system_label"] = "RENAMED"
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return volumeOK(t, data), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	info, err := f.SetLabel(context.Background(), `\\?\Volume{1}\`, "RENAMED")
	if err != nil {
		t.Fatalf("SetLabel err: %v", err)
	}
	if info == nil || info.FileSystemLabel != "RENAMED" {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "Set-Volume -NewFileSystemLabel") {
		t.Errorf("label script must call Set-Volume -NewFileSystemLabel: %s", captured)
	}
}

func TestVolumeSetLabel_EmptyID_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	if _, err := f.SetLabel(context.Background(), "  ", "X"); err == nil {
		t.Error("empty UniqueId should fail validation")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

func TestVolumeLookup_ByLetter(t *testing.T) {
	var captured string
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return volumeOK(t, fakeVolumeData()), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	info, err := f.Lookup(context.Background(), VolumeLookup{DriveLetter: "e:"})
	if err != nil {
		t.Fatalf("Lookup err: %v", err)
	}
	if info == nil || info.DriveLetter != "E" {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "Get-Volume -DriveLetter") {
		t.Errorf("letter lookup must query by drive letter: %s", captured)
	}
	if !strings.Contains(captured, "$lookupMode = 'letter'") {
		t.Errorf("lookup script must carry the letter mode: %s", captured)
	}
}

func TestVolumeLookup_ByLabel(t *testing.T) {
	var captured string
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return volumeOK(t, fakeVolumeData()), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	info, err := f.Lookup(context.Background(), VolumeLookup{FileSystemLabel: "TFDATA"})
	if err != nil {
		t.Fatalf("Lookup err: %v", err)
	}
	if info == nil {
		t.Fatal("expected info, got nil")
	}
	if !strings.Contains(captured, "FileSystemLabel -eq") {
		t.Errorf("label lookup must filter on FileSystemLabel: %s", captured)
	}
}

func TestVolumeLookup_NotFound(t *testing.T) {
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return volumeErr(t, "not_found", "No volume with file system label NOPE."), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	_, err := f.Lookup(context.Background(), VolumeLookup{FileSystemLabel: "NOPE"})
	if !IsVolumeError(err, VolumeErrorNotFound) {
		t.Errorf("expected not_found, got %v", err)
	}
}

// Several label matches surface as unknown (the volume vocabulary has no
// ambiguous kind).
func TestVolumeLookup_AmbiguousLabel_Unknown(t *testing.T) {
	restore := stubVolumeRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return volumeErr(t, "unknown", "2 volumes carry file system label DUP; refine the lookup."), "", nil
	})
	defer restore()
	f := NewVolumeClient(newVolumeTestClient(t))
	_, err := f.Lookup(context.Background(), VolumeLookup{FileSystemLabel: "DUP"})
	if !IsVolumeError(err, VolumeErrorUnknown) {
		t.Errorf("expected unknown for several label matches, got %v", err)
	}
	if !strings.Contains(err.Error(), "2 volumes") {
		t.Errorf("message should carry the match count: %s", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Compile-time assertion mirror.
// ---------------------------------------------------------------------------

func TestVolumeClient_ImplementsInterface(t *testing.T) {
	var _ WindowsVolumeClient = (*VolumeClient)(nil)
}
