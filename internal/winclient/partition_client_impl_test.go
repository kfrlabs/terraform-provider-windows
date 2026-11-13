// Package winclient — unit tests for PartitionClient.
//
// These tests stub the package-level seam runPartitionPowerShell to inject
// scripted stdout/stderr/err triples. They cover the envelope mapping for
// every PartitionErrorKind, the pure-Go helpers (drive-letter normalize,
// GPT aliases, MBR validation, ID build/parse, grow-vs-shrink), input
// validation short-circuits (no remote call), and the script invariants:
// quoting, no `exit`, -Confirm:$false, Update-HostStorageCache,
// -AssignDriveLetter:$false on create, and the protected-partition guard.
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

func newPartitionTestClient(t *testing.T) *Client {
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

// stubPartitionRun replaces runPartitionPowerShell for the duration of a test.
func stubPartitionRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runPartitionPowerShell
	runPartitionPowerShell = fn
	return func() { runPartitionPowerShell = prev }
}

func partitionOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func partitionErr(t *testing.T, kind, msg string) string {
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

func fakePartitionData(key string) map[string]any {
	data := map[string]any{
		"disk_unique_id":     "U1",
		"partition_number":   3,
		"guid":               "",
		"offset_bytes":       1048576,
		"size_bytes":         16777216,
		"drive_letter":       "E",
		"gpt_type":           "",
		"mbr_type":           "0x07",
		"is_hidden":          false,
		"is_active":          false,
		"is_boot":            false,
		"is_system":          false,
		"operational_status": "Online",
		"access_paths":       []string{`E:\`},
	}
	if strings.Contains(key, "-") {
		data["guid"] = key
		data["gpt_type"] = GPTBasicDataPartitionGUID
		data["mbr_type"] = ""
	}
	return data
}

func okPartitionCreateOpts() PartitionCreateOptions {
	return PartitionCreateOptions{
		DiskUniqueID: "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK",
		SizeBytes:    16777216,
		DriveLetter:  "E",
	}
}

// ---------------------------------------------------------------------------
// PartitionError type
// ---------------------------------------------------------------------------

func TestPartitionError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	e := NewPartitionError(PartitionErrorUnknown, "timed out", cause, map[string]string{"host": "win01"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "unknown") || !strings.Contains(msg, "timed out") ||
		!strings.Contains(msg, "underlying") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewPartitionError(PartitionErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestPartitionError_Is_And_IsPartitionError(t *testing.T) {
	e := NewPartitionError(PartitionErrorProtected, "x", nil, nil)
	if !errors.Is(e, ErrPartitionProtected) {
		t.Error("errors.Is(ErrPartitionProtected) should match by kind")
	}
	if errors.Is(e, ErrPartitionNotFound) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsPartitionError(e, PartitionErrorProtected) {
		t.Error("IsPartitionError should match")
	}
	if IsPartitionError(errors.New("plain"), PartitionErrorProtected) {
		t.Error("IsPartitionError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-PartitionError should be false")
	}
}

func TestMapPartitionKind(t *testing.T) {
	cases := map[string]PartitionErrorKind{
		"not_found":                PartitionErrorNotFound,
		"disk_not_found":           PartitionErrorDiskNotFound,
		"disk_not_ready":           PartitionErrorDiskNotReady,
		"insufficient_space":       PartitionErrorInsufficientSpace,
		"drive_letter_in_use":      PartitionErrorDriveLetterInUse,
		"shrink_not_supported":     PartitionErrorShrinkNotSupported,
		"protected_storage":        PartitionErrorProtected,
		"access_denied":            PartitionErrorAccessDenied,
		"unknown":                  PartitionErrorUnknown,
		"":                         PartitionErrorUnknown,
		"weird_kind":               PartitionErrorUnknown,
		"partition_style_mismatch": PartitionErrorUnknown,
	}
	for in, want := range cases {
		if got := mapPartitionKind(in); got != want {
			t.Errorf("mapPartitionKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: drive letters
// ---------------------------------------------------------------------------

func TestNormalizeDriveLetter_Table(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"E", "E", false},
		{"e", "E", false},
		{"  f  ", "F", false},
		{"D", "D", false},
		{"Z", "Z", false},
		{"z", "Z", false},
		{"A", "", true},
		{"B", "", true},
		{"C", "", true},
		{"c", "", true},
		{"", "", true},
		{"  ", "", true},
		{"EE", "", true},
		{"1", "", true},
		{"E:", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := NormalizeDriveLetter(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("NormalizeDriveLetter(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDriveLetter(%q) err: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeDriveLetter(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: GPT aliases
// ---------------------------------------------------------------------------

func TestCanonicalizeGPTType_Table(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"basic_data", GPTBasicDataPartitionGUID, false},
		{"BASIC_DATA", GPTBasicDataPartitionGUID, false},
		{"  msr  ", GPTMicrosoftReservedGUID, false},
		{"Recovery", GPTRecoveryPartitionGUID, false},
		{"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", GPTBasicDataPartitionGUID, false},
		{"{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}", GPTBasicDataPartitionGUID, false},
		{"not-a-guid", "", true},
		{"basic", "", true},
		{"ebd0a0a2-b9e5", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := CanonicalizeGPTType(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("CanonicalizeGPTType(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalizeGPTType(%q) err: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("CanonicalizeGPTType(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: MBR types
// ---------------------------------------------------------------------------

func TestCanonicalizeMBRType_Table(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"IFS", "0x07", false},
		{"ifs", "0x07", false},
		{"NTFS", "0x07", false},
		{"FAT32", "0x0B", false},
		{"fat32_lba", "0x0C", false},
		{"EXTENDED", "0x0F", false},
		{"0x07", "0x07", false},
		{"0x7", "0x07", false},
		{"0x27", "0x27", false},
		{"7", "0x07", false},
		{"39", "0x27", false},
		{"0", "0x00", false},
		{"255", "0xFF", false},
		{"0x100", "", true},
		{"256", "", true},
		{"-1", "", true},
		{"IFS2", "", true},
		{"0xZZ", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := CanonicalizeMBRType(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("CanonicalizeMBRType(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalizeMBRType(%q) err: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("CanonicalizeMBRType(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: ID build/parse round-trip (GPT vs MBR)
// ---------------------------------------------------------------------------

func TestPartitionID_RoundTrip(t *testing.T) {
	disk := `SCSI\DISK&VEN_MSFT&PROD_VIRTUAL_DISK`
	for _, key := range []string{
		"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		"1048576",
	} {
		id, err := BuildPartitionID(disk, key)
		if err != nil {
			t.Fatalf("BuildPartitionID: %v", err)
		}
		gotDisk, gotKey, err := ParsePartitionID(id)
		if err != nil {
			t.Fatalf("ParsePartitionID(%q): %v", id, err)
		}
		if gotDisk != disk || gotKey != key {
			t.Errorf("round-trip(%q) = (%q, %q)", id, gotDisk, gotKey)
		}
	}
}

func TestParsePartitionID_Invalid(t *testing.T) {
	for _, id := range []string{"", "no-separator", "|key", "disk|", "  |  "} {
		if _, _, err := ParsePartitionID(id); err == nil {
			t.Errorf("ParsePartitionID(%q) should fail", id)
		}
	}
}

func TestPartitionResourceKey_GPTvsMBR(t *testing.T) {
	gpt := &PartitionInfo{GUID: "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}", OffsetBytes: 1048576}
	if got := PartitionResourceKey(gpt); got != "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" {
		t.Errorf("GPT key = %q", got)
	}
	mbr := &PartitionInfo{OffsetBytes: 32256}
	if got := PartitionResourceKey(mbr); got != "32256" {
		t.Errorf("MBR key = %q", got)
	}
	zeroGUID := &PartitionInfo{GUID: "00000000-0000-0000-0000-000000000000", OffsetBytes: 32256}
	if got := PartitionResourceKey(zeroGUID); got != "32256" {
		t.Errorf("all-zero GUID must fall back to offset, got %q", got)
	}
	if got := PartitionResourceKey(nil); got != "" {
		t.Errorf("nil info key = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Pure-Go: grow-vs-shrink decision
// ---------------------------------------------------------------------------

func TestDecidePartitionResize_Table(t *testing.T) {
	grow, err := DecidePartitionResize(16777216, 33554432)
	if err != nil || !grow {
		t.Errorf("grow case = (%v, %v), want (true, nil)", grow, err)
	}
	grow, err = DecidePartitionResize(16777216, 16777216)
	if err != nil || grow {
		t.Errorf("equal case = (%v, %v), want (false, nil)", grow, err)
	}
	_, err = DecidePartitionResize(33554432, 16777216)
	if !IsPartitionError(err, PartitionErrorShrinkNotSupported) {
		t.Errorf("shrink must be shrink_not_supported, got %v", err)
	}
	if !errors.Is(err, ErrPartitionShrinkNotSupported) {
		t.Errorf("shrink must match the sentinel, got %v", err)
	}
	if _, err = DecidePartitionResize(16777216, 0); err == nil {
		t.Error("zero desired size must fail")
	}
	if _, err = DecidePartitionResize(16777216, -8); err == nil {
		t.Error("negative desired size must fail")
	}
}

func TestValidatePartitionCreateOptions(t *testing.T) {
	if err := ValidatePartitionCreateOptions(okPartitionCreateOpts()); err != nil {
		t.Errorf("valid opts rejected: %v", err)
	}
	bad := okPartitionCreateOpts()
	bad.DiskUniqueID = "  "
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("empty disk id must fail")
	}
	bad = okPartitionCreateOpts()
	bad.SizeBytes = 0
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("zero size without use_maximum_size must fail")
	}
	maxOpts := okPartitionCreateOpts()
	maxOpts.SizeBytes = 0
	maxOpts.UseMaximumSize = true
	if err := ValidatePartitionCreateOptions(maxOpts); err != nil {
		t.Errorf("use_maximum_size with zero size must pass: %v", err)
	}
	bad = okPartitionCreateOpts()
	bad.DriveLetter = "C"
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("reserved letter must fail")
	}
	bad = okPartitionCreateOpts()
	bad.GptType = "x"
	bad.MbrType = "y"
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("gpt+mbr together must fail")
	}
	bad = okPartitionCreateOpts()
	bad.GptType = "not-a-guid"
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("malformed gpt_type must fail even without mbr_type")
	}
	bad = okPartitionCreateOpts()
	bad.MbrType = "0xZZ"
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("malformed mbr_type must fail even without gpt_type")
	}
	aliasOpts := okPartitionCreateOpts()
	aliasOpts.GptType = "basic_data"
	if err := ValidatePartitionCreateOptions(aliasOpts); err != nil {
		t.Errorf("gpt alias must pass validation: %v", err)
	}
	aliasOpts = okPartitionCreateOpts()
	aliasOpts.MbrType = "ifs"
	if err := ValidatePartitionCreateOptions(aliasOpts); err != nil {
		t.Errorf("mbr alias must pass validation: %v", err)
	}
	bad = okPartitionCreateOpts()
	bad.HasOffset = true
	bad.OffsetBytes = -1
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("negative offset must fail")
	}
	bad = okPartitionCreateOpts()
	bad.UseMaximumSize = true
	bad.SizeBytes = 16777216
	if err := ValidatePartitionCreateOptions(bad); err == nil {
		t.Error("use_maximum_size with an explicit size must fail (size is silently ignored)")
	}
}

// ---------------------------------------------------------------------------
// Script invariants: quoting, no exit, prelude
// ---------------------------------------------------------------------------

func partitionTestScripts(t *testing.T) map[string]string {
	t.Helper()
	opts := okPartitionCreateOpts()
	boolPtr := func(b bool) *bool { return &b }
	return map[string]string{
		"create": buildPartitionCreateScript(opts),
		"read":   buildPartitionReadScript("U", "K"),
		"grow":   buildPartitionGrowScript("U", "K", 33554432),
		"letter": buildPartitionLetterScript("U", "K", "E"),
		"flags":  buildPartitionFlagsScript("U", "K", boolPtr(true), boolPtr(false)),
		"delete": buildPartitionDeleteScript("U", "K"),
		"lib":    psStorageHeader + "\n" + psDiskFunctions + "\n" + psPartitionFunctions,
	}
}

func TestPartitionScripts_NeverUseExit(t *testing.T) {
	scripts := partitionTestScripts(t)
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

func TestPartitionScripts_MutationsCarryNoConfirm(t *testing.T) {
	hidden := true
	for name, s := range map[string]string{
		"create": buildPartitionCreateScript(okPartitionCreateOpts()),
		"grow":   buildPartitionGrowScript("U", "K", 33554432),
		"letter": buildPartitionLetterScript("U", "K", "E"),
		"flags":  buildPartitionFlagsScript("U", "K", &hidden, nil),
		"delete": buildPartitionDeleteScript("U", "K"),
	} {
		if !strings.Contains(s, "-Confirm:$false") {
			t.Errorf("%s: mutating cmdlet must carry -Confirm:$false", name)
		}
	}
}

// Create must pin -AssignDriveLetter:$false and assign the configured letter
// explicitly afterwards (no random letters, no Explorer format race).
func TestPartitionCreateScript_AssignDriveLetterFalse(t *testing.T) {
	s := buildPartitionCreateScript(okPartitionCreateOpts())
	if !strings.Contains(s, "-AssignDriveLetter:$false") && !strings.Contains(s, "AssignDriveLetter = $false") {
		t.Errorf("create must pin -AssignDriveLetter:$false:\n%s", s)
	}
	if !strings.Contains(s, "Set-Partition -NewDriveLetter") {
		t.Errorf("create must assign the configured letter explicitly:\n%s", s)
	}
	if !strings.Contains(s, "'E'") {
		t.Errorf("create must carry the quoted drive letter:\n%s", s)
	}
}

// TestPartitionScripts_ProtectedGuardOrder pins the Test-PartitionProtected
// reason precedence: boot, system, EFI, MSR, recovery, pagefile.
func TestPartitionScripts_ProtectedGuardOrder(t *testing.T) {
	probes := []string{
		"the partition is the boot partition",
		"the partition is the system partition",
		"the partition is the EFI system partition",
		"the partition is a Microsoft reserved (MSR) partition",
		"the partition is a recovery partition",
		"the partition hosts the active pagefile",
	}
	prev := -1
	for _, p := range probes {
		idx := strings.Index(psPartitionFunctions, p)
		if idx < 0 {
			t.Fatalf("Test-PartitionProtected must report %q", p)
		}
		if idx <= prev {
			t.Errorf("guard order drift: %q must come after the previous probe", p)
		}
		prev = idx
	}
}

// The guard must be fail-closed: an undeterminable pagefile placement is a
// reason, and a letterless partition skips the probe without failing.
func TestPartitionScripts_GuardFailClosed(t *testing.T) {
	if !strings.Contains(psPartitionFunctions, "pagefile placement could not be determined") {
		t.Error("guard must fail closed when pagefile placement cannot be determined")
	}
	if !strings.Contains(psPartitionFunctions, "if ($dl -eq '')") {
		t.Error("guard must skip the pagefile probe for letterless partitions")
	}
	// Delete (and every other op body) must consult the guard.
	for name, s := range partitionTestScripts(t) {
		if name == "lib" {
			continue
		}
		if !strings.Contains(s, "Test-PartitionProtected") && name != "create" {
			t.Errorf("%s must consult Test-PartitionProtected", name)
		}
	}
	if !strings.Contains(psDiskFunctions, "Test-DiskProtected") {
		t.Error("partition package must reuse the shared disk guard")
	}
	if !strings.Contains(partitionTestScripts(t)["create"], "Test-DiskProtected") {
		t.Error("create must reuse the shared disk guard")
	}
}

func TestPartitionScripts_IdentityNeverByNumber(t *testing.T) {
	// Resolve-Partition takes GUID-or-offset keys; PartitionNumber must never
	// select (it is only forwarded to cmdlets that require it, alongside the
	// disk number that scopes them).
	lib := psDiskFunctions + "\n" + psPartitionFunctions
	if strings.Contains(lib, "Get-Partition -PartitionNumber") {
		t.Error("partition lookup must never select by partition number")
	}
	for _, s := range []string{
		buildPartitionReadScript("U", "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"),
		buildPartitionDeleteScript("U", "1048576"),
	} {
		if !strings.Contains(s, "$partKey") {
			t.Error("op scripts must thread the GUID/offset key")
		}
	}
}

func TestPartitionScripts_QuoteInputs(t *testing.T) {
	var captured string
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, fakePartitionData("1048576")), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	// A hostile disk id must land in the script only as a quoted literal.
	if _, err := f.Read(context.Background(), "x'; $evil; '", "1048576"); err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if !strings.Contains(captured, "'X''; $EVIL; '''") {
		t.Errorf("script must carry the quoted doubled disk id, got: %s", captured)
	}
	if strings.Contains(captured, "x'; $evil; '") {
		t.Errorf("unquoted hostile value must not appear in the script: %s", captured)
	}
}

// ---------------------------------------------------------------------------
// Input validation short-circuits (no remote call)
// ---------------------------------------------------------------------------

func TestPartitionRead_EmptyRef_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	for _, tc := range [][2]string{{"", "K"}, {"U", ""}, {"  ", "  "}} {
		if _, err := f.Read(context.Background(), tc[0], tc[1]); err == nil {
			t.Errorf("empty ref (%q, %q) should fail validation", tc[0], tc[1])
		}
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestPartitionCreate_InvalidOpts_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	bad := okPartitionCreateOpts()
	bad.SizeBytes = -1
	if _, err := f.Create(context.Background(), bad); err == nil {
		t.Error("negative size should fail validation")
	}
	bad = okPartitionCreateOpts()
	bad.DriveLetter = "C"
	if _, err := f.Create(context.Background(), bad); err == nil {
		t.Error("reserved letter should fail validation")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestPartitionGrow_InvalidSize_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	if _, err := f.Grow(context.Background(), "U", "K", 0); err == nil {
		t.Error("zero grow size should fail")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestPartitionSetDriveLetter_InvalidLetter_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	if _, err := f.SetDriveLetter(context.Background(), "U", "K", "C"); err == nil {
		t.Error("reserved letter should fail validation")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestPartitionDelete_EmptyRef_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	if err := f.Delete(context.Background(), "", "K"); err == nil {
		t.Error("empty disk id should fail")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// runPartitionEnvelope mapping
// ---------------------------------------------------------------------------

func TestRunPartitionEnvelope_Timeout(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := NewPartitionClient(newPartitionTestClient(t))
	_, err := f.Read(ctx, "U", "K")
	if !IsPartitionError(err, PartitionErrorUnknown) {
		t.Errorf("timeout should map to unknown (no dedicated timeout kind), got %v", err)
	}
}

func TestRunPartitionEnvelope_TransportError(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "stdout-junk", "stderr-junk", errors.New("ssh: tcp reset")
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	_, err := f.Read(context.Background(), "U", "K")
	if !IsPartitionError(err, PartitionErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestPartitionRead_HappyPath(t *testing.T) {
	var captured string
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, fakePartitionData("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	info, err := f.Read(context.Background(), "U1", "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if info == nil {
		t.Fatal("expected info, got nil")
	}
	if info.DiskUniqueID != "U1" || info.SizeBytes != 16777216 {
		t.Errorf("unexpected info: %+v", info)
	}
	if info.GUID != "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" || info.PartitionNumber != 3 {
		t.Errorf("unexpected identity: %+v", info)
	}
	if info.DriveLetter != "E" || info.PartitionNumber != 3 {
		t.Errorf("unexpected flags: %+v", info)
	}
	if !strings.Contains(captured, "'U1'") {
		t.Errorf("script missing quoted disk id: %s", captured)
	}
}

func TestPartitionRead_NotFound_NilNil(t *testing.T) {
	for _, kind := range []string{"not_found", "disk_not_found"} {
		restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
			return partitionErr(t, kind, "gone"), "", nil
		})
		f := NewPartitionClient(newPartitionTestClient(t))
		info, err := f.Read(context.Background(), "U", "K")
		restore()
		if err != nil {
			t.Errorf("%s should be swallowed by Read, got %v", kind, err)
		}
		if info != nil {
			t.Errorf("%s: expected nil info, got %+v", kind, info)
		}
	}
}

func TestPartitionRead_Protected(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return partitionErr(t, "protected_storage", "Refusing to manage a protected partition: the partition is the boot partition."), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	_, err := f.Read(context.Background(), "U", "K")
	if !IsPartitionError(err, PartitionErrorProtected) {
		t.Errorf("expected protected_storage, got %v", err)
	}
	if !strings.Contains(err.Error(), "boot") {
		t.Errorf("message should carry the reason: %s", err.Error())
	}
}

func TestPartitionRead_UnparseablePayload(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":"not-an-object"}` + "\n", "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	_, err := f.Read(context.Background(), "U", "K")
	if !IsPartitionError(err, PartitionErrorUnknown) {
		t.Errorf("expected unknown for unparseable payload, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestPartitionCreate_HappyPath(t *testing.T) {
	var captured string
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, fakePartitionData("1048576")), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	info, err := f.Create(context.Background(), okPartitionCreateOpts())
	if err != nil {
		t.Fatalf("Create err: %v", err)
	}
	if info == nil || info.SizeBytes != 16777216 {
		t.Errorf("unexpected info: %+v", info)
	}
	for _, want := range []string{"New-Partition", "Get-PartitionSupportedSize", "insufficient_space", "disk_not_ready"} {
		if !strings.Contains(captured, want) {
			t.Errorf("create script must contain %q", want)
		}
	}
}

func TestPartitionCreate_InsufficientSpace(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return partitionErr(t, "insufficient_space", "largest free extent is 4096 bytes"), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	_, err := f.Create(context.Background(), okPartitionCreateOpts())
	if !IsPartitionError(err, PartitionErrorInsufficientSpace) {
		t.Errorf("expected insufficient_space, got %v", err)
	}
	if !strings.Contains(err.Error(), "4096") {
		t.Errorf("message should carry the largest extent: %s", err.Error())
	}
}

func TestPartitionCreate_DiskNotReady(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return partitionErr(t, "disk_not_ready", "is not initialized (RAW)"), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	_, err := f.Create(context.Background(), okPartitionCreateOpts())
	if !IsPartitionError(err, PartitionErrorDiskNotReady) {
		t.Errorf("expected disk_not_ready, got %v", err)
	}
}

func TestPartitionCreate_DriveLetterInUse(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return partitionErr(t, "drive_letter_in_use", "letter E is already in use"), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	_, err := f.Create(context.Background(), okPartitionCreateOpts())
	if !IsPartitionError(err, PartitionErrorDriveLetterInUse) {
		t.Errorf("expected drive_letter_in_use, got %v", err)
	}
}

// Aliases must be canonicalized client-side so direct API callers never send
// a friendly spelling to the host (which would fail host-side as unknown).
func TestPartitionCreate_CanonicalizesTypes(t *testing.T) {
	var captured string
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, fakePartitionData("1048576")), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	opts := okPartitionCreateOpts()
	opts.GptType = "basic_data"
	if _, err := f.Create(context.Background(), opts); err != nil {
		t.Fatalf("Create err: %v", err)
	}
	if !strings.Contains(captured, GPTBasicDataPartitionGUID) {
		t.Errorf("create script must carry the canonical GPT GUID, got: %s", captured)
	}
	if strings.Contains(captured, "basic_data") {
		t.Errorf("create script must not carry the raw alias, got: %s", captured)
	}
	opts = okPartitionCreateOpts()
	opts.MbrType = "ifs"
	if _, err := f.Create(context.Background(), opts); err != nil {
		t.Fatalf("Create err: %v", err)
	}
	if !strings.Contains(captured, "0x07") {
		t.Errorf("create script must carry the canonical MBR byte, got: %s", captured)
	}
}

// ---------------------------------------------------------------------------
// Grow / SetDriveLetter / SetFlags / Delete
// ---------------------------------------------------------------------------

func TestPartitionGrow_HappyPath(t *testing.T) {
	var captured string
	data := fakePartitionData("1048576")
	data["size_bytes"] = 33554432
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, data), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	info, err := f.Grow(context.Background(), "U1", "1048576", 33554432)
	if err != nil {
		t.Fatalf("Grow err: %v", err)
	}
	if info == nil || info.SizeBytes != 33554432 {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "Resize-Partition") || !strings.Contains(captured, "Get-PartitionSupportedSize") {
		t.Errorf("grow script must probe supported size and resize: %s", captured)
	}
}

// The grow script must refuse shrinking host-side against the re-read size
// (a stale desired size must never resize blindly) and treat an equal size
// as a no-op re-read.
func TestPartitionGrowScript_ShrinkBackstop(t *testing.T) {
	s := buildPartitionGrowScript("U", "K", 33554432)
	for _, want := range []string{"$cur", "shrink_not_supported", "Resize-Partition"} {
		if !strings.Contains(s, want) {
			t.Errorf("grow script must contain %q", want)
		}
	}
}

func TestPartitionSetDriveLetter_Removal(t *testing.T) {
	var captured string
	data := fakePartitionData("1048576")
	data["drive_letter"] = ""
	data["access_paths"] = []string{}
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, data), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	info, err := f.SetDriveLetter(context.Background(), "U1", "1048576", "")
	if err != nil {
		t.Fatalf("SetDriveLetter err: %v", err)
	}
	if info == nil || info.DriveLetter != "" {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "Remove-PartitionAccessPath") {
		t.Errorf("letter removal must use Remove-PartitionAccessPath: %s", captured)
	}
}

func TestPartitionSetFlags_HiddenOnly(t *testing.T) {
	var captured string
	hidden := true
	data := fakePartitionData("1048576")
	data["is_hidden"] = true
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, data), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	info, err := f.SetFlags(context.Background(), "U1", "1048576", &hidden, nil)
	if err != nil {
		t.Fatalf("SetFlags err: %v", err)
	}
	if info == nil || !info.IsHidden {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "IsHidden") {
		t.Errorf("flags script must set IsHidden: %s", captured)
	}
}

func TestPartitionSetFlags_BothNil_ReReads(t *testing.T) {
	called := 0
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called++
		return partitionOK(t, fakePartitionData("1048576")), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	if _, err := f.SetFlags(context.Background(), "U1", "1048576", nil, nil); err != nil {
		t.Fatalf("SetFlags err: %v", err)
	}
	if called != 1 {
		t.Errorf("both-nil flags should re-read once, calls=%d", called)
	}
}

func TestPartitionDelete_HappyPath(t *testing.T) {
	var captured string
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return partitionOK(t, nil), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	if err := f.Delete(context.Background(), "U1", "1048576"); err != nil {
		t.Fatalf("Delete err: %v", err)
	}
	if !strings.Contains(captured, "Remove-Partition") {
		t.Errorf("delete script must call Remove-Partition: %s", captured)
	}
	if !strings.Contains(captured, "Test-PartitionProtected") {
		t.Errorf("delete must consult the partition guard: %s", captured)
	}
}

// Delete must consult the disk guard and use a non-quiet lookup: enumerate
// and probe failures must surface as errors, while a genuine not_found is
// swallowed Go-side as success (Delete stays idempotent).
func TestPartitionDeleteScript_GuardsAndNonQuietLookup(t *testing.T) {
	s := buildPartitionDeleteScript("U", "K")
	if !strings.Contains(s, "Test-DiskProtected") {
		t.Error("delete must consult the disk guard")
	}
	if !strings.Contains(s, "Resolve-Partition $d $partKey $false") {
		t.Error("delete lookup must be non-quiet so enumerate failures surface")
	}
	// The missing-partition branch must return without emitting success
	// script-side: the not_found envelope is swallowed Go-side instead.
	if !strings.Contains(s, "$p = Resolve-Partition $d $partKey $false\n  if ($null -eq $p) { return }") {
		t.Error("delete must return (not Emit-OK) when the lookup finds nothing")
	}
}

func TestPartitionDelete_NotFound_Success(t *testing.T) {
	for _, kind := range []string{"not_found", "disk_not_found"} {
		restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
			return partitionErr(t, kind, "gone"), "", nil
		})
		f := NewPartitionClient(newPartitionTestClient(t))
		err := f.Delete(context.Background(), "U", "K")
		restore()
		if err != nil {
			t.Errorf("%s should be success on Delete, got %v", kind, err)
		}
	}
}

func TestPartitionDelete_Protected(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return partitionErr(t, "protected_storage", "Refusing to manage a protected partition: the partition hosts the active pagefile on drive C:"), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	err := f.Delete(context.Background(), "U", "K")
	if !IsPartitionError(err, PartitionErrorProtected) {
		t.Errorf("expected protected_storage, got %v", err)
	}
}

func TestPartitionDelete_AccessDenied(t *testing.T) {
	restore := stubPartitionRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return partitionErr(t, "access_denied", "Access is denied"), "", nil
	})
	defer restore()
	f := NewPartitionClient(newPartitionTestClient(t))
	err := f.Delete(context.Background(), "U", "K")
	if !IsPartitionError(err, PartitionErrorAccessDenied) {
		t.Errorf("expected access_denied, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Compile-time assertion mirror.
// ---------------------------------------------------------------------------

func TestPartitionClient_ImplementsInterface(t *testing.T) {
	var _ WindowsPartitionClient = (*PartitionClient)(nil)
}
