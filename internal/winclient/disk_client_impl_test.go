// Package winclient — unit tests for DiskClient.
//
// These tests stub the package-level seam runDiskPowerShell to inject
// scripted stdout/stderr/err triples. They cover the envelope mapping for
// every DiskErrorKind, selector short-circuits (no remote call), the
// RAW-only Initialize gate, the Set scripts, and the invariant that scripts
// never terminate the persistent session (no `exit`).
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newDiskTestClient(t *testing.T) *Client {
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

// stubDiskRun replaces runDiskPowerShell for the duration of a test.
func stubDiskRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runDiskPowerShell
	runDiskPowerShell = fn
	return func() { runDiskPowerShell = prev }
}

func diskOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func diskErr(t *testing.T, kind, msg string) string {
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

func fakeDiskData(uniqueID string) map[string]any {
	return map[string]any{
		"number":             2,
		"unique_id":          uniqueID,
		"serial_number":      "6000C296-ABC",
		"location":           "PCI Slot 0",
		"friendly_name":      "Msft Virtual Disk",
		"bus_type":           "Virtual",
		"health_status":      "Healthy",
		"operational_status": "Online",
		"partition_style":    "GPT",
		"is_offline":         false,
		"is_read_only":       false,
		"is_boot":            false,
		"is_system":          false,
		"is_clustered":       false,
		"size_bytes":         137438953472,
	}
}

// ---------------------------------------------------------------------------
// DiskError type
// ---------------------------------------------------------------------------

func TestDiskError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	e := NewDiskError(DiskErrorUnknown, "timed out", cause, map[string]string{"host": "win01"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "unknown") || !strings.Contains(msg, "timed out") ||
		!strings.Contains(msg, "underlying") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewDiskError(DiskErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestDiskError_Is_And_IsDiskError(t *testing.T) {
	e := NewDiskError(DiskErrorAmbiguous, "x", nil, nil)
	if !errors.Is(e, ErrDiskAmbiguous) {
		t.Error("errors.Is(ErrDiskAmbiguous) should match by kind")
	}
	if errors.Is(e, ErrDiskNotFound) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsDiskError(e, DiskErrorAmbiguous) {
		t.Error("IsDiskError should match")
	}
	if IsDiskError(errors.New("plain"), DiskErrorAmbiguous) {
		t.Error("IsDiskError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-DiskError should be false")
	}
}

func TestMapDiskKind(t *testing.T) {
	cases := map[string]DiskErrorKind{
		"disk_not_found":           DiskErrorNotFound,
		"ambiguous_disk":           DiskErrorAmbiguous,
		"protected_storage":        DiskErrorProtected,
		"partition_style_mismatch": DiskErrorPartitionStyleMismatch,
		"disk_offline":             DiskErrorOffline,
		"access_denied":            DiskErrorAccessDenied,
		"unsupported":              DiskErrorUnsupported,
		"unknown":                  DiskErrorUnknown,
		"":                         DiskErrorUnknown,
		"weird_kind":               DiskErrorUnknown,
	}
	for in, want := range cases {
		if got := mapDiskKind(in); got != want {
			t.Errorf("mapDiskKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Script invariants: quoting, no exit, prelude
// ---------------------------------------------------------------------------

var exitWord = regexp.MustCompile(`(?i)\bexit\b`)

func TestDiskScripts_NeverUseExit(t *testing.T) {
	sel := DiskSelectorByUniqueID("SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK")
	scripts := map[string]string{
		"read":    buildDiskReadScript(sel),
		"set_off": buildDiskSetOfflineScript("U", true),
		"set_ro":  buildDiskSetReadOnlyScript("U", true),
		"prelude": psStorageHeader + "\n" + psDiskFunctions,
	}
	init, err := buildDiskInitializeScript("U", "GPT")
	if err != nil {
		t.Fatalf("buildDiskInitializeScript: %v", err)
	}
	scripts["initialize"] = init
	for name, s := range scripts {
		t.Run(name, func(t *testing.T) {
			if exitWord.MatchString(s) {
				t.Errorf("script must never use `exit` (it would kill the persistent session)")
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

func TestDiskScripts_MutationsCarryNoConfirm(t *testing.T) {
	init, err := buildDiskInitializeScript("U", "GPT")
	if err != nil {
		t.Fatalf("buildDiskInitializeScript: %v", err)
	}
	for name, s := range map[string]string{
		"initialize": init,
		"set_off":    buildDiskSetOfflineScript("U", true),
		"set_ro":     buildDiskSetReadOnlyScript("U", false),
	} {
		if !strings.Contains(s, "-Confirm:$false") {
			t.Errorf("%s: mutating cmdlet must carry -Confirm:$false", name)
		}
	}
}

// TestDiskScripts_LocationMatchTrims pins the documented case-insensitive,
// trim-tolerant location match: the host side is trimmed just like the
// serial branch, while -eq keeps the comparison case-insensitive and both
// selector values are upper-cased Go-side via NormalizeDiskIdentity.
func TestDiskScripts_LocationMatchTrims(t *testing.T) {
	if !strings.Contains(psDiskFunctions, "([string]$d.Location).Trim() -eq $selLocation") {
		t.Error("Resolve-Disk must trim the host location before comparing, mirroring the serial branch")
	}
	if !strings.Contains(psDiskFunctions, "([string]$d.SerialNumber).Trim() -eq $selSerial") {
		t.Error("Resolve-Disk must keep trimming the host serial number before comparing")
	}
	script := buildDiskReadScript(DiskSelectorByLocation("  pci slot 0  "))
	if !strings.Contains(script, "$selLocation = 'PCI SLOT 0'") {
		t.Errorf("location selector must be normalized (trimmed + upper-cased), got:\n%s", script)
	}
}

// TestDiskScripts_ProtectedGuardOrder pins the Test-DiskProtected reason
// precedence shared with DiskGuardInfo.ProtectedStorageReason (Go): boot,
// system, clustered, pagefile, crash-dump. The script additionally
// short-circuits offline disks between clustered and the placement probe.
func TestDiskScripts_ProtectedGuardOrder(t *testing.T) {
	probes := []string{
		"the disk is the boot disk",
		"the disk is the system disk",
		"the disk is clustered",
		"the disk hosts the active pagefile",
		"the disk hosts the crash-dump target",
	}
	prev := -1
	for _, p := range probes {
		idx := strings.Index(psDiskFunctions, p)
		if idx < 0 {
			t.Fatalf("Test-DiskProtected must report %q", p)
		}
		if idx <= prev {
			t.Errorf("guard order drift: %q must come after the previous probe (shared precedence boot > system > clustered > pagefile > crash-dump)", p)
		}
		prev = idx
	}
}

func TestDiskScripts_QuoteSelector(t *testing.T) {
	var captured string
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return diskOK(t, fakeDiskData("U1")), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	// A hostile serial must land in the script only as a quoted literal
	// (normalized to upper-case, embedded quotes doubled).
	if _, err := f.Read(context.Background(), DiskSelector{SerialNumber: "x'; $evil; '"}); err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if !strings.Contains(captured, "'X''; $EVIL; '''") {
		t.Errorf("script must carry the quoted doubled serial, got: %s", captured)
	}
	if strings.Contains(captured, "x'; $evil; '") {
		t.Errorf("unquoted hostile value must not appear in the script: %s", captured)
	}
}

// ---------------------------------------------------------------------------
// Input validation short-circuits (no remote call)
// ---------------------------------------------------------------------------

func TestDiskRead_EmptySelector_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	if _, err := f.Read(context.Background(), DiskSelector{}); err == nil {
		t.Error("empty selector should fail validation")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestDiskInitialize_InvalidStyle_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	for _, style := range []string{"", "RAW", "dynamic", "basic"} {
		if _, err := f.Initialize(context.Background(), "U", style); err == nil {
			t.Errorf("style %q should fail validation", style)
		}
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

func TestDiskSet_EmptyUniqueID_NoRemoteCall(t *testing.T) {
	called := false
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	if _, err := f.SetOnlineState(context.Background(), "  ", true); err == nil {
		t.Error("empty UniqueId should fail")
	}
	if _, err := f.SetReadOnlyState(context.Background(), "", true); err == nil {
		t.Error("empty UniqueId should fail")
	}
	if called {
		t.Error("validation failure must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// runDiskEnvelope mapping
// ---------------------------------------------------------------------------

func TestRunDiskEnvelope_Timeout(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(ctx, DiskSelectorByNumber(2))
	if !IsDiskError(err, DiskErrorUnknown) {
		t.Errorf("timeout should map to unknown (no dedicated timeout kind), got %v", err)
	}
}

func TestRunDiskEnvelope_TransportError(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "stdout-junk", "stderr-junk", errors.New("ssh: tcp reset")
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorByNumber(2))
	if !IsDiskError(err, DiskErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestRunDiskEnvelope_NoJSON(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "WARNING: no JSON\n", "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorByNumber(2))
	if !IsDiskError(err, DiskErrorUnknown) {
		t.Errorf("missing envelope should yield unknown, got %v", err)
	}
}

func TestRunDiskEnvelope_MalformedJSON(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "{not:valid,json}\n", "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorByNumber(2))
	if !IsDiskError(err, DiskErrorUnknown) {
		t.Errorf("malformed JSON should yield unknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestDiskRead_HappyPath(t *testing.T) {
	var captured string
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return diskOK(t, fakeDiskData("SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK")), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	info, err := f.Read(context.Background(), DiskSelectorByUniqueID("SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK"))
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if info == nil {
		t.Fatal("expected info, got nil")
	}
	if info.UniqueID != "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK" || info.Number != 2 || info.SizeBytes != 137438953472 {
		t.Errorf("unexpected info: %+v", info)
	}
	if info.PartitionStyle != "GPT" || info.IsOffline || info.IsReadOnly {
		t.Errorf("unexpected flags: %+v", info)
	}
	if !strings.Contains(captured, "'SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK'") {
		t.Errorf("script missing quoted UniqueId: %s", captured)
	}
}

func TestDiskRead_NotFound_NilNil(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskErr(t, "disk_not_found", "No disk matches number 9."), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	info, err := f.Read(context.Background(), DiskSelectorByNumber(9))
	if err != nil {
		t.Errorf("disk_not_found should be swallowed by Read, got %v", err)
	}
	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}
}

func TestDiskRead_Ambiguous(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskErr(t, "ambiguous_disk", "2 disks match serial_number."), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorBySerialNumber("DUP"))
	if !IsDiskError(err, DiskErrorAmbiguous) {
		t.Errorf("expected ambiguous_disk, got %v", err)
	}
}

func TestDiskRead_Protected(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskErr(t, "protected_storage", "Refusing to manage protected storage: the disk is the boot disk."), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorByNumber(0))
	if !IsDiskError(err, DiskErrorProtected) {
		t.Errorf("expected protected_storage, got %v", err)
	}
	if !strings.Contains(err.Error(), "boot") {
		t.Errorf("message should carry the reason: %s", err.Error())
	}
}

func TestDiskRead_UnparseablePayload(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":"not-an-object"}` + "\n", "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorByNumber(2))
	if !IsDiskError(err, DiskErrorUnknown) {
		t.Errorf("expected unknown for unparseable payload, got %v", err)
	}
}

func TestDiskRead_MissingUniqueID(t *testing.T) {
	data := fakeDiskData("")
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskOK(t, data), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorByNumber(2))
	if !IsDiskError(err, DiskErrorUnknown) {
		t.Errorf("a disk without UniqueId cannot be adopted, want unknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Initialize (RAW-only gate)
// ---------------------------------------------------------------------------

func TestDiskInitialize_HappyPath(t *testing.T) {
	var captured string
	data := fakeDiskData("U1")
	data["partition_style"] = "GPT"
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return diskOK(t, data), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	info, err := f.Initialize(context.Background(), "U1", "gpt")
	if err != nil {
		t.Fatalf("Initialize err: %v", err)
	}
	if info == nil || info.PartitionStyle != "GPT" {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "Initialize-Disk") {
		t.Errorf("script must call Initialize-Disk: %s", captured)
	}
	if !strings.Contains(captured, "-PartitionStyle GPT") {
		t.Errorf("script must initialize to GPT: %s", captured)
	}
	if !strings.Contains(captured, "'RAW'") {
		t.Errorf("script must gate on RAW: %s", captured)
	}
	if !strings.Contains(captured, "partition_style_mismatch") {
		t.Errorf("script must emit partition_style_mismatch for non-RAW: %s", captured)
	}
}

func TestDiskInitialize_Mismatch(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskErr(t, "partition_style_mismatch", "already carries partition style GPT"), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Initialize(context.Background(), "U1", "MBR")
	if !IsDiskError(err, DiskErrorPartitionStyleMismatch) {
		t.Errorf("expected partition_style_mismatch, got %v", err)
	}
}

func TestDiskInitialize_OfflineDisk(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskErr(t, "disk_offline", "is offline; bring it online"), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Initialize(context.Background(), "U1", "GPT")
	if !IsDiskError(err, DiskErrorOffline) {
		t.Errorf("expected disk_offline, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SetOnlineState / SetReadOnlyState
// ---------------------------------------------------------------------------

func TestDiskSetOnlineState_HappyPath(t *testing.T) {
	var captured string
	data := fakeDiskData("U1")
	data["is_offline"] = true
	data["operational_status"] = "Offline"
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return diskOK(t, data), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	info, err := f.SetOnlineState(context.Background(), "U1", true)
	if err != nil {
		t.Fatalf("SetOnlineState err: %v", err)
	}
	if info == nil || !info.IsOffline {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "Set-Disk") || !strings.Contains(captured, "-IsOffline:$true") {
		t.Errorf("script must take the disk offline: %s", captured)
	}
}

func TestDiskSetReadOnlyState_HappyPath(t *testing.T) {
	var captured string
	data := fakeDiskData("U1")
	data["is_read_only"] = true
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return diskOK(t, data), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	info, err := f.SetReadOnlyState(context.Background(), "U1", true)
	if err != nil {
		t.Fatalf("SetReadOnlyState err: %v", err)
	}
	if info == nil || !info.IsReadOnly {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "-IsReadOnly:$true") {
		t.Errorf("script must set read-only: %s", captured)
	}
}

func TestDiskSet_AccessDenied(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskErr(t, "access_denied", "Access is denied"), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.SetOnlineState(context.Background(), "U1", false)
	if !IsDiskError(err, DiskErrorAccessDenied) {
		t.Errorf("expected access_denied, got %v", err)
	}
}

func TestDiskRead_Unsupported(t *testing.T) {
	restore := stubDiskRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return diskErr(t, "unsupported", "Get-Disk is not recognized"), "", nil
	})
	defer restore()
	f := NewDiskClient(newDiskTestClient(t))
	_, err := f.Read(context.Background(), DiskSelectorByNumber(0))
	if !IsDiskError(err, DiskErrorUnsupported) {
		t.Errorf("expected unsupported, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Compile-time assertion mirror.
// ---------------------------------------------------------------------------

func TestDiskClient_ImplementsInterface(t *testing.T) {
	var _ WindowsDiskClient = (*DiskClient)(nil)
}
