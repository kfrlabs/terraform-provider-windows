// Package winclient — unit tests for OSInfoClient.
//
// These tests stub the package-level runPowerShell seam to inject scripted
// stdout/stderr/err triples. They cover the windows_os_info mapping tables
// (SKU / product type / architecture, including unknown codes degrading to
// ""), the missing DisplayVersion/UBR fallbacks, ISO 8601 date passthrough,
// empty MachineGuid tolerance, transport/timeout classification, the #81
// no-exit invariant and the Classify-OSInfo mapping.
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func newOSInfoTestClient(t *testing.T) *Client {
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

// stubOSInfoRun replaces runPowerShell for the duration of a test and
// captures the script the client sends.
func stubOSInfoRun(t *testing.T, fn func(script string) (string, string, error)) (func(), *string) {
	t.Helper()
	prev := runPowerShell
	var gotScript string
	runPowerShell = func(_ context.Context, _ *Client, script string) (string, string, error) {
		gotScript = script
		return fn(script)
	}
	return func() { runPowerShell = prev }, &gotScript
}

func osInfoOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func osInfoErr(t *testing.T, kind, msg string) string {
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

// fakeOSInfoPayload returns a full server-style payload for a Server 2025
// host.
func fakeOSInfoPayload() map[string]any {
	return map[string]any{
		"product_name":       "Microsoft Windows Server 2025 Standard",
		"version":            "10.0.26100",
		"build_number":       26100,
		"ubr":                1,
		"display_version":    "24H2",
		"edition_id":         "ServerStandard",
		"sku":                7,
		"installation_type":  "Server",
		"product_type_raw":   3,
		"architecture_raw":   9,
		"install_date":       "2024-11-01T00:00:00Z",
		"last_boot_time":     "2026-11-12T08:00:00Z",
		"system_drive":       "C:",
		"windows_directory":  `C:\Windows`,
		"os_language":        "en-US",
		"powershell_version": "5.1.26100.1",
		"machine_id":         "abc-123-def",
	}
}

// -----------------------------------------------------------------------------
// OSInfoError type
// -----------------------------------------------------------------------------

func TestOSInfoError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying-cause")
	e := NewOSInfoError(OSInfoErrorTimeout, "operation timed out", cause,
		map[string]string{"host": "win01"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "timeout") || !strings.Contains(msg, "operation timed out") ||
		!strings.Contains(msg, "underlying-cause") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewOSInfoError(OSInfoErrorUnknown, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestOSInfoError_Is_And_Helper(t *testing.T) {
	e := NewOSInfoError(OSInfoErrorAccessDenied, "x", nil, nil)
	if !errors.Is(e, ErrOSInfoAccessDenied) {
		t.Error("errors.Is(ErrOSInfoAccessDenied) should match by kind")
	}
	if errors.Is(e, ErrOSInfoCIMUnavailable) {
		t.Error("errors.Is across kinds must not match")
	}
	if !IsOSInfoError(e, OSInfoErrorAccessDenied) {
		t.Error("IsOSInfoError should match")
	}
	if IsOSInfoError(errors.New("plain"), OSInfoErrorAccessDenied) {
		t.Error("IsOSInfoError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-OSInfoError should be false")
	}
}

func TestMapOSInfoKind(t *testing.T) {
	cases := map[string]OSInfoErrorKind{
		"access_denied":     OSInfoErrorAccessDenied,
		"cim_unavailable":   OSInfoErrorCIMUnavailable,
		"timeout":           OSInfoErrorTimeout,
		"invalid_parameter": OSInfoErrorInvalidParameter,
		"":                  OSInfoErrorUnknown,
		"weird_kind":        OSInfoErrorUnknown,
		"unknown":           OSInfoErrorUnknown,
	}
	for in, want := range cases {
		if got := mapOSInfoKind(in); got != want {
			t.Errorf("mapOSInfoKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// Read — happy path and mapping tables
// -----------------------------------------------------------------------------

func TestOSInfoRead_HappyPath(t *testing.T) {
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return osInfoOK(t, fakeOSInfoPayload()), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	info, err := o.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.ProductName != "Microsoft Windows Server 2025 Standard" {
		t.Errorf("ProductName = %q", info.ProductName)
	}
	if info.Version != "10.0.26100" {
		t.Errorf("Version = %q", info.Version)
	}
	if info.BuildNumber != 26100 || info.UBR != 1 {
		t.Errorf("BuildNumber/UBR = %d/%d", info.BuildNumber, info.UBR)
	}
	if info.FullBuild != "26100.1" {
		t.Errorf("FullBuild = %q, want 26100.1", info.FullBuild)
	}
	if info.DisplayVersion != "24H2" {
		t.Errorf("DisplayVersion = %q", info.DisplayVersion)
	}
	if info.EditionID != "ServerStandard" {
		t.Errorf("EditionID = %q", info.EditionID)
	}
	if info.SKU != 7 || info.SKUName != "Server Standard" {
		t.Errorf("SKU/SKUName = %d/%q", info.SKU, info.SKUName)
	}
	if info.InstallationType != "Server" {
		t.Errorf("InstallationType = %q", info.InstallationType)
	}
	if !info.IsServer {
		t.Error("IsServer should be true for product_type_raw=3")
	}
	if info.IsServerCore {
		t.Error("IsServerCore should be false for InstallationType=Server")
	}
	if info.ProductType != "Server" {
		t.Errorf("ProductType = %q", info.ProductType)
	}
	if info.Architecture != "x64" {
		t.Errorf("Architecture = %q", info.Architecture)
	}
	if info.InstallDate != "2024-11-01T00:00:00Z" {
		t.Errorf("InstallDate = %q, want ISO 8601 passthrough", info.InstallDate)
	}
	if info.LastBootTime != "2026-11-12T08:00:00Z" {
		t.Errorf("LastBootTime = %q, want ISO 8601 passthrough", info.LastBootTime)
	}
	if info.SystemDrive != "C:" {
		t.Errorf("SystemDrive = %q", info.SystemDrive)
	}
	if info.WindowsDirectory != `C:\Windows` {
		t.Errorf("WindowsDirectory = %q", info.WindowsDirectory)
	}
	if info.OSLanguage != "en-US" {
		t.Errorf("OSLanguage = %q", info.OSLanguage)
	}
	if info.PowerShellVersion != "5.1.26100.1" {
		t.Errorf("PowerShellVersion = %q", info.PowerShellVersion)
	}
	if info.MachineID != "abc-123-def" {
		t.Errorf("MachineID = %q", info.MachineID)
	}
}

func TestOSInfoRead_ServerCore(t *testing.T) {
	payload := fakeOSInfoPayload()
	payload["installation_type"] = "Server Core"
	payload["sku"] = 12
	payload["edition_id"] = "ServerDatacenter"
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return osInfoOK(t, payload), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	info, err := o.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !info.IsServerCore {
		t.Error("IsServerCore should be true for InstallationType=Server Core")
	}
	if info.SKUName != "Server Datacenter Core" {
		t.Errorf("SKUName = %q, want Server Datacenter Core", info.SKUName)
	}
}

func TestOSInfoMappingTables(t *testing.T) {
	skuCases := map[int64]string{
		0:   "",
		1:   "Ultimate",
		4:   "Enterprise",
		5:   "Home Basic N",
		6:   "Business",
		7:   "Server Standard",
		8:   "Server Datacenter",
		10:  "Enterprise Server",
		12:  "Server Datacenter Core",
		13:  "Server Standard Core",
		14:  "Enterprise Server Core",
		48:  "Professional",
		999: "",
		-1:  "",
	}
	for sku, want := range skuCases {
		if got := skuName(sku); got != want {
			t.Errorf("skuName(%d) = %q, want %q", sku, got, want)
		}
	}
	productCases := map[int64]string{
		1:  "Workstation",
		2:  "DomainController",
		3:  "Server",
		0:  "",
		99: "",
		-1: "",
	}
	for raw, want := range productCases {
		if got := osProductType(raw); got != want {
			t.Errorf("osProductType(%d) = %q, want %q", raw, got, want)
		}
	}
	archCases := map[int64]string{
		0:  "x86",
		5:  "arm",
		9:  "x64",
		12: "arm64",
		1:  "",
		99: "",
	}
	for raw, want := range archCases {
		if got := osArchitecture(raw); got != want {
			t.Errorf("osArchitecture(%d) = %q, want %q", raw, got, want)
		}
	}
}

func TestOSInfoRead_UnknownCodesDegrade(t *testing.T) {
	payload := fakeOSInfoPayload()
	payload["sku"] = 4242
	payload["product_type_raw"] = 42
	payload["architecture_raw"] = 42
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return osInfoOK(t, payload), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	info, err := o.Read(context.Background())
	if err != nil {
		t.Fatalf("unknown codes must not error, got: %v", err)
	}
	if info.SKUName != "" {
		t.Errorf("SKUName = %q, want empty for unknown SKU", info.SKUName)
	}
	if info.ProductType != "" {
		t.Errorf("ProductType = %q, want empty for unknown product type", info.ProductType)
	}
	if info.Architecture != "" {
		t.Errorf("Architecture = %q, want empty for unknown architecture", info.Architecture)
	}
	if info.IsServer {
		t.Error("IsServer should be false for unknown product type (only raw 2/3 are servers)")
	}
}

func TestOSInfoRead_MissingUBRNoSuffix(t *testing.T) {
	payload := fakeOSInfoPayload()
	delete(payload, "ubr")
	delete(payload, "display_version")
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return osInfoOK(t, payload), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	info, err := o.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	// A missing UBR key unmarshals to zero, so FullBuild carries no suffix.
	if info.UBR != 0 {
		t.Errorf("UBR = %d, want 0 for missing key", info.UBR)
	}
	if info.FullBuild != "26100" {
		t.Errorf("FullBuild = %q, want 26100 without .ubr suffix", info.FullBuild)
	}
	if info.DisplayVersion != "" {
		t.Errorf("DisplayVersion = %q, want empty for missing key", info.DisplayVersion)
	}
}

// TestOSInfoScript_DisplayVersionFallback asserts the host-side fallback:
// DisplayVersion falls back to ReleaseId on hosts that predate it, so the
// Go layer only ever sees a resolved display_version.
func TestOSInfoScript_DisplayVersionFallback(t *testing.T) {
	restore, gotScript := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return osInfoOK(t, fakeOSInfoPayload()), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	if _, err := o.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !strings.Contains(*gotScript, "DisplayVersion") {
		t.Error("script must read CurrentVersion DisplayVersion")
	}
	if !strings.Contains(*gotScript, "ReleaseId") {
		t.Error("script must fall back to ReleaseId when DisplayVersion is empty")
	}
}

func TestOSInfoRead_EmptyMachineIDTolerated(t *testing.T) {
	payload := fakeOSInfoPayload()
	payload["machine_id"] = ""
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return osInfoOK(t, payload), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	info, err := o.Read(context.Background())
	if err != nil {
		t.Fatalf("empty MachineGuid must not error, got: %v", err)
	}
	if info.MachineID != "" {
		t.Errorf("MachineID = %q, want empty (data source falls back to current)", info.MachineID)
	}
}

func TestOSInfoRead_Workstation(t *testing.T) {
	payload := fakeOSInfoPayload()
	payload["product_type_raw"] = 1
	payload["installation_type"] = "Client"
	payload["sku"] = 48
	payload["edition_id"] = "Professional"
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return osInfoOK(t, payload), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	info, err := o.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.ProductType != "Workstation" {
		t.Errorf("ProductType = %q, want Workstation", info.ProductType)
	}
	if info.IsServer {
		t.Error("IsServer should be false for product_type_raw=1")
	}
	if info.SKUName != "Professional" {
		t.Errorf("SKUName = %q, want Professional", info.SKUName)
	}
}

// -----------------------------------------------------------------------------
// Envelope errors
// -----------------------------------------------------------------------------

func TestOSInfoRead_TransportError(t *testing.T) {
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return "", "boom", errors.New("winclient: powershell run: dial tcp: connection refused")
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	_, err := o.Read(context.Background())
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsOSInfoError(err, OSInfoErrorUnknown) {
		t.Errorf("transport failure must map to unknown, got %v", err)
	}
}

func TestOSInfoRead_Timeout(t *testing.T) {
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return "", "", context.DeadlineExceeded
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // ensure the deadline has passed
	_, err := o.Read(ctx)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !IsOSInfoError(err, OSInfoErrorTimeout) {
		t.Errorf("cancelled context must map to timeout, got %v", err)
	}
}

func TestOSInfoRead_ClassifiedErrors(t *testing.T) {
	cases := map[string]OSInfoErrorKind{
		"access_denied":   OSInfoErrorAccessDenied,
		"cim_unavailable": OSInfoErrorCIMUnavailable,
		"weird_kind":      OSInfoErrorUnknown,
	}
	for kind, want := range cases {
		restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
			return osInfoErr(t, kind, "host said no"), "", nil
		})
		o := NewOSInfoClient(newOSInfoTestClient(t))
		_, err := o.Read(context.Background())
		restore()
		if !IsOSInfoError(err, want) {
			t.Errorf("kind %q must map to %q, got %v", kind, want, err)
		}
	}
}

func TestOSInfoRead_BadDataPayload(t *testing.T) {
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		return `{"ok":true,"data":"not-an-object"}` + "\n", "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	_, err := o.Read(context.Background())
	if !IsOSInfoError(err, OSInfoErrorUnknown) {
		t.Errorf("expected unknown for bad payload, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Script invariants
// -----------------------------------------------------------------------------

// TestOSInfoScript_NeverExit guards the #81 invariant: scripts may run
// inside a reused PowerShell session, so "exit" would kill the session.
func TestOSInfoScript_NeverExit(t *testing.T) {
	for name, body := range map[string]string{
		"header": psOSInfoHeader,
		"read":   psOSInfoReadBody,
	} {
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(strings.ToLower(line))
			if trimmed == "exit" || strings.HasPrefix(trimmed, "exit ") ||
				strings.HasPrefix(trimmed, "exit;") || strings.HasPrefix(trimmed, "exit\t") {
				t.Errorf("%s body contains an exit statement: %q", name, line)
			}
		}
	}
}

// TestOSInfoScript_ClassifyMapping asserts the Classify-OSInfo branches
// exist host-side: access-denied / Win32 5 substrings map to access_denied,
// CIM/WMI tokens map to cim_unavailable. A generic "resource unavailable"
// message must not match: the bare 'unavailable' alternative was removed so
// it degrades to unknown.
func TestOSInfoScript_ClassifyMapping(t *testing.T) {
	for _, want := range []string{"Access is denied", "AccessDenied", "winmgmt", "WMI", "CIM", "repository", "provider load failure", "access_denied", "cim_unavailable"} {
		if !strings.Contains(psOSInfoHeader, want) {
			t.Errorf("Classify-OSInfo header must contain %q", want)
		}
	}
	if strings.Contains(psOSInfoHeader, "'unavailable'") {
		t.Error("Classify-OSInfo header must not contain the over-broad bare 'unavailable' alternative: generic unavailable messages degrade to unknown")
	}
}

// TestOSInfoScript_SingleRoundTrip asserts the read path issues exactly one
// PowerShell call.
func TestOSInfoScript_SingleRoundTrip(t *testing.T) {
	calls := 0
	restore, _ := stubOSInfoRun(t, func(_ string) (string, string, error) {
		calls++
		return osInfoOK(t, fakeOSInfoPayload()), "", nil
	})
	defer restore()

	o := NewOSInfoClient(newOSInfoTestClient(t))
	if _, err := o.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if calls != 1 {
		t.Errorf("Read must issue exactly one PowerShell call, got %d", calls)
	}
}

// -----------------------------------------------------------------------------
// toOSInfo — nil safety
// -----------------------------------------------------------------------------

func TestToOSInfo_Nil(t *testing.T) {
	if got := toOSInfo(nil); got != nil {
		t.Errorf("toOSInfo(nil) = %+v, want nil", got)
	}
}
