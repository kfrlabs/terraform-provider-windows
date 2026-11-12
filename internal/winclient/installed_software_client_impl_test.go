// Package winclient — unit tests for InstalledSoftwareClient.
//
// The package-level seam runInstalledSoftwarePowerShell is stubbed so no
// real SSH connection is needed. Coverage targets (issue #296):
//
//	InstalledSoftwareError: Error(), Unwrap(), Is(), sentinels
//	mapInstalledSoftwareKind: access_denied / unknown fallback
//	NormalizeInstalledSoftwareProductCode: spelling variants + invalid
//	normalizeInstalledSoftwareDate: YYYYMMDD -> YYYY-MM-DD, invalid -> ""
//	normalizeInstalledSoftwareRowCode: GUID detect, non-GUID -> ""
//	deriveInstalledSoftwareArchitecture: wow/host-arch table
//	isInstalledSoftwareUpdate: ParentKeyName / ReleaseType
//	validateInstalledSoftwareFilter: invalid regex/product code ->
//	invalid_parameter, no host call
//	script builder: single round-trip (one PowerShell call), no "exit",
//	hives via psQuoteList, product_code via psQuote
//	List: Go-side filter combos, name/version/key sort, broken-value skip
//	+ skipped count, DisplayName-less omission (not counted), empty hives
//	-> empty, envelope mapping
//	TestUninstallHivesAligned: shared hive constant matches
//	Get-LpUninstallEntry in legacy_package.go
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isNewClient returns an *InstalledSoftwareClient for tests.
func isNewClient(t *testing.T) *InstalledSoftwareClient {
	t.Helper()
	c, err := New(Config{Host: "winis01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewInstalledSoftwareClient(c)
}

// isOK returns a JSON ok-envelope whose data field is the supplied value.
func isOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("isOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// isErr returns a JSON error-envelope for the given kind/message.
func isErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": false, "kind": kind, "message": msg, "context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("isErr marshal: %v", err)
	}
	return string(b) + "\n"
}

// isStubRun replaces runInstalledSoftwarePowerShell for one test and counts
// calls while capturing the script.
func isStubRun(calls *int, script *string, fn func(script string) (string, string, error)) func() {
	prev := runInstalledSoftwarePowerShell
	runInstalledSoftwarePowerShell = func(_ context.Context, _ *Client, s string) (string, string, error) {
		if calls != nil {
			*calls++
		}
		if script != nil {
			*script = s
		}
		return fn(s)
	}
	return func() { runInstalledSoftwarePowerShell = prev }
}

// isPayload builds a minimal valid per-package payload.
func isPayload(name, keyName string) map[string]any {
	return map[string]any{
		"name":                   name,
		"version":                "1.0",
		"publisher":              "Acme",
		"install_date_raw":       "20240115",
		"install_location":       `C:\Acme`,
		"product_code_raw":       keyName,
		"windows_installer":      1,
		"system_component":       0,
		"parent_key_name":        "",
		"release_type":           "",
		"estimated_size":         1234,
		"uninstall_string":       `"C:\Acme\uninstall.exe"`,
		"quiet_uninstall_string": `"C:\Acme\uninstall.exe" /S`,
		"registry_key":           `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` + keyName,
		"scope":                  "machine",
		"user_sid":               "",
		"hive_arch":              "native",
		"host_arch":              "AMD64",
	}
}

// isListData wraps package payloads in the List envelope data shape.
func isListData(pkgs []any, skipped int64) map[string]any {
	if pkgs == nil {
		pkgs = []any{}
	}
	return map[string]any{"packages": pkgs, "skipped_entries": skipped}
}

// ---------------------------------------------------------------------------
// InstalledSoftwareError type
// ---------------------------------------------------------------------------

func TestInstalledSoftwareError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying-cause")
	e := NewInstalledSoftwareError(InstalledSoftwareErrorTimeout, "operation timed out", cause,
		map[string]string{"host": "winis01"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "timeout") || !strings.Contains(msg, "operation timed out") ||
		!strings.Contains(msg, "underlying-cause") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewInstalledSoftwareError(InstalledSoftwareErrorUnknown, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestInstalledSoftwareError_Is_And_Helper(t *testing.T) {
	e := NewInstalledSoftwareError(InstalledSoftwareErrorAccessDenied, "x", nil, nil)
	if !errors.Is(e, ErrInstalledSoftwareAccessDenied) {
		t.Error("errors.Is(ErrInstalledSoftwareAccessDenied) should match by kind")
	}
	if errors.Is(e, ErrInstalledSoftwareTimeout) {
		t.Error("errors.Is across kinds must not match")
	}
	if !IsInstalledSoftwareError(e, InstalledSoftwareErrorAccessDenied) {
		t.Error("IsInstalledSoftwareError should match")
	}
	if IsInstalledSoftwareError(errors.New("plain"), InstalledSoftwareErrorAccessDenied) {
		t.Error("IsInstalledSoftwareError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-InstalledSoftwareError should be false")
	}
}

func TestMapInstalledSoftwareKind(t *testing.T) {
	cases := map[string]InstalledSoftwareErrorKind{
		"access_denied":     InstalledSoftwareErrorAccessDenied,
		"timeout":           InstalledSoftwareErrorTimeout,
		"invalid_parameter": InstalledSoftwareErrorInvalidParameter,
		"":                  InstalledSoftwareErrorUnknown,
		"weird_kind":        InstalledSoftwareErrorUnknown,
		"unknown":           InstalledSoftwareErrorUnknown,
	}
	for in, want := range cases {
		if got := mapInstalledSoftwareKind(in); got != want {
			t.Errorf("mapInstalledSoftwareKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

func TestNormalizeInstalledSoftwareProductCode(t *testing.T) {
	want := "{12345678-1234-1234-1234-123456789ABC}"
	for _, in := range []string{
		"{12345678-1234-1234-1234-123456789abc}",
		"12345678-1234-1234-1234-123456789abc",
		"  {12345678-1234-1234-1234-123456789ABC}  ",
	} {
		got, err := NormalizeInstalledSoftwareProductCode(in)
		if err != nil {
			t.Errorf("NormalizeInstalledSoftwareProductCode(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeInstalledSoftwareProductCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got, err := NormalizeInstalledSoftwareProductCode(""); err != nil || got != "" {
		t.Errorf("empty input must stay empty without error, got %q, %v", got, err)
	}
	for _, in := range []string{"not-a-guid", "{12345678-1234}", "DisplayName Match", "{ZZZZ5678-1234-1234-1234-123456789ABC}"} {
		if _, err := NormalizeInstalledSoftwareProductCode(in); !IsInstalledSoftwareError(err, InstalledSoftwareErrorInvalidParameter) {
			t.Errorf("NormalizeInstalledSoftwareProductCode(%q) must be invalid_parameter, got %v", in, err)
		}
	}
}

func TestNormalizeInstalledSoftwareDate(t *testing.T) {
	if got := normalizeInstalledSoftwareDate("20240115"); got != "2024-01-15" {
		t.Errorf("valid YYYYMMDD = %q, want 2024-01-15", got)
	}
	for _, in := range []string{"", "2024-01-15", "15/01/2024", "20241301", "garbage"} {
		if got := normalizeInstalledSoftwareDate(in); got != "" {
			t.Errorf("normalizeInstalledSoftwareDate(%q) = %q, want empty", in, got)
		}
	}
}

func TestNormalizeInstalledSoftwareRowCode(t *testing.T) {
	if got := normalizeInstalledSoftwareRowCode("{12345678-1234-1234-1234-123456789abc}"); got != "{12345678-1234-1234-1234-123456789ABC}" {
		t.Errorf("GUID key = %q, want normalised upper with braces", got)
	}
	if got := normalizeInstalledSoftwareRowCode("7-Zip 23.01 (x64)"); got != "" {
		t.Errorf("non-GUID key = %q, want empty", got)
	}
}

func TestDeriveInstalledSoftwareArchitecture(t *testing.T) {
	cases := []struct{ hive, host, want string }{
		{"wow", "AMD64", "x86"},
		{"wow", "ARM64", "x86"},
		{"native", "AMD64", "x64"},
		{"native", "ARM64", "arm64"},
		{"native", "x86", "x86"},
		{"native", "", "x64"},
	}
	for _, tc := range cases {
		if got := deriveInstalledSoftwareArchitecture(tc.hive, tc.host); got != tc.want {
			t.Errorf("derive(%q, %q) = %q, want %q", tc.hive, tc.host, got, tc.want)
		}
	}
}

func TestIsInstalledSoftwareUpdate(t *testing.T) {
	if isInstalledSoftwareUpdate("", "") {
		t.Error("plain product must not be an update")
	}
	if !isInstalledSoftwareUpdate("ParentProduct", "") {
		t.Error("non-empty ParentKeyName must be an update")
	}
	for _, rt := range []string{"Security Update", "Update", "Hotfix", "security update"} {
		if !isInstalledSoftwareUpdate("", rt) {
			t.Errorf("ReleaseType %q must be an update", rt)
		}
	}
	if isInstalledSoftwareUpdate("", "Service Pack") {
		t.Error("ReleaseType Service Pack must not be an update")
	}
}

// ---------------------------------------------------------------------------
// Shared hives alignment
// ---------------------------------------------------------------------------

// TestUninstallHivesAligned asserts the shared UninstallRegistryHivePaths
// constant covers exactly the hives Get-LpUninstallEntry scans in
// legacy_package.go. legacy_package.go itself is untouched by #296 apart
// from the additive constant; this test keeps the two in step.
func TestUninstallHivesAligned(t *testing.T) {
	want := []string{
		`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	if len(UninstallRegistryHivePaths) != len(want) {
		t.Fatalf("UninstallRegistryHivePaths has %d entries, want %d", len(UninstallRegistryHivePaths), len(want))
	}
	for i, h := range want {
		if UninstallRegistryHivePaths[i] != h {
			t.Errorf("UninstallRegistryHivePaths[%d] = %q, want %q", i, UninstallRegistryHivePaths[i], h)
		}
	}
	src, err := os.ReadFile("legacy_package.go")
	if err != nil {
		t.Fatalf("read legacy_package.go: %v", err)
	}
	for _, h := range UninstallRegistryHivePaths {
		if !strings.Contains(string(src), h) {
			t.Errorf("legacy_package.go no longer contains shared hive %q; keep Get-LpUninstallEntry aligned", h)
		}
	}
}

// ---------------------------------------------------------------------------
// List — filtering, sorting, skipped entries
// ---------------------------------------------------------------------------

func TestInstalledSoftwareList_HappyPath(t *testing.T) {
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData([]any{
			isPayload("Bravo", "{22222222-2222-2222-2222-222222222222}"),
			isPayload("Alpha", "{11111111-1111-1111-1111-111111111111}"),
		}, 0)), "", nil
	})
	defer restore()

	res, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("packages = %d, want 2", len(res.Packages))
	}
	// Sorted by name case-insensitively: Alpha before Bravo.
	if res.Packages[0].Name != "Alpha" || res.Packages[1].Name != "Bravo" {
		t.Errorf("packages not sorted by name: %q, %q", res.Packages[0].Name, res.Packages[1].Name)
	}
	first := res.Packages[0]
	if first.ProductCode != "{11111111-1111-1111-1111-111111111111}" {
		t.Errorf("ProductCode = %q, want normalised upper with braces", first.ProductCode)
	}
	if !first.IsMSI {
		t.Error("IsMSI should be true for WindowsInstaller=1")
	}
	if first.Architecture != "x64" {
		t.Errorf("Architecture = %q, want x64 for native hive on AMD64", first.Architecture)
	}
	if first.InstallDate != "2024-01-15" {
		t.Errorf("InstallDate = %q, want 2024-01-15", first.InstallDate)
	}
	if first.Scope != "machine" || first.UserSID != "" {
		t.Errorf("Scope/UserSID = %q/%q, want machine/empty", first.Scope, first.UserSID)
	}
	if first.EstimatedSizeKB != 1234 {
		t.Errorf("EstimatedSizeKB = %d, want 1234", first.EstimatedSizeKB)
	}
	if res.SkippedEntries != 0 {
		t.Errorf("SkippedEntries = %d, want 0", res.SkippedEntries)
	}
}

func TestInstalledSoftwareList_EmptyHivesEmpty(t *testing.T) {
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData(nil, 0)), "", nil
	})
	defer restore()

	res, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{})
	if err != nil {
		t.Fatalf("empty hives must not error, got: %v", err)
	}
	if len(res.Packages) != 0 {
		t.Errorf("packages = %d, want 0", len(res.Packages))
	}
	if res.SkippedEntries != 0 {
		t.Errorf("SkippedEntries = %d, want 0", res.SkippedEntries)
	}
}

func TestInstalledSoftwareList_SkippedAndDisplayNameLess(t *testing.T) {
	// The host reports one skipped (unreadable) key; the DisplayName-less
	// key is omitted host-side and not counted.
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData([]any{isPayload("Solo", "SoloKey")}, 1)), "", nil
	})
	defer restore()

	res, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(res.Packages))
	}
	if res.Packages[0].Name != "Solo" {
		t.Errorf("Name = %q, want Solo", res.Packages[0].Name)
	}
	if res.Packages[0].ProductCode != "" {
		t.Errorf("non-GUID key ProductCode = %q, want empty", res.Packages[0].ProductCode)
	}
	if res.SkippedEntries != 1 {
		t.Errorf("SkippedEntries = %d, want 1", res.SkippedEntries)
	}
}

func TestInstalledSoftwareList_SystemUpdateFiltering(t *testing.T) {
	sys := isPayload("SysComp", "{44444444-4444-4444-4444-444444444444}")
	sys["system_component"] = 1
	upd := isPayload("Hotfix", "{55555555-5555-5555-5555-555555555555}")
	upd["release_type"] = "Security Update"
	plain := isPayload("Plain", "{66666666-6666-6666-6666-666666666666}")
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData([]any{sys, upd, plain}, 0)), "", nil
	})
	defer restore()

	c := isNewClient(t)
	res, err := c.List(context.Background(), InstalledSoftwareFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "Plain" {
		t.Errorf("default filter must drop system/update entries, got %+v", res.Packages)
	}

	res, err = c.List(context.Background(), InstalledSoftwareFilter{IncludeSystemComponents: true, IncludeUpdates: true})
	if err != nil {
		t.Fatalf("List with includes: %v", err)
	}
	if len(res.Packages) != 3 {
		t.Errorf("include flags must keep all entries, got %d", len(res.Packages))
	}
}

func TestInstalledSoftwareList_RegexAndProductCode(t *testing.T) {
	a := isPayload("Microsoft .NET Runtime 8", "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}")
	b := isPayload("7-Zip 23.01 (x64)", "7-Zip 23.01 (x64)")
	b["publisher"] = "Igor Pavlov"
	b["windows_installer"] = 0
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData([]any{a, b}, 0)), "", nil
	})
	defer restore()

	c := isNewClient(t)
	res, err := c.List(context.Background(), InstalledSoftwareFilter{NameRegex: `\.NET.*8$`})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "Microsoft .NET Runtime 8" {
		t.Errorf("name_regex mismatch, got %+v", res.Packages)
	}

	res, err = c.List(context.Background(), InstalledSoftwareFilter{PublisherRegex: `^Igor`})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "7-Zip 23.01 (x64)" {
		t.Errorf("publisher_regex mismatch, got %+v", res.Packages)
	}

	res, err = c.List(context.Background(), InstalledSoftwareFilter{ProductCode: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "Microsoft .NET Runtime 8" {
		t.Errorf("product_code spelling variant must match, got %+v", res.Packages)
	}
}

func TestInstalledSoftwareList_SortStability(t *testing.T) {
	p1 := isPayload("Same", "{11111111-1111-1111-1111-111111111111}")
	p1["version"] = "2.0"
	p1["registry_key"] = `HKLM:\...\Uninstall\{11111111-1111-1111-1111-111111111111}`
	p2 := isPayload("Same", "{22222222-2222-2222-2222-222222222222}")
	p2["version"] = "1.0"
	p2["registry_key"] = `HKLM:\...\Uninstall\{22222222-2222-2222-2222-222222222222}`
	p3 := isPayload("same", "{33333333-3333-3333-3333-333333333333}")
	p3["version"] = "1.0"
	p3["registry_key"] = `HKLM:\...\Uninstall\AAAA`
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData([]any{p1, p2, p3}, 0)), "", nil
	})
	defer restore()

	res, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Name compares case-insensitively (all equal), then version, then key:
	// p2 (1.0, {222...}) before p3 (1.0, AAAA)? No: registry_key "AAAA..."
	// sorts before "{222...}", so p3 comes first among the 1.0 pair.
	if len(res.Packages) != 3 {
		t.Fatalf("packages = %d, want 3", len(res.Packages))
	}
	if res.Packages[0].RegistryKey != `HKLM:\...\Uninstall\AAAA` || res.Packages[1].Version != "1.0" || res.Packages[2].Version != "2.0" {
		t.Errorf("sort order wrong: %+v", res.Packages)
	}
}

func TestInstalledSoftwareList_InvalidFiltersNoHostCall(t *testing.T) {
	calls := 0
	restore := isStubRun(&calls, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData(nil, 0)), "", nil
	})
	defer restore()

	c := isNewClient(t)
	for name, filter := range map[string]InstalledSoftwareFilter{
		"bad name regex":      {NameRegex: "(unclosed"},
		"bad publisher regex": {PublisherRegex: "[bad"},
		"bad product code":    {ProductCode: "not-a-guid"},
	} {
		if _, err := c.List(context.Background(), filter); !IsInstalledSoftwareError(err, InstalledSoftwareErrorInvalidParameter) {
			t.Errorf("%s must be invalid_parameter, got %v", name, err)
		}
	}
	if calls != 0 {
		t.Errorf("invalid filters must not reach the host, got %d calls", calls)
	}
}

func TestInstalledSoftwareList_BadEntryPayload(t *testing.T) {
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isOK(t, map[string]any{"packages": "not-an-array", "skipped_entries": 0}), "", nil
	})
	defer restore()

	if _, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{}); !IsInstalledSoftwareError(err, InstalledSoftwareErrorUnknown) {
		t.Errorf("bad payload must be unknown, got %v", err)
	}
}

func TestInstalledSoftwareList_EnvelopeErrors(t *testing.T) {
	c := isNewClient(t)

	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		return "", "boom", errors.New("winclient: powershell run: dial tcp: connection refused")
	})
	_, err := c.List(context.Background(), InstalledSoftwareFilter{})
	restore()
	if !IsInstalledSoftwareError(err, InstalledSoftwareErrorUnknown) {
		t.Errorf("transport failure must map to unknown, got %v", err)
	}

	restore = isStubRun(nil, nil, func(_ string) (string, string, error) {
		return "", "", context.DeadlineExceeded
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_, err = c.List(ctx, InstalledSoftwareFilter{})
	restore()
	if !IsInstalledSoftwareError(err, InstalledSoftwareErrorTimeout) {
		t.Errorf("cancelled context must map to timeout, got %v", err)
	}

	restore = isStubRun(nil, nil, func(_ string) (string, string, error) {
		return isErr(t, "access_denied", "host said no"), "", nil
	})
	_, err = c.List(context.Background(), InstalledSoftwareFilter{})
	restore()
	if !IsInstalledSoftwareError(err, InstalledSoftwareErrorAccessDenied) {
		t.Errorf("access_denied kind must map, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Script invariants
// ---------------------------------------------------------------------------

// TestInstalledSoftwareScript_NeverExit guards the #81 invariant: scripts
// may run inside a reused PowerShell session, so "exit" would kill it.
func TestInstalledSoftwareScript_NeverExit(t *testing.T) {
	for name, body := range map[string]string{
		"header": psInstalledSoftwareHeader,
		"list":   psInstalledSoftwareListBody,
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

// TestInstalledSoftwareScript_ClassifyMapping asserts the
// Classify-InstalledSoftware branches exist host-side: access-denied
// substrings map to access_denied and everything else degrades to unknown.
func TestInstalledSoftwareScript_ClassifyMapping(t *testing.T) {
	for _, want := range []string{"Access is denied", "PermissionDenied", "UnauthorizedAccess", "access_denied", "'unknown'"} {
		if !strings.Contains(psInstalledSoftwareHeader, want) {
			t.Errorf("Classify-InstalledSoftware header must contain %q", want)
		}
	}
}

// TestInstalledSoftwareScript_SingleRoundTrip asserts List issues exactly
// one PowerShell call.
func TestInstalledSoftwareScript_SingleRoundTrip(t *testing.T) {
	calls := 0
	restore := isStubRun(&calls, nil, func(_ string) (string, string, error) {
		return isOK(t, isListData(nil, 0)), "", nil
	})
	defer restore()

	if _, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if calls != 1 {
		t.Errorf("List must issue exactly one PowerShell call, got %d", calls)
	}
}

// TestInstalledSoftwareScript_Interpolation asserts the script carries the
// shared hives and the psQuote-escaped product code, the user-hive flag as
// a literal, and never interpolates the regex filters or Win32_Product.
func TestInstalledSoftwareScript_Interpolation(t *testing.T) {
	var script string
	restore := isStubRun(nil, &script, func(_ string) (string, string, error) {
		return isOK(t, isListData(nil, 0)), "", nil
	})
	defer restore()

	code := "{12345678-1234-1234-1234-123456789ABC}"
	c := isNewClient(t)
	if _, err := c.List(context.Background(), InstalledSoftwareFilter{
		NameRegex:           "evil.*",
		PublisherRegex:      "evil-pub",
		ProductCode:         "12345678-1234-1234-1234-123456789abc",
		IncludeUserInstalls: true,
	}); err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, hive := range UninstallRegistryHivePaths {
		if !strings.Contains(script, hive) {
			t.Errorf("script must enumerate shared hive %q", hive)
		}
	}
	if !strings.Contains(script, psQuote(code)) {
		t.Errorf("script must carry the psQuote-escaped product code %q", psQuote(code))
	}
	if !strings.Contains(script, "$IncludeUserInstalls = $true") {
		t.Error("script must interpolate the user-hive flag as a $true literal")
	}
	if strings.Contains(script, "evil.*") || strings.Contains(script, "evil-pub") {
		t.Error("regex filters must never reach the host (Go-side only)")
	}
	if strings.Contains(script, "Win32_Product") {
		t.Error("script must never query Win32_Product")
	}
}

// TestInstalledSoftwareList_EnumerateAccessDenied asserts an access-denied
// failure while enumerating a hive fails closed as access_denied (never an
// empty inventory).
func TestInstalledSoftwareList_EnumerateAccessDenied(t *testing.T) {
	var script string
	restore := isStubRun(nil, &script, func(_ string) (string, string, error) {
		return isErr(t, "access_denied", "Access is denied"), "", nil
	})
	defer restore()

	_, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{})
	if !IsInstalledSoftwareError(err, InstalledSoftwareErrorAccessDenied) {
		t.Fatalf("enumerate access-denied must surface access_denied, got %v", err)
	}
	for _, want := range []string{"step = 'enumerate'", "Access is denied", "UnauthorizedAccess", "0x80070005"} {
		if !strings.Contains(script, want) {
			t.Errorf("list script must distinguish access-denied at enumerate, missing %q", want)
		}
	}
}

// TestInstalledSoftwareList_ProductCodeBraceInsensitive asserts a product
// key stored without braces still matches a braced filter: the host
// pre-filter normalises braces/case before comparing.
func TestInstalledSoftwareList_ProductCodeBraceInsensitive(t *testing.T) {
	p := isPayload("Braceless", "12345678-1234-1234-1234-123456789ABC")
	var script string
	restore := isStubRun(nil, &script, func(_ string) (string, string, error) {
		return isOK(t, isListData([]any{p}, 0)), "", nil
	})
	defer restore()

	res, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{
		ProductCode: "{12345678-1234-1234-1234-123456789abc}",
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "Braceless" {
		t.Fatalf("braceless key must match braced filter, got %+v", res.Packages)
	}
	if res.Packages[0].ProductCode != "{12345678-1234-1234-1234-123456789ABC}" {
		t.Errorf("ProductCode = %q, want normalised upper with braces", res.Packages[0].ProductCode)
	}
	if !strings.Contains(script, "Trim('{}')") {
		t.Error("list script must normalise braces for the host pre-filter")
	}
}

// TestInstalledSoftwareList_BadRowSkipped asserts one corrupt row degrades
// to skipped instead of failing the whole inventory.
func TestInstalledSoftwareList_BadRowSkipped(t *testing.T) {
	restore := isStubRun(nil, nil, func(_ string) (string, string, error) {
		good, merr := json.Marshal(isPayload("Good", "{11111111-1111-1111-1111-111111111111}"))
		if merr != nil {
			t.Fatalf("marshal good payload: %v", merr)
		}
		data := map[string]any{
			"packages":        []any{json.RawMessage(good), "not-an-object"},
			"skipped_entries": int64(0),
		}
		return isOK(t, data), "", nil
	})
	defer restore()

	res, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{})
	if err != nil {
		t.Fatalf("one bad row must not fail List, got: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "Good" {
		t.Fatalf("good rows must survive a bad row, got %+v", res.Packages)
	}
	if res.SkippedEntries != 1 {
		t.Errorf("SkippedEntries = %d, want 1 for the corrupt row", res.SkippedEntries)
	}
}

// TestInstalledSoftwareScript_UserHiveAllowlist asserts the HKU allowlist
// excludes the well-known service SIDs while keeping domain user SIDs.
func TestInstalledSoftwareScript_UserHiveAllowlist(t *testing.T) {
	var script string
	restore := isStubRun(nil, &script, func(_ string) (string, string, error) {
		return isOK(t, isListData(nil, 0)), "", nil
	})
	defer restore()

	if _, err := isNewClient(t).List(context.Background(), InstalledSoftwareFilter{IncludeUserInstalls: true}); err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, want := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20", `^S-1-5-21-`} {
		if !strings.Contains(script, want) {
			t.Errorf("user-hive allowlist must reference %q", want)
		}
	}
}
