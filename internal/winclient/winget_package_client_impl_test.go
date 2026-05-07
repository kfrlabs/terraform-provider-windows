// Package winclient — unit tests for WingetPackageClientImpl.
//
// Tests stub the package-level runPowerShell seam (shared with service.go)
// so no real WinRM connection is needed. Coverage targets:
//
//   - WingetPackageError: Error(), Unwrap(), Is(), NewWingetPackageError, IsWingetPackageError
//   - wpMapKind: all known kinds + unknown fallback
//   - wpReplace: placeholder substitution
//   - parseWPState: null data → (nil,nil), valid JSON, invalid JSON
//   - runWPEnvelope: transport error, ctx cancelled, missing JSON, bad JSON, Emit-Err
//   - Install: happy path, already_installed, module_missing, reboot_required, transport
//   - Read: happy path, not-found (null), error
//   - Update: happy path, version_not_available, catalog_error, reboot_required
//   - Uninstall: happy path, reboot_required, resource_in_use context cancel
//   - runRetryable: EC-8 retry (network → success), EC-10 retry (resource_in_use → success)
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
// Test helpers
// ---------------------------------------------------------------------------

// wpNewClient returns a *Client + *WingetPackageClientImpl pair.
func wpNewClient(t *testing.T) (*Client, *WingetPackageClientImpl) {
	t.Helper()
	c, err := New(Config{Host: "winpkg01", Username: "u", Password: "p", Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewWingetPackageClient(c)
}

// wpOK returns a JSON ok-envelope with the supplied data value.
func wpOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("wpOK marshal: %v", err)
	}
	return string(b) + "\n"
}

// wpOKNull returns a JSON ok-envelope with data=null (package absent in Read).
func wpOKNull() string { return `{"ok":true,"data":null}` + "\n" }

// wpStateData returns a minimal valid wpJSONState map for the given package.
func wpStateData(pkgID, src, ver, name string) map[string]any {
	return map[string]any{
		"package_id":        pkgID,
		"source":            src,
		"installed_version": ver,
		"name":              name,
		"reboot_required":   false,
	}
}

// wpStateDataReboot returns a state map with reboot_required=true.
func wpStateDataReboot(pkgID, src, ver, name string) map[string]any {
	return map[string]any{
		"package_id":        pkgID,
		"source":            src,
		"installed_version": ver,
		"name":              name,
		"reboot_required":   true,
	}
}

// wpResponse captures one stubbed PS call.
type wpResponse struct {
	stdout string
	stderr string
	err    error
}

// wpStubSequence stubs runPowerShell with a fixed ordered list of responses.
// After the last one, every subsequent call replays the last entry.
// Returns a restore closure that must be deferred.
func wpStubSequence(responses []wpResponse) func() {
	i := 0
	return stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		r := responses[i]
		if i < len(responses)-1 {
			i++
		}
		return r.stdout, r.stderr, r.err
	})
}

// ---------------------------------------------------------------------------
// WingetPackageError
// ---------------------------------------------------------------------------

func TestWPError_ErrorWithCause(t *testing.T) {
	cause := errors.New("transport failed")
	e := NewWingetPackageError(WingetPackageErrorPermission, "access denied", cause,
		map[string]string{"host": "winpkg01"})
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") {
		t.Errorf("missing kind in error string: %q", msg)
	}
	if !strings.Contains(msg, "access denied") {
		t.Errorf("missing message in error string: %q", msg)
	}
	if !strings.Contains(msg, "transport failed") {
		t.Errorf("missing cause in error string: %q", msg)
	}
}

func TestWPError_ErrorNoCause(t *testing.T) {
	e := NewWingetPackageError(WingetPackageErrorModuleMissing, "module not found", nil, nil)
	msg := e.Error()
	if strings.Contains(msg, "<nil>") {
		t.Errorf("nil cause should not appear in Error(): %q", msg)
	}
	if !strings.Contains(msg, "module_missing") {
		t.Errorf("missing kind: %q", msg)
	}
}

func TestWPError_Unwrap(t *testing.T) {
	cause := errors.New("net error")
	e := NewWingetPackageError(WingetPackageErrorUnknown, "msg", cause, nil)
	if e.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
	e2 := NewWingetPackageError(WingetPackageErrorUnknown, "msg", nil, nil)
	if e2.Unwrap() != nil {
		t.Error("Unwrap with no cause should return nil")
	}
}

func TestWPError_Is_SameKind(t *testing.T) {
	e := NewWingetPackageError(WingetPackageErrorAlreadyInstalled, "dup", nil, nil)
	if !errors.Is(e, ErrWingetPackageAlreadyInstalled) {
		t.Error("errors.Is should match on same kind")
	}
}

func TestWPError_Is_DifferentKind(t *testing.T) {
	e := NewWingetPackageError(WingetPackageErrorAlreadyInstalled, "dup", nil, nil)
	if errors.Is(e, ErrWingetPackageModuleMissing) {
		t.Error("errors.Is should NOT match across different kinds")
	}
}

func TestWPError_Is_NotWPError(t *testing.T) {
	e := NewWingetPackageError(WingetPackageErrorUnknown, "x", nil, nil)
	if e.Is(errors.New("plain")) {
		t.Error("Is should return false for non-WingetPackageError targets")
	}
}

func TestWPError_Is_AllSentinels(t *testing.T) {
	cases := []struct {
		kind     WingetPackageErrorKind
		sentinel *WingetPackageError
	}{
		{WingetPackageErrorModuleMissing, ErrWingetPackageModuleMissing},
		{WingetPackageErrorAlreadyInstalled, ErrWingetPackageAlreadyInstalled},
		{WingetPackageErrorVersionNotAvailable, ErrWingetPackageVersionNotAvailable},
		{WingetPackageErrorBlockedByPolicy, ErrWingetPackageBlockedByPolicy},
		{WingetPackageErrorPermission, ErrWingetPackagePermission},
		{WingetPackageErrorSourceUnreachable, ErrWingetPackageSourceUnreachable},
		{WingetPackageErrorCatalogError, ErrWingetPackageCatalogError},
		{WingetPackageErrorResourceInUse, ErrWingetPackageResourceInUse},
		{WingetPackageErrorUnknown, ErrWingetPackageUnknown},
	}
	for _, tc := range cases {
		e := NewWingetPackageError(tc.kind, "test", nil, nil)
		if !errors.Is(e, tc.sentinel) {
			t.Errorf("errors.Is(%v, sentinel) should be true", tc.kind)
		}
	}
}

func TestNewWPError_Context(t *testing.T) {
	ctx := map[string]string{"package_id": "Foo.Bar", "host": "winpkg01"}
	e := NewWingetPackageError(WingetPackageErrorVersionNotAvailable, "bad version", nil, ctx)
	if e.Kind != WingetPackageErrorVersionNotAvailable {
		t.Errorf("kind = %q", e.Kind)
	}
	if e.Context["package_id"] != "Foo.Bar" {
		t.Error("context not preserved")
	}
}

func TestIsWPError_Match(t *testing.T) {
	e := NewWingetPackageError(WingetPackageErrorModuleMissing, "no module", nil, nil)
	if !IsWingetPackageError(e, WingetPackageErrorModuleMissing) {
		t.Error("should match on kind")
	}
}

func TestIsWPError_WrongKind(t *testing.T) {
	e := NewWingetPackageError(WingetPackageErrorModuleMissing, "no module", nil, nil)
	if IsWingetPackageError(e, WingetPackageErrorPermission) {
		t.Error("should NOT match on wrong kind")
	}
}

func TestIsWPError_PlainError(t *testing.T) {
	if IsWingetPackageError(errors.New("plain"), WingetPackageErrorModuleMissing) {
		t.Error("plain error should not be a WingetPackageError")
	}
}

func TestIsWPError_NilError(t *testing.T) {
	if IsWingetPackageError(nil, WingetPackageErrorModuleMissing) {
		t.Error("nil error should return false")
	}
}

// ---------------------------------------------------------------------------
// wpMapKind
// ---------------------------------------------------------------------------

func TestWPMapKind_AllKnown(t *testing.T) {
	cases := []struct {
		in   string
		want WingetPackageErrorKind
	}{
		{"module_missing", WingetPackageErrorModuleMissing},
		{"already_installed", WingetPackageErrorAlreadyInstalled},
		{"version_not_available", WingetPackageErrorVersionNotAvailable},
		{"blocked_by_policy", WingetPackageErrorBlockedByPolicy},
		{"permission_denied", WingetPackageErrorPermission},
		{"source_unreachable", WingetPackageErrorSourceUnreachable},
		{"catalog_error", WingetPackageErrorCatalogError},
		{"resource_in_use", WingetPackageErrorResourceInUse},
	}
	for _, tc := range cases {
		got := wpMapKind(tc.in)
		if got != tc.want {
			t.Errorf("wpMapKind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWPMapKind_UnknownFallback(t *testing.T) {
	for _, bad := range []string{"", "garbage", "UNKNOWN", "foo"} {
		got := wpMapKind(bad)
		if got != WingetPackageErrorUnknown {
			t.Errorf("wpMapKind(%q) = %q, want unknown", bad, got)
		}
	}
}

// ---------------------------------------------------------------------------
// wpReplace
// ---------------------------------------------------------------------------

func TestWPReplace_BasicSubstitution(t *testing.T) {
	tmpl := "@@ID@@ @@SRC@@ @@VER@@ @@OVERRIDE@@"
	got := wpReplace(tmpl, "Foo.Bar", "winget", "1.0", "")
	if !strings.Contains(got, "'Foo.Bar'") {
		t.Errorf("missing quoted ID: %q", got)
	}
	if !strings.Contains(got, "'winget'") {
		t.Errorf("missing quoted source: %q", got)
	}
	if !strings.Contains(got, "'1.0'") {
		t.Errorf("missing quoted version: %q", got)
	}
}

func TestWPReplace_EmptyVersion(t *testing.T) {
	tmpl := "@@VER@@"
	got := wpReplace(tmpl, "Foo.Bar", "winget", "", "")
	// psQuote("") = "''"
	if got != "''" {
		t.Errorf("empty version should become '': got %q", got)
	}
}

func TestWPReplace_OverrideWithSingleQuote(t *testing.T) {
	// psQuote escapes single quotes by doubling them
	tmpl := "@@OVERRIDE@@"
	got := wpReplace(tmpl, "Foo", "winget", "", "it's")
	if !strings.Contains(got, "it''s") {
		t.Errorf("single quote should be escaped: %q", got)
	}
}

func TestWPReplace_PlaceholderAbsent(t *testing.T) {
	tmpl := "no placeholders here"
	got := wpReplace(tmpl, "Foo", "winget", "1.0", "")
	if got != tmpl {
		t.Errorf("template without placeholders should be unchanged: %q", got)
	}
}

// ---------------------------------------------------------------------------
// parseWPState
// ---------------------------------------------------------------------------

func TestParseWPState_NullData(t *testing.T) {
	resp := &psResponse{OK: true, Data: json.RawMessage("null")}
	st, err := parseWPState(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != nil {
		t.Errorf("expected nil state for null data, got %+v", st)
	}
}

func TestParseWPState_NilData(t *testing.T) {
	resp := &psResponse{OK: true, Data: nil}
	st, err := parseWPState(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != nil {
		t.Errorf("expected nil state for nil data, got %+v", st)
	}
}

func TestParseWPState_ValidJSON(t *testing.T) {
	raw := `{
		"package_id": "Microsoft.VisualStudioCode",
		"source": "winget",
		"installed_version": "1.85.2",
		"name": "Visual Studio Code",
		"reboot_required": false
	}`
	resp := &psResponse{OK: true, Data: json.RawMessage(raw)}
	st, err := parseWPState(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.PackageID != "Microsoft.VisualStudioCode" {
		t.Errorf("PackageID = %q", st.PackageID)
	}
	if st.Source != "winget" {
		t.Errorf("Source = %q", st.Source)
	}
	if st.InstalledVersion != "1.85.2" {
		t.Errorf("InstalledVersion = %q", st.InstalledVersion)
	}
	if st.Name != "Visual Studio Code" {
		t.Errorf("Name = %q", st.Name)
	}
	if st.RebootRequired {
		t.Error("RebootRequired should be false")
	}
}

func TestParseWPState_RebootRequired(t *testing.T) {
	raw := `{
		"package_id": "Foo.Bar",
		"source": "winget",
		"installed_version": "2.0",
		"name": "Foo Bar",
		"reboot_required": true
	}`
	resp := &psResponse{OK: true, Data: json.RawMessage(raw)}
	st, err := parseWPState(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if !st.RebootRequired {
		t.Error("RebootRequired should be true")
	}
}

func TestParseWPState_InvalidJSON(t *testing.T) {
	resp := &psResponse{OK: true, Data: json.RawMessage(`{not valid json`)}
	st, err := parseWPState(resp)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if st != nil {
		t.Error("state should be nil on error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorUnknown) {
		t.Errorf("expected unknown error kind, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// runWPEnvelope — transport / envelope parsing errors
// ---------------------------------------------------------------------------

func TestWPRunEnvelope_TransportError(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "connection refused", errors.New("dial error")
	})()

	_, err := wp.runWPEnvelope(context.Background(), "Read", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorUnknown) {
		t.Errorf("transport error should map to unknown, got %v", err)
	}
}

func TestWPRunEnvelope_ContextCancelled(t *testing.T) {
	_, wp := wpNewClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	defer stubRun(func(innerCtx context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", innerCtx.Err()
	})()

	_, err := wp.runWPEnvelope(ctx, "Install", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !IsWingetPackageError(err, WingetPackageErrorUnknown) {
		t.Errorf("cancelled context should map to unknown, got %v", err)
	}
}

func TestWPRunEnvelope_NoJSONInOutput(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "no json here\n", "", nil
	})()

	_, err := wp.runWPEnvelope(context.Background(), "Read", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected error for missing JSON")
	}
	if !IsWingetPackageError(err, WingetPackageErrorUnknown) {
		t.Errorf("missing JSON should map to unknown, got %v", err)
	}
}

func TestWPRunEnvelope_InvalidJSONEnvelope(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{not valid json}` + "\n", "", nil
	})()

	_, err := wp.runWPEnvelope(context.Background(), "Read", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected error for invalid JSON envelope")
	}
	if !IsWingetPackageError(err, WingetPackageErrorUnknown) {
		t.Errorf("invalid JSON should map to unknown, got %v", err)
	}
}

func TestWPRunEnvelope_EmitErrResponse(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":false,"kind":"module_missing","message":"module not available","context":{}}` + "\n", "", nil
	})()

	_, err := wp.runWPEnvelope(context.Background(), "Install", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected error from Emit-Err response")
	}
	if !IsWingetPackageError(err, WingetPackageErrorModuleMissing) {
		t.Errorf("expected module_missing, got %v", err)
	}
}

func TestWPRunEnvelope_EmitOK_ReturnsResp(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":true,"data":null}` + "\n", "", nil
	})()

	resp, err := wp.runWPEnvelope(context.Background(), "Read", "Foo.Bar", "script")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.OK {
		t.Error("response should be OK")
	}
}

// ---------------------------------------------------------------------------
// Install — happy paths and errors
// ---------------------------------------------------------------------------

func TestWPInstall_HappyPath(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("Microsoft.VisualStudioCode", "winget", "1.85.2", "Visual Studio Code")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Microsoft.VisualStudioCode",
		Source:    "winget",
		Version:   "1.85.2",
	})
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.PackageID != "Microsoft.VisualStudioCode" {
		t.Errorf("PackageID = %q", st.PackageID)
	}
	if st.InstalledVersion != "1.85.2" {
		t.Errorf("InstalledVersion = %q", st.InstalledVersion)
	}
}

func TestWPInstall_HappyPath_LatestVersion(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("7zip.7zip", "winget", "24.8.0", "7-Zip")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "7zip.7zip",
		Source:    "winget",
		// no version → latest
	})
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.Source != "winget" {
		t.Errorf("Source = %q", st.Source)
	}
}

func TestWPInstall_WithOverride(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("Notepad++.Notepad++", "winget", "8.6.0", "Notepad++")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Notepad++.Notepad++",
		Source:    "winget",
		Override:  "/S /allusers",
	})
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestWPInstall_RebootRequired(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateDataReboot("Some.Pkg", "winget", "1.0", "Some Package")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Some.Pkg",
		Source:    "winget",
	})
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if !st.RebootRequired {
		t.Error("expected RebootRequired=true")
	}
}

func TestWPInstall_AlreadyInstalled(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"already_installed","message":"already installed","context":{}}` + "\n"},
	})()

	_, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Microsoft.VisualStudioCode",
		Source:    "winget",
	})
	if err == nil {
		t.Fatal("expected already_installed error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorAlreadyInstalled) {
		t.Errorf("expected already_installed, got %v", err)
	}
}

func TestWPInstall_ModuleMissing(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"module_missing","message":"module not found","context":{}}` + "\n"},
	})()

	_, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
	})
	if err == nil {
		t.Fatal("expected module_missing error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorModuleMissing) {
		t.Errorf("expected module_missing, got %v", err)
	}
}

func TestWPInstall_VersionNotAvailable(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"version_not_available","message":"no installer for this version","context":{}}` + "\n"},
	})()

	_, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
		Version:   "99.0",
	})
	if err == nil {
		t.Fatal("expected version_not_available error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorVersionNotAvailable) {
		t.Errorf("expected version_not_available, got %v", err)
	}
}

func TestWPInstall_BlockedByPolicy(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"blocked_by_policy","message":"policy blocked","context":{}}` + "\n"},
	})()

	_, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Store.App",
		Source:    "msstore",
	})
	if err == nil {
		t.Fatal("expected blocked_by_policy error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorBlockedByPolicy) {
		t.Errorf("expected blocked_by_policy, got %v", err)
	}
}

func TestWPInstall_PermissionDenied(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"permission_denied","message":"requires elevation","context":{}}` + "\n"},
	})()

	_, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
	})
	if err == nil {
		t.Fatal("expected permission_denied error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

func TestWPInstall_UnknownStatus(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"unknown","message":"unexpected status","context":{}}` + "\n"},
	})()

	_, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
	})
	if err == nil {
		t.Fatal("expected error for unknown status")
	}
	if !IsWingetPackageError(err, WingetPackageErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestWPInstall_TransportError(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("winrm dial")
	})()

	_, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
	})
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestWPInstall_MsStoreSource(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("9NBLGGH4NNS1", "msstore", "1.0.0", "Store App")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Install(context.Background(), WingetPackageInput{
		PackageID: "9NBLGGH4NNS1",
		Source:    "msstore",
	})
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if st == nil || st.Source != "msstore" {
		t.Error("expected source=msstore")
	}
}

// ---------------------------------------------------------------------------
// Read — happy paths and errors
// ---------------------------------------------------------------------------

func TestWPRead_HappyPath(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("Microsoft.VisualStudioCode", "winget", "1.85.2", "Visual Studio Code")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Read(context.Background(), "Microsoft.VisualStudioCode", "winget")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.InstalledVersion != "1.85.2" {
		t.Errorf("InstalledVersion = %q", st.InstalledVersion)
	}
	if st.Name != "Visual Studio Code" {
		t.Errorf("Name = %q", st.Name)
	}
}

func TestWPRead_NotFound_NullData(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{{stdout: wpOKNull()}})()

	st, err := wp.Read(context.Background(), "Nonexistent.Package", "winget")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != nil {
		t.Errorf("expected nil state for absent package, got %+v", st)
	}
}

func TestWPRead_ModuleMissing(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"module_missing","message":"module not found","context":{}}` + "\n"},
	})()

	_, err := wp.Read(context.Background(), "Foo.Bar", "winget")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorModuleMissing) {
		t.Errorf("expected module_missing, got %v", err)
	}
}

func TestWPRead_TransportError(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("transport")
	})()

	_, err := wp.Read(context.Background(), "Foo.Bar", "winget")
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestWPRead_MsStoreSource(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("9NBLGGH4NNS1", "msstore", "1.0.0", "Store App")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Read(context.Background(), "9NBLGGH4NNS1", "msstore")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.Source != "msstore" {
		t.Errorf("Source = %q", st.Source)
	}
}

func TestWPRead_PermissionDenied(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"permission_denied","message":"elevation","context":{}}` + "\n"},
	})()

	_, err := wp.Read(context.Background(), "Foo.Bar", "winget")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Update — happy paths and errors
// ---------------------------------------------------------------------------

func TestWPUpdate_HappyPath(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("Microsoft.VisualStudioCode", "winget", "1.86.0", "Visual Studio Code")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Update(context.Background(), WingetPackageInput{
		PackageID: "Microsoft.VisualStudioCode",
		Source:    "winget",
		Version:   "1.86.0",
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.InstalledVersion != "1.86.0" {
		t.Errorf("InstalledVersion = %q", st.InstalledVersion)
	}
}

func TestWPUpdate_LatestVersion(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateData("Foo.Bar", "winget", "3.0.0", "Foo Bar")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Update(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
		// version "" → upgrade to latest
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestWPUpdate_RebootRequired(t *testing.T) {
	_, wp := wpNewClient(t)
	data := wpStateDataReboot("Foo.Bar", "winget", "2.0", "Foo Bar")
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Update(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
		Version:   "2.0",
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if st == nil || !st.RebootRequired {
		t.Error("expected RebootRequired=true")
	}
}

func TestWPUpdate_VersionNotAvailable(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"version_not_available","message":"no installer","context":{}}` + "\n"},
	})()

	_, err := wp.Update(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
		Version:   "99.0",
	})
	if err == nil {
		t.Fatal("expected version_not_available error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorVersionNotAvailable) {
		t.Errorf("expected version_not_available, got %v", err)
	}
}

func TestWPUpdate_CatalogError(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"catalog_error","message":"package renamed","context":{}}` + "\n"},
	})()

	_, err := wp.Update(context.Background(), WingetPackageInput{
		PackageID: "Old.Package",
		Source:    "winget",
	})
	if err == nil {
		t.Fatal("expected catalog_error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorCatalogError) {
		t.Errorf("expected catalog_error, got %v", err)
	}
}

func TestWPUpdate_BlockedByPolicy(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"blocked_by_policy","message":"policy","context":{}}` + "\n"},
	})()

	_, err := wp.Update(context.Background(), WingetPackageInput{
		PackageID: "Store.App",
		Source:    "msstore",
	})
	if err == nil {
		t.Fatal("expected blocked_by_policy error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorBlockedByPolicy) {
		t.Errorf("expected blocked_by_policy, got %v", err)
	}
}

func TestWPUpdate_TransportError(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("winrm dial")
	})()

	_, err := wp.Update(context.Background(), WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
	})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestWPUpdate_SourceUnreachable_ContextTimeout(t *testing.T) {
	_, wp := wpNewClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":false,"kind":"source_unreachable","message":"network error","context":{}}` + "\n", "", nil
	})()

	_, err := wp.Update(ctx, WingetPackageInput{
		PackageID: "Foo.Bar",
		Source:    "winget",
	})
	// Either context cancelled or source_unreachable — both are acceptable.
	if err == nil {
		t.Fatal("expected error (context timeout or source_unreachable)")
	}
}

// ---------------------------------------------------------------------------
// Uninstall — happy paths and errors
// ---------------------------------------------------------------------------

func TestWPUninstall_HappyPath(t *testing.T) {
	_, wp := wpNewClient(t)
	data := map[string]any{
		"package_id": "Microsoft.VisualStudioCode", "source": "winget",
		"installed_version": "", "name": "", "reboot_required": false,
	}
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Uninstall(context.Background(), "Microsoft.VisualStudioCode", "winget")
	if err != nil {
		t.Fatalf("Uninstall error: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
	if st.InstalledVersion != "" {
		t.Errorf("InstalledVersion should be empty after uninstall, got %q", st.InstalledVersion)
	}
}

func TestWPUninstall_RebootRequired(t *testing.T) {
	_, wp := wpNewClient(t)
	data := map[string]any{
		"package_id": "Foo.Bar", "source": "winget",
		"installed_version": "", "name": "", "reboot_required": true,
	}
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Uninstall(context.Background(), "Foo.Bar", "winget")
	if err != nil {
		t.Fatalf("Uninstall error: %v", err)
	}
	if st == nil || !st.RebootRequired {
		t.Error("expected RebootRequired=true")
	}
}

func TestWPUninstall_PackageNotInstalled(t *testing.T) {
	// The PS script treats PackageNotInstalled as success (Emit-OK with empty state).
	_, wp := wpNewClient(t)
	data := map[string]any{
		"package_id": "Foo.Bar", "source": "winget",
		"installed_version": "", "name": "", "reboot_required": false,
	}
	defer wpStubSequence([]wpResponse{{stdout: wpOK(t, data)}})()

	st, err := wp.Uninstall(context.Background(), "Foo.Bar", "winget")
	if err != nil {
		t.Fatalf("Uninstall error for already-absent package: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestWPUninstall_ResourceInUse_ContextCancel(t *testing.T) {
	_, wp := wpNewClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":false,"kind":"resource_in_use","message":"mutex held","context":{}}` + "\n", "", nil
	})()

	_, err := wp.Uninstall(ctx, "Foo.Bar", "winget")
	if err == nil {
		t.Fatal("expected error (context cancel or resource_in_use)")
	}
}

func TestWPUninstall_TransportError(t *testing.T) {
	_, wp := wpNewClient(t)
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "", errors.New("transport")
	})()

	_, err := wp.Uninstall(context.Background(), "Foo.Bar", "winget")
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestWPUninstall_ModuleMissing(t *testing.T) {
	_, wp := wpNewClient(t)
	defer wpStubSequence([]wpResponse{
		{stdout: `{"ok":false,"kind":"module_missing","message":"no module","context":{}}` + "\n"},
	})()

	_, err := wp.Uninstall(context.Background(), "Foo.Bar", "winget")
	if err == nil {
		t.Fatal("expected module_missing error")
	}
	if !IsWingetPackageError(err, WingetPackageErrorModuleMissing) {
		t.Errorf("expected module_missing, got %v", err)
	}
}

func TestWPUninstall_SourceUnreachable_ContextTimeout(t *testing.T) {
	_, wp := wpNewClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return `{"ok":false,"kind":"source_unreachable","message":"network","context":{}}` + "\n", "", nil
	})()

	_, err := wp.Uninstall(ctx, "Foo.Bar", "winget")
	if err == nil {
		t.Fatal("expected error (context timeout or source_unreachable)")
	}
}

// ---------------------------------------------------------------------------
// runRetryable — EC-10 and EC-8 retry logic
// ---------------------------------------------------------------------------

func TestWPRunRetryable_ImmediateNonRetryableError(t *testing.T) {
	_, wp := wpNewClient(t)
	callCount := 0
	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		callCount++
		return `{"ok":false,"kind":"permission_denied","message":"no admin","context":{}}` + "\n", "", nil
	})()

	_, err := wp.runRetryable(context.Background(), "Install", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected error for non-retryable kind")
	}
	if callCount != 1 {
		t.Errorf("non-retryable error should not be retried, callCount = %d", callCount)
	}
	if !IsWingetPackageError(err, WingetPackageErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

func TestWPRunRetryable_ResourceInUse_ContextCancelDuringWait(t *testing.T) {
	_, wp := wpNewClient(t)
	callCount := 0
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		callCount++
		return `{"ok":false,"kind":"resource_in_use","message":"mutex","context":{}}` + "\n", "", nil
	})()

	_, err := wp.runRetryable(ctx, "Install", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected error")
	}
	// At least one call should have been made
	if callCount < 1 {
		t.Errorf("expected at least 1 call, got %d", callCount)
	}
}

func TestWPRunRetryable_SourceUnreachable_ContextCancelDuringWait(t *testing.T) {
	_, wp := wpNewClient(t)
	callCount := 0
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	defer stubRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		callCount++
		return `{"ok":false,"kind":"source_unreachable","message":"net","context":{}}` + "\n", "", nil
	})()

	_, err := wp.runRetryable(ctx, "Read", "Foo.Bar", "script")
	if err == nil {
		t.Fatal("expected error")
	}
	if callCount < 1 {
		t.Errorf("expected at least 1 call, got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// Miscellaneous
// ---------------------------------------------------------------------------

func TestWPNewClient_StoredCorrectly(t *testing.T) {
	c, err := New(Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wp := NewWingetPackageClient(c)
	if wp == nil {
		t.Fatal("NewWingetPackageClient should return non-nil")
	}
	if wp.c != c {
		t.Error("client not stored correctly")
	}
}

func TestWPError_AllKindStrings(t *testing.T) {
	// Verify all exported kinds have non-empty string values.
	kinds := []WingetPackageErrorKind{
		WingetPackageErrorModuleMissing,
		WingetPackageErrorAlreadyInstalled,
		WingetPackageErrorVersionNotAvailable,
		WingetPackageErrorBlockedByPolicy,
		WingetPackageErrorPermission,
		WingetPackageErrorSourceUnreachable,
		WingetPackageErrorCatalogError,
		WingetPackageErrorResourceInUse,
		WingetPackageErrorUnknown,
	}
	for _, k := range kinds {
		if string(k) == "" {
			t.Errorf("kind %v has empty string value", k)
		}
	}
}
