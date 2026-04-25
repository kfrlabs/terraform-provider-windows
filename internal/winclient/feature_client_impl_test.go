// Package winclient — unit tests for FeatureClient.
//
// These tests stub the package-level seam runFeaturePowerShell to inject
// scripted stdout/stderr/err triples. They cover the 9 edge cases from the
// windows_feature spec:
//
//   EC-1  Unknown feature name           -> NewFeatureError(not_found) at Install
//   EC-2  Drift (uninstalled out-of-band)-> Read returns FeatureInfo with installed=false
//   EC-3  install_state=Removed w/o source -> source_missing at Install
//   EC-4  Reboot required, restart=false -> resp.RestartNeeded surfaced
//   EC-5  Insufficient permissions      -> permission_denied with admin hint
//   EC-6  ForceNew on include_*         -> resource layer concern, asserted there
//   EC-7  Parent feature absent         -> dependency_missing
//   EC-8  WinRM timeout                 -> ctx.Err() -> FeatureErrorTimeout
//   EC-9  Cmdlet unavailable (client SKU)-> unsupported_sku
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

func newFeatTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:     "win01",
		Username: "u",
		Password: "p",
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// stubFeatRun replaces runFeaturePowerShell for the duration of a test.
func stubFeatRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runFeaturePowerShell
	runFeaturePowerShell = fn
	return func() { runFeaturePowerShell = prev }
}

func featOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func featErr(t *testing.T, kind, msg string) string {
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

func fakeFeatureData(name, state string) map[string]any {
	return map[string]any{
		"name":            name,
		"display_name":    name + " Display",
		"description":     "feature description",
		"installed":       state == "Installed",
		"install_state":   state,
		"restart_pending": false,
	}
}

func fakeInstallData(name, state string, restart bool, exitCode string) map[string]any {
	return map[string]any{
		"feature":        fakeFeatureData(name, state),
		"restart_needed": restart,
		"success":        true,
		"exit_code":      exitCode,
	}
}

// -----------------------------------------------------------------------------
// FeatureError type
// -----------------------------------------------------------------------------

func TestFeatureError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	e := NewFeatureError(FeatureErrorTimeout, "install timed out", cause,
		map[string]string{"name": "Web-Server"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "timeout") || !strings.Contains(msg, "install timed out") ||
		!strings.Contains(msg, "underlying") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewFeatureError(FeatureErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestFeatureError_Is_And_IsFeatureError(t *testing.T) {
	e := NewFeatureError(FeatureErrorNotFound, "x", nil, nil)
	if !errors.Is(e, ErrFeatureNotFound) {
		t.Error("errors.Is(ErrFeatureNotFound) should match by kind")
	}
	if errors.Is(e, ErrFeaturePermission) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsFeatureError(e, FeatureErrorNotFound) {
		t.Error("IsFeatureError should match")
	}
	if IsFeatureError(errors.New("plain"), FeatureErrorNotFound) {
		t.Error("IsFeatureError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-FeatureError should be false")
	}
}

func TestMapFeatureKind(t *testing.T) {
	cases := map[string]FeatureErrorKind{
		"not_found":          FeatureErrorNotFound,
		"permission_denied":  FeatureErrorPermission,
		"source_missing":     FeatureErrorSourceMissing,
		"dependency_missing": FeatureErrorDependencyMissing,
		"unsupported_sku":    FeatureErrorUnsupportedSKU,
		"timeout":            FeatureErrorTimeout,
		"invalid_parameter": FeatureErrorInvalidParameter,
		"":                   FeatureErrorUnknown,
		"weird_kind":         FeatureErrorUnknown,
	}
	for in, want := range cases {
		if got := mapFeatureKind(in); got != want {
			t.Errorf("mapFeatureKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPsBool(t *testing.T) {
	if psBool(true) != "true" {
		t.Errorf("psBool(true) = %q", psBool(true))
	}
	if psBool(false) != "false" {
		t.Errorf("psBool(false) = %q", psBool(false))
	}
}

// -----------------------------------------------------------------------------
// Input validation short-circuits
// -----------------------------------------------------------------------------

func TestFeatureRead_EmptyName(t *testing.T) {
	f := NewFeatureClient(newFeatTestClient(t))
	if _, err := f.Read(context.Background(), ""); !IsFeatureError(err, FeatureErrorInvalidParameter) {
		t.Errorf("empty name should yield invalid_parameter, got %v", err)
	}
	if _, err := f.Read(context.Background(), "   "); !IsFeatureError(err, FeatureErrorInvalidParameter) {
		t.Errorf("whitespace name should yield invalid_parameter, got %v", err)
	}
}

func TestFeatureInstall_EmptyName(t *testing.T) {
	f := NewFeatureClient(newFeatTestClient(t))
	if _, _, err := f.Install(context.Background(), FeatureInput{}); !IsFeatureError(err, FeatureErrorInvalidParameter) {
		t.Errorf("expected invalid_parameter, got %v", err)
	}
}

func TestFeatureUninstall_EmptyName(t *testing.T) {
	f := NewFeatureClient(newFeatTestClient(t))
	if _, _, err := f.Uninstall(context.Background(), FeatureInput{}); !IsFeatureError(err, FeatureErrorInvalidParameter) {
		t.Errorf("expected invalid_parameter, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// runFeatureEnvelope: ctx cancel (EC-8) / transport / no envelope / bad JSON
// -----------------------------------------------------------------------------

func TestRunFeatureEnvelope_Timeout_EC8(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := NewFeatureClient(newFeatTestClient(t))
	_, err := f.Read(ctx, "Web-Server")
	if !IsFeatureError(err, FeatureErrorTimeout) {
		t.Errorf("EC-8 expected timeout, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "Web-Server") {
		t.Errorf("timeout error should reference feature name: %s", err.Error())
	}
}

func TestRunFeatureEnvelope_TransportError(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "stdout-junk", "stderr-junk", errors.New("winrm: tcp reset")
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, err := f.Read(context.Background(), "Web-Server")
	if !IsFeatureError(err, FeatureErrorUnknown) {
		t.Errorf("expected unknown, got %v", err)
	}
}

func TestRunFeatureEnvelope_NoJSON(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "WARNING: no JSON\n", "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, err := f.Read(context.Background(), "Web-Server")
	if !IsFeatureError(err, FeatureErrorUnknown) {
		t.Errorf("missing envelope should yield unknown, got %v", err)
	}
}

func TestRunFeatureEnvelope_MalformedJSON(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "{not:valid,json}\n", "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, err := f.Read(context.Background(), "Web-Server")
	if !IsFeatureError(err, FeatureErrorUnknown) {
		t.Errorf("malformed JSON should yield unknown, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestFeatureRead_HappyPath_Installed(t *testing.T) {
	var captured string
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return featOK(t, fakeFeatureData("Web-Server", "Installed")), "", nil
	})
	defer restore()

	f := NewFeatureClient(newFeatTestClient(t))
	info, err := f.Read(context.Background(), "Web-Server")
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if info == nil {
		t.Fatal("expected info, got nil")
	}
	if info.Name != "Web-Server" || !info.Installed || info.InstallState != "Installed" {
		t.Errorf("unexpected info: %+v", info)
	}
	if !strings.Contains(captured, "'Web-Server'") {
		t.Errorf("script missing quoted feature name: %s", captured)
	}
}

func TestFeatureRead_DriftAvailable_EC2(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featOK(t, fakeFeatureData("Web-Server", "Available")), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	info, err := f.Read(context.Background(), "Web-Server")
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if info == nil || info.Installed || info.InstallState != "Available" {
		t.Errorf("EC-2 drift: expected Available/installed=false, got %+v", info)
	}
}

func TestFeatureRead_NullData_NotFound(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":null}` + "\n", "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	info, err := f.Read(context.Background(), "Web-Server")
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}
}

func TestFeatureRead_NotFoundViaKind(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featErr(t, "not_found", "No match was found"), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	info, err := f.Read(context.Background(), "Web-Server")
	if err != nil {
		t.Errorf("not_found should be swallowed by Read, got %v", err)
	}
	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}
}

func TestFeatureRead_PermissionDenied_EC5(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, err := f.Read(context.Background(), "Web-Server")
	if !IsFeatureError(err, FeatureErrorPermission) {
		t.Fatalf("EC-5 expected permission_denied, got %v", err)
	}
	if !strings.Contains(err.Error(), "Local Administrator") {
		t.Errorf("EC-5 missing admin hint: %s", err.Error())
	}
}

func TestFeatureRead_UnsupportedSKU_EC9(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featErr(t, "unsupported_sku",
			"Install-WindowsFeature is not available; use Enable-WindowsOptionalFeature instead."), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, err := f.Read(context.Background(), "Web-Server")
	if !IsFeatureError(err, FeatureErrorUnsupportedSKU) {
		t.Errorf("EC-9 expected unsupported_sku, got %v", err)
	}
}

func TestFeatureRead_UnparseablePayload(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":"not-an-object"}` + "\n", "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, err := f.Read(context.Background(), "Web-Server")
	if !IsFeatureError(err, FeatureErrorUnknown) {
		t.Errorf("expected unknown for unparseable payload, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Install
// -----------------------------------------------------------------------------

func TestFeatureInstall_HappyPath(t *testing.T) {
	var captured string
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return featOK(t, fakeInstallData("Web-Server", "Installed", false, "Success")), "", nil
	})
	defer restore()

	f := NewFeatureClient(newFeatTestClient(t))
	info, result, err := f.Install(context.Background(), FeatureInput{
		Name:                   "Web-Server",
		IncludeSubFeatures:     true,
		IncludeManagementTools: true,
		Source:                 `\\srv\share\sxs`,
		Restart:                false,
	})
	if err != nil {
		t.Fatalf("Install err: %v", err)
	}
	if info == nil || info.Name != "Web-Server" || !info.Installed {
		t.Errorf("unexpected info: %+v", info)
	}
	if result == nil || result.RestartNeeded || !result.Success || result.ExitCode != "Success" {
		t.Errorf("unexpected result: %+v", result)
	}
	if !strings.Contains(captured, "'Web-Server'") {
		t.Errorf("script missing quoted name")
	}
	if !strings.Contains(captured, `'\\srv\share\sxs'`) {
		t.Errorf("script missing quoted source: %s", captured)
	}
	if !strings.Contains(captured, "-IncludeSub:$true") || !strings.Contains(captured, "-IncludeMgmt:$true") {
		t.Errorf("script missing IncludeSub/IncludeMgmt switches: %s", captured)
	}
}

func TestFeatureInstall_RestartNeeded_EC4(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		d := fakeInstallData("Web-Server", "Installed", true, "SuccessRestartRequired")
		feat := d["feature"].(map[string]any)
		feat["restart_pending"] = true
		return featOK(t, d), "", nil
	})
	defer restore()

	f := NewFeatureClient(newFeatTestClient(t))
	info, result, err := f.Install(context.Background(), FeatureInput{Name: "Web-Server"})
	if err != nil {
		t.Fatalf("Install err: %v", err)
	}
	if !result.RestartNeeded {
		t.Error("EC-4: result.RestartNeeded should be true")
	}
	if !info.RestartPending {
		t.Error("EC-4: info.RestartPending should be true")
	}
	if result.ExitCode != "SuccessRestartRequired" {
		t.Errorf("ExitCode = %q", result.ExitCode)
	}
}

func TestFeatureInstall_NotFound_EC1(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featErr(t, "not_found", "Feature 'Bogus-Role' was not found on this host."), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, _, err := f.Install(context.Background(), FeatureInput{Name: "Bogus-Role"})
	if !IsFeatureError(err, FeatureErrorNotFound) {
		t.Errorf("EC-1 expected not_found, got %v", err)
	}
}

func TestFeatureInstall_SourceMissing_EC3(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featErr(t, "source_missing",
			"Feature 'Web-Server' has install_state=Removed; an SxS/WIM 'source' path is required to install it."),
			"", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, _, err := f.Install(context.Background(), FeatureInput{Name: "Web-Server"})
	if !IsFeatureError(err, FeatureErrorSourceMissing) {
		t.Errorf("EC-3 expected source_missing, got %v", err)
	}
	if !strings.Contains(err.Error(), "source") {
		t.Errorf("EC-3 message should mention 'source': %s", err.Error())
	}
}

func TestFeatureInstall_DependencyMissing_EC7(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featErr(t, "dependency_missing",
			"The feature 'Web-Mgmt-Service' depends on parent feature 'Web-Server' which is not installed."),
			"", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, _, err := f.Install(context.Background(), FeatureInput{Name: "Web-Mgmt-Service"})
	if !IsFeatureError(err, FeatureErrorDependencyMissing) {
		t.Errorf("EC-7 expected dependency_missing, got %v", err)
	}
}

func TestFeatureInstall_BadPayload(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":42}` + "\n", "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, _, err := f.Install(context.Background(), FeatureInput{Name: "Web-Server"})
	if !IsFeatureError(err, FeatureErrorUnknown) {
		t.Errorf("expected unknown for bad payload, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Uninstall
// -----------------------------------------------------------------------------

func TestFeatureUninstall_HappyPath(t *testing.T) {
	var captured string
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		captured = script
		return featOK(t, fakeInstallData("Web-Server", "Available", false, "Success")), "", nil
	})
	defer restore()

	f := NewFeatureClient(newFeatTestClient(t))
	info, result, err := f.Uninstall(context.Background(), FeatureInput{
		Name:                   "Web-Server",
		IncludeManagementTools: true,
		Restart:                true,
	})
	if err != nil {
		t.Fatalf("Uninstall err: %v", err)
	}
	if info == nil || info.Installed {
		t.Errorf("after uninstall, installed must be false: %+v", info)
	}
	if result == nil || !result.Success {
		t.Errorf("unexpected result: %+v", result)
	}
	if !strings.Contains(captured, "Run-Uninstall") {
		t.Errorf("script must call Run-Uninstall: %s", captured)
	}
}

func TestFeatureUninstall_AlreadyAbsent(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featOK(t, map[string]any{
			"feature":        nil,
			"restart_needed": false,
			"success":        true,
			"exit_code":      "NoChangeNeeded",
		}), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	info, result, err := f.Uninstall(context.Background(), FeatureInput{Name: "Web-Server"})
	if err != nil {
		t.Fatalf("Uninstall err: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil info when feature absent, got %+v", info)
	}
	if result == nil || result.ExitCode != "NoChangeNeeded" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestFeatureUninstall_RestartNeeded(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featOK(t, fakeInstallData("Web-Server", "Available", true, "SuccessRestartRequired")), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, result, err := f.Uninstall(context.Background(), FeatureInput{Name: "Web-Server"})
	if err != nil {
		t.Fatalf("Uninstall err: %v", err)
	}
	if !result.RestartNeeded {
		t.Error("expected RestartNeeded=true")
	}
}

func TestFeatureUninstall_PermissionDenied(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return featErr(t, "permission_denied", "Access is denied"), "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, _, err := f.Uninstall(context.Background(), FeatureInput{Name: "Web-Server"})
	if !IsFeatureError(err, FeatureErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

func TestFeatureUninstall_BadPayload(t *testing.T) {
	restore := stubFeatRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return `{"ok":true,"data":"oops"}` + "\n", "", nil
	})
	defer restore()
	f := NewFeatureClient(newFeatTestClient(t))
	_, _, err := f.Uninstall(context.Background(), FeatureInput{Name: "Web-Server"})
	if !IsFeatureError(err, FeatureErrorUnknown) {
		t.Errorf("expected unknown for bad payload, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// toFeatureInfo
// -----------------------------------------------------------------------------

func TestToFeatureInfo_Nil(t *testing.T) {
	if toFeatureInfo(nil) != nil {
		t.Error("toFeatureInfo(nil) must return nil")
	}
}

func TestToFeatureInfo_AllFields(t *testing.T) {
	got := toFeatureInfo(&featureDataPayload{
		Name: "n", DisplayName: "d", Description: "desc",
		Installed: true, InstallState: "Installed", RestartPending: true,
	})
	if got.Name != "n" || got.DisplayName != "d" || got.Description != "desc" ||
		!got.Installed || got.InstallState != "Installed" || !got.RestartPending {
		t.Errorf("unexpected: %+v", got)
	}
}

// Compile-time assertion mirror.
func TestFeatureClient_ImplementsInterface(t *testing.T) {
	var _ WindowsFeatureClient = (*FeatureClient)(nil)
}
