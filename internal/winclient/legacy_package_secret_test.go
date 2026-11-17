// Unit tests for issue #346: MSI verbose log keeps secrets in clear text.
//
// Covers the secret-hygiene contract of the legacy_package install and
// uninstall pipelines:
//
//   - install_args_wo travels to the host inside the stdin JSON payload and
//     is merged into the installer argument list without ever appearing in
//     the script body.
//   - keep_log=false (default) deletes the installer log after a successful
//     run and keeps it on every failure path.
//   - The uninstall pipeline honors keep_log the same way.
package winclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestLPCreate_MergesInstallArgsWOFromStdin(t *testing.T) {
	lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdin), &payload); err != nil {
			t.Fatalf("stdin is not JSON: %v", err)
		}
		wo, ok := payload["install_args_wo"].([]any)
		if !ok || len(wo) != 1 || wo[0] != "SERVICEPASSWORD=s3cret" {
			t.Errorf("stdin install_args_wo = %v, want [SERVICEPASSWORD=s3cret]", payload["install_args_wo"])
		}
		if payload["keep_log"] != nil {
			t.Errorf("stdin keep_log should be omitted when false, got %v", payload["keep_log"])
		}
		// The secret value must never be interpolated into the script body.
		if strings.Contains(script, "s3cret") {
			t.Error("script body must not contain the WriteOnly secret value")
		}
		return lpOK(t, lpStateMap("{01234567-89AB-CDEF-0123-456789ABCDEF}", "1.0")), "", nil
	})()

	_, err := lp.Create(context.Background(), LegacyPackageInput{
		Name:          "pkg",
		InstallerType: "msi",
		SourcePath:    `C:\pkg.msi`,
		InstallArgs:   []string{"/quiet"},
		InstallArgsWO: []string{"SERVICEPASSWORD=s3cret"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestLPCreate_ForwardsKeepLog(t *testing.T) {
	lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, stdin string) (string, string, error) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdin), &payload); err != nil {
			t.Fatalf("stdin is not JSON: %v", err)
		}
		if payload["keep_log"] != true {
			t.Errorf("stdin keep_log = %v, want true", payload["keep_log"])
		}
		return lpOK(t, lpStateMap("{01234567-89AB-CDEF-0123-456789ABCDEF}", "1.0")), "", nil
	})()

	_, err := lp.Create(context.Background(), LegacyPackageInput{
		Name:          "pkg",
		InstallerType: "msi",
		SourcePath:    `C:\pkg.msi`,
		KeepLog:       true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestLPCreateScript_SecretMergeAndLogLifecycle(t *testing.T) {
	body := lpCreateScript()
	for _, want := range []string{
		// WriteOnly args merged from the stdin payload, never logged.
		// Elements are quoted via ConvertTo-LpArg so values with spaces
		// survive Start-Process -ArgumentList intact (2026-11-17: an
		// unquoted SALVOPROP=hello world corrupted the msiexec command
		// line and hung the installer until timeout).
		`if ($cfg.install_args) { $extraInstall = @([string[]]$cfg.install_args | ForEach-Object { ConvertTo-LpArg $_ }) }`,
		`if ($cfg.install_args_wo) { $extraInstall += @([string[]]$cfg.install_args_wo | ForEach-Object { ConvertTo-LpArg $_ }) }`,
		// Default-secure: the installer log is deleted after success ...
		`if (-not $cfg.keep_log) {`,
		`Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("create script is missing %q", want)
		}
	}
	// ... but every failure path returns before its success-path deletion
	// marker so the log is kept for troubleshooting. The final deletion
	// (step 8) must come after the exit-code validation block and the
	// registry read-back checks.
	delIdx := strings.LastIndex(body, "Remove-Item -LiteralPath $logPath")
	for _, marker := range []string{
		`Emit-Err 'timeout'`,
		`Emit-Err $kind ("installer exited with code "`,
		`Emit-Err 'exec_failed'`,
		`Emit-Err 'multiple_matches'`,
	} {
		if idx := strings.Index(body, marker); idx < 0 || idx > delIdx {
			t.Errorf("failure marker %q must precede the log deletion", marker)
		}
	}
}

func TestLPDeleteScript_HonorsKeepLog(t *testing.T) {
	for _, want := range []string{
		`if (-not $cfg.keep_log) {`,
		`Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue`,
	} {
		if !strings.Contains(lpDeleteBody, want) {
			t.Errorf("delete script is missing %q", want)
		}
	}
	delIdx := strings.Index(lpDeleteBody, "Remove-Item -LiteralPath $logPath")
	for _, marker := range []string{
		`Emit-Err 'timeout' ("uninstall timed out after "`,
		`Emit-Err $kind ("msiexec exited with code "`,
	} {
		if idx := strings.Index(lpDeleteBody, marker); idx < 0 || idx > delIdx {
			t.Errorf("failure marker %q must precede the uninstall log deletion", marker)
		}
	}
}

func TestLPDelete_ForwardsUninstallSettings(t *testing.T) {
	lp := lpNewClient(t)
	defer stubLPInput(func(_ context.Context, _ *Client, _, stdin string) (string, string, error) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdin), &payload); err != nil {
			t.Fatalf("stdin is not JSON: %v", err)
		}
		args, ok := payload["uninstall_args"].([]any)
		if !ok || len(args) != 1 || args[0] != "/quiet" {
			t.Errorf("stdin uninstall_args = %v, want [/quiet]", payload["uninstall_args"])
		}
		if payload["keep_log"] != true {
			t.Errorf("stdin keep_log = %v, want true", payload["keep_log"])
		}
		return lpOKNull(), "", nil
	})()

	err := lp.Delete(context.Background(), "{01234567-89AB-CDEF-0123-456789ABCDEF}", LegacyPackageInput{
		UninstallArgs: []string{"/quiet"},
		KeepLog:       true,
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestLPArgQuoting_SpacesSurviveStartProcess(t *testing.T) {
	// Aggressive CLI campaign (2026-11-17): install_args ["SALVOPROP=hello
	// world"] reached msiexec unquoted (PS 5.1 Start-Process -ArgumentList
	// joins array elements with spaces and performs no quoting), corrupting
	// the command line and hanging the installer until timeout.
	// ConvertTo-LpArg must exist and wrap every user-supplied installer arg.
	if !strings.Contains(lpRemainder, "function ConvertTo-LpArg") {
		t.Fatal("lpRemainder is missing ConvertTo-LpArg")
	}
	for _, want := range []string{
		`[string[]]$cfg.install_args | ForEach-Object { ConvertTo-LpArg $_ }`,
		`[string[]]$cfg.install_args_wo | ForEach-Object { ConvertTo-LpArg $_ }`,
		`[string[]]$cfg.uninstall_args | ForEach-Object { ConvertTo-LpArg $_ }`,
	} {
		if !strings.Contains(lpCreateScript(), want) && !strings.Contains(lpDeleteBody, want) {
			t.Errorf("no script quotes user args via %q", want)
		}
	}
}
