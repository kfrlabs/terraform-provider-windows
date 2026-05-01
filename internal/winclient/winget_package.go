// Package winclient — WingetPackageClientImpl
//
// Implements WingetPackageClient by executing Microsoft.WinGet.Client
// PowerShell cmdlets over WinRM. Every PowerShell script is emitted through
// the standard JSON envelope (Emit-OK / Emit-Err) so output is
// locale-independent and machine-parseable.
//
// Edge cases handled:
//
//	EC-1  Microsoft.WinGet.Client module missing → module_missing error.
//	EC-2  Package already installed at Create → already_installed error (pre-flight).
//	EC-3  Drift: Read returns (nil, nil) when Get-WinGetPackage returns nothing.
//	EC-4  Pinned version not in catalog → version_not_available error.
//	EC-5  msstore interactive/policy block → blocked_by_policy error.
//	EC-6  RebootRequired status → WingetPackageState.RebootRequired = true, no error.
//	EC-7  Elevation required → permission_denied error.
//	EC-8  Network failure → retry once (5 s) before returning source_unreachable.
//	EC-9  Package renamed/removed from catalog → catalog_error error.
//	EC-10 winget mutex held → retry 3x (5 s / 15 s / 30 s) before returning resource_in_use.
//	EC-11 Malformed import ID → validated at resource layer, not here.
//	EC-12 override quoting → handled by psQuote at substitution time.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Compile-time assertion: WingetPackageClientImpl satisfies WingetPackageClient.
var _ WingetPackageClient = (*WingetPackageClientImpl)(nil)

// WingetPackageClientImpl is the PowerShell/WinRM-backed WingetPackageClient.
type WingetPackageClientImpl struct {
	c *Client
}

// NewWingetPackageClient constructs a WingetPackageClientImpl wrapping the
// given WinRM Client.
func NewWingetPackageClient(c *Client) *WingetPackageClientImpl {
	return &WingetPackageClientImpl{c: c}
}

// ---------------------------------------------------------------------------
// PowerShell header — shared across all winget package scripts
// ---------------------------------------------------------------------------

// wpHeader is prepended to every winget script. It defines:
//   - Emit-OK / Emit-Err  : JSON envelope emitters (locale-independent).
//   - Classify-WP         : maps error message fragments to WingetPackageErrorKind strings.
//   - Assert-WinGetModule  : pre-flight that checks and imports Microsoft.WinGet.Client;
//     emits Emit-Err 'module_missing' + exit 0 on failure (EC-1).
const wpHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}

function Emit-Err([string]$Kind, [string]$Msg, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Msg; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}

function Classify-WP([string]$Msg) {
  if ($Msg -match 'NoApplicableInstaller|InvalidVersion|no applicable installer') { return 'version_not_available' }
  if ($Msg -match 'BlockedByPolicy|RequiresInteractive')                          { return 'blocked_by_policy' }
  if ($Msg -match '[Ee]levation|[Aa]ccess.*[Dd]enied|requires elevation')        { return 'permission_denied' }
  if ($Msg -match 'SourceError|DownloadError|[Nn]etwork error|[Cc]onnection')    { return 'source_unreachable' }
  if ($Msg -match 'CatalogError|not found in catalog')                           { return 'catalog_error' }
  if ($Msg -match 'ResourceInUse|another transaction|another instance')          { return 'resource_in_use' }
  return 'unknown'
}

function Assert-WinGetModule {
  $m = @(Get-Module -ListAvailable 'Microsoft.WinGet.Client' -ErrorAction SilentlyContinue)
  if ($m.Count -eq 0) {
    Emit-Err 'module_missing' 'Microsoft.WinGet.Client PowerShell module is not available on this host. Install it with: Install-Module Microsoft.WinGet.Client -Scope AllUsers' @{}
    exit 0
  }
  try {
    Import-Module 'Microsoft.WinGet.Client' -ErrorAction Stop
  } catch {
    Emit-Err 'module_missing' ('Failed to import Microsoft.WinGet.Client: ' + $_.Exception.Message) @{}
    exit 0
  }
}
`

// ---------------------------------------------------------------------------
// PowerShell script templates
// ---------------------------------------------------------------------------
// Placeholders (replaced by wpReplace before execution):
//
//	@@ID@@       - psQuote(packageID)
//	@@SRC@@      - psQuote(source)
//	@@VER@@      - psQuote(version)   (empty string when not pinned)
//	@@OVERRIDE@@ - psQuote(override)  (empty string when not set)

const wpReadBody = `
$wpId  = @@ID@@
$wpSrc = @@SRC@@
Assert-WinGetModule
try {
  $pkgs = @(Get-WinGetPackage -Id $wpId -Source $wpSrc -MatchOption Equals -ErrorAction Stop)
  if ($pkgs.Count -eq 0) {
    Emit-OK $null
  } else {
    $p = $pkgs[0]
    Emit-OK ([ordered]@{
      package_id        = [string]$p.Id
      source            = $wpSrc
      installed_version = [string]$p.InstalledVersion
      name              = [string]$p.Name
      reboot_required   = $false
    })
  }
} catch {
  Emit-Err (Classify-WP $_.Exception.Message) $_.Exception.Message @{ package_id = $wpId; source = $wpSrc }
}
`

const wpInstallBody = `
$wpId  = @@ID@@
$wpSrc = @@SRC@@
$wpVer = @@VER@@
$wpOvr = @@OVERRIDE@@
Assert-WinGetModule
try {
  # EC-2: pre-flight existence check before Install
  $existing = @(Get-WinGetPackage -Id $wpId -Source $wpSrc -MatchOption Equals -ErrorAction SilentlyContinue)
  if ($existing.Count -gt 0) {
    $existVer = [string]$existing[0].InstalledVersion
    $importId = $wpSrc + ':' + $wpId
    Emit-Err 'already_installed' ('Package ' + $wpId + ' is already installed (version ' + $existVer + ') from source ' + $wpSrc + '. Import with: terraform import windows_winget_package.<name> ' + $importId) @{ installed_version = $existVer }
    exit 0
  }
  $params = @{
    Id                      = $wpId
    Source                  = $wpSrc
    MatchOption             = 'Equals'
    Mode                    = 'Silent'
    Scope                   = 'SystemOrUnknown'
    AcceptPackageAgreements = $true
    AcceptSourceAgreements  = $true
  }
  if ($wpVer -ne '') { $params['Version'] = $wpVer }
  if ($wpOvr -ne '') { $params['Override'] = $wpOvr }
  $result = Install-WinGetPackage @params
  $status = [string]$result.Status
  if ($status -eq 'NoApplicableInstaller' -or $status -eq 'InvalidVersion') {
    Emit-Err 'version_not_available' ('Version ' + $wpVer + ' not available for ' + $wpId + ' on source ' + $wpSrc + ' (status: ' + $status + ')') @{ status = $status }
    exit 0
  }
  if ($status -eq 'BlockedByPolicy' -or $status -eq 'RequiresInteractive') {
    Emit-Err 'blocked_by_policy' ('Package ' + $wpId + ' from ' + $wpSrc + ' is blocked by policy or requires interactive authentication. Consider source=winget.') @{ status = $status }
    exit 0
  }
  if ($status -eq 'ResourceInUse') {
    Emit-Err 'resource_in_use' 'winget resource in use (another transaction is in progress)' @{ status = $status }
    exit 0
  }
  if ($status -eq 'DownloadError' -or $status -eq 'SourceError') {
    Emit-Err 'source_unreachable' ('Network/source error installing ' + $wpId + ' from ' + $wpSrc + ' (status: ' + $status + ')') @{ status = $status }
    exit 0
  }
  if ($status -ne 'Ok' -and $status -ne 'RebootRequired' -and $status -ne 'AlreadyInstalled') {
    $extCode = ''
    if ($null -ne $result.ExtendedErrorCode) { $extCode = [string]$result.ExtendedErrorCode }
    Emit-Err 'unknown' ('Install-WinGetPackage returned status ' + $status + ' for ' + $wpId + ' (ExtendedErrorCode: ' + $extCode + ')') @{ status = $status; extended_error_code = $extCode }
    exit 0
  }
  $reboot = ($status -eq 'RebootRequired')
  $pkgs2 = @(Get-WinGetPackage -Id $wpId -Source $wpSrc -MatchOption Equals -ErrorAction SilentlyContinue)
  $instVer2 = ''
  $pkgName2 = ''
  if ($pkgs2.Count -gt 0) {
    $instVer2 = [string]$pkgs2[0].InstalledVersion
    $pkgName2 = [string]$pkgs2[0].Name
  }
  Emit-OK ([ordered]@{
    package_id        = $wpId
    source            = $wpSrc
    installed_version = $instVer2
    name              = $pkgName2
    reboot_required   = $reboot
  })
} catch {
  $errMsg = $_.Exception.Message
  Emit-Err (Classify-WP $errMsg) $errMsg @{ package_id = $wpId; source = $wpSrc }
}
`

const wpUpdateBody = `
$wpId  = @@ID@@
$wpSrc = @@SRC@@
$wpVer = @@VER@@
Assert-WinGetModule
try {
  $params = @{
    Id                      = $wpId
    Source                  = $wpSrc
    MatchOption             = 'Equals'
    Mode                    = 'Silent'
    Scope                   = 'SystemOrUnknown'
    AcceptPackageAgreements = $true
    AcceptSourceAgreements  = $true
  }
  if ($wpVer -ne '') { $params['Version'] = $wpVer }
  $result = Update-WinGetPackage @params
  $status = [string]$result.Status
  if ($status -eq 'NoApplicableInstaller' -or $status -eq 'InvalidVersion') {
    Emit-Err 'version_not_available' ('Version ' + $wpVer + ' not available for ' + $wpId + ' on source ' + $wpSrc + ' (status: ' + $status + ')') @{ status = $status }
    exit 0
  }
  if ($status -eq 'CatalogError') {
    Emit-Err 'catalog_error' ('Package ' + $wpId + ' was not found in catalog on source ' + $wpSrc + '. It may have been renamed or removed. Consider: terraform destroy + re-import under the new ID.') @{ status = $status }
    exit 0
  }
  if ($status -eq 'BlockedByPolicy' -or $status -eq 'RequiresInteractive') {
    Emit-Err 'blocked_by_policy' ('Package ' + $wpId + ' from ' + $wpSrc + ' is blocked by policy or requires interactive authentication.') @{ status = $status }
    exit 0
  }
  if ($status -eq 'ResourceInUse') {
    Emit-Err 'resource_in_use' 'winget resource in use (another transaction is in progress)' @{ status = $status }
    exit 0
  }
  if ($status -eq 'DownloadError' -or $status -eq 'SourceError') {
    Emit-Err 'source_unreachable' ('Network/source error updating ' + $wpId + ' from ' + $wpSrc + ' (status: ' + $status + ')') @{ status = $status }
    exit 0
  }
  if ($status -eq 'PackageNotInstalled') {
    Emit-Err 'unknown' ('Cannot update ' + $wpId + ': package is not currently installed (PackageNotInstalled).') @{ status = $status }
    exit 0
  }
  if ($status -ne 'Ok' -and $status -ne 'RebootRequired' -and $status -ne 'NoAvailableUpgrade' -and $status -ne 'AlreadyInstalled') {
    $extCode = ''
    if ($null -ne $result.ExtendedErrorCode) { $extCode = [string]$result.ExtendedErrorCode }
    Emit-Err 'unknown' ('Update-WinGetPackage returned status ' + $status + ' for ' + $wpId + ' (ExtendedErrorCode: ' + $extCode + ')') @{ status = $status; extended_error_code = $extCode }
    exit 0
  }
  $reboot = ($status -eq 'RebootRequired')
  $pkgs2 = @(Get-WinGetPackage -Id $wpId -Source $wpSrc -MatchOption Equals -ErrorAction SilentlyContinue)
  $instVer2 = ''
  $pkgName2 = ''
  if ($pkgs2.Count -gt 0) {
    $instVer2 = [string]$pkgs2[0].InstalledVersion
    $pkgName2 = [string]$pkgs2[0].Name
  }
  Emit-OK ([ordered]@{
    package_id        = $wpId
    source            = $wpSrc
    installed_version = $instVer2
    name              = $pkgName2
    reboot_required   = $reboot
  })
} catch {
  $errMsg = $_.Exception.Message
  Emit-Err (Classify-WP $errMsg) $errMsg @{ package_id = $wpId; source = $wpSrc }
}
`

const wpUninstallBody = `
$wpId  = @@ID@@
$wpSrc = @@SRC@@
Assert-WinGetModule
try {
  $result = Uninstall-WinGetPackage -Id $wpId -Source $wpSrc -MatchOption Equals -Mode Silent -Scope SystemOrUnknown
  $status = [string]$result.Status
  if ($status -eq 'PackageNotInstalled') {
    Emit-OK ([ordered]@{ package_id = $wpId; source = $wpSrc; installed_version = ''; name = ''; reboot_required = $false })
    exit 0
  }
  if ($status -eq 'ResourceInUse') {
    Emit-Err 'resource_in_use' 'winget resource in use (another transaction is in progress)' @{ status = $status }
    exit 0
  }
  if ($status -ne 'Ok' -and $status -ne 'RebootRequired') {
    $extCode = ''
    if ($null -ne $result.ExtendedErrorCode) { $extCode = [string]$result.ExtendedErrorCode }
    Emit-Err 'unknown' ('Uninstall-WinGetPackage returned status ' + $status + ' for ' + $wpId + ' (ExtendedErrorCode: ' + $extCode + ')') @{ status = $status; extended_error_code = $extCode }
    exit 0
  }
  $reboot = ($status -eq 'RebootRequired')
  Emit-OK ([ordered]@{ package_id = $wpId; source = $wpSrc; installed_version = ''; name = ''; reboot_required = $reboot })
} catch {
  $errMsg = $_.Exception.Message
  Emit-Err (Classify-WP $errMsg) $errMsg @{ package_id = $wpId; source = $wpSrc }
}
`

// ---------------------------------------------------------------------------
// Internal JSON state model
// ---------------------------------------------------------------------------

// wpJSONState mirrors the PowerShell ordered hashtable emitted by every
// Emit-OK call in the winget package scripts.
type wpJSONState struct {
	PackageID        string `json:"package_id"`
	Source           string `json:"source"`
	InstalledVersion string `json:"installed_version"`
	Name             string `json:"name"`
	RebootRequired   bool   `json:"reboot_required"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// wpMapKind translates the PS-side "kind" string into a WingetPackageErrorKind.
func wpMapKind(k string) WingetPackageErrorKind {
	switch WingetPackageErrorKind(k) {
	case WingetPackageErrorModuleMissing,
		WingetPackageErrorAlreadyInstalled,
		WingetPackageErrorVersionNotAvailable,
		WingetPackageErrorBlockedByPolicy,
		WingetPackageErrorPermission,
		WingetPackageErrorSourceUnreachable,
		WingetPackageErrorCatalogError,
		WingetPackageErrorResourceInUse:
		return WingetPackageErrorKind(k)
	default:
		return WingetPackageErrorUnknown
	}
}

// wpReplace substitutes @@PLACEHOLDER@@ tokens in tmpl with psQuote-escaped
// values. All user-controlled input is routed through psQuote to prevent
// PowerShell injection (EC-12).
func wpReplace(tmpl, id, src, ver, override string) string {
	return strings.NewReplacer(
		"@@ID@@", psQuote(id),
		"@@SRC@@", psQuote(src),
		"@@VER@@", psQuote(ver),
		"@@OVERRIDE@@", psQuote(override),
	).Replace(tmpl)
}

// parseWPState unmarshals the Data field of a psResponse into a
// *WingetPackageState. Returns (nil, nil) when resp.Data is JSON null,
// signalling that the package is not installed (EC-3 drift).
func parseWPState(resp *psResponse) (*WingetPackageState, error) {
	if resp.Data == nil || string(resp.Data) == "null" {
		return nil, nil
	}
	var js wpJSONState
	if err := json.Unmarshal(resp.Data, &js); err != nil {
		return nil, NewWingetPackageError(WingetPackageErrorUnknown,
			"failed to parse winget package state JSON", err, nil)
	}
	return &WingetPackageState{
		PackageID:        js.PackageID,
		Source:           js.Source,
		InstalledVersion: js.InstalledVersion,
		Name:             js.Name,
		RebootRequired:   js.RebootRequired,
	}, nil
}

// ---------------------------------------------------------------------------
// Core execution methods
// ---------------------------------------------------------------------------

// runWPEnvelope executes a winget script (prefixed with wpHeader) over WinRM
// and parses the JSON envelope. Transport errors that bypass Emit-Err (non-zero
// exit, context cancellation) are wrapped as WingetPackageErrorUnknown.
func (w *WingetPackageClientImpl) runWPEnvelope(ctx context.Context, op, pkgID, script string) (*psResponse, error) {
	full := wpHeader + "\n" + script
	stdout, stderr, err := runPowerShell(ctx, w.c, full)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, NewWingetPackageError(WingetPackageErrorUnknown,
				fmt.Sprintf("operation %q cancelled or timed out", op),
				ctxErr,
				map[string]string{
					"operation":  op,
					"package_id": pkgID,
					"host":       w.c.cfg.Host,
				})
		}
		return nil, NewWingetPackageError(WingetPackageErrorUnknown,
			fmt.Sprintf("WinRM transport error during %q", op),
			err,
			map[string]string{
				"operation":  op,
				"package_id": pkgID,
				"host":       w.c.cfg.Host,
				"stderr":     truncate(stderr, 2048),
				"stdout":     truncate(stdout, 2048),
			})
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewWingetPackageError(WingetPackageErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op), nil,
			map[string]string{
				"operation":  op,
				"package_id": pkgID,
				"host":       w.c.cfg.Host,
				"stderr":     truncate(stderr, 2048),
				"stdout":     truncate(stdout, 2048),
			})
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewWingetPackageError(WingetPackageErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op), jerr,
			map[string]string{
				"operation":  op,
				"package_id": pkgID,
				"host":       w.c.cfg.Host,
				"stdout":     truncate(stdout, 2048),
			})
	}

	if !resp.OK {
		kind := wpMapKind(resp.Kind)
		errCtx := resp.Context
		if errCtx == nil {
			errCtx = map[string]string{}
		}
		errCtx["operation"] = op
		errCtx["package_id"] = pkgID
		errCtx["host"] = w.c.cfg.Host
		return &resp, NewWingetPackageError(kind, resp.Message, nil, errCtx)
	}
	return &resp, nil
}

// runRetryable executes a winget script with automatic retry for:
//   - EC-10 (resource_in_use): up to 3 retries with 5 s / 15 s / 30 s back-off.
//   - EC-8  (source_unreachable): 1 retry after 5 s.
//
// All other errors are returned immediately.
func (w *WingetPackageClientImpl) runRetryable(ctx context.Context, op, pkgID, script string) (*psResponse, error) {
	riuDelays := []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second}
	riuAttempts := 0
	netRetried := false

	for {
		resp, err := w.runWPEnvelope(ctx, op, pkgID, script)
		if err == nil {
			return resp, nil
		}

		// EC-10: winget mutex held — retry with exponential back-off
		if IsWingetPackageError(err, WingetPackageErrorResourceInUse) && riuAttempts < len(riuDelays) {
			delay := riuDelays[riuAttempts]
			riuAttempts++
			select {
			case <-ctx.Done():
				return nil, NewWingetPackageError(WingetPackageErrorUnknown,
					"context cancelled while waiting to retry (resource_in_use)",
					ctx.Err(),
					map[string]string{"operation": op, "package_id": pkgID})
			case <-time.After(delay):
				continue
			}
		}

		// EC-8: network/source failure — retry once after 5 s
		if IsWingetPackageError(err, WingetPackageErrorSourceUnreachable) && !netRetried {
			netRetried = true
			select {
			case <-ctx.Done():
				return nil, NewWingetPackageError(WingetPackageErrorUnknown,
					"context cancelled while waiting to retry (source_unreachable)",
					ctx.Err(),
					map[string]string{"operation": op, "package_id": pkgID})
			case <-time.After(5 * time.Second):
				continue
			}
		}

		return nil, err
	}
}

// ---------------------------------------------------------------------------
// WingetPackageClient interface implementation
// ---------------------------------------------------------------------------

// Install adds a new package via Install-WinGetPackage. The PowerShell script
// includes EC-1 (module pre-flight) and EC-2 (existence pre-flight). Always
// uses Mode=Silent, Scope=SystemOrUnknown, and auto-accepts agreements.
//
// Returns (*WingetPackageState, nil) on success. RebootRequired = true signals
// that the host must be rebooted (EC-6); the caller emits a warning diagnostic.
func (w *WingetPackageClientImpl) Install(ctx context.Context, input WingetPackageInput) (*WingetPackageState, error) {
	script := wpReplace(wpInstallBody,
		input.PackageID, input.Source, input.Version, input.Override)
	resp, err := w.runRetryable(ctx, "Install", input.PackageID, script)
	if err != nil {
		return nil, err
	}
	return parseWPState(resp)
}

// Read retrieves the current installed state via Get-WinGetPackage
// -MatchOption Equals. Returns (nil, nil) when the package is not installed
// (EC-3 drift handling — caller must call resp.State.RemoveResource).
func (w *WingetPackageClientImpl) Read(ctx context.Context, packageID, source string) (*WingetPackageState, error) {
	script := wpReplace(wpReadBody, packageID, source, "", "")
	resp, err := w.runWPEnvelope(ctx, "Read", packageID, script)
	if err != nil {
		return nil, err
	}
	return parseWPState(resp)
}

// Update applies a version change via Update-WinGetPackage. When
// input.Version is "" (cleared to null in config), the cmdlet is called
// without -Version to advance to the latest release.
//
// If the installed version already matches the desired version (race or
// external upgrade), the method is a no-op and returns the current state.
func (w *WingetPackageClientImpl) Update(ctx context.Context, input WingetPackageInput) (*WingetPackageState, error) {
	// EC-race: skip Update when the pinned version is already installed.
	if input.Version != "" {
		current, err := w.Read(ctx, input.PackageID, input.Source)
		if err != nil {
			return nil, err
		}
		if current != nil && current.InstalledVersion == input.Version {
			return current, nil
		}
	}

	script := wpReplace(wpUpdateBody, input.PackageID, input.Source, input.Version, "")
	resp, err := w.runRetryable(ctx, "Update", input.PackageID, script)
	if err != nil {
		return nil, err
	}
	return parseWPState(resp)
}

// Uninstall removes the package via Uninstall-WinGetPackage. PackageNotInstalled
// status is treated as success for idempotency (EC-3). RebootRequired is
// propagated via WingetPackageState.RebootRequired = true with nil error (EC-6).
func (w *WingetPackageClientImpl) Uninstall(ctx context.Context, packageID, source string) (*WingetPackageState, error) {
	script := wpReplace(wpUninstallBody, packageID, source, "", "")
	resp, err := w.runRetryable(ctx, "Uninstall", packageID, script)
	if err != nil {
		return nil, err
	}
	return parseWPState(resp)
}
