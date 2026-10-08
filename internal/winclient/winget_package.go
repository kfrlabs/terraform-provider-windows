// Package winclient — WingetPackageClientImpl
//
// Implements WingetPackageClient by executing winget.exe directly (no
// PowerShell module required) from PowerShell scripts run over SSH. Every
// script is emitted through the standard JSON envelope (Emit-OK / Emit-Err)
// so output is machine-parseable.
//
// Locale independence: winget's human-readable output is localized, so
// results are never classified from message text. Outcomes are derived from
// winget's process exit codes (HRESULTs), which are stable across languages.
// The only text parsing left is the "winget list" table, which is located by
// its dashed separator line and read by column order, not by header names.
//
// winget.exe is resolved by its real path under %ProgramFiles%\WindowsApps
// (highest version wins), because the "winget" App Execution Alias only
// exists in interactive user profiles and is missing for SYSTEM.
//
// Edge cases handled:
//
//	EC-1  winget.exe not found → module_missing error (kind name kept for
//	      compatibility with the resource layer).
//	EC-2  Package already installed at Create → already_installed error (pre-flight).
//	EC-3  Drift: Read returns (nil, nil) when "winget list" reports no match
//	      (exit code NO_APPLICATIONS_FOUND); Uninstall treats the same exit
//	      code as success.
//	EC-4  Pinned version not in catalog → version_not_available error.
//	EC-5  msstore / Group Policy block → blocked_by_policy error.
//	EC-6  Reboot exit codes → WingetPackageState.RebootRequired = true, no error.
//	EC-7  Elevation required → permission_denied error.
//	EC-8  Network failure → retry once (5 s) before returning source_unreachable.
//	EC-9  Package renamed/removed from catalog, or Install/Update resolving an
//	      unknown id (NO_APPLICATIONS_FOUND) → catalog_error error.
//	EC-10 winget transaction in progress → retry 3x (5 s / 15 s / 30 s) before
//	      returning resource_in_use.
//	EC-11 Malformed import ID → validated at resource layer, not here.
//	EC-12 override quoting → psQuote at substitution time, then a Windows
//	      command-line quoting pass (ConvertTo-WinArg) when starting winget.exe.
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

// WingetPackageClientImpl is the PowerShell/SSH-backed WingetPackageClient.
type WingetPackageClientImpl struct {
	c *Client
}

// NewWingetPackageClient constructs a WingetPackageClientImpl wrapping the
// given SSH Client.
func NewWingetPackageClient(c *Client) *WingetPackageClientImpl {
	return &WingetPackageClientImpl{c: c}
}

// ---------------------------------------------------------------------------
// PowerShell header — shared across all winget package scripts
// ---------------------------------------------------------------------------

// wpHeader is prepended to every winget script. It defines:
//   - Emit-OK / Emit-Err   : JSON envelope emitters.
//   - $WG_* constants      : winget exit codes (signed 32-bit HRESULTs).
//   - Classify-WG          : maps an exit code to a WingetPackageErrorKind string.
//   - Resolve-WingetPath   : finds the real winget.exe (works for SYSTEM).
//   - Assert-Winget        : pre-flight; emits 'module_missing' + returns $false (EC-1).
//   - Invoke-Winget        : runs winget.exe, captures stdout/stderr/exit code.
//   - Get-WPState          : reads the installed state of one package.
const wpHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# winget exit codes as signed 32-bit integers.
# Reference: https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-manager/winget/returnCodes.md
$WG_NO_APPS       = -1978335212            # 0x8A150014 NO_APPLICATIONS_FOUND
$WG_NO_MANIFEST   = -1978335209            # 0x8A150017 NO_MANIFEST_FOUND
$WG_NO_INSTALLER  = -1978335216            # 0x8A150010 NO_APPLICABLE_INSTALLER
$WG_POLICY        = @(-1978335205, -1978335204, -1978335174, -1978334961, -1978335114)  # MSSTORE(_APP)_BLOCKED, BLOCKED_BY_POLICY, INSTALL_BLOCKED_BY_POLICY, AUTH_INTERACTIVE_REQUIRED
$WG_ADMIN         = @(-1978335207)         # 0x8A150019 COMMAND_REQUIRES_ADMIN
$WG_NETWORK       = @(-1978335224, -1978335163, -1978335157, -1978335123, -1978334969)  # DOWNLOAD_FAILED, SOURCE_OPEN_FAILED, FAILED_TO_OPEN_ALL_SOURCES, SERVICE_UNAVAILABLE, INSTALL_NO_NETWORK
$WG_BUSY          = @(-1978334975, -1978334974, -1978334973)  # INSTALL_PACKAGE_IN_USE, INSTALL_IN_PROGRESS, INSTALL_FILE_IN_USE
$WG_ALREADY       = @(-1978335135, -1978334963)  # PACKAGE_ALREADY_INSTALLED, INSTALL_ALREADY_INSTALLED
$WG_REBOOT_OK     = @(-1978334967, -1978334965)  # REBOOT_REQUIRED_TO_FINISH, REBOOT_INITIATED (operation succeeded)
$WG_NO_UPDATE     = @(-1978335189, -1978335153)  # UPDATE_NOT_APPLICABLE, UPGRADE_VERSION_NOT_NEWER

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}

function Emit-Err([string]$Kind, [string]$Msg, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Msg; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}

function Classify-WG([int]$Code, [bool]$HasVersion) {
  if ($Code -eq $WG_NO_INSTALLER)  { return 'version_not_available' }
  if ($Code -eq $WG_NO_MANIFEST)   { if ($HasVersion) { return 'version_not_available' } else { return 'catalog_error' } }
  if ($Code -in $WG_POLICY)        { return 'blocked_by_policy' }
  if ($Code -in $WG_ADMIN)         { return 'permission_denied' }
  if ($Code -in $WG_NETWORK)       { return 'source_unreachable' }
  if ($Code -eq $WG_NO_APPS)       { return 'catalog_error' }
  if ($Code -in $WG_BUSY)          { return 'resource_in_use' }
  if ($Code -in $WG_ALREADY)       { return 'already_installed' }
  return 'unknown'
}

function Get-WGTail($R) {
  $text  = [string]$R.Output + [Environment]::NewLine + [string]$R.Error
  $lines = @($text -split '\r?\n' | Where-Object { $_ -and $_.Trim() })
  return (($lines | Select-Object -Last 3) -join ' | ')
}

# Emits an error envelope classified from a winget exit code.
function Emit-WGErr([int]$Code, [string]$What, [string]$Tail, [bool]$HasVersion, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $hex = '0x{0:X8}' -f $Code
  $Ctx['exit_code'] = $hex
  $Ctx['output']    = $Tail
  Emit-Err (Classify-WG $Code $HasVersion) ($What + ' (winget exit code ' + $hex + ')') $Ctx
}

# Throws an exception that carries the winget exit code and output tail.
function Throw-WGFailure($R, [string]$What) {
  $ex = New-Object System.Exception($What)
  $ex.Data['ExitCode'] = [int]$R.ExitCode
  $ex.Data['Tail']     = Get-WGTail $R
  throw $ex
}

# Emits an error envelope from a caught error record (winget failure or not).
function Emit-FromCatch($Err, [hashtable]$Ctx, [bool]$HasVersion) {
  $ex = $Err.Exception
  if ($ex.Data.Contains('ExitCode')) {
    Emit-WGErr ([int]$ex.Data['ExitCode']) $ex.Message ([string]$ex.Data['Tail']) $HasVersion $Ctx
  } else {
    Emit-Err 'unknown' $ex.Message $Ctx
  }
}

function Resolve-WingetPath {
  if ($script:WingetPath -and (Test-Path -LiteralPath $script:WingetPath)) { return $script:WingetPath }

  # The "winget" alias is per-user and absent for SYSTEM: use the real executable
  # and sort the version folders numerically (1.10 > 1.9), not alphabetically.
  $pf = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
  $patterns = @(
    ($pf + '\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe'),
    ($pf + '\WindowsApps\Microsoft.DesktopAppInstaller_*_arm64__8wekyb3d8bbwe\winget.exe')
  )
  $found = Get-ChildItem -Path $patterns -ErrorAction SilentlyContinue |
    Sort-Object { try { [version](($_.Directory.Name -split '_')[1]) } catch { [version]'0.0' } } |
    Select-Object -Last 1
  if ($found) { $script:WingetPath = $found.FullName; return $script:WingetPath }

  # Fallback for interactive user sessions where only the alias exists
  $cmd = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
  if ($cmd) { $script:WingetPath = $cmd.Source; return $script:WingetPath }
  return $null
}

function Assert-Winget {
  # Returns $true on success, $false (after Emit-Err) on failure. Since #81
  # this script runs inside a long-lived, reused PowerShell session, where
  # "exit" would kill the session instead of just this call; callers must
  # check the return value and stop rather than fall through.
  if (-not (Resolve-WingetPath)) {
    Emit-Err 'module_missing' 'winget.exe was not found on this host. Install the Microsoft App Installer (Microsoft.DesktopAppInstaller) package.' @{}
    return $false
  }
  return $true
}

# Quotes one argument following the Windows command-line rules
# (CommandLineToArgvW), so values with spaces or embedded quotes survive.
function ConvertTo-WinArg([string]$Arg) {
  if ($Arg -eq '') { return '""' }
  if ($Arg -notmatch '[\s"]') { return $Arg }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  $bs = 0
  foreach ($ch in $Arg.ToCharArray()) {
    if ($ch -eq [char]92) { $bs++; continue }
    if ($ch -eq [char]34) {
      [void]$sb.Append([char]92, ($bs * 2 + 1))
      [void]$sb.Append([char]34)
      $bs = 0
      continue
    }
    if ($bs -gt 0) { [void]$sb.Append([char]92, $bs); $bs = 0 }
    [void]$sb.Append($ch)
  }
  if ($bs -gt 0) { [void]$sb.Append([char]92, ($bs * 2)) }
  [void]$sb.Append('"')
  return $sb.ToString()
}

function Invoke-Winget([string[]]$WgArgs, [int]$TimeoutSec = 120) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName               = $script:WingetPath
  $psi.Arguments              = (($WgArgs | ForEach-Object { ConvertTo-WinArg $_ }) -join ' ')
  $psi.UseShellExecute        = $false
  $psi.CreateNoWindow         = $true
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
  $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8

  $p = [System.Diagnostics.Process]::Start($psi)
  try {
    $p.StandardInput.Close()  # winget must never wait for input
    # Read both streams asynchronously to avoid pipe-buffer deadlocks
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
      try { $p.Kill() } catch { }
      throw ('winget timed out after ' + $TimeoutSec + ' seconds: ' + $psi.Arguments)
    }
    $p.WaitForExit()  # flush the async readers
    return [pscustomobject]@{
      ExitCode = [int]$p.ExitCode
      Output   = [string]$outTask.Result
      Error    = [string]$errTask.Result
    }
  } finally {
    $p.Dispose()
  }
}

# Parses the fixed-width table printed by "winget list". The header is located
# through the dashed separator line and columns are taken by order
# (Name, Id, Version), so the parser does not depend on the OS language.
function ConvertFrom-WGTable([string]$Text) {
  # Progress spinners rewrite a line with carriage returns: keep the last part
  $lines = @($Text -split '\r?\n' | ForEach-Object { ($_ -split '\r')[-1] })
  $sep = -1
  for ($i = 1; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^-{5,}\s*$' -and $lines[$i - 1].Trim() -ne '') { $sep = $i; break }
  }
  if ($sep -lt 0) { return @() }
  $starts = @([regex]::Matches($lines[$sep - 1], '\S+') | ForEach-Object { $_.Index })
  if ($starts.Count -lt 3) { return @() }

  $rows = @()
  for ($i = $sep + 1; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line.Trim() -eq '') { break }
    $cells = @()
    for ($c = 0; $c -lt 3; $c++) {
      $s = $starts[$c]
      $e = if ($c -lt $starts.Count - 1) { $starts[$c + 1] } else { $line.Length }
      if ($s -ge $line.Length) {
        $cells += ''
      } else {
        $cells += $line.Substring($s, [Math]::Min($e - $s, $line.Length - $s)).Trim()
      }
    }
    $rows += [pscustomobject]@{
      Name    = $cells[0]
      Id      = $cells[1]
      Version = ($cells[2] -replace '^[<>~]\s*', '')
    }
  }
  return $rows
}

# Fallback used when the table version is empty or truncated: "winget export"
# produces JSON, which is neither localized nor truncated.
function Get-VersionFromExport([string]$Id, [string]$Src) {
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('winget-export-' + [guid]::NewGuid().ToString('N') + '.json')
  try {
    $null = Invoke-Winget @('export', '--output', $tmp, '--source', $Src, '--include-versions', '--accept-source-agreements', '--disable-interactivity') 300
    if (-not (Test-Path -LiteralPath $tmp)) { return '' }
    $json = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($s in @($json.Sources)) {
      foreach ($pkg in @($s.Packages)) {
        if ([string]$pkg.PackageIdentifier -ieq $Id) { return [string]$pkg.Version }
      }
    }
    return ''
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

# Returns the installed state of one package, or $null when it is not installed.
# Throws (via Throw-WGFailure) on any other winget failure.
function Get-WPState([string]$Id, [string]$Src) {
  $r = Invoke-Winget @('list', '--id', $Id, '--exact', '--source', $Src, '--accept-source-agreements', '--disable-interactivity') 120
  if ($r.ExitCode -eq $WG_NO_APPS) { return $null }
  if ($r.ExitCode -ne 0) { Throw-WGFailure $r ('winget list failed for ' + $Id + ' from ' + $Src) }

  $row = ConvertFrom-WGTable $r.Output | Select-Object -First 1
  $name = ''
  $ver  = ''
  if ($row) { $name = [string]$row.Name; $ver = [string]$row.Version }
  # winget truncates long cells with an ellipsis when its output is redirected
  if ($ver -eq '' -or $ver.Contains([string][char]0x2026)) { $ver = Get-VersionFromExport $Id $Src }

  return [ordered]@{
    package_id        = $Id
    source            = $Src
    installed_version = $ver
    name              = $name
    reboot_required   = $false
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
if (-not (Assert-Winget)) { return }
try {
  # $null (not installed) is emitted as "data": null → drift (EC-3)
  Emit-OK (Get-WPState $wpId $wpSrc)
} catch {
  Emit-FromCatch $_ @{ package_id = $wpId; source = $wpSrc } $false
}
`

const wpInstallBody = `
$wpId  = @@ID@@
$wpSrc = @@SRC@@
$wpVer = @@VER@@
$wpOvr = @@OVERRIDE@@
if (-not (Assert-Winget)) { return }
$ctx = @{ package_id = $wpId; source = $wpSrc }
try {
  # EC-2: pre-flight existence check before install
  $existing = Get-WPState $wpId $wpSrc
  if ($null -ne $existing) {
    $existVer = [string]$existing['installed_version']
    $importId = $wpSrc + ':' + $wpId
    Emit-Err 'already_installed' ('Package ' + $wpId + ' is already installed (version ' + $existVer + ') from source ' + $wpSrc + '. Import with: terraform import windows_winget_package.<name> ' + $importId) @{ installed_version = $existVer }
    return
  }

  $wgArgs = @('install', '--id', $wpId, '--exact', '--source', $wpSrc, '--silent', '--scope', 'machine',
              '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
  if ($wpVer -ne '') { $wgArgs += @('--version', $wpVer) }
  if ($wpOvr -ne '') { $wgArgs += @('--override', $wpOvr) }

  $r = Invoke-Winget $wgArgs 1800
  $reboot = $false
  if ($r.ExitCode -in $WG_REBOOT_OK) {
    $reboot = $true
  } elseif ($r.ExitCode -in $WG_NO_UPDATE) {
    # Race: the package appeared (or reached the requested version) between
    # the EC-2 pre-flight and the install — e.g. winget auto-upgraded an
    # existing install and reports UPDATE_NOT_APPLICABLE. Re-read below.
  } elseif ($r.ExitCode -ne 0) {
    Emit-WGErr $r.ExitCode ('winget install failed for ' + $wpId + ' from ' + $wpSrc) (Get-WGTail $r) ($wpVer -ne '') $ctx
    return
  }

  $state = Get-WPState $wpId $wpSrc
  if ($null -eq $state) {
    $state = [ordered]@{ package_id = $wpId; source = $wpSrc; installed_version = ''; name = ''; reboot_required = $false }
  }
  $state['reboot_required'] = $reboot
  Emit-OK $state
} catch {
  Emit-FromCatch $_ $ctx ($wpVer -ne '')
}
`

const wpUpdateBody = `
$wpId  = @@ID@@
$wpSrc = @@SRC@@
$wpVer = @@VER@@
if (-not (Assert-Winget)) { return }
$ctx = @{ package_id = $wpId; source = $wpSrc }
try {
  $current = Get-WPState $wpId $wpSrc
  if ($null -eq $current) {
    Emit-Err 'unknown' ('Cannot update ' + $wpId + ': package is not currently installed.') $ctx
    return
  }

  $wgArgs = @('upgrade', '--id', $wpId, '--exact', '--source', $wpSrc, '--silent', '--include-unknown',
              '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
  if ($wpVer -ne '') { $wgArgs += @('--version', $wpVer) }

  $r = Invoke-Winget $wgArgs 1800
  $reboot = $false
  if ($r.ExitCode -in $WG_REBOOT_OK) {
    $reboot = $true
  } elseif ($r.ExitCode -in $WG_NO_UPDATE) {
    # Already at the latest / requested version: nothing to do
  } elseif ($r.ExitCode -ne 0) {
    Emit-WGErr $r.ExitCode ('winget upgrade failed for ' + $wpId + ' from ' + $wpSrc) (Get-WGTail $r) ($wpVer -ne '') $ctx
    return
  }

  $state = Get-WPState $wpId $wpSrc
  if ($null -eq $state) {
    $state = [ordered]@{ package_id = $wpId; source = $wpSrc; installed_version = ''; name = ''; reboot_required = $false }
  }
  $state['reboot_required'] = $reboot
  Emit-OK $state
} catch {
  Emit-FromCatch $_ $ctx ($wpVer -ne '')
}
`

const wpUninstallBody = `
$wpId  = @@ID@@
$wpSrc = @@SRC@@
if (-not (Assert-Winget)) { return }
$ctx = @{ package_id = $wpId; source = $wpSrc }
try {
  $r = Invoke-Winget @('uninstall', '--id', $wpId, '--exact', '--source', $wpSrc, '--silent',
                       '--accept-source-agreements', '--disable-interactivity') 1800
  $reboot = $false
  if ($r.ExitCode -eq $WG_NO_APPS) {
    # Nothing matched: the package is not installed. Absent is the desired
    # state for Delete, so report success for idempotency (EC-3).
  } elseif ($r.ExitCode -in $WG_REBOOT_OK) {
    $reboot = $true
  } elseif ($r.ExitCode -ne 0) {
    Emit-WGErr $r.ExitCode ('winget uninstall failed for ' + $wpId + ' from ' + $wpSrc) (Get-WGTail $r) $false $ctx
    return
  }
  Emit-OK ([ordered]@{ package_id = $wpId; source = $wpSrc; installed_version = ''; name = ''; reboot_required = $reboot })
} catch {
  Emit-FromCatch $_ $ctx $false
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

// runWPEnvelope executes a winget script (prefixed with wpHeader) over SSH
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
			fmt.Sprintf("SSH transport error during %q", op),
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

		// EC-10: winget transaction in progress — retry with exponential back-off
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

// Install adds a new package via "winget install". The PowerShell script
// includes EC-1 (winget pre-flight) and EC-2 (existence pre-flight). Always
// uses --silent, --scope machine, and auto-accepts agreements.
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

// Read retrieves the current installed state via "winget list --exact".
// Returns (nil, nil) when the package is not installed (EC-3 drift handling —
// caller must call resp.State.RemoveResource).
func (w *WingetPackageClientImpl) Read(ctx context.Context, packageID, source string) (*WingetPackageState, error) {
	script := wpReplace(wpReadBody, packageID, source, "", "")
	resp, err := w.runWPEnvelope(ctx, "Read", packageID, script)
	if err != nil {
		return nil, err
	}
	return parseWPState(resp)
}

// Update applies a version change via "winget upgrade". When input.Version
// is "" (cleared to null in config), the command is run without --version to
// advance to the latest release.
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

// Uninstall removes the package via "winget uninstall". The NO_APPLICATIONS_FOUND
// exit code (nothing installed under the given id) is treated as success for
// idempotency (EC-3). Reboot exit codes are propagated via
// WingetPackageState.RebootRequired = true with nil error (EC-6).
func (w *WingetPackageClientImpl) Uninstall(ctx context.Context, packageID, source string) (*WingetPackageState, error) {
	script := wpReplace(wpUninstallBody, packageID, source, "", "")
	resp, err := w.runRetryable(ctx, "Uninstall", packageID, script)
	if err != nil {
		return nil, err
	}
	return parseWPState(resp)
}
