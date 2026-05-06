// LegacyPackageClient PowerShell/WinRM-backed implementation.
//
// Implements LegacyPackageClient by executing PowerShell scripts over WinRM.
// The full input payload is forwarded to the script via stdin as JSON
// (Client.RunPowerShellWithInput) so that complex fields (lists, maps) are
// transferred without any PowerShell quoting concern. Every script emits a
// single JSON envelope through Emit-OK / Emit-Err so stdout is locale
// independent and machine-parseable.
//
// Spec alignment: windows_legacy_package spec v1 (2026-05-05).
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// LegacyPackageInput — desired configuration consumed by Create / Update
// ---------------------------------------------------------------------------

// LegacyPackageInput carries the user-provided configuration for a legacy
// package operation. Empty / zero values mean "unset" (use spec defaults).
//
// JSON tags match the lower_snake keys used by the PowerShell payloads
// emitted via ConvertTo-Json on the target host.
type LegacyPackageInput struct {
	// Name is the logical Terraform identifier and display label.
	Name string `json:"name"`

	// InstallerType selects the engine: "msi" (msiexec) or "exe" (Start-Process).
	InstallerType string `json:"installer_type"`

	// SourcePath is the local Windows path to the installer. Mutually
	// exclusive with SourceURL.
	SourcePath string `json:"source_path,omitempty"`

	// SourceURL is the http(s) URL the installer is downloaded from on the
	// target host. Mutually exclusive with SourcePath.
	SourceURL string `json:"source_url,omitempty"`

	// Checksum is the expected installer hash, format "<algo>:<hex>".
	Checksum string `json:"checksum,omitempty"`

	// InsecureSkipVerify disables TLS certificate validation for SourceURL.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// ProductID is the MSI ProductCode GUID. Auto-extracted from the MSI
	// when empty (MSI only).
	ProductID string `json:"product_id,omitempty"`

	// DisplayNamePattern locates EXE installs in the Uninstall registry
	// hives by DisplayName. Required for EXE when UninstallCommand is empty.
	DisplayNamePattern string `json:"display_name_pattern,omitempty"`

	// InstallArgs are extra arguments passed to the installer.
	InstallArgs []string `json:"install_args,omitempty"`

	// UninstallArgs are extra arguments passed at uninstall time.
	UninstallArgs []string `json:"uninstall_args,omitempty"`

	// UninstallCommand overrides the registry UninstallString for EXE.
	UninstallCommand string `json:"uninstall_command,omitempty"`

	// ValidExitCodes are the exit codes treated as success. Default [0, 3010].
	ValidExitCodes []int64 `json:"valid_exit_codes,omitempty"`

	// WorkingDirectory is the CWD for the installer process.
	WorkingDirectory string `json:"working_directory,omitempty"`

	// TimeoutSeconds bounds the install/uninstall execution. Default 1800.
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`

	// LogPath is the path to the MSI /l*v log or EXE stdout/stderr capture.
	LogPath string `json:"log_path,omitempty"`

	// Environment holds extra env vars injected into the installer process.
	// Sensitive: may carry license keys or proxy credentials.
	Environment map[string]string `json:"environment,omitempty"`
}

// ---------------------------------------------------------------------------
// LegacyPackageState — observed state returned by Read / Create / Update
// ---------------------------------------------------------------------------

// LegacyPackageState is the snapshot of the package as observed on the
// target host. JSON tags mirror the PowerShell ConvertTo-Json output
// produced by the read pipeline against the Uninstall registry hives.
type LegacyPackageState struct {
	// ID is the Terraform identifier: ProductCode GUID for MSI, exact
	// resolved DisplayName for EXE.
	ID string `json:"id"`

	// ProductID is the MSI ProductCode GUID (empty for EXE).
	ProductID string `json:"product_id,omitempty"`

	// LogPath is the resolved log path (auto-generated when not user-set).
	LogPath string `json:"log_path,omitempty"`

	// InstalledVersion is the DisplayVersion read from the registry.
	InstalledVersion string `json:"installed_version,omitempty"`

	// Installed reports whether the package is currently detected.
	Installed bool `json:"installed"`

	// InstallDate is the registry InstallDate, normalized to ISO-8601 when
	// parseable.
	InstallDate string `json:"install_date,omitempty"`
}

// ---------------------------------------------------------------------------
// LegacyPackageClient — CRUD contract
// ---------------------------------------------------------------------------

// LegacyPackageClient is the contract used by the resource layer to manage
// legacy Windows installers via PowerShell over WinRM.
//
// Implementations MUST:
//
//   - Treat MSI exit code 3010 as success (reboot pending) by default.
//   - Search both the 64-bit and Wow6432Node Uninstall hives at Read time.
//   - Return (nil, nil) from Read when the package is no longer detected so
//     the resource layer can flag drift and schedule re-create.
//   - Validate Checksum BEFORE executing the installer.
//   - Kill the entire process tree on TimeoutSeconds expiry, not just the
//     parent process.
type LegacyPackageClient interface {
	// Create runs the installer end-to-end: source resolution, checksum
	// verification, exec, and state read-back.
	Create(ctx context.Context, in LegacyPackageInput) (*LegacyPackageState, error)

	// Read refreshes the observed state from the Uninstall registry hives.
	// Returns (nil, nil) when the package is no longer present.
	Read(ctx context.Context, id string) (*LegacyPackageState, error)

	// Update applies in-place mutations (valid_exit_codes, timeout_seconds,
	// log_path, environment). All other changes are ForceNew at the
	// resource layer and never reach this method.
	Update(ctx context.Context, id string, in LegacyPackageInput) (*LegacyPackageState, error)

	// Delete uninstalls the package. MSI uses msiexec /x; EXE prefers
	// UninstallCommand and falls back to the parsed registry UninstallString.
	Delete(ctx context.Context, id string) error
}

// Compile-time assertion: LegacyPackageClientImpl satisfies LegacyPackageClient.
var _ LegacyPackageClient = (*LegacyPackageClientImpl)(nil)

// LegacyPackageError is the structured error type returned by every
// LegacyPackageClient method on a non-transport failure (Emit-Err on the
// PowerShell side or a Go-side parse error). It mirrors the shape of
// ServiceError / WingetPackageError used by the rest of the package.
type LegacyPackageError struct {
	// Kind is the machine-readable error category (matches the PS-side `kind`).
	Kind string
	// Message is the human-readable description.
	Message string
	// Context carries structured key/value diagnostic data.
	Context map[string]string
	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *LegacyPackageError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_legacy_package [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_legacy_package [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *LegacyPackageError) Unwrap() error { return e.Cause }

// IsLegacyPackageError reports whether err is a *LegacyPackageError with the
// given kind.
func IsLegacyPackageError(err error, kind string) bool {
	var e *LegacyPackageError
	if errors.As(err, &e) {
		return e.Kind == kind
	}
	return false
}

// LegacyPackageClientImpl is the concrete LegacyPackageClient.
type LegacyPackageClientImpl struct {
	c *Client
}

// NewLegacyPackageClient constructs a LegacyPackageClientImpl wrapping the
// given WinRM Client.
func NewLegacyPackageClient(c *Client) *LegacyPackageClientImpl {
	return &LegacyPackageClientImpl{c: c}
}

// readPayload is the stdin JSON payload consumed by the read script.
type readPayload struct {
	ID string `json:"id"`
}

// deletePayload is the stdin JSON payload consumed by the delete script.
type deletePayload struct {
	ID               string   `json:"id"`
	UninstallCommand string   `json:"uninstall_command,omitempty"`
	UninstallArgs    []string `json:"uninstall_args,omitempty"`
	ValidExitCodes   []int64  `json:"valid_exit_codes,omitempty"`
	TimeoutSeconds   int64    `json:"timeout_seconds,omitempty"`
}

// runEnvelope executes script over WinRM with stdin piped from payload (JSON
// encoded) and decodes the JSON envelope written to stdout by Emit-OK /
// Emit-Err. Transport errors are wrapped as LegacyPackageError{Kind:"unknown"}.
func (l *LegacyPackageClientImpl) runEnvelope(ctx context.Context, op string, payload any, script string) (*psResponse, error) {
	stdin, err := json.Marshal(payload)
	if err != nil {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: "marshal payload", Cause: err,
			Context: map[string]string{"operation": op},
		}
	}
	full := lpHeader + "\n" + script
	// Route through the package-level runPSInput seam (also used by local_user.go)
	// so unit tests can stub the WinRM transport without a real host.
	stdout, stderr, err := runPSInput(ctx, l.c, full, string(stdin))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &LegacyPackageError{
				Kind: "timeout", Message: fmt.Sprintf("operation %q cancelled or timed out", op),
				Cause: ctxErr,
				Context: map[string]string{
					"operation": op,
					"host":      l.c.cfg.Host,
				},
			}
		}
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: fmt.Sprintf("WinRM transport error during %q", op),
			Cause: err,
			Context: map[string]string{
				"operation": op,
				"host":      l.c.cfg.Host,
				"stderr":    truncate(stderr, 2048),
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: fmt.Sprintf("no JSON envelope returned from %q", op),
			Context: map[string]string{
				"operation": op,
				"host":      l.c.cfg.Host,
				"stderr":    truncate(stderr, 2048),
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: fmt.Sprintf("invalid JSON envelope from %q", op),
			Cause: jerr,
			Context: map[string]string{
				"operation": op,
				"host":      l.c.cfg.Host,
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	if !resp.OK {
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["host"] = l.c.cfg.Host
		return &resp, &LegacyPackageError{
			Kind: resp.Kind, Message: resp.Message, Context: ctxMap,
		}
	}
	return &resp, nil
}

// parseLPState decodes the Data field of resp into a *LegacyPackageState.
// Returns (nil, nil) when resp.Data is JSON null (package absent).
func parseLPState(resp *psResponse) (*LegacyPackageState, error) {
	if resp.Data == nil || string(resp.Data) == "null" {
		return nil, nil
	}
	var st LegacyPackageState
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: "failed to parse legacy package state JSON", Cause: err,
		}
	}
	return &st, nil
}

// ---------------------------------------------------------------------------
// LegacyPackageClient interface implementation
// ---------------------------------------------------------------------------

// Create runs the installer end-to-end: source resolution, checksum
// verification, exec, exit-code validation, and state read-back.
func (l *LegacyPackageClientImpl) Create(ctx context.Context, in LegacyPackageInput) (*LegacyPackageState, error) {
	resp, err := l.runEnvelope(ctx, "Create", in, lpCreateBody)
	if err != nil {
		return nil, err
	}
	return parseLPState(resp)
}

// Read refreshes the observed state from the Uninstall registry hives.
// Returns (nil, nil) when the package is no longer present so the resource
// layer can flag drift and schedule re-create.
func (l *LegacyPackageClientImpl) Read(ctx context.Context, id string) (*LegacyPackageState, error) {
	resp, err := l.runEnvelope(ctx, "Read", readPayload{ID: id}, lpReadBody)
	if err != nil {
		return nil, err
	}
	return parseLPState(resp)
}

// Update is a no-op on the Windows host: only state-level fields
// (valid_exit_codes, timeout_seconds, log_path, environment) are updatable
// in place and they affect future invocations only. The current observed
// state is refreshed via Read.
func (l *LegacyPackageClientImpl) Update(ctx context.Context, id string, _ LegacyPackageInput) (*LegacyPackageState, error) {
	return l.Read(ctx, id)
}

// Delete uninstalls the package. MSI uses msiexec /x; EXE prefers
// UninstallCommand and falls back to the parsed registry UninstallString
// (QuietUninstallString preferred).
func (l *LegacyPackageClientImpl) Delete(ctx context.Context, id string) error {
	_, err := l.runEnvelope(ctx, "Delete", deletePayload{ID: id}, lpDeleteBody)
	return err
}

// ---------------------------------------------------------------------------
// PowerShell scripts
//
// All scripts read their input payload from stdin as JSON
// (Client.RunPowerShellWithInput) and emit a single JSON envelope to stdout
// via Emit-OK / Emit-Err. They are designed to be locale-independent and
// safe to run repeatedly.
// ---------------------------------------------------------------------------

// lpHeader is prepended to every legacy package script. It defines:
//
//   - Emit-OK / Emit-Err  : JSON envelope emitters.
//   - Read-LpInput        : reads stdin once and returns a parsed PSObject.
//   - Get-LpUninstallEntry: scans the 64-bit and Wow6432Node Uninstall hives
//     and returns matching entries by ProductCode (MSI) or DisplayName /
//     pattern (EXE).
//   - To-LpIsoDate        : normalises registry InstallDate (YYYYMMDD) to
//     ISO-8601 (YYYY-MM-DD); pass-through for unknown formats.
//   - Invoke-LpProcess    : runs an executable with a hard timeout, killing
//     the entire process tree on expiry.
const lpHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 10 -Compress))
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 10 -Compress))
}

function Read-LpInput {
  $raw = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw)) { return [pscustomobject]@{} }
  return ($raw | ConvertFrom-Json)
}

function Get-LpUninstallEntry {
  param(
    [string]$Id,
    [string]$Type,
    [string]$Pattern
  )
  $hives = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  $found = New-Object System.Collections.ArrayList
  foreach ($h in $hives) {
    if (-not (Test-Path $h)) { continue }
    Get-ChildItem -Path $h -ErrorAction SilentlyContinue | ForEach-Object {
      $key = $_.PSChildName
      $p   = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
      if (-not $p) { return }
      if ($Type -eq 'msi') {
        if ($Id -and ($key -ieq $Id)) { [void]$found.Add($p) }
      } else {
        $dn = [string]$p.DisplayName
        if ([string]::IsNullOrEmpty($dn)) { return }
        if ($Id -and ($dn -ceq $Id)) {
          [void]$found.Add($p)
        } elseif ($Pattern) {
          $matched = $false
          try { if ($dn -like $Pattern) { $matched = $true } } catch {}
          if (-not $matched) {
            try { if ($dn -match $Pattern) { $matched = $true } } catch {}
          }
          if ($matched) { [void]$found.Add($p) }
        }
      }
    }
  }
  return ,$found.ToArray()
}

function To-LpIsoDate([string]$s) {
  if ([string]::IsNullOrEmpty($s)) { return '' }
  if ($s -match '^(\d{4})(\d{2})(\d{2})$') {
    return ('{0}-{1}-{2}' -f $Matches[1], $Matches[2], $Matches[3])
  }
  return $s
}

function Invoke-LpProcess {
  param(
    [string]$FilePath,
    [string[]]$ArgumentList,
    [string]$WorkingDirectory,
    [int]$TimeoutSeconds,
    [string]$RedirectOut,
    [string]$RedirectErr
  )
  $sp = @{
    FilePath    = $FilePath
    PassThru    = $true
    WindowStyle = 'Hidden'
  }
  if ($ArgumentList -and $ArgumentList.Count -gt 0) { $sp['ArgumentList'] = $ArgumentList }
  if ($WorkingDirectory) { $sp['WorkingDirectory'] = $WorkingDirectory }
  if ($RedirectOut) { $sp['RedirectStandardOutput'] = $RedirectOut }
  if ($RedirectErr) { $sp['RedirectStandardError']  = $RedirectErr }

  $proc = Start-Process @sp
  $ms = $TimeoutSeconds * 1000
  if (-not $proc.WaitForExit($ms)) {
    try { & taskkill.exe /T /F /PID $proc.Id 2>$null | Out-Null } catch {}
    return [pscustomobject]@{ TimedOut = $true; ExitCode = -1; Pid = $proc.Id }
  }
  return [pscustomobject]@{ TimedOut = $false; ExitCode = $proc.ExitCode; Pid = $proc.Id }
}
`

// lpCreateBody runs the full install pipeline:
//  1. Resolve the installer (download via Invoke-WebRequest if source_url).
//  2. Verify the checksum (Get-FileHash).
//  3. For MSI: extract the ProductCode via WindowsInstaller.Installer COM
//     and reject if it conflicts with a user-supplied product_id.
//  4. Build the argument list and execute under a timeout.
//  5. Validate the exit code against valid_exit_codes (default [0,3010]).
//  6. Read back the state from the Uninstall registry hives.
const lpCreateBody = `
$cfg = Read-LpInput
$installerType = [string]$cfg.installer_type
if ($installerType -ne 'msi' -and $installerType -ne 'exe') {
  Emit-Err 'invalid_parameter' ("installer_type must be 'msi' or 'exe', got: " + $installerType) @{}
  exit 0
}
if ($installerType -eq 'exe' -and -not $cfg.display_name_pattern -and -not $cfg.uninstall_command) {
  Emit-Err 'invalid_parameter' "installer_type=exe requires display_name_pattern or uninstall_command" @{}
  exit 0
}

# 1) Resolve installer file
$installerPath = ''
$downloaded = $false
if ($cfg.source_path) {
  $installerPath = [string]$cfg.source_path
  if (-not (Test-Path -LiteralPath $installerPath)) {
    Emit-Err 'source_not_found' ("source_path does not exist: " + $installerPath) @{ source_path = $installerPath }
    exit 0
  }
} elseif ($cfg.source_url) {
  $tmpDir = Join-Path $env:TEMP 'windows_legacy_package'
  New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
  try { $fname = [System.IO.Path]::GetFileName(([Uri]([string]$cfg.source_url)).AbsolutePath) } catch { $fname = '' }
  if ([string]::IsNullOrEmpty($fname)) { $fname = 'installer_' + [guid]::NewGuid().ToString() + '.bin' }
  $installerPath = Join-Path $tmpDir $fname
  $downloaded = $true
  $prevCB = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
  if ([bool]$cfg.insecure_skip_verify) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  }
  try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
    Invoke-WebRequest -Uri ([string]$cfg.source_url) -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
  } catch {
    Emit-Err 'download_failed' ("download error: " + $_.Exception.Message) @{ url = [string]$cfg.source_url }
    exit 0
  } finally {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCB
  }
} else {
  Emit-Err 'invalid_parameter' "either source_path or source_url is required" @{}
  exit 0
}

# 2) Checksum verification
if ($cfg.checksum) {
  $parts = ([string]$cfg.checksum).Split(':', 2)
  if ($parts.Count -ne 2) {
    Emit-Err 'invalid_parameter' "checksum must be '<algo>:<hex>'" @{ checksum = [string]$cfg.checksum }
    exit 0
  }
  $algo = $parts[0].ToUpperInvariant()
  $expected = $parts[1].ToLowerInvariant()
  try {
    $got = (Get-FileHash -LiteralPath $installerPath -Algorithm $algo -ErrorAction Stop).Hash.ToLowerInvariant()
  } catch {
    Emit-Err 'checksum_failed' ("hash compute error: " + $_.Exception.Message) @{ algo = $algo }
    exit 0
  }
  if ($got -ne $expected) {
    Emit-Err 'checksum_mismatch' ("checksum mismatch (algo=" + $algo + " expected=" + $expected + " got=" + $got + ")") @{ algo = $algo; expected = $expected; got = $got; path = $installerPath }
    exit 0
  }
}

# 3) MSI ProductCode extraction
$productId = [string]$cfg.product_id
if ($installerType -eq 'msi') {
  $extracted = ''
  try {
    $msiInst = New-Object -ComObject WindowsInstaller.Installer
    $db = $msiInst.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $msiInst, @($installerPath, 0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property='ProductCode'"))
    [void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    if ($rec) {
      $extracted = [string]$rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @(1))
    }
    [void]$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) | Out-Null
    [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($msiInst) | Out-Null
  } catch {
    Emit-Err 'msi_inspect_failed' ("failed to read MSI ProductCode: " + $_.Exception.Message) @{ path = $installerPath }
    exit 0
  }
  if ([string]::IsNullOrEmpty($extracted)) {
    Emit-Err 'msi_no_product_code' "MSI does not expose a ProductCode property" @{ path = $installerPath }
    exit 0
  }
  if ($productId -and ($productId -ne $extracted)) {
    Emit-Err 'product_id_mismatch' ("configured product_id (" + $productId + ") does not match MSI ProductCode (" + $extracted + ")") @{ configured = $productId; actual = $extracted }
    exit 0
  }
  $productId = $extracted
}

# 4) Log path resolution
$logDir = Join-Path $env:TEMP 'windows_legacy_package'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = [string]$cfg.log_path
if ([string]::IsNullOrEmpty($logPath)) {
  $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
  $safeName = (([string]$cfg.name) -replace '[^A-Za-z0-9._-]', '_')
  $logPath = Join-Path $logDir ($safeName + '_install_' + $stamp + '.log')
}

# 5) Build argument list
$extraInstall = @()
if ($cfg.install_args) { $extraInstall = @([string[]]$cfg.install_args) }

$argList = @()
if ($installerType -eq 'msi') {
  $argList += '/i'
  $argList += ('"' + $installerPath + '"')
  $argList += '/qn'
  $argList += '/norestart'
  $argList += '/l*v'
  $argList += ('"' + $logPath + '"')
  if ($extraInstall.Count -gt 0) { $argList += $extraInstall }
  $exe = 'msiexec.exe'
  $redirOut = $null
  $redirErr = $null
} else {
  if ($extraInstall.Count -gt 0) { $argList += $extraInstall }
  $exe = $installerPath
  $redirOut = $logPath + '.out'
  $redirErr = $logPath + '.err'
}

# Working directory
$cwd = [string]$cfg.working_directory
if ([string]::IsNullOrEmpty($cwd)) { $cwd = Split-Path -Parent $installerPath }

# valid exit codes
$valid = @(0, 3010)
if ($cfg.valid_exit_codes -and (@($cfg.valid_exit_codes)).Count -gt 0) {
  $valid = @($cfg.valid_exit_codes | ForEach-Object { [int]$_ })
}

# Timeout
$timeout = 1800
if ($cfg.timeout_seconds -and [int]$cfg.timeout_seconds -gt 0) { $timeout = [int]$cfg.timeout_seconds }

# Environment overrides (process scope; restored after exec)
$envSnapshot = @{}
if ($cfg.environment) {
  foreach ($prop in $cfg.environment.PSObject.Properties) {
    $envSnapshot[$prop.Name] = [Environment]::GetEnvironmentVariable($prop.Name, 'Process')
    [Environment]::SetEnvironmentVariable($prop.Name, [string]$prop.Value, 'Process')
  }
}

# 6) Execute
try {
  $r = Invoke-LpProcess -FilePath $exe -ArgumentList $argList -WorkingDirectory $cwd -TimeoutSeconds $timeout -RedirectOut $redirOut -RedirectErr $redirErr
} catch {
  foreach ($k in $envSnapshot.Keys) { [Environment]::SetEnvironmentVariable($k, $envSnapshot[$k], 'Process') }
  Emit-Err 'exec_failed' ("installer exec failed: " + $_.Exception.Message) @{ exe = $exe; log_path = $logPath }
  exit 0
}

foreach ($k in $envSnapshot.Keys) { [Environment]::SetEnvironmentVariable($k, $envSnapshot[$k], 'Process') }

# Merge EXE redirected streams into the single log file
if ($installerType -eq 'exe') {
  try {
    $sb = New-Object System.Text.StringBuilder
    if (Test-Path -LiteralPath ($logPath + '.out')) {
      [void]$sb.AppendLine('--- stdout ---')
      [void]$sb.AppendLine((Get-Content -LiteralPath ($logPath + '.out') -Raw -ErrorAction SilentlyContinue))
    }
    if (Test-Path -LiteralPath ($logPath + '.err')) {
      [void]$sb.AppendLine('--- stderr ---')
      [void]$sb.AppendLine((Get-Content -LiteralPath ($logPath + '.err') -Raw -ErrorAction SilentlyContinue))
    }
    Set-Content -LiteralPath $logPath -Value $sb.ToString() -Encoding UTF8 -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($logPath + '.out') -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($logPath + '.err') -Force -ErrorAction SilentlyContinue
  } catch {}
}

if ($r.TimedOut) {
  Emit-Err 'timeout' ("installer timed out after " + $timeout + " seconds") @{ pid = [string]$r.Pid; log_path = $logPath }
  exit 0
}
$exitCode = [int]$r.ExitCode
if ($valid -notcontains $exitCode) {
  $kind = 'exit_code_invalid'
  if ($exitCode -eq 1618) { $kind = 'msi_in_progress' }
  Emit-Err $kind ("installer exited with code " + $exitCode + " (valid: " + ($valid -join ',') + ")") @{ exit_code = [string]$exitCode; log_path = $logPath }
  exit 0
}

# 7) Cleanup downloaded source on success
if ($downloaded -and (Test-Path -LiteralPath $installerPath)) {
  Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue
}

# 8) Read state from Uninstall hives
$searchId = ''
$searchPattern = ''
if ($installerType -eq 'msi') { $searchId = $productId } else { $searchPattern = [string]$cfg.display_name_pattern }
$entries = @(Get-LpUninstallEntry -Id $searchId -Type $installerType -Pattern $searchPattern)

if ($entries.Count -eq 0) {
  # Installer reported success but the entry is not detectable. Surface a
  # minimal state so Terraform records the resource and a subsequent Read
  # can flag drift if needed.
  $idOut = if ($installerType -eq 'msi') { $productId } else { [string]$cfg.name }
  Emit-OK ([ordered]@{
    id                = $idOut
    product_id        = $productId
    log_path          = $logPath
    installed_version = ''
    installed         = $false
    install_date      = ''
  })
  exit 0
}
if ($installerType -eq 'exe' -and $entries.Count -gt 1) {
  $names = ($entries | ForEach-Object { [string]$_.DisplayName }) -join '; '
  Emit-Err 'multiple_matches' ("display_name_pattern matches multiple installed entries: " + $names) @{ matches = $names }
  exit 0
}

$e = $entries[0]
$dn = [string]$e.DisplayName
$idOut = if ($installerType -eq 'msi') { $productId } else { $dn }
Emit-OK ([ordered]@{
  id                = $idOut
  product_id        = $productId
  log_path          = $logPath
  installed_version = [string]$e.DisplayVersion
  installed         = $true
  install_date      = (To-LpIsoDate ([string]$e.InstallDate))
})
`

// lpReadBody scans the Uninstall hives for the supplied id. The id format
// determines the lookup mode: a GUID-in-braces is treated as an MSI
// ProductCode (matched against the registry sub-key name); anything else is
// matched verbatim (case-sensitive) against DisplayName for EXE.
const lpReadBody = `
$cfg = Read-LpInput
$id = [string]$cfg.id
if ([string]::IsNullOrEmpty($id)) {
  Emit-Err 'invalid_parameter' "id is required" @{}
  exit 0
}
$isMsi = $id -match '^\{[0-9A-Fa-f-]{36}\}$'
$type = if ($isMsi) { 'msi' } else { 'exe' }
$entries = @(Get-LpUninstallEntry -Id $id -Type $type -Pattern '')
if ($entries.Count -eq 0) {
  Emit-OK $null
  exit 0
}
$e = $entries[0]
$pidOut = if ($isMsi) { $id } else { '' }
$dn = [string]$e.DisplayName
Emit-OK ([ordered]@{
  id                = if ($isMsi) { $id } else { $dn }
  product_id        = $pidOut
  log_path          = ''
  installed_version = [string]$e.DisplayVersion
  installed         = $true
  install_date      = (To-LpIsoDate ([string]$e.InstallDate))
})
`

// lpDeleteBody uninstalls the package keyed by id.
//
// MSI path: msiexec /x <ProductCode> /qn /norestart [+ uninstall_args].
// EXE path: prefer the user-supplied uninstall_command; otherwise parse
//
//	QuietUninstallString / UninstallString from the matched key,
//	splitting executable and inline arguments on the first quoted
//	token boundary, then append uninstall_args.
const lpDeleteBody = `
$cfg = Read-LpInput
$id = [string]$cfg.id
if ([string]::IsNullOrEmpty($id)) {
  Emit-Err 'invalid_parameter' "id is required" @{}
  exit 0
}
$isMsi = $id -match '^\{[0-9A-Fa-f-]{36}\}$'

$timeout = 1800
if ($cfg.timeout_seconds -and [int]$cfg.timeout_seconds -gt 0) { $timeout = [int]$cfg.timeout_seconds }
$valid = @(0, 3010)
if ($cfg.valid_exit_codes -and (@($cfg.valid_exit_codes)).Count -gt 0) {
  $valid = @($cfg.valid_exit_codes | ForEach-Object { [int]$_ })
}
$extraUninstall = @()
if ($cfg.uninstall_args) { $extraUninstall = @([string[]]$cfg.uninstall_args) }

if ($isMsi) {
  $entries = @(Get-LpUninstallEntry -Id $id -Type 'msi' -Pattern '')
  if ($entries.Count -eq 0) { Emit-OK $null; exit 0 }
  $logDir = Join-Path $env:TEMP 'windows_legacy_package'
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
  $logPath = Join-Path $logDir ("uninstall_" + $stamp + ".log")
  $argList = @('/x', $id, '/qn', '/norestart', '/l*v', ('"' + $logPath + '"'))
  if ($extraUninstall.Count -gt 0) { $argList += $extraUninstall }
  try {
    $r = Invoke-LpProcess -FilePath 'msiexec.exe' -ArgumentList $argList -WorkingDirectory $env:TEMP -TimeoutSeconds $timeout
  } catch {
    Emit-Err 'exec_failed' ("msiexec exec failed: " + $_.Exception.Message) @{}
    exit 0
  }
  if ($r.TimedOut) {
    Emit-Err 'timeout' ("uninstall timed out after " + $timeout + " seconds") @{ pid = [string]$r.Pid; log_path = $logPath }
    exit 0
  }
  $exitCode = [int]$r.ExitCode
  if ($valid -notcontains $exitCode) {
    $kind = 'exit_code_invalid'
    if ($exitCode -eq 1618) { $kind = 'msi_in_progress' }
    Emit-Err $kind ("msiexec exited with code " + $exitCode + " (valid: " + ($valid -join ',') + ")") @{ exit_code = [string]$exitCode; log_path = $logPath }
    exit 0
  }
  Emit-OK $null
  exit 0
}

# EXE branch
$entries = @(Get-LpUninstallEntry -Id $id -Type 'exe' -Pattern '')
if ($entries.Count -eq 0) { Emit-OK $null; exit 0 }
$e = $entries[0]
$cmd = [string]$cfg.uninstall_command
if ([string]::IsNullOrEmpty($cmd)) {
  $cmd = [string]$e.QuietUninstallString
  if ([string]::IsNullOrEmpty($cmd)) { $cmd = [string]$e.UninstallString }
}
if ([string]::IsNullOrEmpty($cmd)) {
  Emit-Err 'no_uninstall_string' "matched entry has no UninstallString and no uninstall_command was provided" @{ display_name = [string]$e.DisplayName }
  exit 0
}

$exePart = ''
$argPart = ''
$cmd = $cmd.Trim()
if ($cmd.StartsWith('"')) {
  $endIdx = $cmd.IndexOf('"', 1)
  if ($endIdx -gt 0) {
    $exePart = $cmd.Substring(1, $endIdx - 1)
    if ($endIdx + 1 -lt $cmd.Length) { $argPart = $cmd.Substring($endIdx + 1).Trim() }
  } else {
    Emit-Err 'invalid_parameter' ("unterminated quoted UninstallString: " + $cmd) @{}
    exit 0
  }
} else {
  $sp = $cmd.IndexOf(' ')
  if ($sp -lt 0) {
    $exePart = $cmd
  } else {
    $exePart = $cmd.Substring(0, $sp)
    $argPart = $cmd.Substring($sp + 1).Trim()
  }
}

$argList = @()
if (-not [string]::IsNullOrEmpty($argPart)) { $argList += $argPart }
if ($extraUninstall.Count -gt 0) { $argList += $extraUninstall }

try {
  $r = Invoke-LpProcess -FilePath $exePart -ArgumentList $argList -TimeoutSeconds $timeout
} catch {
  Emit-Err 'exec_failed' ("uninstaller exec failed: " + $_.Exception.Message) @{ exe = $exePart }
  exit 0
}
if ($r.TimedOut) {
  Emit-Err 'timeout' ("uninstall timed out after " + $timeout + " seconds") @{ pid = [string]$r.Pid }
  exit 0
}
$exitCode = [int]$r.ExitCode
if ($valid -notcontains $exitCode) {
  Emit-Err 'exit_code_invalid' ("uninstaller exited with code " + $exitCode + " (valid: " + ($valid -join ',') + ")") @{ exit_code = [string]$exitCode }
  exit 0
}
Emit-OK $null
`
