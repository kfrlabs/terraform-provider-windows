// Package winclient: Windows feature CRUD over WinRM.
//
// This file provides FeatureClient, the concrete WindowsFeatureClient used by
// the windows_feature Terraform resource. All operations execute PowerShell
// scripts wrapped in a JSON envelope (Emit-OK/Emit-Err) so stdout is
// machine-parseable regardless of Windows locale.
//
// Security invariants:
//   - feature name and source path are interpolated only through psQuote
//     (single-quoted PS literal) so $var / backtick / subexpression injection
//     is impossible.
//   - All scripts are sent via -EncodedCommand by Client.RunPowerShell.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: FeatureClient satisfies WindowsFeatureClient.
var _ WindowsFeatureClient = (*FeatureClient)(nil)

// FeatureClient is the PowerShell/WinRM-backed WindowsFeatureClient.
type FeatureClient struct {
	c *Client
}

// NewFeatureClient constructs a FeatureClient wrapping the given WinRM Client.
func NewFeatureClient(c *Client) *FeatureClient { return &FeatureClient{c: c} }

// psFeatureHeader prepends Emit-OK/Emit-Err and Classify-Feature.
//
// Classify-Feature maps common Install-WindowsFeature/Get-WindowsFeature error
// substrings to FeatureErrorKind values. Detection is best-effort and
// substring-based because Windows error messages are localised; callers should
// fall back to FeatureErrorUnknown when the kind is empty.
const psFeatureHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Classify-Feature([string]$Msg) {
  if ($Msg -match 'Access is denied' -or $Msg -match 'AccessDenied' -or $Msg -match 'not authorized') { return 'permission_denied' }
  if ($Msg -match 'source files could not be found' -or $Msg -match 'specify an alternate source' -or $Msg -match 'Source could not be found') { return 'source_missing' }
  if ($Msg -match 'depends on' -or $Msg -match 'parent feature' -or $Msg -match 'required feature') { return 'dependency_missing' }
  if ($Msg -match 'is not recognized' -or $Msg -match 'CommandNotFoundException' -or $Msg -match 'ServerManager') { return 'unsupported_sku' }
  if ($Msg -match 'No match was found' -or $Msg -match 'is not valid on this system' -or $Msg -match 'No feature') { return 'not_found' }
  if ($Msg -match 'parameter' -and $Msg -match 'invalid') { return 'invalid_parameter' }
  return 'unknown'
}

function Test-PendingReboot {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
  )
  if (Test-Path $paths[0]) { return $true }
  if (Test-Path $paths[1]) { return $true }
  try {
    $sm = Get-ItemProperty -Path $paths[2] -ErrorAction Stop
    if ($sm.PSObject.Properties['PendingFileRenameOperations']) { return $true }
  } catch {}
  return $false
}

function Ensure-FeatureCmdlets {
  if (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
    Emit-Err 'unsupported_sku' 'Install-WindowsFeature is not available on this host. The ServerManager module ships with Windows Server only; on client SKUs use Enable-WindowsOptionalFeature instead.' @{}
    exit 0
  }
}
`

// featurePSResponse is the parsed JSON envelope for feature operations.
type featurePSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// runFeaturePowerShell is the indirection used by FeatureClient. Tests can
// override it; production code must not.
var runFeaturePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// runFeatureEnvelope executes script (prepended with psFeatureHeader) and
// parses the JSON envelope.
func (f *FeatureClient) runFeatureEnvelope(ctx context.Context, op, name, script string) (*featurePSResponse, error) {
	full := psFeatureHeader + "\n" + script
	stdout, stderr, err := runFeaturePowerShell(ctx, f.c, full)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, NewFeatureError(FeatureErrorTimeout,
				fmt.Sprintf("operation %q on feature %q timed out or was cancelled (consider increasing provider timeout for long installs such as Web-Server)", op, name),
				ctxErr,
				map[string]string{"operation": op, "name": name, "host": f.c.cfg.Host})
		}
		return nil, NewFeatureError(FeatureErrorUnknown,
			fmt.Sprintf("powershell transport error during %q", op),
			err,
			map[string]string{
				"operation": op, "name": name, "host": f.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewFeatureError(FeatureErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op), nil,
			map[string]string{
				"operation": op, "name": name, "host": f.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}
	var resp featurePSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewFeatureError(FeatureErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op), jerr,
			map[string]string{"operation": op, "name": name, "host": f.c.cfg.Host, "stdout": truncate(stdout, 2048)})
	}
	if !resp.OK {
		kind := mapFeatureKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["name"] = name
		ctxMap["host"] = f.c.cfg.Host
		msg := resp.Message
		if kind == FeatureErrorPermission {
			msg += " (Local Administrator on the target host is required.)"
		}
		return &resp, NewFeatureError(kind, msg, nil, ctxMap)
	}
	return &resp, nil
}

// mapFeatureKind translates the PS-side "kind" string to a typed FeatureErrorKind.
func mapFeatureKind(k string) FeatureErrorKind {
	switch k {
	case string(FeatureErrorNotFound),
		string(FeatureErrorPermission),
		string(FeatureErrorSourceMissing),
		string(FeatureErrorDependencyMissing),
		string(FeatureErrorUnsupportedSKU),
		string(FeatureErrorTimeout),
		string(FeatureErrorInvalidParameter):
		return FeatureErrorKind(k)
	default:
		return FeatureErrorUnknown
	}
}

// featureDataPayload mirrors the JSON object returned by the read script.
type featureDataPayload struct {
	Name           string `json:"name"`
	DisplayName    string `json:"display_name"`
	Description    string `json:"description"`
	Installed      bool   `json:"installed"`
	InstallState   string `json:"install_state"`
	RestartPending bool   `json:"restart_pending"`
}

// installDataPayload mirrors the JSON returned by Install/Uninstall scripts.
type installDataPayload struct {
	Feature        *featureDataPayload `json:"feature"`
	RestartNeeded  bool                `json:"restart_needed"`
	Success        bool                `json:"success"`
	ExitCode       string              `json:"exit_code"`
}

func toFeatureInfo(d *featureDataPayload) *FeatureInfo {
	if d == nil {
		return nil
	}
	return &FeatureInfo{
		Name:           d.Name,
		DisplayName:    d.DisplayName,
		Description:    d.Description,
		Installed:      d.Installed,
		InstallState:   d.InstallState,
		RestartPending: d.RestartPending,
	}
}

// psFeatureReadBody emits the feature data (or null when not found).
const psFeatureReadBody = `
Ensure-FeatureCmdlets
function Read-Feature([string]$Name) {
  try {
    $f = Get-WindowsFeature -Name $Name -ErrorAction Stop
  } catch {
    $msg = $_.Exception.Message
    Emit-Err (Classify-Feature $msg) $msg @{ name = $Name }
    return
  }
  if (-not $f) { Emit-OK $null; return }
  $pending = Test-PendingReboot
  Emit-OK ([ordered]@{
    name           = [string]$f.Name
    display_name   = [string]$f.DisplayName
    description    = [string]$f.Description
    installed      = ($f.InstallState -eq 'Installed')
    install_state  = [string]$f.InstallState
    restart_pending = [bool]$pending
  })
}
`

// Read implements WindowsFeatureClient.Read.
func (f *FeatureClient) Read(ctx context.Context, name string) (*FeatureInfo, error) {
	if strings.TrimSpace(name) == "" {
		return nil, NewFeatureError(FeatureErrorInvalidParameter, "feature name is empty", nil, nil)
	}
	script := psFeatureReadBody + "\nRead-Feature -Name " + psQuote(name) + "\n"
	resp, err := f.runFeatureEnvelope(ctx, "read", name, script)
	if err != nil {
		if IsFeatureError(err, FeatureErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, nil
	}
	var payload featureDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewFeatureError(FeatureErrorUnknown, "failed to parse feature payload", jerr, map[string]string{"name": name})
	}
	return toFeatureInfo(&payload), nil
}

// psFeatureInstallBody installs a feature and emits the post-state plus the
// install result. Pre-checks for InstallState=Removed without -Source.
const psFeatureInstallBody = `
Ensure-FeatureCmdlets
function Run-Install([string]$Name, [bool]$IncludeSub, [bool]$IncludeMgmt, [string]$Source, [bool]$Restart) {
  try {
    $cur = Get-WindowsFeature -Name $Name -ErrorAction Stop
  } catch {
    $msg = $_.Exception.Message
    Emit-Err (Classify-Feature $msg) $msg @{ name = $Name; phase = 'precheck' }
    return
  }
  if (-not $cur) {
    Emit-Err 'not_found' ("Feature '" + $Name + "' was not found on this host.") @{ name = $Name }
    return
  }
  if ($cur.InstallState -eq 'Removed' -and [string]::IsNullOrEmpty($Source)) {
    Emit-Err 'source_missing' ("Feature '" + $Name + "' has install_state=Removed; an SxS/WIM 'source' path is required to install it.") @{ name = $Name; install_state = 'Removed' }
    return
  }
  $params = @{ Name = $Name; ErrorAction = 'Stop' }
  if ($IncludeSub)  { $params['IncludeAllSubFeature'] = $true }
  if ($IncludeMgmt) { $params['IncludeManagementTools'] = $true }
  if ($Restart)     { $params['Restart'] = $true }
  if (-not [string]::IsNullOrEmpty($Source)) { $params['Source'] = $Source }
  try {
    $r = Install-WindowsFeature @params
  } catch {
    $msg = $_.Exception.Message
    Emit-Err (Classify-Feature $msg) $msg @{ name = $Name; phase = 'install' }
    return
  }
  $restartNeeded = $false
  $exitCode = ''
  $success = $true
  if ($r) {
    if ($r.PSObject.Properties['RestartNeeded']) { $restartNeeded = ([string]$r.RestartNeeded -eq 'Yes' -or [bool]$r.RestartNeeded) }
    if ($r.PSObject.Properties['ExitCode'])      { $exitCode = [string]$r.ExitCode }
    if ($r.PSObject.Properties['Success'])       { $success = [bool]$r.Success }
  }
  $f = Get-WindowsFeature -Name $Name -ErrorAction Stop
  $pending = Test-PendingReboot -or $restartNeeded
  Emit-OK ([ordered]@{
    feature = [ordered]@{
      name = [string]$f.Name; display_name = [string]$f.DisplayName; description = [string]$f.Description
      installed = ($f.InstallState -eq 'Installed'); install_state = [string]$f.InstallState
      restart_pending = [bool]$pending
    }
    restart_needed = [bool]$restartNeeded
    success = [bool]$success
    exit_code = [string]$exitCode
  })
}
`

// Install implements WindowsFeatureClient.Install.
func (f *FeatureClient) Install(ctx context.Context, in FeatureInput) (*FeatureInfo, *InstallResult, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, nil, NewFeatureError(FeatureErrorInvalidParameter, "feature name is empty", nil, nil)
	}
	call := fmt.Sprintf("Run-Install -Name %s -IncludeSub:$%s -IncludeMgmt:$%s -Source %s -Restart:$%s",
		psQuote(in.Name),
		psBool(in.IncludeSubFeatures),
		psBool(in.IncludeManagementTools),
		psQuote(in.Source),
		psBool(in.Restart),
	)
	script := psFeatureInstallBody + "\n" + call + "\n"
	resp, err := f.runFeatureEnvelope(ctx, "install", in.Name, script)
	if err != nil {
		return nil, nil, err
	}
	var payload installDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, nil, NewFeatureError(FeatureErrorUnknown, "failed to parse install payload", jerr, map[string]string{"name": in.Name})
	}
	return toFeatureInfo(payload.Feature), &InstallResult{
		RestartNeeded: payload.RestartNeeded,
		Success:       payload.Success,
		ExitCode:      payload.ExitCode,
	}, nil
}

// psFeatureUninstallBody uninstalls a feature and reports post-state.
const psFeatureUninstallBody = `
Ensure-FeatureCmdlets
function Run-Uninstall([string]$Name, [bool]$IncludeMgmt, [bool]$Restart) {
  try {
    $cur = Get-WindowsFeature -Name $Name -ErrorAction Stop
  } catch {
    $msg = $_.Exception.Message
    Emit-Err (Classify-Feature $msg) $msg @{ name = $Name; phase = 'precheck' }
    return
  }
  if (-not $cur) {
    Emit-OK ([ordered]@{
      feature = $null
      restart_needed = $false
      success = $true
      exit_code = 'NoChangeNeeded'
    })
    return
  }
  $params = @{ Name = $Name; ErrorAction = 'Stop' }
  if ($IncludeMgmt) { $params['IncludeManagementTools'] = $true }
  if ($Restart)     { $params['Restart'] = $true }
  try {
    $r = Uninstall-WindowsFeature @params
  } catch {
    $msg = $_.Exception.Message
    Emit-Err (Classify-Feature $msg) $msg @{ name = $Name; phase = 'uninstall' }
    return
  }
  $restartNeeded = $false
  $exitCode = ''
  $success = $true
  if ($r) {
    if ($r.PSObject.Properties['RestartNeeded']) { $restartNeeded = ([string]$r.RestartNeeded -eq 'Yes' -or [bool]$r.RestartNeeded) }
    if ($r.PSObject.Properties['ExitCode'])      { $exitCode = [string]$r.ExitCode }
    if ($r.PSObject.Properties['Success'])       { $success = [bool]$r.Success }
  }
  $f = Get-WindowsFeature -Name $Name -ErrorAction Stop
  $pending = Test-PendingReboot -or $restartNeeded
  $payload = $null
  if ($f) {
    $payload = [ordered]@{
      name = [string]$f.Name; display_name = [string]$f.DisplayName; description = [string]$f.Description
      installed = ($f.InstallState -eq 'Installed'); install_state = [string]$f.InstallState
      restart_pending = [bool]$pending
    }
  }
  Emit-OK ([ordered]@{
    feature = $payload
    restart_needed = [bool]$restartNeeded
    success = [bool]$success
    exit_code = [string]$exitCode
  })
}
`

// Uninstall implements WindowsFeatureClient.Uninstall.
func (f *FeatureClient) Uninstall(ctx context.Context, in FeatureInput) (*FeatureInfo, *InstallResult, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, nil, NewFeatureError(FeatureErrorInvalidParameter, "feature name is empty", nil, nil)
	}
	call := fmt.Sprintf("Run-Uninstall -Name %s -IncludeMgmt:$%s -Restart:$%s",
		psQuote(in.Name),
		psBool(in.IncludeManagementTools),
		psBool(in.Restart),
	)
	script := psFeatureUninstallBody + "\n" + call + "\n"
	resp, err := f.runFeatureEnvelope(ctx, "uninstall", in.Name, script)
	if err != nil {
		return nil, nil, err
	}
	var payload installDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, nil, NewFeatureError(FeatureErrorUnknown, "failed to parse uninstall payload", jerr, map[string]string{"name": in.Name})
	}
	return toFeatureInfo(payload.Feature), &InstallResult{
		RestartNeeded: payload.RestartNeeded,
		Success:       payload.Success,
		ExitCode:      payload.ExitCode,
	}, nil
}

// psBool returns "true" / "false" — used to render PowerShell switch values.
func psBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
