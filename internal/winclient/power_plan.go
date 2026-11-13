// Package winclient: active power plan (singleton) management over SSH.
//
// PowerPlanClient is the concrete WindowsPowerPlanClient backing the
// windows_power_plan Terraform resource and data source. All operations
// execute PowerShell scripts wrapped in a JSON envelope (Emit-OK/Emit-Err)
// so stdout is machine-parseable regardless of the Windows locale.
//
// Identity model (GUID-only, never localised):
//   - Plans are identified by GUID. Plan aliases (balanced,
//     high_performance, power_saver, ultimate_performance) resolve to
//     GUIDs in Go (power_plan_types.go); ElementName is surfaced as the
//     informational plan_name attribute only.
//   - Subgroup/setting aliases (SUB_SLEEP, DISKIDLE, ...) resolve on the
//     host via powercfg /aliases (stable, non-localised alias/GUID
//     pairs, cached per call). powercfg /query text is never parsed.
//   - Existence checks read WMI root\cimv2\power (Win32_PowerPlan
//     InstanceID, Win32_PowerSetting, Win32_PowerSettingDataIndex
//     SettingIndexValue).
//
// Activation uses powercfg /setactive gated on $LASTEXITCODE:
// Win32_PowerPlan.Activate() is unreliable on recent builds and is never
// called.
//
// Security invariants:
//   - User-supplied values are interpolated only through psQuote
//     (single-quoted PS literal) or as Go-formatted integers, so $var /
//     backtick / subexpression injection is impossible.
//   - All scripts are sent via -EncodedCommand by Client.RunPowerShell.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: PowerPlanClient satisfies WindowsPowerPlanClient.
var _ WindowsPowerPlanClient = (*PowerPlanClient)(nil)

// PowerPlanClient is the PowerShell/SSH-backed WindowsPowerPlanClient.
type PowerPlanClient struct {
	c *Client
}

// NewPowerPlanClient wraps the given SSH Client.
func NewPowerPlanClient(c *Client) *PowerPlanClient { return &PowerPlanClient{c: c} }

// runPowerPlanPowerShell is the package-level indirection used by
// PowerPlanClient. Tests may override it; production code must not.
var runPowerPlanPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// powerPlanPSResponse is the JSON envelope produced by Emit-OK/Emit-Err. It
// aliases the shared Envelope type so every resource parses the same shape
// through runEnvelope (#198).
type powerPlanPSResponse = Envelope

// powerPlanSettingPayload is one element of the settings array emitted by
// the Read/state projections.
type powerPlanSettingPayload struct {
	SubgroupGUID string `json:"subgroup_guid"`
	SettingGUID  string `json:"setting_guid"`
	ACValue      *int64 `json:"ac_value"`
	DCValue      *int64 `json:"dc_value"`
}

// powerPlanStatePayload is the data shape emitted by the state projections.
type powerPlanStatePayload struct {
	MachineID          string                    `json:"machine_id"`
	PlanGUID           string                    `json:"plan_guid"`
	PlanName           string                    `json:"plan_name"`
	DuplicatedPlanGUID string                    `json:"duplicated_plan_guid"`
	Settings           []powerPlanSettingPayload `json:"settings"`
}

// powerPlanInfoPayload is one element of the plans array emitted by List.
type powerPlanInfoPayload struct {
	GUID     string `json:"guid"`
	Name     string `json:"name"`
	IsActive bool   `json:"is_active"`
}

// powerPlanListPayload is the data shape emitted by the List projection.
type powerPlanListPayload struct {
	MachineID      string                 `json:"machine_id"`
	ActivePlanGUID string                 `json:"active_plan_guid"`
	ActivePlanName string                 `json:"active_plan_name"`
	Plans          []powerPlanInfoPayload `json:"plans"`
}

// psPowerPlanHeader prepends Emit-OK/Emit-Err, Classify-PowerPlan and the
// shared read helpers.
//
// Classify-PowerPlan maps error records to PowerPlanErrorKind values. The
// script itself emits the precise kinds for the failures it anticipates
// (unsupported preflight, plan_not_found, setting_not_found,
// invalid_value); Classify is the backstop for WMI/CIM and unexpected
// powercfg failures.
//
// Get-PowerAliasTable parses powercfg /aliases (stable alias/GUID pairs,
// never localised text) into an upper-cased-alias to lower-case-GUID
// table. Lines without a GUID (headers, blanks) are skipped, so the parse
// does not depend on column layout or localisation.
const psPowerPlanHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture   = [System.Globalization.CultureInfo]::InvariantCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Classify-PowerPlan([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'is not recognized as the name of a cmdlet' -or $msg -match 'is not recognized as an internal or external command' -or $msg -match 'Not supported' -or $msg -match 'Invalid namespace' -or $msg -match 'Invalid class') { return 'unsupported' }
  if ($msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess' -or $msg -match 'Unauthorized' -or $msg -match 'requires elevation' -or $msg -match 'Requested registry access is not allowed') { return 'access_denied' }
  if ($msg -match 'No valid power scheme' -or $msg -match 'does not exist' -or $msg -match 'was not found' -or $msg -match 'cannot find' -or $msg -match 'could not be found' -or $msg -match 'Invalid Parameters') { return 'plan_not_found' }
  if ($msg -match 'setting was not found' -or $msg -match 'subgroup was not found' -or $msg -match 'could not be resolved' -or $msg -match 'no such setting' -or $msg -match 'no such subgroup' -or $msg -match 'no such alias') { return 'setting_not_found' }
  if ($msg -match 'out of range' -or $msg -match 'Invalid value' -or $msg -match 'The parameter is incorrect' -or $msg -match 'greater than the maximum' -or $msg -match 'less than the minimum') { return 'invalid_value' }
  return 'unknown'
}

function Get-PowerAliasTable([string]$PowerCfg) {
  $t = @{}
  $out = & $PowerCfg /aliases 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw ('powercfg /aliases failed (exit {0}): {1}' -f $LASTEXITCODE, $out.Trim()) }
  foreach ($line in ($out -split "\r?\n")) {
    $m = [regex]::Match($line, '([A-Za-z][A-Za-z0-9_]*)\s+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
    if ($m.Success) { $t[$m.Groups[1].Value.ToUpperInvariant()] = $m.Groups[2].Value.ToLowerInvariant() }
  }
  return $t
}

function Resolve-PowerGuid([hashtable]$Table, [string]$Value, [string]$What) {
  $v = $Value.Trim()
  if ($v -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return $v.ToLowerInvariant() }
  $k = $v.ToUpperInvariant()
  if ($Table.ContainsKey($k)) { return $Table[$k] }
  throw ('{0} {1} could not be resolved via powercfg /aliases' -f $What, $Value)
}

function Read-PowerSettingValue([string]$PlanGuid, [string]$AcDc, [string]$SettingGuid) {
  $id = ('Microsoft:PowerSettingDataIndex\{0}\{1}\{2}' -f $PlanGuid, $AcDc, $SettingGuid)
  $o = Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerSettingDataIndex -Filter ("InstanceID='" + $id + "'") -ErrorAction Stop
  if ($null -eq $o) { return $null }
  return [int64]$o.SettingIndexValue
}

function Get-PowerPlans {
  $plans = @(Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerPlan -ErrorAction Stop)
  $list = @()
  foreach ($p in $plans) {
    $m = [regex]::Match([string]$p.InstanceID, 'Microsoft:PowerPlan\\\{([0-9a-fA-F-]{36})\}')
    if (-not $m.Success) { continue }
    $list += [ordered]@{ guid = $m.Groups[1].Value.ToLowerInvariant(); name = [string]$p.ElementName; is_active = [bool]$p.IsActive }
  }
  return $list
}
`

// ppReadBody reads the active plan and the values of the listed settings.
// Placeholder @@SETTINGS@@ is the Go-rendered array of @{ Sub; Setting }
// entries (GUID or alias, resolved on the host). Plan identity and values
// come from WMI only; powercfg /query text is never parsed.
const ppReadBody = `
$PowerCfg = Join-Path $env:SystemRoot 'System32\powercfg.exe'
$Settings = @@SETTINGS@@

& {
  try {
    if (-not (Test-Path -LiteralPath $PowerCfg -ErrorAction Stop)) { Emit-Err 'unsupported' ('powercfg.exe is not available on the target host: ' + $PowerCfg) @{ step = 'preflight' }; return }
    $machineId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $all = @(Get-PowerPlans)
    $live = @($all | Where-Object { $_.is_active })
    if ($live.Count -eq 0) { Emit-Err 'unsupported' 'No active power plan was found on the target host (power plans are unavailable, e.g. containers).' @{ step = 'read' }; return }
    $planGuid = [string]$live[0].guid
    $aliasTable = Get-PowerAliasTable $PowerCfg
    $vals = @()
    foreach ($s in $Settings) {
      try {
        $subGuid = Resolve-PowerGuid $aliasTable ([string]$s.Sub) 'subgroup'
        $setGuid = Resolve-PowerGuid $aliasTable ([string]$s.Setting) 'setting'
      } catch { Emit-Err 'setting_not_found' $_.Exception.Message @{ step = 'resolve'; subgroup = [string]$s.Sub; setting = [string]$s.Setting }; return }
      $def = @(Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerSetting -Filter ("InstanceID='Microsoft:PowerSetting\{" + $setGuid + "}'") -ErrorAction Stop)
      if ($def.Count -eq 0) { Emit-Err 'setting_not_found' ('power setting ' + [string]$s.Setting + ' is unknown to the target host') @{ step = 'resolve'; setting = [string]$s.Setting }; return }
      try {
        $ac = Read-PowerSettingValue $planGuid 'AC' $setGuid
        $dc = Read-PowerSettingValue $planGuid 'DC' $setGuid
      } catch { Emit-Err (Classify-PowerPlan $_) $_.Exception.Message @{ step = 'read_values'; setting = $setGuid }; return }
      $vals += [ordered]@{ subgroup_guid = $subGuid; setting_guid = $setGuid; ac_value = $ac; dc_value = $dc }
    }
    Emit-OK ([ordered]@{ machine_id = [string]$machineId; plan_guid = $planGuid; plan_name = [string]$live[0].name; duplicated_plan_guid = ''; settings = $vals })
  } catch { Emit-Err (Classify-PowerPlan $_) $_.Exception.Message @{ step = 'read' } }
}
`

// ppApplyBody resolves the desired plan (duplicating the template when
// requested and absent), writes the configured AC/DC values, activates the
// plan and verifies by re-reading. Placeholders, all rendered by Go:
// @@PLANGUID@@ (psQuote'd canonical GUID), @@TEMPLATEGUID@@ (psQuote'd,
// used only for /duplicatescheme), @@CREATEIFMISSING@@ ($true/$false) and
// @@SETTINGS@@ (Go-rendered @{ Sub; Setting; AC; DC } entries).
//
// DC values are always stored, even on hosts without a battery: Windows
// keeps them and applies them if a battery ever appears.
const ppApplyBody = `
$PowerCfg = Join-Path $env:SystemRoot 'System32\powercfg.exe'
$PlanGuid = @@PLANGUID@@
$TemplateGuid = @@TEMPLATEGUID@@
$CreateIfMissing = @@CREATEIFMISSING@@
$Settings = @@SETTINGS@@

& {
  try {
    if (-not (Test-Path -LiteralPath $PowerCfg -ErrorAction Stop)) { Emit-Err 'unsupported' ('powercfg.exe is not available on the target host: ' + $PowerCfg) @{ step = 'preflight' }; return }
    $machineId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $all = @(Get-PowerPlans)
    $known = @{}
    foreach ($p in $all) { $known[[string]$p.guid] = $p }
    $effective = $PlanGuid.ToLowerInvariant()
    $duplicated = ''
    if (-not $known.ContainsKey($effective)) {
      if (-not $CreateIfMissing) { Emit-Err 'plan_not_found' ('power plan ' + $PlanGuid + ' was not found on the target host') @{ step = 'preflight'; plan = $PlanGuid }; return }
      try {
        $dupOut = & $PowerCfg /duplicatescheme $TemplateGuid 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { Emit-Err 'plan_not_found' ('powercfg /duplicatescheme failed (exit {0}): {1}' -f $LASTEXITCODE, $dupOut.Trim()) @{ step = 'duplicate'; plan = $PlanGuid }; return }
        $dm = [regex]::Match($dupOut, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
        if (-not $dm.Success) { Emit-Err 'unknown' ('powercfg /duplicatescheme did not report a new plan GUID: ' + $dupOut.Trim()) @{ step = 'duplicate'; plan = $PlanGuid }; return }
        $effective = $dm.Groups[1].Value.ToLowerInvariant()
        $duplicated = $effective
      } catch { Emit-Err (Classify-PowerPlan $_) $_.Exception.Message @{ step = 'duplicate'; plan = $PlanGuid }; return }
    }
    $aliasTable = Get-PowerAliasTable $PowerCfg
    $resolved = @()
    foreach ($s in $Settings) {
      try {
        $subGuid = Resolve-PowerGuid $aliasTable ([string]$s.Sub) 'subgroup'
        $setGuid = Resolve-PowerGuid $aliasTable ([string]$s.Setting) 'setting'
      } catch { Emit-Err 'setting_not_found' $_.Exception.Message @{ step = 'resolve'; subgroup = [string]$s.Sub; setting = [string]$s.Setting }; return }
      $def = @(Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerSetting -Filter ("InstanceID='Microsoft:PowerSetting\{" + $setGuid + "}'") -ErrorAction Stop)
      if ($def.Count -eq 0) { Emit-Err 'setting_not_found' ('power setting ' + [string]$s.Setting + ' is unknown to the target host') @{ step = 'resolve'; setting = [string]$s.Setting }; return }
      $resolved += [ordered]@{ subgroup = $subGuid; setting = $setGuid; ac = $s.AC; dc = $s.DC }
    }
    foreach ($r in $resolved) {
      if ($null -ne $r.ac) {
        $w = & $PowerCfg /setacvalueindex $effective $r.subgroup $r.setting ([int64]$r.ac) 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { Emit-Err 'invalid_value' ('powercfg /setacvalueindex failed (exit {0}): {1}' -f $LASTEXITCODE, $w.Trim()) @{ step = 'set'; setting = $r.setting }; return }
      }
      if ($null -ne $r.dc) {
        $w = & $PowerCfg /setdcvalueindex $effective $r.subgroup $r.setting ([int64]$r.dc) 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { Emit-Err 'invalid_value' ('powercfg /setdcvalueindex failed (exit {0}): {1}' -f $LASTEXITCODE, $w.Trim()) @{ step = 'set'; setting = $r.setting }; return }
      }
    }
    $a = & $PowerCfg /setactive $effective 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify-PowerPlan $a) ('powercfg /setactive failed (exit {0}): {1}' -f $LASTEXITCODE, $a.Trim()) @{ step = 'activate'; plan = $effective }; return }
    $back = @(Get-PowerPlans)
    $live = @($back | Where-Object { $_.is_active })
    if ($live.Count -eq 0 -or ([string]$live[0].guid -ne $effective)) { Emit-Err 'unknown' ('power plan change did not take effect: active plan is not ' + $effective) @{ step = 'verify'; plan = $effective }; return }
    $vals = @()
    foreach ($r in $resolved) {
      $ac = $null
      $dc = $null
      try {
        if ($null -ne $r.ac) { $ac = Read-PowerSettingValue $effective 'AC' $r.setting }
        if ($null -ne $r.dc) { $dc = Read-PowerSettingValue $effective 'DC' $r.setting }
      } catch { Emit-Err (Classify-PowerPlan $_) $_.Exception.Message @{ step = 'verify'; setting = $r.setting }; return }
      if (($null -ne $r.ac -and $ac -ne [int64]$r.ac) -or ($null -ne $r.dc -and $dc -ne [int64]$r.dc)) {
        Emit-Err 'unknown' ('power setting change did not take effect for ' + $r.setting) @{ step = 'verify'; setting = $r.setting }
        return
      }
      $vals += [ordered]@{ subgroup_guid = $r.subgroup; setting_guid = $r.setting; ac_value = $ac; dc_value = $dc }
    }
    Emit-OK ([ordered]@{ machine_id = [string]$machineId; plan_guid = $effective; plan_name = [string]$live[0].name; duplicated_plan_guid = $duplicated; settings = $vals })
  } catch { Emit-Err (Classify-PowerPlan $_) $_.Exception.Message @{ step = 'apply' } }
}
`

// ppListBody returns the active plan plus every plan known to the host.
// Plan names are ElementName (localised, informational); matching uses the
// GUID parsed from InstanceID only.
const ppListBody = `
$PowerCfg = Join-Path $env:SystemRoot 'System32\powercfg.exe'

& {
  try {
    if (-not (Test-Path -LiteralPath $PowerCfg -ErrorAction Stop)) { Emit-Err 'unsupported' ('powercfg.exe is not available on the target host: ' + $PowerCfg) @{ step = 'preflight' }; return }
    $machineId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $all = @(Get-PowerPlans)
    if ($all.Count -eq 0) { Emit-Err 'unsupported' 'No power plans were found on the target host (power plans are unavailable, e.g. containers).' @{ step = 'list' }; return }
    $live = @($all | Where-Object { $_.is_active })
    if ($live.Count -eq 0) { Emit-Err 'unsupported' 'No active power plan was found on the target host (power plans are unavailable, e.g. containers).' @{ step = 'list' }; return }
    Emit-OK ([ordered]@{ machine_id = [string]$machineId; active_plan_guid = [string]$live[0].guid; active_plan_name = [string]$live[0].name; plans = $all })
  } catch { Emit-Err (Classify-PowerPlan $_) $_.Exception.Message @{ step = 'list' } }
}
`

// ppDeleteBody removes one plan by GUID. A missing plan is success
// (idempotent): existence is pre-checked locale-free via Get-PowerPlans
// (GUID-parsed WMI, never localised text), so /delete is only called when
// the plan exists; the English "not found" text match stays as a
// belt-and-braces fallback, and the Go caller additionally treats a typed
// plan_not_found error (via Classify-PowerPlan for any other phrasing) as
// success; deleting the active plan fails — the caller must ensure the
// plan is inactive first.
const ppDeleteBody = `
$PowerCfg = Join-Path $env:SystemRoot 'System32\powercfg.exe'
$PlanGuid = @@PLANGUID@@

& {
  try {
    if (-not (Test-Path -LiteralPath $PowerCfg -ErrorAction Stop)) { Emit-Err 'unsupported' ('powercfg.exe is not available on the target host: ' + $PowerCfg) @{ step = 'preflight' }; return }
    $existing = @(Get-PowerPlans | Where-Object { $_.guid -eq $PlanGuid.ToLowerInvariant() })
    if ($existing.Count -eq 0) { Emit-OK $null; return }
    $d = & $PowerCfg /delete $PlanGuid 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
      $t = $d.Trim()
      if ($t -match 'does not exist' -or $t -match 'was not found' -or $t -match 'could not be found' -or $t -match 'cannot find' -or $t -match 'cannot be found') { Emit-OK $null; return }
      Emit-Err (Classify-PowerPlan $t) ('powercfg /delete failed (exit {0}): {1}' -f $LASTEXITCODE, $t) @{ step = 'delete'; plan = $PlanGuid }
      return
    }
    Emit-OK $null
  } catch { Emit-Err (Classify-PowerPlan $_) $_.Exception.Message @{ step = 'delete' } }
}
`

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

// buildPowerPlanReadSettingsArray renders the $Settings array for the read
// path: @{ Sub; Setting } entries (GUID or alias, resolved on the host).
func buildPowerPlanReadSettingsArray(keys []PowerPlanSettingKey) string {
	if len(keys) == 0 {
		return "@()"
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("@{ Sub = %s; Setting = %s }",
			psQuote(k.Subgroup), psQuote(k.Setting)))
	}
	return "@(\n  " + strings.Join(parts, ",\n  ") + "\n)"
}

// buildPowerPlanWriteSettingsArray renders the $Settings array for the
// apply/restore path: @{ Sub; Setting; AC; DC } entries. Unset values
// render as $null so the host value is left untouched.
func buildPowerPlanWriteSettingsArray(settings []PowerPlanSettingInput) string {
	if len(settings) == 0 {
		return "@()"
	}
	numOrNull := func(v *int64) string {
		if v == nil {
			return "$null"
		}
		return fmt.Sprintf("%d", *v)
	}
	parts := make([]string, 0, len(settings))
	for _, s := range settings {
		parts = append(parts, fmt.Sprintf("@{ Sub = %s; Setting = %s; AC = %s; DC = %s }",
			psQuote(s.Subgroup), psQuote(s.Setting),
			numOrNull(s.ACValue), numOrNull(s.DCValue)))
	}
	return "@(\n  " + strings.Join(parts, ",\n  ") + "\n)"
}

// buildPowerPlanApplyScript renders ppApplyBody for the given resolved
// plan GUID, duplicatescheme template, create flag and settings.
func buildPowerPlanApplyScript(planGUID, templateGUID string, createIfMissing bool, settings []PowerPlanSettingInput) string {
	createFlag := "$false"
	if createIfMissing {
		createFlag = "$true"
	}
	return strings.NewReplacer(
		"@@PLANGUID@@", psQuote(planGUID),
		"@@TEMPLATEGUID@@", psQuote(templateGUID),
		"@@CREATEIFMISSING@@", createFlag,
		"@@SETTINGS@@", buildPowerPlanWriteSettingsArray(settings),
	).Replace(ppApplyBody)
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// mapPowerPlanKind translates a PS-side "kind" string to a typed
// PowerPlanErrorKind. Unknown values fall through to PowerPlanErrorUnknown.
func mapPowerPlanKind(k string) PowerPlanErrorKind {
	switch k {
	case string(PowerPlanErrorPlanNotFound),
		string(PowerPlanErrorSettingNotFound),
		string(PowerPlanErrorInvalidValue),
		string(PowerPlanErrorUnsupported),
		string(PowerPlanErrorAccessDenied):
		return PowerPlanErrorKind(k)
	default:
		return PowerPlanErrorUnknown
	}
}

// runPowerPlanEnvelope executes script (prepended with psPowerPlanHeader)
// and parses the JSON envelope through the shared runEnvelope helper.
// Transport / cancellation errors that bypass Emit-Err are mapped to
// PowerPlanErrorUnknown (with the timeout stage surfaced in the message);
// the timeout stage is additionally recognisable by callers via the
// context. Caller-supplied baseCtx entries are preserved alongside the
// connection identity.
func (p *PowerPlanClient) runPowerPlanEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*powerPlanPSResponse, error) {
	baseContext := map[string]string{
		"host":      p.c.cfg.Host,
		"port":      fmt.Sprintf("%d", p.c.cfg.Port),
		"transport": "ssh",
	}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerPlanPowerShell(ctx, p.c, full)
		},
		op, psPowerPlanHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewPowerPlanError(PowerPlanErrorUnknown,
			fmt.Sprintf("operation %q on power plan timed out or was cancelled", op),
			eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewPowerPlanError(PowerPlanErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewPowerPlanError(mapPowerPlanKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// powerPlanPayloadToState projects a powerPlanStatePayload onto the public
// PowerPlanState. GUIDs are normalised to lower-case on the way out so a
// host reporting upper-case spellings compares equal to the canonical
// lower-case references.
func powerPlanPayloadToState(p powerPlanStatePayload) *PowerPlanState {
	settings := make([]PowerPlanSettingState, 0, len(p.Settings))
	for _, s := range p.Settings {
		settings = append(settings, PowerPlanSettingState{
			SubgroupGUID: strings.ToLower(s.SubgroupGUID),
			SettingGUID:  strings.ToLower(s.SettingGUID),
			ACValue:      s.ACValue,
			DCValue:      s.DCValue,
		})
	}
	return &PowerPlanState{
		MachineID:          p.MachineID,
		PlanGUID:           strings.ToLower(p.PlanGUID),
		PlanName:           p.PlanName,
		Settings:           settings,
		DuplicatedPlanGUID: strings.ToLower(p.DuplicatedPlanGUID),
	}
}

// parsePowerPlanState unmarshals the envelope Data of a read/apply/restore
// call into a *PowerPlanState.
func parsePowerPlanState(resp *powerPlanPSResponse, host string) (*PowerPlanState, error) {
	var p powerPlanStatePayload
	if jerr := json.Unmarshal(resp.Data, &p); jerr != nil {
		return nil, NewPowerPlanError(PowerPlanErrorUnknown,
			"failed to parse power plan state JSON", jerr,
			map[string]string{"host": host, "raw": truncate(string(resp.Data), 512)})
	}
	return powerPlanPayloadToState(p), nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the active plan and the observed values of the listed
// settings.
func (p *PowerPlanClient) Read(ctx context.Context, settings []PowerPlanSettingKey) (*PowerPlanState, error) {
	script := strings.NewReplacer(
		"@@SETTINGS@@", buildPowerPlanReadSettingsArray(settings),
	).Replace(ppReadBody)
	resp, err := p.runPowerPlanEnvelope(ctx, "read", script, nil)
	if err != nil {
		return nil, err
	}
	return parsePowerPlanState(resp, p.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Apply (Create and Update share it: the active plan is a singleton)
// ---------------------------------------------------------------------------

// applyPowerPlan runs the rendered apply script and parses the state. The
// input must already be validated (Apply validates; Restore builds its
// input from host-observed snapshot values).
func (p *PowerPlanClient) applyPowerPlan(ctx context.Context, op string, planGUID, templateGUID string, createIfMissing bool, settings []PowerPlanSettingInput) (*PowerPlanState, error) {
	script := buildPowerPlanApplyScript(planGUID, templateGUID, createIfMissing, settings)
	resp, err := p.runPowerPlanEnvelope(ctx, op, script, map[string]string{"plan": planGUID})
	if err != nil {
		return nil, err
	}
	return parsePowerPlanState(resp, p.c.cfg.Host)
}

// Apply resolves the desired plan (duplicating the template when
// CreateIfMissing and the plan is absent), writes the configured AC/DC
// values, activates the plan and verifies by re-reading.
func (p *PowerPlanClient) Apply(ctx context.Context, input PowerPlanInput) (*PowerPlanState, error) {
	if err := ValidatePowerPlanInput(input); err != nil {
		return nil, err
	}
	planGUID, err := ResolvePowerPlanReference(input.Plan)
	if err != nil {
		return nil, err
	}
	// The duplicatescheme template is the resolved plan GUID itself. This
	// only restores well-known template GUIDs (balanced, high_performance,
	// power_saver, ultimate_performance): the template must be known to the
	// host or the duplicate fails with plan_not_found. Arbitrary custom
	// plan GUIDs cannot be duplicated — they have no template source — so
	// create_if_missing is only meaningful for the well-known templates
	// (plan-time guidance lives on the resource schema).
	return p.applyPowerPlan(ctx, "apply", planGUID, planGUID, input.CreateIfMissing, input.Settings)
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// List returns the active plan plus every plan known to the host.
func (p *PowerPlanClient) List(ctx context.Context) (*PowerPlanListState, error) {
	resp, err := p.runPowerPlanEnvelope(ctx, "list", ppListBody, nil)
	if err != nil {
		return nil, err
	}
	var pl powerPlanListPayload
	if jerr := json.Unmarshal(resp.Data, &pl); jerr != nil {
		return nil, NewPowerPlanError(PowerPlanErrorUnknown,
			"failed to parse power plan list JSON", jerr,
			map[string]string{"host": p.c.cfg.Host, "raw": truncate(string(resp.Data), 512)})
	}
	plans := make([]PowerPlanInfo, 0, len(pl.Plans))
	for _, pi := range pl.Plans {
		plans = append(plans, PowerPlanInfo{
			GUID:     strings.ToLower(pi.GUID),
			Name:     pi.Name,
			IsActive: pi.IsActive,
		})
	}
	return &PowerPlanListState{
		MachineID:      pl.MachineID,
		ActivePlanGUID: strings.ToLower(pl.ActivePlanGUID),
		ActivePlanName: pl.ActivePlanName,
		Plans:          plans,
	}, nil
}

// ---------------------------------------------------------------------------
// Restore (Delete with restore_on_destroy)
// ---------------------------------------------------------------------------

// Restore re-activates the snapshot plan and re-applies its captured
// setting values verbatim. The plan must exist; Restore never duplicates
// a template (a missing snapshot plan is a plan_not_found error).
func (p *PowerPlanClient) Restore(ctx context.Context, snapshot PowerPlanSnapshot) (*PowerPlanState, error) {
	planGUID, err := ResolvePowerPlanReference(snapshot.PlanGUID)
	if err != nil {
		return nil, err
	}
	settings := make([]PowerPlanSettingInput, 0, len(snapshot.Settings))
	for _, s := range snapshot.Settings {
		// Settings whose host values were both null carry nothing to
		// restore; skipping them also keeps the apply verify exact.
		if s.ACValue == nil && s.DCValue == nil {
			continue
		}
		settings = append(settings, PowerPlanSettingInput{
			Subgroup: s.SubgroupGUID,
			Setting:  s.SettingGUID,
			ACValue:  s.ACValue,
			DCValue:  s.DCValue,
		})
	}
	return p.applyPowerPlan(ctx, "restore", planGUID, planGUID, false, settings)
}

// ---------------------------------------------------------------------------
// DeletePlan
// ---------------------------------------------------------------------------

// DeletePlan removes the named plan (powercfg /delete). Missing plans are
// success (idempotent, including a typed plan_not_found from Classify).
// The plan must be inactive: deleting the active plan is an error.
func (p *PowerPlanClient) DeletePlan(ctx context.Context, guid string) error {
	trimmed := strings.TrimSpace(guid)
	if !IsPowerPlanGUID(trimmed) {
		return NewPowerPlanError(PowerPlanErrorPlanNotFound,
			fmt.Sprintf("unknown power plan %q: must be a GUID", guid),
			nil, map[string]string{"plan": guid})
	}
	script := strings.NewReplacer(
		"@@PLANGUID@@", psQuote(strings.ToLower(trimmed)),
	).Replace(ppDeleteBody)
	_, err := p.runPowerPlanEnvelope(ctx, "delete", script, map[string]string{"plan": strings.ToLower(trimmed)})
	if err != nil && IsPowerPlanError(err, PowerPlanErrorPlanNotFound) {
		return nil
	}
	return err
}
