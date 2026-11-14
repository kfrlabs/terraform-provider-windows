// Package winclient — DSCResourceClient is the concrete
// WindowsDSCResourceClient backed by PowerShell over SSH (issue #293).
//
// The implementation drives any DSC resource through Invoke-DscResource
// (Test/Set/Get). Every operation starts with a scoped preflight script
// (Get-DscLocalConfigurationManager plus Get-DscResource -Name with a
// resolved module object, never unfiltered) whose output is parsed and
// re-gated Go-side. Property values are coerced and validated pure-Go
// before any Invoke-DscResource call.
//
// Security invariants:
//   - Only module_name and resource_name are interpolated into PowerShell
//     script bodies, and only through psQuote (single-quoted PowerShell
//     literal with embedded single-quotes doubled).
//   - Property values travel on stdin as a JSON document (first line) and
//     credentials on a second stdin line, rebuilt server-side into
//     PSCredential objects. Passwords never reach the script body, error
//     messages or Context maps.
//   - Get output is redacted Go-side (RedactDSCState) before it leaves this
//     package.
//
// Reused helpers from the same package:
//   - psQuote       - safe PS string literal (psquote.go)
//   - runEnvelope   - shared JSON envelope pipeline (envelope.go)
package winclient

// PowerShell script bodies and the LCM remediation text. Split from dsc_resource.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// dscPsHeader is prepended to every DSC script. It pins the session culture
// to InvariantCulture and defines the shared Emit-OK / Emit-Err /
// Classify-DscResource helpers.
//
// Note: Go raw-string literals (backtick-delimited) must not contain PS
// backtick sequences (`n, `t). None are needed here; single-quoted PS
// literals avoid all expansion.
const dscPsHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture   = [System.Globalization.CultureInfo]::InvariantCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture

function Emit-OK([object]$Data) {
  $obj  = [ordered]@{ ok = $true; data = $Data }
  $json = ($obj | ConvertTo-Json -Depth 10 -Compress)
  [Console]::Out.WriteLine($json)
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj  = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Classify-DscResource([object]$Rec, [string]$Method) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'Access is denied' -or
      $msg -match 'PermissionDenied' -or
      $msg -match 'UnauthorizedAccess' -or
      $msg -match 'requires elevation') {
    return 'access_denied'
  }
  if ($msg -match 'RefreshMode' -or
      $msg -match 'Pull mode' -or
      $msg -match 'Local Configuration Manager' -or
      $msg -match 'pending reboot' -or
      $msg -match 'another configuration.*in progress' -or
      $msg -match 'is currently running') {
    return 'lcm_conflict'
  }
  if ($msg -match 'Could not find the module' -or
      $msg -match 'Cannot find module' -or
      $msg -match 'No modules found' -or
      $msg -match 'module .* was not found') {
    return 'module_not_found'
  }
  if ($msg -match 'Resource .* was not found' -or
      $msg -match 'was not found' -or
      $msg -match 'could not be found' -or
      $msg -match 'No resource' -or
      $msg -match 'not recognized') {
    return 'resource_not_found'
  }
  if ($msg -match 'does not have a property' -or
      $msg -match 'No such property' -or
      $msg -match 'Invalid property' -or
      $msg -match 'is not a valid property') {
    return 'invalid_property'
  }
  if ($msg -match 'is required' -or
      $msg -match 'is mandatory' -or
      $msg -match 'missing.*property' -or
      $msg -match 'Because the property.*is Null') {
    return 'missing_property'
  }
  if ($msg -match 'Cannot bind' -or
      $msg -match 'Cannot convert' -or
      $msg -match 'Cannot validate' -or
      $msg -match 'is not valid' -or
      $msg -match 'ValidateSet' -or
      $msg -match 'ValueMap') {
    return 'invalid_value'
  }
  if ($msg -match 'not supported' -or
      $msg -match 'not implemented') {
    return 'unsupported'
  }
  if ($Method -eq 'Set') { return 'set_failed' }
  return 'unknown'
}

function Get-DSCPropFlag([object]$p, [string]$n) {
  try {
    $v = $p.$n
    if ($null -ne $v) { return [bool]$v }
  } catch { }
  return $false
}

# Convert-DscJsonToHashtable parses a JSON document into nested hashtables.
# ConvertFrom-Json -AsHashtable requires PowerShell 6+, but DSC only runs on
# Windows PowerShell 5.1, so the PSCustomObject tree is converted manually
# (recursively: objects to hashtables, arrays element-wise, scalars kept).
function Convert-DscValueToHashtable([object]$Value) {
  if ($null -eq $Value) { return $null }
  if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
  if ($Value -is [System.Collections.IDictionary]) {
    $h = @{}
    foreach ($k in $Value.Keys) { $h[[string]$k] = Convert-DscValueToHashtable $Value[$k] }
    return $h
  }
  if ($Value -is [System.Collections.IEnumerable]) {
    # NOTE: do not use $a += $x here: array-concat enumerates hashtable
    # values, shredding embedded objects into DictionaryEntries. And do not
    # bare-return the array: PowerShell unrolls single-element arrays on
    # function output (turning ["1"] into "1"), so -NoEnumerate preserves
    # the array object itself.
    $a = New-Object System.Collections.ArrayList
    foreach ($e in $Value) { [void]$a.Add((Convert-DscValueToHashtable $e)) }
    Write-Output $a.ToArray() -NoEnumerate
    return
  }
  $props = @($Value.PSObject.Properties)
  if ($props.Count -gt 0) {
    $h = @{}
    foreach ($p in $props) { $h[[string]$p.Name] = Convert-DscValueToHashtable $p.Value }
    return $h
  }
  return $Value
}
function Convert-DscJsonToHashtable([string]$Json) {
  if ([string]::IsNullOrWhiteSpace($Json)) { return @{} }
  $obj = $Json | ConvertFrom-Json -ErrorAction Stop
  $h = Convert-DscValueToHashtable $obj
  if ($null -eq $h) { return @{} }
  return $h
}
`

// ---------------------------------------------------------------------------
// Preflight body (LCM gate + scoped schema fetch)
// ---------------------------------------------------------------------------

// dscPreflightBody checks the LCM (fail closed, never changes settings) and
// fetches the resource schema with a scoped Get-DscResource -Name -Module
// query. Placeholders: @@MODULENAME@@, @@MODULEVERSION@@ (” when unpinned),
// @@RESOURCENAME@@.
const dscPreflightBody = `
$modName = @@MODULENAME@@
$modReqVer = @@MODULEVERSION@@
$resName = @@RESOURCENAME@@

$lcm = Get-DscLocalConfigurationManager
$refreshMode = [string]$lcm.RefreshMode
$lcmState = [string]$lcm.LCMState
if ($refreshMode -eq 'Pull') {
  Emit-Err 'lcm_conflict' ('The DSC Local Configuration Manager on node uses RefreshMode ''Pull''. windows_dsc_resource never changes LCM settings: switch the node to PUSH mode out-of-band (Set-DscLocalConfigurationManager with RefreshMode PUSH, or apply a metaconfiguration), then re-apply.') @{ refresh_mode = $refreshMode; lcm_state = $lcmState; step = 'lcm' }
  return
}
if ($lcmState -match '^(Busy|Pending)') {
  Emit-Err 'lcm_conflict' ('The DSC Local Configuration Manager reports LCMState ''' + $lcmState + '''. windows_dsc_resource never changes LCM settings: wait for the current configuration operation to finish (reboot the node first when a reboot is pending), then re-apply.') @{ refresh_mode = $refreshMode; lcm_state = $lcmState; step = 'lcm' }
  return
}

$rawMods = @(Get-Module -ListAvailable -Name $modName)
# Flatten ModuleInfoGrouping wrappers: when several versions of a module
# are installed, Get-Module returns group objects that -Module parameters
# cannot convert ("Cannot convert ... ModuleInfoGrouping to ...").
$mods = @()
foreach ($m in $rawMods) {
  if ($null -ne $m.PSObject.Properties['Group']) { $mods += @($m.Group) } else { $mods += $m }
}
if ($mods.Count -eq 0) {
  Emit-Err 'module_not_found' ('DSC module ''' + $modName + ''' is not installed on the target host.') @{ module = $modName; step = 'module' }
  return
}
$mods = @($mods | Sort-Object Version -Descending)
if ($modReqVer -ne '') {
  $wantNorm = ''
  try {
    $wv = [version]$modReqVer
    $wb = if ($wv.Build -lt 0) { 0 } else { $wv.Build }
    $wr = if ($wv.Revision -lt 0) { 0 } else { $wv.Revision }
    $wantNorm = "$($wv.Major).$($wv.Minor).$wb.$wr"
  } catch {
    Emit-Err 'module_not_found' ('DSC module ''' + $modName + ''' version ''' + $modReqVer + ''' is not installed on the target host.') @{ module = $modName; wanted_version = $modReqVer; step = 'module' }
    return
  }
  $sel = @($mods | Where-Object {
    $iv = $_.Version
    $ib = if ($iv.Build -lt 0) { 0 } else { $iv.Build }
    $ir = if ($iv.Revision -lt 0) { 0 } else { $iv.Revision }
    ("$($iv.Major).$($iv.Minor).$ib.$ir" -eq $wantNorm)
  })
  if ($sel.Count -eq 0) {
    $have = ($mods | ForEach-Object { $_.Version.ToString() }) -join ', '
    Emit-Err 'module_not_found' ('DSC module ''' + $modName + ''' version ''' + $modReqVer + ''' is not installed on the target host (installed: ' + $have + ').') @{ module = $modName; wanted_version = $modReqVer; installed_versions = $have; step = 'module' }
    return
  }
  $modVerResolved = $sel[0].Version.ToString()
} else {
  $modVerResolved = $mods[0].Version.ToString()
}
# Pass a ModuleName+RequiredVersion specification rather than a module
# object: -Module only accepts ModuleSpecification-convertible values.
$modArg = @{ ModuleName = $modName; RequiredVersion = $modVerResolved }
try {
  $found = @(Get-DscResource -Name $resName -Module $modArg -ErrorAction Stop)
} catch {
  Emit-Err (Classify-DscResource $_ 'schema') ([string]$_.Exception.Message) @{ module = $modName; resource = $resName; step = 'schema' }
  return
}
if ($found.Count -eq 0) {
  Emit-Err 'resource_not_found' ('DSC resource ''' + $resName + ''' was not found in module ''' + $modName + ''' version ' + $modVerResolved + ' on the target host.') @{ module = $modName; resource = $resName; step = 'schema' }
  return
}
$r = $found[0]
$props = @($r.Properties | ForEach-Object {
  $propVals = @()
  if ($null -ne $_.Values) { $propVals = @($_.Values | ForEach-Object { [string]$_ }) }
  [ordered]@{
    name          = [string]$_.Name
    property_type = [string]$_.PropertyType
    values        = $propVals
    is_mandatory  = (Get-DSCPropFlag $_ 'IsMandatory')
    is_key        = (Get-DSCPropFlag $_ 'IsKey')
  }
})
Emit-OK ([ordered]@{
  refresh_mode   = $refreshMode
  lcm_state      = $lcmState
  module_name    = $modName
  module_version = $modVerResolved
  resource_name  = [string]$r.Name
  properties     = $props
})
`

// ---------------------------------------------------------------------------
// Invoke body (Test/Set/Get via Invoke-DscResource)
// ---------------------------------------------------------------------------

// dscInvokeBody runs one Invoke-DscResource method. Placeholders:
// @@MODULENAME@@, @@MODULEVERSION@@ (resolved, always set), @@RESOURCENAME@@,
// @@METHOD@@ ('Test', 'Set' or 'Get').
//
// Stdin carries two lines: the coerced properties JSON document, then the
// credentials JSON document ({property: {username, password}}). Both are
// rebuilt server-side; the Set/Test/Get -Property hashtable never contains
// plaintext from the script body.
const dscInvokeBody = `
$modName = @@MODULENAME@@
$modVer = @@MODULEVERSION@@
$resName = @@RESOURCENAME@@
$method = @@METHOD@@

$propsLine = [Console]::In.ReadLine()
$credsLine = [Console]::In.ReadLine()
if ([string]::IsNullOrEmpty($propsLine)) { $propsLine = '{}' }
if ([string]::IsNullOrEmpty($credsLine)) { $credsLine = '{}' }
try {
  $propsH = Convert-DscJsonToHashtable $propsLine
  $credsH = Convert-DscJsonToHashtable $credsLine
} catch {
  Emit-Err 'invalid_value' 'Could not parse the properties document sent to the target host.' @{ step = 'decode' }
  return
}
$invokeProps = @{}
foreach ($k in $propsH.Keys) { $invokeProps[$k] = $propsH[$k] }
foreach ($k in $credsH.Keys) {
  try {
    $entry = $credsH[$k]
    $sec = ConvertTo-SecureString ([string]$entry['password']) -AsPlainText -Force
    $invokeProps[$k] = New-Object System.Management.Automation.PSCredential ([string]$entry['username'], $sec)
  } catch {
    Emit-Err (Classify-DscResource $_ 'Set') ([string]$_.Exception.Message) @{ step = 'credential'; property = [string]$k }
    return
  }
}
$modArg = @{ ModuleName = $modName; RequiredVersion = $modVer }
try {
  $out = Invoke-DscResource -Name $resName -ModuleName $modArg -Method $method -Property $invokeProps -ErrorAction Stop
} catch {
  Emit-Err (Classify-DscResource $_ $method) ([string]$_.Exception.Message) @{ module = $modName; resource = $resName; step = 'invoke'; method = $method }
  return
}
if ($method -eq 'Test') {
  $desired = $false
  try { $desired = [bool]$out.InDesiredState } catch { $desired = $false }
  $rb = $false
  try { if ($null -ne $out.RebootRequired) { $rb = [bool]$out.RebootRequired } } catch { $rb = $false }
  Emit-OK ([ordered]@{ in_desired_state = $desired; reboot_required = $rb })
  return
}
if ($method -eq 'Set') {
  $rb = $false
  try { if ($null -ne $out.RebootRequired) { $rb = [bool]$out.RebootRequired } } catch { $rb = $false }
  Emit-OK ([ordered]@{ reboot_required = $rb })
  return
}
Emit-OK ([ordered]@{ state = $out })
`

// ---------------------------------------------------------------------------
// LCM gate (Go-side defence in depth; the preflight script gates too)
// ---------------------------------------------------------------------------

// dscLCMRemediation is appended to every lcm_conflict message. The gateway
// never changes LCM settings: the operator fixes the node out-of-band.
const dscLCMRemediation = "windows_dsc_resource never changes LCM settings: " +
	"switch the node to PUSH mode out-of-band (Set-DscLocalConfigurationManager " +
	"with RefreshMode PUSH, or apply a metaconfiguration) when RefreshMode is Pull, " +
	"or wait for the current configuration operation to finish (reboot the node " +
	"first when a reboot is pending), then re-apply."
