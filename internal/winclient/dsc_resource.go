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

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Compile-time assertion: DSCResourceClient satisfies
// WindowsDSCResourceClient.
var _ WindowsDSCResourceClient = (*DSCResourceClient)(nil)

// DSCResourceClient is the PowerShell/SSH-backed WindowsDSCResourceClient.
type DSCResourceClient struct {
	c *Client
}

// NewDSCResourceClient wraps the given SSH Client.
func NewDSCResourceClient(c *Client) *DSCResourceClient {
	return &DSCResourceClient{c: c}
}

// runDSCPowerShell is the package-level indirection used by
// DSCResourceClient. Tests may override it; production code must not. It
// always runs in a one-shot Windows PowerShell 5.1 process: Invoke-DscResource
// / PSDesiredStateConfiguration 1.1 do not exist in the persistent pwsh 7
// session, whose module path cannot see the inbox 5.1 DSC module. The
// stdin string carries the properties JSON document on the first line and
// the credentials JSON document on the second line; scripts that take no
// payload pass "".
var runDSCPowerShell = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	return c.RunPowerShell5WithInput(ctx, script, stdin)
}

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

// mapDSCKind converts a script-emitted kind string to DSCResourceErrorKind.
func mapDSCKind(k string) DSCResourceErrorKind {
	switch DSCResourceErrorKind(k) {
	case DSCResourceErrorModuleNotFound,
		DSCResourceErrorResourceNotFound,
		DSCResourceErrorInvalidProperty,
		DSCResourceErrorMissingProperty,
		DSCResourceErrorInvalidValue,
		DSCResourceErrorLCMConflict,
		DSCResourceErrorNotConverged,
		DSCResourceErrorSetFailed,
		DSCResourceErrorAccessDenied,
		DSCResourceErrorUnsupported:
		return DSCResourceErrorKind(k)
	default:
		return DSCResourceErrorUnknown
	}
}

// runDSCEnvelope executes script (prefixed with dscPsHeader) with the given
// stdin through the shared runEnvelope helper. Transport/PS-level errors
// that bypass Emit-Err are translated into *DSCResourceError.
func (d *DSCResourceClient) runDSCEnvelope(ctx context.Context, op, script, stdin, module, resource string, scrubContext bool) (*psResponse, error) {
	baseContext := map[string]string{"module": module, "resource": resource, "host": d.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, in string) (string, string, error) {
			return runDSCPowerShell(ctx, d.c, full, in)
		},
		op, dscPsHeader+"\n"+script, stdin, baseContext)
	if eerr == nil {
		return resp, nil
	}
	// Get output may carry credential-bearing host values: scrub
	// transport/no-envelope/invalid-JSON context for Get callers.
	// Success-path state is redacted separately by RedactDSCState.
	ctxMap := eerr.Context
	if scrubContext {
		ctxMap = nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			fmt.Sprintf("operation %q on DSC resource %q (module %q) timed out or was cancelled", op, resource, module),
			eerr.Cause,
			ctxMap,
		)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			eerr.Message,
			eerr.Cause,
			ctxMap,
		)
	}
	return resp, NewDSCResourceError(mapDSCKind(eerr.RemoteKind), eerr.Message, nil, ctxMap)
}

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

// gateDSCLCM fails closed with lcm_conflict when refreshMode is Pull or
// lcmState shows a busy/pending operation. PUSH and Disabled refresh modes
// combined with an Idle (or empty) LCM state pass. The comparison is
// case-insensitive; surrounding whitespace is ignored.
func gateDSCLCM(refreshMode, lcmState, module, resource string) error {
	if strings.EqualFold(strings.TrimSpace(refreshMode), "Pull") {
		return NewDSCResourceError(
			DSCResourceErrorLCMConflict,
			fmt.Sprintf("DSC resource %q (module %q) refused: the LCM RefreshMode is Pull. %s",
				resource, module, dscLCMRemediation),
			nil,
			map[string]string{"refresh_mode": refreshMode, "lcm_state": lcmState},
		)
	}
	s := strings.ToLower(strings.TrimSpace(lcmState))
	if s != "" && s != "idle" {
		return NewDSCResourceError(
			DSCResourceErrorLCMConflict,
			fmt.Sprintf("DSC resource %q (module %q) refused: the LCM reports LCMState %q. %s",
				resource, module, lcmState, dscLCMRemediation),
			nil,
			map[string]string{"refresh_mode": refreshMode, "lcm_state": lcmState},
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Preflight (LCM + schema)
// ---------------------------------------------------------------------------

// dscPreflightProp mirrors one property entry of the preflight JSON payload.
type dscPreflightProp struct {
	Name         string   `json:"name"`
	PropertyType string   `json:"property_type"`
	Values       []string `json:"values"`
	IsMandatory  bool     `json:"is_mandatory"`
	IsKey        bool     `json:"is_key"`
}

// dscPreflightData mirrors the JSON payload emitted by dscPreflightBody.
type dscPreflightData struct {
	RefreshMode   string             `json:"refresh_mode"`
	LCMState      string             `json:"lcm_state"`
	ModuleName    string             `json:"module_name"`
	ModuleVersion string             `json:"module_version"`
	ResourceName  string             `json:"resource_name"`
	Properties    []dscPreflightProp `json:"properties"`
}

// dscPreflight runs the LCM gate plus the scoped schema fetch and returns
// the normalised schema. A missing module or resource surfaces the typed
// module_not_found / resource_not_found errors; an LCM conflict surfaces
// lcm_conflict with remediation text.
func (d *DSCResourceClient) dscPreflight(ctx context.Context, module, version, resource string) (*DSCResourceSchema, error) {
	script := strings.NewReplacer(
		"@@MODULENAME@@", psQuote(module),
		"@@MODULEVERSION@@", psQuote(version),
		"@@RESOURCENAME@@", psQuote(resource),
	).Replace(dscPreflightBody)

	resp, err := d.runDSCEnvelope(ctx, "preflight", script, "", module, resource, false)
	if err != nil {
		return nil, err
	}
	var data dscPreflightData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC preflight JSON",
			jerr,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	if gerr := gateDSCLCM(data.RefreshMode, data.LCMState, module, resource); gerr != nil {
		return nil, gerr
	}
	schema := &DSCResourceSchema{
		ModuleName:    data.ModuleName,
		ModuleVersion: data.ModuleVersion,
		ResourceName:  data.ResourceName,
	}
	if schema.ModuleName == "" {
		schema.ModuleName = module
	}
	if schema.ResourceName == "" {
		schema.ResourceName = resource
	}
	for _, p := range data.Properties {
		schema.Properties = append(schema.Properties, DSCPropertySchema{
			Name:         p.Name,
			PropertyType: normalizeDSCType(p.PropertyType),
			Values:       p.Values,
			Mandatory:    p.IsMandatory,
			IsKey:        p.IsKey,
		})
	}
	return schema, nil
}

// ---------------------------------------------------------------------------
// Pure-Go coercion, validation, ID hash, stdin composition, redaction
// ---------------------------------------------------------------------------

// equalFoldDSC compares two DSC names case-insensitively. DSC property,
// module and resource names are case-insensitive on the host.
func equalFoldDSC(a, b string) bool {
	return strings.EqualFold(a, b)
}

// normalizeDSCType strips PowerShell type-literal brackets and lower-cases
// the name: "[string]" becomes "string", "[PSCredential]" becomes
// "pscredential", "UInt32" becomes "uint32". Array spellings ("string[]")
// keep their "[]" suffix.
func normalizeDSCType(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimPrefix(t, "[")
	t = strings.TrimSuffix(t, "]")
	return strings.ToLower(strings.TrimSpace(t))
}

// dscIsIntegerType reports whether the normalised schema type is coerced as
// an integer.
func dscIsIntegerType(pt string) bool {
	switch pt {
	case "uint16", "uint32", "uint64", "sint16", "sint32", "sint64",
		"int", "int16", "int32", "int64", "byte", "sbyte":
		return true
	default:
		return false
	}
}

// dscIsArrayType reports whether the normalised schema type is an array
// ("string[]", "uint32[]", ...).
func dscIsArrayType(pt string) bool {
	return strings.HasSuffix(pt, "[]")
}

// dscArrayBase strips the "[]" suffix from an array type name.
func dscArrayBase(pt string) string {
	return strings.TrimSuffix(pt, "[]")
}

// dscIsScalar reports whether v is a JSON scalar (string, bool or number).
func dscIsScalar(v any) bool {
	switch v.(type) {
	case string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return true
	default:
		return false
	}
}

// dscToInt64 converts a JSON number to int64. Floats must be integral;
// unsigned and narrow types are range-checked by the caller via dscIntMax.
func dscToInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case float32:
		f := float64(n)
		if f != float64(int64(f)) {
			return 0, false
		}
		return int64(f), true
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}

// dscIntMax returns the maximum value for a normalised integer schema type.
func dscIntMax(pt string) int64 {
	switch pt {
	case "byte", "uint8":
		return 255
	case "uint16":
		return 65535
	case "uint32":
		return 4294967295
	case "int8", "sbyte":
		return 127
	case "int16", "sint16":
		return 32767
	case "int32", "sint32":
		return 2147483647
	default:
		return 9223372036854775807
	}
}

// dscIntMin returns the minimum value for a normalised integer schema type.
func dscIntMin(pt string) int64 {
	switch pt {
	case "byte", "uint8", "uint16", "uint32", "uint64":
		return 0
	case "int8", "sbyte":
		return -128
	case "int16", "sint16":
		return -32768
	case "int32", "sint32":
		return -2147483648
	default:
		return -9223372036854775808
	}
}

// CoerceDSCProperties validates props against schema and returns the coerced
// property document sent to the host. Output keys use the schema canonical
// casing; null-valued inputs are dropped (treated as unset).
//
// Rules:
//   - Unknown property names are invalid_property.
//   - PSCredential-typed properties must arrive through creds (the
//     credential_properties_wo map keyed by property name), never inline:
//     an inline value is invalid_property with guidance.
//   - Mandatory schema properties (IsMandatory) with no value — neither in
//     props nor, for credentials, in creds — are missing_property.
//   - Values are coerced by normalised schema type (string, bool, integer
//     with range checks, string[]/integer[]/bool[] arrays, embedded
//     instances as one-level maps). Mismatches are invalid_value.
//   - Non-empty ValueMap lists constrain the value (case-insensitive) and
//     canonicalise string values to the schema entry; violations are
//     invalid_value.
func CoerceDSCProperties(schema *DSCResourceSchema, props map[string]any, creds map[string]DSCredential) (map[string]any, error) {
	ctx := map[string]string{"module": schema.ModuleName, "resource": schema.ResourceName}

	// Index the supplied properties case-insensitively.
	lowered := make(map[string]string, len(props))
	for name := range props {
		lowered[strings.ToLower(name)] = name
	}
	loweredCreds := make(map[string]string, len(creds))
	for name := range creds {
		loweredCreds[strings.ToLower(name)] = name
	}

	// Unknown properties fail before anything else, so a typo can never
	// silently ride along to the host.
	supplied := make([]string, 0, len(props))
	for name := range props {
		supplied = append(supplied, name)
	}
	sort.Strings(supplied)
	for _, name := range supplied {
		sp := schema.Property(name)
		if sp == nil {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("DSC resource %q (module %q) has no property %q.",
					schema.ResourceName, schema.ModuleName, name),
				nil,
				extendDSCContext(ctx, map[string]string{"property": name}),
			)
		}
		if sp.IsCredential() {
			// A credential passed inline is a distinct, guided error:
			// the value belongs in credential_properties_wo.
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("DSC property %q takes a PSCredential: pass it through credential_properties_wo[%q], never inline in properties.",
					sp.Name, sp.Name),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name}),
			)
		}
	}
	for name := range creds {
		if schema.Property(name) == nil {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("credential_properties_wo[%q] names no property of DSC resource %q (module %q).",
					name, schema.ResourceName, schema.ModuleName),
				nil,
				extendDSCContext(ctx, map[string]string{"property": name}),
			)
		}
		if !schema.Property(name).IsCredential() {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("credential_properties_wo[%q] targets DSC property %q, which is not a PSCredential: pass plain values through properties instead.",
					name, schema.Property(name).Name),
				nil,
				extendDSCContext(ctx, map[string]string{"property": name}),
			)
		}
	}

	out := make(map[string]any, len(props))
	for i := range schema.Properties {
		sp := &schema.Properties[i]
		if sp.IsCredential() {
			_, ok := loweredCreds[strings.ToLower(sp.Name)]
			if sp.Mandatory && !ok {
				return nil, NewDSCResourceError(
					DSCResourceErrorMissingProperty,
					fmt.Sprintf("DSC property %q is mandatory: pass it through credential_properties_wo[%q].",
						sp.Name, sp.Name),
					nil,
					extendDSCContext(ctx, map[string]string{"property": sp.Name}),
				)
			}
			continue
		}
		rawName, ok := lowered[strings.ToLower(sp.Name)]
		if !ok {
			if sp.Mandatory {
				return nil, NewDSCResourceError(
					DSCResourceErrorMissingProperty,
					fmt.Sprintf("DSC property %q is mandatory: set properties[%q].",
						sp.Name, sp.Name),
					nil,
					extendDSCContext(ctx, map[string]string{"property": sp.Name}),
				)
			}
			continue
		}
		v := props[rawName]
		if v == nil {
			if sp.Mandatory {
				return nil, NewDSCResourceError(
					DSCResourceErrorMissingProperty,
					fmt.Sprintf("DSC property %q is mandatory: set properties[%q] to a non-null value.",
						sp.Name, sp.Name),
					nil,
					extendDSCContext(ctx, map[string]string{"property": sp.Name}),
				)
			}
			continue
		}
		coerced, err := coerceDSCValue(sp, v, ctx)
		if err != nil {
			return nil, err
		}
		out[sp.Name] = coerced
	}
	return out, nil
}

// coerceDSCValue coerces one property value to its schema type.
func coerceDSCValue(sp *DSCPropertySchema, v any, ctx map[string]string) (any, error) {
	pt := sp.PropertyType
	if dscIsArrayType(pt) {
		items, ok := v.([]any)
		if !ok {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q takes an array of %s: got %s.",
					sp.Name, dscArrayBase(pt), dscTypeName(v)),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name}),
			)
		}
		base := dscArrayBase(pt)
		elem := &DSCPropertySchema{Name: sp.Name, PropertyType: base, Values: sp.Values}
		coerced := make([]any, 0, len(items))
		for _, item := range items {
			c, err := coerceDSCScalar(elem, item, ctx)
			if err != nil {
				return nil, err
			}
			coerced = append(coerced, c)
		}
		return coerced, nil
	}
	if dscIsIntegerType(pt) || pt == "string" || pt == "bool" || pt == "boolean" {
		return coerceDSCScalar(sp, v, ctx)
	}
	// Embedded instance: a one-level map. Nested maps inside are rejected
	// (nested-1-level support); deeper structures must be flattened by the
	// operator.
	m, ok := v.(map[string]any)
	if !ok {
		return nil, NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			fmt.Sprintf("DSC property %q takes an embedded instance (object with scalar values): got %s.",
				sp.Name, dscTypeName(v)),
			nil,
			extendDSCContext(ctx, map[string]string{"property": sp.Name}),
		)
	}
	nested := make(map[string]any, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		nv := m[k]
		if nv == nil {
			continue
		}
		if sub, ok := nv.(map[string]any); ok && len(sub) > 0 {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q supports one nesting level: nested object %q must hold only scalar or array values.",
					sp.Name, k),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
			)
		}
		if items, ok := nv.([]any); ok {
			for _, item := range items {
				if _, isMap := item.(map[string]any); isMap {
					return nil, NewDSCResourceError(
						DSCResourceErrorInvalidValue,
						fmt.Sprintf("DSC property %q supports one nesting level: nested array %q must hold only scalar values.",
							sp.Name, k),
						nil,
						extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
					)
				}
				if !dscIsScalar(item) {
					return nil, NewDSCResourceError(
						DSCResourceErrorInvalidValue,
						fmt.Sprintf("DSC property %q supports one nesting level: nested array %q must hold only scalar values, got %s.",
							sp.Name, k, dscTypeName(item)),
						nil,
						extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
					)
				}
			}
		} else if !dscIsScalar(nv) {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q supports one nesting level: nested value %q must be a scalar or an array, got %s.",
					sp.Name, k, dscTypeName(nv)),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
			)
		}
		nested[k] = nv
	}
	return nested, nil
}

// coerceDSCScalar coerces one scalar value to a string, bool or integer
// schema type and enforces the ValueMap allow-list.
func coerceDSCScalar(sp *DSCPropertySchema, v any, ctx map[string]string) (any, error) {
	pt := sp.PropertyType
	var coerced any
	switch {
	case pt == "string":
		s, ok := v.(string)
		if !ok {
			return nil, dscInvalidValue(sp, "a string", v, ctx)
		}
		coerced = s
	case pt == "bool" || pt == "boolean":
		b, ok := v.(bool)
		if !ok {
			return nil, dscInvalidValue(sp, "a boolean", v, ctx)
		}
		coerced = b
	case dscIsIntegerType(pt):
		n, ok := dscToInt64(v)
		if !ok || n < dscIntMin(pt) || n > dscIntMax(pt) {
			return nil, dscInvalidValue(sp, fmt.Sprintf("an integer in [%d, %d]", dscIntMin(pt), dscIntMax(pt)), v, ctx)
		}
		coerced = n
	default:
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			fmt.Sprintf("DSC property %q has an unrecognised schema type %q: cannot coerce the value.",
				sp.Name, sp.PropertyType),
			nil,
			extendDSCContext(ctx, map[string]string{"property": sp.Name}),
		)
	}
	if len(sp.Values) > 0 {
		s := fmt.Sprintf("%v", coerced)
		matched := false
		canonical := ""
		for _, allowed := range sp.Values {
			if strings.EqualFold(s, allowed) {
				matched = true
				canonical = allowed
				break
			}
		}
		if !matched {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q value %q is not in the ValueMap (%s).",
					sp.Name, s, strings.Join(sp.Values, ", ")),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name}),
			)
		}
		// Canonicalise string values to the schema Values entry so
		// case variants ("Present" vs "present") hash to the same
		// Terraform ID. Non-string scalars keep their typed value.
		if pt == "string" {
			return canonical, nil
		}
	}
	return coerced, nil
}

// dscInvalidValue builds an invalid_value error for a scalar coercion
// failure. The offending value itself is never echoed (it may be long, and
// only its type is diagnostic).
func dscInvalidValue(sp *DSCPropertySchema, want string, v any, ctx map[string]string) *DSCResourceError {
	return NewDSCResourceError(
		DSCResourceErrorInvalidValue,
		fmt.Sprintf("DSC property %q takes %s: got %s.", sp.Name, want, dscTypeName(v)),
		nil,
		extendDSCContext(ctx, map[string]string{"property": sp.Name}),
	)
}

// dscTypeName names the Go-dynamic type of a property value for diagnostics.
func dscTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "bool"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "number"
	case float32, float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "value"
	}
}

// extendDSCContext returns a copy of ctx with extra entries overlaid. The
// caller's map is never mutated.
func extendDSCContext(ctx map[string]string, extra map[string]string) map[string]string {
	out := make(map[string]string, len(ctx)+len(extra))
	for k, v := range ctx {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Terraform ID hash
// ---------------------------------------------------------------------------

// DSCKeyProperties selects the properties feeding the Terraform ID hash:
// the Key-marked properties present in props, else the mandatory properties
// present in props, else every supplied property. Matching is
// case-insensitive; returned keys use the schema canonical casing when
// known. Credential values never feed the ID.
func DSCKeyProperties(schema *DSCResourceSchema, props map[string]any) map[string]any {
	lowered := make(map[string]string, len(props))
	for name := range props {
		lowered[strings.ToLower(name)] = name
	}
	collect := func(names []string) map[string]any {
		out := make(map[string]any, len(names))
		for _, n := range names {
			if raw, ok := lowered[strings.ToLower(n)]; ok {
				if props[raw] != nil {
					out[n] = props[raw]
				}
			}
		}
		return out
	}
	var keys, mandatory []string
	for i := range schema.Properties {
		sp := &schema.Properties[i]
		if sp.IsCredential() {
			continue
		}
		if sp.IsKey {
			keys = append(keys, sp.Name)
		}
		if sp.Mandatory {
			mandatory = append(mandatory, sp.Name)
		}
	}
	if out := collect(keys); len(keys) > 0 && len(out) > 0 {
		return out
	}
	if out := collect(mandatory); len(mandatory) > 0 && len(out) > 0 {
		return out
	}
	// Fall back to every supplied property, sorted for determinism.
	names := make([]string, 0, len(props))
	for name, v := range props {
		if v == nil {
			continue
		}
		if sp := schema.Property(name); sp != nil && sp.IsCredential() {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make(map[string]any, len(names))
	for _, n := range names {
		out[n] = props[n]
	}
	return out
}

// BuildDSCResourceID returns the Terraform ID
// "<module>|<resource>|<sha256 hex of the canonical key-properties JSON>".
// encoding/json marshals maps with sorted keys at every level, so the hash
// is deterministic for equal key sets.
func BuildDSCResourceID(module, resource string, keyProps map[string]any) string {
	canon, err := json.Marshal(keyProps)
	if err != nil {
		canon = []byte("{}")
	}
	sum := sha256.Sum256(canon)
	return module + "|" + resource + "|" + hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Stdin composition
// ---------------------------------------------------------------------------

// ComposeDSCStdin builds the two-line stdin payload for the invoke script:
// the coerced properties JSON document, then the credentials JSON document
// ({property: {username, password}}). Usernames and passwords must not
// contain carriage return or line feed characters: the script consumes each
// line with ReadLine(), so anything from the first line break on would be
// silently truncated. An empty propertiesJSON becomes "{}".
func ComposeDSCStdin(propertiesJSON string, creds map[string]DSCredential) (string, error) {
	if strings.TrimSpace(propertiesJSON) == "" {
		propertiesJSON = "{}"
	}
	credDoc := make(map[string]map[string]string, len(creds))
	names := make([]string, 0, len(creds))
	for name := range creds {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		c := creds[name]
		if strings.ContainsAny(c.Username, "\r\n") {
			return "", NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("credential_properties_wo[%q].username must not contain carriage return or line feed characters: secrets are read with ReadLine().",
					name),
				nil,
				map[string]string{"property": name},
			)
		}
		if strings.ContainsAny(c.Password, "\r\n") {
			return "", NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("credential_properties_wo[%q].password must not contain carriage return or line feed characters: secrets are read with ReadLine().",
					name),
				nil,
				map[string]string{"property": name},
			)
		}
		if c.Username == "" {
			return "", NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("credential_properties_wo[%q].username must not be empty.", name),
				nil,
				map[string]string{"property": name},
			)
		}
		credDoc[name] = map[string]string{"username": c.Username, "password": c.Password}
	}
	credJSON, err := json.Marshal(credDoc)
	if err != nil {
		return "", NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to encode the DSC credentials document",
			err,
			nil,
		)
	}
	return propertiesJSON + "\n" + string(credJSON) + "\n", nil
}

// ---------------------------------------------------------------------------
// Get redaction
// ---------------------------------------------------------------------------

// Redacted credential values become null and null-valued keys are dropped
// from current_state_json, so secrets never reach Terraform state.

// isDSCCredentialLike reports whether a nested Get-output object looks like
// a serialised PSCredential ({UserName, Password} in any casing).
func isDSCCredentialLike(m map[string]any) bool {
	var hasUser, hasPass bool
	for k := range m {
		lk := strings.ToLower(k)
		if lk == "username" {
			hasUser = true
		}
		if lk == "password" {
			hasPass = true
		}
	}
	return hasUser && hasPass
}

// redactDSCValue recursively redacts a Get-output value: credential-like
// maps are dropped (reported as not kept), null map values are omitted at
// every level, null array elements are skipped, and nested maps and arrays
// are walked to any depth.
func redactDSCValue(v any) (any, bool) {
	if v == nil {
		return nil, false
	}
	if m, ok := v.(map[string]any); ok {
		if isDSCCredentialLike(m) {
			return nil, false
		}
		out := make(map[string]any, len(m))
		for k, nv := range m {
			if nv == nil {
				continue
			}
			if rv, ok := redactDSCValue(nv); ok {
				out[k] = rv
			}
		}
		return out, true
	}
	if arr, ok := v.([]any); ok {
		out := make([]any, 0, len(arr))
		for _, e := range arr {
			if e == nil {
				continue
			}
			if rv, ok := redactDSCValue(e); ok {
				out = append(out, rv)
			}
		}
		return out, true
	}
	return v, true
}

// RedactDSCState returns a copy of the Invoke-DscResource -Method Get output
// safe to persist: PSCredential values (including nested ones) are dropped
// and null-valued keys are omitted. Keys keep the schema canonical casing
// when known, otherwise the host casing.
func RedactDSCState(schema *DSCResourceSchema, state map[string]any) map[string]any {
	out := make(map[string]any, len(state))
	for k, v := range state {
		if v == nil {
			continue
		}
		name := k
		if sp := schema.Property(k); sp != nil {
			if sp.IsCredential() {
				continue
			}
			name = sp.Name
		}
		if m, ok := v.(map[string]any); ok {
			if rv, keep := redactDSCValue(m); keep {
				if rm, ok := rv.(map[string]any); ok {
					out[name] = rm
				} else {
					out[name] = rv
				}
			}
			continue
		}
		if arr, ok := v.([]any); ok {
			if rv, keep := redactDSCValue(arr); keep {
				out[name] = rv
			}
			continue
		}
		out[name] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Invoke helpers
// ---------------------------------------------------------------------------

// dscTestData mirrors the Test-method envelope payload.
type dscTestData struct {
	InDesiredState bool `json:"in_desired_state"`
	RebootRequired bool `json:"reboot_required"`
}

// dscSetData mirrors the Set-method envelope payload.
type dscSetData struct {
	RebootRequired bool `json:"reboot_required"`
}

// dscGetData mirrors the Get-method envelope payload.
type dscGetData struct {
	State map[string]any `json:"state"`
}

// dscInvoke runs one Invoke-DscResource method with the given coerced
// properties and credentials documents. scrubContext scrubs envelope
// error context (Get output may be credential-bearing).
func (d *DSCResourceClient) dscInvoke(ctx context.Context, method, module, version, resource, stdin string, scrubContext bool) (*psResponse, error) {
	script := strings.NewReplacer(
		"@@MODULENAME@@", psQuote(module),
		"@@MODULEVERSION@@", psQuote(version),
		"@@RESOURCENAME@@", psQuote(resource),
		"@@METHOD@@", psQuote(method),
	).Replace(dscInvokeBody)
	return d.runDSCEnvelope(ctx, "Invoke-DscResource "+method, script, stdin, module, resource, scrubContext)
}

// dscTest runs Method Test and decodes the outcome.
func (d *DSCResourceClient) dscTest(ctx context.Context, module, version, resource, stdin string) (bool, bool, error) {
	resp, err := d.dscInvoke(ctx, "Test", module, version, resource, stdin, false)
	if err != nil {
		return false, false, err
	}
	var data dscTestData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return false, false, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC Test JSON",
			jerr,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	return data.InDesiredState, data.RebootRequired, nil
}

// dscSet runs Method Set and decodes the reboot flag.
func (d *DSCResourceClient) dscSet(ctx context.Context, module, version, resource, stdin string) (bool, error) {
	resp, err := d.dscInvoke(ctx, "Set", module, version, resource, stdin, false)
	if err != nil {
		return false, err
	}
	var data dscSetData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return false, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC Set JSON",
			jerr,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	return data.RebootRequired, nil
}

// dscGet runs Method Get and decodes the live state. A JSON parse failure
// carries no response payload in its context: Get output may carry
// credential-bearing host values, so the raw document is never embedded in
// error context.
func (d *DSCResourceClient) dscGet(ctx context.Context, module, version, resource, stdin string) (map[string]any, error) {
	resp, err := d.dscInvoke(ctx, "Get", module, version, resource, stdin, true)
	if err != nil {
		return nil, err
	}
	var data dscGetData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC Get JSON",
			jerr,
			nil,
		)
	}
	if data.State == nil {
		data.State = map[string]any{}
	}
	return data.State, nil
}

// dscPrepare coerces and validates the desired properties and composes the
// stdin payload shared by Test/Set/Get. It returns the coerced properties
// (schema-canonical keys) and the two-line stdin document.
func dscPrepare(schema *DSCResourceSchema, props map[string]any, creds map[string]DSCredential) (map[string]any, string, error) {
	coerced, err := CoerceDSCProperties(schema, props, creds)
	if err != nil {
		return nil, "", err
	}
	propsJSON, jerr := json.Marshal(coerced)
	if jerr != nil {
		return nil, "", NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to encode the DSC properties document",
			jerr,
			nil,
		)
	}
	stdin, serr := ComposeDSCStdin(string(propsJSON), creds)
	if serr != nil {
		return nil, "", serr
	}
	return coerced, stdin, nil
}

// dscConverge runs the Test-driven converge loop: Test first, Set only on
// drift, then re-Test. A Set that does not converge is not_converged.
// Returns the reboot flag observed along the way.
func (d *DSCResourceClient) dscConverge(ctx context.Context, schema *DSCResourceSchema, coerced map[string]any, stdin string) (bool, error) {
	desired, rbTest, err := d.dscTest(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return false, err
	}
	if desired {
		return rbTest, nil
	}
	rbSet, err := d.dscSet(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return false, err
	}
	again, rbRetest, err := d.dscTest(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return false, err
	}
	if !again {
		keys := make([]string, 0, len(coerced))
		for k := range coerced {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return false, NewDSCResourceError(
			DSCResourceErrorNotConverged,
			fmt.Sprintf("DSC resource %q (module %q) did not converge: Set completed but the follow-up Test still reports InDesiredState=false. Inspect the resource properties outside Terraform (Test-DscConfiguration, event logs) for a resource that cannot satisfy the desired state.",
				schema.ResourceName, schema.ModuleName),
			nil,
			map[string]string{
				"module":   schema.ModuleName,
				"resource": schema.ResourceName,
				// Property names only: values never enter diagnostics.
				"properties": strings.Join(keys, ", "),
			},
		)
	}
	return rbTest || rbSet || rbRetest, nil
}

// ---------------------------------------------------------------------------
// Ensure / Read / Delete
// ---------------------------------------------------------------------------

// Ensure converges the target to the desired input (Test, then Set on drift,
// then re-Test) and returns the observed post-convergence state including
// the redacted Get output.
func (d *DSCResourceClient) Ensure(ctx context.Context, input DSCEnsureInput) (*DSCEnsureResult, error) {
	if strings.TrimSpace(input.ModuleName) == "" || strings.TrimSpace(input.ResourceName) == "" {
		return nil, NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			"module_name and resource_name must not be empty.",
			nil,
			map[string]string{"module": input.ModuleName, "resource": input.ResourceName},
		)
	}
	if input.Properties == nil {
		input.Properties = map[string]any{}
	}
	if input.Credentials == nil {
		input.Credentials = map[string]DSCredential{}
	}
	schema, err := d.dscPreflight(ctx, input.ModuleName, input.ModuleVersion, input.ResourceName)
	if err != nil {
		return nil, err
	}
	coerced, stdin, err := dscPrepare(schema, input.Properties, input.Credentials)
	if err != nil {
		return nil, err
	}
	reboot, err := d.dscConverge(ctx, schema, coerced, stdin)
	if err != nil {
		return nil, err
	}
	raw, err := d.dscGet(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return nil, err
	}
	return &DSCEnsureResult{
		ID:                    BuildDSCResourceID(schema.ModuleName, schema.ResourceName, DSCKeyProperties(schema, coerced)),
		InDesiredState:        true,
		CurrentState:          RedactDSCState(schema, raw),
		RebootRequired:        reboot,
		ResolvedModuleVersion: schema.ModuleVersion,
	}, nil
}

// Read reports the live state without changing it (Test plus Get, never
// Set). Returns (nil, nil) when the module or resource is gone from the
// host, so the resource handler can drop it from state.
func (d *DSCResourceClient) Read(ctx context.Context, input DSCEnsureInput) (*DSCEnsureResult, error) {
	if strings.TrimSpace(input.ModuleName) == "" || strings.TrimSpace(input.ResourceName) == "" {
		return nil, NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			"module_name and resource_name must not be empty.",
			nil,
			map[string]string{"module": input.ModuleName, "resource": input.ResourceName},
		)
	}
	if input.Properties == nil {
		input.Properties = map[string]any{}
	}
	if input.Credentials == nil {
		input.Credentials = map[string]DSCredential{}
	}
	schema, err := d.dscPreflight(ctx, input.ModuleName, input.ModuleVersion, input.ResourceName)
	if err != nil {
		if IsDSCResourceError(err, DSCResourceErrorModuleNotFound) ||
			IsDSCResourceError(err, DSCResourceErrorResourceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	coerced, stdin, err := dscPrepare(schema, input.Properties, input.Credentials)
	if err != nil {
		return nil, err
	}
	desired, reboot, err := d.dscTest(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return nil, err
	}
	raw, err := d.dscGet(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return nil, err
	}
	return &DSCEnsureResult{
		ID:                    BuildDSCResourceID(schema.ModuleName, schema.ResourceName, DSCKeyProperties(schema, coerced)),
		InDesiredState:        desired,
		CurrentState:          RedactDSCState(schema, raw),
		RebootRequired:        reboot,
		ResolvedModuleVersion: schema.ModuleVersion,
	}, nil
}

// Delete converges the target to the destroy configuration via Set (full
// replacement semantics: destroy_properties is the complete desired state).
// With no destroy configuration it is state-only and makes no remote call.
// A module or resource gone from the host is success.
func (d *DSCResourceClient) Delete(ctx context.Context, input DSCDeleteInput) error {
	if !input.HasDestroy {
		return nil
	}
	if strings.TrimSpace(input.ModuleName) == "" || strings.TrimSpace(input.ResourceName) == "" {
		return NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			"module_name and resource_name must not be empty.",
			nil,
			map[string]string{"module": input.ModuleName, "resource": input.ResourceName},
		)
	}
	props := input.DestroyProperties
	if props == nil {
		props = map[string]any{}
	}
	creds := input.Credentials
	if creds == nil {
		creds = map[string]DSCredential{}
	}
	schema, err := d.dscPreflight(ctx, input.ModuleName, input.ModuleVersion, input.ResourceName)
	if err != nil {
		if IsDSCResourceError(err, DSCResourceErrorModuleNotFound) ||
			IsDSCResourceError(err, DSCResourceErrorResourceNotFound) {
			return nil
		}
		return err
	}
	dscCoerced, stdin, err := dscPrepare(schema, props, creds)
	if err != nil {
		return err
	}
	_, err = d.dscConverge(ctx, schema, dscCoerced, stdin)
	return err
}
