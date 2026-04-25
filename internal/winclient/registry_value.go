// Package winclient: Windows registry value CRUD implementation over WinRM.
//
// All operations use the .NET Microsoft.Win32.Registry API via PowerShell
// (ADR-RV-1). Scripts emit a JSON envelope (Emit-OK/Emit-Err) for
// locale-independent, machine-parseable output.
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted PS
//     literal) or injected at a known concatenation point; never raw-concatenated.
//   - DWORD/QWORD values are validated as uint32/uint64 by Go before appearing
//     in PS scripts as decimal integer literals.
//   - Binary values are validated as lowercase hex by Go before appearing as
//     quoted PS string literals passed to Hex-To-Bytes.
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Compile-time assertion: RegistryValueClientImpl satisfies RegistryValueClient.
var _ RegistryValueClient = (*RegistryValueClientImpl)(nil)

// RegistryValueClientImpl is the PowerShell/WinRM-backed RegistryValueClient.
type RegistryValueClientImpl struct {
	c *Client
}

// NewRegistryValueClient constructs a RegistryValueClientImpl wrapping the given WinRM Client.
func NewRegistryValueClient(c *Client) *RegistryValueClientImpl {
	return &RegistryValueClientImpl{c: c}
}

// psRegistryValueHeader defines all PowerShell helper functions used by the
// registry value scripts. Kept in a single constant so all three operations
// (Set/Read/Delete) share identical helpers.
const psRegistryValueHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 16 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Get-RegHive([string]$Hive) {
  switch ($Hive) {
    'HKLM' { return [Microsoft.Win32.Registry]::LocalMachine }
    'HKCU' { return [Microsoft.Win32.Registry]::CurrentUser }
    'HKCR' { return [Microsoft.Win32.Registry]::ClassesRoot }
    'HKU'  { return [Microsoft.Win32.Registry]::Users }
    'HKCC' { return [Microsoft.Win32.Registry]::CurrentConfig }
    default { throw ("Unknown hive: " + $Hive) }
  }
}
function Hex-To-Bytes([string]$Hex) {
  $n = $Hex.Length / 2
  $bytes = New-Object byte[] $n
  for ($i = 0; $i -lt $Hex.Length; $i += 2) {
    $bytes[$i/2] = [Convert]::ToByte($Hex.Substring($i, 2), 16)
  }
  return $bytes
}
function Bytes-To-Hex([byte[]]$Bytes) {
  if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
  $sb = New-Object System.Text.StringBuilder ($Bytes.Length * 2)
  foreach ($b in $Bytes) { [void]$sb.Append($b.ToString('x2')) }
  return $sb.ToString()
}
function RVK-To-Kind([int]$RVK) {
  switch ($RVK) {
    1  { return 'REG_SZ' }
    2  { return 'REG_EXPAND_SZ' }
    7  { return 'REG_MULTI_SZ' }
    4  { return 'REG_DWORD' }
    11 { return 'REG_QWORD' }
    3  { return 'REG_BINARY' }
    0  { return 'REG_NONE' }
    default { return 'REG_NONE' }
  }
}
function Build-DataResult([string]$KindStr, [object]$RawVal) {
  $data = [ordered]@{
    found = $true; kind = $KindStr
    value_string = $null; value_strings = $null; value_binary = $null
  }
  switch ($KindStr) {
    'REG_SZ'        { $data['value_string'] = [string]$RawVal }
    'REG_EXPAND_SZ' { $data['value_string'] = [string]$RawVal }
    'REG_DWORD'     {
      $b4 = [System.BitConverter]::GetBytes([int]$RawVal)
      $data['value_string'] = ([System.BitConverter]::ToUInt32($b4, 0)).ToString()
    }
    'REG_QWORD'     {
      $b8 = [System.BitConverter]::GetBytes([long]$RawVal)
      $data['value_string'] = ([System.BitConverter]::ToUInt64($b8, 0)).ToString()
    }
    'REG_MULTI_SZ'  {
      if ($null -eq $RawVal) {
        $data['value_strings'] = [string[]]@()
      } else {
        $data['value_strings'] = [string[]]$RawVal
      }
    }
    default {
      if ($null -eq $RawVal) {
        $bval = [byte[]]@()
      } else {
        $bval = [byte[]]$RawVal
      }
      $data['value_binary'] = Bytes-To-Hex $bval
    }
  }
  return $data
}
`

// psRegistryValueSetBody1 is the first part of the Set PS script (up to "$valData = ").
// The value expression is injected via Go string concatenation between body1 and body2.
// Placeholders @@HIVE@@, @@PATH@@, @@NAME@@, @@KIND@@ are replaced by strings.NewReplacer.
const psRegistryValueSetBody1 = `
& {
  $_rvKey = $null
  try {
    $root = Get-RegHive @@HIVE@@
    $_rvKey = $root.CreateSubKey(@@PATH@@)
    if ($null -eq $_rvKey) {
      Emit-Err 'permission_denied' 'CreateSubKey returned null (insufficient privileges)' @{}
      return
    }
    $existProbe = $_rvKey.GetValue(@@NAME@@, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -ne $existProbe) {
      $existKindStr = ''
      try { $existKindStr = RVK-To-Kind ([int]$_rvKey.GetValueKind(@@NAME@@)) } catch [System.IO.IOException] {}
      if ($existKindStr -ne '' -and $existKindStr -ne @@KIND@@) {
        Emit-Err 'type_conflict' ('type_conflict: existing=' + $existKindStr + ' declared=' + @@KIND@@) @{ existing_type=$existKindStr; declared_type=@@KIND@@ }
        return
      }
    }
    $rvk = switch (@@KIND@@) {
      'REG_SZ'        { [Microsoft.Win32.RegistryValueKind]::String }
      'REG_EXPAND_SZ' { [Microsoft.Win32.RegistryValueKind]::ExpandString }
      'REG_MULTI_SZ'  { [Microsoft.Win32.RegistryValueKind]::MultiString }
      'REG_DWORD'     { [Microsoft.Win32.RegistryValueKind]::DWord }
      'REG_QWORD'     { [Microsoft.Win32.RegistryValueKind]::QWord }
      'REG_BINARY'    { [Microsoft.Win32.RegistryValueKind]::Binary }
      'REG_NONE'      { [Microsoft.Win32.RegistryValueKind]::None }
    }
    $valData = `

// psRegistryValueSetBody2 is the second part of the Set PS script (after the value expression).
const psRegistryValueSetBody2 = `
    $_rvKey.SetValue(@@NAME@@, $valData, $rvk)
    $postKindStr = RVK-To-Kind ([int]$_rvKey.GetValueKind(@@NAME@@))
    $opts = if (@@EXPAND@@) { [Microsoft.Win32.RegistryValueOptions]::None } else { [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames }
    $postRaw = $_rvKey.GetValue(@@NAME@@, $null, $opts)
    Emit-OK (Build-DataResult $postKindStr $postRaw)
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_rvKey) { $_rvKey.Close() }
  }
}
`

// psRegistryValueReadBody is the Read PS script template.
// Placeholders @@HIVE@@, @@PATH@@, @@NAME@@, @@EXPAND@@ replaced by strings.NewReplacer.
const psRegistryValueReadBody = `
& {
  $_rvKey = $null
  try {
    $root = Get-RegHive @@HIVE@@
    $_rvKey = $root.OpenSubKey(@@PATH@@, $false)
    if ($null -eq $_rvKey) {
      Emit-OK @{ found = $false }
      return
    }
    $kindEnum = $null
    try {
      $kindEnum = $_rvKey.GetValueKind(@@NAME@@)
    } catch [System.IO.IOException] {
      Emit-OK @{ found = $false }
      return
    }
    $kindStr = RVK-To-Kind ([int]$kindEnum)
    $opts = if (@@EXPAND@@) { [Microsoft.Win32.RegistryValueOptions]::None } else { [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames }
    $rawVal = $_rvKey.GetValue(@@NAME@@, $null, $opts)
    Emit-OK (Build-DataResult $kindStr $rawVal)
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_rvKey) { $_rvKey.Close() }
  }
}
`

// psRegistryValueDeleteBody is the Delete PS script template.
// Placeholders @@HIVE@@, @@PATH@@, @@NAME@@ replaced by strings.NewReplacer.
const psRegistryValueDeleteBody = `
& {
  $_rvKey = $null
  try {
    $root = Get-RegHive @@HIVE@@
    $_rvKey = $root.OpenSubKey(@@PATH@@, $true)
    if ($null -eq $_rvKey) {
      Emit-OK @{ deleted = $false; reason = 'key_not_found' }
      return
    }
    $_rvKey.DeleteValue(@@NAME@@, $false)
    Emit-OK @{ deleted = $true }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_rvKey) { $_rvKey.Close() }
  }
}
`

// runRegistryValuePowerShell is the package-level hook for test substitution.
// Production code must not reassign this outside tests.
var runRegistryValuePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// rvPSResponse is the parsed JSON envelope for registry value operations.
type rvPSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// rvDataPayload mirrors the JSON object returned by Set and Read PS scripts.
// ValueStrings is json.RawMessage to handle the PowerShell ConvertTo-Json
// quirk where a single-element [string[]] may be serialised as a scalar string.
type rvDataPayload struct {
	Found        bool            `json:"found"`
	Kind         string          `json:"kind"`
	ValueString  *string         `json:"value_string"`
	ValueStrings json.RawMessage `json:"value_strings"`
	ValueBinary  *string         `json:"value_binary"`
}

// runScript executes a PS script and parses the JSON envelope.
func (r *RegistryValueClientImpl) runScript(ctx context.Context, op, script string) (*rvPSResponse, error) {
	stdout, stderr, err := runRegistryValuePowerShell(ctx, r.c, script)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &RegistryValueError{
				Kind:    RegistryValueErrorUnknown,
				Message: fmt.Sprintf("operation %q timed out or was cancelled", op),
				Cause:   ctxErr,
				Context: map[string]string{"operation": op, "host": r.c.cfg.Host},
			}
		}
		return nil, &RegistryValueError{
			Kind:    RegistryValueErrorUnknown,
			Message: fmt.Sprintf("powershell transport error during %q", op),
			Cause:   err,
			Context: map[string]string{
				"operation": op, "host": r.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		}
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, &RegistryValueError{
			Kind:    RegistryValueErrorUnknown,
			Message: fmt.Sprintf("no JSON envelope returned from %q", op),
			Context: map[string]string{
				"operation": op, "host": r.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		}
	}

	var resp rvPSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, &RegistryValueError{
			Kind:    RegistryValueErrorUnknown,
			Message: fmt.Sprintf("invalid JSON envelope from %q", op),
			Cause:   jerr,
			Context: map[string]string{"operation": op, "stdout": truncate(stdout, 2048)},
		}
	}

	if !resp.OK {
		kind := mapRegistryValueErrorKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["host"] = r.c.cfg.Host
		return &resp, &RegistryValueError{Kind: kind, Message: resp.Message, Context: ctxMap}
	}
	return &resp, nil
}

// mapRegistryValueErrorKind translates the PS-side "kind" string to a typed RegistryValueErrorKind.
func mapRegistryValueErrorKind(k string) RegistryValueErrorKind {
	switch k {
	case string(RegistryValueErrorNotFound),
		string(RegistryValueErrorTypeConflict),
		string(RegistryValueErrorPermission),
		string(RegistryValueErrorInvalidInput):
		return RegistryValueErrorKind(k)
	default:
		return RegistryValueErrorUnknown
	}
}

// buildPSValueExpr returns the PowerShell expression that assigns the correct
// .NET-typed value to $valData for a SetValue call.
//
// Security: only validated decimal strings (DWORD/QWORD) and psQuote-escaped
// strings reach the PS script. User data never appears as unquoted PS syntax.
func buildPSValueExpr(input RegistryValueInput) (string, error) {
	switch input.Kind {
	case RegistryValueKindString, RegistryValueKindExpandString:
		if input.ValueString == nil {
			return "", &RegistryValueError{Kind: RegistryValueErrorInvalidInput,
				Message: fmt.Sprintf("ValueString is required for %s", input.Kind)}
		}
		return psQuote(*input.ValueString), nil

	case RegistryValueKindDWord:
		if input.ValueString == nil {
			return "", &RegistryValueError{Kind: RegistryValueErrorInvalidInput,
				Message: "ValueString is required for REG_DWORD"}
		}
		u32, err := strconv.ParseUint(*input.ValueString, 10, 32)
		if err != nil {
			return "", &RegistryValueError{Kind: RegistryValueErrorInvalidInput,
				Message: fmt.Sprintf("invalid REG_DWORD value %q", *input.ValueString), Cause: err}
		}
		// Convert to int32 bit-pattern for .NET SetValue(name, int32, DWord).
		return fmt.Sprintf("([System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]%d), 0))", u32), nil

	case RegistryValueKindQWord:
		if input.ValueString == nil {
			return "", &RegistryValueError{Kind: RegistryValueErrorInvalidInput,
				Message: "ValueString is required for REG_QWORD"}
		}
		u64, err := strconv.ParseUint(*input.ValueString, 10, 64)
		if err != nil {
			return "", &RegistryValueError{Kind: RegistryValueErrorInvalidInput,
				Message: fmt.Sprintf("invalid REG_QWORD value %q", *input.ValueString), Cause: err}
		}
		// Use ::Parse to avoid PS literal overflow for values > Int64.MaxValue.
		return fmt.Sprintf("([System.BitConverter]::ToInt64([System.BitConverter]::GetBytes([uint64]::Parse('%s')), 0))",
			strconv.FormatUint(u64, 10)), nil

	case RegistryValueKindMultiString:
		strs := input.ValueStrings
		if strs == nil {
			strs = []string{}
		}
		return "[string[]]" + psQuoteList(strs), nil

	case RegistryValueKindBinary, RegistryValueKindNone:
		hex := ""
		if input.ValueBinary != nil {
			hex = *input.ValueBinary
		}
		if hex == "" {
			return "[byte[]]@()", nil
		}
		return fmt.Sprintf("(Hex-To-Bytes %s)", psQuote(hex)), nil

	default:
		return "", &RegistryValueError{Kind: RegistryValueErrorInvalidInput,
			Message: fmt.Sprintf("unknown RegistryValueKind: %s", input.Kind)}
	}
}

// parseMultiStringPayload handles the PS ConvertTo-Json quirk where a
// single-element [string[]] may be serialised as a JSON string scalar rather
// than a JSON array.
func parseMultiStringPayload(raw json.RawMessage) ([]string, error) {
	if raw == nil || string(raw) == "null" {
		return []string{}, nil // EC-10: treat absent as empty
	}
	// Preferred: JSON array.
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	// Fallback: single JSON string (PS single-element array serialisation quirk).
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}, nil
	}
	return nil, fmt.Errorf("cannot parse value_strings from JSON: %s", string(raw))
}

// parseDataPayload converts the JSON data blob from a Set/Read PS script into
// a *RegistryValueState.  Returns nil when found=false.
func (r *RegistryValueClientImpl) parseDataPayload(raw json.RawMessage, hive, regPath, name string) (*RegistryValueState, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var payload rvDataPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &RegistryValueError{Kind: RegistryValueErrorUnknown,
			Message: "failed to parse registry value payload", Cause: err}
	}
	if !payload.Found {
		return nil, nil
	}

	state := &RegistryValueState{
		Hive: hive,
		Path: regPath,
		Name: name,
		Kind: RegistryValueKind(payload.Kind),
	}

	switch state.Kind {
	case RegistryValueKindMultiString:
		strs, err := parseMultiStringPayload(payload.ValueStrings)
		if err != nil {
			return nil, &RegistryValueError{Kind: RegistryValueErrorUnknown, Message: err.Error()}
		}
		state.ValueStrings = strs

	case RegistryValueKindBinary, RegistryValueKindNone:
		if payload.ValueBinary != nil {
			state.ValueBinary = payload.ValueBinary
		} else {
			empty := ""
			state.ValueBinary = &empty
		}

	default:
		state.ValueString = payload.ValueString
	}

	return state, nil
}

// Set implements RegistryValueClient.Set.
//
// Creates missing parent keys (EC-1), enforces type-conflict guard (EC-3),
// writes the value, and returns the post-write state.
func (r *RegistryValueClientImpl) Set(ctx context.Context, input RegistryValueInput) (*RegistryValueState, error) {
	valueExpr, err := buildPSValueExpr(input)
	if err != nil {
		return nil, err
	}

	repl := strings.NewReplacer(
		"@@HIVE@@", psQuote(input.Hive),
		"@@PATH@@", psQuote(input.Path),
		"@@NAME@@", psQuote(input.Name),
		"@@KIND@@", psQuote(string(input.Kind)),
		"@@EXPAND@@", "$"+psBool(input.ExpandEnvironmentVariables),
	)

	script := psRegistryValueHeader + "\n" +
		repl.Replace(psRegistryValueSetBody1) +
		valueExpr +
		repl.Replace(psRegistryValueSetBody2)

	resp, err := r.runScript(ctx, "set", script)
	if err != nil {
		return nil, err
	}

	return r.parseDataPayload(resp.Data, input.Hive, input.Path, input.Name)
}

// Read implements RegistryValueClient.Read.
//
// Returns (nil, nil) when the key or value does not exist (EC-4).
// The resource Read handler must call resp.State.RemoveResource() in that case.
func (r *RegistryValueClientImpl) Read(ctx context.Context, hive, regPath, name string, expandEnvVars bool) (*RegistryValueState, error) {
	repl := strings.NewReplacer(
		"@@HIVE@@", psQuote(hive),
		"@@PATH@@", psQuote(regPath),
		"@@NAME@@", psQuote(name),
		"@@EXPAND@@", "$"+psBool(expandEnvVars),
	)

	script := psRegistryValueHeader + "\n" + repl.Replace(psRegistryValueReadBody)

	resp, err := r.runScript(ctx, "read", script)
	if err != nil {
		// Distinguish not_found from real errors.
		if IsRegistryValueError(err, RegistryValueErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return r.parseDataPayload(resp.Data, hive, regPath, name)
}

// Delete implements RegistryValueClient.Delete.
//
// Idempotent: a missing value or parent key is a silent no-op (EC-12).
func (r *RegistryValueClientImpl) Delete(ctx context.Context, hive, regPath, name string) error {
	repl := strings.NewReplacer(
		"@@HIVE@@", psQuote(hive),
		"@@PATH@@", psQuote(regPath),
		"@@NAME@@", psQuote(name),
	)

	script := psRegistryValueHeader + "\n" + repl.Replace(psRegistryValueDeleteBody)

	_, err := r.runScript(ctx, "delete", script)
	if err != nil {
		// Idempotent: treat not_found as success.
		if IsRegistryValueError(err, RegistryValueErrorNotFound) {
			return nil
		}
		return err
	}
	return nil
}

// Ensure errors package is used (for IsRegistryValueError).
var _ = errors.As
