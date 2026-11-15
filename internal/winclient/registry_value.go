// Package winclient: Windows registry value CRUD implementation over SSH.
//
// All operations use the .NET Microsoft.Win32.Registry API via PowerShell
// (ADR-RV-1). Scripts emit a JSON envelope (Emit-OK/Emit-Err) for
// locale-independent, machine-parseable output.
//
// Security invariants:
//   - Hive, path, name and kind are interpolated via psQuote (single-quoted
//     PS literal); never raw-concatenated.
//   - Value payloads (value_string, value_strings, value_binary) are Sensitive
//     and NEVER appear in the script body. They travel as JSON on stdin via
//     RunPowerShellWithInput and are decoded remote-side with
//     [Console]::In.ReadToEnd() | ConvertFrom-Json (multi-line safe).
//   - DWORD/QWORD values are validated as uint32/uint64 by Go before transport
//     and converted to .NET int32/int64 bit-patterns remote-side.
//   - Binary values are validated as lowercase hex by the provider schema;
//     the remote Hex-To-Bytes conversion never echoes the payload.
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

// RegistryValueClientImpl is the PowerShell/SSH-backed RegistryValueClient.
type RegistryValueClientImpl struct {
	c *Client
}

// NewRegistryValueClient constructs a RegistryValueClientImpl wrapping the given SSH Client.
func NewRegistryValueClient(c *Client) *RegistryValueClientImpl {
	return &RegistryValueClientImpl{c: c}
}

// psRegistryValueHeader defines all PowerShell helper functions used by the
// registry value scripts. Kept in a single constant so all three operations
// (Set/Read/Delete) share identical helpers.
const psRegistryValueHeader = psEnvelopePrelude + psRegistryValueHeaderRemainder

// psRegistryValueHeaderRemainder Hive helpers stay here; envelope emitters come from the prelude. Emit-OK depth 16->8: payloads are flat dicts and string lists (depth <= 3).
const psRegistryValueHeaderRemainder = `function Get-RegHive([string]$Hive) {
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
  # Comma operator prevents the pipeline from enumerating $bytes into
  # Object[]; without it SetValue(..., RegistryValueKind.Binary) rejects
  # the value with "type of the value object did not match".
  return ,$bytes
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

// psRegistryValueSetBody is the Set PS script template. The secret value
// payload arrives as JSON on stdin ($rvInput, decoded with
// ReadToEnd+ConvertFrom-Json) and is materialised into the .NET-typed
// $valData here; only hive/path/name/kind travel in the script body.
// Placeholders @@HIVE@@, @@PATH@@, @@NAME@@, @@KIND@@, @@EXPAND@@ are
// replaced by strings.NewReplacer. A stdin JSON parse failure is
// invalid_input and never echoes the payload.
const psRegistryValueSetBody = `
& {
  $_rvKey = $null
  try {
    try { $rvRaw = [Console]::In.ReadToEnd() } catch {
      Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
      return
    }
    if ([string]::IsNullOrWhiteSpace($rvRaw)) {
      Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
      return
    }
    try { $rvInput = ($rvRaw | ConvertFrom-Json) } catch {
      Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
      return
    }
    if ($null -eq $rvInput) {
      Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
      return
    }
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
    switch (@@KIND@@) {
      'REG_SZ'        {
        if ($null -eq $rvInput.value_string) {
          Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
          return
        }
        $valData = [string]$rvInput.value_string
      }
      'REG_EXPAND_SZ' {
        if ($null -eq $rvInput.value_string) {
          Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
          return
        }
        $valData = [string]$rvInput.value_string
      }
      'REG_DWORD'     {
        if ($null -eq $rvInput.value_string) {
          Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
          return
        }
        $valData = ([System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]$rvInput.value_string), 0))
      }
      'REG_QWORD'     {
        if ($null -eq $rvInput.value_string) {
          Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
          return
        }
        $valData = ([System.BitConverter]::ToInt64([System.BitConverter]::GetBytes([uint64]$rvInput.value_string), 0))
      }
      'REG_MULTI_SZ'  {
        if ($null -eq $rvInput.value_strings) { $valData = [string[]]@() }
        else { $valData = [string[]]$rvInput.value_strings }
      }
      default {
        if ($null -eq $rvInput.value_binary) {
          Emit-Err 'invalid_input' 'invalid registry value payload on stdin' @{}
          return
        }
        $rvHex = [string]$rvInput.value_binary
        if ([string]::IsNullOrEmpty($rvHex)) { $valData = [byte[]]@() }
        else { $valData = (Hex-To-Bytes $rvHex) }
      }
    }
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
// Production code must not reassign this outside tests. When stdin is empty
// the plain RunPowerShell path is used.
var runRegistryValuePowerShell = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	if stdin == "" {
		return c.RunPowerShell(ctx, script)
	}
	return c.RunPowerShellWithInput(ctx, script, stdin)
}

// rvPSResponse is the parsed JSON envelope for registry value operations. It
// aliases the shared Envelope type so every resource parses the same shape
// through runEnvelope (#198).
type rvPSResponse = Envelope

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

// runScript executes a PS script and parses the JSON envelope through the
// shared runEnvelope helper (#198). stdin carries the secret value payload
// for Set and is never copied into error context or logs.
func (r *RegistryValueClientImpl) runScript(ctx context.Context, op, script, stdin string) (*rvPSResponse, error) {
	baseContext := map[string]string{"host": r.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runRegistryValuePowerShell(ctx, r.c, full, stdin)
		},
		op, script, stdin, baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, &RegistryValueError{Resource: "windows_registry_value",
			Kind:    RegistryValueErrorUnknown,
			Message: eerr.Message,
			Cause:   eerr.Cause,
			Context: eerr.Context,
		}
	}
	return resp, &RegistryValueError{Resource: "windows_registry_value", Kind: string(mapRegistryValueErrorKind(eerr.RemoteKind)), Message: eerr.Message, Context: eerr.Context}
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

// rvSetStdin is the JSON document streamed on stdin for Set. It carries the
// Sensitive value payload (value_string, value_strings, value_binary) so the
// secret never appears in the script body; the script decodes it with
// ReadToEnd+ConvertFrom-Json and builds the .NET-typed value remote-side.
type rvSetStdin struct {
	ValueString  *string  `json:"value_string,omitempty"`
	ValueStrings []string `json:"value_strings,omitempty"`
	ValueBinary  *string  `json:"value_binary,omitempty"`
}

// isRVHexDigits reports whether s consists only of ASCII hex digits. It backs
// the Go-side REG_BINARY/REG_NONE validation in buildRVSetStdin so malformed
// payloads fail closed as invalid_input without echoing the value.
func isRVHexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

// buildRVSetStdin validates the Set input and encodes the secret value
// payload as JSON for stdin transport.
//
// Security: DWORD/QWORD decimal strings are validated as uint32/uint64 by Go
// here (and canonicalised), so the remote [uint32]/[uint64] conversion cannot
// fail on malformed input. User data never reaches the PS script as code.
func buildRVSetStdin(input RegistryValueInput) (string, error) {
	payload := rvSetStdin{}
	switch input.Kind {
	case RegistryValueKindString, RegistryValueKindExpandString:
		if input.ValueString == nil {
			return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
				Message: fmt.Sprintf("ValueString is required for %s", input.Kind)}
		}
		payload.ValueString = input.ValueString

	case RegistryValueKindDWord:
		if input.ValueString == nil {
			return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
				Message: "ValueString is required for REG_DWORD"}
		}
		u32, err := strconv.ParseUint(*input.ValueString, 10, 32)
		if err != nil {
			return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
				Message: "invalid REG_DWORD value: must be decimal 0..4294967295", Cause: err}
		}
		s := strconv.FormatUint(u32, 10)
		payload.ValueString = &s

	case RegistryValueKindQWord:
		if input.ValueString == nil {
			return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
				Message: "ValueString is required for REG_QWORD"}
		}
		u64, err := strconv.ParseUint(*input.ValueString, 10, 64)
		if err != nil {
			return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
				Message: "invalid REG_QWORD value: must be decimal 0..18446744073709551615", Cause: err}
		}
		s := strconv.FormatUint(u64, 10)
		payload.ValueString = &s

	case RegistryValueKindMultiString:
		strs := input.ValueStrings
		if strs == nil {
			strs = []string{}
		}
		payload.ValueStrings = strs

	case RegistryValueKindBinary, RegistryValueKindNone:
		hex := ""
		if input.ValueBinary != nil {
			hex = *input.ValueBinary
		}
		if hex == "" {
			empty := ""
			payload.ValueBinary = &empty
		} else {
			if len(hex)%2 != 0 || !isRVHexDigits(hex) {
				return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
					Message: fmt.Sprintf("invalid %s value: must be even-length hex digits", input.Kind)}
			}
			payload.ValueBinary = input.ValueBinary
		}

	default:
		return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
			Message: fmt.Sprintf("unknown RegistryValueKind: %s", input.Kind)}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorInvalidInput,
			Message: "cannot encode registry value payload", Cause: err}
	}
	return string(raw), nil
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
		return nil, &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorUnknown,
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
			return nil, &RegistryValueError{Resource: "windows_registry_value", Kind: RegistryValueErrorUnknown, Message: err.Error()}
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
// writes the value, and returns the post-write state. The secret value
// payload travels as JSON on stdin, never in the script body.
func (r *RegistryValueClientImpl) Set(ctx context.Context, input RegistryValueInput) (*RegistryValueState, error) {
	stdin, err := buildRVSetStdin(input)
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

	script := psRegistryValueHeader + "\n" + repl.Replace(psRegistryValueSetBody)

	resp, err := r.runScript(ctx, "set", script, stdin)
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

	resp, err := r.runScript(ctx, "read", script, "")
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

	_, err := r.runScript(ctx, "delete", script, "")
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
