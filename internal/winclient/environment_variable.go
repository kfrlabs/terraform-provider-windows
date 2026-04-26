// Package winclient: Windows environment variable CRUD implementation over WinRM.
//
// Uses the .NET Microsoft.Win32.Registry API via PowerShell (ADR-EV-1).
// Scripts emit a JSON envelope (Emit-OK/Emit-Err) for locale-independent,
// machine-parseable output.
//
// Security invariants:
//   - All user-supplied strings (name, value) are interpolated via psQuote
//     (single-quoted PS literal) — no raw concatenation of user input.
//   - Scripts are sent via -EncodedCommand (UTF-16LE base64) by Client.RunPowerShell.
//   - WM_SETTINGCHANGE broadcast failure is non-fatal (ADR-EV-2).
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: EnvVarClientImpl satisfies EnvVarClient.
var _ EnvVarClient = (*EnvVarClientImpl)(nil)

// EnvVarClientImpl is the PowerShell/WinRM-backed EnvVarClient.
type EnvVarClientImpl struct {
	c *Client
}

// NewEnvVarClient constructs an EnvVarClientImpl wrapping the given WinRM Client.
func NewEnvVarClient(c *Client) *EnvVarClientImpl {
	return &EnvVarClientImpl{c: c}
}

// registryPathForScope returns the .NET hive identifier and the subkey path
// for the given scope. Returns an error for unknown scope values.
//
//	machine -> ("LocalMachine", "SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
//	user    -> ("CurrentUser",  "Environment")
func registryPathForScope(scope EnvVarScope) (hiveIdent string, subkeyPath string, err error) {
	switch scope {
	case EnvVarScopeMachine:
		return "LocalMachine",
			`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`,
			nil
	case EnvVarScopeUser:
		return "CurrentUser", "Environment", nil
	default:
		return "", "", fmt.Errorf("winclient: unknown EnvVarScope %q", scope)
	}
}

// psEnvVarHeader is prepended to every env-var script.
// Defines Emit-OK, Emit-Err, and Send-EnvBroadcast helpers.
//
// Send-EnvBroadcast compiles an inline C# P/Invoke for SendMessageTimeout
// (user32.dll) and broadcasts WM_SETTINGCHANGE. Compilation failure and
// broadcast failure are both caught and returned as a warning string so that
// the overall operation is never failed solely due to broadcast issues (ADR-EV-2).
const psEnvVarHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Send-EnvBroadcast {
  try {
    if (-not ([System.Management.Automation.PSTypeName]'Win32EnvBroadcast').Type) {
      $cs = 'using System; using System.Runtime.InteropServices; public class Win32EnvBroadcast { [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult); }'
      Add-Type -TypeDefinition $cs -Language CSharp
    }
    [UIntPtr]$lResult = [UIntPtr]::Zero
    [IntPtr]$hBroadcast = [IntPtr]0xFFFF
    [uint32]$wmMsg = 0x001A
    [uint32]$smtoFlags = 0x0002
    $ret = [Win32EnvBroadcast]::SendMessageTimeout($hBroadcast, $wmMsg, [UIntPtr]::Zero, 'Environment', $smtoFlags, 5000, [ref]$lResult)
    if ($ret -eq 0) {
      return 'SendMessageTimeout returned 0 (timeout or broadcast error)'
    }
    return ''
  } catch {
    return $_.Exception.Message
  }
}
`

// psEnvVarSetBody is the Set (Create/Update) PS script body.
// Placeholders: @@HIVE_IDENT@@, @@SUBKEY@@, @@SCOPE@@, @@NAME@@, @@VALUE@@, @@EXPAND@@
const psEnvVarSetBody = `
& {
  $_evKey = $null
  try {
    $root = [Microsoft.Win32.Registry]::@@HIVE_IDENT@@
    $_evKey = $root.OpenSubKey(@@SUBKEY@@, $true)
    if ($null -eq $_evKey) {
      Emit-Err 'invalid_input' 'Environment registry key not found for scope @@SCOPE_RAW@@ — possible OS corruption' @{ scope=@@SCOPE@@ }
      return
    }
    $targetKind = if (@@EXPAND@@) { [Microsoft.Win32.RegistryValueKind]::ExpandString } else { [Microsoft.Win32.RegistryValueKind]::String }
    $existKind = $null
    $existVal  = $null
    try {
      $existKind = $_evKey.GetValueKind(@@NAME@@)
      $existVal  = $_evKey.GetValue(@@NAME@@, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } catch [System.IO.IOException] {}
    $skipWrite = ($null -ne $existKind -and $existKind -eq $targetKind -and $existVal -ceq @@VALUE@@)
    if (-not $skipWrite) {
      $_evKey.SetValue(@@NAME@@, @@VALUE@@, $targetKind)
    }
    $postKind = $_evKey.GetValueKind(@@NAME@@)
    $postVal  = $_evKey.GetValue(@@NAME@@, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -eq $postVal) { $postVal = '' }
    $postExpand = ($postKind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString)
    $bcastWarn = ''
    if (-not $skipWrite) { $bcastWarn = Send-EnvBroadcast }
    Emit-OK @{ value=$postVal; expand=$postExpand; broadcast_warning=$bcastWarn }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_evKey) { $_evKey.Close() }
  }
}
`

// psEnvVarReadBody is the Read PS script body.
// Placeholders: @@HIVE_IDENT@@, @@SUBKEY@@, @@NAME@@
const psEnvVarReadBody = `
& {
  $_evKey = $null
  try {
    $root = [Microsoft.Win32.Registry]::@@HIVE_IDENT@@
    $_evKey = $root.OpenSubKey(@@SUBKEY@@, $false)
    if ($null -eq $_evKey) {
      Emit-OK @{ found=$false }
      return
    }
    $kind = $null
    try {
      $kind = $_evKey.GetValueKind(@@NAME@@)
    } catch [System.IO.IOException] {
      Emit-OK @{ found=$false }
      return
    }
    if ($kind -ne [Microsoft.Win32.RegistryValueKind]::String -and $kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) {
      Emit-Err 'unknown' ('Unexpected registry value kind: ' + $kind.ToString()) @{ actual_kind=$kind.ToString() }
      return
    }
    $raw = $_evKey.GetValue(@@NAME@@, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -eq $raw) { $raw = '' }
    $expand = ($kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString)
    Emit-OK @{ found=$true; value=$raw; expand=$expand }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_evKey) { $_evKey.Close() }
  }
}
`

// psEnvVarDeleteBody is the Delete PS script body.
// Placeholders: @@HIVE_IDENT@@, @@SUBKEY@@, @@NAME@@
const psEnvVarDeleteBody = `
& {
  $_evKey = $null
  try {
    $root = [Microsoft.Win32.Registry]::@@HIVE_IDENT@@
    $_evKey = $root.OpenSubKey(@@SUBKEY@@, $true)
    if ($null -eq $_evKey) {
      Emit-OK @{ deleted=$false; reason='key_not_found'; broadcast_warning='' }
      return
    }
    $wasPresent = $false
    try {
      $_evKey.GetValueKind(@@NAME@@) | Out-Null
      $wasPresent = $true
    } catch [System.IO.IOException] {}
    $_evKey.DeleteValue(@@NAME@@, $false)
    $bcastWarn = ''
    if ($wasPresent) { $bcastWarn = Send-EnvBroadcast }
    Emit-OK @{ deleted=$wasPresent; broadcast_warning=$bcastWarn }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_evKey) { $_evKey.Close() }
  }
}
`

// runEnvVarPowerShell is the package-level hook for test substitution.
var runEnvVarPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// evPSResponse is the parsed JSON envelope for env var operations.
type evPSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// evSetData mirrors the JSON object returned by the Set PS script.
type evSetData struct {
	Value            string `json:"value"`
	Expand           bool   `json:"expand"`
	BroadcastWarning string `json:"broadcast_warning"`
}

// evReadData mirrors the JSON object returned by the Read PS script.
type evReadData struct {
	Found  bool   `json:"found"`
	Value  string `json:"value"`
	Expand bool   `json:"expand"`
}

// runScript executes a PS script and parses the JSON envelope.
func (e *EnvVarClientImpl) runScript(ctx context.Context, op, script string) (*evPSResponse, error) {
	stdout, stderr, err := runEnvVarPowerShell(ctx, e.c, script)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &EnvVarError{
				Kind:    EnvVarErrorUnknown,
				Message: fmt.Sprintf("operation %q timed out or was cancelled", op),
				Cause:   ctxErr,
				Context: map[string]string{"operation": op, "host": e.c.cfg.Host},
			}
		}
		return nil, &EnvVarError{
			Kind:    EnvVarErrorUnknown,
			Message: fmt.Sprintf("powershell transport error during %q", op),
			Cause:   err,
			Context: map[string]string{
				"operation": op,
				"host":      e.c.cfg.Host,
				"stderr":    truncate(stderr, 2048),
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, &EnvVarError{
			Kind:    EnvVarErrorUnknown,
			Message: fmt.Sprintf("no JSON envelope returned from %q", op),
			Context: map[string]string{
				"operation": op,
				"host":      e.c.cfg.Host,
				"stderr":    truncate(stderr, 2048),
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	var resp evPSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, &EnvVarError{
			Kind:    EnvVarErrorUnknown,
			Message: fmt.Sprintf("invalid JSON envelope from %q", op),
			Cause:   jerr,
			Context: map[string]string{"operation": op, "stdout": truncate(stdout, 2048)},
		}
	}

	if !resp.OK {
		kind := mapEnvVarErrorKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["host"] = e.c.cfg.Host
		return &resp, &EnvVarError{Kind: kind, Message: resp.Message, Context: ctxMap}
	}
	return &resp, nil
}

// mapEnvVarErrorKind translates the PS-side "kind" string to a typed EnvVarErrorKind.
func mapEnvVarErrorKind(k string) EnvVarErrorKind {
	switch k {
	case string(EnvVarErrorNotFound),
		string(EnvVarErrorPermission),
		string(EnvVarErrorInvalidInput):
		return EnvVarErrorKind(k)
	default:
		return EnvVarErrorUnknown
	}
}

// Set implements EnvVarClient.Set.
//
// Creates or overwrites a Windows environment variable using
// RegistryKey.SetValue with the correct kind (REG_SZ or REG_EXPAND_SZ).
// Performs an idempotent pre-check (EC-3) and sends WM_SETTINGCHANGE
// broadcast on actual writes (ADR-EV-2).
func (e *EnvVarClientImpl) Set(ctx context.Context, input EnvVarInput) (*EnvVarState, error) {
	hiveIdent, subkey, err := registryPathForScope(input.Scope)
	if err != nil {
		return nil, &EnvVarError{Kind: EnvVarErrorInvalidInput, Message: err.Error()}
	}

	repl := strings.NewReplacer(
		"@@HIVE_IDENT@@", hiveIdent,
		"@@SUBKEY@@", psQuote(subkey),
		"@@SCOPE@@", psQuote(string(input.Scope)),
		"@@SCOPE_RAW@@", string(input.Scope),
		"@@NAME@@", psQuote(input.Name),
		"@@VALUE@@", psQuote(input.Value),
		"@@EXPAND@@", "$"+psBool(input.Expand),
	)

	script := psEnvVarHeader + repl.Replace(psEnvVarSetBody)

	resp, runErr := e.runScript(ctx, "set", script)
	if runErr != nil {
		return nil, runErr
	}

	var data evSetData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, &EnvVarError{
			Kind:    EnvVarErrorUnknown,
			Message: "failed to parse set response data",
			Cause:   jerr,
		}
	}

	return &EnvVarState{
		Scope:            input.Scope,
		Name:             input.Name,
		Value:            data.Value,
		Expand:           data.Expand,
		BroadcastWarning: data.BroadcastWarning,
	}, nil
}

// Read implements EnvVarClient.Read.
//
// Returns (nil, nil) when the scope-resolved registry key or the value name is
// absent (EC-4 drift signal). The resource Read handler MUST call
// resp.State.RemoveResource() in that case.
func (e *EnvVarClientImpl) Read(ctx context.Context, scope EnvVarScope, name string) (*EnvVarState, error) {
	hiveIdent, subkey, err := registryPathForScope(scope)
	if err != nil {
		return nil, &EnvVarError{Kind: EnvVarErrorInvalidInput, Message: err.Error()}
	}

	repl := strings.NewReplacer(
		"@@HIVE_IDENT@@", hiveIdent,
		"@@SUBKEY@@", psQuote(subkey),
		"@@NAME@@", psQuote(name),
	)

	script := psEnvVarHeader + repl.Replace(psEnvVarReadBody)

	resp, runErr := e.runScript(ctx, "read", script)
	if runErr != nil {
		return nil, runErr
	}

	var data evReadData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, &EnvVarError{
			Kind:    EnvVarErrorUnknown,
			Message: "failed to parse read response data",
			Cause:   jerr,
		}
	}

	if !data.Found {
		return nil, nil
	}

	return &EnvVarState{
		Scope:  scope,
		Name:   name,
		Value:  data.Value,
		Expand: data.Expand,
	}, nil
}

// Delete implements EnvVarClient.Delete.
//
// Idempotent: a missing variable or missing scope key is a silent no-op (EC-8).
// Sends WM_SETTINGCHANGE broadcast only when the variable was actually present.
// The parent registry key is NEVER deleted.
func (e *EnvVarClientImpl) Delete(ctx context.Context, scope EnvVarScope, name string) error {
	hiveIdent, subkey, err := registryPathForScope(scope)
	if err != nil {
		return &EnvVarError{Kind: EnvVarErrorInvalidInput, Message: err.Error()}
	}

	repl := strings.NewReplacer(
		"@@HIVE_IDENT@@", hiveIdent,
		"@@SUBKEY@@", psQuote(subkey),
		"@@NAME@@", psQuote(name),
	)

	script := psEnvVarHeader + repl.Replace(psEnvVarDeleteBody)

	_, runErr := e.runScript(ctx, "delete", script)
	if runErr != nil {
		return runErr
	}
	return nil
}
