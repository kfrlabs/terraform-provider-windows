// Package winclient: Windows registry key CRUD implementation over SSH.
//
// Key enumeration and creation use the .NET Microsoft.Win32.Registry API via
// PowerShell (ADR-RV-1), sharing the helper header with registry_value.go
// (Get-RegHive, RVK-To-Kind, Emit-OK/Emit-Err) for locale-independent,
// machine-parseable output. Value deletion also stays on the .NET API
// (DeleteValue handles the Default "" name, which Remove-ItemProperty cannot
// address); only key-tree removal uses Remove-Item against a
// provider-qualified Registry:: path so no PSDrive mapping is required.
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted PS
//     literal) or injected at a known concatenation point; never raw-concatenated.
//   - Value-name lists travel as psQuoteList array literals.
//   - The Default (unnamed) value is DeleteValue(""): Remove-ItemProperty
//     cannot address it, so value deletion stays on the .NET API which
//     handles "" consistently with windows_registry_value (name="").
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: RegistryKeyClientImpl satisfies RegistryKeyClient.
var _ RegistryKeyClient = (*RegistryKeyClientImpl)(nil)

// RegistryKeyClientImpl is the PowerShell/SSH-backed RegistryKeyClient.
type RegistryKeyClientImpl struct {
	c *Client
}

// NewRegistryKeyClient constructs a RegistryKeyClientImpl wrapping the given SSH Client.
func NewRegistryKeyClient(c *Client) *RegistryKeyClientImpl {
	return &RegistryKeyClientImpl{c: c}
}

// psRegistryKeyListBody is the List PS script template.
// Placeholders @@HIVE@@, @@PATH@@ are replaced by strings.NewReplacer.
const psRegistryKeyListBody = `
& {
  $_rkKey = $null
  try {
    $root = Get-RegHive @@HIVE@@
    $_rkKey = $root.OpenSubKey(@@PATH@@, $false)
    if ($null -eq $_rkKey) {
      Emit-OK @{ found = $false; value_names = @(); value_kinds = @() }
      return
    }
    $names = @($_rkKey.GetValueNames())
    $kinds = @()
    foreach ($n in $names) { $kinds += RVK-To-Kind ([int]$_rkKey.GetValueKind($n)) }
    Emit-OK @{ found = $true; value_names = $names; value_kinds = $kinds }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_rkKey) { $_rkKey.Close() }
  }
}
`

// psRegistryKeyEnsureBody is the EnsureKey PS script template: CreateSubKey
// creates the full key chain when missing, then enumerates names+kinds.
// Placeholders @@HIVE@@, @@PATH@@ are replaced by strings.NewReplacer.
const psRegistryKeyEnsureBody = `
& {
  $_rkKey = $null
  try {
    $root = Get-RegHive @@HIVE@@
    $_rkKey = $root.CreateSubKey(@@PATH@@)
    if ($null -eq $_rkKey) {
      Emit-Err 'permission_denied' 'CreateSubKey returned null (insufficient privileges)' @{}
      return
    }
    $names = @($_rkKey.GetValueNames())
    $kinds = @()
    foreach ($n in $names) { $kinds += RVK-To-Kind ([int]$_rkKey.GetValueKind($n)) }
    Emit-OK @{ found = $true; value_names = $names; value_kinds = $kinds }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_rkKey) { $_rkKey.Close() }
  }
}
`

// psRegistryKeyDeleteValuesBody deletes the given value names idempotently:
// DeleteValue($name, $false) ignores missing values, and name "" addresses
// the Default value consistently with windows_registry_value.
// Placeholders @@HIVE@@, @@PATH@@, @@NAMES@@ are replaced by strings.NewReplacer.
const psRegistryKeyDeleteValuesBody = `
& {
  $_rkKey = $null
  try {
    $root = Get-RegHive @@HIVE@@
    $_rkKey = $root.OpenSubKey(@@PATH@@, $true)
    if ($null -eq $_rkKey) {
      Emit-OK @{ deleted = $false; reason = 'key_not_found' }
      return
    }
    foreach ($n in @@NAMES@@) { $_rkKey.DeleteValue($n, $false) }
    Emit-OK @{ deleted = $true }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  } finally {
    if ($null -ne $_rkKey) { $_rkKey.Close() }
  }
}
`

// psRegistryKeyDeleteKeyBody is the DeleteKey PS script template.
// Placeholders @@PSPATH@@ (provider-qualified Registry:: path, quoted) and
// @@RECURSE@@ ($true/$false literal) are replaced by strings.NewReplacer.
//
// Without -Recurse a key that still has subkeys is refused with
// invalid_input (checked up front via Get-ChildItem, which lists subkeys
// only) instead of surfacing a locale-dependent Remove-Item message.
const psRegistryKeyDeleteKeyBody = `
& {
  try {
    $base = @@PSPATH@@
    if (-not (Test-Path -LiteralPath $base)) {
      Emit-OK @{ deleted = $false; reason = 'key_not_found' }
      return
    }
    if (-not @@RECURSE@@) {
      $kids = @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)
      if ($kids.Count -gt 0) {
        Emit-Err 'invalid_input' 'key has subkeys; set recursive=true to delete the key tree' @{}
        return
      }
    }
    Remove-Item -LiteralPath $base -Recurse:@@RECURSE@@ -Force -ErrorAction Stop
    Emit-OK @{ deleted = $true }
  } catch [System.UnauthorizedAccessException] {
    Emit-Err 'permission_denied' $_.Exception.Message @{}
  } catch {
    Emit-Err 'unknown' $_.Exception.Message @{}
  }
}
`

// runRegistryKeyPowerShell is the package-level hook for test substitution.
// Production code must not reassign this outside tests.
var runRegistryKeyPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// rkPSResponse is the parsed JSON envelope for registry key operations. It
// aliases the shared Envelope type so every resource parses the same shape
// through runEnvelope (#198).
type rkPSResponse = Envelope

// rkListPayload mirrors the JSON object returned by the List/Ensure scripts.
// ValueNames/ValueKinds are json.RawMessage to handle the PowerShell
// ConvertTo-Json quirk where a single-element array may be serialised as a
// scalar (shared with parseMultiStringPayload).
type rkListPayload struct {
	Found      bool            `json:"found"`
	ValueNames json.RawMessage `json:"value_names"`
	ValueKinds json.RawMessage `json:"value_kinds"`
}

// runScript executes a PS script and parses the JSON envelope through the
// shared runEnvelope helper (#198).
func (r *RegistryKeyClientImpl) runScript(ctx context.Context, op, script string) (*rkPSResponse, error) {
	baseContext := map[string]string{"host": r.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runRegistryKeyPowerShell(ctx, r.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, &RegistryKeyError{Resource: "windows_registry_key",
			Kind:    RegistryKeyErrorUnknown,
			Message: eerr.Message,
			Cause:   eerr.Cause,
			Context: eerr.Context,
		}
	}
	return resp, &RegistryKeyError{Resource: "windows_registry_key", Kind: string(mapRegistryKeyErrorKind(eerr.RemoteKind)), Message: eerr.Message, Context: eerr.Context}
}

// mapRegistryKeyErrorKind translates the PS-side "kind" string to a typed RegistryKeyErrorKind.
func mapRegistryKeyErrorKind(k string) RegistryKeyErrorKind {
	switch k {
	case string(RegistryKeyErrorNotFound),
		string(RegistryKeyErrorPermission),
		string(RegistryKeyErrorInvalidInput):
		return RegistryKeyErrorKind(k)
	default:
		return RegistryKeyErrorUnknown
	}
}

// parseListPayload converts the JSON data blob from a List/Ensure PS script
// into a *RegistryKeyState. found=false yields a state with Found=false.
func (r *RegistryKeyClientImpl) parseListPayload(raw json.RawMessage, hive, regPath string) (*RegistryKeyState, error) {
	if raw == nil || string(raw) == "null" {
		return nil, &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorUnknown,
			Message: "empty registry key payload"}
	}
	var payload rkListPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorUnknown,
			Message: "failed to parse registry key payload", Cause: err}
	}
	state := &RegistryKeyState{
		Hive:       hive,
		Path:       regPath,
		Found:      payload.Found,
		ValueNames: []string{},
		Values:     []RegistryKeyValueSummary{},
	}
	if !payload.Found {
		return state, nil
	}

	names, err := parseMultiStringPayload(payload.ValueNames)
	if err != nil {
		return nil, &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorUnknown,
			Message: "cannot parse value_names: " + err.Error()}
	}
	kinds, err := parseMultiStringPayload(payload.ValueKinds)
	if err != nil {
		return nil, &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorUnknown,
			Message: "cannot parse value_kinds: " + err.Error()}
	}
	if len(names) != len(kinds) {
		return nil, &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorUnknown,
			Message: fmt.Sprintf("value_names (%d) and value_kinds (%d) length mismatch", len(names), len(kinds))}
	}

	state.ValueNames = names
	for i, n := range names {
		state.Values = append(state.Values, RegistryKeyValueSummary{
			Name: n,
			Kind: RegistryValueKind(kinds[i]),
		})
	}
	return state, nil
}

// registryKeyPSPath returns the provider-qualified Registry:: path for a
// hive, e.g. "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE".
// Provider-qualified paths work regardless of which PSDrives exist on the
// target (HKCR/HKU/HKCC have no default drive).
func registryKeyPSPath(hive string) (string, error) {
	var full string
	switch strings.ToUpper(hive) {
	case "HKLM":
		full = "HKEY_LOCAL_MACHINE"
	case "HKCU":
		full = "HKEY_CURRENT_USER"
	case "HKCR":
		full = "HKEY_CLASSES_ROOT"
	case "HKU":
		full = "HKEY_USERS"
	case "HKCC":
		full = "HKEY_CURRENT_CONFIG"
	default:
		return "", &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorInvalidInput,
			Message: fmt.Sprintf("unknown hive %q; must be one of HKLM, HKCU, HKCR, HKU, HKCC", hive)}
	}
	return `Microsoft.PowerShell.Core\Registry::` + full, nil
}

// validateRegistryKeyPath is defence-in-depth for every RegistryKeyClient
// operation: reject empty paths (which would address the hive root) and
// traversal segments (".", "..", empty) before any remote call, mirroring
// the Terraform-side registryPathValidator.
func validateRegistryKeyPath(regPath string) error {
	if strings.TrimSpace(regPath) == "" {
		return &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorInvalidInput,
			Message: "registry key path must not be empty (the hive root cannot be managed)"}
	}
	for _, seg := range strings.Split(regPath, "\\") {
		if t := strings.TrimSpace(seg); t == "" || t == "." || t == ".." {
			return &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorInvalidInput,
				Message: fmt.Sprintf("invalid path segment %q in registry key path %q", seg, regPath)}
		}
	}
	return nil
}

// EnsureKey implements RegistryKeyClient.EnsureKey.
//
// Creates the full key chain when missing (EC-1 equivalent) and returns the
// live value-name enumeration.
func (r *RegistryKeyClientImpl) EnsureKey(ctx context.Context, hive, regPath string) (*RegistryKeyState, error) {
	if err := validateRegistryKeyPath(regPath); err != nil {
		return nil, err
	}
	repl := strings.NewReplacer(
		"@@HIVE@@", psQuote(hive),
		"@@PATH@@", psQuote(regPath),
	)

	script := psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyEnsureBody)

	resp, err := r.runScript(ctx, "ensure_key", script)
	if err != nil {
		return nil, err
	}

	return r.parseListPayload(resp.Data, hive, regPath)
}

// List implements RegistryKeyClient.List.
//
// Returns a state with Found=false (and no error) when the key does not exist.
func (r *RegistryKeyClientImpl) List(ctx context.Context, hive, regPath string) (*RegistryKeyState, error) {
	if err := validateRegistryKeyPath(regPath); err != nil {
		return nil, err
	}
	repl := strings.NewReplacer(
		"@@HIVE@@", psQuote(hive),
		"@@PATH@@", psQuote(regPath),
	)

	script := psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyListBody)

	resp, err := r.runScript(ctx, "list_key", script)
	if err != nil {
		if IsRegistryKeyError(err, RegistryKeyErrorNotFound) {
			return &RegistryKeyState{Hive: hive, Path: regPath, Found: false,
				ValueNames: []string{}, Values: []RegistryKeyValueSummary{}}, nil
		}
		return nil, err
	}

	return r.parseListPayload(resp.Data, hive, regPath)
}

// DeleteValues implements RegistryKeyClient.DeleteValues.
//
// Idempotent: a missing key or missing value is a silent no-op.
func (r *RegistryKeyClientImpl) DeleteValues(ctx context.Context, hive, regPath string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	if err := validateRegistryKeyPath(regPath); err != nil {
		return err
	}
	repl := strings.NewReplacer(
		"@@HIVE@@", psQuote(hive),
		"@@PATH@@", psQuote(regPath),
		"@@NAMES@@", psQuoteList(names),
	)

	script := psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyDeleteValuesBody)

	_, err := r.runScript(ctx, "delete_values", script)
	if err != nil {
		if IsRegistryKeyError(err, RegistryKeyErrorNotFound) {
			return nil
		}
		return err
	}
	return nil
}

// DeleteKey implements RegistryKeyClient.DeleteKey.
//
// Idempotent: a missing key is a silent no-op. Without recursive=true a key
// that still has subkeys fails with RegistryKeyErrorInvalidInput.
func (r *RegistryKeyClientImpl) DeleteKey(ctx context.Context, hive, regPath string, recursive bool) error {
	if err := validateRegistryKeyPath(regPath); err != nil {
		return err
	}
	psPath, err := registryKeyPSPath(hive)
	if err != nil {
		return err
	}
	repl := strings.NewReplacer(
		"@@PSPATH@@", psQuote(psPath+`\`+regPath),
		"@@RECURSE@@", "$"+psBool(recursive),
	)

	script := psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyDeleteKeyBody)

	_, err = r.runScript(ctx, "delete_key", script)
	if err != nil {
		if IsRegistryKeyError(err, RegistryKeyErrorNotFound) {
			return nil
		}
		return err
	}
	return nil
}
