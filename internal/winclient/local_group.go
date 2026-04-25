// Package winclient provides the PowerShell/WinRM-backed implementation of
// WindowsLocalGroupClient.
//
// Security invariants:
//   - All user-supplied strings are escaped via psQuote before interpolation
//     into PowerShell scripts; no raw string concatenation with user input.
//   - All scripts run via -EncodedCommand (UTF-16LE base64) through the
//     underlying Client; no shell metacharacters reach cmd.exe.
//   - No credentials are written to LocalGroupError.Message or Context.
//
// Reused helpers from service.go (same package):
//   - psQuote          — single-quote PowerShell literal with embedded ' doubled
//   - extractLastJSONLine — scan stdout for last JSON-starting line
//   - truncate         — cap strings for diagnostic context
//   - runPowerShell    — package-level hook for testability
//   - psResponse       — parsed Emit-OK / Emit-Err JSON envelope
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: LocalGroupClient satisfies WindowsLocalGroupClient.
var _ WindowsLocalGroupClient = (*LocalGroupClient)(nil)

// LocalGroupClient is the PowerShell/WinRM-backed WindowsLocalGroupClient.
type LocalGroupClient struct {
	c *Client
}

// NewLocalGroupClient constructs a LocalGroupClient wrapping the given WinRM
// Client.
func NewLocalGroupClient(c *Client) *LocalGroupClient {
	return &LocalGroupClient{c: c}
}

// ---------------------------------------------------------------------------
// PowerShell header — Emit-OK, Emit-Err, Classify-LG
// ---------------------------------------------------------------------------

// lgPsHeader is prepended to every local-group script. It defines:
//
//   - Emit-OK  / Emit-Err : JSON envelope emitters.
//   - Classify-LG         : maps PowerShell LocalAccounts exception identifiers
//     and message patterns to LocalGroupErrorKind strings for locale-independent
//     error handling.
//
// Note: this constant is a raw Go backtick string. PowerShell backtick escape
// sequences (`n, `t) are NOT used in this script body, so the raw string form
// is safe (ADR-LG-9).
const lgPsHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Classify-LG([string]$Msg, [string]$FQEI) {
  if ($FQEI -match 'GroupNotFound'    -or $Msg -match 'was not found')          { return 'not_found' }
  if ($FQEI -match 'GroupNameExists'  -or $Msg -match 'not unique')             { return 'name_conflict' }
  if ($FQEI -match 'GroupExists'      -or $Msg -match 'already exists')         { return 'already_exists' }
  if ($FQEI -match 'AccessDenied'     -or $Msg -match 'Access is denied')       { return 'permission_denied' }
  if ($FQEI -match 'InvalidName'      -or $Msg -match 'invalid.*name')          { return 'invalid_name' }
  return 'unknown'
}
`

// ---------------------------------------------------------------------------
// psLocalGroup — JSON shape returned by Get-LocalGroup | ConvertTo-Json
// ---------------------------------------------------------------------------

// psLocalGroup is the JSON shape of a Windows LocalGroup object serialised by
// Get-LocalGroup | ConvertTo-Json -Depth 8 -Compress.
// The SID property is a SecurityIdentifier object; at depth ≥ 2 it serialises
// as {"BinaryLength":..., "AccountDomainSid":null, "Value":"S-1-5-21-..."}.
// We extract only the fields we need.
type psLocalGroup struct {
	Name        string `json:"Name"`
	Description string `json:"Description"`
	SID         struct {
		Value string `json:"Value"`
	} `json:"SID"`
}

// ---------------------------------------------------------------------------
// mapLGKind — kind string → LocalGroupErrorKind
// ---------------------------------------------------------------------------

// mapLGKind converts the kind string emitted by Classify-LG in PowerShell to
// the corresponding LocalGroupErrorKind constant.
func mapLGKind(k string) LocalGroupErrorKind {
	switch k {
	case "not_found":
		return LocalGroupErrorNotFound
	case "already_exists":
		return LocalGroupErrorAlreadyExists
	case "builtin_group":
		return LocalGroupErrorBuiltinGroup
	case "permission_denied":
		return LocalGroupErrorPermission
	case "name_conflict":
		return LocalGroupErrorNameConflict
	case "invalid_name":
		return LocalGroupErrorInvalidName
	default:
		return LocalGroupErrorUnknown
	}
}

// ---------------------------------------------------------------------------
// runLGEnvelope — execute a script and parse the JSON envelope
// ---------------------------------------------------------------------------

// runLGEnvelope executes script (prefixed with lgPsHeader) on the remote host
// and returns the parsed psResponse envelope. key is a diagnostic identifier
// (sid or name) used in error context.
//
// Transport / PS-level errors that bypass Emit-Err (non-zero exit, context
// cancellation) are translated into *LocalGroupError with
// Kind=LocalGroupErrorUnknown.
func (lc *LocalGroupClient) runLGEnvelope(ctx context.Context, op, key, script string) (*psResponse, error) {
	full := lgPsHeader + "\n" + script
	stdout, stderr, err := runPowerShell(ctx, lc.c, full)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewLocalGroupError(LocalGroupErrorUnknown,
				fmt.Sprintf("operation %q timed out or was cancelled", op),
				ctx.Err(), map[string]string{
					"operation": op, "key": key, "host": lc.c.cfg.Host,
				})
		}
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			fmt.Sprintf("WinRM transport error during %q", op),
			err, map[string]string{
				"operation": op, "key": key, "host": lc.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op), nil,
			map[string]string{
				"operation": op, "key": key, "host": lc.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op), jerr,
			map[string]string{
				"operation": op, "key": key, "host": lc.c.cfg.Host,
				"stdout": truncate(stdout, 2048),
			})
	}

	if !resp.OK {
		kind := mapLGKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["key"] = key
		ctxMap["host"] = lc.c.cfg.Host
		return &resp, NewLocalGroupError(kind, resp.Message, nil, ctxMap)
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// parseGroupData — unmarshal psResponse.Data into GroupState
// ---------------------------------------------------------------------------

// parseGroupData deserialises the Data field of a psResponse (produced by
// Emit-OK with a LocalGroup object) into a *GroupState.
func parseGroupData(op string, data json.RawMessage) (*GroupState, error) {
	var g psLocalGroup
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			fmt.Sprintf("failed to parse LocalGroup JSON from %q", op), err, nil)
	}
	if g.SID.Value == "" {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			fmt.Sprintf("LocalGroup JSON from %q has empty SID.Value", op), nil, nil)
	}
	return &GroupState{
		Name:        g.Name,
		Description: g.Description,
		SID:         g.SID.Value,
	}, nil
}

// ---------------------------------------------------------------------------
// Create — EC-1, module guard
// ---------------------------------------------------------------------------

// Create creates a new Windows local group. It performs two pre-flight checks
// before calling New-LocalGroup:
//  1. Module availability (Microsoft.PowerShell.LocalAccounts).
//  2. Existence check by name (EC-1): returns ErrLocalGroupAlreadyExists if the
//     group already exists, directing the operator to use terraform import.
func (lc *LocalGroupClient) Create(ctx context.Context, input GroupInput) (*GroupState, error) {
	qName := psQuote(input.Name)
	qDesc := psQuote(input.Description)

	script := fmt.Sprintf(`
# Module guard (EC-9: requires Windows Server 2016 / Windows 10+)
if (-not (Get-Command New-LocalGroup -ErrorAction SilentlyContinue)) {
    Emit-Err 'unknown' 'Microsoft.PowerShell.LocalAccounts module not available; requires Windows Server 2016 / Windows 10 or later' @{}
    return
}

# Pre-flight: detect name collision before calling New-LocalGroup (EC-1)
try {
    $existing = Get-LocalGroup -Name %s -ErrorAction Stop
    $existingSid = $existing.SID.Value
    Emit-Err 'already_exists' ("local group '%s' already exists on this host (SID: " + $existingSid + "); use 'terraform import' to bring it under management instead of creating a duplicate") @{ sid = $existingSid; name = $existing.Name }
    return
} catch {
    if ($_.FullyQualifiedErrorId -notmatch 'GroupNotFound' -and $_.Exception.Message -notmatch 'was not found') {
        $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
        Emit-Err $kind $_.Exception.Message @{ name = %s; step = 'preflight_read' }
        return
    }
    # GroupNotFound is expected — group does not exist, proceed with create
}

# Create the group
try {
    $group = New-LocalGroup -Name %s -Description %s -ErrorAction Stop
    Emit-OK $group
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ name = %s; step = 'new_local_group' }
}
`, qName, input.Name, qName, qName, qDesc, qName)

	resp, err := lc.runLGEnvelope(ctx, "create", input.Name, script)
	if err != nil {
		return nil, err
	}
	return parseGroupData("create", resp.Data)
}

// ---------------------------------------------------------------------------
// Read — EC-3 (GroupNotFound → nil, nil)
// ---------------------------------------------------------------------------

// Read retrieves the current state of the group identified by sid.
// Returns (nil, nil) when the group does not exist (EC-3); the resource
// handler must call resp.State.RemoveResource() in that case.
func (lc *LocalGroupClient) Read(ctx context.Context, sid string) (*GroupState, error) {
	qSID := psQuote(sid)

	script := fmt.Sprintf(`
try {
    $group = Get-LocalGroup -SID %s -ErrorAction Stop
    Emit-OK $group
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'get_local_group' }
}
`, qSID, qSID)

	resp, err := lc.runLGEnvelope(ctx, "read", sid, script)
	if err != nil {
		// EC-3: group has disappeared outside Terraform — not an error.
		if IsLocalGroupError(err, LocalGroupErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseGroupData("read", resp.Data)
}

// ---------------------------------------------------------------------------
// Update — rename (EC-5) + set description; order: Rename THEN Set
// ---------------------------------------------------------------------------

// Update applies in-place changes to the group identified by sid.
//
// The PowerShell script performs a single round-trip that:
//  1. Reads the current state to check if a rename is needed.
//  2. Calls Rename-LocalGroup if the desired name differs (case-insensitive).
//  3. Always calls Set-LocalGroup to apply the desired description.
//  4. Returns the refreshed state via Get-LocalGroup.
//
// Both rename and set use -SID to remain immune to concurrent renames
// (spec §operations.update.notes).
func (lc *LocalGroupClient) Update(ctx context.Context, sid string, input GroupInput) (*GroupState, error) {
	qSID := psQuote(sid)
	qName := psQuote(input.Name)
	qDesc := psQuote(input.Description)

	script := fmt.Sprintf(`
try {
    # Read current state
    $current = Get-LocalGroup -SID %s -ErrorAction Stop

    # Rename if needed — PowerShell -ne is case-insensitive for strings,
    # so this skips the rename when names differ only in casing (ADR-LG-4, EC-5).
    if ($current.Name -ne %s) {
        Rename-LocalGroup -SID %s -NewName %s -ErrorAction Stop
    }

    # Always apply description (idempotent)
    Set-LocalGroup -SID %s -Description %s -ErrorAction Stop

    # Return refreshed state
    $final = Get-LocalGroup -SID %s -ErrorAction Stop
    Emit-OK $final
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; new_name = %s; step = 'update' }
}
`, qSID, qName, qSID, qName, qSID, qDesc, qSID, qSID, qName)

	resp, err := lc.runLGEnvelope(ctx, "update", sid, script)
	if err != nil {
		return nil, err
	}
	return parseGroupData("update", resp.Data)
}

// ---------------------------------------------------------------------------
// Delete — EC-2 BUILTIN guard, idempotent on GroupNotFound
// ---------------------------------------------------------------------------

// Delete removes the Windows local group identified by sid.
//
// Pre-flight: if the SID starts with "S-1-5-32-" (BUILTIN authority), returns
// ErrLocalGroupBuiltinGroup immediately without calling Remove-LocalGroup
// (EC-2, ADR-LG-2). This SID-prefix check is reliable even if the group was
// renamed by an operator.
//
// A GroupNotFound error from Remove-LocalGroup is treated as success
// (idempotent delete — the group is already gone).
func (lc *LocalGroupClient) Delete(ctx context.Context, sid string) error {
	// EC-2: BUILTIN authority guard (SID-prefix check, ADR-LG-2).
	if strings.HasPrefix(sid, "S-1-5-32-") {
		// We need the group name for a useful error message. Attempt a quick
		// read; if that fails, fall back to a generic message.
		name := sid
		if gs, readErr := lc.Read(ctx, sid); readErr == nil && gs != nil {
			name = gs.Name
		}
		return NewLocalGroupError(LocalGroupErrorBuiltinGroup,
			fmt.Sprintf(
				"cannot destroy built-in local group %q (SID: %s); "+
					"Windows built-in groups (Administrators, Users, Guests, etc.) must not be "+
					"deleted. Remove this resource from your configuration instead.",
				name, sid,
			),
			nil, map[string]string{"sid": sid, "name": name},
		)
	}

	qSID := psQuote(sid)

	script := fmt.Sprintf(`
try {
    Remove-LocalGroup -SID %s -ErrorAction Stop
    Emit-OK @{ deleted = $true }
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    # GroupNotFound means the group is already gone — treat as success (idempotent).
    if ($kind -eq 'not_found') {
        Emit-OK @{ deleted = $true; note = 'already_absent' }
        return
    }
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'remove_local_group' }
}
`, qSID, qSID)

	_, err := lc.runLGEnvelope(ctx, "delete", sid, script)
	return err
}

// ---------------------------------------------------------------------------
// ImportByName — EC-10 (name-based import path)
// ---------------------------------------------------------------------------

// ImportByName resolves a local group by its display name and returns the
// canonical *GroupState (including SID). Called during terraform import when
// the import ID does not start with "S-" (EC-10).
func (lc *LocalGroupClient) ImportByName(ctx context.Context, name string) (*GroupState, error) {
	qName := psQuote(name)

	script := fmt.Sprintf(`
try {
    $group = Get-LocalGroup -Name %s -ErrorAction Stop
    Emit-OK $group
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ name = %s; step = 'import_by_name' }
}
`, qName, qName)

	resp, err := lc.runLGEnvelope(ctx, "import_by_name", name, script)
	if err != nil {
		return nil, err
	}
	return parseGroupData("import_by_name", resp.Data)
}

// ---------------------------------------------------------------------------
// ImportBySID — EC-10 (SID-based import path)
// ---------------------------------------------------------------------------

// ImportBySID resolves a local group by its SID string and returns the
// canonical *GroupState. Called during terraform import when the import ID
// starts with "S-" (EC-10).
func (lc *LocalGroupClient) ImportBySID(ctx context.Context, sid string) (*GroupState, error) {
	qSID := psQuote(sid)

	script := fmt.Sprintf(`
try {
    $group = Get-LocalGroup -SID %s -ErrorAction Stop
    Emit-OK $group
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'import_by_sid' }
}
`, qSID, qSID)

	resp, err := lc.runLGEnvelope(ctx, "import_by_sid", sid, script)
	if err != nil {
		return nil, err
	}
	return parseGroupData("import_by_sid", resp.Data)
}
