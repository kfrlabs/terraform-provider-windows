// Package winclient provides the PowerShell/SSH-backed implementation of
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
//   - runEnvelope      — shared JSON envelope pipeline (envelope.go)
//   - runPowerShell    — package-level hook for testability
//   - psResponse       — parsed Emit-OK / Emit-Err JSON envelope (aliases Envelope)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Compile-time assertion: LocalGroupClient satisfies WindowsLocalGroupClient.
var _ WindowsLocalGroupClient = (*LocalGroupClient)(nil)

// LocalGroupClient is the PowerShell/SSH-backed WindowsLocalGroupClient.
type LocalGroupClient struct {
	c *Client
}

// NewLocalGroupClient constructs a LocalGroupClient wrapping the given SSH
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
const lgPsHeader = psEnvelopePrelude + lgPsHeaderRemainder

// lgPsHeaderRemainder Classify-LG and group helpers stay here; envelope emitters come from the prelude.
const lgPsHeaderRemainder = `
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
	case "invalid_parameter":
		return LocalGroupErrorInvalidParameter
	case "unsupported_on_domain_controller":
		return LocalGroupErrorUnsupportedOnDC
	default:
		return LocalGroupErrorUnknown
	}
}

// ---------------------------------------------------------------------------
// runLGEnvelope — execute a script and parse the JSON envelope
// ---------------------------------------------------------------------------

// runLGEnvelope executes script (prefixed with lgPsHeader) on the remote host
// and returns the parsed psResponse envelope through the shared runEnvelope
// helper (#198). key is a diagnostic identifier (sid or name) used in error
// context.
//
// Transport / PS-level errors that bypass Emit-Err (non-zero exit, context
// cancellation) are translated into *LocalGroupError with
// Kind=LocalGroupErrorUnknown.
func (lc *LocalGroupClient) runLGEnvelope(ctx context.Context, op, key, script string) (*psResponse, error) {
	baseContext := map[string]string{"key": key, "host": lc.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, lc.c, full)
		},
		op, lgPsHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewLocalGroupError(mapLGKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
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
// IsBuiltinLocalGroupSID — BUILTIN authority check (EC-2, ADR-LG-2)
// ---------------------------------------------------------------------------

// IsBuiltinLocalGroupSID reports whether sid belongs to the BUILTIN authority
// ("S-1-5-32-" prefix: Administrators, Users, Guests, ...). It mirrors the
// Delete EC-2 pre-flight check (ADR-LG-2) and implements the List
// IncludeBuiltin filter.
func IsBuiltinLocalGroupSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-32-")
}

// ---------------------------------------------------------------------------
// List — read-only inventory for windows_local_groups (issue #298)
// ---------------------------------------------------------------------------

// Compile-time assertion: LocalGroupClient satisfies LocalGroupLister.
var _ LocalGroupLister = (*LocalGroupClient)(nil)

// psLocalGroupListEntry is the JSON shape of one group in the List response:
// the exact Read projection (psLocalGroup) plus the optional Members array
// from the shared Get-LgmMembers projection. Members is null when membership
// was not requested and an array (possibly empty) otherwise.
type psLocalGroupListEntry struct {
	psLocalGroup
	Members []lgmMember `json:"Members"`
}

// buildLocalGroupListScript renders the inventory script: the domain
// controller guard FIRST (LocalAccounts addresses the domain database on a
// DC, not local groups), then the same LocalAccounts module-availability
// check Create uses (probing Get-LocalGroup, the cmdlet List needs, with the
// identical message), then Get-LocalGroup over all accounts narrowed
// host-side by the exact names/sids filters, projected with the shared
// Get-LgmMembers function in a loop when membership is requested.
func buildLocalGroupListScript(names, sids []string, includeMembers bool) string {
	var b strings.Builder
	b.WriteString("$nameFilter = @(")
	for i, n := range names {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(psQuote(n))
	}
	b.WriteString(")\n$sidFilter = @(")
	for i, s := range sids {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(psQuote(s))
	}
	b.WriteString(")\n")
	if includeMembers {
		b.WriteString("$wantMembers = $true\n")
	} else {
		b.WriteString("$wantMembers = $false\n")
	}
	b.WriteString(`
# DC guard (must run first): on a domain controller the LocalAccounts
# cmdlets address the domain database, so a local-group inventory is meaningless.
$domainRole = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole
if ($domainRole -ge 4) {
    Emit-Err 'unsupported_on_domain_controller' ("local group inventory is not supported on a domain controller (DomainRole " + $domainRole + "); run this data source against a member server or workstation instead") @{ domain_role = "$domainRole"; step = 'dc_guard' }
    return
}

# Module guard (same check and message as Create; probes the cmdlet List uses).
if (-not (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue)) {
    Emit-Err 'unknown' 'Microsoft.PowerShell.LocalAccounts module not available; requires Windows Server 2016 / Windows 10 or later' @{}
    return
}

try {
    $groups = @(Get-LocalGroup -ErrorAction Stop)
    if ($nameFilter.Count -gt 0) { $groups = @($groups | Where-Object { $nameFilter -contains $_.Name }) }
    if ($sidFilter.Count -gt 0) { $groups = @($groups | Where-Object { $sidFilter -contains $_.SID.Value }) }
    $out = @()
    foreach ($g in $groups) {
        $sidVal = $g.SID.Value
        # SID keeps the exact Read projection shape (psLocalGroup): the
        # SecurityIdentifier serialises as an object, so re-wrap the string
        # value instead of emitting it bare.
        $entry = [ordered]@{ Name = $g.Name; Description = $g.Description; SID = @{ Value = $sidVal }; Members = $null }
        if ($wantMembers) {
            $res = Get-LgmMembers $sidVal
            if ($res.ok) {
                $entry.Members = $res.members
            } else {
                # The group vanished between enumeration and member read —
                # degrade to empty membership (conservative, ADR-LGM-5).
                $entry.Members = @()
            }
        }
        $out += $entry
    }
    Emit-OK $out
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ step = 'list_local_groups' }
}
`)
	return lgmMembersPsFunction + "\n" + b.String()
}

// mapLGListMember projects one lgmMember JSON entry onto a
// LocalGroupMemberState. Unlike ClientLocalGroupMember.List, an empty Name
// is kept as-is (orphaned SIDs carry MemberName "" with the SID in
// MemberSID); the resource mapping keeps its own ""-to-SID coercion
// untouched. An empty ObjectClass normalises to "Unknown".
func mapLGListMember(groupSID string, m lgmMember) LocalGroupMemberState {
	oc := m.ObjectClass
	if oc == "" {
		oc = "Unknown"
	}
	return LocalGroupMemberState{
		GroupSID:        groupSID,
		MemberSID:       m.SID,
		MemberName:      m.Name,
		PrincipalSource: normalizePrincipalSource(m.PrincipalSource),
		ObjectClass:     oc,
	}
}

// List returns every local group in a single round-trip, filtered and sorted
// by name (case-insensitive). Members are populated only when the filter
// requests them, sorted by member SID. An empty inventory match is valid
// (empty slice, nil error). Filters are validated before any host call; an
// invalid filter never reaches the host.
func (lc *LocalGroupClient) List(ctx context.Context, filter LocalGroupFilter) ([]GroupState, error) {
	var nameRe *regexp.Regexp
	if strings.TrimSpace(filter.NameRegex) != "" {
		var err error
		nameRe, err = regexp.Compile(filter.NameRegex)
		if err != nil {
			return nil, NewLocalGroupError(LocalGroupErrorInvalidParameter,
				fmt.Sprintf("name_regex %q is not a valid regular expression: %v", filter.NameRegex, err), nil,
				map[string]string{"name_regex": filter.NameRegex})
		}
	}

	resp, err := lc.runLGEnvelope(ctx, "list", "", buildLocalGroupListScript(filter.Names, filter.SIDs, filter.IncludeMembers))
	if err != nil {
		return nil, err
	}
	var entries []psLocalGroupListEntry
	if jerr := json.Unmarshal(resp.Data, &entries); jerr != nil {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			"failed to parse LocalGroup list JSON", jerr,
			map[string]string{"host": lc.c.cfg.Host})
	}
	out := make([]GroupState, 0, len(entries))
	for _, e := range entries {
		if e.SID.Value == "" {
			return nil, NewLocalGroupError(LocalGroupErrorUnknown,
				"LocalGroup list JSON has empty SID.Value", nil, nil)
		}
		if nameRe != nil && !nameRe.MatchString(e.Name) {
			continue
		}
		if !filter.IncludeBuiltin && IsBuiltinLocalGroupSID(e.SID.Value) {
			continue
		}
		gs := GroupState{
			Name:        e.Name,
			Description: e.Description,
			SID:         e.SID.Value,
		}
		if filter.IncludeMembers {
			members := make([]LocalGroupMemberState, 0, len(e.Members))
			for _, m := range e.Members {
				members = append(members, mapLGListMember(e.SID.Value, m))
			}
			sort.Slice(members, func(i, j int) bool {
				return strings.ToLower(members[i].MemberSID) < strings.ToLower(members[j].MemberSID)
			})
			gs.Members = members
		}
		out = append(out, gs)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
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

# Pre-flight: detect name collision before calling New-LocalGroup (EC-1).
# The already_exists message references the runtime $existing identity
# (name and SID) rather than interpolating the Go-side input: names may
# legally contain $ and backticks, which PowerShell would expand inside a
# double-quoted string. $existing is already fetched by the lookup above.
try {
    $existing = Get-LocalGroup -Name %s -ErrorAction Stop
    $existingSid = $existing.SID.Value
    Emit-Err 'already_exists' ("local group '" + $existing.Name + "' already exists on this host (SID: " + $existingSid + "); use 'terraform import' to bring it under management instead of creating a duplicate") @{ sid = $existingSid; name = $existing.Name }
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
`, qName, qName, qName, qDesc, qName)

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
