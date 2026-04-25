// Package winclient provides the PowerShell/WinRM-backed implementation of
// ClientLocalGroupMember.
//
// Security invariants:
//   - All user-supplied strings are escaped via psQuote before interpolation
//     into PowerShell scripts; no raw string concatenation with user input.
//   - All scripts run via -EncodedCommand (UTF-16LE base64) through the
//     underlying Client; no shell metacharacters reach cmd.exe.
//   - No credentials are written to LocalGroupMemberError.Message or Context.
//
// Reused helpers from service.go / local_group.go (same package):
//   - psQuote             — single-quote PowerShell literal
//   - extractLastJSONLine — scan stdout for last JSON-starting line
//   - truncate            — cap strings for diagnostic context
//   - runPowerShell       — package-level hook for testability
//   - psResponse          — parsed Emit-OK / Emit-Err JSON envelope
//   - lgPsHeader          — PowerShell header with Emit-OK / Emit-Err / Classify-LG
//
// The three-tier orphaned-SID fallback for List (EC-6, ADR-LGM-5):
//   Tier 1 — Get-LocalGroupMember -SID (primary)
//   Tier 2 — Win32_GroupUser WMI (orphan-resilient)
//   Tier 3 — net localgroup (last resort text parsing)
//   All-fail — empty slice returned, no error (conservative)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: LocalGroupMemberClient satisfies ClientLocalGroupMember.
var _ ClientLocalGroupMember = (*LocalGroupMemberClient)(nil)

// LocalGroupMemberClient is the PowerShell/WinRM-backed ClientLocalGroupMember.
type LocalGroupMemberClient struct {
	c *Client
}

// NewLocalGroupMemberClient constructs a LocalGroupMemberClient wrapping the
// given WinRM Client.
func NewLocalGroupMemberClient(c *Client) *LocalGroupMemberClient {
	return &LocalGroupMemberClient{c: c}
}

// ---------------------------------------------------------------------------
// mapLGMKind — kind string → LocalGroupMemberErrorKind
// ---------------------------------------------------------------------------

// mapLGMKind converts the kind string emitted by PowerShell error handling to
// the corresponding LocalGroupMemberErrorKind constant.
func mapLGMKind(k string) LocalGroupMemberErrorKind {
	switch k {
	case "group_not_found":
		return LocalGroupMemberErrorGroupNotFound
	case "member_already_exists":
		return LocalGroupMemberErrorAlreadyExists
	case "member_unresolvable":
		return LocalGroupMemberErrorUnresolvable
	case "member_not_found":
		return LocalGroupMemberErrorNotFound
	case "permission_denied":
		return LocalGroupMemberErrorPermission
	default:
		return LocalGroupMemberErrorUnknown
	}
}

// normalizePrincipalSource maps both the string enum name and the integer
// representation (PS 5.1 ConvertTo-Json) to the canonical string values
// expected by the schema validator.
//
// Windows enum values (Microsoft.PowerShell.Commands.LocalAccounts):
//
//	Local = 1, ActiveDirectory = 2, MicrosoftAccount = 4, AzureAD = 8
func normalizePrincipalSource(s string) string {
	switch s {
	case "Local", "1":
		return "Local"
	case "ActiveDirectory", "2":
		return "ActiveDirectory"
	case "MicrosoftAccount", "4":
		return "MicrosoftAccount"
	case "AzureAD", "8":
		return "AzureAD"
	case "Unknown", "0":
		return "Unknown"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// runLGMEnvelope — execute a script and parse the JSON envelope
// ---------------------------------------------------------------------------

// runLGMEnvelope executes script (prefixed with lgPsHeader) on the remote host
// and returns the parsed psResponse envelope. op is the operation name and key
// is a diagnostic identifier used in error context.
//
// Transport / PS-level errors that bypass Emit-Err (non-zero exit, context
// cancellation) are translated into *LocalGroupMemberError with Kind=Unknown.
func (mc *LocalGroupMemberClient) runLGMEnvelope(ctx context.Context, op, key, script string) (*psResponse, error) {
	full := lgPsHeader + "\n" + script
	stdout, stderr, err := runPowerShell(ctx, mc.c, full)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewLocalGroupMemberError(LocalGroupMemberErrorUnknown,
				fmt.Sprintf("operation %q timed out or was cancelled", op),
				ctx.Err(),
				map[string]string{
					"operation": op, "key": key, "host": mc.c.cfg.Host,
				})
		}
		return nil, NewLocalGroupMemberError(LocalGroupMemberErrorUnknown,
			fmt.Sprintf("WinRM transport error during %q", op),
			err,
			map[string]string{
				"operation": op, "key": key, "host": mc.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewLocalGroupMemberError(LocalGroupMemberErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op),
			nil,
			map[string]string{
				"operation": op, "key": key, "host": mc.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewLocalGroupMemberError(LocalGroupMemberErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op),
			jerr,
			map[string]string{
				"operation": op, "key": key, "host": mc.c.cfg.Host,
				"stdout": truncate(stdout, 2048),
			})
	}

	if !resp.OK {
		kind := mapLGMKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["key"] = key
		ctxMap["host"] = mc.c.cfg.Host
		return &resp, NewLocalGroupMemberError(kind, resp.Message, nil, ctxMap)
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// List — three-tier orphan-SID fallback (EC-6, ADR-LGM-5)
// ---------------------------------------------------------------------------

// lgmMember is the JSON shape of a single member entry in the List response.
type lgmMember struct {
	SID             string `json:"SID"`
	Name            string `json:"Name"`
	PrincipalSource string `json:"PrincipalSource"`
}

// lgmListData is the JSON shape of the data field in the List response.
type lgmListData struct {
	Tier    string      `json:"tier"`
	Members []lgmMember `json:"members"`
}

// List returns all current members of the group identified by groupSID.
//
// Implementation applies the three-tier orphan-SID fallback (EC-6, ADR-LGM-5):
//
//	Tier 1 — Get-LocalGroupMember -SID <groupSID> (primary)
//	Tier 2 — Win32_GroupUser WMI query (orphan-resilient)
//	Tier 3 — net localgroup text parsing (last resort)
//	All-fail — returns empty slice, no error (conservative, ADR-LGM-5)
//
// Returns (nil, ErrLocalGroupMemberGroupNotFound) when the group itself is
// absent (EC-5). Returns (nil, ErrLocalGroupMemberPermission) on AccessDenied.
func (mc *LocalGroupMemberClient) List(ctx context.Context, groupSID string) ([]*LocalGroupMemberState, error) {
	qSID := psQuote(groupSID)

	script := fmt.Sprintf(`
$gSID  = %s

# ─── Tier 1: Get-LocalGroupMember ───────────────────────────────────────────
$t1Err  = $null
$t1Done = $false
$members = $null
try {
    $rawM = @(Get-LocalGroupMember -SID $gSID -ErrorAction Stop)
    $members = @()
    foreach ($m in $rawM) {
        $sidVal = if ($m.SID.PSObject.Properties.Name -contains 'Value') {
            $m.SID.Value
        } else {
            [string]$m.SID
        }
        $srcStr  = try { $m.PrincipalSource.ToString() } catch { 'Unknown' }
        $nameVal = if ($m.Name -and $m.Name.Length -gt 0) { $m.Name } else { $sidVal }
        $members += [ordered]@{ SID = $sidVal; Name = $nameVal; PrincipalSource = $srcStr }
    }
    $t1Done = $true
} catch {
    $t1Err = $_
}

if ($t1Done) {
    Emit-OK @{ tier = 'primary'; members = $members }
    return
}

# Group-not-found: distinct from orphaned-SID failure (EC-5)
if ($t1Err -and (
    $t1Err.FullyQualifiedErrorId -match 'GroupNotFound' -or
    $t1Err.Exception.Message     -match 'was not found'
)) {
    Emit-Err 'group_not_found' $t1Err.Exception.Message @{ group_sid = $gSID }
    return
}

# ─── Tier 2: Win32_GroupUser WMI ────────────────────────────────────────────
$t2Done  = $false
$members = $null
try {
    $grpWMI = @(Get-WmiObject -Class Win32_Group |
                 Where-Object { $_.SID -eq $gSID })
    if ($grpWMI.Count -eq 0) { throw "SID $gSID not found in Win32_Group" }
    $grpPath = $grpWMI[0].__PATH
    $rels    = @(Get-WmiObject -Class Win32_GroupUser |
                  Where-Object { $_.GroupComponent -eq $grpPath })
    $members = @()
    foreach ($rel in $rels) {
        $pc = $rel.PartComponent
        if ($pc -match "\.Domain='([^']+)',Name='([^']+)'") {
            $dom = $Matches[1]; $nm = $Matches[2]
            $dn  = "$dom\$nm"
            $sid = $dn
            try {
                $ntAcc = New-Object System.Security.Principal.NTAccount($dom, $nm)
                $sid   = $ntAcc.Translate(
                             [System.Security.Principal.SecurityIdentifier]).Value
            } catch {}
            $members += [ordered]@{
                SID             = $sid
                Name            = $dn
                PrincipalSource = 'Unknown'
            }
        }
    }
    $t2Done = $true
} catch {}

if ($t2Done) {
    Emit-OK @{ tier = 'wmi'; members = $members }
    return
}

# ─── Tier 3: net localgroup ─────────────────────────────────────────────────
$t3Done  = $false
$members = $null
try {
    $grpName = ''
    try {
        $grpName = (Get-LocalGroup -SID $gSID -ErrorAction Stop).Name
    } catch {}
    if ($grpName -eq '') {
        $w = @(Get-WmiObject -Class Win32_Group |
                Where-Object { $_.SID -eq $gSID })
        if ($w.Count -gt 0) { $grpName = $w[0].Name }
    }
    if ($grpName -eq '') { throw "Cannot resolve group name for SID $gSID" }

    $output  = & net localgroup $grpName 2>&1
    $members = @()
    $inSect  = $false
    foreach ($line in $output) {
        $s = [string]$line
        if ($s -match '^-+)                 { $inSect = $true;  continue }
        if ($s -match 'The command completed') { break }
        if (-not $inSect)                     { continue }
        $name = $s.Trim()
        if ($name -eq '')                     { continue }
        $sid = $name
        if (-not ($name -match '^S-\d')) {
            try {
                $ntAcc = New-Object System.Security.Principal.NTAccount($name)
                $sid   = $ntAcc.Translate(
                             [System.Security.Principal.SecurityIdentifier]).Value
            } catch {}
        }
        $members += [ordered]@{
            SID             = $sid
            Name            = $name
            PrincipalSource = 'Unknown'
        }
    }
    $t3Done = $true
} catch {}

if ($t3Done) {
    Emit-OK @{ tier = 'net_localgroup'; members = $members }
    return
}

# All tiers failed — conservative empty response (ADR-LGM-5)
Emit-OK @{ tier = 'all_failed'; members = @() }
`, qSID)

	resp, err := mc.runLGMEnvelope(ctx, "list", groupSID, script)
	if err != nil {
		return nil, err
	}

	var data lgmListData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, NewLocalGroupMemberError(LocalGroupMemberErrorUnknown,
			"list: failed to parse member list JSON",
			jerr,
			map[string]string{"group_sid": groupSID, "host": mc.c.cfg.Host})
	}

	states := make([]*LocalGroupMemberState, 0, len(data.Members))
	for _, m := range data.Members {
		sid := m.SID
		name := m.Name
		if name == "" {
			name = sid
		}
		src := normalizePrincipalSource(m.PrincipalSource)
		states = append(states, &LocalGroupMemberState{
			GroupSID:        groupSID,
			MemberSID:       sid,
			MemberName:      name,
			PrincipalSource: src,
		})
	}
	return states, nil
}

// ---------------------------------------------------------------------------
// Get — scan List output for matching member SID (EC-7)
// ---------------------------------------------------------------------------

// Get returns the observed state of the membership (groupSID, memberSID).
//
// Internally calls List (which applies the orphan fallback, EC-6) then scans
// the results for an entry whose MemberSID matches memberSID (strings.EqualFold,
// EC-7).
//
// Return semantics:
//
//	(*LocalGroupMemberState, nil) — membership exists and was read.
//	(nil, nil)                    — membership absent; group exists (EC-4 drift).
//	(nil, *LocalGroupMemberError{GroupNotFound}) — group absent (EC-5 drift).
func (mc *LocalGroupMemberClient) Get(ctx context.Context, groupSID string, memberSID string) (*LocalGroupMemberState, error) {
	members, err := mc.List(ctx, groupSID)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if strings.EqualFold(m.MemberSID, memberSID) {
			return m, nil
		}
	}
	return nil, nil // membership absent
}

// ---------------------------------------------------------------------------
// resolveMemberSID — translate identity string to SID via NTAccount (EC-3)
// ---------------------------------------------------------------------------

// resolveMemberSID resolves a member identity string (DOMAIN\user, UPN,
// bare username) to a Windows SID string via NTAccount.Translate on the
// remote host.
//
// If member already starts with "S-", it is returned as-is without a PS call
// (skip SID pre-resolution per spec §operations.create Step 1).
//
// On failure, returns ErrLocalGroupMemberUnresolvable with sub_type "local"
// or "domain" (EC-3, EC-10).
func (mc *LocalGroupMemberClient) resolveMemberSID(ctx context.Context, member string) (string, error) {
	if strings.HasPrefix(member, "S-") {
		return member, nil
	}

	qMember := psQuote(member)
	script := fmt.Sprintf(`
try {
    $m     = %s
    $ntAcc = New-Object System.Security.Principal.NTAccount($m)
    $sid   = $ntAcc.Translate([System.Security.Principal.SecurityIdentifier]).Value
    Emit-OK @{ sid = $sid }
} catch {
    $msg = $_.Exception.Message
    $sub = if ($msg -match '1355' -or $msg -match 'trusted' -or $msg -match 'domain') {
               'domain'
           } else {
               'local'
           }
    Emit-Err 'member_unresolvable' $msg @{ member = %s; sub_type = $sub }
}
`, qMember, qMember)

	resp, err := mc.runLGMEnvelope(ctx, "resolve_member_sid", member, script)
	if err != nil {
		return "", err
	}

	// Parse data: {"sid": "S-1-5-..."}
	var data struct {
		SID string `json:"sid"`
	}
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil || data.SID == "" {
		return "", NewLocalGroupMemberError(LocalGroupMemberErrorUnknown,
			"resolve_member_sid: unexpected response shape",
			jerr,
			map[string]string{"member": member, "host": mc.c.cfg.Host})
	}
	return data.SID, nil
}

// ---------------------------------------------------------------------------
// addMember — call Add-LocalGroupMember on the remote host
// ---------------------------------------------------------------------------

// addMember invokes Add-LocalGroupMember -SID <groupSID> -Member <member>
// on the remote host. It maps PowerShell exception patterns to typed
// LocalGroupMemberErrors. member is the identity string as supplied by the
// operator (not the resolved SID).
func (mc *LocalGroupMemberClient) addMember(ctx context.Context, groupSID, member string) error {
	qSID := psQuote(groupSID)
	qMember := psQuote(member)

	script := fmt.Sprintf(`
try {
    Add-LocalGroupMember -SID %s -Member %s -ErrorAction Stop
    Emit-OK @{ added = $true }
} catch {
    $msg  = $_.Exception.Message
    $fqei = $_.FullyQualifiedErrorId
    if ($fqei -match 'MemberExists' -or $msg -match 'already a member') {
        Emit-Err 'member_already_exists' $msg @{ member = %s }
    } elseif ($fqei -match 'GroupNotFound' -or $msg -match 'was not found') {
        Emit-Err 'group_not_found' $msg @{ group_sid = %s }
    } elseif ($fqei -match 'PrincipalNotFound' -or
              $msg  -match 'not found'          -or
              $msg  -match 'not recognized'     -or
              $msg  -match 'principal') {
        Emit-Err 'member_unresolvable' $msg @{ member = %s }
    } elseif ($fqei -match 'AccessDenied' -or $msg -match 'Access is denied') {
        Emit-Err 'permission_denied' $msg @{ member = %s; operation = 'add' }
    } else {
        Emit-Err 'unknown' $msg @{ member = %s; fqei = $fqei }
    }
}
`, qSID, qMember, qMember, qSID, qMember, qMember, qMember)

	_, err := mc.runLGMEnvelope(ctx, "add_member", groupSID+"/"+member, script)
	return err
}

// ---------------------------------------------------------------------------
// Add — pre-flight checks + Add-LocalGroupMember + Get (EC-1, EC-2, EC-3)
// ---------------------------------------------------------------------------

// Add adds a single member to the group identified by input.GroupSID.
//
// Pre-conditions (in order, per spec §operations.create):
//  1. SID pre-resolution: if input.Member does not start with "S-", resolve
//     it via NTAccount.Translate.  On failure → ErrLocalGroupMemberUnresolvable.
//  2. Pre-flight duplicate check via List.  Duplicate → ErrLocalGroupMemberAlreadyExists
//     with an import hint (EC-1, ADR-LGM-3).
//
// After Add-LocalGroupMember succeeds, calls Get to populate the computed
// attributes (MemberSID, MemberName, PrincipalSource) and returns the
// resulting *LocalGroupMemberState.
func (mc *LocalGroupMemberClient) Add(ctx context.Context, input LocalGroupMemberInput) (*LocalGroupMemberState, error) {
	// Step 1 — Resolve member SID for pre-flight (skip if already a SID).
	resolvedSID, err := mc.resolveMemberSID(ctx, input.Member)
	if err != nil {
		// Attach member + host context for EC-3 diagnostic.
		var lgme *LocalGroupMemberError
		if !IsLocalGroupMemberError(err, LocalGroupMemberErrorUnresolvable) {
			return nil, err
		}
		_ = lgme // type hint only
		return nil, err
	}

	// Step 2 — Pre-flight duplicate check (EC-1, ADR-LGM-3).
	members, listErr := mc.List(ctx, input.GroupSID)
	if listErr != nil {
		return nil, listErr
	}
	for _, m := range members {
		if strings.EqualFold(m.MemberSID, resolvedSID) {
			importHint := fmt.Sprintf(
				"Use: terraform import windows_local_group_member.<name> %q",
				input.GroupSID+"/"+resolvedSID,
			)
			return nil, NewLocalGroupMemberError(
				LocalGroupMemberErrorAlreadyExists,
				fmt.Sprintf(
					"member %q (SID: %s) is already a member of group %s on host %s. %s",
					input.Member, resolvedSID, input.GroupSID, mc.c.cfg.Host, importHint,
				),
				nil,
				map[string]string{
					"group_sid":  input.GroupSID,
					"member_sid": resolvedSID,
					"member":     input.Member,
					"host":       mc.c.cfg.Host,
				},
			)
		}
	}

	// Step 3 — Add-LocalGroupMember.
	if addErr := mc.addMember(ctx, input.GroupSID, input.Member); addErr != nil {
		return nil, addErr
	}

	// Step 4 — Read back the full state via Get to populate computed attrs.
	state, getErr := mc.Get(ctx, input.GroupSID, resolvedSID)
	if getErr != nil {
		return nil, getErr
	}
	if state == nil {
		// Unlikely — the member was just added; return a minimal state.
		return &LocalGroupMemberState{
			GroupSID:        input.GroupSID,
			MemberSID:       resolvedSID,
			MemberName:      resolvedSID,
			PrincipalSource: "Unknown",
		}, nil
	}
	return state, nil
}

// ---------------------------------------------------------------------------
// Remove — idempotent delete via SID (ADR-LGM-2, EC-4, EC-5)
// ---------------------------------------------------------------------------

// Remove removes the member identified by memberSID from the group identified
// by groupSID.
//
// PowerShell call:
//
//	Remove-LocalGroupMember -SID <groupSID> -Member <memberSID>
//
// The -Member parameter receives the SID string directly (ADR-LGM-2), which
// is the only approach that succeeds for renamed accounts and orphaned AD SIDs.
//
// Idempotency:
//   - "Member not found" from Windows → treat as success (EC-4).
//   - GroupNotFound → treat as success; log occurs at resource layer (EC-5).
//
// Returns ErrLocalGroupMemberPermission on AccessDenied (EC-8).
func (mc *LocalGroupMemberClient) Remove(ctx context.Context, groupSID string, memberSID string) error {
	qSID := psQuote(groupSID)
	qMemberSID := psQuote(memberSID)

	script := fmt.Sprintf(`
try {
    Remove-LocalGroupMember -SID %s -Member %s -ErrorAction Stop
    Emit-OK @{ removed = $true }
} catch {
    $msg  = $_.Exception.Message
    $fqei = $_.FullyQualifiedErrorId
    if ($fqei -match 'GroupNotFound' -or $msg -match 'was not found') {
        Emit-OK @{ removed = $true; note = 'group_not_found' }
    } elseif ($fqei -match 'MemberNotFound' -or
              $msg  -match 'not a member'    -or
              $msg  -match 'could not be found') {
        Emit-OK @{ removed = $true; note = 'member_not_found' }
    } elseif ($fqei -match 'AccessDenied' -or $msg -match 'Access is denied') {
        Emit-Err 'permission_denied' $msg @{
            group_sid  = %s
            member_sid = %s
            operation  = 'remove'
        }
    } else {
        Emit-Err 'unknown' $msg @{
            group_sid  = %s
            member_sid = %s
            fqei       = $fqei
        }
    }
}
`, qSID, qMemberSID, qSID, qMemberSID, qSID, qMemberSID)

	_, err := mc.runLGMEnvelope(ctx, "remove", groupSID+"/"+memberSID, script)
	return err
}
