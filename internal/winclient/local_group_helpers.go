// Package winclient — shared helper for resolving a Windows local group to a
// canonical GroupState.
//
// ADR-LGM-6: This helper is extracted from local_group.go so that both
// LocalGroupClient (windows_local_group) and LocalGroupMemberClient
// (windows_local_group_member) can resolve a user-supplied name-or-SID to a
// canonical GroupState.SID without duplicating the PowerShell logic.
//
// Design invariants:
//   - If groupOrSID starts with "S-", Get-LocalGroup -SID is used.
//   - Otherwise, Get-LocalGroup -Name is used.
//   - Errors are returned as *LocalGroupError (same as local_group.go).
//   - The caller (LocalGroupMemberClient) is responsible for converting
//     LocalGroupErrorNotFound to LocalGroupMemberErrorGroupNotFound.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ResolveGroup resolves a user-supplied group identifier (name or SID string)
// to a *GroupState containing the canonical SID and name as returned by Windows.
//
// Auto-detection:
//   - If groupOrSID starts with "S-" → calls Get-LocalGroup -SID <groupOrSID>.
//   - Otherwise                       → calls Get-LocalGroup -Name <groupOrSID>.
//
// On success, GroupState.SID is the stable SID used for all subsequent
// Add-LocalGroupMember / Remove-LocalGroupMember operations (ADR-LGM-6).
//
// On failure, returns a *LocalGroupError. Callers that need a
// *LocalGroupMemberError should check for LocalGroupErrorNotFound and wrap
// it accordingly.
//
// The function reuses lgPsHeader, runPowerShell, extractLastJSONLine,
// truncate, psResponse, mapLGKind, and parseGroupData from local_group.go
// and service.go (all in the same package).
func ResolveGroup(ctx context.Context, c *Client, groupOrSID string) (*GroupState, error) {
	q := psQuote(groupOrSID)

	var param string
	if strings.HasPrefix(groupOrSID, "S-") {
		param = "-SID " + q
	} else {
		param = "-Name " + q
	}

	script := lgPsHeader + "\n" + fmt.Sprintf(`
try {
    $group = Get-LocalGroup %s -ErrorAction Stop
    Emit-OK $group
} catch {
    $kind = Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ group = %s; step = 'resolve_group' }
}
`, param, q)

	stdout, stderr, err := runPowerShell(ctx, c, script)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewLocalGroupError(LocalGroupErrorUnknown,
				"ResolveGroup: operation timed out or was cancelled",
				ctx.Err(),
				map[string]string{
					"group": groupOrSID,
					"host":  c.cfg.Host,
				})
		}
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			"ResolveGroup: WinRM transport error",
			err,
			map[string]string{
				"group":  groupOrSID,
				"host":   c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			"ResolveGroup: no JSON envelope returned",
			nil,
			map[string]string{
				"group":  groupOrSID,
				"host":   c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			"ResolveGroup: invalid JSON envelope",
			jerr,
			map[string]string{
				"group":  groupOrSID,
				"host":   c.cfg.Host,
				"stdout": truncate(stdout, 2048),
			})
	}

	if !resp.OK {
		kind := mapLGKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["group"] = groupOrSID
		ctxMap["host"] = c.cfg.Host
		return nil, NewLocalGroupError(kind, resp.Message, nil, ctxMap)
	}

	return parseGroupData("resolve_group", resp.Data)
}
