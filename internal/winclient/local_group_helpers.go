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
// The function reuses lgPsHeader, runPowerShell and parseGroupData from
// local_group.go and service.go (all in the same package), with envelope
// parsing centralised in runEnvelope (see envelope.go).
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

	baseContext := map[string]string{"group": groupOrSID, "host": c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, c, full)
		},
		"resolve_group", script, "", baseContext)
	if eerr == nil {
		return parseGroupData("resolve_group", resp.Data)
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewLocalGroupError(LocalGroupErrorUnknown,
			"ResolveGroup: operation timed out or was cancelled",
			eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		msg := "ResolveGroup: SSH transport error"
		switch eerr.Stage {
		case EnvelopeStageNoEnvelope:
			msg = "ResolveGroup: no JSON envelope returned"
		case EnvelopeStageInvalidJSON:
			msg = "ResolveGroup: invalid JSON envelope"
		}
		return nil, NewLocalGroupError(LocalGroupErrorUnknown, msg, eerr.Cause, eerr.Context)
	}
	return nil, NewLocalGroupError(mapLGKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}
