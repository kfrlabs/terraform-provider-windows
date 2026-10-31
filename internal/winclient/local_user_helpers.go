// Package winclient — shared helper for resolving a Windows local user to a
// canonical UserState.
//
// ADR-LU-6: This helper is symmetric to ResolveGroup in local_group_helpers.go.
// It may be used by future resources (e.g. a local_group_member variant) to
// pre-resolve a local user identity without duplicating PowerShell logic.
//
// Design invariants:
//   - If nameOrSID starts with "S-", Get-LocalUser -SID is used.
//   - Otherwise, Get-LocalUser -Name is used.
//   - Errors are returned as *LocalUserError (same as local_user.go).
//   - Does NOT touch existing files (local_group_helpers.go, etc.).
package winclient

import (
	"context"
	"fmt"
	"strings"
)

// ResolveLocalUserSID resolves a user-supplied identifier (SAM name or SID
// string) to a *UserState containing the canonical SID and all observable
// attributes as returned by Windows.
//
// Auto-detection:
//   - If nameOrSID starts with "S-" → calls Get-LocalUser -SID <nameOrSID>.
//   - Otherwise             → calls Get-LocalUser -Name <nameOrSID>.
//
// On success, UserState.SID is the stable SID used for all subsequent
// mutating cmdlets (ADR-LU-1).
//
// On failure, returns a *LocalUserError. Callers that need a different error
// type should check for LocalUserErrorNotFound and wrap accordingly.
//
// Reuses luPsHeader and runPowerShell from local_user.go (same package),
// with envelope parsing centralised in runEnvelope (see envelope.go).
func ResolveLocalUserSID(ctx context.Context, c *Client, nameOrSID string) (*UserState, error) {
	q := psQuote(nameOrSID)

	var param string
	if strings.HasPrefix(nameOrSID, "S-") {
		param = "-SID " + q
	} else {
		param = "-Name " + q
	}

	script := luPsHeader + "\n" + fmt.Sprintf(`
try {
    $user = Get-LocalUser %s -ErrorAction Stop
    $data = Get-UserData $user
    Emit-OK $data
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ user = %s; step = 'resolve_user_sid' }
}
`, param, q)

	baseContext := map[string]string{"user": nameOrSID, "host": c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, c, full)
		},
		"resolve_local_user_sid", script, "", baseContext)
	if eerr == nil {
		return parseUserData("resolve_local_user_sid", resp.Data)
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			"ResolveLocalUserSID: operation timed out or was cancelled",
			eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		msg := "ResolveLocalUserSID: SSH transport error"
		switch eerr.Stage {
		case EnvelopeStageNoEnvelope:
			msg = "ResolveLocalUserSID: no JSON envelope returned"
		case EnvelopeStageInvalidJSON:
			msg = "ResolveLocalUserSID: invalid JSON envelope"
		}
		return nil, NewLocalUserError(LocalUserErrorUnknown, msg, eerr.Cause, eerr.Context)
	}
	return nil, NewLocalUserError(mapLUKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}
