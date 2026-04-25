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
	"encoding/json"
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
// Reuses luPsHeader, runPowerShell, extractLastJSONLine, truncate, psResponse,
// mapLUKind, and parseUserData from local_user.go (same package).
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

	stdout, stderr, err := runPowerShell(ctx, c, script)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewLocalUserError(LocalUserErrorUnknown,
				"ResolveLocalUserSID: operation timed out or was cancelled",
				ctx.Err(),
				map[string]string{"user": nameOrSID, "host": c.cfg.Host},
			)
		}
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			"ResolveLocalUserSID: WinRM transport error",
			err,
			map[string]string{
				"user":   nameOrSID,
				"host":   c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		)
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			"ResolveLocalUserSID: no JSON envelope returned",
			nil,
			map[string]string{
				"user":   nameOrSID,
				"host":   c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		)
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			"ResolveLocalUserSID: invalid JSON envelope",
			jerr,
			map[string]string{
				"user":   nameOrSID,
				"host":   c.cfg.Host,
				"stdout": truncate(stdout, 2048),
			},
		)
	}

	if !resp.OK {
		kind := mapLUKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["user"] = nameOrSID
		ctxMap["host"] = c.cfg.Host
		return nil, NewLocalUserError(kind, resp.Message, nil, ctxMap)
	}

	return parseUserData("resolve_local_user_sid", resp.Data)
}
