// Package winclient — shared types for the windows_local_group_member resource.
//
// Spec alignment: windows_local_group_member spec v1 (2026-04-25).
//
// File layout (this file only — no helpers):
//
//	LocalGroupMemberErrorKind  — string enum of typed error categories (6 kinds)
//	LocalGroupMemberError      — structured error type with Kind, Message, Context, Cause
//	Sentinel errors            — pre-constructed *LocalGroupMemberError for errors.Is
//	LocalGroupMemberInput      — parameters consumed by ClientLocalGroupMember.Add
//	LocalGroupMemberState      — observed state returned by Get / Add
//	ClientLocalGroupMember     — interface for managing (group, member) pairs
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// LocalGroupMemberErrorKind — typed error categories
// ---------------------------------------------------------------------------

// LocalGroupMemberErrorKind categorises errors returned by
// ClientLocalGroupMember operations.  Use
// errors.Is(err, ErrLocalGroupMember*) or
// IsLocalGroupMemberError(err, kind) for programmatic error handling in
// resource CRUD handlers.
type LocalGroupMemberErrorKind string

const (
	// LocalGroupMemberErrorGroupNotFound is returned when the group resolved
	// from groupSID is absent (Get-LocalGroup -SID returns GroupNotFound).
	//
	//   • Add (Create) → hard error; diagnostic attribute path: "group" (EC-2).
	//   • Get (Read)   → the caller MUST call resp.State.RemoveResource()
	//                    and return nil — not an error (EC-5).
	//   • Remove (Delete) → treat as success; log tflog.Debug and return nil.
	LocalGroupMemberErrorGroupNotFound LocalGroupMemberErrorKind = "group_not_found"

	// LocalGroupMemberErrorAlreadyExists is returned by Add when the
	// pre-flight duplicate check detects that the resolved member SID is
	// already present in the group (EC-1, ADR-LGM-3).
	//
	// The diagnostic MUST include an import hint.
	LocalGroupMemberErrorAlreadyExists LocalGroupMemberErrorKind = "member_already_exists"

	// LocalGroupMemberErrorUnresolvable is returned when the member identity
	// string cannot be resolved to a SID on the target host (EC-3, EC-10).
	//
	// Context MUST carry:
	//   "sub_type"  → "local" or "domain"
	//   "member"    → the original identity string.
	//   "host"      → the WinRM target hostname.
	//
	// Diagnostic attribute path: "member".
	LocalGroupMemberErrorUnresolvable LocalGroupMemberErrorKind = "member_unresolvable"

	// LocalGroupMemberErrorNotFound is used by the import path when the
	// requested membership is absent after full resolution.  During normal
	// Read, Get returns (nil, nil) rather than this error (EC-4 drift).
	LocalGroupMemberErrorNotFound LocalGroupMemberErrorKind = "member_not_found"

	// LocalGroupMemberErrorPermission is returned when Add-LocalGroupMember
	// or Remove-LocalGroupMember raises AccessDenied (EC-8).
	LocalGroupMemberErrorPermission LocalGroupMemberErrorKind = "permission_denied"

	// LocalGroupMemberErrorUnknown is the catch-all for unrecognised
	// PowerShell errors or WinRM transport failures.
	LocalGroupMemberErrorUnknown LocalGroupMemberErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// LocalGroupMemberError — structured error type
// ---------------------------------------------------------------------------

// LocalGroupMemberError is the structured error type returned by all
// ClientLocalGroupMember methods.
//
// Caller idiom:
//
//	errors.Is(err, ErrLocalGroupMemberAlreadyExists)  // kind matching
//	errors.As(err, &lgme)                             // full Context access
//
// No secrets (passwords, tokens) may appear in Message, Context, or Cause.
type LocalGroupMemberError struct {
	// Kind is the machine-readable error category.
	Kind LocalGroupMemberErrorKind

	// Message is a human-readable, diagnostic-safe description.
	Message string

	// Context holds structured key-value pairs for diagnostics.
	// All values MUST be log-safe (no credentials).
	Context map[string]string

	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *LocalGroupMemberError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_local_group_member [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_local_group_member [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *LocalGroupMemberError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only, enabling:
//
//	errors.Is(err, ErrLocalGroupMemberAlreadyExists)
//	// true for any *LocalGroupMemberError{Kind: LocalGroupMemberErrorAlreadyExists}
func (e *LocalGroupMemberError) Is(target error) bool {
	t, ok := target.(*LocalGroupMemberError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewLocalGroupMemberError constructs a *LocalGroupMemberError.
// Pass nil cause when no underlying error exists; ctx may be nil.
func NewLocalGroupMemberError(
	kind LocalGroupMemberErrorKind,
	message string,
	cause error,
	ctx map[string]string,
) *LocalGroupMemberError {
	return &LocalGroupMemberError{
		Kind:    kind,
		Message: message,
		Cause:   cause,
		Context: ctx,
	}
}

// IsLocalGroupMemberError reports whether err is a *LocalGroupMemberError
// of the given kind.
func IsLocalGroupMemberError(err error, kind LocalGroupMemberErrorKind) bool {
	var lgme *LocalGroupMemberError
	if errors.As(err, &lgme) {
		return lgme.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

// ErrLocalGroupMemberGroupNotFound is a sentinel for group-not-found (EC-5).
var ErrLocalGroupMemberGroupNotFound = &LocalGroupMemberError{Kind: LocalGroupMemberErrorGroupNotFound}

// ErrLocalGroupMemberAlreadyExists is a sentinel for duplicate membership (EC-1).
var ErrLocalGroupMemberAlreadyExists = &LocalGroupMemberError{Kind: LocalGroupMemberErrorAlreadyExists}

// ErrLocalGroupMemberUnresolvable is a sentinel for unresolvable member identity (EC-3).
var ErrLocalGroupMemberUnresolvable = &LocalGroupMemberError{Kind: LocalGroupMemberErrorUnresolvable}

// ErrLocalGroupMemberNotFound is a sentinel for absent membership (import path, EC-4).
var ErrLocalGroupMemberNotFound = &LocalGroupMemberError{Kind: LocalGroupMemberErrorNotFound}

// ErrLocalGroupMemberPermission is a sentinel for AccessDenied (EC-8).
var ErrLocalGroupMemberPermission = &LocalGroupMemberError{Kind: LocalGroupMemberErrorPermission}

// ErrLocalGroupMemberUnknown is a sentinel for unmapped errors.
var ErrLocalGroupMemberUnknown = &LocalGroupMemberError{Kind: LocalGroupMemberErrorUnknown}

// ---------------------------------------------------------------------------
// LocalGroupMemberInput — parameters for ClientLocalGroupMember.Add
// ---------------------------------------------------------------------------

// LocalGroupMemberInput carries the inputs required to add one member to a
// group.  Consumed exclusively by ClientLocalGroupMember.Add.
//
// Naming mirrors the PowerShell parameter semantics:
//
//	Add-LocalGroupMember -SID <GroupSID> -Member <Member>
type LocalGroupMemberInput struct {
	// GroupSID is the Security Identifier of the target local group,
	// obtained by calling ResolveGroup (ADR-LGM-6) before invoking Add.
	GroupSID string

	// Member is the Windows identity string for the account being added.
	// Accepted formats (passed verbatim to Add-LocalGroupMember -Member):
	//   "DOMAIN\username"    — domain user via NetBIOS domain
	//   "MACHINE\username"   — local account with explicit machine prefix
	//   "username"           — local account (implicit local machine)
	//   "user@domain.tld"    — UPN format (domain account)
	//   "S-1-5-21-...-XXXX" — direct SID string (skip SID pre-resolution)
	Member string
}

// ---------------------------------------------------------------------------
// LocalGroupMemberState — observed state returned by Add / Get
// ---------------------------------------------------------------------------

// LocalGroupMemberState holds the observed state of a single (group, member)
// membership as resolved by Windows.
//
// SID comparisons MUST use strings.EqualFold (case-insensitive) per EC-7.
//
// Orphaned AD SID handling (EC-6):
//   - MemberName      is set to MemberSID when Windows returns an empty name.
//   - PrincipalSource is set to "Unknown" when the account is orphaned.
type LocalGroupMemberState struct {
	// GroupSID is the Security Identifier of the containing group.
	GroupSID string

	// MemberSID is the Security Identifier of the member account as resolved
	// by Windows. Source of truth for drift detection and Remove.
	MemberSID string

	// MemberName is the canonical display name returned by Windows.
	// Set to MemberSID for orphaned AD SIDs (EC-6).
	MemberName string

	// PrincipalSource is the account origin: "Local", "ActiveDirectory",
	// "AzureAD", "MicrosoftAccount", or "Unknown" (orphaned SIDs, EC-6).
	PrincipalSource string
}

// ---------------------------------------------------------------------------
// ClientLocalGroupMember — interface for managing a single (group, member) pair
// ---------------------------------------------------------------------------

// ClientLocalGroupMember defines the contract for managing a single
// (group, member) membership on a remote Windows host via WinRM.
//
// Design invariants:
//   - All group lookups use the group SID to be immune to concurrent renames (ADR-LGM-6).
//   - The member SID is used for Remove and Get after initial creation (ADR-LGM-2, ADR-LGM-4).
//   - Non-authoritative: List and Get only observe; they never alter unowned memberships.
//   - Idempotent delete: Remove treats "member not found" as success (EC-4).
//   - Orphaned AD SID fallback: List applies the three-tier fallback (EC-6, ADR-LGM-5).
//   - Update is a no-op at the resource layer (all attributes are ForceNew, EC-11).
type ClientLocalGroupMember interface {
	// Add adds a single member to the group identified by input.GroupSID.
	//
	// Pre-conditions (in order):
	//  1. SID pre-resolution: if input.Member does not start with "S-",
	//     resolve it via NTAccount.Translate. Failure → ErrLocalGroupMemberUnresolvable.
	//  2. Pre-flight duplicate check via List. Duplicate → ErrLocalGroupMemberAlreadyExists.
	//
	// After success: calls Get to populate computed attributes and returns
	// the resulting *LocalGroupMemberState.
	Add(ctx context.Context, input LocalGroupMemberInput) (*LocalGroupMemberState, error)

	// Remove removes the member identified by memberSID from the group.
	// Treats "member not found" and "group not found" as success (idempotent).
	Remove(ctx context.Context, groupSID string, memberSID string) error

	// Get returns the observed state of the membership.
	//
	// Return semantics:
	//   (*LocalGroupMemberState, nil) — membership exists.
	//   (nil, nil)                    — membership absent; group exists (EC-4 drift).
	//   (nil, ErrLocalGroupMemberGroupNotFound) — group absent (EC-5 drift).
	Get(ctx context.Context, groupSID string, memberSID string) (*LocalGroupMemberState, error)

	// List returns all current members of the group, applying the three-tier
	// orphan-SID fallback (EC-6). On all-tiers failure: returns empty slice.
	// Returns (nil, ErrLocalGroupMemberGroupNotFound) when the group is absent.
	List(ctx context.Context, groupSID string) ([]*LocalGroupMemberState, error)
}
