// Package winclient defines types and the client interface for managing
// Windows local groups over SSH.
//
// Spec alignment: windows_local_group spec v1 (2026-04-25).
//
// File layout:
//
//	LocalGroupErrorKind      — string enum of typed error categories (7 kinds)
//	LocalGroupError          — structured error type with Kind, Message, Context, Cause
//	Sentinel errors          — pre-constructed *LocalGroupError values for errors.Is
//	GroupInput               — input parameters for Create/Update operations
//	GroupState               — observed state returned by Read
//	WindowsLocalGroupClient  — CRUD + import interface
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// LocalGroupErrorKind — typed error categories
// ---------------------------------------------------------------------------

// LocalGroupErrorKind categorises errors returned by WindowsLocalGroupClient
// operations. Use errors.Is(err, ErrLocalGroup*) or
// IsLocalGroupError(err, kind) for programmatic error handling in resource
// CRUD handlers.
type LocalGroupErrorKind string

const (
	// LocalGroupErrorNotFound is returned when Get-LocalGroup raises
	// GroupNotFound for the given SID. In Read, this triggers
	// RemoveResource() — the drift-tolerant "disappeared outside Terraform"
	// path (EC-3).
	LocalGroupErrorNotFound = "not_found"

	// LocalGroupErrorAlreadyExists is returned when Create detects a
	// pre-existing group with the same name before calling New-LocalGroup
	// (EC-1). Hard error — the operator must use terraform import.
	LocalGroupErrorAlreadyExists = "already_exists"

	// LocalGroupErrorBuiltinGroup is returned when Delete detects that the
	// target group's SID matches the BUILTIN authority prefix "S-1-5-32-"
	// (EC-2, ADR-LG-2). Hard error — not a warning.
	LocalGroupErrorBuiltinGroup = "builtin_group"

	// LocalGroupErrorPermission is returned when a mutating cmdlet is
	// rejected with AccessDenied (EC-8).
	LocalGroupErrorPermission = "permission_denied"

	// LocalGroupErrorNameConflict is returned when Rename-LocalGroup fails
	// because the target name is already used by another local group (EC-5).
	LocalGroupErrorNameConflict = "name_conflict"

	// LocalGroupErrorInvalidName is returned when a group name fails
	// Windows-side validation (defence-in-depth, EC-6).
	LocalGroupErrorInvalidName = "invalid_name"

	// LocalGroupErrorInvalidParameter is returned when a List filter fails
	// Go-side validation (e.g. name_regex is not a valid regular expression).
	// No host call is made in that case.
	LocalGroupErrorInvalidParameter = "invalid_parameter"

	// LocalGroupErrorUnsupportedOnDC is returned when List runs on a domain
	// controller (Win32_ComputerSystem DomainRole >= 4), where the
	// LocalAccounts cmdlets address the domain database, not local groups.
	LocalGroupErrorUnsupportedOnDC = "unsupported_on_domain_controller"

	// LocalGroupErrorUnknown is returned for unrecognised PowerShell errors
	// or unexpected SSH transport failures.
	LocalGroupErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// LocalGroupError — structured error type
// ---------------------------------------------------------------------------

// LocalGroupError is the structured error type returned by all
// WindowsLocalGroupClient methods.
//
// Callers should use errors.Is(err, ErrLocalGroup*) for kind matching, or
// errors.As(err, &lge) to access the full Context map for diagnostics.
type LocalGroupError = ResourceError

// NewLocalGroupError constructs a *LocalGroupError. Pass a nil cause when no
// underlying error exists. The ctx map may be nil.
func NewLocalGroupError(
	kind LocalGroupErrorKind,
	message string,
	cause error,
	ctx map[string]string,
) *LocalGroupError {
	return NewResourceError("windows_local_group", string(kind), message, cause, ctx)
}

// IsLocalGroupError reports whether err is a *LocalGroupError with the given
// kind. Equivalent to errors.Is(err, &LocalGroupError{Kind: kind}) but more
// readable at call sites.
func IsLocalGroupError(err error, kind LocalGroupErrorKind) bool {
	return IsResourceError(err, "windows_local_group", string(kind))
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

// ErrLocalGroupNotFound is a sentinel for GroupNotFound (EC-3, EC-10).
var ErrLocalGroupNotFound = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorNotFound}

// ErrLocalGroupAlreadyExists is a sentinel for name collision at Create (EC-1).
var ErrLocalGroupAlreadyExists = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorAlreadyExists}

// ErrLocalGroupBuiltinGroup is a sentinel for BUILTIN group deletion attempt (EC-2).
var ErrLocalGroupBuiltinGroup = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorBuiltinGroup}

// ErrLocalGroupPermission is a sentinel for AccessDenied (EC-8).
var ErrLocalGroupPermission = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorPermission}

// ErrLocalGroupNameConflict is a sentinel for rename target already taken (EC-5).
var ErrLocalGroupNameConflict = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorNameConflict}

// ErrLocalGroupInvalidName is a sentinel for invalid name (EC-6).
var ErrLocalGroupInvalidName = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorInvalidName}

// ErrLocalGroupInvalidParameter is a sentinel for invalid List filters.
var ErrLocalGroupInvalidParameter = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorInvalidParameter}

// ErrLocalGroupUnsupportedOnDC is a sentinel for List on a domain controller.
var ErrLocalGroupUnsupportedOnDC = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorUnsupportedOnDC}

// ErrLocalGroupUnknown is a sentinel for unexpected errors.
var ErrLocalGroupUnknown = &LocalGroupError{Resource: "windows_local_group", Kind: LocalGroupErrorUnknown}

// ---------------------------------------------------------------------------
// GroupInput — input parameters for Create and Update
// ---------------------------------------------------------------------------

// GroupInput carries the desired configuration for a Windows local group.
// It is consumed by the Create and Update methods of WindowsLocalGroupClient.
type GroupInput struct {
	// Name is the desired Windows local group name.
	// Create: passed to New-LocalGroup -Name.
	// Update: if it differs from the current name (strings.EqualFold = false),
	// passed to Rename-LocalGroup -SID <sid> -NewName <name> BEFORE Set-LocalGroup.
	Name string

	// Description is the optional free-text description of the group.
	// Create: passed to New-LocalGroup -Description.
	// Update: passed to Set-LocalGroup -SID <sid> -Description.
	Description string
}

// ---------------------------------------------------------------------------
// GroupState — observed state returned by Read
// ---------------------------------------------------------------------------

// GroupState holds the observed state of a Windows local group as returned
// by Read (Get-LocalGroup -SID <sid> | ConvertTo-Json -Depth 3).
//
// Members are populated only by LocalGroupLister.List when the
// IncludeMembers filter is set; every other entry point (Read, Create,
// Update, Import) leaves them nil. Membership management itself is out of
// scope for the resource (ADR-LG-3); the windows_local_group_member
// resource owns single-membership lifecycle.
type GroupState struct {
	// Name is the Windows local group name as returned by Get-LocalGroup.
	// Always stored in the casing that Windows uses (ADR-LG-4).
	Name string

	// Description is the group description from Get-LocalGroup.Description.
	// Empty string when Windows stores no description.
	Description string

	// SID is the Security Identifier string (e.g. "S-1-5-21-...-1001"),
	// extracted from the LocalGroup.SID.Value field of the JSON response.
	// Used as the Terraform resource ID and as the -SID parameter for all
	// subsequent mutating cmdlets.
	SID string

	// Members holds the observed membership of the group, sorted by member
	// SID. Nil when membership was not requested (IncludeMembers false);
	// a non-nil empty slice means the group was read with membership and
	// has none. Orphaned SIDs keep an empty MemberName (no ""-to-SID
	// coercion here — that coercion lives in ClientLocalGroupMember.List).
	Members []LocalGroupMemberState
}

// ---------------------------------------------------------------------------
// WindowsLocalGroupClient — CRUD + import interface
// ---------------------------------------------------------------------------

// WindowsLocalGroupClient defines the contract for managing Windows local
// groups over SSH (Microsoft.PowerShell.LocalAccounts module).
//
// All methods accept a context.Context for cancellation and timeout propagation.
// All methods return *LocalGroupError (wrapped in error).
type WindowsLocalGroupClient interface {
	// Create creates a new local group via New-LocalGroup.
	// Pre-flight: checks for existing group by name (EC-1) and module availability.
	// Returns ErrLocalGroupAlreadyExists (EC-1), ErrLocalGroupPermission (EC-8),
	// or ErrLocalGroupInvalidName (EC-6).
	Create(ctx context.Context, input GroupInput) (*GroupState, error)

	// Read retrieves the current state of the group identified by its SID.
	// Returns (nil, nil) when the group does not exist (EC-3).
	// Returns ErrLocalGroupPermission (EC-8) on AccessDenied.
	Read(ctx context.Context, sid string) (*GroupState, error)

	// Update applies in-place changes: Rename-LocalGroup (if name changed,
	// case-insensitive) then Set-LocalGroup for description.
	// Returns ErrLocalGroupNameConflict (EC-5) or ErrLocalGroupPermission (EC-8).
	Update(ctx context.Context, sid string, input GroupInput) (*GroupState, error)

	// Delete removes the group. Pre-flight BUILTIN guard (EC-2, ADR-LG-2).
	// Returns ErrLocalGroupBuiltinGroup (EC-2) or ErrLocalGroupPermission (EC-8).
	Delete(ctx context.Context, sid string) error

	// ImportByName resolves a local group by name (EC-10, non-SID import path).
	// Returns ErrLocalGroupNotFound when no group with the given name exists.
	ImportByName(ctx context.Context, name string) (*GroupState, error)

	// ImportBySID resolves a local group by SID string (EC-10, SID import path).
	// Returns ErrLocalGroupNotFound when no group with the given SID exists.
	ImportBySID(ctx context.Context, sid string) (*GroupState, error)
}

// ---------------------------------------------------------------------------
// LocalGroupFilter / LocalGroupLister — read-only inventory (issue #298)
// ---------------------------------------------------------------------------

// LocalGroupFilter narrows a LocalGroupLister List call. The zero value
// matches every non-built-in local group on the host; set IncludeBuiltin to
// include groups under the S-1-5-32 BUILTIN authority.
type LocalGroupFilter struct {
	// Names is an optional exact-match set of group names. Empty matches all.
	// Applied host-side via Where-Object -eq (case-insensitive, like Windows).
	Names []string

	// SIDs is an optional exact-match set of group SID strings. Empty matches
	// all. Applied host-side via Where-Object -eq.
	SIDs []string

	// NameRegex is an optional RE2 regular expression matched against the
	// group name. Matching is case-sensitive; prefix the pattern with (?i)
	// for a case-insensitive match. Applied Go-side.
	NameRegex string

	// IncludeBuiltin keeps built-in groups (SID prefix "S-1-5-32-", e.g.
	// Administrators, Users, Guests) when true; false drops them.
	IncludeBuiltin bool

	// IncludeMembers populates GroupState.Members via the shared
	// Get-LgmMembers projection when true; false leaves Members nil.
	IncludeMembers bool
}

// LocalGroupLister is the read-only inventory contract for the
// windows_local_groups collection data source.
//
// It is intentionally separate from WindowsLocalGroupClient: adding List to
// WindowsLocalGroupClient would break every existing fake implementing that
// interface (resource + singular data source tests). List reuses the exact
// per-group JSON projection of Read plus the shared Get-LgmMembers member
// projection of ClientLocalGroupMember.List, so all paths evolve together.
type LocalGroupLister interface {
	// List returns every local group in a single round-trip, filtered and
	// sorted by name (case-insensitive). Members are populated only when
	// the filter requests them, sorted by member SID. An empty inventory
	// match is valid (empty slice, nil error); invalid filters return a
	// typed invalid_parameter error without any host call.
	List(ctx context.Context, filter LocalGroupFilter) ([]GroupState, error)
}
