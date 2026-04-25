// Package winclient defines types and the client interface for managing
// Windows local groups over WinRM.
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
	"errors"
	"fmt"
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
	LocalGroupErrorNotFound LocalGroupErrorKind = "not_found"

	// LocalGroupErrorAlreadyExists is returned when Create detects a
	// pre-existing group with the same name before calling New-LocalGroup
	// (EC-1). Hard error — the operator must use terraform import.
	LocalGroupErrorAlreadyExists LocalGroupErrorKind = "already_exists"

	// LocalGroupErrorBuiltinGroup is returned when Delete detects that the
	// target group's SID matches the BUILTIN authority prefix "S-1-5-32-"
	// (EC-2, ADR-LG-2). Hard error — not a warning.
	LocalGroupErrorBuiltinGroup LocalGroupErrorKind = "builtin_group"

	// LocalGroupErrorPermission is returned when a mutating cmdlet is
	// rejected with AccessDenied (EC-8).
	LocalGroupErrorPermission LocalGroupErrorKind = "permission_denied"

	// LocalGroupErrorNameConflict is returned when Rename-LocalGroup fails
	// because the target name is already used by another local group (EC-5).
	LocalGroupErrorNameConflict LocalGroupErrorKind = "name_conflict"

	// LocalGroupErrorInvalidName is returned when a group name fails
	// Windows-side validation (defence-in-depth, EC-6).
	LocalGroupErrorInvalidName LocalGroupErrorKind = "invalid_name"

	// LocalGroupErrorUnknown is returned for unrecognised PowerShell errors
	// or unexpected WinRM transport failures.
	LocalGroupErrorUnknown LocalGroupErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// LocalGroupError — structured error type
// ---------------------------------------------------------------------------

// LocalGroupError is the structured error type returned by all
// WindowsLocalGroupClient methods.
//
// Callers should use errors.Is(err, ErrLocalGroup*) for kind matching, or
// errors.As(err, &lge) to access the full Context map for diagnostics.
type LocalGroupError struct {
	// Kind is the machine-readable error category.
	Kind LocalGroupErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics and provider logs.
	Message string

	// Context holds structured diagnostic key-value pairs (e.g. "host",
	// "sid", "name", "new_name", "operation", "output", "exit_code").
	// All values must be safe to log — no secrets.
	Context map[string]string

	// Cause is the underlying error, if any (e.g. a WinRM transport error).
	Cause error
}

// Error implements the error interface.
func (e *LocalGroupError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_local_group [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_local_group [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *LocalGroupError) Unwrap() error {
	return e.Cause
}

// Is implements errors.Is comparison by Kind only.
//
// This allows:
//
//	errors.Is(err, ErrLocalGroupNotFound) // true when err.Kind == LocalGroupErrorNotFound
func (e *LocalGroupError) Is(target error) bool {
	t, ok := target.(*LocalGroupError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewLocalGroupError constructs a *LocalGroupError. Pass a nil cause when no
// underlying error exists. The ctx map may be nil.
func NewLocalGroupError(
	kind LocalGroupErrorKind,
	message string,
	cause error,
	ctx map[string]string,
) *LocalGroupError {
	return &LocalGroupError{
		Kind:    kind,
		Message: message,
		Cause:   cause,
		Context: ctx,
	}
}

// IsLocalGroupError reports whether err is a *LocalGroupError with the given
// kind. Equivalent to errors.Is(err, &LocalGroupError{Kind: kind}) but more
// readable at call sites.
func IsLocalGroupError(err error, kind LocalGroupErrorKind) bool {
	var lge *LocalGroupError
	if errors.As(err, &lge) {
		return lge.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

// ErrLocalGroupNotFound is a sentinel for GroupNotFound (EC-3, EC-10).
var ErrLocalGroupNotFound = &LocalGroupError{Kind: LocalGroupErrorNotFound}

// ErrLocalGroupAlreadyExists is a sentinel for name collision at Create (EC-1).
var ErrLocalGroupAlreadyExists = &LocalGroupError{Kind: LocalGroupErrorAlreadyExists}

// ErrLocalGroupBuiltinGroup is a sentinel for BUILTIN group deletion attempt (EC-2).
var ErrLocalGroupBuiltinGroup = &LocalGroupError{Kind: LocalGroupErrorBuiltinGroup}

// ErrLocalGroupPermission is a sentinel for AccessDenied (EC-8).
var ErrLocalGroupPermission = &LocalGroupError{Kind: LocalGroupErrorPermission}

// ErrLocalGroupNameConflict is a sentinel for rename target already taken (EC-5).
var ErrLocalGroupNameConflict = &LocalGroupError{Kind: LocalGroupErrorNameConflict}

// ErrLocalGroupInvalidName is a sentinel for invalid name (EC-6).
var ErrLocalGroupInvalidName = &LocalGroupError{Kind: LocalGroupErrorInvalidName}

// ErrLocalGroupUnknown is a sentinel for unexpected errors.
var ErrLocalGroupUnknown = &LocalGroupError{Kind: LocalGroupErrorUnknown}

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
// Members are intentionally absent: membership management is out of scope for
// this resource version (ADR-LG-3).
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
}

// ---------------------------------------------------------------------------
// WindowsLocalGroupClient — CRUD + import interface
// ---------------------------------------------------------------------------

// WindowsLocalGroupClient defines the contract for managing Windows local
// groups over WinRM (Microsoft.PowerShell.LocalAccounts module).
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
