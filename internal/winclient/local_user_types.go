// Package winclient defines types and the client interface for managing
// Windows local user accounts over WinRM.
//
// Spec alignment: windows_local_user spec v1 (2026-04-25).
//
// File layout:
//
//	LocalUserErrorKind      — string enum of typed error categories (8 kinds)
//	LocalUserError          — structured error type with Kind, Message, Context, Cause
//	Sentinel errors          — pre-constructed *LocalUserError values for errors.Is
//	UserInput               — input parameters for Create/Update operations
//	UserState               — observed state returned by Read / Create / Import
//	LocalUserClient         — granular CRUD + import interface
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// LocalUserErrorKind — typed error categories (ADR-LU-10)
// ---------------------------------------------------------------------------

// LocalUserErrorKind categorises errors returned by LocalUserClient methods.
// Use errors.Is(err, ErrLocalUser*) or IsLocalUserError(err, kind) for
// programmatic error handling in resource CRUD handlers.
type LocalUserErrorKind string

const (
	// LocalUserErrorNotFound is returned when Get-LocalUser raises UserNotFound
	// for the given SID. In Read, this triggers RemoveResource() (EC-3).
	LocalUserErrorNotFound LocalUserErrorKind = "not_found"

	// LocalUserErrorAlreadyExists is returned when Create detects a pre-existing
	// user with the same name (EC-1). Hard error — use terraform import.
	LocalUserErrorAlreadyExists LocalUserErrorKind = "already_exists"

	// LocalUserErrorBuiltinAccount is returned when Delete detects a built-in
	// RID (500/501/503/504, ADR-LU-2, EC-2). Hard error — not a warning.
	LocalUserErrorBuiltinAccount LocalUserErrorKind = "builtin_account"

	// LocalUserErrorRenameConflict is returned when Rename-LocalUser fails
	// because the target name is already used by another local user (EC-5).
	LocalUserErrorRenameConflict LocalUserErrorKind = "rename_conflict"

	// LocalUserErrorPasswordPolicy is returned when New-LocalUser or
	// Set-LocalUser -Password violates the local password policy (EC-7).
	LocalUserErrorPasswordPolicy LocalUserErrorKind = "password_policy"

	// LocalUserErrorPermission is returned when a mutating cmdlet is
	// rejected with AccessDenied (EC-9).
	LocalUserErrorPermission LocalUserErrorKind = "permission_denied"

	// LocalUserErrorInvalidName is returned when a user name fails
	// Windows-side validation — defence-in-depth (EC-10).
	LocalUserErrorInvalidName LocalUserErrorKind = "invalid_name"

	// LocalUserErrorUnknown is the catch-all for unrecognised PowerShell
	// errors or unexpected WinRM transport failures.
	LocalUserErrorUnknown LocalUserErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// LocalUserError — structured error type
// ---------------------------------------------------------------------------

// LocalUserError is the structured error type returned by all LocalUserClient
// methods.
//
// Callers should use errors.Is(err, ErrLocalUser*) for kind matching, or
// errors.As(err, &lue) to access the full Context map for diagnostics.
type LocalUserError struct {
	// Kind is the machine-readable error category.
	Kind LocalUserErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics and provider logs. MUST NOT contain the plaintext password.
	Message string

	// Context holds structured diagnostic key-value pairs (host, sid, name,
	// operation, output, exit_code). MUST NOT contain passwords or secrets.
	Context map[string]string

	// Cause is the underlying error, if any (WinRM transport error, etc.).
	Cause error
}

// Error implements the error interface.
func (e *LocalUserError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_local_user [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_local_user [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *LocalUserError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *LocalUserError) Is(target error) bool {
	t, ok := target.(*LocalUserError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewLocalUserError constructs a *LocalUserError. Pass nil cause when no
// underlying error exists. The ctx map may be nil.
func NewLocalUserError(
	kind LocalUserErrorKind,
	message string,
	cause error,
	ctx map[string]string,
) *LocalUserError {
	return &LocalUserError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsLocalUserError reports whether err is a *LocalUserError with the given kind.
func IsLocalUserError(err error, kind LocalUserErrorKind) bool {
	var lue *LocalUserError
	if errors.As(err, &lue) {
		return lue.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

// ErrLocalUserNotFound is a sentinel for UserNotFound (EC-3, EC-11).
var ErrLocalUserNotFound = &LocalUserError{Kind: LocalUserErrorNotFound}

// ErrLocalUserAlreadyExists is a sentinel for name collision at Create (EC-1).
var ErrLocalUserAlreadyExists = &LocalUserError{Kind: LocalUserErrorAlreadyExists}

// ErrLocalUserBuiltinAccount is a sentinel for built-in RID deletion (EC-2).
var ErrLocalUserBuiltinAccount = &LocalUserError{Kind: LocalUserErrorBuiltinAccount}

// ErrLocalUserRenameConflict is a sentinel for rename target already taken (EC-5).
var ErrLocalUserRenameConflict = &LocalUserError{Kind: LocalUserErrorRenameConflict}

// ErrLocalUserPasswordPolicy is a sentinel for password policy violation (EC-7).
var ErrLocalUserPasswordPolicy = &LocalUserError{Kind: LocalUserErrorPasswordPolicy}

// ErrLocalUserPermission is a sentinel for AccessDenied (EC-9).
var ErrLocalUserPermission = &LocalUserError{Kind: LocalUserErrorPermission}

// ErrLocalUserInvalidName is a sentinel for invalid name (EC-10).
var ErrLocalUserInvalidName = &LocalUserError{Kind: LocalUserErrorInvalidName}

// ErrLocalUserUnknown is a sentinel for unexpected errors.
var ErrLocalUserUnknown = &LocalUserError{Kind: LocalUserErrorUnknown}

// ---------------------------------------------------------------------------
// UserInput — input parameters for Create and Update
// ---------------------------------------------------------------------------

// UserInput carries the desired configuration for a Windows local user account.
// Consumed by Create and Update methods of LocalUserClient.
type UserInput struct {
	// Name is the SAM account name (1..20 chars, no forbidden chars).
	Name string

	// FullName is the optional display name of the user.
	FullName string

	// Description is the optional free-text description (max 48 chars, EC-8).
	Description string

	// PasswordNeverExpires maps to -PasswordNeverExpires (New-LocalUser switch)
	// or -PasswordNeverExpires $true/$false (Set-LocalUser bool param).
	PasswordNeverExpires bool

	// UserMayNotChangePassword maps to -UserMayNotChangePassword (positive=cannot).
	// NOTE: Windows stores/returns UserMayChangePassword (positive=can); this field
	// uses the negated form to match the Terraform attribute name.
	UserMayNotChangePassword bool

	// AccountNeverExpires maps to -AccountNeverExpires (mutually exclusive with AccountExpires).
	AccountNeverExpires bool

	// AccountExpires is an RFC3339 timestamp. Non-empty only when AccountNeverExpires=false
	// and the operator has set an explicit expiry. Empty means no expiry change.
	AccountExpires string

	// Enabled is the desired account state. Create: false => pass -Disabled to New-LocalUser.
	Enabled bool
}

// ---------------------------------------------------------------------------
// UserState — observed state returned by Read / Create / Import
// ---------------------------------------------------------------------------

// UserState holds the observed state of a Windows local user account as
// returned by Get-LocalUser -SID | ConvertTo-Json.
//
// Password is intentionally absent: the Windows API cannot return plaintext
// passwords. The resource handler is responsible for preserving the in-state
// password value unchanged across Read cycles (ADR-LU-3).
type UserState struct {
	// Name is the SAM account name as returned by Windows (Windows casing wins).
	Name string

	// FullName is the display name.
	FullName string

	// Description is the account description.
	Description string

	// Enabled is true when the account is active.
	Enabled bool

	// PasswordNeverExpires is true when the password has no expiry policy.
	PasswordNeverExpires bool

	// UserMayNotChangePassword is true when self-service password change is blocked.
	// Derived from the Windows UserMayChangePassword property (inverted).
	UserMayNotChangePassword bool

	// AccountNeverExpires is true when AccountExpires == null / zero-date.
	AccountNeverExpires bool

	// AccountExpires is the RFC3339 expiry timestamp, or "" when the account
	// never expires (AccountNeverExpires == true).
	AccountExpires string

	// LastLogon is the RFC3339 timestamp of the last logon, or "" if never.
	LastLogon string

	// PasswordLastSet is the RFC3339 timestamp of the last password change,
	// or "" if not yet set.
	PasswordLastSet string

	// PrincipalSource is the origin of the account ("Local", "ActiveDirectory", etc.).
	PrincipalSource string

	// SID is the Security Identifier (e.g. "S-1-5-21-...-1001").
	// Stable across renames — used as the Terraform resource ID (ADR-LU-1).
	SID string
}

// ---------------------------------------------------------------------------
// LocalUserClient — granular CRUD + import interface (ADR-LU-6)
// ---------------------------------------------------------------------------

// LocalUserClient defines the contract for managing Windows local user accounts
// over WinRM (Microsoft.PowerShell.LocalAccounts module).
//
// Methods are intentionally granular (Rename/SetPassword/Enable/Disable as
// separate calls) to match the distinct PowerShell cmdlets and allow
// independent error handling in the resource handler (ADR-LU-6).
//
// All methods accept a context.Context and return *LocalUserError (wrapped
// in error) for structured error handling.
type LocalUserClient interface {
	// Create creates a new local user via New-LocalUser.
	// password is injected via stdin (never in the script body, ADR-LU-3).
	// Pre-flight: module check + name collision guard (EC-1).
	Create(ctx context.Context, input UserInput, password string) (*UserState, error)

	// Read retrieves the current state of the user identified by SID.
	// Returns (nil, nil) when the user does not exist (EC-3 drift detection).
	Read(ctx context.Context, sid string) (*UserState, error)

	// Update applies scalar attribute changes via Set-LocalUser -SID.
	// Does NOT handle name changes (use Rename), password (use SetPassword),
	// or enabled state (use Enable/Disable).
	Update(ctx context.Context, sid string, input UserInput) (*UserState, error)

	// Rename renames the user via Rename-LocalUser -SID -NewName.
	// The SID is unchanged; must be called BEFORE Update in the same plan.
	Rename(ctx context.Context, sid, newName string) error

	// SetPassword rotates the password via Set-LocalUser -SID -Password.
	// password is injected via stdin (never logged, ADR-LU-3, EC-6).
	SetPassword(ctx context.Context, sid, password string) error

	// Enable enables the account via Enable-LocalUser -SID.
	Enable(ctx context.Context, sid string) error

	// Disable disables the account via Disable-LocalUser -SID.
	Disable(ctx context.Context, sid string) error

	// Delete removes the user via Remove-LocalUser -SID.
	// Pre-flight built-in RID guard: returns ErrLocalUserBuiltinAccount for
	// RIDs 500/501/503/504 (EC-2, ADR-LU-2).
	Delete(ctx context.Context, sid string) error

	// ImportByName resolves a user by SAM name (non-SID import path).
	ImportByName(ctx context.Context, name string) (*UserState, error)

	// ImportBySID resolves a user by SID string (SID import path).
	ImportBySID(ctx context.Context, sid string) (*UserState, error)
}
