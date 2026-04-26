// Package winclient defines the EnvVarClient interface and associated types
// for managing Windows environment variables over WinRM.
//
// Spec alignment: windows_environment_variable spec v1 (2026-04-26).
//
// File layout:
//
//	EnvVarScope            — string enum {machine, user}
//	EnvVarErrorKind        — string enum of typed error categories (4 kinds)
//	EnvVarError            — structured error type
//	Sentinel errors        — pre-constructed *EnvVarError values for errors.Is
//	EnvVarInput            — input parameters for Set operations
//	EnvVarState            — observed state returned by Read and Set
//	EnvVarClient           — interface: Set / Read / Delete
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// EnvVarScope — scope enum
// ---------------------------------------------------------------------------

// EnvVarScope identifies the Windows environment variable scope.
// String values match the Terraform schema attribute values exactly.
type EnvVarScope string

const (
	// EnvVarScopeMachine targets the system-wide environment stored at
	// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment.
	// Requires Local Administrator privileges on the WinRM target.
	EnvVarScopeMachine EnvVarScope = "machine"

	// EnvVarScopeUser targets the per-user environment stored at
	// HKCU\Environment (scoped to the WinRM authentication identity).
	EnvVarScopeUser EnvVarScope = "user"
)

// ---------------------------------------------------------------------------
// EnvVarErrorKind — typed error categories
// ---------------------------------------------------------------------------

// EnvVarErrorKind categorises errors returned by EnvVarClient operations.
type EnvVarErrorKind string

const (
	// EnvVarErrorNotFound is returned when the variable does not exist and
	// the caller requires its presence (e.g. Import — EC-10).
	EnvVarErrorNotFound EnvVarErrorKind = "not_found"

	// EnvVarErrorPermission is returned when an UnauthorizedAccessException
	// occurs (e.g. writing to machine scope without Local Administrator — EC-9).
	EnvVarErrorPermission EnvVarErrorKind = "permission_denied"

	// EnvVarErrorInvalidInput is returned when the PS layer rejects the input
	// (e.g. the scope-resolved registry key does not exist — EC-2).
	EnvVarErrorInvalidInput EnvVarErrorKind = "invalid_input"

	// EnvVarErrorUnknown is returned for unrecognised PS errors or unexpected
	// WinRM transport failures.
	EnvVarErrorUnknown EnvVarErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// EnvVarError — structured error type
// ---------------------------------------------------------------------------

// EnvVarError is the structured error type returned by all EnvVarClient methods.
//
// Callers should use errors.Is(err, ErrEnvVar*) for kind-based matching or
// errors.As(err, &eve) to access the full Context map for diagnostics.
type EnvVarError struct {
	// Kind is the machine-readable error category.
	Kind EnvVarErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics and provider logs.
	Message string

	// Context holds structured diagnostic key-value pairs.
	Context map[string]string

	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *EnvVarError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_environment_variable [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_environment_variable [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors chain walking.
func (e *EnvVarError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *EnvVarError) Is(target error) bool {
	t, ok := target.(*EnvVarError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewEnvVarError constructs a *EnvVarError. Pass nil cause when no underlying
// error exists. ctx may be nil.
func NewEnvVarError(kind EnvVarErrorKind, message string, cause error, ctx map[string]string) *EnvVarError {
	return &EnvVarError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsEnvVarError reports whether err is an *EnvVarError with the given kind.
func IsEnvVarError(err error, kind EnvVarErrorKind) bool {
	var eve *EnvVarError
	if errors.As(err, &eve) {
		return eve.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

var (
	// ErrEnvVarNotFound is the sentinel for EnvVarErrorNotFound.
	ErrEnvVarNotFound = &EnvVarError{Kind: EnvVarErrorNotFound}

	// ErrEnvVarPermission is the sentinel for EnvVarErrorPermission.
	ErrEnvVarPermission = &EnvVarError{Kind: EnvVarErrorPermission}

	// ErrEnvVarInvalidInput is the sentinel for EnvVarErrorInvalidInput.
	ErrEnvVarInvalidInput = &EnvVarError{Kind: EnvVarErrorInvalidInput}

	// ErrEnvVarUnknown is the sentinel for EnvVarErrorUnknown.
	ErrEnvVarUnknown = &EnvVarError{Kind: EnvVarErrorUnknown}
)

// ---------------------------------------------------------------------------
// EnvVarInput — input parameters for Set operations
// ---------------------------------------------------------------------------

// EnvVarInput carries the parameters for an EnvVarClient.Set call.
//
// Both Create and Update use Set with the same EnvVarInput structure (ADR-EV-3).
type EnvVarInput struct {
	// Scope is the target scope: EnvVarScopeMachine or EnvVarScopeUser.
	Scope EnvVarScope

	// Name is the environment variable name. Non-empty; must not contain '='.
	Name string

	// Value is the variable value to write verbatim to the registry.
	// May be an empty string (EC-12).
	Value string

	// Expand controls the registry value kind:
	//   false -> RegistryValueKind.String       (REG_SZ)
	//   true  -> RegistryValueKind.ExpandString (REG_EXPAND_SZ)
	Expand bool
}

// ---------------------------------------------------------------------------
// EnvVarState — observed state returned by Read and Set
// ---------------------------------------------------------------------------

// EnvVarState is the observed state of a Windows environment variable as
// returned by EnvVarClient.Read and EnvVarClient.Set.
//
// Value is always the raw (unexpanded) string (DoNotExpandEnvironmentNames —
// ADR-EV-5).
type EnvVarState struct {
	// Scope is the scope from which the variable was read.
	Scope EnvVarScope

	// Name is the exact variable name as stored in the registry.
	Name string

	// Value is the variable value verbatim and unexpanded.
	Value string

	// Expand is true when the registry value kind is REG_EXPAND_SZ;
	// false when REG_SZ.
	Expand bool

	// BroadcastWarning is non-empty when the WM_SETTINGCHANGE broadcast
	// returned a non-zero result or timed out (ADR-EV-2).
	BroadcastWarning string
}

// ---------------------------------------------------------------------------
// EnvVarClient — interface
// ---------------------------------------------------------------------------

// EnvVarClient is the interface for creating, reading, updating, and deleting
// Windows environment variables over WinRM (ADR-EV-3).
//
// Error conventions:
//   - Read returns (nil, nil) when the variable does not exist (EC-4).
//   - Delete is idempotent: a missing variable is a silent no-op (EC-8).
//   - WM_SETTINGCHANGE failure is reported in EnvVarState.BroadcastWarning (ADR-EV-2).
type EnvVarClient interface {
	// Set creates or overwrites a Windows environment variable.
	//
	// On success, returns the post-write state (equivalent to an immediate Read).
	// Returns EnvVarErrorInvalidInput when the scope-resolved registry key
	// does not exist (EC-2).
	Set(ctx context.Context, input EnvVarInput) (*EnvVarState, error)

	// Read retrieves a Windows environment variable.
	//
	// Returns (nil, nil) when the variable does not exist (EC-4 drift signal).
	// The resource Read handler MUST call resp.State.RemoveResource() on (nil, nil).
	Read(ctx context.Context, scope EnvVarScope, name string) (*EnvVarState, error)

	// Delete removes a Windows environment variable.
	//
	// Idempotent: a missing variable or missing scope key is a silent no-op (EC-8).
	Delete(ctx context.Context, scope EnvVarScope, name string) error
}
