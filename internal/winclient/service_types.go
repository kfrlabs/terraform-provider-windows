
// Package winclient defines the WindowsServiceClient interface and associated
// types for managing Windows services over WinRM.
//
// Spec alignment: windows_service spec v7 (2026-04-24).
//
// File layout:
//
//	ServiceErrorKind  — string enum of typed error categories (9 kinds)
//	ServiceError      — structured error type with Kind, Message, Context, Cause
//	Sentinel errors   — pre-constructed *ServiceError values for errors.Is
//	ServiceInput      — input parameters for Create/Update operations
//	ServiceState      — observed state returned by Read (no ServicePassword)
//	WindowsServiceClient — CRUD + state-control interface
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// ServiceErrorKind — typed error categories
// ---------------------------------------------------------------------------

// ServiceErrorKind categorises errors returned by WindowsServiceClient
// operations.  Use errors.Is(err, ErrService*) or IsServiceError(err, kind)
// for programmatic error handling.
type ServiceErrorKind string

const (
	// ServiceErrorNotFound is returned when the target service does not exist
	// in the Windows SCM (Win32 error 1060).  In Read it triggers
	// RemoveResource() (EC-2); in Delete it is treated as success (idempotency).
	ServiceErrorNotFound ServiceErrorKind = "not_found"

	// ServiceErrorAlreadyExists is returned when Create detects a pre-existing
	// service with the same name before calling New-Service (EC-1).
	// This is a hard error — not transient, must not be retried.
	ServiceErrorAlreadyExists ServiceErrorKind = "already_exists"

	// ServiceErrorPermission is returned when the SCM refuses the operation
	// with Win32 error 5 "Access is denied" (EC-3).
	ServiceErrorPermission ServiceErrorKind = "permission_denied"

	// ServiceErrorTimeout is returned when a Start/Stop/Delete operation
	// exceeds the provider-level timeout or context deadline (EC-7).
	// Includes structured context: service name, operation, elapsed time,
	// host, port.
	ServiceErrorTimeout ServiceErrorKind = "timeout"

	// ServiceErrorInvalidParameter is returned for Win32 error 87
	// "The parameter is incorrect" — most commonly caused by passing a
	// password for a built-in account (EC-11).
	ServiceErrorInvalidParameter ServiceErrorKind = "invalid_parameter"

	// ServiceErrorRunning is returned when Start-Service is called on a
	// service that is already Running (Win32 error 1056).
	ServiceErrorRunning ServiceErrorKind = "already_running"

	// ServiceErrorNotRunning is returned when Stop-Service is called on a
	// service that is already Stopped (Win32 error 1062).
	ServiceErrorNotRunning ServiceErrorKind = "not_running"

	// ServiceErrorDisabled is returned when Start-Service is called on a
	// Disabled service (Win32 error 1058).
	ServiceErrorDisabled ServiceErrorKind = "disabled"

	// ServiceErrorUnknown is returned for generic sc.exe non-zero exit codes
	// or unrecognised PowerShell errors.  The full sc.exe stdout/stderr is
	// captured in ServiceError.Context["output"] for diagnostics.
	ServiceErrorUnknown ServiceErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// ServiceError — structured error type
// ---------------------------------------------------------------------------

// ServiceError is the structured error type returned by all
// WindowsServiceClient methods.
//
// Callers should use errors.Is(err, ErrService*) for kind matching, or
// errors.As(err, &se) to access the full Context map.
//
// SECURITY: service_password MUST NEVER appear in Message, Context, or
// anywhere the error might be surfaced in provider logs or Terraform output.
type ServiceError struct {
	// Kind is the machine-readable error category.
	Kind ServiceErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics.  Must not contain service_password or other secrets.
	Message string

	// Context holds structured diagnostic key-value pairs (e.g. "host",
	// "port", "operation", "elapsed", "exit_code", "output").
	// All values must be safe to log.
	Context map[string]string

	// Cause is the underlying error, if any (e.g. a WinRM transport error).
	Cause error
}

// Error implements the error interface.
func (e *ServiceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_service [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_service [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *ServiceError) Unwrap() error {
	return e.Cause
}

// Is implements errors.Is comparison by Kind only.
// This allows:
//
//	errors.Is(err, ErrServiceNotFound) // true when err.Kind == ServiceErrorNotFound
func (e *ServiceError) Is(target error) bool {
	t, ok := target.(*ServiceError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewServiceError constructs a *ServiceError.  Pass a nil cause when no
// underlying error exists.  The ctx map may be nil.
func NewServiceError(kind ServiceErrorKind, message string, cause error, ctx map[string]string) *ServiceError {
	return &ServiceError{
		Kind:    kind,
		Message: message,
		Cause:   cause,
		Context: ctx,
	}
}

// IsServiceError reports whether err is a *ServiceError with the given kind.
// Equivalent to errors.Is(err, &ServiceError{Kind: kind}) but more readable.
func IsServiceError(err error, kind ServiceErrorKind) bool {
	var se *ServiceError
	if errors.As(err, &se) {
		return se.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

// Pre-constructed sentinel *ServiceError values.  Because ServiceError.Is
// compares by Kind, errors.Is(returnedErr, ErrServiceNotFound) returns true
// for any *ServiceError{Kind: ServiceErrorNotFound}, regardless of Message or
// Context.
var (
	ErrServiceNotFound         = &ServiceError{Kind: ServiceErrorNotFound}
	ErrServiceAlreadyExists    = &ServiceError{Kind: ServiceErrorAlreadyExists}
	ErrServicePermission       = &ServiceError{Kind: ServiceErrorPermission}
	ErrServiceTimeout          = &ServiceError{Kind: ServiceErrorTimeout}
	ErrServiceInvalidParameter = &ServiceError{Kind: ServiceErrorInvalidParameter}
	ErrServiceRunning          = &ServiceError{Kind: ServiceErrorRunning}
	ErrServiceNotRunning       = &ServiceError{Kind: ServiceErrorNotRunning}
	ErrServiceDisabled         = &ServiceError{Kind: ServiceErrorDisabled}
	ErrServiceUnknown          = &ServiceError{Kind: ServiceErrorUnknown}
)

// ---------------------------------------------------------------------------
// ServiceInput — input parameters for Create and Update
// ---------------------------------------------------------------------------

// ServiceInput carries the desired configuration for a Windows service.
// It is consumed by Create and Update methods of WindowsServiceClient.
//
// Zero-value semantics:
//   - DisplayName ""  → Windows defaults to Name on Create; no change on Update.
//   - Description ""  → no description set / cleared.
//   - StartType ""    → defaults to "Automatic" on Create.
//   - DesiredStatus "" → observe-only (no Start/Stop/Pause issued, ADR SS4).
//   - ServiceAccount "" → Windows defaults to LocalSystem on Create.
//   - ServicePassword "" → no password / built-in account (never paired with
//     built-in ServiceAccount).
//   - Dependencies nil   → preserve existing deps on Update; none on Create.
//   - Dependencies []{}  → clear all deps (sc.exe config depend= /).
type ServiceInput struct {
	// Name is the Windows short service name (required, immutable after Create).
	Name string

	// BinaryPath is the full executable path with arguments (required on Create;
	// excluded from Update — ForceNew attribute).
	BinaryPath string

	// DisplayName is the human-readable name shown in services.msc.
	// Empty string on Create → Windows defaults to Name.
	DisplayName string

	// Description is the service description text.
	Description string

	// StartType is one of: "Automatic", "AutomaticDelayedStart", "Manual",
	// "Disabled".  Empty → "Automatic" on Create.
	StartType string

	// DesiredStatus is the target runtime state: "Running", "Stopped", or
	// "Paused".  Empty string means observe-only — no state transition
	// issued (ADR SS4).
	DesiredStatus string

	// ServiceAccount is the account under which the service runs.
	// Examples: "LocalSystem", "NT AUTHORITY\\NetworkService", ".\\myuser",
	// "DOMAIN\\svc-app".  Empty → LocalSystem on Create.
	ServiceAccount string

	// ServicePassword is the password for ServiceAccount.  Write-only: this
	// field is sent to Windows but never read back (ADR SS6).
	// MUST NOT be logged or included in any error message.
	ServicePassword string

	// Dependencies is the ordered list of service names this service depends
	// on.  nil means "do not change existing dependencies" (Update only).
	// An empty non-nil slice clears all dependencies.
	Dependencies []string
}

// ---------------------------------------------------------------------------
// ServiceState — observed state returned by Read
// ---------------------------------------------------------------------------

// ServiceState holds the observed state of a Windows service as returned by
// Read (Get-Service + sc.exe qc + sc.exe qdescription).
//
// ServicePassword is intentionally absent: the SCM never exposes passwords.
// The Read handler in the resource implementation copies service_password
// from prior Terraform state (semantic write-only, ADR SS6).
type ServiceState struct {
	// Name is the Windows short service name (equals the resource ID).
	Name string

	// DisplayName is the human-readable name from Get-Service.DisplayName.
	DisplayName string

	// Description is the service description from sc.exe qdescription.
	// Empty string when Windows returns no description.
	Description string

	// BinaryPath is the executable path from sc.exe qc BINARY_PATH_NAME,
	// after EC-14 outer-quote normalisation.
	BinaryPath string

	// StartType is one of: "Automatic", "AutomaticDelayedStart", "Manual",
	// "Disabled".  Derived from sc.exe qc START_TYPE field (incl. DELAYED flag).
	StartType string

	// CurrentStatus is the observed runtime state from Get-Service.Status:
	// "Running", "Stopped", or "Paused".
	CurrentStatus string

	// ServiceAccount is the account from sc.exe qc SERVICE_START_NAME, after
	// normalisation (.\user → HOSTNAME\user; NT AUTHORITY\SYSTEM → LocalSystem).
	ServiceAccount string

	// Dependencies is the ordered list of dependency service names parsed from
	// sc.exe qc DEPENDENCIES section.  Empty slice when no dependencies.
	Dependencies []string
}

// ---------------------------------------------------------------------------
// WindowsServiceClient — CRUD + state-control interface
// ---------------------------------------------------------------------------

// WindowsServiceClient defines the contract for managing Windows services
// over WinRM.  All methods accept a context.Context for cancellation and
// timeout propagation (respecting the provider-level cfg.Timeout, EC-7).
//
// Error taxonomy: all methods return *ServiceError (wrapped in error).
// Use errors.Is(err, ErrService*) or IsServiceError(err, kind) to branch
// on specific error kinds in the resource CRUD handlers.
//
//	Notable invariants:
//	  - Create always checks for pre-existence (EC-1); returns
//	    ErrServiceAlreadyExists if the service name is already registered.
//	  - Read returns (nil, nil) when the service does not exist, allowing
//	    the resource handler to call resp.State.RemoveResource() (EC-2).
//	  - Delete stops the service before removal (Stop → WaitForStatus →
//	    Remove/sc.exe delete) and treats Win32 1060 as success (EC-6, SS11).
//	  - service_password is never read back from Windows; the resource
//	    Read handler copies it from prior state (ADR SS6).
type WindowsServiceClient interface {
	// Create registers a new Windows service in the SCM via New-Service, then
	// applies AutomaticDelayedStart and dependencies via sc.exe, and finally
	// reconciles the runtime state (Start/Stop/Pause) if DesiredStatus is set.
	//
	// Returns ErrServiceAlreadyExists (EC-1) if the service name is already
	// registered — this is a hard error, not retried.
	// Returns ErrServicePermission (EC-3) on Win32 error 5 "Access is denied".
	Create(ctx context.Context, input ServiceInput) (*ServiceState, error)

	// Read retrieves the current state of the named service using
	// Get-Service + sc.exe qc + sc.exe qdescription.
	//
	// Returns (nil, nil) when the service does not exist (Win32 1060, EC-2).
	// The resource handler must call resp.State.RemoveResource() on (nil, nil).
	// Returns ErrServicePermission on Win32 error 5.
	Read(ctx context.Context, name string) (*ServiceState, error)

	// Update applies in-place configuration changes via Set-Service and
	// sc.exe config.  BinaryPath changes are not supported (ForceNew) and must
	// never be passed in ServiceInput.BinaryPath during Update.
	//
	// Dependency changes always use sc.exe config depend=, regardless of
	// PowerShell version (ADR SS3).
	// AutomaticDelayedStart uses sc.exe config start= delayed-auto (ADR SS3).
	// Runtime state is reconciled last (Start/Stop/Pause).
	Update(ctx context.Context, name string, input ServiceInput) (*ServiceState, error)

	// Delete stops the service (if Running or Paused), waits for Stopped
	// status (WaitForStatus, max 30 s), then removes it via Remove-Service
	// (PS 6.0+) or sc.exe delete (PS 5.1 fallback).
	//
	// Ordering: Stop → WaitForStatus(Stopped, 30s) → Remove (ADR SS11, EC-6).
	// Win32 error 1060 (not found) is treated as success for idempotency.
	// If WaitForStatus times out: returns ErrServiceTimeout and ABORTS —
	// the service and Terraform state are left unchanged (EC-6 → EC-7).
	Delete(ctx context.Context, name string) error

	// StartService starts the named service via Start-Service.
	//
	// Returns ErrServiceRunning   (Win32 1056) if already Running — caller may
	// treat this as success.
	// Returns ErrServiceDisabled  (Win32 1058) if start_type is Disabled.
	// Returns ErrServiceTimeout   (EC-7) if the service does not reach Running
	// within the context deadline.
	StartService(ctx context.Context, name string) error

	// StopService stops the named service via Stop-Service -Force (cascade).
	//
	// Returns ErrServiceNotRunning (Win32 1062) if already Stopped — caller
	// may treat this as success.
	// Returns ErrServiceTimeout    (EC-7) if the service does not reach Stopped
	// within the context deadline.
	// -Force cascades to dependent services (EC-10); document this side-effect
	// in resource docs.
	StopService(ctx context.Context, name string) error

	// PauseService suspends the named service via Suspend-Service.
	//
	// The implementation MUST verify CanPauseAndContinue = true before calling
	// Suspend-Service; if false it returns ErrServiceInvalidParameter with a
	// message referencing EC-13 ("CanPauseAndContinue=false").
	// Returns ErrServiceTimeout (EC-7) if the service does not reach Paused
	// within the context deadline.
	PauseService(ctx context.Context, name string) error
}
