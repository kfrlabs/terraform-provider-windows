// Package winclient: types for the windows_iis_app_pool resource.
//
// IISAppPoolState is the observed pool reported by Read; IISAppPoolSettings
// is the partial-management delta consumed by Create/Update (nil means
// unmanaged, never written). IISAppPoolErrorKind / IISAppPoolError follow the
// same shape as the other resources so the provider layer branches with
// errors.Is.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// IISAppPoolErrorKind
// ---------------------------------------------------------------------------

// IISAppPoolErrorKind categorises errors returned by WindowsIISAppPoolClient.
type IISAppPoolErrorKind string

const (
	// IISAppPoolErrorNotFound is returned when the pool does not exist.
	// Read maps it to (nil, nil) for drift removal; Delete treats it as
	// already absent.
	IISAppPoolErrorNotFound IISAppPoolErrorKind = "not_found"

	// IISAppPoolErrorAlreadyExists is returned by Create when a pool with
	// the same name already exists. The message suggests terraform import.
	IISAppPoolErrorAlreadyExists IISAppPoolErrorKind = "already_exists"

	// IISAppPoolErrorInUse is returned by Delete when sites or applications
	// still reference the pool. The message lists them.
	IISAppPoolErrorInUse IISAppPoolErrorKind = "in_use"

	// IISAppPoolErrorIISNotInstalled is returned when the W3SVC/WAS
	// services or the WebAdministration module are missing. The message
	// points at the windows_feature resource (Web-Server).
	IISAppPoolErrorIISNotInstalled IISAppPoolErrorKind = "iis_not_installed"

	// IISAppPoolErrorInvalidIdentity is returned when a SpecificUser
	// identity fails logon (0x8007052e). The message never echoes the
	// password.
	IISAppPoolErrorInvalidIdentity IISAppPoolErrorKind = "invalid_identity"

	// IISAppPoolErrorAccessDenied is returned when the SSH user lacks the
	// privilege to manage IIS configuration.
	IISAppPoolErrorAccessDenied IISAppPoolErrorKind = "access_denied"

	// IISAppPoolErrorConfigLocked is returned when applicationHost.config
	// cannot be committed (locked section, or the concurrent-writer flake
	// persisting past retries).
	IISAppPoolErrorConfigLocked IISAppPoolErrorKind = "config_locked"

	// IISAppPoolErrorUnknown is the catch-all for unrecognised PowerShell
	// errors or SSH transport failures.
	IISAppPoolErrorUnknown IISAppPoolErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// IISAppPoolError
// ---------------------------------------------------------------------------

// IISAppPoolError is the structured error type returned by all
// WindowsIISAppPoolClient methods. Message and Context MUST NOT contain the
// SpecificUser password: it travels on stdin and is never interpolated into
// script text or diagnostics.
type IISAppPoolError struct {
	Kind    IISAppPoolErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements error.
func (e *IISAppPoolError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_iis_app_pool [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_iis_app_pool [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *IISAppPoolError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *IISAppPoolError) Is(target error) bool {
	t, ok := target.(*IISAppPoolError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewIISAppPoolError constructs a *IISAppPoolError.
func NewIISAppPoolError(kind IISAppPoolErrorKind, message string, cause error, ctx map[string]string) *IISAppPoolError {
	return &IISAppPoolError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsIISAppPoolError reports whether err is a *IISAppPoolError with the given kind.
func IsIISAppPoolError(err error, kind IISAppPoolErrorKind) bool {
	var ae *IISAppPoolError
	if errors.As(err, &ae) {
		return ae.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrIISAppPoolNotFound        = &IISAppPoolError{Kind: IISAppPoolErrorNotFound}
	ErrIISAppPoolAlreadyExists   = &IISAppPoolError{Kind: IISAppPoolErrorAlreadyExists}
	ErrIISAppPoolInUse           = &IISAppPoolError{Kind: IISAppPoolErrorInUse}
	ErrIISAppPoolIISNotInstalled = &IISAppPoolError{Kind: IISAppPoolErrorIISNotInstalled}
	ErrIISAppPoolInvalidIdentity = &IISAppPoolError{Kind: IISAppPoolErrorInvalidIdentity}
	ErrIISAppPoolAccessDenied    = &IISAppPoolError{Kind: IISAppPoolErrorAccessDenied}
	ErrIISAppPoolConfigLocked    = &IISAppPoolError{Kind: IISAppPoolErrorConfigLocked}
	ErrIISAppPoolUnknown         = &IISAppPoolError{Kind: IISAppPoolErrorUnknown}
)

// ---------------------------------------------------------------------------
// IISAppPoolSettings — partial-management delta for Create/Update
// ---------------------------------------------------------------------------

// IISAppPoolSettings carries the desired configuration delta for an IIS
// application pool. Every field beyond Name is optional: a nil pointer (or
// an unset RecyclingSchedule) means "unmanaged" — the attribute is omitted
// from the Set-ItemProperty script and the host value is left untouched.
// A non-nil RecyclingSchedule (even empty) is authoritative: the schedule
// collection is fully replaced.
type IISAppPoolSettings struct {
	ManagedRuntimeVersion           *string
	ManagedPipelineMode             *string
	Enable32BitAppOnWin64           *bool
	StartMode                       *string
	AutoStart                       *bool
	QueueLength                     *int64
	IdentityType                    *string
	IdentityUsername                *string
	LoadUserProfile                 *bool
	IdleTimeoutMinutes              *int64
	IdleTimeoutAction               *string
	MaxProcesses                    *int64
	RecyclingPeriodicRestartMinutes *int64
	RecyclingSchedule               []string
	RecyclingScheduleSet            bool
	RecyclingPrivateMemoryKB        *int64
	RapidFailProtection             *bool
	CPULimitPercent                 *int64
	CPUAction                       *string
	State                           *string
}

// IISAppPoolConfigured reports whether at least one attribute is managed.
func (s IISAppPoolSettings) IISAppPoolConfigured() bool {
	return s.ManagedRuntimeVersion != nil ||
		s.ManagedPipelineMode != nil ||
		s.Enable32BitAppOnWin64 != nil ||
		s.StartMode != nil ||
		s.AutoStart != nil ||
		s.QueueLength != nil ||
		s.IdentityType != nil ||
		s.IdentityUsername != nil ||
		s.LoadUserProfile != nil ||
		s.IdleTimeoutMinutes != nil ||
		s.IdleTimeoutAction != nil ||
		s.MaxProcesses != nil ||
		s.RecyclingPeriodicRestartMinutes != nil ||
		s.RecyclingScheduleSet ||
		s.RecyclingPrivateMemoryKB != nil ||
		s.RapidFailProtection != nil ||
		s.CPULimitPercent != nil ||
		s.CPUAction != nil ||
		s.State != nil
}

// ---------------------------------------------------------------------------
// IISAppPoolState — observed pool state
// ---------------------------------------------------------------------------

// IISAppPoolState holds the observed state of an IIS application pool as
// returned by the Read pipeline. Durations are whole minutes (converted
// server-side from TimeSpan); CPULimitPercent is whole percent (converted
// server-side from cpu.limit thousandths).
type IISAppPoolState struct {
	Name                            string
	ManagedRuntimeVersion           string
	ManagedPipelineMode             string
	Enable32BitAppOnWin64           bool
	StartMode                       string
	AutoStart                       bool
	QueueLength                     int64
	IdentityType                    string
	IdentityUsername                string
	LoadUserProfile                 bool
	IdleTimeoutMinutes              int64
	IdleTimeoutAction               string
	MaxProcesses                    int64
	RecyclingPeriodicRestartMinutes int64
	RecyclingSchedule               []string
	RecyclingPrivateMemoryKB        int64
	RapidFailProtection             bool
	CPULimitPercent                 int64
	CPUAction                       string
	State                           string
}

// ---------------------------------------------------------------------------
// IISAppPoolInput — Create/Update envelope
// ---------------------------------------------------------------------------

// IISAppPoolInput carries the desired configuration for Create/Update.
// Password is the SpecificUser plaintext: it travels on stdin via
// RunPowerShellWithInput and never appears in the script body. An empty
// Password means "do not touch the stored credential" (Update only re-sends
// it when the provider's identity_password_wo_version counter changes).
type IISAppPoolInput struct {
	Name     string
	Settings IISAppPoolSettings
	Password string
}

// ---------------------------------------------------------------------------
// WindowsIISAppPoolClient
// ---------------------------------------------------------------------------

// WindowsIISAppPoolClient defines the contract for managing IIS application
// pools via SSH (WebAdministration PowerShell module).
//
// Error conventions:
//   - Read returns (nil, nil) when the pool does not exist (drift removal).
//   - Create returns already_exists with an import hint when the pool
//     already exists; on partial failure the half-created pool is deleted
//     best-effort and the original error is returned.
//   - Delete returns in_use (listing the referencing sites/applications)
//     when the pool is still referenced; a missing pool is already absent.
//   - Update writes only the configured settings; an empty Password leaves
//     the stored credential untouched.
type WindowsIISAppPoolClient interface {
	// Create creates the pool, applies the configured settings in one
	// script, enforces the configured state, and returns the read-back
	// state.
	Create(ctx context.Context, in IISAppPoolInput) (*IISAppPoolState, error)

	// Read returns the current state of the named pool, or (nil, nil) when
	// the pool does not exist.
	Read(ctx context.Context, name string) (*IISAppPoolState, error)

	// Update applies only the configured settings to the named pool,
	// re-sends the password only when in.Password is non-empty, enforces
	// the configured state, and returns the read-back state.
	Update(ctx context.Context, in IISAppPoolInput) (*IISAppPoolState, error)

	// Delete removes the named pool. Refuses with in_use while sites or
	// applications still reference it.
	Delete(ctx context.Context, name string) error
}
