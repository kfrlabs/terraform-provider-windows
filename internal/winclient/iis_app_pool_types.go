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
	IISAppPoolErrorNotFound = "not_found"

	// IISAppPoolErrorAlreadyExists is returned by Create when a pool with
	// the same name already exists. The message suggests terraform import.
	IISAppPoolErrorAlreadyExists = "already_exists"

	// IISAppPoolErrorInUse is returned by Delete when sites or applications
	// still reference the pool. The message lists them.
	IISAppPoolErrorInUse = "in_use"

	// IISAppPoolErrorIISNotInstalled is returned when the W3SVC/WAS
	// services or the WebAdministration module are missing. The message
	// points at the windows_feature resource (Web-Server).
	IISAppPoolErrorIISNotInstalled = "iis_not_installed"

	// IISAppPoolErrorInvalidIdentity is returned when a SpecificUser
	// identity fails logon (0x8007052e). The message never echoes the
	// password.
	IISAppPoolErrorInvalidIdentity = "invalid_identity"

	// IISAppPoolErrorAccessDenied is returned when the SSH user lacks the
	// privilege to manage IIS configuration.
	IISAppPoolErrorAccessDenied = "access_denied"

	// IISAppPoolErrorConfigLocked is returned when applicationHost.config
	// cannot be committed (locked section, or the concurrent-writer flake
	// persisting past retries).
	IISAppPoolErrorConfigLocked = "config_locked"

	// IISAppPoolErrorUnknown is the catch-all for unrecognised PowerShell
	// errors or SSH transport failures.
	IISAppPoolErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// IISAppPoolError
// ---------------------------------------------------------------------------

// IISAppPoolError is the structured error type returned by all
// WindowsIISAppPoolClient methods. Message and Context MUST NOT contain the
// SpecificUser password: it travels on stdin and is never interpolated into
// script text or diagnostics.
type IISAppPoolError = ResourceError

// NewIISAppPoolError constructs a *IISAppPoolError.
func NewIISAppPoolError(kind IISAppPoolErrorKind, message string, cause error, ctx map[string]string) *IISAppPoolError {
	return NewResourceError("windows_iis_app_pool", string(kind), message, cause, ctx)
}

// IsIISAppPoolError reports whether err is a *IISAppPoolError with the given kind.
func IsIISAppPoolError(err error, kind IISAppPoolErrorKind) bool {
	return IsResourceError(err, "windows_iis_app_pool", string(kind))
}

// Sentinel errors for use with errors.Is.
var (
	ErrIISAppPoolNotFound        = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorNotFound}
	ErrIISAppPoolAlreadyExists   = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorAlreadyExists}
	ErrIISAppPoolInUse           = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorInUse}
	ErrIISAppPoolIISNotInstalled = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorIISNotInstalled}
	ErrIISAppPoolInvalidIdentity = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorInvalidIdentity}
	ErrIISAppPoolAccessDenied    = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorAccessDenied}
	ErrIISAppPoolConfigLocked    = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorConfigLocked}
	ErrIISAppPoolUnknown         = &IISAppPoolError{Resource: "windows_iis_app_pool", Kind: IISAppPoolErrorUnknown}
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
