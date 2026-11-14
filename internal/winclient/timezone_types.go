// Package winclient: WindowsTimezoneClient interface and associated types
// for managing the system time zone of a remote Windows host over SSH +
// PowerShell.
//
// File layout:
//
//	TimezoneErrorKind    — string enum of typed error categories
//	TimezoneError        — structured error with Kind, Message, Context, Cause
//	Sentinel errors      — pre-constructed *TimezoneError for errors.Is
//	TimezoneInput        — input parameters for Set (Create/Update share it)
//	TimezoneState        — observed state returned by Read
//	WindowsTimezoneClient — Read/Set contract (no separate Update: the zone
//	                         is a singleton, Set is idempotent)
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// TimezoneErrorKind — typed error categories
// ---------------------------------------------------------------------------

// TimezoneErrorKind categorises errors returned by WindowsTimezoneClient
// operations. Use errors.Is(err, ErrTimezone*) or IsTimezoneError(err, kind)
// for programmatic error handling.
type TimezoneErrorKind string

const (
	// TimezoneErrorInvalidTimezone is returned when the desired time zone ID
	// is unknown to the host (Set-TimeZone / tzutil reject it). The error
	// context carries up to five close-match suggestions when available.
	TimezoneErrorInvalidTimezone = "invalid_timezone"

	// TimezoneErrorAccessDenied is returned when the SSH user lacks the
	// SeTimeZonePrivilege privilege (or administrator rights) required to
	// change the system time zone.
	TimezoneErrorAccessDenied = "access_denied"

	// TimezoneErrorTimeout is returned when the operation timed out or was
	// cancelled. The script outcome is unknown, so the caller must not
	// retry blindly.
	TimezoneErrorTimeout = "timeout"

	// TimezoneErrorUnknown is the catch-all for unmapped PowerShell or SSH
	// failures. Stdout/stderr SHOULD be captured in Context.
	TimezoneErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// TimezoneError — structured error
// ---------------------------------------------------------------------------

// TimezoneError is the structured error type returned by all
// WindowsTimezoneClient methods. Use errors.Is(err, ErrTimezone*) for kind
// matching, or errors.As(err, &te) to inspect Context.
type TimezoneError = ResourceError

// NewTimezoneError constructs a *TimezoneError. Pass a nil cause when no
// underlying error exists. The ctx map may be nil.
func NewTimezoneError(kind TimezoneErrorKind, message string, cause error, ctx map[string]string) *TimezoneError {
	return NewResourceError("windows_timezone", string(kind), message, cause, ctx)
}

// IsTimezoneError reports whether err is a *TimezoneError of the given kind.
func IsTimezoneError(err error, kind TimezoneErrorKind) bool {
	return IsResourceError(err, "windows_timezone", string(kind))
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

var (
	ErrTimezoneInvalidTimezone = &TimezoneError{Resource: "windows_timezone", Kind: TimezoneErrorInvalidTimezone}
	ErrTimezoneAccessDenied    = &TimezoneError{Resource: "windows_timezone", Kind: TimezoneErrorAccessDenied}
	ErrTimezoneTimeout         = &TimezoneError{Resource: "windows_timezone", Kind: TimezoneErrorTimeout}
	ErrTimezoneUnknown         = &TimezoneError{Resource: "windows_timezone", Kind: TimezoneErrorUnknown}
)

// ---------------------------------------------------------------------------
// TimezoneInput — parameters for Set
// ---------------------------------------------------------------------------

// TimezoneInput carries the desired time zone configuration. Consumed by
// Set (shared by Create and Update: the system time zone is a singleton,
// so there is no separate Create/Update client operation).
type TimezoneInput struct {
	// TimezoneID is the Windows time zone ID (e.g. "Romance Standard
	// Time"). Windows IDs never contain "/": IANA IDs such as
	// "Europe/Paris" are rejected at plan time and re-checked here.
	TimezoneID string

	// DaylightSavingDisabled, when true, disables daylight saving time for
	// the zone (tzutil.exe /s "<id>_dstoff"). When false, the zone is set
	// with Set-TimeZone and DST stays governed by the zone definition.
	DaylightSavingDisabled bool
}

// ---------------------------------------------------------------------------
// TimezoneState — observed state returned by Read
// ---------------------------------------------------------------------------

// TimezoneState is the observed time zone state of the remote Windows host.
//
// MachineID is the value of HKLM:\SOFTWARE\Microsoft\Cryptography\
// MachineGuid — stable per machine, anchors the Terraform resource ID.
// Offsets are formatted server-side in invariant culture as "+HH:mm".
// CurrentUTCOffset is the live effective offset (base plus the active DST
// delta); TzautoupdateEnabled reports the HKLM tzautoupdate service start
// mode (best-effort, false when unreadable) so the provider can warn when
// Windows may move the zone out from under Terraform.
type TimezoneState struct {
	// MachineID anchors the Terraform resource ID.
	MachineID string

	// TimezoneID is the configured Windows time zone ID.
	TimezoneID string

	// DisplayName is the localized display name of the zone.
	DisplayName string

	// BaseUTCOffset is the standard (non-DST) offset, e.g. "+01:00".
	BaseUTCOffset string

	// SupportsDaylightSavingTime reports whether the zone defines DST.
	SupportsDaylightSavingTime bool

	// CurrentUTCOffset is the live effective offset (base plus the active
	// DST delta, if any), e.g. "+02:00".
	CurrentUTCOffset string

	// DaylightSavingDisabled is true when DST is disabled for the zone
	// (tzutil "<id>_dstoff").
	DaylightSavingDisabled bool

	// TzautoupdateEnabled is true when the tzautoupdate service is set to
	// automatic start (it may then change the zone automatically).
	TzautoupdateEnabled bool
}

// ---------------------------------------------------------------------------
// WindowsTimezoneClient — Read/Set contract
// ---------------------------------------------------------------------------

// WindowsTimezoneClient defines the contract for managing the system time
// zone of a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation. All methods return *TimezoneError (wrapped in error).
//
//	Notable invariants:
//	  - Singleton: the host has exactly one system time zone. Create and
//	    Update on the resource layer both funnel into Set (idempotent when
//	    the live zone already matches the input).
//	  - Set verifies by re-reading the state and comparing the zone ID
//	    (case-insensitive) plus the DST-disabled flag; a mismatch after
//	    apply returns ErrTimezoneInvalidTimezone with close-match
//	    suggestions when available.
//	  - Read never fails on a machine change: the resource handler anchors
//	    its ID on MachineID and always refreshes from the live state.
type WindowsTimezoneClient interface {
	// Read returns the currently configured time zone state of the host.
	//
	// Returns ErrTimezoneTimeout when the operation timed out or was
	// cancelled. Returns ErrTimezoneAccessDenied when the HKLM reads are
	// refused.
	Read(ctx context.Context) (*TimezoneState, error)

	// Set configures the system time zone (idempotent) and returns the
	// freshly observed state.
	//
	// Returns ErrTimezoneInvalidTimezone when the ID is unknown to the
	// host (with "suggestions" in Context when close matches exist).
	// Returns ErrTimezoneAccessDenied when the caller lacks
	// SeTimeZonePrivilege. Returns ErrTimezoneTimeout when the operation
	// timed out or was cancelled.
	Set(ctx context.Context, input TimezoneInput) (*TimezoneState, error)
}
