// Package winclient: types for the windows_domain_membership resource.
//
// DomainMembershipErrorKind / DomainMembershipError follow the same shape as
// ServiceError so the resource layer can branch with errors.Is.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// DomainMembershipErrorKind categorises errors returned by
// WindowsDomainMembershipClient.
type DomainMembershipErrorKind string

const (
	// DomainMembershipErrorAlreadyJoined is returned by Join when the host is
	// already joined to the desired domain. Hard error — use terraform import.
	DomainMembershipErrorAlreadyJoined DomainMembershipErrorKind = "already_joined"

	// DomainMembershipErrorJoinedToOtherDomain is returned by Join when the
	// host is already joined to a different domain.
	DomainMembershipErrorJoinedToOtherDomain DomainMembershipErrorKind = "joined_to_other_domain"

	// DomainMembershipErrorDomainNotFound is returned when the domain (or a
	// domain controller for it) cannot be located (Win32 1355 / 53).
	DomainMembershipErrorDomainNotFound DomainMembershipErrorKind = "domain_not_found"

	// DomainMembershipErrorBadCredentials is returned on logon failure
	// (Win32 1326): unknown user name or bad password.
	DomainMembershipErrorBadCredentials DomainMembershipErrorKind = "bad_credentials"

	// DomainMembershipErrorAccountExists is returned when the computer
	// account already exists in the domain (Win32 2224).
	DomainMembershipErrorAccountExists DomainMembershipErrorKind = "account_exists"

	// DomainMembershipErrorOuNotFound is returned when the requested
	// organisational unit does not exist.
	DomainMembershipErrorOuNotFound DomainMembershipErrorKind = "ou_not_found"

	// DomainMembershipErrorAccessDenied is returned on AccessDenied (Win32 5).
	DomainMembershipErrorAccessDenied DomainMembershipErrorKind = "access_denied"

	// DomainMembershipErrorRebootPending is returned when a pending reboot
	// blocks the join/unjoin operation.
	DomainMembershipErrorRebootPending DomainMembershipErrorKind = "reboot_pending"

	// DomainMembershipErrorTimeout is returned when the operation timed out
	// or was cancelled.
	DomainMembershipErrorTimeout DomainMembershipErrorKind = "timeout"

	// DomainMembershipErrorInvalidParameter is returned for empty required
	// inputs (domain, username).
	DomainMembershipErrorInvalidParameter DomainMembershipErrorKind = "invalid_parameter"

	// DomainMembershipErrorUnknown is the catch-all for unmapped PowerShell
	// or SSH failures.
	DomainMembershipErrorUnknown DomainMembershipErrorKind = "unknown"
)

// DomainMembershipError is the structured error type returned by
// WindowsDomainMembershipClient.
type DomainMembershipError struct {
	Kind    DomainMembershipErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements error.
func (e *DomainMembershipError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_domain_membership [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_domain_membership [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *DomainMembershipError) Unwrap() error { return e.Cause }

// Is matches by Kind only.
func (e *DomainMembershipError) Is(target error) bool {
	t, ok := target.(*DomainMembershipError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewDomainMembershipError constructs a *DomainMembershipError.
func NewDomainMembershipError(kind DomainMembershipErrorKind, msg string, cause error, ctx map[string]string) *DomainMembershipError {
	return &DomainMembershipError{Kind: kind, Message: msg, Cause: cause, Context: ctx}
}

// IsDomainMembershipError reports whether err is a *DomainMembershipError of
// the given kind.
func IsDomainMembershipError(err error, kind DomainMembershipErrorKind) bool {
	var de *DomainMembershipError
	if errors.As(err, &de) {
		return de.Kind == kind
	}
	return false
}

// Sentinel errors usable with errors.Is.
var (
	ErrDomainMembershipAlreadyJoined       = &DomainMembershipError{Kind: DomainMembershipErrorAlreadyJoined}
	ErrDomainMembershipJoinedToOtherDomain = &DomainMembershipError{Kind: DomainMembershipErrorJoinedToOtherDomain}
	ErrDomainMembershipDomainNotFound      = &DomainMembershipError{Kind: DomainMembershipErrorDomainNotFound}
	ErrDomainMembershipBadCredentials      = &DomainMembershipError{Kind: DomainMembershipErrorBadCredentials}
	ErrDomainMembershipAccountExists       = &DomainMembershipError{Kind: DomainMembershipErrorAccountExists}
	ErrDomainMembershipOuNotFound          = &DomainMembershipError{Kind: DomainMembershipErrorOuNotFound}
	ErrDomainMembershipAccessDenied        = &DomainMembershipError{Kind: DomainMembershipErrorAccessDenied}
	ErrDomainMembershipRebootPending       = &DomainMembershipError{Kind: DomainMembershipErrorRebootPending}
	ErrDomainMembershipTimeout             = &DomainMembershipError{Kind: DomainMembershipErrorTimeout}
	ErrDomainMembershipInvalidParameter    = &DomainMembershipError{Kind: DomainMembershipErrorInvalidParameter}
	ErrDomainMembershipUnknown             = &DomainMembershipError{Kind: DomainMembershipErrorUnknown}
)

// DomainJoinInput carries the desired configuration for Join.
type DomainJoinInput struct {
	// Domain is the DNS name of the Active Directory domain to join.
	Domain string
	// OUPath is the distinguished name of the OU for the computer account.
	// Empty means the default Computers container.
	OUPath string
	// Server is an optional domain controller or domain name passed to
	// Add-Computer -Server. Empty omits the parameter.
	Server string
	// Username is the domain account used for the join (UPN or DOMAIN\user).
	Username string
	// Password is the plaintext password for Username. It travels on stdin
	// and never appears in the script body or logs.
	Password string
	// Restart gates the deferred reboot: when true and the join reports a
	// pending reboot, a detached reboot is scheduled ~60s out.
	Restart bool
}

// DomainUnjoinInput carries the desired configuration for Unjoin.
type DomainUnjoinInput struct {
	// Username is the domain account used for the unjoin.
	Username string
	// Password is the plaintext password for Username. It travels on stdin
	// and never appears in the script body or logs.
	Password string
	// WorkgroupName is the workgroup the host joins after leaving the domain.
	WorkgroupName string
	// Restart gates the deferred reboot, mirroring Join.
	Restart bool
}

// DomainMembershipState is the observed domain-membership state of a host.
type DomainMembershipState struct {
	// Domain is the domain reported by Win32_ComputerSystem.Domain.
	Domain string
	// PartOfDomain is true when the host is domain-joined.
	PartOfDomain bool
	// ComputerName is the active computer name (Win32_ComputerSystem.Name).
	ComputerName string
	// PendingReboot is true when the OS exposes a pending reboot flag.
	PendingReboot bool
	// SecureChannelOk is the Test-ComputerSecureChannel result.
	// Informational only: it may be false while a join reboot is pending.
	SecureChannelOk bool
}

// DomainJoinResult is the side-channel returned by Join.
type DomainJoinResult struct {
	// RebootScheduled is true when the host-side script successfully
	// scheduled the deferred reboot (shutdown.exe exit code 0).
	RebootScheduled bool
}

// DomainUnjoinResult is the side-channel returned by Unjoin.
type DomainUnjoinResult struct {
	// AlreadyAbsent is true when the host was already workgroup-joined, so
	// no Remove-Computer call was needed.
	AlreadyAbsent bool
	// RebootScheduled mirrors DomainJoinResult.RebootScheduled.
	RebootScheduled bool
}

// WindowsDomainMembershipClient is the contract for the
// windows_domain_membership resource.
type WindowsDomainMembershipClient interface {
	// Read returns the current domain-membership state of the target host.
	Read(ctx context.Context) (*DomainMembershipState, error)

	// Join joins the host to the given domain. The pre-flight refuses hosts
	// that are already joined (ErrDomainMembershipAlreadyJoined for the
	// desired domain, ErrDomainMembershipJoinedToOtherDomain otherwise).
	// Returns the observed state plus the reboot side-channel.
	Join(ctx context.Context, in DomainJoinInput) (*DomainMembershipState, *DomainJoinResult, error)

	// Unjoin removes the host from its domain into the given workgroup.
	// Idempotent: an already workgroup-joined host succeeds with
	// AlreadyAbsent=true. Returns the observed state plus the reboot
	// side-channel.
	Unjoin(ctx context.Context, in DomainUnjoinInput) (*DomainMembershipState, *DomainUnjoinResult, error)
}
