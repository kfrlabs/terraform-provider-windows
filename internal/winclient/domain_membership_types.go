// Package winclient: types for the windows_domain_membership resource.
//
// DomainMembershipErrorKind / DomainMembershipError follow the same shape as
// ServiceError so the resource layer can branch with errors.Is.
package winclient

import (
	"context"
)

// DomainMembershipErrorKind categorises errors returned by
// WindowsDomainMembershipClient.
type DomainMembershipErrorKind string

const (
	// DomainMembershipErrorAlreadyJoined is returned by Join when the host is
	// already joined to the desired domain. Hard error — use terraform import.
	DomainMembershipErrorAlreadyJoined = "already_joined"

	// DomainMembershipErrorJoinedToOtherDomain is returned by Join when the
	// host is already joined to a different domain.
	DomainMembershipErrorJoinedToOtherDomain = "joined_to_other_domain"

	// DomainMembershipErrorDomainNotFound is returned when the domain (or a
	// domain controller for it) cannot be located (Win32 1355 / 53).
	DomainMembershipErrorDomainNotFound = "domain_not_found"

	// DomainMembershipErrorBadCredentials is returned on logon failure
	// (Win32 1326): unknown user name or bad password.
	DomainMembershipErrorBadCredentials = "bad_credentials"

	// DomainMembershipErrorAccountExists is returned when the computer
	// account already exists in the domain (Win32 2224).
	DomainMembershipErrorAccountExists = "account_exists"

	// DomainMembershipErrorOuNotFound is returned when the requested
	// organisational unit does not exist.
	DomainMembershipErrorOuNotFound = "ou_not_found"

	// DomainMembershipErrorAccessDenied is returned on AccessDenied (Win32 5).
	DomainMembershipErrorAccessDenied = "access_denied"

	// DomainMembershipErrorRebootPending is returned when a pending reboot
	// blocks the join/unjoin operation.
	DomainMembershipErrorRebootPending = "reboot_pending"

	// DomainMembershipErrorTimeout is returned when the operation timed out
	// or was cancelled.
	DomainMembershipErrorTimeout = "timeout"

	// DomainMembershipErrorInvalidParameter is returned for empty required
	// inputs (domain, username).
	DomainMembershipErrorInvalidParameter = "invalid_parameter"

	// DomainMembershipErrorUnknown is the catch-all for unmapped PowerShell
	// or SSH failures.
	DomainMembershipErrorUnknown = "unknown"
)

// DomainMembershipError is the structured error type returned by
// WindowsDomainMembershipClient.
type DomainMembershipError = ResourceError

// NewDomainMembershipError constructs a *DomainMembershipError.
func NewDomainMembershipError(kind DomainMembershipErrorKind, msg string, cause error, ctx map[string]string) *DomainMembershipError {
	return NewResourceError("windows_domain_membership", string(kind), msg, cause, ctx)
}

// IsDomainMembershipError reports whether err is a *DomainMembershipError of
// the given kind.
func IsDomainMembershipError(err error, kind DomainMembershipErrorKind) bool {
	return IsResourceError(err, "windows_domain_membership", string(kind))
}

// Sentinel errors usable with errors.Is.
var (
	ErrDomainMembershipAlreadyJoined       = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorAlreadyJoined}
	ErrDomainMembershipJoinedToOtherDomain = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorJoinedToOtherDomain}
	ErrDomainMembershipDomainNotFound      = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorDomainNotFound}
	ErrDomainMembershipBadCredentials      = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorBadCredentials}
	ErrDomainMembershipAccountExists       = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorAccountExists}
	ErrDomainMembershipOuNotFound          = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorOuNotFound}
	ErrDomainMembershipAccessDenied        = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorAccessDenied}
	ErrDomainMembershipRebootPending       = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorRebootPending}
	ErrDomainMembershipTimeout             = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorTimeout}
	ErrDomainMembershipInvalidParameter    = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorInvalidParameter}
	ErrDomainMembershipUnknown             = &DomainMembershipError{Resource: "windows_domain_membership", Kind: DomainMembershipErrorUnknown}
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
	// Domain is the DNS name of the joined domain (Win32_ComputerSystem.Domain).
	// Empty when the host is not domain-joined — never the workgroup name.
	Domain string
	// PartOfDomain is true when the host is domain-joined.
	PartOfDomain bool
	// ComputerName is the active computer name (Win32_ComputerSystem.Name).
	ComputerName string
	// PendingReboot is true when the OS exposes a pending reboot flag.
	PendingReboot bool
	// SecureChannelOk is the Test-ComputerSecureChannel result.
	// Informational only: it may be false while a join reboot is pending.
	// Meaningless when SecureChannelNull is true; kept as false then.
	SecureChannelOk bool
	// SecureChannelNull reports that no secure-channel result exists: the
	// host is not domain-joined, or the read skipped the
	// Test-ComputerSecureChannel probe (DomainMembershipReadOptions).
	// The resource path ignores this flag and keeps reading SecureChannelOk
	// (false when null, matching the historical workgroup behavior); the
	// data source maps it to a null secure_channel_ok.
	SecureChannelNull bool
	// Workgroup is the workgroup name (Win32_ComputerSystem.Workgroup).
	// Empty when the host is domain-joined.
	Workgroup string
	// DNSHostName is the fully qualified host name
	// (Win32_ComputerSystem.DNSHostName).
	DNSHostName string
	// NetBIOSDomain is the NetBIOS (short) domain name, resolved from
	// Win32_NTDomain with a first-DNS-label fallback. Empty when the host
	// is not domain-joined.
	NetBIOSDomain string
	// DomainRole is the Win32_ComputerSystem.DomainRole value mapped to its
	// documented name (StandaloneWorkstation, MemberWorkstation,
	// StandaloneServer, MemberServer, BackupDomainController,
	// PrimaryDomainController).
	DomainRole string
	// MachineID is the stable per-machine identifier
	// (HKLM:\SOFTWARE\Microsoft\Cryptography\MachineGuid).
	MachineID string
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

// DomainMembershipReadOptions tunes ReadWithOptions.
type DomainMembershipReadOptions struct {
	// CheckSecureChannel controls the Test-ComputerSecureChannel probe.
	// True preserves the historical Read behavior. False skips the probe
	// (no domain-controller round-trip) for inventory-only reads; the
	// state then reports SecureChannelNull with SecureChannelOk false.
	CheckSecureChannel bool
}

// WindowsDomainMembershipClient is the contract for the
// windows_domain_membership resource and data source.
type WindowsDomainMembershipClient interface {
	// Read returns the current domain-membership state of the target host.
	// Equivalent to ReadWithOptions with CheckSecureChannel=true.
	Read(ctx context.Context) (*DomainMembershipState, error)

	// ReadWithOptions returns the current domain-membership state of the
	// target host, optionally skipping the secure-channel probe.
	ReadWithOptions(ctx context.Context, opts DomainMembershipReadOptions) (*DomainMembershipState, error)

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
