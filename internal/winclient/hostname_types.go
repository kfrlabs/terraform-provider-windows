// Package winclient: WindowsHostnameClient interface and associated types
// for managing the NetBIOS computer name of a remote Windows host over
// SSH + PowerShell.
//
// Spec alignment: windows_hostname spec v1 (2026-04-25).
//
// File layout:
//
//	HostnameErrorKind     — string enum of typed error categories
//	HostnameError         — alias of ResourceError (Resource windows_hostname)
//	Sentinel errors       — pre-constructed *HostnameError for errors.Is
//	HostnameInput         — input parameters for Create/Update
//	HostnameState         — observed state returned by Read
//	WindowsHostnameClient — CRUD interface (Delete is a documented no-op)
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// HostnameErrorKind — typed error categories
// ---------------------------------------------------------------------------

// HostnameErrorKind categorises errors returned by WindowsHostnameClient
// operations.  Use errors.Is(err, ErrHostname*) or IsHostnameError(err, kind)
// for programmatic error handling.
type HostnameErrorKind string

const (
	// HostnameErrorInvalidName is returned when the desired name fails the
	// server-side NetBIOS validation (length, charset, leading/trailing
	// hyphen, purely numeric).  Mirrors EC-1.
	HostnameErrorInvalidName = "invalid_name"

	// HostnameErrorPermission is returned when Rename-Computer or the HKLM
	// reads fail with AccessDenied / RenameComputerNotAuthorized (EC-4).
	HostnameErrorPermission = "permission_denied"

	// HostnameErrorDomainJoined is returned when the target machine is
	// part of a domain (PartOfDomain == true).  v1 does not support
	// domain-joined renames (EC-5).
	HostnameErrorDomainJoined = "domain_joined"

	// HostnameErrorUnreachable is returned when SSH cannot be contacted
	// (connection refused, TLS error, auth failure, timeout).  Context
	// SHOULD include host, port and transport (EC-6).
	HostnameErrorUnreachable = "unreachable"

	// HostnameErrorMachineMismatch is returned by Read when the live
	// MachineGuid differs from the supplied state ID (EC-10).  Causes
	// the resource handler to RemoveResource and recreate.
	HostnameErrorMachineMismatch = "machine_mismatch"

	// HostnameErrorConcurrent is returned when an external rename happens
	// between Read and Update — the observed pending_name diverges from
	// what the client expected (EC-11).  Context contains both names.
	HostnameErrorConcurrent = "concurrent_modification"

	// HostnameErrorUnknown is the catch-all for unmapped PowerShell or
	// SSH failures.  Stdout/stderr SHOULD be captured in Context.
	HostnameErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// HostnameError — alias of the generic ResourceError (issue #348, batch 5)
//
// HostnameError is the structured error type returned by all
// WindowsHostnameClient methods. It is an alias of the generic
// ResourceError with Resource fixed to "windows_hostname": use
// errors.Is(err, ErrHostname*) for kind matching (matches by
// (Resource, Kind), same as the old Kind-only match within this
// resource), or errors.As(err, &he) to inspect Context.
// The wire format is unchanged: "windows_hostname [<kind>]: <message>".
type HostnameError = ResourceError

// NewHostnameError constructs a *HostnameError. Pass a nil cause when no
// underlying error exists.  The ctx map may be nil.
func NewHostnameError(kind HostnameErrorKind, message string, cause error, ctx map[string]string) *HostnameError {
	return NewResourceError(hostnameResource, string(kind), message, cause, ctx)
}

// IsHostnameError reports whether err is a *HostnameError of the given kind.
func IsHostnameError(err error, kind HostnameErrorKind) bool {
	return IsResourceError(err, hostnameResource, string(kind))
}

// hostnameResource is the Resource key carried by every HostnameError.
const hostnameResource = "windows_hostname"

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

var (
	ErrHostnameInvalidName     = &HostnameError{Resource: hostnameResource, Kind: HostnameErrorInvalidName}
	ErrHostnamePermission      = &HostnameError{Resource: hostnameResource, Kind: HostnameErrorPermission}
	ErrHostnameDomainJoined    = &HostnameError{Resource: hostnameResource, Kind: HostnameErrorDomainJoined}
	ErrHostnameUnreachable     = &HostnameError{Resource: hostnameResource, Kind: HostnameErrorUnreachable}
	ErrHostnameMachineMismatch = &HostnameError{Resource: hostnameResource, Kind: HostnameErrorMachineMismatch}
	ErrHostnameConcurrent      = &HostnameError{Resource: hostnameResource, Kind: HostnameErrorConcurrent}
	ErrHostnameUnknown         = &HostnameError{Resource: hostnameResource, Kind: HostnameErrorUnknown}
)

// ---------------------------------------------------------------------------
// HostnameInput — parameters for Create / Update
// ---------------------------------------------------------------------------

// HostnameInput carries the desired hostname configuration.  Consumed by
// Create and Update.
//
// Zero-value semantics:
//   - Name ""    → invalid (Create/Update return ErrHostnameInvalidName).
//   - Force false → Rename-Computer is invoked without -Force.
type HostnameInput struct {
	// Name is the desired NetBIOS computer name.  Required.  The client
	// re-validates the NetBIOS rule (length 1..15, charset, no leading/
	// trailing hyphen, not purely numeric) before issuing Rename-Computer
	// to defend against schema bypass (EC-1).
	Name string

	// Force, when true, passes -Force to Rename-Computer to suppress the
	// interactive confirmation prompt.
	Force bool
}

// ---------------------------------------------------------------------------
// HostnameState — observed state returned by Read
// ---------------------------------------------------------------------------

// HostnameState aggregates the four reads documented in the spec
// (Win32_ComputerSystem + 3 HKLM registry properties).
//
// MachineID is the stable Terraform resource ID; CurrentName and
// PendingName drive drift detection (EC-3).
type HostnameState struct {
	// MachineID is the value of HKLM:\SOFTWARE\Microsoft\Cryptography\
	// MachineGuid — stable per machine, anchors the Terraform ID.
	MachineID string

	// CurrentName is the active computer name (Win32_ComputerSystem.Name,
	// equivalent to HKLM ActiveComputerName).
	CurrentName string

	// PendingName is HKLM ComputerName\ComputerName — the name that will
	// take effect on next reboot.  Equal to CurrentName when no rename
	// is pending.
	PendingName string

	// RebootPending is true when PendingName != CurrentName
	// (case-insensitive comparison done by the client).
	RebootPending bool

	// PartOfDomain is true when the machine is domain-joined.  v1
	// rejects domain-joined hosts (EC-5); the field is exposed so the
	// resource handler can produce a precise diagnostic.
	PartOfDomain bool

	// Domain is the AD domain name when PartOfDomain == true; empty
	// otherwise.  Surfaced in EC-5 diagnostics.
	Domain string
}

// ---------------------------------------------------------------------------
// WindowsHostnameClient — CRUD interface
// ---------------------------------------------------------------------------

// WindowsHostnameClient defines the contract for managing the NetBIOS
// hostname of a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation.  All methods return *HostnameError (wrapped in error).
//
//	Notable invariants:
//	  - Pre-flight: Create and Update MUST check PartOfDomain and reject
//	    with ErrHostnameDomainJoined (EC-5) before any rename attempt.
//	  - Idempotency: Create returns success without calling Rename-Computer
//	    when both CurrentName and PendingName already match input.Name
//	    (case-insensitive, EC-2).
//	  - Drift: the Read state's PendingName is what the resource handler
//	    must compare against the desired `name` to avoid apply loops while
//	    a reboot is pending (EC-3).
//	  - Delete is a documented no-op (EC-7); the implementation MUST emit
//	    a tflog.Warn but never invoke Rename-Computer.
//	  - Read returns ErrHostnameMachineMismatch when the live MachineGuid
//	    differs from the supplied id (EC-10), so the resource handler can
//	    RemoveResource and force re-creation.
type WindowsHostnameClient interface {
	// Create renames the target host to input.Name (idempotent if already
	// at the desired name).  Returns the post-call HostnameState read back
	// from the host (current_name, pending_name, reboot_pending, machine_id).
	//
	// Returns ErrHostnameDomainJoined (EC-5) if the host is domain-joined.
	// Returns ErrHostnameInvalidName  (EC-1) on server-side validation failure.
	// Returns ErrHostnamePermission   (EC-4) on AccessDenied / RenameComputerNotAuthorized.
	// Returns ErrHostnameUnreachable  (EC-6) if SSH cannot be reached.
	Create(ctx context.Context, input HostnameInput) (*HostnameState, error)

	// Read aggregates Win32_ComputerSystem and the three HKLM registry
	// reads documented in the spec.  The id argument is the previously
	// observed MachineGuid; if the live MachineGuid differs, the method
	// returns ErrHostnameMachineMismatch (EC-10).
	//
	// Read does NOT raise EC-5 by itself: the resource handler decides
	// whether domain membership should fail-fast or merely surface a
	// warning during a stale-state refresh.
	Read(ctx context.Context, id string) (*HostnameState, error)

	// Update renames the host in place via Rename-Computer (no replace).
	// id is the MachineGuid stored in state, used to verify the resource
	// still targets the same machine before issuing the rename.
	//
	// After the call, Update re-reads the state and returns the freshly
	// observed HostnameState (RebootPending will typically be true).
	// Same error contract as Create plus ErrHostnameMachineMismatch and
	// ErrHostnameConcurrent (EC-11).
	Update(ctx context.Context, id string, input HostnameInput) (*HostnameState, error)

	// Delete is a no-op (EC-7).  Implementations MUST NOT issue any
	// PowerShell rename / reset and MUST emit tflog.Warn:
	//   "windows_hostname destroy is a no-op; the computer keeps its
	//    current name (<current_name>)".
	// The id argument is accepted for symmetry with the other CRUD
	// methods and to allow the implementation to log the current name.
	Delete(ctx context.Context, id string) error
}
