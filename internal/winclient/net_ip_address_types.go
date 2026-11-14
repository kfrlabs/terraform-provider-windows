// Package winclient defines the NetIPAddressClient interface and associated
// types for managing static IP addresses on a remote Windows host over SSH.
//
// Spec alignment: windows_net_ip_address spec v1 (issue #230).
//
// Scope: one static address on one network interface (New-NetIPAddress /
// Set-NetIPAddress / Remove-NetIPAddress). Several resources may target the
// same interface, one per address. The default gateway is deliberately not
// managed here (see windows_net_route); neither are DNS, adapter
// rename/enable/disable, DHCP servers, or address lifetimes.
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// NetIPAddressErrorKind — typed error categories
// ---------------------------------------------------------------------------

// NetIPAddressErrorKind categorises errors returned by NetIPAddressClient
// operations. Use errors.Is(err, ErrNetIPAddress*) or IsNetIPAddressError
// for programmatic error handling.
type NetIPAddressErrorKind string

const (
	// NetIPAddressErrorInterfaceNotFound is returned when no interface
	// matches the requested alias (exact, case-insensitive comparison —
	// never -InterfaceAlias wildcard semantics). The message lists the
	// valid aliases.
	NetIPAddressErrorInterfaceNotFound = "interface_not_found"

	// NetIPAddressErrorNotFound is returned when the requested address is
	// not present (read of a missing address, update/delete pre-flight).
	NetIPAddressErrorNotFound = "not_found"

	// NetIPAddressErrorAlreadyExists is returned when the requested address
	// is already present on the same interface (suggest terraform import).
	NetIPAddressErrorAlreadyExists = "already_exists"

	// NetIPAddressErrorInUseElsewhere is returned when the requested address
	// is present on a different interface, or when a lookup matches several
	// addresses. The message lists the candidates.
	NetIPAddressErrorInUseElsewhere = "address_in_use_elsewhere"

	// NetIPAddressErrorInvalidAddress is returned when the address, prefix
	// length or family combination is rejected by the host or by
	// client-side validation.
	NetIPAddressErrorInvalidAddress = "invalid_address"

	// NetIPAddressErrorDHCPEnabled is returned when an IPv4 address cannot
	// be created because the interface still has DHCP enabled
	// ("inconsistent parameters PolicyStore PersistentStore and Dhcp
	// Enabled"). The message hints at setting disable_dhcp.
	NetIPAddressErrorDHCPEnabled = "dhcp_enabled"

	// NetIPAddressErrorDuplicate is returned when the new address fails
	// duplicate address detection (AddressState Duplicate). The address is
	// removed again (rollback) before this error is returned.
	NetIPAddressErrorDuplicate = "duplicate_address"

	// NetIPAddressErrorPermission is returned when the SSH user lacks the
	// privilege to manage addresses (typically a non-administrator
	// connection).
	NetIPAddressErrorPermission = "permission_denied"

	// NetIPAddressErrorMgmtAtRisk is returned, fail-closed, when the
	// operation would remove or alter the management address or the route
	// currently carrying the SSH traffic. Nothing is applied.
	NetIPAddressErrorMgmtAtRisk = "management_path_at_risk"

	// NetIPAddressErrorMgmtUnknown is returned, fail-closed, when the
	// management path cannot be determined and the operation is risky.
	// Nothing is applied.
	NetIPAddressErrorMgmtUnknown = "management_path_unknown"

	// NetIPAddressErrorUnreachable is returned when SSH cannot be contacted
	// (connection refused, auth failure, timeout). Context SHOULD include
	// host, port and transport.
	NetIPAddressErrorUnreachable = "unreachable"

	// NetIPAddressErrorUnknown is the catch-all for unmapped PowerShell or
	// SSH failures.
	NetIPAddressErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// NetIPAddressError — structured error
// ---------------------------------------------------------------------------

// NetIPAddressError is the structured error type returned by all
// NetIPAddressClient methods. Use errors.Is(err, ErrNetIPAddress*) for kind
// matching, or errors.As(err, &ne) to inspect Context.
type NetIPAddressError = ResourceError

// NewNetIPAddressError constructs a *NetIPAddressError. Pass a nil cause
// when no underlying error exists. The ctx map may be nil.
func NewNetIPAddressError(kind NetIPAddressErrorKind, message string, cause error, ctx map[string]string) *NetIPAddressError {
	return NewResourceError("windows_net_ip_address", string(kind), message, cause, ctx)
}

// IsNetIPAddressError reports whether err is a *NetIPAddressError of the given kind.
func IsNetIPAddressError(err error, kind NetIPAddressErrorKind) bool {
	return IsResourceError(err, "windows_net_ip_address", string(kind))
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

var (
	ErrNetIPAddressInterfaceNotFound = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorInterfaceNotFound}
	ErrNetIPAddressNotFound          = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorNotFound}
	ErrNetIPAddressAlreadyExists     = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorAlreadyExists}
	ErrNetIPAddressInUseElsewhere    = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorInUseElsewhere}
	ErrNetIPAddressInvalidAddress    = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorInvalidAddress}
	ErrNetIPAddressDHCPEnabled       = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorDHCPEnabled}
	ErrNetIPAddressDuplicate         = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorDuplicate}
	ErrNetIPAddressPermission        = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorPermission}
	ErrNetIPAddressMgmtAtRisk        = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorMgmtAtRisk}
	ErrNetIPAddressMgmtUnknown       = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorMgmtUnknown}
	ErrNetIPAddressUnreachable       = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorUnreachable}
	ErrNetIPAddressUnknown           = &NetIPAddressError{Resource: "windows_net_ip_address", Kind: NetIPAddressErrorUnknown}
)

// ---------------------------------------------------------------------------
// NetIPAddressInput — parameters for Create
// ---------------------------------------------------------------------------

// NetIPAddressInput carries the desired address configuration. Consumed by
// Create.
//
// The IPAddress must already be canonicalised with netip (lower-case,
// compressed IPv6, no zone ID); Create re-validates defensively.
type NetIPAddressInput struct {
	// InterfaceAlias is the target adapter's friendly name. Matched with an
	// exact, case-insensitive comparison (never wildcard semantics).
	InterfaceAlias string

	// IPAddress is the static address in canonical netip spelling.
	IPAddress string

	// PrefixLength is the subnet prefix length (1-32 for IPv4, 1-128 IPv6).
	PrefixLength int

	// SkipAsSource excludes the address from outbound source selection.
	SkipAsSource bool

	// DisableDHCP disables DHCP on the interface before creating an IPv4
	// address (IPv4 only). Remembered by the caller so destroy can restore it.
	DisableDHCP bool

	// UnsafeSkipManagementCheck bypasses the management-path guard. The host
	// must stay reachable at the provider host address afterwards.
	UnsafeSkipManagementCheck bool
}

// ---------------------------------------------------------------------------
// NetIPAddressInfo — observed state
// ---------------------------------------------------------------------------

// NetIPAddressInfo holds the observed state of one static IP address as
// returned by the Read pipeline.
type NetIPAddressInfo struct {
	// InterfaceAlias is the adapter's friendly name (host spelling).
	InterfaceAlias string

	// InterfaceIndex is the adapter's numeric index.
	InterfaceIndex int

	// IPAddress is the address in canonical netip spelling.
	IPAddress string

	// PrefixLength is the observed subnet prefix length.
	PrefixLength int

	// AddressFamily is "IPv4" or "IPv6".
	AddressFamily string

	// AddressState is "Preferred", "Tentative", "Duplicate" or "Deprecated".
	AddressState string

	// PrefixOrigin is "Manual", "Dhcp", "WellKnown",
	// "RouterAdvertisement" or "Other".
	PrefixOrigin string

	// SkipAsSource mirrors the host's SkipAsSource flag.
	SkipAsSource bool
}

// ---------------------------------------------------------------------------
// NetIPAddressClient — CRUD interface
// ---------------------------------------------------------------------------

// NetIPAddressClient defines the contract for managing static IP addresses
// on a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation. All methods return *NetIPAddressError (wrapped in error).
//
// Guard invariants: every mutating operation consults the shared
// management-path guard (Client.ManagementPath, computed per operation,
// never cached) unless UnsafeSkipManagementCheck is set. Touching the
// management address returns ErrNetIPAddressMgmtAtRisk; an undeterminable
// path returns ErrNetIPAddressMgmtUnknown. Nothing is applied in either
// case.
type NetIPAddressClient interface {
	// Create provisions the static address: resolves the interface,
	// pre-flights duplicates, optionally disables DHCP (IPv4), runs
	// New-NetIPAddress, polls AddressState (~10 s, rolling back on
	// Duplicate), and reads the result back. The returned bool reports
	// whether this call disabled DHCP (so the caller can restore it on
	// destroy).
	Create(ctx context.Context, input NetIPAddressInput) (*NetIPAddressInfo, bool, error)

	// Read returns the observed address, or (nil, nil) when the address —
	// or its interface — is gone (the resource handler then drops the
	// resource from state).
	Read(ctx context.Context, interfaceAlias, ipAddress string) (*NetIPAddressInfo, error)

	// Lookup lists every address matching ipAddress, optionally restricted
	// to one interface (exact, case-insensitive alias match). Zero matches
	// return ErrNetIPAddressNotFound; several return
	// ErrNetIPAddressInUseElsewhere listing the candidates. Backs the data
	// source, which accepts an address with or without an interface.
	Lookup(ctx context.Context, ipAddress, interfaceAlias string) ([]*NetIPAddressInfo, error)

	// Update changes prefix length and/or SkipAsSource in place via
	// Set-NetIPAddress after the guard passes. The returned bool reports
	// whether this call disabled DHCP (disableDHCP is honoured idempotently
	// like in Create).
	Update(ctx context.Context, interfaceAlias, ipAddress string, prefixLength int, skipAsSource, disableDHCP, unsafeSkip bool) (*NetIPAddressInfo, bool, error)

	// Delete removes the address via Remove-NetIPAddress after the guard
	// passes. A missing address or interface is a successful no-op (nil).
	Delete(ctx context.Context, interfaceAlias, ipAddress string, unsafeSkip bool) error

	// RestoreDHCP re-enables DHCP on the interface (Set-NetIPInterface
	// -AddressFamily IPv4 -Dhcp Enabled). Used by destroy with
	// restore_dhcp_on_destroy when this resource disabled DHCP. It is
	// exempt from the management-path guard by design: re-enabling DHCP
	// never removes an address or a route, so it cannot sever the SSH
	// session; see the implementation for the full justification.
	RestoreDHCP(ctx context.Context, interfaceAlias string) error
}
