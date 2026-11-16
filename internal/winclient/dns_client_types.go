// Package winclient defines the DNSClientClient interface and associated
// types for managing per-interface DNS client settings on a remote Windows
// host over SSH.
//
// Spec alignment: windows_dns_client spec (issue #229).
//
// Scope: one network interface (Set-DnsClientServerAddress / Set-DnsClient).
// Static server addresses are read from the Tcpip/Tcpip6 registry
// (Interfaces\{guid}\NameServer); effective addresses include DHCP-provided
// servers and come from Get-DnsClientServerAddress. Several resources must
// not target the same interface: the last writer wins for the managed
// families.
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// DNSClientErrorKind — typed error categories
// ---------------------------------------------------------------------------

// DNSClientErrorKind categorises errors returned by DNSClientClient
// operations. Use errors.Is(err, ErrDNSClient*) or IsDNSClientError for
// programmatic error handling.
type DNSClientErrorKind string

const (
	// DNSClientErrorInterfaceNotFound is returned when no interface
	// matches the requested alias (exact, case-insensitive comparison —
	// never -InterfaceAlias wildcard semantics). The message lists the
	// valid aliases.
	DNSClientErrorInterfaceNotFound = "interface_not_found"

	// DNSClientErrorInvalidAddress is returned when a server address fails
	// client-side validation (unparsable, wrong family, duplicate,
	// unspecified, multicast, broadcast, zone ID) or when the host rejects
	// it.
	DNSClientErrorInvalidAddress = "invalid_address"

	// DNSClientErrorInvalidSuffix is returned when the connection-specific
	// suffix fails client-side DNS name validation or when the host
	// rejects it.
	DNSClientErrorInvalidSuffix = "invalid_suffix"

	// DNSClientErrorPermission is returned when the SSH user lacks the
	// privilege to read or write DNS client settings (typically a
	// non-administrator connection).
	DNSClientErrorPermission = "permission_denied"

	// DNSClientErrorUnreachable is returned when SSH cannot be contacted
	// (connection refused, auth failure, timeout). Context SHOULD include
	// host, port and transport.
	DNSClientErrorUnreachable = "unreachable"

	// DNSClientErrorUnknown is the catch-all for unmapped PowerShell or SSH
	// failures.
	DNSClientErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// DNSClientError — structured error
// ---------------------------------------------------------------------------

// DNSClientError is the structured error type returned by all
// DNSClientClient methods. Use errors.Is(err, ErrDNSClient*) for kind
// matching, or errors.As(err, &de) to inspect Context.
type DNSClientError = ResourceError

// NewDNSClientError constructs a *DNSClientError. Pass a nil cause when no
// underlying error exists. The ctx map may be nil.
func NewDNSClientError(kind DNSClientErrorKind, message string, cause error, ctx map[string]string) *DNSClientError {
	return NewResourceError("windows_dns_client", string(kind), message, cause, ctx)
}

// IsDNSClientError reports whether err is a *DNSClientError of the given kind.
func IsDNSClientError(err error, kind DNSClientErrorKind) bool {
	return IsResourceError(err, "windows_dns_client", string(kind))
}

// Sentinel errors — use with errors.Is.
var (
	ErrDNSClientInterfaceNotFound = &DNSClientError{Resource: "windows_dns_client", Kind: DNSClientErrorInterfaceNotFound}
	ErrDNSClientInvalidAddress    = &DNSClientError{Resource: "windows_dns_client", Kind: DNSClientErrorInvalidAddress}
	ErrDNSClientInvalidSuffix     = &DNSClientError{Resource: "windows_dns_client", Kind: DNSClientErrorInvalidSuffix}
	ErrDNSClientPermission        = &DNSClientError{Resource: "windows_dns_client", Kind: DNSClientErrorPermission}
	ErrDNSClientUnreachable       = &DNSClientError{Resource: "windows_dns_client", Kind: DNSClientErrorUnreachable}
	ErrDNSClientUnknown           = &DNSClientError{Resource: "windows_dns_client", Kind: DNSClientErrorUnknown}
)

// ---------------------------------------------------------------------------
// DNSClientSettings — desired configuration delta
// ---------------------------------------------------------------------------

// DNSClientSettings carries the desired DNS client configuration delta for
// one interface. Consumed by Apply (Create and Update share the operation
// because the interface always exists).
//
// Partial management: a nil slice (IPv4Addresses / IPv6Addresses) or a nil
// pointer (ConnectionSpecificSuffix, RegisterThisConnectionAddress,
// UseSuffixWhenRegistering) means "unmanaged" — the attribute is left
// untouched on the host. A non-nil slice is authoritative: an empty slice
// resets the family to automatic (DHCP). The *Set flags disambiguate an
// explicitly configured empty value from an unmanaged attribute for the
// slice fields where nil already carries meaning at the provider boundary.
type DNSClientSettings struct {
	// IPv4Addresses holds the desired static IPv4 servers in order, or nil
	// when the IPv4 family is unmanaged. An empty non-nil slice resets
	// the family to automatic.
	IPv4Addresses []string
	// IPv4Set reports whether the IPv4 family is managed.
	IPv4Set bool

	// IPv6Addresses holds the desired static IPv6 servers in order, or nil
	// when the IPv6 family is unmanaged. An empty non-nil slice resets
	// the family to automatic.
	IPv6Addresses []string
	// IPv6Set reports whether the IPv6 family is managed.
	IPv6Set bool

	// ConnectionSpecificSuffix is the desired DNS suffix, or nil when
	// unmanaged. A pointer to "" clears the suffix.
	ConnectionSpecificSuffix *string
	// SuffixSet reports whether the suffix is managed.
	SuffixSet bool

	// RegisterThisConnectionAddress mirrors Set-DnsClient
	// -RegisterThisConnectionsAddress, or nil when unmanaged.
	RegisterThisConnectionAddress *bool

	// UseSuffixWhenRegistering mirrors Set-DnsClient
	// -UseSuffixWhenRegistering, or nil when unmanaged.
	UseSuffixWhenRegistering *bool
}

// DNSClientConfigured reports whether at least one attribute is managed
// (used to skip a no-op Set round trip).
func (s DNSClientSettings) DNSClientConfigured() bool {
	return s.IPv4Set || s.IPv6Set || s.SuffixSet ||
		s.RegisterThisConnectionAddress != nil ||
		s.UseSuffixWhenRegistering != nil
}

// ---------------------------------------------------------------------------
// DNSClientState — observed state
// ---------------------------------------------------------------------------

// DNSClientState holds the observed DNS client state of one interface as
// returned by the Read pipeline.
type DNSClientState struct {
	// InterfaceAlias is the adapter's friendly name (host spelling).
	InterfaceAlias string

	// InterfaceIndex is the adapter's numeric index.
	InterfaceIndex int

	// InterfaceGUID is the adapter's GUID (braces included, host spelling).
	InterfaceGUID string

	// StaticIPv4 holds the statically configured IPv4 servers in order
	// (registry NameServer); empty when the family is automatic (DHCP).
	StaticIPv4 []string

	// StaticIPv6 holds the statically configured IPv6 servers in order
	// (registry NameServer); empty when the family is automatic (DHCP).
	StaticIPv6 []string

	// EffectiveIPv4 holds the live IPv4 servers (static plus
	// DHCP-provided), as reported by Get-DnsClientServerAddress.
	EffectiveIPv4 []string

	// EffectiveIPv6 holds the live IPv6 servers (static plus
	// DHCP-provided), as reported by Get-DnsClientServerAddress.
	EffectiveIPv6 []string

	// ConnectionSpecificSuffix is the observed DNS suffix (""
	// when unset).
	ConnectionSpecificSuffix string

	// RegisterThisConnectionAddress mirrors Get-DnsClient.
	RegisterThisConnectionAddress bool

	// UseSuffixWhenRegistering mirrors Get-DnsClient.
	UseSuffixWhenRegistering bool
}

// ---------------------------------------------------------------------------
// DNSClientClient — CRUD interface
// ---------------------------------------------------------------------------

// DNSClientClient defines the contract for managing per-interface DNS
// client settings on a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation. All methods return *DNSClientError (wrapped in error).
//
// Read returns (nil, nil) when the interface is gone (renamed or removed);
// the resource handler then drops the resource from state.
//
// Apply is idempotent: setting values identical to the observed state is a
// successful no-op round trip. Because Set-DnsClientServerAddress replaces
// the server list across families, Apply performs a cross-family
// read-modify-write: unmanaged families keep their observed static
// addresses while managed families (including explicitly empty ones, which
// reset the family to automatic) are replaced.
//
// Reset is Apply with an empty delta for the managed families: it is kept
// as a separate method so destroy can express "reset every family this
// resource managed, clear the suffix only when asked" without the provider
// layer re-deriving the merge.
type DNSClientClient interface {
	// Read returns the observed DNS client state of the named interface,
	// or (nil, nil) when no interface matches the alias.
	Read(ctx context.Context, interfaceAlias string) (*DNSClientState, error)

	// Apply writes the managed attributes (server addresses for the
	// managed families, suffix and registration flags when set) and reads
	// the resulting state back. Unmanaged attributes are left untouched.
	Apply(ctx context.Context, interfaceAlias string, settings DNSClientSettings) (*DNSClientState, error)

	// Reset returns the managed families to automatic (DHCP) and,
	// when clearSuffix is true, clears the connection-specific suffix.
	// Flags are left untouched. A missing interface is a successful
	// no-op (nil).
	Reset(ctx context.Context, interfaceAlias string, resetIPv4, resetIPv6, clearSuffix bool) (*DNSClientState, error)
}
