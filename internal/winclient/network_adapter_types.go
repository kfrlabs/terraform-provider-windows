// Package winclient defines the WindowsNetworkAdaptersClient interface and
// associated types for the standalone windows_network_adapters collection
// data source (issue #295). There is no sibling resource: List is a
// read-only inventory of every adapter on the remote Windows host, narrowed
// by Go-side filters.
//
// Scope: Get-NetAdapter plus bulk-collected Get-NetIPInterface,
// Get-NetIPAddress, Get-NetRoute (default routes only), Get-DnsClientServerAddress
// and Get-NetConnectionProfile, joined by interface index in a single
// round-trip. Out of scope: creating, renaming, enabling or disabling
// adapters; advanced properties; teaming answers beyond the reported
// driver/media fields.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// NetworkAdapterErrorKind — typed error categories
// ---------------------------------------------------------------------------

// NetworkAdapterErrorKind categorises errors returned by
// WindowsNetworkAdaptersClient operations. Use errors.Is(err,
// ErrNetworkAdapter*) or IsNetworkAdapterError for programmatic error
// handling.
type NetworkAdapterErrorKind string

const (
	// NetworkAdapterErrorAccessDenied is returned when the SSH user lacks
	// the privilege to read adapter state (typically a non-administrator
	// connection).
	NetworkAdapterErrorAccessDenied NetworkAdapterErrorKind = "access_denied"

	// NetworkAdapterErrorCIMUnavailable is returned when the CIM/WMI stack
	// itself is unavailable (winmgmt service stopped, repository
	// corruption, provider load failure).
	NetworkAdapterErrorCIMUnavailable NetworkAdapterErrorKind = "cim_unavailable"

	// NetworkAdapterErrorTimeout is returned when the operation timed out
	// or was cancelled.
	NetworkAdapterErrorTimeout NetworkAdapterErrorKind = "timeout"

	// NetworkAdapterErrorInvalidParameter is returned when a filter fails
	// client-side validation (unknown status, malformed MAC, uncompilable
	// name regex). No host call is made.
	NetworkAdapterErrorInvalidParameter NetworkAdapterErrorKind = "invalid_parameter"

	// NetworkAdapterErrorUnknown is the catch-all for unmapped PowerShell
	// or SSH failures.
	NetworkAdapterErrorUnknown NetworkAdapterErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// NetworkAdapterError — structured error
// ---------------------------------------------------------------------------

// NetworkAdapterError is the structured error type returned by all
// WindowsNetworkAdaptersClient methods. Use errors.Is(err,
// ErrNetworkAdapter*) for kind matching, or errors.As(err, &ne) to inspect
// Context.
type NetworkAdapterError struct {
	// Kind is the machine-readable error category.
	Kind NetworkAdapterErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics. It must not contain SSH credentials.
	Message string

	// Context holds structured diagnostic key-value pairs (e.g. "host",
	// "port", "transport"). All values must be safe to log.
	Context map[string]string

	// Cause is the underlying error, if any (typically an SSH transport or
	// PowerShell parsing error).
	Cause error
}

// Error implements the error interface.
func (e *NetworkAdapterError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_network_adapters [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_network_adapters [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *NetworkAdapterError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *NetworkAdapterError) Is(target error) bool {
	t, ok := target.(*NetworkAdapterError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewNetworkAdapterError constructs a *NetworkAdapterError. Pass a nil cause
// when no underlying error exists. The ctx map may be nil.
func NewNetworkAdapterError(kind NetworkAdapterErrorKind, message string, cause error, ctx map[string]string) *NetworkAdapterError {
	return &NetworkAdapterError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsNetworkAdapterError reports whether err is a *NetworkAdapterError of the
// given kind.
func IsNetworkAdapterError(err error, kind NetworkAdapterErrorKind) bool {
	var ne *NetworkAdapterError
	if errors.As(err, &ne) {
		return ne.Kind == kind
	}
	return false
}

// Sentinel errors — use with errors.Is.
var (
	ErrNetworkAdapterAccessDenied     = &NetworkAdapterError{Kind: NetworkAdapterErrorAccessDenied}
	ErrNetworkAdapterCIMUnavailable   = &NetworkAdapterError{Kind: NetworkAdapterErrorCIMUnavailable}
	ErrNetworkAdapterTimeout          = &NetworkAdapterError{Kind: NetworkAdapterErrorTimeout}
	ErrNetworkAdapterInvalidParameter = &NetworkAdapterError{Kind: NetworkAdapterErrorInvalidParameter}
	ErrNetworkAdapterUnknown          = &NetworkAdapterError{Kind: NetworkAdapterErrorUnknown}
)

// ---------------------------------------------------------------------------
// NetworkAdapterFilter — List filters
// ---------------------------------------------------------------------------

// NetworkAdapterFilter narrows the List inventory. Every field is optional;
// the zero value lists every visible adapter.
//
// Names matches adapter names exactly and case-insensitively (PowerShell
// -Name is wildcard-capable, so the client re-filters exactly Go-side).
// NameRegex is a RE2 regular expression matched against the adapter name.
// MACAddress is any common spelling (colons, dashes, dots, upper/lower
// case); it is normalised to lower aa:bb:cc:dd:ee:ff before comparison.
// Status is one of Up, Disconnected, Disabled or NotPresent
// (case-insensitive). PhysicalOnly and IncludeHidden are passed to
// Get-NetAdapter; every other filter is applied Go-side.
type NetworkAdapterFilter struct {
	// Names restricts the result to these adapter names (exact,
	// case-insensitive).
	Names []string

	// NameRegex restricts the result to names matching this RE2 pattern.
	NameRegex string

	// MACAddress restricts the result to the adapter with this MAC
	// address, in any common spelling.
	MACAddress string

	// Status restricts the result to one adapter status: Up,
	// Disconnected, Disabled or NotPresent (case-insensitive).
	Status string

	// PhysicalOnly passes -Physical to Get-NetAdapter.
	PhysicalOnly bool

	// IncludeHidden passes -IncludeHidden to Get-NetAdapter.
	IncludeHidden bool
}

// ---------------------------------------------------------------------------
// NetworkAdapter — observed state
// ---------------------------------------------------------------------------

// NetworkAdapter holds the observed state of one network adapter as
// returned by the List pipeline.
//
// MTUIPv4 and MTUIPv6 carry the per-family NlMtu from Get-NetIPInterface;
// 0 means the family is unbound on the interface (never a real MTU: the
// minimum valid MTU is 576), and the provider maps 0 to null.
type NetworkAdapter struct {
	// Name is the adapter's friendly name (host spelling).
	Name string

	// InterfaceIndex is the adapter's numeric index.
	InterfaceIndex int64

	// InterfaceDescription is the driver description string.
	InterfaceDescription string

	// MACAddress is the adapter MAC in lower aa:bb:cc:dd:ee:ff form, or
	// "" when the host reports none.
	MACAddress string

	// Status is the derived adapter status: Up, Disconnected, Disabled
	// or NotPresent (see deriveNetworkAdapterStatus).
	Status string

	// AdminEnabled mirrors AdminStatus (true unless Down).
	AdminEnabled bool

	// LinkSpeedBps is the receive link speed in bits per second (0 when
	// unknown or disconnected).
	LinkSpeedBps int64

	// MediaType is the NdisMedium value mapped to its documented name
	// (e.g. "802.3", "Native802.11"); "" when unknown.
	MediaType string

	// PhysicalMediaType is the NdisPhysicalMedium value mapped to its
	// documented name (e.g. "802.3", "WirelessLan"); "" when unknown.
	PhysicalMediaType string

	// IsPhysical is true for physical adapters (the negation of the
	// host-reported Virtual flag).
	IsPhysical bool

	// IsVirtual is the host-reported Virtual flag.
	IsVirtual bool

	// VlanID is the adapter VLAN ID (0 when untagged or unreported).
	VlanID int64

	// DriverDescription is the driver description ("" when unreported).
	DriverDescription string

	// DriverVersion is the driver version ("" when unreported).
	DriverVersion string

	// DriverProvider is the driver provider ("" when unreported).
	DriverProvider string

	// MTUIPv4 is the IPv4 NlMtu; 0 means the family is unbound (null).
	MTUIPv4 int64

	// MTUIPv6 is the IPv6 NlMtu; 0 means the family is unbound (null).
	MTUIPv6 int64

	// DHCPEnabled is true when DHCP is enabled on the IPv4 interface.
	DHCPEnabled bool

	// IPv4Addresses holds the bound IPv4 addresses in canonical CIDR
	// form (host bits preserved), sorted.
	IPv4Addresses []string

	// IPv6Addresses holds the bound IPv6 addresses in canonical CIDR
	// form (host bits preserved, link-local kept), sorted.
	IPv6Addresses []string

	// DefaultGateways holds the default-route next hops covering this
	// interface, canonicalised and sorted.
	DefaultGateways []string

	// DNSServers holds the effective DNS servers for this interface,
	// canonicalised and sorted.
	DNSServers []string

	// NetworkCategory is the connection-profile category (Public,
	// Private, DomainAuthenticated, ...); "" when the interface has no
	// profile.
	NetworkCategory string

	// IsManagement is true when this adapter owns the address carrying
	// the current SSH session. A failed management-path probe clears the
	// flag on every adapter instead of failing the listing.
	IsManagement bool
}

// ---------------------------------------------------------------------------
// WindowsNetworkAdaptersClient — List interface
// ---------------------------------------------------------------------------

// WindowsNetworkAdaptersClient defines the contract for the standalone
// windows_network_adapters collection data source: a read-only inventory
// with Go-side filters. An empty result is valid (empty slice, nil error);
// only validation, transport and host failures return an error.
type WindowsNetworkAdaptersClient interface {
	// List returns every adapter matching filter, sorted by interface
	// index. Invalid filters return a typed invalid_parameter error
	// without any host call.
	List(ctx context.Context, filter NetworkAdapterFilter) ([]NetworkAdapter, error)
}
