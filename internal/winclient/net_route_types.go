// Package winclient defines the NetRouteClient interface and associated
// types for managing persistent IP routes on a remote Windows host over SSH.
//
// Spec alignment: windows_net_route spec v1 (issue #231).
//
// Scope: one persistent route per resource (New-NetRoute / Set-NetRoute /
// Remove-NetRoute without -PolicyStore, so the default both-stores behaviour
// keeps the route reboot-surviving). Static routes to remote
// networks, on-link routes (next hop 0.0.0.0 / ::) and manually managed
// default gateways. Out of scope: policy-based routing, route print
// persistent-route compatibility, IPv6 router-advertisement routes, route
// publishing/lifetimes (Publish, ValidLifetime), BGP/OSPF, and the default
// gateway attribute of windows_net_ip_address.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// NetRouteErrorKind — typed error categories
// ---------------------------------------------------------------------------

// NetRouteErrorKind categorises errors returned by NetRouteClient
// operations. Use errors.Is(err, ErrNetRoute*) or IsNetRouteError for
// programmatic error handling.
type NetRouteErrorKind string

const (
	// NetRouteErrorInterfaceNotFound is returned when no interface matches
	// the requested alias (exact, case-insensitive comparison — never
	// wildcard semantics). The message lists the valid aliases.
	NetRouteErrorInterfaceNotFound NetRouteErrorKind = "interface_not_found"

	// NetRouteErrorNotFound is returned when the requested route triplet is
	// not present (read of a missing route, update/delete pre-flight,
	// unimportable lookup).
	NetRouteErrorNotFound NetRouteErrorKind = "not_found"

	// NetRouteErrorAlreadyExists is returned when the exact triplet is
	// already present with protocol NetMgmt (suggest terraform import).
	NetRouteErrorAlreadyExists NetRouteErrorKind = "already_exists"

	// NetRouteErrorOwnedByOtherProtocol is returned when the exact triplet
	// is present with a non-NetMgmt protocol (Dhcp, Local, ...): Windows
	// would otherwise create a competing duplicate.
	NetRouteErrorOwnedByOtherProtocol NetRouteErrorKind = "route_owned_by_other_protocol"

	// NetRouteErrorInvalidRoute is returned when the prefix/next-hop
	// combination is rejected by client-side validation (unmasked prefix,
	// family disagreement, multicast/loopback next hop) or by the host.
	NetRouteErrorInvalidRoute NetRouteErrorKind = "invalid_route"

	// NetRouteErrorNextHopUnreachable is returned when the gateway is not
	// on-link on the given interface.
	NetRouteErrorNextHopUnreachable NetRouteErrorKind = "next_hop_unreachable"

	// NetRouteErrorPermission is returned when the SSH user lacks the
	// privilege to manage routes (typically a non-administrator
	// connection).
	NetRouteErrorPermission NetRouteErrorKind = "permission_denied"

	// NetRouteErrorMgmtAtRisk is returned, fail-closed, when the operation
	// would remove or alter the management route or hijack the SSH
	// session's return path. Nothing is applied.
	NetRouteErrorMgmtAtRisk NetRouteErrorKind = "management_path_at_risk"

	// NetRouteErrorMgmtUnknown is returned, fail-closed, when the
	// management path cannot be determined. Nothing is applied.
	NetRouteErrorMgmtUnknown NetRouteErrorKind = "management_path_unknown"

	// NetRouteErrorUnreachable is returned when SSH cannot be contacted
	// (connection refused, auth failure, timeout). Context SHOULD include
	// host, port and transport.
	NetRouteErrorUnreachable NetRouteErrorKind = "unreachable"

	// NetRouteErrorUnknown is the catch-all for unmapped PowerShell or SSH
	// failures.
	NetRouteErrorUnknown NetRouteErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// NetRouteError — structured error
// ---------------------------------------------------------------------------

// NetRouteError is the structured error type returned by all
// NetRouteClient methods. Use errors.Is(err, ErrNetRoute*) for kind
// matching, or errors.As(err, &ne) to inspect Context.
type NetRouteError struct {
	// Kind is the machine-readable error category.
	Kind NetRouteErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics. It must not contain SSH credentials. Guard refusals name
	// the route, say why (the SSH session's client IP and current best
	// route), and point at the unsafe_skip_management_check escape hatch.
	Message string

	// Context holds structured diagnostic key-value pairs (e.g. "host",
	// "port", "transport", "interface_alias", "destination_prefix",
	// "next_hop"). All values must be safe to log.
	Context map[string]string

	// Cause is the underlying error, if any (typically an SSH transport or
	// PowerShell parsing error).
	Cause error
}

// Error implements the error interface.
func (e *NetRouteError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_net_route [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_net_route [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *NetRouteError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *NetRouteError) Is(target error) bool {
	t, ok := target.(*NetRouteError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewNetRouteError constructs a *NetRouteError. Pass a nil cause when no
// underlying error exists. The ctx map may be nil.
func NewNetRouteError(kind NetRouteErrorKind, message string, cause error, ctx map[string]string) *NetRouteError {
	return &NetRouteError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsNetRouteError reports whether err is a *NetRouteError of the given kind.
func IsNetRouteError(err error, kind NetRouteErrorKind) bool {
	var ne *NetRouteError
	if errors.As(err, &ne) {
		return ne.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

var (
	ErrNetRouteInterfaceNotFound    = &NetRouteError{Kind: NetRouteErrorInterfaceNotFound}
	ErrNetRouteNotFound             = &NetRouteError{Kind: NetRouteErrorNotFound}
	ErrNetRouteAlreadyExists        = &NetRouteError{Kind: NetRouteErrorAlreadyExists}
	ErrNetRouteOwnedByOtherProtocol = &NetRouteError{Kind: NetRouteErrorOwnedByOtherProtocol}
	ErrNetRouteInvalidRoute         = &NetRouteError{Kind: NetRouteErrorInvalidRoute}
	ErrNetRouteNextHopUnreachable   = &NetRouteError{Kind: NetRouteErrorNextHopUnreachable}
	ErrNetRoutePermission           = &NetRouteError{Kind: NetRouteErrorPermission}
	ErrNetRouteMgmtAtRisk           = &NetRouteError{Kind: NetRouteErrorMgmtAtRisk}
	ErrNetRouteMgmtUnknown          = &NetRouteError{Kind: NetRouteErrorMgmtUnknown}
	ErrNetRouteUnreachable          = &NetRouteError{Kind: NetRouteErrorUnreachable}
	ErrNetRouteUnknown              = &NetRouteError{Kind: NetRouteErrorUnknown}
)

// ---------------------------------------------------------------------------
// NetRouteInput — parameters for Create
// ---------------------------------------------------------------------------

// NetRouteInput carries the desired route configuration. Consumed by Create.
//
// The destination prefix must already be canonical masked form (netip
// Masked); Create re-validates defensively. The next hop must already be
// canonical netip spelling; 0.0.0.0 / :: means on-link.
type NetRouteInput struct {
	// InterfaceAlias is the target adapter's friendly name. Matched with an
	// exact, case-insensitive comparison (never wildcard semantics).
	InterfaceAlias string

	// DestinationPrefix is the route destination in canonical masked CIDR
	// form (e.g. "198.51.100.0/24", "0.0.0.0/0").
	DestinationPrefix string

	// NextHop is the gateway in canonical netip spelling, or the
	// unspecified address ("0.0.0.0" / "::") for an on-link route.
	NextHop string

	// RouteMetric is the route metric (0-9999, Windows default 256).
	RouteMetric int

	// UnsafeSkipManagementCheck bypasses the management-path guard. The host
	// must stay reachable at the provider host address afterwards.
	UnsafeSkipManagementCheck bool
}

// ---------------------------------------------------------------------------
// NetRouteInfo — observed state
// ---------------------------------------------------------------------------

// NetRouteInfo holds the observed state of one persistent route as returned
// by the Read pipeline.
type NetRouteInfo struct {
	// InterfaceAlias is the adapter's friendly name (host spelling).
	InterfaceAlias string

	// InterfaceIndex is the adapter's numeric index.
	InterfaceIndex int

	// DestinationPrefix is the route destination in canonical masked CIDR
	// form.
	DestinationPrefix string

	// NextHop is the gateway in canonical netip spelling ("0.0.0.0" / "::"
	// for on-link routes).
	NextHop string

	// RouteMetric is the route metric, as observed on the host.
	RouteMetric int

	// InterfaceMetric is the interface metric from Get-NetIPInterface.
	InterfaceMetric int

	// EffectiveMetric is RouteMetric + InterfaceMetric, the value Windows
	// uses for route selection.
	EffectiveMetric int

	// AddressFamily is "IPv4" or "IPv6".
	AddressFamily string

	// Protocol is the route protocol ("NetMgmt" for managed routes).
	Protocol string
}

// ---------------------------------------------------------------------------
// NetRouteClient — CRUD interface
// ---------------------------------------------------------------------------

// NetRouteClient defines the contract for managing persistent IP routes on
// a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation. All methods return *NetRouteError (wrapped in error).
//
// Guard invariants: every mutating operation performs one ManagementPath
// probe (computed per operation, never cached) plus an exact-match and a
// hijack check, unless UnsafeSkipManagementCheck is set. Touching the
// management route returns ErrNetRouteMgmtAtRisk; an undeterminable path
// returns ErrNetRouteMgmtUnknown. Nothing is applied in either case.
type NetRouteClient interface {
	// Create provisions the persistent route: resolves the interface,
	// validates prefix/next-hop family agreement, pre-flights the exact
	// triplet (NetMgmt present -> already_exists, other protocol ->
	// route_owned_by_other_protocol), consults the guard, then runs
	// New-NetRoute and reads the result back.
	Create(ctx context.Context, input NetRouteInput) (*NetRouteInfo, error)

	// Read returns the observed route for the exact triplet on the given
	// interface, or (nil, nil) when the route — or its interface — is gone
	// (the resource handler then drops the resource from state).
	Read(ctx context.Context, interfaceAlias, destinationPrefix, nextHop string) (*NetRouteInfo, error)

	// Lookup lists every persistent route for destinationPrefix,
	// optionally restricted to one interface alias and/or next hop (exact,
	// case-insensitive matches). Zero matches return ErrNetRouteNotFound.
	// Backs the data source, which picks the lowest effective metric win.
	Lookup(ctx context.Context, destinationPrefix, interfaceAlias, nextHop string) ([]*NetRouteInfo, error)

	// Update changes the route metric in place via Set-NetRoute after the
	// guard passes.
	Update(ctx context.Context, interfaceAlias, destinationPrefix, nextHop string, routeMetric int, unsafeSkip bool) (*NetRouteInfo, error)

	// Delete removes the route via Remove-NetRoute after the guard passes.
	// A missing route or interface is a successful no-op (nil).
	Delete(ctx context.Context, interfaceAlias, destinationPrefix, nextHop string, unsafeSkip bool) error
}
