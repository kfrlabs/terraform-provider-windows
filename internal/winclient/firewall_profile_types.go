// Package winclient defines the WindowsFirewallProfileClient interface and
// associated types for managing Windows Defender Firewall profiles via SSH.
//
// Spec alignment: windows_firewall_profile spec v1 (issue #223).
//
// Scope note: a profile (Domain, Private, Public) always exists — Windows
// creates it with the OS. Create and Update are therefore the same operation
// (Set-NetFirewallProfile); Delete never removes anything by default and only
// re-applies the pre-existing values captured at Create time when the
// operator opts in with restore_on_destroy. GPO-managed NotConfigured
// tri-states are observed but never written by the guard or restore paths
// beyond round-tripping what was captured.
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// FirewallProfileErrorKind
// ---------------------------------------------------------------------------

// FirewallProfileErrorKind categorises errors returned by
// WindowsFirewallProfileClient operations.
type FirewallProfileErrorKind string

const (
	// FirewallProfileErrorInvalidProfile is returned when the profile name is
	// not one of Domain, Private or Public, or when Get-NetFirewallProfile
	// reports the profile does not exist.
	FirewallProfileErrorInvalidProfile = "invalid_profile"

	// FirewallProfileErrorAccessDenied is returned when the SSH user lacks
	// the privilege to read or write firewall configuration (typically a
	// non-administrator connection).
	FirewallProfileErrorAccessDenied = "access_denied"

	// FirewallProfileErrorWouldLockOut is returned, fail-closed, when applying
	// the requested settings to the profile that carries the current SSH
	// session would block inbound traffic without an enabled inbound Allow
	// rule for the provider port — or when the guard cannot determine the SSH
	// profile while the change is risky. Nothing is applied.
	FirewallProfileErrorWouldLockOut = "would_lock_out"

	// FirewallProfileErrorServiceUnavailable is returned when the Windows
	// Firewall service (MpsSvc) is stopped on the target host.
	FirewallProfileErrorServiceUnavailable = "firewall_service_unavailable"

	// FirewallProfileErrorUnknown is returned for unexpected PowerShell
	// errors or SSH transport failures.
	FirewallProfileErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// FirewallProfileError
// ---------------------------------------------------------------------------

// FirewallProfileError is the structured error type returned by all
// WindowsFirewallProfileClient methods.
type FirewallProfileError = ResourceError

// NewFirewallProfileError constructs a *FirewallProfileError.
func NewFirewallProfileError(kind FirewallProfileErrorKind, message string, cause error, ctx map[string]string) *FirewallProfileError {
	return NewResourceError("windows_firewall_profile", string(kind), message, cause, ctx)
}

// IsFirewallProfileError reports whether err is a *FirewallProfileError with the given kind.
func IsFirewallProfileError(err error, kind FirewallProfileErrorKind) bool {
	return IsResourceError(err, "windows_firewall_profile", string(kind))
}

// Sentinel errors for use with errors.Is.
var (
	ErrFirewallProfileInvalidProfile     = &FirewallProfileError{Resource: "windows_firewall_profile", Kind: FirewallProfileErrorInvalidProfile}
	ErrFirewallProfileAccessDenied       = &FirewallProfileError{Resource: "windows_firewall_profile", Kind: FirewallProfileErrorAccessDenied}
	ErrFirewallProfileWouldLockOut       = &FirewallProfileError{Resource: "windows_firewall_profile", Kind: FirewallProfileErrorWouldLockOut}
	ErrFirewallProfileServiceUnavailable = &FirewallProfileError{Resource: "windows_firewall_profile", Kind: FirewallProfileErrorServiceUnavailable}
	ErrFirewallProfileUnknown            = &FirewallProfileError{Resource: "windows_firewall_profile", Kind: FirewallProfileErrorUnknown}
)

// ---------------------------------------------------------------------------
// FirewallProfileSettings
// ---------------------------------------------------------------------------

// FirewallProfileSettings carries the desired configuration delta for a
// Windows Defender Firewall profile. Consumed by Apply (Create and Update
// share the operation because profiles always exist).
//
// Partial management: every field beyond Name is optional. A nil pointer (or
// a nil DisabledInterfaceAliases slice) means "unmanaged" — the attribute is
// omitted from Set-NetFirewallProfile and the host value is left untouched.
// A non-nil DisabledInterfaceAliases (even empty) is authoritative: an empty
// list clears the exclusion list.
type FirewallProfileSettings struct {
	Enabled                         *bool
	DefaultInboundAction            *string
	DefaultOutboundAction           *string
	AllowInboundRules               *bool
	AllowLocalFirewallRules         *bool
	AllowLocalIPsecRules            *bool
	AllowUnicastResponseToMulticast *bool
	NotifyOnListen                  *bool
	LogFileName                     *string
	LogMaxSizeKilobytes             *int64
	LogAllowed                      *bool
	LogBlocked                      *bool
	LogIgnored                      *bool
	DisabledInterfaceAliases        []string
	DisabledInterfaceAliasesSet     bool
}

// FirewallProfileConfigured reports whether at least one attribute is
// managed (used to skip a no-op Set round trip).
func (s FirewallProfileSettings) FirewallProfileConfigured() bool {
	return s.Enabled != nil ||
		s.DefaultInboundAction != nil ||
		s.DefaultOutboundAction != nil ||
		s.AllowInboundRules != nil ||
		s.AllowLocalFirewallRules != nil ||
		s.AllowLocalIPsecRules != nil ||
		s.AllowUnicastResponseToMulticast != nil ||
		s.NotifyOnListen != nil ||
		s.LogFileName != nil ||
		s.LogMaxSizeKilobytes != nil ||
		s.LogAllowed != nil ||
		s.LogBlocked != nil ||
		s.LogIgnored != nil ||
		s.DisabledInterfaceAliasesSet
}

// ---------------------------------------------------------------------------
// FirewallProfileState
// ---------------------------------------------------------------------------

// FirewallProfileState holds the observed state of a Windows Defender
// Firewall profile as returned by the Read pipeline.
//
// Tri-state fields (AllowInboundRules, AllowLocalFirewallRules,
// AllowLocalIPsecRules, AllowUnicastResponseToMulticast, LogAllowed,
// LogBlocked, LogIgnored) carry the raw host spelling: "True", "False" or
// "NotConfigured" (GPO-managed). The provider layer maps "NotConfigured" to
// null; the restore path round-trips it verbatim so a captured snapshot is
// re-applied exactly.
//
// DisabledInterfaceAliases never contains "NotConfigured": the host reports
// {NotConfigured} when no interface is excluded, which normalises to an
// empty list.
type FirewallProfileState struct {
	Name                            string
	Enabled                         bool
	DefaultInboundAction            string
	DefaultOutboundAction           string
	AllowInboundRules               string
	AllowLocalFirewallRules         string
	AllowLocalIPsecRules            string
	AllowUnicastResponseToMulticast string
	NotifyOnListen                  bool
	LogFileName                     string
	LogMaxSizeKilobytes             int64
	LogAllowed                      string
	LogBlocked                      string
	LogIgnored                      string
	DisabledInterfaceAliases        []string
}

// ---------------------------------------------------------------------------
// WindowsFirewallProfileClient
// ---------------------------------------------------------------------------

// WindowsFirewallProfileClient defines the contract for managing Windows
// Defender Firewall profiles via SSH (NetSecurity PowerShell module).
//
// Error conventions:
//   - Read returns (nil, nil) only when the profile name is unknown to the
//     host (invalid_profile surfaces instead for a bad name at the provider
//     layer, which validates OneOf Domain/Private/Public at plan time).
//   - Apply runs the SSH lockout guard fail-closed before writing: a risky
//     change without inbound Allow coverage for the provider port returns
//     FirewallProfileErrorWouldLockOut and applies nothing.
//   - Restore re-applies a snapshot captured by an earlier Read (used by
//     Delete with restore_on_destroy).
type WindowsFirewallProfileClient interface {
	// Read retrieves the current state of the named firewall profile.
	Read(ctx context.Context, name string) (*FirewallProfileState, error)

	// Apply writes only the configured settings to the named profile
	// (Set-NetFirewallProfile -PolicyStore PersistentStore) after the
	// lockout guard passes, then reads back the full state.
	Apply(ctx context.Context, name string, settings FirewallProfileSettings) (*FirewallProfileState, error)

	// Restore re-applies a previously captured snapshot verbatim.
	Restore(ctx context.Context, snapshot FirewallProfileState) (*FirewallProfileState, error)

	// SSHProfile resolves which firewall profile carries the provider's own
	// SSH session ($env:SSH_CONNECTION mapped through Get-NetIPAddress to
	// Get-NetConnectionProfile, DomainAuthenticated normalised to Domain).
	// It backs the acceptance suite; a failure to determine the profile is
	// a typed unknown error so the caller fails closed instead of guarding
	// the wrong profile.
	SSHProfile(ctx context.Context) (string, error)
}
