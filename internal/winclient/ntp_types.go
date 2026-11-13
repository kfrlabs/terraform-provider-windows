// Package winclient defines the WindowsNTPClient interface and associated
// types for managing the Windows Time service (W32Time) time source — the
// NTP/NTDS sync type, NTP peers, poll interval, reliable-source flag and
// the optional NTP server role — over SSH.
//
// Spec alignment: windows_ntp spec (issue #287).
//
// Scope note: the time source is a singleton — the host always has exactly
// one. Set is therefore idempotent (write the registry values, run
// w32tm /config /update, optionally resync, then verify by re-reading);
// Delete never removes anything by default and only re-applies the
// pre-existing values captured at Create time when the operator opts in
// with restore_on_destroy.
package winclient

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// NTPErrorKind
// ---------------------------------------------------------------------------

// NTPErrorKind categorises errors returned by WindowsNTPClient operations.
type NTPErrorKind string

const (
	// NTPErrorServiceUnavailable is returned when the W32Time service is
	// not registered (or not startable) on the target host — the usual
	// outcome on containers, which typically share the host clock and ship
	// no W32Time service.
	NTPErrorServiceUnavailable NTPErrorKind = "service_unavailable"

	// NTPErrorAccessDenied is returned when the SSH user lacks the
	// privilege to read or write the W32Time registry keys or to
	// reconfigure the W32Time service.
	NTPErrorAccessDenied NTPErrorKind = "access_denied"

	// NTPErrorInvalidPeer is returned when a configured NTP peer is
	// rejected: an empty address, an address containing whitespace or a
	// comma, or flags outside the 0x1-0xF range. The primary gate is the
	// plan validator; this kind is the defence-in-depth host-side and
	// client-side check.
	NTPErrorInvalidPeer NTPErrorKind = "invalid_peer"

	// NTPErrorUnknown is returned for unexpected PowerShell errors or SSH
	// transport failures.
	NTPErrorUnknown NTPErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// NTPError
// ---------------------------------------------------------------------------

// NTPError is the structured error type returned by all WindowsNTPClient
// methods.
type NTPError struct {
	Kind    NTPErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *NTPError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_ntp [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_ntp [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *NTPError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *NTPError) Is(target error) bool {
	t, ok := target.(*NTPError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewNTPError constructs a *NTPError.
func NewNTPError(kind NTPErrorKind, message string, cause error, ctx map[string]string) *NTPError {
	return &NTPError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsNTPError reports whether err is a *NTPError with the given kind.
func IsNTPError(err error, kind NTPErrorKind) bool {
	var ne *NTPError
	if errors.As(err, &ne) {
		return ne.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrNTPServiceUnavailable = &NTPError{Kind: NTPErrorServiceUnavailable}
	ErrNTPAccessDenied       = &NTPError{Kind: NTPErrorAccessDenied}
	ErrNTPInvalidPeer        = &NTPError{Kind: NTPErrorInvalidPeer}
	ErrNTPUnknown            = &NTPError{Kind: NTPErrorUnknown}
)

// ---------------------------------------------------------------------------
// Sync type
// ---------------------------------------------------------------------------

// Valid W32Time sync types (HKLM W32Time\Parameters\Type).
const (
	// NTPTypeNTP syncs from the configured NTP peers only.
	NTPTypeNTP = "NTP"
	// NTPTypeNT5DS syncs from the domain hierarchy (domain-joined hosts).
	NTPTypeNT5DS = "NT5DS"
	// NTPTypeAllSync syncs from both the domain hierarchy and NTP peers.
	NTPTypeAllSync = "AllSync"
	// NTPTypeNoSync disables time synchronisation.
	NTPTypeNoSync = "NoSync"
)

// ValidateNTPType rejects sync types outside NTP/NT5DS/AllSync/NoSync.
func ValidateNTPType(t string) error {
	switch t {
	case NTPTypeNTP, NTPTypeNT5DS, NTPTypeAllSync, NTPTypeNoSync:
		return nil
	default:
		return NewNTPError(
			NTPErrorUnknown,
			fmt.Sprintf("unknown NTP type %q: must be one of NTP, NT5DS, AllSync, NoSync", t),
			nil,
			map[string]string{"type": t},
		)
	}
}

// NTPTypeUsesPeers reports whether the sync type consumes the NtpServer
// peer list (NTP and AllSync). NT5DS and NoSync leave the peer list
// unmanaged.
func NTPTypeUsesPeers(t string) bool {
	return t == NTPTypeNTP || t == NTPTypeAllSync
}

// ---------------------------------------------------------------------------
// NTPPeer — pure-Go NtpServer parse/build
// ---------------------------------------------------------------------------

// NTPPeer is one entry of the W32Time NtpServer value: an address plus the
// per-peer flags (default 0x9 = SpecialInterval + Client). The flags use
// the canonical lower-case "0xN" spelling.
type NTPPeer struct {
	Address string
	Flags   string
}

// DefaultNTPPeerFlags is applied when a peer carries no explicit flags.
const DefaultNTPPeerFlags = "0x9"

// ntpFlagsRe accepts the W32Time per-peer flags: a single hex digit 1-F
// with a 0x/0X prefix (normalised to lower-case on the way out).
var ntpFlagsRe = regexp.MustCompile(`^0[xX][1-9a-fA-F]$`)

// ValidateNTPFlags rejects flags outside the 0x1-0xF range.
func ValidateNTPFlags(flags string) error {
	if !ntpFlagsRe.MatchString(flags) {
		return NewNTPError(
			NTPErrorInvalidPeer,
			fmt.Sprintf("invalid NTP peer flags %q: must be a single hex digit 0x1-0xF (e.g. 0x9)", flags),
			nil,
			map[string]string{"flags": flags},
		)
	}
	return nil
}

// NormalizeNTPFlags validates flags and returns the canonical lower-case
// spelling (e.g. "0X9" becomes "0x9").
func NormalizeNTPFlags(flags string) (string, error) {
	if err := ValidateNTPFlags(flags); err != nil {
		return "", err
	}
	return strings.ToLower(flags), nil
}

// ValidateNTPPeerAddress rejects empty addresses and addresses containing
// whitespace or commas (both would corrupt the space/comma-separated
// NtpServer value).
func ValidateNTPPeerAddress(address string) error {
	if address == "" {
		return NewNTPError(
			NTPErrorInvalidPeer,
			"NTP peer address is empty",
			nil,
			map[string]string{"address": address},
		)
	}
	if strings.ContainsAny(address, " \t\r\n\v\f,") {
		return NewNTPError(
			NTPErrorInvalidPeer,
			fmt.Sprintf("invalid NTP peer address %q: must not contain whitespace or commas", address),
			nil,
			map[string]string{"address": address},
		)
	}
	return nil
}

// ValidateNTPPeer rejects peers with an invalid address or flags.
func ValidateNTPPeer(p NTPPeer) error {
	if err := ValidateNTPPeerAddress(p.Address); err != nil {
		return err
	}
	return ValidateNTPFlags(p.Flags)
}

// ParseNtpServerString parses a W32Time NtpServer registry value
// ("addr,flags addr,flags ...", space-separated) into peers. A token
// without a comma takes the default flags (0x9); flags are normalised to
// lower-case. An empty string yields no peers.
func ParseNtpServerString(s string) ([]NTPPeer, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, nil
	}
	peers := make([]NTPPeer, 0, len(fields))
	for _, tok := range fields {
		addr, flags := tok, DefaultNTPPeerFlags
		if i := strings.Index(tok, ","); i >= 0 {
			addr, flags = tok[:i], tok[i+1:]
		}
		norm, err := NormalizeNTPFlags(flags)
		if err != nil {
			return nil, err
		}
		if err := ValidateNTPPeerAddress(addr); err != nil {
			return nil, err
		}
		peers = append(peers, NTPPeer{Address: addr, Flags: norm})
	}
	return peers, nil
}

// BuildNtpServerString renders peers as a W32Time NtpServer registry
// value ("addr,flags" pairs joined with single spaces, flags normalised to
// lower-case). It is the inverse of ParseNtpServerString and fails closed
// on invalid peers before anything reaches the host.
func BuildNtpServerString(peers []NTPPeer) (string, error) {
	if len(peers) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(peers))
	for _, p := range peers {
		if err := ValidateNTPPeerAddress(p.Address); err != nil {
			return "", err
		}
		norm, err := NormalizeNTPFlags(p.Flags)
		if err != nil {
			return "", err
		}
		parts = append(parts, p.Address+","+norm)
	}
	return strings.Join(parts, " "), nil
}

// NTPPeersEqual compares two peer lists element-wise (order matters — the
// host honours peer order). Addresses compare case-insensitively
// (hostnames), flags compare exactly (both sides are expected to carry the
// canonical lower-case spelling).
func NTPPeersEqual(a, b []NTPPeer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i].Address, b[i].Address) || a[i].Flags != b[i].Flags {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// AnnounceFlags mapping
// ---------------------------------------------------------------------------

// W32Time Config\AnnounceFlags values managed by this provider: 5 marks
// the host as a reliable time source, 10 marks it as not reliable.
const (
	// NTPAnnounceFlagsReliable is written when reliable is true.
	NTPAnnounceFlagsReliable = int64(5)
	// NTPAnnounceFlagsNotReliable is written when reliable is false.
	NTPAnnounceFlagsNotReliable = int64(10)
)

// NTPAnnounceFlagsFromReliable maps the Terraform reliable flag to the
// W32Time AnnounceFlags DWORD.
func NTPAnnounceFlagsFromReliable(reliable bool) int64 {
	if reliable {
		return NTPAnnounceFlagsReliable
	}
	return NTPAnnounceFlagsNotReliable
}

// NTPReliableFromAnnounceFlags maps a host AnnounceFlags DWORD back to the
// Terraform reliable flag. Only 5 counts as reliable; every other value
// (10 and any exotic setting a GPO or admin may have written) observes as
// false rather than erroring.
func NTPReliableFromAnnounceFlags(flags int64) bool {
	return flags == NTPAnnounceFlagsReliable
}

// ParseAnnounceFlags parses a decimal AnnounceFlags rendering (used only
// in tests and diagnostics plumbing).
func ParseAnnounceFlags(s string) (int64, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, NewNTPError(
			NTPErrorUnknown,
			fmt.Sprintf("invalid AnnounceFlags value %q", s),
			err,
			map[string]string{"announce_flags": s},
		)
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// NTP poll-interval and phase-correction bounds
// ---------------------------------------------------------------------------

// W32Time NtpClient\SpecialPollInterval bounds in seconds (plan-validated,
// re-checked host-side before writing).
const (
	// NTPMinPollIntervalSeconds is the smallest accepted poll interval.
	NTPMinPollIntervalSeconds = int64(16)
	// NTPMaxPollIntervalSeconds is the largest accepted poll interval.
	NTPMaxPollIntervalSeconds = int64(86400)
)

// ValidateNTPPollInterval rejects poll intervals outside 16-86400 seconds.
func ValidateNTPPollInterval(seconds int64) error {
	if seconds < NTPMinPollIntervalSeconds || seconds > NTPMaxPollIntervalSeconds {
		return NewNTPError(
			NTPErrorUnknown,
			fmt.Sprintf("special_poll_interval_seconds %d is out of range: must be between %d and %d",
				seconds, NTPMinPollIntervalSeconds, NTPMaxPollIntervalSeconds),
			nil,
			map[string]string{"special_poll_interval_seconds": strconv.FormatInt(seconds, 10)},
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// NTPInput — parameters for Set
// ---------------------------------------------------------------------------

// NTPInput carries the desired W32Time time-source configuration.
// Consumed by Set (Create and Update share the operation: the time source
// is a singleton, so there is no separate Create/Update client operation).
//
// Partial management: every field beyond Type is optional. A nil pointer
// (or a nil Servers slice) means "unmanaged" — the registry value is never
// written and the host value is left untouched. The provider layer converts
// null (or unknown, which defers) Terraform values to this delta.
//
// AnnounceFlags, when non-nil, is written verbatim (used by Delete with
// restore_on_destroy to re-apply the exact snapshot DWORD); otherwise the
// Reliable flag is mapped to 5/10. When both are set, AnnounceFlags wins.
type NTPInput struct {
	// Type is the W32Time sync type: NTP, NT5DS, AllSync or NoSync.
	Type string

	// Servers is the desired NTP peer list. Nil (or empty) means the
	// NtpServer value is left untouched — the provider passes nil for
	// NT5DS/NoSync (peers forbidden there) and on restore when the
	// snapshot carries no peers.
	Servers []NTPPeer

	// SpecialPollIntervalSeconds overrides
	// TimeProviders\NtpClient\SpecialPollInterval when non-nil.
	SpecialPollIntervalSeconds *int64

	// Reliable maps to Config\AnnounceFlags (5/10) when non-nil and
	// AnnounceFlags is nil.
	Reliable *bool

	// AnnounceFlags overrides Reliable with a verbatim DWORD when
	// non-nil (restore path).
	AnnounceFlags *int64

	// NtpServerEnabled overrides TimeProviders\NtpServer\Enabled when
	// non-nil.
	NtpServerEnabled *bool

	// MaxPosPhaseCorrectionSeconds overrides
	// Config\MaxPosPhaseCorrection when non-nil.
	MaxPosPhaseCorrectionSeconds *int64

	// MaxNegPhaseCorrectionSeconds overrides
	// Config\MaxNegPhaseCorrection when non-nil.
	MaxNegPhaseCorrectionSeconds *int64

	// ManageService, when true (the default), sets the W32Time service
	// StartupType to Automatic and starts it before writing. When false
	// the service is left untouched (for operators whose windows_service
	// resource owns W32Time).
	ManageService bool

	// ResyncOnApply, when true (the default), runs
	// w32tm /resync /rediscover after w32tm /config /update. A resync
	// failure is recorded on the returned state as a warning, never as
	// an error (the peer may be unreachable at apply time).
	ResyncOnApply bool
}

// NTPConfigured reports whether the input carries at least one managed
// setting beyond the always-written Type.
func (in NTPInput) NTPConfigured() bool {
	return len(in.Servers) > 0 ||
		in.SpecialPollIntervalSeconds != nil ||
		in.Reliable != nil ||
		in.AnnounceFlags != nil ||
		in.NtpServerEnabled != nil ||
		in.MaxPosPhaseCorrectionSeconds != nil ||
		in.MaxNegPhaseCorrectionSeconds != nil
}

// ValidateNTPInput rejects unknown sync types and invalid peers before
// anything reaches the host. It enforces both halves of the type x servers
// matrix (peers required for NTP/AllSync, forbidden for NT5DS/NoSync),
// the defence-in-depth counterpart of the provider ConfigValidator.
func ValidateNTPInput(in NTPInput) error {
	if err := ValidateNTPType(in.Type); err != nil {
		return err
	}
	if NTPTypeUsesPeers(in.Type) && len(in.Servers) == 0 {
		return NewNTPError(
			NTPErrorInvalidPeer,
			fmt.Sprintf("type %q requires at least one NTP server peer", in.Type),
			nil,
			map[string]string{"type": in.Type},
		)
	}
	if !NTPTypeUsesPeers(in.Type) && len(in.Servers) > 0 {
		return NewNTPError(
			NTPErrorInvalidPeer,
			fmt.Sprintf("type %q does not consume NTP peers: remove servers", in.Type),
			nil,
			map[string]string{"type": in.Type},
		)
	}
	for _, p := range in.Servers {
		if err := ValidateNTPPeer(p); err != nil {
			return err
		}
	}
	// DWORD bound shared by the verbatim restore path: every registry DWORD
	// the provider writes (AnnounceFlags, SpecialPollInterval,
	// MaxPos/MaxNegPhaseCorrection) must fit in 0..4294967295. Host-observed
	// values outside this range are rejected before rendering so a corrupt
	// snapshot can never reach Set-ItemProperty.
	const ntpMaxDWORD = int64(4294967295)
	if in.AnnounceFlags != nil && (*in.AnnounceFlags < 0 || *in.AnnounceFlags > ntpMaxDWORD) {
		return NewNTPError(
			NTPErrorUnknown,
			fmt.Sprintf("announce_flags %d is out of range: must be between 0 and %d",
				*in.AnnounceFlags, ntpMaxDWORD),
			nil,
			map[string]string{"announce_flags": strconv.FormatInt(*in.AnnounceFlags, 10)},
		)
	}
	if in.SpecialPollIntervalSeconds != nil {
		if err := ValidateNTPPollInterval(*in.SpecialPollIntervalSeconds); err != nil {
			return err
		}
	}
	for _, v := range []*int64{in.MaxPosPhaseCorrectionSeconds, in.MaxNegPhaseCorrectionSeconds} {
		if v != nil && (*v < 0 || *v > ntpMaxDWORD) {
			return NewNTPError(
				NTPErrorUnknown,
				fmt.Sprintf("phase correction %d is out of range: must be between 0 and %d", *v, ntpMaxDWORD),
				nil,
				map[string]string{"phase_correction": strconv.FormatInt(*v, 10)},
			)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// NTPState — observed state returned by Read/Set
// ---------------------------------------------------------------------------

// NTPState is the observed W32Time time-source state of the remote
// Windows host.
//
// MachineID is the value of HKLM:\SOFTWARE\Microsoft\Cryptography\
// MachineGuid — stable per machine, anchors the Terraform resource ID.
// ResyncWarning carries a non-fatal w32tm /resync failure from Set (empty
// otherwise); it is transient and never persisted to Terraform state.
// VmICEnabled reports the Hyper-V time-sync provider state for the
// provider-layer warning only and is not exposed as a Terraform attribute.
type NTPState struct {
	MachineID string
	Type      string
	Servers   []NTPPeer

	SpecialPollIntervalSeconds   int64
	Reliable                     bool
	AnnounceFlags                int64
	NtpServerEnabled             bool
	MaxPosPhaseCorrectionSeconds int64
	MaxNegPhaseCorrectionSeconds int64
	CurrentSource                string
	PolicyOverride               bool
	DomainJoined                 bool
	VmICEnabled                  bool
	ResyncWarning                string
}

// ---------------------------------------------------------------------------
// WindowsNTPClient — Read/Set contract
// ---------------------------------------------------------------------------

// WindowsNTPClient defines the contract for managing the W32Time
// time source of a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation. All methods return *NTPError (wrapped in error).
//
//	Notable invariants:
//	  - Singleton: the host has exactly one time source. Create and Update
//	    on the resource layer both funnel into Set (registry writes plus
//	    w32tm /config /update, then verify by re-reading).
//	  - Set optionally runs w32tm /resync /rediscover; a resync failure is
//	    recorded on the returned state (ResyncWarning) and must surface as
//	    a warning, never as an error.
//	  - Read never fails on a machine change: the resource handler anchors
//	    its ID on MachineID and always refreshes from the live state.
//	  - No w32tm query output is ever parsed for state (its text is
//	    localised): registry values are the source of truth, and
//	    w32tm /query /source is read as an opaque peer name gated on the
//	    exit code.
type WindowsNTPClient interface {
	// Read returns the currently configured W32Time time-source state.
	//
	// Returns ErrNTPServiceUnavailable when W32Time is not registered on
	// the host (containers). Returns ErrNTPAccessDenied when the HKLM
	// reads are refused.
	Read(ctx context.Context) (*NTPState, error)

	// Set writes the configured registry values (leaving unmanaged ones
	// untouched), runs w32tm /config /update, optionally resyncs, then
	// verifies by re-reading and returns the freshly observed state.
	//
	// Returns ErrNTPServiceUnavailable when W32Time is not registered.
	// Returns ErrNTPInvalidPeer when a peer or the type is rejected.
	// Returns ErrNTPAccessDenied when the caller lacks the required
	// privilege. A resync failure never errors: it is recorded on the
	// returned state's ResyncWarning field.
	Set(ctx context.Context, input NTPInput) (*NTPState, error)
}
