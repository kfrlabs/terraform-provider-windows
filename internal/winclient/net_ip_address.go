// Package winclient - NetIPAddressClient is the concrete
// NetIPAddressClient backed by PowerShell over SSH.
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted
//     PowerShell literal with embedded single-quotes doubled); no raw
//     concatenation of user input into PS scripts.
//   - No credentials are involved in address management; none are written to
//     NetIPAddressError.Message or Context.
//
// Reused helpers from the same package:
//   - psQuote                  - safe PS string literals (psquote.go)
//   - runEnvelope              - shared JSON envelope pipeline (envelope.go)
//   - ManagementPath           - shared SSH management-path guard (mgmtpath.go)
//   - sshProviderPort          - sshd port default (sshpath.go)
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Compile-time assertion: NetIPAddressClientImpl satisfies NetIPAddressClient.
var _ NetIPAddressClient = (*NetIPAddressClientImpl)(nil)

// NetIPAddressClientImpl is the PowerShell/SSH-backed NetIPAddressClient.
type NetIPAddressClientImpl struct {
	c *Client
}

// NewNetIPAddressClient wraps the given SSH Client.
func NewNetIPAddressClient(c *Client) *NetIPAddressClientImpl {
	return &NetIPAddressClientImpl{c: c}
}

// runNetIPAddressPowerShell is the package-level indirection used by
// NetIPAddressClientImpl. Tests may override it; production code must not.
var runNetIPAddressPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// netIPAddressManagementPath is the package-level indirection for the shared
// management-path probe. Tests may override it; production code must not.
var netIPAddressManagementPath = func(ctx context.Context, c *Client) (*ManagementPath, error) {
	return c.ManagementPath(ctx)
}

// Poll budget after New-NetIPAddress: duplicate address detection (DAD) is
// asynchronous, so AddressState may still be Tentative right after creation.
// Duplicate rolls the address back; Tentative at the deadline is returned
// as-is so the provider can warn instead of failing.
const (
	netIPAddressPollTimeout  = 10 * time.Second
	netIPAddressPollInterval = time.Second
)

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// netIPAddressJSON mirrors the JSON object emitted by
// ConvertTo-NetAddressJson. AddressFamily is derived Go-side from the IP,
// never trusted from enum decoding.
type netIPAddressJSON struct {
	InterfaceAlias string `json:"interface_alias"`
	InterfaceIndex int    `json:"interface_index"`
	IPAddress      string `json:"ip_address"`
	PrefixLength   int    `json:"prefix_length"`
	AddressState   string `json:"address_state"`
	PrefixOrigin   string `json:"prefix_origin"`
	SkipAsSource   bool   `json:"skip_as_source"`
}

// netIPAddressDHCPJSON mirrors the Emit-OK payload of the DHCP scripts.
type netIPAddressDHCPJSON struct {
	DHCPDisabled bool `json:"dhcp_disabled"`
}

// runNetIPAddressEnvelope executes script (prefixed with
// psNetIPAddressHeader by the builders) and parses the JSON envelope through
// the shared runEnvelope helper. Transport/timeout failures map to
// unreachable; remote Emit-Err kinds map via mapNetIPAddressKind.
func (n *NetIPAddressClientImpl) runNetIPAddressEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
	baseContext := map[string]string{
		"host":      n.c.cfg.Host,
		"port":      strconv.Itoa(n.c.cfg.Port),
		"transport": "ssh",
	}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runNetIPAddressPowerShell(ctx, n.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout || eerr.Stage == EnvelopeStageTransport {
		return nil, NewNetIPAddressError(NetIPAddressErrorUnreachable, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewNetIPAddressError(NetIPAddressErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewNetIPAddressError(mapNetIPAddressKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapNetIPAddressKind translates a PS-side "kind" string to a typed
// NetIPAddressErrorKind. Unknown values fall through to Unknown.
func mapNetIPAddressKind(k string) NetIPAddressErrorKind {
	switch NetIPAddressErrorKind(k) {
	case NetIPAddressErrorInterfaceNotFound,
		NetIPAddressErrorNotFound,
		NetIPAddressErrorAlreadyExists,
		NetIPAddressErrorInUseElsewhere,
		NetIPAddressErrorInvalidAddress,
		NetIPAddressErrorDHCPEnabled,
		NetIPAddressErrorDuplicate,
		NetIPAddressErrorPermission,
		NetIPAddressErrorMgmtAtRisk,
		NetIPAddressErrorMgmtUnknown:
		return NetIPAddressErrorKind(k)
	default:
		return NetIPAddressErrorUnknown
	}
}

// parseNetIPAddressInfo projects a netIPAddressJSON payload onto a
// NetIPAddressInfo, canonicalising the address and deriving the family.
func parseNetIPAddressInfo(raw json.RawMessage, host string) (*NetIPAddressInfo, error) {
	var j netIPAddressJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, NewNetIPAddressError(NetIPAddressErrorUnknown,
			"failed to parse IP address state JSON", err,
			map[string]string{"host": host, "raw": truncate(string(raw), 512)})
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(j.IPAddress))
	if err != nil {
		return nil, NewNetIPAddressError(NetIPAddressErrorUnknown,
			fmt.Sprintf("host returned an unparsable IP address %q", j.IPAddress), nil,
			map[string]string{"host": host})
	}
	family := "IPv4"
	if addr.Is6() && !addr.Is4In6() {
		family = "IPv6"
	}
	return &NetIPAddressInfo{
		InterfaceAlias: j.InterfaceAlias,
		InterfaceIndex: j.InterfaceIndex,
		IPAddress:      addr.Unmap().String(),
		PrefixLength:   j.PrefixLength,
		AddressFamily:  family,
		AddressState:   j.AddressState,
		PrefixOrigin:   j.PrefixOrigin,
		SkipAsSource:   j.SkipAsSource,
	}, nil
}

// ---------------------------------------------------------------------------
// Client-side input validation (defence in depth; the schema validates first)
// ---------------------------------------------------------------------------

// validateNetIPAddressInput parses and checks the address, prefix length and
// DHCP flag, returning the canonical address and its family.
func validateNetIPAddressInput(alias, ip string, prefix int, disableDHCP bool) (canonical string, isV6 bool, err error) {
	if strings.TrimSpace(alias) == "" {
		return "", false, NewNetIPAddressError(NetIPAddressErrorInterfaceNotFound,
			"interface alias must not be empty", nil, nil)
	}
	addr, perr := netip.ParseAddr(strings.TrimSpace(ip))
	if perr != nil {
		return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is not a valid IPv4 or IPv6 address", ip), nil,
			map[string]string{"ip_address": ip})
	}
	if zone := addr.Zone(); zone != "" {
		return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q must not carry a zone ID (%q)", ip, zone), nil,
			map[string]string{"ip_address": ip})
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified():
		return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is the unspecified address", ip), nil,
			map[string]string{"ip_address": ip})
	case addr.IsLoopback():
		return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is a loopback address", ip), nil,
			map[string]string{"ip_address": ip})
	case addr.IsMulticast():
		return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is a multicast address", ip), nil,
			map[string]string{"ip_address": ip})
	case addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is the IPv4 broadcast address", ip), nil,
			map[string]string{"ip_address": ip})
	}
	v6 := addr.Is6()
	if v6 {
		if prefix < 1 || prefix > 128 {
			return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
				fmt.Sprintf("prefix length %d is out of range for IPv6 address %q (want 1-128)", prefix, ip), nil,
				map[string]string{"ip_address": ip})
		}
		if disableDHCP {
			return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
				"disable_dhcp is IPv4 only and must not be set for an IPv6 address", nil,
				map[string]string{"ip_address": ip})
		}
	} else {
		if prefix < 1 || prefix > 32 {
			return "", false, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
				fmt.Sprintf("prefix length %d is out of range for IPv4 address %q (want 1-32)", prefix, ip), nil,
				map[string]string{"ip_address": ip})
		}
	}
	return addr.String(), v6, nil
}

// ---------------------------------------------------------------------------
// Management-path guard
// ---------------------------------------------------------------------------

// resolveNetIPAddressManagementPath resolves the management path once per
// operation, fail-closed, honouring unsafeSkip (which yields a nil path).
// Callers must reuse the returned path for every guard in the same operation
// (the address guard and the DHCP-disable guard) instead of probing again:
// two probes around a mutation race each other (TOCTOU).
func (n *NetIPAddressClientImpl) resolveNetIPAddressManagementPath(ctx context.Context, op, alias string, ip netip.Addr, unsafeSkip bool) (*ManagementPath, error) {
	if unsafeSkip {
		return nil, nil
	}
	mp, err := netIPAddressManagementPath(ctx, n.c)
	if err != nil {
		return nil, NewNetIPAddressError(NetIPAddressErrorMgmtUnknown,
			fmt.Sprintf("cannot determine the management path for this SSH session, refusing %s of %s on interface %q fail-closed. Set unsafe_skip_management_check = true to proceed anyway; the host must stay reachable at the provider host address %q afterwards or the apply will hang and fail. Cause: %s",
				op, ip, alias, n.c.cfg.Host, managementPathCause(err)),
			nil, map[string]string{
				"host": n.c.cfg.Host, "operation": op,
				"interface_alias": alias, "ip_address": ip.String(),
			})
	}
	return mp, nil
}

// checkNetIPAddressManagementTouches refuses the operation when the resolved
// path shows it would touch the management address. It is pure — it never
// probes — so Create and Update share one probe per operation.
func checkNetIPAddressManagementTouches(op, alias, host string, ip netip.Addr, mp *ManagementPath) error {
	// A nil path means the guard was bypassed via
	// unsafe_skip_management_check.
	if mp == nil {
		return nil
	}
	if mp.TouchesAddress(ip) {
		return NewNetIPAddressError(NetIPAddressErrorMgmtAtRisk,
			fmt.Sprintf("refusing %s of %s on interface %q: it is the management address this SSH session arrived on (SSH_CONNECTION server_ip %s via %s). Removing or altering it would cut the provider connection. Set unsafe_skip_management_check = true to proceed anyway; the host must stay reachable at the provider host address %q afterwards or the apply will hang and fail.",
				op, ip, alias, mp.ServerIP, mp.Source, host),
			nil, map[string]string{
				"host": host, "operation": op,
				"interface_alias": alias, "ip_address": ip.String(),
				"management_server_ip": mp.ServerIP.String(),
				"management_source":    mp.Source,
			})
	}
	return nil
}

// ensureNetIPAddressManagementSafe refuses the operation when it would touch
// the management address, or when the management path cannot be determined.
// It must run before any mutation; nothing is applied when it returns an
// error. Set unsafeSkip to bypass via unsafe_skip_management_check.
func (n *NetIPAddressClientImpl) ensureNetIPAddressManagementSafe(ctx context.Context, op, alias string, ip netip.Addr, unsafeSkip bool) error {
	mp, err := n.resolveNetIPAddressManagementPath(ctx, op, alias, ip, unsafeSkip)
	if err != nil {
		return err
	}
	return checkNetIPAddressManagementTouches(op, alias, n.c.cfg.Host, ip, mp)
}

// ensureNetIPAddressDHCPDisableSafe refuses disable_dhcp on the interface
// carrying a DHCP-origin management address: disabling DHCP would drop that
// lease and cut the SSH session. Only consulted when disabling DHCP on the
// management interface itself.
func (n *NetIPAddressClientImpl) ensureNetIPAddressDHCPDisableSafe(ctx context.Context, mp *ManagementPath, ifIndex int, alias string) error {
	if mp == nil || mp.InterfaceIndex != ifIndex {
		return nil
	}
	origin, err := n.prefixOriginOf(ctx, mp.ServerIP.String())
	if err != nil {
		return NewNetIPAddressError(NetIPAddressErrorMgmtUnknown,
			fmt.Sprintf("cannot determine the prefix origin of the management address %s, refusing disable_dhcp on interface %q fail-closed. Set unsafe_skip_management_check = true to proceed anyway; the host must stay reachable at the provider host address %q afterwards. Cause: %s",
				mp.ServerIP, alias, n.c.cfg.Host, managementPathCause(err)),
			nil, map[string]string{
				"host": n.c.cfg.Host, "operation": "disable_dhcp",
				"interface_alias": alias,
			})
	}
	if origin == "Dhcp" {
		return NewNetIPAddressError(NetIPAddressErrorMgmtAtRisk,
			fmt.Sprintf("refusing disable_dhcp on interface %q: the management address %s this SSH session arrived on (SSH_CONNECTION server_ip %s) has prefix origin Dhcp, and disabling DHCP would drop that lease. Configure the management NIC out-of-band (unattend, cloud-init, DHCP reservation) and manage only secondary NICs with this resource. Set unsafe_skip_management_check = true to proceed anyway; the host must stay reachable at the provider host address %q afterwards.",
				alias, mp.ServerIP, mp.ServerIP, n.c.cfg.Host),
			nil, map[string]string{
				"host": n.c.cfg.Host, "operation": "disable_dhcp",
				"interface_alias":      alias,
				"management_server_ip": mp.ServerIP.String(),
			})
	}
	return nil
}

// managementPathCause renders the underlying probe failure for guard
// messages without leaking credentials (IPs and ports only).
func managementPathCause(err error) string {
	if err == nil {
		return "unknown reason"
	}
	var mpe *ManagementPathError
	if errors.As(err, &mpe) {
		return mpe.Message
	}
	return err.Error()
}

// prefixOriginOf returns the PrefixOrigin of one address (used by the DHCP
// disable-safety rule).
func (n *NetIPAddressClientImpl) prefixOriginOf(ctx context.Context, ip string) (string, error) {
	resp, err := n.runNetIPAddressEnvelope(ctx, "prefix_origin",
		buildNetIPAddressPrefixOriginScript(ip),
		map[string]string{"ip_address": ip})
	if err != nil {
		return "", err
	}
	if resp.Data == nil || string(resp.Data) == "null" {
		return "", NewNetIPAddressError(NetIPAddressErrorUnknown,
			"empty prefix origin response", nil, map[string]string{"ip_address": ip})
	}
	var origin string
	if jerr := json.Unmarshal(resp.Data, &origin); jerr != nil {
		return "", NewNetIPAddressError(NetIPAddressErrorUnknown,
			"failed to parse prefix origin JSON", jerr, map[string]string{"ip_address": ip})
	}
	return origin, nil
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

// resolveInterfaceIndex returns the numeric index of alias for the given
// family, or an interface_not_found error listing the valid aliases.
func (n *NetIPAddressClientImpl) resolveInterfaceIndex(ctx context.Context, alias string, isV6 bool) (int, error) {
	resp, err := n.runNetIPAddressEnvelope(ctx, "resolve_interface",
		buildNetIPAddressResolveScript(alias, isV6),
		map[string]string{"interface_alias": alias})
	if err != nil {
		return 0, err
	}
	var j struct {
		InterfaceIndex int    `json:"interface_index"`
		InterfaceAlias string `json:"interface_alias"`
	}
	if jerr := json.Unmarshal(resp.Data, &j); jerr != nil {
		return 0, NewNetIPAddressError(NetIPAddressErrorUnknown,
			"failed to parse interface resolution JSON", jerr,
			map[string]string{"interface_alias": alias})
	}
	if j.InterfaceIndex <= 0 {
		return 0, NewNetIPAddressError(NetIPAddressErrorUnknown,
			"host returned an invalid interface index", nil,
			map[string]string{"interface_alias": alias})
	}
	return j.InterfaceIndex, nil
}

// readSingleAddress reads one address on one interface. A missing address
// surfaces as a not_found typed error; callers decide whether that is fatal
// (Create pre-flight, Update) or a state drop (Read, Delete).
func (n *NetIPAddressClientImpl) readSingleAddress(ctx context.Context, op, alias, canonical string, isV6 bool) (*NetIPAddressInfo, error) {
	resp, err := n.runNetIPAddressEnvelope(ctx, op,
		buildNetIPAddressReadScript(alias, canonical, isV6),
		map[string]string{"interface_alias": alias, "ip_address": canonical})
	if err != nil {
		return nil, err
	}
	return parseNetIPAddressInfo(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create provisions the static address on the interface. The returned bool
// reports whether this call disabled DHCP (so the caller can restore it on
// destroy). When Create fails after disabling DHCP it best-effort restores
// DHCP again, so a failed apply leaves no DHCP side effect behind; only when
// that restore also fails is the flag still reported, and the caller must
// surface it (private state, warning diagnostic).
func (n *NetIPAddressClientImpl) Create(ctx context.Context, input NetIPAddressInput) (*NetIPAddressInfo, bool, error) {
	canonical, isV6, err := validateNetIPAddressInput(input.InterfaceAlias, input.IPAddress, input.PrefixLength, input.DisableDHCP)
	if err != nil {
		return nil, false, err
	}
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling (see netIPAddressID).
	alias := strings.TrimSpace(input.InterfaceAlias)
	addr := netip.MustParseAddr(canonical)

	ifIdx, err := n.resolveInterfaceIndex(ctx, alias, isV6)
	if err != nil {
		return nil, false, err
	}
	// One management-path probe per operation, shared by the address guard
	// and the DHCP-disable guard below (never re-probed mid-operation).
	mp, err := n.resolveNetIPAddressManagementPath(ctx, "create", alias, addr, input.UnsafeSkipManagementCheck)
	if err != nil {
		return nil, false, err
	}
	if err := checkNetIPAddressManagementTouches("create", alias, n.c.cfg.Host, addr, mp); err != nil {
		return nil, false, err
	}

	dhcpDisabled := false
	if input.DisableDHCP && !isV6 {
		if !input.UnsafeSkipManagementCheck {
			if err := n.ensureNetIPAddressDHCPDisableSafe(ctx, mp, ifIdx, alias); err != nil {
				return nil, false, err
			}
		}
		disabled, derr := n.ensureDHCPDisabled(ctx, alias, input.DisableDHCP)
		if derr != nil {
			return nil, false, derr
		}
		dhcpDisabled = disabled
	}

	resp, err := n.runNetIPAddressEnvelope(ctx, "create",
		buildNetIPAddressCreateScript(alias, canonical, input.PrefixLength, input.SkipAsSource, isV6),
		map[string]string{"interface_alias": alias, "ip_address": canonical})
	if err != nil {
		return nil, n.restoreDHCPAfterFailure(ctx, alias, dhcpDisabled), err
	}
	info, err := parseNetIPAddressInfo(resp.Data, n.c.cfg.Host)
	if err != nil {
		return nil, n.restoreDHCPAfterFailure(ctx, alias, dhcpDisabled), err
	}
	info, dhcpDisabled, err = n.pollAddressState(ctx, alias, canonical, isV6, info, dhcpDisabled)
	if err != nil {
		return nil, n.restoreDHCPAfterFailure(ctx, alias, dhcpDisabled), err
	}
	return info, dhcpDisabled, nil
}

// ensureDHCPDisabled runs the idempotent DHCP disable probe. It returns true
// when this call disabled DHCP.
func (n *NetIPAddressClientImpl) ensureDHCPDisabled(ctx context.Context, alias string, disable bool) (bool, error) {
	resp, err := n.runNetIPAddressEnvelope(ctx, "ensure_dhcp",
		buildNetIPAddressEnsureDHCPDisabledScript(alias, disable),
		map[string]string{"interface_alias": alias})
	if err != nil {
		return false, err
	}
	var j netIPAddressDHCPJSON
	if jerr := json.Unmarshal(resp.Data, &j); jerr != nil {
		return false, NewNetIPAddressError(NetIPAddressErrorUnknown,
			"failed to parse DHCP state JSON", jerr,
			map[string]string{"interface_alias": alias})
	}
	return j.DHCPDisabled, nil
}

// restoreDHCPAfterFailure best-effort re-enables DHCP after a failed Create
// or Update that had already disabled it, so a failed apply leaves no DHCP
// side effect behind. It reports whether DHCP remains disabled: false when
// nothing was disabled or the restore succeeded; true when the restore
// failed and the caller must surface that (private-state flag on Update, a
// warning diagnostic naming the manual re-enable step).
func (n *NetIPAddressClientImpl) restoreDHCPAfterFailure(ctx context.Context, alias string, dhcpDisabled bool) bool {
	if !dhcpDisabled {
		return false
	}
	if err := n.RestoreDHCP(ctx, alias); err != nil {
		return true
	}
	return false
}

// pollAddressState waits up to netIPAddressPollTimeout for duplicate address
// detection to settle. Duplicate rolls the address back and fails; a stable
// non-duplicate state returns the read-back info.
func (n *NetIPAddressClientImpl) pollAddressState(ctx context.Context, alias, canonical string, isV6 bool, created *NetIPAddressInfo, dhcpDisabled bool) (*NetIPAddressInfo, bool, error) {
	if created.AddressState == "Duplicate" {
		return nil, dhcpDisabled, n.rollbackDuplicate(ctx, alias, canonical, isV6)
	}
	if created.AddressState == "Preferred" || created.AddressState == "Deprecated" {
		return created, dhcpDisabled, nil
	}
	deadline := time.Now().Add(netIPAddressPollTimeout)
	current := created
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, dhcpDisabled, NewNetIPAddressError(NetIPAddressErrorUnreachable,
				fmt.Sprintf("operation %q timed out or was cancelled while polling address state", "create"),
				ctx.Err(), map[string]string{"interface_alias": alias, "ip_address": canonical})
		case <-time.After(netIPAddressPollInterval):
		}
		info, err := n.readSingleAddress(ctx, "poll", alias, canonical, isV6)
		if err != nil {
			if IsNetIPAddressError(err, NetIPAddressErrorNotFound) {
				continue // transient: the address is still appearing
			}
			return nil, dhcpDisabled, err
		}
		current = info
		if info.AddressState == "Duplicate" {
			return nil, dhcpDisabled, n.rollbackDuplicate(ctx, alias, canonical, isV6)
		}
		if info.AddressState == "Preferred" || info.AddressState == "Deprecated" {
			return info, dhcpDisabled, nil
		}
	}
	// Still Tentative (or another transitional state) at the deadline: return
	// the last observation so the provider can warn instead of failing.
	return current, dhcpDisabled, nil
}

// rollbackDuplicate removes a Duplicate address again and reports the
// duplicate_address failure. A failed rollback is recorded in the context.
func (n *NetIPAddressClientImpl) rollbackDuplicate(ctx context.Context, alias, canonical string, isV6 bool) error {
	resp, rerr := n.runNetIPAddressEnvelope(ctx, "rollback",
		buildNetIPAddressRemoveScript(alias, canonical, isV6),
		map[string]string{"interface_alias": alias, "ip_address": canonical})
	if rerr != nil {
		return NewNetIPAddressError(NetIPAddressErrorDuplicate,
			fmt.Sprintf("address %s on interface %q failed duplicate address detection and the rollback removal also failed: %s",
				canonical, alias, rerr.Error()),
			nil, map[string]string{"interface_alias": alias, "ip_address": canonical})
	}
	_ = resp
	return NewNetIPAddressError(NetIPAddressErrorDuplicate,
		fmt.Sprintf("address %s on interface %q failed duplicate address detection (another host already uses it); the address was removed again",
			canonical, alias),
		nil, map[string]string{"interface_alias": alias, "ip_address": canonical})
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the observed address, or (nil, nil) when the address — or
// its interface, e.g. after a rename — is gone.
func (n *NetIPAddressClientImpl) Read(ctx context.Context, interfaceAlias, ipAddress string) (*NetIPAddressInfo, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipAddress))
	if err != nil {
		return nil, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is not a valid IPv4 or IPv6 address", ipAddress), nil,
			map[string]string{"ip_address": ipAddress})
	}
	addr = addr.Unmap()
	isV6 := addr.Is6()
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling (see splitNetIPAddressID).
	alias := strings.TrimSpace(interfaceAlias)
	info, err := n.readSingleAddress(ctx, "read", alias, addr.String(), isV6)
	if err != nil {
		if IsNetIPAddressError(err, NetIPAddressErrorNotFound) ||
			IsNetIPAddressError(err, NetIPAddressErrorInterfaceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return info, nil
}

// ---------------------------------------------------------------------------
// Lookup (data source)
// ---------------------------------------------------------------------------

// Lookup lists every address matching ipAddress, optionally restricted to
// one interface. Zero matches return not_found; several return
// address_in_use_elsewhere listing the candidates. A whitespace-only alias
// is rejected instead of widening the lookup to all interfaces.
func (n *NetIPAddressClientImpl) Lookup(ctx context.Context, ipAddress, interfaceAlias string) ([]*NetIPAddressInfo, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipAddress))
	if err != nil {
		return nil, NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is not a valid IPv4 or IPv6 address", ipAddress), nil,
			map[string]string{"ip_address": ipAddress})
	}
	addr = addr.Unmap()
	alias := strings.TrimSpace(interfaceAlias)
	if interfaceAlias != "" && alias == "" {
		return nil, NewNetIPAddressError(NetIPAddressErrorInterfaceNotFound,
			"interface alias must not be blank; omit it to search all interfaces", nil,
			map[string]string{"ip_address": addr.String()})
	}
	resp, err := n.runNetIPAddressEnvelope(ctx, "lookup",
		buildNetIPAddressLookupScript(addr.String(), alias),
		map[string]string{"ip_address": addr.String(), "interface_alias": alias})
	if err != nil {
		return nil, err
	}
	// The lookup script emits either a single object or an Emit-Err; a
	// defensive array decode covers hosts that wrap single results.
	trimmed := strings.TrimSpace(string(resp.Data))
	if strings.HasPrefix(trimmed, "[") {
		var arr []netIPAddressJSON
		if jerr := json.Unmarshal(resp.Data, &arr); jerr != nil {
			return nil, NewNetIPAddressError(NetIPAddressErrorUnknown,
				"failed to parse IP address lookup JSON", jerr,
				map[string]string{"ip_address": addr.String()})
		}
		out := make([]*NetIPAddressInfo, 0, len(arr))
		for _, j := range arr {
			raw, _ := json.Marshal(j)
			info, perr := parseNetIPAddressInfo(raw, n.c.cfg.Host)
			if perr != nil {
				return nil, perr
			}
			out = append(out, info)
		}
		return out, nil
	}
	info, err := parseNetIPAddressInfo(resp.Data, n.c.cfg.Host)
	if err != nil {
		return nil, err
	}
	return []*NetIPAddressInfo{info}, nil
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update changes prefix length and/or SkipAsSource in place via
// Set-NetIPAddress after the guard passes. The returned bool reports whether
// this call disabled DHCP. Like Create, a failure after disabling DHCP
// best-effort restores it; a residual disable is still reported so the
// caller can persist the flag.
func (n *NetIPAddressClientImpl) Update(ctx context.Context, interfaceAlias, ipAddress string, prefixLength int, skipAsSource, disableDHCP, unsafeSkip bool) (*NetIPAddressInfo, bool, error) {
	canonical, isV6, err := validateNetIPAddressInput(interfaceAlias, ipAddress, prefixLength, disableDHCP)
	if err != nil {
		return nil, false, err
	}
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling (see netIPAddressID).
	alias := strings.TrimSpace(interfaceAlias)
	addr := netip.MustParseAddr(canonical)

	ifIdx, err := n.resolveInterfaceIndex(ctx, alias, isV6)
	if err != nil {
		return nil, false, err
	}
	if _, err := n.readSingleAddress(ctx, "update_preflight", alias, canonical, isV6); err != nil {
		return nil, false, err
	}
	// One management-path probe per operation, shared by the address guard
	// and the DHCP-disable guard below (never re-probed mid-operation).
	mp, err := n.resolveNetIPAddressManagementPath(ctx, "update", alias, addr, unsafeSkip)
	if err != nil {
		return nil, false, err
	}
	if err := checkNetIPAddressManagementTouches("update", alias, n.c.cfg.Host, addr, mp); err != nil {
		return nil, false, err
	}

	dhcpDisabled := false
	if disableDHCP && !isV6 {
		if !unsafeSkip {
			if err := n.ensureNetIPAddressDHCPDisableSafe(ctx, mp, ifIdx, alias); err != nil {
				return nil, false, err
			}
		}
		disabled, derr := n.ensureDHCPDisabled(ctx, alias, true)
		if derr != nil {
			return nil, false, derr
		}
		dhcpDisabled = disabled
	}

	resp, err := n.runNetIPAddressEnvelope(ctx, "update",
		buildNetIPAddressSetScript(alias, canonical, prefixLength, skipAsSource),
		map[string]string{"interface_alias": alias, "ip_address": canonical})
	if err != nil {
		return nil, n.restoreDHCPAfterFailure(ctx, alias, dhcpDisabled), err
	}
	info, err := parseNetIPAddressInfo(resp.Data, n.c.cfg.Host)
	if err != nil {
		return nil, n.restoreDHCPAfterFailure(ctx, alias, dhcpDisabled), err
	}
	return info, dhcpDisabled, nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the address via Remove-NetIPAddress after the guard passes.
// A missing address or interface is a successful no-op (nil).
func (n *NetIPAddressClientImpl) Delete(ctx context.Context, interfaceAlias, ipAddress string, unsafeSkip bool) error {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipAddress))
	if err != nil {
		return NewNetIPAddressError(NetIPAddressErrorInvalidAddress,
			fmt.Sprintf("IP address %q is not a valid IPv4 or IPv6 address", ipAddress), nil,
			map[string]string{"ip_address": ipAddress})
	}
	addr = addr.Unmap()
	isV6 := addr.Is6()
	canonical := addr.String()
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling (see splitNetIPAddressID).
	alias := strings.TrimSpace(interfaceAlias)

	if _, err := n.resolveInterfaceIndex(ctx, alias, isV6); err != nil {
		if IsNetIPAddressError(err, NetIPAddressErrorInterfaceNotFound) {
			return nil // interface already gone: nothing to remove
		}
		return err
	}
	if _, err := n.readSingleAddress(ctx, "delete_preflight", alias, canonical, isV6); err != nil {
		if IsNetIPAddressError(err, NetIPAddressErrorNotFound) {
			return nil // address already gone: nothing to remove
		}
		return err
	}
	if err := n.ensureNetIPAddressManagementSafe(ctx, "delete", alias, addr, unsafeSkip); err != nil {
		return err
	}

	resp, err := n.runNetIPAddressEnvelope(ctx, "delete",
		buildNetIPAddressRemoveScript(alias, canonical, isV6),
		map[string]string{"interface_alias": alias, "ip_address": canonical})
	if err != nil {
		return err
	}
	_ = resp
	return nil
}

// ---------------------------------------------------------------------------
// RestoreDHCP
// ---------------------------------------------------------------------------

// RestoreDHCP re-enables DHCP on the interface (Set-NetIPInterface
// -AddressFamily IPv4 -Dhcp Enabled).
//
// It deliberately bypasses the management-path guard (no unsafe_skip
// parameter): re-enabling DHCP never removes an address or a route, so it
// cannot sever the SSH session the way disable_dhcp, address removal or
// route changes can — statically assigned (Manual) addresses persist
// alongside DHCP, and a DHCP-origin management lease is only refreshed,
// never dropped. It runs only at destroy, after the managed address itself
// has been removed, and only when this resource previously disabled DHCP
// (private-state flag).
func (n *NetIPAddressClientImpl) RestoreDHCP(ctx context.Context, interfaceAlias string) error {
	alias := strings.TrimSpace(interfaceAlias)
	if alias == "" {
		return NewNetIPAddressError(NetIPAddressErrorInterfaceNotFound,
			"interface alias must not be empty", nil, nil)
	}
	if _, err := n.resolveInterfaceIndex(ctx, alias, false); err != nil {
		return err
	}
	resp, err := n.runNetIPAddressEnvelope(ctx, "restore_dhcp",
		buildNetIPAddressRestoreDHCPScript(alias),
		map[string]string{"interface_alias": alias})
	if err != nil {
		return err
	}
	_ = resp
	return nil
}
