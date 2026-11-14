// Package winclient: shared management-path guard for lockout-sensitive resources.
//
// Several resources can sever the very SSH session Terraform uses
// (windows_net_ip_address in issue #230, windows_net_route and
// windows_firewall_profile follow-ups). They all need the same target-side
// question answered: "which address and route carry the current SSH session,
// and would this change cut it?" The PowerShell probe and the Go-side pure
// helpers live here so those resources share one implementation instead of
// drifting apart.
//
// How the path is determined (one extra round trip, computed per risky
// operation, never cached: earlier resources in the same apply may have
// changed it):
//
//  1. Primary: $env:SSH_CONNECTION in the persistent session
//     ("<client IP> <client port> <server IP> <server port>", space separated,
//     IPv6 not bracketed). It reflects NAT correctly because it is the
//     server's view.
//  2. Fallback: when the variable is empty, match the established connection
//     with Get-NetTCPConnection -State Established -LocalPort <ssh port>
//     whose RemotePort equals the executing session's local source port.
//     Client.run substitutes that port into the probe just before execution
//     (mgmtPathLocalPortPlaceholder), so the fallback always matches the
//     in-flight session — never a client-global snapshot of the most
//     recently dialled connection (issue #230). An ambiguous match or no
//     match means "unknown".
//  3. Interface: Get-NetIPAddress -IPAddress <server_ip>.
//  4. Route: Find-NetRoute -RemoteIPAddress <client_ip> (the output mixes
//     NetIPAddress and NetRoute objects; only the NetRoute one is kept).
//
// Rules (fail closed): an operation is refused with
// management_path_at_risk when it would remove or alter the management
// address or the route currently carrying the SSH traffic. When the path
// cannot be determined and the operation is risky, it is refused with
// management_path_unknown. Non-risky operations never call the guard.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Management-path Source values reported in ManagementPath.Source.
const (
	// ManagementPathSourceSSH means the path was resolved from
	// $env:SSH_CONNECTION (the primary probe).
	ManagementPathSourceSSH = "ssh_connection"
	// ManagementPathSourceTCP means $env:SSH_CONNECTION was unusable and the
	// path was resolved via the Get-NetTCPConnection fallback.
	ManagementPathSourceTCP = "tcp_connection"
)

// ManagementPath describes how the current SSH session reaches the host, as
// seen from the Windows side. IPv4-mapped IPv6 addresses are unmapped.
type ManagementPath struct {
	// ClientIP is the SSH client's address as the server sees it.
	ClientIP netip.Addr
	// ServerIP is the host address the SSH session arrived on.
	ServerIP netip.Addr
	// ClientPort is the client's (ephemeral) source port.
	ClientPort int
	// ServerPort is the sshd listening port the session arrived on.
	ServerPort int
	// InterfaceIndex owns ServerIP.
	InterfaceIndex int
	// InterfaceAlias is the friendly name of InterfaceIndex.
	InterfaceAlias string
	// RouteDestinationPrefix is the destination prefix of the best route
	// towards ClientIP (e.g. "0.0.0.0/0").
	RouteDestinationPrefix string
	// RouteNextHop is the next hop of that route.
	RouteNextHop string
	// RouteInterfaceIndex is the outgoing interface of that route.
	RouteInterfaceIndex int
	// Source is "ssh_connection" or "tcp_connection".
	Source string
}

// RouteCandidate describes a route about to be created or applied, for the
// WouldHijack decision. EffectiveMetric is the candidate's effective metric
// (route metric + interface metric); a zero value means unknown and compares
// as the most preferred, so an unknown metric fails closed towards hijack.
type RouteCandidate struct {
	DestinationPrefix string
	NextHop           string
	InterfaceIndex    int
	EffectiveMetric   int
}

// RouteInfo describes the currently observed route being replaced, for the
// WouldHijack decision. EffectiveMetric is the observed route's effective
// metric (route metric + interface metric); zero means unknown.
type RouteInfo struct {
	DestinationPrefix string
	NextHop           string
	InterfaceIndex    int
	EffectiveMetric   int
}

// TouchesAddress reports whether ip is the management address itself, i.e.
// removing or altering it would cut the SSH session. A nil path never
// touches: callers fail closed on an unknown path before consulting this.
func (p *ManagementPath) TouchesAddress(ip netip.Addr) bool {
	if p == nil || !p.ServerIP.IsValid() || !ip.IsValid() {
		return false
	}
	return p.ServerIP.Unmap() == ip.Unmap()
}

// TouchesRoute reports whether changing the described route to the given
// next hop / interface could reroute the SSH session's traffic. It returns
// true when prefix covers the management ClientIP and the new next hop or
// interface differs from the route currently carrying the session; an
// identical route (a no-op re-apply) does not touch it. A nil path or an
// invalid prefix never touches: callers fail closed on an unknown path
// before consulting this.
func (p *ManagementPath) TouchesRoute(prefix netip.Prefix, nextHop netip.Addr, ifIndex int) bool {
	if p == nil || !p.ClientIP.IsValid() || !prefix.IsValid() {
		return false
	}
	if !prefix.Contains(p.ClientIP) {
		return false
	}
	curPrefix, curErr := netip.ParsePrefix(p.RouteDestinationPrefix)
	curNextHop, nextErr := netip.ParseAddr(p.RouteNextHop)
	if curErr != nil || nextErr != nil {
		// The current management route is not parseable, so identity with
		// it cannot be established: fail closed.
		return true
	}
	if curPrefix.Masked() == prefix.Masked() &&
		curNextHop.Unmap() == nextHop.Unmap() &&
		p.RouteInterfaceIndex == ifIndex {
		return false
	}
	return true
}

// WouldHijack reports whether adding cand alongside the currently observed
// route (current) would hijack the SSH session's traffic. It returns true
// when current carries the session (its destination prefix covers the
// management ClientIP) and cand would deliver that traffic differently:
// a more specific covering prefix always wins; at the same prefix length the
// lower effective metric wins, with a tie treated as a hijack risk because
// Windows tie-breaking is not stable across builds. A candidate that does
// not cover the client cannot win the longest-prefix selection (this
// includes cross-family candidates, where Contains across families is
// false), so it never hijacks; replacing the management prefix itself is
// refused separately by the exact-match check. An identical route (same
// prefix, next hop and interface) is a no-op re-apply and never hijacks,
// even on a metric tie: exact-metric changes to the management route itself
// are refused separately by the exact-match check. A nil path never
// hijacks: callers fail closed on an unknown path before consulting this.
func (p *ManagementPath) WouldHijack(cand RouteCandidate, current RouteInfo) bool {
	if p == nil || !p.ClientIP.IsValid() {
		return false
	}
	curPrefix, err := netip.ParsePrefix(current.DestinationPrefix)
	if err != nil || !curPrefix.Contains(p.ClientIP) {
		return false
	}
	candPrefix, err := netip.ParsePrefix(cand.DestinationPrefix)
	if err != nil || !candPrefix.Contains(p.ClientIP) {
		// Additive semantics: a candidate that does not cover the client
		// cannot win route selection, so it cannot hijack (cross-family
		// Contains is false, hence not a hijack either).
		return false
	}
	if !sameRouteHop(cand.NextHop, current.NextHop) {
		// A different next hop only diverts the traffic when the candidate
		// can actually win the longest-prefix / lowest-metric selection.
		// A less specific prefix never does; at the same length only an
		// equal-or-better (lower-or-tied) effective metric does.
		if candPrefix.Bits() < curPrefix.Bits() {
			return false
		}
		if candPrefix.Bits() == curPrefix.Bits() && cand.EffectiveMetric > current.EffectiveMetric {
			return false
		}
		return true
	}
	if cand.InterfaceIndex != current.InterfaceIndex {
		if candPrefix.Bits() < curPrefix.Bits() {
			return false
		}
		if candPrefix.Bits() == curPrefix.Bits() && cand.EffectiveMetric > current.EffectiveMetric {
			return false
		}
		return true
	}
	return false
}

// sameRouteHop compares two next-hop spellings, tolerating IPv4-mapped IPv6
// and case differences; unparseable spellings fall back to a trimmed
// case-insensitive string comparison.
func sameRouteHop(a, b string) bool {
	aa, aerr := netip.ParseAddr(strings.TrimSpace(a))
	bb, berr := netip.ParseAddr(strings.TrimSpace(b))
	if aerr == nil && berr == nil {
		return aa.Unmap() == bb.Unmap()
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// parseManagementSSHConnection parses an $env:SSH_CONNECTION value
// ("<client IP> <client port> <server IP> <server port>") into its four
// parts. IPv6 addresses contain no whitespace, so a plain whitespace split
// is sufficient. IPv4-mapped IPv6 addresses are unmapped. A malformed value
// yields an error so the caller fails closed instead of guarding the wrong
// address.
func parseManagementSSHConnection(sshConnection string) (clientIP, serverIP netip.Addr, clientPort, serverPort int, err error) {
	tokens := strings.Fields(sshConnection)
	if len(tokens) < 4 {
		return netip.Addr{}, netip.Addr{}, 0, 0, fmt.Errorf("SSH_CONNECTION has an unexpected shape (want \"<client IP> <client port> <server IP> <server port>\"): %q", sshConnection)
	}
	clientIP, err = netip.ParseAddr(tokens[0])
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, 0, fmt.Errorf("SSH_CONNECTION carries an unparsable client IP %q: %v", tokens[0], err)
	}
	serverIP, err = netip.ParseAddr(tokens[2])
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, 0, fmt.Errorf("SSH_CONNECTION carries an unparsable server IP %q: %v", tokens[2], err)
	}
	clientPort, err = parseSSHPort(tokens[1], "client")
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, 0, err
	}
	serverPort, err = parseSSHPort(tokens[3], "server")
	if err != nil {
		return netip.Addr{}, netip.Addr{}, 0, 0, err
	}
	return clientIP.Unmap(), serverIP.Unmap(), clientPort, serverPort, nil
}

// parseSSHPort parses one SSH_CONNECTION port token (1-65535).
func parseSSHPort(token, side string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(token))
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("SSH_CONNECTION carries an invalid %s port %q", side, token)
	}
	return port, nil
}

// ---------------------------------------------------------------------------
// ManagementPathError — typed error for an undeterminable management path
// ---------------------------------------------------------------------------

// ManagementPathErrorKind categorises ManagementPath failures. Resolution
// either succeeds or fails closed as unknown; there is no partial result.
type ManagementPathErrorKind string

const (
	// ManagementPathErrorUnknown means the SSH session's management path
	// could not be determined (no SSH_CONNECTION, ambiguous TCP fallback,
	// unresolvable interface or route, transport failure). Risky operations
	// must be refused when this occurs.
	ManagementPathErrorUnknown ManagementPathErrorKind = "unknown"
)

// ManagementPathError is the structured error returned by
// Client.ManagementPath. Resources map it to their own
// management_path_unknown kind.
type ManagementPathError struct {
	Kind    ManagementPathErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *ManagementPathError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("management_path [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("management_path [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *ManagementPathError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *ManagementPathError) Is(target error) bool {
	t, ok := target.(*ManagementPathError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewManagementPathError constructs a *ManagementPathError.
func NewManagementPathError(kind ManagementPathErrorKind, message string, cause error, ctx map[string]string) *ManagementPathError {
	return &ManagementPathError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// Sentinel errors for use with errors.Is.
var (
	// ErrManagementPathUnknown matches any undeterminable-path failure.
	ErrManagementPathUnknown = &ManagementPathError{Kind: ManagementPathErrorUnknown}
)

// ---------------------------------------------------------------------------
// PowerShell probe
// ---------------------------------------------------------------------------

// mgmtPathPSHeader is prepended to the management-path probe. It composes
// the shared envelope prelude (Emit-OK / Emit-Err, InvariantCulture pins
// so enum .ToString() values are always English regardless of the host
// locale).
const mgmtPathPSHeader = psEnvelopePrelude + mgmtPathPSHeaderRemainder

// mgmtPathPSHeaderRemainder is intentionally empty: this header held only the envelope emitters (the probe lives in mgmtPathPSBody).
const mgmtPathPSHeaderRemainder = ``

// mgmtPathPSBody resolves the SSH session's management path and emits it.
// Placeholders: @@SSHPORT@@ (sshd port, int, rendered by
// buildMgmtPathScript), @@LOCALPORT@@ (execution-time placeholder for the
// executing session's source port, substituted by Client.run/runOneShot; a
// literal 0 here would mean "no fallback possible" and fail closed).
const mgmtPathPSBody = `
& {
  $sshPort   = @@SSHPORT@@
  $localPort = @@LOCALPORT@@

  $clientIP = $null; $clientPort = 0; $serverIP = $null; $serverPort = 0; $source = $null

  # Primary: $env:SSH_CONNECTION is the server's own view, NAT-correct.
  $sshConn = [string]$env:SSH_CONNECTION
  $tokens = @($sshConn -split '\s+' | Where-Object { $_ -ne '' })
  if ($tokens.Count -ge 4 -and $tokens[0] -ne '' -and $tokens[2] -ne '') {
    try {
      $null = [System.Net.IPAddress]::Parse($tokens[0])
      $null = [System.Net.IPAddress]::Parse($tokens[2])
      $cp = [int]$tokens[1]
      $sp = [int]$tokens[3]
      if ($cp -gt 0 -and $cp -le 65535 -and $sp -gt 0 -and $sp -le 65535) {
        $clientIP = $tokens[0]; $clientPort = $cp
        $serverIP = $tokens[2]; $serverPort = $sp
        $source = 'ssh_connection'
      }
    } catch { }
  }

  # Fallback: match the established TCP connection to this session.
  if ($null -eq $source) {
    if ($localPort -le 0) {
      Emit-Err 'unknown' 'Cannot determine the management path: $env:SSH_CONNECTION is not set or malformed, and no client source port is known for the Get-NetTCPConnection fallback.' @{}
      return
    }
    try {
      $conns = @(Get-NetTCPConnection -State Established -LocalPort $sshPort -ErrorAction Stop | Where-Object { $_.RemotePort -eq $localPort })
    } catch {
      Emit-Err 'unknown' ('Cannot determine the management path: the Get-NetTCPConnection fallback failed: ' + [string]$_.Exception.Message) @{}
      return
    }
    if ($conns.Count -ne 1) {
      Emit-Err 'unknown' ('Cannot determine the management path: the Get-NetTCPConnection fallback matched ' + [string]$conns.Count + ' connections (want exactly 1).') @{}
      return
    }
    $clientIP = [string]$conns[0].RemoteAddress
    $clientPort = [int]$conns[0].RemotePort
    $serverIP = [string]$conns[0].LocalAddress
    $serverPort = [int]$conns[0].LocalPort
    $source = 'tcp_connection'
  }

  try {
    $ipRow = Get-NetIPAddress -IPAddress $serverIP -ErrorAction Stop | Select-Object -First 1
  } catch {
    Emit-Err 'unknown' ('Cannot determine the management path: no interface owns the SSH server IP ' + [string]$serverIP + ': ' + [string]$_.Exception.Message) @{}
    return
  }
  if ($null -eq $ipRow) {
    Emit-Err 'unknown' ('Cannot determine the management path: no interface owns the SSH server IP ' + [string]$serverIP + '.') @{}
    return
  }

  try {
    $routeRow = Find-NetRoute -RemoteIPAddress $clientIP -ErrorAction Stop | Where-Object { $_.PSObject.Properties.Name -contains 'DestinationPrefix' } | Select-Object -First 1
  } catch {
    Emit-Err 'unknown' ('Cannot determine the management path: no route towards the SSH client IP ' + [string]$clientIP + ' could be found: ' + [string]$_.Exception.Message) @{}
    return
  }
  if ($null -eq $routeRow) {
    Emit-Err 'unknown' ('Cannot determine the management path: no route towards the SSH client IP ' + [string]$clientIP + ' could be found.') @{}
    return
  }

  Emit-OK ([ordered]@{
    client_ip                = [string]$clientIP
    client_port              = [int]$clientPort
    server_ip                = [string]$serverIP
    server_port              = [int]$serverPort
    interface_index          = [int]$ipRow.InterfaceIndex
    interface_alias          = [string]$ipRow.InterfaceAlias
    route_destination_prefix = [string]$routeRow.DestinationPrefix
    route_next_hop           = [string]$routeRow.NextHop
    route_interface_index    = [int]$routeRow.InterfaceIndex
    source                   = [string]$source
  })
}
`

// mgmtPathLocalPortPlaceholder is the execution-time placeholder for the
// fallback source port in the probe script. buildMgmtPathScript leaves it in
// place; Client.run and Client.runOneShot replace it with the executing
// session's own source port (see substituteSessionPort) just before the
// script runs. It must stay a string no legitimate script contains, and no
// other script builder may emit it.
const mgmtPathLocalPortPlaceholder = "@@LOCALPORT@@"

// buildMgmtPathScript renders the probe with the sshd port. The Go-side
// source port is intentionally not rendered here: it is the execution-time
// placeholder above, substituted per call with the session that actually
// executes the probe. Both values are ints formatted with Itoa, never user
// input, so no quoting is required.
func buildMgmtPathScript(sshPort int) string {
	return mgmtPathPSHeader + "\n" + strings.NewReplacer(
		"@@SSHPORT@@", strconv.Itoa(sshPort),
	).Replace(mgmtPathPSBody)
}

// mgmtPathJSON mirrors the JSON object emitted by the probe.
type mgmtPathJSON struct {
	ClientIP               string `json:"client_ip"`
	ClientPort             int    `json:"client_port"`
	ServerIP               string `json:"server_ip"`
	ServerPort             int    `json:"server_port"`
	InterfaceIndex         int    `json:"interface_index"`
	InterfaceAlias         string `json:"interface_alias"`
	RouteDestinationPrefix string `json:"route_destination_prefix"`
	RouteNextHop           string `json:"route_next_hop"`
	RouteInterfaceIndex    int    `json:"route_interface_index"`
	Source                 string `json:"source"`
}

// ManagementPath resolves how the current SSH session reaches the host, as
// seen from the Windows side. It performs one extra round trip and must be
// called per risky operation, never cached: earlier resources in the same
// apply may have changed the path. A resolution failure is a typed unknown
// error so the caller fails closed instead of guarding the wrong address.
//
// The TCP fallback matches the session executing this very probe: run
// substitutes its source port at execution time, so the port is always the
// in-flight session's own — including the first probe on a fresh client,
// which has no earlier dial to snapshot.
func (c *Client) ManagementPath(ctx context.Context) (*ManagementPath, error) {
	if c == nil {
		return nil, NewManagementPathError(ManagementPathErrorUnknown,
			"cannot determine the management path: winclient: nil client", nil, nil)
	}
	baseContext := map[string]string{
		"host":      c.cfg.Host,
		"port":      strconv.Itoa(c.cfg.Port),
		"transport": "ssh",
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return c.RunPowerShell(ctx, full)
		},
		"management_path", buildMgmtPathScript(sshProviderPort(c.cfg.Port)), "", baseContext)
	if eerr == nil {
		return parseManagementPath(resp, baseContext)
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewManagementPathError(ManagementPathErrorUnknown,
			fmt.Sprintf("cannot determine the management path: operation %q timed out or was cancelled", eerr.Operation),
			eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewManagementPathError(ManagementPathErrorUnknown,
			eerr.Message, eerr.Cause, eerr.Context)
	}
	return nil, NewManagementPathError(ManagementPathErrorUnknown,
		fmt.Sprintf("cannot determine the management path: %s", eerr.Message), nil, eerr.Context)
}

// parseManagementPath validates the probe's Emit-OK payload and projects it
// onto a ManagementPath. Anything unexpected is an unknown error: guessing
// the management address is worse than refusing.
func parseManagementPath(resp *Envelope, baseContext map[string]string) (*ManagementPath, error) {
	ctx := map[string]string{}
	for k, v := range baseContext {
		ctx[k] = v
	}
	fail := func(msg string, cause error) (*ManagementPath, error) {
		return nil, NewManagementPathError(ManagementPathErrorUnknown, msg, cause, ctx)
	}
	if resp == nil || resp.Data == nil || string(resp.Data) == "null" {
		return fail("cannot determine the management path: empty response from the probe", nil)
	}
	var j mgmtPathJSON
	if err := json.Unmarshal(resp.Data, &j); err != nil {
		return fail("cannot determine the management path: failed to parse the probe response", err)
	}
	clientIP, err := netip.ParseAddr(strings.TrimSpace(j.ClientIP))
	if err != nil {
		return fail(fmt.Sprintf("cannot determine the management path: unparsable client IP %q", j.ClientIP), nil)
	}
	serverIP, err := netip.ParseAddr(strings.TrimSpace(j.ServerIP))
	if err != nil {
		return fail(fmt.Sprintf("cannot determine the management path: unparsable server IP %q", j.ServerIP), nil)
	}
	if j.ClientPort <= 0 || j.ClientPort > 65535 || j.ServerPort <= 0 || j.ServerPort > 65535 {
		return fail("cannot determine the management path: probe returned invalid ports", nil)
	}
	if j.InterfaceIndex <= 0 || strings.TrimSpace(j.InterfaceAlias) == "" {
		return fail("cannot determine the management path: probe returned no interface for the SSH server IP", nil)
	}
	if strings.TrimSpace(j.RouteDestinationPrefix) == "" {
		return fail("cannot determine the management path: probe returned no route towards the SSH client IP", nil)
	}
	if _, err := netip.ParsePrefix(strings.TrimSpace(j.RouteDestinationPrefix)); err != nil {
		return fail(fmt.Sprintf("cannot determine the management path: unparsable route destination prefix %q", j.RouteDestinationPrefix), nil)
	}
	if _, err := netip.ParseAddr(strings.TrimSpace(j.RouteNextHop)); err != nil {
		return fail(fmt.Sprintf("cannot determine the management path: unparsable route next hop %q", j.RouteNextHop), nil)
	}
	if j.Source != ManagementPathSourceSSH && j.Source != ManagementPathSourceTCP {
		return fail(fmt.Sprintf("cannot determine the management path: probe returned unknown source %q", j.Source), nil)
	}
	return &ManagementPath{
		ClientIP:               clientIP.Unmap(),
		ServerIP:               serverIP.Unmap(),
		ClientPort:             j.ClientPort,
		ServerPort:             j.ServerPort,
		InterfaceIndex:         j.InterfaceIndex,
		InterfaceAlias:         j.InterfaceAlias,
		RouteDestinationPrefix: j.RouteDestinationPrefix,
		RouteNextHop:           j.RouteNextHop,
		RouteInterfaceIndex:    j.RouteInterfaceIndex,
		Source:                 j.Source,
	}, nil
}
