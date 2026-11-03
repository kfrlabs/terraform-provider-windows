// Package winclient - NetRouteClientImpl is the concrete NetRouteClient
// backed by PowerShell over SSH.
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted
//     PowerShell literal with embedded single-quotes doubled); no raw
//     concatenation of user input into PS scripts.
//   - No credentials are involved in route management; none are written to
//     NetRouteError.Message or Context.
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
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Compile-time assertion: NetRouteClientImpl satisfies NetRouteClient.
var _ NetRouteClient = (*NetRouteClientImpl)(nil)

// NetRouteClientImpl is the PowerShell/SSH-backed NetRouteClient.
type NetRouteClientImpl struct {
	c *Client
}

// NewNetRouteClient wraps the given SSH Client.
func NewNetRouteClient(c *Client) *NetRouteClientImpl {
	return &NetRouteClientImpl{c: c}
}

// runNetRoutePowerShell is the package-level indirection used by
// NetRouteClientImpl. Tests may override it; production code must not.
var runNetRoutePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// netRouteManagementPath is the package-level indirection for the shared
// management-path probe. Tests may override it; production code must not.
var netRouteManagementPath = func(ctx context.Context, c *Client) (*ManagementPath, error) {
	return c.ManagementPath(ctx)
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// psNetRouteHeader is prepended to every net-route PS script. It pins the
// session culture to InvariantCulture so enum .ToString() values (Protocol)
// are always English regardless of the host locale, and defines the shared
// Emit-OK / Emit-Err / Classify-NetRoute helpers.
//
// Classify-NetRoute prefers CIM/HRESULT codes over localized message
// substrings (hosts are not all English); substring matches remain as a
// backstop where no stable code exists (the unreachable-gateway wording,
// whose exact Windows behaviour is verified by the acceptance suite).
const psNetRouteHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture   = [System.Globalization.CultureInfo]::InvariantCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture

function Emit-OK([object]$Data) {
  $obj  = [ordered]@{ ok = $true; data = $Data }
  $json = ($obj | ConvertTo-Json -Depth 10 -Compress)
  [Console]::Out.WriteLine($json)
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj  = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Classify-NetRoute([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  if ($code -eq '0x80070005' -or $msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess') { return 'permission_denied' }
  if ($code -eq '0x800700B7' -or $msg -match 'already exists') { return 'already_exists' }
  if ($code -eq '0x80070490' -or $code -eq '0x80041002' -or $msg -match 'No matching MSFT_NetRoute' -or $msg -match 'No MSFT_NetRoute') { return 'not_found' }
  if ($msg -match 'No matching MSFT_NetIPInterface' -or $msg -match 'No MSFT_NetIPInterface') { return 'interface_not_found' }
  if ($code -eq '0x80070057' -or $msg -match 'InvalidParameter' -or $msg -match 'is not valid' -or $msg -match 'Invalid prefix') { return 'invalid_route' }
  if ($msg -match 'unreachable') { return 'next_hop_unreachable' }
  return 'unknown'
}

function ConvertTo-NetRouteJson([object]$Row, [string]$Alias, [int]$IfMetric) {
  return [ordered]@{
    interface_alias     = $Alias
    interface_index     = [int]$Row.InterfaceIndex
    destination_prefix  = [string]$Row.DestinationPrefix
    next_hop            = [string]$Row.NextHop
    route_metric        = [int]$Row.RouteMetric
    interface_metric    = $IfMetric
    effective_metric    = ([int]$Row.RouteMetric + $IfMetric)
    protocol            = [string]$Row.Protocol
  }
}
`

// netRouteResolveFragment resolves $alias with an exact (-eq,
// case-insensitive, never wildcard) comparison and stores the interface
// index in $ifIndex, the host spelling in $ifaceAlias and the interface
// metric in $ifMetric. On failure it emits interface_not_found listing the
// valid aliases and returns. Callers set $family ('IPv4'/'IPv6') and $alias
// before invoking it.
const netRouteResolveFragment = `
$iface = Get-NetIPInterface -AddressFamily $family -ErrorAction Stop | Where-Object { $_.InterfaceAlias -eq $alias } | Select-Object -First 1
if ($null -eq $iface) {
  $valid = @(Get-NetIPInterface -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias -Unique | Sort-Object)
  Emit-Err 'interface_not_found' ('No interface matches alias ' + [string]$alias + '. Valid aliases: ' + ($valid -join ', ') + '.') @{ interface_alias = [string]$alias }
  return
}
$ifIndex = [int]$iface.InterfaceIndex
$ifaceAlias = [string]$iface.InterfaceAlias
$ifMetric = [int]$iface.InterfaceMetric
`

// ---------------------------------------------------------------------------
// Script builders (every user value via psQuote; ints via tokens)
// ---------------------------------------------------------------------------

// netRouteFamilyToken renders the PS address-family literal for the prefix.
func netRouteFamilyToken(isV6 bool) string {
	if isV6 {
		return "'IPv6'"
	}
	return "'IPv4'"
}

// buildNetRouteResolveScript renders a resolve-only probe returning
// {interface_index, interface_alias, interface_metric}.
func buildNetRouteResolveScript(alias string, isV6 bool) string {
	return psNetRouteHeader + fmt.Sprintf(`
$family = %s
$alias = %s
& {
%s
  Emit-OK ([ordered]@{ interface_index = $ifIndex; interface_alias = $ifaceAlias; interface_metric = $ifMetric })
}
`, netRouteFamilyToken(isV6), psQuote(alias), netRouteResolveFragment)
}

// buildNetRouteReadScript renders a resolve + exact-triplet read. A missing
// route emits not_found. The triplet is matched with -eq on
// DestinationPrefix and NextHop (never wildcard-capable parameters).
func buildNetRouteReadScript(alias, prefix, nextHop string, isV6 bool) string {
	return psNetRouteHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantPrefix = %s
$wantNextHop = %s
& {
%s
  try {
    $row = Get-NetRoute -InterfaceIndex $ifIndex -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $wantPrefix -and $_.NextHop -eq $wantNextHop } | Select-Object -First 1
  } catch {
    Emit-Err (Classify-NetRoute $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; step = 'read' }
    return
  }
  if ($null -eq $row) {
    Emit-Err 'not_found' ('No route ' + [string]$wantPrefix + ' via ' + [string]$wantNextHop + ' on interface ' + [string]$alias + '.') @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop }
    return
  }
  Emit-OK (ConvertTo-NetRouteJson $row $ifaceAlias $ifMetric)
}
`, netRouteFamilyToken(isV6), psQuote(alias), psQuote(prefix), psQuote(nextHop), netRouteResolveFragment)
}

// buildNetRouteLookupScript renders a prefix lookup across all interfaces,
// optionally restricted to one alias (resolved to its index first, exact
// -eq) and/or next hop. Zero matches emit not_found; several matches emit
// the whole array so the data source can pick the lowest effective metric.
func buildNetRouteLookupScript(prefix, alias, nextHop string) string {
	aliasFilter := ""
	if alias != "" {
		aliasFilter = fmt.Sprintf(`
  try {
    $only = Get-NetIPInterface -ErrorAction Stop | Where-Object { $_.InterfaceAlias -eq %s } | Select-Object -First 1
  } catch {
    Emit-Err (Classify-NetRoute $_) ([string]$_.Exception.Message) @{ interface_alias = %s; step = 'lookup_resolve' }
    return
  }
  if ($null -eq $only) {
    $valid = @(Get-NetIPInterface -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias -Unique | Sort-Object)
    Emit-Err 'interface_not_found' ('No interface matches alias ' + %s + '. Valid aliases: ' + ($valid -join ', ') + '.') @{ interface_alias = %s }
    return
  }
  $rows = @($rows | Where-Object { [int]$_.InterfaceIndex -eq [int]$only.InterfaceIndex })`, psQuote(alias), psQuote(alias), psQuote(alias), psQuote(alias))
	}
	nextHopFilter := ""
	if nextHop != "" {
		nextHopFilter = fmt.Sprintf(`
  $rows = @($rows | Where-Object { $_.NextHop -eq %s })`, psQuote(nextHop))
	}
	return psNetRouteHeader + fmt.Sprintf(`
$wantPrefix = %s
& {
  try {
    $rows = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $wantPrefix })
  } catch {
    Emit-Err (Classify-NetRoute $_) ([string]$_.Exception.Message) @{ destination_prefix = [string]$wantPrefix; step = 'lookup' }
    return
  }
  %s
  %s
  if ($rows.Count -eq 0) {
    Emit-Err 'not_found' ('No route ' + [string]$wantPrefix + ' found on any interface.') @{ destination_prefix = [string]$wantPrefix }
    return
  }
  $out = @()
  foreach ($r in $rows) {
    $ri = Get-NetIPInterface -InterfaceIndex ([int]$r.InterfaceIndex) -ErrorAction SilentlyContinue | Select-Object -First 1
    $nm = ''
    $im = 0
    if ($null -ne $ri) { $nm = [string]$ri.InterfaceAlias; $im = [int]$ri.InterfaceMetric }
    $out += (ConvertTo-NetRouteJson $r $nm $im)
  }
  Emit-OK $out
}
`, psQuote(prefix), aliasFilter, nextHopFilter)
}

// buildNetRouteCreateScript renders the atomic create: resolve, exact-triplet
// pre-flight with protocol discrimination (NetMgmt -> already_exists with an
// import hint, anything else -> route_owned_by_other_protocol), New-NetRoute
// into the PersistentStore, read-back.
func buildNetRouteCreateScript(alias, prefix, nextHop string, metric int, isV6 bool) string {
	return psNetRouteHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantPrefix = %s
$wantNextHop = %s
$metric = %d
& {
%s
  try {
    $existing = @(Get-NetRoute -InterfaceIndex $ifIndex -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $wantPrefix -and $_.NextHop -eq $wantNextHop })
  } catch {
    $existing = @()
  }
  if ($existing.Count -gt 0) {
    $mgmt = @($existing | Where-Object { [string]$_.Protocol -eq 'NetMgmt' })
    if ($mgmt.Count -gt 0) {
      Emit-Err 'already_exists' ('Route ' + [string]$wantPrefix + ' via ' + [string]$wantNextHop + ' already exists on interface ' + [string]$alias + ' (protocol NetMgmt). Import it with terraform import <name> "' + [string]$alias + '|' + [string]$wantPrefix + '|' + [string]$wantNextHop + '".') @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; protocol = 'NetMgmt' }
    } else {
      $protos = (($existing | ForEach-Object { [string]$_.Protocol } | Sort-Object -Unique) -join ', ')
      Emit-Err 'route_owned_by_other_protocol' ('Route ' + [string]$wantPrefix + ' via ' + [string]$wantNextHop + ' on interface ' + [string]$alias + ' is owned by protocol ' + [string]$protos + ' (not NetMgmt): Windows would create a competing duplicate. Remove it on the host or choose another route.') @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; protocol = [string]$protos }
    }
    return
  }
  try {
    $null = New-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $wantPrefix -NextHop $wantNextHop -RouteMetric $metric -PolicyStore PersistentStore -ErrorAction Stop
  } catch {
    Emit-Err (Classify-NetRoute $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; step = 'create' }
    return
  }
  try {
    $row = Get-NetRoute -InterfaceIndex $ifIndex -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $wantPrefix -and $_.NextHop -eq $wantNextHop } | Select-Object -First 1
  } catch {
    Emit-Err (Classify-NetRoute $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; step = 'readback' }
    return
  }
  if ($null -eq $row) {
    Emit-Err 'unknown' ('Route ' + [string]$wantPrefix + ' via ' + [string]$wantNextHop + ' was created but could not be read back on interface ' + [string]$alias + '.') @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; step = 'readback' }
    return
  }
  Emit-OK (ConvertTo-NetRouteJson $row $ifaceAlias $ifMetric)
}
`, netRouteFamilyToken(isV6), psQuote(alias), psQuote(prefix), psQuote(nextHop), metric, netRouteResolveFragment)
}

// buildNetRouteSetScript renders the in-place metric update (Set-NetRoute in
// the PersistentStore) plus read-back.
func buildNetRouteSetScript(alias, prefix, nextHop string, metric int, isV6 bool) string {
	return psNetRouteHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantPrefix = %s
$wantNextHop = %s
$metric = %d
& {
%s
  try {
    $null = Set-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $wantPrefix -NextHop $wantNextHop -RouteMetric $metric -PolicyStore PersistentStore -ErrorAction Stop
  } catch {
    Emit-Err (Classify-NetRoute $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; step = 'set' }
    return
  }
  try {
    $row = Get-NetRoute -InterfaceIndex $ifIndex -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $wantPrefix -and $_.NextHop -eq $wantNextHop } | Select-Object -First 1
  } catch {
    Emit-Err (Classify-NetRoute $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; step = 'readback' }
    return
  }
  if ($null -eq $row) {
    Emit-Err 'not_found' ('No route ' + [string]$wantPrefix + ' via ' + [string]$wantNextHop + ' on interface ' + [string]$alias + '.') @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop }
    return
  }
  Emit-OK (ConvertTo-NetRouteJson $row $ifaceAlias $ifMetric)
}
`, netRouteFamilyToken(isV6), psQuote(alias), psQuote(prefix), psQuote(nextHop), metric, netRouteResolveFragment)
}

// buildNetRouteRemoveScript renders the guarded delete. A missing route
// emits Emit-OK null (idempotent delete); a concurrently removed route
// between pre-flight and removal maps to the same outcome via Classify.
func buildNetRouteRemoveScript(alias, prefix, nextHop string, isV6 bool) string {
	return psNetRouteHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantPrefix = %s
$wantNextHop = %s
& {
%s
  try {
    $row = Get-NetRoute -InterfaceIndex $ifIndex -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $wantPrefix -and $_.NextHop -eq $wantNextHop } | Select-Object -First 1
  } catch {
    Emit-OK $null
    return
  }
  if ($null -eq $row) {
    Emit-OK $null
    return
  }
  try {
    $null = Remove-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix $wantPrefix -NextHop $wantNextHop -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop
  } catch {
    $kind = Classify-NetRoute $_
    if ($kind -eq 'not_found') {
      Emit-OK $null
      return
    }
    Emit-Err $kind ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop; step = 'remove' }
    return
  }
  Emit-OK ([ordered]@{ removed = $true })
}
`, netRouteFamilyToken(isV6), psQuote(alias), psQuote(prefix), psQuote(nextHop), netRouteResolveFragment)
}

// buildNetRouteMgmtRouteScript renders the effective-metric probe for the
// route currently carrying the SSH session (its triplet comes from the
// ManagementPath probe). Emits {route_metric, interface_metric}; a missing
// route emits 'unknown' so the caller treats the current metric as unknown
// (fail-closed tie) instead of guessing.
func buildNetRouteMgmtRouteScript(prefix, nextHop string, ifIndex int) string {
	return psNetRouteHeader + fmt.Sprintf(`
$wantPrefix = %s
$wantNextHop = %s
$wantIfIndex = %d
& {
  try {
    $row = Get-NetRoute -InterfaceIndex $wantIfIndex -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $wantPrefix -and $_.NextHop -eq $wantNextHop } | Select-Object -First 1
  } catch {
    Emit-Err 'unknown' ('Cannot determine the effective metric of the management route: the route lookup failed: ' + [string]$_.Exception.Message) @{ destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop }
    return
  }
  if ($null -eq $row) {
    Emit-Err 'unknown' ('Cannot determine the effective metric of the management route: no route ' + [string]$wantPrefix + ' via ' + [string]$wantNextHop + ' on interface index ' + [string]$wantIfIndex + '.') @{ destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop }
    return
  }
  try {
    $ri = Get-NetIPInterface -InterfaceIndex $wantIfIndex -ErrorAction Stop | Select-Object -First 1
  } catch {
    Emit-Err 'unknown' ('Cannot determine the effective metric of the management route: the interface lookup failed: ' + [string]$_.Exception.Message) @{ destination_prefix = [string]$wantPrefix; next_hop = [string]$wantNextHop }
    return
  }
  Emit-OK ([ordered]@{ route_metric = [int]$row.RouteMetric; interface_metric = [int]$ri.InterfaceMetric })
}
`, psQuote(prefix), psQuote(nextHop), ifIndex)
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// netRouteJSON mirrors the JSON object emitted by ConvertTo-NetRouteJson.
// AddressFamily is derived Go-side from the prefix, never trusted from enum
// decoding; EffectiveMetric is recomputed Go-side.
type netRouteJSON struct {
	InterfaceAlias    string `json:"interface_alias"`
	InterfaceIndex    int    `json:"interface_index"`
	DestinationPrefix string `json:"destination_prefix"`
	NextHop           string `json:"next_hop"`
	RouteMetric       int    `json:"route_metric"`
	InterfaceMetric   int    `json:"interface_metric"`
	EffectiveMetric   int    `json:"effective_metric"`
	Protocol          string `json:"protocol"`
}

// netRouteIfaceJSON mirrors the Emit-OK payload of the resolve-only probe.
type netRouteIfaceJSON struct {
	InterfaceIndex  int    `json:"interface_index"`
	InterfaceAlias  string `json:"interface_alias"`
	InterfaceMetric int    `json:"interface_metric"`
}

// runNetRouteEnvelope executes script (prefixed with psNetRouteHeader by
// the builders) and parses the JSON envelope through the shared
// runEnvelope helper. Transport/timeout failures map to unreachable;
// remote Emit-Err kinds map via mapNetRouteKind.
func (n *NetRouteClientImpl) runNetRouteEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
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
			return runNetRoutePowerShell(ctx, n.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout || eerr.Stage == EnvelopeStageTransport {
		return nil, NewNetRouteError(NetRouteErrorUnreachable, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewNetRouteError(NetRouteErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewNetRouteError(mapNetRouteKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapNetRouteKind translates a PS-side "kind" string to a typed
// NetRouteErrorKind. Unknown values fall through to Unknown.
func mapNetRouteKind(k string) NetRouteErrorKind {
	switch NetRouteErrorKind(k) {
	case NetRouteErrorInterfaceNotFound,
		NetRouteErrorNotFound,
		NetRouteErrorAlreadyExists,
		NetRouteErrorOwnedByOtherProtocol,
		NetRouteErrorInvalidRoute,
		NetRouteErrorNextHopUnreachable,
		NetRouteErrorPermission,
		NetRouteErrorMgmtAtRisk,
		NetRouteErrorMgmtUnknown:
		return NetRouteErrorKind(k)
	default:
		return NetRouteErrorUnknown
	}
}

// parseNetRouteInfo projects a netRouteJSON payload onto a NetRouteInfo,
// canonicalising the prefix (masked) and next hop (netip) and deriving the
// family and effective metric Go-side.
func parseNetRouteInfo(raw json.RawMessage, host string) (*NetRouteInfo, error) {
	var j netRouteJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, NewNetRouteError(NetRouteErrorUnknown,
			"failed to parse route state JSON", err,
			map[string]string{"host": host, "raw": truncate(string(raw), 512)})
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(j.DestinationPrefix))
	if err != nil {
		return nil, NewNetRouteError(NetRouteErrorUnknown,
			fmt.Sprintf("host returned an unparsable destination prefix %q", j.DestinationPrefix), nil,
			map[string]string{"host": host})
	}
	prefix = prefix.Masked()
	nextHop, err := netip.ParseAddr(strings.TrimSpace(j.NextHop))
	if err != nil {
		return nil, NewNetRouteError(NetRouteErrorUnknown,
			fmt.Sprintf("host returned an unparsable next hop %q", j.NextHop), nil,
			map[string]string{"host": host})
	}
	nextHop = nextHop.Unmap()
	family := "IPv4"
	if prefix.Addr().Is6() {
		family = "IPv6"
	}
	return &NetRouteInfo{
		InterfaceAlias:    j.InterfaceAlias,
		InterfaceIndex:    j.InterfaceIndex,
		DestinationPrefix: prefix.String(),
		NextHop:           nextHop.String(),
		RouteMetric:       j.RouteMetric,
		InterfaceMetric:   j.InterfaceMetric,
		EffectiveMetric:   j.RouteMetric + j.InterfaceMetric,
		AddressFamily:     family,
		Protocol:          j.Protocol,
	}, nil
}

// ---------------------------------------------------------------------------
// Client-side input validation (defence in depth; the schema validates first)
// ---------------------------------------------------------------------------

// normalizeNetRouteTriplet parses and checks the interface alias,
// destination prefix and next hop, returning the canonical masked prefix,
// the canonical next hop and the address family. The prefix is normalised
// with Masked (host-bits callers are normalised, not rejected, here);
// validateNetRouteInput adds the canonical-form rejection for Create/Update.
func normalizeNetRouteTriplet(alias, prefix, nextHop string) (canonicalPrefix, canonicalNextHop string, isV6 bool, err error) {
	trimmedAlias := strings.TrimSpace(alias)
	if trimmedAlias == "" {
		return "", "", false, NewNetRouteError(NetRouteErrorInterfaceNotFound,
			"interface alias must not be empty", nil, nil)
	}
	p, perr := netip.ParsePrefix(strings.TrimSpace(prefix))
	if perr != nil {
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("destination prefix %q is not a valid CIDR prefix", prefix), nil,
			map[string]string{"destination_prefix": prefix})
	}
	p = p.Masked()
	v6 := p.Addr().Is6()
	rawNext := strings.TrimSpace(nextHop)
	nh, nerr := netip.ParseAddr(rawNext)
	if nerr != nil {
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("next hop %q is not a valid IPv4 or IPv6 address", nextHop), nil,
			map[string]string{"next_hop": nextHop})
	}
	if zone := nh.Zone(); zone != "" {
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("next hop %q must not carry a zone ID (%q)", nextHop, zone), nil,
			map[string]string{"next_hop": nextHop})
	}
	nh = nh.Unmap()
	switch {
	case nh.IsMulticast():
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("next hop %q is a multicast address (on-link routes use the unspecified address 0.0.0.0 or ::)", nextHop), nil,
			map[string]string{"next_hop": nextHop})
	case nh.IsLoopback():
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("next hop %q is a loopback address", nextHop), nil,
			map[string]string{"next_hop": nextHop})
	case nh.Is4() && nh == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("next hop %q is the IPv4 broadcast address", nextHop), nil,
			map[string]string{"next_hop": nextHop})
	}
	if nh.Is4() == v6 {
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("destination prefix %q and next hop %q disagree on the address family", p.String(), nh.String()), nil,
			map[string]string{"destination_prefix": p.String(), "next_hop": nh.String()})
	}
	return p.String(), nh.String(), v6, nil
}

// validateNetRouteInput parses and checks the full create/update input,
// returning the canonical masked prefix, the canonical next hop and the
// family. Unlike normalizeNetRouteTriplet it rejects unmasked prefixes
// (the schema reports the canonical form at plan time) and out-of-range
// route metrics.
func validateNetRouteInput(alias, prefix, nextHop string, metric int) (canonicalPrefix, canonicalNextHop string, isV6 bool, err error) {
	raw := strings.TrimSpace(prefix)
	p, perr := netip.ParsePrefix(raw)
	if perr != nil {
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("destination prefix %q is not a valid CIDR prefix", prefix), nil,
			map[string]string{"destination_prefix": prefix})
	}
	if p.Masked() != p {
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("destination prefix %q has host bits set; use the canonical masked form %q", prefix, p.Masked().String()), nil,
			map[string]string{"destination_prefix": prefix})
	}
	if metric < 0 || metric > 9999 {
		return "", "", false, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("route metric %d is out of range (want 0-9999)", metric), nil,
			map[string]string{"route_metric": strconv.Itoa(metric)})
	}
	return normalizeNetRouteTriplet(alias, prefix, nextHop)
}

// ---------------------------------------------------------------------------
// Management-path guard
// ---------------------------------------------------------------------------

// resolveNetRouteManagementPath resolves the management path once per
// operation, fail-closed, honouring unsafeSkip (which yields a nil path).
// Callers must reuse the returned path for every guard in the same
// operation instead of probing again: two probes around a mutation race
// each other (TOCTOU).
func (n *NetRouteClientImpl) resolveNetRouteManagementPath(ctx context.Context, op, routeDesc string, unsafeSkip bool) (*ManagementPath, error) {
	if unsafeSkip {
		return nil, nil
	}
	mp, err := netRouteManagementPath(ctx, n.c)
	if err != nil {
		return nil, NewNetRouteError(NetRouteErrorMgmtUnknown,
			formatNetRouteUnknownMessage(op, routeDesc, n.c.cfg.Host, managementPathCause(err)),
			nil, map[string]string{
				"host": n.c.cfg.Host, "operation": op,
				"route": routeDesc,
			})
	}
	return mp, nil
}

// isNetRouteManagementRoute reports whether the candidate triplet is exactly
// the route currently carrying the SSH session (same masked prefix, next hop
// and outgoing interface). An unparseable management route fails closed
// (true): identity with it cannot be disproven.
func isNetRouteManagementRoute(mp *ManagementPath, prefix netip.Prefix, nextHop netip.Addr, ifIndex int) bool {
	if mp == nil {
		return false
	}
	curPrefix, err := netip.ParsePrefix(mp.RouteDestinationPrefix)
	if err != nil {
		return true
	}
	curNextHop, err := netip.ParseAddr(mp.RouteNextHop)
	if err != nil {
		return true
	}
	return curPrefix.Masked() == prefix.Masked() &&
		curNextHop.Unmap() == nextHop.Unmap() &&
		mp.RouteInterfaceIndex == ifIndex
}

// checkNetRouteManagementExact refuses the operation when the candidate
// triplet is exactly the management route. It is pure — it never probes —
// so Create, Update and Delete share one probe per operation.
func checkNetRouteManagementExact(op, alias, prefix, nextHop string, ifIndex int, host string, mp *ManagementPath) error {
	// A nil path means the guard was bypassed via
	// unsafe_skip_management_check.
	if mp == nil {
		return nil
	}
	p, perr := netip.ParsePrefix(strings.TrimSpace(prefix))
	nh, nerr := netip.ParseAddr(strings.TrimSpace(nextHop))
	if perr != nil || nerr != nil {
		// Fail closed: an unparseable candidate cannot be proven different
		// from the management route.
		cause := "unparsable route triplet"
		if perr != nil {
			cause = perr.Error()
		}
		if nerr != nil {
			cause = nerr.Error()
		}
		return NewNetRouteError(NetRouteErrorMgmtUnknown,
			formatNetRouteUnknownMessage(op, prefix+" via "+nextHop, host, cause),
			nil, map[string]string{
				"host": host, "operation": op,
				"interface_alias": alias, "destination_prefix": prefix, "next_hop": nextHop,
			})
	}
	if !isNetRouteManagementRoute(mp, p, nh, ifIndex) {
		return nil
	}
	return NewNetRouteError(NetRouteErrorMgmtAtRisk,
		fmt.Sprintf("refusing %s of route %s via %s on interface %q: it is the management route currently carrying this SSH session (client %s via %s). Removing, replacing or re-metricing it would cut the provider connection. Set unsafe_skip_management_check = true to proceed anyway; the host must stay reachable at the provider host address %q afterwards or the apply will hang and fail.",
			op, p.Masked().String(), nh.Unmap().String(), alias, mp.ClientIP, mp.RouteDestinationPrefix, host),
		nil, map[string]string{
			"host": host, "operation": op,
			"interface_alias": alias, "destination_prefix": p.Masked().String(), "next_hop": nh.Unmap().String(),
			"management_client_ip": mp.ClientIP.String(),
			"management_source":    mp.Source,
		})
}

// managementRouteEffectiveMetric returns the effective metric (route +
// interface) of the route currently carrying the SSH session. When it cannot
// be determined the metric is unknown (known=false) and the caller treats
// the comparison as a tie — fail-closed towards hijack.
func (n *NetRouteClientImpl) managementRouteEffectiveMetric(ctx context.Context, mp *ManagementPath) (eff int, known bool) {
	resp, err := n.runNetRouteEnvelope(ctx, "mgmt_route_metric",
		buildNetRouteMgmtRouteScript(mp.RouteDestinationPrefix, mp.RouteNextHop, mp.RouteInterfaceIndex),
		map[string]string{"destination_prefix": mp.RouteDestinationPrefix, "next_hop": mp.RouteNextHop})
	if err != nil {
		return 0, false
	}
	var j struct {
		RouteMetric     int `json:"route_metric"`
		InterfaceMetric int `json:"interface_metric"`
	}
	if jerr := json.Unmarshal(resp.Data, &j); jerr != nil {
		return 0, false
	}
	return j.RouteMetric + j.InterfaceMetric, true
}

// checkNetRouteManagementHijack refuses the operation when the candidate
// route would hijack the SSH session's return path (more specific covering
// prefix, or the same prefix length with an equal-or-better effective
// metric, delivering the traffic via a different next hop or interface). It
// is pure apart from the effective-metric probe it is given.
func checkNetRouteManagementHijack(op, alias, prefix, nextHop string, ifIndex, effectiveMetric int, host string, mp *ManagementPath, currentEffectiveMetric int) error {
	// A nil path means the guard was bypassed via
	// unsafe_skip_management_check.
	if mp == nil {
		return nil
	}
	curPrefix, err := netip.ParsePrefix(mp.RouteDestinationPrefix)
	// An unparseable management prefix cannot prove a hijack: treat it
	// like a non-containing prefix (no refusal). The parse error is
	// intentionally swallowed here — this is a guardrail probe, not I/O —
	// and the boolean form keeps that explicit for nilerr.
	hijackPossible := err == nil && curPrefix.Contains(mp.ClientIP)
	if !hijackPossible {
		return nil
	}
	cand := RouteCandidate{DestinationPrefix: prefix, NextHop: nextHop, InterfaceIndex: ifIndex, EffectiveMetric: effectiveMetric}
	current := RouteInfo{DestinationPrefix: mp.RouteDestinationPrefix, NextHop: mp.RouteNextHop, InterfaceIndex: mp.RouteInterfaceIndex, EffectiveMetric: currentEffectiveMetric}
	if !mp.WouldHijack(cand, current) {
		return nil
	}
	return NewNetRouteError(NetRouteErrorMgmtAtRisk,
		fmt.Sprintf("refusing %s of route %s via %s on interface %q: it would hijack the return path of this SSH session (client %s, currently via %s). Set unsafe_skip_management_check = true to proceed anyway; the host must stay reachable at the provider host address %q afterwards or the apply will hang and fail.",
			op, prefix, nextHop, alias, mp.ClientIP, mp.RouteDestinationPrefix, host),
		nil, map[string]string{
			"host": host, "operation": op,
			"interface_alias": alias, "destination_prefix": prefix, "next_hop": nextHop,
			"management_client_ip": mp.ClientIP.String(),
			"management_source":    mp.Source,
		})
}

// ensureNetRouteManagementSafeForWrite runs the full guard for Create and
// Update: two round trips per operation (one management-path probe,
// fail-closed unknown, plus one effective-metric probe for the management
// route), then the exact-match check and the hijack check against the
// measured effective metric (unknown measures as a tie, fail-closed).
// The two probes race each other (TOCTOU): the route may change between
// them, in which case the guard fails closed towards hijack. Nothing is
// applied when it returns an error.
func (n *NetRouteClientImpl) ensureNetRouteManagementSafeForWrite(ctx context.Context, op, alias, prefix, nextHop string, ifIndex, routeMetric, ifMetric int, unsafeSkip bool) error {
	routeDesc := prefix + " via " + nextHop
	mp, err := n.resolveNetRouteManagementPath(ctx, op, routeDesc, unsafeSkip)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	if err := checkNetRouteManagementExact(op, alias, prefix, nextHop, ifIndex, n.c.cfg.Host, mp); err != nil {
		return err
	}
	candidateEffective := routeMetric + ifMetric
	currentEffective, known := n.managementRouteEffectiveMetric(ctx, mp)
	if !known {
		// The current metric is unknown: compare as a tie so any
		// same-or-better candidate fails closed towards hijack.
		currentEffective = candidateEffective
	}
	return checkNetRouteManagementHijack(op, alias, prefix, nextHop, ifIndex, candidateEffective, n.c.cfg.Host, mp, currentEffective)
}

// ensureNetRouteManagementSafeForDelete runs the delete guard: one
// management-path probe per operation (fail-closed unknown) plus the
// exact-match check. Only the exact management route is refused: removing
// any other route cannot divert the session's return path away from the
// probed best route (traffic falls back to it), so no hijack check applies.
func (n *NetRouteClientImpl) ensureNetRouteManagementSafeForDelete(ctx context.Context, alias, prefix, nextHop string, ifIndex int, unsafeSkip bool) error {
	routeDesc := prefix + " via " + nextHop
	mp, err := n.resolveNetRouteManagementPath(ctx, "delete", routeDesc, unsafeSkip)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	return checkNetRouteManagementExact("delete", alias, prefix, nextHop, ifIndex, n.c.cfg.Host, mp)
}

// formatNetRouteUnknownMessage renders the fail-closed unknown-path message,
// shared by every mutating operation.
func formatNetRouteUnknownMessage(op, routeDesc, host, cause string) string {
	return fmt.Sprintf("cannot determine the management path for this SSH session, refusing %s of route %s fail-closed. Set unsafe_skip_management_check = true to proceed anyway; the host must stay reachable at the provider host address %q afterwards or the apply will hang and fail. Cause: %s",
		op, routeDesc, host, cause)
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

// resolveNetRouteInterface returns the numeric index and
// interface metric of alias for the given family, or an
// interface_not_found error listing the valid aliases.
func (n *NetRouteClientImpl) resolveNetRouteInterface(ctx context.Context, alias string, isV6 bool) (index int, ifMetric int, err error) {
	resp, err := n.runNetRouteEnvelope(ctx, "resolve_interface",
		buildNetRouteResolveScript(alias, isV6),
		map[string]string{"interface_alias": alias})
	if err != nil {
		return 0, 0, err
	}
	var j netRouteIfaceJSON
	if jerr := json.Unmarshal(resp.Data, &j); jerr != nil {
		return 0, 0, NewNetRouteError(NetRouteErrorUnknown,
			"failed to parse interface resolution JSON", jerr,
			map[string]string{"interface_alias": alias})
	}
	if j.InterfaceIndex <= 0 {
		return 0, 0, NewNetRouteError(NetRouteErrorUnknown,
			"host returned an invalid interface index", nil,
			map[string]string{"interface_alias": alias})
	}
	return j.InterfaceIndex, j.InterfaceMetric, nil
}

// readSingleRoute reads one route for the exact triplet on one interface. A
// missing route surfaces as a not_found typed error; callers decide whether
// that is fatal (Create pre-flight is inside the script, Update) or a state
// drop (Read, Delete).
func (n *NetRouteClientImpl) readSingleRoute(ctx context.Context, op, alias, prefix, nextHop string, isV6 bool) (*NetRouteInfo, error) {
	resp, err := n.runNetRouteEnvelope(ctx, op,
		buildNetRouteReadScript(alias, prefix, nextHop, isV6),
		map[string]string{"interface_alias": alias, "destination_prefix": prefix, "next_hop": nextHop})
	if err != nil {
		return nil, err
	}
	return parseNetRouteInfo(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create provisions the persistent route on the interface: resolves the
// interface, guards the management path (one probe per operation), then
// runs the atomic pre-flight + New-NetRoute + read-back script.
func (n *NetRouteClientImpl) Create(ctx context.Context, input NetRouteInput) (*NetRouteInfo, error) {
	canonicalPrefix, canonicalNextHop, isV6, err := validateNetRouteInput(input.InterfaceAlias, input.DestinationPrefix, input.NextHop, input.RouteMetric)
	if err != nil {
		return nil, err
	}
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling (see netRouteID).
	alias := strings.TrimSpace(input.InterfaceAlias)

	ifIndex, ifMetric, err := n.resolveNetRouteInterface(ctx, alias, isV6)
	if err != nil {
		return nil, err
	}
	if err := n.ensureNetRouteManagementSafeForWrite(ctx, "create", alias, canonicalPrefix, canonicalNextHop, ifIndex, input.RouteMetric, ifMetric, input.UnsafeSkipManagementCheck); err != nil {
		return nil, err
	}

	resp, err := n.runNetRouteEnvelope(ctx, "create",
		buildNetRouteCreateScript(alias, canonicalPrefix, canonicalNextHop, input.RouteMetric, isV6),
		map[string]string{"interface_alias": alias, "destination_prefix": canonicalPrefix, "next_hop": canonicalNextHop})
	if err != nil {
		// A classify miss on next_hop_unreachable wording stays actionable:
		// enrich unknown create failures that mention the gateway.
		if IsNetRouteError(err, NetRouteErrorUnknown) && gatewayHint(err.Error()) {
			return nil, NewNetRouteError(NetRouteErrorNextHopUnreachable,
				fmt.Sprintf("route %s via %s on interface %q: the next hop is unreachable (it must be on-link on that interface; on-link routes use the unspecified address 0.0.0.0 or ::): %s",
					canonicalPrefix, canonicalNextHop, alias, err.Error()),
				nil, map[string]string{"interface_alias": alias, "destination_prefix": canonicalPrefix, "next_hop": canonicalNextHop})
		}
		return nil, err
	}
	return parseNetRouteInfo(resp.Data, n.c.cfg.Host)
}

// gatewayHint reports whether an unclassified create failure mentions a
// gateway problem, so the message stays actionable even when the host's
// exact wording is not in Classify-NetRoute.
func gatewayHint(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "gateway") || strings.Contains(lower, "unreachable")
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the observed route for the exact triplet on the given
// interface, or (nil, nil) when the route — or its interface — is gone.
func (n *NetRouteClientImpl) Read(ctx context.Context, interfaceAlias, destinationPrefix, nextHop string) (*NetRouteInfo, error) {
	canonicalPrefix, canonicalNextHop, isV6, err := normalizeNetRouteTriplet(interfaceAlias, destinationPrefix, nextHop)
	if err != nil {
		return nil, err
	}
	alias := strings.TrimSpace(interfaceAlias)
	info, err := n.readSingleRoute(ctx, "read", alias, canonicalPrefix, canonicalNextHop, isV6)
	if err != nil {
		if IsNetRouteError(err, NetRouteErrorNotFound) ||
			IsNetRouteError(err, NetRouteErrorInterfaceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return info, nil
}

// ---------------------------------------------------------------------------
// Lookup (data source)
// ---------------------------------------------------------------------------

// Lookup lists every persistent route for destinationPrefix, optionally
// restricted to one interface alias and/or next hop. Zero matches return
// not_found; several matches return the whole list so the data source can
// deterministically pick the lowest effective metric. A whitespace-only
// alias is rejected instead of widening the lookup to all interfaces.
func (n *NetRouteClientImpl) Lookup(ctx context.Context, destinationPrefix, interfaceAlias, nextHop string) ([]*NetRouteInfo, error) {
	p, perr := netip.ParsePrefix(strings.TrimSpace(destinationPrefix))
	if perr != nil {
		return nil, NewNetRouteError(NetRouteErrorInvalidRoute,
			fmt.Sprintf("destination prefix %q is not a valid CIDR prefix", destinationPrefix), nil,
			map[string]string{"destination_prefix": destinationPrefix})
	}
	canonicalPrefix := p.Masked().String()
	alias := strings.TrimSpace(interfaceAlias)
	if interfaceAlias != "" && alias == "" {
		return nil, NewNetRouteError(NetRouteErrorInterfaceNotFound,
			"interface alias must not be blank; omit it to search all interfaces", nil,
			map[string]string{"destination_prefix": canonicalPrefix})
	}
	canonicalNextHop := ""
	if strings.TrimSpace(nextHop) != "" {
		nh, nerr := netip.ParseAddr(strings.TrimSpace(nextHop))
		if nerr != nil {
			return nil, NewNetRouteError(NetRouteErrorInvalidRoute,
				fmt.Sprintf("next hop %q is not a valid IPv4 or IPv6 address", nextHop), nil,
				map[string]string{"next_hop": nextHop})
		}
		canonicalNextHop = nh.Unmap().String()
		if familyMismatch(canonicalPrefix, canonicalNextHop) {
			return nil, NewNetRouteError(NetRouteErrorInvalidRoute,
				fmt.Sprintf("destination prefix %q and next hop %q disagree on the address family", canonicalPrefix, canonicalNextHop), nil,
				map[string]string{"destination_prefix": canonicalPrefix, "next_hop": canonicalNextHop})
		}
	}
	resp, err := n.runNetRouteEnvelope(ctx, "lookup",
		buildNetRouteLookupScript(canonicalPrefix, alias, canonicalNextHop),
		map[string]string{"destination_prefix": canonicalPrefix, "interface_alias": alias, "next_hop": canonicalNextHop})
	if err != nil {
		return nil, err
	}
	// The lookup script always emits an array (possibly one element).
	var arr []netRouteJSON
	if jerr := json.Unmarshal(resp.Data, &arr); jerr != nil {
		return nil, NewNetRouteError(NetRouteErrorUnknown,
			"failed to parse route lookup JSON", jerr,
			map[string]string{"destination_prefix": canonicalPrefix})
	}
	out := make([]*NetRouteInfo, 0, len(arr))
	for _, j := range arr {
		raw, _ := json.Marshal(j)
		info, perr := parseNetRouteInfo(raw, n.c.cfg.Host)
		if perr != nil {
			return nil, perr
		}
		out = append(out, info)
	}
	return out, nil
}

// familyMismatch reports whether prefix and next hop disagree on the
// address family. Both inputs must already be canonical netip spellings.
func familyMismatch(prefix, nextHop string) bool {
	p, perr := netip.ParsePrefix(strings.TrimSpace(prefix))
	nh, nerr := netip.ParseAddr(strings.TrimSpace(nextHop))
	if perr != nil || nerr != nil {
		return false
	}
	return nh.Unmap().Is4() == p.Addr().Is6()
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update changes the route metric in place via Set-NetRoute after the guard
// passes (exact-match refusal when this is the management route, hijack
// refusal when the new metric would win the selection).
func (n *NetRouteClientImpl) Update(ctx context.Context, interfaceAlias, destinationPrefix, nextHop string, routeMetric int, unsafeSkip bool) (*NetRouteInfo, error) {
	canonicalPrefix, canonicalNextHop, isV6, err := validateNetRouteInput(interfaceAlias, destinationPrefix, nextHop, routeMetric)
	if err != nil {
		return nil, err
	}
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling (see netRouteID).
	alias := strings.TrimSpace(interfaceAlias)

	ifIndex, ifMetric, err := n.resolveNetRouteInterface(ctx, alias, isV6)
	if err != nil {
		return nil, err
	}
	if _, err := n.readSingleRoute(ctx, "update_preflight", alias, canonicalPrefix, canonicalNextHop, isV6); err != nil {
		return nil, err
	}
	if err := n.ensureNetRouteManagementSafeForWrite(ctx, "update", alias, canonicalPrefix, canonicalNextHop, ifIndex, routeMetric, ifMetric, unsafeSkip); err != nil {
		return nil, err
	}

	resp, err := n.runNetRouteEnvelope(ctx, "update",
		buildNetRouteSetScript(alias, canonicalPrefix, canonicalNextHop, routeMetric, isV6),
		map[string]string{"interface_alias": alias, "destination_prefix": canonicalPrefix, "next_hop": canonicalNextHop})
	if err != nil {
		return nil, err
	}
	return parseNetRouteInfo(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the route via Remove-NetRoute after the guard passes. A
// missing route or interface is a successful no-op (nil).
func (n *NetRouteClientImpl) Delete(ctx context.Context, interfaceAlias, destinationPrefix, nextHop string, unsafeSkip bool) error {
	canonicalPrefix, canonicalNextHop, isV6, err := normalizeNetRouteTriplet(interfaceAlias, destinationPrefix, nextHop)
	if err != nil {
		return err
	}
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling (see splitNetRouteID).
	alias := strings.TrimSpace(interfaceAlias)

	ifIndex, _, err := n.resolveNetRouteInterface(ctx, alias, isV6)
	if err != nil {
		if IsNetRouteError(err, NetRouteErrorInterfaceNotFound) {
			return nil // interface already gone: nothing to remove
		}
		return err
	}
	if _, err := n.readSingleRoute(ctx, "delete_preflight", alias, canonicalPrefix, canonicalNextHop, isV6); err != nil {
		if IsNetRouteError(err, NetRouteErrorNotFound) {
			return nil // route already gone: nothing to remove
		}
		return err
	}
	if err := n.ensureNetRouteManagementSafeForDelete(ctx, alias, canonicalPrefix, canonicalNextHop, ifIndex, unsafeSkip); err != nil {
		return err
	}

	resp, err := n.runNetRouteEnvelope(ctx, "delete",
		buildNetRouteRemoveScript(alias, canonicalPrefix, canonicalNextHop, isV6),
		map[string]string{"interface_alias": alias, "destination_prefix": canonicalPrefix, "next_hop": canonicalNextHop})
	if err != nil {
		return err
	}
	_ = resp
	return nil
}
