// Package winclient - DNSClientClient is the concrete DNSClientClient
// backed by PowerShell over SSH.
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted
//     PowerShell literal with embedded single-quotes doubled); arrays via
//     psQuoteList; no raw concatenation of user input into PS scripts.
//   - No credentials are involved in DNS client management; none are written
//     to DNSClientError.Message or Context.
//
// Reused helpers from the same package:
//   - psQuote, psQuoteList      - safe PS string/array literals (psquote.go)
//   - runEnvelope               - shared JSON envelope pipeline (envelope.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Compile-time assertion: DNSClientClientImpl satisfies DNSClientClient.
var _ DNSClientClient = (*DNSClientClientImpl)(nil)

// DNSClientClientImpl is the PowerShell/SSH-backed DNSClientClient.
type DNSClientClientImpl struct {
	c *Client
}

// NewDNSClientClient wraps the given SSH Client.
func NewDNSClientClient(c *Client) *DNSClientClientImpl {
	return &DNSClientClientImpl{c: c}
}

// runDNSClientPowerShell is the package-level indirection used by
// DNSClientClientImpl. Tests may override it; production code must not.
var runDNSClientPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// psDNSClientHeader is prepended to every dns-client PS script. It pins the
// session culture to InvariantCulture so enum .ToString() values are always
// English regardless of the host locale, and defines the shared Emit-OK /
// Emit-Err / Classify-DnsClient helpers.
//
// Classify-DnsClient prefers HRESULT codes and cmdlet noun substrings over
// localized message text (hosts are not all English); substring matches
// remain as a backstop where no stable code exists.
const psDNSClientHeader = psEnvelopePrelude + psDNSClientHeaderRemainder

// psDNSClientHeaderRemainder Classify + ConvertTo-DnsClientJson stay here; envelope emitters come from the prelude. Emit depth 10->8: payloads are flat dicts and string lists.
const psDNSClientHeaderRemainder = `
function Classify-DnsClient([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  if ($code -eq '0x80070005' -or $msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess') { return 'permission_denied' }
  if ($msg -match 'No matching MSFT_DNSClient' -or $msg -match 'No MSFT_DNSClient' -or $msg -match 'No matching MSFT_NetAdapter' -or $msg -match 'No MSFT_NetAdapter') { return 'interface_not_found' }
  if ($code -eq '0x80070057' -or $msg -match 'is not a valid IP address' -or $msg -match 'Invalid.*[Aa]ddress') { return 'invalid_address' }
  if ($msg -match '[Ss]uffix') { return 'invalid_suffix' }
  return 'unknown'
}

function Test-DnsClientAccessDenied([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  if ($code -eq '0x80070005') { return $true }
  if ($msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess') { return $true }
  return $false
}

function Get-StaticDnsServers([string]$Guid, [string]$Stack) {
  $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $Stack + '\Parameters\Interfaces\' + $Guid
  try {
    $v = (Get-ItemProperty -Path $key -Name 'NameServer' -ErrorAction Stop).NameServer
  } catch {
    # A missing key or NameServer value means the family is automatic;
    # access-denied and other provider failures must surface instead of
    # masquerading as an empty (automatic) list.
    if (Test-DnsClientAccessDenied $_) { throw }
    $msg = ''
    try { $msg = [string]$_.Exception.Message } catch { $msg = [string]$_ }
    if ($msg -match 'does not exist' -or $msg -match 'cannot find' -or $msg -match 'No such') { return @() }
    throw
  }
  if ([string]::IsNullOrWhiteSpace([string]$v)) { return @() }
  return @(([string]$v -split '[,\s]+' | Where-Object { $_ -ne '' }))
}

function ConvertTo-DnsClientJson([object]$Client, [int]$IfIndex, [string]$Guid) {
  $eff4 = @()
  $eff6 = @()
  try {
    $rows = @(Get-DnsClientServerAddress -InterfaceIndex $IfIndex -ErrorAction Stop)
    foreach ($r in $rows) {
      $fam = [string]$r.AddressFamily
      if ($fam -eq '2' -or $fam -eq 'InterNetwork' -or $fam -eq 'IPv4') {
        $eff4 = @($r.ServerAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
      } elseif ($fam -eq '23' -or $fam -eq 'InterNetworkV6' -or $fam -eq 'IPv6') {
        $eff6 = @($r.ServerAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
      }
    }
  } catch {
    # An unreadable effective list is only benign when the interface
    # simply reports no addresses; access-denied failures must surface
    # instead of masquerading as an empty (automatic) list.
    if (Test-DnsClientAccessDenied $_) { throw }
  }
  $static4 = @()
  $static6 = @()
  if ($Guid -ne '') {
    $static4 = @(Get-StaticDnsServers $Guid 'Tcpip')
    $static6 = @(Get-StaticDnsServers $Guid 'Tcpip6')
  }
  $suffix = [string]$Client.ConnectionSpecificSuffix
  if ($null -eq $Client.ConnectionSpecificSuffix) { $suffix = '' }
  return [ordered]@{
    interface_alias                   = [string]$Client.InterfaceAlias
    interface_index                   = [int]$IfIndex
    interface_guid                    = [string]$Guid
    static_ipv4                       = [array]$static4
    static_ipv6                       = [array]$static6
    effective_ipv4                    = [array]$eff4
    effective_ipv6                    = [array]$eff6
    connection_specific_suffix        = $suffix
    register_this_connection_address  = [bool]$Client.RegisterThisConnectionsAddress
    use_suffix_when_registering       = [bool]$Client.UseSuffixWhenRegistering
  }
}
`

// dnsClientResolveFragment resolves $alias with an exact (-eq,
// case-insensitive, never wildcard) comparison against Get-DnsClient and
// stores the interface index in $ifIndex, the client row in $client and the
// adapter GUID in $guid (empty only when Get-NetAdapter has no row for the
// interface, e.g. pseudo-interfaces; any other lookup failure emits a typed
// error and returns). On failure it emits interface_not_found listing the
// valid aliases and returns.
const dnsClientResolveFragment = `
$client = Get-DnsClient -ErrorAction Stop | Where-Object { $_.InterfaceAlias -eq $alias } | Select-Object -First 1
if ($null -eq $client) {
  $valid = @(Get-DnsClient -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias -Unique | Sort-Object)
  Emit-Err 'interface_not_found' ('No interface matches alias ' + [string]$alias + '. Valid aliases: ' + ($valid -join ', ') + '.') @{ interface_alias = [string]$alias }
  return
}
$ifIndex = [int]$client.InterfaceIndex
$guid = ''
try {
  $adapter = Get-NetAdapter -InterfaceIndex $ifIndex -ErrorAction Stop
  $guid = [string]$adapter.InterfaceGuid
} catch {
  $guidMsg = ''
  try { $guidMsg = [string]$_.Exception.Message } catch { $guidMsg = [string]$_ }
  if ($guidMsg -match 'No matching MSFT_NetAdapter' -or $guidMsg -match 'No MSFT_NetAdapter') {
    $guid = ''
  } else {
    Emit-Err (Classify-DnsClient $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'resolve_guid' }
    return
  }
}
`

// ---------------------------------------------------------------------------
// Script builders (every user value via psQuote/psQuoteList; bools via tokens)
// ---------------------------------------------------------------------------

func dnsClientBoolToken(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// buildDNSClientReadScript renders a resolve + full state read.
// A missing interface emits interface_not_found; registry or lookup
// failures emit a typed error instead of an empty (automatic) state.
func buildDNSClientReadScript(alias string) string {
	return psDNSClientHeader + fmt.Sprintf(`
$alias = %s
& {
%s
  try {
    Emit-OK (ConvertTo-DnsClientJson $client $ifIndex $guid)
  } catch {
    Emit-Err (Classify-DnsClient $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'read' }
    return
  }
}
`, psQuote(alias), dnsClientResolveFragment)
}

// buildDNSClientApplyScript renders the idempotent write: resolve, read the
// current static lists, merge unmanaged families from observed state, write
// server addresses (Set-DnsClientServerAddress, -ResetServerAddresses when
// the merged list is empty), write suffix/flags (Set-DnsClient) only for the
// managed attributes, then read back.
//
// Because Set-DnsClientServerAddress replaces the server list across
// families, unmanaged families keep their observed static addresses via a
// cross-family read-modify-write. Resetting one family while keeping the
// other resets all addresses first and then re-adds the preserved family,
// so the reset family cannot linger when only the other family is written.
func buildDNSClientApplyScript(alias string, s DNSClientSettings) string {
	return psDNSClientHeader + fmt.Sprintf(`
$alias = %s
$wantV4Set = %s
$wantV4 = %s
$wantV6Set = %s
$wantV6 = %s
$suffixSet = %s
$suffix = %s
$regSet = %s
$reg = %s
$useSet = %s
$use = %s
& {
%s
  $curV4 = @()
  $curV6 = @()
  if ($guid -ne '') {
    try {
      $curV4 = @(Get-StaticDnsServers $guid 'Tcpip')
      $curV6 = @(Get-StaticDnsServers $guid 'Tcpip6')
    } catch {
      Emit-Err (Classify-DnsClient $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'read_current' }
      return
    }
  }
  if ($wantV4Set -or $wantV6Set) {
    $merged = @()
    if ($wantV4Set) { $merged += @($wantV4) } else { $merged += @($curV4) }
    if ($wantV6Set) { $merged += @($wantV6) } else { $merged += @($curV6) }
    $resetV4 = ($wantV4Set -and $wantV4.Count -eq 0)
    $resetV6 = ($wantV6Set -and $wantV6.Count -eq 0)
    $singleFamilyReset = ((($resetV4 -and -not $resetV6) -or ($resetV6 -and -not $resetV4)) -and ($merged.Count -gt 0))
    try {
      if ($merged.Count -eq 0) {
        $null = Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ResetServerAddresses -ErrorAction Stop
      } else {
        if ($singleFamilyReset) {
          # Single-family reset: reset all addresses first, then re-add the
          # preserved family, so the reset family cannot linger.
          $null = Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ResetServerAddresses -ErrorAction Stop
        }
        $null = Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $merged -ErrorAction Stop
      }
    } catch {
      Emit-Err (Classify-DnsClient $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'set_server_addresses' }
      return
    }
  }
  if ($suffixSet -or $regSet -or $useSet) {
    try {
      $p = @{ InterfaceIndex = $ifIndex; ErrorAction = 'Stop' }
      if ($suffixSet) { $p['ConnectionSpecificSuffix'] = [string]$suffix }
      if ($regSet) { $p['RegisterThisConnectionsAddress'] = [bool]$reg }
      if ($useSet) { $p['UseSuffixWhenRegistering'] = [bool]$use }
      $null = Set-DnsClient @p
    } catch {
      Emit-Err (Classify-DnsClient $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'set_dns_client' }
      return
    }
  }
  try {
    $fresh = Get-DnsClient -ErrorAction Stop | Where-Object { $_.InterfaceAlias -eq $alias } | Select-Object -First 1
  } catch {
    Emit-Err (Classify-DnsClient $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'readback' }
    return
  }
  if ($null -eq $fresh) {
    Emit-Err 'interface_not_found' ('No interface matches alias ' + [string]$alias + '.') @{ interface_alias = [string]$alias }
    return
  }
  try {
    Emit-OK (ConvertTo-DnsClientJson $fresh $ifIndex $guid)
  } catch {
    Emit-Err (Classify-DnsClient $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'readback' }
    return
  }
}
`, psQuote(alias),
		dnsClientBoolToken(s.IPv4Set), psQuoteList(s.IPv4Addresses),
		dnsClientBoolToken(s.IPv6Set), psQuoteList(s.IPv6Addresses),
		dnsClientBoolToken(s.SuffixSet), psQuote(dnsClientSuffixOrEmpty(s)),
		dnsClientBoolToken(s.RegisterThisConnectionAddress != nil), dnsClientBoolToken(dnsClientBoolOrFalse(s.RegisterThisConnectionAddress)),
		dnsClientBoolToken(s.UseSuffixWhenRegistering != nil), dnsClientBoolToken(dnsClientBoolOrFalse(s.UseSuffixWhenRegistering)),
		dnsClientResolveFragment)
}

// dnsClientSuffixOrEmpty renders the suffix for interpolation ("" when
// unmanaged; the $suffixSet flag guards its use).
func dnsClientSuffixOrEmpty(s DNSClientSettings) string {
	if s.ConnectionSpecificSuffix == nil {
		return ""
	}
	return *s.ConnectionSpecificSuffix
}

// dnsClientBoolOrFalse dereferences an optional bool (false when unmanaged;
// the corresponding *Set flag guards its use).
func dnsClientBoolOrFalse(b *bool) bool {
	return b != nil && *b
}

// ---------------------------------------------------------------------------
// Client-side input validation (defence in depth; the schema validates first)
// ---------------------------------------------------------------------------

// ValidateDNSClientAlias rejects blank aliases before any remote call, as
// well as aliases carrying whitespace/control characters: Windows interface
// aliases never contain them, and a truncated alias would match the wrong
// interface (or none) at apply time.
func ValidateDNSClientAlias(alias string) error {
	if strings.TrimSpace(alias) == "" {
		return NewDNSClientError(DNSClientErrorInterfaceNotFound,
			"interface alias must not be empty", nil, nil)
	}
	if strings.IndexFunc(alias, isControlRune) >= 0 {
		return NewDNSClientError(DNSClientErrorInterfaceNotFound,
			"interface alias must not contain control characters", nil, nil)
	}
	return nil
}

// validateDNSClientServerAddress parses one server address, enforces its
// family, and rejects values that can never be a DNS server: unparsable,
// zone IDs, unspecified, multicast and limited IPv4 broadcast
// (255.255.255.255). Loopback addresses are allowed (a local resolver is a
// legitimate forwarder target).
func validateDNSClientServerAddress(raw string, wantV6 bool) (string, error) {
	family := "IPv4"
	if wantV6 {
		family = "IPv6"
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", NewDNSClientError(DNSClientErrorInvalidAddress,
			fmt.Sprintf("DNS server address %q is not a valid IP address", raw), nil,
			map[string]string{"server_address": raw})
	}
	if zone := addr.Zone(); zone != "" {
		return "", NewDNSClientError(DNSClientErrorInvalidAddress,
			fmt.Sprintf("DNS server address %q must not carry a zone ID (%q)", raw, zone), nil,
			map[string]string{"server_address": raw})
	}
	addr = addr.Unmap()
	isV6 := addr.Is6()
	if isV6 != wantV6 {
		return "", NewDNSClientError(DNSClientErrorInvalidAddress,
			fmt.Sprintf("DNS server address %q is not an %s address", raw, family), nil,
			map[string]string{"server_address": raw})
	}
	switch {
	case addr.IsUnspecified():
		return "", NewDNSClientError(DNSClientErrorInvalidAddress,
			fmt.Sprintf("DNS server address %q is the unspecified address", raw), nil,
			map[string]string{"server_address": raw})
	case addr.IsMulticast():
		return "", NewDNSClientError(DNSClientErrorInvalidAddress,
			fmt.Sprintf("DNS server address %q is a multicast address", raw), nil,
			map[string]string{"server_address": raw})
	case addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "", NewDNSClientError(DNSClientErrorInvalidAddress,
			fmt.Sprintf("DNS server address %q is the limited IPv4 broadcast address (255.255.255.255)", raw), nil,
			map[string]string{"server_address": raw})
	}
	// Canonicalise (lower-case, compressed IPv6) but preserve the
	// configured order: the host serves addresses first-answer-wins.
	return addr.String(), nil
}

// ValidateDNSClientServerAddresses parses and canonicalises one family's
// server list (order preserved), rejecting duplicates after
// canonicalisation.
func ValidateDNSClientServerAddresses(addrs []string, wantV6 bool) ([]string, error) {
	family := "IPv4"
	if wantV6 {
		family = "IPv6"
	}
	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, raw := range addrs {
		canonical, err := validateDNSClientServerAddress(raw, wantV6)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[canonical]; dup {
			return nil, NewDNSClientError(DNSClientErrorInvalidAddress,
				fmt.Sprintf("duplicate %s DNS server address %q", family, raw), nil,
				map[string]string{"server_address": raw})
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

// ValidateDNSClientSuffix checks the connection-specific suffix against DNS
// name rules: total length, label length, charset and placement. A single
// label (e.g. "corp") is accepted. An empty suffix is rejected here; clearing
// the suffix is a destroy-time operation, not a configured value.
func ValidateDNSClientSuffix(suffix string) error {
	if suffix == "" {
		return NewDNSClientError(DNSClientErrorInvalidSuffix,
			"connection-specific suffix must not be empty; omit it to leave the suffix unmanaged", nil, nil)
	}
	if len(suffix) > 253 {
		return NewDNSClientError(DNSClientErrorInvalidSuffix,
			fmt.Sprintf("connection-specific suffix %q exceeds 253 characters", suffix), nil,
			map[string]string{"connection_specific_suffix": suffix})
	}
	for _, label := range strings.Split(suffix, ".") {
		if label == "" {
			return NewDNSClientError(DNSClientErrorInvalidSuffix,
				fmt.Sprintf("connection-specific suffix %q contains an empty label", suffix), nil,
				map[string]string{"connection_specific_suffix": suffix})
		}
		if len(label) > 63 {
			return NewDNSClientError(DNSClientErrorInvalidSuffix,
				fmt.Sprintf("connection-specific suffix %q contains a label exceeding 63 characters", suffix), nil,
				map[string]string{"connection_specific_suffix": suffix})
		}
		if len(label) == 1 {
			if !isDNSNameChar(label[0]) {
				return NewDNSClientError(DNSClientErrorInvalidSuffix,
					fmt.Sprintf("connection-specific suffix %q contains invalid character %q", suffix, label), nil,
					map[string]string{"connection_specific_suffix": suffix})
			}
			continue
		}
		if !isDNSNameChar(label[0]) || !isDNSNameChar(label[len(label)-1]) ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return NewDNSClientError(DNSClientErrorInvalidSuffix,
				fmt.Sprintf("connection-specific suffix %q has a label that must start and end with a letter or digit", suffix), nil,
				map[string]string{"connection_specific_suffix": suffix})
		}
		for i := 1; i < len(label)-1; i++ {
			c := label[i]
			if !isDNSNameChar(c) && c != '-' {
				return NewDNSClientError(DNSClientErrorInvalidSuffix,
					fmt.Sprintf("connection-specific suffix %q contains invalid character %q", suffix, string(c)), nil,
					map[string]string{"connection_specific_suffix": suffix})
			}
		}
	}
	return nil
}

// isDNSNameChar reports whether c is an ASCII letter or digit.
func isDNSNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// validateDNSClientSettings re-validates every managed attribute before any
// remote call and returns the canonicalised settings (order preserved).
func validateDNSClientSettings(s DNSClientSettings) (DNSClientSettings, error) {
	out := s
	if s.IPv4Set {
		canonical, err := ValidateDNSClientServerAddresses(nullToEmpty(s.IPv4Addresses), false)
		if err != nil {
			return DNSClientSettings{}, err
		}
		out.IPv4Addresses = canonical
	}
	if s.IPv6Set {
		canonical, err := ValidateDNSClientServerAddresses(nullToEmpty(s.IPv6Addresses), true)
		if err != nil {
			return DNSClientSettings{}, err
		}
		out.IPv6Addresses = canonical
	}
	if s.SuffixSet {
		if s.ConnectionSpecificSuffix == nil {
			return DNSClientSettings{}, NewDNSClientError(DNSClientErrorInvalidSuffix,
				"connection-specific suffix is marked managed but has no value", nil, nil)
		}
		if *s.ConnectionSpecificSuffix != "" {
			if err := ValidateDNSClientSuffix(*s.ConnectionSpecificSuffix); err != nil {
				return DNSClientSettings{}, err
			}
		}
	}
	return out, nil
}

// nullToEmpty normalises a nil slice to an empty one so validation and
// script rendering treat "managed but empty" uniformly.
func nullToEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// dnsClientJSON mirrors the JSON object emitted by
// ConvertTo-DnsClientJson.
type dnsClientJSON struct {
	InterfaceAlias                string   `json:"interface_alias"`
	InterfaceIndex                int      `json:"interface_index"`
	InterfaceGUID                 string   `json:"interface_guid"`
	StaticIPv4                    []string `json:"static_ipv4"`
	StaticIPv6                    []string `json:"static_ipv6"`
	EffectiveIPv4                 []string `json:"effective_ipv4"`
	EffectiveIPv6                 []string `json:"effective_ipv6"`
	ConnectionSpecificSuffix      string   `json:"connection_specific_suffix"`
	RegisterThisConnectionAddress bool     `json:"register_this_connection_address"`
	UseSuffixWhenRegistering      bool     `json:"use_suffix_when_registering"`
}

// runDNSClientEnvelope executes script (prefixed with psDNSClientHeader by
// the builders) and parses the JSON envelope through the shared runEnvelope
// helper. Transport/timeout failures map to unreachable; remote Emit-Err
// kinds map via mapDNSClientKind.
func (n *DNSClientClientImpl) runDNSClientEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
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
			return runDNSClientPowerShell(ctx, n.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout || eerr.Stage == EnvelopeStageTransport {
		return nil, NewDNSClientError(DNSClientErrorUnreachable, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewDNSClientError(DNSClientErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewDNSClientError(mapDNSClientKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapDNSClientKind translates a PS-side "kind" string to a typed
// DNSClientErrorKind. Unknown values fall through to Unknown.
func mapDNSClientKind(k string) DNSClientErrorKind {
	switch DNSClientErrorKind(k) {
	case DNSClientErrorInterfaceNotFound,
		DNSClientErrorInvalidAddress,
		DNSClientErrorInvalidSuffix,
		DNSClientErrorPermission:
		return DNSClientErrorKind(k)
	default:
		return DNSClientErrorUnknown
	}
}

// parseDNSClientState projects a dnsClientJSON payload onto a DNSClientState,
// canonicalising every address (order preserved). A host value that cannot
// parse or lands in the wrong family fails the operation with a typed
// unknown error instead of being silently dropped.
func parseDNSClientState(raw json.RawMessage, host string) (*DNSClientState, error) {
	var j dnsClientJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, NewDNSClientError(DNSClientErrorUnknown,
			"failed to parse DNS client state JSON", err,
			map[string]string{"host": host, "raw": truncate(string(raw), 512)})
	}
	static4, err := canonicaliseAll(j.StaticIPv4, false, host)
	if err != nil {
		return nil, err
	}
	static6, err := canonicaliseAll(j.StaticIPv6, true, host)
	if err != nil {
		return nil, err
	}
	eff4, err := canonicaliseAll(j.EffectiveIPv4, false, host)
	if err != nil {
		return nil, err
	}
	eff6, err := canonicaliseAll(j.EffectiveIPv6, true, host)
	if err != nil {
		return nil, err
	}
	return &DNSClientState{
		InterfaceAlias:                j.InterfaceAlias,
		InterfaceIndex:                j.InterfaceIndex,
		InterfaceGUID:                 j.InterfaceGUID,
		StaticIPv4:                    static4,
		StaticIPv6:                    static6,
		EffectiveIPv4:                 eff4,
		EffectiveIPv6:                 eff6,
		ConnectionSpecificSuffix:      j.ConnectionSpecificSuffix,
		RegisterThisConnectionAddress: j.RegisterThisConnectionAddress,
		UseSuffixWhenRegistering:      j.UseSuffixWhenRegistering,
	}, nil
}

// canonicaliseAll canonicalises each address via netip (order preserved,
// empty normalised to an empty non-nil slice). An unparsable host value is
// a typed unknown error: the host returned something the client cannot
// represent.
func canonicaliseAll(in []string, wantV6 bool, host string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return nil, NewDNSClientError(DNSClientErrorUnknown,
				fmt.Sprintf("host returned an unparsable DNS server address %q", raw), nil,
				map[string]string{"host": host})
		}
		addr = addr.Unmap()
		if wantV6 && !addr.Is6() {
			return nil, NewDNSClientError(DNSClientErrorUnknown,
				fmt.Sprintf("host returned non-IPv6 address %q in the IPv6 server list", raw), nil,
				map[string]string{"host": host})
		}
		if !wantV6 && !addr.Is4() {
			return nil, NewDNSClientError(DNSClientErrorUnknown,
				fmt.Sprintf("host returned non-IPv4 address %q in the IPv4 server list", raw), nil,
				map[string]string{"host": host})
		}
		out = append(out, addr.String())
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the observed DNS client state of the named interface, or
// (nil, nil) when the interface is gone (renamed or removed).
func (n *DNSClientClientImpl) Read(ctx context.Context, interfaceAlias string) (*DNSClientState, error) {
	if err := ValidateDNSClientAlias(interfaceAlias); err != nil {
		return nil, err
	}
	// Host operations use the trimmed alias; the resource ID keeps the
	// configured spelling.
	alias := strings.TrimSpace(interfaceAlias)
	resp, err := n.runDNSClientEnvelope(ctx, "read",
		buildDNSClientReadScript(alias),
		map[string]string{"interface_alias": alias})
	if err != nil {
		if IsDNSClientError(err, DNSClientErrorInterfaceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseDNSClientState(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Apply (Create and Update share this idempotent path)
// ---------------------------------------------------------------------------

// Apply writes the managed attributes and reads the resulting state back.
// Unmanaged attributes are left untouched via the cross-family
// read-modify-write in the script. Setting values identical to the observed
// state is a successful round trip.
func (n *DNSClientClientImpl) Apply(ctx context.Context, interfaceAlias string, settings DNSClientSettings) (*DNSClientState, error) {
	if err := ValidateDNSClientAlias(interfaceAlias); err != nil {
		return nil, err
	}
	canonical, err := validateDNSClientSettings(settings)
	if err != nil {
		return nil, err
	}
	alias := strings.TrimSpace(interfaceAlias)
	resp, err := n.runDNSClientEnvelope(ctx, "apply",
		buildDNSClientApplyScript(alias, canonical),
		map[string]string{"interface_alias": alias})
	if err != nil {
		return nil, err
	}
	return parseDNSClientState(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Reset (destroy with reset_on_destroy)
// ---------------------------------------------------------------------------

// Reset returns the given families to automatic (DHCP) and, when
// clearSuffix is true, clears the connection-specific suffix. Flags are left
// untouched. A missing interface is a successful no-op (nil).
func (n *DNSClientClientImpl) Reset(ctx context.Context, interfaceAlias string, resetIPv4, resetIPv6, clearSuffix bool) (*DNSClientState, error) {
	if err := ValidateDNSClientAlias(interfaceAlias); err != nil {
		return nil, err
	}
	if !resetIPv4 && !resetIPv6 && !clearSuffix {
		return n.Read(ctx, interfaceAlias)
	}
	settings := DNSClientSettings{}
	if resetIPv4 {
		settings.IPv4Set = true
		settings.IPv4Addresses = []string{}
	}
	if resetIPv6 {
		settings.IPv6Set = true
		settings.IPv6Addresses = []string{}
	}
	if clearSuffix {
		settings.SuffixSet = true
		empty := ""
		settings.ConnectionSpecificSuffix = &empty
	}
	alias := strings.TrimSpace(interfaceAlias)
	resp, err := n.runDNSClientEnvelope(ctx, "reset",
		buildDNSClientApplyScript(alias, settings),
		map[string]string{"interface_alias": alias})
	if err != nil {
		if IsDNSClientError(err, DNSClientErrorInterfaceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseDNSClientState(resp.Data, n.c.cfg.Host)
}
