// Package winclient - NetworkAdaptersClient is the concrete
// WindowsNetworkAdaptersClient backed by PowerShell over SSH.
//
// Security invariants:
//   - Only the name list is interpolated into the PS script, via psQuoteList
//     (single-quoted PowerShell literals); bools travel as $true/$false
//     literals. Regex, MAC and status filters never reach the host: they are
//     applied Go-side (Get-NetAdapter -Name is wildcard-capable, so names are
//     re-matched exactly Go-side too).
//   - No credentials are involved in adapter inventory; none are written to
//     NetworkAdapterError.Message or Context.
//   - Scripts never call "exit": since #81 a script may run inside a
//     long-lived, reused PowerShell session, where "exit" would kill that
//     session instead of just this call. Early returns use "return" after
//     Emit-Err instead.
//
// Reused helpers from the same package:
//   - psQuote, psQuoteList      - safe PS string/array literals (psquote.go)
//   - runEnvelope               - shared JSON envelope pipeline (envelope.go)
//   - ManagementPath            - shared SSH management-path guard (mgmtpath.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Compile-time assertion: NetworkAdaptersClient satisfies
// WindowsNetworkAdaptersClient.
var _ WindowsNetworkAdaptersClient = (*NetworkAdaptersClient)(nil)

// NetworkAdaptersClient is the PowerShell/SSH-backed
// WindowsNetworkAdaptersClient.
type NetworkAdaptersClient struct {
	c *Client
}

// NewNetworkAdaptersClient wraps the given SSH Client.
func NewNetworkAdaptersClient(c *Client) *NetworkAdaptersClient {
	return &NetworkAdaptersClient{c: c}
}

// runNetworkAdaptersPowerShell is the package-level indirection used by
// NetworkAdaptersClient. Tests may override it; production code must not.
var runNetworkAdaptersPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// networkAdaptersManagementPath is the package-level indirection for the
// shared management-path probe. Tests may override it; production code must
// not.
var networkAdaptersManagementPath = func(ctx context.Context, c *Client) (*ManagementPath, error) {
	return c.ManagementPath(ctx)
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// psNetworkAdaptersHeader is prepended to the network-adapters PS script. It
// pins the session culture to InvariantCulture so enum .ToString() values are
// always English regardless of the host locale, and defines the shared
// Emit-OK / Emit-Err / Classify-NetworkAdapters helpers plus the safe
// property readers (Get-NetAdapter object shapes vary by driver and build,
// so every optional property degrades to its zero value instead of failing
// the whole listing).
//
// Classify-NetworkAdapters prefers HRESULT codes and cmdlet noun substrings
// over localized message text (hosts are not all English); the CIM token
// list is word-anchored like Classify-OSInfo so prose containing "cim" as a
// substring does not misfire.
const psNetworkAdaptersHeader = `
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

function Classify-NetworkAdapters([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  if ($code -eq '0x80070005' -or $msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess') { return 'access_denied' }
  if ($msg -match 'winmgmt' -or $msg -match '\bWMI\b' -or $msg -match '\bCIM\b' -or $msg -match 'CimException' -or $msg -match 'Get-CimInstance' -or $msg -match 'Get-NetAdapter' -or $msg -match '\brepository\b' -or $msg -match 'provider load failure') { return 'cim_unavailable' }
  return 'unknown'
}

function Get-IntProp([object]$Obj, [string]$Name, [int]$Default) {
  try {
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return [int]$p.Value
  } catch { return $Default }
}

function Get-Int64Prop([object]$Obj, [string]$Name, [int64]$Default) {
  try {
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return [int64]$p.Value
  } catch { return $Default }
}

function Get-StrProp([object]$Obj, [string]$Name) {
  try {
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return '' }
    return [string]$p.Value
  } catch { return '' }
}

function Get-BoolProp([object]$Obj, [string]$Name, [bool]$Default) {
  try {
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return [bool]$p.Value
  } catch { return $Default }
}
`

// psNetworkAdaptersBody defines List-NetworkAdapters: one round-trip that
// collects Get-NetAdapter plus every bulk collection exactly once and joins
// them by interface index in PowerShell. Only the name list and the two
// bools are interpolated (buildNetworkAdaptersListScript); every row is
// emitted with numeric status codes so the Go side owns the status/media
// mapping tables and the MAC/CIDR canonicalisation.
//
// Per-adapter lookups inside the loop are hashtable reads only: no cmdlet
// runs per adapter.
const psNetworkAdaptersBody = `
function List-NetworkAdapters([string[]]$Names, [bool]$PhysicalOnly, [bool]$IncludeHidden) {
  $splat = @{}
  if ($Names.Count -gt 0) { $splat['Name'] = $Names }
  if ($PhysicalOnly) { $splat['Physical'] = $true }
  if ($IncludeHidden) { $splat['IncludeHidden'] = $true }
  try {
    $adapters = @(Get-NetAdapter @splat -ErrorAction Stop)
  } catch {
    # A names filter matching nothing throws a CimCmdlets query-not-found
    # record (CategoryInfo ObjectNotFound,
    # FullyQualifiedErrorId ..._NotFound/CmdletizationQuery_NotFound,
    # "No MSFT_NetAdapter objects found ..."). That is an empty inventory,
    # not an error: emit an empty collection and return (single round-trip,
    # no second host call). Mirrors the smb_share not_found patterns.
    $naRec = $_
    $naCat = [string]$naRec.CategoryInfo.Category
    $naFid = [string]$naRec.FullyQualifiedErrorId
    $naMsg = ''
    try { $naMsg = [string]$naRec.Exception.Message } catch { $naMsg = [string]$naRec }
    if ($naCat -match 'ObjectNotFound' -or $naFid -match 'NotFound|CmdletizationQuery_NotFound' -or $naMsg -match 'No MSFT_NetAdapter objects found') {
      Emit-OK @()
      return
    }
    Emit-Err (Classify-NetworkAdapters $_) ([string]$_.Exception.Message) @{ step = 'adapters' }
    return
  }
  try {
    $ipIfaces = @(Get-NetIPInterface -ErrorAction Stop)
  } catch {
    Emit-Err (Classify-NetworkAdapters $_) ([string]$_.Exception.Message) @{ step = 'ip_interfaces' }
    return
  }
  try {
    $ipAddrs = @(Get-NetIPAddress -ErrorAction Stop)
  } catch {
    Emit-Err (Classify-NetworkAdapters $_) ([string]$_.Exception.Message) @{ step = 'ip_addresses' }
    return
  }
  # Default routes are queried one family at a time with
  # SilentlyContinue: a host without a gateway (or with a stack disabled)
  # matches no row for that prefix, which must yield an empty gateway list
  # rather than fail the whole listing.
  $routes = @()
  foreach ($pfx in @('0.0.0.0/0', '::/0')) {
    $routes += @(Get-NetRoute -DestinationPrefix $pfx -ErrorAction SilentlyContinue)
  }
  try {
    $dnsRows = @(Get-DnsClientServerAddress -ErrorAction Stop)
  } catch {
    Emit-Err (Classify-NetworkAdapters $_) ([string]$_.Exception.Message) @{ step = 'dns' }
    return
  }
  try {
    $profiles = @(Get-NetConnectionProfile -ErrorAction Stop)
  } catch {
    Emit-Err (Classify-NetworkAdapters $_) ([string]$_.Exception.Message) @{ step = 'profiles' }
    return
  }

  $byIface = @{}
  foreach ($r in $ipIfaces) {
    $i = [int]$r.InterfaceIndex
    if (-not $byIface.ContainsKey($i)) { $byIface[$i] = @() }
    $byIface[$i] += $r
  }
  $byAddr = @{}
  foreach ($r in $ipAddrs) {
    $i = [int]$r.InterfaceIndex
    if (-not $byAddr.ContainsKey($i)) { $byAddr[$i] = @() }
    $byAddr[$i] += ([string]$r.IPAddress + '/' + [string]$r.PrefixLength)
  }
  $byRoute = @{}
  foreach ($r in $routes) {
    $i = [int]$r.InterfaceIndex
    if (-not $byRoute.ContainsKey($i)) { $byRoute[$i] = @() }
    $byRoute[$i] += [string]$r.NextHop
  }
  $byDNS = @{}
  foreach ($r in $dnsRows) {
    $i = [int]$r.InterfaceIndex
    if (-not $byDNS.ContainsKey($i)) { $byDNS[$i] = @() }
    foreach ($s in $r.ServerAddresses) {
      $t = [string]$s
      if ($t -ne '') { $byDNS[$i] += $t }
    }
  }
  $byProfile = @{}
  foreach ($r in $profiles) {
    $i = [int]$r.InterfaceIndex
    if (-not $byProfile.ContainsKey($i)) { $byProfile[$i] = [string]$r.NetworkCategory }
  }

  $out = @()
  foreach ($a in $adapters) {
    $ifIndex = [int]$a.InterfaceIndex
    $mtu4 = 0
    $mtu6 = 0
    $dhcp = $false
    if ($byIface.ContainsKey($ifIndex)) {
      foreach ($ii in $byIface[$ifIndex]) {
        $fam = [string]$ii.AddressFamily
        if ($fam -eq '2' -or $fam -eq 'InterNetwork' -or $fam -eq 'IPv4') {
          try { $mtu4 = [int]$ii.NlMtu } catch { $mtu4 = 0 }
          try { if ([string]$ii.Dhcp -eq 'Enabled') { $dhcp = $true } } catch { }
        } elseif ($fam -eq '23' -or $fam -eq 'InterNetworkV6' -or $fam -eq 'IPv6') {
          try { $mtu6 = [int]$ii.NlMtu } catch { $mtu6 = 0 }
        }
      }
    }
    $v4 = @()
    $v6 = @()
    if ($byAddr.ContainsKey($ifIndex)) {
      foreach ($c in $byAddr[$ifIndex]) {
        if ($c -match ':') { $v6 += $c } else { $v4 += $c }
      }
    }
    $gw = @()
    if ($byRoute.ContainsKey($ifIndex)) { $gw = @($byRoute[$ifIndex]) }
    $dns = @()
    if ($byDNS.ContainsKey($ifIndex)) { $dns = @($byDNS[$ifIndex]) }
    $cat = ''
    if ($byProfile.ContainsKey($ifIndex)) { $cat = $byProfile[$ifIndex] }
    $out += [ordered]@{
      name                  = [string]$a.Name
      interface_index       = $ifIndex
      interface_description = [string]$a.InterfaceDescription
      mac_address           = (Get-StrProp $a 'MacAddress')
      oper_status           = (Get-IntProp $a 'InterfaceOperationalStatus' 0)
      media_state           = (Get-IntProp $a 'MediaConnectState' 0)
      admin_status          = (Get-IntProp $a 'AdminStatus' 0)
      link_speed_bps        = (Get-Int64Prop $a 'ReceiveLinkSpeed' 0)
      ndis_medium           = (Get-IntProp $a 'NdisMedium' -1)
      ndis_physical_medium  = (Get-IntProp $a 'NdisPhysicalMedium' -1)
      is_virtual            = (Get-BoolProp $a 'Virtual' $false)
      vlan_id               = (Get-IntProp $a 'VlanID' 0)
      driver_description    = (Get-StrProp $a 'DriverDescription')
      driver_version        = (Get-StrProp $a 'DriverVersion')
      driver_provider       = (Get-StrProp $a 'DriverProvider')
      mtu_ipv4              = $mtu4
      mtu_ipv6              = $mtu6
      dhcp_enabled          = $dhcp
      ipv4_addresses        = $v4
      ipv6_addresses        = $v6
      default_gateways      = $gw
      dns_servers           = $dns
      network_category      = $cat
    }
  }
  Emit-OK $out
}
`

// ---------------------------------------------------------------------------
// Script builder (only names/bools interpolated; bools as literals)
// ---------------------------------------------------------------------------

// networkAdaptersBoolToken renders a Go bool as a PowerShell literal.
func networkAdaptersBoolToken(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// buildNetworkAdaptersListScript renders the single-round-trip inventory
// script. Names travel via psQuoteList; regex, MAC and status filters never
// reach the host (Go-side).
func buildNetworkAdaptersListScript(names []string, physicalOnly, includeHidden bool) string {
	trimmed := make([]string, 0, len(names))
	for _, n := range names {
		if strings.TrimSpace(n) != "" {
			trimmed = append(trimmed, strings.TrimSpace(n))
		}
	}
	return psNetworkAdaptersHeader + psNetworkAdaptersBody + fmt.Sprintf(`
$Names = %s
$PhysicalOnly = %s
$IncludeHidden = %s
List-NetworkAdapters -Names $Names -PhysicalOnly $PhysicalOnly -IncludeHidden $IncludeHidden
`, psQuoteList(trimmed), networkAdaptersBoolToken(physicalOnly), networkAdaptersBoolToken(includeHidden))
}

// ---------------------------------------------------------------------------
// Status and media mapping tables (Go-side; numeric sources only)
// ---------------------------------------------------------------------------

// deriveNetworkAdapterStatus maps the numeric triple to a status string.
//
// InterfaceOperationalStatus: 1 Up, 2 Down, 3 Testing, 4 Unknown, 5 Dormant,
// 6 NotPresent, 7 LowerLayerDown. MediaConnectState: 1 Connected,
// 2 Disconnected. AdminStatus: 1 Up, 2 Down (3 Testing counts as up).
//
// A disabled adapter reports Disabled even when its media is connected; a
// missing or lower-layer-down adapter reports NotPresent; anything that is
// neither administratively down nor physically gone but cannot carry traffic
// (disconnected media, Down oper state, Testing/Unknown/Dormant states)
// reports Disconnected.
func deriveNetworkAdapterStatus(oper, media, admin int) string {
	if admin == 2 {
		return "Disabled"
	}
	if oper == 6 || oper == 7 {
		return "NotPresent"
	}
	if media == 2 || oper == 2 {
		return "Disconnected"
	}
	if oper == 1 && media == 1 {
		return "Up"
	}
	return "Disconnected"
}

// networkAdapterMediaType maps an NdisMedium value to its documented name.
// Unknown values degrade to "" instead of erroring.
func networkAdapterMediaType(raw int) string {
	switch raw {
	case 0:
		return "802.3"
	case 1:
		return "802.5"
	case 2:
		return "Fddi"
	case 3:
		return "Wan"
	case 4:
		return "LocalTalk"
	case 5:
		return "Dix"
	case 6:
		return "ArcnetRaw"
	case 7:
		return "Arcnet878.2"
	case 8:
		return "Atm"
	case 9:
		return "WirelessWan"
	case 10:
		return "Irda"
	case 11:
		return "Bpc"
	case 12:
		return "CoWan"
	case 13:
		return "1394"
	case 14:
		return "InfiniBand"
	case 15:
		return "Tunnel"
	case 16:
		return "Native802.11"
	case 17:
		return "Loopback"
	case 18:
		return "Wimax"
	case 19:
		return "Ip"
	default:
		return ""
	}
}

// networkAdapterPhysicalMediaType maps an NdisPhysicalMedium value to its
// documented name. Unknown values degrade to "" instead of erroring.
func networkAdapterPhysicalMediaType(raw int) string {
	switch raw {
	case 0:
		return "Unspecified"
	case 1:
		return "WirelessLan"
	case 2:
		return "CableModem"
	case 3:
		return "PhoneLine"
	case 4:
		return "PowerLine"
	case 5:
		return "DSL"
	case 6:
		return "FibreChannel"
	case 7:
		return "1394"
	case 8:
		return "WirelessWan"
	case 9:
		return "Native802.11"
	case 10:
		return "Bluetooth"
	case 11:
		return "InfiniBand"
	case 12:
		return "WiMax"
	case 13:
		return "UWB"
	case 14:
		return "802.3"
	case 15:
		return "802.5"
	case 16:
		return "Irda"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Client-side parsing and validation (all filters checked before any call)
// ---------------------------------------------------------------------------

// normalizeNetworkAdapterMAC canonicalises a MAC address to lower
// aa:bb:cc:dd:ee:ff form, accepting colons, dashes, dots and any hex case.
// Anything else (wrong digit count, non-hex characters) is an
// invalid_parameter error.
// NormalizeNetworkAdapterMAC canonicalises a MAC address to lower
// aa:bb:cc:dd:ee:ff form. It is the exported counterpart of
// normalizeNetworkAdapterMAC for provider-layer use (stable filter-hash
// IDs); the winclient internals keep calling the unexported form.
func NormalizeNetworkAdapterMAC(raw string) (string, error) {
	return normalizeNetworkAdapterMAC(raw)
}

func normalizeNetworkAdapterMAC(raw string) (string, error) {
	hex := make([]byte, 0, 12)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= '0' && c <= '9' || c >= 'a' && c <= 'f':
			hex = append(hex, c)
		case c >= 'A' && c <= 'F':
			hex = append(hex, c+('a'-'A'))
		case c == ':' || c == '-' || c == '.':
			// Separators are skipped.
		default:
			return "", NewNetworkAdapterError(NetworkAdapterErrorInvalidParameter,
				fmt.Sprintf("MAC address %q contains invalid character %q", raw, string(c)), nil,
				map[string]string{"mac_address": raw})
		}
	}
	if len(hex) != 12 {
		return "", NewNetworkAdapterError(NetworkAdapterErrorInvalidParameter,
			fmt.Sprintf("MAC address %q must hold 12 hex digits", raw), nil,
			map[string]string{"mac_address": raw})
	}
	var sb strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.Write(hex[i : i+2])
	}
	return sb.String(), nil
}

// canonicalizeNetworkAdapterCIDR parses one "address/prefixlen" string and
// re-renders it canonically (lower-case, compressed IPv6, IPv4-mapped IPv6
// unmapped). Host bits are preserved: this is an address, not a subnet. A
// host value that cannot parse is a typed unknown error.
func canonicalizeNetworkAdapterCIDR(raw, host string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", NewNetworkAdapterError(NetworkAdapterErrorUnknown,
			fmt.Sprintf("host returned an unparsable address %q", raw), nil,
			map[string]string{"host": host})
	}
	addr := p.Addr().Unmap()
	return addr.String() + "/" + strconv.Itoa(p.Bits()), nil
}

// canonicalizeNetworkAdapterAddr parses one bare address and re-renders it
// canonically (IPv4-mapped IPv6 unmapped). A host value that cannot parse
// is a typed unknown error.
func canonicalizeNetworkAdapterAddr(raw, host string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", NewNetworkAdapterError(NetworkAdapterErrorUnknown,
			fmt.Sprintf("host returned an unparsable address %q", raw), nil,
			map[string]string{"host": host})
	}
	return addr.Unmap().String(), nil
}

// canonicalizeNetworkAdapterStrings canonicalises each entry with fn,
// drops blanks, de-duplicates and sorts for stable plans.
func canonicalizeNetworkAdapterStrings(in []string, host string, fn func(string, string) (string, error)) ([]string, error) {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		canonical, err := fn(raw, host)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out, nil
}

// canonicalizeNetworkAdapterStringsDegraded canonicalises each entry with
// fn like canonicalizeNetworkAdapterStrings, but drops blanks and
// unparsable host values instead of failing. One corrupt address on one
// adapter must not abort the whole inventory; skipped values are silently
// ignored (no new error kind).
func canonicalizeNetworkAdapterStringsDegraded(in []string, host string, fn func(string, string) (string, error)) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		canonical, err := fn(raw, host)
		if err != nil {
			continue
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}

// validateNetworkAdapterFilter checks every Go-side filter before any host
// call and returns the normalised comparison values: the lower-cased name
// set, the compiled regex (nil when unset), the normalised MAC and the
// upper-cased status. An invalid filter is an invalid_parameter error.
func validateNetworkAdapterFilter(filter NetworkAdapterFilter) (names map[string]struct{}, re *regexp.Regexp, mac, status string, err error) {
	names = make(map[string]struct{}, len(filter.Names))
	for _, n := range filter.Names {
		if strings.TrimSpace(n) == "" {
			continue
		}
		names[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	if strings.TrimSpace(filter.NameRegex) != "" {
		re, err = regexp.Compile(filter.NameRegex)
		if err != nil {
			return nil, nil, "", "", NewNetworkAdapterError(NetworkAdapterErrorInvalidParameter,
				fmt.Sprintf("name_regex %q is not a valid regular expression: %v", filter.NameRegex, err), nil,
				map[string]string{"name_regex": filter.NameRegex})
		}
	}
	if strings.TrimSpace(filter.MACAddress) != "" {
		mac, err = normalizeNetworkAdapterMAC(filter.MACAddress)
		if err != nil {
			return nil, nil, "", "", err
		}
	}
	if strings.TrimSpace(filter.Status) != "" {
		switch strings.ToLower(strings.TrimSpace(filter.Status)) {
		case "up":
			status = "Up"
		case "disconnected":
			status = "Disconnected"
		case "disabled":
			status = "Disabled"
		case "notpresent":
			status = "NotPresent"
		default:
			return nil, nil, "", "", NewNetworkAdapterError(NetworkAdapterErrorInvalidParameter,
				fmt.Sprintf("status %q is not one of Up, Disconnected, Disabled, NotPresent", filter.Status), nil,
				map[string]string{"status": filter.Status})
		}
	}
	return names, re, mac, status, nil
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// networkAdapterJSON mirrors one object emitted per adapter by
// List-NetworkAdapters. Status and media arrive as raw numbers; the Go side
// owns the mapping tables. A null MTU unmarshals to 0, which means unbound.
type networkAdapterJSON struct {
	Name                 string   `json:"name"`
	InterfaceIndex       int64    `json:"interface_index"`
	InterfaceDescription string   `json:"interface_description"`
	MACAddress           string   `json:"mac_address"`
	OperStatus           int      `json:"oper_status"`
	MediaState           int      `json:"media_state"`
	AdminStatus          int      `json:"admin_status"`
	LinkSpeedBps         int64    `json:"link_speed_bps"`
	NdisMedium           int      `json:"ndis_medium"`
	NdisPhysicalMedium   int      `json:"ndis_physical_medium"`
	IsVirtual            bool     `json:"is_virtual"`
	VlanID               int64    `json:"vlan_id"`
	DriverDescription    string   `json:"driver_description"`
	DriverVersion        string   `json:"driver_version"`
	DriverProvider       string   `json:"driver_provider"`
	MTUIPv4              int64    `json:"mtu_ipv4"`
	MTUIPv6              int64    `json:"mtu_ipv6"`
	DHCPEnabled          bool     `json:"dhcp_enabled"`
	IPv4Addresses        []string `json:"ipv4_addresses"`
	IPv6Addresses        []string `json:"ipv6_addresses"`
	DefaultGateways      []string `json:"default_gateways"`
	DNSServers           []string `json:"dns_servers"`
	NetworkCategory      string   `json:"network_category"`
}

// runNetworkAdaptersEnvelope executes the list script and parses the JSON
// envelope through the shared runEnvelope helper. A cancelled call maps to
// timeout; transport and envelope failures map to unknown; remote Emit-Err
// kinds map via mapNetworkAdaptersKind.
func (n *NetworkAdaptersClient) runNetworkAdaptersEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
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
			return runNetworkAdaptersPowerShell(ctx, n.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewNetworkAdapterError(NetworkAdapterErrorTimeout, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewNetworkAdapterError(NetworkAdapterErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewNetworkAdapterError(mapNetworkAdaptersKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapNetworkAdaptersKind translates a PS-side "kind" string to a typed
// NetworkAdapterErrorKind. Unknown values fall through to Unknown.
func mapNetworkAdaptersKind(k string) NetworkAdapterErrorKind {
	switch NetworkAdapterErrorKind(k) {
	case NetworkAdapterErrorAccessDenied,
		NetworkAdapterErrorCIMUnavailable,
		NetworkAdapterErrorTimeout,
		NetworkAdapterErrorInvalidParameter:
		return NetworkAdapterErrorKind(k)
	default:
		return NetworkAdapterErrorUnknown
	}
}

// parseNetworkAdapter projects one networkAdapterJSON payload onto a
// NetworkAdapter, canonicalising the MAC and every address list and
// deriving status and media names from the numeric codes.
func parseNetworkAdapter(raw json.RawMessage, host string) (NetworkAdapter, error) {
	var j networkAdapterJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return NetworkAdapter{}, NewNetworkAdapterError(NetworkAdapterErrorUnknown,
			"failed to parse network adapter JSON", err,
			map[string]string{"host": host, "raw": truncate(string(raw), 512)})
	}
	mac := ""
	if strings.TrimSpace(j.MACAddress) != "" {
		// An unparsable host MAC degrades to "" for this adapter only;
		// the rest of the inventory still parses.
		if normalised, merr := normalizeNetworkAdapterMAC(j.MACAddress); merr == nil {
			mac = normalised
		}
	}
	// Unparsable host addresses degrade per value: the single bad
	// address is dropped, the rest of the adapter (and inventory) still
	// parses. Skipped values are silently ignored (no new error kind).
	v4 := canonicalizeNetworkAdapterStringsDegraded(j.IPv4Addresses, host, canonicalizeNetworkAdapterCIDR)
	v6 := canonicalizeNetworkAdapterStringsDegraded(j.IPv6Addresses, host, canonicalizeNetworkAdapterCIDR)
	gw := canonicalizeNetworkAdapterStringsDegraded(j.DefaultGateways, host, canonicalizeNetworkAdapterAddr)
	dns := canonicalizeNetworkAdapterStringsDegraded(j.DNSServers, host, canonicalizeNetworkAdapterAddr)
	return NetworkAdapter{
		Name:                 j.Name,
		InterfaceIndex:       j.InterfaceIndex,
		InterfaceDescription: j.InterfaceDescription,
		MACAddress:           mac,
		Status:               deriveNetworkAdapterStatus(j.OperStatus, j.MediaState, j.AdminStatus),
		AdminEnabled:         j.AdminStatus != 2,
		LinkSpeedBps:         j.LinkSpeedBps,
		MediaType:            networkAdapterMediaType(j.NdisMedium),
		PhysicalMediaType:    networkAdapterPhysicalMediaType(j.NdisPhysicalMedium),
		IsPhysical:           !j.IsVirtual,
		IsVirtual:            j.IsVirtual,
		VlanID:               j.VlanID,
		DriverDescription:    j.DriverDescription,
		DriverVersion:        j.DriverVersion,
		DriverProvider:       j.DriverProvider,
		MTUIPv4:              j.MTUIPv4,
		MTUIPv6:              j.MTUIPv6,
		DHCPEnabled:          j.DHCPEnabled,
		IPv4Addresses:        v4,
		IPv6Addresses:        v6,
		DefaultGateways:      gw,
		DNSServers:           dns,
		NetworkCategory:      j.NetworkCategory,
	}, nil
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// List returns the adapter inventory in a single round-trip, filtered
// Go-side and sorted by interface index. Filters are validated before any
// host call; an invalid filter never reaches the host. The management-path
// probe runs once per call and marks the adapter owning the SSH server
// address; a failed probe clears every IsManagement flag instead of failing
// the listing. An empty result is valid (empty slice, nil error).
func (n *NetworkAdaptersClient) List(ctx context.Context, filter NetworkAdapterFilter) ([]NetworkAdapter, error) {
	names, re, mac, status, err := validateNetworkAdapterFilter(filter)
	if err != nil {
		return nil, err
	}
	resp, err := n.runNetworkAdaptersEnvelope(ctx, "list",
		buildNetworkAdaptersListScript(filter.Names, filter.PhysicalOnly, filter.IncludeHidden),
		map[string]string{})
	if err != nil {
		return nil, err
	}
	var arr []json.RawMessage
	if jerr := json.Unmarshal(resp.Data, &arr); jerr != nil {
		return nil, NewNetworkAdapterError(NetworkAdapterErrorUnknown,
			"failed to parse network adapter list JSON", jerr,
			map[string]string{"host": n.c.cfg.Host})
	}
	out := make([]NetworkAdapter, 0, len(arr))
	for _, raw := range arr {
		adapter, perr := parseNetworkAdapter(raw, n.c.cfg.Host)
		if perr != nil {
			return nil, perr
		}
		if len(names) > 0 {
			if _, ok := names[strings.ToLower(adapter.Name)]; !ok {
				continue
			}
		}
		if re != nil && !re.MatchString(adapter.Name) {
			continue
		}
		if mac != "" && adapter.MACAddress != mac {
			continue
		}
		if status != "" && adapter.Status != status {
			continue
		}
		out = append(out, adapter)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InterfaceIndex < out[j].InterfaceIndex })
	if len(out) == 0 {
		// No match: skip the management-path probe (no second
		// round-trip for an empty inventory).
		return out, nil
	}
	n.markManagement(ctx, out)
	return out, nil
}

// markManagement sets IsManagement on the adapter owning the SSH server
// address. A failed probe clears every flag instead of failing the listing:
// management identity is advisory inventory, not a guard.
func (n *NetworkAdaptersClient) markManagement(ctx context.Context, out []NetworkAdapter) {
	mp, err := networkAdaptersManagementPath(ctx, n.c)
	if err != nil || mp == nil {
		return
	}
	for i := range out {
		out[i].IsManagement = int64(mp.InterfaceIndex) == out[i].InterfaceIndex
	}
}
