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
	"fmt"
	"net/netip"
	"strings"
)

// PowerShell header, fragments and script builders. Split from net_ip_address.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// psNetIPAddressHeader is prepended to every net-ip-address PS script. It
// pins the session culture to InvariantCulture so enum .ToString() values
// (PrefixOrigin, AddressState, Dhcp) are always English regardless of the
// host locale, and defines the shared Emit-OK / Emit-Err /
// Classify-NetIpAddress helpers.
//
// Classify-NetIpAddress prefers CIM/HRESULT codes over localized message
// substrings (hosts are not all English); substring matches remain as a
// backstop where no stable code exists (the DHCP "inconsistent parameters"
// error, duplicate detection wording).
const psNetIPAddressHeader = `
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

function Classify-NetIpAddress([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  if ($code -eq '0x80070005' -or $msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess') { return 'permission_denied' }
  if ($msg -match 'Inconsistent parameters' -and $msg -match 'Dhcp') { return 'dhcp_enabled' }
  if ($code -eq '0x800700B7' -or $msg -match 'already exists') { return 'already_exists' }
  if ($code -eq '0x80070490' -or $code -eq '0x80041002' -or $msg -match 'No matching MSFT_NetIPAddress' -or $msg -match 'No MSFT_NetIPAddress') { return 'not_found' }
  if ($msg -match 'No matching MSFT_NetIPInterface' -or $msg -match 'No MSFT_NetIPInterface') { return 'interface_not_found' }
  if ($code -eq '0x80070057' -or $msg -match 'Invalid prefix' -or $msg -match 'is not valid' -or $msg -match 'InvalidParameter') { return 'invalid_address' }
  if ($msg -match 'duplicate') { return 'duplicate_address' }
  return 'unknown'
}

function ConvertTo-NetAddressJson([object]$Row) {
  return [ordered]@{
    interface_alias  = [string]$Row.InterfaceAlias
    interface_index  = [int]$Row.InterfaceIndex
    ip_address       = [string]$Row.IPAddress
    prefix_length    = [int]$Row.PrefixLength
    address_state    = [string]$Row.AddressState
    prefix_origin    = [string]$Row.PrefixOrigin
    skip_as_source   = [bool]$Row.SkipAsSource
  }
}
`

// netIPAddressResolveFragment resolves $alias with an exact (-eq,
// case-insensitive, never wildcard) comparison and stores the interface
// index in $ifIndex. On failure it emits interface_not_found listing the
// valid aliases and returns. Callers set $family ('IPv4'/'IPv6') and $alias
// before invoking it.
const netIPAddressResolveFragment = `
$iface = Get-NetIPInterface -AddressFamily $family -ErrorAction Stop | Where-Object { $_.InterfaceAlias -eq $alias } | Select-Object -First 1
if ($null -eq $iface) {
  $valid = @(Get-NetIPInterface -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceAlias -Unique | Sort-Object)
  Emit-Err 'interface_not_found' ('No interface matches alias ' + [string]$alias + '. Valid aliases: ' + ($valid -join ', ') + '.') @{ interface_alias = [string]$alias }
  return
}
$ifIndex = [int]$iface.InterfaceIndex
`

// ---------------------------------------------------------------------------
// Script builders (every user value via psQuote; ints/bools via tokens)
// ---------------------------------------------------------------------------

func netIPAddressFamilyToken(isV6 bool) string {
	if isV6 {
		return "'IPv6'"
	}
	return "'IPv4'"
}

func netIPAddressBoolToken(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// buildNetIPAddressResolveScript renders a resolve-only probe returning
// {interface_index, interface_alias}.
func buildNetIPAddressResolveScript(alias string, isV6 bool) string {
	return psNetIPAddressHeader + fmt.Sprintf(`
$family = %s
$alias = %s
& {
%s
  Emit-OK ([ordered]@{ interface_index = $ifIndex; interface_alias = [string]$iface.InterfaceAlias })
}
`, netIPAddressFamilyToken(isV6), psQuote(alias), netIPAddressResolveFragment)
}

// buildNetIPAddressReadScript renders a resolve + single-address read.
// Missing addresses emit not_found.
func buildNetIPAddressReadScript(alias, ip string, isV6 bool) string {
	return psNetIPAddressHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantIP = %s
& {
%s
  try {
    $row = Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -ErrorAction Stop | Select-Object -First 1
  } catch {
    Emit-Err 'not_found' ('No address ' + [string]$wantIP + ' on interface ' + [string]$alias + '.') @{ interface_alias = [string]$alias; ip_address = [string]$wantIP }
    return
  }
  if ($null -eq $row) {
    Emit-Err 'not_found' ('No address ' + [string]$wantIP + ' on interface ' + [string]$alias + '.') @{ interface_alias = [string]$alias; ip_address = [string]$wantIP }
    return
  }
  Emit-OK (ConvertTo-NetAddressJson $row)
}
`, netIPAddressFamilyToken(isV6), psQuote(alias), psQuote(ip), netIPAddressResolveFragment)
}

// buildNetIPAddressLookupScript renders an address lookup across all
// interfaces, optionally restricted to one alias. Zero matches emit
// not_found; several emit address_in_use_elsewhere listing the candidates.
func buildNetIPAddressLookupScript(ip, alias string) string {
	aliasFilter := ""
	if alias != "" {
		aliasFilter = fmt.Sprintf("\n  $rows = @($rows | Where-Object { $_.InterfaceAlias -eq %s })", psQuote(alias))
	}
	return psNetIPAddressHeader + fmt.Sprintf(`
$wantIP = %s
& {
  try {
    $rows = @(Get-NetIPAddress -IPAddress $wantIP -ErrorAction Stop)
  } catch {
    Emit-Err 'not_found' ('No address ' + [string]$wantIP + ' found on any interface.') @{ ip_address = [string]$wantIP }
    return
  }
  %s
  if ($rows.Count -eq 0) {
    Emit-Err 'not_found' ('No address ' + [string]$wantIP + ' found on any interface.') @{ ip_address = [string]$wantIP }
    return
  }
  if ($rows.Count -gt 1) {
    $holders = @($rows | ForEach-Object { ([string]$_.InterfaceAlias + ' (ifIndex ' + [string]$_.InterfaceIndex + ')') } | Sort-Object -Unique)
    Emit-Err 'address_in_use_elsewhere' ('Address ' + [string]$wantIP + ' matches several addresses: ' + ($holders -join ', ') + '. Refine the lookup with interface_alias.') @{ ip_address = [string]$wantIP }
    return
  }
  Emit-OK (ConvertTo-NetAddressJson $rows[0])
}
`, psQuote(ip), aliasFilter)
}

// buildNetIPAddressEnsureDHCPDisabledScript renders an idempotent DHCP
// disable (IPv4 only). A DHCP-enabled interface without the flag emits
// dhcp_enabled with a hint; with the flag it disables DHCP first.
func buildNetIPAddressEnsureDHCPDisabledScript(alias string, disable bool) string {
	return psNetIPAddressHeader + fmt.Sprintf(`
$family = 'IPv4'
$alias = %s
$disableDhcp = %s
& {
%s
  $ipIface = Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop
  if ([string]$ipIface.Dhcp -ne 'Enabled') {
    Emit-OK ([ordered]@{ dhcp_disabled = $false })
    return
  }
  if (-not $disableDhcp) {
    Emit-Err 'dhcp_enabled' ('Interface ' + [string]$alias + ' still has DHCP enabled (New-NetIPAddress refuses inconsistent parameters PolicyStore PersistentStore and Dhcp Enabled). Set disable_dhcp = true to disable DHCP on this interface first.') @{ interface_alias = [string]$alias }
    return
  }
  try {
    Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
  } catch {
    Emit-Err (Classify-NetIpAddress $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'disable_dhcp' }
    return
  }
  Emit-OK ([ordered]@{ dhcp_disabled = $true })
}
`, psQuote(alias), netIPAddressBoolToken(disable), netIPAddressResolveFragment)
}

// buildNetIPAddressCreateScript renders the atomic create: resolve,
// duplicate pre-flight (same interface -> already_exists, elsewhere ->
// address_in_use_elsewhere), New-NetIPAddress, read-back.
func buildNetIPAddressCreateScript(alias, ip string, prefix int, skipAsSource, isV6 bool) string {
	newCmd := fmt.Sprintf("New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -PrefixLength %d -ErrorAction Stop", prefix)
	if skipAsSource {
		newCmd = fmt.Sprintf("New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -PrefixLength %d -SkipAsSource -ErrorAction Stop", prefix)
	}
	return psNetIPAddressHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantIP = %s
& {
%s
  try {
    $existing = @(Get-NetIPAddress -IPAddress $wantIP -ErrorAction Stop)
  } catch {
    $existing = @()
  }
  foreach ($e in $existing) {
    if ([int]$e.InterfaceIndex -eq $ifIndex) {
      if ([string]$e.PrefixOrigin -eq 'Manual') {
        Emit-Err 'already_exists' ('Address ' + [string]$wantIP + ' already exists on interface ' + [string]$alias + '. Import it with terraform import <name> "' + [string]$alias + '|' + [string]$wantIP + '".') @{ interface_alias = [string]$alias; ip_address = [string]$wantIP }
      } else {
        Emit-Err 'already_exists' ('Address ' + [string]$wantIP + ' already exists on interface ' + [string]$alias + ' with prefix origin ' + [string]$e.PrefixOrigin + ' (only Manual addresses are importable; remove it from the host or choose another address).') @{ interface_alias = [string]$alias; ip_address = [string]$wantIP }
      }
      return
    }
  }
  if ($existing.Count -gt 0) {
    $holders = @($existing | ForEach-Object { [string]$_.InterfaceAlias } | Sort-Object -Unique)
    Emit-Err 'address_in_use_elsewhere' ('Address ' + [string]$wantIP + ' is already assigned on another interface: ' + ($holders -join ', ') + '.') @{ interface_alias = [string]$alias; ip_address = [string]$wantIP }
    return
  }
  try {
    $null = %s
  } catch {
    Emit-Err (Classify-NetIpAddress $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; ip_address = [string]$wantIP; step = 'create' }
    return
  }
  try {
    $row = Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -ErrorAction Stop | Select-Object -First 1
  } catch {
    Emit-Err (Classify-NetIpAddress $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; ip_address = [string]$wantIP; step = 'readback' }
    return
  }
  Emit-OK (ConvertTo-NetAddressJson $row)
}
`, netIPAddressFamilyToken(isV6), psQuote(alias), psQuote(ip), netIPAddressResolveFragment, newCmd)
}

// buildNetIPAddressSetScript renders the in-place update (Set-NetIPAddress)
// plus read-back.
func buildNetIPAddressSetScript(alias, ip string, prefix int, skipAsSource bool) string {
	return psNetIPAddressHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantIP = %s
$prefix = %d
$skip = %s
& {
%s
  try {
    $null = Set-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -PrefixLength $prefix -SkipAsSource $skip -ErrorAction Stop
  } catch {
    Emit-Err (Classify-NetIpAddress $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; ip_address = [string]$wantIP; step = 'set' }
    return
  }
  try {
    $row = Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -ErrorAction Stop | Select-Object -First 1
  } catch {
    Emit-Err (Classify-NetIpAddress $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; ip_address = [string]$wantIP; step = 'readback' }
    return
  }
  Emit-OK (ConvertTo-NetAddressJson $row)
}
`, netIPAddressFamilyToken(isV6ForIP(ip)), psQuote(alias), psQuote(ip), prefix, netIPAddressBoolToken(skipAsSource), netIPAddressResolveFragment)
}

// buildNetIPAddressRemoveScript renders the guarded delete. A missing
// interface or address emits Emit-OK null (idempotent delete); a
// concurrently removed address between pre-flight and removal maps to the
// same outcome via Classify.
func buildNetIPAddressRemoveScript(alias, ip string, isV6 bool) string {
	return psNetIPAddressHeader + fmt.Sprintf(`
$family = %s
$alias = %s
$wantIP = %s
& {
%s
  try {
    $row = Get-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -ErrorAction Stop | Select-Object -First 1
  } catch {
    Emit-OK $null
    return
  }
  if ($null -eq $row) {
    Emit-OK $null
    return
  }
  try {
    $null = Remove-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $wantIP -Confirm:$false -ErrorAction Stop
  } catch {
    $kind = Classify-NetIpAddress $_
    if ($kind -eq 'not_found') {
      Emit-OK $null
      return
    }
    Emit-Err $kind ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; ip_address = [string]$wantIP; step = 'remove' }
    return
  }
  Emit-OK ([ordered]@{ removed = $true })
}
`, netIPAddressFamilyToken(isV6), psQuote(alias), psQuote(ip), netIPAddressResolveFragment)
}

// buildNetIPAddressRestoreDHCPScript renders the DHCP re-enable used by
// destroy with restore_dhcp_on_destroy.
func buildNetIPAddressRestoreDHCPScript(alias string) string {
	return psNetIPAddressHeader + fmt.Sprintf(`
$family = 'IPv4'
$alias = %s
& {
%s
  try {
    $null = Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
  } catch {
    Emit-Err (Classify-NetIpAddress $_) ([string]$_.Exception.Message) @{ interface_alias = [string]$alias; step = 'restore_dhcp' }
    return
  }
  Emit-OK ([ordered]@{ dhcp_enabled = $true })
}
`, psQuote(alias), netIPAddressResolveFragment)
}

// buildNetIPAddressPrefixOriginScript renders a PrefixOrigin probe for one
// address (used by the DHCP disable-safety rule for the management
// interface). Emits the raw origin string.
func buildNetIPAddressPrefixOriginScript(ip string) string {
	return psNetIPAddressHeader + fmt.Sprintf(`
$wantIP = %s
& {
  try {
    $row = Get-NetIPAddress -IPAddress $wantIP -ErrorAction Stop | Select-Object -First 1
  } catch {
    Emit-Err (Classify-NetIpAddress $_) ([string]$_.Exception.Message) @{ ip_address = [string]$wantIP; step = 'prefix_origin' }
    return
  }
  if ($null -eq $row) {
    Emit-Err 'not_found' ('No address ' + [string]$wantIP + ' found on any interface.') @{ ip_address = [string]$wantIP }
    return
  }
  Emit-OK ([string]$row.PrefixOrigin)
}
`, psQuote(ip))
}

// isV6ForIP reports whether ip parses as IPv6. Callers pass validated input;
// an unparsable value defaults to IPv4 (the family token only selects the
// Get-NetIPInterface address family for alias resolution).
func isV6ForIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	return addr.Is6() && !addr.Is4In6()
}
