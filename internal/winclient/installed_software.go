// Package winclient - InstalledSoftwareClient is the concrete
// WindowsInstalledSoftwareClient backed by PowerShell over SSH.
//
// Security invariants:
//   - Only the hive list, the normalised product code and the
//     include-user-installs flag are interpolated into the PS script, via
//     psQuoteList/psQuote (single-quoted PowerShell literals) and a
//     $true/$false literal. Regex filters never reach the host: they are
//     applied Go-side.
//   - No credentials are involved in software inventory; none are written
//     to InstalledSoftwareError.Message or Context.
//   - Scripts never call "exit": since #81 a script may run inside a
//     long-lived, reused PowerShell session, where "exit" would kill that
//     session instead of just this call. Early returns use "return" after
//     Emit-Err instead.
//   - Win32_Product is never queried: it triggers a consistency check of
//     every MSI on the host. Inventory reads the Uninstall registry hives
//     only.
//
// Reused helpers from the same package:
//   - psQuote, psQuoteList      - safe PS string/array literals (psquote.go)
//   - runEnvelope               - shared JSON envelope pipeline (envelope.go)
//   - UninstallRegistryHivePaths - machine hives shared with
//     windows_legacy_package (legacy_package.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Compile-time assertion: InstalledSoftwareClient satisfies
// WindowsInstalledSoftwareClient.
var _ WindowsInstalledSoftwareClient = (*InstalledSoftwareClient)(nil)

// InstalledSoftwareClient is the PowerShell/SSH-backed
// WindowsInstalledSoftwareClient.
type InstalledSoftwareClient struct {
	c *Client
}

// NewInstalledSoftwareClient wraps the given SSH Client.
func NewInstalledSoftwareClient(c *Client) *InstalledSoftwareClient {
	return &InstalledSoftwareClient{c: c}
}

// runInstalledSoftwarePowerShell is the package-level indirection used by
// InstalledSoftwareClient. Tests may override it; production code must not.
var runInstalledSoftwarePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// psInstalledSoftwareHeader is prepended to the installed-software PS
// script. It pins the session culture to InvariantCulture so values render
// identically regardless of the host locale, and defines the shared
// Emit-OK / Emit-Err / Classify-InstalledSoftware helpers plus the safe
// per-value property readers (one broken registry value degrades to its
// zero value instead of failing the whole key, let alone the listing).
//
// Classify-InstalledSoftware maps access-denied substrings to access_denied
// and degrades everything else to unknown: registry reads fail with plain
// .NET/PSDrive errors, so there is no CIM-style token family to anchor on.
const psInstalledSoftwareHeader = `
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

function Classify-InstalledSoftware([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  if ($code -eq '0x80070005' -or $msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess') { return 'access_denied' }
  return 'unknown'
}

function Get-SWStr([object]$Obj, [string]$Name) {
  try {
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return '' }
    return [string]$p.Value
  } catch { return '' }
}

function Get-SWInt([object]$Obj, [string]$Name, [int]$Default) {
  try {
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return [int]$p.Value
  } catch { return $Default }
}

function Get-SWInt64([object]$Obj, [string]$Name, [int64]$Default) {
  try {
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return [int64]$p.Value
  } catch { return $Default }
}
`

// psInstalledSoftwareListBody defines List-InstalledSoftware: one round-trip
// that enumerates the machine Uninstall hives (interpolated from
// UninstallRegistryHivePaths) plus, when requested, the Uninstall keys of
// the loaded per-user hives under HKU. Every registry value is read through
// the safe Get-SW* helpers so one broken value degrades to its zero value
// instead of aborting the key; a key whose properties cannot be read at all
// counts as skipped. Keys without a DisplayName are silently omitted (they
// are not installed products and are not counted as skipped).
//
// Only the product code is pre-filtered host-side (exact key-name match);
// every other filter is applied Go-side so the script keeps a single shape.
const psInstalledSoftwareListBody = `
function List-InstalledSoftware([string[]]$Hives, [string]$ProductCode, [bool]$IncludeUserInstalls) {
  $hostArch = ''
  try { $hostArch = [string]$env:PROCESSOR_ARCHITECTURE } catch { $hostArch = '' }
  $targets = @()
  foreach ($h in $Hives) {
    $arch = 'native'
    if ($h -match 'WOW6432Node') { $arch = 'wow' }
    $targets += [pscustomobject]@{ Path = $h; HiveArch = $arch; Scope = 'machine'; Sid = '' }
  }
  if ($IncludeUserInstalls) {
    # HKU: is not a default PSDrive; mount it idempotently (the drive
    # persists on the reused session, so an existing drive is reused).
    try {
      if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop | Out-Null
      }
    } catch { }
    $sids = @()
    try { $sids = @(Get-ChildItem -Path 'HKU:' -ErrorAction Stop | ForEach-Object { $_.PSChildName }) } catch { $sids = @() }
    # Only loaded interactive/domain user hives (S-1-5-21-*) are scanned.
    # Well-known service accounts (SYSTEM S-1-5-18, LocalService S-1-5-19,
    # NetworkService S-1-5-20) are excluded explicitly; unloaded profiles
    # have no HKU key and are never scanned.
    foreach ($sid in $sids) {
      if (($sid -eq 'S-1-5-18') -or ($sid -eq 'S-1-5-19') -or ($sid -eq 'S-1-5-20')) { continue }
      if ($sid -notmatch '^S-1-5-21-') { continue }
      $upath = ('HKU:\' + $sid + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
      $targets += [pscustomobject]@{ Path = $upath; HiveArch = 'native'; Scope = 'user'; Sid = [string]$sid }
    }
  }
  # Brace/case-insensitive host pre-filter: registry key names may or may
  # not carry braces, so compare normalised (braces trimmed, upper-cased).
  # An empty product code stays empty (unfiltered).
  $ProductCodeNorm = $ProductCode.Trim('{}').ToUpper()
  $skipped = 0
  $out = @()
  foreach ($t in $targets) {
    if (-not (Test-Path -LiteralPath $t.Path)) { continue }
    $keys = @()
    try { $keys = @(Get-ChildItem -LiteralPath $t.Path -ErrorAction Stop) } catch {
      # An unreadable hive fails closed as access_denied (fail-closed, never
      # an empty inventory); any other enumeration error skips the hive.
      # Branch on the classifier (single token list) rather than duplicating
      # its substrings, so PermissionDenied-only and HResult-only shapes
      # agree with Classify-InstalledSoftware.
      $em = ''
      try { $em = [string]$_.Exception.Message } catch { $em = [string]$_ }
      if ((Classify-InstalledSoftware $em) -eq 'access_denied') {
        Emit-Err 'access_denied' ([string]$_.Exception.Message) @{ step = 'enumerate'; target = $t.Path }
        return
      }
      continue
    }
    foreach ($k in $keys) {
      $keyName = [string]$k.PSChildName
      if (($ProductCodeNorm -ne '') -and ($keyName.Trim('{}').ToUpper() -ne $ProductCodeNorm)) { continue }
      $p = $null
      try { $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { $p = $null }
      if ($null -eq $p) { $skipped++; continue }
      $dn = ''
      try { $dn = [string]$p.DisplayName } catch { $dn = '' }
      if ([string]::IsNullOrEmpty($dn)) { continue }
      $out += [ordered]@{
        name                   = $dn
        version                = (Get-SWStr $p 'DisplayVersion')
        publisher              = (Get-SWStr $p 'Publisher')
        install_date_raw       = (Get-SWStr $p 'InstallDate')
        install_location       = (Get-SWStr $p 'InstallLocation')
        product_code_raw       = $keyName
        windows_installer      = (Get-SWInt $p 'WindowsInstaller' 0)
        system_component       = (Get-SWInt $p 'SystemComponent' 0)
        parent_key_name        = (Get-SWStr $p 'ParentKeyName')
        release_type           = (Get-SWStr $p 'ReleaseType')
        estimated_size         = (Get-SWInt64 $p 'EstimatedSize' 0)
        uninstall_string       = (Get-SWStr $p 'UninstallString')
        quiet_uninstall_string = (Get-SWStr $p 'QuietUninstallString')
        registry_key           = ($t.Path + '\' + $keyName)
        scope                  = [string]$t.Scope
        user_sid               = [string]$t.Sid
        hive_arch              = [string]$t.HiveArch
        host_arch              = $hostArch
      }
    }
  }
  Emit-OK ([ordered]@{ packages = $out; skipped_entries = $skipped })
}
`

// ---------------------------------------------------------------------------
// Script builder (only hives/product code/user flag interpolated)
// ---------------------------------------------------------------------------

// installedSoftwareBoolToken renders a Go bool as a PowerShell literal.
func installedSoftwareBoolToken(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// buildInstalledSoftwareListScript renders the single-round-trip inventory
// script. The machine hives travel via psQuoteList from the shared
// UninstallRegistryHivePaths constant, the pre-normalised product code via
// psQuote, and the user-hive flag as a literal; regex, system/update and
// architecture filters are applied Go-side.
func buildInstalledSoftwareListScript(productCode string, includeUserInstalls bool) string {
	return psInstalledSoftwareHeader + psInstalledSoftwareListBody + fmt.Sprintf(`
$Hives = %s
$ProductCode = %s
$IncludeUserInstalls = %s
List-InstalledSoftware -Hives $Hives -ProductCode $ProductCode -IncludeUserInstalls $IncludeUserInstalls
`, psQuoteList(UninstallRegistryHivePaths), psQuote(productCode), installedSoftwareBoolToken(includeUserInstalls))
}

// ---------------------------------------------------------------------------
// Client-side parsing and validation (all filters checked before any call)
// ---------------------------------------------------------------------------

// installedSoftwareGUIDRe matches a bare MSI ProductCode GUID (no braces).
var installedSoftwareGUIDRe = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// NormalizeInstalledSoftwareProductCode canonicalises an MSI ProductCode
// GUID to upper-case with braces, accepting any common spelling (with or
// without braces, any case). An empty input stays empty (unfiltered).
// Anything else is an invalid_parameter error.
func NormalizeInstalledSoftwareProductCode(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if !installedSoftwareGUIDRe.MatchString(s) {
		return "", NewInstalledSoftwareError(InstalledSoftwareErrorInvalidParameter,
			fmt.Sprintf("product_code %q is not a valid MSI ProductCode GUID", raw), nil,
			map[string]string{"product_code": raw})
	}
	return "{" + strings.ToUpper(s) + "}", nil
}

// validateInstalledSoftwareFilter checks every Go-side filter before any
// host call and returns the compiled regexes (nil when unset) and the
// normalised product code. An invalid filter is an invalid_parameter error.
func validateInstalledSoftwareFilter(filter InstalledSoftwareFilter) (nameRe, pubRe *regexp.Regexp, productCode string, err error) {
	if trimmed := strings.TrimSpace(filter.NameRegex); trimmed != "" {
		nameRe, err = regexp.Compile(trimmed)
		if err != nil {
			return nil, nil, "", NewInstalledSoftwareError(InstalledSoftwareErrorInvalidParameter,
				fmt.Sprintf("name_regex %q is not a valid regular expression: %v", filter.NameRegex, err), nil,
				map[string]string{"name_regex": filter.NameRegex})
		}
	}
	if trimmed := strings.TrimSpace(filter.PublisherRegex); trimmed != "" {
		pubRe, err = regexp.Compile(trimmed)
		if err != nil {
			return nil, nil, "", NewInstalledSoftwareError(InstalledSoftwareErrorInvalidParameter,
				fmt.Sprintf("publisher_regex %q is not a valid regular expression: %v", filter.PublisherRegex, err), nil,
				map[string]string{"publisher_regex": filter.PublisherRegex})
		}
	}
	if productCode, err = NormalizeInstalledSoftwareProductCode(filter.ProductCode); err != nil {
		return nil, nil, "", err
	}
	return nameRe, pubRe, productCode, nil
}

// normalizeInstalledSoftwareDate converts a registry InstallDate
// (YYYYMMDD) to YYYY-MM-DD. Missing or unparseable values degrade to "".
func normalizeInstalledSoftwareDate(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if t, err := time.Parse("20060102", s); err == nil {
		return t.Format("2006-01-02")
	}
	return ""
}

// normalizeInstalledSoftwareRowCode derives the entry ProductCode from the
// registry key name: a GUID key normalises to upper-case with braces,
// anything else means a non-MSI entry ("").
func normalizeInstalledSoftwareRowCode(keyName string) string {
	s := strings.TrimSpace(keyName)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if !installedSoftwareGUIDRe.MatchString(s) {
		return ""
	}
	return "{" + strings.ToUpper(s) + "}"
}

// deriveInstalledSoftwareArchitecture maps the hive view to the entry
// architecture: the WOW6432Node hive always holds 32-bit ("x86") entries;
// a native-hive entry follows the host architecture ("arm64" on ARM64
// hosts, "x86" on 32-bit hosts, "x64" otherwise).
func deriveInstalledSoftwareArchitecture(hiveArch, hostArch string) string {
	if hiveArch == "wow" {
		return "x86"
	}
	switch strings.ToUpper(strings.TrimSpace(hostArch)) {
	case "ARM64":
		return "arm64"
	case "X86":
		return "x86"
	default:
		return "x64"
	}
}

// isInstalledSoftwareUpdate reports whether an entry is an update rather
// than a product: a non-empty ParentKeyName, or a ReleaseType of Security
// Update, Update or Hotfix (case-insensitive).
func isInstalledSoftwareUpdate(parentKeyName, releaseType string) bool {
	if strings.TrimSpace(parentKeyName) != "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(releaseType)) {
	case "security update", "update", "hotfix":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// installedSoftwareJSON mirrors one object emitted per package by
// List-InstalledSoftware. Numeric flags arrive as JSON numbers; missing
// keys unmarshal to their zero values.
type installedSoftwareJSON struct {
	Name                 string `json:"name"`
	Version              string `json:"version"`
	Publisher            string `json:"publisher"`
	InstallDateRaw       string `json:"install_date_raw"`
	InstallLocation      string `json:"install_location"`
	ProductCodeRaw       string `json:"product_code_raw"`
	WindowsInstaller     int    `json:"windows_installer"`
	SystemComponent      int    `json:"system_component"`
	ParentKeyName        string `json:"parent_key_name"`
	ReleaseType          string `json:"release_type"`
	EstimatedSize        int64  `json:"estimated_size"`
	UninstallString      string `json:"uninstall_string"`
	QuietUninstallString string `json:"quiet_uninstall_string"`
	RegistryKey          string `json:"registry_key"`
	Scope                string `json:"scope"`
	UserSID              string `json:"user_sid"`
	HiveArch             string `json:"hive_arch"`
	HostArch             string `json:"host_arch"`
}

// runInstalledSoftwareEnvelope executes the list script and parses the JSON
// envelope through the shared runEnvelope helper. A cancelled call maps to
// timeout; transport and envelope failures map to unknown; remote Emit-Err
// kinds map via mapInstalledSoftwareKind.
func (s *InstalledSoftwareClient) runInstalledSoftwareEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
	baseContext := map[string]string{
		"host":      s.c.cfg.Host,
		"port":      strconv.Itoa(s.c.cfg.Port),
		"transport": "ssh",
	}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runInstalledSoftwarePowerShell(ctx, s.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewInstalledSoftwareError(InstalledSoftwareErrorTimeout, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewInstalledSoftwareError(InstalledSoftwareErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewInstalledSoftwareError(mapInstalledSoftwareKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapInstalledSoftwareKind translates a PS-side "kind" string to a typed
// InstalledSoftwareErrorKind. Unknown values fall through to Unknown.
func mapInstalledSoftwareKind(k string) InstalledSoftwareErrorKind {
	switch InstalledSoftwareErrorKind(k) {
	case InstalledSoftwareErrorAccessDenied,
		InstalledSoftwareErrorTimeout,
		InstalledSoftwareErrorInvalidParameter:
		return InstalledSoftwareErrorKind(k)
	default:
		return InstalledSoftwareErrorUnknown
	}
}

// projectInstalledSoftwareRow maps one installedSoftwareJSON payload onto
// an InstalledSoftware, applying the host-shape normalisations (install
// date, product code, MSI flag, architecture, scope). System/update flags
// are returned separately so the caller can apply the include toggles.
func projectInstalledSoftwareRow(j installedSoftwareJSON) (InstalledSoftware, bool, bool) {
	code := normalizeInstalledSoftwareRowCode(j.ProductCodeRaw)
	scope := "machine"
	sid := ""
	if j.Scope == "user" {
		scope = "user"
		sid = j.UserSID
	}
	return InstalledSoftware{
		Name:                 j.Name,
		Version:              j.Version,
		Publisher:            j.Publisher,
		InstallDate:          normalizeInstalledSoftwareDate(j.InstallDateRaw),
		InstallLocation:      j.InstallLocation,
		ProductCode:          code,
		IsMSI:                j.WindowsInstaller == 1,
		Architecture:         deriveInstalledSoftwareArchitecture(j.HiveArch, j.HostArch),
		Scope:                scope,
		UserSID:              sid,
		EstimatedSizeKB:      j.EstimatedSize,
		UninstallString:      j.UninstallString,
		QuietUninstallString: j.QuietUninstallString,
		RegistryKey:          j.RegistryKey,
	}, j.SystemComponent == 1, isInstalledSoftwareUpdate(j.ParentKeyName, j.ReleaseType)
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// List returns the installed software inventory in a single round-trip,
// filtered Go-side and sorted by name (case-insensitive), then version,
// then registry key. Filters are validated before any host call; an invalid
// filter never reaches the host. Only the normalised product code is
// pre-filtered host-side (exact key-name match); the machine hives are
// always enumerated and the loaded per-user hives only when
// IncludeUserInstalls is set. An empty result is valid (empty packages, nil
// error). Win32_Product is never queried.
func (s *InstalledSoftwareClient) List(ctx context.Context, filter InstalledSoftwareFilter) (*InstalledSoftwareResult, error) {
	nameRe, pubRe, productCode, err := validateInstalledSoftwareFilter(filter)
	if err != nil {
		return nil, err
	}
	resp, err := s.runInstalledSoftwareEnvelope(ctx, "list",
		buildInstalledSoftwareListScript(productCode, filter.IncludeUserInstalls),
		map[string]string{})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Packages       []json.RawMessage `json:"packages"`
		SkippedEntries int64             `json:"skipped_entries"`
	}
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewInstalledSoftwareError(InstalledSoftwareErrorUnknown,
			"failed to parse installed software list JSON", jerr,
			map[string]string{"host": s.c.cfg.Host})
	}
	out := make([]InstalledSoftware, 0, len(payload.Packages))
	for _, raw := range payload.Packages {
		var j installedSoftwareJSON
		if uerr := json.Unmarshal(raw, &j); uerr != nil {
			// One corrupt row degrades to skipped instead of failing the
			// whole inventory; only a totally malformed envelope errors.
			payload.SkippedEntries++
			continue
		}
		if strings.TrimSpace(j.Name) == "" {
			continue
		}
		pkg, isSystem, isUpdate := projectInstalledSoftwareRow(j)
		if isSystem && !filter.IncludeSystemComponents {
			continue
		}
		if isUpdate && !filter.IncludeUpdates {
			continue
		}
		if nameRe != nil && !nameRe.MatchString(pkg.Name) {
			continue
		}
		if pubRe != nil && !pubRe.MatchString(pkg.Publisher) {
			continue
		}
		if productCode != "" && pkg.ProductCode != productCode {
			continue
		}
		out = append(out, pkg)
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].RegistryKey < out[j].RegistryKey
	})
	return &InstalledSoftwareResult{Packages: out, SkippedEntries: payload.SkippedEntries}, nil
}
