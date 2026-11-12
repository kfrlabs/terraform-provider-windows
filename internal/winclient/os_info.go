// Package winclient: OS inventory (windows_os_info data source) over SSH.
//
// OSInfoClient is the concrete WindowsOSInfoClient backing the standalone
// windows_os_info Terraform data source (no sibling resource). The single
// Read operation collects Win32_OperatingSystem, the HKLM CurrentVersion
// key, Win32_Processor and the MachineGuid in one round-trip, wrapped in
// the JSON envelope (Emit-OK/Emit-Err) so stdout is machine-parseable
// regardless of the Windows locale.
//
// Security invariants:
//   - Read takes no user input, so no value is interpolated into the script
//     body (psQuote is unnecessary here; do not add interpolation without
//     routing it through psQuote).
//   - Scripts never call "exit": since #81 a script may run inside a
//     long-lived, reused PowerShell session, where "exit" would kill that
//     session instead of just this call. Early returns use "return" after
//     Emit-Err instead.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
)

// Compile-time assertion: OSInfoClient satisfies WindowsOSInfoClient.
var _ WindowsOSInfoClient = (*OSInfoClient)(nil)

// OSInfoClient is the PowerShell/SSH-backed WindowsOSInfoClient.
type OSInfoClient struct {
	c *Client
}

// NewOSInfoClient constructs an OSInfoClient wrapping the given SSH Client.
func NewOSInfoClient(c *Client) *OSInfoClient {
	return &OSInfoClient{c: c}
}

// psOSInfoHeader prepends Emit-OK/Emit-Err and Classify-OSInfo.
//
// Classify-OSInfo maps CIM / registry error substrings to OSInfoErrorKind
// values. Detection is best-effort and substring-based because Windows
// error messages are localised.
const psOSInfoHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Classify-OSInfo([string]$Msg) {
  if ($Msg -match 'Access is denied' -or $Msg -match 'AccessDenied' -or (($Msg -match '\b5\b') -and ($Msg -match 'denied'))) { return 'access_denied' }
  if ($Msg -match 'winmgmt' -or $Msg -match '\bWMI\b' -or $Msg -match '\bCIM\b' -or $Msg -match 'CimException' -or $Msg -match 'Get-CimInstance' -or $Msg -match '\brepository\b' -or $Msg -match 'provider load failure') { return 'cim_unavailable' }
  return 'unknown'
}
`

// psOSInfoReadBody defines Read-OSInfo, which collects the OS inventory in
// a single round-trip. Every volatile read degrades to its zero value
// instead of failing the whole call: dates fall back to "", numeric casts
// fall back to 0, DisplayVersion falls back to ReleaseId on hosts that
// predate it, and MachineGuid falls back to "" (the data source then uses
// the singleton literal "current" as the ID).
const psOSInfoReadBody = `
function Read-OSInfo {
  $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $cv   = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $proc = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
  try { $installDate = ([Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)).ToUniversalTime().ToString('o') } catch { $installDate = "" }
  try { $lastBoot = ([Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)).ToUniversalTime().ToString('o') } catch { $lastBoot = "" }
  $psVersion = $PSVersionTable.PSVersion.ToString()
  try { $osLang = (Get-Culture).Name } catch { $osLang = "" }
  try { $mid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid } catch { $mid = "" }
  try { $build = [int64]$cv.CurrentBuild } catch { $build = [int64]0 }
  try { $ubr = [int64]$cv.UBR } catch { $ubr = [int64]0 }
  try { $dv = [string]$cv.DisplayVersion } catch { $dv = "" }
  if ([string]::IsNullOrEmpty($dv)) { try { $dv = [string]$cv.ReleaseId } catch { $dv = "" } }
  try { $sku = [int64]$os.OperatingSystemSKU } catch { $sku = [int64]0 }
  try { $ptRaw = [int64]$os.ProductType } catch { $ptRaw = [int64]0 }
  try { $archRaw = [int64]$proc.Architecture } catch { $archRaw = [int64]0 }
  return [ordered]@{
    product_name       = [string]$os.Caption
    version            = [string]$os.Version
    build_number       = $build
    ubr                = $ubr
    display_version    = $dv
    edition_id         = [string]$cv.EditionID
    sku                = $sku
    installation_type  = [string]$cv.InstallationType
    product_type_raw   = $ptRaw
    architecture_raw   = $archRaw
    install_date       = $installDate
    last_boot_time     = $lastBoot
    system_drive       = [string]$os.SystemDrive
    windows_directory  = [string]$os.WindowsDirectory
    os_language        = $osLang
    powershell_version = $psVersion
    machine_id         = [string]$mid
  }
}
`

// osInfoPSResponse is the parsed JSON envelope for OS inventory reads. It
// aliases the shared Envelope type so every resource parses the same shape
// through runEnvelope (#198).
type osInfoPSResponse = Envelope

// runOSInfoEnvelope executes script (prepended with psOSInfoHeader) through
// the shared runEnvelope helper without stdin, mapping failures to
// *OSInfoError.
func (o *OSInfoClient) runOSInfoEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*osInfoPSResponse, error) {
	baseContext := map[string]string{"host": o.c.cfg.Host}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, o.c, full)
		},
		op, psOSInfoHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	return resp, mapOSInfoEnvelopeError(eerr)
}

// mapOSInfoEnvelopeError converts an *EnvelopeError to an *OSInfoError.
// Context cancellation keeps a timeout kind; remote Emit-Err kinds map
// through mapOSInfoKind.
func mapOSInfoEnvelopeError(eerr *EnvelopeError) error {
	if eerr.Stage == EnvelopeStageTimeout {
		return NewOSInfoError(OSInfoErrorTimeout, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return NewOSInfoError(OSInfoErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return NewOSInfoError(mapOSInfoKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapOSInfoKind translates the PS-side "kind" string to a typed
// OSInfoErrorKind.
func mapOSInfoKind(k string) OSInfoErrorKind {
	switch k {
	case string(OSInfoErrorAccessDenied),
		string(OSInfoErrorCIMUnavailable),
		string(OSInfoErrorTimeout),
		string(OSInfoErrorInvalidParameter):
		return OSInfoErrorKind(k)
	default:
		return OSInfoErrorUnknown
	}
}

// osInfoPayload mirrors the JSON object produced by Read-OSInfo. Numbers
// arrive as JSON numbers; missing keys unmarshal to their zero values.
type osInfoPayload struct {
	ProductName      string `json:"product_name"`
	Version          string `json:"version"`
	BuildNumber      int64  `json:"build_number"`
	UBR              int64  `json:"ubr"`
	DisplayVersion   string `json:"display_version"`
	EditionID        string `json:"edition_id"`
	SKU              int64  `json:"sku"`
	InstallationType string `json:"installation_type"`
	ProductTypeRaw   int64  `json:"product_type_raw"`
	ArchitectureRaw  int64  `json:"architecture_raw"`
	InstallDate      string `json:"install_date"`
	LastBootTime     string `json:"last_boot_time"`
	SystemDrive      string `json:"system_drive"`
	WindowsDirectory string `json:"windows_directory"`
	OSLanguage       string `json:"os_language"`
	PowerShellVer    string `json:"powershell_version"`
	MachineID        string `json:"machine_id"`
}

// skuName maps a Win32_OperatingSystem.OperatingSystemSKU value to its
// documented product name. Unlisted codes return "" so new SKUs degrade
// instead of erroring. Reference: MS documentation of the
// OperatingSystemSKU property (PRODUCT_* constants).
func skuName(sku int64) string {
	switch sku {
	case 0:
		return ""
	case 1:
		return "Ultimate"
	case 2:
		return "Home Basic"
	case 3:
		return "Home Premium"
	case 4:
		return "Enterprise"
	case 5:
		return "Home Basic N"
	case 6:
		return "Business"
	case 7:
		return "Server Standard"
	case 8:
		return "Server Datacenter"
	case 10:
		return "Enterprise Server"
	case 12:
		return "Server Datacenter Core"
	case 13:
		return "Server Standard Core"
	case 14:
		return "Enterprise Server Core"
	case 48:
		return "Professional"
	default:
		return ""
	}
}

// osProductType maps a Win32_OperatingSystem.ProductType value to its
// documented name. Unknown values return "".
func osProductType(raw int64) string {
	switch raw {
	case 1:
		return "Workstation"
	case 2:
		return "DomainController"
	case 3:
		return "Server"
	default:
		return ""
	}
}

// osArchitecture maps a Win32_Processor.Architecture value to its
// documented name. Unknown values return "".
func osArchitecture(raw int64) string {
	switch raw {
	case 0:
		return "x86"
	case 5:
		return "arm"
	case 9:
		return "x64"
	case 12:
		return "arm64"
	default:
		return ""
	}
}

// toOSInfo projects a payload onto the public OSInfo type, deriving
// FullBuild, SKUName, ProductType, Architecture, IsServer and IsServerCore.
func toOSInfo(p *osInfoPayload) *OSInfo {
	if p == nil {
		return nil
	}
	full := fmt.Sprintf("%d", p.BuildNumber)
	if p.UBR > 0 {
		full = fmt.Sprintf("%d.%d", p.BuildNumber, p.UBR)
	}
	return &OSInfo{
		MachineID:         p.MachineID,
		ProductName:       p.ProductName,
		Version:           p.Version,
		BuildNumber:       p.BuildNumber,
		UBR:               p.UBR,
		FullBuild:         full,
		DisplayVersion:    p.DisplayVersion,
		EditionID:         p.EditionID,
		SKU:               p.SKU,
		SKUName:           skuName(p.SKU),
		InstallationType:  p.InstallationType,
		IsServer:          p.ProductTypeRaw == 2 || p.ProductTypeRaw == 3,
		IsServerCore:      p.InstallationType == "Server Core",
		ProductType:       osProductType(p.ProductTypeRaw),
		Architecture:      osArchitecture(p.ArchitectureRaw),
		InstallDate:       p.InstallDate,
		LastBootTime:      p.LastBootTime,
		SystemDrive:       p.SystemDrive,
		WindowsDirectory:  p.WindowsDirectory,
		OSLanguage:        p.OSLanguage,
		PowerShellVersion: p.PowerShellVer,
	}
}

// Read returns the current OS inventory of the target host in a single
// round-trip.
func (o *OSInfoClient) Read(ctx context.Context) (*OSInfo, error) {
	script := psOSInfoReadBody + "\ntry { $s = Read-OSInfo; Emit-OK $s } catch { Emit-Err (Classify-OSInfo $_.Exception.Message) $_.Exception.Message @{} }"
	resp, err := o.runOSInfoEnvelope(ctx, "read", script, nil)
	if err != nil {
		return nil, err
	}
	var payload osInfoPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewOSInfoError(OSInfoErrorUnknown, "failed to parse OS inventory", jerr, map[string]string{"host": o.c.cfg.Host})
	}
	return toOSInfo(&payload), nil
}
