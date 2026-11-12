// Package winclient: shared storage helpers for disk-backed resources.
//
// Disk selection, the protected-storage guard and the PowerShell prelude
// live here so windows_disk (issue #290) and its follow-ups (partitions in
// #291, volumes in #292) share one implementation instead of drifting apart.
//
// Conventions (mirroring mgmtpath.go):
//   - Every user-supplied string reaching PowerShell is interpolated only
//     through psQuote. Disk numbers are ints rendered with Itoa, never user
//     text, so no quoting is required for them.
//   - CIM failures are classified from MI_RESULT / HRESULT codes first and
//     from localized message substrings only as a backstop: hosts are not
//     all English.
//   - The guard fails closed: a disk that cannot be proven safe is refused
//     with protected_storage rather than managed on a guess.
package winclient

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// PowerShell prelude
// ---------------------------------------------------------------------------

// psStorageHeader is prepended to every storage PS script. It pins the
// session culture to InvariantCulture so enum .ToString() values are always
// English regardless of the host locale, silences progress/warning streams
// that would otherwise pollute stdout, and defines the shared Emit-OK /
// Emit-Err / Classify-Storage helpers.
//
// Classify-Storage maps CIM/storage failures to DiskErrorKind values.
// Detection is HRESULT / MI_RESULT-first because those codes are stable
// across locales; message-substring matches remain as a backstop where no
// stable code exists. Callers fall back to DiskErrorUnknown when the kind is
// empty.
const psStorageHeader = `
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

function Classify-Storage([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  $mi = ''
  try { $mi = [string]$Rec.FullyQualifiedErrorId } catch { }
  try {
    if ($Rec.Exception -is [Microsoft.Management.Infrastructure.CimException]) { $mi = $mi + ' ' + [string]$Rec.Exception.MessageId }
  } catch { }
  # HRESULT / MI_RESULT identities first: stable across locales.
  if ($code -eq '0x80070005' -or $code -eq '0x80041003' -or $mi -match 'MI RESULT 2\b') { return 'access_denied' }
  if ($code -eq '0x80070490' -or $code -eq '0x80041002' -or $mi -match 'MI RESULT 6\b') { return 'disk_not_found' }
  # Localized-substring backstop.
  if ($msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'not authorized' -or $msg -match 'UnauthorizedAccess') { return 'access_denied' }
  if ($msg -match 'is not recognized' -or $msg -match 'CommandNotFoundException') { return 'unsupported' }
  if ($msg -match 'No MSFT_Disk' -or $msg -match 'No disk' -or $msg -match 'does not exist' -or $msg -match 'could not find' -or $msg -match 'Cannot find') { return 'disk_not_found' }
  if ($msg -match 'is offline' -or $msg -match 'offline disk') { return 'disk_offline' }
  if ($msg -match 'already initialized' -or $msg -match 'is not raw' -or $msg -match 'is not RAW') { return 'partition_style_mismatch' }
  return 'unknown'
}
`

// ---------------------------------------------------------------------------
// Disk selector
// ---------------------------------------------------------------------------

// DiskSelector identifies one physical disk on the target host. Exactly one
// of the four coordinates must be set (enforced by the provider schema via
// ExactlyOneOf and re-checked defensively here): UniqueID (Get-Disk
// UniqueId, the stable identity and Terraform resource ID), SerialNumber
// (Get-Disk SerialNumber), Location (Get-Disk Location) or Number (Get-Disk
// Number, the least stable coordinate: Windows assigns it at scan time and
// it can shift across reboots or when disks are added/removed).
type DiskSelector struct {
	// UniqueID is the Get-Disk UniqueId (e.g. "SCSI\\DISK&VEN_...").
	UniqueID string
	// SerialNumber is the Get-Disk SerialNumber.
	SerialNumber string
	// Location is the Get-Disk Location (adapter path).
	Location string
	// Number is the Get-Disk Number. HasNumber reports whether it is set:
	// disk 0 is valid, so the int zero value cannot mean "unset".
	Number int
	// HasNumber reports whether Number carries a selection.
	HasNumber bool
}

// DiskSelectorByUniqueID selects the disk with the given UniqueId.
func DiskSelectorByUniqueID(uniqueID string) DiskSelector {
	return DiskSelector{UniqueID: NormalizeDiskIdentity(uniqueID)}
}

// DiskSelectorBySerialNumber selects the disk with the given serial number.
func DiskSelectorBySerialNumber(serial string) DiskSelector {
	return DiskSelector{SerialNumber: NormalizeDiskIdentity(serial)}
}

// DiskSelectorByLocation selects the disk at the given adapter location.
func DiskSelectorByLocation(location string) DiskSelector {
	return DiskSelector{Location: NormalizeDiskIdentity(location)}
}

// DiskSelectorByNumber selects the disk with the given disk number.
func DiskSelectorByNumber(number int) DiskSelector {
	return DiskSelector{Number: number, HasNumber: true}
}

// setCount reports how many selector coordinates are set.
func (s DiskSelector) setCount() int {
	n := 0
	if strings.TrimSpace(s.UniqueID) != "" {
		n++
	}
	if strings.TrimSpace(s.SerialNumber) != "" {
		n++
	}
	if strings.TrimSpace(s.Location) != "" {
		n++
	}
	if s.HasNumber {
		n++
	}
	return n
}

// Validate reports whether the selector carries exactly one coordinate.
// The provider schema enforces this at plan time; the client re-checks so a
// programming error fails fast instead of matching every disk (zero set) or
// an unpredictable intersection (several set).
func (s DiskSelector) Validate() error {
	switch s.setCount() {
	case 1:
		if s.HasNumber {
			return ValidateDiskNumber(s.Number)
		}
		return nil
	case 0:
		return NewDiskError(DiskErrorUnknown,
			"no disk selector is set: exactly one of unique_id, serial_number, location or number is required",
			nil, nil)
	default:
		return NewDiskError(DiskErrorUnknown,
			"several disk selectors are set: exactly one of unique_id, serial_number, location or number is required",
			nil, map[string]string{"selector": s.Describe()})
	}
}

// Describe renders the selector for diagnostics and error context. Values
// are safe to log: disk identities carry no secrets.
func (s DiskSelector) Describe() string {
	switch {
	case strings.TrimSpace(s.UniqueID) != "":
		return fmt.Sprintf("unique_id %q", strings.TrimSpace(s.UniqueID))
	case strings.TrimSpace(s.SerialNumber) != "":
		return fmt.Sprintf("serial_number %q", strings.TrimSpace(s.SerialNumber))
	case strings.TrimSpace(s.Location) != "":
		return fmt.Sprintf("location %q", strings.TrimSpace(s.Location))
	case s.HasNumber:
		return fmt.Sprintf("number %d", s.Number)
	default:
		return "no selector"
	}
}

// NormalizeDiskIdentity canonicalises a string disk identity (unique_id,
// serial_number, location) for comparison: surrounding whitespace is
// dropped and the remainder is upper-cased. Get-Disk spellings vary in case
// and padding, and PowerShell -eq already compares case-insensitively, so
// both sides normalize to the same form.
func NormalizeDiskIdentity(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

// ValidateDiskNumber rejects negative disk numbers. Disk 0 is valid.
func ValidateDiskNumber(n int) error {
	if n < 0 {
		return NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("invalid disk number %d: numbers start at 0", n),
			nil, map[string]string{"number": strconv.Itoa(n)})
	}
	return nil
}

// ---------------------------------------------------------------------------
// Protected-storage guard (pure-Go decision)
// ---------------------------------------------------------------------------

// DiskGuardInfo carries the placement facts the host reports for one disk.
// The PowerShell probe collects them; ProtectedStorageReason decides.
type DiskGuardInfo struct {
	// IsBoot / IsSystem / IsClustered mirror the Get-Disk flags.
	IsBoot      bool
	IsSystem    bool
	IsClustered bool
	// HoldsPagefile is true when an active pagefile lives on the disk.
	HoldsPagefile bool
	// HoldsCrashDump is true when the crash-dump target lives on the disk.
	HoldsCrashDump bool
	// PlacementUnknown is true when pagefile/crash-dump placement could not
	// be determined. The guard fails closed on it: refusing is safer than
	// managing a disk that might page the host.
	PlacementUnknown bool
}

// ProtectedStorageReason returns the human-readable reason the disk must
// not be managed, or "" when it is safe. Any non-empty reason maps to the
// protected_storage error. The precedence (boot, system, clustered,
// pagefile, crash-dump, undeterminable placement) mirrors Test-DiskProtected
// in disk.go, which additionally skips the pagefile/crash-dump probe while
// the disk is offline (an offline disk hosts no active pagefile; placement
// is re-verified the next time it is online). An undeterminable placement
// fails closed last.
func (g DiskGuardInfo) ProtectedStorageReason() string {
	switch {
	case g.IsBoot:
		return "the disk is the boot disk"
	case g.IsSystem:
		return "the disk is the system disk"
	case g.IsClustered:
		return "the disk is clustered"
	case g.HoldsPagefile:
		return "the disk hosts the active pagefile"
	case g.HoldsCrashDump:
		return "the disk hosts the crash-dump target"
	case g.PlacementUnknown:
		return "pagefile/crash-dump placement could not be determined"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Storage sizes (pure-Go parse/validate)
// ---------------------------------------------------------------------------

// Binary size multipliers matching PowerShell suffix semantics (1KB = 1024).
const (
	storageByte = 1
	storageKB   = 1024
	storageMB   = 1024 * 1024
	storageGB   = 1024 * 1024 * 1024
	storageTB   = 1024 * 1024 * 1024 * 1024
	storagePB   = 1024 * 1024 * 1024 * 1024 * 1024
)

// storageSizeUnits maps accepted suffixes (upper-cased, trimmed) to their
// byte multiplier. Single letters follow PowerShell (1K = 1KB = 1024); the
// 1000-based SI spellings are deliberately absent so "10MB" never means
// 10,000,000 bytes here.
var storageSizeUnits = map[string]int64{
	"B": storageByte, "": storageByte,
	"K": storageKB, "KB": storageKB, "KIB": storageKB, "KI": storageKB,
	"M": storageMB, "MB": storageMB, "MIB": storageMB, "MI": storageMB,
	"G": storageGB, "GB": storageGB, "GIB": storageGB, "GI": storageGB,
	"T": storageTB, "TB": storageTB, "TIB": storageTB, "TI": storageTB,
	"P": storagePB, "PB": storagePB, "PIB": storagePB, "PI": storagePB,
}

// ParseStorageSizeBytes parses a human size ("1024", "512MB", "10 GiB",
// "1.5T") into bytes. Fractions are allowed only when they resolve to a
// whole byte. Partition sizing (#291) shares this helper.
//
// The arithmetic is exact: float64 cannot represent every int64 (precision
// is lost past 2^53), so the decimal is scaled as a rational instead.
// Explicit signs are rejected: sizes are magnitudes, so "+5GB" is not an
// accepted spelling and "-" never yields a positive byte count.
func ParseStorageSizeBytes(raw string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return 0, NewDiskError(DiskErrorUnknown, "size must not be empty", nil, nil)
	}
	// Split the leading numeric prefix from the unit suffix.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.' || s[i] == '+' || s[i] == '-') {
		i++
	}
	numPart := strings.TrimSpace(s[:i])
	unitPart := strings.TrimSpace(s[i:])
	mult, ok := storageSizeUnits[unitPart]
	if !ok {
		return 0, NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("unknown size suffix %q in %q (want B, K/KB/KiB, M/MB/MiB, G/GB/GiB, T/TB/TiB or P/PB/PiB)", unitPart, raw),
			nil, map[string]string{"size": raw})
	}
	if strings.ContainsAny(numPart, "+-") {
		return 0, NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("invalid size %q: explicit signs are not accepted", raw), nil, map[string]string{"size": raw})
	}
	if numPart == "" || strings.Count(numPart, ".") > 1 {
		return 0, NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("invalid size %q", raw), nil, map[string]string{"size": raw})
	}
	for _, c := range strings.ReplaceAll(numPart, ".", "") {
		if c < '0' || c > '9' {
			return 0, NewDiskError(DiskErrorUnknown,
				fmt.Sprintf("invalid size %q", raw), nil, map[string]string{"size": raw})
		}
	}
	// Normalize edge decimals ("1."/"0.5"-style) to a form the rational
	// parser accepts; both spellings resolved through float64 before.
	if strings.HasPrefix(numPart, ".") {
		numPart = "0" + numPart
	}
	numPart = strings.TrimSuffix(numPart, ".")
	num, ok := new(big.Rat).SetString(numPart)
	if !ok {
		return 0, NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("invalid size %q", raw), nil, map[string]string{"size": raw})
	}
	bytesRat := new(big.Rat).Mul(num, big.NewRat(mult, 1))
	if bytesRat.Sign() <= 0 || !bytesRat.IsInt() {
		return 0, NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("invalid size %q: must resolve to a positive whole number of bytes", raw),
			nil, map[string]string{"size": raw})
	}
	bytesNum := bytesRat.Num()
	if !bytesNum.IsInt64() {
		return 0, NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("invalid size %q: must resolve to a positive whole number of bytes", raw),
			nil, map[string]string{"size": raw})
	}
	return bytesNum.Int64(), nil
}

// ValidateStorageSizeBytes rejects non-positive sizes.
func ValidateStorageSizeBytes(bytes int64) error {
	if bytes <= 0 {
		return NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("invalid size %d: must be a positive number of bytes", bytes),
			nil, map[string]string{"size": strconv.FormatInt(bytes, 10)})
	}
	return nil
}

// ---------------------------------------------------------------------------
// GPT partition-type GUIDs
// ---------------------------------------------------------------------------

// Well-known GPT partition-type GUIDs (canonical upper-case with braces
// omitted, as Get-Partition GptType reports them). Initializing a disk only
// needs the style, but validating partition layouts (#291) compares GptType
// values against these constants.
const (
	// GPTBasicDataPartitionGUID is the plain data partition (EBD0A0A2-...).
	GPTBasicDataPartitionGUID = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
	// GPTEFIPartitionGUID is the EFI System Partition (C12A7328-...).
	GPTEFIPartitionGUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
	// GPTMicrosoftReservedGUID is the MSR partition (E3C9E316-...).
	GPTMicrosoftReservedGUID = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE"
	// GPTRecoveryPartitionGUID is the Windows recovery partition (DE94BBA4-...).
	GPTRecoveryPartitionGUID = "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"
	// GPTStorageSpacesPartitionGUID is the Storage Spaces partition (E75CAF8F-...).
	GPTStorageSpacesPartitionGUID = "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D"
)
