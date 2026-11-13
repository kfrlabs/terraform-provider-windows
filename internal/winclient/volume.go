// Package winclient: Windows volume CRUD over SSH.
//
// This file provides VolumeClient, the concrete WindowsVolumeClient used by
// the windows_volume Terraform resource and data source. All operations
// execute PowerShell scripts wrapped in a JSON envelope (Emit-OK/Emit-Err) so
// stdout is machine-parseable regardless of Windows locale.
//
// Identity is the Get-Volume UniqueId (the `\\?\Volume{...}\` object path).
// The hosting partition ("<disk_unique_id>|<key>") is resolved host-side
// from the volume so imports can repopulate the required partition_id input.
//
// Security invariants:
//   - Partition keys, the disk UniqueId, the volume UniqueId, the lookup
//     value, the file system name and the label are interpolated only
//     through psQuote (single-quoted PS literal) so $var / backtick /
//     subexpression injection is impossible. Allocation unit sizes are int64
//     magnitudes rendered with FormatInt; bools render as $true/$false
//     tokens; the file system is a validated canonical literal (NTFS, ReFS,
//     exFAT, FAT32). No user input ever reaches the script unquoted.
//   - Scripts never terminate the session: they signal completion with
//     `return` after Emit-OK/Emit-Err (since #81 the client keeps one
//     long-lived PowerShell session, where `exit` would kill the session
//     instead of just the call).
//   - Every mutating cmdlet carries -Confirm:$false so a non-interactive
//     session never blocks on a confirmation prompt, and every operation
//     refreshes the storage cache with Update-HostStorageCache first.
//
// Reused helpers from the same package:
//   - psStorageHeader + Classify-Storage - shared prelude (storage_common.go)
//   - DiskSelector                      - exactly-one selector (storage_common.go)
//   - Resolve-Disk / Test-DiskProtected - disk resolution + guard (disk.go)
//   - Resolve-Partition / Test-PartitionProtected - partition resolution +
//     guard (partition.go); identity is the GUID/offset key, never the
//     scan-time partition number
//   - ParsePartitionID                  - partition identity split (partition_types.go)
//   - runEnvelope                       - shared JSON envelope pipeline (envelope.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Compile-time assertion: VolumeClient satisfies WindowsVolumeClient.
var _ WindowsVolumeClient = (*VolumeClient)(nil)

// VolumeClient is the PowerShell/SSH-backed WindowsVolumeClient.
type VolumeClient struct {
	c *Client
}

// NewVolumeClient constructs a VolumeClient wrapping the given SSH Client.
func NewVolumeClient(c *Client) *VolumeClient { return &VolumeClient{c: c} }

// runVolumePowerShell is the package-level indirection used by VolumeClient.
// Tests override it; production code must not.
var runVolumePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// ---------------------------------------------------------------------------
// Shared PowerShell fragments
// ---------------------------------------------------------------------------

// psVolumeFunctions defines ConvertTo-VolumeJson, Resolve-VolumeFromPartition
// and Classify-Volume on top of psStorageHeader, psDiskFunctions and
// psPartitionFunctions (partition.go). Format scripts are:
// psStorageHeader + disk selector vars + psDiskFunctions +
// psPartitionFunctions + psVolumeFunctions + one op body; read/label/lookup
// scripts skip the disk selector vars (they never resolve a disk).
//
// Resolve-VolumeFromPartition pipes the resolved partition to Get-Volume. An
// unformatted partition has no volume (Get-Volume throws "No MSFT_Volume
// objects found"): that probe failure returns $null so the caller can
// format; any other probe failure is re-emitted so a real error never reads
// as "unformatted".
//
// ConvertTo-VolumeJson resolves the hosting partition back from the volume
// (Get-Partition -Volume, then the disk UniqueId) so the payload carries the
// "<disk_unique_id>|<key>" partition_id imports need. When that reverse
// lookup fails the field is empty and the Go layer keeps the prior value
// (imports reject an empty partition_id instead).
//
// Classify-Volume maps CIM/storage failures via Classify-Storage first
// (stable HRESULT / MI_RESULT codes), then volume-specific message patterns.
// File-system and allocation-unit validation already runs Go-side, so those
// patterns are a backstop for host-side rejections (e.g. Set-Volume refusing
// an over-long label).
const psVolumeFunctions = `
function Resolve-VolumeFromPartition([object]$P, [string]$UniqueId) {
  $vol = $null
  $volErr = $null
  try {
    $vol = $P | Get-Volume -ErrorAction Stop
  } catch {
    $volErr = $_
  }
  if (($null -eq $vol) -and ($null -ne $volErr)) {
    $k = Classify-Volume $volErr
    if ($k -ne 'not_found') {
      Emit-Err $k ([string]$volErr.Exception.Message) @{ phase = 'probe_volume'; unique_id = $UniqueId }
      return 'error'
    }
  }
  return $vol
}

function ConvertTo-VolumeJson([object]$V) {
  $sz = 0
  try { $sz = [uint64]$V.Size } catch { $sz = 0 }
  $rem = 0
  try { $rem = [uint64]$V.SizeRemaining } catch { $rem = 0 }
  $aus = 0
  try { $aus = [uint64]$V.AllocationUnitSize } catch { $aus = 0 }
  $partId = ''
  try {
    $part = Get-Partition -Volume $V -ErrorAction Stop
    $disk = Get-Disk -Number ([int]$part.DiskNumber) -ErrorAction Stop
    $key = [string]$part.Guid
    if (($key -eq '') -or ($key -eq '00000000-0000-0000-0000-000000000000')) { $key = [string]([uint64]$part.Offset) }
    $partId = [string]$disk.UniqueId + '|' + $key
  } catch {
    $partId = ''
  }
  return [ordered]@{
    unique_id            = [string]$V.UniqueId
    partition_id         = $partId
    drive_letter         = ([string]$V.DriveLetter).ToUpperInvariant()
    path                 = [string]$V.Path
    file_system          = [string]$V.FileSystem
    file_system_label    = [string]$V.FileSystemLabel
    allocation_unit_size = $aus
    size_bytes           = $sz
    size_remaining_bytes = $rem
    health_status        = [string]$V.HealthStatus
    operational_status   = [string]$V.OperationalStatus
    drive_type           = [string]$V.DriveType
  }
}

function Test-VolumeFormatted([object]$V) {
  $fs = ([string]$V.FileSystem).Trim()
  if (($fs -eq '') -or ($fs -eq 'RAW') -or ($fs.ToUpperInvariant() -eq 'UNKNOWN')) { return '' }
  return $fs
}

function Classify-Volume([object]$Rec) {
  $base = Classify-Storage $Rec
  if ($base -ne 'unknown') { return $base }
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'not a (valid|supported|recognized) file system' -or $msg -match 'is not a valid file system' -or $msg -match 'Invalid file system') { return 'unsupported_file_system' }
  if ($msg -match 'allocation unit' -or $msg -match 'cluster size') { return 'invalid_allocation_unit' }
  if ($msg -match 'No MSFT_Volume' -or $msg -match 'No MSFT_Partition' -or $msg -match 'could not find' -or $msg -match 'Cannot find' -or $msg -match 'does not exist') { return 'not_found' }
  return 'unknown'
}
`

// volumeFormatScript concatenates the shared prelude, the disk selector vars
// for the hosting disk, the disk + partition + volume function libraries and
// one op body into a complete format script.
func volumeFormatScript(diskUniqueID, body string) string {
	return psStorageHeader + "\n" + buildDiskSelectorVars(DiskSelectorByUniqueID(diskUniqueID)) + "\n" + psDiskFunctions + "\n" + psPartitionFunctions + "\n" + psVolumeFunctions + "\n" + body + "\n"
}

// volumeDirectScript concatenates the shared prelude, the volume function
// library (disk/partition resolution is included for the format-adjacent
// bodies that need it, but no selector vars: reads never resolve a disk)
// and one op body into a complete script.
func volumeDirectScript(body string) string {
	return psStorageHeader + "\n" + psDiskFunctions + "\n" + psPartitionFunctions + "\n" + psVolumeFunctions + "\n" + body + "\n"
}

// psVolumeVars renders the $vol* variables consumed by the format body.
// Strings go through psQuote; the allocation unit size is an int64 magnitude
// rendered with FormatInt (the host casts to [uint32]); bools render as
// $true/$false tokens.
func psVolumeVars(partKey, fsName, fsLabel string, ausBytes int64, allowExisting, fullFormat bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$partKey = %s\n", psQuote(partKey))
	fmt.Fprintf(&b, "$fsName = %s\n", psQuote(fsName))
	fmt.Fprintf(&b, "$fsLabel = %s\n", psQuote(fsLabel))
	fmt.Fprintf(&b, "$ausBytes = %s\n", strconv.FormatInt(ausBytes, 10))
	if allowExisting {
		b.WriteString("$allowExisting = $true\n")
	} else {
		b.WriteString("$allowExisting = $false\n")
	}
	if fullFormat {
		b.WriteString("$fullFmt = $true\n")
	} else {
		b.WriteString("$fullFmt = $false\n")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Operation bodies
// ---------------------------------------------------------------------------

// psVolumeFormatBody resolves the disk and the partition (by GUID/offset,
// never by number), refuses protected storage fail-closed, refuses an
// already-formatted volume unless $allowExisting is set, formats it (quick by
// default, full when $fullFmt is set) and emits the re-read volume.
//
// The partition lookup stays quiet with an explicit partition_not_found
// emit: the volume vocabulary has no disk_not_found kind, so a gone
// partition (or a gone disk, whose disk_not_found maps Go-side to
// partition_not_found) reads as "the hosting partition is gone".
const psVolumeFormatBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  $p = Resolve-Partition $d $partKey $true
  if ($null -eq $p) {
    Emit-Err 'partition_not_found' ('No partition with key ' + $partKey + ' on disk ' + [string]$d.UniqueId + '.') @{ unique_id = [string]$d.UniqueId; key = $partKey }
    return
  }
  $preason = Test-PartitionProtected $p
  if ($preason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage a protected partition: ' + $preason + '.') @{ unique_id = [string]$d.UniqueId; key = $partKey; reason = $preason }
    return
  }
  $vol = Resolve-VolumeFromPartition $p ([string]$d.UniqueId)
  if ($vol -eq 'error') { return }
  if ($null -ne $vol) {
    $cur = Test-VolumeFormatted $vol
    if ($cur -ne '') {
      if (-not $allowExisting) {
        Emit-Err 'already_formatted' ('Partition ' + $partKey + ' on disk ' + [string]$d.UniqueId + ' already carries a formatted ' + $cur + ' volume. Set allow_format_existing to true to reformat it (this destroys its data), or import the existing volume.') @{ unique_id = [string]$d.UniqueId; key = $partKey; file_system = $cur }
        return
      }
    }
  }
  $params = @{ Partition = $p; FileSystem = $fsName; Confirm = $false; Force = $true; ErrorAction = 'Stop' }
  if ($fsLabel -ne '') { $params['NewFileSystemLabel'] = $fsLabel }
  if ([int64]$ausBytes -gt 0) { $params['AllocationUnitSize'] = [uint32]$ausBytes }
  if ($fullFmt) { $params['Full'] = $true }
  try {
    Format-Volume @params -Confirm:$false | Out-Null
  } catch {
    Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 'format'; unique_id = [string]$d.UniqueId; key = $partKey; file_system = $fsName }
    return
  }
  $fresh = $null
  try {
    $fresh = $p | Get-Volume -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 're_read'; unique_id = [string]$d.UniqueId; key = $partKey }
    return
  }
  Emit-OK (ConvertTo-VolumeJson $fresh)
}
`

// psVolumeReadBody reads one volume by UniqueId. A missing volume — or a
// present but unformatted one (null/RAW/Unknown file system) — is a
// not_found the Go layer swallows to (nil, nil).
const psVolumeReadBody = `
& {
  try { Update-HostStorageCache -ErrorAction Stop } catch { }
  $v = $null
  try {
    $v = Get-Volume -UniqueId $volId -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 'read'; unique_id = $volId }
    return
  }
  if ($null -eq $v) {
    Emit-Err 'not_found' ('No volume with UniqueId ' + $volId + '.') @{ unique_id = $volId }
    return
  }
  if ((Test-VolumeFormatted $v) -eq '') {
    Emit-Err 'not_found' ('Volume ' + $volId + ' is not formatted (its file system is null or RAW).') @{ unique_id = $volId }
    return
  }
  Emit-OK (ConvertTo-VolumeJson $v)
}
`

// psVolumeLabelBody re-labels one volume by UniqueId via Set-Volume and emits
// the re-read volume. An empty label clears the volume label. The hosting
// partition and disk resolve from the volume (Get-Partition -Volume /
// Get-Disk) and the protected-storage guards refuse boot/system/EFI/MSR/
// recovery/pagefile placement fail-closed before Set-Volume, mirroring the
// format path so an imported C: cannot be relabeled.
const psVolumeLabelBody = `
& {
  try { Update-HostStorageCache -ErrorAction Stop } catch { }
  $v = $null
  try {
    $v = Get-Volume -UniqueId $volId -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 'read'; unique_id = $volId }
    return
  }
  if ($null -eq $v) {
    Emit-Err 'not_found' ('No volume with UniqueId ' + $volId + '.') @{ unique_id = $volId }
    return
  }
  if ((Test-VolumeFormatted $v) -eq '') {
    Emit-Err 'not_found' ('Volume ' + $volId + ' is not formatted (its file system is null or RAW).') @{ unique_id = $volId }
    return
  }
  $part = $null
  try {
    $part = Get-Partition -Volume $v -ErrorAction Stop
  } catch {
    Emit-Err 'protected_storage' ('Refusing to relabel protected storage: the hosting partition could not be determined.') @{ unique_id = $volId; reason = 'hosting partition could not be determined' }
    return
  }
  if ($null -eq $part) {
    Emit-Err 'protected_storage' ('Refusing to relabel protected storage: the hosting partition could not be determined.') @{ unique_id = $volId; reason = 'hosting partition could not be determined' }
    return
  }
  $gdisk = $null
  try {
    $gdisk = Get-Disk -Number ([int]$part.DiskNumber) -ErrorAction Stop
  } catch {
    Emit-Err 'protected_storage' ('Refusing to relabel protected storage: the hosting disk could not be determined.') @{ unique_id = $volId; reason = 'hosting disk could not be determined' }
    return
  }
  if ($null -eq $gdisk) {
    Emit-Err 'protected_storage' ('Refusing to relabel protected storage: the hosting disk could not be determined.') @{ unique_id = $volId; reason = 'hosting disk could not be determined' }
    return
  }
  $reason = Test-DiskProtected $gdisk
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = $volId; reason = $reason }
    return
  }
  $preason = Test-PartitionProtected $part
  if ($preason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage a protected partition: ' + $preason + '.') @{ unique_id = $volId; reason = $preason }
    return
  }
  try {
    $v | Set-Volume -NewFileSystemLabel $fsLabel -Confirm:$false -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 'set_label'; unique_id = $volId }
    return
  }
  $fresh = $null
  try {
    $fresh = Get-Volume -UniqueId $volId -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 're_read'; unique_id = $volId }
    return
  }
  Emit-OK (ConvertTo-VolumeJson $fresh)
}
`

// psVolumeLookupBody resolves exactly one lookup coordinate — a drive letter
// ($lookupMode 'letter'), a volume UniqueId ('unique_id') or an exact file
// system label ('label') — and emits the volume. Zero matches are a
// not_found; several label matches are an unknown error (the volume
// vocabulary has no ambiguous kind); an unformatted match reads as
// not_found, like Read.
const psVolumeLookupBody = `
& {
  try { Update-HostStorageCache -ErrorAction Stop } catch { }
  $v = $null
  if ($lookupMode -eq 'letter') {
    try {
      $v = Get-Volume -DriveLetter $lookupValue -ErrorAction Stop
    } catch {
      Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 'lookup'; mode = $lookupMode; value = $lookupValue }
      return
    }
  } elseif ($lookupMode -eq 'unique_id') {
    try {
      $v = Get-Volume -UniqueId $lookupValue -ErrorAction Stop
    } catch {
      Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 'lookup'; mode = $lookupMode; value = $lookupValue }
      return
    }
  } else {
    $found = @()
    try {
      $found = @(Get-Volume -ErrorAction Stop | Where-Object { [string]$_.FileSystemLabel -eq $lookupValue })
    } catch {
      Emit-Err (Classify-Volume $_) ([string]$_.Exception.Message) @{ phase = 'lookup'; mode = $lookupMode; value = $lookupValue }
      return
    }
    if ($found.Count -eq 0) {
      Emit-Err 'not_found' ('No volume with file system label ' + $lookupValue + '.') @{ mode = $lookupMode; value = $lookupValue }
      return
    }
    if ($found.Count -gt 1) {
      Emit-Err 'unknown' ([string]$found.Count + ' volumes carry file system label ' + $lookupValue + '; refine the lookup to a drive letter or UniqueId.') @{ mode = $lookupMode; value = $lookupValue; match_count = [string]$found.Count }
      return
    }
    $v = $found[0]
  }
  if ($null -eq $v) {
    Emit-Err 'not_found' ('No volume matches the lookup.') @{ mode = $lookupMode; value = $lookupValue }
    return
  }
  if ((Test-VolumeFormatted $v) -eq '') {
    Emit-Err 'not_found' ('The matched volume is not formatted (its file system is null or RAW).') @{ mode = $lookupMode; value = $lookupValue }
    return
  }
  Emit-OK (ConvertTo-VolumeJson $v)
}
`

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

// buildVolumeFormatScript renders the full format script for opts. Sizes and
// the label are pre-validated Go-side; the file system is the canonical
// literal; the disk/partition guards and the already-formatted check run
// host-side in the same script so a concurrent change cannot slip between
// check and write.
func buildVolumeFormatScript(opts VolumeFormatOptions) string {
	disk, key, _ := ParsePartitionID(opts.PartitionID)
	vars := psVolumeVars(key, opts.FileSystem, opts.FileSystemLabel, opts.AllocationUnitSize, opts.AllowFormatExisting, opts.FullFormat)
	return volumeFormatScript(disk, vars+psVolumeFormatBody)
}

// buildVolumeReadScript renders the read-by-UniqueId script.
func buildVolumeReadScript(uniqueID string) string {
	return volumeDirectScript(fmt.Sprintf("$volId = %s\n", psQuote(uniqueID)) + psVolumeReadBody)
}

// buildVolumeLabelScript renders the re-label script.
func buildVolumeLabelScript(uniqueID, label string) string {
	return volumeDirectScript(fmt.Sprintf("$volId = %s\n$fsLabel = %s\n", psQuote(uniqueID), psQuote(label)) + psVolumeLabelBody)
}

// buildVolumeLookupScript renders the import/data-source lookup script for
// exactly one coordinate.
func buildVolumeLookupScript(lookup VolumeLookup) string {
	mode := ""
	value := ""
	switch {
	case strings.TrimSpace(lookup.UniqueID) != "":
		mode, value = "unique_id", strings.TrimSpace(lookup.UniqueID)
	case strings.TrimSpace(lookup.DriveLetter) != "":
		mode, value = "letter", strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(lookup.DriveLetter), ":"))
	default:
		mode, value = "label", strings.TrimSpace(lookup.FileSystemLabel)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$lookupMode = %s\n", psQuote(mode))
	fmt.Fprintf(&b, "$lookupValue = %s\n", psQuote(value))
	return volumeDirectScript(b.String() + psVolumeLookupBody)
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// volumeJSON mirrors the JSON object emitted by ConvertTo-VolumeJson.
type volumeJSON struct {
	UniqueID           string `json:"unique_id"`
	PartitionID        string `json:"partition_id"`
	DriveLetter        string `json:"drive_letter"`
	Path               string `json:"path"`
	FileSystem         string `json:"file_system"`
	FileSystemLabel    string `json:"file_system_label"`
	AllocationUnitSize uint64 `json:"allocation_unit_size"`
	SizeBytes          uint64 `json:"size_bytes"`
	SizeRemainingBytes uint64 `json:"size_remaining_bytes"`
	HealthStatus       string `json:"health_status"`
	OperationalStatus  string `json:"operational_status"`
	DriveType          string `json:"drive_type"`
}

// parseVolumeInfo projects a volumeJSON payload onto a VolumeInfo. An empty
// envelope, an unparseable payload, a missing UniqueId (the Terraform ID
// anchor) or an overflowing size is an unknown error: the read cannot be
// trusted. An empty PartitionID is tolerated (the resource keeps the prior
// value; imports reject it instead). An empty drive letter means "no
// letter"; the file system is converged to canonical form when recognized.
func parseVolumeInfo(raw json.RawMessage, host string) (*VolumeInfo, error) {
	ctx := map[string]string{"host": host}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, NewVolumeError(VolumeErrorUnknown, "empty volume state returned by the host", nil, ctx)
	}
	var j volumeJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, NewVolumeError(VolumeErrorUnknown, "failed to parse volume state JSON", err, ctx)
	}
	if strings.TrimSpace(j.UniqueID) == "" {
		return nil, NewVolumeError(VolumeErrorUnknown,
			"the host returned a volume without a UniqueId, which cannot be adopted as a Terraform resource", nil, ctx)
	}
	if j.SizeBytes > math.MaxInt64 {
		return nil, NewVolumeError(VolumeErrorUnknown, "the host returned a volume size that overflows int64", nil, ctx)
	}
	if j.SizeRemainingBytes > math.MaxInt64 {
		return nil, NewVolumeError(VolumeErrorUnknown, "the host returned a volume remaining size that overflows int64", nil, ctx)
	}
	if j.AllocationUnitSize > math.MaxInt64 {
		return nil, NewVolumeError(VolumeErrorUnknown, "the host returned an allocation unit size that overflows int64", nil, ctx)
	}
	fs := strings.TrimSpace(j.FileSystem)
	if canon, err := CanonicalizeVolumeFileSystem(fs); err == nil {
		fs = canon
	}
	return &VolumeInfo{
		UniqueID:           strings.TrimSpace(j.UniqueID),
		PartitionID:        strings.TrimSpace(j.PartitionID),
		DriveLetter:        strings.ToUpper(strings.TrimSpace(j.DriveLetter)),
		Path:               strings.TrimSpace(j.Path),
		FileSystem:         fs,
		FileSystemLabel:    j.FileSystemLabel,
		AllocationUnitSize: int64(j.AllocationUnitSize),
		SizeBytes:          int64(j.SizeBytes),
		SizeRemainingBytes: int64(j.SizeRemainingBytes),
		HealthStatus:       j.HealthStatus,
		OperationalStatus:  j.OperationalStatus,
		DriveType:          j.DriveType,
	}, nil
}

// runVolumeEnvelope executes script and parses the JSON envelope through the
// shared runEnvelope helper. Transport/timeout failures map to unknown (the
// volume vocabulary has no dedicated timeout kind); remote Emit-Err kinds
// map via mapVolumeKind.
func (c *VolumeClient) runVolumeEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
	baseContext := map[string]string{
		"host":      c.c.cfg.Host,
		"port":      strconv.Itoa(c.c.cfg.Port),
		"transport": "ssh",
	}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runVolumePowerShell(ctx, c.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewVolumeError(VolumeErrorUnknown,
			fmt.Sprintf("operation %q timed out or was cancelled", op), eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewVolumeError(VolumeErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewVolumeError(mapVolumeKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapVolumeKind translates the PS-side "kind" string to a typed
// VolumeErrorKind. The disk vocabulary's disk_not_found has no volume
// counterpart: it surfaces only from the format path (a gone hosting disk)
// and reads as partition_not_found. Unknown values fall through to Unknown.
func mapVolumeKind(k string) VolumeErrorKind {
	switch VolumeErrorKind(k) {
	case VolumeErrorNotFound,
		VolumeErrorPartitionNotFound,
		VolumeErrorAlreadyFormatted,
		VolumeErrorProtected,
		VolumeErrorUnsupportedFileSystem,
		VolumeErrorInvalidAllocationUnit,
		VolumeErrorAccessDenied:
		return VolumeErrorKind(k)
	case "disk_not_found":
		return VolumeErrorPartitionNotFound
	default:
		return VolumeErrorUnknown
	}
}

// requireVolumeUniqueID validates the UniqueId handed to the read and label
// calls.
func requireVolumeUniqueID(op, uniqueID string) (string, error) {
	id := strings.TrimSpace(uniqueID)
	if id == "" {
		return "", NewVolumeError(VolumeErrorUnknown,
			fmt.Sprintf("cannot %s: volume UniqueId is empty", op), nil, nil)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Format
// ---------------------------------------------------------------------------

// Format resolves the hosting disk and partition (refusing protected storage
// fail-closed), refuses an already-formatted volume unless
// AllowFormatExisting is set, formats it (quick by default, full when
// FullFormat is set) and returns the re-read state.
func (c *VolumeClient) Format(ctx context.Context, opts VolumeFormatOptions) (*VolumeInfo, error) {
	opts.PartitionID = strings.TrimSpace(opts.PartitionID)
	if err := ValidateVolumeFormatOptions(opts); err != nil {
		return nil, err
	}
	// Canonicalize the file system so direct API callers get the same
	// spelling the provider plan path resolves.
	if canon, err := CanonicalizeVolumeFileSystem(opts.FileSystem); err == nil {
		opts.FileSystem = canon
	}
	resp, rerr := c.runVolumeEnvelope(ctx, "format", buildVolumeFormatScript(opts),
		map[string]string{"partition_id": opts.PartitionID, "file_system": opts.FileSystem})
	if rerr != nil {
		return nil, rerr
	}
	return parseVolumeInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the observed state of the volume with the given UniqueId, or
// (nil, nil) when it is gone or unformatted (null/RAW file system).
func (c *VolumeClient) Read(ctx context.Context, uniqueID string) (*VolumeInfo, error) {
	id, err := requireVolumeUniqueID("read volume", uniqueID)
	if err != nil {
		return nil, err
	}
	resp, rerr := c.runVolumeEnvelope(ctx, "read", buildVolumeReadScript(id),
		map[string]string{"unique_id": id})
	if rerr != nil {
		if IsVolumeError(rerr, VolumeErrorNotFound) || IsVolumeError(rerr, VolumeErrorPartitionNotFound) {
			return nil, nil
		}
		return nil, rerr
	}
	return parseVolumeInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// SetLabel
// ---------------------------------------------------------------------------

// SetLabel changes the volume label via Set-Volume and returns the re-read
// state. An empty label clears the volume label. Length validation is the
// caller's job (the provider validates against the observed file system);
// the script quotes the value so any spelling is transport-safe.
func (c *VolumeClient) SetLabel(ctx context.Context, uniqueID, label string) (*VolumeInfo, error) {
	id, err := requireVolumeUniqueID("change volume label", uniqueID)
	if err != nil {
		return nil, err
	}
	resp, rerr := c.runVolumeEnvelope(ctx, "set_label", buildVolumeLabelScript(id, label),
		map[string]string{"unique_id": id})
	if rerr != nil {
		return nil, rerr
	}
	return parseVolumeInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

// Lookup resolves exactly one lookup coordinate (drive letter, UniqueId or
// exact label) to its observed state for imports and the data source. Zero
// matches are a not_found error; several label matches are an unknown error.
func (c *VolumeClient) Lookup(ctx context.Context, lookup VolumeLookup) (*VolumeInfo, error) {
	if err := lookup.Validate(); err != nil {
		return nil, err
	}
	resp, rerr := c.runVolumeEnvelope(ctx, "lookup", buildVolumeLookupScript(lookup),
		map[string]string{"lookup": lookup.Describe()})
	if rerr != nil {
		return nil, rerr
	}
	return parseVolumeInfo(resp.Data, c.c.cfg.Host)
}

// Describe renders the lookup for diagnostics and error context. Values are
// safe to log: volume identities carry no secrets.
func (l VolumeLookup) Describe() string {
	switch {
	case strings.TrimSpace(l.UniqueID) != "":
		return fmt.Sprintf("unique_id %q", strings.TrimSpace(l.UniqueID))
	case strings.TrimSpace(l.DriveLetter) != "":
		return fmt.Sprintf("drive_letter %q", strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(l.DriveLetter), ":")))
	case strings.TrimSpace(l.FileSystemLabel) != "":
		return fmt.Sprintf("file_system_label %q", strings.TrimSpace(l.FileSystemLabel))
	default:
		return "no lookup"
	}
}
