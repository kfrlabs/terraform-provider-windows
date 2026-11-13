// Package winclient: Windows partition CRUD over SSH.
//
// This file provides PartitionClient, the concrete WindowsPartitionClient
// used by the windows_partition Terraform resource. All operations execute
// PowerShell scripts wrapped in a JSON envelope (Emit-OK/Emit-Err) so stdout
// is machine-parseable regardless of Windows locale.
//
// Identity is the (disk, key) pair: the partition GUID on GPT disks, the
// byte offset on MBR disks — never the scan-time partition number.
//
// Security invariants:
//   - Selector strings, the disk UniqueId, the partition key and the drive
//     letter are interpolated only through psQuote (single-quoted PS
//     literal) so $var / backtick / subexpression injection is impossible.
//     Sizes and offsets are uint64 rendered with FormatUint; bools render as
//     $true/$false tokens. No user input ever reaches the script unquoted.
//   - Scripts never terminate the session: they signal completion with
//     `return` after Emit-OK/Emit-Err (since #81 the client keeps one
//     long-lived PowerShell session, where `exit` would kill the session
//     instead of just the call).
//   - Every mutating cmdlet carries -Confirm:$false so a non-interactive
//     session never blocks on a confirmation prompt, and every read refreshes
//     the storage cache with Update-HostStorageCache first.
//
// Reused helpers from the same package:
//   - psStorageHeader + Classify-Storage - shared prelude (storage_common.go)
//   - DiskSelector                      - exactly-one selector (storage_common.go)
//   - Resolve-Disk / Test-DiskProtected - disk resolution + guard (disk.go)
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

// Compile-time assertion: PartitionClient satisfies WindowsPartitionClient.
var _ WindowsPartitionClient = (*PartitionClient)(nil)

// PartitionClient is the PowerShell/SSH-backed WindowsPartitionClient.
type PartitionClient struct {
	c *Client
}

// NewPartitionClient constructs a PartitionClient wrapping the given SSH Client.
func NewPartitionClient(c *Client) *PartitionClient { return &PartitionClient{c: c} }

// runPartitionPowerShell is the package-level indirection used by
// PartitionClient. Tests override it; production code must not.
var runPartitionPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// ---------------------------------------------------------------------------
// Shared PowerShell fragments
// ---------------------------------------------------------------------------

// psPartitionFunctions defines Resolve-Partition, Test-PartitionProtected,
// ConvertTo-PartitionJson and Classify-Partition on top of psStorageHeader
// and psDiskFunctions (disk.go). Every operation script is:
// psStorageHeader + selector vars + psDiskFunctions + psPartitionFunctions +
// one op body.
//
// Resolve-Partition finds the partition on an already-resolved disk by GUID
// (GPT) or by decimal byte offset (MBR) — never by partition number. A
// numeric key compares against Offset; anything else compares against Guid
// (braces and case normalized). Quiet suppresses every Emit-Err (used only
// where the caller re-checks); Delete uses a non-quiet lookup so enumerate
// and probe failures surface, while a genuine not_found is swallowed Go-side
// as success.
//
// Test-PartitionProtected implements the partition guard and returns "" when
// the partition is safe or a human-readable reason otherwise. Boot, system,
// EFI, MSR and recovery partitions are refused outright, as is an MBR
// recovery type (0x27). A partition holding the active pagefile is refused;
// a partition with no drive letter hosts no pagefile, so the CIM probe only
// runs when a letter exists — a letterless data partition never fails
// closed on a probe error it could not have caused. When the probe itself
// fails with a letter present, placement cannot be determined and the
// partition fails closed (protected).
const psPartitionFunctions = `
function Resolve-Partition([object]$D, [string]$Key, [bool]$Quiet) {
  $parts = @()
  try {
    $parts = @(Get-Partition -DiskNumber ([int]$D.Number) -ErrorAction Stop)
  } catch {
    if (-not $Quiet) {
      Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'enumerate_partitions'; unique_id = [string]$D.UniqueId }
    }
    return $null
  }
  $normKey = $Key.Trim('{} ').ToUpperInvariant()
  $isOffset = ($Key -match '^\d+$')
  foreach ($p in $parts) {
    if ($isOffset) {
      $off = ''
      try { $off = [string]([uint64]$p.Offset) } catch { $off = '' }
      if ($off -ne '' -and $off -eq $Key) { return $p }
    } else {
      $g = ([string]$p.Guid).Trim('{} ').ToUpperInvariant()
      if ($g -ne '' -and $g -ne '00000000-0000-0000-0000-000000000000' -and $g -eq $normKey) { return $p }
    }
  }
  if (-not $Quiet) {
    Emit-Err 'not_found' ('No partition with key ' + $Key + ' on disk ' + [string]$D.UniqueId + '.') @{ unique_id = [string]$D.UniqueId; key = $Key }
  }
  return $null
}

function Test-PartitionProtected([object]$P) {
  if ([bool]$P.IsBoot) { return 'the partition is the boot partition' }
  if ([bool]$P.IsSystem) { return 'the partition is the system partition' }
  $gpt = ([string]$P.GptType).ToUpperInvariant()
  if ($gpt -ne '') {
    if ($gpt -like '*C12A7328*') { return 'the partition is the EFI system partition' }
    if ($gpt -like '*E3C9E316*') { return 'the partition is a Microsoft reserved (MSR) partition' }
    if ($gpt -like '*DE94BBA4*') { return 'the partition is a recovery partition' }
  }
  $mb = -1
  try { $mb = [int]$P.MbrType } catch { $mb = -1 }
  if ($mb -eq 0x27) { return 'the partition is a recovery partition (MBR type 0x27)' }
  $t = ([string]$P.Type)
  if ($t -match 'Recovery|Reserved|System|EFI|MSR') { return ('the partition is a protected ' + $t + ' partition') }
  $dl = ([string]$P.DriveLetter).Trim().ToUpperInvariant()
  if ($dl -eq '') {
    return ''
  }
  try {
    foreach ($pf in @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop)) {
      $n = [string]$pf.Name
      if ($n.Length -ge 2 -and $n[1] -eq ':') {
        if ($n.Substring(0, 1).ToUpperInvariant() -eq $dl) { return ('the partition hosts the active pagefile on drive ' + $dl + ':') }
      }
    }
  } catch {
    return ('pagefile placement could not be determined: ' + [string]$_.Exception.Message)
  }
  return ''
}

function ConvertTo-PartitionJson([object]$P, [string]$DiskId) {
  $sz = 0
  try { $sz = [uint64]$P.Size } catch { $sz = 0 }
  $off = 0
  try { $off = [uint64]$P.Offset } catch { $off = 0 }
  $paths = @()
  try { $paths = @($P.AccessPaths | ForEach-Object { [string]$_ }) } catch { $paths = @() }
  return [ordered]@{
    disk_unique_id     = $DiskId
    partition_number   = [int]$P.PartitionNumber
    guid               = [string]$P.Guid
    offset_bytes       = $off
    size_bytes         = $sz
    drive_letter       = ([string]$P.DriveLetter).ToUpperInvariant()
    gpt_type           = [string]$P.GptType
    mbr_type           = [string]$P.MbrType
    is_hidden          = [bool]$P.IsHidden
    is_active          = [bool]$P.IsActive
    is_boot            = [bool]$P.IsBoot
    is_system          = [bool]$P.IsSystem
    operational_status = [string]$P.OperationalStatus
    access_paths       = @($paths)
  }
}

function Classify-Partition([object]$Rec) {
  $base = Classify-Storage $Rec
  if ($base -ne 'unknown') { return $base }
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'not enough (free |usable )?space' -or $msg -match 'insufficient space' -or $msg -match 'no usable free extent' -or $msg -match 'There is not enough space') { return 'insufficient_space' }
  if ($msg -match 'already (assigned|in use|exists)' -or $msg -match 'is already in use' -or $msg -match 'drive letter .* (in use|unavailable)') { return 'drive_letter_in_use' }
  if ($msg -match 'is not initialized' -or $msg -match 'not initialized' -or $msg -match 'is offline' -or $msg -match 'read.only' -or $msg -match 'is RAW') { return 'disk_not_ready' }
  if ($msg -match 'No MSFT_Partition' -or $msg -match 'could not find' -or $msg -match 'Cannot find' -or $msg -match 'does not exist') { return 'not_found' }
  return 'unknown'
}
`

// partitionScript concatenates the shared prelude, the disk selector vars
// for the hosting disk, the disk + partition function libraries and one op
// body into a complete script.
func partitionScript(diskUniqueID, body string) string {
	return psStorageHeader + "\n" + buildDiskSelectorVars(DiskSelectorByUniqueID(diskUniqueID)) + "\n" + psDiskFunctions + "\n" + psPartitionFunctions + "\n" + body + "\n"
}

// psPartitionVars renders the $part* variables consumed by the operation
// bodies. Strings go through psQuote; sizes are int64 magnitudes rendered
// with FormatInt (never converted to uint64 Go-side: the host casts to
// [uint64] where it needs them, and negative values are rejected by the
// validators before a script is ever built); bools render as $true/$false
// tokens.
func psPartitionVars(sizeBytes int64, useMax bool, hasOffset bool, offsetBytes int64, driveLetter, gptType, mbrType, key string, newSize int64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$partKey = %s\n", psQuote(key))
	fmt.Fprintf(&b, "$sizeBytes = %s\n", strconv.FormatInt(sizeBytes, 10))
	if useMax {
		b.WriteString("$useMax = $true\n")
	} else {
		b.WriteString("$useMax = $false\n")
	}
	if hasOffset {
		b.WriteString("$hasOffset = $true\n")
	} else {
		b.WriteString("$hasOffset = $false\n")
	}
	fmt.Fprintf(&b, "$offsetBytes = %s\n", strconv.FormatInt(offsetBytes, 10))
	fmt.Fprintf(&b, "$driveLetter = %s\n", psQuote(driveLetter))
	fmt.Fprintf(&b, "$gptType = %s\n", psQuote(gptType))
	fmt.Fprintf(&b, "$mbrType = %s\n", psQuote(mbrType))
	fmt.Fprintf(&b, "$newSize = %s\n", strconv.FormatInt(newSize, 10))
	return b.String()
}

// ---------------------------------------------------------------------------
// Operation bodies
// ---------------------------------------------------------------------------

// psPartitionCreateBody resolves the disk, refuses protected/offline/
// read-only/RAW disks, checks the largest free extent, creates the partition
// with -AssignDriveLetter:$false (the configured letter is assigned
// explicitly afterwards), and emits the re-read partition.
const psPartitionCreateBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  if ([string]$d.PartitionStyle -eq 'RAW') {
    Emit-Err 'disk_not_ready' ('Disk ' + [string]$d.UniqueId + ' is not initialized (RAW); initialize it to GPT or MBR before creating partitions.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number }
    return
  }
  if ([bool]$d.IsOffline) {
    Emit-Err 'disk_not_ready' ('Disk ' + [string]$d.UniqueId + ' is offline; bring it online before creating partitions.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number }
    return
  }
  if ([bool]$d.IsReadOnly) {
    Emit-Err 'disk_not_ready' ('Disk ' + [string]$d.UniqueId + ' is read-only; clear the read-only flag before creating partitions.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number }
    return
  }
  if ($gptType -ne '' -and [string]$d.PartitionStyle -ne 'GPT') {
    Emit-Err 'unknown' ('gpt_type ' + $gptType + ' requires a GPT disk, but disk ' + [string]$d.UniqueId + ' carries partition style ' + [string]$d.PartitionStyle + '.') @{ unique_id = [string]$d.UniqueId; partition_style = [string]$d.PartitionStyle }
    return
  }
  if ($mbrType -ne '' -and [string]$d.PartitionStyle -ne 'MBR') {
    Emit-Err 'unknown' ('mbr_type ' + $mbrType + ' requires an MBR disk, but disk ' + [string]$d.UniqueId + ' carries partition style ' + [string]$d.PartitionStyle + '.') @{ unique_id = [string]$d.UniqueId; partition_style = [string]$d.PartitionStyle }
    return
  }
  $sup = $null
  try {
    $sup = Get-PartitionSupportedSize -DiskNumber ([int]$d.Number) -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'probe_extent'; unique_id = [string]$d.UniqueId }
    return
  }
  $largest = 0
  try { $largest = [uint64]$sup.SizeMax } catch { $largest = 0 }
  $params = @{ DiskNumber = ([int]$d.Number); ErrorAction = 'Stop'; AssignDriveLetter = $false }
  if ($useMax) {
    $params['UseMaximumSize'] = $true
  } else {
    if ([uint64]$sizeBytes -gt $largest) {
      Emit-Err 'insufficient_space' ('Not enough free space on disk ' + [string]$d.UniqueId + ': requested ' + [string]$sizeBytes + ' bytes but the largest free extent is ' + [string]$largest + ' bytes.') @{ unique_id = [string]$d.UniqueId; requested_bytes = [string]$sizeBytes; largest_free_extent_bytes = [string]$largest }
      return
    }
    $params['Size'] = [uint64]$sizeBytes
  }
  if ($hasOffset) { $params['Offset'] = [uint64]$offsetBytes }
  if ($gptType -ne '') { $params['GptType'] = $gptType }
  elseif ($mbrType -ne '') { $params['MbrType'] = $mbrType }
  $created = $null
  try {
    $created = New-Partition @params -Confirm:$false
  } catch {
    Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'create'; unique_id = [string]$d.UniqueId }
    return
  }
  $key = [string]$created.Guid
  if ($key -eq '' -or $key -eq '00000000-0000-0000-0000-000000000000') { $key = [string]([uint64]$created.Offset) }
  $fresh = Resolve-Partition $d $key $false
  if ($null -eq $fresh) { return }
  if ($driveLetter -ne '') {
    try {
      $fresh | Set-Partition -NewDriveLetter $driveLetter -Confirm:$false -ErrorAction Stop
    } catch {
      Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'assign_letter'; unique_id = [string]$d.UniqueId; drive_letter = $driveLetter }
      return
    }
    $fresh = Resolve-Partition $d $key $false
    if ($null -eq $fresh) { return }
  }
  Emit-OK (ConvertTo-PartitionJson $fresh ([string]$d.UniqueId))
}
`

// psPartitionReadBody resolves the disk and the partition (by GUID/offset,
// never by number), guards both, and emits the partition.
const psPartitionReadBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  $p = Resolve-Partition $d $partKey $false
  if ($null -eq $p) { return }
  $preason = Test-PartitionProtected $p
  if ($preason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage a protected partition: ' + $preason + '.') @{ unique_id = [string]$d.UniqueId; key = $partKey; reason = $preason }
    return
  }
  Emit-OK (ConvertTo-PartitionJson $p ([string]$d.UniqueId))
}
`

// psPartitionGrowBody guards, refuses shrinking host-side (the re-read $p
// size is fresh from this script run, so a stale or racy desired size can
// never resize blindly), checks Get-PartitionSupportedSize against the
// desired size, resizes, and emits the re-read partition. An equal size is a
// no-op that re-emits the current state.
const psPartitionGrowBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  $p = Resolve-Partition $d $partKey $false
  if ($null -eq $p) { return }
  $preason = Test-PartitionProtected $p
  if ($preason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage a protected partition: ' + $preason + '.') @{ unique_id = [string]$d.UniqueId; key = $partKey; reason = $preason }
    return
  }
  $cur = 0
  try { $cur = [uint64]$p.Size } catch { $cur = 0 }
  if ([uint64]$newSize -lt $cur) {
    Emit-Err 'shrink_not_supported' ('Shrinking a partition from ' + [string]$cur + ' to ' + [string]$newSize + ' bytes is not supported in v1: grow only.') @{ unique_id = [string]$d.UniqueId; key = $partKey; current_bytes = [string]$cur; requested_bytes = [string]$newSize }
    return
  }
  if ([uint64]$newSize -eq $cur) {
    Emit-OK (ConvertTo-PartitionJson $p ([string]$d.UniqueId))
    return
  }
  $sup = $null
  try {
    $sup = Get-PartitionSupportedSize -DiskNumber ([int]$d.Number) -PartitionNumber ([int]$p.PartitionNumber) -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'probe_supported_size'; unique_id = [string]$d.UniqueId; key = $partKey }
    return
  }
  $max = 0
  try { $max = [uint64]$sup.SizeMax } catch { $max = 0 }
  if ([uint64]$newSize -gt $max) {
    Emit-Err 'insufficient_space' ('Cannot grow the partition to ' + [string]$newSize + ' bytes: the largest supported size is ' + [string]$max + ' bytes.') @{ unique_id = [string]$d.UniqueId; key = $partKey; requested_bytes = [string]$newSize; largest_supported_bytes = [string]$max }
    return
  }
  try {
    $p | Resize-Partition -Size ([uint64]$newSize) -ErrorAction Stop -Confirm:$false
  } catch {
    Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'resize'; unique_id = [string]$d.UniqueId; key = $partKey }
    return
  }
  $fresh = Resolve-Partition $d $partKey $false
  if ($null -eq $fresh) { return }
  Emit-OK (ConvertTo-PartitionJson $fresh ([string]$d.UniqueId))
}
`

// psPartitionLetterBody assigns the configured letter (Set-Partition
// -NewDriveLetter) or removes the current one (Remove-PartitionAccessPath)
// and emits the re-read partition.
const psPartitionLetterBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  $p = Resolve-Partition $d $partKey $false
  if ($null -eq $p) { return }
  $preason = Test-PartitionProtected $p
  if ($preason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage a protected partition: ' + $preason + '.') @{ unique_id = [string]$d.UniqueId; key = $partKey; reason = $preason }
    return
  }
  if ($driveLetter -eq '') {
    $cur = ([string]$p.DriveLetter).Trim().ToUpperInvariant()
    if ($cur -ne '') {
      try {
        $p | Remove-PartitionAccessPath -AccessPath ($cur + ':') -ErrorAction Stop -Confirm:$false
      } catch {
        Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'remove_letter'; unique_id = [string]$d.UniqueId; key = $partKey }
        return
      }
    }
  } else {
    try {
      $p | Set-Partition -NewDriveLetter $driveLetter -ErrorAction Stop -Confirm:$false
    } catch {
      Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'assign_letter'; unique_id = [string]$d.UniqueId; key = $partKey; drive_letter = $driveLetter }
      return
    }
  }
  $fresh = Resolve-Partition $d $partKey $false
  if ($null -eq $fresh) { return }
  Emit-OK (ConvertTo-PartitionJson $fresh ([string]$d.UniqueId))
}
`

// psPartitionFlagsBody enforces the hidden/active flags (only the $set*
// switches that are true take effect) and emits the re-read partition.
const psPartitionFlagsBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  $p = Resolve-Partition $d $partKey $false
  if ($null -eq $p) { return }
  $preason = Test-PartitionProtected $p
  if ($preason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage a protected partition: ' + $preason + '.') @{ unique_id = [string]$d.UniqueId; key = $partKey; reason = $preason }
    return
  }
  $fparams = @{ ErrorAction = 'Stop' }
  if ($setHidden) {
    if ($hiddenVal) { $fparams['IsHidden'] = $true } else { $fparams['IsHidden'] = $false }
  }
  if ($setActive) {
    if ($activeVal) { $fparams['IsActive'] = $true } else { $fparams['IsActive'] = $false }
  }
  try {
    $p | Set-Partition @fparams -Confirm:$false
  } catch {
    Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'set_flags'; unique_id = [string]$d.UniqueId; key = $partKey }
    return
  }
  $fresh = Resolve-Partition $d $partKey $false
  if ($null -eq $fresh) { return }
  Emit-OK (ConvertTo-PartitionJson $fresh ([string]$d.UniqueId))
}
`

// psPartitionDeleteBody guards (disk and partition) and removes the
// partition. The lookup stays non-quiet so enumerate/probe failures surface
// as errors; a genuinely missing partition (not_found/disk_not_found, which
// the Go Delete swallows) is success: Delete is idempotent.
const psPartitionDeleteBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  $p = Resolve-Partition $d $partKey $false
  if ($null -eq $p) { return }
  $preason = Test-PartitionProtected $p
  if ($preason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage a protected partition: ' + $preason + '.') @{ unique_id = [string]$d.UniqueId; key = $partKey; reason = $preason }
    return
  }
  try {
    $p | Remove-Partition -ErrorAction Stop -Confirm:$false
  } catch {
    Emit-Err (Classify-Partition $_) ([string]$_.Exception.Message) @{ phase = 'remove'; unique_id = [string]$d.UniqueId; key = $partKey }
    return
  }
  Emit-OK $null
}
`

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

// buildPartitionCreateScript renders the full create script. Size, offset
// and the letter/type values are pre-validated Go-side; the style-vs-disk
// check runs host-side in the same script.
func buildPartitionCreateScript(opts PartitionCreateOptions) string {
	vars := psPartitionVars(opts.SizeBytes, opts.UseMaximumSize, opts.HasOffset, opts.OffsetBytes,
		opts.DriveLetter, opts.GptType, opts.MbrType, "", 0)
	return partitionScript(opts.DiskUniqueID, vars+psPartitionCreateBody)
}

// buildPartitionReadScript renders the read script for (disk, key).
func buildPartitionReadScript(diskUniqueID, key string) string {
	vars := psPartitionVars(0, false, false, 0, "", "", "", key, 0)
	return partitionScript(diskUniqueID, vars+psPartitionReadBody)
}

// buildPartitionGrowScript renders the grow script for (disk, key, size).
func buildPartitionGrowScript(diskUniqueID, key string, sizeBytes int64) string {
	vars := psPartitionVars(0, false, false, 0, "", "", "", key, sizeBytes)
	return partitionScript(diskUniqueID, vars+psPartitionGrowBody)
}

// buildPartitionLetterScript renders the drive-letter assign/remove script.
func buildPartitionLetterScript(diskUniqueID, key, letter string) string {
	vars := psPartitionVars(0, false, false, 0, letter, "", "", key, 0)
	return partitionScript(diskUniqueID, vars+psPartitionLetterBody)
}

// buildPartitionFlagsScript renders the hidden/active flag script. Only the
// non-nil switches take effect ($setHidden/$setActive gate each assignment).
func buildPartitionFlagsScript(diskUniqueID, key string, hidden, active *bool) string {
	var b strings.Builder
	b.WriteString(psPartitionVars(0, false, false, 0, "", "", "", key, 0))
	if hidden != nil {
		b.WriteString("$setHidden = $true\n")
		if *hidden {
			b.WriteString("$hiddenVal = $true\n")
		} else {
			b.WriteString("$hiddenVal = $false\n")
		}
	} else {
		b.WriteString("$setHidden = $false\n$hiddenVal = $false\n")
	}
	if active != nil {
		b.WriteString("$setActive = $true\n")
		if *active {
			b.WriteString("$activeVal = $true\n")
		} else {
			b.WriteString("$activeVal = $false\n")
		}
	} else {
		b.WriteString("$setActive = $false\n$activeVal = $false\n")
	}
	return partitionScript(diskUniqueID, b.String()+psPartitionFlagsBody)
}

// buildPartitionDeleteScript renders the guarded delete script.
func buildPartitionDeleteScript(diskUniqueID, key string) string {
	vars := psPartitionVars(0, false, false, 0, "", "", "", key, 0)
	return partitionScript(diskUniqueID, vars+psPartitionDeleteBody)
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// partitionJSON mirrors the JSON object emitted by ConvertTo-PartitionJson.
type partitionJSON struct {
	DiskUniqueID      string   `json:"disk_unique_id"`
	PartitionNumber   int      `json:"partition_number"`
	GUID              string   `json:"guid"`
	OffsetBytes       uint64   `json:"offset_bytes"`
	SizeBytes         uint64   `json:"size_bytes"`
	DriveLetter       string   `json:"drive_letter"`
	GptType           string   `json:"gpt_type"`
	MbrType           string   `json:"mbr_type"`
	IsHidden          bool     `json:"is_hidden"`
	IsActive          bool     `json:"is_active"`
	IsBoot            bool     `json:"is_boot"`
	IsSystem          bool     `json:"is_system"`
	OperationalStatus string   `json:"operational_status"`
	AccessPaths       []string `json:"access_paths"`
}

// parsePartitionInfo projects a partitionJSON payload onto a PartitionInfo.
// An empty envelope, an unparseable payload or an overflowing size/offset is
// an unknown error: the read cannot be trusted. An empty Guid is valid (MBR
// partitions carry none) and an empty drive letter means "no letter".
func parsePartitionInfo(raw json.RawMessage, host string) (*PartitionInfo, error) {
	ctx := map[string]string{"host": host}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, NewPartitionError(PartitionErrorUnknown, "empty partition state returned by the host", nil, ctx)
	}
	var j partitionJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, NewPartitionError(PartitionErrorUnknown, "failed to parse partition state JSON", err, ctx)
	}
	if j.SizeBytes > math.MaxInt64 {
		return nil, NewPartitionError(PartitionErrorUnknown, "the host returned a partition size that overflows int64", nil, ctx)
	}
	if j.OffsetBytes > math.MaxInt64 {
		return nil, NewPartitionError(PartitionErrorUnknown, "the host returned a partition offset that overflows int64", nil, ctx)
	}
	paths := j.AccessPaths
	if paths == nil {
		paths = []string{}
	}
	return &PartitionInfo{
		DiskUniqueID:      strings.TrimSpace(j.DiskUniqueID),
		PartitionNumber:   j.PartitionNumber,
		GUID:              strings.TrimSpace(j.GUID),
		OffsetBytes:       int64(j.OffsetBytes),
		SizeBytes:         int64(j.SizeBytes),
		DriveLetter:       strings.ToUpper(strings.TrimSpace(j.DriveLetter)),
		GptType:           strings.TrimSpace(j.GptType),
		MbrType:           strings.TrimSpace(j.MbrType),
		IsHidden:          j.IsHidden,
		IsActive:          j.IsActive,
		IsBoot:            j.IsBoot,
		IsSystem:          j.IsSystem,
		OperationalStatus: j.OperationalStatus,
		AccessPaths:       paths,
	}, nil
}

// runPartitionEnvelope executes script and parses the JSON envelope through
// the shared runEnvelope helper. Transport/timeout failures map to unknown
// (the partition vocabulary has no dedicated timeout kind); remote Emit-Err
// kinds map via mapPartitionKind.
func (c *PartitionClient) runPartitionEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
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
			return runPartitionPowerShell(ctx, c.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("operation %q timed out or was cancelled", op), eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewPartitionError(PartitionErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewPartitionError(mapPartitionKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapPartitionKind translates the PS-side "kind" string to a typed
// PartitionErrorKind. Unknown values fall through to Unknown.
func mapPartitionKind(k string) PartitionErrorKind {
	switch PartitionErrorKind(k) {
	case PartitionErrorNotFound,
		PartitionErrorDiskNotFound,
		PartitionErrorDiskNotReady,
		PartitionErrorInsufficientSpace,
		PartitionErrorDriveLetterInUse,
		PartitionErrorShrinkNotSupported,
		PartitionErrorProtected,
		PartitionErrorAccessDenied:
		return PartitionErrorKind(k)
	default:
		return PartitionErrorUnknown
	}
}

// requirePartitionRef validates the (disk, key) identity handed to the
// mutating and read calls.
func requirePartitionRef(op, diskUniqueID, key string) (string, string, error) {
	disk := strings.TrimSpace(diskUniqueID)
	k := strings.TrimSpace(key)
	if disk == "" || k == "" {
		return "", "", NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("cannot %s: disk UniqueId and partition key must both be set", op),
			nil, map[string]string{"disk_unique_id": diskUniqueID, "key": key})
	}
	return disk, k, nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the observed state of the partition identified by (disk, key),
// or (nil, nil) when the disk or the partition is gone.
func (c *PartitionClient) Read(ctx context.Context, diskUniqueID, key string) (*PartitionInfo, error) {
	disk, k, err := requirePartitionRef("read partition", diskUniqueID, key)
	if err != nil {
		return nil, err
	}
	resp, rerr := c.runPartitionEnvelope(ctx, "read", buildPartitionReadScript(disk, k),
		map[string]string{"disk_unique_id": disk, "key": k})
	if rerr != nil {
		if IsPartitionError(rerr, PartitionErrorNotFound) || IsPartitionError(rerr, PartitionErrorDiskNotFound) {
			return nil, nil
		}
		return nil, rerr
	}
	return parsePartitionInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create resolves the hosting disk (refusing protected, offline, read-only
// or RAW disks), checks the free extent, creates the partition with
// -AssignDriveLetter:$false, assigns the configured letter explicitly, and
// returns the re-read state.
func (c *PartitionClient) Create(ctx context.Context, opts PartitionCreateOptions) (*PartitionInfo, error) {
	opts.DiskUniqueID = strings.TrimSpace(opts.DiskUniqueID)
	opts.DriveLetter = strings.ToUpper(strings.TrimSpace(opts.DriveLetter))
	if err := ValidatePartitionCreateOptions(opts); err != nil {
		return nil, err
	}
	// Canonicalize the partition types (aliases to GUID/byte form) so direct
	// API callers get the same spelling the provider plan path resolves.
	if strings.TrimSpace(opts.GptType) != "" {
		gpt, err := CanonicalizeGPTType(opts.GptType)
		if err != nil {
			return nil, err
		}
		opts.GptType = gpt
	}
	if strings.TrimSpace(opts.MbrType) != "" {
		mbr, err := CanonicalizeMBRType(opts.MbrType)
		if err != nil {
			return nil, err
		}
		opts.MbrType = mbr
	}
	resp, rerr := c.runPartitionEnvelope(ctx, "create", buildPartitionCreateScript(opts),
		map[string]string{"disk_unique_id": opts.DiskUniqueID})
	if rerr != nil {
		return nil, rerr
	}
	return parsePartitionInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Grow
// ---------------------------------------------------------------------------

// Grow enlarges the partition to sizeBytes via Get-PartitionSupportedSize +
// Resize-Partition and returns the re-read state. Values at or below the
// current size never reach the host: equal sizes re-read, smaller sizes are
// a shrink_not_supported error — but the client cannot know the current size
// without reading, so callers that already hold observed state must gate
// with DecidePartitionResize first. As a backstop, a stale or racy call that
// turns out not to grow fails here instead of resizing blindly.
func (c *PartitionClient) Grow(ctx context.Context, diskUniqueID, key string, sizeBytes int64) (*PartitionInfo, error) {
	disk, k, err := requirePartitionRef("grow partition", diskUniqueID, key)
	if err != nil {
		return nil, err
	}
	if sizeBytes <= 0 {
		return nil, NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid grow size %d: must be a positive number of bytes", sizeBytes),
			nil, map[string]string{"size_bytes": strconv.FormatInt(sizeBytes, 10)})
	}
	resp, rerr := c.runPartitionEnvelope(ctx, "grow", buildPartitionGrowScript(disk, k, sizeBytes),
		map[string]string{"disk_unique_id": disk, "key": k, "size_bytes": strconv.FormatInt(sizeBytes, 10)})
	if rerr != nil {
		return nil, rerr
	}
	return parsePartitionInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// SetDriveLetter / SetFlags
// ---------------------------------------------------------------------------

// SetDriveLetter assigns letter (upper-cased D-Z), or removes the current
// letter when letter is "", and returns the re-read state.
func (c *PartitionClient) SetDriveLetter(ctx context.Context, diskUniqueID, key, letter string) (*PartitionInfo, error) {
	disk, k, err := requirePartitionRef("change partition drive letter", diskUniqueID, key)
	if err != nil {
		return nil, err
	}
	norm := ""
	if strings.TrimSpace(letter) != "" {
		norm, err = NormalizeDriveLetter(letter)
		if err != nil {
			return nil, err
		}
	}
	resp, rerr := c.runPartitionEnvelope(ctx, "set_drive_letter", buildPartitionLetterScript(disk, k, norm),
		map[string]string{"disk_unique_id": disk, "key": k, "drive_letter": norm})
	if rerr != nil {
		return nil, rerr
	}
	return parsePartitionInfo(resp.Data, c.c.cfg.Host)
}

// SetFlags enforces the hidden/active flags (nil = leave unmanaged) and
// returns the re-read state. Both nil re-reads without a remote write.
func (c *PartitionClient) SetFlags(ctx context.Context, diskUniqueID, key string, hidden, active *bool) (*PartitionInfo, error) {
	disk, k, err := requirePartitionRef("change partition flags", diskUniqueID, key)
	if err != nil {
		return nil, err
	}
	if hidden == nil && active == nil {
		return c.Read(ctx, disk, k)
	}
	resp, rerr := c.runPartitionEnvelope(ctx, "set_flags", buildPartitionFlagsScript(disk, k, hidden, active),
		map[string]string{"disk_unique_id": disk, "key": k})
	if rerr != nil {
		return nil, rerr
	}
	return parsePartitionInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete guards (never system/boot/recovery/MSR/pagefile partitions) then
// removes the partition with Remove-Partition -Confirm:$false. A missing
// partition is success.
func (c *PartitionClient) Delete(ctx context.Context, diskUniqueID, key string) error {
	disk, k, err := requirePartitionRef("delete partition", diskUniqueID, key)
	if err != nil {
		return err
	}
	_, rerr := c.runPartitionEnvelope(ctx, "delete", buildPartitionDeleteScript(disk, k),
		map[string]string{"disk_unique_id": disk, "key": k})
	if rerr != nil {
		if IsPartitionError(rerr, PartitionErrorNotFound) || IsPartitionError(rerr, PartitionErrorDiskNotFound) {
			return nil
		}
		return rerr
	}
	return nil
}
