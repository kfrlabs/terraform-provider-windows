// Package winclient: Windows disk CRUD over SSH.
//
// This file provides DiskClient, the concrete WindowsDiskClient used by the
// windows_disk Terraform resource and data source. All operations execute
// PowerShell scripts wrapped in a JSON envelope (Emit-OK/Emit-Err) so stdout
// is machine-parseable regardless of Windows locale.
//
// Security invariants:
//   - Selector strings and the UniqueId are interpolated only through
//     psQuote (single-quoted PS literal) so $var / backtick / subexpression
//     injection is impossible. Disk numbers are ints rendered with Itoa;
//     bools render as $true/$false tokens. No user input ever reaches the
//     script unquoted.
//   - Scripts never terminate the session: they signal completion with
//     `return` after Emit-OK/Emit-Err (since #81 the client keeps one
//     long-lived PowerShell session, where `exit` would kill the session
//     instead of just the call).
//   - Every mutating cmdlet carries -Confirm:$false so a non-interactive
//     session never blocks on a confirmation prompt, and every read refreshes
//     the storage cache with Update-HostStorageCache first.
//
// Reused helpers from the same package:
//   - psStorageHeader  - shared prelude + Classify-Storage (storage_common.go)
//   - DiskSelector      - exactly-one selector (storage_common.go)
//   - runEnvelope       - shared JSON envelope pipeline (envelope.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Compile-time assertion: DiskClient satisfies WindowsDiskClient.
var _ WindowsDiskClient = (*DiskClient)(nil)

// DiskClient is the PowerShell/SSH-backed WindowsDiskClient.
type DiskClient struct {
	c *Client
}

// NewDiskClient constructs a DiskClient wrapping the given SSH Client.
func NewDiskClient(c *Client) *DiskClient { return &DiskClient{c: c} }

// runDiskPowerShell is the package-level indirection used by DiskClient.
// Tests override it; production code must not.
var runDiskPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// ---------------------------------------------------------------------------
// Shared PowerShell fragments
// ---------------------------------------------------------------------------

// psDiskFunctions defines Resolve-Disk, Test-DiskProtected and
// ConvertTo-DiskJson on top of psStorageHeader. Every operation script is:
// psStorageHeader + selector vars + psDiskFunctions + one op body.
//
// Resolve-Disk enumerates Get-Disk (after Update-HostStorageCache), applies
// the single active selector coordinate, and enforces the exactly-one-match
// rule: zero matches emit disk_not_found, several emit ambiguous_disk with
// the candidate list. It returns $null after emitting, which callers check
// before touching the disk.
//
// Test-DiskProtected implements the protected-storage guard and returns ""
// when the disk is safe or a human-readable reason otherwise. Boot, system
// and clustered disks are refused outright. Pagefile/crash-dump placement is
// resolved from Get-Partition/Get-Volume drive letters against
// Win32_PageFileUsage and Win32_OSRecoveryConfiguration; when that
// placement cannot be determined the disk fails closed (protected). An
// offline disk hosts no active pagefile, so placement checks are skipped
// while offline and re-verified the next time it is online.
const psDiskFunctions = `
function Resolve-Disk {
  try { Update-HostStorageCache -ErrorAction Stop } catch { }
  $all = @()
  try {
    $all = @(Get-Disk -ErrorAction Stop)
  } catch {
    Emit-Err (Classify-Storage $_) ([string]$_.Exception.Message) @{ phase = 'enumerate' }
    return $null
  }
  $found = @()
  foreach ($d in $all) {
    $hit = $false
    if ($selUniqueID -ne '') {
      if ([string]$d.UniqueId -eq $selUniqueID) { $hit = $true }
    } elseif ($selSerial -ne '') {
      if (([string]$d.SerialNumber).Trim() -eq $selSerial) { $hit = $true }
    } elseif ($selLocation -ne '') {
      if (([string]$d.Location).Trim() -eq $selLocation) { $hit = $true }
    } elseif ($selUseNumber) {
      if ([int]$d.Number -eq $selNumber) { $hit = $true }
    }
    if ($hit) { $found += $d }
  }
  if ($found.Count -eq 0) {
    Emit-Err 'disk_not_found' ('No disk matches ' + $selDescribe + '.') @{ selector = $selDescribe }
    return $null
  }
  if ($found.Count -gt 1) {
    $names = @($found | ForEach-Object { [string]$_.UniqueId + ' (number ' + [string]$_.Number + ')' }) -join '; '
    Emit-Err 'ambiguous_disk' ([string]$found.Count + ' disks match ' + $selDescribe + ': ' + $names + '. Refine the selector.') @{ selector = $selDescribe; match_count = [string]$found.Count }
    return $null
  }
  return $found[0]
}

function Test-DiskProtected([object]$D) {
  if ([bool]$D.IsBoot) { return 'the disk is the boot disk' }
  if ([bool]$D.IsSystem) { return 'the disk is the system disk' }
  if ([bool]$D.IsClustered) { return 'the disk is clustered' }
  if ([bool]$D.IsOffline) {
    return ''
  }
  try {
    $letters = @()
    $parts = @(Get-Partition -DiskNumber ([int]$D.Number) -ErrorAction Stop)
    foreach ($part in $parts) {
      try {
        $vol = $part | Get-Volume -ErrorAction Stop
        if ($null -ne $vol.DriveLetter -and ([string]$vol.DriveLetter).Trim() -ne '') {
          $letters += ([string]$vol.DriveLetter).Trim().ToUpperInvariant()
        }
      } catch { }
    }
    $pfDrives = @()
    foreach ($pf in @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop)) {
      $n = [string]$pf.Name
      if ($n.Length -ge 2 -and $n[1] -eq ':') { $pfDrives += $n.Substring(0, 1).ToUpperInvariant() }
    }
    foreach ($pd in $pfDrives) {
      if ($letters -contains $pd) { return ('the disk hosts the active pagefile on drive ' + $pd + ':') }
    }
    $rec = Get-CimInstance -ClassName Win32_OSRecoveryConfiguration -ErrorAction Stop | Select-Object -First 1
    foreach ($field in @([string]$rec.DebugFilePath, [string]$rec.MiniDumpDirectory)) {
      if ($field.Length -ge 2 -and $field[1] -eq ':') {
        $dl = $field.Substring(0, 1).ToUpperInvariant()
        if ($letters -contains $dl) { return ('the disk hosts the crash-dump target (' + $field + ')') }
      }
    }
  } catch {
    return ('pagefile/crash-dump placement could not be determined: ' + [string]$_.Exception.Message)
  }
  return ''
}

function ConvertTo-DiskJson([object]$D) {
  $sz = 0
  try { $sz = [uint64]$D.Size } catch { $sz = 0 }
  return [ordered]@{
    number             = [int]$D.Number
    unique_id          = [string]$D.UniqueId
    serial_number      = ([string]$D.SerialNumber).Trim()
    location           = [string]$D.Location
    friendly_name      = [string]$D.FriendlyName
    bus_type           = [string]$D.BusType
    health_status      = [string]$D.HealthStatus
    operational_status = [string]$D.OperationalStatus
    partition_style    = [string]$D.PartitionStyle
    is_offline         = [bool]$D.IsOffline
    is_read_only       = [bool]$D.IsReadOnly
    is_boot            = [bool]$D.IsBoot
    is_system          = [bool]$D.IsSystem
    is_clustered       = [bool]$D.IsClustered
    size_bytes         = $sz
  }
}
`

// buildDiskSelectorVars renders the $sel* variables consumed by
// Resolve-Disk. Strings go through psQuote; the number is an int rendered
// with Itoa, so no quoting is required for it.
func buildDiskSelectorVars(sel DiskSelector) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$selUniqueID = %s\n", psQuote(NormalizeDiskIdentity(sel.UniqueID)))
	fmt.Fprintf(&b, "$selSerial = %s\n", psQuote(NormalizeDiskIdentity(sel.SerialNumber)))
	fmt.Fprintf(&b, "$selLocation = %s\n", psQuote(NormalizeDiskIdentity(sel.Location)))
	if sel.HasNumber {
		fmt.Fprintf(&b, "$selNumber = %s\n", strconv.Itoa(sel.Number))
		b.WriteString("$selUseNumber = $true\n")
	} else {
		b.WriteString("$selNumber = 0\n$selUseNumber = $false\n")
	}
	fmt.Fprintf(&b, "$selDescribe = %s\n", psQuote(sel.Describe()))
	return b.String()
}

// psDiskReadBody resolves the selector, guards protected storage, and emits
// the disk JSON.
const psDiskReadBody = `
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  Emit-OK (ConvertTo-DiskJson $d)
}
`

// buildDiskReadScript renders the full read script for the selector.
func buildDiskReadScript(sel DiskSelector) string {
	return psStorageHeader + "\n" + buildDiskSelectorVars(sel) + "\n" + psDiskFunctions + "\n" + psDiskReadBody + "\n"
}

// buildDiskInitializeScript renders the initialize script. The style is a
// validated literal (GPT/MBR): callers never interpolate raw input.
func buildDiskInitializeScript(uniqueID, style string) (string, error) {
	styleLit := ""
	switch NormalizeDiskIdentity(style) {
	case DiskPartitionStyleGPT:
		styleLit = "GPT"
	case DiskPartitionStyleMBR:
		styleLit = "MBR"
	default:
		return "", NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("cannot initialize a disk to partition style %q: want GPT or MBR", style),
			nil, map[string]string{"style": style})
	}
	body := fmt.Sprintf(`
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  if ([string]$d.PartitionStyle -ne 'RAW') {
    Emit-Err 'partition_style_mismatch' ('Disk ' + [string]$d.UniqueId + ' already carries partition style ' + [string]$d.PartitionStyle + '; only RAW disks can be initialized in place.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; current_style = [string]$d.PartitionStyle; desired_style = '%s' }
    return
  }
  if ([bool]$d.IsOffline) {
    Emit-Err 'disk_offline' ('Disk ' + [string]$d.UniqueId + ' is offline; bring it online before initializing.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number }
    return
  }
  try {
    Initialize-Disk -Number ([int]$d.Number) -PartitionStyle %s -Confirm:$false -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Storage $_) ([string]$_.Exception.Message) @{ phase = 'initialize'; unique_id = [string]$d.UniqueId; number = [string]$d.Number }
    return
  }
  $fresh = Resolve-Disk
  if ($null -eq $fresh) { return }
  Emit-OK (ConvertTo-DiskJson $fresh)
}
`, styleLit, styleLit)
	return psStorageHeader + "\n" + buildDiskSelectorVars(DiskSelectorByUniqueID(uniqueID)) + "\n" + psDiskFunctions + "\n" + body + "\n", nil
}

// buildDiskSetOfflineScript renders the online/offline script.
func buildDiskSetOfflineScript(uniqueID string, offline bool) string {
	token := "$false"
	phase := "set_online"
	if offline {
		token = "$true"
		phase = "set_offline"
	}
	body := fmt.Sprintf(`
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  try {
    Set-Disk -Number ([int]$d.Number) -IsOffline:%s -Confirm:$false -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Storage $_) ([string]$_.Exception.Message) @{ phase = '%s'; unique_id = [string]$d.UniqueId; number = [string]$d.Number }
    return
  }
  $fresh = Resolve-Disk
  if ($null -eq $fresh) { return }
  Emit-OK (ConvertTo-DiskJson $fresh)
}
`, token, phase)
	return psStorageHeader + "\n" + buildDiskSelectorVars(DiskSelectorByUniqueID(uniqueID)) + "\n" + psDiskFunctions + "\n" + body + "\n"
}

// buildDiskSetReadOnlyScript renders the read-only flag script.
func buildDiskSetReadOnlyScript(uniqueID string, readOnly bool) string {
	token := "$false"
	if readOnly {
		token = "$true"
	}
	body := fmt.Sprintf(`
& {
  $d = Resolve-Disk
  if ($null -eq $d) { return }
  $reason = Test-DiskProtected $d
  if ($reason -ne '') {
    Emit-Err 'protected_storage' ('Refusing to manage protected storage: ' + $reason + '.') @{ unique_id = [string]$d.UniqueId; number = [string]$d.Number; reason = $reason }
    return
  }
  try {
    Set-Disk -Number ([int]$d.Number) -IsReadOnly:%s -Confirm:$false -ErrorAction Stop
  } catch {
    Emit-Err (Classify-Storage $_) ([string]$_.Exception.Message) @{ phase = 'set_read_only'; unique_id = [string]$d.UniqueId; number = [string]$d.Number }
    return
  }
  $fresh = Resolve-Disk
  if ($null -eq $fresh) { return }
  Emit-OK (ConvertTo-DiskJson $fresh)
}
`, token)
	return psStorageHeader + "\n" + buildDiskSelectorVars(DiskSelectorByUniqueID(uniqueID)) + "\n" + psDiskFunctions + "\n" + body + "\n"
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// diskJSON mirrors the JSON object emitted by ConvertTo-DiskJson.
type diskJSON struct {
	Number            int    `json:"number"`
	UniqueID          string `json:"unique_id"`
	SerialNumber      string `json:"serial_number"`
	Location          string `json:"location"`
	FriendlyName      string `json:"friendly_name"`
	BusType           string `json:"bus_type"`
	HealthStatus      string `json:"health_status"`
	OperationalStatus string `json:"operational_status"`
	PartitionStyle    string `json:"partition_style"`
	IsOffline         bool   `json:"is_offline"`
	IsReadOnly        bool   `json:"is_read_only"`
	IsBoot            bool   `json:"is_boot"`
	IsSystem          bool   `json:"is_system"`
	IsClustered       bool   `json:"is_clustered"`
	SizeBytes         uint64 `json:"size_bytes"`
}

// parseDiskInfo projects a diskJSON payload onto a DiskInfo. An empty
// envelope, an unparseable payload, a missing UniqueId (the Terraform ID
// anchor) or an overflowing size are unknown errors: the read cannot be
// trusted.
func parseDiskInfo(raw json.RawMessage, host string) (*DiskInfo, error) {
	ctx := map[string]string{"host": host}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, NewDiskError(DiskErrorUnknown, "empty disk state returned by the host", nil, ctx)
	}
	var j diskJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, NewDiskError(DiskErrorUnknown, "failed to parse disk state JSON", err, ctx)
	}
	if strings.TrimSpace(j.UniqueID) == "" {
		return nil, NewDiskError(DiskErrorUnknown,
			"the host returned a disk without a UniqueId, which cannot be adopted as a Terraform resource", nil, ctx)
	}
	if j.SizeBytes > math.MaxInt64 {
		return nil, NewDiskError(DiskErrorUnknown, "the host returned a disk size that overflows int64", nil, ctx)
	}
	style := strings.ToUpper(strings.TrimSpace(j.PartitionStyle))
	if style == "" {
		style = DiskPartitionStyleUnknown
	}
	return &DiskInfo{
		Number:            j.Number,
		UniqueID:          strings.TrimSpace(j.UniqueID),
		SerialNumber:      strings.TrimSpace(j.SerialNumber),
		Location:          strings.TrimSpace(j.Location),
		FriendlyName:      j.FriendlyName,
		BusType:           j.BusType,
		HealthStatus:      j.HealthStatus,
		OperationalStatus: j.OperationalStatus,
		PartitionStyle:    style,
		IsOffline:         j.IsOffline,
		IsReadOnly:        j.IsReadOnly,
		IsBoot:            j.IsBoot,
		IsSystem:          j.IsSystem,
		IsClustered:       j.IsClustered,
		SizeBytes:         int64(j.SizeBytes),
	}, nil
}

// runDiskEnvelope executes script and parses the JSON envelope through the
// shared runEnvelope helper. Transport/timeout failures map to unknown (the
// disk vocabulary has no dedicated timeout kind); remote Emit-Err kinds map
// via mapDiskKind.
func (c *DiskClient) runDiskEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*Envelope, error) {
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
			return runDiskPowerShell(ctx, c.c, full)
		},
		op, script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("operation %q timed out or was cancelled", op), eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewDiskError(DiskErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewDiskError(mapDiskKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapDiskKind translates the PS-side "kind" string to a typed DiskErrorKind.
// Unknown values fall through to Unknown.
func mapDiskKind(k string) DiskErrorKind {
	switch DiskErrorKind(k) {
	case DiskErrorNotFound,
		DiskErrorAmbiguous,
		DiskErrorProtected,
		DiskErrorPartitionStyleMismatch,
		DiskErrorOffline,
		DiskErrorAccessDenied,
		DiskErrorUnsupported:
		return DiskErrorKind(k)
	default:
		return DiskErrorUnknown
	}
}

// canonicalDiskStyle validates the desired initialize style. Only GPT and
// MBR are meaningful targets; RAW is the absence of a style, not a target.
func canonicalDiskStyle(style string) (string, error) {
	switch NormalizeDiskIdentity(style) {
	case DiskPartitionStyleGPT:
		return DiskPartitionStyleGPT, nil
	case DiskPartitionStyleMBR:
		return DiskPartitionStyleMBR, nil
	default:
		return "", NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("cannot initialize a disk to partition style %q: want GPT or MBR", style),
			nil, map[string]string{"style": style})
	}
}

// requireUniqueID validates the UniqueId handed to the mutating calls.
func requireUniqueID(op, uniqueID string) (string, error) {
	id := strings.TrimSpace(uniqueID)
	if id == "" {
		return "", NewDiskError(DiskErrorUnknown,
			fmt.Sprintf("cannot %s: disk UniqueId is empty", op), nil, nil)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read resolves the selector to exactly one disk and returns its observed
// state, or (nil, nil) when no disk matches (the resource handler then drops
// the resource from state; the data source reports not found instead).
func (c *DiskClient) Read(ctx context.Context, sel DiskSelector) (*DiskInfo, error) {
	if err := sel.Validate(); err != nil {
		return nil, err
	}
	resp, rerr := c.runDiskEnvelope(ctx, "read", buildDiskReadScript(sel),
		map[string]string{"selector": sel.Describe()})
	if rerr != nil {
		if IsDiskError(rerr, DiskErrorNotFound) {
			return nil, nil
		}
		return nil, rerr
	}
	return parseDiskInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

// Initialize converts a RAW disk to style ("GPT" or "MBR") and returns the
// re-read state. style is validated Go-side; the RAW pre-check, the offline
// pre-check and the protection guard run host-side in the same script so a
// concurrent change cannot slip between check and write.
func (c *DiskClient) Initialize(ctx context.Context, uniqueID, style string) (*DiskInfo, error) {
	id, err := requireUniqueID("initialize disk", uniqueID)
	if err != nil {
		return nil, err
	}
	canon, err := canonicalDiskStyle(style)
	if err != nil {
		return nil, err
	}
	script, serr := buildDiskInitializeScript(id, canon)
	if serr != nil {
		return nil, serr
	}
	resp, rerr := c.runDiskEnvelope(ctx, "initialize", script,
		map[string]string{"unique_id": id, "style": canon})
	if rerr != nil {
		return nil, rerr
	}
	return parseDiskInfo(resp.Data, c.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// SetOnlineState / SetReadOnlyState
// ---------------------------------------------------------------------------

// SetOnlineState brings the disk online (offline=false) or takes it offline
// (offline=true) and returns the re-read state.
func (c *DiskClient) SetOnlineState(ctx context.Context, uniqueID string, offline bool) (*DiskInfo, error) {
	id, err := requireUniqueID("change disk online state", uniqueID)
	if err != nil {
		return nil, err
	}
	resp, rerr := c.runDiskEnvelope(ctx, "set_online_state", buildDiskSetOfflineScript(id, offline),
		map[string]string{"unique_id": id, "offline": strconv.FormatBool(offline)})
	if rerr != nil {
		return nil, rerr
	}
	return parseDiskInfo(resp.Data, c.c.cfg.Host)
}

// SetReadOnlyState sets the disk read-only flag and returns the re-read state.
func (c *DiskClient) SetReadOnlyState(ctx context.Context, uniqueID string, readOnly bool) (*DiskInfo, error) {
	id, err := requireUniqueID("change disk read-only state", uniqueID)
	if err != nil {
		return nil, err
	}
	resp, rerr := c.runDiskEnvelope(ctx, "set_read_only_state", buildDiskSetReadOnlyScript(id, readOnly),
		map[string]string{"unique_id": id, "read_only": strconv.FormatBool(readOnly)})
	if rerr != nil {
		return nil, rerr
	}
	return parseDiskInfo(resp.Data, c.c.cfg.Host)
}
