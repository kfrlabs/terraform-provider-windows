// Package winclient - EventLogClient is the concrete WindowsEventLogClient
// backed by PowerShell over SSH.
//
// The implementation drives the .NET EventLogConfiguration API:
// Get-WinEvent -ListLog for reads, property assignment plus SaveChanges for
// writes. Limit-EventLog is deliberately not used: it only handles classic
// logs, and its retention parameters have had no effect since Vista.
//
// Security invariants:
//   - All user-supplied strings are interpolated only via psQuote
//     (single-quoted PowerShell literal with embedded single-quotes doubled);
//     no raw concatenation of user input into PS scripts.
//   - No credentials are written to EventLogError.Message or Context.
//
// Reused helpers from the same package:
//   - psQuote                 - safe PS string literal (psquote.go)
//   - runEnvelope             - shared JSON envelope pipeline (envelope.go)
//   - runPowerShell           - package-level hook, stubbed in tests
//   - psResponse              - Emit-OK / Emit-Err JSON envelope (service.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: EventLogClient satisfies WindowsEventLogClient.
var _ WindowsEventLogClient = (*EventLogClient)(nil)

// EventLogClient is the PowerShell/SSH-backed WindowsEventLogClient.
type EventLogClient struct {
	c *Client
}

// NewEventLogClient constructs an EventLogClient wrapping the given SSH Client.
func NewEventLogClient(c *Client) *EventLogClient {
	return &EventLogClient{c: c}
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// elPsHeader is prepended to every event-log PS script. It pins the session
// culture to InvariantCulture so enum .ToString() values are always English
// regardless of the host locale, and defines the shared Emit-OK / Emit-Err /
// Classify-EventLog / Read-EventLogState helpers.
//
// Log lookups match LogName literally (Where-Object -eq over the full list)
// so names containing wildcard characters or "/" (modern channels) can never
// over-match. The Group Policy override check reads
// HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\<log> with -LiteralPath
// so a "/" in the log name is never treated as a key separator, and only
// reports presence of the MaxSize / Retention / AutoBackupLogFiles values —
// those win at the next policy refresh.
//
// Note: Go raw-string literals (backtick-delimited) must not contain PS
// backtick sequences (`n, `t). None are needed here; single-quoted PS
// literals avoid all expansion.
const elPsHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
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

function Classify-EventLog([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'No such log' -or
      $msg -match 'does not exist' -or
      $msg -match 'cannot find' -or
      $msg -match 'was not found') {
    return 'not_found'
  }
  if ($msg -match 'Access is denied' -or
      $msg -match 'PermissionDenied' -or
      $msg -match 'UnauthorizedAccess' -or
      $msg -match 'Unauthorized' -or
      $msg -match 'SeSecurityPrivilege' -or
      $msg -match 'requires elevation') {
    return 'access_denied'
  }
  if ($msg -match 'classic log' -or
      $msg -match 'cannot be disabled' -or
      $msg -match 'IsEnabled' -or
      $msg -match 'not supported') {
    return 'unsupported'
  }
  if ($msg -match 'MaximumSizeInBytes' -or
      $msg -match 'multiple of' -or
      $msg -match 'invalid size' -or
      $msg -match 'The parameter is incorrect') {
    return 'invalid_size'
  }
  return 'unknown'
}

function Get-EventLogProp([object]$o, [string]$n) {
  try {
    $p = $o.PSObject.Properties[$n]
    if ($null -ne $p) { return $p.Value }
  } catch { }
  return $null
}

function Read-EventLogState([object]$c, [string]$logName) {
  $policyOverride = $false
  try {
    $policyPath = ('HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\' + $logName)
    if (Test-Path -LiteralPath $policyPath -ErrorAction Stop) {
      $pol = Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop
      foreach ($pn in @('MaxSize', 'Retention', 'AutoBackupLogFiles')) {
        if ($null -ne $pol.$pn) { $policyOverride = $true }
      }
    }
  } catch { $policyOverride = $false }

  $logType = ''
  try { $logType = [string]$c.LogType } catch { $logType = '' }

  $rc = Get-EventLogProp $c 'RecordCount'
  if ($null -eq $rc) { $rc = 0 }
  $fs = Get-EventLogProp $c 'FileSize'
  if ($null -eq $fs) { $fs = Get-EventLogProp $c 'FileSizeInBytes' }
  if ($null -eq $fs) { $fs = 0 }

  return [ordered]@{
    log_name           = [string]$c.LogName
    log_type           = $logType
    is_classic         = [bool]$c.IsClassic
    is_enabled         = [bool]$c.IsEnabled
    log_mode           = [string]$c.LogMode
    maximum_size_bytes = [int64]$c.MaximumSizeInBytes
    log_file_path      = [string]$c.LogFilePath
    record_count       = [int64]$rc
    file_size_bytes    = [int64]$fs
    policy_override    = [bool]$policyOverride
  }
}
`

// ---------------------------------------------------------------------------
// Read body
// ---------------------------------------------------------------------------

// elReadBody reads one event log and emits the normalised state JSON, or
// Emit-OK $null when the log does not exist. Uses the @@NAME@@ placeholder
// replaced by buildEventLogReplacer.
const elReadBody = `
$logName = @@NAME@@

& {
  try {
    $found = @(Get-WinEvent -ListLog -ErrorAction Stop | Where-Object { $_.LogName -eq $logName })
  } catch {
    Emit-Err (Classify-EventLog $_) ([string]$_.Exception.Message) @{ log = $logName; step = 'read' }
    return
  }
  if ($found.Count -eq 0) {
    Emit-OK $null
    return
  }
  Emit-OK (Read-EventLogState $found[0] $logName)
}
`

// ---------------------------------------------------------------------------
// Apply body (Create and Update share it: logs always exist)
// ---------------------------------------------------------------------------

// elApplyBody writes only the configured properties to the named log and
// emits the re-read state. Placeholders: @@NAME@@, @@GUARD@@ (the
// classic-disable refusal, emitted only when IsEnabled=false is configured)
// and @@SETBLOCK@@ (Go-built assignment lines covering only configured
// settings, possibly empty — Apply short-circuits to Read Go-side when no
// setting is configured, so an empty block never reaches the host).
const elApplyBody = `
$logName = @@NAME@@

& {
  try {
    $found = @(Get-WinEvent -ListLog -ErrorAction Stop | Where-Object { $_.LogName -eq $logName })
  } catch {
    Emit-Err (Classify-EventLog $_) ([string]$_.Exception.Message) @{ log = $logName; step = 'preflight' }
    return
  }
  if ($found.Count -eq 0) {
    Emit-Err 'not_found' ('Event log ' + $logName + ' was not found on the target host.') @{ log = $logName; step = 'preflight' }
    return
  }
  $c = $found[0]

  @@GUARD@@

  try {
    @@SETBLOCK@@
    $c.SaveChanges()
  } catch {
    Emit-Err (Classify-EventLog $_) ([string]$_.Exception.Message) @{ log = $logName; step = 'set' }
    return
  }

  try {
    $back = @(Get-WinEvent -ListLog -ErrorAction Stop | Where-Object { $_.LogName -eq $logName })
  } catch {
    Emit-Err (Classify-EventLog $_) ([string]$_.Exception.Message) @{ log = $logName; step = 'readback' }
    return
  }
  if ($back.Count -eq 0) {
    Emit-Err 'not_found' ('Event log ' + $logName + ' was not found on the target host.') @{ log = $logName; step = 'readback' }
    return
  }
  Emit-OK (Read-EventLogState $back[0] $logName)
}
`

// ---------------------------------------------------------------------------
// Restore body (Delete with restore_on_destroy)
// ---------------------------------------------------------------------------

// elRestoreBody re-applies a captured snapshot verbatim (preflight plus
// SaveChanges plus readback). Placeholders: @@NAME@@, @@SETBLOCK@@ (Go-built
// assignment lines covering every managed snapshot field).
const elRestoreBody = `
$logName = @@NAME@@

& {
  try {
    $found = @(Get-WinEvent -ListLog -ErrorAction Stop | Where-Object { $_.LogName -eq $logName })
  } catch {
    Emit-Err (Classify-EventLog $_) ([string]$_.Exception.Message) @{ log = $logName; step = 'preflight' }
    return
  }
  if ($found.Count -eq 0) {
    Emit-Err 'not_found' ('Event log ' + $logName + ' was not found on the target host.') @{ log = $logName; step = 'preflight' }
    return
  }
  $c = $found[0]

  try {
    @@SETBLOCK@@
    $c.SaveChanges()
  } catch {
    Emit-Err (Classify-EventLog $_) ([string]$_.Exception.Message) @{ log = $logName; step = 'restore' }
    return
  }

  try {
    $back = @(Get-WinEvent -ListLog -ErrorAction Stop | Where-Object { $_.LogName -eq $logName })
  } catch {
    Emit-Err (Classify-EventLog $_) ([string]$_.Exception.Message) @{ log = $logName; step = 'readback' }
    return
  }
  if ($back.Count -eq 0) {
    Emit-Err 'not_found' ('Event log ' + $logName + ' was not found on the target host.') @{ log = $logName; step = 'readback' }
    return
  }
  Emit-OK (Read-EventLogState $back[0] $logName)
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mapEventLogKind maps a PS-emitted kind string to EventLogErrorKind.
func mapEventLogKind(k string) EventLogErrorKind {
	switch EventLogErrorKind(k) {
	case EventLogErrorNotFound,
		EventLogErrorAccessDenied,
		EventLogErrorUnsupported,
		EventLogErrorInvalidSize:
		return EventLogErrorKind(k)
	default:
		return EventLogErrorUnknown
	}
}

// buildEventLogReplacer returns a strings.Replacer for the @@NAME@@
// placeholder shared by all event-log PS scripts.
func buildEventLogReplacer(name string) *strings.Replacer {
	return strings.NewReplacer(
		"@@NAME@@", psQuote(name),
	)
}

// buildEventLogGuard returns the PS fragment refusing to disable a classic
// log. It is emitted only when the caller configures Enabled=false; the
// IsClassic check itself must run on the host because the log type is only
// known there.
func buildEventLogGuard(settings EventLogSettings) string {
	if settings.Enabled == nil || *settings.Enabled {
		return ""
	}
	return `if ([bool]$c.IsClassic) {
    Emit-Err 'unsupported' ('Event log ' + $logName + ' is a classic log and cannot be disabled.') @{ log = $logName; step = 'guard' }
    return
  }`
}

// buildEventLogSetBlock renders the Go-known assignment lines for exactly
// the configured settings (partial management): nil fields are omitted so
// the host value is left untouched. Retention is translated to the .NET
// LogMode spelling here; an unknown retention fails closed before any
// script is built.
func buildEventLogSetBlock(settings EventLogSettings) (string, error) {
	var sb strings.Builder
	if settings.MaximumSizeBytes != nil {
		if err := ValidateEventLogSize(*settings.MaximumSizeBytes); err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "    $c.MaximumSizeInBytes = %d\n", *settings.MaximumSizeBytes)
	}
	if settings.Retention != nil {
		mode, err := EventLogRetentionToLogMode(*settings.Retention)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "    $c.LogMode = %s\n", psQuote(mode))
	}
	if settings.Enabled != nil {
		if *settings.Enabled {
			sb.WriteString("    $c.IsEnabled = $true\n")
		} else {
			sb.WriteString("    $c.IsEnabled = $false\n")
		}
	}
	if settings.LogFilePath != nil {
		fmt.Fprintf(&sb, "    $c.LogFilePath = %s\n", psQuote(*settings.LogFilePath))
	}
	return sb.String(), nil
}

// buildEventLogRestoreBlock renders the assignment lines that re-apply a
// captured snapshot verbatim. The stored LogMode is already the host
// spelling (Circular, AutoBackup, Retain).
func buildEventLogRestoreBlock(snap EventLogState) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "    $c.MaximumSizeInBytes = %d\n", snap.MaximumSizeBytes)
	fmt.Fprintf(&sb, "    $c.LogMode = %s\n", psQuote(snap.LogMode))
	if snap.IsEnabled {
		sb.WriteString("    $c.IsEnabled = $true\n")
	} else {
		sb.WriteString("    $c.IsEnabled = $false\n")
	}
	fmt.Fprintf(&sb, "    $c.LogFilePath = %s\n", psQuote(snap.LogFilePath))
	return sb.String()
}

// runEventLogEnvelope executes script (prefixed with elPsHeader) and returns
// the parsed psResponse envelope through the shared runEnvelope helper.
// Transport/PS-level errors that bypass Emit-Err are translated into
// *EventLogError.
func (c *EventLogClient) runEventLogEnvelope(ctx context.Context, op, name, script string) (*psResponse, error) {
	baseContext := map[string]string{"log": name, "host": c.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, c.c, full)
		},
		op, elPsHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewEventLogError(
			EventLogErrorUnknown,
			fmt.Sprintf("operation %q on event log %q timed out or was cancelled", op, name),
			eerr.Cause,
			eerr.Context,
		)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewEventLogError(
			EventLogErrorUnknown,
			eerr.Message,
			eerr.Cause,
			eerr.Context,
		)
	}
	return resp, NewEventLogError(mapEventLogKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// ---------------------------------------------------------------------------
// elStateJSON - mirrors the JSON emitted by Read-EventLogState
// ---------------------------------------------------------------------------

type elStateJSON struct {
	LogName          string `json:"log_name"`
	LogType          string `json:"log_type"`
	IsClassic        bool   `json:"is_classic"`
	IsEnabled        bool   `json:"is_enabled"`
	LogMode          string `json:"log_mode"`
	MaximumSizeBytes int64  `json:"maximum_size_bytes"`
	LogFilePath      string `json:"log_file_path"`
	RecordCount      int64  `json:"record_count"`
	FileSizeBytes    int64  `json:"file_size_bytes"`
	PolicyOverride   bool   `json:"policy_override"`
}

// normalizeEventLogType maps host spellings of the .NET EventLogType enum to
// the documented Terraform values. The enum member is "Analytical" but
// Get-WinEvent surfaces "Analytic" on some hosts; both are accepted.
func normalizeEventLogType(v string) string {
	if strings.EqualFold(v, "Analytical") {
		return "Analytic"
	}
	return v
}

// parseEventLogState parses the psResponse.Data field into an
// *EventLogState. Returns (nil, nil) when Data is JSON null (the log does
// not exist on the host).
func parseEventLogState(resp *psResponse, name string) (*EventLogState, error) {
	if resp.Data == nil || string(resp.Data) == "null" {
		return nil, nil
	}
	var j elStateJSON
	if err := json.Unmarshal(resp.Data, &j); err != nil {
		return nil, NewEventLogError(
			EventLogErrorUnknown,
			"failed to parse event log state JSON",
			err,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	logName := j.LogName
	if logName == "" {
		logName = name
	}
	return &EventLogState{
		Name:             logName,
		LogType:          normalizeEventLogType(j.LogType),
		IsClassic:        j.IsClassic,
		IsEnabled:        j.IsEnabled,
		LogMode:          j.LogMode,
		MaximumSizeBytes: j.MaximumSizeBytes,
		LogFilePath:      j.LogFilePath,
		RecordCount:      j.RecordCount,
		FileSizeBytes:    j.FileSizeBytes,
		PolicyOverride:   j.PolicyOverride,
	}, nil
}

// verifyEventLogState checks that every configured setting took effect in
// the re-read state. A mismatch is an unknown error: SaveChanges reported
// success but the host does not reflect the request (for example a Group
// Policy refresh raced the apply, in which case the message names the
// policy_override flag to check).
// normalizeEventLogPath unifies path separators so host and Terraform
// spellings compare equal: Windows accepts "/" and "\" interchangeably.
func normalizeEventLogPath(p string) string {
	return strings.ReplaceAll(p, "/", "\\")
}

// splitEventLogSysRoot splits a %SystemRoot%-based or expanded
// (<drive>:\Windows-based) prefix from the remainder of a log path.
// Reports ok=false when the path carries neither prefix.
func splitEventLogSysRoot(p string) (rest string, isEnv, ok bool) {
	if len(p) >= 12 && strings.EqualFold(p[:12], "%systemroot%") {
		return p[12:], true, true
	}
	// Expanded form: <letter>:\Windows optionally followed by "\" or end.
	if len(p) >= 11 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') && strings.EqualFold(p[3:10], "windows") &&
		(len(p) == 10 || p[10] == '\\' || p[10] == '/') {
		return p[10:], false, true
	}
	return "", false, false
}

// eventLogPathsEqual compares a requested log path with the host-reported
// value. Comparison is case-insensitive after separator normalisation, and
// a %SystemRoot% prefix on either side matches an expanded
// <drive>:\Windows prefix on the other (the host may expand environment
// variables when reporting LogFilePath).
func eventLogPathsEqual(want, got string) bool {
	w := normalizeEventLogPath(want)
	g := normalizeEventLogPath(got)
	if strings.EqualFold(w, g) {
		return true
	}
	wRest, wEnv, wOK := splitEventLogSysRoot(w)
	gRest, gEnv, gOK := splitEventLogSysRoot(g)
	if !wOK || !gOK {
		return false
	}
	// At least one side used the %SystemRoot% spelling: compare the
	// remainder below the Windows root case-insensitively. When both
	// sides are expanded absolute paths the exact EqualFold above
	// already decided (different drives must not compare equal).
	if !wEnv && !gEnv {
		return false
	}
	return strings.EqualFold(wRest, gRest)
}

func verifyEventLogState(want EventLogSettings, got *EventLogState) error {
	if want.MaximumSizeBytes != nil && got.MaximumSizeBytes != *want.MaximumSizeBytes {
		return NewEventLogError(
			EventLogErrorUnknown,
			fmt.Sprintf("event log change did not take effect: requested maximum_size_bytes %d, host reports %d", *want.MaximumSizeBytes, got.MaximumSizeBytes),
			nil,
			map[string]string{"log": got.Name, "policy_override": fmt.Sprintf("%v", got.PolicyOverride)},
		)
	}
	if want.Retention != nil {
		mode, err := EventLogRetentionToLogMode(*want.Retention)
		if err != nil {
			return err
		}
		if got.LogMode != mode {
			return NewEventLogError(
				EventLogErrorUnknown,
				fmt.Sprintf("event log change did not take effect: requested retention %q (%s), host reports LogMode %q", *want.Retention, mode, got.LogMode),
				nil,
				map[string]string{"log": got.Name, "policy_override": fmt.Sprintf("%v", got.PolicyOverride)},
			)
		}
	}
	if want.Enabled != nil && got.IsEnabled != *want.Enabled {
		return NewEventLogError(
			EventLogErrorUnknown,
			fmt.Sprintf("event log change did not take effect: requested enabled %v, host reports %v", *want.Enabled, got.IsEnabled),
			nil,
			map[string]string{"log": got.Name, "policy_override": fmt.Sprintf("%v", got.PolicyOverride)},
		)
	}
	if want.LogFilePath != nil && !eventLogPathsEqual(*want.LogFilePath, got.LogFilePath) {
		return NewEventLogError(
			EventLogErrorUnknown,
			fmt.Sprintf("event log change did not take effect: requested log_file_path %q, host reports %q", *want.LogFilePath, got.LogFilePath),
			nil,
			map[string]string{"log": got.Name, "policy_override": fmt.Sprintf("%v", got.PolicyOverride)},
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read retrieves the current state of the named event log using
// Get-WinEvent -ListLog. Returns (nil, nil) when the log does not exist on
// the host.
func (c *EventLogClient) Read(ctx context.Context, name string) (*EventLogState, error) {
	script := buildEventLogReplacer(name).Replace(elReadBody)
	resp, err := c.runEventLogEnvelope(ctx, "Read", name, script)
	if err != nil {
		return nil, err
	}
	st, perr := parseEventLogState(resp, name)
	if perr != nil {
		return nil, perr
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// Apply (Create and Update share it: logs always exist)
// ---------------------------------------------------------------------------

// Apply writes only the configured settings to the named log
// (EventLogConfiguration.SaveChanges), re-reads the log and verifies every
// configured property took effect. When no setting is configured it
// short-circuits to Read (nothing to guard, nothing to write).
//
// A missing log is a not_found error; disabling a classic log is an
// unsupported error; an invalid size is an invalid_size error — all fail
// closed before SaveChanges.
func (c *EventLogClient) Apply(ctx context.Context, name string, settings EventLogSettings) (*EventLogState, error) {
	if !settings.EventLogConfigured() {
		return c.Read(ctx, name)
	}
	setBlock, err := buildEventLogSetBlock(settings)
	if err != nil {
		return nil, err
	}
	script := strings.NewReplacer(
		"@@NAME@@", psQuote(name),
		"@@GUARD@@", buildEventLogGuard(settings),
		"@@SETBLOCK@@", setBlock,
	).Replace(elApplyBody)

	resp, err := c.runEventLogEnvelope(ctx, "Apply", name, script)
	if err != nil {
		return nil, err
	}
	st, perr := parseEventLogState(resp, name)
	if perr != nil {
		return nil, perr
	}
	if st == nil {
		return nil, NewEventLogError(
			EventLogErrorNotFound,
			fmt.Sprintf("event log %q was not found on the target host", name),
			nil,
			map[string]string{"log": name},
		)
	}
	if verr := verifyEventLogState(settings, st); verr != nil {
		return nil, verr
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

// Restore re-applies a previously captured snapshot verbatim (Delete with
// restore_on_destroy), then returns the read-back state.
func (c *EventLogClient) Restore(ctx context.Context, snapshot EventLogState) (*EventLogState, error) {
	if err := ValidateEventLogSize(snapshot.MaximumSizeBytes); err != nil {
		return nil, err
	}
	setBlock := buildEventLogRestoreBlock(snapshot)
	script := strings.NewReplacer(
		"@@NAME@@", psQuote(snapshot.Name),
		"@@SETBLOCK@@", setBlock,
	).Replace(elRestoreBody)

	resp, err := c.runEventLogEnvelope(ctx, "Restore", snapshot.Name, script)
	if err != nil {
		return nil, err
	}
	st, perr := parseEventLogState(resp, snapshot.Name)
	if perr != nil {
		return nil, perr
	}
	if st == nil {
		return nil, NewEventLogError(
			EventLogErrorNotFound,
			fmt.Sprintf("event log %q was not found on the target host", snapshot.Name),
			nil,
			map[string]string{"log": snapshot.Name},
		)
	}
	return st, nil
}
