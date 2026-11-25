// Package winclient: IIS application pool CRUD over SSH.
//
// This file implements WindowsIISAppPoolClient, the concrete client used by
// the windows_iis_app_pool Terraform resource and data source. All
// operations execute PowerShell scripts (WebAdministration module) wrapped
// in a JSON envelope (Emit-OK/Emit-Err) so stdout is machine-parseable
// regardless of Windows locale.
//
// Security invariants:
//   - Pool names, usernames and every other user-supplied string are
//     interpolated only through psQuote (single-quoted PS literal). Lookups
//     filter with Where-Object { $_.Name -eq $Name } (literal comparison,
//     same rule as windows_net_ip_address); -Name parameters that accept
//     wildcards additionally receive the wildcard-escaped spelling
//     (psEscapeWildcard) — pool names cannot contain wildcard characters
//     (ValidateIISAppPoolName), so this is defence in depth.
//   - The SpecificUser password is NEVER interpolated into script bodies. It
//     is injected via stdin (runAppPoolEnvelopeWithInput) and read by the PS
//     script via [Console]::In.ReadLine(). It never appears in error
//     messages or diagnostic context (the invalid_identity mapping keys off
//     0x8007052e without echoing any credential).
//
// Reused helpers from the same package:
//   - psQuote                  — safe single-quote escaping (psquote.go)
//   - psEscapeWildcard         — backtick-escape of * ? [ ] (iis_common.go)
//   - runEnvelope              — shared JSON envelope pipeline (envelope.go)
//   - runIISPowerShell — package-level hook (one-shot 5.1), stubbed in tests
//   - psResponse               — Emit-OK / Emit-Err envelope (service.go)
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Compile-time assertion: IISAppPoolClient satisfies WindowsIISAppPoolClient.
var _ WindowsIISAppPoolClient = (*IISAppPoolClient)(nil)

// IISAppPoolClient is the PowerShell/SSH-backed WindowsIISAppPoolClient.
type IISAppPoolClient struct {
	c *Client
}

// NewIISAppPoolClient constructs an IISAppPoolClient wrapping the given SSH Client.
func NewIISAppPoolClient(c *Client) *IISAppPoolClient { return &IISAppPoolClient{c: c} }

// ---------------------------------------------------------------------------
// PowerShell fragments
// ---------------------------------------------------------------------------

// iisAppPoolReadFragment defines Get-AppPoolData, which returns the pool as
// an ordered hashtable (or $null when absent). Durations are converted to
// whole minutes and cpu.limit thousandths to whole percent server-side to
// avoid locale formatting; the password is never read back.
const iisAppPoolReadFragment = `
function Get-AppPoolData([string]$Name) {
  $pool = Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
  if (-not $pool) { return $null }
  $poolPath = ('IIS:\AppPools\' + $Name)
  $p = Get-ItemProperty $poolPath -ErrorAction Stop
  $sched = @()
  try {
    $col = (Get-ItemProperty $poolPath -Name recycling.periodicRestart.schedule -ErrorAction Stop).Collection
    foreach ($e in @($col)) {
      if ($null -ne $e.value) { $sched += ([string]$e.value) }
    }
  } catch {}
  # recycling/periodicRestart is read via Get-WebConfiguration, not the
  # IIS: PSDrive: Get-ItemProperty returns $null for periodicRestart.time
  # (even at 60 min or the 29 h default) and for privateMemory, so
  # [int64]$null collapsed every non-zero value to 0 (F05/F06/F07).
  # Get-WebConfiguration returns .time as a TimeSpan (e.g. 300.00:00:00)
  # and .privateMemory as an int, converted server-side like the other
  # durations. The XPath filter quotes the pool name with double quotes
  # (names cannot contain '"' per ValidateIISAppPoolName, while "'" is
  # legal), mirroring the schedule write path.
  $restartMinutes = 0
  $restartPrivateMemory = 0
  try {
    $restartFilter = ('system.applicationHost/applicationPools/add[@name="' + $Name + '"]/recycling/periodicRestart')
    $restart = Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $restartFilter -ErrorAction Stop
    if ($null -ne $restart.time) { $restartMinutes = [int64][math]::Round($restart.time.TotalMinutes) }
    if ($null -ne $restart.privateMemory) { $restartPrivateMemory = [int64]$restart.privateMemory }
  } catch {}
  $state = 'Stopped'
  try { if ([string]$pool.State -eq 'Started') { $state = 'Started' } } catch {}
  return [ordered]@{
    name                               = [string]$pool.Name
    managed_runtime_version            = [string]$p.managedRuntimeVersion
    managed_pipeline_mode              = [string]$p.managedPipelineMode
    enable_32bit_app_on_win64          = [bool]$p.enable32BitAppOnWin64
    start_mode                         = [string]$p.startMode
    auto_start                         = [bool]$p.autoStart
    queue_length                       = [int64]$p.queueLength
    identity_type                      = [string]$p.processModel.identityType
    identity_username                  = [string]$p.processModel.userName
    load_user_profile                  = [bool]$p.processModel.loadUserProfile
    idle_timeout_minutes               = [int64]$p.processModel.idleTimeout.TotalMinutes
    idle_timeout_action                = [string]$p.processModel.idleTimeoutAction
    max_processes                      = [int64]$p.processModel.maxProcesses
    recycling_periodic_restart_minutes = $restartMinutes
    recycling_schedule                 = [array]$sched
    recycling_private_memory_kb        = $restartPrivateMemory
    rapid_fail_protection              = [bool]$p.failure.rapidFailProtection
    cpu_limit_percent                  = [int64]([int64]$p.cpu.limit / 1000)
    cpu_action                         = [string]$p.cpu.action
    state                              = $state
  }
}

function Classify-AppPool([string]$Msg) {
  $shared = Classify-IIS $Msg
  if ($shared -ne 'unknown') { return $shared }
  return 'unknown'
}
`

// ---------------------------------------------------------------------------
// Set-statement builder (partial management: only configured attrs emitted)
// ---------------------------------------------------------------------------

// psBoolLiteral renders a Go bool as a PowerShell boolean literal.
func psBoolLiteral(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// buildIISAppPoolSetStatements renders the Set-ItemProperty lines covering
// ONLY the configured settings. $poolPath and $Name are script variables set
// by the caller. When withPassword is true the caller must also prepend the
// stdin read for $AppPoolPassword and invoke through runPSInput.
func buildIISAppPoolSetStatements(s IISAppPoolSettings, withPassword bool) string {
	var sb strings.Builder
	str := func(prop string, v *string) {
		fmt.Fprintf(&sb, "  Set-ItemProperty $poolPath -Name %s -Value %s -ErrorAction Stop\n", prop, psQuote(*v))
	}
	boolean := func(prop string, v *bool) {
		fmt.Fprintf(&sb, "  Set-ItemProperty $poolPath -Name %s -Value %s -ErrorAction Stop\n", prop, psBoolLiteral(*v))
	}
	num := func(prop string, v *int64) {
		fmt.Fprintf(&sb, "  Set-ItemProperty $poolPath -Name %s -Value %d -ErrorAction Stop\n", prop, *v)
	}
	if s.ManagedRuntimeVersion != nil {
		str("managedRuntimeVersion", s.ManagedRuntimeVersion)
	}
	if s.ManagedPipelineMode != nil {
		str("managedPipelineMode", s.ManagedPipelineMode)
	}
	if s.Enable32BitAppOnWin64 != nil {
		boolean("enable32BitAppOnWin64", s.Enable32BitAppOnWin64)
	}
	if s.StartMode != nil {
		str("startMode", s.StartMode)
	}
	if s.AutoStart != nil {
		boolean("autoStart", s.AutoStart)
	}
	if s.QueueLength != nil {
		num("queueLength", s.QueueLength)
	}
	if s.IdentityType != nil {
		str("processModel.identityType", s.IdentityType)
	}
	if s.IdentityUsername != nil {
		str("processModel.userName", s.IdentityUsername)
	}
	// The password travels on stdin ($AppPoolPassword): it must never be
	// interpolated here — this line is only a variable reference.
	if withPassword {
		sb.WriteString("  Set-ItemProperty $poolPath -Name processModel.password -Value $AppPoolPassword -ErrorAction Stop\n")
	}
	if s.LoadUserProfile != nil {
		boolean("processModel.loadUserProfile", s.LoadUserProfile)
	}
	if s.IdleTimeoutMinutes != nil {
		// Assign-then-use: passing (New-TimeSpan ...) inline as -Value
		// throws InvalidCastException ("Specified cast is not valid") on
		// some hosts (Server 2025 build 26100, aggressive CLI campaign
		// 2026-11-17) — the WebAdministration provider direct-casts the
		// value and chokes on the PSObject wrapper of an inline
		// expression, while a variable unrolls cleanly. The same rule
		// covers recycling.periodicRestart.time below and the site
		// limits.connectionTimeout.
		fmt.Fprintf(&sb, "  $idleTimeoutValue = New-TimeSpan -Minutes %d\n", *s.IdleTimeoutMinutes)
		sb.WriteString("  Set-ItemProperty $poolPath -Name processModel.idleTimeout -Value $idleTimeoutValue -ErrorAction Stop\n")
	}
	if s.IdleTimeoutAction != nil {
		str("processModel.idleTimeoutAction", s.IdleTimeoutAction)
	}
	if s.MaxProcesses != nil {
		num("processModel.maxProcesses", s.MaxProcesses)
	}
	if s.RecyclingPeriodicRestartMinutes != nil {
		// Assign-then-use (see processModel.idleTimeout above): an inline
		// (New-TimeSpan ...) -Value throws InvalidCastException on some
		// hosts while the same TimeSpan through a variable applies cleanly.
		fmt.Fprintf(&sb, "  $restartTimeValue = New-TimeSpan -Minutes %d\n", *s.RecyclingPeriodicRestartMinutes)
		sb.WriteString("  Set-ItemProperty $poolPath -Name recycling.periodicRestart.time -Value $restartTimeValue -ErrorAction Stop\n")
	}
	// A configured schedule (even empty) replaces the whole collection:
	// clear it, then add each entry. The XPath filter quotes the pool name
	// with double quotes (names cannot contain '"' per
	// ValidateIISAppPoolName, while "'" is legal), so the filter cannot be
	// broken out of.
	if s.RecyclingScheduleSet {
		sb.WriteString("  Clear-ItemProperty $poolPath -Name recycling.periodicRestart.schedule -ErrorAction Stop\n")
		if len(s.RecyclingSchedule) > 0 {
			quoted := make([]string, 0, len(s.RecyclingSchedule))
			for _, t := range s.RecyclingSchedule {
				quoted = append(quoted, psQuote(t))
			}
			fmt.Fprintf(&sb, "  foreach ($t in @(%s)) {\n", strings.Join(quoted, ","))
			sb.WriteString("    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter ('system.applicationHost/applicationPools/add[@name=\"' + $Name + '\"]/recycling/periodicRestart/schedule') -Name '.' -Value @{value=$t} -ErrorAction Stop\n")
			sb.WriteString("  }\n")
		}
	}
	if s.RecyclingPrivateMemoryKB != nil {
		num("recycling.periodicRestart.privateMemory", s.RecyclingPrivateMemoryKB)
	}
	if s.RapidFailProtection != nil {
		boolean("failure.rapidFailProtection", s.RapidFailProtection)
	}
	if s.CPULimitPercent != nil {
		fmt.Fprintf(&sb, "  Set-ItemProperty $poolPath -Name cpu.limit -Value %d -ErrorAction Stop\n", *s.CPULimitPercent*1000)
	}
	if s.CPUAction != nil {
		str("cpu.action", s.CPUAction)
	}
	return sb.String()
}

// buildIISAppPoolStateStatement renders the runtime-state enforcement lines.
// A nil state emits nothing: the pool keeps whatever state the host reports.
func buildIISAppPoolStateStatement(state *string, escapedName string) string {
	if state == nil {
		return ""
	}
	if *state == "Started" {
		return "  Start-WebAppPool -Name " + escapedName + " -ErrorAction Stop\n"
	}
	return "  Stop-WebAppPool -Name " + escapedName + " -ErrorAction Stop\n"
}

// ---------------------------------------------------------------------------
// Envelope runners
// ---------------------------------------------------------------------------

// mapIISAppPoolKind translates the PS-side kind string to a typed
// IISAppPoolErrorKind. A logon-failure signature (0x8007052e) always maps to
// invalid_identity — even when the script-side classifier missed it — without
// echoing any credential (the password never reaches msg: it travels on
// stdin, never in script text).
func mapIISAppPoolKind(kind, msg string) IISAppPoolErrorKind {
	switch IISAppPoolErrorKind(kind) {
	case IISAppPoolErrorNotFound,
		IISAppPoolErrorAlreadyExists,
		IISAppPoolErrorInUse,
		IISAppPoolErrorIISNotInstalled,
		IISAppPoolErrorInvalidIdentity,
		IISAppPoolErrorAccessDenied,
		IISAppPoolErrorConfigLocked:
		return IISAppPoolErrorKind(kind)
	default:
		if strings.Contains(strings.ToLower(msg), "0x8007052e") {
			return IISAppPoolErrorInvalidIdentity
		}
		return IISAppPoolErrorUnknown
	}
}

// runAppPoolEnvelope executes script (prefixed with psIISHeader) and parses
// the JSON envelope through the shared runEnvelope helper. Transport and
// parsing failures become IISAppPoolErrorUnknown; timeouts keep their
// operation-scoped message.
func (a *IISAppPoolClient) runAppPoolEnvelope(ctx context.Context, op, name, script string) (*psResponse, error) {
	baseContext := map[string]string{"name": name, "host": a.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runIISPowerShell(ctx, a.c, full, stdin)
		},
		op, psIISHeader+"\n"+iisAppPoolReadFragment+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewIISAppPoolError(mapIISAppPoolKind(eerr.RemoteKind, eerr.Message), eerr.Message, nil, eerr.Context)
}

// runAppPoolEnvelopeWithInput is the stdin-aware sibling of
// runAppPoolEnvelope for scripts that consume the SpecificUser password via
// [Console]::In.ReadLine(). The stdin value is NEVER copied into error
// context or logs.
func (a *IISAppPoolClient) runAppPoolEnvelopeWithInput(ctx context.Context, op, name, script, stdin string) (*psResponse, error) {
	baseContext := map[string]string{"name": name, "host": a.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runIISPowerShell(ctx, a.c, full, stdin)
		},
		op, psIISHeader+"\n"+iisAppPoolReadFragment+"\n"+script, stdin, baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewIISAppPoolError(mapIISAppPoolKind(eerr.RemoteKind, eerr.Message), eerr.Message, nil, eerr.Context)
}

// runAppPoolWrite executes a mutating script with the concurrent-writer
// retry: the file-has-changed-on-disk flake and the transient
// WebAdministration NullReference flake (F08, concurrent one-shot 5.1
// writers racing on applicationHost.config) are retried (up to
// iisWriteMaxAttempts attempts with backoff); transport errors and every
// other remote failure surface immediately. When a flake persists past
// retries it surfaces as config_locked rather than an opaque host error.
// Only write paths (create/update/delete) consult the retry predicate, so a
// genuine read-side null-ref keeps surfacing as unknown via Read.
// The backoff sleep honours ctx cancellation so a timed-out operation never
// sleeps past its deadline.
//
// Create is not idempotent across retries: a first attempt may pass
// New-WebAppPool and then fail on Set-ItemProperty with the flake while the
// best-effort Remove-WebAppPool cleanup also fails, so the retry hits the
// $found guard and returns already_exists instead of the flake. When op is
// "create" and already_exists follows an observed flake, the original flake
// error is returned as config_locked (with its original message and context)
// instead of the misleading already_exists.
// isAppPoolWriteFlake reports whether err is a transient concurrent-writer
// flake worth retrying: the file-has-changed-on-disk signature (any kind),
// or the WebAdministration NullReference (F08) which the shared Classify-IIS
// leaves as unknown. The NullReference match additionally requires the
// unknown kind so a pool literally named like the phrase (already_exists
// with the name interpolated into the message) is never mis-retried into
// config_locked.
func isAppPoolWriteFlake(ae *IISAppPoolError) bool {
	if IISConfigChangedOnDisk(ae.Message) {
		return true
	}
	return ae.Kind == IISAppPoolErrorUnknown && IISConcurrentWriteNullReference(ae.Message)
}

func (a *IISAppPoolClient) runAppPoolWrite(
	ctx context.Context, op, name, script, stdin string,
) (*psResponse, error) {
	var flakeErr *IISAppPoolError
	for attempt := 1; ; attempt++ {
		var resp *psResponse
		var err error
		if stdin != "" {
			resp, err = a.runAppPoolEnvelopeWithInput(ctx, op, name, script, stdin)
		} else {
			resp, err = a.runAppPoolEnvelope(ctx, op, name, script)
		}
		if err == nil {
			return resp, nil
		}
		var ae *IISAppPoolError
		if !errors.As(err, &ae) {
			return nil, err
		}
		if !isAppPoolWriteFlake(ae) {
			if op == "create" && flakeErr != nil && ae.Kind == IISAppPoolErrorAlreadyExists {
				flakeErr.Kind = IISAppPoolErrorConfigLocked
				return nil, flakeErr
			}
			return nil, err
		}
		if flakeErr == nil {
			flakeCopy := *ae
			flakeErr = &flakeCopy
		}
		if attempt >= iisWriteMaxAttempts {
			ae.Kind = IISAppPoolErrorConfigLocked
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(iisRetryBackoff(attempt)):
		}
	}
}

// ---------------------------------------------------------------------------
// Payload parsing
// ---------------------------------------------------------------------------

// iisAppPoolJSON mirrors the JSON object returned by Get-AppPoolData.
type iisAppPoolJSON struct {
	Name                            string          `json:"name"`
	ManagedRuntimeVersion           string          `json:"managed_runtime_version"`
	ManagedPipelineMode             string          `json:"managed_pipeline_mode"`
	Enable32BitAppOnWin64           bool            `json:"enable_32bit_app_on_win64"`
	StartMode                       string          `json:"start_mode"`
	AutoStart                       bool            `json:"auto_start"`
	QueueLength                     int64           `json:"queue_length"`
	IdentityType                    string          `json:"identity_type"`
	IdentityUsername                string          `json:"identity_username"`
	LoadUserProfile                 bool            `json:"load_user_profile"`
	IdleTimeoutMinutes              int64           `json:"idle_timeout_minutes"`
	IdleTimeoutAction               string          `json:"idle_timeout_action"`
	MaxProcesses                    int64           `json:"max_processes"`
	RecyclingPeriodicRestartMinutes int64           `json:"recycling_periodic_restart_minutes"`
	RecyclingSchedule               json.RawMessage `json:"recycling_schedule"`
	RecyclingPrivateMemoryKB        int64           `json:"recycling_private_memory_kb"`
	RapidFailProtection             bool            `json:"rapid_fail_protection"`
	CPULimitPercent                 int64           `json:"cpu_limit_percent"`
	CPUAction                       string          `json:"cpu_action"`
	State                           string          `json:"state"`
}

// parseIISAppPoolSchedule decodes the recycling_schedule blob, tolerating
// null (empty collection) and the ConvertTo-Json single-element quirk (a
// bare string instead of an array).
func parseIISAppPoolSchedule(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []string{}, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var items []string
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, NewIISAppPoolError(
				IISAppPoolErrorUnknown,
				"failed to parse app pool recycling schedule",
				err, nil,
			)
		}
		if items == nil {
			return []string{}, nil
		}
		return items, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, NewIISAppPoolError(
			IISAppPoolErrorUnknown,
			"failed to parse app pool recycling schedule",
			err, nil,
		)
	}
	if single == "" {
		return []string{}, nil
	}
	return []string{single}, nil
}

// parseIISAppPoolState converts the envelope data into an IISAppPoolState.
// A JSON null data means "pool absent" and yields (nil, nil).
func parseIISAppPoolState(op, name string, data json.RawMessage) (*IISAppPoolState, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var j iisAppPoolJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown,
			fmt.Sprintf("failed to parse app pool JSON from %q", op), err,
			map[string]string{"name": name})
	}
	sched, err := parseIISAppPoolSchedule(j.RecyclingSchedule)
	if err != nil {
		return nil, err
	}
	poolName := j.Name
	if poolName == "" {
		poolName = name
	}
	return &IISAppPoolState{
		Name:                            poolName,
		ManagedRuntimeVersion:           j.ManagedRuntimeVersion,
		ManagedPipelineMode:             j.ManagedPipelineMode,
		Enable32BitAppOnWin64:           j.Enable32BitAppOnWin64,
		StartMode:                       j.StartMode,
		AutoStart:                       j.AutoStart,
		QueueLength:                     j.QueueLength,
		IdentityType:                    j.IdentityType,
		IdentityUsername:                j.IdentityUsername,
		LoadUserProfile:                 j.LoadUserProfile,
		IdleTimeoutMinutes:              j.IdleTimeoutMinutes,
		IdleTimeoutAction:               j.IdleTimeoutAction,
		MaxProcesses:                    j.MaxProcesses,
		RecyclingPeriodicRestartMinutes: j.RecyclingPeriodicRestartMinutes,
		RecyclingSchedule:               sched,
		RecyclingPrivateMemoryKB:        j.RecyclingPrivateMemoryKB,
		RapidFailProtection:             j.RapidFailProtection,
		CPULimitPercent:                 j.CPULimitPercent,
		CPUAction:                       j.CPUAction,
		State:                           j.State,
	}, nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create creates the pool, applies the configured settings in a single
// script, enforces the configured state, and returns the read-back state.
// An existing pool yields already_exists with an import hint. On partial
// failure the half-created pool is deleted best-effort (script-side) and
// the original error is returned.
func (a *IISAppPoolClient) Create(ctx context.Context, in IISAppPoolInput) (*IISAppPoolState, error) {
	if strings.ContainsAny(in.Password, "\r\n") {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown,
			"password must not contain carriage return or line feed characters: secrets are read with ReadLine().",
			nil, map[string]string{"name": in.Name})
	}
	if err := ValidateIISAppPoolName(in.Name); err != nil {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown, err.Error(), nil, map[string]string{"name": in.Name})
	}
	withPassword := in.Password != ""
	stdin := ""
	pwRead := ""
	if withPassword {
		stdin = in.Password + "\n"
		pwRead = "$AppPoolPassword = [Console]::In.ReadLine()\n"
	}
	script := fmt.Sprintf(`
$Name = %s
$poolPath = ('IIS:\AppPools\' + $Name)
if (-not (Ensure-IIS)) { return }
$found = Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
if ($found) {
  Emit-Err 'already_exists' ('IIS application pool ''' + $found.Name + ''' already exists on this host (use ''terraform import'' to bring it under management instead of creating a duplicate).') @{ name = $found.Name }
  return
}
%s
try {
  New-WebAppPool -Name %s -ErrorAction Stop | Out-Null
  try {
%s
%s
    Emit-OK (Get-AppPoolData $Name)
  } catch {
    try { Remove-WebAppPool -Name %s -ErrorAction SilentlyContinue } catch {}
    throw
  }
} catch {
  $createErr = [string]$_.Exception.Message
  # A concurrent create (duplicate resource, parallel apply) can pass the
  # $found pre-flight above and then fail inside New-WebAppPool with an
  # opaque error even though the pool now exists. Re-check before
  # classifying: an existing pool is already_exists with the import hint,
  # never unknown (same class as the site create race, aggressive CLI
  # campaign, 2026-11-17). A failed cleanup of our own partial pool
  # surfaces the same way, which is accurate.
  try {
    $nowFound = Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
    if ($nowFound) {
      Emit-Err 'already_exists' ('IIS application pool ''' + $nowFound.Name + ''' already exists on this host (use ''terraform import'' to bring it under management instead of creating a duplicate).') @{ name = $nowFound.Name }
      return
    }
  } catch {}
  Emit-Err (Classify-AppPool $createErr) $createErr @{ name = $Name; step = 'create' }
}
`,
		psQuote(in.Name),
		pwRead,
		psQuote(psEscapeWildcard(in.Name)),
		buildIISAppPoolSetStatements(in.Settings, withPassword),
		buildIISAppPoolStateStatement(in.Settings.State, psQuote(psEscapeWildcard(in.Name))),
		psQuote(psEscapeWildcard(in.Name)),
	)

	resp, err := a.runAppPoolWrite(ctx, "create", in.Name, script, stdin)
	if err != nil {
		return nil, err
	}
	return parseIISAppPoolState("create", in.Name, resp.Data)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the current state of the named pool, or (nil, nil) when the
// pool does not exist (drift detection). The password is never returned.
func (a *IISAppPoolClient) Read(ctx context.Context, name string) (*IISAppPoolState, error) {
	if err := ValidateIISAppPoolName(name); err != nil {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown, err.Error(), nil, map[string]string{"name": name})
	}
	script := fmt.Sprintf(`
$Name = %s
if (-not (Ensure-IIS)) { return }
try {
  Emit-OK (Get-AppPoolData $Name)
} catch {
  Emit-Err (Classify-AppPool $_.Exception.Message) ([string]$_.Exception.Message) @{ name = $Name; step = 'read' }
}
`, psQuote(name))

	resp, err := a.runAppPoolEnvelope(ctx, "read", name, script)
	if err != nil {
		if IsIISAppPoolError(err, IISAppPoolErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseIISAppPoolState("read", name, resp.Data)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies only the configured settings to the named pool (plus the
// password when in.Password is non-empty), enforces the configured state,
// and returns the read-back state. A missing pool yields not_found.
func (a *IISAppPoolClient) Update(ctx context.Context, in IISAppPoolInput) (*IISAppPoolState, error) {
	if strings.ContainsAny(in.Password, "\r\n") {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown,
			"password must not contain carriage return or line feed characters: secrets are read with ReadLine().",
			nil, map[string]string{"name": in.Name})
	}
	if err := ValidateIISAppPoolName(in.Name); err != nil {
		return nil, NewIISAppPoolError(IISAppPoolErrorUnknown, err.Error(), nil, map[string]string{"name": in.Name})
	}
	withPassword := in.Password != ""
	stdin := ""
	pwRead := ""
	if withPassword {
		stdin = in.Password + "\n"
		pwRead = "$AppPoolPassword = [Console]::In.ReadLine()\n"
	}
	script := fmt.Sprintf(`
$Name = %s
$poolPath = ('IIS:\AppPools\' + $Name)
if (-not (Ensure-IIS)) { return }
$found = Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
if (-not $found) {
  Emit-Err 'not_found' ('IIS application pool ''' + $Name + ''' was not found on this host.') @{ name = $Name }
  return
}
%s
try {
%s
%s
  Emit-OK (Get-AppPoolData $Name)
} catch {
  Emit-Err (Classify-AppPool $_.Exception.Message) ([string]$_.Exception.Message) @{ name = $Name; step = 'update' }
}
`,
		psQuote(in.Name),
		pwRead,
		buildIISAppPoolSetStatements(in.Settings, withPassword),
		buildIISAppPoolStateStatement(in.Settings.State, psQuote(psEscapeWildcard(in.Name))),
	)

	resp, err := a.runAppPoolWrite(ctx, "update", in.Name, script, stdin)
	if err != nil {
		return nil, err
	}
	return parseIISAppPoolState("update", in.Name, resp.Data)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the named pool. When sites or applications still reference
// it, the delete is refused with in_use listing them. A missing pool is
// already absent (Emit-OK, nil error).
func (a *IISAppPoolClient) Delete(ctx context.Context, name string) error {
	if err := ValidateIISAppPoolName(name); err != nil {
		return NewIISAppPoolError(IISAppPoolErrorUnknown, err.Error(), nil, map[string]string{"name": name})
	}
	script := fmt.Sprintf(`
$Name = %s
if (-not (Ensure-IIS)) { return }
$found = Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
if (-not $found) {
  Emit-OK ([ordered]@{ deleted = $true; note = 'already_absent' })
  return
}
$refs = @()
foreach ($s in @(Get-Website -ErrorAction SilentlyContinue | Where-Object { $_.applicationPool -eq $Name })) { $refs += ('site:' + $s.name) }
foreach ($ws in @(Get-WebApplication -ErrorAction SilentlyContinue | Where-Object { $_.applicationPool -eq $Name })) { $refs += ('application:' + $ws.path) }
if ($refs.Count -gt 0) {
  Emit-Err 'in_use' ('Cannot delete IIS application pool ''' + $Name + ''': it is still referenced by ' + ($refs -join ', ') + '. Move those sites or applications to another pool first.') @{ name = $Name; referenced_by = ($refs -join ',') }
  return
}
try {
  Remove-WebAppPool -Name %s -ErrorAction Stop
  Emit-OK ([ordered]@{ deleted = $true })
} catch {
  Emit-Err (Classify-AppPool $_.Exception.Message) ([string]$_.Exception.Message) @{ name = $Name; step = 'delete' }
}
`, psQuote(name), psQuote(psEscapeWildcard(name)))

	_, err := a.runAppPoolWrite(ctx, "delete", name, script, "")
	return err
}
