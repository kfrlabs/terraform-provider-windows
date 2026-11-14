// Package winclient: Windows Scheduled Task CRUD implementation over SSH.
//
// ScheduledTaskClientImpl uses the ScheduledTasks PowerShell module for all
// task-level operations, and Schedule.Service COM for folder creation/pruning.
// OnEvent triggers are injected via raw task XML (ADR-ST-5).
//
// Security invariants:
//   - All user-supplied strings are passed through psQuote (single-quoted PS literals)
//     EXCEPT principal.password, which is never embedded in the script body.
//   - principal.password is injected on stdin via runSTEnvelopeWithInput and read by
//     the script through [Console]::In.ReadLine(), keeping the plaintext out of
//     the SSH -EncodedCommand payload, SSH trace logs, IIS WMSvc traces, and
//     any host-side Set-PSDebug/Start-Transcript output (mirrors ADR-LU-3).
//   - Passwords are never logged or included in error context (ADR-ST-3).
//   - All scripts are transmitted via -EncodedCommand (UTF-16LE base64).
package winclient

import (
	"context"
	"fmt"
)

// PowerShell header, JSON envelope structs and envelope runners. Split from scheduled_task.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// PowerShell header — shared helper functions
// ---------------------------------------------------------------------------

// psSTHeader is prepended to every script.  It defines Emit-OK/Emit-Err and
// all helper functions used by Read-TaskState, Ensure-TaskFolder, etc.
// NOTE: Go raw strings cannot contain backtick; we avoid PS backtick-escapes
// by using explicit PS techniques (e.g. [char]10, [char]39 or [Environment]::NewLine).
const psSTHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 12 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}

function Format-DT([string]$dt) {
  if ([string]::IsNullOrEmpty($dt)) { return '' }
  try {
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::RoundtripKind
    $d = [datetime]::Parse($dt, [cultureinfo]::InvariantCulture, $styles)
    return $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  } catch { return $dt }
}

function Format-InfoDT([object]$dt) {
  if ($null -eq $dt) { return '' }
  try {
    $d = [datetime]$dt
    if ($d.Year -le 1900 -or $d -eq [datetime]::MinValue) { return '' }
    return $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  } catch { return '' }
}

function Get-TriggerType([object]$t) {
  $cn = $t.CimClass.CimClassName
  if ($cn -eq 'MSFT_TaskTimeTrigger')   { return 'Once' }
  if ($cn -eq 'MSFT_TaskDailyTrigger')  { return 'Daily' }
  if ($cn -eq 'MSFT_TaskWeeklyTrigger') { return 'Weekly' }
  if ($cn -eq 'MSFT_TaskLogonTrigger')  { return 'AtLogon' }
  if ($cn -eq 'MSFT_TaskBootTrigger')   { return 'AtStartup' }
  if ($cn -eq 'MSFT_TaskEventTrigger')  { return 'OnEvent' }
  return 'Unknown'
}

function Get-DaysOfWeek([int]$mask) {
  $days = [System.Collections.Generic.List[string]]::new()
  if ($mask -band 1)  { $days.Add('Sunday') }
  if ($mask -band 2)  { $days.Add('Monday') }
  if ($mask -band 4)  { $days.Add('Tuesday') }
  if ($mask -band 8)  { $days.Add('Wednesday') }
  if ($mask -band 16) { $days.Add('Thursday') }
  if ($mask -band 32) { $days.Add('Friday') }
  if ($mask -band 64) { $days.Add('Saturday') }
  return ,$days.ToArray()
}

function Get-LogonTypeStr([int]$lt) {
  switch ($lt) {
    1 { return 'Password' }
    2 { return 'S4U' }
    3 { return 'Interactive' }
    4 { return 'Group' }
    5 { return 'ServiceAccount' }
    6 { return 'InteractiveOrPassword' }
    default { return 'ServiceAccount' }
  }
}

function Get-RunLevelStr([int]$rl) {
  if ($rl -eq 1) { return 'Highest' }
  return 'Limited'
}

function Get-TaskStateStr([int]$s) {
  switch ($s) {
    1 { return 'Disabled' }
    2 { return 'Queued' }
    3 { return 'Ready' }
    4 { return 'Running' }
    default { return 'Unknown' }
  }
}

function Get-MultipleInstancesStr([int]$mi) {
  switch ($mi) {
    0 { return 'Parallel' }
    1 { return 'Queue' }
    2 { return 'IgnoreNew' }
    3 { return 'StopExisting' }
    default { return 'Queue' }
  }
}

function Build-TriggerObj([object]$t) {
  $type = Get-TriggerType $t
  $dows = [string[]]@()
  if ($type -eq 'Weekly' -and $t.PSObject.Properties['DaysOfWeek'] -and $null -ne $t.DaysOfWeek) {
    $dows = [string[]](Get-DaysOfWeek ([int]$t.DaysOfWeek))
  }
  $etl  = if ($t.PSObject.Properties['ExecutionTimeLimit']  -and -not [string]::IsNullOrEmpty($t.ExecutionTimeLimit))  { [string]$t.ExecutionTimeLimit  } else { '' }
  $dly  = if ($t.PSObject.Properties['Delay']               -and -not [string]::IsNullOrEmpty($t.Delay))               { [string]$t.Delay               } else { '' }
  $sb   = if ($t.PSObject.Properties['StartBoundary']       -and -not [string]::IsNullOrEmpty($t.StartBoundary))       { Format-DT ([string]$t.StartBoundary) } else { '' }
  $eb   = if ($t.PSObject.Properties['EndBoundary']         -and -not [string]::IsNullOrEmpty($t.EndBoundary))         { Format-DT ([string]$t.EndBoundary)   } else { '' }
  $uid  = if ($t.PSObject.Properties['UserId']              -and -not [string]::IsNullOrEmpty($t.UserId))              { [string]$t.UserId              } else { '' }
  $sub  = if ($t.PSObject.Properties['Subscription']        -and -not [string]::IsNullOrEmpty($t.Subscription))        { [string]$t.Subscription        } else { '' }
  $di   = if ($t.PSObject.Properties['DaysInterval']        -and $null -ne $t.DaysInterval)                            { [long]$t.DaysInterval          } else { [long]0 }
  $wi   = if ($t.PSObject.Properties['WeeksInterval']       -and $null -ne $t.WeeksInterval)                           { [long]$t.WeeksInterval         } else { [long]0 }
  $en   = if ($t.PSObject.Properties['Enabled']             -and $null -ne $t.Enabled)                                 { [bool]$t.Enabled               } else { $true }
  return [ordered]@{
    type                = [string]$type
    enabled             = [bool]$en
    start_boundary      = [string]$sb
    end_boundary        = [string]$eb
    execution_time_limit = [string]$etl
    delay               = [string]$dly
    days_interval       = [long]$di
    days_of_week        = $dows
    weeks_interval      = [long]$wi
    user_id             = [string]$uid
    subscription        = [string]$sub
  }
}

function Read-TaskState([string]$TaskName, [string]$TaskPath) {
  $task = $null
  try {
    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match 'Access is denied' -or $msg -match 'UnauthorizedAccess' -or $msg -match 'privilege') {
      Emit-Err 'permission_denied' $msg @{ task_name = $TaskName; task_path = $TaskPath }
      return
    }
    Emit-OK $null
    return
  }
  if ($null -eq $task) { Emit-OK $null; return }

  $info = $null
  try { $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop } catch {}

  $lastRT   = ''
  $nextRT   = ''
  $lastRes  = [long]0
  if ($null -ne $info) {
    $lastRT  = Format-InfoDT $info.LastRunTime
    $nextRT  = Format-InfoDT $info.NextRunTime
    if ($null -ne $info.LastTaskResult) { $lastRes = [long]$info.LastTaskResult }
  }

  $actions = [object[]]@()
  if ($task.Actions) {
    $actionList = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $task.Actions) {
      $exec = if ($a.PSObject.Properties['Execute']) { [string]$a.Execute } else { '' }
      $args = if ($a.PSObject.Properties['Arguments'] -and -not [string]::IsNullOrEmpty($a.Arguments)) { [string]$a.Arguments } else { '' }
      $wd   = if ($a.PSObject.Properties['WorkingDirectory'] -and -not [string]::IsNullOrEmpty($a.WorkingDirectory)) { [string]$a.WorkingDirectory } else { '' }
      $actionList.Add([ordered]@{ execute = $exec; arguments = $args; working_directory = $wd })
    }
    $actions = $actionList.ToArray()
  }

  $triggers = [object[]]@()
  if ($task.Triggers) {
    $trigList = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $task.Triggers) { $trigList.Add((Build-TriggerObj $t)) }
    $triggers = $trigList.ToArray()
  }

  $principal = $null
  if ($task.Principal) {
    $principal = [ordered]@{
      user_id    = [string]$task.Principal.UserId
      logon_type = Get-LogonTypeStr ([int]$task.Principal.LogonType)
      run_level  = Get-RunLevelStr  ([int]$task.Principal.RunLevel)
    }
  }

  $settings = $null
  $enabled  = $true
  if ($task.Settings) {
    $s = $task.Settings
    if ($null -ne $s.Enabled) { $enabled = [bool]$s.Enabled }
    $etl = if (-not [string]::IsNullOrEmpty($s.ExecutionTimeLimit)) { [string]$s.ExecutionTimeLimit } else { '' }
    $settings = [ordered]@{
      allow_demand_start             = [bool]$s.AllowDemandStart
      allow_hard_terminate           = [bool]$s.AllowHardTerminate
      start_when_available           = [bool]$s.StartWhenAvailable
      run_only_if_network_available  = [bool]$s.RunOnlyIfNetworkAvailable
      execution_time_limit           = $etl
      multiple_instances             = Get-MultipleInstancesStr ([int]$s.MultipleInstances)
      disallow_start_if_on_batteries = [bool]$s.DisallowStartIfOnBatteries
      stop_if_going_on_batteries     = [bool]$s.StopIfGoingOnBatteries
      wake_to_run                    = [bool]$s.WakeToRun
      run_only_if_idle               = [bool]$s.RunOnlyIfIdle
    }
  }

  Emit-OK ([ordered]@{
    name            = [string]$task.TaskName
    path            = [string]$task.TaskPath
    description     = [string]$task.Description
    enabled         = [bool]$enabled
    state           = Get-TaskStateStr ([int]$task.State)
    last_run_time   = $lastRT
    last_task_result = $lastRes
    next_run_time   = $nextRT
    principal       = $principal
    actions         = $actions
    triggers        = $triggers
    settings        = $settings
  })
}

function Ensure-TaskFolder([string]$FolderPath) {
  # ITaskFolder::CreateFolder rejects a trailing backslash (ERROR_INVALID_NAME,
  # 0x8007007B), so normalise first; Remove-EmptyFolder already does this. The
  # root path '\' trims to '' and needs no folder created.
  #
  # Returns $true on success, $false (after Emit-Err) on failure. Since #81
  # this script runs inside a long-lived, reused PowerShell session, where
  # "exit" would kill the session instead of just this call; callers must
  # check the return value and stop rather than fall through.
  $FolderPath = $FolderPath.TrimEnd('\')
  if ($FolderPath -eq '') { return $true }
  try {
    $svc = New-Object -ComObject 'Schedule.Service'
    $svc.Connect()
    # ITaskFolder::CreateFolder builds the entire folder tree in one call when
    # given a multi-level path, so no segment-by-segment loop is needed. Guard
    # with GetFolder first to stay idempotent when the folder already exists.
    try { $svc.GetFolder($FolderPath) | Out-Null }
    catch { $svc.GetFolder('\').CreateFolder($FolderPath, $null) | Out-Null }
  } catch {
    Emit-Err 'unknown' ('Folder creation failed: ' + $_.Exception.Message) @{ path = $FolderPath }
    return $false
  }
  return $true
}

function Remove-EmptyFolder([string]$FolderPath) {
  if ($FolderPath -eq '\') { return }
  try {
    $svc = New-Object -ComObject 'Schedule.Service'
    $svc.Connect()
    $folder = $null
    try { $folder = $svc.GetFolder($FolderPath.TrimEnd('\')) } catch { return }
    if ($null -eq $folder) { return }
    $tasks   = $folder.GetTasks(1)
    $subdirs = $folder.GetFolders(1)
    if ($tasks.Count -eq 0 -and $subdirs.Count -eq 0) {
      $parentPath = $FolderPath.TrimEnd('\')
      $lastSep = $parentPath.LastIndexOf('\')
      if ($lastSep -le 0) { return }
      $parent = $svc.GetFolder($parentPath.Substring(0, $lastSep))
      $segName = $parentPath.Substring($lastSep + 1)
      $parent.DeleteFolder($segName, 0) | Out-Null
    }
  } catch {}
}
`

// ---------------------------------------------------------------------------
// JSON envelope structs
// ---------------------------------------------------------------------------

// stPSResponse is the parsed JSON envelope for scheduled task operations.
// It aliases the shared Envelope type so every resource parses the same
// shape through runEnvelope (#198).
type stPSResponse = Envelope

type stTaskPayload struct {
	Name           string              `json:"name"`
	Path           string              `json:"path"`
	Description    string              `json:"description"`
	Enabled        bool                `json:"enabled"`
	State          string              `json:"state"`
	LastRunTime    string              `json:"last_run_time"`
	LastTaskResult int64               `json:"last_task_result"`
	NextRunTime    string              `json:"next_run_time"`
	Principal      *stPrincipalPayload `json:"principal"`
	Actions        []stActionPayload   `json:"actions"`
	Triggers       []stTriggerPayload  `json:"triggers"`
	Settings       *stSettingsPayload  `json:"settings"`
}

type stPrincipalPayload struct {
	UserID    string `json:"user_id"`
	LogonType string `json:"logon_type"`
	RunLevel  string `json:"run_level"`
}

type stActionPayload struct {
	Execute          string `json:"execute"`
	Arguments        string `json:"arguments"`
	WorkingDirectory string `json:"working_directory"`
}

type stTriggerPayload struct {
	Type               string   `json:"type"`
	Enabled            bool     `json:"enabled"`
	StartBoundary      string   `json:"start_boundary"`
	EndBoundary        string   `json:"end_boundary"`
	ExecutionTimeLimit string   `json:"execution_time_limit"`
	Delay              string   `json:"delay"`
	DaysInterval       int64    `json:"days_interval"`
	DaysOfWeek         []string `json:"days_of_week"`
	WeeksInterval      int64    `json:"weeks_interval"`
	UserID             string   `json:"user_id"`
	Subscription       string   `json:"subscription"`
}

type stSettingsPayload struct {
	AllowDemandStart           bool   `json:"allow_demand_start"`
	AllowHardTerminate         bool   `json:"allow_hard_terminate"`
	StartWhenAvailable         bool   `json:"start_when_available"`
	RunOnlyIfNetworkAvailable  bool   `json:"run_only_if_network_available"`
	ExecutionTimeLimit         string `json:"execution_time_limit"`
	MultipleInstances          string `json:"multiple_instances"`
	DisallowStartIfOnBatteries bool   `json:"disallow_start_if_on_batteries"`
	StopIfGoingOnBatteries     bool   `json:"stop_if_going_on_batteries"`
	WakeToRun                  bool   `json:"wake_to_run"`
	RunOnlyIfIdle              bool   `json:"run_only_if_idle"`
}

// ---------------------------------------------------------------------------
// PS execution hook + envelope runner
// ---------------------------------------------------------------------------

// runSTPS is the execution hook, replaceable in tests.
var runSTPS = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// runSTPSInput is the stdin-aware sibling of runSTPS, used for principal.password
// injection. Tests can override it independently of runSTPS.
var runSTPSInput = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	return c.RunPowerShellWithInput(ctx, script, stdin)
}

func (c *ScheduledTaskClientImpl) runSTEnvelope(ctx context.Context, op, id, script string) (*stPSResponse, error) {
	baseContext := map[string]string{"op": op, "id": id, "host": c.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runSTPS(ctx, c.c, full)
		},
		op, psSTHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	return resp, mapSTEnvelopeError(eerr, op, id)
}

// runSTEnvelopeWithInput is the stdin-aware sibling of runSTEnvelope. It is used
// by Create / Update when principal.password is set, so that the plaintext is
// piped over stdin instead of embedded in the script body. The stdin value is
// NEVER copied into error context or logs.
func (c *ScheduledTaskClientImpl) runSTEnvelopeWithInput(ctx context.Context, op, id, script, stdin string) (*stPSResponse, error) {
	baseContext := map[string]string{"op": op, "id": id, "host": c.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runSTPSInput(ctx, c.c, full, stdin)
		},
		op, psSTHeader+"\n"+script, stdin, baseContext)
	if eerr == nil {
		return resp, nil
	}
	return resp, mapSTEnvelopeError(eerr, op, id)
}

// mapSTEnvelopeError converts a shared EnvelopeError into the historical
// *ScheduledTaskError for this resource, preserving the op/id context keys
// and the historical timeout / no-envelope / invalid-JSON messages.
func mapSTEnvelopeError(eerr *EnvelopeError, op, id string) error {
	switch eerr.Stage {
	case EnvelopeStageTimeout:
		eerr.Message = fmt.Sprintf("operation %q for %q timed out or was cancelled", op, id)
	case EnvelopeStageNoEnvelope:
		eerr.Message = fmt.Sprintf("no JSON envelope from %q", op)
	case EnvelopeStageInvalidJSON:
		eerr.Message = fmt.Sprintf("invalid JSON from %q", op)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return NewScheduledTaskError(ScheduledTaskErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return NewScheduledTaskError(mapSTKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

func mapSTKind(k string) ScheduledTaskErrorKind {
	switch ScheduledTaskErrorKind(k) {
	case ScheduledTaskErrorAlreadyExists,
		ScheduledTaskErrorNotFound,
		ScheduledTaskErrorBuiltinTask,
		ScheduledTaskErrorInvalidPath,
		ScheduledTaskErrorInvalidTrigger,
		ScheduledTaskErrorInvalidAction,
		ScheduledTaskErrorPasswordRequired,
		ScheduledTaskErrorPasswordForbidden,
		ScheduledTaskErrorPermissionDenied,
		ScheduledTaskErrorRunning,
		ScheduledTaskErrorInvalidInput:
		return ScheduledTaskErrorKind(k)
	}
	return ScheduledTaskErrorUnknown
}
