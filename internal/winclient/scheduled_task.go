// Package winclient: Windows Scheduled Task CRUD implementation over WinRM.
//
// ScheduledTaskClientImpl uses the ScheduledTasks PowerShell module for all
// task-level operations, and Schedule.Service COM for folder creation/pruning.
// OnEvent triggers are injected via raw task XML (ADR-ST-5).
//
// Security invariants:
//   - All user-supplied strings are passed through psQuote (single-quoted PS literals).
//   - Passwords are never logged or included in error context (ADR-ST-3).
//   - All scripts are transmitted via -EncodedCommand (UTF-16LE base64).
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion.
var _ ScheduledTaskClient = (*ScheduledTaskClientImpl)(nil)

// ScheduledTaskClientImpl is the PowerShell/WinRM-backed ScheduledTaskClient.
type ScheduledTaskClientImpl struct {
	c *Client
}

// NewScheduledTaskClient constructs a ScheduledTaskClientImpl.
func NewScheduledTaskClient(c *Client) *ScheduledTaskClientImpl {
	return &ScheduledTaskClientImpl{c: c}
}

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
  if ($FolderPath -eq '\') { return }
  try {
    $svc = New-Object -ComObject 'Schedule.Service'
    $svc.Connect()
    $segments = ($FolderPath.Trim('\') -split '\\') | Where-Object { $_ -ne '' }
    $curPath = ''
    foreach ($seg in $segments) {
      $curPath = $curPath + '\' + $seg
      $folder = $null
      try { $folder = $svc.GetFolder($curPath) } catch {}
      if ($null -eq $folder) {
        $parentPath = if ($curPath.IndexOf('\', 1) -lt 0) { '\' } else { $curPath.Substring(0, $curPath.LastIndexOf('\')) }
        $parent = $svc.GetFolder($parentPath)
        $parent.CreateSubFolder($seg, '') | Out-Null
      }
    }
  } catch {
    Emit-Err 'unknown' ('Folder creation failed: ' + $_.Exception.Message) @{ path = $FolderPath }
    exit 0
  }
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

type stPSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

type stTaskPayload struct {
	Name           string             `json:"name"`
	Path           string             `json:"path"`
	Description    string             `json:"description"`
	Enabled        bool               `json:"enabled"`
	State          string             `json:"state"`
	LastRunTime    string             `json:"last_run_time"`
	LastTaskResult int64              `json:"last_task_result"`
	NextRunTime    string             `json:"next_run_time"`
	Principal      *stPrincipalPayload `json:"principal"`
	Actions        []stActionPayload  `json:"actions"`
	Triggers       []stTriggerPayload `json:"triggers"`
	Settings       *stSettingsPayload `json:"settings"`
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

func (c *ScheduledTaskClientImpl) runSTEnvelope(ctx context.Context, op, id, script string) (*stPSResponse, error) {
	full := psSTHeader + "\n" + script
	stdout, stderr, err := runSTPS(ctx, c.c, full)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown,
				fmt.Sprintf("operation %q for %q timed out or was cancelled", op, id),
				ctx.Err(),
				map[string]string{"op": op, "id": id, "host": c.c.cfg.Host})
		}
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown,
			fmt.Sprintf("transport error during %q", op),
			err,
			map[string]string{"op": op, "id": id, "host": c.c.cfg.Host,
				"stderr": truncate(stderr, 2048), "stdout": truncate(stdout, 2048)})
	}
	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown,
			fmt.Sprintf("no JSON envelope from %q", op), nil,
			map[string]string{"op": op, "id": id,
				"stderr": truncate(stderr, 2048), "stdout": truncate(stdout, 2048)})
	}
	var resp stPSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown,
			fmt.Sprintf("invalid JSON from %q", op), jerr,
			map[string]string{"op": op, "id": id, "stdout": truncate(stdout, 2048)})
	}
	if !resp.OK {
		kind := mapSTKind(resp.Kind)
		ctx2 := resp.Context
		if ctx2 == nil {
			ctx2 = map[string]string{}
		}
		ctx2["op"] = op
		ctx2["id"] = id
		ctx2["host"] = c.c.cfg.Host
		return &resp, NewScheduledTaskError(kind, resp.Message, nil, ctx2)
	}
	return &resp, nil
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
		ScheduledTaskErrorRunning:
		return ScheduledTaskErrorKind(k)
	}
	return ScheduledTaskErrorUnknown
}

// ---------------------------------------------------------------------------
// payloadToState
// ---------------------------------------------------------------------------

func stPayloadToState(p *stTaskPayload) *ScheduledTaskState {
	if p == nil {
		return nil
	}
	s := &ScheduledTaskState{
		Name:           p.Name,
		Path:           p.Path,
		Description:    p.Description,
		Enabled:        p.Enabled,
		State:          p.State,
		LastRunTime:    p.LastRunTime,
		LastTaskResult: p.LastTaskResult,
		NextRunTime:    p.NextRunTime,
	}
	if p.Principal != nil {
		s.Principal = &ScheduledTaskPrincipalState{
			UserID:    p.Principal.UserID,
			LogonType: p.Principal.LogonType,
			RunLevel:  p.Principal.RunLevel,
		}
	}
	s.Actions = make([]ScheduledTaskActionState, len(p.Actions))
	for i, a := range p.Actions {
		s.Actions[i] = ScheduledTaskActionState{
			Execute:          a.Execute,
			Arguments:        a.Arguments,
			WorkingDirectory: a.WorkingDirectory,
		}
	}
	s.Triggers = make([]ScheduledTaskTriggerState, len(p.Triggers))
	for i, t := range p.Triggers {
		dow := t.DaysOfWeek
		if dow == nil {
			dow = []string{}
		}
		s.Triggers[i] = ScheduledTaskTriggerState{
			Type:               t.Type,
			Enabled:            t.Enabled,
			StartBoundary:      t.StartBoundary,
			EndBoundary:        t.EndBoundary,
			ExecutionTimeLimit: t.ExecutionTimeLimit,
			Delay:              t.Delay,
			DaysInterval:       t.DaysInterval,
			DaysOfWeek:         dow,
			WeeksInterval:      t.WeeksInterval,
			UserID:             t.UserID,
			Subscription:       t.Subscription,
		}
	}
	if p.Settings != nil {
		s.Settings = &ScheduledTaskSettingsState{
			AllowDemandStart:           p.Settings.AllowDemandStart,
			AllowHardTerminate:         p.Settings.AllowHardTerminate,
			StartWhenAvailable:         p.Settings.StartWhenAvailable,
			RunOnlyIfNetworkAvailable:  p.Settings.RunOnlyIfNetworkAvailable,
			ExecutionTimeLimit:         p.Settings.ExecutionTimeLimit,
			MultipleInstances:          p.Settings.MultipleInstances,
			DisallowStartIfOnBatteries: p.Settings.DisallowStartIfOnBatteries,
			StopIfGoingOnBatteries:     p.Settings.StopIfGoingOnBatteries,
			WakeToRun:                  p.Settings.WakeToRun,
			RunOnlyIfIdle:              p.Settings.RunOnlyIfIdle,
		}
	}
	return s
}

// ---------------------------------------------------------------------------
// Script-building helpers
// ---------------------------------------------------------------------------

// splitTaskID splits composite ID "<TaskPath><TaskName>" into parts.
func splitTaskID(id string) (taskPath, taskName string) {
	idx := strings.LastIndex(id, "\\")
	if idx < 0 {
		return "\\", id
	}
	return id[:idx+1], id[idx+1:]
}

// buildActionsFragment returns a PS fragment that populates $_stActions.
func buildActionsFragment(actions []ScheduledTaskActionInput) string {
	var sb strings.Builder
	sb.WriteString("$_stActions = @()\n")
	for i, a := range actions {
		vn := fmt.Sprintf("$_stAct%d", i)
		line := fmt.Sprintf("%s = New-ScheduledTaskAction -Execute %s", vn, psQuote(a.Execute))
		if a.Arguments != "" {
			line += fmt.Sprintf(" -Argument %s", psQuote(a.Arguments))
		}
		if a.WorkingDirectory != "" {
			line += fmt.Sprintf(" -WorkingDirectory %s", psQuote(a.WorkingDirectory))
		}
		sb.WriteString(line + "\n")
		sb.WriteString(fmt.Sprintf("$_stActions += %s\n", vn))
	}
	return sb.String()
}

// buildTriggersFragment returns a PS fragment for $_stTriggers (non-OnEvent only).
func buildTriggersFragment(triggers []ScheduledTaskTriggerInput) string {
	var sb strings.Builder
	sb.WriteString("$_stTriggers = @()\n")
	idx := 0
	for _, t := range triggers {
		if t.Type == "OnEvent" {
			continue
		}
		vn := fmt.Sprintf("$_stTrg%d", idx)
		idx++
		var line string
		switch t.Type {
		case "Once":
			line = fmt.Sprintf("%s = New-ScheduledTaskTrigger -Once -At %s", vn, psQuote(t.StartBoundary))
		case "Daily":
			line = fmt.Sprintf("%s = New-ScheduledTaskTrigger -Daily -At %s", vn, psQuote(t.StartBoundary))
			if t.DaysInterval > 0 {
				line += fmt.Sprintf(" -DaysInterval %d", t.DaysInterval)
			}
		case "Weekly":
			dows := strings.Join(t.DaysOfWeek, ",")
			line = fmt.Sprintf("%s = New-ScheduledTaskTrigger -Weekly -At %s -DaysOfWeek %s", vn, psQuote(t.StartBoundary), dows)
			if t.WeeksInterval > 0 {
				line += fmt.Sprintf(" -WeeksInterval %d", t.WeeksInterval)
			}
		case "AtLogon":
			line = fmt.Sprintf("%s = New-ScheduledTaskTrigger -AtLogon", vn)
			if t.UserID != "" {
				line += fmt.Sprintf(" -User %s", psQuote(t.UserID))
			}
		case "AtStartup":
			line = fmt.Sprintf("%s = New-ScheduledTaskTrigger -AtStartup", vn)
		default:
			continue
		}
		sb.WriteString(line + "\n")
		// Set optional properties on the CIM instance
		enabled := true
		if t.Enabled != nil {
			enabled = *t.Enabled
		}
		if !enabled {
			sb.WriteString(fmt.Sprintf("try { %s.Enabled = $false } catch {}\n", vn))
		}
		if t.EndBoundary != "" {
			sb.WriteString(fmt.Sprintf("try { %s.EndBoundary = %s } catch {}\n", vn, psQuote(t.EndBoundary)))
		}
		if t.Delay != "" {
			sb.WriteString(fmt.Sprintf("try { %s.Delay = %s } catch {}\n", vn, psQuote(t.Delay)))
		}
		if t.ExecutionTimeLimit != "" {
			sb.WriteString(fmt.Sprintf("try { %s.ExecutionTimeLimit = %s } catch {}\n", vn, psQuote(t.ExecutionTimeLimit)))
		}
		sb.WriteString(fmt.Sprintf("$_stTriggers += %s\n", vn))
	}
	return sb.String()
}

// buildPrincipalFragment returns a PS fragment for $_stPrincipal.
func buildPrincipalFragment(p *ScheduledTaskPrincipalInput) string {
	if p == nil {
		return "$_stPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Limited\n"
	}
	userID := p.UserID
	if userID == "" {
		userID = "SYSTEM"
	}
	line := fmt.Sprintf("$_stPrincipal = New-ScheduledTaskPrincipal -UserId %s", psQuote(userID))
	if p.LogonType != "" {
		line += " -LogonType " + p.LogonType
	}
	if p.RunLevel != "" {
		line += " -RunLevel " + p.RunLevel
	}
	return line + "\n"
}

// buildSettingsFragment returns a PS fragment for $_stSettings.
func buildSettingsFragment(s *ScheduledTaskSettingsInput, enabled bool) string {
	if s == nil {
		return fmt.Sprintf("$_stSettings = New-ScheduledTaskSettingsSet\n$_stSettings.Enabled = $%s\n", psBool(enabled))
	}
	etl := s.ExecutionTimeLimit
	if etl == "" {
		etl = "PT72H"
	}
	mi := s.MultipleInstances
	if mi == "" {
		mi = "Queue"
	}
	line := fmt.Sprintf(
		"$_stSettings = New-ScheduledTaskSettingsSet"+
			" -AllowDemandStart:$%s"+
			" -AllowHardTerminate:$%s"+
			" -StartWhenAvailable:$%s"+
			" -RunOnlyIfNetworkAvailable:$%s"+
			" -ExecutionTimeLimit %s"+
			" -MultipleInstances %s"+
			" -DisallowStartIfOnBatteries:$%s"+
			" -StopIfGoingOnBatteries:$%s"+
			" -WakeToRun:$%s"+
			" -RunOnlyIfIdle:$%s\n",
		psBool(s.AllowDemandStart),
		psBool(s.AllowHardTerminate),
		psBool(s.StartWhenAvailable),
		psBool(s.RunOnlyIfNetworkAvailable),
		psQuote(etl),
		mi,
		psBool(s.DisallowStartIfOnBatteries),
		psBool(s.StopIfGoingOnBatteries),
		psBool(s.WakeToRun),
		psBool(s.RunOnlyIfIdle),
	)
	return line + fmt.Sprintf("$_stSettings.Enabled = $%s\n", psBool(enabled))
}

// buildOnEventFragment returns a PS fragment that injects OnEvent triggers via XML.
func buildOnEventFragment(taskName, taskPath string, triggers []ScheduledTaskTriggerInput) string {
	var sb strings.Builder
	// Build the PS array literal for the event triggers
	sb.WriteString("$_stEvtTriggers = @(\n")
	for _, t := range triggers {
		if t.Type != "OnEvent" {
			continue
		}
		enabled := true
		if t.Enabled != nil {
			enabled = *t.Enabled
		}
		sb.WriteString(fmt.Sprintf(
			"  [ordered]@{ enabled=$%s; subscription=%s; start_boundary=%s; end_boundary=%s; delay=%s; execution_time_limit=%s },\n",
			psBool(enabled),
			psQuote(t.Subscription),
			psQuote(t.StartBoundary),
			psQuote(t.EndBoundary),
			psQuote(t.Delay),
			psQuote(t.ExecutionTimeLimit),
		))
	}
	sb.WriteString(")\n")
	sb.WriteString(fmt.Sprintf(`
$_stXml = $null
try { $_stXml = Export-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop } catch {
  Emit-Err 'unknown' ('XML export failed: ' + $_.Exception.Message) @{}; exit 0
}
$_stDoc = [xml]$_stXml
$_stNs  = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
$_stTask = $_stDoc.DocumentElement
$_stTrigNode = $_stTask['Triggers', $_stNs]
if ($null -eq $_stTrigNode) {
  $_stTrigNode = $_stDoc.CreateElement('Triggers', $_stNs)
  $_stActNode  = $_stTask['Actions', $_stNs]
  if ($_stActNode) { $_stTask.InsertBefore($_stTrigNode, $_stActNode) | Out-Null }
  else             { $_stTask.AppendChild($_stTrigNode) | Out-Null }
}
foreach ($_stEt in $_stEvtTriggers) {
  $_stEtNode = $_stDoc.CreateElement('EventTrigger', $_stNs)
  $_stEnNode = $_stDoc.CreateElement('Enabled', $_stNs)
  $_stEnNode.InnerText = if ($_stEt.enabled) { 'true' } else { 'false' }
  $_stEtNode.AppendChild($_stEnNode) | Out-Null
  $_stSubNode = $_stDoc.CreateElement('Subscription', $_stNs)
  $_stSubNode.InnerText = $_stEt.subscription
  $_stEtNode.AppendChild($_stSubNode) | Out-Null
  if (-not [string]::IsNullOrEmpty($_stEt.start_boundary)) {
    $_stSbNode = $_stDoc.CreateElement('StartBoundary', $_stNs)
    $_stSbNode.InnerText = $_stEt.start_boundary
    $_stEtNode.AppendChild($_stSbNode) | Out-Null
  }
  if (-not [string]::IsNullOrEmpty($_stEt.end_boundary)) {
    $_stEbNode = $_stDoc.CreateElement('EndBoundary', $_stNs)
    $_stEbNode.InnerText = $_stEt.end_boundary
    $_stEtNode.AppendChild($_stEbNode) | Out-Null
  }
  if (-not [string]::IsNullOrEmpty($_stEt.delay)) {
    $_stDlNode = $_stDoc.CreateElement('Delay', $_stNs)
    $_stDlNode.InnerText = $_stEt.delay
    $_stEtNode.AppendChild($_stDlNode) | Out-Null
  }
  if (-not [string]::IsNullOrEmpty($_stEt.execution_time_limit)) {
    $_stEtlNode = $_stDoc.CreateElement('ExecutionTimeLimit', $_stNs)
    $_stEtlNode.InnerText = $_stEt.execution_time_limit
    $_stEtNode.AppendChild($_stEtlNode) | Out-Null
  }
  $_stTrigNode.AppendChild($_stEtNode) | Out-Null
}
$_stNewXml = $_stDoc.OuterXml
try { Register-ScheduledTask -Xml $_stNewXml -TaskName %s -TaskPath %s -Force -ErrorAction Stop | Out-Null } catch {
  Emit-Err 'unknown' ('XML re-register failed: ' + $_.Exception.Message) @{}; exit 0
}
`, psQuote(taskName), psQuote(taskPath), psQuote(taskName), psQuote(taskPath)))
	return sb.String()
}

// hasOnEventTrigger returns true if any trigger in the list is OnEvent.
func hasOnEventTrigger(triggers []ScheduledTaskTriggerInput) bool {
	for _, t := range triggers {
		if t.Type == "OnEvent" {
			return true
		}
	}
	return false
}

// hasNonEventTrigger returns true if any trigger is NOT OnEvent.
func hasNonEventTrigger(triggers []ScheduledTaskTriggerInput) bool {
	for _, t := range triggers {
		if t.Type != "OnEvent" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read implements ScheduledTaskClient.Read.
// Returns (nil, nil) when the task is not found (EC-9 drift signal).
func (c *ScheduledTaskClientImpl) Read(ctx context.Context, id string) (*ScheduledTaskState, error) {
	taskPath, taskName := splitTaskID(id)
	script := fmt.Sprintf("Read-TaskState %s %s\n", psQuote(taskName), psQuote(taskPath))
	resp, err := c.runSTEnvelope(ctx, "read", id, script)
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, nil
	}
	var payload stTaskPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown, "failed to parse read payload", jerr,
			map[string]string{"id": id})
	}
	return stPayloadToState(&payload), nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create implements ScheduledTaskClient.Create.
func (c *ScheduledTaskClientImpl) Create(ctx context.Context, input ScheduledTaskInput) (*ScheduledTaskState, error) {
	id := input.Path + input.Name

	// Builtin guard (ADR-ST-6 / EC-13)
	if strings.HasPrefix(strings.ToLower(input.Path), `\microsoft\windows\`) {
		return nil, NewScheduledTaskError(ScheduledTaskErrorBuiltinTask,
			fmt.Sprintf("cannot create task in protected path %q (ADR-ST-6)", input.Path), nil,
			map[string]string{"path": input.Path})
	}

	var sb strings.Builder

	// Pre-flight: existing task check (EC-1)
	sb.WriteString(fmt.Sprintf(`
$_stExisting = $null
try { $_stExisting = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop } catch {}
if ($null -ne $_stExisting) {
  Emit-Err 'already_exists' ('Task already exists: %s. Use terraform import to adopt it.') @{ task_name = %s; task_path = %s }
  exit 0
}
`, psQuote(input.Name), psQuote(input.Path),
		strings.ReplaceAll(id, "'", "''"),
		psQuote(input.Name), psQuote(input.Path)))

	// Folder creation (ADR-ST-1)
	sb.WriteString(fmt.Sprintf("Ensure-TaskFolder %s\n", psQuote(input.Path)))

	// Actions
	sb.WriteString(buildActionsFragment(input.Actions))

	// Triggers (non-OnEvent)
	sb.WriteString(buildTriggersFragment(input.Triggers))

	// Principal
	sb.WriteString(buildPrincipalFragment(input.Principal))

	// Settings
	sb.WriteString(buildSettingsFragment(input.Settings, input.Enabled))

	// Register-ScheduledTask
	sb.WriteString(fmt.Sprintf(`
$_stRegParams = @{
  TaskName    = %s
  TaskPath    = %s
  Action      = $_stActions
  Principal   = $_stPrincipal
  Settings    = $_stSettings
  ErrorAction = 'Stop'
}
if ($null -ne %s -and %s -ne '') { $_stRegParams['Description'] = %s }
`, psQuote(input.Name), psQuote(input.Path),
		psQuote(input.Description), psQuote(input.Description), psQuote(input.Description)))

	if input.Principal != nil && input.Principal.Password != nil {
		sb.WriteString(fmt.Sprintf("$_stRegParams['Password'] = %s\n", psQuote(*input.Principal.Password)))
	}

	if hasNonEventTrigger(input.Triggers) {
		sb.WriteString("$_stRegParams['Trigger'] = $_stTriggers\n")
	}

	sb.WriteString(`
try {
  Register-ScheduledTask @_stRegParams | Out-Null
} catch {
  $msg = $_.Exception.Message
  if ($msg -match 'Access is denied' -or $msg -match 'UnauthorizedAccess') { Emit-Err 'permission_denied' $msg @{ phase = 'register' }; exit 0 }
  if ($msg -match 'argument' -or $msg -match 'invalid' -or $msg -match 'parameter') { Emit-Err 'invalid_input' $msg @{ phase = 'register' }; exit 0 }
  Emit-Err 'unknown' $msg @{ phase = 'register' }; exit 0
}
`)

	// OnEvent XML injection (ADR-ST-5)
	if hasOnEventTrigger(input.Triggers) {
		sb.WriteString(buildOnEventFragment(input.Name, input.Path, input.Triggers))
	}

	// Read-back
	sb.WriteString(fmt.Sprintf("Read-TaskState %s %s\n", psQuote(input.Name), psQuote(input.Path)))

	resp, err := c.runSTEnvelope(ctx, "create", id, sb.String())
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown, "task not found after create", nil,
			map[string]string{"id": id})
	}
	var payload stTaskPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown, "failed to parse create payload", jerr,
			map[string]string{"id": id})
	}
	return stPayloadToState(&payload), nil
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update implements ScheduledTaskClient.Update.
func (c *ScheduledTaskClientImpl) Update(ctx context.Context, id string, input ScheduledTaskInput) (*ScheduledTaskState, error) {
	taskPath, taskName := splitTaskID(id)

	var sb strings.Builder

	// Actions
	sb.WriteString(buildActionsFragment(input.Actions))

	// Triggers (non-OnEvent)
	sb.WriteString(buildTriggersFragment(input.Triggers))

	// Principal
	sb.WriteString(buildPrincipalFragment(input.Principal))

	// Settings
	sb.WriteString(buildSettingsFragment(input.Settings, input.Enabled))

	// Set-ScheduledTask
	sb.WriteString(fmt.Sprintf(`
$_stSetParams = @{
  TaskName    = %s
  TaskPath    = %s
  Action      = $_stActions
  Principal   = $_stPrincipal
  Settings    = $_stSettings
  ErrorAction = 'Stop'
}
$_stSetParams['Description'] = %s
`, psQuote(taskName), psQuote(taskPath), psQuote(input.Description)))

	if input.Principal != nil && input.Principal.Password != nil {
		sb.WriteString(fmt.Sprintf("$_stSetParams['Password'] = %s\n", psQuote(*input.Principal.Password)))
	}

	if hasNonEventTrigger(input.Triggers) {
		sb.WriteString("$_stSetParams['Trigger'] = $_stTriggers\n")
	}

	sb.WriteString(`
try {
  Set-ScheduledTask @_stSetParams | Out-Null
} catch {
  $msg = $_.Exception.Message
  if ($msg -match 'Access is denied' -or $msg -match 'UnauthorizedAccess') { Emit-Err 'permission_denied' $msg @{ phase = 'update' }; exit 0 }
  if ($msg -match 'argument' -or $msg -match 'invalid' -or $msg -match 'parameter') { Emit-Err 'invalid_input' $msg @{ phase = 'update' }; exit 0 }
  Emit-Err 'unknown' $msg @{ phase = 'update' }; exit 0
}
`)

	// OnEvent XML injection (ADR-ST-5)
	if hasOnEventTrigger(input.Triggers) {
		sb.WriteString(buildOnEventFragment(taskName, taskPath, input.Triggers))
	}

	// Read-back
	sb.WriteString(fmt.Sprintf("Read-TaskState %s %s\n", psQuote(taskName), psQuote(taskPath)))

	resp, err := c.runSTEnvelope(ctx, "update", id, sb.String())
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown, "task not found after update", nil,
			map[string]string{"id": id})
	}
	var payload stTaskPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown, "failed to parse update payload", jerr,
			map[string]string{"id": id})
	}
	return stPayloadToState(&payload), nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete implements ScheduledTaskClient.Delete.
func (c *ScheduledTaskClientImpl) Delete(ctx context.Context, id string) error {
	taskPath, taskName := splitTaskID(id)

	// Builtin guard (ADR-ST-6 / EC-13)
	if strings.HasPrefix(strings.ToLower(taskPath), `\microsoft\windows\`) {
		return NewScheduledTaskError(ScheduledTaskErrorBuiltinTask,
			fmt.Sprintf("cannot delete task in protected path %q (ADR-ST-6)", taskPath), nil,
			map[string]string{"path": taskPath})
	}

	script := fmt.Sprintf(`
# Check if task exists
$_stTask = $null
try { $_stTask = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop } catch {}
if ($null -eq $_stTask) { Emit-OK 'not_found'; exit 0 }

# Stop if running (ADR-ST-7)
$_stInfo = $null
try { $_stInfo = Get-ScheduledTaskInfo -TaskName %s -TaskPath %s -ErrorAction Stop } catch {}
if ($null -ne $_stInfo -and $_stInfo.LastTaskResult -eq 0x41301) {
  # 0x41301 = SCHED_S_TASK_RUNNING — use task State instead
}
$_stCurState = [int]$_stTask.State
if ($_stCurState -eq 4) {
  try { Stop-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop } catch {}
  $_stDeadline = (Get-Date).AddSeconds(30)
  while ((Get-Date) -lt $_stDeadline) {
    Start-Sleep -Seconds 2
    $_stTask = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop
    if ([int]$_stTask.State -ne 4) { break }
  }
  $_stTask = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop
  if ([int]$_stTask.State -eq 4) {
    Emit-Err 'task_running' 'Task is still running after 30s stop timeout (ADR-ST-7 / EC-14).' @{ task_name = %s; task_path = %s }
    exit 0
  }
}

# Unregister
try {
  Unregister-ScheduledTask -TaskName %s -TaskPath %s -Confirm:$false -ErrorAction Stop
} catch {
  $msg = $_.Exception.Message
  if ($msg -match 'Access is denied' -or $msg -match 'UnauthorizedAccess') { Emit-Err 'permission_denied' $msg @{}; exit 0 }
  Emit-Err 'unknown' $msg @{}; exit 0
}

# Prune empty folder (non-fatal)
Remove-EmptyFolder %s

Emit-OK 'deleted'
`,
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskPath),
	)

	_, err := c.runSTEnvelope(ctx, "delete", id, script)
	return err
}

// ---------------------------------------------------------------------------
// ImportByID
// ---------------------------------------------------------------------------

// ImportByID implements ScheduledTaskClient.ImportByID.
// Returns ScheduledTaskErrorNotFound if the task does not exist (EC-11).
func (c *ScheduledTaskClientImpl) ImportByID(ctx context.Context, id string) (*ScheduledTaskState, error) {
	taskPath, taskName := splitTaskID(id)
	script := fmt.Sprintf(`
$_stTask = $null
try { $_stTask = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop } catch {}
if ($null -eq $_stTask) {
  Emit-Err 'not_found' ('Task not found for import: %s') @{ task_name = %s; task_path = %s }
  exit 0
}
Read-TaskState %s %s
`,
		psQuote(taskName), psQuote(taskPath),
		strings.ReplaceAll(id, "'", "''"),
		psQuote(taskName), psQuote(taskPath),
		psQuote(taskName), psQuote(taskPath),
	)
	resp, err := c.runSTEnvelope(ctx, "import", id, script)
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, NewScheduledTaskError(ScheduledTaskErrorNotFound,
			fmt.Sprintf("task %q not found for import", id), nil,
			map[string]string{"id": id})
	}
	var payload stTaskPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewScheduledTaskError(ScheduledTaskErrorUnknown, "failed to parse import payload", jerr,
			map[string]string{"id": id})
	}
	return stPayloadToState(&payload), nil
}
