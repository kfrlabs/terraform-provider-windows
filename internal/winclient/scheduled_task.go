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
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion.
var _ ScheduledTaskClient = (*ScheduledTaskClientImpl)(nil)

// ScheduledTaskClientImpl is the PowerShell/SSH-backed ScheduledTaskClient.
type ScheduledTaskClientImpl struct {
	c *Client
}

// NewScheduledTaskClient constructs a ScheduledTaskClientImpl.
func NewScheduledTaskClient(c *Client) *ScheduledTaskClientImpl {
	return &ScheduledTaskClientImpl{c: c}
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
	fmt.Fprintf(&sb, `
$_stExisting = $null
try { $_stExisting = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop } catch {}
if ($null -ne $_stExisting) {
  Emit-Err 'already_exists' ('Task already exists: ' + %s + '. Use terraform import to adopt it.') @{ task_name = %s; task_path = %s }
  return
}
`, psQuote(input.Name), psQuote(input.Path), psQuote(id), psQuote(input.Name), psQuote(input.Path))

	// Folder creation (ADR-ST-1)
	fmt.Fprintf(&sb, "if (-not (Ensure-TaskFolder %s)) { return }\n", psQuote(input.Path))

	// Actions
	sb.WriteString(buildActionsFragment(input.Actions))

	// Triggers (non-OnEvent)
	sb.WriteString(buildTriggersFragment(input.Triggers))

	// Principal
	sb.WriteString(buildPrincipalFragment(input.Principal))

	// Settings
	sb.WriteString(buildSettingsFragment(input.Settings, input.Enabled))

	// Register-ScheduledTask
	fmt.Fprintf(&sb, `
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
		psQuote(input.Description), psQuote(input.Description), psQuote(input.Description))

	if input.Principal != nil && input.Principal.Password != nil {
		// principal.password is read from stdin (never embedded in the script
		// body, see ADR-LU-3 / ADR-ST-3). The Go side dispatches via
		// runSTEnvelopeWithInput when this branch is taken. An empty stdin
		// read is rejected with an invalid_input diagnostic (phase=register)
		// rather than letting Register-ScheduledTask fail cryptically
		// ("Parameter set cannot be resolved", issue #101).
		sb.WriteString("$_stRegPassword = [Console]::In.ReadLine()\n")
		sb.WriteString("if ([string]::IsNullOrEmpty($_stRegPassword)) { Emit-Err 'invalid_input' 'Scheduled task password was empty on stdin while a Password principal was requested.' @{ phase = 'register' }; return }\n")
		// Register-ScheduledTask's -Principal parameter set does not accept
		// -Password. Password principals must use the -User/-Password parameter
		// set, with RunLevel passed separately; mixing Principal and Password
		// fails on Windows with "Parameter set cannot be resolved".
		sb.WriteString(buildPasswordPrincipalParamsFragment("$_stRegParams", input.Principal, true))
		sb.WriteString("$_stRegParams['Password'] = $_stRegPassword\n")
	}

	if hasNonEventTrigger(input.Triggers) {
		sb.WriteString("$_stRegParams['Trigger'] = $_stTriggers\n")
	}

	sb.WriteString(`
try {
  Register-ScheduledTask @_stRegParams | Out-Null
} catch {
  $msg = $_.Exception.Message
  if ($msg -match 'Access is denied' -or $msg -match 'UnauthorizedAccess') { Emit-Err 'permission_denied' $msg @{ phase = 'register' }; return }
  if ($msg -match 'argument' -or $msg -match 'invalid' -or $msg -match 'parameter') { Emit-Err 'invalid_input' $msg @{ phase = 'register' }; return }
  Emit-Err 'unknown' $msg @{ phase = 'register' }; return
}
`)

	// OnEvent XML injection (ADR-ST-5)
	if hasOnEventTrigger(input.Triggers) {
		sb.WriteString(buildOnEventFragment(input.Name, input.Path, input.Triggers))
	}

	// Read-back
	fmt.Fprintf(&sb, "Read-TaskState %s %s\n", psQuote(input.Name), psQuote(input.Path))

	var resp *stPSResponse
	var err error
	if input.Principal != nil && input.Principal.Password != nil {
		// Inject password via stdin — never present in the script body.
		resp, err = c.runSTEnvelopeWithInput(ctx, "create", id, sb.String(), *input.Principal.Password+"\n")
	} else {
		resp, err = c.runSTEnvelope(ctx, "create", id, sb.String())
	}
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

	// Set-ScheduledTask. Note the absence of Description here: unlike
	// Register-ScheduledTask (see Create), Set-ScheduledTask has no
	// -Description parameter, and passing one fails the whole update with
	// "A parameter cannot be found that matches parameter name 'Description'".
	// It is applied separately below, on the task object.
	fmt.Fprintf(&sb, `
$_stSetParams = @{
  TaskName    = %s
  TaskPath    = %s
  Action      = $_stActions
  Principal   = $_stPrincipal
  Settings    = $_stSettings
  ErrorAction = 'Stop'
}
`, psQuote(taskName), psQuote(taskPath))

	if input.Principal != nil && input.Principal.Password != nil {
		// principal.password is read from stdin (see Create for rationale).
		// An empty stdin read is rejected with an invalid_input diagnostic
		// (phase=update) rather than letting Set-ScheduledTask fail
		// cryptically (issue #101).
		sb.WriteString("$_stSetPassword = [Console]::In.ReadLine()\n")
		sb.WriteString("if ([string]::IsNullOrEmpty($_stSetPassword)) { Emit-Err 'invalid_input' 'Scheduled task password was empty on stdin while a Password principal was requested.' @{ phase = 'update' }; return }\n")
		// Set-ScheduledTask has a separate -User/-Password parameter set too;
		// it cannot be combined with -Principal.
		sb.WriteString(buildPasswordPrincipalParamsFragment("$_stSetParams", input.Principal, false))
		sb.WriteString("$_stSetParams['Password'] = $_stSetPassword\n")
	}

	if hasNonEventTrigger(input.Triggers) {
		sb.WriteString("$_stSetParams['Trigger'] = $_stTriggers\n")
	}

	// The description rides on the task object, not on the cmdlet. Applied
	// unconditionally rather than only when non-empty: removing description
	// from the configuration has to clear it on the host too, and an empty
	// string is how that is expressed. Inside the same try so a failure is
	// classified like any other update failure.
	sb.WriteString(`
try {
  $_stUpdatePhase = 'set'
  Set-ScheduledTask @_stSetParams | Out-Null
  $_stUpdatePhase = 'description'
`)
	sb.WriteString(buildTaskDescriptionUpdateFragment(taskName, taskPath, input.Description, input.Principal))
	sb.WriteString(`
} catch {
  $msg = $_.Exception.Message
  $phase = if ([string]::IsNullOrEmpty($_stUpdatePhase)) { 'update' } else { $_stUpdatePhase }
  $detail = $msg + ' (phase=' + $phase + ', user=' + [string]$_stSetParams['User'] + ')'
  if ($msg -match 'Access is denied' -or $msg -match 'UnauthorizedAccess') { Emit-Err 'permission_denied' $detail @{ phase = $phase }; return }
  if ($msg -match 'argument' -or $msg -match 'invalid' -or $msg -match 'parameter') { Emit-Err 'invalid_input' $detail @{ phase = $phase }; return }
  Emit-Err 'unknown' $detail @{ phase = $phase }; return
}
`)

	// OnEvent XML injection (ADR-ST-5)
	if hasOnEventTrigger(input.Triggers) {
		sb.WriteString(buildOnEventFragment(taskName, taskPath, input.Triggers))
	}

	// Read-back
	fmt.Fprintf(&sb, "Read-TaskState %s %s\n", psQuote(taskName), psQuote(taskPath))

	var resp *stPSResponse
	var err error
	if input.Principal != nil && input.Principal.Password != nil {
		// Inject password via stdin — never present in the script body.
		resp, err = c.runSTEnvelopeWithInput(ctx, "update", id, sb.String(), *input.Principal.Password+"\n")
	} else {
		resp, err = c.runSTEnvelope(ctx, "update", id, sb.String())
	}
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
if ($null -eq $_stTask) { Emit-OK 'not_found'; return }

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
    return
  }
}

# Unregister
try {
  Unregister-ScheduledTask -TaskName %s -TaskPath %s -Confirm:$false -ErrorAction Stop
} catch {
  $msg = $_.Exception.Message
  if ($msg -match 'Access is denied' -or $msg -match 'UnauthorizedAccess') { Emit-Err 'permission_denied' $msg @{}; return }
  Emit-Err 'unknown' $msg @{}; return
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
  Emit-Err 'not_found' ('Task not found for import: ' + %s) @{ task_name = %s; task_path = %s }
  return
}
Read-TaskState %s %s
`,
		psQuote(taskName), psQuote(taskPath),
		psQuote(id),
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
