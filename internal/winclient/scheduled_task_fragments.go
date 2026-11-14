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
	"fmt"
	"strings"
	"time"
)

// State mapping and PowerShell fragment builders. Split from scheduled_task.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// payloadToState
// ---------------------------------------------------------------------------

// normalizeDT canonicalizes an RFC3339 datetime to UTC "...Z" form so that plan
// and post-apply state compare equal (e.g. "+00:00" -> "Z"). Get-ScheduledTask
// can report offsets as "+00:00"; Terraform requires strict plan<->apply string
// equality, so we re-emit the canonical form here (mirrors the PowerShell
// Format-DT helper). Empty or unparseable values are returned unchanged.
func normalizeDT(s string) string {
	if s == "" {
		return s
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

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
		LastRunTime:    normalizeDT(p.LastRunTime),
		LastTaskResult: p.LastTaskResult,
		NextRunTime:    normalizeDT(p.NextRunTime),
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
		s.Actions[i] = ScheduledTaskActionState(a)
	}
	s.Triggers = make([]ScheduledTaskTriggerState, len(p.Triggers))
	for i, t := range p.Triggers {
		dow := t.DaysOfWeek
		if dow == nil {
			dow = []string{}
		}
		s.Triggers[i] = ScheduledTaskTriggerState{
			Type:          t.Type,
			Enabled:       t.Enabled,
			StartBoundary: normalizeDT(t.StartBoundary),
			EndBoundary:   normalizeDT(t.EndBoundary),
			// Trigger execution_time_limit/delay are string-typed CIM
			// properties assigned verbatim on write and reported back
			// verbatim by Get-ScheduledTask, so the read path must not
			// rewrite them: the matching schema attributes are Optional-only
			// (not Computed), so Terraform requires planned == applied
			// exactly. See buildTriggersFragment.
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
			AllowDemandStart:          p.Settings.AllowDemandStart,
			AllowHardTerminate:        p.Settings.AllowHardTerminate,
			StartWhenAvailable:        p.Settings.StartWhenAvailable,
			RunOnlyIfNetworkAvailable: p.Settings.RunOnlyIfNetworkAvailable,
			// Verbatim, like the trigger durations: settings.execution_time_limit
			// is applied as a TimeSpan (see buildSettingsFragment) but
			// TaskSettings.ExecutionTimeLimit is a string property documented in
			// XSD form (PnYnMnDTnHnMnS, where PT0S means "run indefinitely"), so
			// Get-ScheduledTask reports the configured spelling back unchanged.
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
		fmt.Fprintf(&sb, "$_stActions += %s\n", vn)
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
			fmt.Fprintf(&sb, "try { %s.Enabled = $false } catch {}\n", vn)
		}
		if t.EndBoundary != "" {
			fmt.Fprintf(&sb, "try { %s.EndBoundary = %s } catch {}\n", vn, psQuote(t.EndBoundary))
		}
		if t.Delay != "" {
			fmt.Fprintf(&sb, "try { %s.Delay = %s } catch {}\n", vn, psQuote(t.Delay))
		}
		if t.ExecutionTimeLimit != "" {
			// MSFT_TaskTrigger.ExecutionTimeLimit is a string-typed CIM
			// property carrying an XSD duration (PnYnMnDTnHnMnS, per
			// Trigger.ExecutionTimeLimit docs), so the ISO value is
			// assigned verbatim — unlike SettingsSet, which takes a
			// TimeSpan and needs XmlConvert (see buildSettingsFragment).
			// The silent catch skips CIM trigger types that do not expose
			// the property; covered by TestBuildTriggersFragment tests.
			fmt.Fprintf(&sb, "try { %s.ExecutionTimeLimit = %s } catch {}\n", vn, psQuote(t.ExecutionTimeLimit))
		}
		fmt.Fprintf(&sb, "$_stTriggers += %s\n", vn)
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

func buildPasswordPrincipalParamsFragment(paramName string, p *ScheduledTaskPrincipalInput, includeRunLevel bool) string {
	userID := p.UserID
	if userID == "" {
		userID = "SYSTEM"
	}
	fragment := fmt.Sprintf("%s.Remove('Principal')\n%s['User'] = %s\n", paramName, paramName, psQuote(userID))
	if includeRunLevel {
		runLevel := p.RunLevel
		if runLevel == "" {
			runLevel = "Limited"
		}
		fragment += fmt.Sprintf("%s['RunLevel'] = %s\n", paramName, psQuote(runLevel))
	}
	return fragment
}

func buildTaskDescriptionUpdateFragment(taskName, taskPath, description string, principal *ScheduledTaskPrincipalInput) string {
	fragment := fmt.Sprintf(
		"  $_stDescTask = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop\n"+
			"  if ([string]$_stDescTask.Description -ne %s) {\n",
		psQuote(taskName), psQuote(taskPath), psQuote(description),
	)
	if principal != nil && principal.Password != nil {
		userID := principal.UserID
		if userID == "" {
			userID = "SYSTEM"
		}
		fragment += fmt.Sprintf(
			"    $_stDescXML = [xml](Export-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop)\n"+
				"    $_stRegInfo = $_stDescXML.Task.RegistrationInfo\n"+
				"    if ($null -eq $_stRegInfo) {\n"+
				"      $_stRegInfo = $_stDescXML.CreateElement('RegistrationInfo', $_stDescXML.DocumentElement.NamespaceURI)\n"+
				"      $null = $_stDescXML.Task.AppendChild($_stRegInfo)\n"+
				"    }\n"+
				"    $_stDescNode = $_stRegInfo.SelectSingleNode('./*[local-name()=\"Description\"]')\n"+
				"    if ($null -eq $_stDescNode) {\n"+
				"      $_stDescNode = $_stDescXML.CreateElement('Description', $_stDescXML.DocumentElement.NamespaceURI)\n"+
				"      $null = $_stRegInfo.AppendChild($_stDescNode)\n"+
				"    }\n"+
				"    $_stDescNode.InnerText = %s\n"+
				"    Register-ScheduledTask -TaskName %s -TaskPath %s -Xml $_stDescXML.OuterXml -User %s -Password $_stSetPassword -Force -ErrorAction Stop | Out-Null\n",
			psQuote(taskName), psQuote(taskPath), psQuote(description),
			psQuote(taskName), psQuote(taskPath), psQuote(userID),
		)
	} else {
		fragment += fmt.Sprintf(
			"    $_stDescTask.Description = %s\n"+
				"    Set-ScheduledTask -InputObject $_stDescTask -ErrorAction Stop | Out-Null\n",
			psQuote(description),
		)
	}
	return fragment + "  }\n"
}

// buildSettingsFragment returns a PS fragment for $_stSettings.
// New-ScheduledTaskSettingsSet -ExecutionTimeLimit takes a TimeSpan, so the
// ISO 8601 value is converted via XmlConvert (PT0S -> TimeSpan.Zero runs
// indefinitely).
// Both the conversion and the cmdlet call sit inside one guard: they run before
// the register try/catch further down the script, so a throw there would escape
// and surface as a bare "no JSON envelope" transport error instead of a
// classified invalid_input. The schema validator already rejects every value
// ToTimeSpan cannot convert, so this is defence in depth for direct winclient
// callers that bypass it.
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
	// mi is schema-allowlisted (Parallel|Queue|IgnoreNew|StopExisting) and
	// additionally psQuote-hardened as defense in depth.
	//
	// NOTE: the cmdlet parameter names differ from the CIM property names the
	// Read path reports (and the schema mirrors). New-ScheduledTaskSettingsSet
	// on PowerShell 5.1 exposes -DisallowDemandStart / -DisallowHardTerminate
	// (negative polarity), -AllowStartIfOnBatteries (negated vs the schema's
	// disallow_start_if_on_batteries) and -DontStopIfGoingOnBatteries (negated
	// vs stop_if_going_on_batteries). The Allow* spellings used here previously
	// do not exist and every task with a settings block failed to register
	// with "A parameter cannot be found that matches parameter name
	// 'AllowDemandStart'". Go-side negation keeps the schema (and Read output)
	// in the positive CIM polarity.
	line := fmt.Sprintf(
		"try {"+
			" $_stETL = [System.Xml.XmlConvert]::ToTimeSpan(%s)"+
			"; $_stSettings = New-ScheduledTaskSettingsSet"+
			" -DisallowDemandStart:$%s"+
			" -DisallowHardTerminate:$%s"+
			" -StartWhenAvailable:$%s"+
			" -RunOnlyIfNetworkAvailable:$%s"+
			" -ExecutionTimeLimit $_stETL"+
			" -MultipleInstances %s"+
			" -AllowStartIfOnBatteries:$%s"+
			" -DontStopIfGoingOnBatteries:$%s"+
			" -WakeToRun:$%s"+
			" -RunOnlyIfIdle:$%s"+
			" } catch { Emit-Err 'invalid_input' ('Invalid settings block: ' + $_.Exception.Message) @{}; return }\n",
		psQuote(etl),
		psBool(!s.AllowDemandStart),
		psBool(!s.AllowHardTerminate),
		psBool(s.StartWhenAvailable),
		psBool(s.RunOnlyIfNetworkAvailable),
		psQuote(mi),
		psBool(!s.DisallowStartIfOnBatteries),
		psBool(!s.StopIfGoingOnBatteries),
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
		fmt.Fprintf(&sb, "  [ordered]@{ enabled=$%s; subscription=%s; start_boundary=%s; end_boundary=%s; delay=%s; execution_time_limit=%s }\n",
			psBool(enabled),
			psQuote(t.Subscription),
			psQuote(t.StartBoundary),
			psQuote(t.EndBoundary),
			psQuote(t.Delay),
			psQuote(t.ExecutionTimeLimit))
	}
	sb.WriteString(")\n")
	fmt.Fprintf(&sb, `
$_stXml = $null
try { $_stXml = Export-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction Stop } catch {
  Emit-Err 'unknown' ('XML export failed: ' + $_.Exception.Message) @{}; return
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
  Emit-Err 'unknown' ('XML re-register failed: ' + $_.Exception.Message) @{}; return
}
`, psQuote(taskName), psQuote(taskPath), psQuote(taskName), psQuote(taskPath))
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
