// Package winclient: Windows service CRUD implementation over WinRM.
//
// This file provides ServiceClient, the concrete WindowsServiceClient used by
// the Terraform provider. All operations are executed as PowerShell scripts
// wrapped in a JSON envelope so stdout is machine-parseable regardless of the
// Windows locale (see psHeader below).
//
// Security invariants:
//   - service_password is interpolated only through psQuote (single-quoted
//     PowerShell literal with embedded "''" escape). It is NEVER concatenated
//     raw into scripts and NEVER logged or copied into ServiceError.
//   - All scripts are rendered as UTF-16LE / base64 via the underlying Client
//     (-EncodedCommand); no shell metacharacters ever reach cmd.exe.
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Compile-time assertion: ServiceClient satisfies WindowsServiceClient.
var _ WindowsServiceClient = (*ServiceClient)(nil)

// ServiceClient is the PowerShell/WinRM-backed WindowsServiceClient.
type ServiceClient struct {
	c *Client
}

// NewServiceClient constructs a ServiceClient wrapping the given WinRM Client.
func NewServiceClient(c *Client) *ServiceClient { return &ServiceClient{c: c} }

// -----------------------------------------------------------------------------
// PowerShell helpers — safe quoting and JSON envelope
// -----------------------------------------------------------------------------

// psQuote returns s wrapped as a single-quoted PowerShell string literal, with
// embedded single quotes doubled. No PowerShell expansion occurs inside single
// quotes, which prevents $var, backtick, and subexpression injection.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// psQuoteList renders a []string as a PowerShell string array literal.
// Example: []string{"A", "B"} -> "@('A','B')". An empty slice renders as "@()".
func psQuoteList(items []string) string {
	if len(items) == 0 {
		return "@()"
	}
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = psQuote(it)
	}
	return "@(" + strings.Join(parts, ",") + ")"
}

// psHeader is prepended to every script. It defines:
//
//   - Emit-OK  / Emit-Err : JSON envelope emitters. The provider parses the
//     single JSON line written to stdout.
//   - Classify            : maps Win32 error codes (5/87/1056/1058/1060/1062)
//     to ServiceErrorKind strings for robust, locale-independent error
//     handling (SS12).
const psHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Classify([string]$Msg) {
  if ($Msg -match '\b1060\b')                        { return 'not_found' }
  if ($Msg -match '\b5\b.*[Dd]enied' -or $Msg -match '[Aa]ccess is denied') { return 'permission_denied' }
  if ($Msg -match '\b87\b')                          { return 'invalid_parameter' }
  if ($Msg -match '\b1056\b')                        { return 'already_running' }
  if ($Msg -match '\b1058\b')                        { return 'disabled' }
  if ($Msg -match '\b1062\b')                        { return 'not_running' }
  return 'unknown'
}
`

// runPowerShell is the hook used by ServiceClient to execute PowerShell
// scripts on the remote host. It is a package-level variable so tests can
// substitute a deterministic, in-memory fake for the real WinRM transport
// (see service_client_impl_test.go). Production code must not reassign this
// outside tests.
var runPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// psResponse is the unmarshalled JSON envelope produced by Emit-OK/Emit-Err.
type psResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// runEnvelope executes script (prefixed with psHeader) and returns the parsed
// envelope. Transport / PS-level errors that bypass Emit-Err (non-zero exit,
// context cancellation) are translated into *ServiceError with Kind=unknown or
// Kind=timeout as appropriate.
func (s *ServiceClient) runEnvelope(ctx context.Context, op, name, script string) (*psResponse, error) {
	full := psHeader + "\n" + script
	stdout, stderr, err := runPowerShell(ctx, s.c, full)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, NewServiceError(ServiceErrorTimeout,
				fmt.Sprintf("operation %q timed out or was cancelled", op),
				ctxErr, map[string]string{
					"operation": op, "name": name, "host": s.c.cfg.Host,
				})
		}
		return nil, NewServiceError(ServiceErrorUnknown,
			fmt.Sprintf("powershell transport error during %q", op),
			err, map[string]string{
				"operation": op, "name": name, "host": s.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewServiceError(ServiceErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op), nil,
			map[string]string{
				"operation": op, "name": name, "host": s.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}
	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewServiceError(ServiceErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op), jerr,
			map[string]string{
				"operation": op, "name": name, "host": s.c.cfg.Host,
				"stdout": truncate(stdout, 2048),
			})
	}
	if !resp.OK {
		kind := mapKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["name"] = name
		ctxMap["host"] = s.c.cfg.Host
		return &resp, NewServiceError(kind, resp.Message, nil, ctxMap)
	}
	return &resp, nil
}

// extractLastJSONLine scans stdout and returns the last line that starts with
// '{' — the JSON envelope produced by Emit-OK/Emit-Err. Any preceding PS
// warning lines are ignored.
func extractLastJSONLine(stdout string) string {
	lines := strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		trim := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trim, "{") {
			return trim
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}

// mapKind translates a PS-side "kind" string to a typed ServiceErrorKind.
func mapKind(k string) ServiceErrorKind {
	switch k {
	case string(ServiceErrorNotFound),
		string(ServiceErrorAlreadyExists),
		string(ServiceErrorPermission),
		string(ServiceErrorTimeout),
		string(ServiceErrorInvalidParameter),
		string(ServiceErrorRunning),
		string(ServiceErrorNotRunning),
		string(ServiceErrorDisabled):
		return ServiceErrorKind(k)
	default:
		return ServiceErrorUnknown
	}
}

// -----------------------------------------------------------------------------
// Read-state PowerShell snippet
// -----------------------------------------------------------------------------

// psReadStateBody produces a PowerShell fragment that reads the service state
// for $Name, normalises .\ into HOSTNAME\ and LocalSystem / NT AUTHORITY\SYSTEM,
// and emits it via Emit-OK. If the service does not exist, it emits
// ok=true / data=null so the caller can surface ErrServiceNotFound.
const psReadStateBody = `
function Read-ServiceState([string]$Name) {
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if (-not $svc) { return $null }

  # sc.exe qc
  $qcRaw  = & sc.exe qc $Name 2>&1 | Out-String
  $qcCode = $LASTEXITCODE
  if ($qcCode -ne 0) {
    if ($qcRaw -match '\b1060\b') { return $null }
    throw "sc.exe qc failed (exit=$qcCode): $qcRaw"
  }

  # sc.exe qdescription (non-fatal on failure)
  $descRaw  = & sc.exe qdescription $Name 2>&1 | Out-String
  $descCode = $LASTEXITCODE

  # Parse qc
  $binary     = ''
  $startType  = 'Automatic'
  $account    = 'LocalSystem'
  $deps       = New-Object System.Collections.Generic.List[string]
  $inDeps     = $false

  foreach ($raw in ($qcRaw -split [char]10)) {
    $line = $raw.TrimEnd()
    if ($line -match '^\s*BINARY_PATH_NAME\s*:\s*(.*)$')  { $binary = $Matches[1].Trim(); $inDeps=$false; continue }
    if ($line -match '^\s*START_TYPE\s*:\s*(.*)$') {
      $st = $Matches[1].Trim()
      if ($st -match 'DELAYED')           { $startType = 'AutomaticDelayedStart' }
      elseif ($st -match 'AUTO_START')    { $startType = 'Automatic' }
      elseif ($st -match 'DEMAND_START')  { $startType = 'Manual' }
      elseif ($st -match 'DISABLED')      { $startType = 'Disabled' }
      $inDeps=$false; continue
    }
    if ($line -match '^\s*SERVICE_START_NAME\s*:\s*(.*)$') { $account = $Matches[1].Trim(); $inDeps=$false; continue }
    if ($line -match '^\s*DEPENDENCIES\s*:\s*(.*)$') {
      $inDeps = $true
      $rest = $Matches[1].Trim()
      if ($rest) { $deps.Add($rest) | Out-Null }
      continue
    }
    if ($inDeps) {
      # subsequent DEPENDENCIES entries are indented; a new key resets
      if ($line -match '^\s*[A-Z_]+\s*:') { $inDeps = $false; continue }
      $v = $line.Trim()
      if ($v) { $deps.Add($v) | Out-Null }
    }
  }

  # Parse description (skip header line “[SC] QueryServiceConfig2 SUCCESS”)
  $description = ''
  if ($descCode -eq 0) {
    foreach ($raw in ($descRaw -split [char]10)) {
      $line = $raw.TrimEnd()
      if ($line -match '^\s*DESCRIPTION\s*:\s*(.*)$') { $description = $Matches[1].Trim(); break }
    }
  }

  # Map Get-Service status enum -> provider values
  $statusName = [string]$svc.Status
  switch ($statusName) {
    'Running'       { $current = 'Running' }
    'Stopped'       { $current = 'Stopped' }
    'Paused'        { $current = 'Paused' }
    'StartPending'  { $current = 'Stopped' }
    'StopPending'   { $current = 'Running' }
    'PausePending'  { $current = 'Running' }
    'ContinuePending'{ $current = 'Paused' }
    default         { $current = 'Stopped' }
  }

  return [ordered]@{
    name            = $svc.Name
    display_name    = $svc.DisplayName
    description     = $description
    binary_path     = $binary
    start_type      = $startType
    current_status  = $current
    service_account = $account
    dependencies    = @($deps)
    hostname        = $env:COMPUTERNAME
  }
}
`

// stateData mirrors the shape produced by Read-ServiceState (psReadStateBody).
type stateData struct {
	Name           string   `json:"name"`
	DisplayName    string   `json:"display_name"`
	Description    string   `json:"description"`
	BinaryPath     string   `json:"binary_path"`
	StartType      string   `json:"start_type"`
	CurrentStatus  string   `json:"current_status"`
	ServiceAccount string   `json:"service_account"`
	Dependencies   []string `json:"dependencies"`
	Hostname       string   `json:"hostname"`
}

// quoteOuterRe strips symmetric outer double-quotes from binary paths (EC-14).
var quoteOuterRe = regexp.MustCompile(`^"(.*)"$`)

// normaliseState applies EC-14 (outer quote strip) and SS10 (service_account
// normalisation) on a raw stateData, producing a canonical *ServiceState.
func normaliseState(d *stateData) *ServiceState {
	if d == nil {
		return nil
	}
	bin := d.BinaryPath
	if m := quoteOuterRe.FindStringSubmatch(bin); m != nil {
		bin = m[1]
	}
	account := strings.TrimSpace(d.ServiceAccount)
	switch {
	case strings.EqualFold(account, "NT AUTHORITY\\SYSTEM"), strings.EqualFold(account, "LocalSystem"):
		account = "LocalSystem"
	case strings.HasPrefix(account, ".\\") && d.Hostname != "":
		account = d.Hostname + "\\" + strings.TrimPrefix(account, ".\\")
	}
	deps := d.Dependencies
	if deps == nil {
		deps = []string{}
	}
	return &ServiceState{
		Name:           d.Name,
		DisplayName:    d.DisplayName,
		Description:    d.Description,
		BinaryPath:     bin,
		StartType:      d.StartType,
		CurrentStatus:  d.CurrentStatus,
		ServiceAccount: account,
		Dependencies:   deps,
	}
}

// -----------------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------------

// Create registers a new Windows service. EC-1: fails with AlreadyExists if a
// service with the same name is already registered.
func (s *ServiceClient) Create(ctx context.Context, input ServiceInput) (*ServiceState, error) {
	if input.Name == "" {
		return nil, NewServiceError(ServiceErrorInvalidParameter, "Name is required", nil, nil)
	}
	if input.BinaryPath == "" {
		return nil, NewServiceError(ServiceErrorInvalidParameter, "BinaryPath is required", nil, nil)
	}

	startType := input.StartType
	if startType == "" {
		startType = "Automatic"
	}
	// New-Service only accepts Automatic / Manual / Disabled; DelayedStart is
	// applied via sc.exe post-create (ADR SS3).
	newSvcStart := startType
	if newSvcStart == "AutomaticDelayedStart" {
		newSvcStart = "Automatic"
	}

	display := input.DisplayName
	if display == "" {
		display = input.Name
	}

	script := psReadStateBody + `
try {
  $name    = ` + psQuote(input.Name) + `
  $binary  = ` + psQuote(input.BinaryPath) + `
  $display = ` + psQuote(display) + `
  $desc    = ` + psQuote(input.Description) + `
  $stype   = ` + psQuote(newSvcStart) + `
  $finalStart = ` + psQuote(startType) + `
  $account = ` + psQuote(input.ServiceAccount) + `
  $password = ` + psQuote(input.ServicePassword) + `
  $deps     = ` + psQuoteList(input.Dependencies) + `

  # EC-1 pre-existence check
  $existing = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($existing) { Emit-Err 'already_exists' "service '$name' already exists" @{}; return }

  $args = @{ Name = $name; BinaryPathName = $binary; StartupType = $stype; DisplayName = $display }
  if ($desc) { $args['Description'] = $desc }
  if ($account -and $password) {
    $sec  = ConvertTo-SecureString $password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($account, $sec)
    $args['Credential'] = $cred
  } elseif ($account) {
    # Built-in account (LocalSystem / NT AUTHORITY\*): New-Service has no
    # -Credential-less account param; apply via sc.exe config obj=.
  }
  New-Service @args | Out-Null

  # Apply built-in account via sc.exe (no Credential) if needed
  if ($account -and -not $password) {
    $out = & sc.exe config $name obj= $account 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify $out) ("sc.exe config obj= failed: " + $out.Trim()) @{}; return }
  }

  # DelayedStart via sc.exe (ADR SS3)
  if ($finalStart -eq 'AutomaticDelayedStart') {
    $out = & sc.exe config $name start= delayed-auto 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify $out) ("sc.exe delayed-auto failed: " + $out.Trim()) @{}; return }
  }

  # Dependencies (always via sc.exe)
  if ($deps.Count -gt 0) {
    $depArg = ($deps -join '/')
    $out = & sc.exe config $name depend= $depArg 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify $out) ("sc.exe depend= failed: " + $out.Trim()) @{}; return }
  }

  $st = Read-ServiceState $name
  if (-not $st) { Emit-Err 'unknown' "service disappeared after create" @{}; return }
  Emit-OK $st
} catch {
  $msg  = $_.Exception.Message
  $kind = Classify $msg
  Emit-Err $kind $msg @{}
}
`

	resp, err := s.runEnvelope(ctx, "Create", input.Name, script)
	if err != nil {
		return nil, err
	}
	var data stateData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, NewServiceError(ServiceErrorUnknown, "invalid create state payload", jerr, nil)
	}
	state := normaliseState(&data)

	// Reconcile runtime state if DesiredStatus set.
	if input.DesiredStatus != "" {
		if err := s.reconcileStatus(ctx, input.Name, input.DesiredStatus); err != nil {
			return state, err
		}
		// Re-read to capture new current_status.
		ns, rerr := s.Read(ctx, input.Name)
		if rerr == nil && ns != nil {
			state = ns
		}
	}
	return state, nil
}

// -----------------------------------------------------------------------------
// Read (EC-2)
// -----------------------------------------------------------------------------

// Read returns the current state. (nil, nil) if the service does not exist.
func (s *ServiceClient) Read(ctx context.Context, name string) (*ServiceState, error) {
	if name == "" {
		return nil, NewServiceError(ServiceErrorInvalidParameter, "name is required", nil, nil)
	}
	script := psReadStateBody + `
try {
  $name = ` + psQuote(name) + `
  $st = Read-ServiceState $name
  if (-not $st) { Emit-OK $null; return }
  Emit-OK $st
} catch {
  $msg  = $_.Exception.Message
  $kind = Classify $msg
  Emit-Err $kind $msg @{}
}
`
	resp, err := s.runEnvelope(ctx, "Read", name, script)
	if err != nil {
		if errors.Is(err, ErrServiceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		return nil, nil
	}
	var d stateData
	if jerr := json.Unmarshal(resp.Data, &d); jerr != nil {
		return nil, NewServiceError(ServiceErrorUnknown, "invalid read payload", jerr, nil)
	}
	return normaliseState(&d), nil
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

// Update applies in-place configuration changes. BinaryPath is ForceNew and
// must not be mutated here; any non-empty input.BinaryPath is ignored.
func (s *ServiceClient) Update(ctx context.Context, name string, input ServiceInput) (*ServiceState, error) {
	if name == "" {
		return nil, NewServiceError(ServiceErrorInvalidParameter, "name is required", nil, nil)
	}
	startType := input.StartType
	if startType == "" {
		startType = "Automatic"
	}
	setSvcStart := startType
	if setSvcStart == "AutomaticDelayedStart" {
		setSvcStart = "Automatic"
	}

	// Dependencies == nil means "do not touch". Empty slice means "clear".
	depsMode := "skip"
	depArg := ""
	if input.Dependencies != nil {
		if len(input.Dependencies) == 0 {
			depsMode = "clear"
			depArg = "/"
		} else {
			depsMode = "set"
			depArg = strings.Join(input.Dependencies, "/")
		}
	}

	script := psReadStateBody + `
try {
  $name     = ` + psQuote(name) + `
  $display  = ` + psQuote(input.DisplayName) + `
  $desc     = ` + psQuote(input.Description) + `
  $stype    = ` + psQuote(setSvcStart) + `
  $finalStart = ` + psQuote(startType) + `
  $account  = ` + psQuote(input.ServiceAccount) + `
  $password = ` + psQuote(input.ServicePassword) + `
  $depsMode = ` + psQuote(depsMode) + `
  $depArg   = ` + psQuote(depArg) + `

  $existing = Get-Service -Name $name -ErrorAction SilentlyContinue
  if (-not $existing) { Emit-Err 'not_found' "service '$name' does not exist" @{}; return }

  # Set-Service: display_name, description, start_type, credential
  $setArgs = @{ Name = $name; StartupType = $stype }
  if ($display) { $setArgs['DisplayName'] = $display }
  if ($desc -ne $null) { $setArgs['Description'] = $desc }
  if ($account -and $password) {
    $sec  = ConvertTo-SecureString $password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($account, $sec)
    $setArgs['Credential'] = $cred
  }
  Set-Service @setArgs

  # Account without password (built-in) via sc.exe obj=
  if ($account -and -not $password) {
    $out = & sc.exe config $name obj= $account 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify $out) ("sc.exe config obj= failed: " + $out.Trim()) @{}; return }
  }

  if ($finalStart -eq 'AutomaticDelayedStart') {
    $out = & sc.exe config $name start= delayed-auto 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify $out) ("sc.exe delayed-auto failed: " + $out.Trim()) @{}; return }
  }

  if ($depsMode -ne 'skip') {
    $out = & sc.exe config $name depend= $depArg 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify $out) ("sc.exe depend= failed: " + $out.Trim()) @{}; return }
  }

  $st = Read-ServiceState $name
  if (-not $st) { Emit-Err 'not_found' "service disappeared after update" @{}; return }
  Emit-OK $st
} catch {
  $msg  = $_.Exception.Message
  $kind = Classify $msg
  Emit-Err $kind $msg @{}
}
`
	resp, err := s.runEnvelope(ctx, "Update", name, script)
	if err != nil {
		return nil, err
	}
	var d stateData
	if jerr := json.Unmarshal(resp.Data, &d); jerr != nil {
		return nil, NewServiceError(ServiceErrorUnknown, "invalid update payload", jerr, nil)
	}
	state := normaliseState(&d)

	if input.DesiredStatus != "" {
		if err := s.reconcileStatus(ctx, name, input.DesiredStatus); err != nil {
			return state, err
		}
		if ns, rerr := s.Read(ctx, name); rerr == nil && ns != nil {
			state = ns
		}
	}
	return state, nil
}

// -----------------------------------------------------------------------------
// Delete (SS11: Stop → WaitForStatus → Remove)
// -----------------------------------------------------------------------------

// Delete stops and removes the service. Win32 1060 (not found) is success.
func (s *ServiceClient) Delete(ctx context.Context, name string) error {
	if name == "" {
		return NewServiceError(ServiceErrorInvalidParameter, "name is required", nil, nil)
	}
	waitSec := int(s.c.cfg.Timeout / time.Second)
	if waitSec < 10 {
		waitSec = 30
	}

	script := `
try {
  $name = ` + psQuote(name) + `
  $waitSec = ` + fmt.Sprintf("%d", waitSec) + `

  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if (-not $svc) { Emit-OK @{ deleted = $true; already_absent = $true }; return }

  if ($svc.Status -eq 'Running' -or $svc.Status -eq 'Paused') {
    try { Stop-Service -Name $name -Force -ErrorAction Stop } catch {
      $m = $_.Exception.Message
      if ($m -notmatch '1062') { Emit-Err (Classify $m) $m @{}; return }
    }
    try {
      $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($waitSec))
    } catch {
      Emit-Err 'timeout' ("service '$name' did not stop within $waitSec s") @{ elapsed = ($waitSec.ToString() + 's') }
      return
    }
  }

  if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
    try { Remove-Service -Name $name -ErrorAction Stop } catch {
      $m = $_.Exception.Message
      if ($m -match '1060') { Emit-OK @{ deleted = $true; already_absent = $true }; return }
      Emit-Err (Classify $m) $m @{}; return
    }
  } else {
    $out = & sc.exe delete $name 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
      if ($out -match '1060') { Emit-OK @{ deleted = $true; already_absent = $true }; return }
      Emit-Err (Classify $out) ("sc.exe delete failed: " + $out.Trim()) @{}; return
    }
  }
  Emit-OK @{ deleted = $true }
} catch {
  $msg  = $_.Exception.Message
  $kind = Classify $msg
  if ($kind -eq 'not_found') { Emit-OK @{ deleted = $true; already_absent = $true }; return }
  Emit-Err $kind $msg @{}
}
`
	_, err := s.runEnvelope(ctx, "Delete", name, script)
	if err != nil {
		if errors.Is(err, ErrServiceNotFound) {
			return nil
		}
		return err
	}
	return nil
}

// -----------------------------------------------------------------------------
// StartService / StopService / PauseService
// -----------------------------------------------------------------------------

// StartService starts the named service.
func (s *ServiceClient) StartService(ctx context.Context, name string) error {
	return s.runStateOp(ctx, "Start", name, `
  try {
    Start-Service -Name $name -ErrorAction Stop
    $svc = Get-Service -Name $name
    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds($waitSec))
    Emit-OK @{ status = 'Running' }
  } catch {
    $m = $_.Exception.Message
    if ($m -match '1056') { Emit-Err 'already_running' $m @{}; return }
    if ($m -match '1058') { Emit-Err 'disabled' $m @{}; return }
    $k = Classify $m
    if ($k -eq 'unknown' -and $m -match 'time') { $k = 'timeout' }
    Emit-Err $k $m @{}
  }`)
}

// StopService stops the named service (cascades to dependents).
func (s *ServiceClient) StopService(ctx context.Context, name string) error {
	return s.runStateOp(ctx, "Stop", name, `
  try {
    Stop-Service -Name $name -Force -ErrorAction Stop
    $svc = Get-Service -Name $name
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($waitSec))
    Emit-OK @{ status = 'Stopped' }
  } catch {
    $m = $_.Exception.Message
    if ($m -match '1062') { Emit-Err 'not_running' $m @{}; return }
    $k = Classify $m
    if ($k -eq 'unknown' -and $m -match 'time') { $k = 'timeout' }
    Emit-Err $k $m @{}
  }`)
}

// PauseService suspends the named service. EC-13: verifies CanPauseAndContinue.
func (s *ServiceClient) PauseService(ctx context.Context, name string) error {
	return s.runStateOp(ctx, "Pause", name, `
  try {
    $svc = Get-Service -Name $name -ErrorAction Stop
    if (-not $svc.CanPauseAndContinue) {
      Emit-Err 'invalid_parameter' ("service '$name' does not support Pause (CanPauseAndContinue=false, EC-13)") @{}
      return
    }
    Suspend-Service -Name $name -ErrorAction Stop
    $svc.WaitForStatus('Paused', [TimeSpan]::FromSeconds($waitSec))
    Emit-OK @{ status = 'Paused' }
  } catch {
    $m = $_.Exception.Message
    $k = Classify $m
    if ($k -eq 'unknown' -and $m -match 'time') { $k = 'timeout' }
    Emit-Err $k $m @{}
  }`)
}

// runStateOp factors the body used by Start/Stop/Pause.
func (s *ServiceClient) runStateOp(ctx context.Context, op, name, body string) error {
	waitSec := int(s.c.cfg.Timeout / time.Second)
	if waitSec < 10 {
		waitSec = 30
	}
	script := `
$name    = ` + psQuote(name) + `
$waitSec = ` + fmt.Sprintf("%d", waitSec) + `
` + body + "\n"
	_, err := s.runEnvelope(ctx, op, name, script)
	return err
}

// reconcileStatus dispatches to Start / Stop / Pause based on desired. Idempotent
// "already in target state" responses are swallowed.
func (s *ServiceClient) reconcileStatus(ctx context.Context, name, desired string) error {
	var err error
	switch desired {
	case "Running":
		err = s.StartService(ctx, name)
		if errors.Is(err, ErrServiceRunning) {
			return nil
		}
	case "Stopped":
		err = s.StopService(ctx, name)
		if errors.Is(err, ErrServiceNotRunning) {
			return nil
		}
	case "Paused":
		err = s.PauseService(ctx, name)
	default:
		return NewServiceError(ServiceErrorInvalidParameter,
			fmt.Sprintf("unknown desired status %q", desired), nil, nil)
	}
	return err
}
