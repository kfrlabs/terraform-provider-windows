// Package winclient — PowerShell implementation of WindowsServiceClient.
//
// Minimal viable CRUD for the windows_service resource (spec v7).
//
// SECURITY: Every value coming from the Terraform configuration is embedded
// in the PowerShell payload via psSingleQuote (single-quoted literal with ''
// escape). The full script is then sent over WinRM as a UTF-16LE base64
// -EncodedCommand, so neither PowerShell nor cmd.exe interpretation occurs
// along the wire. service_password is passed to PowerShell as a literal and
// is NEVER echoed back in stdout / stderr / error messages.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// serviceClient is the PowerShell-over-WinRM implementation of
// WindowsServiceClient.
type serviceClient struct {
	c *Client
}

// NewWindowsServiceClient wraps a generic WinRM *Client into a typed
// WindowsServiceClient. The underlying client is reused for every call.
func NewWindowsServiceClient(c *Client) WindowsServiceClient {
	return &serviceClient{c: c}
}

// psSingleQuote returns s wrapped as a PowerShell single-quoted literal with
// internal apostrophes doubled. Safe for embedding untrusted values.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// psBool returns "$true" / "$false".
func psBool(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// psStringArray renders a Go []string as a PowerShell @('a','b') array.
func psStringArray(ss []string) string {
	if len(ss) == 0 {
		return "@()"
	}
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = psSingleQuote(s)
	}
	return "@(" + strings.Join(parts, ",") + ")"
}

// classifyErrorKind maps a PowerShell error message to a ServiceErrorKind.
func classifyErrorKind(msg string) ServiceErrorKind {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "1060"),
		strings.Contains(m, "does not exist"),
		strings.Contains(m, "cannot find any service"),
		strings.Contains(m, "no service with name"):
		return ServiceErrorNotFound
	case strings.Contains(m, "1073"),
		strings.Contains(m, "already exists"):
		return ServiceErrorAlreadyExists
	case strings.Contains(m, "access is denied"),
		strings.Contains(m, "error 5 "),
		strings.Contains(m, "(5)"):
		return ServiceErrorPermission
	case strings.Contains(m, "1056"),
		strings.Contains(m, "already been started"),
		strings.Contains(m, "already running"):
		return ServiceErrorRunning
	case strings.Contains(m, "1062"),
		strings.Contains(m, "has not been started"),
		strings.Contains(m, "not started"):
		return ServiceErrorNotRunning
	case strings.Contains(m, "1058"),
		strings.Contains(m, "disabled"):
		return ServiceErrorDisabled
	case strings.Contains(m, "error 87"),
		strings.Contains(m, "(87)"),
		strings.Contains(m, "parameter is incorrect"):
		return ServiceErrorInvalidParameter
	}
	return ServiceErrorUnknown
}

// psResult is the JSON envelope emitted by every PS script.
type psResult struct {
	OK      bool            `json:"ok"`
	Data    json.RawMessage `json:"data,omitempty"`
	Kind    string          `json:"kind,omitempty"`
	Message string          `json:"message,omitempty"`
}

// wrapPS wraps a PS body in a standard try/catch envelope that emits a
// single JSON line on stdout and ALWAYS exits 0 so RunPowerShell never
// returns an exit-code error (which would lose stdout).
func wrapPS(body string) string {
	return `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
` + body + `
} catch {
  $m = $_.Exception.Message
  @{ ok=$false; kind=''; message=$m } | ConvertTo-Json -Compress
  exit 0
}
`
}

// runScript executes wrapped PowerShell and returns the parsed JSON envelope
// or a *ServiceError on transport / protocol failure.
func (s *serviceClient) runScript(ctx context.Context, body string, op, name string) (*psResult, error) {
	script := wrapPS(body)
	stdout, stderr, err := s.c.RunPowerShell(ctx, script)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewServiceError(ServiceErrorTimeout,
				fmt.Sprintf("timeout executing PowerShell for %s(%s)", op, name),
				ctx.Err(),
				map[string]string{"operation": op, "name": name})
		}
		return nil, NewServiceError(ServiceErrorUnknown,
			"winrm transport error",
			err,
			map[string]string{
				"operation": op, "name": name,
				"stderr": truncate(stderr, 2048),
			})
	}
	line := lastJSONLine(stdout)
	if line == "" {
		return nil, NewServiceError(ServiceErrorUnknown,
			"empty PowerShell output",
			nil,
			map[string]string{"operation": op, "name": name, "stderr": truncate(stderr, 2048)})
	}
	var pr psResult
	if err := json.Unmarshal([]byte(line), &pr); err != nil {
		return nil, NewServiceError(ServiceErrorUnknown,
			"unparseable PowerShell output",
			err,
			map[string]string{"operation": op, "name": name, "stdout": truncate(stdout, 2048)})
	}
	if !pr.OK {
		kind := ServiceErrorKind(pr.Kind)
		if kind == "" {
			kind = classifyErrorKind(pr.Message)
		}
		return &pr, NewServiceError(kind, pr.Message, nil,
			map[string]string{"operation": op, "name": name})
	}
	return &pr, nil
}

// lastJSONLine returns the last non-blank line of s, trimmed.
func lastJSONLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l != "" {
			return l
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// readStateJSON is the JSON shape emitted by the Read PowerShell payload.
type readStateJSON struct {
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

// Read implements WindowsServiceClient.Read.
// Returns (nil, nil) when the service is absent (EC-2).
func (s *serviceClient) Read(ctx context.Context, name string) (*ServiceState, error) {
	body := `$Name = ` + psSingleQuote(name) + `
$svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + ($Name -replace "'", "''") + "'") -ErrorAction SilentlyContinue
if (-not $svc) {
  @{ ok=$true; data=$null } | ConvertTo-Json -Compress
  return
}
$deps = @()
try {
  $g = Get-Service -Name $Name -ErrorAction Stop
  if ($g.ServicesDependedOn) { $deps = @($g.ServicesDependedOn | ForEach-Object { $_.Name }) }
} catch {}
$startType = 'Manual'
switch ($svc.StartMode) {
  'Auto'     { if ($svc.DelayedAutoStart) { $startType='AutomaticDelayedStart' } else { $startType='Automatic' } }
  'Manual'   { $startType='Manual' }
  'Disabled' { $startType='Disabled' }
  default    { $startType = [string]$svc.StartMode }
}
$state = [string]$svc.State
$data = [ordered]@{
  name            = $svc.Name
  display_name    = [string]$svc.DisplayName
  description     = if ($svc.Description) { [string]$svc.Description } else { '' }
  binary_path     = [string]$svc.PathName
  start_type      = $startType
  current_status  = $state
  service_account = [string]$svc.StartName
  dependencies    = $deps
  hostname        = $env:COMPUTERNAME
}
@{ ok=$true; data=$data } | ConvertTo-Json -Compress -Depth 5
`
	pr, err := s.runScript(ctx, body, "read", name)
	if err != nil {
		return nil, err
	}
	if len(pr.Data) == 0 || string(pr.Data) == "null" {
		return nil, nil
	}
	var rs readStateJSON
	if err := json.Unmarshal(pr.Data, &rs); err != nil {
		return nil, NewServiceError(ServiceErrorUnknown, "unparseable read payload", err,
			map[string]string{"name": name})
	}
	return &ServiceState{
		Name:           rs.Name,
		DisplayName:    rs.DisplayName,
		Description:    rs.Description,
		BinaryPath:     normalizeBinaryPath(rs.BinaryPath),
		StartType:      rs.StartType,
		CurrentStatus:  rs.CurrentStatus,
		ServiceAccount: normalizeServiceAccount(rs.ServiceAccount, rs.Hostname),
		Dependencies:   rs.Dependencies,
	}, nil
}

// normalizeBinaryPath implements EC-14: strip outer double quotes when they
// wrap the entire path (no arguments and no inner quotes).
func normalizeBinaryPath(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		inner := p[1 : len(p)-1]
		if !strings.Contains(inner, `"`) {
			return inner
		}
	}
	return p
}

// normalizeServiceAccount implements ADR SS10:
//   - NT AUTHORITY\SYSTEM → LocalSystem
//   - .\user → HOSTNAME\user
func normalizeServiceAccount(acct, hostname string) string {
	if acct == "" {
		return ""
	}
	if strings.EqualFold(acct, `NT AUTHORITY\SYSTEM`) {
		return "LocalSystem"
	}
	if strings.HasPrefix(acct, `.\`) && hostname != "" {
		return hostname + `\` + acct[2:]
	}
	return acct
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create implements WindowsServiceClient.Create.
func (s *serviceClient) Create(ctx context.Context, input ServiceInput) (*ServiceState, error) {
	startType := input.StartType
	if startType == "" {
		startType = "Automatic"
	}
	// New-Service does not know AutomaticDelayedStart — apply as Automatic
	// then promote via sc.exe config start= delayed-auto (ADR SS3).
	newSvcStartType := startType
	if newSvcStartType == "AutomaticDelayedStart" {
		newSvcStartType = "Automatic"
	}

	body := `$Name = ` + psSingleQuote(input.Name) + `
$BinaryPath = ` + psSingleQuote(input.BinaryPath) + `
$DisplayName = ` + psSingleQuote(input.DisplayName) + `
$Description = ` + psSingleQuote(input.Description) + `
$StartType = ` + psSingleQuote(newSvcStartType) + `
$ServiceAccount = ` + psSingleQuote(input.ServiceAccount) + `
$ServicePassword = ` + psSingleQuote(input.ServicePassword) + `
$DelayedAuto = ` + psBool(startType == "AutomaticDelayedStart") + `
$Dependencies = ` + psStringArray(input.Dependencies) + `

if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
  throw "service '$Name' already exists (1073)"
}

$params = @{
  Name           = $Name
  BinaryPathName = $BinaryPath
  StartupType    = $StartType
}
if ($DisplayName) { $params.DisplayName = $DisplayName }
if ($Description) { $params.Description = $Description }
if ($Dependencies.Count -gt 0) { $params.DependsOn = $Dependencies }
if ($ServiceAccount -and $ServicePassword) {
  $sp = ConvertTo-SecureString $ServicePassword -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($ServiceAccount, $sp)
  $params.Credential = $cred
}
New-Service @params | Out-Null

# Non-default built-in account (no password) → sc.exe config obj=
if ($ServiceAccount -and -not $ServicePassword -and $ServiceAccount -ne 'LocalSystem') {
  $scOut = & sc.exe config $Name obj= $ServiceAccount 2>&1
  if ($LASTEXITCODE -ne 0) { throw "sc.exe config obj= failed: $scOut" }
}

# AutomaticDelayedStart (ADR SS3, EC-9).
if ($DelayedAuto) {
  $scOut = & sc.exe config $Name start= delayed-auto 2>&1
  if ($LASTEXITCODE -ne 0) { throw "sc.exe config start= delayed-auto failed: $scOut" }
}

@{ ok=$true; data=@{ created=$true } } | ConvertTo-Json -Compress
`
	if _, err := s.runScript(ctx, body, "create", input.Name); err != nil {
		return nil, err
	}

	// Runtime state reconciliation.
	if err := s.reconcileStatus(ctx, input.Name, input.DesiredStatus); err != nil {
		return nil, err
	}

	st, err := s.Read(ctx, input.Name)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, NewServiceError(ServiceErrorUnknown,
			"service disappeared immediately after creation", nil,
			map[string]string{"name": input.Name})
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update implements WindowsServiceClient.Update.
func (s *serviceClient) Update(ctx context.Context, name string, input ServiceInput) (*ServiceState, error) {
	startType := input.StartType
	setSvcStart := startType
	delayedAuto := startType == "AutomaticDelayedStart"
	if delayedAuto {
		setSvcStart = "Automatic"
	}

	depsProvided := input.Dependencies != nil

	body := `$Name = ` + psSingleQuote(name) + `
$DisplayName = ` + psSingleQuote(input.DisplayName) + `
$Description = ` + psSingleQuote(input.Description) + `
$StartType = ` + psSingleQuote(setSvcStart) + `
$ServiceAccount = ` + psSingleQuote(input.ServiceAccount) + `
$ServicePassword = ` + psSingleQuote(input.ServicePassword) + `
$DelayedAuto = ` + psBool(delayedAuto) + `
$DepsProvided = ` + psBool(depsProvided) + `
$Dependencies = ` + psStringArray(input.Dependencies) + `

if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
  throw "service '$Name' does not exist (1060)"
}

$setParams = @{ Name = $Name }
if ($DisplayName) { $setParams.DisplayName = $DisplayName }
if ($Description) { $setParams.Description = $Description }
if ($StartType)   { $setParams.StartupType = $StartType }
if ($setParams.Keys.Count -gt 1) { Set-Service @setParams }

# AutomaticDelayedStart promotion.
if ($DelayedAuto) {
  $scOut = & sc.exe config $Name start= delayed-auto 2>&1
  if ($LASTEXITCODE -ne 0) { throw "sc.exe config start= delayed-auto failed: $scOut" }
}

# Account / password (sc.exe config obj= / password=).
if ($ServiceAccount) {
  if ($ServicePassword) {
    $scOut = & sc.exe config $Name obj= $ServiceAccount password= $ServicePassword 2>&1
  } else {
    $scOut = & sc.exe config $Name obj= $ServiceAccount 2>&1
  }
  if ($LASTEXITCODE -ne 0) { throw "sc.exe config obj= failed: $scOut" }
}

# Dependencies: only when explicitly provided (nil = preserve).
if ($DepsProvided) {
  $arg = '/'
  if ($Dependencies.Count -gt 0) { $arg = [string]::Join('/', $Dependencies) }
  $scOut = & sc.exe config $Name depend= $arg 2>&1
  if ($LASTEXITCODE -ne 0) { throw "sc.exe config depend= failed: $scOut" }
}

@{ ok=$true; data=@{ updated=$true } } | ConvertTo-Json -Compress
`
	if _, err := s.runScript(ctx, body, "update", name); err != nil {
		return nil, err
	}

	if err := s.reconcileStatus(ctx, name, input.DesiredStatus); err != nil {
		return nil, err
	}

	st, err := s.Read(ctx, name)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, NewServiceError(ServiceErrorNotFound,
			"service not found after update", nil,
			map[string]string{"name": name})
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete implements WindowsServiceClient.Delete. Ordering: Stop (if running)
// → WaitForStatus(Stopped, 30s) → Remove. Not-found is treated as success.
func (s *serviceClient) Delete(ctx context.Context, name string) error {
	body := `$Name = ` + psSingleQuote(name) + `
$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if (-not $svc) {
  @{ ok=$true; data=@{ deleted=$false; reason='not_found' } } | ConvertTo-Json -Compress
  return
}
if ($svc.Status -ne 'Stopped') {
  try {
    Stop-Service -Name $Name -Force -ErrorAction Stop
    (Get-Service -Name $Name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  } catch {
    throw ("stop-before-delete failed: " + $_.Exception.Message)
  }
}

if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
  Remove-Service -Name $Name -ErrorAction Stop
} else {
  $scOut = & sc.exe delete $Name 2>&1
  if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed: $scOut" }
}

@{ ok=$true; data=@{ deleted=$true } } | ConvertTo-Json -Compress
`
	_, err := s.runScript(ctx, body, "delete", name)
	if err != nil {
		// EC-6: treat not_found as success for idempotency.
		if IsServiceError(err, ServiceErrorNotFound) {
			return nil
		}
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// State control: Start / Stop / Pause
// ---------------------------------------------------------------------------

// StartService implements WindowsServiceClient.StartService.
func (s *serviceClient) StartService(ctx context.Context, name string) error {
	body := `$Name = ` + psSingleQuote(name) + `
Start-Service -Name $Name -ErrorAction Stop
(Get-Service -Name $Name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
@{ ok=$true; data=@{ status='Running' } } | ConvertTo-Json -Compress
`
	_, err := s.runScript(ctx, body, "start", name)
	return err
}

// StopService implements WindowsServiceClient.StopService.
func (s *serviceClient) StopService(ctx context.Context, name string) error {
	body := `$Name = ` + psSingleQuote(name) + `
Stop-Service -Name $Name -Force -ErrorAction Stop
(Get-Service -Name $Name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
@{ ok=$true; data=@{ status='Stopped' } } | ConvertTo-Json -Compress
`
	_, err := s.runScript(ctx, body, "stop", name)
	return err
}

// PauseService implements WindowsServiceClient.PauseService.
// Verifies CanPauseAndContinue=$true before Suspend-Service (EC-13).
func (s *serviceClient) PauseService(ctx context.Context, name string) error {
	body := `$Name = ` + psSingleQuote(name) + `
$svc = Get-Service -Name $Name -ErrorAction Stop
if (-not $svc.CanPauseAndContinue) {
  throw "service '$Name' does not support pause (CanPauseAndContinue=false) EC-13 (error 87, parameter is incorrect)"
}
Suspend-Service -Name $Name -ErrorAction Stop
(Get-Service -Name $Name).WaitForStatus('Paused', [TimeSpan]::FromSeconds(30))
@{ ok=$true; data=@{ status='Paused' } } | ConvertTo-Json -Compress
`
	_, err := s.runScript(ctx, body, "pause", name)
	return err
}

// reconcileStatus issues the state transition corresponding to desired.
// desired == "" → observe-only (ADR SS4); no-op.
func (s *serviceClient) reconcileStatus(ctx context.Context, name, desired string) error {
	switch desired {
	case "":
		return nil
	case "Running":
		err := s.StartService(ctx, name)
		if IsServiceError(err, ServiceErrorRunning) {
			return nil
		}
		return err
	case "Stopped":
		err := s.StopService(ctx, name)
		if IsServiceError(err, ServiceErrorNotRunning) {
			return nil
		}
		return err
	case "Paused":
		return s.PauseService(ctx, name)
	default:
		return NewServiceError(ServiceErrorInvalidParameter,
			"invalid desired status: "+desired, nil,
			map[string]string{"name": name, "desired": desired})
	}
}

// Compile-time interface assertion.
var _ WindowsServiceClient = (*serviceClient)(nil)
