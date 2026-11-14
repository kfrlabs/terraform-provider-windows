// Package winclient: domain membership (AD join/unjoin) over SSH.
//
// This file provides DomainMembershipClient, the concrete
// WindowsDomainMembershipClient used by the windows_domain_membership
// Terraform resource. All operations execute PowerShell scripts wrapped in
// a JSON envelope (Emit-OK/Emit-Err) so stdout is machine-parseable
// regardless of Windows locale.
//
// Security invariants:
//   - The join/unjoin password is NEVER interpolated into a script body. It
//     is injected via stdin (RunPowerShellWithInput) and read by the script
//     with [Console]::In.ReadLine(), then converted with
//     ConvertTo-SecureString. The plaintext never appears in the
//     -EncodedCommand payload, SSH logs or diagnostics.
//   - Every other user-supplied string (domain, OU path, server, username,
//     workgroup) is interpolated only through psQuote (single-quoted PS
//     literal) so $var / backtick / subexpression injection is impossible.
//   - Scripts never call "exit": since #81 a script may run inside a
//     long-lived, reused PowerShell session, where "exit" would kill that
//     session instead of just this call. Early returns use "return" after
//     Emit-Err instead.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: DomainMembershipClient satisfies
// WindowsDomainMembershipClient.
var _ WindowsDomainMembershipClient = (*DomainMembershipClient)(nil)

// DomainMembershipClient is the PowerShell/SSH-backed
// WindowsDomainMembershipClient.
type DomainMembershipClient struct {
	c *Client
}

// NewDomainMembershipClient constructs a DomainMembershipClient wrapping the
// given SSH Client.
func NewDomainMembershipClient(c *Client) *DomainMembershipClient {
	return &DomainMembershipClient{c: c}
}

// psDomainMembershipHeader prepends Emit-OK/Emit-Err,
// Classify-DomainMembership and Test-DMPendingReboot.
//
// Classify-DomainMembership maps Add-Computer/Remove-Computer error
// substrings to DomainMembershipErrorKind values. Detection prefers Win32
// error codes (1326 logon failure, 1355/53 domain unreachable, 2224 account
// exists, 5 access denied) because Windows error messages are localised;
// message-substring fallbacks cover the same failures when only text is
// available.
const psDomainMembershipHeader = psEnvelopePrelude + psDomainMembershipRemainder

// psDomainMembershipRemainder Classifier and join/unjoin helpers stay here; envelope emitters come from the prelude.
const psDomainMembershipRemainder = `function Classify-DomainMembership([string]$Msg) {
  if ($Msg -match '\b1326\b' -or $Msg -match 'unknown user name or bad password' -or $Msg -match 'Logon failure') { return 'bad_credentials' }
  if ($Msg -match '\b1355\b' -or $Msg -match 'either does not exist or could not be contacted' -or $Msg -match 'cannot find the domain') { return 'domain_not_found' }
  if (($Msg -match '\b53\b') -and ($Msg -match 'network path was not found')) { return 'domain_not_found' }
  if ($Msg -match '\b2224\b' -or $Msg -match 'account already exists') { return 'account_exists' }
  if (($Msg -match 'organizational unit') -and ($Msg -match 'does not exist|not found|could not be found')) { return 'ou_not_found' }
  if ($Msg -match 'Access is denied' -or $Msg -match 'AccessDenied' -or (($Msg -match '\b5\b') -and ($Msg -match 'denied'))) { return 'access_denied' }
  if (($Msg -match 'reboot') -and ($Msg -match 'pending')) { return 'reboot_pending' }
  return 'unknown'
}

function Test-DMPendingReboot {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
  )
  if (Test-Path $paths[0]) { return $true }
  if (Test-Path $paths[1]) { return $true }
  try {
    $sm = Get-ItemProperty -Path $paths[2] -ErrorAction Stop
    if ($sm.PSObject.Properties['PendingFileRenameOperations']) { return $true }
  } catch {}
  return $false
}

function Read-DomainMembershipState([bool]$CheckSecureChannel = $true) {
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
  $pending = Test-DMPendingReboot
  $partOfDomain = [bool]$cs.PartOfDomain
  $domain = ""
  if ($partOfDomain) { $domain = [string]$cs.Domain }
  $workgroup = ""
  if (-not $partOfDomain) { $workgroup = [string]$cs.Workgroup }
  $netbiosDomain = ""
  if ($partOfDomain) {
    try {
      $domains = @(Get-CimInstance -ClassName Win32_NTDomain -ErrorAction Stop)
      $match = $domains | Where-Object { $_.DomainName -eq $cs.Domain -or $_.DnsForestName -eq $cs.Domain } | Select-Object -First 1
      if ($null -eq $match) { $match = $domains | Select-Object -First 1 }
      if (($null -ne $match) -and $match.DomainName) { $netbiosDomain = [string]$match.DomainName }
    } catch { $netbiosDomain = "" }
    if ([string]::IsNullOrEmpty($netbiosDomain) -and $domain.Contains('.')) {
      $netbiosDomain = $domain.Split('.')[0].ToUpperInvariant()
    }
  }
  $sc = $null
  if ($partOfDomain -and $CheckSecureChannel) {
    try { $sc = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { $sc = $false }
  }
  $machineId = ""
  try { $machineId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid } catch { $machineId = "" }
  return [ordered]@{
    domain            = $domain
    part_of_domain    = $partOfDomain
    computer_name     = [string]$cs.Name
    workgroup         = $workgroup
    dns_host_name     = [string]$cs.DNSHostName
    netbios_domain    = $netbiosDomain
    domain_role       = [int]$cs.DomainRole
    machine_id        = [string]$machineId
    pending_reboot    = [bool]$pending
    secure_channel_ok = $sc
  }
}
`

// domainMembershipPSResponse is the parsed JSON envelope for domain
// membership operations. It aliases the shared Envelope type so every
// resource parses the same shape through runEnvelope (#198).
type domainMembershipPSResponse = Envelope

// runDomainMembershipEnvelope executes script (prepended with
// psDomainMembershipHeader) through the shared runEnvelope helper without
// stdin, mapping failures to *DomainMembershipError.
func (d *DomainMembershipClient) runDomainMembershipEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*domainMembershipPSResponse, error) {
	baseContext := map[string]string{"host": d.c.cfg.Host}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, d.c, full)
		},
		op, psDomainMembershipHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	return resp, mapDomainMembershipEnvelopeError(eerr)
}

// runDomainMembershipEnvelopeWithInput is the stdin-aware sibling of
// runDomainMembershipEnvelope. It injects the join/unjoin password via stdin
// instead of the script body. The stdin value is NEVER copied into error
// context or logs.
func (d *DomainMembershipClient) runDomainMembershipEnvelopeWithInput(ctx context.Context, op, script, stdin string, baseCtx map[string]string) (*domainMembershipPSResponse, error) {
	baseContext := map[string]string{"host": d.c.cfg.Host}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPSInput(ctx, d.c, full, stdin)
		},
		op, psDomainMembershipHeader+"\n"+script, stdin, baseContext)
	if eerr == nil {
		return resp, nil
	}
	return resp, mapDomainMembershipEnvelopeError(eerr)
}

// mapDomainMembershipEnvelopeError converts an *EnvelopeError to a
// *DomainMembershipError. Context cancellation keeps a timeout kind; remote
// Emit-Err kinds map through mapDomainMembershipKind.
func mapDomainMembershipEnvelopeError(eerr *EnvelopeError) error {
	if eerr.Stage == EnvelopeStageTimeout {
		return NewDomainMembershipError(DomainMembershipErrorTimeout, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return NewDomainMembershipError(DomainMembershipErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	kind := mapDomainMembershipKind(eerr.RemoteKind)
	msg := eerr.Message
	if kind == DomainMembershipErrorAccessDenied {
		msg += " (The join/unjoin account needs permission to manage computer accounts in the domain.)"
	}
	return NewDomainMembershipError(kind, msg, nil, eerr.Context)
}

// mapDomainMembershipKind translates the PS-side "kind" string to a typed
// DomainMembershipErrorKind.
func mapDomainMembershipKind(k string) DomainMembershipErrorKind {
	switch k {
	case string(DomainMembershipErrorAlreadyJoined),
		string(DomainMembershipErrorJoinedToOtherDomain),
		string(DomainMembershipErrorDomainNotFound),
		string(DomainMembershipErrorBadCredentials),
		string(DomainMembershipErrorAccountExists),
		string(DomainMembershipErrorOuNotFound),
		string(DomainMembershipErrorAccessDenied),
		string(DomainMembershipErrorRebootPending),
		string(DomainMembershipErrorTimeout),
		string(DomainMembershipErrorInvalidParameter):
		return DomainMembershipErrorKind(k)
	default:
		return DomainMembershipErrorUnknown
	}
}

// domainMembershipStatePayload mirrors the JSON object produced by
// Read-DomainMembershipState. SecureChannelOk is a pointer so a JSON null
// (no probe: workgroup host, or CheckSecureChannel=false) unmarshals to nil
// instead of collapsing to false. Older hosts omit the newer keys; JSON
// unmarshal leaves them at their zero values.
type domainMembershipStatePayload struct {
	Domain          string `json:"domain"`
	PartOfDomain    bool   `json:"part_of_domain"`
	ComputerName    string `json:"computer_name"`
	PendingReboot   bool   `json:"pending_reboot"`
	SecureChannelOk *bool  `json:"secure_channel_ok"`
	Workgroup       string `json:"workgroup"`
	DNSHostName     string `json:"dns_host_name"`
	NetBIOSDomain   string `json:"netbios_domain"`
	DomainRole      int    `json:"domain_role"`
	MachineID       string `json:"machine_id"`
}

// mapDomainRole translates a Win32_ComputerSystem.DomainRole value (0-5) to
// its documented name. Unknown values are a hard error, never a silent
// default: an unmapped role means the host reports something this provider
// does not understand.
func mapDomainRole(role int) (string, error) {
	switch role {
	case 0:
		return "StandaloneWorkstation", nil
	case 1:
		return "MemberWorkstation", nil
	case 2:
		return "StandaloneServer", nil
	case 3:
		return "MemberServer", nil
	case 4:
		return "BackupDomainController", nil
	case 5:
		return "PrimaryDomainController", nil
	default:
		return "", NewDomainMembershipError(DomainMembershipErrorUnknown,
			fmt.Sprintf("unknown domain role %d reported by Win32_ComputerSystem", role), nil, nil)
	}
}

// toDomainMembershipState projects a payload onto the public state type.
// The Go layer — not PowerShell — enforces the empty-string rules so they
// stay unit-testable: Domain and NetBIOSDomain are "" when the host is not
// joined (never the workgroup name), Workgroup is "" when it is, and a null
// secure_channel_ok (or any workgroup host) surfaces as SecureChannelNull
// with SecureChannelOk false, preserving the historical resource read.
func toDomainMembershipState(p *domainMembershipStatePayload) (*DomainMembershipState, error) {
	if p == nil {
		return nil, nil
	}
	role, err := mapDomainRole(p.DomainRole)
	if err != nil {
		return nil, err
	}
	st := &DomainMembershipState{
		Domain:        p.Domain,
		PartOfDomain:  p.PartOfDomain,
		ComputerName:  p.ComputerName,
		Workgroup:     p.Workgroup,
		DNSHostName:   p.DNSHostName,
		NetBIOSDomain: p.NetBIOSDomain,
		DomainRole:    role,
		MachineID:     p.MachineID,
		PendingReboot: p.PendingReboot,
	}
	if p.SecureChannelOk != nil {
		st.SecureChannelOk = *p.SecureChannelOk
	}
	if !p.PartOfDomain {
		st.Domain = ""
		st.NetBIOSDomain = ""
		st.SecureChannelNull = true
	} else {
		st.Workgroup = ""
		if p.SecureChannelOk == nil {
			st.SecureChannelNull = true
		}
	}
	return st, nil
}

// toDomainMembershipStateLenient projects a payload onto the public state
// type for the mutation paths (Join/Unjoin). A successful mutation must not
// collapse into a total failure just because the post-operation state
// reports a Win32_ComputerSystem.DomainRole this provider does not know
// yet: the reboot side-channel and the rest of the state are still valid.
// Unknown roles map to "" instead of erroring; Read/ReadWithOptions keep
// the strict mapping above and fail loudly per spec.
func toDomainMembershipStateLenient(p *domainMembershipStatePayload) *DomainMembershipState {
	if p == nil {
		return nil
	}
	role, err := mapDomainRole(p.DomainRole)
	if err != nil {
		role = ""
	}
	st := &DomainMembershipState{
		Domain:        p.Domain,
		PartOfDomain:  p.PartOfDomain,
		ComputerName:  p.ComputerName,
		Workgroup:     p.Workgroup,
		DNSHostName:   p.DNSHostName,
		NetBIOSDomain: p.NetBIOSDomain,
		DomainRole:    role,
		MachineID:     p.MachineID,
		PendingReboot: p.PendingReboot,
	}
	if p.SecureChannelOk != nil {
		st.SecureChannelOk = *p.SecureChannelOk
	}
	if !p.PartOfDomain {
		st.Domain = ""
		st.NetBIOSDomain = ""
		st.SecureChannelNull = true
	} else {
		st.Workgroup = ""
		if p.SecureChannelOk == nil {
			st.SecureChannelNull = true
		}
	}
	return st
}

// Read returns the current domain-membership state of the target host.
// It delegates to ReadWithOptions with the secure-channel probe enabled,
// preserving the historical resource behavior.
func (d *DomainMembershipClient) Read(ctx context.Context) (*DomainMembershipState, error) {
	return d.ReadWithOptions(ctx, DomainMembershipReadOptions{CheckSecureChannel: true})
}

// ReadWithOptions returns the current domain-membership state of the target
// host, optionally skipping the Test-ComputerSecureChannel probe
// (CheckSecureChannel=false). Skipping avoids a domain-controller
// round-trip for inventory-only reads such as the
// windows_domain_membership data source; the state then reports
// SecureChannelNull with SecureChannelOk false.
func (d *DomainMembershipClient) ReadWithOptions(ctx context.Context, opts DomainMembershipReadOptions) (*DomainMembershipState, error) {
	script := fmt.Sprintf("try { $s = Read-DomainMembershipState -CheckSecureChannel:$%s; Emit-OK $s } catch { Emit-Err (Classify-DomainMembership $_.Exception.Message) $_.Exception.Message @{} }",
		psBool(opts.CheckSecureChannel))
	resp, err := d.runDomainMembershipEnvelope(ctx, "read", script, nil)
	if err != nil {
		return nil, err
	}
	var payload domainMembershipStatePayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewDomainMembershipError(DomainMembershipErrorUnknown, "failed to parse domain membership state", jerr, map[string]string{"host": d.c.cfg.Host})
	}
	return toDomainMembershipState(&payload)
}

// psDomainJoinBody runs the join pre-flight, consumes the credential from
// stdin, calls Add-Computer (never with -Restart: the reboot is deferred
// below), then emits the post-join state.
const psDomainJoinBody = `
function Join-Domain([string]$Domain, [string]$OUPath, [string]$Server, [string]$Username, [bool]$Restart) {
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
  } catch {
    Emit-Err (Classify-DomainMembership $_.Exception.Message) $_.Exception.Message @{ phase = 'preflight'; domain = $Domain }
    return
  }
  if ($cs.PartOfDomain) {
    if ($cs.Domain -eq $Domain) {
      Emit-Err 'already_joined' ("This host is already joined to domain '" + $cs.Domain + "'; use 'terraform import' to bring it under management instead of joining again.") @{ domain = [string]$cs.Domain }
      return
    }
    Emit-Err 'joined_to_other_domain' ("This host is already joined to domain '" + $cs.Domain + "' (desired '" + $Domain + "'); unjoin it first.") @{ domain = [string]$cs.Domain; desired = $Domain }
    return
  }
  # Read the join password from stdin (plaintext never in script body).
  $PlainPassword = [Console]::In.ReadLine()
  $SecurePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
  $cred = New-Object PSCredential($Username, $SecurePassword)
  $params = @{ DomainName = $Domain; Credential = $cred; Force = $true; ErrorAction = 'Stop' }
  if (-not [string]::IsNullOrEmpty($OUPath)) { $params['OUPath'] = $OUPath }
  if (-not [string]::IsNullOrEmpty($Server)) { $params['Server'] = $Server }
  # NOTE: never pass -Restart to the cmdlet. A synchronous reboot would land
  # mid-call, killing the SSH session before the envelope is emitted and
  # Terraform records state. The reboot is deferred below instead.
  try {
    Add-Computer @params
  } catch {
    Emit-Err (Classify-DomainMembership $_.Exception.Message) $_.Exception.Message @{ phase = 'join'; domain = $Domain }
    return
  }
  $s = Read-DomainMembershipState
  $rebootScheduled = $false
  # Deferred reboot: when the caller opted in ($Restart) and the join left a
  # pending reboot, schedule a detached reboot 60s out so it lands after this
  # resource records state. Best-effort: native shutdown.exe exit codes do not
  # throw, so $LASTEXITCODE is checked explicitly and a scheduling failure must
  # not fail the already-successful join (pending_reboot in state still lets
  # the operator reboot manually). Shutdown output is swallowed so the Emit-OK
  # envelope stays the last stdout line.
  if ($Restart -and $s.pending_reboot) {
    try { & shutdown.exe /r /t 60 /c "Terraform windows_domain_membership: reboot after domain join" /d p:4:1 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $rebootScheduled = $true } } catch { $rebootScheduled = $false }
  }
  Emit-OK ([ordered]@{ state = $s; reboot_scheduled = [bool]$rebootScheduled })
}
`

// domainJoinDataPayload mirrors the JSON object produced by Join-Domain.
type domainJoinDataPayload struct {
	State           *domainMembershipStatePayload `json:"state"`
	RebootScheduled bool                          `json:"reboot_scheduled"`
}

// Join joins the host to the given domain.
func (d *DomainMembershipClient) Join(ctx context.Context, in DomainJoinInput) (*DomainMembershipState, *DomainJoinResult, error) {
	if strings.TrimSpace(in.Domain) == "" {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorInvalidParameter, "domain is empty", nil, nil)
	}
	if strings.TrimSpace(in.Username) == "" {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorInvalidParameter, "join username is empty", nil, nil)
	}
	if strings.TrimSpace(in.Password) == "" {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorInvalidParameter, "join password is empty", nil, nil)
	}
	call := fmt.Sprintf("Join-Domain -Domain %s -OUPath %s -Server %s -Username %s -Restart:$%s",
		psQuote(in.Domain),
		psQuote(in.OUPath),
		psQuote(in.Server),
		psQuote(in.Username),
		psBool(in.Restart),
	)
	script := psDomainJoinBody + "\n" + call + "\n"
	resp, err := d.runDomainMembershipEnvelopeWithInput(ctx, "join", script, in.Password+"\n",
		map[string]string{"domain": in.Domain})
	if err != nil {
		return nil, nil, err
	}
	var payload domainJoinDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorUnknown, "failed to parse join payload", jerr, map[string]string{"domain": in.Domain})
	}
	if payload.State == nil {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorUnknown, "missing state in payload", nil, map[string]string{"domain": in.Domain})
	}
	state := toDomainMembershipStateLenient(payload.State)
	return state, &DomainJoinResult{
		RebootScheduled: payload.RebootScheduled,
	}, nil
}

// psDomainUnjoinBody runs Remove-Computer (never with -Restart: the reboot is
// deferred below). An already workgroup-joined host succeeds with
// already_absent so Delete stays idempotent.
const psDomainUnjoinBody = `
function Leave-Domain([string]$Username, [string]$Workgroup, [bool]$Restart) {
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
  } catch {
    Emit-Err (Classify-DomainMembership $_.Exception.Message) $_.Exception.Message @{ phase = 'preflight' }
    return
  }
  if (-not $cs.PartOfDomain) {
    $s = Read-DomainMembershipState
    Emit-OK ([ordered]@{ state = $s; already_absent = $true; reboot_scheduled = $false })
    return
  }
  # Read the unjoin password from stdin (plaintext never in script body).
  $PlainPassword = [Console]::In.ReadLine()
  $SecurePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
  $cred = New-Object PSCredential($Username, $SecurePassword)
  # NOTE: never pass -Restart to the cmdlet (see Join-Domain above).
  try {
    Remove-Computer -UnjoinDomainCredential $cred -WorkgroupName $Workgroup -Force -ErrorAction Stop
  } catch {
    Emit-Err (Classify-DomainMembership $_.Exception.Message) $_.Exception.Message @{ phase = 'unjoin' }
    return
  }
  $s = Read-DomainMembershipState
  $rebootScheduled = $false
  # Deferred reboot: same gate as Join-Domain above.
  if ($Restart -and $s.pending_reboot) {
    try { & shutdown.exe /r /t 60 /c "Terraform windows_domain_membership: reboot after domain unjoin" /d p:4:1 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $rebootScheduled = $true } } catch { $rebootScheduled = $false }
  }
  Emit-OK ([ordered]@{ state = $s; already_absent = $false; reboot_scheduled = [bool]$rebootScheduled })
}
`

// domainUnjoinDataPayload mirrors the JSON object produced by Leave-Domain.
type domainUnjoinDataPayload struct {
	State           *domainMembershipStatePayload `json:"state"`
	AlreadyAbsent   bool                          `json:"already_absent"`
	RebootScheduled bool                          `json:"reboot_scheduled"`
}

// Unjoin removes the host from its domain into the given workgroup.
func (d *DomainMembershipClient) Unjoin(ctx context.Context, in DomainUnjoinInput) (*DomainMembershipState, *DomainUnjoinResult, error) {
	if strings.TrimSpace(in.Username) == "" {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorInvalidParameter, "unjoin username is empty", nil, nil)
	}
	if strings.TrimSpace(in.Password) == "" {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorInvalidParameter, "unjoin password is empty", nil, nil)
	}
	if strings.TrimSpace(in.WorkgroupName) == "" {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorInvalidParameter, "workgroup name is empty", nil, nil)
	}
	call := fmt.Sprintf("Leave-Domain -Username %s -Workgroup %s -Restart:$%s",
		psQuote(in.Username),
		psQuote(in.WorkgroupName),
		psBool(in.Restart),
	)
	script := psDomainUnjoinBody + "\n" + call + "\n"
	resp, err := d.runDomainMembershipEnvelopeWithInput(ctx, "unjoin", script, in.Password+"\n", nil)
	if err != nil {
		return nil, nil, err
	}
	var payload domainUnjoinDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorUnknown, "failed to parse unjoin payload", jerr, nil)
	}
	if payload.State == nil {
		return nil, nil, NewDomainMembershipError(DomainMembershipErrorUnknown, "missing state in payload", nil, nil)
	}
	state := toDomainMembershipStateLenient(payload.State)
	return state, &DomainUnjoinResult{
		AlreadyAbsent:   payload.AlreadyAbsent,
		RebootScheduled: payload.RebootScheduled,
	}, nil
}
