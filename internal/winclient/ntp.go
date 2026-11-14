// Package winclient: Windows Time service (W32Time) time-source management
// over SSH.
//
// NTPClient is the concrete WindowsNTPClient backing the windows_ntp
// Terraform resource and data source. All operations execute PowerShell
// scripts wrapped in a JSON envelope (Emit-OK/Emit-Err) so stdout is
// machine-parseable regardless of the Windows locale.
//
// Failure model:
//   - The W32Time service may be absent entirely (containers share the
//     host clock): the preflight Get-Service check emits
//     service_unavailable before anything is read or written.
//   - Registry values are the source of truth. No w32tm query output is
//     ever parsed for state (its text is localised): w32tm is invoked
//     only for /config /update and /resync /rediscover (exit-code gated
//     via $LASTEXITCODE) and for /query /source, whose stdout is taken as
//     an opaque peer name.
//   - A /resync failure never fails the apply: it is recorded on the
//     returned state (resync_warning) and surfaces as a Terraform warning
//     (the peer may be unreachable at apply time).
//
// Security invariants:
//   - User-supplied values (sync type, peer list, DWORDs rendered by Go)
//     are interpolated only via psQuote (single-quoted PS literal) or as
//     Go-formatted integers, so $var / backtick / subexpression injection
//     is impossible.
//   - All scripts are sent via -EncodedCommand by Client.RunPowerShell.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: NTPClient satisfies WindowsNTPClient.
var _ WindowsNTPClient = (*NTPClient)(nil)

// NTPClient is the PowerShell/SSH-backed WindowsNTPClient.
type NTPClient struct {
	c *Client
}

// NewNTPClient wraps the given SSH Client.
func NewNTPClient(c *Client) *NTPClient { return &NTPClient{c: c} }

// ntpPSResponse is the JSON envelope produced by Emit-OK/Emit-Err. It
// aliases the shared Envelope type so every resource parses the same shape
// through runEnvelope (#198).
type ntpPSResponse = Envelope

// ntpStatePayload is the data shape emitted by Read-NTPState.
type ntpStatePayload struct {
	MachineID             string `json:"machine_id"`
	Type                  string `json:"type"`
	NtpServer             string `json:"ntp_server"`
	SpecialPollInterval   int64  `json:"special_poll_interval"`
	Reliable              bool   `json:"reliable"`
	AnnounceFlags         int64  `json:"announce_flags"`
	NtpServerEnabled      bool   `json:"ntp_server_enabled"`
	MaxPosPhaseCorrection int64  `json:"max_pos_phase_correction"`
	MaxNegPhaseCorrection int64  `json:"max_neg_phase_correction"`
	CurrentSource         string `json:"current_source"`
	PolicyOverride        bool   `json:"policy_override"`
	DomainJoined          bool   `json:"domain_joined"`
	VmICEnabled           bool   `json:"vmic_enabled"`
	ResyncWarning         string `json:"resync_warning"`
}

// psNTPHeader prepends Emit-OK/Emit-Err, Classify-NTP and the
// Read-NTPState projection.
//
// Classify-NTP maps service/registry error records to NTPErrorKind
// values. Access-denied patterns are checked first: a message such as
// "Failed to ensure the W32Time service: Access is denied" names W32Time
// but must still classify as access_denied, not service_unavailable.
//
// Read-NTPState reads the W32Time registry views directly (locale-free)
// plus three best-effort signals that never fail the read: the Group
// Policy override view (presence of Type/NtpServer under
// HKLM\SOFTWARE\Policies\Microsoft\W32Time\Parameters), the domain-joined
// flag (Win32_ComputerSystem.PartOfDomain) and the Hyper-V time-sync
// provider flag (VMICTimeProvider\Enabled). The current source is the
// trimmed stdout of w32tm /query /source gated on $LASTEXITCODE — an
// opaque peer name, never parsed — and degrades to "" when the query
// fails (e.g. the service is registered but stopped).
const psNTPHeader = psEnvelopePrelude + psNTPRemainder

// psNTPRemainder Classifier and time-source bodies stay here; envelope emitters come from the prelude.
const psNTPRemainder = `function Classify-NTP([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess' -or $msg -match 'Unauthorized' -or $msg -match 'requires elevation' -or $msg -match 'Requested registry access is not allowed') { return 'access_denied' }
  if ($msg -match 'Cannot find any service' -or $msg -match 'No such service' -or $msg -match 'has not been started' -or $msg -match 'was not started' -or $msg -match 'cannot be started') { return 'service_unavailable' }
  if ($msg -match 'invalid peer' -or $msg -match 'invalid NTP') { return 'invalid_peer' }
  return 'unknown'
}

function Read-NTPState {
  $params = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop
  $ntpServerRaw = [string]$params.NtpServer
  $poll = 0
  try { $poll = [int64](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient' -Name SpecialPollInterval -ErrorAction Stop).SpecialPollInterval } catch { $poll = 0 }
  $srvEnabled = $false
  try { $srvEnabled = ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer' -Name Enabled -ErrorAction Stop).Enabled -eq 1) } catch { $srvEnabled = $false }
  $announce = 10
  try { $announce = [int64](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name AnnounceFlags -ErrorAction Stop).AnnounceFlags } catch { $announce = 10 }
  $maxPos = 0
  try { $maxPos = [int64](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name MaxPosPhaseCorrection -ErrorAction Stop).MaxPosPhaseCorrection } catch { $maxPos = 0 }
  $maxNeg = 0
  try { $maxNeg = [int64](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name MaxNegPhaseCorrection -ErrorAction Stop).MaxNegPhaseCorrection } catch { $maxNeg = 0 }
  $guid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
  $policyOverride = $false
  try {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters'
    if (Test-Path -LiteralPath $policyPath -ErrorAction Stop) {
      $pol = Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop
      foreach ($pn in @('Type', 'NtpServer')) {
        if ($null -ne $pol.$pn) { $policyOverride = $true }
      }
    }
  } catch { $policyOverride = $false }
  $joined = $false
  try { $joined = [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { $joined = $false }
  $vmic = $false
  try { $vmic = ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider' -Name Enabled -ErrorAction Stop).Enabled -eq 1) } catch { $vmic = $false }
  $src = ''
  try {
    $out = & w32tm /query /source 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { $src = $out.Trim() }
  } catch { $src = '' }
  return [ordered]@{
    machine_id               = [string]$guid
    type                     = [string]$params.Type
    ntp_server               = $ntpServerRaw
    special_poll_interval    = [int64]$poll
    reliable                 = [bool]($announce -eq 5)
    announce_flags           = [int64]$announce
    ntp_server_enabled       = [bool]$srvEnabled
    max_pos_phase_correction = [int64]$maxPos
    max_neg_phase_correction = [int64]$maxNeg
    current_source           = $src
    policy_override          = [bool]$policyOverride
    domain_joined            = [bool]$joined
    vmic_enabled             = [bool]$vmic
  }
}
`

// ntpReadBody reads the W32Time time source and emits the normalised
// state JSON. The preflight Get-Service check turns a missing W32Time
// service (containers) into service_unavailable before any registry read.
const ntpReadBody = `
& {
  try { $null = Get-Service -Name W32Time -ErrorAction Stop }
  catch { Emit-Err 'service_unavailable' ('W32Time service is not available on the target host: ' + $_.Exception.Message) @{ step = 'preflight' }; return }
  try { $s = Read-NTPState; Emit-OK $s }
  catch { Emit-Err (Classify-NTP $_) $_.Exception.Message @{ step = 'read' } }
}
`

// ntpSetBody writes the configured registry values, runs
// w32tm /config /update, optionally resyncs (warning-only), then re-reads
// and verifies every configured property. Placeholders, all rendered by
// Go: @@DESIRED@@ (the $ManageService/$DoResync/$Desired*/$Check* preamble),
// @@SETBLOCK@@ (the Set-ItemProperty lines covering only configured inputs
// — Type is always written).
const ntpSetBody = `
$ParamsPath    = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$NtpClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
$NtpServerPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer'
$ConfigPath    = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config'

@@DESIRED@@

& {
  try { $null = Get-Service -Name W32Time -ErrorAction Stop }
  catch { Emit-Err 'service_unavailable' ('W32Time service is not available on the target host: ' + $_.Exception.Message) @{ step = 'preflight' }; return }

  if ($ManageService) {
    try {
      Set-Service -Name W32Time -StartupType Automatic -ErrorAction Stop
      $w = Get-Service -Name W32Time -ErrorAction Stop
      if ($w.Status -ne 'Running') { Start-Service -Name W32Time -ErrorAction Stop }
    } catch { Emit-Err (Classify-NTP $_) ('Failed to ensure the W32Time service: ' + $_.Exception.Message) @{ step = 'ensure_service' }; return }
  }

  try {
@@SETBLOCK@@
  } catch { Emit-Err (Classify-NTP $_) $_.Exception.Message @{ step = 'set' }; return }

  try {
    $cfgOut = & w32tm /config /update 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Emit-Err (Classify-NTP $cfgOut) ('w32tm /config /update failed (exit {0}): {1}' -f $LASTEXITCODE, $cfgOut.Trim()) @{ step = 'config_update' }; return }
  } catch { Emit-Err (Classify-NTP $_) $_.Exception.Message @{ step = 'config_update' }; return }

  $resyncWarning = ''
  if ($DoResync) {
    try {
      $reOut = & w32tm /resync /rediscover 2>&1 | Out-String
      if ($LASTEXITCODE -ne 0) { $resyncWarning = ('w32tm /resync /rediscover exited {0}: {1}' -f $LASTEXITCODE, $reOut.Trim()) }
    } catch { $resyncWarning = ('w32tm /resync /rediscover failed: ' + $_.Exception.Message) }
  }

  try { $s = Read-NTPState }
  catch { Emit-Err (Classify-NTP $_) $_.Exception.Message @{ step = 'readback' }; return }

  $bad = @()
  if ([string]$s.type -ne $DesiredType) { $bad += 'Type' }
  if ($null -ne $DesiredNtpServer) {
    $wantPeers = @($DesiredNtpServer -split '\s+' | Where-Object { $_ -ne '' })
    $gotPeers = @([string]$s.ntp_server -split '\s+' | Where-Object { $_ -ne '' })
    $peersOk = ($wantPeers.Count -eq $gotPeers.Count)
    if ($peersOk) {
      for ($i = 0; $i -lt $wantPeers.Count; $i++) {
        if ($wantPeers[$i] -ne $gotPeers[$i]) { $peersOk = $false; break }
      }
    }
    if (-not $peersOk) { $bad += 'NtpServer' }
  }
  if ($CheckPoll -and ([int64]$s.special_poll_interval -ne $DesiredPoll)) { $bad += 'SpecialPollInterval' }
  if ($CheckAnnounce -and ([int64]$s.announce_flags -ne $DesiredAnnounce)) { $bad += 'AnnounceFlags' }
  if ($CheckServerEnabled -and ([bool]$s.ntp_server_enabled -ne $DesiredServerEnabled)) { $bad += 'NtpServerEnabled' }
  if ($CheckMaxPos -and ([int64]$s.max_pos_phase_correction -ne $DesiredMaxPos)) { $bad += 'MaxPosPhaseCorrection' }
  if ($CheckMaxNeg -and ([int64]$s.max_neg_phase_correction -ne $DesiredMaxNeg)) { $bad += 'MaxNegPhaseCorrection' }
  if ($bad.Count -gt 0) {
    Emit-Err 'unknown' ('W32Time change did not take effect: ' + ($bad -join ', ') + ' does not match the desired values') @{ step = 'verify'; mismatched = ($bad -join ',') }
    return
  }

  $s['resync_warning'] = $resyncWarning
  Emit-OK $s
}
`

// ntpBoolLiteral renders a Go bool as a PowerShell $true/$false literal.
func ntpBoolLiteral(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// buildNTPDesiredBlock renders the $ManageService/$DoResync/$Desired* preamble
// consumed by the static verify block. Unmanaged values degrade to $null
// (peers) or $false $Check* flags (scalars) so the verifier skips them.
func buildNTPDesiredBlock(in NTPInput) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "$ManageService = %s\n", ntpBoolLiteral(in.ManageService))
	fmt.Fprintf(&sb, "$DoResync = %s\n", ntpBoolLiteral(in.ResyncOnApply))
	fmt.Fprintf(&sb, "$DesiredType = %s\n", psQuote(in.Type))
	if len(in.Servers) > 0 {
		raw, err := BuildNtpServerString(in.Servers)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "$DesiredNtpServer = %s\n", psQuote(raw))
	} else {
		sb.WriteString("$DesiredNtpServer = $null\n")
	}
	announce := int64(0)
	checkAnnounce := false
	if in.AnnounceFlags != nil {
		announce, checkAnnounce = *in.AnnounceFlags, true
	} else if in.Reliable != nil {
		announce, checkAnnounce = NTPAnnounceFlagsFromReliable(*in.Reliable), true
	}
	writeCheck := func(name string, v int64, check bool) {
		fmt.Fprintf(&sb, "$Check%s = %s; $Desired%s = %d\n", name, ntpBoolLiteral(check), name, v)
	}
	if in.SpecialPollIntervalSeconds != nil {
		writeCheck("Poll", *in.SpecialPollIntervalSeconds, true)
	} else {
		writeCheck("Poll", 0, false)
	}
	writeCheck("Announce", announce, checkAnnounce)
	if in.NtpServerEnabled != nil {
		fmt.Fprintf(&sb, "$CheckServerEnabled = %s; $DesiredServerEnabled = %s\n",
			ntpBoolLiteral(true), ntpBoolLiteral(*in.NtpServerEnabled))
	} else {
		fmt.Fprintf(&sb, "$CheckServerEnabled = %s; $DesiredServerEnabled = %s\n",
			ntpBoolLiteral(false), ntpBoolLiteral(false))
	}
	if in.MaxPosPhaseCorrectionSeconds != nil {
		writeCheck("MaxPos", *in.MaxPosPhaseCorrectionSeconds, true)
	} else {
		writeCheck("MaxPos", 0, false)
	}
	if in.MaxNegPhaseCorrectionSeconds != nil {
		writeCheck("MaxNeg", *in.MaxNegPhaseCorrectionSeconds, true)
	} else {
		writeCheck("MaxNeg", 0, false)
	}
	return sb.String(), nil
}

// buildNTPSetBlock renders the Set-ItemProperty lines covering exactly the
// configured inputs (partial management): nil fields are omitted so the
// host value is left untouched. Type is always written (Required).
func buildNTPSetBlock(in NTPInput) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "    Set-ItemProperty -Path $ParamsPath -Name Type -Value %s -Type String -ErrorAction Stop\n", psQuote(in.Type))
	if len(in.Servers) > 0 {
		raw, err := BuildNtpServerString(in.Servers)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "    Set-ItemProperty -Path $ParamsPath -Name NtpServer -Value %s -Type String -ErrorAction Stop\n", psQuote(raw))
	}
	if in.SpecialPollIntervalSeconds != nil {
		fmt.Fprintf(&sb, "    Set-ItemProperty -Path $NtpClientPath -Name SpecialPollInterval -Value %d -Type DWord -ErrorAction Stop\n", *in.SpecialPollIntervalSeconds)
	}
	if in.AnnounceFlags != nil {
		fmt.Fprintf(&sb, "    Set-ItemProperty -Path $ConfigPath -Name AnnounceFlags -Value %d -Type DWord -ErrorAction Stop\n", *in.AnnounceFlags)
	} else if in.Reliable != nil {
		fmt.Fprintf(&sb, "    Set-ItemProperty -Path $ConfigPath -Name AnnounceFlags -Value %d -Type DWord -ErrorAction Stop\n", NTPAnnounceFlagsFromReliable(*in.Reliable))
	}
	if in.NtpServerEnabled != nil {
		v := 0
		if *in.NtpServerEnabled {
			v = 1
		}
		fmt.Fprintf(&sb, "    Set-ItemProperty -Path $NtpServerPath -Name Enabled -Value %d -Type DWord -ErrorAction Stop\n", v)
	}
	if in.MaxPosPhaseCorrectionSeconds != nil {
		fmt.Fprintf(&sb, "    Set-ItemProperty -Path $ConfigPath -Name MaxPosPhaseCorrection -Value %d -Type DWord -ErrorAction Stop\n", *in.MaxPosPhaseCorrectionSeconds)
	}
	if in.MaxNegPhaseCorrectionSeconds != nil {
		fmt.Fprintf(&sb, "    Set-ItemProperty -Path $ConfigPath -Name MaxNegPhaseCorrection -Value %d -Type DWord -ErrorAction Stop\n", *in.MaxNegPhaseCorrectionSeconds)
	}
	return sb.String(), nil
}

// runNTPEnvelope executes script (prepended with psNTPHeader) and parses
// the JSON envelope through the shared runEnvelope helper. Transport /
// cancellation errors that bypass Emit-Err are mapped to NTPErrorTimeout
// equivalents (service_unavailable is never synthesized here: a missing
// envelope means the transport failed, not the service). Caller-supplied
// baseCtx entries (e.g. the desired type) are preserved alongside the
// connection identity.
func (n *NTPClient) runNTPEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*ntpPSResponse, error) {
	baseContext := map[string]string{
		"host":      n.c.cfg.Host,
		"port":      fmt.Sprintf("%d", n.c.cfg.Port),
		"transport": "ssh",
	}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, n.c, full)
		},
		op, psNTPHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		kind := NTPErrorKind(NTPErrorUnknown)
		if eerr.Stage == EnvelopeStageTimeout {
			return nil, NewNTPError(kind,
				fmt.Sprintf("operation %q on W32Time timed out or was cancelled", op),
				eerr.Cause, eerr.Context)
		}
		return nil, NewNTPError(kind, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewNTPError(mapNTPKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapNTPKind translates a PS-side "kind" string to a typed NTPErrorKind.
// Unknown values fall through to NTPErrorUnknown.
func mapNTPKind(k string) NTPErrorKind {
	switch k {
	case string(NTPErrorServiceUnavailable),
		string(NTPErrorAccessDenied),
		string(NTPErrorInvalidPeer):
		return NTPErrorKind(k)
	default:
		return NTPErrorUnknown
	}
}

// ntpPayloadToState projects an ntpStatePayload onto the public NTPState.
// A host NtpServer value that fails the pure-Go parse fails closed: the
// provider must not manage a value it cannot round-trip.
func ntpPayloadToState(p ntpStatePayload) (*NTPState, error) {
	var peers []NTPPeer
	if strings.TrimSpace(p.NtpServer) != "" {
		parsed, err := ParseNtpServerString(p.NtpServer)
		if err != nil {
			return nil, NewNTPError(NTPErrorUnknown,
				fmt.Sprintf("failed to parse host NtpServer value %q", p.NtpServer), err,
				map[string]string{"ntp_server": p.NtpServer})
		}
		peers = parsed
	}
	return &NTPState{
		MachineID:                    p.MachineID,
		Type:                         p.Type,
		Servers:                      peers,
		SpecialPollIntervalSeconds:   p.SpecialPollInterval,
		Reliable:                     p.Reliable,
		AnnounceFlags:                p.AnnounceFlags,
		NtpServerEnabled:             p.NtpServerEnabled,
		MaxPosPhaseCorrectionSeconds: p.MaxPosPhaseCorrection,
		MaxNegPhaseCorrectionSeconds: p.MaxNegPhaseCorrection,
		CurrentSource:                p.CurrentSource,
		PolicyOverride:               p.PolicyOverride,
		DomainJoined:                 p.DomainJoined,
		VmICEnabled:                  p.VmICEnabled,
		ResyncWarning:                p.ResyncWarning,
	}, nil
}

// readState runs Read-NTPState and parses the response.
func (n *NTPClient) readState(ctx context.Context, op string) (*NTPState, error) {
	resp, err := n.runNTPEnvelope(ctx, op, ntpReadBody, nil)
	if err != nil {
		return nil, err
	}
	var p ntpStatePayload
	if jerr := json.Unmarshal(resp.Data, &p); jerr != nil {
		return nil, NewNTPError(NTPErrorUnknown,
			fmt.Sprintf("failed to parse W32Time state from %q", op), jerr,
			map[string]string{"host": n.c.cfg.Host})
	}
	return ntpPayloadToState(p)
}

// Read returns the currently configured W32Time time-source state.
func (n *NTPClient) Read(ctx context.Context) (*NTPState, error) {
	return n.readState(ctx, "read")
}

// Set writes the configured registry values (Type always; every other
// value only when its input field is set), ensures the W32Time service when
// asked, runs w32tm /config /update, optionally resyncs, then verifies by
// re-reading and returns the freshly observed state. A resync failure is
// recorded on the returned state's ResyncWarning field — never returned as
// an error.
func (n *NTPClient) Set(ctx context.Context, input NTPInput) (*NTPState, error) {
	if err := ValidateNTPInput(input); err != nil {
		return nil, err
	}

	desired, err := buildNTPDesiredBlock(input)
	if err != nil {
		return nil, err
	}
	setBlock, err := buildNTPSetBlock(input)
	if err != nil {
		return nil, err
	}
	script := strings.NewReplacer(
		"@@DESIRED@@", desired,
		"@@SETBLOCK@@", setBlock,
	).Replace(ntpSetBody)

	resp, err := n.runNTPEnvelope(ctx, "set", script, map[string]string{"type": input.Type})
	if err != nil {
		return nil, err
	}
	var p ntpStatePayload
	if jerr := json.Unmarshal(resp.Data, &p); jerr != nil {
		return nil, NewNTPError(NTPErrorUnknown,
			"failed to parse W32Time state after Set", jerr,
			map[string]string{"host": n.c.cfg.Host})
	}
	return ntpPayloadToState(p)
}
