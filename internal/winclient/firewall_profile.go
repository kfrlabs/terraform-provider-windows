// Package winclient - FirewallProfileClient is the concrete
// WindowsFirewallProfileClient backed by PowerShell over SSH.
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted
//     PowerShell literal with embedded single-quotes doubled); no raw
//     concatenation of user input into PS scripts.
//   - DisabledInterfaceAliases renders through psQuoteList; no raw injection.
//   - No credentials are written to FirewallProfileError.Message or Context.
//
// Reused helpers from the same package:
//   - psQuote, psQuoteList      - safe PS string/array literals (psquote.go)
//   - runEnvelope               - shared JSON envelope pipeline (envelope.go)
//   - runPowerShell             - package-level hook, stubbed in tests
//   - psResponse                - Emit-OK / Emit-Err JSON envelope (service.go)
//   - sshProfilePSFragment      - shared SSH-profile resolution (sshpath.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Compile-time assertion: FirewallProfileClient satisfies WindowsFirewallProfileClient.
var _ WindowsFirewallProfileClient = (*FirewallProfileClient)(nil)

// FirewallProfileClient is the PowerShell/SSH-backed WindowsFirewallProfileClient.
type FirewallProfileClient struct {
	c *Client
}

// NewFirewallProfileClient constructs a FirewallProfileClient wrapping the given SSH Client.
func NewFirewallProfileClient(c *Client) *FirewallProfileClient {
	return &FirewallProfileClient{c: c}
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// fpPsHeader is prepended to every firewall-profile PS script.
// It pins the session culture to InvariantCulture so enum .ToString() values
// are always English regardless of the host locale, and defines the shared
// Emit-OK / Emit-Err / Classify-FirewallProfile helpers.
//
// Note: Go raw-string literals (backtick-delimited) must not contain PS
// backtick sequences (`n, `t). None are needed here; single-quoted PS
// literals avoid all expansion.
const fpPsHeader = psEnvelopePrelude + fpPsHeaderRemainder

// fpPsHeaderRemainder Classify + profile bodies stay here; envelope emitters come from the prelude. Emit depth 10->8: payloads are flat profile dicts. Gains WarningPreference (suppression only).
const fpPsHeaderRemainder = `
function Classify-FirewallProfile([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'MpsSvc' -or $msg -match 'Windows Firewall service') {
    return 'firewall_service_unavailable'
  }
  if ($msg -match 'Access is denied' -or
      $msg -match 'PermissionDenied' -or
      $msg -match 'UnauthorizedAccess' -or
      $msg -match 'Unauthorized') {
    return 'access_denied'
  }
  if ($msg -match 'No MSFT_NetFirewallProfile' -or
      $msg -match 'Invalid profile' -or
      $msg -match 'InvalidProfile' -or
      $msg -match 'Cannot validate argument on parameter .Name.') {
    return 'invalid_profile'
  }
  return 'unknown'
}

function Test-FirewallPortCovers([object]$FilterPorts, [int]$WantPort) {
  foreach ($entry in @($FilterPorts)) {
    $token = [string]$entry
    if ($token -eq '' -or $token -eq 'Any' -or $token -eq '*') { return $true }
    foreach ($part in @($token -split ',')) {
      $p = $part.Trim()
      if ($p -eq 'Any' -or $p -eq '*') { return $true }
      if ($p -match '^\d+$' -and [int]$p -eq $WantPort) { return $true }
      if ($p -match '^(\d+)\s*-\s*(\d+)$') {
        $lo = [int]$Matches[1]
        $hi = [int]$Matches[2]
        if ($WantPort -ge $lo -and $WantPort -le $hi) { return $true }
      }
    }
  }
  return $false
}
`

// ---------------------------------------------------------------------------
// Read body
// ---------------------------------------------------------------------------

// fpReadBody reads one firewall profile and emits a normalised state JSON.
// Uses the @@NAME@@ placeholder replaced by buildFirewallProfileReplacer.
const fpReadBody = `
$profileName = @@NAME@@

& {
  try {
    $p = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
  } catch {
    Emit-Err (Classify-FirewallProfile $_) ([string]$_.Exception.Message) @{ profile = $profileName }
    return
  }

  $disabledRaw = @($p.DisabledInterfaceAliases | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' -and $_ -ne 'NotConfigured' })
  if ($null -eq $disabledRaw) { $disabledRaw = @() }

  $state = [ordered]@{
    name                               = [string]$profileName
    enabled                            = [bool]$p.Enabled
    default_inbound_action             = [string]$p.DefaultInboundAction
    default_outbound_action            = [string]$p.DefaultOutboundAction
    allow_inbound_rules                = [string]$p.AllowInboundRules
    allow_local_firewall_rules         = [string]$p.AllowLocalFirewallRules
    allow_local_ipsec_rules            = [string]$p.AllowLocalIPsecRules
    allow_unicast_response_to_multicast = [string]$p.AllowUnicastResponseToMulticast
    notify_on_listen                   = [bool]$p.NotifyOnListen
    log_file_name                      = [string]$p.LogFileName
    log_max_size_kilobytes             = [int64]$p.LogMaxSizeKilobytes
    log_allowed                        = [string]$p.LogAllowed
    log_blocked                        = [string]$p.LogBlocked
    log_ignored                        = [string]$p.LogIgnored
    disabled_interface_aliases         = [array]$disabledRaw
  }
  Emit-OK $state
}
`

// ---------------------------------------------------------------------------
// Apply body (Create and Update share it: profiles always exist)
// ---------------------------------------------------------------------------

// fpApplyBody guards against SSH lockout fail-closed, then writes only the
// configured attributes via Set-NetFirewallProfile -PolicyStore
// PersistentStore, then emits the read-back state.
// Placeholders: @@NAME@@, @@PARAMS@@ (Go-built $params entries, possibly
// empty), @@SSHPORT@@, @@RESULT_INBOUND@@, @@RESULT_ALLOW_INBOUND@@.
// The RESULT_* placeholders carry the effective post-apply values the guard
// reasons about: the configured value when set, otherwise the token
// CURRENT (resolved from $cur inside the script).
const fpApplyBody = `
$profileName = @@NAME@@
$sshPort     = @@SSHPORT@@

& {
  try {
    $cur = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
  } catch {
    Emit-Err (Classify-FirewallProfile $_) ([string]$_.Exception.Message) @{ profile = $profileName; step = 'preflight' }
    return
  }

  # Effective post-apply values: configured values win, otherwise current.
  $wantInbound = @@RESULT_INBOUND@@
  if ($wantInbound -eq 'CURRENT') { $wantInbound = [string]$cur.DefaultInboundAction }
  $wantAllowInbound = @@RESULT_ALLOW_INBOUND@@
  if ($wantAllowInbound -eq 'CURRENT') { $wantAllowInbound = [string]$cur.AllowInboundRules }

  # A change is risky when inbound would be blocked by default or inbound
  # rules would no longer be honoured.
  $risky = ($wantInbound -eq 'Block') -or ($wantAllowInbound -eq 'False')

  if ($risky) {
    @@SSHPROFILE@@

    if ($null -ne $sshProfileError -and $sshProfileError -ne '') {
      Emit-Err 'would_lock_out' ('Refusing to tighten firewall profile ' + $profileName + ': the change would block inbound traffic or disable inbound rules, and the SSH session profile could not be determined (' + $sshProfileError + '). Nothing was applied.') @{ profile = $profileName; step = 'guard' }
      return
    }

    if ([string]$profileName -eq [string]$sshProfile) {
      # This profile carries the SSH session: an enabled inbound Allow rule
      # for the provider port must exist or this apply severs the session.
      $covered = $false
      try {
        $rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)
        foreach ($r in $rules) {
          $ruleProfiles = @([string]$r.Profile -split ',\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
          $applies = ($ruleProfiles.Count -eq 0)
          foreach ($rp in $ruleProfiles) {
            if ($rp -eq 'Any' -or $rp -eq $sshProfile) { $applies = $true }
          }
          if (-not $applies) { continue }
          foreach ($f in @($r | Get-NetFirewallPortFilter -ErrorAction Stop)) {
            if (([string]$f.Protocol -eq 'TCP' -or [string]$f.Protocol -eq 'Any') -and (Test-FirewallPortCovers $f.LocalPort $sshPort)) {
              $covered = $true
              break
            }
          }
          if ($covered) { break }
        }
      } catch {
        Emit-Err 'would_lock_out' ('Refusing to tighten firewall profile ' + $profileName + ': the change would block inbound traffic or disable inbound rules, and inbound Allow coverage for the SSH port could not be verified (' + [string]$_.Exception.Message + '). Nothing was applied.') @{ profile = $profileName; step = 'guard' }
        return
      }
      if (-not $covered) {
        Emit-Err 'would_lock_out' ('Refusing to tighten firewall profile ' + $profileName + ': the change would block inbound traffic or disable inbound rules on the profile carrying this SSH session, and no enabled inbound Allow TCP rule for port ' + [string]$sshPort + ' covers that profile. Add one with windows_firewall_rule first (for example an OpenSSH-Server-In-TCP style rule), then re-apply. Nothing was applied.') @{ profile = $profileName; step = 'guard'; ssh_profile = [string]$sshProfile; ssh_port = [string]$sshPort }
        return
      }
    }
  }

  @@PARAMS@@

  try {
    Set-NetFirewallProfile @params -ErrorAction Stop
  } catch {
    Emit-Err (Classify-FirewallProfile $_) ([string]$_.Exception.Message) @{ profile = $profileName; step = 'set' }
    return
  }

  try {
    $p = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
  } catch {
    Emit-Err (Classify-FirewallProfile $_) ([string]$_.Exception.Message) @{ profile = $profileName; step = 'readback' }
    return
  }

  $disabledRaw = @($p.DisabledInterfaceAliases | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' -and $_ -ne 'NotConfigured' })
  if ($null -eq $disabledRaw) { $disabledRaw = @() }

  $state = [ordered]@{
    name                               = [string]$profileName
    enabled                            = [bool]$p.Enabled
    default_inbound_action             = [string]$p.DefaultInboundAction
    default_outbound_action            = [string]$p.DefaultOutboundAction
    allow_inbound_rules                = [string]$p.AllowInboundRules
    allow_local_firewall_rules         = [string]$p.AllowLocalFirewallRules
    allow_local_ipsec_rules            = [string]$p.AllowLocalIPsecRules
    allow_unicast_response_to_multicast = [string]$p.AllowUnicastResponseToMulticast
    notify_on_listen                   = [bool]$p.NotifyOnListen
    log_file_name                      = [string]$p.LogFileName
    log_max_size_kilobytes             = [int64]$p.LogMaxSizeKilobytes
    log_allowed                        = [string]$p.LogAllowed
    log_blocked                        = [string]$p.LogBlocked
    log_ignored                        = [string]$p.LogIgnored
    disabled_interface_aliases         = [array]$disabledRaw
  }
  Emit-OK $state
}
`

// ---------------------------------------------------------------------------
// Restore body (Delete with restore_on_destroy)
// ---------------------------------------------------------------------------

// fpRestoreBody re-applies a captured snapshot verbatim.
// Placeholders: @@NAME@@, @@PARAMS@@ (Go-built $params entries covering every
// snapshot field, including NotConfigured tri-states).
const fpRestoreBody = `
$profileName = @@NAME@@

& {
  @@PARAMS@@

  try {
    Set-NetFirewallProfile @params -ErrorAction Stop
  } catch {
    Emit-Err (Classify-FirewallProfile $_) ([string]$_.Exception.Message) @{ profile = $profileName; step = 'restore' }
    return
  }

  try {
    $p = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
  } catch {
    Emit-Err (Classify-FirewallProfile $_) ([string]$_.Exception.Message) @{ profile = $profileName; step = 'readback' }
    return
  }

  $disabledRaw = @($p.DisabledInterfaceAliases | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' -and $_ -ne 'NotConfigured' })
  if ($null -eq $disabledRaw) { $disabledRaw = @() }

  $state = [ordered]@{
    name                               = [string]$profileName
    enabled                            = [bool]$p.Enabled
    default_inbound_action             = [string]$p.DefaultInboundAction
    default_outbound_action            = [string]$p.DefaultOutboundAction
    allow_inbound_rules                = [string]$p.AllowInboundRules
    allow_local_firewall_rules         = [string]$p.AllowLocalFirewallRules
    allow_local_ipsec_rules            = [string]$p.AllowLocalIPsecRules
    allow_unicast_response_to_multicast = [string]$p.AllowUnicastResponseToMulticast
    notify_on_listen                   = [bool]$p.NotifyOnListen
    log_file_name                      = [string]$p.LogFileName
    log_max_size_kilobytes             = [int64]$p.LogMaxSizeKilobytes
    log_allowed                        = [string]$p.LogAllowed
    log_blocked                        = [string]$p.LogBlocked
    log_ignored                        = [string]$p.LogIgnored
    disabled_interface_aliases         = [array]$disabledRaw
  }
  Emit-OK $state
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// firewallProfileValidNames is the closed set of Windows firewall profiles.
var firewallProfileValidNames = []string{"Domain", "Private", "Public"}

// ValidateFirewallProfileName rejects anything but Domain/Private/Public
// (case-insensitive) so typos fail fast without reaching the host.
func ValidateFirewallProfileName(name string) error {
	for _, n := range firewallProfileValidNames {
		if strings.EqualFold(n, name) {
			return nil
		}
	}
	return NewFirewallProfileError(
		FirewallProfileErrorInvalidProfile,
		fmt.Sprintf("invalid firewall profile %q: must be one of Domain, Private, Public", name),
		nil,
		map[string]string{"profile": name},
	)
}

// canonicalFirewallProfileName returns the canonical-cased profile name.
func canonicalFirewallProfileName(name string) string {
	for _, n := range firewallProfileValidNames {
		if strings.EqualFold(n, name) {
			return n
		}
	}
	return name
}

// mapFirewallProfileKind maps a PS-emitted kind string to FirewallProfileErrorKind.
func mapFirewallProfileKind(k string) FirewallProfileErrorKind {
	switch FirewallProfileErrorKind(k) {
	case FirewallProfileErrorInvalidProfile,
		FirewallProfileErrorAccessDenied,
		FirewallProfileErrorWouldLockOut,
		FirewallProfileErrorServiceUnavailable:
		return FirewallProfileErrorKind(k)
	default:
		return FirewallProfileErrorUnknown
	}
}

// buildFirewallProfileReplacer returns a strings.Replacer for the @@NAME@@
// placeholder shared by all firewall-profile PS scripts.
func buildFirewallProfileReplacer(name string) *strings.Replacer {
	return strings.NewReplacer(
		"@@NAME@@", psQuote(name),
	)
}

// psBoolToken renders a Go bool as a PowerShell boolean literal.
func psBoolToken(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// triToken renders a tri-state host spelling as a PowerShell token:
// True/False become booleans, anything else (NotConfigured) stays quoted.
func triToken(v string) string {
	switch v {
	case "True":
		return "$true"
	case "False":
		return "$false"
	default:
		return psQuote(v)
	}
}

// buildFirewallProfileParams constructs the PowerShell $params hashtable
// covering ONLY the configured settings (partial management): nil pointers
// and an unset DisabledInterfaceAliases are omitted so the host value is
// left untouched. The -PolicyStore is always PersistentStore: group policy
// owns ActiveStore and Terraform never writes there.
func buildFirewallProfileParams(name string, s FirewallProfileSettings) string {
	var sb strings.Builder
	sb.WriteString("$params = @{\n")
	fmt.Fprintf(&sb, "  Name        = %s\n", psQuote(name))
	sb.WriteString("  PolicyStore = 'PersistentStore'\n")
	if s.Enabled != nil {
		fmt.Fprintf(&sb, "  Enabled = %s\n", psBoolToken(*s.Enabled))
	}
	if s.DefaultInboundAction != nil {
		fmt.Fprintf(&sb, "  DefaultInboundAction = %s\n", psQuote(*s.DefaultInboundAction))
	}
	if s.DefaultOutboundAction != nil {
		fmt.Fprintf(&sb, "  DefaultOutboundAction = %s\n", psQuote(*s.DefaultOutboundAction))
	}
	if s.AllowInboundRules != nil {
		fmt.Fprintf(&sb, "  AllowInboundRules = %s\n", psBoolToken(*s.AllowInboundRules))
	}
	if s.AllowLocalFirewallRules != nil {
		fmt.Fprintf(&sb, "  AllowLocalFirewallRules = %s\n", psBoolToken(*s.AllowLocalFirewallRules))
	}
	if s.AllowLocalIPsecRules != nil {
		fmt.Fprintf(&sb, "  AllowLocalIPsecRules = %s\n", psBoolToken(*s.AllowLocalIPsecRules))
	}
	if s.AllowUnicastResponseToMulticast != nil {
		fmt.Fprintf(&sb, "  AllowUnicastResponseToMulticast = %s\n", psBoolToken(*s.AllowUnicastResponseToMulticast))
	}
	if s.NotifyOnListen != nil {
		fmt.Fprintf(&sb, "  NotifyOnListen = %s\n", psBoolToken(*s.NotifyOnListen))
	}
	if s.LogFileName != nil {
		fmt.Fprintf(&sb, "  LogFileName = %s\n", psQuote(*s.LogFileName))
	}
	if s.LogMaxSizeKilobytes != nil {
		fmt.Fprintf(&sb, "  LogMaxSizeKilobytes = %d\n", *s.LogMaxSizeKilobytes)
	}
	if s.LogAllowed != nil {
		fmt.Fprintf(&sb, "  LogAllowed = %s\n", psBoolToken(*s.LogAllowed))
	}
	if s.LogBlocked != nil {
		fmt.Fprintf(&sb, "  LogBlocked = %s\n", psBoolToken(*s.LogBlocked))
	}
	if s.LogIgnored != nil {
		fmt.Fprintf(&sb, "  LogIgnored = %s\n", psBoolToken(*s.LogIgnored))
	}
	if s.DisabledInterfaceAliasesSet {
		fmt.Fprintf(&sb, "  DisabledInterfaceAliases = %s\n", psQuoteList(s.DisabledInterfaceAliases))
	}
	sb.WriteString("}")
	return sb.String()
}

// buildFirewallProfileRestoreParams constructs the $params hashtable that
// re-applies a captured snapshot verbatim, including NotConfigured
// tri-states (round-tripped quoted) and the full interface-alias list.
func buildFirewallProfileRestoreParams(name string, snap FirewallProfileState) string {
	var sb strings.Builder
	sb.WriteString("$params = @{\n")
	fmt.Fprintf(&sb, "  Name        = %s\n", psQuote(name))
	sb.WriteString("  PolicyStore = 'PersistentStore'\n")
	fmt.Fprintf(&sb, "  Enabled = %s\n", psBoolToken(snap.Enabled))
	fmt.Fprintf(&sb, "  DefaultInboundAction = %s\n", psQuote(snap.DefaultInboundAction))
	fmt.Fprintf(&sb, "  DefaultOutboundAction = %s\n", psQuote(snap.DefaultOutboundAction))
	fmt.Fprintf(&sb, "  AllowInboundRules = %s\n", triToken(snap.AllowInboundRules))
	fmt.Fprintf(&sb, "  AllowLocalFirewallRules = %s\n", triToken(snap.AllowLocalFirewallRules))
	fmt.Fprintf(&sb, "  AllowLocalIPsecRules = %s\n", triToken(snap.AllowLocalIPsecRules))
	fmt.Fprintf(&sb, "  AllowUnicastResponseToMulticast = %s\n", triToken(snap.AllowUnicastResponseToMulticast))
	fmt.Fprintf(&sb, "  NotifyOnListen = %s\n", psBoolToken(snap.NotifyOnListen))
	fmt.Fprintf(&sb, "  LogFileName = %s\n", psQuote(snap.LogFileName))
	fmt.Fprintf(&sb, "  LogMaxSizeKilobytes = %d\n", snap.LogMaxSizeKilobytes)
	fmt.Fprintf(&sb, "  LogAllowed = %s\n", triToken(snap.LogAllowed))
	fmt.Fprintf(&sb, "  LogBlocked = %s\n", triToken(snap.LogBlocked))
	fmt.Fprintf(&sb, "  LogIgnored = %s\n", triToken(snap.LogIgnored))
	fmt.Fprintf(&sb, "  DisabledInterfaceAliases = %s\n", psQuoteList(snap.DisabledInterfaceAliases))
	sb.WriteString("}")
	return sb.String()
}

// effectiveGuardInputs resolves the post-apply inbound values the guard
// reasons about: the configured value when set, otherwise the CURRENT token
// the script resolves from the live profile.
func effectiveGuardInputs(s FirewallProfileSettings) (inbound, allowInbound string) {
	inbound = "CURRENT"
	if s.DefaultInboundAction != nil {
		inbound = *s.DefaultInboundAction
	}
	allowInbound = "CURRENT"
	if s.AllowInboundRules != nil {
		if *s.AllowInboundRules {
			allowInbound = "True"
		} else {
			allowInbound = "False"
		}
	}
	return inbound, allowInbound
}

// runFirewallProfileEnvelope executes script (prefixed with fpPsHeader) and
// returns the parsed psResponse envelope through the shared runEnvelope
// helper. Transport/PS-level errors that bypass Emit-Err are translated into
// *FirewallProfileError.
func (c *FirewallProfileClient) runFirewallProfileEnvelope(ctx context.Context, op, name, script string) (*psResponse, error) {
	baseContext := map[string]string{"profile": name, "host": c.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, c.c, full)
		},
		op, fpPsHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewFirewallProfileError(
			FirewallProfileErrorUnknown,
			fmt.Sprintf("operation %q on firewall profile %q timed out or was cancelled", op, name),
			eerr.Cause,
			eerr.Context,
		)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewFirewallProfileError(
			FirewallProfileErrorUnknown,
			eerr.Message,
			eerr.Cause,
			eerr.Context,
		)
	}
	return resp, NewFirewallProfileError(mapFirewallProfileKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// ---------------------------------------------------------------------------
// fpStateJSON - mirrors the JSON emitted by the read/readback bodies
// ---------------------------------------------------------------------------

type fpStateJSON struct {
	Name                            string          `json:"name"`
	Enabled                         bool            `json:"enabled"`
	DefaultInboundAction            string          `json:"default_inbound_action"`
	DefaultOutboundAction           string          `json:"default_outbound_action"`
	AllowInboundRules               string          `json:"allow_inbound_rules"`
	AllowLocalFirewallRules         string          `json:"allow_local_firewall_rules"`
	AllowLocalIPsecRules            string          `json:"allow_local_ipsec_rules"`
	AllowUnicastResponseToMulticast string          `json:"allow_unicast_response_to_multicast"`
	NotifyOnListen                  bool            `json:"notify_on_listen"`
	LogFileName                     string          `json:"log_file_name"`
	LogMaxSizeKilobytes             int64           `json:"log_max_size_kilobytes"`
	LogAllowed                      string          `json:"log_allowed"`
	LogBlocked                      string          `json:"log_blocked"`
	LogIgnored                      string          `json:"log_ignored"`
	DisabledInterfaceAliases        json.RawMessage `json:"disabled_interface_aliases"`
}

// parseFirewallProfileState parses the psResponse.Data field into a
// *FirewallProfileState. Returns (nil, nil) when Data is JSON null.
// DisabledInterfaceAliases tolerates the ConvertTo-Json single-element
// object quirk (bare string instead of an array) plus null/missing.
func parseFirewallProfileState(resp *psResponse, name string) (*FirewallProfileState, error) {
	if resp.Data == nil || string(resp.Data) == "null" {
		return nil, nil
	}
	var j fpStateJSON
	if err := json.Unmarshal(resp.Data, &j); err != nil {
		return nil, NewFirewallProfileError(
			FirewallProfileErrorUnknown,
			"failed to parse firewall profile state JSON",
			err,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	aliases, err := parseFirewallProfileAliases(j.DisabledInterfaceAliases)
	if err != nil {
		return nil, err
	}
	profile := j.Name
	if profile == "" {
		profile = name
	}
	return &FirewallProfileState{
		Name:                            canonicalFirewallProfileName(profile),
		Enabled:                         j.Enabled,
		DefaultInboundAction:            j.DefaultInboundAction,
		DefaultOutboundAction:           j.DefaultOutboundAction,
		AllowInboundRules:               j.AllowInboundRules,
		AllowLocalFirewallRules:         j.AllowLocalFirewallRules,
		AllowLocalIPsecRules:            j.AllowLocalIPsecRules,
		AllowUnicastResponseToMulticast: j.AllowUnicastResponseToMulticast,
		NotifyOnListen:                  j.NotifyOnListen,
		LogFileName:                     j.LogFileName,
		LogMaxSizeKilobytes:             j.LogMaxSizeKilobytes,
		LogAllowed:                      j.LogAllowed,
		LogBlocked:                      j.LogBlocked,
		LogIgnored:                      j.LogIgnored,
		DisabledInterfaceAliases:        aliases,
	}, nil
}

// parseFirewallProfileAliases decodes the disabled_interface_aliases blob,
// tolerating null, a bare string (single-element ConvertTo-Json quirk) and
// an array, and filtering the "NotConfigured" sentinel the host reports when
// no interface is excluded.
func parseFirewallProfileAliases(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []string{}, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	var items []string
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &items); err != nil {
			// A single-element array may arrive as ["x"]; fall through to the
			// single-string attempt for anything else shaped.
			var single string
			if serr := json.Unmarshal(raw, &single); serr != nil {
				return nil, NewFirewallProfileError(
					FirewallProfileErrorUnknown,
					"failed to parse disabled interface aliases",
					err,
					nil,
				)
			}
			items = []string{single}
		}
	} else {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			var n json.Number
			if nerr := json.Unmarshal(raw, &n); nerr != nil {
				return nil, NewFirewallProfileError(
					FirewallProfileErrorUnknown,
					"failed to parse disabled interface aliases",
					err,
					nil,
				)
			}
			items = []string{n.String()}
		} else {
			items = []string{single}
		}
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		t := strings.TrimSpace(it)
		if t == "" || strings.EqualFold(t, "NotConfigured") {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// SSHProfile
// ---------------------------------------------------------------------------

// fpSSHProfileBody resolves the profile carrying the current SSH session.
// Emits Emit-OK with the profile name, or Emit-Err 'unknown' fail-closed
// when it cannot be determined.
const fpSSHProfileBody = `
& {
  @@SSHPROFILE@@

  if ([string]::IsNullOrWhiteSpace($sshProfile)) {
    if ([string]::IsNullOrWhiteSpace($sshProfileError)) {
      $sshProfileError = 'could not determine the SSH session profile'
    }
    Emit-Err 'unknown' $sshProfileError @{ step = 'ssh_profile' }
    return
  }
  Emit-OK $sshProfile
}
`

// SSHProfile resolves which firewall profile carries the provider's own SSH
// session. A resolution failure is a typed unknown error (fail closed).
func (c *FirewallProfileClient) SSHProfile(ctx context.Context) (string, error) {
	script := strings.NewReplacer(
		"@@SSHPROFILE@@", sshProfilePSFragment,
	).Replace(fpSSHProfileBody)

	resp, err := c.runFirewallProfileEnvelope(ctx, "SSHProfile", "", script)
	if err != nil {
		return "", err
	}
	if resp.Data == nil || string(resp.Data) == "null" {
		return "", NewFirewallProfileError(
			FirewallProfileErrorUnknown,
			"could not determine the SSH session profile: empty response",
			nil,
			nil,
		)
	}
	var profile string
	if uerr := json.Unmarshal(resp.Data, &profile); uerr != nil {
		return "", NewFirewallProfileError(
			FirewallProfileErrorUnknown,
			"failed to parse SSH session profile JSON",
			uerr,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	if err := ValidateFirewallProfileName(profile); err != nil {
		return "", NewFirewallProfileError(
			FirewallProfileErrorUnknown,
			fmt.Sprintf("SSH session profile %q is not a known firewall profile", profile),
			nil,
			map[string]string{"profile": profile},
		)
	}
	return canonicalFirewallProfileName(profile), nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read retrieves the current state of the named firewall profile using
// Get-NetFirewallProfile. Returns (nil, nil) when the host reports no data
// (invalid names are rejected client-side by ValidateFirewallProfileName, so
// this only happens on genuinely unexpected responses).
func (c *FirewallProfileClient) Read(ctx context.Context, name string) (*FirewallProfileState, error) {
	if err := ValidateFirewallProfileName(name); err != nil {
		return nil, err
	}
	canonical := canonicalFirewallProfileName(name)
	script := buildFirewallProfileReplacer(canonical).Replace(fpReadBody)
	resp, err := c.runFirewallProfileEnvelope(ctx, "Read", canonical, script)
	if err != nil {
		return nil, err
	}
	st, perr := parseFirewallProfileState(resp, canonical)
	if perr != nil {
		return nil, perr
	}
	if st == nil {
		return nil, NewFirewallProfileError(
			FirewallProfileErrorInvalidProfile,
			fmt.Sprintf("firewall profile %q was not found on the target host", canonical),
			nil,
			map[string]string{"profile": canonical},
		)
	}
	return st, nil
}

// ---------------------------------------------------------------------------
// Apply (Create and Update share it: profiles always exist)
// ---------------------------------------------------------------------------

// Apply writes only the configured settings to the named profile after the
// SSH lockout guard passes, then returns the read-back state. When no
// setting is configured it short-circuits to Read (nothing to guard, nothing
// to write).
func (c *FirewallProfileClient) Apply(ctx context.Context, name string, settings FirewallProfileSettings) (*FirewallProfileState, error) {
	if err := ValidateFirewallProfileName(name); err != nil {
		return nil, err
	}
	canonical := canonicalFirewallProfileName(name)
	if !settings.FirewallProfileConfigured() {
		return c.Read(ctx, canonical)
	}
	inbound, allowInbound := effectiveGuardInputs(settings)
	quoted := func(v string) string {
		if v == "CURRENT" {
			return "'CURRENT'"
		}
		return psQuote(v)
	}
	script := strings.NewReplacer(
		"@@NAME@@", psQuote(canonical),
		"@@SSHPORT@@", strconv.Itoa(sshProviderPort(c.c.cfg.Port)),
		"@@SSHPROFILE@@", sshProfilePSFragment,
		"@@RESULT_INBOUND@@", quoted(inbound),
		"@@RESULT_ALLOW_INBOUND@@", quoted(allowInbound),
		"@@PARAMS@@", buildFirewallProfileParams(canonical, settings),
	).Replace(fpApplyBody)

	resp, err := c.runFirewallProfileEnvelope(ctx, "Apply", canonical, script)
	if err != nil {
		return nil, err
	}
	return parseFirewallProfileState(resp, canonical)
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

// Restore re-applies a previously captured snapshot verbatim (Delete with
// restore_on_destroy), then returns the read-back state.
func (c *FirewallProfileClient) Restore(ctx context.Context, snapshot FirewallProfileState) (*FirewallProfileState, error) {
	if err := ValidateFirewallProfileName(snapshot.Name); err != nil {
		return nil, err
	}
	canonical := canonicalFirewallProfileName(snapshot.Name)
	script := strings.NewReplacer(
		"@@NAME@@", psQuote(canonical),
		"@@PARAMS@@", buildFirewallProfileRestoreParams(canonical, snapshot),
	).Replace(fpRestoreBody)

	resp, err := c.runFirewallProfileEnvelope(ctx, "Restore", canonical, script)
	if err != nil {
		return nil, err
	}
	return parseFirewallProfileState(resp, canonical)
}
