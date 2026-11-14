// Package winclient: Windows system time zone management over SSH.
//
// TimezoneClient is the concrete WindowsTimezoneClient backing the
// windows_timezone Terraform resource and data source. All operations
// execute PowerShell scripts wrapped in a JSON envelope (Emit-OK/Emit-Err)
// so stdout is machine-parseable regardless of the Windows locale.
//
// Security invariants:
//   - User-supplied zone IDs are interpolated only via psQuote
//     (single-quoted PS literal) so $var / backtick / subexpression
//     injection is impossible.
//   - All scripts are sent via -EncodedCommand by Client.RunPowerShell.
//   - tzutil.exe failures are gated on $LASTEXITCODE (never on localized
//     stdout), and the synthesized error text carries an
//     invalid-timezone marker so Classify-Timezone maps it correctly.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: TimezoneClient satisfies WindowsTimezoneClient.
var _ WindowsTimezoneClient = (*TimezoneClient)(nil)

// TimezoneClient is the PowerShell/SSH-backed WindowsTimezoneClient.
type TimezoneClient struct {
	c *Client
}

// NewTimezoneClient wraps the given SSH Client.
func NewTimezoneClient(c *Client) *TimezoneClient { return &TimezoneClient{c: c} }

// runTimezonePowerShell is the package-level indirection used by
// TimezoneClient. Tests may override it; production code must not.
var runTimezonePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// timezonePSResponse is the JSON envelope produced by Emit-OK/Emit-Err. It
// aliases the shared Envelope type so every resource parses the same shape
// through runEnvelope (#198).
type timezonePSResponse = Envelope

// timezoneStatePayload is the data shape emitted by Read-TimezoneState.
type timezoneStatePayload struct {
	MachineID              string `json:"machine_id"`
	TimezoneID             string `json:"timezone_id"`
	DisplayName            string `json:"display_name"`
	BaseUTCOffset          string `json:"base_utc_offset"`
	SupportsDST            bool   `json:"supports_dst"`
	CurrentUTCOffset       string `json:"current_utc_offset"`
	DaylightSavingDisabled bool   `json:"daylight_saving_disabled"`
	TzautoupdateEnabled    bool   `json:"tzautoupdate_enabled"`
}

// psTimezoneHeader prepends Emit-OK/Emit-Err, Classify-Timezone and the
// Read-TimezoneState projection.
//
// Classify-Timezone maps Set-TimeZone / tzutil / HKLM error records to
// TimezoneErrorKind values. Detection is best-effort and substring-based
// because Windows error messages are localised; the tzutil exit-code path
// synthesizes its own English marker text (see Set) so it still classifies.
//
// Read-TimezoneState reflects the CONFIGURED zone (Get-TimeZone), not the
// live system clock: Set-TimeZone takes effect system-wide immediately, so
// outside the brief apply window they agree. CurrentUTCOffset is the live
// effective offset computed server-side via TimeZoneInfo.GetUtcOffset(now),
// which handles the exact DST delta, formatted in invariant culture as
// "+HH:mm". The session culture is pinned to InvariantCulture so enum and
// TimeSpan stringification stay English on any host locale.
const psTimezoneHeader = psEnvelopePrelude + psTimezoneRemainder

// psTimezoneRemainder Classifier and time-zone bodies stay here; envelope emitters come from the prelude.
const psTimezoneRemainder = `function Classify-Timezone([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  if ($msg -match 'SeTimeZonePrivilege' -or $msg -match 'privilege' -or $msg -match 'Access is denied' -or $msg -match 'AccessDenied' -or $msg -match 'UnauthorizedAccess' -or $msg -match 'Unauthorized') { return 'access_denied' }
  if ($msg -match 'invalid timezone' -or $msg -match 'was not found' -or $msg -match 'not recognized' -or $msg -match 'TZID0001' -or $msg -match 'TimeZoneNotFound') { return 'invalid_timezone' }
  return 'unknown'
}

function Format-TimezoneOffset([TimeSpan]$Ts) {
  $mins = [int]$Ts.TotalMinutes
  $sign = '+'
  if ($mins -lt 0) { $sign = '-'; $mins = -$mins }
  return ('{0}{1:00}:{2:00}' -f $sign, [int]($mins / 60), ($mins % 60))
}

function Get-TimezoneSuggestions([string]$Fragment) {
  try {
    $frag = ('*' + $Fragment + '*')
    return @(Get-TimeZone -ListAvailable | Where-Object { $_.Id -like $frag } | Select-Object -First 5 -ExpandProperty Id)
  } catch { return @() }
}

function Read-TimezoneState {
  $tz   = Get-TimeZone -ErrorAction Stop
  $guid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
  $dsd = $false
  try {
    $v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -Name DynamicDaylightTimeDisabled -ErrorAction Stop).DynamicDaylightTimeDisabled
    $dsd = ([int]$v -eq 1)
  } catch { $dsd = $false }
  $tza = $false
  try {
    $tza = ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name Start -ErrorAction Stop).Start -eq 3)
  } catch { $tza = $false }
  $now = Get-Date
  $cur = $tz.GetUtcOffset($now)
  return [ordered]@{
    machine_id               = [string]$guid
    timezone_id              = [string]$tz.Id
    display_name             = [string]$tz.DisplayName
    base_utc_offset          = (Format-TimezoneOffset $tz.BaseUtcOffset)
    supports_dst             = [bool]$tz.SupportsDaylightSavingTime
    current_utc_offset       = (Format-TimezoneOffset $cur)
    daylight_saving_disabled = [bool]$dsd
    tzautoupdate_enabled     = [bool]$tza
  }
}
`

// runTimezoneEnvelope executes script (prepended with psTimezoneHeader) and
// parses the JSON envelope through the shared runEnvelope helper (#198).
// Transport / cancellation errors that bypass Emit-Err are mapped to
// TimezoneErrorTimeout / TimezoneErrorUnknown. Caller-supplied baseCtx
// entries (e.g. desired timezone_id) are preserved alongside the connection
// identity.
func (t *TimezoneClient) runTimezoneEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*timezonePSResponse, error) {
	baseContext := map[string]string{
		"host":      t.c.cfg.Host,
		"port":      fmt.Sprintf("%d", t.c.cfg.Port),
		"transport": "ssh",
	}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runTimezonePowerShell(ctx, t.c, full)
		},
		op, psTimezoneHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		kind := TimezoneErrorUnknown
		if eerr.Stage == EnvelopeStageTimeout {
			kind = TimezoneErrorTimeout
		}
		return nil, NewTimezoneError(kind, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewTimezoneError(mapTimezoneKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapTimezoneKind translates a PS-side "kind" string to a typed
// TimezoneErrorKind. Unknown values fall through to TimezoneErrorUnknown.
func mapTimezoneKind(k string) TimezoneErrorKind {
	switch k {
	case string(TimezoneErrorInvalidTimezone),
		string(TimezoneErrorAccessDenied),
		string(TimezoneErrorTimeout):
		return TimezoneErrorKind(k)
	default:
		return TimezoneErrorUnknown
	}
}

// timezonePayloadToState projects a timezoneStatePayload onto the public TimezoneState.
func timezonePayloadToState(p timezoneStatePayload) *TimezoneState {
	return &TimezoneState{
		MachineID:                  p.MachineID,
		TimezoneID:                 p.TimezoneID,
		DisplayName:                p.DisplayName,
		BaseUTCOffset:              p.BaseUTCOffset,
		SupportsDaylightSavingTime: p.SupportsDST,
		CurrentUTCOffset:           p.CurrentUTCOffset,
		DaylightSavingDisabled:     p.DaylightSavingDisabled,
		TzautoupdateEnabled:        p.TzautoupdateEnabled,
	}
}

// readState runs Read-TimezoneState and parses the response.
func (t *TimezoneClient) readState(ctx context.Context, op string) (*TimezoneState, error) {
	script := "try { $s = Read-TimezoneState; Emit-OK $s } catch { Emit-Err (Classify-Timezone $_) $_.Exception.Message @{} }"
	resp, err := t.runTimezoneEnvelope(ctx, op, script, nil)
	if err != nil {
		return nil, err
	}
	var p timezoneStatePayload
	if jerr := json.Unmarshal(resp.Data, &p); jerr != nil {
		return nil, NewTimezoneError(TimezoneErrorUnknown,
			fmt.Sprintf("failed to parse time zone state from %q", op), jerr,
			map[string]string{"host": t.c.cfg.Host})
	}
	return timezonePayloadToState(p), nil
}

// validateTimezoneInput rejects empty IDs and IANA-style IDs containing "/"
// (defence-in-depth: the provider schema validator is the primary gate).
func validateTimezoneInput(input TimezoneInput) error {
	if input.TimezoneID == "" {
		return NewTimezoneError(TimezoneErrorInvalidTimezone,
			"timezone_id is empty: provide a Windows time zone ID such as Romance Standard Time", nil,
			map[string]string{"timezone_id": input.TimezoneID})
	}
	if strings.Contains(input.TimezoneID, "/") {
		return NewTimezoneError(TimezoneErrorInvalidTimezone,
			fmt.Sprintf("timezone_id %q contains '/': Windows time zone IDs never contain '/'; IANA IDs such as Europe/Paris are not supported", input.TimezoneID), nil,
			map[string]string{"timezone_id": input.TimezoneID})
	}
	return nil
}

// normalizeTimezoneID strips a trailing "_dstoff" marker (case-insensitive)
// so an observed ID compares equal to the desired ID regardless of whether
// the host reports the DST-disabled spelling.
func normalizeTimezoneID(id string) string {
	if len(id) > 7 && strings.EqualFold(id[len(id)-7:], "_dstoff") {
		return id[:len(id)-7]
	}
	return id
}

// Read returns the currently configured time zone state of the host.
func (t *TimezoneClient) Read(ctx context.Context) (*TimezoneState, error) {
	return t.readState(ctx, "read")
}

// Set configures the system time zone (idempotent when the live zone
// already matches the input) and returns the freshly observed state.
//
// With DaylightSavingDisabled=false the zone is applied with Set-TimeZone;
// with true it is applied with tzutil.exe /s "<id>_dstoff", whose failure
// is gated on $LASTEXITCODE (never on localized stdout) and synthesized
// into an invalid-timezone marker so Classify-Timezone maps it. The script
// verifies by re-reading the state and comparing the (normalized) ID plus
// the DST-disabled flag; a mismatch emits invalid_timezone with up to five
// close-match suggestions.
func (t *TimezoneClient) Set(ctx context.Context, input TimezoneInput) (*TimezoneState, error) {
	if err := validateTimezoneInput(input); err != nil {
		return nil, err
	}

	cur, err := t.readState(ctx, "pre-set-read")
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(normalizeTimezoneID(cur.TimezoneID), input.TimezoneID) &&
		cur.DaylightSavingDisabled == input.DaylightSavingDisabled {
		return cur, nil
	}

	dstFlag := "$false"
	applyStep := "Set-TimeZone -Id $DesiredId -ErrorAction Stop"
	if input.DaylightSavingDisabled {
		dstFlag = "$true"
		applyStep = `& tzutil.exe /s ($DesiredId + '_dstoff')
    if ($LASTEXITCODE -ne 0) { throw ('tzutil.exe rejected time zone ID {0} (exit code {1}); the ID was not found on the host' -f $DesiredId, $LASTEXITCODE) }`
	}
	script := fmt.Sprintf(`
try {
  $DesiredId = %s
  $DstDisabled = %s
  %s
  $s = Read-TimezoneState
  $normObserved = [string]$s.timezone_id
  if ($normObserved -like '*_dstoff') { $normObserved = $normObserved.Substring(0, $normObserved.Length - 7) }
  $idOk = ($normObserved -eq $DesiredId)
  $dstOk = ([bool]$s.daylight_saving_disabled -eq $DstDisabled)
  if (-not ($idOk -and $dstOk)) {
    $sugs = (@(Get-TimezoneSuggestions $DesiredId) -join '; ')
    Emit-Err 'invalid_timezone' ('Time zone change did not take effect: desired {0} (DST disabled: {1}), observed {2} (DST disabled: {3})' -f $DesiredId, $DstDisabled, $s.timezone_id, $s.daylight_saving_disabled) @{ desired = $DesiredId; observed = [string]$s.timezone_id; suggestions = $sugs }
  } else {
    Emit-OK $s
  }
} catch {
  $kind = Classify-Timezone $_
  $ctx = @{ desired = %s }
  if ($kind -eq 'invalid_timezone') {
    $ctx['suggestions'] = (@(Get-TimezoneSuggestions ([string]$ctx['desired'])) -join '; ')
  }
  Emit-Err $kind $_.Exception.Message $ctx
}
`, psQuote(input.TimezoneID), dstFlag, applyStep, psQuote(input.TimezoneID))

	resp, err := t.runTimezoneEnvelope(ctx, "set", script,
		map[string]string{"timezone_id": input.TimezoneID})
	if err != nil {
		return nil, err
	}
	var p timezoneStatePayload
	if jerr := json.Unmarshal(resp.Data, &p); jerr != nil {
		return nil, NewTimezoneError(TimezoneErrorUnknown,
			"failed to parse time zone state after Set-TimeZone", jerr,
			map[string]string{"host": t.c.cfg.Host})
	}
	return timezonePayloadToState(p), nil
}
