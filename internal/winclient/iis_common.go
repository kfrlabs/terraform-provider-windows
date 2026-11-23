// Package winclient: shared IIS prerequisites for the windows_iis_* resources.
//
// This file owns Deliverable A of issue #283: the PowerShell prelude injected
// in every IIS script, the shared Classify-IIS fragment, and the Go helpers
// for IIS TimeSpan conversion, pool-name validation and the
// applicationHost.config concurrent-writer retry.
//
// Security invariants:
//   - User-supplied values are interpolated only through psQuote
//     (single-quoted PS literal). Cmdlet -Name parameters that accept
//     wildcards are never fed raw user input: lookups filter with
//     Where-Object { $_.Name -eq <psQuote> } (same rule as
//     windows_net_ip_address). App-pool names additionally cannot contain
//     wildcard characters (* ? [ ]) per ValidateIISAppPoolName, so a -Name
//     use after a literal lookup cannot expand.
//   - Secrets (SpecificUser passwords) travel on stdin via
//     RunPowerShellWithInput and never appear in script text, error messages
//     or diagnostic context.
package winclient

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// psIISHeader is prepended to every IIS script. It pins the session culture
// to InvariantCulture so enum .ToString() values stay English regardless of
// the host locale, and defines the shared Emit-OK / Emit-Err / Classify-IIS
// helpers plus Ensure-IIS.
//
// Ensure-IIS detects the IIS installation (W3SVC/WAS services plus the
// WebAdministration module) and imports the module idempotently: the
// persistent session (#81) may already have it loaded. A missing IIS emits
// an iis_not_installed envelope with a hint pointing at windows_feature
// (Web-Server, plus Web-Mgmt-Console / Web-Scripting-Tools for the module on
// Server Core) and returns $false instead of exiting the process, so the
// shared session survives. Callers must check the return value and stop.
//
// NOTE: this constant uses a Go raw string (backtick-delimited). PowerShell
// backtick escape sequences (`n, `t) MUST NOT appear in this body.
const psIISHeader = psEnvelopePrelude + psClassifyPrelude + psIISHeaderRemainder

// psIISHeaderRemainder Shared IIS header: Classify-IIS + Ensure-IIS stay here; envelope emitters come from the prelude. Emit depth 10->8: app-pool/site payloads are flat dicts.
const psIISHeaderRemainder = `
function Classify-IIS([string]$Msg) {
  return (Classify-ByPatterns $Msg @(
    @('0x8007052e|unknown user name or bad password|Logon failure', 'invalid_identity'),
    @('Access is denied|AccessDenied|UnauthorizedAccess|0x80070005', 'access_denied'),
    @('0x800700b7|already exists', 'already_exists'),
    @('0x80070002|was not found|Cannot find path', 'not_found'),
    @('0x80070021|locked|Cannot read configuration file', 'config_locked')
  ))
}

function Ensure-IIS {
  # Returns $false (after Emit-Err) instead of exiting the process: since
  # #81 scripts may run inside a long-lived, reused PowerShell session,
  # where "exit" would kill that session instead of just this call. Callers
  # must check the return value and stop rather than fall through to the
  # WebAdministration cmdlets, which would otherwise overwrite the JSON
  # envelope already emitted here with a second, less specific error.
  $hint = 'IIS is not installed on this host. Install it with the windows_feature resource (Web-Server; add Web-Mgmt-Console / Web-Scripting-Tools for the WebAdministration module on Server Core).'
  $svc = Get-Service W3SVC,WAS -ErrorAction SilentlyContinue
  if (-not $svc -or @($svc).Count -lt 2) {
    Emit-Err 'iis_not_installed' $hint @{ reason = 'missing_service' }
    return $false
  }
  if (-not (Get-Module -ListAvailable WebAdministration)) {
    Emit-Err 'iis_not_installed' ($hint + ' The WebAdministration module was not found.') @{ reason = 'missing_module' }
    return $false
  }
  try {
    Import-Module WebAdministration -ErrorAction Stop
  } catch {
    Emit-Err 'iis_not_installed' ($hint + ' Import-Module WebAdministration failed: ' + [string]$_.Exception.Message) @{ reason = 'import_failed' }
    return $false
  }
  return $true
}
`

// runIISPowerShell is the package-level indirection used by the IIS clients.
// Tests may override it; production code must not. It always runs in a
// one-shot Windows PowerShell 5.1 process: the WebAdministration module (and
// its IIS: drive) is not discoverable from the persistent pwsh 7 session, so
// on any host with pwsh installed every IIS call would otherwise fail with
// iis_not_installed/missing_module despite IIS being present (same class of
// limitation as Invoke-DscResource, see RunPowerShell5WithInput).
var runIISPowerShell = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	return c.RunPowerShell5WithInput(ctx, script, stdin)
}

// ---------------------------------------------------------------------------
// IIS TimeSpan <-> Terraform minutes
// ---------------------------------------------------------------------------

// iisTimeSpanRe parses IIS TimeSpan strings: [d.]hh:mm:ss[.fffffff], the
// format .NET serialises TimeSpan values in (e.g. "00:20:00", "1.00:00:00").
var iisTimeSpanRe = regexp.MustCompile(`^(?:(\d+)\.)?(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?$`)

// IISTimeSpanToMinutes parses an IIS TimeSpan string ([d.]hh:mm:ss) into
// whole Terraform minutes. Sub-minute remainders truncate toward zero:
// server-side reads normalise through this same rule, so a value IIS reports
// with seconds (e.g. a schedule-adjacent "00:19:59") maps deterministically.
func IISTimeSpanToMinutes(s string) (int64, error) {
	m := iisTimeSpanRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("invalid IIS TimeSpan %q: want [d.]hh:mm:ss", s)
	}
	days, _ := strconv.ParseInt(m[1], 10, 64)
	hours, _ := strconv.ParseInt(m[2], 10, 64)
	mins, _ := strconv.ParseInt(m[3], 10, 64)
	secs, _ := strconv.ParseInt(m[4], 10, 64)
	if hours > 23 {
		return 0, fmt.Errorf("invalid IIS TimeSpan %q: hours out of range", s)
	}
	return days*24*60 + hours*60 + mins + secs/60, nil
}

// IISMinutesToTimeSpan renders whole Terraform minutes as an IIS TimeSpan
// string the WebAdministration provider accepts ([d.]hh:mm:ss). Values of
// 24h or more carry the day component (e.g. 1500 minutes -> "1.01:00:00").
func IISMinutesToTimeSpan(minutes int64) string {
	if minutes < 0 {
		minutes = 0
	}
	d := minutes / (24 * 60)
	h := (minutes % (24 * 60)) / 60
	m := minutes % 60
	if d > 0 {
		return fmt.Sprintf("%d.%02d:%02d:00", d, h, m)
	}
	return fmt.Sprintf("%02d:%02d:00", h, m)
}

// ---------------------------------------------------------------------------
// Pool-name validation (defence in depth; the provider schema enforces this
// at plan time first)
// ---------------------------------------------------------------------------

// iisAppPoolForbiddenChars are the characters IIS rejects in pool names and
// the wildcard characters PowerShell -Name parameters would expand.
const iisAppPoolForbiddenChars = `/\[]:;,?*"<>|`

// isControlRune reports whether r is a C0 control or DEL: characters that
// can never appear in an IIS, DNS or NTP name and that would truncate (NUL)
// or corrupt (CR/LF in XML config) the value if they reached the host.
func isControlRune(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// ValidateIISAppPoolName rejects names IIS cannot carry: anything outside
// 1-64 characters, the forbidden / \ [ ] : ; , ? * " < > | set (which also
// keeps wildcard expansion impossible), leading/trailing spaces, and control
// characters (NUL/CR/LF would truncate or corrupt the applicationHost.config
// XML entry at apply time, so they fail fast here instead).
func ValidateIISAppPoolName(name string) error {
	if len(name) < 1 || len(name) > 64 {
		return fmt.Errorf("invalid IIS application pool name %q: must be 1-64 characters", name)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("invalid IIS application pool name %q: must not have leading or trailing spaces", name)
	}
	if strings.ContainsAny(name, iisAppPoolForbiddenChars) {
		return fmt.Errorf("invalid IIS application pool name %q: must not contain any of / \\ [ ] : ; , ? * \" < > |", name)
	}
	if strings.IndexFunc(name, isControlRune) >= 0 {
		return fmt.Errorf("invalid IIS application pool name %q: must not contain control characters", name)
	}
	return nil
}

// psEscapeWildcard prefixes PowerShell wildcard characters with the
// backtick escape so a user value can be passed to a -Name parameter that
// accepts wildcards without expansion. App-pool names cannot contain these
// characters (ValidateIISAppPoolName), so for valid names this is a no-op;
// it keeps invalid or future names from expanding.
var psWildcardEscaper = strings.NewReplacer(
	"[", "`[",
	"]", "`]",
	"*", "`*",
	"?", "`?",
)

// psEscapeWildcard escapes the PowerShell wildcard characters in s.
func psEscapeWildcard(s string) string { return psWildcardEscaper.Replace(s) }

// ---------------------------------------------------------------------------
// applicationHost.config concurrent-writer retry
// ---------------------------------------------------------------------------

// IISConfigChangedOnDisk reports whether a remote failure message is the
// known applicationHost.config concurrent-writer flake ("Cannot commit
// configuration changes because the file has changed on disk"). Both halves
// of the signature are required (case-insensitive): matching on the
// "file has changed on disk" tail alone would let a pool name containing
// that phrase (interpolated into the message) trigger a spurious retry.
// Only this specific error is retried; every other failure surfaces
// immediately.
func IISConfigChangedOnDisk(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "cannot commit configuration changes") &&
		strings.Contains(lower, "file has changed on disk")
}

// IISConcurrentWriteNullReference reports whether a remote failure message is
// the known applicationHost.config concurrent-writer NullReference flake
// ("Object reference not set to an instance of an object") raised
// transiently by the WebAdministration cmdlets when concurrent one-shot
// powershell.exe writers race on the file (F08). The match is
// case-insensitive; the IIS NullReference carries no second signature half,
// so callers must additionally require the unknown error kind (a pool
// literally named like the phrase surfaces as already_exists with the name
// interpolated, never as unknown) and must only consult this on write paths,
// so a genuine read-side null-ref still surfaces instead of being retried as
// config_locked.
func IISConcurrentWriteNullReference(msg string) bool {
	return strings.Contains(strings.ToLower(msg), "object reference not set to an instance of an object")
}

// iisWriteMaxAttempts bounds the retry loop for IIS writes.
const iisWriteMaxAttempts = 3

// iisRetryBackoff is the pause before retry attempt n (1-based). A variable
// so unit tests can stub it to zero; production backoff stays short.
var iisRetryBackoff = func(attempt int) time.Duration {
	return time.Duration(attempt) * 200 * time.Millisecond
}
