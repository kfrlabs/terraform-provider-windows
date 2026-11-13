// Package winclient: IIS site CRUD over SSH.
//
// This file implements WindowsIISSiteClient, the concrete client used by
// the windows_iis_site Terraform resource and data source. All operations
// execute PowerShell scripts (WebAdministration module) wrapped in a JSON
// envelope (Emit-OK/Emit-Err) so stdout is machine-parseable regardless of
// Windows locale.
//
// Bindings are deliberately NOT managed here: the site is always created
// with zero bindings (New-Item -Bindings @(), so no transient *:80:http
// binding ever exists) and the bindings attribute is a read-only view
// (protocol plus binding_information) owned by the
// windows_iis_binding resource (issue #285).
//
// Security invariants:
//   - Site names, paths and every other user-supplied string are
//     interpolated only through psQuote (single-quoted PS literal).
//     Lookups filter with Where-Object { $_.Name -eq $Name } (literal
//     comparison, same rule as windows_net_ip_address); -Name parameters
//     that accept wildcards additionally receive the wildcard-escaped
//     spelling (psEscapeWildcard) — site names cannot contain wildcard
//     characters (ValidateIISSiteName), so this is defence in depth. The
//     XPath [@name="..."] filters use double-quoted literals (safe
//     because " is forbidden by ValidateIISSiteName while ' is allowed:
//     single-quote doubling is invalid in XPath 1.0).
//
// Reused helpers from the same package:
//   - psQuote                  — safe single-quote escaping (psquote.go)
//   - psEscapeWildcard         — backtick-escape of * ? [ ] (iis_common.go)
//   - psIISHeader              — shared prelude, Ensure-IIS, Classify-IIS
//   - IISConfigChangedOnDisk   — concurrent-writer flake detector
//   - iisRetryBackoff          — short retry backoff, stubbed in tests
//   - runEnvelope              — shared JSON envelope pipeline (envelope.go)
//   - runPowerShell            — package-level hook, stubbed in tests
//   - psResponse               — Emit-OK / Emit-Err envelope (service.go)
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Compile-time assertion: IISSiteClient satisfies WindowsIISSiteClient.
var _ WindowsIISSiteClient = (*IISSiteClient)(nil)

// IISSiteClient is the PowerShell/SSH-backed WindowsIISSiteClient.
type IISSiteClient struct {
	c *Client
}

// NewIISSiteClient constructs an IISSiteClient wrapping the given SSH Client.
func NewIISSiteClient(c *Client) *IISSiteClient { return &IISSiteClient{c: c} }

// ---------------------------------------------------------------------------
// PowerShell fragments
// ---------------------------------------------------------------------------

// iisSiteReadFragment defines Get-SiteData, which returns the site as an
// ordered hashtable (or $null when absent). Site attributes come from the
// IIS: provider (serverAutoStart, logFile.*, limits.*); the root
// application attributes (applicationPool, enabledProtocols,
// preloadEnabled) and the root virtual directory physicalPath come from
// the configuration system so the read works even for sites whose
// provider view is partial. limits.connectionTimeout is converted to
// whole seconds server-side to avoid locale formatting. Bindings are
// projected from the live Site object ($site.Bindings: protocol plus
// binding_information) — a literal enumeration, never a wildcard -Name
// lookup — and stay empty for the zero-binding sites this resource
// creates.
const iisSiteReadFragment = `
function Get-SiteData([string]$Name) {
  $site = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
  if (-not $site) { return $null }
  $appFilter = ('system.applicationHost/sites/site[@name="' + $Name + '"]/application[@path=''/']')
  $vdirFilter = ($appFilter + "/virtualDirectory[@path='/']")
  $pool = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $appFilter -Name 'applicationPool' -ErrorAction Stop).Value
  $phys = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $vdirFilter -Name 'physicalPath' -ErrorAction Stop).Value
  $protocols = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $appFilter -Name 'enabledProtocols' -ErrorAction Stop).Value
  $preload = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $appFilter -Name 'preloadEnabled' -ErrorAction Stop).Value
  $sitePath = ('IIS:\Sites\' + $Name)
  $p = Get-ItemProperty $sitePath -ErrorAction Stop
  $bindings = @()
  if ($null -ne $site.Bindings) {
    foreach ($b in @($site.Bindings)) {
      if ($null -eq $b) { continue }
      $bindings += [ordered]@{ protocol = [string]$b.Protocol; binding_information = [string]$b.BindingInformation }
    }
  }
  $state = 'Stopped'
  try { if ([string]$site.State -eq 'Started') { $state = 'Started' } } catch {}
  return [ordered]@{
    name                       = [string]$site.Name
    site_id                    = [int64]$site.ID
    physical_path              = [string]$phys
    application_pool           = [string]$pool
    auto_start                 = [bool]$p.serverAutoStart
    preload_enabled            = [bool]$preload
    enabled_protocols          = [string]$protocols
    log_enabled                = [bool]$p.logFile.enabled
    log_directory              = [string]$p.logFile.directory
    log_format                 = [string]$p.logFile.logFormat
    connection_timeout_seconds = [int64]$p.limits.connectionTimeout.TotalSeconds
    max_connections            = [int64]$p.limits.maxConnections
    bindings                   = [array]$bindings
    state                      = $state
  }
}

function Classify-Site([string]$Msg) {
  $shared = Classify-IIS $Msg
  if ($shared -ne 'unknown') { return $shared }
  return 'unknown'
}
`

// ---------------------------------------------------------------------------
// Set-statement builder (partial management: only configured attrs emitted)
// ---------------------------------------------------------------------------

// buildIISSiteSetStatements renders the configuration writes covering ONLY
// the configured settings. $sitePath, $appFilter and $vdirFilter are script
// variables set by the caller preamble; $PhysicalPath / $AppPool carry the
// configured values when (and only when) they are managed.
func buildIISSiteSetStatements(s IISSiteSettings) string {
	var sb strings.Builder
	if s.PhysicalPath != nil {
		sb.WriteString("  Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $vdirFilter -Name 'physicalPath' -Value $PhysicalPath -ErrorAction Stop\n")
	}
	if s.ApplicationPool != nil {
		sb.WriteString("  Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $appFilter -Name 'applicationPool' -Value $AppPool -ErrorAction Stop\n")
	}
	if s.EnabledProtocols != nil {
		fmt.Fprintf(&sb, "  Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $appFilter -Name 'enabledProtocols' -Value %s -ErrorAction Stop\n", psQuote(*s.EnabledProtocols))
	}
	if s.PreloadEnabled != nil {
		fmt.Fprintf(&sb, "  Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $appFilter -Name 'preloadEnabled' -Value %s -ErrorAction Stop\n", psBoolLiteral(*s.PreloadEnabled))
	}
	if s.AutoStart != nil {
		fmt.Fprintf(&sb, "  Set-ItemProperty $sitePath -Name serverAutoStart -Value %s -ErrorAction Stop\n", psBoolLiteral(*s.AutoStart))
	}
	if s.LogEnabled != nil {
		fmt.Fprintf(&sb, "  Set-ItemProperty $sitePath -Name logFile.enabled -Value %s -ErrorAction Stop\n", psBoolLiteral(*s.LogEnabled))
	}
	if s.LogDirectory != nil {
		fmt.Fprintf(&sb, "  Set-ItemProperty $sitePath -Name logFile.directory -Value %s -ErrorAction Stop\n", psQuote(*s.LogDirectory))
	}
	if s.LogFormat != nil {
		fmt.Fprintf(&sb, "  Set-ItemProperty $sitePath -Name logFile.logFormat -Value %s -ErrorAction Stop\n", psQuote(*s.LogFormat))
	}
	if s.ConnectionTimeoutSeconds != nil {
		fmt.Fprintf(&sb, "  Set-ItemProperty $sitePath -Name limits.connectionTimeout -Value (New-TimeSpan -Seconds %d) -ErrorAction Stop\n", *s.ConnectionTimeoutSeconds)
	}
	if s.MaxConnections != nil {
		fmt.Fprintf(&sb, "  Set-ItemProperty $sitePath -Name limits.maxConnections -Value %d -ErrorAction Stop\n", *s.MaxConnections)
	}
	return sb.String()
}

// buildIISSiteStateStatement renders the runtime-state enforcement lines.
// A nil state emits nothing: the site keeps whatever state the host
// reports. A Started enforcement skips the Start-Website call when the
// site has no bindings: IIS cannot run an unbound site, so the script
// leaves it Stopped instead of failing (the provider layer warns). The
// binding count is re-read from the host rather than trusted from an
// earlier variable so the guard observes the post-write reality.
func buildIISSiteStateStatement(state *string, escapedName string) string {
	if state == nil {
		return ""
	}
	if *state == "Started" {
		return "  $stateCheck = Get-ChildItem 'IIS:\\Sites' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }\n" +
			"  $bindCount = 0\n" +
			"  if ($null -ne $stateCheck.Bindings) { $bindCount = @($stateCheck.Bindings).Count }\n" +
			"  if ($bindCount -gt 0) { Start-Website -Name " + escapedName + " -ErrorAction Stop }\n"
	}
	return "  Stop-Website -Name " + escapedName + " -ErrorAction Stop\n"
}

// iisSitePreamble sets the script variables shared by every mutating
// script: the escaped XPath filters plus the optional $PhysicalPath /
// $AppPool / $SiteId inputs ($null when unmanaged).
func iisSitePreamble() string {
	return `
$appFilter = ('system.applicationHost/sites/site[@name="' + $Name + '"]/application[@path=''/']')
$vdirFilter = ($appFilter + "/virtualDirectory[@path='/']")
`
}

// iisSiteGuardFragment emits the Create/Update pre-flight checks: the
// application pool must exist (app_pool_not_found) and the physical path
// must exist (path_not_found, host-side environment expansion with a
// literal Test-Path, never mkdir). Each check only runs when the
// corresponding value is configured ($null means unmanaged).
const iisSiteGuardFragment = `
if ($null -ne $AppPool) {
  $poolFound = Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop | Where-Object { $_.Name -eq $AppPool }
  if (-not $poolFound) {
    Emit-Err 'app_pool_not_found' ('IIS application pool ''' + $AppPool + ''' does not exist on this host (manage it with the windows_iis_app_pool resource).') @{ name = $Name; application_pool = $AppPool }
    return
  }
}
if ($null -ne $PhysicalPath) {
  $expandedPath = [System.Environment]::ExpandEnvironmentVariables($PhysicalPath)
  if (-not (Test-Path -LiteralPath $expandedPath)) {
    Emit-Err 'path_not_found' ('Physical path ''' + $PhysicalPath + ''' does not exist on this host (manage it with the windows_directory resource; it is never created implicitly).') @{ name = $Name; physical_path = $PhysicalPath }
    return
  }
}
`

// ---------------------------------------------------------------------------
// Envelope runners
// ---------------------------------------------------------------------------

// mapIISSiteKind translates the PS-side kind string to a typed
// IISSiteErrorKind.
func mapIISSiteKind(kind, _ string) IISSiteErrorKind {
	switch IISSiteErrorKind(kind) {
	case IISSiteErrorNotFound,
		IISSiteErrorAlreadyExists,
		IISSiteErrorIDConflict,
		IISSiteErrorAppPoolNotFound,
		IISSiteErrorPathNotFound,
		IISSiteErrorIISNotInstalled,
		IISSiteErrorAccessDenied:
		return IISSiteErrorKind(kind)
	default:
		return IISSiteErrorUnknown
	}
}

// runSiteEnvelope executes script (prefixed with psIISHeader) and parses
// the JSON envelope through the shared runEnvelope helper. Transport and
// parsing failures become IISSiteErrorUnknown; timeouts keep their
// operation-scoped message.
func (a *IISSiteClient) runSiteEnvelope(ctx context.Context, op, name, script string) (*psResponse, error) {
	baseContext := map[string]string{"name": name, "host": a.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, a.c, full)
		},
		op, psIISHeader+"\n"+iisSiteReadFragment+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewIISSiteError(IISSiteErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewIISSiteError(mapIISSiteKind(eerr.RemoteKind, eerr.Message), eerr.Message, nil, eerr.Context)
}

// runSiteWrite executes a mutating script with the concurrent-writer
// retry: only the file-has-changed-on-disk flake is retried (up to
// iisWriteMaxAttempts attempts with backoff); transport errors and every
// other remote failure surface immediately. When the flake persists past
// retries it surfaces as config_locked... but sites have no config_locked
// kind: like every other non-flake error it surfaces as unknown with the
// original message preserved. The backoff sleep honours ctx cancellation
// so a timed-out operation never sleeps past its deadline.
//
// Create is not idempotent across retries: a first attempt may pass
// New-Item and then fail on a Set with the flake while the best-effort
// Remove-Website cleanup also fails, so the retry hits the $found guard
// and returns already_exists instead of the flake. When op is "create"
// and already_exists follows an observed flake, the original flake error
// is returned instead of the misleading already_exists.
func (a *IISSiteClient) runSiteWrite(
	ctx context.Context, op, name, script string,
) (*psResponse, error) {
	var flakeErr *IISSiteError
	for attempt := 1; ; attempt++ {
		resp, err := a.runSiteEnvelope(ctx, op, name, script)
		if err == nil {
			return resp, nil
		}
		var ae *IISSiteError
		if !errors.As(err, &ae) {
			return nil, err
		}
		if !IISConfigChangedOnDisk(ae.Message) {
			if op == "create" && flakeErr != nil && ae.Kind == IISSiteErrorAlreadyExists {
				return nil, flakeErr
			}
			return nil, err
		}
		if flakeErr == nil {
			flakeCopy := *ae
			flakeErr = &flakeCopy
		}
		if attempt >= iisWriteMaxAttempts {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(iisRetryBackoff(attempt)):
		}
	}
}

// ---------------------------------------------------------------------------
// Payload parsing
// ---------------------------------------------------------------------------

// iisSiteBindingJSON mirrors one entry of the bindings view.
type iisSiteBindingJSON struct {
	Protocol           string `json:"protocol"`
	BindingInformation string `json:"binding_information"`
}

// iisSiteJSON mirrors the JSON object returned by Get-SiteData.
type iisSiteJSON struct {
	Name                     string               `json:"name"`
	SiteID                   int64                `json:"site_id"`
	PhysicalPath             string               `json:"physical_path"`
	ApplicationPool          string               `json:"application_pool"`
	AutoStart                bool                 `json:"auto_start"`
	PreloadEnabled           bool                 `json:"preload_enabled"`
	EnabledProtocols         string               `json:"enabled_protocols"`
	LogEnabled               bool                 `json:"log_enabled"`
	LogDirectory             string               `json:"log_directory"`
	LogFormat                string               `json:"log_format"`
	ConnectionTimeoutSeconds int64                `json:"connection_timeout_seconds"`
	MaxConnections           int64                `json:"max_connections"`
	Bindings                 []iisSiteBindingJSON `json:"bindings"`
	State                    string               `json:"state"`
}

// parseIISSiteState converts the envelope data into an IISSiteState.
// A JSON null data means "site absent" and yields (nil, nil).
func parseIISSiteState(op, name string, data json.RawMessage) (*IISSiteState, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var j iisSiteJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, NewIISSiteError(IISSiteErrorUnknown,
			fmt.Sprintf("failed to parse IIS site JSON from %q", op), err,
			map[string]string{"name": name})
	}
	siteName := j.Name
	if siteName == "" {
		siteName = name
	}
	bindings := make([]IISSiteBinding, 0, len(j.Bindings))
	for _, b := range j.Bindings {
		bindings = append(bindings, IISSiteBinding(b))
	}
	return &IISSiteState{
		Name:                     siteName,
		SiteID:                   j.SiteID,
		PhysicalPath:             j.PhysicalPath,
		ApplicationPool:          j.ApplicationPool,
		AutoStart:                j.AutoStart,
		PreloadEnabled:           j.PreloadEnabled,
		EnabledProtocols:         j.EnabledProtocols,
		LogEnabled:               j.LogEnabled,
		LogDirectory:             j.LogDirectory,
		LogFormat:                j.LogFormat,
		ConnectionTimeoutSeconds: j.ConnectionTimeoutSeconds,
		MaxConnections:           j.MaxConnections,
		Bindings:                 bindings,
		State:                    j.State,
	}, nil
}

// validateIISSiteInput rejects invalid names (never sent to the host) and
// out-of-range site IDs before any script runs.
func validateIISSiteInput(in IISSiteInput, allowSiteID bool) error {
	if err := ValidateIISSiteName(in.Name); err != nil {
		return NewIISSiteError(IISSiteErrorUnknown, err.Error(), nil, map[string]string{"name": in.Name})
	}
	if in.Settings.SiteID != nil {
		if !allowSiteID {
			return NewIISSiteError(IISSiteErrorUnknown,
				fmt.Sprintf("site_id is ForceNew and cannot be changed for IIS site %q", in.Name),
				nil, map[string]string{"name": in.Name})
		}
		if err := ValidateIISSiteID(*in.Settings.SiteID); err != nil {
			return NewIISSiteError(IISSiteErrorUnknown, err.Error(), nil, map[string]string{"name": in.Name})
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create creates the site with zero bindings, applies the configured
// settings in a single script, enforces the configured runtime state
// (Started with zero bindings leaves the site Stopped without failing),
// and returns the read-back state. An existing site yields already_exists
// with an import hint; a colliding site_id yields id_conflict; a missing
// pool or path yields app_pool_not_found / path_not_found. On partial
// failure the half-created site is deleted best-effort (script-side) and
// the original error is returned.
func (a *IISSiteClient) Create(ctx context.Context, in IISSiteInput) (*IISSiteState, error) {
	if err := validateIISSiteInput(in, true); err != nil {
		return nil, err
	}
	script := fmt.Sprintf(`
$Name = %s
$sitePath = ('IIS:\Sites\' + $Name)
$SiteId = %s
$PhysicalPath = %s
$AppPool = %s
if (-not (Ensure-IIS)) { return }
$found = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
if ($found) {
  Emit-Err 'already_exists' ('IIS site ''' + $found.Name + ''' already exists on this host (use ''terraform import'' to bring it under management instead of creating a duplicate).') @{ name = $found.Name }
  return
}
if ($null -ne $SiteId) {
  $idClash = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | Where-Object { $_.ID -eq $SiteId }
  if ($idClash) {
    Emit-Err 'id_conflict' ('IIS site ID ' + $SiteId + ' is already used by site ''' + $idClash.Name + ''' on this host.') @{ name = $Name; conflicting_site = $idClash.Name }
    return
  }
}
%s
%s
try {
  $newParams = @{ physicalPath = $PhysicalPath; bindings = @(); ErrorAction = 'Stop' }
  if ($null -ne $SiteId) { $newParams.id = $SiteId }
  New-Item $sitePath @newParams | Out-Null
  try {
%s
%s
    Emit-OK (Get-SiteData $Name)
  } catch {
    try { Remove-Website -Name %s -ErrorAction SilentlyContinue } catch {}
    throw
  }
} catch {
  Emit-Err (Classify-Site $_.Exception.Message) ([string]$_.Exception.Message) @{ name = $Name; step = 'create' }
}
`,
		psQuote(in.Name),
		psSiteIDLiteral(in.Settings.SiteID),
		psSiteOptionalLiteral(in.Settings.PhysicalPath),
		psSiteOptionalLiteral(in.Settings.ApplicationPool),
		iisSitePreamble(),
		iisSiteGuardFragment,
		buildIISSiteSetStatements(in.Settings),
		buildIISSiteStateStatement(in.Settings.State, psQuote(psEscapeWildcard(in.Name))),
		psQuote(psEscapeWildcard(in.Name)),
	)

	resp, err := a.runSiteWrite(ctx, "create", in.Name, script)
	if err != nil {
		return nil, err
	}
	return parseIISSiteState("create", in.Name, resp.Data)
}

// psSiteIDLiteral renders the $SiteId assignment: the bare number when
// configured, $null when IIS allocates the lowest free ID itself.
func psSiteIDLiteral(id *int64) string {
	if id == nil {
		return "$null"
	}
	return fmt.Sprintf("%d", *id)
}

// psSiteOptionalLiteral renders an optional string assignment: the
// psQuote'd value when configured, $null when unmanaged.
func psSiteOptionalLiteral(v *string) string {
	if v == nil {
		return "$null"
	}
	return psQuote(*v)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the current state of the named site, or (nil, nil) when
// the site does not exist (drift detection).
func (a *IISSiteClient) Read(ctx context.Context, name string) (*IISSiteState, error) {
	if err := ValidateIISSiteName(name); err != nil {
		return nil, NewIISSiteError(IISSiteErrorUnknown, err.Error(), nil, map[string]string{"name": name})
	}
	script := fmt.Sprintf(`
$Name = %s
if (-not (Ensure-IIS)) { return }
try {
  Emit-OK (Get-SiteData $Name)
} catch {
  Emit-Err (Classify-Site $_.Exception.Message) ([string]$_.Exception.Message) @{ name = $Name; step = 'read' }
}
`, psQuote(name))

	resp, err := a.runSiteEnvelope(ctx, "read", name, script)
	if err != nil {
		if IsIISSiteError(err, IISSiteErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseIISSiteState("read", name, resp.Data)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies only the configured settings to the named site (site_id
// is create-only and never re-sent), enforces the configured state
// (Started with zero bindings leaves the site Stopped without failing),
// and returns the read-back state. A missing site yields not_found.
func (a *IISSiteClient) Update(ctx context.Context, in IISSiteInput) (*IISSiteState, error) {
	if err := validateIISSiteInput(in, false); err != nil {
		return nil, err
	}
	script := fmt.Sprintf(`
$Name = %s
$sitePath = ('IIS:\Sites\' + $Name)
$PhysicalPath = %s
$AppPool = %s
if (-not (Ensure-IIS)) { return }
$found = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
if (-not $found) {
  Emit-Err 'not_found' ('IIS site ''' + $Name + ''' was not found on this host.') @{ name = $Name }
  return
}
%s
%s
try {
%s
%s
  Emit-OK (Get-SiteData $Name)
} catch {
  Emit-Err (Classify-Site $_.Exception.Message) ([string]$_.Exception.Message) @{ name = $Name; step = 'update' }
}
`,
		psQuote(in.Name),
		psSiteOptionalLiteral(in.Settings.PhysicalPath),
		psSiteOptionalLiteral(in.Settings.ApplicationPool),
		iisSitePreamble(),
		iisSiteGuardFragment,
		buildIISSiteSetStatements(in.Settings),
		buildIISSiteStateStatement(in.Settings.State, psQuote(psEscapeWildcard(in.Name))),
	)

	resp, err := a.runSiteWrite(ctx, "update", in.Name, script)
	if err != nil {
		return nil, err
	}
	return parseIISSiteState("update", in.Name, resp.Data)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the named site (Remove-Website). A missing site is
// already absent (Emit-OK, nil error).
func (a *IISSiteClient) Delete(ctx context.Context, name string) error {
	if err := ValidateIISSiteName(name); err != nil {
		return NewIISSiteError(IISSiteErrorUnknown, err.Error(), nil, map[string]string{"name": name})
	}
	script := fmt.Sprintf(`
$Name = %s
if (-not (Ensure-IIS)) { return }
$found = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
if (-not $found) {
  Emit-OK ([ordered]@{ deleted = $true; note = 'already_absent' })
  return
}
try {
  Remove-Website -Name %s -ErrorAction Stop
  Emit-OK ([ordered]@{ deleted = $true })
} catch {
  Emit-Err (Classify-Site $_.Exception.Message) ([string]$_.Exception.Message) @{ name = $Name; step = 'delete' }
}
`, psQuote(name), psQuote(psEscapeWildcard(name)))

	_, err := a.runSiteWrite(ctx, "delete", name, script)
	return err
}
