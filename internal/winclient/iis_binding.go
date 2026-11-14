// Package winclient: IIS binding CRUD over SSH.
//
// This file implements WindowsIISBindingClient, the concrete client used by
// the windows_iis_binding Terraform resource. All operations execute
// PowerShell scripts (WebAdministration module) wrapped in a JSON envelope
// (Emit-OK/Emit-Err) so stdout is machine-parseable regardless of Windows
// locale.
//
// Create flow: SSH-port guard (Go-side, fail-closed) -> site-exists ->
// global conflict scan -> certificate plus private-key plus SslBindings
// checks -> New-WebBinding -SslFlags -> AddSslCertificate with binding
// rollback on failure -> auto-start the site when its serverAutoStart asks
// for it. Read matches the exact binding (site plus protocol plus
// bindingInformation). Update removes and re-adds the binding with the new
// certificate/SNI pair in one script (identity fields are ForceNew and are
// never re-written). Delete removes the SSL certificate first and then the
// binding; a missing binding is already absent.
//
// Security invariants:
//   - Site names, protocols and every other user-supplied string are
//     interpolated only through psQuote (single-quoted PS literal).
//     Lookups filter with Where-Object { ... -eq ... } (literal
//     comparison, same rule as windows_net_ip_address); -Name parameters
//     that accept wildcards receive the wildcard-escaped spelling via the
//     script-side Escape-Wildcard helper — host-enumerated site names are
//     escaped where they are used because they may predate validation.
//     Site names cannot contain wildcard characters
//     (ValidateIISSiteName), so for managed names this is defence in
//     depth.
//   - Thumbprints are hex only (no wildcard or quote characters) after
//     normalisation, so -eq comparisons cannot expand.
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
//   - sshProviderPort          — sshd port default (sshpath.go)
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Compile-time assertion: IISBindingClient satisfies WindowsIISBindingClient.
var _ WindowsIISBindingClient = (*IISBindingClient)(nil)

// IISBindingClient is the PowerShell/SSH-backed WindowsIISBindingClient.
type IISBindingClient struct {
	c *Client
}

// NewIISBindingClient constructs an IISBindingClient wrapping the given SSH Client.
func NewIISBindingClient(c *Client) *IISBindingClient { return &IISBindingClient{c: c} }

// iisBindingManagementPath is the package-level indirection for the shared
// management-path probe. Tests may override it; production code must not.
var iisBindingManagementPath = func(ctx context.Context, c *Client) (*ManagementPath, error) {
	return c.ManagementPath(ctx)
}

// ---------------------------------------------------------------------------
// PowerShell fragments
// ---------------------------------------------------------------------------

// iisBindingWildcardEscape renders the script-side wildcard escaper. It is
// a Go interpreted string (not a raw string) because the PowerShell
// replacement text contains a backtick, which cannot appear in a Go raw
// string literal.
const iisBindingWildcardEscape = "function Escape-BindingWildcard([string]$s) { return ($s -replace '([*?\\[\\]])', '`$1') }\n"

// iisBindingReadFragment defines Get-BindingData, which returns the exact
// binding match (site plus protocol plus bindingInformation, all literal
// -eq comparisons) as an ordered hashtable, or $null when absent. The
// bindingInformation is split bracket-aware into ip/port/host; the
// certificate pair comes from the binding object itself (certificateHash /
// certificateStoreName), so no IIS:\SslBindings property guessing is
// needed on the read path.
const iisBindingReadFragment = `
function Get-BindingParts([string]$BI) {
  $ip = ''; $port = 0; $hostHeader = ''
  $rest = $BI
  if ($rest.StartsWith('[')) {
    $end = $rest.IndexOf(']')
    if ($end -lt 0) { return $null }
    $ip = $rest.Substring(1, $end - 1)
    $rest = $rest.Substring($end + 1)
    if (-not $rest.StartsWith(':')) { return $null }
    $rest = $rest.Substring(1)
  } else {
    $first = $rest.Split(':', 3)
    if ($first.Count -ne 3) { return $null }
    $ip = $first[0]
    $rest = ($first[1] + ':' + $first[2])
  }
  $tail = $rest.Split(':', 2)
  if ($tail.Count -ne 2) { return $null }
  $port = [int]$tail[0]
  $hostHeader = $tail[1]
  return [ordered]@{ ip = $ip; port = $port; host_header = $hostHeader }
}

function Get-BindingData([string]$SiteName, [string]$Protocol, [string]$BindingInfo) {
  $escSite = Escape-BindingWildcard $SiteName
  $bs = @(Get-WebBinding -Name $escSite -ErrorAction Stop)
  foreach ($b in $bs) {
    if ($null -eq $b) { continue }
    if ([string]$b.protocol -eq $Protocol -and [string]$b.bindingInformation -eq $BindingInfo) {
      $parts = Get-BindingParts ([string]$b.bindingInformation)
      if ($null -eq $parts) { continue }
      $flags = 0
      try { $flags = [int]$b.sslFlags } catch {}
      $certHash = ''
      try { $certHash = [string]$b.certificateHash } catch {}
      $certStore = ''
      try { $certStore = [string]$b.certificateStoreName } catch {}
      $sni = $false
      if (($flags -band 1) -ne 0) { $sni = $true }
      return [ordered]@{
        protocol               = [string]$b.protocol
        binding_information    = [string]$b.bindingInformation
        ip_address             = [string]$parts.ip
        port                   = [int]$parts.port
        host_header            = [string]$parts.host_header
        ssl_flags              = $flags
        require_sni            = $sni
        certificate_thumbprint = $certHash
        certificate_store_name = $certStore
      }
    }
  }
  return $null
}

function Classify-Binding([string]$Msg) {
  $shared = Classify-IIS $Msg
  if ($shared -ne 'unknown') { return $shared }
  return (Classify-ByPatterns $Msg @(
    @('already exists|0x800700b7', 'already_exists'),
    @('was not found|Cannot find path|0x80070490', 'not_found'),
    @('in use|conflict|0x80076380', 'ssl_binding_conflict')
  ))
}
`

// iisBindingScanFragment enumerates every binding on the host into
// $allBound (@{ site, protocol, binding_information, ssl_flags, cert_hash,
// cert_store, ip, port, host_header }) so Create/Update can detect
// same-site duplicates (already_exists), cross-site duplicates (conflict)
// and HTTP.sys SSL ownership clashes (ssl_binding_conflict) without
// guessing IIS:\SslBindings property names. Site names come from the host
// and are wildcard-escaped where they are used; every comparison below is
// a literal -eq/-ne.
const iisBindingScanFragment = `
$siteNames = @(Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | ForEach-Object { $_.Name })
$allBound = @()
foreach ($sn in $siteNames) {
  $escSn = Escape-BindingWildcard $sn
  foreach ($b in @(Get-WebBinding -Name $escSn -ErrorAction Stop)) {
    if ($null -eq $b) { continue }
    $parts = Get-BindingParts ([string]$b.bindingInformation)
    if ($null -eq $parts) { continue }
    $flags = 0
    try { $flags = [int]$b.sslFlags } catch {}
    $allBound += [ordered]@{
      site                = [string]$sn
      protocol            = [string]$b.protocol
      binding_information = [string]$b.bindingInformation
      ssl_flags           = $flags
      cert_hash           = [string]$b.certificateHash
      cert_store          = [string]$b.certificateStoreName
      ip                  = [string]$parts.ip
      port                = [int]$parts.port
      host_header         = [string]$parts.host_header
    }
  }
}
`

// iisBindingSSLCheckFragment emits the HTTP.sys SSL ownership pre-checks
// for an https binding that will carry a certificate ($Thumb non-empty).
// The check runs over the $allBound enumeration plus a direct
// IIS:\SslBindings lookup (IPAddress/Port/Thumbprint only — the stable
// properties) so a stale sslcert with no live binding still conflicts
// instead of failing later inside AddSslCertificate. $BindingInfo,
// $WantedIP, $WantedHost and $Thumb are script variables set by the caller;
// $ExcludeSelf skips the caller's own binding on the Update path.
const iisBindingSSLCheckFragment = `
if ($Thumb -ne '') {
  $sniWanted = (($SslFlags -band 1) -ne 0)
  foreach ($e in $allBound) {
    if ([string]$e.protocol -ne 'https') { continue }
    if ([int]$e.port -ne $Port) { continue }
    if ([string]$e.ip -ne $WantedIP) { continue }
    if ($ExcludeSelf -and [string]$e.site -eq $Name -and [string]$e.binding_information -eq $BindingInfo) { continue }
    $eSni = (([int]$e.ssl_flags -band 1) -ne 0)
    if ($sniWanted -and $eSni) {
      if ([string]$e.host_header -eq $WantedHost -and [string]$e.cert_hash -ne '' -and [string]$e.cert_hash -ne $Thumb) {
        Emit-Err 'ssl_binding_conflict' ('Another SNI binding for host ''' + $WantedHost + ''' on ' + $WantedIP + ':' + $Port + ' already uses a different certificate. Use the same certificate or a different host/port.') @{ site_name = $Name; binding_information = $BindingInfo }
        return
      }
      continue
    }
    if ([string]$e.cert_hash -ne '' -and [string]$e.cert_hash -ne $Thumb) {
      Emit-Err 'ssl_binding_conflict' ('The SSL binding for ' + $WantedIP + ':' + $Port + ' already carries a different certificate (used by site ''' + [string]$e.site + '''). Use the same certificate or a different IP/port.') @{ site_name = $Name; binding_information = $BindingInfo; conflicting_site = [string]$e.site }
      return
    }
  }
  foreach ($s in @(Get-ChildItem 'IIS:\SslBindings' -ErrorAction SilentlyContinue)) {
    if ($null -eq $s) { continue }
    try { $sPort = [int]$s.Port } catch { continue }
    if ($sPort -ne $Port) { continue }
    $sIP = [string]$s.IPAddress
    $ipMatch = ($sIP -eq $WantedIP) -or (($WantedIP -eq '*' -or $WantedIP -eq '') -and ($sIP -eq '*' -or $sIP -eq '0.0.0.0'))
    if (-not $ipMatch) { continue }
    $sThumb = ''
    try { $sThumb = [string]$s.Thumbprint } catch {}
    if ($sThumb -ne '' -and $sThumb -ne $Thumb) {
      Emit-Err 'ssl_binding_conflict' ('The SSL binding for ' + $WantedIP + ':' + $Port + ' already carries a different certificate. Use the same certificate or a different IP/port.') @{ site_name = $Name; binding_information = $BindingInfo }
      return
    }
  }
}
`

// iisBindingCertCheckFragment verifies the configured certificate exists
// in Cert:\LocalMachine\<store> and carries a private key. Certificates
// are managed by windows_certificate and are never created implicitly.
const iisBindingCertCheckFragment = `
if ($Thumb -ne '') {
  $certPath = ('Cert:\LocalMachine\' + $Store)
  $cert = Get-ChildItem $certPath -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $Thumb }
  if (-not $cert) {
    Emit-Err 'certificate_not_found' ('Certificate ' + $Thumb + ' was not found in ' + $certPath + ' (manage it with the windows_certificate resource; it is never created implicitly).') @{ site_name = $Name; thumbprint = $Thumb; store = $Store }
    return
  }
  if (-not $cert.HasPrivateKey) {
    Emit-Err 'certificate_no_private_key' ('Certificate ' + $Thumb + ' in ' + $certPath + ' has no private key: HTTP.sys cannot serve TLS without one.') @{ site_name = $Name; thumbprint = $Thumb; store = $Store }
    return
  }
}
`

// ---------------------------------------------------------------------------
// Envelope runners
// ---------------------------------------------------------------------------

// mapIISBindingKind translates the PS-side kind string to a typed
// IISBindingErrorKind.
func mapIISBindingKind(kind, _ string) IISBindingErrorKind {
	switch IISBindingErrorKind(kind) {
	case IISBindingErrorNotFound,
		IISBindingErrorSiteNotFound,
		IISBindingErrorAlreadyExists,
		IISBindingErrorConflict,
		IISBindingErrorSSLBindingConflict,
		IISBindingErrorCertificateNotFound,
		IISBindingErrorCertificateNoPrivateKey,
		IISBindingErrorWouldLockOut,
		IISBindingErrorIISNotInstalled,
		IISBindingErrorAccessDenied:
		return IISBindingErrorKind(kind)
	default:
		return IISBindingErrorUnknown
	}
}

// runBindingEnvelope executes script (prefixed with psIISHeader plus the
// binding fragments) and parses the JSON envelope through the shared
// runEnvelope helper. Transport and parsing failures become
// IISBindingErrorUnknown; timeouts keep their operation-scoped message.
func (b *IISBindingClient) runBindingEnvelope(ctx context.Context, op, site, script string) (*psResponse, error) {
	baseContext := map[string]string{"site_name": site, "host": b.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runPowerShell(ctx, b.c, full)
		},
		op, psIISHeader+"\n"+iisBindingWildcardEscape+iisBindingReadFragment+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewIISBindingError(IISBindingErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewIISBindingError(mapIISBindingKind(eerr.RemoteKind, eerr.Message), eerr.Message, nil, eerr.Context)
}

// runBindingWrite executes a mutating script with the concurrent-writer
// retry: only the file-has-changed-on-disk flake is retried (up to
// iisWriteMaxAttempts attempts with backoff); transport errors and every
// other remote failure surface immediately. The backoff sleep honours ctx
// cancellation so a timed-out operation never sleeps past its deadline.
func (b *IISBindingClient) runBindingWrite(
	ctx context.Context, op, site, script string,
) (*psResponse, error) {
	for attempt := 1; ; attempt++ {
		resp, err := b.runBindingEnvelope(ctx, op, site, script)
		if err == nil {
			return resp, nil
		}
		var ae *IISBindingError
		if !errors.As(err, &ae) {
			return nil, err
		}
		if !IISConfigChangedOnDisk(ae.Message) {
			return nil, err
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
// SSH-port lockout guard (Go side of the would_lock_out refusal)
// ---------------------------------------------------------------------------

// ensureIISBindingPortSafe refuses Create when the binding port equals the
// SSH management port: the provider-configured port first (no probe
// needed), then the probed ManagementPath ServerPort (which observes the
// server-side port, NAT-correct). An undeterminable path fails closed —
// binding HTTP.sys to the management port risks cutting the very session
// applying the change, so guessing is worse than refusing. Nothing is
// applied when this returns an error.
func (b *IISBindingClient) ensureIISBindingPortSafe(ctx context.Context, op string, in IISBindingInput) error {
	base := map[string]string{
		"host": b.c.cfg.Host, "operation": op,
		"site_name": in.SiteName, "port": fmt.Sprintf("%d", in.Port),
	}
	if IISBindingWouldLockOut(in.Port, sshProviderPort(b.c.cfg.Port)) {
		return NewIISBindingError(IISBindingErrorWouldLockOut,
			fmt.Sprintf("refusing %s of IIS binding %s on port %d: it is the SSH port this provider session dials (provider port %d). Binding HTTP.sys to the management port risks cutting the provider connection. Choose a different port.",
				op, BuildIISBindingInformation(in.IPAddress, in.Port, in.HostHeader), in.Port, sshProviderPort(b.c.cfg.Port)),
			nil, base)
	}
	mp, err := iisBindingManagementPath(ctx, b.c)
	if err != nil {
		var mpe *ManagementPathError
		cause := err.Error()
		if errors.As(err, &mpe) {
			cause = mpe.Message
		}
		return NewIISBindingError(IISBindingErrorWouldLockOut,
			fmt.Sprintf("cannot determine the management path for this SSH session, refusing %s of IIS binding %s on port %d fail-closed. Cause: %s",
				op, BuildIISBindingInformation(in.IPAddress, in.Port, in.HostHeader), in.Port, cause),
			nil, base)
	}
	if IISBindingWouldLockOut(in.Port, mp.ServerPort) {
		return NewIISBindingError(IISBindingErrorWouldLockOut,
			fmt.Sprintf("refusing %s of IIS binding %s on port %d: it is the SSH server port this session arrived on (SSH_CONNECTION server port %d via %s). Binding HTTP.sys to the management port risks cutting the provider connection. Choose a different port.",
				op, BuildIISBindingInformation(in.IPAddress, in.Port, in.HostHeader), in.Port, mp.ServerPort, mp.Source),
			nil, base)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Payload parsing
// ---------------------------------------------------------------------------

// iisBindingJSON mirrors the JSON object returned by Get-BindingData.
type iisBindingJSON struct {
	Protocol              string `json:"protocol"`
	BindingInformation    string `json:"binding_information"`
	IPAddress             string `json:"ip_address"`
	Port                  int64  `json:"port"`
	HostHeader            string `json:"host_header"`
	SslFlags              int64  `json:"ssl_flags"`
	RequireSNI            bool   `json:"require_sni"`
	CertificateThumbprint string `json:"certificate_thumbprint"`
	CertificateStoreName  string `json:"certificate_store_name"`
}

// parseIISBindingState converts the envelope data into an IISBindingState.
// A JSON null data means "binding absent" and yields (nil, nil). The IP,
// host and (when present) thumbprint are re-canonicalised Go-side so state
// never depends on host casing or spacing.
func parseIISBindingState(op, site string, data json.RawMessage) (*IISBindingState, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var j iisBindingJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, NewIISBindingError(IISBindingErrorUnknown,
			fmt.Sprintf("failed to parse IIS binding JSON from %q", op), err,
			map[string]string{"site_name": site})
	}
	ip, err := NormalizeIISBindingIPAddress(j.IPAddress)
	if err != nil {
		ip = strings.TrimSpace(j.IPAddress)
		if ip == "" {
			ip = "*"
		}
	}
	thumb := ""
	if strings.TrimSpace(j.CertificateThumbprint) != "" {
		if norm, nerr := NormalizeIISBindingThumbprint(j.CertificateThumbprint); nerr == nil {
			thumb = norm
		} else {
			thumb = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(j.CertificateThumbprint), " ", ""))
		}
	}
	store := ""
	if thumb != "" {
		if canon, serr := CanonicalizeIISBindingStoreName(j.CertificateStoreName); serr == nil {
			store = canon
		} else {
			store = strings.TrimSpace(j.CertificateStoreName)
		}
	}
	return &IISBindingState{
		SiteName:              site,
		Protocol:              strings.ToLower(strings.TrimSpace(j.Protocol)),
		IPAddress:             ip,
		Port:                  j.Port,
		HostHeader:            NormalizeIISBindingHostHeader(j.HostHeader),
		RequireSNI:            IISBindingRequireSNIFromSslFlags(j.SslFlags) || j.RequireSNI,
		CertificateThumbprint: thumb,
		CertificateStoreName:  store,
		BindingInformation:    strings.TrimSpace(j.BindingInformation),
		SslFlags:              j.SslFlags,
	}, nil
}

// bindingScriptVars renders the shared $Name/$Protocol/$BindingInfo/
// $WantedIP/$WantedHost/$Port/$SslFlags/$Thumb/$Store assignments for the
// mutating scripts. Thumb is "" when no certificate is desired; Store
// defaults to My then.
func bindingScriptVars(in IISBindingInput, excludeSelf bool) string {
	thumb := ""
	if in.CertificateThumbprint != nil {
		if norm, err := NormalizeIISBindingThumbprint(*in.CertificateThumbprint); err == nil {
			thumb = norm
		}
	}
	store := IISBindingStoreMy
	if in.CertificateStoreName != "" {
		if canon, err := CanonicalizeIISBindingStoreName(in.CertificateStoreName); err == nil {
			store = canon
		}
	}
	var sni bool
	if in.RequireSNI != nil {
		sni = *in.RequireSNI
	}
	ip, _ := NormalizeIISBindingIPAddress(in.IPAddress)
	protocol, _ := CanonicalizeIISBindingProtocol(in.Protocol)
	host := NormalizeIISBindingHostHeader(in.HostHeader)
	return fmt.Sprintf(`
$Name = %s
$Protocol = %s
$BindingInfo = %s
$WantedIP = %s
$WantedHost = %s
$Port = %d
$SslFlags = %d
$Thumb = %s
$Store = %s
$ExcludeSelf = %s
`,
		psQuote(in.SiteName),
		psQuote(protocol),
		psQuote(BuildIISBindingInformation(ip, in.Port, host)),
		psQuote(ip),
		psQuote(host),
		in.Port,
		IISBindingSslFlags(sni),
		psQuote(thumb),
		psQuote(store),
		psBoolLiteral(excludeSelf),
	)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create adds the binding (New-WebBinding -SslFlags), binds the
// certificate when configured (AddSslCertificate with binding rollback on
// failure), auto-starts the site when its serverAutoStart asks for it, and
// returns the read-back state. The SSH-port guard runs before anything is
// applied; a duplicate on the same site yields already_exists (with an
// import hint), on another site conflict (naming it), a missing site
// yields site_not_found, and certificate problems yield
// certificate_not_found / certificate_no_private_key /
// ssl_binding_conflict.
func (b *IISBindingClient) Create(ctx context.Context, in IISBindingInput) (*IISBindingState, error) {
	if err := ValidateIISBindingInput(in); err != nil {
		return nil, err
	}
	if err := b.ensureIISBindingPortSafe(ctx, "create", in); err != nil {
		return nil, err
	}
	// NOTE: $siteNames/$allBound come from the scan fragment, which must
	// run after Ensure-IIS (it needs the WebAdministration drive).
	script := bindingScriptVars(in, false) + `
if (-not (Ensure-IIS)) { return }
` + iisBindingScanFragment + `
if (-not ($siteNames -contains $Name)) {
  Emit-Err 'site_not_found' ('IIS site ''' + $Name + ''' was not found on this host (manage it with the windows_iis_site resource; it is never created implicitly).') @{ site_name = $Name }
  return
}
$mine = $allBound | Where-Object { $_.site -eq $Name -and $_.protocol -eq $Protocol -and $_.binding_information -eq $BindingInfo }
if ($mine) {
  Emit-Err 'already_exists' ('IIS binding ''' + $BindingInfo + ''' (' + $Protocol + ') already exists on site ''' + $Name + ''' on this host (use ''terraform import'' to bring it under management instead of creating a duplicate).') @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo }
  return
}
$other = $allBound | Where-Object { $_.site -ne $Name -and $_.protocol -eq $Protocol -and $_.binding_information -eq $BindingInfo } | Select-Object -First 1
if ($other) {
  Emit-Err 'conflict' ('IIS binding ''' + $BindingInfo + ''' (' + $Protocol + ') already exists on site ''' + [string]$other.site + ''' on this host: one listener cannot serve two sites. Use a different IP, port or host header.') @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo; conflicting_site = [string]$other.site }
  return
}
` + iisBindingCertCheckFragment + "\n" + iisBindingSSLCheckFragment + fmt.Sprintf(`
try {
  New-WebBinding -Name %s -Protocol $Protocol -IPAddress $WantedIP -Port $Port -HostHeader $WantedHost -SslFlags $SslFlags -ErrorAction Stop
  try {
    if ($Thumb -ne '') {
      $fresh = Get-WebBinding -Name %s -ErrorAction Stop | Where-Object { $_.protocol -eq $Protocol -and $_.bindingInformation -eq $BindingInfo }
      if (-not $fresh) { throw 'the new binding was not found after New-WebBinding' }
      try {
        $fresh.AddSslCertificate($Thumb, $Store)
      } catch {
        try { Remove-WebBinding -Name %s -Protocol $Protocol -IPAddress $WantedIP -Port $Port -HostHeader $WantedHost -ErrorAction SilentlyContinue } catch {}
        throw
      }
    }
    try {
      $siteProps = Get-ItemProperty ('IIS:\Sites\' + $Name) -ErrorAction Stop
      if ($siteProps.serverAutoStart) { Start-Website -Name %s -ErrorAction Stop }
    } catch {
    }
    Emit-OK (Get-BindingData $Name $Protocol $BindingInfo)
  } catch {
    Emit-Err (Classify-Binding ([string]$_.Exception.Message)) ([string]$_.Exception.Message) @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo; step = 'create' }
  }
} catch {
  Emit-Err (Classify-Binding ([string]$_.Exception.Message)) ([string]$_.Exception.Message) @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo; step = 'create' }
}
`,
		psQuote(psEscapeWildcard(in.SiteName)),
		psQuote(psEscapeWildcard(in.SiteName)),
		psQuote(psEscapeWildcard(in.SiteName)),
		psQuote(psEscapeWildcard(in.SiteName)),
	)

	resp, err := b.runBindingWrite(ctx, "create", in.SiteName, script)
	if err != nil {
		return nil, err
	}
	return parseIISBindingState("create", in.SiteName, resp.Data)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the exact binding match (site plus protocol plus
// bindingInformation), or (nil, nil) when the site or the binding does not
// exist (drift detection).
func (b *IISBindingClient) Read(ctx context.Context, site, protocol, bindingInformation string) (*IISBindingState, error) {
	if err := ValidateIISSiteName(site); err != nil {
		return nil, NewIISBindingError(IISBindingErrorUnknown, err.Error(), nil, map[string]string{"site_name": site})
	}
	canonProto, err := CanonicalizeIISBindingProtocol(protocol)
	if err != nil {
		return nil, NewIISBindingError(IISBindingErrorUnknown, err.Error(), nil, map[string]string{"site_name": site})
	}
	ip, port, host, err := ParseIISBindingInformation(bindingInformation)
	if err != nil {
		return nil, NewIISBindingError(IISBindingErrorUnknown, err.Error(), nil, map[string]string{"site_name": site})
	}
	canonBI := BuildIISBindingInformation(ip, port, host)
	script := fmt.Sprintf(`
$Name = %s
$Protocol = %s
$BindingInfo = %s
if (-not (Ensure-IIS)) { return }
try {
  $found = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
  if (-not $found) {
    Emit-OK $null
    return
  }
  Emit-OK (Get-BindingData $Name $Protocol $BindingInfo)
} catch {
  Emit-Err (Classify-Binding ([string]$_.Exception.Message)) ([string]$_.Exception.Message) @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo; step = 'read' }
}
`, psQuote(site), psQuote(canonProto), psQuote(canonBI))

	resp, err := b.runBindingEnvelope(ctx, "read", site, script)
	if err != nil {
		if IsIISBindingError(err, IISBindingErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseIISBindingState("read", site, resp.Data)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies only the in-place fields (RequireSNI plus the certificate
// pair) by removing and re-adding the binding with the new SslFlags and
// certificate in one script; identity fields (site, protocol, IP, port,
// host) are ForceNew and are never changed here. A nil
// CertificateThumbprint leaves the certificate untouched; a pointer to ""
// removes it; a pointer to a thumbprint (re-)binds it. A missing site or
// binding yields site_not_found/not_found. When the re-add fails the
// previous binding is restored best-effort and the original error is
// returned.
func (b *IISBindingClient) Update(ctx context.Context, in IISBindingInput) (*IISBindingState, error) {
	if err := ValidateIISBindingInput(in); err != nil {
		return nil, err
	}
	ip, _ := NormalizeIISBindingIPAddress(in.IPAddress)
	host := NormalizeIISBindingHostHeader(in.HostHeader)
	canonBI := BuildIISBindingInformation(ip, in.Port, host)
	script := bindingScriptVars(in, true) + "\n" + iisBindingScanFragment + `
if (-not ($siteNames -contains $Name)) {
  Emit-Err 'site_not_found' ('IIS site ''' + $Name + ''' was not found on this host.') @{ site_name = $Name }
  return
}
$mine = $allBound | Where-Object { $_.site -eq $Name -and $_.protocol -eq $Protocol -and $_.binding_information -eq $BindingInfo }
if (-not $mine) {
  Emit-Err 'not_found' ('IIS binding ''' + $BindingInfo + ''' (' + $Protocol + ') was not found on site ''' + $Name + ''' on this host.') @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo }
  return
}
$OldFlags = [int]$mine.ssl_flags
$OldThumb = [string]$mine.cert_hash
$OldStore = [string]$mine.cert_store
if ($OldStore -eq '') { $OldStore = 'My' }
`
	// NOTE: $Thumb is always a string script-side ("" when the provider
	// passes nil); the Go layer decides whether the certificate pair
	// participates by comparing plan against prior state and only calling
	// Update when it does. An empty $Thumb here therefore means "remove
	// the certificate".
	script += iisBindingCertCheckFragment + "\n" + iisBindingSSLCheckFragment + fmt.Sprintf(`
try {
  Remove-WebBinding -Name %s -Protocol $Protocol -IPAddress $WantedIP -Port $Port -HostHeader $WantedHost -ErrorAction Stop
  try {
    New-WebBinding -Name %s -Protocol $Protocol -IPAddress $WantedIP -Port $Port -HostHeader $WantedHost -SslFlags $SslFlags -ErrorAction Stop
    if ($Thumb -ne '') {
      $fresh = Get-WebBinding -Name %s -ErrorAction Stop | Where-Object { $_.protocol -eq $Protocol -and $_.bindingInformation -eq $BindingInfo }
      if (-not $fresh) { throw 'the re-added binding was not found after New-WebBinding' }
      $fresh.AddSslCertificate($Thumb, $Store)
    }
    Emit-OK (Get-BindingData $Name $Protocol $BindingInfo)
  } catch {
    $addErr = [string]$_.Exception.Message
    $addKind = Classify-Binding $addErr
    try {
      New-WebBinding -Name %s -Protocol $Protocol -IPAddress $WantedIP -Port $Port -HostHeader $WantedHost -SslFlags $OldFlags -ErrorAction SilentlyContinue | Out-Null
      if ($OldThumb -ne '') {
        $restored = Get-WebBinding -Name %s -ErrorAction SilentlyContinue | Where-Object { $_.protocol -eq $Protocol -and $_.bindingInformation -eq $BindingInfo }
        if ($restored) { $restored.AddSslCertificate($OldThumb, $OldStore) }
      }
    } catch {
    }
    Emit-Err $addKind $addErr @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo; step = 'update' }
  }
} catch {
  Emit-Err (Classify-Binding ([string]$_.Exception.Message)) ([string]$_.Exception.Message) @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo; step = 'update' }
}
`,
		psQuote(psEscapeWildcard(in.SiteName)),
		psQuote(psEscapeWildcard(in.SiteName)),
		psQuote(psEscapeWildcard(in.SiteName)),
		psQuote(psEscapeWildcard(in.SiteName)),
		psQuote(psEscapeWildcard(in.SiteName)),
	)

	_ = canonBI
	resp, err := b.runBindingWrite(ctx, "update", in.SiteName, script)
	if err != nil {
		return nil, err
	}
	return parseIISBindingState("update", in.SiteName, resp.Data)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the SSL certificate binding first (when https) and then
// the binding itself. A missing site or binding is already absent
// (Emit-OK, nil error). Certificate removal is best-effort: the binding
// removal is authoritative.
func (b *IISBindingClient) Delete(ctx context.Context, site, protocol, bindingInformation string) error {
	if err := ValidateIISSiteName(site); err != nil {
		return NewIISBindingError(IISBindingErrorUnknown, err.Error(), nil, map[string]string{"site_name": site})
	}
	canonProto, err := CanonicalizeIISBindingProtocol(protocol)
	if err != nil {
		return NewIISBindingError(IISBindingErrorUnknown, err.Error(), nil, map[string]string{"site_name": site})
	}
	ip, port, host, err := ParseIISBindingInformation(bindingInformation)
	if err != nil {
		return NewIISBindingError(IISBindingErrorUnknown, err.Error(), nil, map[string]string{"site_name": site})
	}
	canonBI := BuildIISBindingInformation(ip, port, host)
	script := fmt.Sprintf(`
$Name = %s
$Protocol = %s
$BindingInfo = %s
if (-not (Ensure-IIS)) { return }
$found = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | Where-Object { $_.Name -eq $Name }
if (-not $found) {
  Emit-OK ([ordered]@{ deleted = $true; note = 'already_absent' })
  return
}
try {
  $escSite = Escape-BindingWildcard $Name
  $target = @(Get-WebBinding -Name $escSite -ErrorAction Stop) | Where-Object { $_.protocol -eq $Protocol -and $_.bindingInformation -eq $BindingInfo } | Select-Object -First 1
  if (-not $target) {
    Emit-OK ([ordered]@{ deleted = $true; note = 'already_absent' })
    return
  }
  if ($Protocol -eq 'https') {
    try { $target.RemoveSslCertificate() } catch {}
  }
  Remove-WebBinding -Name %s -Protocol $Protocol -IPAddress %s -Port %d -HostHeader %s -ErrorAction Stop
  Emit-OK ([ordered]@{ deleted = $true })
} catch {
  Emit-Err (Classify-Binding ([string]$_.Exception.Message)) ([string]$_.Exception.Message) @{ site_name = $Name; protocol = $Protocol; binding_information = $BindingInfo; step = 'delete' }
}
`, psQuote(site), psQuote(canonProto), psQuote(canonBI),
		psQuote(psEscapeWildcard(site)), psQuote(ip), port, psQuote(host))

	_, err = b.runBindingWrite(ctx, "delete", site, script)
	return err
}
