// Package winclient - CertificateClientImpl is the concrete CertificateClient
// backed by PowerShell over SSH (issue #222).
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted
//     PowerShell literal with embedded single-quotes doubled); no raw
//     concatenation of user input into PS scripts.
//   - The PEM / PFX payload and the PFX password travel to the host on
//     stdin via RunPowerShellWithInput ([Console]::In.ReadToEnd / first
//     line), never in the script body, the -EncodedCommand bootstrap or SSH
//     session logs. They are never written to CertificateError.Message or
//     Context either.
//
// Reused helpers from the same package:
//   - psQuote       - safe PS string literals (psquote.go)
//   - runEnvelope   - shared JSON envelope pipeline (envelope.go)
package winclient

import (
	"context"
	"crypto/sha1" //nolint:gosec // Windows thumbprints are SHA-1 by platform definition, not a security choice
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Compile-time assertion: CertificateClientImpl satisfies CertificateClient.
var _ CertificateClient = (*CertificateClientImpl)(nil)

// CertificateClientImpl is the PowerShell/SSH-backed CertificateClient.
type CertificateClientImpl struct {
	c *Client
}

// NewCertificateClient wraps the given SSH Client.
func NewCertificateClient(c *Client) *CertificateClientImpl {
	return &CertificateClientImpl{c: c}
}

// runCertificatePowerShell is the package-level indirection used by
// CertificateClientImpl. Tests may override it; production code must not.
// The stdin string carries the payload (base64 DER for PEM, password line +
// base64 PFX for PFX bundles); scripts that take no payload pass "".
var runCertificatePowerShell = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	return c.RunPowerShellWithInput(ctx, script, stdin)
}

// ---------------------------------------------------------------------------
// Pure-Go PEM helpers (no host round-trip)
// ---------------------------------------------------------------------------

// ParseCertificatePEM decodes the first CERTIFICATE block of pemText and
// returns its DER bytes. It rejects empty input, input without a
// CERTIFICATE block, and malformed base64 inside the block.
func ParseCertificatePEM(pemText string) ([]byte, error) {
	trimmed := strings.TrimSpace(pemText)
	if trimmed == "" {
		return nil, NewCertificateError(CertificateErrorCorruptCertificate,
			"certificate_pem must contain a PEM-encoded certificate (missing CERTIFICATE block)", nil, nil)
	}
	rest := []byte(trimmed)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, NewCertificateError(CertificateErrorCorruptCertificate,
				"certificate_pem must contain a PEM-encoded certificate (missing CERTIFICATE block)", nil, nil)
		}
		if block.Type == "CERTIFICATE" {
			if len(block.Bytes) == 0 {
				return nil, NewCertificateError(CertificateErrorCorruptCertificate,
					"certificate_pem contains an empty CERTIFICATE block", nil, nil)
			}
			return block.Bytes, nil
		}
		if len(rest) == 0 {
			return nil, NewCertificateError(CertificateErrorCorruptCertificate,
				"certificate_pem must contain a PEM-encoded certificate (missing CERTIFICATE block)", nil, nil)
		}
	}
}

// NormalizeCertificatePEM re-encodes the first CERTIFICATE block of pemText
// canonically (LF line endings, 64-column base64, trailing newline), so
// semantically identical inputs (CRLF, wrapped differently, bundled with a
// chain or private key) converge to one state spelling.
func NormalizeCertificatePEM(pemText string) (string, error) {
	der, err := ParseCertificatePEM(pemText)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// PEMThumbprint returns the Windows-style SHA-1 thumbprint (uppercase hex)
// of the first CERTIFICATE block in pemText.
func PEMThumbprint(pemText string) (string, error) {
	der, err := ParseCertificatePEM(pemText)
	if err != nil {
		return "", err
	}
	// Windows thumbprints are SHA-1 by platform definition (Cert:\ paths,
	// Get-ChildItem Thumbprint), not a security choice.
	sum := sha1.Sum(der) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// PEMThumbprintSHA256 returns the SHA-256 digest (uppercase hex) of the
// first CERTIFICATE block in pemText.
func PEMThumbprintSHA256(pemText string) (string, error) {
	der, err := ParseCertificatePEM(pemText)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// ---------------------------------------------------------------------------
// Client-side input validation (defence in depth; the schema validates first)
// ---------------------------------------------------------------------------

// CanonicalCertificateStoreLocation normalises the store location
// case-insensitively to its canonical spelling.
func CanonicalCertificateStoreLocation(raw string) (string, error) {
	switch {
	case strings.EqualFold(strings.TrimSpace(raw), CertificateStoreLocalMachine):
		return CertificateStoreLocalMachine, nil
	case strings.EqualFold(strings.TrimSpace(raw), CertificateStoreCurrentUser):
		return CertificateStoreCurrentUser, nil
	default:
		return "", NewCertificateError(CertificateErrorStoreNotFound,
			fmt.Sprintf("unknown store location %q (want %q or %q)", raw, CertificateStoreLocalMachine, CertificateStoreCurrentUser),
			nil, map[string]string{"store_location": raw})
	}
}

// canonicalCertificateStoreName validates the store name: non-empty and
// free of "/" (the resource ID separator). Backslashes are rejected too:
// they never occur in real store names and would corrupt Cert: paths.
func canonicalCertificateStoreName(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", NewCertificateError(CertificateErrorStoreNotFound,
			"store name must not be empty", nil, nil)
	}
	if strings.ContainsAny(trimmed, "/\\") {
		return "", NewCertificateError(CertificateErrorStoreNotFound,
			fmt.Sprintf("store name %q must not contain '/' or '\\'", raw), nil,
			map[string]string{"store_name": raw})
	}
	return trimmed, nil
}

// stripBase64Whitespace removes all whitespace (spaces, tabs, CR/LF) so
// wrapped base64 (e.g. file() output with newlines) decodes like .NET
// FromBase64String, which tolerates embedded whitespace.
func stripBase64Whitespace(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// normalizeCertificateThumbprint uppercases the thumbprint and strips
// whitespace, so lowercase or spaced spellings still match the store's
// canonical uppercase form.
func normalizeCertificateThumbprint(raw string) string {
	return strings.ToUpper(strings.Join(strings.Fields(raw), ""))
}

// validateCertificateInput checks the store coordinates and the exactly-one
// payload rule, returning the canonical location and store name.
func validateCertificateInput(input CertificateInput) (location, store string, err error) {
	location, err = CanonicalCertificateStoreLocation(input.StoreLocation)
	if err != nil {
		return "", "", err
	}
	store, err = canonicalCertificateStoreName(input.StoreName)
	if err != nil {
		return "", "", err
	}
	pemSet := strings.TrimSpace(input.CertificatePEM) != ""
	pfxSet := strings.TrimSpace(input.PFXBase64) != ""
	switch {
	case pemSet && pfxSet:
		return "", "", NewCertificateError(CertificateErrorCorruptCertificate,
			"certificate_pem and pfx_base64_wo are mutually exclusive", nil, nil)
	case !pemSet && !pfxSet:
		return "", "", NewCertificateError(CertificateErrorCorruptCertificate,
			"either certificate_pem or pfx_base64_wo must be set", nil, nil)
	case pemSet && input.Exportable:
		return "", "", NewCertificateError(CertificateErrorCorruptCertificate,
			"exportable applies to PFX bundles only and must not be set with certificate_pem", nil, nil)
	}
	if pfxSet {
		if _, derr := base64.StdEncoding.DecodeString(stripBase64Whitespace(input.PFXBase64)); derr != nil {
			return "", "", NewCertificateError(CertificateErrorCorruptCertificate,
				"pfx_base64_wo is not valid base64", nil, nil)
		}
	}
	return location, store, nil
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// psCertificateHeader is prepended to every certificate PS script. It pins
// the session culture to InvariantCulture and defines the shared Emit-OK /
// Emit-Err / Classify-Certificate / ConvertTo-CertificateJson helpers.
//
// Classify-Certificate prefers Win32 HResult codes over localized message
// substrings (hosts are not all English); substring matches remain as a
// backstop where no stable code exists.
const psCertificateHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture   = [System.Globalization.CultureInfo]::InvariantCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture

function Emit-OK([object]$Data) {
  $obj  = [ordered]@{ ok = $true; data = $Data }
  $json = ($obj | ConvertTo-Json -Depth 10 -Compress)
  [Console]::Out.WriteLine($json)
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj  = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Classify-Certificate([object]$Rec) {
  $msg = ''
  try { $msg = [string]$Rec.Exception.Message } catch { $msg = [string]$Rec }
  $code = ''
  try { $code = ('0x{0:X8}' -f [int]$Rec.Exception.HResult) } catch { }
  $full = ''
  try { $full = $Rec.Exception.ToString() } catch { $full = $msg }
  $text = "$code $msg $full"
  if ($code -eq '0x80070005' -or $msg -match 'Access is denied' -or $msg -match 'PermissionDenied' -or $msg -match 'UnauthorizedAccess') { return 'access_denied' }
  if ($code -eq '0x80070056' -or $msg -match 'network password is not correct' -or $msg -match 'The specified network password') { return 'invalid_password' }
  if ($msg -match 'ASN1' -or $msg -match 'input data cannot be' -or $msg -match 'Cannot decode' -or $msg -match 'is not a valid Base-64' -or $msg -match 'Invalid length for a Base-64' -or $msg -match 'padding is invalid') { return 'corrupt_certificate' }
  if ($msg -match 'requires user interaction' -or $msg -match 'user interaction' -or $msg -match 'A smart card' -or $msg -match 'SmartCard') { return 'interactive_ui_required' }
  if ($code -eq '0x8009200D' -or $msg -match 'Cannot find the requested object' -or $msg -match 'Cannot find path' -or $msg -match 'Cannot find drive' -or $msg -match 'does not exist') { return 'store_not_found' }
  if ($code -eq '0x80070490' -or $code -eq '0x80041002' -or $msg -match 'Cannot find the certificate') { return 'not_found' }
  return 'unknown'
}

function ConvertTo-CertificateJson([object]$C, [string]$Loc, [string]$Name) {
  $dns = @()
  try {
    foreach ($ext in $C.Extensions) {
      if ($ext.Oid.Value -eq '2.5.29.17') {
        $asn = New-Object Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
        foreach ($line in ($asn.Format($false) -split "["` + "`r`n" + `",]+")) {
          $t = $line.Trim()
          if ($t -match '^(?i)DNS Name=(.+)$') { $dns += $Matches[1].Trim() }
        }
      }
    }
  } catch { }
  if ($null -eq $dns) { $dns = @() }
  $sha256 = ''
  try { $sha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($C.RawData))).Replace('-', '') } catch { }
  $rawB64 = ''
  try { $rawB64 = [Convert]::ToBase64String($C.RawData) } catch { }
  $nb = ''
  try { $nb = $C.NotBefore.ToUniversalTime().ToString('o') } catch { }
  $na = ''
  try { $na = $C.NotAfter.ToUniversalTime().ToString('o') } catch { }
  $friendly = ''
  try { if ($null -ne $C.FriendlyName) { $friendly = [string]$C.FriendlyName } } catch { }
  return [ordered]@{
    store_location    = $Loc
    store_name        = $Name
    thumbprint        = [string]$C.Thumbprint
    thumbprint_sha256 = $sha256
    subject           = [string]$C.Subject
    issuer            = [string]$C.Issuer
    serial_number     = [string]$C.SerialNumber
    not_before        = $nb
    not_after         = $na
    dns_names         = $dns
    has_private_key   = [bool]$C.HasPrivateKey
    friendly_name     = $friendly
    raw_base64        = $rawB64
  }
}

function Remove-CertificatePrivateKey([object]$C) {
  $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($C)
  if ($null -ne $rsa) {
    try { $rsa.Key.Delete(); return } catch { }
    $csp = $rsa -as [Security.Cryptography.RSACryptoServiceProvider]
    if ($null -ne $csp) { $csp.PersistKeyInCsp = $false; $csp.Clear(); return }
    throw 'unable to delete the RSA private key (unsupported provider)'
  }
  $ecdsa = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($C)
  if ($null -ne $ecdsa) { $ecdsa.Key.Delete(); return }
  # DSA and other key types expose no deletion API here. This is a
  # documented DSA limitation: warn and return so the caller still removes
  # the store entry instead of orphaning the certificate.
  Write-Warning 'Unable to delete the private key (unsupported key type; DSA keys are not removed from the key store). Continuing with certificate removal.'
  return
}
`

// certificateKeyFlags renders the X509KeyStorageFlags expression for an
// import into location: MachineKeySet for LocalMachine, UserKeySet for
// CurrentUser (MachineKeySet under a non-elevated user context fails or
// lands in the wrong profile), always with PersistKeySet, plus Exportable
// for PFX bundles that request it.
func certificateKeyFlags(location string, exportable bool) string {
	keySet := "MachineKeySet"
	if strings.EqualFold(strings.TrimSpace(location), CertificateStoreCurrentUser) {
		keySet = "UserKeySet"
	}
	base := "([Security.Cryptography.X509Certificates.X509KeyStorageFlags]::" + keySet +
		" -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet"
	if exportable {
		return base + " -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)"
	}
	return base + ")"
}

// ---------------------------------------------------------------------------
// Script builders (every user value via psQuote; payloads via stdin only)
// ---------------------------------------------------------------------------

// buildCertificateCreatePEM Streams base64(DER) on stdin. The single-element
// array wrapper @(,$der) stops PowerShell unrolling the byte array into the
// -ArgumentList slots; the ” password binds the (byte[], string, flags)
// constructor overload unambiguously.
func buildCertificateCreatePEM(location, store, friendlyName string) string {
	return psCertificateHeader + fmt.Sprintf(`
$storeLocation = %s
$storeName = %s
$friendlyName = %s
& {
  try { $der = [Convert]::FromBase64String(([Console]::In.ReadToEnd()).Trim()) } catch {
    Emit-Err 'corrupt_certificate' ('The PEM payload could not be decoded: ' + [string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; step = 'decode' }
    return
  }
  $flags = %s
  try { $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$der), '', $flags } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; step = 'decode' }
    return
  }
  $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
  try { $store.Open('ReadWrite') } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; step = 'open' }
    return
  }
  try {
    $existing = @($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
    if ($existing.Count -gt 0) {
      Emit-Err 'already_exists' ('Certificate ' + [string]$cert.Thumbprint + ' is already present in ' + $storeLocation + '\' + $storeName + '. Import it with terraform import <name> "' + $storeLocation + '/' + $storeName + '/' + [string]$cert.Thumbprint + '".') @{ store_location = $storeLocation; store_name = $storeName; thumbprint = [string]$cert.Thumbprint }
      return
    }
    if ($friendlyName -ne '') { $cert.FriendlyName = $friendlyName }
    try { $store.Add($cert) } catch {
      Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; thumbprint = [string]$cert.Thumbprint; step = 'add' }
      return
    }
    Emit-OK (ConvertTo-CertificateJson $cert $storeLocation $storeName)
  } finally { $store.Close() }
}
`, psQuote(location), psQuote(store), psQuote(friendlyName), certificateKeyFlags(location, false))
}

// buildCertificateCreatePFX streams the PFX password as the first stdin
// line (empty when unprotected) followed by the base64 PFX bundle. The
// password is validated plan-side to contain no line breaks, so the split
// is unambiguous.
//
// Only the certificate(s) carrying a private key are added to the store
// (the leaf; $coll[0] as a fallback when none reports HasPrivateKey).
// Chain intermediates from the bundle are intentionally not added, so
// Delete (which removes the tracked leaf thumbprint) removes exactly what
// Create added.
func buildCertificateCreatePFX(location, store, friendlyName string, exportable bool) string {
	return psCertificateHeader + fmt.Sprintf(`
$storeLocation = %s
$storeName = %s
$friendlyName = %s
& {
  $raw = [Console]::In.ReadToEnd()
  $nl = $raw.IndexOf("`+"`n"+`")
  if ($nl -lt 0) { $pfxPassword = ''; $b64 = $raw } else { $pfxPassword = $raw.Substring(0, $nl).TrimEnd("`+"`r"+`"); $b64 = $raw.Substring($nl + 1) }
  try { $pfxBytes = [Convert]::FromBase64String($b64.Trim()) } catch {
    Emit-Err 'corrupt_certificate' ('The PFX payload could not be decoded: ' + [string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; step = 'decode' }
    return
  }
  $flags = %s
  $coll = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
  try {
    if ([string]::IsNullOrEmpty($pfxPassword)) { $coll.Import($pfxBytes, '', $flags) } else { $coll.Import($pfxBytes, $pfxPassword, $flags) }
  } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; step = 'import' }
    return
  }
  if ($coll.Count -eq 0) {
    Emit-Err 'corrupt_certificate' 'The PFX bundle contained no certificates.' @{ store_location = $storeLocation; store_name = $storeName; step = 'import' }
    return
  }
  $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
  try { $store.Open('ReadWrite') } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; step = 'open' }
    return
  }
  try {
    $keyed = @($coll | Where-Object { $_.HasPrivateKey })
    if ($keyed.Count -eq 0) { $keyed = @($coll[0]) }
    $thumbs = @(foreach ($kc in $keyed) { [string]$kc.Thumbprint })
    $dupes = @($store.Certificates | Where-Object { $thumbs -contains $_.Thumbprint } | ForEach-Object { [string]$_.Thumbprint })
    if ($dupes.Count -gt 0) {
      Emit-Err 'already_exists' ('Certificate ' + [string]$dupes[0] + ' is already present in ' + $storeLocation + '\' + $storeName + '. Import it with terraform import <name> "' + $storeLocation + '/' + $storeName + '/' + [string]$dupes[0] + '".') @{ store_location = $storeLocation; store_name = $storeName; thumbprint = [string]$dupes[0] }
      return
    }
    if ($friendlyName -ne '') { foreach ($kc in $keyed) { $kc.FriendlyName = $friendlyName } }
    try {
      foreach ($kc in $keyed) { $store.Add($kc) }
    } catch {
      Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; step = 'add' }
      return
    }
    $leaf = $keyed[0]
    Emit-OK (ConvertTo-CertificateJson $leaf $storeLocation $storeName)
  } finally { $store.Close() }
}
`, psQuote(location), psQuote(store), psQuote(friendlyName), certificateKeyFlags(location, exportable))
}

// buildCertificateReadScript renders the exact-thumbprint read. A missing
// certificate emits not_found; the handler maps it to a state drop.
func buildCertificateReadScript(location, store, thumbprint string) string {
	return psCertificateHeader + fmt.Sprintf(`
$storeLocation = %s
$storeName = %s
$thumbprint = %s
& {
  $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
  try { $store.Open('ReadOnly') } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint; step = 'open' }
    return
  }
  try {
    $cert = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint } | Select-Object -First 1)
    if ($cert.Count -eq 0) {
      Emit-Err 'not_found' ('No certificate ' + $thumbprint + ' in ' + $storeLocation + '\' + $storeName + '.') @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint }
      return
    }
    Emit-OK (ConvertTo-CertificateJson $cert[0] $storeLocation $storeName)
  } finally { $store.Close() }
}
`, psQuote(location), psQuote(store), psQuote(thumbprint))
}

// buildCertificateLookupScript renders the subject lookup. Exact -eq match
// (case-insensitive, never wildcard); zero matches emit not_found and the
// whole match set is returned so the data source can pick most_recent.
func buildCertificateLookupScript(location, store, subject string) string {
	return psCertificateHeader + fmt.Sprintf(`
$storeLocation = %s
$storeName = %s
$subject = %s
& {
  $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
  try { $store.Open('ReadOnly') } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; subject = $subject; step = 'open' }
    return
  }
  try {
    $matches = @($store.Certificates | Where-Object { $_.Subject -eq $subject })
  } finally { $store.Close() }
  if ($matches.Count -eq 0) {
    Emit-Err 'not_found' ('No certificate with subject ' + $subject + ' in ' + $storeLocation + '\' + $storeName + '.') @{ store_location = $storeLocation; store_name = $storeName; subject = $subject }
    return
  }
  $out = @()
  foreach ($m in $matches) { $out += (ConvertTo-CertificateJson $m $storeLocation $storeName) }
  Emit-OK $out
}
`, psQuote(location), psQuote(store), psQuote(subject))
}

// buildCertificateSetFriendlyScript renders the in-place friendly-name
// update plus read-back. An empty name clears the display name.
func buildCertificateSetFriendlyScript(location, store, thumbprint, friendlyName string) string {
	return psCertificateHeader + fmt.Sprintf(`
$storeLocation = %s
$storeName = %s
$thumbprint = %s
$friendlyName = %s
& {
  $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
  try { $store.Open('ReadWrite') } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint; step = 'open' }
    return
  }
  try {
    $cert = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint } | Select-Object -First 1)
    if ($cert.Count -eq 0) {
      Emit-Err 'not_found' ('No certificate ' + $thumbprint + ' in ' + $storeLocation + '\' + $storeName + '.') @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint }
      return
    }
    try { $cert[0].FriendlyName = $friendlyName } catch {
      Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint; step = 'rename' }
      return
    }
    Emit-OK (ConvertTo-CertificateJson $cert[0] $storeLocation $storeName)
  } finally { $store.Close() }
}
`, psQuote(location), psQuote(store), psQuote(thumbprint), psQuote(friendlyName))
}

// buildCertificateRemoveScript renders the guarded delete. A missing
// certificate emits Emit-OK null (idempotent delete). The private key is
// deleted before the store entry is removed, so a key-deletion failure
// leaves the certificate behind instead of orphaning the key.
func buildCertificateRemoveScript(location, store, thumbprint string, deleteKey bool) string {
	deleteToken := "$false"
	if deleteKey {
		deleteToken = "$true"
	}
	return psCertificateHeader + fmt.Sprintf(`
$storeLocation = %s
$storeName = %s
$thumbprint = %s
$deleteKey = %s
& {
  $store = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
  try { $store.Open('ReadWrite') } catch {
    Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint; step = 'open' }
    return
  }
  try {
    $cert = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint } | Select-Object -First 1)
    if ($cert.Count -eq 0) {
      Emit-OK $null
      return
    }
    if ($deleteKey -and $cert[0].HasPrivateKey) {
      try { Remove-CertificatePrivateKey $cert[0] } catch {
        Emit-Err (Classify-Certificate $_) ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint; step = 'delete_key' }
        return
      }
    }
    try { $store.Remove($cert[0]) } catch {
      $kind = Classify-Certificate $_
      if ($kind -eq 'not_found') {
        Emit-OK $null
        return
      }
      Emit-Err $kind ([string]$_.Exception.Message) @{ store_location = $storeLocation; store_name = $storeName; thumbprint = $thumbprint; step = 'remove' }
      return
    }
    Emit-OK ([ordered]@{ removed = $true })
  } finally { $store.Close() }
}
`, psQuote(location), psQuote(store), psQuote(thumbprint), deleteToken)
}

// ---------------------------------------------------------------------------
// Envelope plumbing
// ---------------------------------------------------------------------------

// certificateJSON mirrors the JSON object emitted by
// ConvertTo-CertificateJson.
type certificateJSON struct {
	StoreLocation string   `json:"store_location"`
	StoreName     string   `json:"store_name"`
	Thumbprint    string   `json:"thumbprint"`
	ThumbprintSHA string   `json:"thumbprint_sha256"`
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	SerialNumber  string   `json:"serial_number"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	DNSNames      []string `json:"dns_names"`
	HasPrivateKey bool     `json:"has_private_key"`
	FriendlyName  string   `json:"friendly_name"`
	RawBase64     string   `json:"raw_base64"`
}

// parseCertificateInfo projects a certificateJSON payload onto a
// CertificateInfo, normalising the thumbprint, timestamps and PEM.
func parseCertificateInfo(raw json.RawMessage, host string) (*CertificateInfo, error) {
	var j certificateJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, NewCertificateError(CertificateErrorUnknown,
			"failed to parse certificate state JSON", err,
			map[string]string{"host": host, "raw": truncate(string(raw), 512)})
	}
	info := &CertificateInfo{
		StoreLocation:    j.StoreLocation,
		StoreName:        j.StoreName,
		Thumbprint:       normalizeCertificateThumbprint(j.Thumbprint),
		ThumbprintSHA256: strings.ToUpper(strings.TrimSpace(j.ThumbprintSHA)),
		Subject:          j.Subject,
		Issuer:           j.Issuer,
		SerialNumber:     j.SerialNumber,
		NotBefore:        normalizeCertificateTime(j.NotBefore),
		NotAfter:         normalizeCertificateTime(j.NotAfter),
		DNSNames:         j.DNSNames,
		HasPrivateKey:    j.HasPrivateKey,
		FriendlyName:     j.FriendlyName,
	}
	if info.DNSNames == nil {
		info.DNSNames = []string{}
	}
	if j.RawBase64 != "" {
		if der, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(j.RawBase64)); derr == nil && len(der) > 0 {
			info.NormalizedPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}
	}
	return info, nil
}

// normalizeCertificateTime parses a host timestamp and renders it as UTC
// RFC 3339. Unparseable values pass through unchanged rather than failing
// the read.
func normalizeCertificateTime(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw)); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return raw
}

// runCertificateEnvelope executes script (prefixed with psCertificateHeader
// by the builders) and parses the JSON envelope through the shared
// runEnvelope helper. stdin carries the payload for create calls.
// Transport/timeout failures map to store_not_found-free unreachable
// context; remote Emit-Err kinds map via mapCertificateKind.
func (n *CertificateClientImpl) runCertificateEnvelope(ctx context.Context, op, script, stdin string, baseCtx map[string]string) (*Envelope, error) {
	baseContext := map[string]string{
		"host":      n.c.cfg.Host,
		"port":      strconv.Itoa(n.c.cfg.Port),
		"transport": "ssh",
	}
	for k, v := range baseCtx {
		baseContext[k] = v
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, in string) (string, string, error) {
			return runCertificatePowerShell(ctx, n.c, full, in)
		},
		op, script, stdin, baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout || eerr.Stage == EnvelopeStageTransport {
		return nil, NewCertificateError(CertificateErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewCertificateError(CertificateErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewCertificateError(mapCertificateKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// mapCertificateKind translates a PS-side "kind" string to a typed
// CertificateErrorKind. Unknown values fall through to Unknown.
func mapCertificateKind(k string) CertificateErrorKind {
	switch CertificateErrorKind(k) {
	case CertificateErrorStoreNotFound,
		CertificateErrorInvalidPassword,
		CertificateErrorCorruptCertificate,
		CertificateErrorAccessDenied,
		CertificateErrorAlreadyExists,
		CertificateErrorNotFound,
		CertificateErrorInteractiveUIRequired:
		return CertificateErrorKind(k)
	default:
		return CertificateErrorUnknown
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create imports the certificate into the store: validates the input,
// streams the payload on stdin, refuses an already-present thumbprint with
// already_exists, adds it via X509Store.Add and reads the result back.
// For PFX bundles only the certificate(s) carrying a private key (the leaf)
// are added; chain intermediates are not stored, so Delete removes exactly
// what Create added.
func (n *CertificateClientImpl) Create(ctx context.Context, input CertificateInput) (*CertificateInfo, error) {
	location, store, err := validateCertificateInput(input)
	if err != nil {
		return nil, err
	}
	baseCtx := map[string]string{"store_location": location, "store_name": store}
	if strings.TrimSpace(input.CertificatePEM) != "" {
		der, perr := ParseCertificatePEM(input.CertificatePEM)
		if perr != nil {
			return nil, perr
		}
		stdin := base64.StdEncoding.EncodeToString(der)
		resp, rerr := n.runCertificateEnvelope(ctx, "create",
			buildCertificateCreatePEM(location, store, input.FriendlyName), stdin, baseCtx)
		if rerr != nil {
			return nil, rerr
		}
		return parseCertificateInfo(resp.Data, n.c.cfg.Host)
	}
	password := ""
	if input.PFXPassword != nil {
		password = *input.PFXPassword
	}
	stdin := password + "\n" + strings.TrimSpace(input.PFXBase64)
	resp, rerr := n.runCertificateEnvelope(ctx, "create",
		buildCertificateCreatePFX(location, store, input.FriendlyName, input.Exportable), stdin, baseCtx)
	if rerr != nil {
		return nil, rerr
	}
	return parseCertificateInfo(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read returns the observed certificate for the thumbprint in the given
// store, or (nil, nil) when the certificate is gone. A missing store
// (store_not_found) is surfaced as an error so callers do not silently drop
// state when the store path itself is wrong.
func (n *CertificateClientImpl) Read(ctx context.Context, storeLocation, storeName, thumbprint string) (*CertificateInfo, error) {
	location, err := CanonicalCertificateStoreLocation(storeLocation)
	if err != nil {
		return nil, err
	}
	store, err := canonicalCertificateStoreName(storeName)
	if err != nil {
		return nil, err
	}
	thumb := normalizeCertificateThumbprint(thumbprint)
	resp, rerr := n.runCertificateEnvelope(ctx, "read",
		buildCertificateReadScript(location, store, thumb), "",
		map[string]string{"store_location": location, "store_name": store, "thumbprint": thumb})
	if rerr != nil {
		if IsCertificateError(rerr, CertificateErrorNotFound) {
			return nil, nil
		}
		return nil, rerr
	}
	return parseCertificateInfo(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// LookupBySubject (data source)
// ---------------------------------------------------------------------------

// LookupBySubject lists every certificate in the store whose Subject matches
// exactly (case-insensitive). Zero matches return not_found; the caller
// picks the winner (e.g. most recent).
func (n *CertificateClientImpl) LookupBySubject(ctx context.Context, storeLocation, storeName, subject string) ([]*CertificateInfo, error) {
	location, err := CanonicalCertificateStoreLocation(storeLocation)
	if err != nil {
		return nil, err
	}
	store, err := canonicalCertificateStoreName(storeName)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(subject) == "" {
		return nil, NewCertificateError(CertificateErrorNotFound,
			"subject must not be empty", nil,
			map[string]string{"store_location": location, "store_name": store})
	}
	resp, rerr := n.runCertificateEnvelope(ctx, "lookup",
		buildCertificateLookupScript(location, store, strings.TrimSpace(subject)), "",
		map[string]string{"store_location": location, "store_name": store, "subject": strings.TrimSpace(subject)})
	if rerr != nil {
		return nil, rerr
	}
	var arr []certificateJSON
	if jerr := json.Unmarshal(resp.Data, &arr); jerr != nil {
		return nil, NewCertificateError(CertificateErrorUnknown,
			"failed to parse certificate lookup JSON", jerr,
			map[string]string{"store_location": location, "store_name": store})
	}
	out := make([]*CertificateInfo, 0, len(arr))
	for _, j := range arr {
		raw, _ := json.Marshal(j)
		info, perr := parseCertificateInfo(raw, n.c.cfg.Host)
		if perr != nil {
			return nil, perr
		}
		out = append(out, info)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// UpdateFriendlyName
// ---------------------------------------------------------------------------

// UpdateFriendlyName sets the display name in place (empty clears it) and
// reads the result back.
func (n *CertificateClientImpl) UpdateFriendlyName(ctx context.Context, storeLocation, storeName, thumbprint, friendlyName string) (*CertificateInfo, error) {
	location, err := CanonicalCertificateStoreLocation(storeLocation)
	if err != nil {
		return nil, err
	}
	store, err := canonicalCertificateStoreName(storeName)
	if err != nil {
		return nil, err
	}
	thumb := normalizeCertificateThumbprint(thumbprint)
	resp, rerr := n.runCertificateEnvelope(ctx, "update",
		buildCertificateSetFriendlyScript(location, store, thumb, friendlyName), "",
		map[string]string{"store_location": location, "store_name": store, "thumbprint": thumb})
	if rerr != nil {
		return nil, rerr
	}
	return parseCertificateInfo(resp.Data, n.c.cfg.Host)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the certificate from the store. A missing certificate or
// store is a successful no-op (nil).
func (n *CertificateClientImpl) Delete(ctx context.Context, storeLocation, storeName, thumbprint string, deletePrivateKey bool) error {
	location, err := CanonicalCertificateStoreLocation(storeLocation)
	if err != nil {
		return err
	}
	store, err := canonicalCertificateStoreName(storeName)
	if err != nil {
		return err
	}
	thumb := normalizeCertificateThumbprint(thumbprint)
	resp, rerr := n.runCertificateEnvelope(ctx, "delete",
		buildCertificateRemoveScript(location, store, thumb, deletePrivateKey), "",
		map[string]string{"store_location": location, "store_name": store, "thumbprint": thumb})
	if rerr != nil {
		if IsCertificateError(rerr, CertificateErrorNotFound) ||
			IsCertificateError(rerr, CertificateErrorStoreNotFound) {
			return nil
		}
		return rerr
	}
	_ = resp
	return nil
}
