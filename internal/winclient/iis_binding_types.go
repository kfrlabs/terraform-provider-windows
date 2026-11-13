// Package winclient: types for the windows_iis_binding resource.
//
// An IISBindingState is one observed binding on a site: the protocol plus
// the bindingInformation string (IP:port:hostheader, e.g.
// "*:80:example.com"), the SSL flags, and — for https bindings — the bound
// certificate (thumbprint plus store). IISBindingErrorKind / IISBindingError
// follow the same shape as the sibling IIS resources so the provider layer
// branches with errors.Is.
package winclient

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// IISBindingErrorKind
// ---------------------------------------------------------------------------

// IISBindingErrorKind categorises errors returned by WindowsIISBindingClient.
type IISBindingErrorKind string

const (
	// IISBindingErrorNotFound is returned when the binding does not exist
	// on the site. Read maps it to (nil, nil) for drift removal; Delete
	// treats it as already absent; Update surfaces it.
	IISBindingErrorNotFound IISBindingErrorKind = "not_found"

	// IISBindingErrorSiteNotFound is returned when the owning site does
	// not exist on the host. The site is managed by windows_iis_site and
	// is never created implicitly.
	IISBindingErrorSiteNotFound IISBindingErrorKind = "site_not_found"

	// IISBindingErrorAlreadyExists is returned by Create when the same
	// protocol plus bindingInformation already exists on the site. The
	// message suggests terraform import.
	IISBindingErrorAlreadyExists IISBindingErrorKind = "already_exists"

	// IISBindingErrorConflict is returned by Create when the same protocol
	// plus bindingInformation already exists on a DIFFERENT site. One
	// listener cannot serve two sites; the message names the conflicting
	// site.
	IISBindingErrorConflict IISBindingErrorKind = "conflict"

	// IISBindingErrorSSLBindingConflict is returned by Create/Update when
	// the HTTP.sys SSL binding for the same IP:port carries a different
	// certificate (or a non-SNI binding already owns the IP:port). The
	// message names the expected remediation.
	IISBindingErrorSSLBindingConflict IISBindingErrorKind = "ssl_binding_conflict"

	// IISBindingErrorCertificateNotFound is returned by Create/Update when
	// the configured certificate thumbprint is absent from
	// Cert:\LocalMachine\<store>. Certificates are managed by
	// windows_certificate and are never created implicitly.
	IISBindingErrorCertificateNotFound IISBindingErrorKind = "certificate_not_found"

	// IISBindingErrorCertificateNoPrivateKey is returned by Create/Update
	// when the configured certificate has no private key
	// (HasPrivateKey is false): HTTP.sys cannot serve TLS without one.
	IISBindingErrorCertificateNoPrivateKey IISBindingErrorKind = "certificate_no_private_key"

	// IISBindingErrorWouldLockOut is returned by Create when the binding
	// port equals the SSH management port (the provider-configured port
	// or the probed ManagementPath ServerPort). Binding HTTP.sys to the
	// port the provider's own SSH session arrived on risks cutting the
	// management connection, so the operation is refused fail-closed
	// before anything is applied. An undeterminable management path also
	// fails closed with this kind.
	IISBindingErrorWouldLockOut IISBindingErrorKind = "would_lock_out"

	// IISBindingErrorIISNotInstalled is returned when the W3SVC/WAS
	// services or the WebAdministration module are missing. The message
	// points at the windows_feature resource (Web-Server).
	IISBindingErrorIISNotInstalled IISBindingErrorKind = "iis_not_installed"

	// IISBindingErrorAccessDenied is returned when the SSH user lacks the
	// privilege to manage IIS configuration.
	IISBindingErrorAccessDenied IISBindingErrorKind = "access_denied"

	// IISBindingErrorUnknown is the catch-all for unrecognised PowerShell
	// errors or SSH transport failures.
	IISBindingErrorUnknown IISBindingErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// IISBindingError
// ---------------------------------------------------------------------------

// IISBindingError is the structured error type returned by all
// WindowsIISBindingClient methods.
type IISBindingError struct {
	Kind    IISBindingErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements error.
func (e *IISBindingError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_iis_binding [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_iis_binding [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *IISBindingError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *IISBindingError) Is(target error) bool {
	t, ok := target.(*IISBindingError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewIISBindingError constructs a *IISBindingError.
func NewIISBindingError(kind IISBindingErrorKind, message string, cause error, ctx map[string]string) *IISBindingError {
	return &IISBindingError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsIISBindingError reports whether err is a *IISBindingError with the given kind.
func IsIISBindingError(err error, kind IISBindingErrorKind) bool {
	var ae *IISBindingError
	if errors.As(err, &ae) {
		return ae.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrIISBindingNotFound            = &IISBindingError{Kind: IISBindingErrorNotFound}
	ErrIISBindingSiteNotFound        = &IISBindingError{Kind: IISBindingErrorSiteNotFound}
	ErrIISBindingAlreadyExists       = &IISBindingError{Kind: IISBindingErrorAlreadyExists}
	ErrIISBindingConflict            = &IISBindingError{Kind: IISBindingErrorConflict}
	ErrIISBindingSSLBindingConflict  = &IISBindingError{Kind: IISBindingErrorSSLBindingConflict}
	ErrIISBindingCertificateNotFound = &IISBindingError{Kind: IISBindingErrorCertificateNotFound}
	ErrIISBindingCertificateNoKey    = &IISBindingError{Kind: IISBindingErrorCertificateNoPrivateKey}
	ErrIISBindingWouldLockOut        = &IISBindingError{Kind: IISBindingErrorWouldLockOut}
	ErrIISBindingIISNotInstalled     = &IISBindingError{Kind: IISBindingErrorIISNotInstalled}
	ErrIISBindingAccessDenied        = &IISBindingError{Kind: IISBindingErrorAccessDenied}
	ErrIISBindingUnknown             = &IISBindingError{Kind: IISBindingErrorUnknown}
)

// ---------------------------------------------------------------------------
// Protocols, ports, stores
// ---------------------------------------------------------------------------

// IIS binding protocols managed by this resource in v1.
const (
	// IISBindingProtocolHTTP is clear-text HTTP.
	IISBindingProtocolHTTP = "http"
	// IISBindingProtocolHTTPS is TLS HTTP.
	IISBindingProtocolHTTPS = "https"
)

// IISBindingStoreMy and IISBindingStoreWebHosting are the LocalMachine
// certificate stores an https binding may reference.
const (
	// IISBindingStoreMy is the personal store.
	IISBindingStoreMy = "My"
	// IISBindingStoreWebHosting is the IIS web-hosting store.
	IISBindingStoreWebHosting = "WebHosting"
)

// ValidateIISBindingProtocol rejects anything but http/https (case-insensitive,
// canonical lower-case).
func ValidateIISBindingProtocol(protocol string) error {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case IISBindingProtocolHTTP, IISBindingProtocolHTTPS:
		return nil
	default:
		return fmt.Errorf("invalid IIS binding protocol %q: want http or https", protocol)
	}
}

// CanonicalizeIISBindingProtocol lower-cases the protocol after validation.
func CanonicalizeIISBindingProtocol(protocol string) (string, error) {
	if err := ValidateIISBindingProtocol(protocol); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(protocol)), nil
}

// ValidateIISBindingPort rejects ports outside the 1-65535 range.
func ValidateIISBindingPort(port int64) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid IIS binding port %d: must be 1-65535", port)
	}
	return nil
}

// ValidateIISBindingStoreName rejects stores other than My/WebHosting
// (case-insensitive, canonical exact spelling).
func ValidateIISBindingStoreName(store string) error {
	switch strings.TrimSpace(store) {
	case IISBindingStoreMy, IISBindingStoreWebHosting:
		return nil
	default:
		for _, want := range []string{IISBindingStoreMy, IISBindingStoreWebHosting} {
			if strings.EqualFold(strings.TrimSpace(store), want) {
				return nil
			}
		}
		return fmt.Errorf("invalid IIS binding certificate store %q: want My or WebHosting", store)
	}
}

// CanonicalizeIISBindingStoreName resolves the store to its exact spelling.
func CanonicalizeIISBindingStoreName(store string) (string, error) {
	if err := ValidateIISBindingStoreName(store); err != nil {
		return "", err
	}
	if strings.EqualFold(strings.TrimSpace(store), IISBindingStoreWebHosting) {
		return IISBindingStoreWebHosting, nil
	}
	return IISBindingStoreMy, nil
}

// ---------------------------------------------------------------------------
// IP address, host header, thumbprint normalisation
// ---------------------------------------------------------------------------

// NormalizeIISBindingIPAddress canonicalises the configured ip_address:
// "*" (all unassigned) stays "*"; anything else must parse via netip (no
// zone IDs) and is rendered canonically (lower-case, compressed IPv6,
// IPv4-mapped IPv6 unmapped). Brackets are never accepted as input — they
// belong to the bindingInformation rendering only.
func NormalizeIISBindingIPAddress(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		s = "*"
	}
	if s == "*" {
		return "*", nil
	}
	if strings.HasPrefix(s, "[") || strings.HasSuffix(s, "]") {
		return "", fmt.Errorf("invalid IIS binding IP address %q: must be * or a bare IP address without brackets", raw)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("invalid IIS binding IP address %q: must be * or a valid IPv4/IPv6 address", raw)
	}
	if zone := addr.Zone(); zone != "" {
		return "", fmt.Errorf("invalid IIS binding IP address %q: must not carry a zone ID", raw)
	}
	return addr.Unmap().String(), nil
}

// NormalizeIISBindingHostHeader canonicalises the host header: surrounding
// whitespace is dropped and the remainder is lower-cased (host names are
// case-insensitive; IIS compares them so). The empty header (catch-all)
// stays empty.
func NormalizeIISBindingHostHeader(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// ValidateIISBindingHostHeader rejects headers that would corrupt the
// bindingInformation rendering or the import ID: embedded whitespace, "|"
// (the import-ID separator) and ":" (the bindingInformation separator).
func ValidateIISBindingHostHeader(host string) error {
	if strings.Contains(host, "|") {
		return fmt.Errorf("invalid IIS binding host header %q: must not contain \"|\"", host)
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("invalid IIS binding host header %q: must not contain \":\"", host)
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("invalid IIS binding host header %q: must not contain whitespace", host)
	}
	return nil
}

// iisBindingThumbprintRe matches a normalised thumbprint: 40 hex digits.
var iisBindingThumbprintRe = regexp.MustCompile(`^[0-9A-F]{40}$`)

// NormalizeIISBindingThumbprint canonicalises a certificate thumbprint:
// spaces are stripped and the remainder is upper-cased (Cert:\ thumbprints
// are upper-case hex; users paste lower-case or space-separated spellings).
func NormalizeIISBindingThumbprint(raw string) (string, error) {
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(raw), " ", ""))
	if !iisBindingThumbprintRe.MatchString(norm) {
		return "", fmt.Errorf("invalid IIS binding certificate thumbprint %q: want 40 hex characters (spaces allowed)", raw)
	}
	return norm, nil
}

// ---------------------------------------------------------------------------
// bindingInformation helpers
// ---------------------------------------------------------------------------

// BuildIISBindingInformation renders the canonical bindingInformation
// string "IP:port:hostheader": "*" for all unassigned, IPv6 addresses in
// brackets (e.g. "[::1]:443:example.com"), the host header lower-cased, and
// a trailing colon when the header is empty (e.g. "*:80:"). The inputs must
// already be normalised (see NormalizeIISBindingIPAddress /
// NormalizeIISBindingHostHeader); the port must pass ValidateIISBindingPort.
func BuildIISBindingInformation(ip string, port int64, host string) string {
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		ip = "[" + ip + "]"
	}
	return fmt.Sprintf("%s:%d:%s", ip, port, host)
}

// ParseIISBindingInformation splits a bindingInformation string back into
// its IP, port and host parts. An empty IP ("**:80:host" with the star
// omitted, i.e. ":80:host") normalises to "*"; a bracketed "[::1]" form
// unwraps to the bare address. The returned IP is canonicalised via
// NormalizeIISBindingIPAddress and the host is lower-cased; the port must
// be 1-65535.
func ParseIISBindingInformation(bindingInformation string) (ip string, port int64, host string, err error) {
	s := strings.TrimSpace(bindingInformation)
	rest := s
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, "", fmt.Errorf("invalid IIS binding information %q: want \"IP:port:hostheader\"", bindingInformation)
		}
		ip = s[1:end]
		rest = s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, "", fmt.Errorf("invalid IIS binding information %q: want \"IP:port:hostheader\"", bindingInformation)
		}
		rest = rest[1:]
	} else {
		parts := strings.SplitN(s, ":", 3)
		if len(parts) != 3 {
			return "", 0, "", fmt.Errorf("invalid IIS binding information %q: want \"IP:port:hostheader\"", bindingInformation)
		}
		ip = parts[0]
		rest = parts[1] + ":" + parts[2]
	}
	tail := strings.SplitN(rest, ":", 2)
	if len(tail) != 2 {
		return "", 0, "", fmt.Errorf("invalid IIS binding information %q: want \"IP:port:hostheader\"", bindingInformation)
	}
	p, cerr := strconv.ParseInt(tail[0], 10, 64)
	if cerr != nil {
		return "", 0, "", fmt.Errorf("invalid IIS binding information %q: bad port %q", bindingInformation, tail[0])
	}
	if err := ValidateIISBindingPort(p); err != nil {
		return "", 0, "", fmt.Errorf("invalid IIS binding information %q: %s", bindingInformation, err)
	}
	normIP, nerr := NormalizeIISBindingIPAddress(ip)
	if nerr != nil {
		return "", 0, "", fmt.Errorf("invalid IIS binding information %q: %s", bindingInformation, nerr)
	}
	normHost := NormalizeIISBindingHostHeader(tail[1])
	if verr := ValidateIISBindingHostHeader(tail[1]); verr != nil {
		return "", 0, "", fmt.Errorf("invalid IIS binding information %q: %s", bindingInformation, verr)
	}
	return normIP, p, normHost, nil
}

// ---------------------------------------------------------------------------
// SslFlags helpers
// ---------------------------------------------------------------------------

// IISBindingSslFlags renders the New-WebBinding -SslFlags value for the
// require_sni setting: bit 0 set (1) selects SNI, 0 is the plain
// IP/port-bound binding.
func IISBindingSslFlags(requireSNI bool) int64 {
	if requireSNI {
		return 1
	}
	return 0
}

// IISBindingRequireSNIFromSslFlags reports whether an observed SslFlags
// value carries the SNI bit.
func IISBindingRequireSNIFromSslFlags(flags int64) bool { return flags&1 != 0 }

// ---------------------------------------------------------------------------
// Import ID helpers (ResolveVolumeImportID-style)
// ---------------------------------------------------------------------------

// ParseIISBindingID splits a resource/import ID back into its site,
// protocol and bindingInformation parts: "<site>|<protocol>|<IP:port:host>".
// The bindingInformation may itself contain colons (IPv6) but never "|"
// (ValidateIISBindingHostHeader forbids it, and site names forbid it via
// ValidateIISSiteName), so exactly three pipe-separated parts are required.
// Each part is validated and canonicalised.
func ParseIISBindingID(id string) (site, protocol, bindingInformation string, err error) {
	parts := strings.Split(id, "|")
	if len(parts) != 3 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return "", "", "", fmt.Errorf("invalid IIS binding ID %q: want \"<site>|<protocol>|<IP:port:hostheader>\"", id)
	}
	site = strings.TrimSpace(parts[0])
	if verr := ValidateIISSiteName(site); verr != nil {
		return "", "", "", fmt.Errorf("invalid IIS binding ID %q: %s", id, verr)
	}
	protocol, perr := CanonicalizeIISBindingProtocol(parts[1])
	if perr != nil {
		return "", "", "", fmt.Errorf("invalid IIS binding ID %q: %s", id, perr)
	}
	ip, port, host, berr := ParseIISBindingInformation(strings.TrimSpace(parts[2]))
	if berr != nil {
		return "", "", "", fmt.Errorf("invalid IIS binding ID %q: %s", id, berr)
	}
	return site, protocol, BuildIISBindingInformation(ip, port, host), nil
}

// IISBindingID builds the resource ID from its canonical parts:
// "<site>|<protocol>|<bindingInformation>".
func IISBindingID(site, protocol, bindingInformation string) string {
	return site + "|" + protocol + "|" + bindingInformation
}

// ---------------------------------------------------------------------------
// SSH-port lockout guard (pure decision helper)
// ---------------------------------------------------------------------------

// IISBindingWouldLockOut reports whether binding the given port would risk
// cutting the management connection: true when port equals any of the
// candidate SSH ports (the provider-configured port and/or the probed
// ManagementPath ServerPort). Non-positive candidates are ignored (an
// unknown ServerPort never matches a valid binding port).
func IISBindingWouldLockOut(port int64, sshPorts ...int) bool {
	for _, sp := range sshPorts {
		if sp > 0 && port == int64(sp) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// IISBindingState — observed binding state
// ---------------------------------------------------------------------------

// IISBindingState holds the observed state of one IIS binding as returned
// by the Read pipeline (and by every mutating call, which re-reads before
// responding). CertificateThumbprint is "" when no certificate is bound;
// CertificateStoreName is "" then as well.
type IISBindingState struct {
	SiteName              string
	Protocol              string
	IPAddress             string
	Port                  int64
	HostHeader            string
	RequireSNI            bool
	CertificateThumbprint string
	CertificateStoreName  string
	BindingInformation    string
	SslFlags              int64
}

// ---------------------------------------------------------------------------
// IISBindingInput — Create/Update envelope
// ---------------------------------------------------------------------------

// IISBindingInput carries the desired configuration for Create/Update.
// SiteName, Protocol, IPAddress, Port and HostHeader identify the binding
// (all ForceNew on the provider side): Update never changes them and only
// applies RequireSNI plus the certificate pair in place. A nil
// RequireSNI means "unmanaged" (leave SslFlags untouched); a nil
// CertificateThumbprint means "no certificate change" on Update and "no
// certificate" on Create. CertificateStoreName is honoured only alongside
// a thumbprint (default "My").
type IISBindingInput struct {
	SiteName              string
	Protocol              string
	IPAddress             string
	Port                  int64
	HostHeader            string
	RequireSNI            *bool
	CertificateThumbprint *string
	CertificateStoreName  string
}

// ValidateIISBindingInput rejects invalid names, protocols, addresses,
// ports, hosts, SNI combinations and certificate references before any
// script runs. https-only rules (thumbprint and require_sni need https;
// require_sni needs a host header) are enforced here as well as at plan
// time so a programming error fails fast instead of reaching the host.
func ValidateIISBindingInput(in IISBindingInput) error {
	ctx := map[string]string{"site_name": in.SiteName}
	fail := func(err error) error {
		return NewIISBindingError(IISBindingErrorUnknown, err.Error(), nil, ctx)
	}
	if err := ValidateIISSiteName(in.SiteName); err != nil {
		return fail(err)
	}
	if _, err := CanonicalizeIISBindingProtocol(in.Protocol); err != nil {
		return fail(err)
	}
	protocol, _ := CanonicalizeIISBindingProtocol(in.Protocol)
	if _, err := NormalizeIISBindingIPAddress(in.IPAddress); err != nil {
		return fail(err)
	}
	if err := ValidateIISBindingPort(in.Port); err != nil {
		return fail(err)
	}
	host := NormalizeIISBindingHostHeader(in.HostHeader)
	if err := ValidateIISBindingHostHeader(in.HostHeader); err != nil {
		return fail(err)
	}
	if in.RequireSNI != nil && *in.RequireSNI {
		if protocol != IISBindingProtocolHTTPS {
			return fail(fmt.Errorf("require_sni needs protocol https, got %q", in.Protocol))
		}
		if host == "" {
			return fail(fmt.Errorf("require_sni needs a host header: SNI selects the certificate by server name"))
		}
	}
	if in.CertificateThumbprint != nil && strings.TrimSpace(*in.CertificateThumbprint) != "" {
		if protocol != IISBindingProtocolHTTPS {
			return fail(fmt.Errorf("certificate_thumbprint needs protocol https, got %q", in.Protocol))
		}
		if _, err := NormalizeIISBindingThumbprint(*in.CertificateThumbprint); err != nil {
			return fail(err)
		}
		if _, err := CanonicalizeIISBindingStoreName(in.CertificateStoreName); err != nil {
			return fail(err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// WindowsIISBindingClient
// ---------------------------------------------------------------------------

// WindowsIISBindingClient defines the contract for managing IIS bindings
// via SSH (WebAdministration PowerShell module).
//
// Error conventions:
//   - Read returns (nil, nil) when the site or the binding does not exist
//     (drift removal).
//   - Create returns already_exists with an import hint when the same
//     protocol plus bindingInformation already exists on the site,
//     conflict (naming the other site) when it exists elsewhere, and
//     site_not_found when the owning site is missing.
//   - Create/Update return certificate_not_found when the thumbprint is
//     absent from Cert:\LocalMachine\<store> and
//     certificate_no_private_key when it carries no private key.
//   - Create refuses the provider/SSH port with would_lock_out
//     fail-closed (before anything is applied).
//   - Update applies only RequireSNI plus the certificate pair in place
//     (remove plus re-add in one script); identity fields are never
//     re-written (ForceNew).
//   - Delete removes the SSL certificate binding first, then the binding
//     itself; a missing binding is already absent.
type WindowsIISBindingClient interface {
	// Create adds the binding (New-WebBinding -SslFlags), binds the
	// certificate when configured (AddSslCertificate with binding
	// rollback on failure), auto-starts the site when its serverAutoStart
	// asks for it, and returns the read-back state.
	Create(ctx context.Context, in IISBindingInput) (*IISBindingState, error)

	// Read returns the exact binding match (site plus protocol plus
	// bindingInformation), or (nil, nil) when the site or the binding
	// does not exist.
	Read(ctx context.Context, site, protocol, bindingInformation string) (*IISBindingState, error)

	// Update applies only the in-place fields (RequireSNI plus the
	// certificate pair) to the named binding and returns the read-back
	// state. A missing site or binding yields site_not_found/not_found.
	Update(ctx context.Context, in IISBindingInput) (*IISBindingState, error)

	// Delete removes the certificate binding (when https) and then the
	// binding itself. A missing binding is already absent.
	Delete(ctx context.Context, site, protocol, bindingInformation string) error
}
