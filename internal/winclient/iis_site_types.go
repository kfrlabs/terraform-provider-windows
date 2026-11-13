// Package winclient: types for the windows_iis_site resource.
//
// IISSiteState is the observed site reported by Read; IISSiteSettings is
// the partial-management delta consumed by Create/Update (nil means
// unmanaged, never written). IISSiteErrorKind / IISSiteError follow the
// same shape as the sibling IIS resources so the provider layer branches
// with errors.Is.
//
// Bindings are intentionally a read-only view (protocol plus
// binding_information): they are observed here so plans stay stable, but
// they are managed by the windows_iis_site_binding resource (issue #285),
// never by this one.
package winclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// IISSiteErrorKind
// ---------------------------------------------------------------------------

// IISSiteErrorKind categorises errors returned by WindowsIISSiteClient.
type IISSiteErrorKind string

const (
	// IISSiteErrorNotFound is returned when the site does not exist.
	// Read maps it to (nil, nil) for drift removal; Delete treats it as
	// already absent.
	IISSiteErrorNotFound IISSiteErrorKind = "not_found"

	// IISSiteErrorAlreadyExists is returned by Create when a site with
	// the same name already exists. The message suggests terraform import.
	IISSiteErrorAlreadyExists IISSiteErrorKind = "already_exists"

	// IISSiteErrorIDConflict is returned by Create/Update when the
	// configured site_id is already used by another site. Site IDs share
	// one namespace across all sites; the message names the conflicting
	// site.
	IISSiteErrorIDConflict IISSiteErrorKind = "id_conflict"

	// IISSiteErrorAppPoolNotFound is returned by Create/Update when the
	// configured application_pool does not exist on the host. The pool
	// must be managed separately (windows_iis_app_pool); it is never
	// created implicitly.
	IISSiteErrorAppPoolNotFound IISSiteErrorKind = "app_pool_not_found"

	// IISSiteErrorPathNotFound is returned by Create/Update when the
	// configured physical_path does not exist on the host. The directory
	// is never created implicitly (manage it with windows_directory).
	IISSiteErrorPathNotFound IISSiteErrorKind = "path_not_found"

	// IISSiteErrorIISNotInstalled is returned when the W3SVC/WAS
	// services or the WebAdministration module are missing. The message
	// points at the windows_feature resource (Web-Server).
	IISSiteErrorIISNotInstalled IISSiteErrorKind = "iis_not_installed"

	// IISSiteErrorAccessDenied is returned when the SSH user lacks the
	// privilege to manage IIS configuration.
	IISSiteErrorAccessDenied IISSiteErrorKind = "access_denied"

	// IISSiteErrorUnknown is the catch-all for unrecognised PowerShell
	// errors or SSH transport failures.
	IISSiteErrorUnknown IISSiteErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// IISSiteError
// ---------------------------------------------------------------------------

// IISSiteError is the structured error type returned by all
// WindowsIISSiteClient methods.
type IISSiteError struct {
	Kind    IISSiteErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements error.
func (e *IISSiteError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_iis_site [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_iis_site [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *IISSiteError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *IISSiteError) Is(target error) bool {
	t, ok := target.(*IISSiteError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewIISSiteError constructs a *IISSiteError.
func NewIISSiteError(kind IISSiteErrorKind, message string, cause error, ctx map[string]string) *IISSiteError {
	return &IISSiteError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsIISSiteError reports whether err is a *IISSiteError with the given kind.
func IsIISSiteError(err error, kind IISSiteErrorKind) bool {
	var ae *IISSiteError
	if errors.As(err, &ae) {
		return ae.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrIISSiteNotFound        = &IISSiteError{Kind: IISSiteErrorNotFound}
	ErrIISSiteAlreadyExists   = &IISSiteError{Kind: IISSiteErrorAlreadyExists}
	ErrIISSiteIDConflict      = &IISSiteError{Kind: IISSiteErrorIDConflict}
	ErrIISSiteAppPoolNotFound = &IISSiteError{Kind: IISSiteErrorAppPoolNotFound}
	ErrIISSitePathNotFound    = &IISSiteError{Kind: IISSiteErrorPathNotFound}
	ErrIISSiteIISNotInstalled = &IISSiteError{Kind: IISSiteErrorIISNotInstalled}
	ErrIISSiteAccessDenied    = &IISSiteError{Kind: IISSiteErrorAccessDenied}
	ErrIISSiteUnknown         = &IISSiteError{Kind: IISSiteErrorUnknown}
)

// ---------------------------------------------------------------------------
// Name and site-ID validation
// ---------------------------------------------------------------------------

// iisSiteIDMax is the largest IIS site ID: IDs are unsigned 32-bit values.
// When site_id is left unconfigured IIS allocates the lowest free ID
// itself, so this bound only guards explicitly configured values.
const iisSiteIDMax = 4294967295

// ValidateIISSiteName rejects names IIS cannot carry. The rules mirror
// ValidateIISAppPoolName (issue #284 open-question decision): 1-64
// characters, none of the forbidden / \ [ ] : ; , ? * " < > | set (which
// also keeps wildcard expansion impossible for the -Name parameters that
// accept wildcards), and no leading/trailing spaces.
func ValidateIISSiteName(name string) error {
	if len(name) < 1 || len(name) > 64 {
		return fmt.Errorf("invalid IIS site name %q: must be 1-64 characters", name)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("invalid IIS site name %q: must not have leading or trailing spaces", name)
	}
	if strings.ContainsAny(name, iisAppPoolForbiddenChars) {
		return fmt.Errorf("invalid IIS site name %q: must not contain any of / \\ [ ] : ; , ? * \" < > |", name)
	}
	return nil
}

// ValidateIISSiteID rejects site IDs outside the IIS uint32 range.
func ValidateIISSiteID(id int64) error {
	if id < 1 || id > iisSiteIDMax {
		return fmt.Errorf("invalid IIS site ID %d: must be 1-%d", id, int64(iisSiteIDMax))
	}
	return nil
}

// ---------------------------------------------------------------------------
// IISSiteBinding — read-only bindings view (owned by issue #285)
// ---------------------------------------------------------------------------

// IISSiteBinding is one observed IIS binding: the protocol (http, https,
// net.tcp, ...) plus the bindingInformation string
// (IP:port:hostheader, e.g. "*:80:example.com"). The shape is frozen for
// issue #285, which promotes this exact view to a managed resource.
type IISSiteBinding struct {
	Protocol           string
	BindingInformation string
}

// ---------------------------------------------------------------------------
// IISSiteSettings — partial-management delta for Create/Update
// ---------------------------------------------------------------------------

// IISSiteSettings carries the desired configuration delta for an IIS
// site. Every field beyond Name is optional: a nil pointer means
// "unmanaged" — the attribute is omitted from the write script and the
// host value is left untouched. SiteID is create-only (ForceNew on the
// provider side): Update never sends it.
type IISSiteSettings struct {
	SiteID                   *int64
	PhysicalPath             *string
	ApplicationPool          *string
	AutoStart                *bool
	PreloadEnabled           *bool
	EnabledProtocols         *string
	LogEnabled               *bool
	LogDirectory             *string
	LogFormat                *string
	ConnectionTimeoutSeconds *int64
	MaxConnections           *int64
	State                    *string
}

// IISSiteConfigured reports whether at least one attribute is managed.
func (s IISSiteSettings) IISSiteConfigured() bool {
	return s.SiteID != nil ||
		s.PhysicalPath != nil ||
		s.ApplicationPool != nil ||
		s.AutoStart != nil ||
		s.PreloadEnabled != nil ||
		s.EnabledProtocols != nil ||
		s.LogEnabled != nil ||
		s.LogDirectory != nil ||
		s.LogFormat != nil ||
		s.ConnectionTimeoutSeconds != nil ||
		s.MaxConnections != nil ||
		s.State != nil
}

// ---------------------------------------------------------------------------
// IISSiteState — observed site state
// ---------------------------------------------------------------------------

// IISSiteState holds the observed state of an IIS site as returned by the
// Read pipeline. ConnectionTimeoutSeconds is whole seconds (converted
// server-side from the limits.connectionTimeout TimeSpan); Bindings is the
// read-only view owned by issue #285.
type IISSiteState struct {
	Name                     string
	SiteID                   int64
	PhysicalPath             string
	ApplicationPool          string
	AutoStart                bool
	PreloadEnabled           bool
	EnabledProtocols         string
	LogEnabled               bool
	LogDirectory             string
	LogFormat                string
	ConnectionTimeoutSeconds int64
	MaxConnections           int64
	Bindings                 []IISSiteBinding
	State                    string
}

// ---------------------------------------------------------------------------
// IISSiteInput — Create/Update envelope
// ---------------------------------------------------------------------------

// IISSiteInput carries the desired configuration for Create/Update.
type IISSiteInput struct {
	Name     string
	Settings IISSiteSettings
}

// ---------------------------------------------------------------------------
// WindowsIISSiteClient
// ---------------------------------------------------------------------------

// WindowsIISSiteClient defines the contract for managing IIS sites via
// SSH (WebAdministration PowerShell module).
//
// Error conventions:
//   - Read returns (nil, nil) when the site does not exist (drift removal).
//   - Create returns already_exists with an import hint when the site
//     already exists; on partial failure the half-created site is deleted
//     best-effort and the original error is returned.
//   - Create/Update return id_conflict when the configured site_id is
//     already used by another site, app_pool_not_found when the configured
//     application_pool does not exist, and path_not_found when the
//     configured physical_path does not exist (the directory is never
//     created implicitly).
//   - Update writes only the configured settings; site_id is never
//     re-sent (ForceNew).
//   - Delete removes the site (Remove-Website); a missing site is already
//     absent.
//   - A configured Started state with zero bindings leaves the site
//     Stopped without failing: IIS cannot run an unbound site. The caller
//     (provider layer) warns; the observed Stopped state is returned.
type WindowsIISSiteClient interface {
	// Create creates the site with zero bindings, applies the configured
	// settings in one script, enforces the configured state (subject to
	// the zero-bindings rule above), and returns the read-back state.
	Create(ctx context.Context, in IISSiteInput) (*IISSiteState, error)

	// Read returns the current state of the named site, or (nil, nil)
	// when the site does not exist.
	Read(ctx context.Context, name string) (*IISSiteState, error)

	// Update applies only the configured settings to the named site,
	// enforces the configured state (subject to the zero-bindings rule
	// above), and returns the read-back state. A missing site yields
	// not_found.
	Update(ctx context.Context, in IISSiteInput) (*IISSiteState, error)

	// Delete removes the named site. A missing site is already absent.
	Delete(ctx context.Context, name string) error
}
