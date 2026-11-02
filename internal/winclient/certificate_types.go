// Package winclient defines the CertificateClient interface and associated
// types for managing X.509 certificates in Windows certificate stores over
// SSH (issue #222).
//
// Scope: import a certificate into Cert:\<location>\<store> from a PEM blob
// or a PFX bundle (X509Certificate2 / X509Certificate2Collection +
// X509Store.Add), read it back, update only its friendly name, and remove
// it (optionally deleting the private key). Out of scope: enrolment and
// renewal (New-SelfSignedCertificate, Request-Certificate), ACLs on private
// keys, and store ACLs.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// CertificateErrorKind — typed error categories
// ---------------------------------------------------------------------------

// CertificateErrorKind categorises errors returned by CertificateClient
// operations. Use errors.Is(err, ErrCertificate*) or IsCertificateError for
// programmatic error handling.
type CertificateErrorKind string

const (
	// CertificateErrorStoreNotFound is returned when the certificate store
	// cannot be opened (unknown store location, missing provider path).
	CertificateErrorStoreNotFound CertificateErrorKind = "store_not_found"

	// CertificateErrorInvalidPassword is returned when a PFX bundle cannot
	// be decrypted with the supplied password.
	CertificateErrorInvalidPassword CertificateErrorKind = "invalid_password"

	// CertificateErrorCorruptCertificate is returned when the PEM or PFX
	// payload cannot be decoded (bad base64, truncated blob, ASN.1 errors).
	CertificateErrorCorruptCertificate CertificateErrorKind = "corrupt_certificate"

	// CertificateErrorAccessDenied is returned when the SSH user lacks the
	// privilege for the store operation (typically writing LocalMachine
	// without elevation).
	CertificateErrorAccessDenied CertificateErrorKind = "access_denied"

	// CertificateErrorAlreadyExists is returned when a certificate with the
	// same thumbprint is already present in the store (suggest terraform
	// import).
	CertificateErrorAlreadyExists CertificateErrorKind = "already_exists"

	// CertificateErrorNotFound is returned when no certificate with the
	// requested thumbprint (or subject) is present.
	CertificateErrorNotFound CertificateErrorKind = "not_found"

	// CertificateErrorInteractiveUIRequired is returned when the host
	// demands user interaction (smart-card prompt, consent UI) to complete
	// a PFX import. Nothing is applied.
	CertificateErrorInteractiveUIRequired CertificateErrorKind = "interactive_ui_required"

	// CertificateErrorUnknown is the catch-all for unmapped PowerShell or
	// SSH failures.
	CertificateErrorUnknown CertificateErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// CertificateError — structured error
// ---------------------------------------------------------------------------

// CertificateError is the structured error type returned by all
// CertificateClient methods. Use errors.Is(err, ErrCertificate*) for kind
// matching, or errors.As(err, &ce) to inspect Context.
type CertificateError struct {
	// Kind is the machine-readable error category.
	Kind CertificateErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics. It must not contain secrets: payloads travel on stdin
	// and are never interpolated into messages.
	Message string

	// Context holds structured diagnostic key-value pairs (e.g. "host",
	// "port", "transport", "store_location", "store_name", "thumbprint").
	// All values must be safe to log.
	Context map[string]string

	// Cause is the underlying error, if any (typically an SSH transport or
	// PowerShell parsing error).
	Cause error
}

// Error implements the error interface.
func (e *CertificateError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_certificate [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_certificate [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *CertificateError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *CertificateError) Is(target error) bool {
	t, ok := target.(*CertificateError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewCertificateError constructs a *CertificateError. Pass a nil cause when
// no underlying error exists. The ctx map may be nil.
func NewCertificateError(kind CertificateErrorKind, message string, cause error, ctx map[string]string) *CertificateError {
	return &CertificateError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsCertificateError reports whether err is a *CertificateError of the given
// kind.
func IsCertificateError(err error, kind CertificateErrorKind) bool {
	var ce *CertificateError
	if errors.As(err, &ce) {
		return ce.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

var (
	ErrCertificateStoreNotFound      = &CertificateError{Kind: CertificateErrorStoreNotFound}
	ErrCertificateInvalidPassword    = &CertificateError{Kind: CertificateErrorInvalidPassword}
	ErrCertificateCorruptCertificate = &CertificateError{Kind: CertificateErrorCorruptCertificate}
	ErrCertificateAccessDenied       = &CertificateError{Kind: CertificateErrorAccessDenied}
	ErrCertificateAlreadyExists      = &CertificateError{Kind: CertificateErrorAlreadyExists}
	ErrCertificateNotFound           = &CertificateError{Kind: CertificateErrorNotFound}
	ErrCertificateInteractiveUI      = &CertificateError{Kind: CertificateErrorInteractiveUIRequired}
	ErrCertificateUnknown            = &CertificateError{Kind: CertificateErrorUnknown}
)

// ---------------------------------------------------------------------------
// Store locations
// ---------------------------------------------------------------------------

// Supported Windows certificate store locations.
const (
	CertificateStoreLocalMachine = "LocalMachine"
	CertificateStoreCurrentUser  = "CurrentUser"
)

// ---------------------------------------------------------------------------
// CertificateInput — parameters for Create
// ---------------------------------------------------------------------------

// CertificateInput carries the desired certificate for Create. Exactly one
// of CertificatePEM and PFXBase64 must be set (enforced by the provider
// schema and re-checked defensively here).
type CertificateInput struct {
	// StoreLocation is "LocalMachine" or "CurrentUser".
	StoreLocation string

	// StoreName is the store name (e.g. "My"). It must not contain "/"
	// (the resource ID separator).
	StoreName string

	// CertificatePEM is the PEM-encoded certificate (CERTIFICATE block).
	// Mutually exclusive with PFXBase64.
	CertificatePEM string

	// PFXBase64 is the base64-encoded PFX/PKCS#12 bundle. It travels to
	// the host on stdin, never in the script body. Mutually exclusive
	// with CertificatePEM.
	PFXBase64 string

	// PFXPassword is the password decrypting the PFX bundle, or nil when
	// the bundle is unprotected. It travels to the host on stdin, never
	// in the script body or in logs.
	PFXPassword *string

	// Exportable marks the imported private key exportable. PFX only:
	// rejected with a PEM payload.
	Exportable bool

	// FriendlyName is the display name assigned at import. Empty means
	// "leave the Windows default".
	FriendlyName string
}

// ---------------------------------------------------------------------------
// CertificateInfo — observed state
// ---------------------------------------------------------------------------

// CertificateInfo holds the observed state of one certificate as returned
// by the Create/Read/Update pipelines.
type CertificateInfo struct {
	// StoreLocation is the canonical location ("LocalMachine" or
	// "CurrentUser").
	StoreLocation string

	// StoreName is the store name, as configured.
	StoreName string

	// Thumbprint is the SHA-1 thumbprint (uppercase hex, Windows style).
	Thumbprint string

	// ThumbprintSHA256 is the SHA-256 digest of the DER bytes (uppercase
	// hex).
	ThumbprintSHA256 string

	// Subject is the distinguished name, as observed on the host
	// (e.g. "CN=example.com, O=Example").
	Subject string

	// Issuer is the issuer distinguished name, as observed on the host.
	Issuer string

	// SerialNumber is the serial number hex string, as observed on the
	// host.
	SerialNumber string

	// NotBefore and NotAfter are RFC 3339 timestamps bounding validity.
	NotBefore string
	NotAfter  string

	// DNSNames are the DNS entries of the subject-alternative-name
	// extension, as observed on the host (possibly empty).
	DNSNames []string

	// HasPrivateKey reports whether the stored certificate carries a
	// private key.
	HasPrivateKey bool

	// FriendlyName is the display name, as observed on the host (possibly
	// empty).
	FriendlyName string

	// NormalizedPEM is the canonical PEM encoding of the observed
	// certificate (first CERTIFICATE block, standard 64-column base64).
	// Empty when the host did not return the raw bytes.
	NormalizedPEM string
}

// ---------------------------------------------------------------------------
// CertificateClient — CRUD interface
// ---------------------------------------------------------------------------

// CertificateClient defines the contract for managing certificates in
// Windows certificate stores on a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation. All methods return *CertificateError (wrapped in error).
//
// Create streams the PEM/PFX payload to the host on stdin via
// RunPowerShellWithInput: secrets never appear in the script body, the
// encoded command or SSH session logs.
type CertificateClient interface {
	// Create imports the certificate into the store: decodes the payload,
	// refuses an already-present thumbprint with already_exists (suggesting
	// import), adds it via X509Store.Add and reads the result back.
	Create(ctx context.Context, input CertificateInput) (*CertificateInfo, error)

	// Read returns the observed certificate for the thumbprint in the
	// given store, or (nil, nil) when the certificate is gone (the resource
	// handler then drops the resource from state). A missing store
	// (store_not_found) is an error, never a silent state drop.
	Read(ctx context.Context, storeLocation, storeName, thumbprint string) (*CertificateInfo, error)

	// LookupBySubject lists every certificate in the store whose Subject
	// matches exactly (case-insensitive). Zero matches return not_found.
	// The caller picks the winner (e.g. most recent).
	LookupBySubject(ctx context.Context, storeLocation, storeName, subject string) ([]*CertificateInfo, error)

	// UpdateFriendlyName sets the display name in place (empty clears it)
	// and reads the result back.
	UpdateFriendlyName(ctx context.Context, storeLocation, storeName, thumbprint, friendlyName string) (*CertificateInfo, error)

	// Delete removes the certificate from the store. When deletePrivateKey
	// is true the private key is deleted from the key store before the
	// certificate entry is removed, so a key-deletion failure leaves the
	// certificate behind instead of orphaning the key. A missing
	// certificate or store is a successful no-op (nil).
	Delete(ctx context.Context, storeLocation, storeName, thumbprint string, deletePrivateKey bool) error
}
