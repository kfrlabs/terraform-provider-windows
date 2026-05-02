// Package winclient — types for windows_winget_package
//
// This file contains the WingetPackageErrorKind enum, WingetPackageError
// struct, sentinel errors, WingetPackageInput, WingetPackageState, and the
// WingetPackageClient interface. The concrete implementation lives in
// winget_package.go.
//
// Spec alignment: windows_winget_package spec v1 (2026-05-01).
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// WingetPackageErrorKind — typed error categories
// ---------------------------------------------------------------------------

// WingetPackageErrorKind categorises errors returned by WingetPackageClient
// operations. Use errors.Is(err, ErrWingetPackage*) or IsWingetPackageError
// for programmatic error handling in resource CRUD handlers.
type WingetPackageErrorKind string

const (
	// WingetPackageErrorModuleMissing is returned when the
	// Microsoft.WinGet.Client PowerShell module is not importable (EC-1).
	WingetPackageErrorModuleMissing WingetPackageErrorKind = "module_missing"

	// WingetPackageErrorAlreadyInstalled is returned when Install detects a
	// pre-existing package via the pre-flight Get-WinGetPackage (EC-2).
	WingetPackageErrorAlreadyInstalled WingetPackageErrorKind = "already_installed"

	// WingetPackageErrorVersionNotAvailable is returned when
	// Install-WinGetPackage or Update-WinGetPackage reports
	// NoApplicableInstaller or InvalidVersion (EC-4).
	WingetPackageErrorVersionNotAvailable WingetPackageErrorKind = "version_not_available"

	// WingetPackageErrorBlockedByPolicy is returned when the source requires
	// interactive MSA authentication or is policy-blocked (EC-5).
	WingetPackageErrorBlockedByPolicy WingetPackageErrorKind = "blocked_by_policy"

	// WingetPackageErrorPermission is returned when the WinRM session lacks
	// Local Administrator privileges (EC-7).
	WingetPackageErrorPermission WingetPackageErrorKind = "permission_denied"

	// WingetPackageErrorSourceUnreachable is returned after one retry for a
	// transient network failure contacting the winget source (EC-8).
	WingetPackageErrorSourceUnreachable WingetPackageErrorKind = "source_unreachable"

	// WingetPackageErrorCatalogError is returned when the package ID has been
	// renamed or removed from the catalog (EC-9).
	WingetPackageErrorCatalogError WingetPackageErrorKind = "catalog_error"

	// WingetPackageErrorResourceInUse is returned when winget's per-machine
	// mutex is held after 3 back-off retries (EC-10).
	WingetPackageErrorResourceInUse WingetPackageErrorKind = "resource_in_use"

	// WingetPackageErrorUnknown is returned for unexpected PowerShell errors
	// or WinRM transport failures not matching any of the above categories.
	WingetPackageErrorUnknown WingetPackageErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// WingetPackageError — structured error type
// ---------------------------------------------------------------------------

// WingetPackageError is the structured error type returned by all
// WingetPackageClient methods.
//
// Use errors.Is(err, ErrWingetPackage*) for kind matching, or
// errors.As(err, &we) to access the full Context map for diagnostics.
type WingetPackageError struct {
	// Kind is the machine-readable error category.
	Kind WingetPackageErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics.
	Message string

	// Context holds structured diagnostic key-value pairs.
	// All values must be safe to log.
	Context map[string]string

	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *WingetPackageError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_winget_package [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_winget_package [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *WingetPackageError) Unwrap() error {
	return e.Cause
}

// Is implements errors.Is comparison by Kind only.
func (e *WingetPackageError) Is(target error) bool {
	t, ok := target.(*WingetPackageError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewWingetPackageError constructs a *WingetPackageError. Pass nil for cause
// when no underlying error exists. The ctx map may be nil.
func NewWingetPackageError(kind WingetPackageErrorKind, message string, cause error, ctx map[string]string) *WingetPackageError {
	return &WingetPackageError{
		Kind:    kind,
		Message: message,
		Cause:   cause,
		Context: ctx,
	}
}

// IsWingetPackageError reports whether err is a *WingetPackageError with the
// given kind.
func IsWingetPackageError(err error, kind WingetPackageErrorKind) bool {
	var we *WingetPackageError
	if errors.As(err, &we) {
		return we.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

// Pre-constructed sentinel *WingetPackageError values. Because
// WingetPackageError.Is compares by Kind only,
// errors.Is(returnedErr, ErrWingetPackageModuleMissing) returns true for any
// *WingetPackageError{Kind: WingetPackageErrorModuleMissing}.
var (
	ErrWingetPackageModuleMissing       = &WingetPackageError{Kind: WingetPackageErrorModuleMissing}
	ErrWingetPackageAlreadyInstalled    = &WingetPackageError{Kind: WingetPackageErrorAlreadyInstalled}
	ErrWingetPackageVersionNotAvailable = &WingetPackageError{Kind: WingetPackageErrorVersionNotAvailable}
	ErrWingetPackageBlockedByPolicy     = &WingetPackageError{Kind: WingetPackageErrorBlockedByPolicy}
	ErrWingetPackagePermission          = &WingetPackageError{Kind: WingetPackageErrorPermission}
	ErrWingetPackageSourceUnreachable   = &WingetPackageError{Kind: WingetPackageErrorSourceUnreachable}
	ErrWingetPackageCatalogError        = &WingetPackageError{Kind: WingetPackageErrorCatalogError}
	ErrWingetPackageResourceInUse       = &WingetPackageError{Kind: WingetPackageErrorResourceInUse}
	ErrWingetPackageUnknown             = &WingetPackageError{Kind: WingetPackageErrorUnknown}
)

// ---------------------------------------------------------------------------
// WingetPackageInput — desired configuration for Install and Update
// ---------------------------------------------------------------------------

// WingetPackageInput carries the desired configuration for a winget package
// operation. Consumed by Install and Update.
//
// Zero-value / empty-string semantics for optional fields:
//   - Version ""  → latest available (no -Version flag passed to winget).
//   - Override "" → no -Override flag passed to Install-WinGetPackage.
type WingetPackageInput struct {
	// PackageID is the winget catalog identifier. Required.
	PackageID string

	// Source is the winget catalog name (e.g. "winget", "msstore"). Required.
	Source string

	// Version is the pinned package version. Empty means "latest available".
	Version string

	// Override is the raw argument string for the underlying installer's
	// -Override parameter. Empty means no -Override flag is passed.
	Override string
}

// ---------------------------------------------------------------------------
// WingetPackageState — observed state returned by Read
// ---------------------------------------------------------------------------

// WingetPackageState holds the observed state of a winget-managed package as
// returned by the Read pipeline.
//
// RebootRequired signals that the last Install/Update/Uninstall reported
// winget status RebootRequired. The resource handler converts this into a
// Terraform warning diagnostic without failing (EC-6). This field is never
// persisted in Terraform state.
type WingetPackageState struct {
	// PackageID is the winget catalog identifier.
	PackageID string

	// Source is the winget catalog name.
	Source string

	// InstalledVersion is the version currently installed on the host.
	InstalledVersion string

	// Name is the human-readable package display name.
	Name string

	// RebootRequired indicates that winget reported a RebootRequired status.
	// Transient: always false when returned by Read.
	RebootRequired bool
}

// ---------------------------------------------------------------------------
// WingetPackageClient — CRUD interface
// ---------------------------------------------------------------------------

// WingetPackageClient defines the contract for managing Windows packages via
// the Microsoft.WinGet.Client PowerShell module over WinRM.
//
// All methods accept a context.Context for cancellation and timeout
// propagation. All errors are returned as *WingetPackageError (wrapped in
// error). Use errors.Is(err, ErrWingetPackage*) or IsWingetPackageError for
// programmatic branching.
//
// Notable invariants:
//   - Install performs EC-1 (module check) and EC-2 (existence pre-flight).
//   - Read returns (nil, nil) on absent package (EC-3 drift).
//   - Uninstall treats PackageNotInstalled as success (EC-3 idempotency).
//   - RebootRequired status sets WingetPackageState.RebootRequired = true and
//     does NOT cause an error (EC-6).
//   - EC-10 (ResourceInUse): retried 3× with 5 s / 15 s / 30 s back-off.
//   - EC-8 (network failure): retried once after 5 s.
type WingetPackageClient interface {
	// Install adds a new package via Install-WinGetPackage.
	Install(ctx context.Context, input WingetPackageInput) (*WingetPackageState, error)

	// Read retrieves the current installed state. Returns (nil, nil) when not
	// installed (EC-3).
	Read(ctx context.Context, packageID, source string) (*WingetPackageState, error)

	// Update applies a version change via Update-WinGetPackage.
	Update(ctx context.Context, input WingetPackageInput) (*WingetPackageState, error)

	// Uninstall removes the package. PackageNotInstalled is treated as
	// success. RebootRequired is propagated via the returned state (EC-6).
	Uninstall(ctx context.Context, packageID, source string) (*WingetPackageState, error)
}
