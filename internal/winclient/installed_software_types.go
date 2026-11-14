// Package winclient defines the WindowsInstalledSoftwareClient interface and
// associated types for the standalone windows_installed_software collection
// data source (issue #296). There is no sibling resource: List is a
// read-only inventory of the Uninstall registry hives on the remote Windows
// host, narrowed by Go-side filters.
//
// Scope: the two machine-wide Uninstall hives shared with
// windows_legacy_package (UninstallRegistryHivePaths), plus the loaded
// per-user hives under HKU when IncludeUserInstalls is set. Out of scope:
// installing, uninstalling or otherwise mutating software; Win32_Product is
// never queried (it triggers a consistency check of every MSI on the host).
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// InstalledSoftwareErrorKind — typed error categories
// ---------------------------------------------------------------------------

// InstalledSoftwareErrorKind categorises errors returned by
// WindowsInstalledSoftwareClient operations. Use errors.Is(err,
// ErrInstalledSoftware*) or IsInstalledSoftwareError for programmatic error
// handling.
type InstalledSoftwareErrorKind string

const (
	// InstalledSoftwareErrorAccessDenied is returned when the SSH user
	// lacks the privilege to read the Uninstall registry hives.
	InstalledSoftwareErrorAccessDenied = "access_denied"

	// InstalledSoftwareErrorInvalidParameter is returned when a filter
	// fails client-side validation (uncompilable regex, malformed product
	// code). No host call is made.
	InstalledSoftwareErrorInvalidParameter = "invalid_parameter"

	// InstalledSoftwareErrorTimeout is returned when the operation timed
	// out or was cancelled.
	InstalledSoftwareErrorTimeout = "timeout"

	// InstalledSoftwareErrorUnknown is the catch-all for unmapped
	// PowerShell or SSH failures.
	InstalledSoftwareErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// InstalledSoftwareError — structured error
// ---------------------------------------------------------------------------

// InstalledSoftwareError is the structured error type returned by all
// WindowsInstalledSoftwareClient methods. Use errors.Is(err,
// ErrInstalledSoftware*) for kind matching, or errors.As(err, &ie) to
// inspect Context.
type InstalledSoftwareError = ResourceError

// NewInstalledSoftwareError constructs an *InstalledSoftwareError. Pass a nil
// cause when no underlying error exists. The ctx map may be nil.
func NewInstalledSoftwareError(kind InstalledSoftwareErrorKind, message string, cause error, ctx map[string]string) *InstalledSoftwareError {
	return NewResourceError("windows_installed_software", string(kind), message, cause, ctx)
}

// IsInstalledSoftwareError reports whether err is an *InstalledSoftwareError
// of the given kind.
func IsInstalledSoftwareError(err error, kind InstalledSoftwareErrorKind) bool {
	return IsResourceError(err, "windows_installed_software", string(kind))
}

// Sentinel errors — use with errors.Is.
var (
	ErrInstalledSoftwareAccessDenied     = &InstalledSoftwareError{Resource: "windows_installed_software", Kind: InstalledSoftwareErrorAccessDenied}
	ErrInstalledSoftwareInvalidParameter = &InstalledSoftwareError{Resource: "windows_installed_software", Kind: InstalledSoftwareErrorInvalidParameter}
	ErrInstalledSoftwareTimeout          = &InstalledSoftwareError{Resource: "windows_installed_software", Kind: InstalledSoftwareErrorTimeout}
	ErrInstalledSoftwareUnknown          = &InstalledSoftwareError{Resource: "windows_installed_software", Kind: InstalledSoftwareErrorUnknown}
)

// ---------------------------------------------------------------------------
// InstalledSoftwareFilter — List filters
// ---------------------------------------------------------------------------

// InstalledSoftwareFilter narrows the List inventory. Every field is
// optional; the zero value lists every detected package (excluding system
// components, updates and per-user entries unless their flags are set).
//
// NameRegex and PublisherRegex are RE2 regular expressions matched against
// the package DisplayName and Publisher. ProductCode is an MSI ProductCode
// GUID in any common spelling (with or without braces, any case); it is
// normalised to upper-case with braces before comparison.
type InstalledSoftwareFilter struct {
	// NameRegex restricts the result to packages whose DisplayName matches
	// this RE2 pattern.
	NameRegex string

	// PublisherRegex restricts the result to packages whose Publisher
	// matches this RE2 pattern.
	PublisherRegex string

	// ProductCode restricts the result to the package with this MSI
	// ProductCode GUID, in any common spelling.
	ProductCode string

	// IncludeSystemComponents keeps entries with SystemComponent=1, which
	// Programs and Features hides.
	IncludeSystemComponents bool

	// IncludeUpdates keeps update entries (ReleaseType of Security
	// Update/Update/Hotfix, or a non-empty ParentKeyName).
	IncludeUpdates bool

	// IncludeUserInstalls additionally enumerates the Uninstall hives of
	// the loaded per-user hives under HKU.
	IncludeUserInstalls bool
}

// ---------------------------------------------------------------------------
// InstalledSoftware — observed state
// ---------------------------------------------------------------------------

// InstalledSoftware holds the observed state of one installed software
// entry as returned by the List pipeline.
type InstalledSoftware struct {
	// Name is the package DisplayName, as observed on the host.
	Name string

	// Version is the DisplayVersion, as observed on the host.
	Version string

	// Publisher is the package publisher, as observed on the host.
	Publisher string

	// InstallDate is the registry InstallDate normalised to YYYY-MM-DD;
	// "" when the host value is missing or unparseable.
	InstallDate string

	// InstallLocation is the InstallLocation, as observed on the host.
	InstallLocation string

	// ProductCode is the MSI ProductCode GUID in upper-case with braces,
	// derived from the registry key name; "" when the key name is not a
	// GUID (non-MSI entries).
	ProductCode string

	// IsMSI is true when the entry's WindowsInstaller value is 1.
	IsMSI bool

	// Architecture is the registry view the entry was read from: "x86"
	// for the WOW6432Node hive, otherwise the host architecture ("x64"
	// or "arm64").
	Architecture string

	// Scope is "machine" for the HKLM hives or "user" for per-user HKU
	// entries.
	Scope string

	// UserSID is the owning user SID for Scope "user"; "" otherwise.
	UserSID string

	// EstimatedSizeKB is the EstimatedSize value (KB); 0 when unreported.
	EstimatedSizeKB int64

	// UninstallString is the UninstallString, as observed on the host.
	UninstallString string

	// QuietUninstallString is the QuietUninstallString, as observed on
	// the host.
	QuietUninstallString string

	// RegistryKey is the full registry path of the entry, e.g.
	// "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<key>".
	RegistryKey string
}

// InstalledSoftwareResult is the List outcome: the sorted packages plus the
// count of registry keys skipped because their values were unreadable.
// Keys without a DisplayName are silently omitted and are NOT counted in
// SkippedEntries.
type InstalledSoftwareResult struct {
	// Packages holds the matching entries, sorted by name
	// (case-insensitive), then version, then registry key.
	Packages []InstalledSoftware

	// SkippedEntries counts registry keys skipped because their values
	// could not be read.
	SkippedEntries int64
}

// ---------------------------------------------------------------------------
// WindowsInstalledSoftwareClient — List interface
// ---------------------------------------------------------------------------

// WindowsInstalledSoftwareClient defines the contract for the standalone
// windows_installed_software collection data source: a read-only inventory
// with Go-side filters. An empty result is valid (empty packages, nil
// error); only validation, transport and host failures return an error.
type WindowsInstalledSoftwareClient interface {
	// List returns the installed software inventory in a single
	// round-trip, filtered Go-side and sorted. Invalid filters return a
	// typed invalid_parameter error without any host call.
	List(ctx context.Context, filter InstalledSoftwareFilter) (*InstalledSoftwareResult, error)
}
