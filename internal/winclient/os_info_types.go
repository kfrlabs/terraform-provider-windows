// Package winclient: types for the windows_os_info data source.
//
// OSInfoErrorKind / OSInfoError follow the same shape as
// DomainMembershipError so the provider layer can branch with errors.Is.
//
// The windows_os_info data source is standalone: no sibling resource
// exists, so this file defines the full WindowsOSInfoClient contract and
// the observed OSInfo state (see ADR-0009 amendment 2026-11-12).
package winclient

import (
	"context"
)

// OSInfoErrorKind categorises errors returned by WindowsOSInfoClient.
type OSInfoErrorKind string

const (
	// OSInfoErrorAccessDenied is returned when the CIM or registry reads
	// fail with AccessDenied (Win32 5).
	OSInfoErrorAccessDenied = "access_denied"

	// OSInfoErrorCIMUnavailable is returned when the CIM/WMI stack itself
	// is unavailable (winmgmt service stopped, repository corruption).
	OSInfoErrorCIMUnavailable = "cim_unavailable"

	// OSInfoErrorTimeout is returned when the operation timed out or was
	// cancelled.
	OSInfoErrorTimeout = "timeout"

	// OSInfoErrorInvalidParameter is reserved for invalid inputs. The
	// current Read takes no parameters, so it is never returned today;
	// kept for parity with the other client error kinds.
	OSInfoErrorInvalidParameter = "invalid_parameter"

	// OSInfoErrorUnknown is the catch-all for unmapped PowerShell or SSH
	// failures.
	OSInfoErrorUnknown = "unknown"
)

// OSInfoError is the structured error type returned by
// WindowsOSInfoClient.
type OSInfoError = ResourceError

// NewOSInfoError constructs a *OSInfoError.
func NewOSInfoError(kind OSInfoErrorKind, msg string, cause error, ctx map[string]string) *OSInfoError {
	return NewResourceError("windows_os_info", string(kind), msg, cause, ctx)
}

// IsOSInfoError reports whether err is a *OSInfoError of the given kind.
func IsOSInfoError(err error, kind OSInfoErrorKind) bool {
	return IsResourceError(err, "windows_os_info", string(kind))
}

// Sentinel errors usable with errors.Is.
var (
	ErrOSInfoAccessDenied     = &OSInfoError{Resource: "windows_os_info", Kind: OSInfoErrorAccessDenied}
	ErrOSInfoCIMUnavailable   = &OSInfoError{Resource: "windows_os_info", Kind: OSInfoErrorCIMUnavailable}
	ErrOSInfoTimeout          = &OSInfoError{Resource: "windows_os_info", Kind: OSInfoErrorTimeout}
	ErrOSInfoInvalidParameter = &OSInfoError{Resource: "windows_os_info", Kind: OSInfoErrorInvalidParameter}
	ErrOSInfoUnknown          = &OSInfoError{Resource: "windows_os_info", Kind: OSInfoErrorUnknown}
)

// OSInfo is the observed OS inventory of a remote Windows host, returned by
// Read. Unknown SKU / product-type / architecture codes degrade to "" (with
// IsServer derived from the raw product type) instead of erroring.
type OSInfo struct {
	// MachineID is the stable per-machine identifier
	// (HKLM:\SOFTWARE\Microsoft\Cryptography\MachineGuid). May be empty
	// when the registry read fails; the data source then falls back to
	// the singleton literal "current".
	MachineID string
	// ProductName is the OS caption (Win32_OperatingSystem.Caption).
	ProductName string
	// Version is the OS version (Win32_OperatingSystem.Version).
	Version string
	// BuildNumber is the OS build
	// (HKLM CurrentVersion CurrentBuild, e.g. 26100).
	BuildNumber int64
	// UBR is the update build revision (HKLM CurrentVersion UBR, e.g. 1).
	UBR int64
	// FullBuild is "build" or "build.ubr" when UBR > 0.
	FullBuild string
	// DisplayVersion is the friendly version (CurrentVersion DisplayVersion,
	// falling back to ReleaseId on older hosts).
	DisplayVersion string
	// EditionID is the OS edition (CurrentVersion EditionID).
	EditionID string
	// SKU is the numeric OS SKU (Win32_OperatingSystem.OperatingSystemSKU).
	SKU int64
	// SKUName is the SKU mapped to its documented name; "" when unknown.
	SKUName string
	// InstallationType is the installation type (CurrentVersion
	// InstallationType, e.g. "Server", "Server Core", "Client").
	InstallationType string
	// IsServer is true when the raw product type is DomainController (2)
	// or Server (3); false otherwise, including unknown values.
	IsServer bool
	// IsServerCore is true when InstallationType is "Server Core".
	IsServerCore bool
	// ProductType is the Win32_OperatingSystem.ProductType mapped to its
	// documented name: Workstation (1), DomainController (2), Server (3);
	// "" when unknown.
	ProductType string
	// Architecture is the Win32_Processor.Architecture mapped to its
	// documented name: x86 (0), arm (5), x64 (9), arm64 (12); "" when
	// unknown.
	Architecture string
	// InstallDate is the OS install time in UTC RFC 3339
	// (Win32_OperatingSystem.InstallDate); "" when unavailable.
	InstallDate string
	// LastBootTime is the last boot time in UTC RFC 3339
	// (Win32_OperatingSystem.LastBootUpTime); "" when unavailable.
	LastBootTime string
	// SystemDrive is the system drive (Win32_OperatingSystem.SystemDrive).
	SystemDrive string
	// WindowsDirectory is the Windows directory
	// (Win32_OperatingSystem.WindowsDirectory).
	WindowsDirectory string
	// OSLanguage is the OS culture name (Get-Culture); "" when unavailable.
	OSLanguage string
	// PowerShellVersion is the responding engine version
	// ($PSVersionTable.PSVersion).
	PowerShellVersion string
}

// WindowsOSInfoClient is the contract for the windows_os_info data source.
type WindowsOSInfoClient interface {
	// Read returns the current OS inventory of the target host in a single
	// round-trip. Unknown codes degrade to "" instead of erroring; only
	// envelope / transport failures return an error.
	Read(ctx context.Context) (*OSInfo, error)
}
