// Package winclient: types for the windows_feature resource.
//
// FeatureInfo is the observed state returned by Read; InstallResult is the
// extra payload returned by Create/Update/Delete (mainly RestartNeeded).
// FeatureErrorKind / FeatureError follow the same shape as ServiceError so the
// resource layer can branch with errors.Is.
package winclient

import (
	"context"
)

// FeatureErrorKind categorises errors returned by WindowsFeatureClient.
type FeatureErrorKind string

const (
	FeatureErrorNotFound          = "not_found"
	FeatureErrorPermission        = "permission_denied"
	FeatureErrorSourceMissing     = "source_missing"
	FeatureErrorDependencyMissing = "dependency_missing"
	FeatureErrorUnsupportedSKU    = "unsupported_sku"
	FeatureErrorTimeout           = "timeout"
	FeatureErrorInvalidParameter  = "invalid_parameter"
	FeatureErrorUnknown           = "unknown"
)

// FeatureError is the structured error type returned by WindowsFeatureClient.
type FeatureError = ResourceError

// NewFeatureError constructs a *FeatureError.
func NewFeatureError(kind FeatureErrorKind, msg string, cause error, ctx map[string]string) *FeatureError {
	return NewResourceError("windows_feature", string(kind), msg, cause, ctx)
}

// IsFeatureError reports whether err is a *FeatureError of the given kind.
func IsFeatureError(err error, kind FeatureErrorKind) bool {
	return IsResourceError(err, "windows_feature", string(kind))
}

// Sentinel errors usable with errors.Is.
var (
	ErrFeatureNotFound          = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorNotFound}
	ErrFeaturePermission        = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorPermission}
	ErrFeatureSourceMissing     = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorSourceMissing}
	ErrFeatureDependencyMissing = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorDependencyMissing}
	ErrFeatureUnsupportedSKU    = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorUnsupportedSKU}
	ErrFeatureTimeout           = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorTimeout}
	ErrFeatureInvalidParameter  = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorInvalidParameter}
	ErrFeatureUnknown           = &FeatureError{Resource: "windows_feature", Kind: FeatureErrorUnknown}
)

// FeatureInfo is the observed state of a Windows feature on a host.
type FeatureInfo struct {
	// Name is the technical short name (e.g. Web-Server).
	Name string
	// DisplayName is the human-readable name.
	DisplayName string
	// Description is the description string returned by Get-WindowsFeature.
	Description string
	// Installed is true when InstallState == "Installed".
	Installed bool
	// InstallState is one of "Installed", "Available", "Removed".
	InstallState string
	// RestartPending is true when the OS exposes a pending reboot flag.
	RestartPending bool
}

// InstallResult is the side-channel returned by Install/Uninstall.
type InstallResult struct {
	// RestartNeeded is true when the cmdlet result reports RestartNeeded=Yes.
	RestartNeeded bool
	// Success is the raw Success boolean from the cmdlet result.
	Success bool
	// ExitCode is the cmdlet ExitCode (often "Success", "NoChangeNeeded", "SuccessRestartRequired").
	ExitCode string
	// RebootScheduled is true when the host-side script successfully
	// scheduled the deferred reboot (shutdown.exe exit code 0).
	RebootScheduled bool
}

// FeatureInput carries the desired configuration for Install/Uninstall.
type FeatureInput struct {
	Name                   string
	IncludeSubFeatures     bool
	IncludeManagementTools bool
	Source                 string
	Restart                bool
}

// WindowsFeatureClient is the contract for the windows_feature resource.
type WindowsFeatureClient interface {
	// Read returns the current state of the feature, or (nil, nil) if the
	// feature does not exist on the target host (drift removal).
	Read(ctx context.Context, name string) (*FeatureInfo, error)

	// Install installs the feature with the given options. Returns the
	// observed FeatureInfo plus the InstallResult for restart_pending.
	Install(ctx context.Context, in FeatureInput) (*FeatureInfo, *InstallResult, error)

	// Uninstall removes the feature. IncludeManagementTools and Restart are
	// honoured; Source / IncludeSubFeatures are ignored.
	Uninstall(ctx context.Context, in FeatureInput) (*FeatureInfo, *InstallResult, error)
}
