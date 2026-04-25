// Package winclient: types for the windows_feature resource.
//
// FeatureInfo is the observed state returned by Read; InstallResult is the
// extra payload returned by Create/Update/Delete (mainly RestartNeeded).
// FeatureErrorKind / FeatureError follow the same shape as ServiceError so the
// resource layer can branch with errors.Is.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// FeatureErrorKind categorises errors returned by WindowsFeatureClient.
type FeatureErrorKind string

const (
	FeatureErrorNotFound          FeatureErrorKind = "not_found"
	FeatureErrorPermission        FeatureErrorKind = "permission_denied"
	FeatureErrorSourceMissing     FeatureErrorKind = "source_missing"
	FeatureErrorDependencyMissing FeatureErrorKind = "dependency_missing"
	FeatureErrorUnsupportedSKU    FeatureErrorKind = "unsupported_sku"
	FeatureErrorTimeout           FeatureErrorKind = "timeout"
	FeatureErrorInvalidParameter  FeatureErrorKind = "invalid_parameter"
	FeatureErrorUnknown           FeatureErrorKind = "unknown"
)

// FeatureError is the structured error type returned by WindowsFeatureClient.
type FeatureError struct {
	Kind    FeatureErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements error.
func (e *FeatureError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_feature [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_feature [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *FeatureError) Unwrap() error { return e.Cause }

// Is matches by Kind only.
func (e *FeatureError) Is(target error) bool {
	t, ok := target.(*FeatureError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewFeatureError constructs a *FeatureError.
func NewFeatureError(kind FeatureErrorKind, msg string, cause error, ctx map[string]string) *FeatureError {
	return &FeatureError{Kind: kind, Message: msg, Cause: cause, Context: ctx}
}

// IsFeatureError reports whether err is a *FeatureError of the given kind.
func IsFeatureError(err error, kind FeatureErrorKind) bool {
	var fe *FeatureError
	if errors.As(err, &fe) {
		return fe.Kind == kind
	}
	return false
}

// Sentinel errors usable with errors.Is.
var (
	ErrFeatureNotFound          = &FeatureError{Kind: FeatureErrorNotFound}
	ErrFeaturePermission        = &FeatureError{Kind: FeatureErrorPermission}
	ErrFeatureSourceMissing     = &FeatureError{Kind: FeatureErrorSourceMissing}
	ErrFeatureDependencyMissing = &FeatureError{Kind: FeatureErrorDependencyMissing}
	ErrFeatureUnsupportedSKU    = &FeatureError{Kind: FeatureErrorUnsupportedSKU}
	ErrFeatureTimeout           = &FeatureError{Kind: FeatureErrorTimeout}
	ErrFeatureInvalidParameter  = &FeatureError{Kind: FeatureErrorInvalidParameter}
	ErrFeatureUnknown           = &FeatureError{Kind: FeatureErrorUnknown}
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
