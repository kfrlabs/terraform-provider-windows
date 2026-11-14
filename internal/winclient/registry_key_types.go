// Package winclient: registry key types, interface, and error definitions.
//
// Spec alignment: windows_registry_key (issue #280). The key resource owns
// the key itself plus an opt-in purge of unmanaged value names; it never
// carries full value payloads (those stay with windows_registry_value).
package winclient

import (
	"context"
)

// RegistryKeyErrorKind categorises errors returned by RegistryKeyClient operations.
type RegistryKeyErrorKind string

const (
	RegistryKeyErrorNotFound     = "not_found"
	RegistryKeyErrorPermission   = "permission_denied"
	RegistryKeyErrorInvalidInput = "invalid_input"
	RegistryKeyErrorUnknown      = "unknown"
)

// RegistryKeyError is the structured error type returned by all RegistryKeyClient methods.
type RegistryKeyError = ResourceError

// NewRegistryKeyError constructs a *RegistryKeyError.
func NewRegistryKeyError(kind RegistryKeyErrorKind, message string, cause error, ctx map[string]string) *RegistryKeyError {
	return NewResourceError("windows_registry_key", string(kind), message, cause, ctx)
}

// IsRegistryKeyError reports whether err is a *RegistryKeyError with the given kind.
func IsRegistryKeyError(err error, kind RegistryKeyErrorKind) bool {
	return IsResourceError(err, "windows_registry_key", string(kind))
}

// Sentinel errors for use with errors.Is.
var (
	ErrRegistryKeyNotFound     = &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorNotFound}
	ErrRegistryKeyPermission   = &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorPermission}
	ErrRegistryKeyInvalidInput = &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorInvalidInput}
	ErrRegistryKeyUnknown      = &RegistryKeyError{Resource: "windows_registry_key", Kind: RegistryKeyErrorUnknown}
)

// RegistryKeyValueSummary is a drift-detection summary of one value: its name
// plus its kind. The key client never returns value data; full payloads stay
// with RegistryValueClient.
type RegistryKeyValueSummary struct {
	Name string
	Kind RegistryValueKind
}

// RegistryKeyState is the observed state of a Windows registry key.
type RegistryKeyState struct {
	Hive string
	Path string
	// Found is false when the key does not exist on the target host.
	Found bool
	// ValueNames holds every value name in the key, in enumeration order.
	// The unnamed Default value appears as "".
	ValueNames []string
	// Values holds a name+kind summary parallel to ValueNames, for drift
	// detection without purge.
	Values []RegistryKeyValueSummary
}

// RegistryKeyClient manages Windows registry keys over SSH using the .NET
// Microsoft.Win32.Registry API via PowerShell (ADR-RV-1), plus the
// Registry provider cmdlets for deletions.
//
// Error conventions:
//   - List returns (&RegistryKeyState{Found: false}, nil) when the key does
//     not exist.
//   - DeleteValues is idempotent: a missing key or missing value is a silent
//     no-op.
//   - DeleteKey is idempotent: a missing key is a silent no-op; without
//     recursive=true a key that still has subkeys fails with
//     RegistryKeyErrorInvalidInput.
type RegistryKeyClient interface {
	EnsureKey(ctx context.Context, hive, path string) (*RegistryKeyState, error)
	List(ctx context.Context, hive, path string) (*RegistryKeyState, error)
	DeleteValues(ctx context.Context, hive, path string, names []string) error
	DeleteKey(ctx context.Context, hive, path string, recursive bool) error
}
