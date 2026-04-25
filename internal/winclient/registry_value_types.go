// Package winclient: registry value types, interface, and error definitions.
//
// Spec alignment: windows_registry_value spec v1 (2026-04-25).
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// RegistryValueKind is the Windows registry value type.
// String values match the Terraform schema attribute values for the `type` attribute.
type RegistryValueKind string

const (
	RegistryValueKindString       RegistryValueKind = "REG_SZ"
	RegistryValueKindExpandString RegistryValueKind = "REG_EXPAND_SZ"
	RegistryValueKindMultiString  RegistryValueKind = "REG_MULTI_SZ"
	RegistryValueKindDWord        RegistryValueKind = "REG_DWORD"
	RegistryValueKindQWord        RegistryValueKind = "REG_QWORD"
	RegistryValueKindBinary       RegistryValueKind = "REG_BINARY"
	RegistryValueKindNone         RegistryValueKind = "REG_NONE"
)

// RegistryValueErrorKind categorises errors returned by RegistryValueClient operations.
type RegistryValueErrorKind string

const (
	RegistryValueErrorNotFound     RegistryValueErrorKind = "not_found"
	RegistryValueErrorTypeConflict RegistryValueErrorKind = "type_conflict"
	RegistryValueErrorPermission   RegistryValueErrorKind = "permission_denied"
	RegistryValueErrorInvalidInput RegistryValueErrorKind = "invalid_input"
	RegistryValueErrorUnknown      RegistryValueErrorKind = "unknown"
)

// RegistryValueError is the structured error type returned by all RegistryValueClient methods.
type RegistryValueError struct {
	Kind    RegistryValueErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *RegistryValueError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_registry_value [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_registry_value [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *RegistryValueError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *RegistryValueError) Is(target error) bool {
	t, ok := target.(*RegistryValueError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewRegistryValueError constructs a *RegistryValueError.
func NewRegistryValueError(kind RegistryValueErrorKind, message string, cause error, ctx map[string]string) *RegistryValueError {
	return &RegistryValueError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsRegistryValueError reports whether err is a *RegistryValueError with the given kind.
func IsRegistryValueError(err error, kind RegistryValueErrorKind) bool {
	var rve *RegistryValueError
	if errors.As(err, &rve) {
		return rve.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrRegistryValueNotFound     = &RegistryValueError{Kind: RegistryValueErrorNotFound}
	ErrRegistryValueTypeConflict = &RegistryValueError{Kind: RegistryValueErrorTypeConflict}
	ErrRegistryValuePermission   = &RegistryValueError{Kind: RegistryValueErrorPermission}
	ErrRegistryValueInvalidInput = &RegistryValueError{Kind: RegistryValueErrorInvalidInput}
	ErrRegistryValueUnknown      = &RegistryValueError{Kind: RegistryValueErrorUnknown}
)

// RegistryValueInput carries the parameters for a RegistryValueClient.Set call.
type RegistryValueInput struct {
	Hive                       string
	Path                       string
	Name                       string
	Kind                       RegistryValueKind
	ValueString                *string
	ValueStrings               []string
	ValueBinary                *string
	ExpandEnvironmentVariables bool
}

// RegistryValueState is the observed state of a Windows registry value.
type RegistryValueState struct {
	Hive         string
	Path         string
	Name         string
	Kind         RegistryValueKind
	ValueString  *string
	ValueStrings []string
	ValueBinary  *string
}

// RegistryValueClient manages Windows registry values over WinRM using
// the .NET Microsoft.Win32.Registry API via PowerShell (ADR-RV-1).
//
// Error conventions:
//   - Read returns (nil, nil) when the key or value does not exist (EC-4).
//   - Set returns RegistryValueErrorTypeConflict when the value exists with a different kind (EC-3).
//   - Delete is idempotent: missing value/key is a silent no-op (EC-12).
type RegistryValueClient interface {
	Set(ctx context.Context, input RegistryValueInput) (*RegistryValueState, error)
	Read(ctx context.Context, hive, path, name string, expandEnvVars bool) (*RegistryValueState, error)
	Delete(ctx context.Context, hive, path, name string) error
}
