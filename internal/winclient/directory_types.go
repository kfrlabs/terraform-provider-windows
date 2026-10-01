// Package winclient: windows_directory types, interface, and error definitions.
//
// Spec alignment: windows_directory spec v1 (2026-10-01).
//
// Scope note: content of the directory (files, sub-directories) is never
// managed here; only the directory entry itself (presence, attributes) is
// owned by this resource. Ownership and ACLs are deliberately NOT managed
// here either; use the separate windows_file_acl resource, which already
// accepts a directory target.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// DirectoryErrorKind categorises errors returned by DirectoryClient operations.
type DirectoryErrorKind string

const (
	DirectoryErrorNotFound     DirectoryErrorKind = "not_found"
	DirectoryErrorTypeConflict DirectoryErrorKind = "type_conflict"
	DirectoryErrorPermission   DirectoryErrorKind = "permission_denied"
	DirectoryErrorNotEmpty     DirectoryErrorKind = "not_empty"
	DirectoryErrorInvalidInput DirectoryErrorKind = "invalid_input"
	DirectoryErrorUnknown      DirectoryErrorKind = "unknown"
)

// DirectoryError is the structured error type returned by all DirectoryClient methods.
type DirectoryError struct {
	Kind    DirectoryErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *DirectoryError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_directory [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_directory [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *DirectoryError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *DirectoryError) Is(target error) bool {
	t, ok := target.(*DirectoryError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewDirectoryError constructs a *DirectoryError.
func NewDirectoryError(kind DirectoryErrorKind, message string, cause error, ctx map[string]string) *DirectoryError {
	return &DirectoryError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsDirectoryError reports whether err is a *DirectoryError with the given kind.
func IsDirectoryError(err error, kind DirectoryErrorKind) bool {
	var de *DirectoryError
	if errors.As(err, &de) {
		return de.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrDirectoryNotFound     = &DirectoryError{Kind: DirectoryErrorNotFound}
	ErrDirectoryTypeConflict = &DirectoryError{Kind: DirectoryErrorTypeConflict}
	ErrDirectoryPermission   = &DirectoryError{Kind: DirectoryErrorPermission}
	ErrDirectoryNotEmpty     = &DirectoryError{Kind: DirectoryErrorNotEmpty}
	ErrDirectoryInvalidInput = &DirectoryError{Kind: DirectoryErrorInvalidInput}
	ErrDirectoryUnknown      = &DirectoryError{Kind: DirectoryErrorUnknown}
)

// Valid directory attribute keywords (schema enum).
const (
	DirectoryAttributeHidden   = "hidden"
	DirectoryAttributeReadOnly = "readonly"
	DirectoryAttributeSystem   = "system"
)

// directoryAttributeToDotNet maps a schema keyword to its
// [System.IO.FileAttributes] member (directories share the same enum as files).
var directoryAttributeToDotNet = map[string]string{
	DirectoryAttributeHidden:   "Hidden",
	DirectoryAttributeReadOnly: "ReadOnly",
	DirectoryAttributeSystem:   "System",
}

// DirectoryInput carries the parameters for a DirectoryClient.Create call.
type DirectoryInput struct {
	Path          string
	CreateParents bool
	Attributes    []string
}

// DirectoryState is the observed state of a directory on the Windows host.
type DirectoryState struct {
	Path           string
	ExistsChildren bool
	ItemCount      int64
	LastWriteTime  string
	Attributes     []string
}

// DirectoryClient manages a single directory on a Windows host over SSH + PowerShell.
//
// Error conventions:
//   - Read returns (nil, nil) when the directory does not exist (EC-1).
//   - Create/Read return DirectoryErrorTypeConflict when the path is an
//     existing file (EC-2).
//   - Create returns DirectoryErrorInvalidInput when a parent directory is
//     missing and CreateParents is false (EC-3).
//   - Create is idempotent: creating an already-present directory is not an
//     error (EC-9).
//   - Delete returns DirectoryErrorNotEmpty when the directory has children
//     and recursive is false (EC-4).
//   - Delete is idempotent: a missing directory is a silent no-op (EC-5).
type DirectoryClient interface {
	// Create ensures the directory at input.Path exists, applying
	// input.Attributes. Idempotent when the directory already exists (EC-9).
	Create(ctx context.Context, input DirectoryInput) (*DirectoryState, error)

	// Read retrieves the observed state of the directory at path.
	// Returns (nil, nil) when the directory does not exist (EC-1).
	Read(ctx context.Context, path string) (*DirectoryState, error)

	// Update applies the given attributes to an existing directory in place.
	Update(ctx context.Context, path string, attributes []string) (*DirectoryState, error)

	// Delete removes the directory at path. When recursive is true, its
	// content is removed as well (Remove-Item -Recurse); otherwise a non-empty
	// directory returns DirectoryErrorNotEmpty (EC-4). Idempotent (EC-5).
	Delete(ctx context.Context, path string, recursive bool) error
}

// NormaliseDirectoryAttributes validates attribute keywords and returns them
// in a stable order so state comparisons do not churn.
func NormaliseDirectoryAttributes(attrs []string) ([]string, error) {
	ordered := []string{DirectoryAttributeHidden, DirectoryAttributeReadOnly, DirectoryAttributeSystem}
	seen := map[string]bool{}
	for _, a := range attrs {
		if _, ok := directoryAttributeToDotNet[a]; !ok {
			return nil, &DirectoryError{
				Kind:    DirectoryErrorInvalidInput,
				Message: fmt.Sprintf("unknown directory attribute %q", a),
			}
		}
		seen[a] = true
	}
	out := make([]string, 0, len(seen))
	for _, a := range ordered {
		if seen[a] {
			out = append(out, a)
		}
	}
	return out, nil
}
