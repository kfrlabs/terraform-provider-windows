// Package winclient: windows_directory types, interface, and error definitions.
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
	DirectoryErrorPathNotFound DirectoryErrorKind = "path_not_found"
	DirectoryErrorPermission   DirectoryErrorKind = "permission_denied"
	DirectoryErrorNotEmpty     DirectoryErrorKind = "directory_not_empty"
	DirectoryErrorInvalidInput DirectoryErrorKind = "invalid_input"
	DirectoryErrorUnknown      DirectoryErrorKind = "unknown"
)

// DirectoryError is the structured error returned by DirectoryClient methods.
type DirectoryError struct {
	Kind    DirectoryErrorKind
	Message string
	Context map[string]string
	Cause   error
}

func (e *DirectoryError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_directory [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_directory [%s]: %s", e.Kind, e.Message)
}
func (e *DirectoryError) Unwrap() error { return e.Cause }
func (e *DirectoryError) Is(target error) bool {
	t, ok := target.(*DirectoryError)
	return ok && e.Kind == t.Kind
}
func NewDirectoryError(kind DirectoryErrorKind, message string, cause error, ctx map[string]string) *DirectoryError {
	return &DirectoryError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}
func IsDirectoryError(err error, kind DirectoryErrorKind) bool {
	var de *DirectoryError
	return errors.As(err, &de) && de.Kind == kind
}

var (
	ErrDirectoryNotFound     = &DirectoryError{Kind: DirectoryErrorNotFound}
	ErrDirectoryTypeConflict = &DirectoryError{Kind: DirectoryErrorTypeConflict}
	ErrDirectoryPathNotFound = &DirectoryError{Kind: DirectoryErrorPathNotFound}
	ErrDirectoryPermission   = &DirectoryError{Kind: DirectoryErrorPermission}
	ErrDirectoryNotEmpty     = &DirectoryError{Kind: DirectoryErrorNotEmpty}
	ErrDirectoryInvalidInput = &DirectoryError{Kind: DirectoryErrorInvalidInput}
	ErrDirectoryUnknown      = &DirectoryError{Kind: DirectoryErrorUnknown}
)

const (
	DirectoryAttributeArchive   = "archive"
	DirectoryAttributeHidden    = "hidden"
	DirectoryAttributeReadOnly  = "readonly"
	DirectoryAttributeSystem    = "system"
	DirectoryAttributeTemporary = "temporary"
)

// DirectoryInput contains the desired directory configuration.
type DirectoryInput struct {
	Path          string
	CreateParents bool
	Attributes    []string
}

// DirectoryState is the observed state of a directory.
type DirectoryState struct {
	Path          string
	LastWriteTime string
	Attributes    []string
}

// DirectoryClient manages one directory on a Windows host.
// Read returns (nil, nil) when the directory is absent. Delete is idempotent
// when the directory is absent and refuses non-empty directories unless the
// caller requests recursive deletion.
type DirectoryClient interface {
	Set(context.Context, DirectoryInput) (*DirectoryState, error)
	Read(context.Context, string) (*DirectoryState, error)
	Delete(context.Context, string, bool) error
}
