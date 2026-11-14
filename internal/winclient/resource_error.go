// Generic structured error for winclient resources (issue #348, batch 1).
//
// ResourceError is the convergence point for the ~38 structurally
// identical per-resource error types (Kind, Message, Context, Cause plus
// Error/Unwrap/Is/New/Is* helpers). Batch 1 introduces the type and its
// helpers with unit tests but rewrites NO existing per-resource type:
// later batches re-express each *Error as an alias or thin wrapper over
// ResourceError (see ADR-0013) so provider handlers, errors.Is sentinels
// and Is* helpers keep compiling and behaving identically.
//
// Wire format: "windows_<resource> [<kind>]: <message>[: <cause>]",
// matching the existing per-resource Error() strings so diagnostics read
// the same before and after migration.
package winclient

import (
	"errors"
	"fmt"
)

// ResourceError is the generic structured error returned by winclient
// clients. Resource is the snake_case resource key (for example
// "windows_hostname"); Kind is the machine-readable error category
// (the PS-side kind string); Message is human-readable and must not
// contain credentials; Context carries safe key/value diagnostics;
// Cause is the underlying error, if any.
type ResourceError struct {
	Resource string
	Kind     string
	Message  string
	Context  map[string]string
	Cause    error
}

// Error implements the error interface.
func (e *ResourceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s [%s]: %s: %v", e.Resource, e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s [%s]: %s", e.Resource, e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is walking.
func (e *ResourceError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by (Resource, Kind) only, mirroring
// the per-resource Kind-only Is methods (e.g. HostnameError.Is).
func (e *ResourceError) Is(target error) bool {
	t, ok := target.(*ResourceError)
	if !ok {
		return false
	}
	return e.Resource == t.Resource && e.Kind == t.Kind
}

// NewResourceError constructs a *ResourceError. Pass a nil cause when no
// underlying error exists. The ctx map may be nil.
func NewResourceError(resource, kind, message string, cause error, ctx map[string]string) *ResourceError {
	return &ResourceError{Resource: resource, Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsResourceError reports whether err is a *ResourceError for the given
// resource with the given kind.
func IsResourceError(err error, resource, kind string) bool {
	var re *ResourceError
	if errors.As(err, &re) {
		return re.Resource == resource && re.Kind == kind
	}
	return false
}
