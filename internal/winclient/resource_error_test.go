// Unit tests for the generic ResourceError (issue #348, batch 1).
//
// The type is additive: no per-resource error is rewritten in batch 1.
// These tests pin the wire format (which mirrors the per-resource
// Error() strings) and the (Resource, Kind) matching semantics that
// later migration batches will rely on.
package winclient

import (
	"errors"
	"testing"
)

func TestResourceError_ErrorFormat(t *testing.T) {
	err := NewResourceError("windows_hostname", "unknown", "boom", nil, nil)
	if got, want := err.Error(), "windows_hostname [unknown]: boom"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	cause := errors.New("dial tcp: refused")
	err = NewResourceError("windows_hostname", "unreachable", "no ssh", cause, map[string]string{"host": "h"})
	if got, want := err.Error(), "windows_hostname [unreachable]: no ssh: dial tcp: refused"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Error("Unwrap must expose the cause")
	}
}

func TestResourceError_Is_ByResourceAndKind(t *testing.T) {
	err := NewResourceError("windows_hostname", "unknown", "boom", nil, nil)
	if !errors.Is(err, &ResourceError{Resource: "windows_hostname", Kind: "unknown"}) {
		t.Error("same (resource, kind) must match")
	}
	if errors.Is(err, &ResourceError{Resource: "windows_hostname", Kind: "other"}) {
		t.Error("different kind must not match")
	}
	if errors.Is(err, &ResourceError{Resource: "windows_file", Kind: "unknown"}) {
		t.Error("different resource must not match")
	}
}

func TestIsResourceError(t *testing.T) {
	err := NewResourceError("windows_hostname", "unknown", "boom", nil, nil)
	if !IsResourceError(err, "windows_hostname", "unknown") {
		t.Error("must match wrapped *ResourceError")
	}
	wrapped := &FileError{Kind: FileErrorNotFound, Message: "boom"}
	if IsResourceError(wrapped, "windows_file", "not_found") {
		t.Error("non-migrated per-resource errors are not *ResourceError")
	}
	aliased := &HostnameError{Resource: "windows_hostname", Kind: "unknown", Message: "boom"}
	if !IsResourceError(aliased, "windows_hostname", "unknown") {
		t.Error("migrated alias HostnameError must match as *ResourceError")
	}
	other := errors.New("plain")
	if IsResourceError(other, "windows_hostname", "unknown") {
		t.Error("plain errors must not match")
	}
}
