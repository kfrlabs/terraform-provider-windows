// Package winclient: windows_file types, interface, and error definitions.
//
// Spec alignment: windows_file spec v1 (2026-09-30).
//
// Scope note: ownership and ACLs are deliberately NOT managed here; they are
// owned by the separate windows_file_acl resource. Every write path in file.go
// must therefore preserve the security descriptor of an existing target.
package winclient

import (
	"context"
	"encoding/base64"
	"fmt"
)

// Content size guard rails (T-2).
const (
	// FileMaxContentBytes is the hard cap on decoded content size. Content
	// larger than this is rejected Go-side with FileErrorInvalidInput: it ends
	// up in the Terraform state and travels over a fresh SSH connection on
	// every apply.
	FileMaxContentBytes int64 = 10 << 20 // 10 MiB

	// FileWarnContentBytes is the threshold above which the provider layer
	// emits a warning diagnostic.
	FileWarnContentBytes int64 = 1 << 20 // 1 MiB

	// FileImportMaxBytes is the hard-coded ceiling under which ImportState
	// fetches the real content so the first post-import plan is clean
	// (import decision (b), validated 2026-09-30).
	FileImportMaxBytes int64 = 1 << 20 // 1 MiB
)

// FileErrorKind categorises errors returned by FileClient operations.
type FileErrorKind string

const (
	FileErrorNotFound         = "not_found"
	FileErrorAlreadyExists    = "already_exists"
	FileErrorTypeConflict     = "type_conflict"
	FileErrorPathNotFound     = "path_not_found"
	FileErrorPermission       = "permission_denied"
	FileErrorLocked           = "file_locked"
	FileErrorDiskFull         = "disk_full"
	FileErrorDownloadFailed   = "download_failed"
	FileErrorChecksumMismatch = "checksum_mismatch"
	FileErrorInvalidInput     = "invalid_input"
	FileErrorUnknown          = "unknown"
)

// FileError is the structured error type returned by all FileClient methods.
type FileError = ResourceError

// NewFileError constructs a *FileError.
func NewFileError(kind FileErrorKind, message string, cause error, ctx map[string]string) *FileError {
	return NewResourceError("windows_file", string(kind), message, cause, ctx)
}

// IsFileError reports whether err is a *FileError with the given kind.
func IsFileError(err error, kind FileErrorKind) bool {
	return IsResourceError(err, "windows_file", string(kind))
}

// Sentinel errors for use with errors.Is.
var (
	ErrFileNotFound         = &FileError{Resource: "windows_file", Kind: FileErrorNotFound}
	ErrFileAlreadyExists    = &FileError{Resource: "windows_file", Kind: FileErrorAlreadyExists}
	ErrFileTypeConflict     = &FileError{Resource: "windows_file", Kind: FileErrorTypeConflict}
	ErrFilePathNotFound     = &FileError{Resource: "windows_file", Kind: FileErrorPathNotFound}
	ErrFilePermission       = &FileError{Resource: "windows_file", Kind: FileErrorPermission}
	ErrFileLocked           = &FileError{Resource: "windows_file", Kind: FileErrorLocked}
	ErrFileDiskFull         = &FileError{Resource: "windows_file", Kind: FileErrorDiskFull}
	ErrFileDownloadFailed   = &FileError{Resource: "windows_file", Kind: FileErrorDownloadFailed}
	ErrFileChecksumMismatch = &FileError{Resource: "windows_file", Kind: FileErrorChecksumMismatch}
	ErrFileInvalidInput     = &FileError{Resource: "windows_file", Kind: FileErrorInvalidInput}
	ErrFileUnknown          = &FileError{Resource: "windows_file", Kind: FileErrorUnknown}
)

// Valid file attribute keywords (schema enum).
const (
	FileAttributeHidden    = "hidden"
	FileAttributeReadOnly  = "readonly"
	FileAttributeArchive   = "archive"
	FileAttributeSystem    = "system"
	FileAttributeTemporary = "temporary"
)

// fileAttributeToDotNet maps a schema keyword to its [System.IO.FileAttributes] member.
var fileAttributeToDotNet = map[string]string{
	FileAttributeHidden:    "Hidden",
	FileAttributeReadOnly:  "ReadOnly",
	FileAttributeArchive:   "Archive",
	FileAttributeSystem:    "System",
	FileAttributeTemporary: "Temporary",
}

// FileInput carries the parameters for a FileClient.Set call.
//
// Exactly one content source must be populated: ContentBase64 (the provider
// layer has already resolved content / content_base64 / content_wo / source /
// a provider-side URL download into raw base64), or SourceURL together with
// DownloadOnTarget when the Windows host performs the download itself.
type FileInput struct {
	Path          string
	ContentBase64 string
	Overwrite     bool
	CreateParents bool
	Attributes    []string

	// Target-side download (download_on = "target").
	DownloadOnTarget            bool
	SourceURL                   string
	SourceURLSHA256             string
	SourceURLHeaders            map[string]string
	SourceURLInsecureSkipVerify bool
}

// FileState is the observed state of a file on the Windows host.
//
// Content is intentionally absent: Read never transfers file bytes (decision
// D-1). Use ReadContent, which only ImportState is allowed to call.
type FileState struct {
	Path          string
	SHA256        string
	SizeBytes     int64
	LastWriteTime string
	Attributes    []string
}

// FileContent is the payload returned by ReadContent.
type FileContent struct {
	ContentBase64 string
	SizeBytes     int64
	SHA256        string
	// Truncated is true when the file exceeded the requested ceiling and no
	// bytes were transferred.
	Truncated bool
}

// FileClient manages a single file on a Windows host over SSH + PowerShell.
//
// Error conventions:
//   - Read returns (nil, nil) when the file does not exist (EC-4).
//   - Set returns FileErrorAlreadyExists when the file exists and Overwrite is
//     false (EC-3), and FileErrorTypeConflict when the path is a directory (EC-2).
//   - Delete is idempotent: a missing file is a silent no-op (EC-12).
//   - ReadContent is reserved for ImportState (decision (b)); the regular Read
//     path must never transfer file bytes.
type FileClient interface {
	Set(ctx context.Context, input FileInput) (*FileState, error)
	Read(ctx context.Context, path string) (*FileState, error)
	ReadContent(ctx context.Context, path string, maxBytes int64) (*FileContent, error)
	Delete(ctx context.Context, path string) error
}

// ValidateFileContentBase64 checks that s is valid standard base64 and that the
// decoded payload fits within FileMaxContentBytes (T-2). It returns the decoded
// size so the provider layer can decide whether to emit the 1 MiB warning.
func ValidateFileContentBase64(s string) (int64, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return 0, &FileError{Resource: "windows_file",
			Kind:    FileErrorInvalidInput,
			Message: "content_base64 is not valid standard base64",
			Cause:   err,
		}
	}
	size := int64(len(raw))
	if size > FileMaxContentBytes {
		return size, &FileError{Resource: "windows_file",
			Kind: FileErrorInvalidInput,
			Message: fmt.Sprintf("content is %d bytes, which exceeds the %d byte limit of windows_file",
				size, FileMaxContentBytes),
		}
	}
	return size, nil
}

// NormaliseFileAttributes validates attribute keywords and returns them in a
// stable order so state comparisons do not churn.
func NormaliseFileAttributes(attrs []string) ([]string, error) {
	ordered := []string{
		FileAttributeArchive, FileAttributeHidden, FileAttributeReadOnly,
		FileAttributeSystem, FileAttributeTemporary,
	}
	seen := map[string]bool{}
	for _, a := range attrs {
		if _, ok := fileAttributeToDotNet[a]; !ok {
			return nil, &FileError{Resource: "windows_file",
				Kind:    FileErrorInvalidInput,
				Message: fmt.Sprintf("unknown file attribute %q", a),
			}
		}
		seen[a] = true
	}
	if seen[FileAttributeSystem] && seen[FileAttributeTemporary] {
		return nil, &FileError{Resource: "windows_file",
			Kind:    FileErrorInvalidInput,
			Message: "attributes \"system\" and \"temporary\" are mutually exclusive",
		}
	}
	out := make([]string, 0, len(seen))
	for _, a := range ordered {
		if seen[a] {
			out = append(out, a)
		}
	}
	return out, nil
}
