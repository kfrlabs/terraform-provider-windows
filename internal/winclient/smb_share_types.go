// Package winclient: windows_smb_share types, interface, and error definitions.
//
// Spec alignment: windows_smb_share spec v1 (issue #221).
//
// Scope note: this resource owns a single SMB share (New-SmbShare /
// Set-SmbShare / Remove-SmbShare) plus its share-level access entries
// (Grant-SmbShareAccess / Block-SmbShareAccess / Revoke-SmbShareAccess).
// It never creates the shared directory itself: pair it with
// windows_directory, which owns the directory entry, so both resources can
// manage the same path without fighting. NTFS ACLs stay with
// windows_file_acl; share permissions and NTFS permissions are evaluated
// together by Windows, with the most restrictive winning.
package winclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// SmbShareErrorKind categorises errors returned by SmbShareClient operations.
type SmbShareErrorKind string

const (
	SmbShareErrorNotFound                 SmbShareErrorKind = "not_found"
	SmbShareErrorAlreadyExists            SmbShareErrorKind = "already_exists"
	SmbShareErrorPathNotFound             SmbShareErrorKind = "path_not_found"
	SmbShareErrorAccessDenied             SmbShareErrorKind = "permission_denied"
	SmbShareErrorInvalidName              SmbShareErrorKind = "invalid_name"
	SmbShareErrorPrincipalNotFound        SmbShareErrorKind = "principal_not_found"
	SmbShareErrorServerServiceUnavailable SmbShareErrorKind = "server_service_unavailable"
	SmbShareErrorUnknown                  SmbShareErrorKind = "unknown"
)

// SmbShareError is the structured error type returned by all SmbShareClient methods.
type SmbShareError struct {
	Kind    SmbShareErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *SmbShareError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_smb_share [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_smb_share [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *SmbShareError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *SmbShareError) Is(target error) bool {
	t, ok := target.(*SmbShareError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewSmbShareError constructs a *SmbShareError.
func NewSmbShareError(kind SmbShareErrorKind, message string, cause error, ctx map[string]string) *SmbShareError {
	return &SmbShareError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsSmbShareError reports whether err is a *SmbShareError with the given kind.
func IsSmbShareError(err error, kind SmbShareErrorKind) bool {
	var se *SmbShareError
	if errors.As(err, &se) {
		return se.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrSmbShareNotFound                 = &SmbShareError{Kind: SmbShareErrorNotFound}
	ErrSmbShareAlreadyExists            = &SmbShareError{Kind: SmbShareErrorAlreadyExists}
	ErrSmbSharePathNotFound             = &SmbShareError{Kind: SmbShareErrorPathNotFound}
	ErrSmbShareAccessDenied             = &SmbShareError{Kind: SmbShareErrorAccessDenied}
	ErrSmbShareInvalidName              = &SmbShareError{Kind: SmbShareErrorInvalidName}
	ErrSmbSharePrincipalNotFound        = &SmbShareError{Kind: SmbShareErrorPrincipalNotFound}
	ErrSmbShareServerServiceUnavailable = &SmbShareError{Kind: SmbShareErrorServerServiceUnavailable}
	ErrSmbShareUnknown                  = &SmbShareError{Kind: SmbShareErrorUnknown}
)

// Share property enums, mirroring the New-SmbShare / Set-SmbShare parameters.
const (
	SmbShareFolderEnumerationUnrestricted = "Unrestricted"
	SmbShareFolderEnumerationAccessBased  = "AccessBased"

	SmbShareCachingNone        = "None"
	SmbShareCachingManual      = "Manual"
	SmbShareCachingPrograms    = "Programs"
	SmbShareCachingDocuments   = "Documents"
	SmbShareCachingBranchCache = "BranchCache"
)

// SmbShareValidFolderEnumerationModes returns the accepted values for
// folder_enumeration_mode, for schema validators and error messages.
func SmbShareValidFolderEnumerationModes() []string {
	return []string{SmbShareFolderEnumerationUnrestricted, SmbShareFolderEnumerationAccessBased}
}

// SmbShareMaxConcurrentUserLimit mirrors the Windows UInt32 range for
// New-SmbShare/Set-SmbShare -ConcurrentUserLimit (0 means no limit).
const SmbShareMaxConcurrentUserLimit = 4294967295

// SmbShareMaxDescriptionLength mirrors the schema cap (≤256 characters).
const SmbShareMaxDescriptionLength = 256

// SmbShareValidCachingModes returns the accepted values for caching_mode.
func SmbShareValidCachingModes() []string {
	return []string{
		SmbShareCachingNone,
		SmbShareCachingManual,
		SmbShareCachingPrograms,
		SmbShareCachingDocuments,
		SmbShareCachingBranchCache,
	}
}

// SmbShareTrustee is one observed share access entry: the display name as
// reported by Get-SmbShareAccess plus the canonical SID the provider layer
// uses for drift comparison (same SID-first precedent as windows_file_acl).
type SmbShareTrustee struct {
	Name string `json:"name"`
	SID  string `json:"sid"`
}

// SmbShareSettings carries the mutable share properties plus the desired
// share-level access sets shared by Create and Update.
//
// Access-set semantics (authoritative): ManageAccess is false when all four
// principal lists are empty, in which case the host access list is left
// untouched and never diffed. When true, all four lists are authoritative:
// an empty list revokes every entry at that level, and any out-of-band entry
// (including the Everyone:Read entry New-SmbShare creates by default and any
// Custom-granularity ACE) is revoked as stale.
type SmbShareSettings struct {
	Description           string
	FolderEnumerationMode string
	CachingMode           string
	ConcurrentUserLimit   int64
	EncryptData           bool

	FullAccess   []string
	ChangeAccess []string
	ReadAccess   []string
	NoAccess     []string

	// ManageAccess is true when at least one access set was configured.
	// It distinguishes "all four sets omitted" (unmanaged) from "configured
	// empty" (revoke everything at that level).
	ManageAccess bool
}

// SmbShareInput carries the parameters for a SmbShareClient.Create call.
type SmbShareInput struct {
	Name string
	Path string
	SmbShareSettings
}

// SmbShareUpdateInput carries the parameters for a SmbShareClient.Update
// call. Path is immutable (ForceNew) and therefore absent: only the name
// keys the share.
type SmbShareUpdateInput struct {
	Name string
	SmbShareSettings
}

// SmbShareInfo is the observed state of one SMB share on the Windows host.
type SmbShareInfo struct {
	Name                  string
	Path                  string
	Description           string
	FolderEnumerationMode string
	CachingMode           string
	ConcurrentUserLimit   int64
	EncryptData           bool
	Special               bool

	FullAccess   []SmbShareTrustee
	ChangeAccess []SmbShareTrustee
	ReadAccess   []SmbShareTrustee
	NoAccess     []SmbShareTrustee
}

// SmbShareClient manages a single SMB share on a Windows host over SSH +
// PowerShell.
//
// Error conventions:
//   - Read returns (nil, nil) when the share does not exist.
//   - Create returns SmbShareErrorAlreadyExists when the share already exists.
//   - Update returns SmbShareErrorNotFound when the share does not exist.
//   - Delete is idempotent: a missing share is a silent no-op.
//   - Read of a Special (administrative, e.g. C$, ADMIN$, IPC$) share
//     succeeds, but the provider layer refuses to import it: special shares
//     are owned by Windows, not by Terraform.
type SmbShareClient interface {
	Create(ctx context.Context, input SmbShareInput) (*SmbShareInfo, error)
	Read(ctx context.Context, name string) (*SmbShareInfo, error)
	Update(ctx context.Context, input SmbShareUpdateInput) (*SmbShareInfo, error)
	Delete(ctx context.Context, name string) error
}

// ValidateSmbShareName performs the Go-side checks for a share name: length
// 1-80, no characters Windows forbids in a share name (backslash, slash,
// brackets, colon, pipe, angle brackets, plus, equals, semicolon, comma,
// asterisk, question mark, double quote, or control characters), and no
// reserved administrative share name (IPC$, ADMIN$, <drive-letter>$).
// The provider schema enforces the same rules at plan time; this is the
// defence-in-depth check shared by Create/Read/Update/Delete.
func ValidateSmbShareName(name string) error {
	if len(name) == 0 || len(name) > 80 {
		return &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("share name %q must be 1-80 characters", name),
		}
	}
	const forbidden = `\/[]:|<>+=;,*?"`
	for _, r := range name {
		if strings.ContainsRune(forbidden, r) || r < 0x20 || r == 0x7f {
			return &SmbShareError{
				Kind:    SmbShareErrorInvalidName,
				Message: fmt.Sprintf("share name %q contains a forbidden character (\\ / [ ] : | < > + = ; , * ? \" or a control character)", name),
			}
		}
	}
	upper := strings.ToUpper(name)
	if upper == "IPC$" || upper == "ADMIN$" {
		return &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("share name %q is a reserved administrative share name", name),
		}
	}
	if len(name) == 2 && upper[1] == '$' && upper[0] >= 'A' && upper[0] <= 'Z' {
		return &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("share name %q is a reserved administrative drive share name (<letter>$)", name),
		}
	}
	return nil
}

// NormalizeSmbSharePath validates a local absolute share path
// (drive-letter form, e.g. D:\Shares\Finance; UNC paths are rejected) and
// normalises it by trimming a trailing backslash (except on a drive root).
// Forward slashes are rejected rather than normalised: share paths must use
// Windows backslash separators throughout, so mixed separators surface as an
// error instead of silently pointing at a different directory.
// Whether the path exists is only known on the host: a missing directory
// surfaces as SmbShareErrorPathNotFound at apply time.
func NormalizeSmbSharePath(path string) (string, error) {
	if strings.Contains(path, "/") {
		return "", &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("share path %q must use backslash separators (e.g. D:\\Shares\\Finance); forward slashes are not accepted", path),
		}
	}
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' {
		return "", &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("share path %q must be a local absolute Windows path (e.g. D:\\Shares\\Finance); UNC paths are not accepted", path),
		}
	}
	drive := path[0]
	if (drive < 'A' || drive > 'Z') && (drive < 'a' || drive > 'z') {
		return "", &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("share path %q must start with a drive letter", path),
		}
	}
	// A drive root (D:\) keeps its trailing separator; anything longer does not.
	if len(path) > 3 {
		path = strings.TrimRight(path, `\`)
	}
	return path, nil
}

// smbShareWellKnownSIDs maps well-known trustee spellings (lower-cased) to
// their canonical SID so plan-time duplicate detection stays SID-aware for
// the identities operators write most often. Full NTAccount resolution only
// happens on the host at apply time.
var smbShareWellKnownSIDs = map[string]string{
	"everyone":                      "S-1-1-1",
	"authenticated users":           "S-1-5-11",
	"builtin\\administrators":       "S-1-5-32-544",
	"builtin\\users":                "S-1-5-32-545",
	"nt authority\\system":          "S-1-5-18",
	"nt authority\\local service":   "S-1-5-19",
	"nt authority\\network service": "S-1-5-20",
}

// canonicalSmbSharePrincipalKey normalises one trustee spelling for
// cross-set duplicate comparison: raw SIDs compare case-insensitively,
// well-known names resolve to their SID, everything else compares as an
// upper-cased name. DOMAIN\user versus user@domain.com spellings of the
// same account cannot be equated without the host and are treated as
// distinct here; the host-side reconcile revokes whatever is truly stale.
func canonicalSmbSharePrincipalKey(p string) string {
	trimmed := strings.TrimSpace(p)
	if strings.HasPrefix(strings.ToUpper(trimmed), "S-1-") {
		return "SID:" + strings.ToUpper(trimmed)
	}
	if sid, ok := smbShareWellKnownSIDs[strings.ToLower(trimmed)]; ok {
		return "SID:" + sid
	}
	return "NAME:" + strings.ToUpper(trimmed)
}

// SmbShareBroadPrincipal reports whether a trustee spelling denotes Everyone
// or Authenticated Users, the two identities that grant access to nearly
// anybody. The provider layer warns (but does not refuse) when they are
// placed in full_access or change_access. Raw SIDs compare case-insensitively
// and well-known names resolve through smbShareWellKnownSIDs.
func SmbShareBroadPrincipal(p string) bool {
	switch canonicalSmbSharePrincipalKey(p) {
	case "SID:S-1-1-1", "SID:S-1-5-11":
		return true
	default:
		return false
	}
}

// ValidateSmbShareSettings performs the Go-side checks shared by Create and
// Update that need no host: enum membership, concurrent_user_limit range,
// and the cross-set duplicate rule (one principal in at most one access
// set). Empty FolderEnumerationMode/CachingMode fall back to the Windows
// defaults (Unrestricted/Manual). ManageAccess is left untouched: the caller
// (provider layer) sets it from the plan's null-ness, which distinguishes
// "all four sets omitted" (unmanaged) from "configured empty" (revoke
// everything at that level) — a distinction slice contents alone cannot
// carry. Validation that needs the host (SID resolution, principal
// existence) surfaces as SmbShareErrorPrincipalNotFound at apply time.
func ValidateSmbShareSettings(s *SmbShareSettings) error {
	switch s.FolderEnumerationMode {
	case "":
		s.FolderEnumerationMode = SmbShareFolderEnumerationUnrestricted
	case SmbShareFolderEnumerationUnrestricted, SmbShareFolderEnumerationAccessBased:
	default:
		return &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("unknown folder_enumeration_mode %q: expected %q or %q", s.FolderEnumerationMode, SmbShareFolderEnumerationUnrestricted, SmbShareFolderEnumerationAccessBased),
		}
	}
	switch s.CachingMode {
	case "":
		s.CachingMode = SmbShareCachingManual
	case SmbShareCachingNone, SmbShareCachingManual, SmbShareCachingPrograms, SmbShareCachingDocuments, SmbShareCachingBranchCache:
	default:
		return &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("unknown caching_mode %q: expected one of None, Manual, Programs, Documents, BranchCache", s.CachingMode),
		}
	}
	if s.ConcurrentUserLimit < 0 || s.ConcurrentUserLimit > SmbShareMaxConcurrentUserLimit {
		return &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("concurrent_user_limit %d must be between 0 and %d (0 means no limit)", s.ConcurrentUserLimit, SmbShareMaxConcurrentUserLimit),
		}
	}
	if utf8.RuneCountInString(s.Description) > SmbShareMaxDescriptionLength {
		return &SmbShareError{
			Kind:    SmbShareErrorInvalidName,
			Message: fmt.Sprintf("description must be at most %d characters", SmbShareMaxDescriptionLength),
		}
	}
	seen := map[string]string{}
	for _, bucket := range []struct {
		level string
		items []string
	}{
		{"full_access", s.FullAccess},
		{"change_access", s.ChangeAccess},
		{"read_access", s.ReadAccess},
		{"no_access", s.NoAccess},
	} {
		for _, p := range bucket.items {
			if strings.TrimSpace(p) == "" {
				return &SmbShareError{
					Kind:    SmbShareErrorInvalidName,
					Message: fmt.Sprintf("%s must not contain empty principals", bucket.level),
				}
			}
			key := canonicalSmbSharePrincipalKey(p)
			if prev, dup := seen[key]; dup {
				return &SmbShareError{
					Kind: SmbShareErrorInvalidName,
					Message: fmt.Sprintf("principal %q appears in both %s and %s: a principal may belong to at most one access set",
						p, prev, bucket.level),
				}
			}
			seen[key] = bucket.level
		}
	}
	return nil
}
