// Package winclient: windows_file_acl types, interface, and error definitions.
//
// Spec alignment: windows_file_acl spec v1 (2026-09-30).
//
// Scope note: this resource owns the security descriptor (owner + DACL +
// inheritance protection) of an EXISTING file or directory. It never creates
// nor deletes the target itself. Content is owned by windows_file, which
// preserves the security descriptor on every write (windows_file EC-15), so the
// two resources can manage the same path without fighting.
//
// SACL/audit entries are deliberately out of scope in v1: they require
// SeSecurityPrivilege and a separate ACL type.
package winclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// FileACLErrorKind categorises errors returned by FileACLClient operations.
type FileACLErrorKind string

const (
	FileACLErrorNotFound         FileACLErrorKind = "not_found"
	FileACLErrorPathNotFound     FileACLErrorKind = "path_not_found"
	FileACLErrorTypeConflict     FileACLErrorKind = "type_conflict"
	FileACLErrorPermission       FileACLErrorKind = "permission_denied"
	FileACLErrorPrivilegeNotHeld FileACLErrorKind = "privilege_not_held"
	FileACLErrorIdentityNotFound FileACLErrorKind = "identity_not_found"
	FileACLErrorInvalidInput     FileACLErrorKind = "invalid_input"
	FileACLErrorLocked           FileACLErrorKind = "file_locked"
	FileACLErrorUnknown          FileACLErrorKind = "unknown"
)

// FileACLError is the structured error type returned by all FileACLClient methods.
type FileACLError struct {
	Kind    FileACLErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *FileACLError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_file_acl [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_file_acl [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *FileACLError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *FileACLError) Is(target error) bool {
	t, ok := target.(*FileACLError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewFileACLError constructs a *FileACLError.
func NewFileACLError(kind FileACLErrorKind, message string, cause error, ctx map[string]string) *FileACLError {
	return &FileACLError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsFileACLError reports whether err is a *FileACLError with the given kind.
func IsFileACLError(err error, kind FileACLErrorKind) bool {
	var fe *FileACLError
	if errors.As(err, &fe) {
		return fe.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrFileACLNotFound         = &FileACLError{Kind: FileACLErrorNotFound}
	ErrFileACLPathNotFound     = &FileACLError{Kind: FileACLErrorPathNotFound}
	ErrFileACLTypeConflict     = &FileACLError{Kind: FileACLErrorTypeConflict}
	ErrFileACLPermission       = &FileACLError{Kind: FileACLErrorPermission}
	ErrFileACLPrivilegeNotHeld = &FileACLError{Kind: FileACLErrorPrivilegeNotHeld}
	ErrFileACLIdentityNotFound = &FileACLError{Kind: FileACLErrorIdentityNotFound}
	ErrFileACLInvalidInput     = &FileACLError{Kind: FileACLErrorInvalidInput}
	ErrFileACLLocked           = &FileACLError{Kind: FileACLErrorLocked}
	ErrFileACLUnknown          = &FileACLError{Kind: FileACLErrorUnknown}
)

// Schema enums.
const (
	FileACLModeAuthoritative = "authoritative"
	FileACLModeAdditive      = "additive"

	FileACLTypeAllow = "allow"
	FileACLTypeDeny  = "deny"

	FileACLInheritanceNone            = "none"
	FileACLInheritanceObject          = "object"
	FileACLInheritanceContainer       = "container"
	FileACLInheritanceContainerObject = "container_object"

	FileACLPropagationNone        = "none"
	FileACLPropagationInheritOnly = "inherit_only"
	FileACLPropagationNoPropagate = "no_propagate"

	FileACLTargetFile      = "file"
	FileACLTargetDirectory = "directory"
)

// FileACLRightSynchronize is the Synchronize bit of FileSystemRights.
//
// Verified on a live host: whether Synchronize appears in a written ACE depends
// on which FileSystemAccessRule constructor is used. The 3-argument one
// (identity, rights, type) silently ORs it in, so an ACE created as "Modify"
// (0x301BF = 197055) reads back as 0x1301BF = 1245631. The 5-argument one with
// explicit inheritance and propagation flags, which is what this client uses,
// adds nothing: masks round-trip byte for byte.
//
// Masks are therefore stored verbatim, never rewritten. Stripping the bit would
// corrupt FullControl, whose canonical mask 0x1F01FF already contains it:
// 0x1F01FF minus Synchronize is 0xF01FF, which decomposes into
// Modify + ChangePermissions + TakeOwnership + 0x40 instead of FullControl.
//
// Drift comparison stays tolerant through FileACLMasksEquivalent, so an ACE
// written by icacls or the Windows GUI (3-argument semantics, Synchronize set)
// does not diff against the same rights declared in Terraform.
const FileACLRightSynchronize int64 = 0x100000

// fileACLRightMasks maps a canonical FileSystemRights keyword to its mask.
// Synchronize is absent on purpose: see FileACLRightSynchronize.
var fileACLRightMasks = map[string]int64{
	"FullControl":                  0x1F01FF, // 2032127
	"Modify":                       0x0301BF, // 197055
	"ReadAndExecute":               0x0200A9, // 131241
	"Read":                         0x020089, // 131209
	"Write":                        0x000116, // 278
	"ListDirectory":                0x000001, // 1 (ReadData on a file)
	"Delete":                       0x010000, // 65536
	"DeleteSubdirectoriesAndFiles": 0x000040, // 64
	"ReadPermissions":              0x020000, // 131072
	"ChangePermissions":            0x040000, // 262144
	"TakeOwnership":                0x080000, // 524288
}

// fileACLRightOrder drives both the canonical output order and the greedy
// decomposition of a mask back into keywords: composite aliases first, so a
// FullControl mask renders as ["FullControl"] and not as its constituent bits.
var fileACLRightOrder = []string{
	"FullControl", "Modify", "ReadAndExecute", "Read", "Write",
	"Delete", "DeleteSubdirectoriesAndFiles", "ReadPermissions", "ChangePermissions",
	"TakeOwnership", "ListDirectory",
}

// CanonicalFileACLRight resolves a user-supplied right to its canonical
// PascalCase spelling, case-insensitively.
func CanonicalFileACLRight(s string) (string, bool) {
	for canonical := range fileACLRightMasks {
		if strings.EqualFold(canonical, s) {
			return canonical, true
		}
	}
	return "", false
}

// FileACLValidRights returns the accepted right keywords in canonical order,
// for schema validators and error messages.
func FileACLValidRights() []string {
	out := make([]string, len(fileACLRightOrder))
	copy(out, fileACLRightOrder)
	return out
}

// NormaliseFileACLRights validates the supplied rights and returns them in a
// stable canonical order together with the resulting access mask, kept verbatim
// (see FileACLRightSynchronize). An empty list is rejected: an ACE granting
// nothing is always a configuration mistake.
func NormaliseFileACLRights(rights []string) ([]string, int64, error) {
	if len(rights) == 0 {
		return nil, 0, &FileACLError{
			Kind:    FileACLErrorInvalidInput,
			Message: "an access rule must declare at least one right",
		}
	}
	seen := map[string]bool{}
	var mask int64
	for _, r := range rights {
		canonical, ok := CanonicalFileACLRight(r)
		if !ok {
			return nil, 0, &FileACLError{
				Kind: FileACLErrorInvalidInput,
				Message: fmt.Sprintf("unknown right %q: accepted values are %s",
					r, strings.Join(fileACLRightOrder, ", ")),
			}
		}
		seen[canonical] = true
		mask |= fileACLRightMasks[canonical]
	}
	out := make([]string, 0, len(seen))
	for _, canonical := range fileACLRightOrder {
		if seen[canonical] {
			out = append(out, canonical)
		}
	}
	return out, mask, nil
}

// FileACLRightsFromMask decomposes an access mask into canonical keywords,
// greedily preferring composite aliases so a FullControl mask renders as
// ["FullControl"] rather than as its constituent bits.
//
// The second return value carries the bits no keyword covers. A leftover
// Synchronize is dropped from it: the bit is implicit and reporting it as an
// unknown right would be noise. Any other leftover is surfaced to the caller,
// so an imported ACE is never silently misrepresented as narrower than it is.
func FileACLRightsFromMask(mask int64) ([]string, int64) {
	remaining := mask
	out := []string{}
	for _, canonical := range fileACLRightOrder {
		bits := fileACLRightMasks[canonical]
		if bits != 0 && remaining&bits == bits {
			out = append(out, canonical)
			remaining &^= bits
		}
	}
	return out, remaining &^ FileACLRightSynchronize
}

// FileACLMasksEquivalent reports whether two access masks grant the same
// effective access, ignoring the Synchronize bit. It is what drift comparison
// must use: the same rights written by icacls, by the Windows security dialog or
// by this provider can legitimately differ on that single bit.
func FileACLMasksEquivalent(a, b int64) bool {
	return a|FileACLRightSynchronize == b|FileACLRightSynchronize
}

// FileACLAccessRule is a single DACL entry.
//
// Identity accepts a SID ("S-1-5-32-544"), a qualified name
// ("BUILTIN\\Administrators", "DOMAIN\\user") or a bare local name, and is
// resolved on the target host. IdentitySID carries the canonical SID and is
// what drift comparison uses: comparing display names breaks as soon as an
// account is renamed or qualified differently, and the container used for
// acceptance tests has a random machine name on every start.
type FileACLAccessRule struct {
	Identity    string   `json:"identity"`
	IdentitySID string   `json:"identity_sid,omitempty"`
	Rights      []string `json:"rights,omitempty"`
	AccessMask  int64    `json:"access_mask"`
	Type        string   `json:"type"`
	Inheritance string   `json:"inheritance,omitempty"`
	Propagation string   `json:"propagation,omitempty"`
	Inherited   bool     `json:"inherited"`
}

// FileACLInput carries the desired security descriptor for a FileACLClient.Set
// call. It is marshalled to JSON and streamed on stdin: ACL data is data, never
// script text, so no user value is ever interpolated into PowerShell.
type FileACLInput struct {
	Path string `json:"path"`
	Mode string `json:"mode"`

	// Owner is empty when ownership is not managed, in which case the existing
	// owner is left untouched and never diffed.
	Owner string `json:"owner,omitempty"`

	InheritanceEnabled         bool `json:"inheritance_enabled"`
	PreserveInheritedOnProtect bool `json:"preserve_inherited_on_protect"`

	AccessRules []FileACLAccessRule `json:"access_rules"`

	// PriorRules are the previously managed rules. They are removed before the
	// new ones are added, and only in additive mode: AddAccessRule only ever ORs
	// rights in, so without an explicit removal pass a shrinking rights list
	// would never take effect.
	PriorRules []FileACLAccessRule `json:"prior_rules,omitempty"`
}

// FileACLState is the observed security descriptor of a target.
//
// AccessRules contains both explicit and inherited entries, flagged by
// Inherited. Filtering to the managed subset in additive mode is the provider
// layer's job, not the client's.
type FileACLState struct {
	Path               string
	TargetType         string
	Owner              string
	OwnerSID           string
	InheritanceEnabled bool
	SDDL               string
	AccessRules        []FileACLAccessRule
}

// ExplicitRules returns only the non-inherited entries.
func (s *FileACLState) ExplicitRules() []FileACLAccessRule {
	if s == nil {
		return nil
	}
	out := make([]FileACLAccessRule, 0, len(s.AccessRules))
	for _, r := range s.AccessRules {
		if !r.Inherited {
			out = append(out, r)
		}
	}
	return out
}

// FileACLClient manages the security descriptor of one file or directory.
//
// Error conventions:
//   - Read returns (nil, nil) when the target does not exist.
//   - Set returns FileACLErrorNotFound when the target does not exist: this
//     resource never creates the file or directory it secures.
//   - Reset is idempotent and never deletes the target: it restores inheritance
//     and strips the managed explicit entries.
type FileACLClient interface {
	Set(ctx context.Context, input FileACLInput) (*FileACLState, error)
	Read(ctx context.Context, path string) (*FileACLState, error)
	Reset(ctx context.Context, path string, managed []FileACLAccessRule) error
}

// ValidateFileACLInput performs the Go-side checks that do not need the target
// host: enum membership, rights normalisation, and the guard rails that protect
// an operator from locking themselves out of a path.
func ValidateFileACLInput(input *FileACLInput) error {
	if strings.TrimSpace(input.Path) == "" {
		return &FileACLError{Kind: FileACLErrorInvalidInput, Message: "path must not be empty"}
	}
	switch input.Mode {
	case FileACLModeAuthoritative, FileACLModeAdditive:
	case "":
		input.Mode = FileACLModeAuthoritative
	default:
		return &FileACLError{
			Kind:    FileACLErrorInvalidInput,
			Message: fmt.Sprintf("unknown mode %q: expected %q or %q", input.Mode, FileACLModeAuthoritative, FileACLModeAdditive),
		}
	}

	// Verified on a live host: SetAccessRuleProtection(true, true) does not
	// convert the inherited entries in memory. GetAccessRules still reports zero
	// explicit entries afterwards, and the conversion is performed by the kernel
	// when Set-Acl commits. No ordering of operations can therefore purge those
	// copies in the same pass: they land on disk as explicit entries, and the
	// next apply removes them, so two consecutive applies never converge.
	//
	// Authoritative mode therefore always protects without preserving. The
	// resulting DACL is exactly the declared rules, which is what the mode
	// promises, and the provider warns when the ignored value was set
	// explicitly.
	if input.Mode == FileACLModeAuthoritative && !input.InheritanceEnabled {
		input.PreserveInheritedOnProtect = false
	}

	if input.Mode == FileACLModeAuthoritative && len(input.AccessRules) == 0 {
		return &FileACLError{
			Kind: FileACLErrorInvalidInput,
			Message: "authoritative mode requires at least one access_rule: applying an empty " +
				"DACL would strip every explicit permission from the target",
		}
	}

	allow := 0
	seen := map[string]bool{}
	for i := range input.AccessRules {
		rule, err := normaliseFileACLRule(input.AccessRules[i])
		if err != nil {
			return err
		}
		input.AccessRules[i] = rule
		if rule.Type == FileACLTypeAllow {
			allow++
		}
		// Two rules differing only in rights are a config mistake: the last one
		// silently wins in authoritative mode.
		key := strings.ToLower(rule.Identity) + "|" + rule.Type + "|" + rule.Inheritance + "|" + rule.Propagation
		if seen[key] {
			return &FileACLError{
				Kind: FileACLErrorInvalidInput,
				Message: fmt.Sprintf("duplicate access_rule for identity %q (type %q, inheritance %q, propagation %q): "+
					"merge the rights into a single rule", rule.Identity, rule.Type, rule.Inheritance, rule.Propagation),
			}
		}
		seen[key] = true
	}

	// Protecting a target whose DACL grants nobody anything makes it
	// unreachable to everyone including its owner, recoverable only by taking
	// ownership. Refuse rather than brick the path.
	if !input.InheritanceEnabled && allow == 0 {
		return &FileACLError{
			Kind: FileACLErrorInvalidInput,
			Message: "inheritance_enabled = false with no allow access_rule would leave the target " +
				"with an empty effective DACL, denying access to everyone including the owner",
		}
	}

	for i := range input.PriorRules {
		rule, err := normaliseFileACLRule(input.PriorRules[i])
		if err != nil {
			return err
		}
		input.PriorRules[i] = rule
	}
	return nil
}

// normaliseFileACLRule validates one rule and fills in its canonical rights and
// access mask. An empty Inheritance is left empty on purpose: the target-side
// script defaults it to "none" on a file and "container_object" on a directory,
// which is the only place where the target type is actually known.
func normaliseFileACLRule(rule FileACLAccessRule) (FileACLAccessRule, error) {
	if strings.TrimSpace(rule.Identity) == "" {
		return rule, &FileACLError{Kind: FileACLErrorInvalidInput, Message: "access_rule identity must not be empty"}
	}

	switch rule.Type {
	case FileACLTypeAllow, FileACLTypeDeny:
	case "":
		rule.Type = FileACLTypeAllow
	default:
		return rule, &FileACLError{
			Kind:    FileACLErrorInvalidInput,
			Message: fmt.Sprintf("unknown access_rule type %q: expected %q or %q", rule.Type, FileACLTypeAllow, FileACLTypeDeny),
		}
	}

	switch rule.Inheritance {
	case "", FileACLInheritanceNone, FileACLInheritanceObject,
		FileACLInheritanceContainer, FileACLInheritanceContainerObject:
	default:
		return rule, &FileACLError{
			Kind:    FileACLErrorInvalidInput,
			Message: fmt.Sprintf("unknown inheritance %q", rule.Inheritance),
		}
	}

	switch rule.Propagation {
	case "", FileACLPropagationNone, FileACLPropagationInheritOnly, FileACLPropagationNoPropagate:
	default:
		return rule, &FileACLError{
			Kind:    FileACLErrorInvalidInput,
			Message: fmt.Sprintf("unknown propagation %q", rule.Propagation),
		}
	}
	if rule.Propagation == "" {
		rule.Propagation = FileACLPropagationNone
	}

	// A propagation flag without an inheritance flag is a no-op that would
	// silently not do what the operator wrote.
	if rule.Propagation != FileACLPropagationNone &&
		(rule.Inheritance == FileACLInheritanceNone || rule.Inheritance == "") {
		return rule, &FileACLError{
			Kind: FileACLErrorInvalidInput,
			Message: fmt.Sprintf("propagation %q requires an inheritance flag other than %q",
				rule.Propagation, FileACLInheritanceNone),
		}
	}

	rights, mask, err := NormaliseFileACLRights(rule.Rights)
	if err != nil {
		return rule, err
	}
	rule.Rights = rights
	rule.AccessMask = mask
	return rule, nil
}
