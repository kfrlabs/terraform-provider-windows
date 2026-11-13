// Package winclient: types for the windows_volume resource.
//
// VolumeInfo is the observed state returned by Read (and by every mutating
// call, which re-reads before responding). VolumeErrorKind / VolumeError
// follow the same shape as DiskError / PartitionError so the resource layer
// can branch with errors.As / errors.Is.
package winclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Supported file systems
// ---------------------------------------------------------------------------

// File systems accepted by the windows_volume resource and passed to
// Format-Volume -FileSystem (canonical spellings).
const (
	// VolumeFileSystemNTFS is the NTFS file system.
	VolumeFileSystemNTFS = "NTFS"
	// VolumeFileSystemReFS is the Resilient File System.
	VolumeFileSystemReFS = "ReFS"
	// VolumeFileSystemExFAT is the exFAT file system.
	VolumeFileSystemExFAT = "exFAT"
	// VolumeFileSystemFAT32 is the FAT32 file system.
	VolumeFileSystemFAT32 = "FAT32"
)

// volumeFileSystemAliases maps case-insensitive spellings to their canonical
// Format-Volume form.
var volumeFileSystemAliases = map[string]string{
	"NTFS":  VolumeFileSystemNTFS,
	"REFS":  VolumeFileSystemReFS,
	"EXFAT": VolumeFileSystemExFAT,
	"FAT32": VolumeFileSystemFAT32,
}

// CanonicalizeVolumeFileSystem resolves a configured file_system value to its
// canonical form (NTFS, ReFS, exFAT, FAT32), case-insensitively with
// surrounding whitespace tolerated. Anything else is an
// unsupported_file_system error.
func CanonicalizeVolumeFileSystem(raw string) (string, error) {
	if canon, ok := volumeFileSystemAliases[strings.ToUpper(strings.TrimSpace(raw))]; ok {
		return canon, nil
	}
	return "", NewVolumeError(VolumeErrorUnsupportedFileSystem,
		fmt.Sprintf("unsupported file system %q: want NTFS, ReFS, exFAT or FAT32", raw),
		nil, map[string]string{"file_system": raw})
}

// ---------------------------------------------------------------------------
// Volume labels (pure-Go validate)
// ---------------------------------------------------------------------------

// VolumeLabelMaxLength maps each canonical file system to the maximum volume
// label length Format-Volume accepts. NTFS and ReFS allow 32 characters;
// exFAT and FAT32 allow 11 characters (the VFAT on-disk label limit).
var VolumeLabelMaxLength = map[string]int{
	VolumeFileSystemNTFS:  32,
	VolumeFileSystemReFS:  32,
	VolumeFileSystemExFAT: 11,
	VolumeFileSystemFAT32: 11,
}

// ValidateVolumeLabel rejects labels that exceed the file-system limit. The
// empty label is always valid: it formats the volume with the host default
// (empty) label. fs must be canonical (see CanonicalizeVolumeFileSystem);
// an unrecognized fs falls back to the 32-character limit.
func ValidateVolumeLabel(fs, label string) error {
	limit := 32
	if m, ok := VolumeLabelMaxLength[fs]; ok {
		limit = m
	}
	if len([]rune(label)) > limit {
		return NewVolumeError(VolumeErrorUnknown,
			fmt.Sprintf("invalid file system label %q for %s: at most %d characters", label, fs, limit),
			nil, map[string]string{"file_system": fs, "file_system_label": label})
	}
	return nil
}

// ---------------------------------------------------------------------------
// Allocation unit sizes (pure-Go validate)
// ---------------------------------------------------------------------------

// Allocation unit size bounds shared by every file system: powers of two
// from 512 bytes to 2 MiB. A zero size means "host default" and is always
// valid; negative sizes are rejected.
const (
	volumeAllocationUnitMin = 512
	volumeAllocationUnitMax = 2097152
)

// volumeAllocationUnitAllow lists the per-file-system sizes Format-Volume
// accepts. NTFS spans 512 B-64 KiB, FAT32 512 B-32 KiB, exFAT the whole
// 512 B-2 MiB range, and ReFS only 4 KiB or 64 KiB.
var volumeAllocationUnitAllow = map[string][]int64{
	VolumeFileSystemNTFS:  {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536},
	VolumeFileSystemFAT32: {512, 1024, 2048, 4096, 8192, 16384, 32768},
	VolumeFileSystemExFAT: {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152},
	VolumeFileSystemReFS:  {4096, 65536},
}

// ValidateVolumeAllocationUnitSize rejects sizes Format-Volume would refuse:
// non-positive values other than the 0 "host default" sentinel, values
// outside 512 B-2 MiB, non-powers-of-two, and sizes outside the per-file
// -system allow-list. fs must be canonical; an unrecognized fs enforces only
// the power-of-two range check.
func ValidateVolumeAllocationUnitSize(fs string, size int64) error {
	if size == 0 {
		return nil // host default
	}
	if size < 0 || size < volumeAllocationUnitMin || size > volumeAllocationUnitMax || size&(size-1) != 0 {
		return NewVolumeError(VolumeErrorInvalidAllocationUnit,
			fmt.Sprintf("invalid allocation unit size %d for %s: want 0 (host default) or a power of two between 512 and 2097152", size, fs),
			nil, map[string]string{"file_system": fs, "allocation_unit_size": fmt.Sprintf("%d", size)})
	}
	if allow, ok := volumeAllocationUnitAllow[fs]; ok {
		for _, a := range allow {
			if a == size {
				return nil
			}
		}
		return NewVolumeError(VolumeErrorInvalidAllocationUnit,
			fmt.Sprintf("invalid allocation unit size %d for %s: allowed sizes are %v (0 selects the host default)", size, fs, allow),
			nil, map[string]string{"file_system": fs, "allocation_unit_size": fmt.Sprintf("%d", size)})
	}
	return nil
}

// ---------------------------------------------------------------------------
// VolumeErrorKind — typed error categories
// ---------------------------------------------------------------------------

// VolumeErrorKind categorises errors returned by WindowsVolumeClient.
type VolumeErrorKind string

const (
	// VolumeErrorNotFound is returned when no volume matches the lookup
	// (UniqueId, drive letter or label). It also covers the RAW case: an
	// unformatted partition reports a null or RAW file system, which reads
	// as "no volume". Read swallows it to (nil, nil); Delete is state-only
	// and never sees it.
	VolumeErrorNotFound VolumeErrorKind = "not_found"

	// VolumeErrorPartitionNotFound is returned when the hosting partition
	// (disk, key) is gone. Read swallows it to (nil, nil): a gone partition
	// means a gone volume.
	VolumeErrorPartitionNotFound VolumeErrorKind = "partition_not_found"

	// VolumeErrorAlreadyFormatted is returned by Format when the partition
	// already carries a formatted file system and allow_format_existing is
	// false. Reformatting destroys data, so it is opt-in.
	VolumeErrorAlreadyFormatted VolumeErrorKind = "already_formatted"

	// VolumeErrorProtected is returned when the hosting disk or partition is
	// protected: boot, system, EFI, MSR, recovery, pagefile-backed, or its
	// placement could not be determined (fail closed).
	VolumeErrorProtected VolumeErrorKind = "protected_storage"

	// VolumeErrorUnsupportedFileSystem is returned when the configured file
	// system is not NTFS, ReFS, exFAT or FAT32.
	VolumeErrorUnsupportedFileSystem VolumeErrorKind = "unsupported_file_system"

	// VolumeErrorInvalidAllocationUnit is returned when the configured
	// allocation unit size is not a per-file-system power of two in range.
	VolumeErrorInvalidAllocationUnit VolumeErrorKind = "invalid_allocation_unit"

	// VolumeErrorAccessDenied is returned when the SSH user lacks the
	// privilege for the operation (storage management needs elevation).
	VolumeErrorAccessDenied VolumeErrorKind = "access_denied"

	// VolumeErrorUnknown is the catch-all for unmapped PowerShell or SSH
	// failures, including timeouts and transport errors.
	VolumeErrorUnknown VolumeErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// VolumeError — structured error
// ---------------------------------------------------------------------------

// VolumeError is the structured error type returned by all
// WindowsVolumeClient methods. Use errors.Is(err, ErrVolume*) for kind
// matching, or errors.As(err, &ve) to inspect Context.
type VolumeError struct {
	// Kind is the machine-readable error category.
	Kind VolumeErrorKind

	// Message is a human-readable description safe to surface in Terraform
	// diagnostics. It never contains secrets: disk, partition and volume
	// identities carry no credentials.
	Message string

	// Context holds structured diagnostic key-value pairs (e.g. "host",
	// "port", "transport", "partition_id"). All values must be safe to log.
	Context map[string]string

	// Cause is the underlying error, if any (typically an SSH transport or
	// PowerShell parsing error).
	Cause error
}

// Error implements the error interface.
func (e *VolumeError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_volume [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_volume [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *VolumeError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *VolumeError) Is(target error) bool {
	t, ok := target.(*VolumeError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewVolumeError constructs a *VolumeError. Pass a nil cause when no underlying
// error exists. The ctx map may be nil.
func NewVolumeError(kind VolumeErrorKind, message string, cause error, ctx map[string]string) *VolumeError {
	return &VolumeError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsVolumeError reports whether err is a *VolumeError of the given kind.
func IsVolumeError(err error, kind VolumeErrorKind) bool {
	var ve *VolumeError
	if errors.As(err, &ve) {
		return ve.Kind == kind
	}
	return false
}

// Sentinel errors usable with errors.Is.
var (
	ErrVolumeNotFound              = &VolumeError{Kind: VolumeErrorNotFound}
	ErrVolumePartitionNotFound     = &VolumeError{Kind: VolumeErrorPartitionNotFound}
	ErrVolumeAlreadyFormatted      = &VolumeError{Kind: VolumeErrorAlreadyFormatted}
	ErrVolumeProtected             = &VolumeError{Kind: VolumeErrorProtected}
	ErrVolumeUnsupportedFileSystem = &VolumeError{Kind: VolumeErrorUnsupportedFileSystem}
	ErrVolumeInvalidAllocationUnit = &VolumeError{Kind: VolumeErrorInvalidAllocationUnit}
	ErrVolumeAccessDenied          = &VolumeError{Kind: VolumeErrorAccessDenied}
	ErrVolumeUnknown               = &VolumeError{Kind: VolumeErrorUnknown}
)

// ---------------------------------------------------------------------------
// VolumeInfo — observed state
// ---------------------------------------------------------------------------

// VolumeInfo holds the observed state of one volume as returned by the
// Format/Read/SetLabel/Lookup pipelines (every mutating call re-reads).
type VolumeInfo struct {
	// UniqueID is the Get-Volume UniqueId (the `\\?\Volume{...}\` object
	// path): the stable identity and the Terraform resource ID.
	UniqueID string

	// PartitionID is the hosting partition in "<disk_unique_id>|<key>" form
	// (GUID on GPT, decimal offset on MBR), resolved host-side from the
	// volume so imports can repopulate the required partition_id input.
	PartitionID string

	// DriveLetter is the assigned drive letter (upper-cased), or "" when the
	// volume has none.
	DriveLetter string

	// Path is the Get-Volume Path (the `\\?\Volume{...}\` object path).
	Path string

	// FileSystem is the Get-Volume FileSystem in canonical form (NTFS, ReFS,
	// exFAT, FAT32).
	FileSystem string

	// FileSystemLabel is the Get-Volume FileSystemLabel.
	FileSystemLabel string

	// AllocationUnitSize is the Get-Volume AllocationUnitSize in bytes (0
	// when the host reports none).
	AllocationUnitSize int64

	// SizeBytes is the Get-Volume Size in bytes.
	SizeBytes int64

	// SizeRemainingBytes is the Get-Volume SizeRemaining in bytes.
	SizeRemainingBytes int64

	// HealthStatus is the Get-Volume HealthStatus (e.g. Healthy).
	HealthStatus string

	// OperationalStatus is the Get-Volume OperationalStatus (e.g. OK).
	OperationalStatus string

	// DriveType is the Get-Volume DriveType (e.g. Fixed, Removable).
	DriveType string
}

// ---------------------------------------------------------------------------
// WindowsVolumeClient — CRUD contract
// ---------------------------------------------------------------------------

// VolumeFormatOptions carries the desired state for one Format-Volume call.
// The file system must be canonical (see CanonicalizeVolumeFileSystem); the
// label and allocation unit size must pass their validators. A zero
// AllocationUnitSize selects the host default.
type VolumeFormatOptions struct {
	// PartitionID is the hosting partition in "<disk_unique_id>|<key>" form
	// (the windows_partition resource ID spellings).
	PartitionID string

	// FileSystem is the canonical file system (NTFS, ReFS, exFAT, FAT32).
	FileSystem string

	// FileSystemLabel is the volume label, or "" for the host default.
	FileSystemLabel string

	// AllocationUnitSize is the allocation unit in bytes, or 0 for the host
	// default.
	AllocationUnitSize int64

	// AllowFormatExisting permits reformatting a partition that already
	// carries a formatted file system. Reformatting destroys data, so it is
	// opt-in; without it Format is an already_formatted error.
	AllowFormatExisting bool

	// FullFormat selects a full format instead of the default quick format.
	// A full format scans for bad sectors and can take a long time on large
	// disks (the resource timeouts default to 30m to cover it).
	FullFormat bool
}

// VolumeLookup selects one volume without managing it: exactly one of the
// three coordinates must be set (enforced by the data source schema via
// ExactlyOneOf and re-checked defensively here). UniqueID is the Get-Volume
// UniqueId, DriveLetter a single letter A-Z (C is allowed: reads never
// change the volume), FileSystemLabel an exact (case-insensitive) label;
// several label matches are an unknown error listing the count.
type VolumeLookup struct {
	// UniqueID is the Get-Volume UniqueId.
	UniqueID string
	// DriveLetter is a single drive letter A-Z (colon optional).
	DriveLetter string
	// FileSystemLabel is the exact volume label to match.
	FileSystemLabel string
}

// Validate reports whether the lookup carries exactly one coordinate. The
// provider schema enforces this at plan time; the client re-checks so a
// programming error fails fast instead of matching every volume (zero set)
// or an unpredictable intersection (several set).
func (l VolumeLookup) Validate() error {
	n := 0
	if strings.TrimSpace(l.UniqueID) != "" {
		n++
	}
	if strings.TrimSpace(l.DriveLetter) != "" {
		n++
	}
	if strings.TrimSpace(l.FileSystemLabel) != "" {
		n++
	}
	switch n {
	case 1:
		if strings.TrimSpace(l.DriveLetter) != "" {
			if _, err := NormalizeVolumeDriveLetter(l.DriveLetter); err != nil {
				return err
			}
		}
		return nil
	case 0:
		return NewVolumeError(VolumeErrorUnknown,
			"no volume lookup is set: exactly one of unique_id, drive_letter or file_system_label is required",
			nil, nil)
	default:
		return NewVolumeError(VolumeErrorUnknown,
			"several volume lookups are set: exactly one of unique_id, drive_letter or file_system_label is required",
			nil, nil)
	}
}

// NormalizeVolumeDriveLetter canonicalises a lookup drive letter: surrounding
// whitespace and a trailing colon are dropped and the remainder is
// upper-cased. Any single letter A-Z is accepted — including C, which the
// partition resource rejects for writes but which is safe to read here.
func NormalizeVolumeDriveLetter(raw string) (string, error) {
	letter := strings.ToUpper(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), ":")))
	if len(letter) != 1 || letter[0] < 'A' || letter[0] > 'Z' {
		return "", NewVolumeError(VolumeErrorUnknown,
			fmt.Sprintf("invalid drive letter %q: want a single letter A-Z (an optional trailing colon is allowed)", raw),
			nil, map[string]string{"drive_letter": raw})
	}
	return letter, nil
}

// VolumeImportKind identifies which spelling an import ID uses.
type VolumeImportKind string

const (
	// VolumeImportByUniqueID imports by the Get-Volume UniqueId.
	VolumeImportByUniqueID VolumeImportKind = "unique_id"
	// VolumeImportByDriveLetter imports by drive letter ("E" or "E:").
	VolumeImportByDriveLetter VolumeImportKind = "drive_letter"
)

// ResolveVolumeImportID classifies an import ID: a single letter (with an
// optional trailing colon) is a drive-letter lookup, anything else a volume
// UniqueId. The returned value is normalized (upper-cased letter without
// colon, trimmed UniqueId); an empty ID is an error.
func ResolveVolumeImportID(raw string) (kind VolumeImportKind, value string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", NewVolumeError(VolumeErrorUnknown,
			"invalid volume import ID: want the volume UniqueId or a drive letter such as E:",
			nil, map[string]string{"id": raw})
	}
	if letter, lerr := NormalizeVolumeDriveLetter(s); lerr == nil {
		return VolumeImportByDriveLetter, letter, nil
	}
	return VolumeImportByUniqueID, s, nil
}

// ValidateVolumeFormatOptions checks the Format inputs that can be decided
// without touching the host: the partition identity (parsed via the shared
// ParsePartitionID helper), the canonical file system, the label length and
// the allocation unit size.
func ValidateVolumeFormatOptions(opts VolumeFormatOptions) error {
	if _, _, err := ParsePartitionID(opts.PartitionID); err != nil {
		return NewVolumeError(VolumeErrorUnknown,
			fmt.Sprintf("invalid partition_id %q: want \"<disk_unique_id>|<guid_or_offset>\"", opts.PartitionID),
			nil, map[string]string{"partition_id": opts.PartitionID})
	}
	fs, err := CanonicalizeVolumeFileSystem(opts.FileSystem)
	if err != nil {
		return err
	}
	if err := ValidateVolumeLabel(fs, opts.FileSystemLabel); err != nil {
		return err
	}
	if err := ValidateVolumeAllocationUnitSize(fs, opts.AllocationUnitSize); err != nil {
		return err
	}
	return nil
}

// WindowsVolumeClient defines the contract for formatting and reading one
// volume on a remote Windows host over SSH.
//
// The resource is adoption-friendly but destructive by nature: Format writes
// a new file system to the hosting partition (already-formatted partitions
// need allow_format_existing). Delete makes no remote call: volumes are
// never unformatted, the resource only drops the adoption from state.
type WindowsVolumeClient interface {
	// Format resolves the hosting disk and partition (refusing protected
	// storage fail-closed), refuses an already-formatted volume unless
	// AllowFormatExisting is set, formats it (quick by default, full when
	// FullFormat is set) and returns the re-read state.
	Format(ctx context.Context, opts VolumeFormatOptions) (*VolumeInfo, error)

	// Read returns the observed state of the volume with the given UniqueId,
	// or (nil, nil) when it is gone or unformatted (null/RAW file system —
	// the resource handler then drops the resource from state).
	Read(ctx context.Context, uniqueID string) (*VolumeInfo, error)

	// SetLabel changes the volume label via Set-Volume and returns the
	// re-read state.
	SetLabel(ctx context.Context, uniqueID, label string) (*VolumeInfo, error)

	// Lookup resolves exactly one lookup coordinate (drive letter, UniqueId
	// or exact label) to its observed state for imports and the data
	// source. Zero matches are a not_found error; several label matches are
	// an unknown error.
	Lookup(ctx context.Context, lookup VolumeLookup) (*VolumeInfo, error)
}
