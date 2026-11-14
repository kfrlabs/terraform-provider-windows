// Package winclient: types for the windows_partition resource.
//
// PartitionInfo is the observed state returned by Read (and by every
// mutating call, which re-reads before responding). PartitionErrorKind /
// PartitionError follow the same shape as DiskError so the resource layer
// can branch with errors.As / errors.Is.
package winclient

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// PartitionErrorKind — typed error categories
// ---------------------------------------------------------------------------

// PartitionErrorKind categorises errors returned by WindowsPartitionClient.
type PartitionErrorKind string

const (
	// PartitionErrorNotFound is returned when no partition matches the
	// disk/key identity (GUID on GPT, offset on MBR). Read swallows it to
	// (nil, nil); Delete treats it as success.
	PartitionErrorNotFound = "not_found"

	// PartitionErrorDiskNotFound is returned when no disk matches the
	// selector. Read swallows it to (nil, nil): a gone disk means a gone
	// partition.
	PartitionErrorDiskNotFound = "disk_not_found"

	// PartitionErrorDiskNotReady is returned when the disk is offline,
	// read-only or still RAW (not initialized), so no partition can be
	// created, grown or otherwise changed on it.
	PartitionErrorDiskNotReady = "disk_not_ready"

	// PartitionErrorInsufficientSpace is returned when the requested size
	// exceeds the largest free extent (Create) or the supported maximum
	// (Grow). The message carries the largest usable size in bytes.
	PartitionErrorInsufficientSpace = "insufficient_space"

	// PartitionErrorDriveLetterInUse is returned when the requested drive
	// letter is already assigned on the host.
	PartitionErrorDriveLetterInUse = "drive_letter_in_use"

	// PartitionErrorShrinkNotSupported is returned Go-side when the desired
	// size is smaller than the observed size. Shrinking a partition is out
	// of scope in v1 and is refused before any remote call.
	PartitionErrorShrinkNotSupported = "shrink_not_supported"

	// PartitionErrorProtected is returned when the partition (or its disk)
	// is protected: boot, system, EFI, MSR, recovery, pagefile-backed, or
	// its placement could not be determined (fail closed).
	PartitionErrorProtected = "protected_storage"

	// PartitionErrorAccessDenied is returned when the SSH user lacks the
	// privilege for the operation (storage management needs elevation).
	PartitionErrorAccessDenied = "access_denied"

	// PartitionErrorUnknown is the catch-all for unmapped PowerShell or SSH
	// failures, including timeouts and transport errors.
	PartitionErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// PartitionError — structured error
// ---------------------------------------------------------------------------

// PartitionError is the structured error type returned by all
// WindowsPartitionClient methods. Use errors.Is(err, ErrPartition*) for kind
// matching, or errors.As(err, &pe) to inspect Context.
type PartitionError = ResourceError

// NewPartitionError constructs a *PartitionError. Pass a nil cause when no
// underlying error exists. The ctx map may be nil.
func NewPartitionError(kind PartitionErrorKind, message string, cause error, ctx map[string]string) *PartitionError {
	return NewResourceError("windows_partition", string(kind), message, cause, ctx)
}

// IsPartitionError reports whether err is a *PartitionError of the given kind.
func IsPartitionError(err error, kind PartitionErrorKind) bool {
	return IsResourceError(err, "windows_partition", string(kind))
}

// Sentinel errors usable with errors.Is.
var (
	ErrPartitionNotFound           = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorNotFound}
	ErrPartitionDiskNotFound       = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorDiskNotFound}
	ErrPartitionDiskNotReady       = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorDiskNotReady}
	ErrPartitionInsufficientSpace  = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorInsufficientSpace}
	ErrPartitionDriveLetterInUse   = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorDriveLetterInUse}
	ErrPartitionShrinkNotSupported = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorShrinkNotSupported}
	ErrPartitionProtected          = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorProtected}
	ErrPartitionAccessDenied       = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorAccessDenied}
	ErrPartitionUnknown            = &PartitionError{Resource: "windows_partition", Kind: PartitionErrorUnknown}
)

// ---------------------------------------------------------------------------
// PartitionInfo — observed state
// ---------------------------------------------------------------------------

// PartitionInfo holds the observed state of one partition as returned by the
// Read/Create/Grow/Set pipelines (every mutating call re-reads).
type PartitionInfo struct {
	// DiskUniqueID is the Get-Disk UniqueId of the hosting disk.
	DiskUniqueID string

	// PartitionNumber is the Get-Partition PartitionNumber (scan-time
	// assignment, informational only: identity never relies on it).
	PartitionNumber int

	// GUID is the Get-Partition Guid. On GPT disks it is the stable
	// identity; on MBR disks it is empty (or all zeros) and OffsetBytes is
	// the identity instead.
	GUID string

	// OffsetBytes is the Get-Partition Offset in bytes (the MBR identity).
	OffsetBytes int64

	// SizeBytes is the Get-Partition Size in bytes.
	SizeBytes int64

	// DriveLetter is the assigned drive letter (upper-cased), or "" when the
	// partition has none.
	DriveLetter string

	// GptType is the Get-Partition GptType (GPT disks only).
	GptType string

	// MbrType is the Get-Partition MbrType (MBR disks only).
	MbrType string

	// IsHidden mirrors Get-Partition IsHidden.
	IsHidden bool

	// IsActive mirrors Get-Partition IsActive (MBR only).
	IsActive bool

	// IsBoot / IsSystem mirror the Get-Partition protection flags.
	IsBoot   bool
	IsSystem bool

	// OperationalStatus is the Get-Partition OperationalStatus.
	OperationalStatus string

	// AccessPaths lists the Get-Partition AccessPaths.
	AccessPaths []string
}

// ---------------------------------------------------------------------------
// WindowsPartitionClient — CRUD contract
// ---------------------------------------------------------------------------

// PartitionCreateOptions carries the desired state for one New-Partition
// call. Sizes are magnitudes in bytes; user input must be validated through
// the helpers below before reaching the scripts.
type PartitionCreateOptions struct {
	// DiskUniqueID selects the hosting disk (Get-Disk UniqueId).
	DiskUniqueID string

	// SizeBytes is the desired partition size. Ignored when UseMaximumSize
	// is true; otherwise it must be positive.
	SizeBytes int64

	// UseMaximumSize creates the partition from the largest free extent
	// (-UseMaximumSize) instead of an explicit size.
	UseMaximumSize bool

	// HasOffset reports whether OffsetBytes carries an explicit placement.
	// Without it the host picks the first fitting extent.
	HasOffset bool

	// OffsetBytes is the explicit partition offset (New-Partition -Offset).
	OffsetBytes int64

	// DriveLetter is the letter to assign after creation (upper-cased D-Z),
	// or "" for no letter. The partition is always created with
	// -AssignDriveLetter:$false first so no random letter — and no Explorer
	// "format disk" race — can slip in.
	DriveLetter string

	// GptType is the canonical GPT type GUID (upper-case, no braces) for
	// GPT disks, or "" for the host default. Conflicts with MbrType.
	GptType string

	// MbrType is the canonical MBR type byte ("0x07" form) for MBR disks,
	// or "" for the host default. Conflicts with GptType.
	MbrType string
}

// WindowsPartitionClient defines the contract for managing one partition on
// a remote Windows host over SSH.
//
// Identity is the (disk, key) pair: the partition GUID on GPT disks, the
// byte offset on MBR disks — never the scan-time partition number. All
// mutating calls re-read and return the observed state.
type WindowsPartitionClient interface {
	// Create resolves the disk (refusing protected, offline, read-only or
	// RAW disks with disk_not_ready), checks the free extent
	// (insufficient_space carries the largest free extent), creates the
	// partition with -AssignDriveLetter:$false, assigns the configured
	// letter explicitly, and returns the re-read state.
	Create(ctx context.Context, opts PartitionCreateOptions) (*PartitionInfo, error)

	// Read returns the observed state of the partition identified by
	// (diskUniqueID, key), or (nil, nil) when the disk or the partition is
	// gone (the resource handler then drops the resource from state).
	Read(ctx context.Context, diskUniqueID, key string) (*PartitionInfo, error)

	// Grow enlarges the partition to sizeBytes via Get-PartitionSupportedSize
	// + Resize-Partition and returns the re-read state. Shrinking is refused
	// Go-side with shrink_not_supported (use DecidePartitionResize first).
	Grow(ctx context.Context, diskUniqueID, key string, sizeBytes int64) (*PartitionInfo, error)

	// SetDriveLetter assigns letter (or removes the letter when "") via
	// Set-Partition -NewDriveLetter / Remove-PartitionAccessPath and returns
	// the re-read state.
	SetDriveLetter(ctx context.Context, diskUniqueID, key, letter string) (*PartitionInfo, error)

	// SetFlags enforces the hidden/active flags (nil = leave unmanaged) via
	// Set-Partition and returns the re-read state.
	SetFlags(ctx context.Context, diskUniqueID, key string, hidden, active *bool) (*PartitionInfo, error)

	// Delete guards (never system/boot/recovery/MSR/pagefile partitions)
	// then removes the partition. A missing partition is success.
	Delete(ctx context.Context, diskUniqueID, key string) error
}

// ---------------------------------------------------------------------------
// Drive letters (pure-Go normalize/validate)
// ---------------------------------------------------------------------------

// NormalizeDriveLetter canonicalises a configured drive letter: surrounding
// whitespace is dropped and the remainder is upper-cased. Exactly one letter
// D-Z is accepted; A, B and C are rejected (floppy- and system-reserved) and
// anything else is rejected as malformed. The empty string is rejected too:
// callers distinguish "remove the letter" with an explicit empty value
// before calling this helper.
func NormalizeDriveLetter(raw string) (string, error) {
	letter := strings.ToUpper(strings.TrimSpace(raw))
	if len(letter) != 1 || letter[0] < 'A' || letter[0] > 'Z' {
		return "", NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid drive letter %q: want a single letter D-Z", raw),
			nil, map[string]string{"drive_letter": raw})
	}
	if letter == "A" || letter == "B" || letter == "C" {
		return "", NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid drive letter %q: A, B and C are reserved, want D-Z", raw),
			nil, map[string]string{"drive_letter": raw})
	}
	return letter, nil
}

// ---------------------------------------------------------------------------
// GPT partition-type aliases (pure-Go)
// ---------------------------------------------------------------------------

// PartitionGPTAliases maps the friendly gpt_type spellings accepted by the
// windows_partition resource to their canonical GPT type GUIDs (upper-case,
// no braces, as Get-Partition reports them without braces). Anything else is
// treated as a literal GUID and validated by CanonicalizeGPTType.
var PartitionGPTAliases = map[string]string{
	"BASIC_DATA": GPTBasicDataPartitionGUID,
	"MSR":        GPTMicrosoftReservedGUID,
	"RECOVERY":   GPTRecoveryPartitionGUID,
}

// guidPattern accepts a GUID with optional surrounding braces.
var guidPattern = regexp.MustCompile(`^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$`)

// CanonicalizeGPTType resolves a configured gpt_type to its canonical GUID
// (upper-case, no braces): a known alias (basic_data, msr, recovery,
// case-insensitive) maps to its well-known GUID, otherwise the value must
// already be a GUID. The empty string passes through as "" (host default).
func CanonicalizeGPTType(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if guid, ok := PartitionGPTAliases[strings.ToUpper(s)]; ok {
		return guid, nil
	}
	if !guidPattern.MatchString(s) {
		return "", NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid gpt_type %q: want basic_data, msr, recovery or a GUID", raw),
			nil, map[string]string{"gpt_type": raw})
	}
	return strings.ToUpper(strings.Trim(s, "{}")), nil
}

// ---------------------------------------------------------------------------
// MBR partition-type values (pure-Go)
// ---------------------------------------------------------------------------

// PartitionMBRAliases maps the friendly mbr_type spellings accepted by the
// windows_partition resource to their canonical partition-type bytes
// ("0x.." form, as passed to New-Partition -MbrType).
var PartitionMBRAliases = map[string]string{
	"IFS":       "0x07",
	"NTFS":      "0x07",
	"FAT32":     "0x0B",
	"FAT32_LBA": "0x0C",
	"EXTENDED":  "0x0F",
}

// CanonicalizeMBRType resolves a configured mbr_type to its canonical byte
// ("0x.." upper-case form): a known alias (IFS, FAT32, ..., case-insensitive)
// maps to its byte, otherwise the value must be a hex byte (0x00-0xFF) or a
// decimal byte (0-255). The empty string passes through as "" (host default).
func CanonicalizeMBRType(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return "", nil
	}
	if b, ok := PartitionMBRAliases[s]; ok {
		return b, nil
	}
	digits := strings.TrimPrefix(s, "0X")
	if strings.HasPrefix(s, "0X") {
		if len(digits) < 1 || len(digits) > 2 {
			return "", mbrTypeError(raw)
		}
		if _, err := strconv.ParseUint(digits, 16, 8); err != nil {
			return "", mbrTypeError(raw)
		}
		digits = strings.ToUpper(digits)
		if len(digits) == 1 {
			digits = "0" + digits
		}
		return "0x" + digits, nil
	}
	if n, err := strconv.ParseUint(s, 10, 8); err == nil {
		return fmt.Sprintf("0x%02X", n), nil
	}
	return "", mbrTypeError(raw)
}

func mbrTypeError(raw string) *PartitionError {
	return NewPartitionError(PartitionErrorUnknown,
		fmt.Sprintf("invalid mbr_type %q: want IFS, FAT32, FAT32_LBA, EXTENDED, NTFS, a hex byte (0x00-0xFF) or a decimal byte (0-255)", raw),
		nil, map[string]string{"mbr_type": raw})
}

// ---------------------------------------------------------------------------
// Partition IDs (pure-Go build/parse)
// ---------------------------------------------------------------------------

// PartitionIDSeparator joins the disk UniqueId and the partition key in the
// Terraform resource ID: "<disk_unique_id>|<guid>" on GPT,
// "<disk_unique_id>|<offset>" on MBR.
const PartitionIDSeparator = "|"

// BuildPartitionID renders the Terraform resource ID for (diskUniqueID, key).
// Both parts must be non-empty.
func BuildPartitionID(diskUniqueID, key string) (string, error) {
	disk := strings.TrimSpace(diskUniqueID)
	k := strings.TrimSpace(key)
	if disk == "" || k == "" {
		return "", NewPartitionError(PartitionErrorUnknown,
			"cannot build a partition ID from an empty disk UniqueId or partition key",
			nil, map[string]string{"disk_unique_id": diskUniqueID, "key": key})
	}
	return disk + PartitionIDSeparator + k, nil
}

// ParsePartitionID splits a Terraform resource ID back into its disk
// UniqueId and partition key (GUID on GPT, decimal offset on MBR).
func ParsePartitionID(id string) (diskUniqueID, key string, err error) {
	parts := strings.SplitN(id, PartitionIDSeparator, 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid partition ID %q: want \"<disk_unique_id>|<guid_or_offset>\"", id),
			nil, map[string]string{"id": id})
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

// PartitionResourceKey returns the stable identity key for info: the GUID on
// GPT, the decimal byte offset on MBR (whose Guid is empty or all zeros).
func PartitionResourceKey(info *PartitionInfo) string {
	if info == nil {
		return ""
	}
	if g := strings.Trim(info.GUID, "{} "); g != "" && !strings.EqualFold(g, "00000000-0000-0000-0000-000000000000") {
		return strings.ToUpper(g)
	}
	return strconv.FormatInt(info.OffsetBytes, 10)
}

// ---------------------------------------------------------------------------
// Grow-vs-shrink decision (pure-Go)
// ---------------------------------------------------------------------------

// DecidePartitionResize compares the observed size to the desired size and
// reports whether a Grow call is needed. A smaller desired size is a
// shrink_not_supported error (shrinking is out of scope in v1); an equal
// size needs no remote call.
func DecidePartitionResize(currentBytes, desiredBytes int64) (grow bool, err error) {
	switch {
	case desiredBytes <= 0:
		return false, NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid desired partition size %d: must be a positive number of bytes", desiredBytes),
			nil, map[string]string{"desired_bytes": strconv.FormatInt(desiredBytes, 10)})
	case desiredBytes < currentBytes:
		return false, NewPartitionError(PartitionErrorShrinkNotSupported,
			fmt.Sprintf("shrinking a partition from %d to %d bytes is not supported in v1: grow only", currentBytes, desiredBytes),
			nil, map[string]string{
				"current_bytes": strconv.FormatInt(currentBytes, 10),
				"desired_bytes": strconv.FormatInt(desiredBytes, 10),
			})
	case desiredBytes == currentBytes:
		return false, nil
	default:
		return true, nil
	}
}

// ---------------------------------------------------------------------------
// Create-option validation (pure-Go)
// ---------------------------------------------------------------------------

// ValidatePartitionCreateOptions checks the Create inputs that can be decided
// without touching the host: disk identity, size-vs-maximum, offset, letter
// and the gpt/mbr types (exclusivity plus alias/GUID/byte form, via the
// Canonicalize helpers). The style-vs-disk check (gpt_type needs a GPT disk)
// runs host-side in the same script so a concurrent change cannot slip
// between check and write.
func ValidatePartitionCreateOptions(opts PartitionCreateOptions) error {
	if strings.TrimSpace(opts.DiskUniqueID) == "" {
		return NewPartitionError(PartitionErrorUnknown,
			"cannot create a partition: disk UniqueId is empty", nil, nil)
	}
	if !opts.UseMaximumSize && opts.SizeBytes <= 0 {
		return NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid partition size %d: set size_bytes to a positive number of bytes or use_maximum_size", opts.SizeBytes),
			nil, map[string]string{"size_bytes": strconv.FormatInt(opts.SizeBytes, 10)})
	}
	if opts.UseMaximumSize && opts.SizeBytes != 0 {
		return NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid partition size %d: size_bytes must not be set when use_maximum_size is true", opts.SizeBytes),
			nil, map[string]string{"size_bytes": strconv.FormatInt(opts.SizeBytes, 10)})
	}
	if opts.HasOffset && opts.OffsetBytes < 0 {
		return NewPartitionError(PartitionErrorUnknown,
			fmt.Sprintf("invalid partition offset %d: must not be negative", opts.OffsetBytes),
			nil, map[string]string{"offset_bytes": strconv.FormatInt(opts.OffsetBytes, 10)})
	}
	if opts.DriveLetter != "" {
		if _, err := NormalizeDriveLetter(opts.DriveLetter); err != nil {
			return err
		}
	}
	if opts.GptType != "" && opts.MbrType != "" {
		return NewPartitionError(PartitionErrorUnknown,
			"gpt_type and mbr_type are mutually exclusive: set at most one",
			nil, map[string]string{"gpt_type": opts.GptType, "mbr_type": opts.MbrType})
	}
	if opts.GptType != "" {
		if _, err := CanonicalizeGPTType(opts.GptType); err != nil {
			return err
		}
	}
	if opts.MbrType != "" {
		if _, err := CanonicalizeMBRType(opts.MbrType); err != nil {
			return err
		}
	}
	return nil
}
