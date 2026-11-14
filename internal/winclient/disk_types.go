// Package winclient: types for the windows_disk resource.
//
// DiskInfo is the observed state returned by Read (and by every mutating
// call, which re-reads before responding). DiskErrorKind / DiskError follow
// the same shape as FeatureError so the resource layer can branch with
// errors.As / errors.Is.
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// Partition styles
// ---------------------------------------------------------------------------

// Partition styles reported by Get-Disk and accepted by Initialize-Disk.
const (
	// DiskPartitionStyleRAW is an uninitialized disk: the only style that
	// may be initialized in place.
	DiskPartitionStyleRAW = "RAW"
	// DiskPartitionStyleMBR is a Master Boot Record disk.
	DiskPartitionStyleMBR = "MBR"
	// DiskPartitionStyleGPT is a GUID Partition Table disk.
	DiskPartitionStyleGPT = "GPT"
	// DiskPartitionStyleUnknown is the projection of an empty host-side
	// PartitionStyle (parseDiskInfo maps "" to this). It is not a real
	// style: callers must not treat it as an initialized disk and must let
	// the host-side RAW gate decide instead of raising a local mismatch.
	DiskPartitionStyleUnknown = "Unknown"
)

// ---------------------------------------------------------------------------
// DiskErrorKind — typed error categories
// ---------------------------------------------------------------------------

// DiskErrorKind categorises errors returned by WindowsDiskClient.
type DiskErrorKind string

const (
	// DiskErrorNotFound is returned when no disk matches the selector.
	DiskErrorNotFound = "disk_not_found"

	// DiskErrorAmbiguous is returned when several disks match the selector.
	DiskErrorAmbiguous = "ambiguous_disk"

	// DiskErrorProtected is returned when the matched disk is the boot or
	// system disk, hosts the active pagefile or the crash-dump target, is
	// clustered, or its placement could not be determined (fail closed).
	DiskErrorProtected = "protected_storage"

	// DiskErrorPartitionStyleMismatch is returned when the disk already
	// carries a partition style different from the desired one. Only RAW
	// disks are initialized in place; converting GPT<->MBR destroys data
	// and is out of scope.
	DiskErrorPartitionStyleMismatch = "partition_style_mismatch"

	// DiskErrorOffline is returned when an operation needs the disk online
	// (e.g. Initialize) but the disk is offline.
	DiskErrorOffline = "disk_offline"

	// DiskErrorAccessDenied is returned when the SSH user lacks the
	// privilege for the operation (storage management needs elevation).
	DiskErrorAccessDenied = "access_denied"

	// DiskErrorUnsupported is returned when the Storage module cmdlets are
	// unavailable on the host.
	DiskErrorUnsupported = "unsupported"

	// DiskErrorUnknown is the catch-all for unmapped PowerShell or SSH
	// failures, including timeouts and transport errors.
	DiskErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// DiskError — structured error
// ---------------------------------------------------------------------------

// DiskError is the structured error type returned by all WindowsDiskClient
// methods. Use errors.Is(err, ErrDisk*) for kind matching, or errors.As(err,
// &de) to inspect Context.
type DiskError = ResourceError

// NewDiskError constructs a *DiskError. Pass a nil cause when no underlying
// error exists. The ctx map may be nil.
func NewDiskError(kind DiskErrorKind, message string, cause error, ctx map[string]string) *DiskError {
	return NewResourceError("windows_disk", string(kind), message, cause, ctx)
}

// IsDiskError reports whether err is a *DiskError of the given kind.
func IsDiskError(err error, kind DiskErrorKind) bool {
	return IsResourceError(err, "windows_disk", string(kind))
}

// Sentinel errors usable with errors.Is.
var (
	ErrDiskNotFound          = &DiskError{Resource: "windows_disk", Kind: DiskErrorNotFound}
	ErrDiskAmbiguous         = &DiskError{Resource: "windows_disk", Kind: DiskErrorAmbiguous}
	ErrDiskProtected         = &DiskError{Resource: "windows_disk", Kind: DiskErrorProtected}
	ErrDiskPartitionMismatch = &DiskError{Resource: "windows_disk", Kind: DiskErrorPartitionStyleMismatch}
	ErrDiskOffline           = &DiskError{Resource: "windows_disk", Kind: DiskErrorOffline}
	ErrDiskAccessDenied      = &DiskError{Resource: "windows_disk", Kind: DiskErrorAccessDenied}
	ErrDiskUnsupported       = &DiskError{Resource: "windows_disk", Kind: DiskErrorUnsupported}
	ErrDiskUnknown           = &DiskError{Resource: "windows_disk", Kind: DiskErrorUnknown}
)

// ---------------------------------------------------------------------------
// DiskInfo — observed state
// ---------------------------------------------------------------------------

// DiskInfo holds the observed state of one disk as returned by the
// Read/Initialize/Set pipelines.
type DiskInfo struct {
	// Number is the Get-Disk Number (scan-time assignment, not stable).
	Number int

	// UniqueID is the Get-Disk UniqueId: the stable identity and the
	// Terraform resource ID.
	UniqueID string

	// SerialNumber is the trimmed Get-Disk SerialNumber (may be empty for
	// virtual disks).
	SerialNumber string

	// Location is the Get-Disk Location (adapter path).
	Location string

	// FriendlyName is the Get-Disk FriendlyName (e.g. "Msft Virtual Disk").
	FriendlyName string

	// BusType is the Get-Disk BusType (e.g. "SATA", "NVMe", "RAID", "USB",
	// "Virtual", "Unknown").
	BusType string

	// HealthStatus is the Get-Disk HealthStatus (e.g. "Healthy").
	HealthStatus string

	// OperationalStatus is the Get-Disk OperationalStatus (e.g. "Online",
	// "Offline").
	OperationalStatus string

	// PartitionStyle is "RAW", "MBR" or "GPT" (upper-cased).
	PartitionStyle string

	// IsOffline mirrors Get-Disk IsOffline.
	IsOffline bool

	// IsReadOnly mirrors Get-Disk IsReadOnly.
	IsReadOnly bool

	// IsBoot / IsSystem / IsClustered mirror the Get-Disk protection flags.
	IsBoot      bool
	IsSystem    bool
	IsClustered bool

	// SizeBytes is the Get-Disk Size in bytes.
	SizeBytes int64
}

// ---------------------------------------------------------------------------
// WindowsDiskClient — CRUD contract
// ---------------------------------------------------------------------------

// WindowsDiskClient defines the contract for managing disk online/offline,
// read-only and partition-style state on a remote Windows host over SSH.
//
// The resource is adoption-only: Create resolves the selector (refusing
// protected disks fail-closed), initializes a RAW disk when a partition
// style is desired, and enforces the online/read-only flags. Delete makes no
// remote call: disks are never destroyed, the resource only drops the
// adoption from state.
type WindowsDiskClient interface {
	// Read resolves the selector to exactly one disk and returns its
	// observed state, or (nil, nil) when no disk matches (the resource
	// handler then drops the resource from state). Several matches are an
	// ambiguous_disk error; a protected disk is a protected_storage error.
	Read(ctx context.Context, sel DiskSelector) (*DiskInfo, error)

	// Initialize converts a RAW disk to style ("GPT" or "MBR") and returns
	// the re-read state. A non-RAW disk is a partition_style_mismatch
	// error; an offline disk is a disk_offline error.
	Initialize(ctx context.Context, uniqueID, style string) (*DiskInfo, error)

	// SetOnlineState brings the disk online (offline=false) or takes it
	// offline (offline=true) and returns the re-read state.
	SetOnlineState(ctx context.Context, uniqueID string, offline bool) (*DiskInfo, error)

	// SetReadOnlyState sets the disk read-only flag and returns the
	// re-read state.
	SetReadOnlyState(ctx context.Context, uniqueID string, readOnly bool) (*DiskInfo, error)
}
