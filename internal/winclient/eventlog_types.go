// Package winclient defines the WindowsEventLogClient interface and
// associated types for managing the size and retention policy of an existing
// Windows event log (classic logs such as Application, System, Security, and
// modern channels such as Microsoft-Windows-PowerShell/Operational) over SSH.
//
// The implementation uses the .NET EventLogConfiguration API
// (Get-WinEvent -ListLog plus SaveChanges). Limit-EventLog is deliberately
// not used: it only handles classic logs, and its -RetentionDays /
// OverwriteOlder parameters have had no effect since Vista.
//
// Spec alignment: windows_eventlog spec (issue #289).
//
// Scope note: a log always exists — Windows (or the owning feature) creates
// it. Create and Update are therefore the same operation (set the configured
// properties, then SaveChanges); Delete never removes anything by default
// and only re-applies the pre-existing values captured at Create time when
// the operator opts in with restore_on_destroy.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// EventLogErrorKind
// ---------------------------------------------------------------------------

// EventLogErrorKind categorises errors returned by WindowsEventLogClient
// operations.
type EventLogErrorKind string

const (
	// EventLogErrorNotFound is returned when the named log does not exist
	// on the target host (for example a feature log whose role or
	// application was uninstalled).
	EventLogErrorNotFound EventLogErrorKind = "not_found"

	// EventLogErrorAccessDenied is returned when the SSH user lacks the
	// privilege to read or write the log configuration. Reading or writing
	// the Security log additionally requires administrator rights and the
	// SeSecurityPrivilege privilege.
	EventLogErrorAccessDenied EventLogErrorKind = "access_denied"

	// EventLogErrorUnsupported is returned when the requested change is not
	// supported by the log type — in v1, disabling a classic log
	// (IsEnabled = false on a log with IsClassic = true). Classic logs are
	// always enabled and cannot be turned off.
	EventLogErrorUnsupported EventLogErrorKind = "unsupported"

	// EventLogErrorInvalidSize is returned when maximum_size_bytes is below
	// 1 MiB or is not a multiple of 64 KiB. The primary gate is the plan
	// validator; this kind is the defence-in-depth host-side check.
	EventLogErrorInvalidSize EventLogErrorKind = "invalid_size"

	// EventLogErrorUnknown is returned for unexpected PowerShell errors or
	// SSH transport failures.
	EventLogErrorUnknown EventLogErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// EventLogError
// ---------------------------------------------------------------------------

// EventLogError is the structured error type returned by all
// WindowsEventLogClient methods.
type EventLogError struct {
	Kind    EventLogErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *EventLogError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_eventlog [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_eventlog [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *EventLogError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *EventLogError) Is(target error) bool {
	t, ok := target.(*EventLogError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewEventLogError constructs a *EventLogError.
func NewEventLogError(kind EventLogErrorKind, message string, cause error, ctx map[string]string) *EventLogError {
	return &EventLogError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsEventLogError reports whether err is a *EventLogError with the given kind.
func IsEventLogError(err error, kind EventLogErrorKind) bool {
	var ee *EventLogError
	if errors.As(err, &ee) {
		return ee.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrEventLogNotFound     = &EventLogError{Kind: EventLogErrorNotFound}
	ErrEventLogAccessDenied = &EventLogError{Kind: EventLogErrorAccessDenied}
	ErrEventLogUnsupported  = &EventLogError{Kind: EventLogErrorUnsupported}
	ErrEventLogInvalidSize  = &EventLogError{Kind: EventLogErrorInvalidSize}
	ErrEventLogUnknown      = &EventLogError{Kind: EventLogErrorUnknown}
)

// ---------------------------------------------------------------------------
// EventLog size and retention mapping
// ---------------------------------------------------------------------------

// Event log size bounds enforced at plan time (validators) and re-checked
// host-side (invalid_size). 1 MiB is the documented lower bound pending host
// confirmation; 64 KiB is the allocation granularity Windows requires.
const (
	// EventLogMinSizeBytes is the minimum accepted maximum_size_bytes.
	EventLogMinSizeBytes = int64(1048576)

	// EventLogSizeMultipleBytes is the required granularity of
	// maximum_size_bytes.
	EventLogSizeMultipleBytes = int64(65536)

	// EventLogClassicWarnSizeBytes is the advisory upper bound for classic
	// logs: sizes above 4 GiB are accepted by Windows but warn, because
	// classic logs were not designed for very large files.
	EventLogClassicWarnSizeBytes = int64(4294967296)
)

// ValidateEventLogSize rejects sizes below 1 MiB or not a multiple of 64
// KiB (invalid_size). It is the defence-in-depth check behind the plan
// validator: Apply and Restore fail closed without reaching the host.
func ValidateEventLogSize(size int64) error {
	if size < EventLogMinSizeBytes {
		return NewEventLogError(
			EventLogErrorInvalidSize,
			fmt.Sprintf("maximum_size_bytes %d is below the minimum of %d (1 MiB)", size, EventLogMinSizeBytes),
			nil,
			map[string]string{"maximum_size_bytes": fmt.Sprintf("%d", size)},
		)
	}
	if size%EventLogSizeMultipleBytes != 0 {
		return NewEventLogError(
			EventLogErrorInvalidSize,
			fmt.Sprintf("maximum_size_bytes %d is not a multiple of %d (64 KiB)", size, EventLogSizeMultipleBytes),
			nil,
			map[string]string{"maximum_size_bytes": fmt.Sprintf("%d", size)},
		)
	}
	return nil
}

// EventLogRetentionToLogMode maps the Terraform retention spelling to the
// .NET EventLogMode value written to the host.
func EventLogRetentionToLogMode(retention string) (string, error) {
	switch retention {
	case "overwrite":
		return "Circular", nil
	case "archive":
		return "AutoBackup", nil
	case "retain":
		return "Retain", nil
	default:
		return "", NewEventLogError(
			EventLogErrorUnknown,
			fmt.Sprintf("unknown retention %q: must be one of overwrite, archive, retain", retention),
			nil,
			map[string]string{"retention": retention},
		)
	}
}

// EventLogLogModeToRetention maps the host .NET EventLogMode spelling back
// to the Terraform retention spelling. Unrecognised modes pass through
// verbatim so a future host value is observed rather than dropped.
func EventLogLogModeToRetention(mode string) string {
	switch mode {
	case "Circular":
		return "overwrite"
	case "AutoBackup":
		return "archive"
	case "Retain":
		return "retain"
	default:
		return mode
	}
}

// ---------------------------------------------------------------------------
// EventLogSettings
// ---------------------------------------------------------------------------

// EventLogSettings carries the desired configuration delta for an event
// log. Consumed by Apply (Create and Update share the operation because logs
// always exist).
//
// Partial management: every field beyond the log name is optional. A nil
// pointer means "unmanaged" — the property is never assigned on the
// EventLogConfiguration object and the host value is left untouched. The
// provider layer converts null (or unknown, which defers) Terraform values
// to this delta.
type EventLogSettings struct {
	MaximumSizeBytes *int64
	Retention        *string
	Enabled          *bool
	LogFilePath      *string
}

// EventLogConfigured reports whether at least one attribute is managed
// (used to skip a no-op SaveChanges round trip).
func (s EventLogSettings) EventLogConfigured() bool {
	return s.MaximumSizeBytes != nil ||
		s.Retention != nil ||
		s.Enabled != nil ||
		s.LogFilePath != nil
}

// ---------------------------------------------------------------------------
// EventLogState
// ---------------------------------------------------------------------------

// EventLogState holds the observed state of a Windows event log as returned
// by the Read pipeline.
//
// RecordCount and FileSizeBytes are informational: the provider layer
// exposes them as Computed-only attributes so they never produce drift.
// PolicyOverride reports whether the Group Policy registry view
// (HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\<log>) carries
// MaxSize, Retention or AutoBackupLogFiles for this log. When set, the GPO
// value wins at the next policy refresh and Terraform-managed values may
// diverge.
type EventLogState struct {
	Name             string
	LogType          string
	IsClassic        bool
	IsEnabled        bool
	LogMode          string
	MaximumSizeBytes int64
	LogFilePath      string
	RecordCount      int64
	FileSizeBytes    int64
	PolicyOverride   bool
}

// ---------------------------------------------------------------------------
// WindowsEventLogClient
// ---------------------------------------------------------------------------

// WindowsEventLogClient defines the contract for managing the size and
// retention policy of an existing Windows event log via SSH.
//
// Error conventions:
//   - Read returns (nil, nil) when the log does not exist on the host. The
//     provider layer drops the resource from state; the data source layer
//     surfaces a not_found diagnostic.
//   - Apply fails with not_found when the log does not exist, with
//     unsupported when disabling a classic log, and with invalid_size when
//     the requested size violates the 1 MiB / 64 KiB rules. After
//     SaveChanges it re-reads the log and verifies every configured
//     property took effect; a mismatch is an unknown error.
//   - Restore re-applies a snapshot captured by an earlier Read (used by
//     Delete with restore_on_destroy).
//
// Log names containing "/" (modern channels such as
// Microsoft-Windows-PowerShell/Operational) are valid: the name is never
// treated as a filesystem or registry path, and lookups match the LogName
// literally (never as a wildcard).
type WindowsEventLogClient interface {
	// Read retrieves the current state of the named event log, or
	// (nil, nil) when the log does not exist on the host.
	Read(ctx context.Context, name string) (*EventLogState, error)

	// Apply writes only the configured settings to the named log
	// (EventLogConfiguration.SaveChanges), then re-reads and verifies.
	Apply(ctx context.Context, name string, settings EventLogSettings) (*EventLogState, error)

	// Restore re-applies a previously captured snapshot verbatim.
	Restore(ctx context.Context, snapshot EventLogState) (*EventLogState, error)
}
