// Package winclient — ScheduledTaskClient interface and associated types.
//
// Source: windows_scheduled_task spec v1 (2026-04-27).
// Implementation lives in scheduled_task.go.
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// ScheduledTaskErrorKind — typed error categories
// ---------------------------------------------------------------------------

// ScheduledTaskErrorKind categorises errors returned by ScheduledTaskClient.
type ScheduledTaskErrorKind string

const (
	ScheduledTaskErrorAlreadyExists    ScheduledTaskErrorKind = "already_exists"
	ScheduledTaskErrorNotFound         ScheduledTaskErrorKind = "not_found"
	ScheduledTaskErrorBuiltinTask      ScheduledTaskErrorKind = "builtin_task"
	ScheduledTaskErrorInvalidPath      ScheduledTaskErrorKind = "invalid_path"
	ScheduledTaskErrorInvalidTrigger   ScheduledTaskErrorKind = "invalid_trigger"
	ScheduledTaskErrorInvalidAction    ScheduledTaskErrorKind = "invalid_action"
	ScheduledTaskErrorPasswordRequired ScheduledTaskErrorKind = "password_required"
	ScheduledTaskErrorPasswordForbidden ScheduledTaskErrorKind = "password_forbidden"
	ScheduledTaskErrorPermissionDenied ScheduledTaskErrorKind = "permission_denied"
	ScheduledTaskErrorRunning          ScheduledTaskErrorKind = "task_running"
	ScheduledTaskErrorUnknown          ScheduledTaskErrorKind = "unknown"
)

// ScheduledTaskError is the structured error type returned by ScheduledTaskClient methods.
type ScheduledTaskError struct {
	Kind    ScheduledTaskErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *ScheduledTaskError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_scheduled_task [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_scheduled_task [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *ScheduledTaskError) Unwrap() error { return e.Cause }

// Is compares by Kind, enabling errors.Is(err, ErrScheduledTask*) matching.
func (e *ScheduledTaskError) Is(target error) bool {
	t, ok := target.(*ScheduledTaskError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewScheduledTaskError constructs a *ScheduledTaskError.
func NewScheduledTaskError(kind ScheduledTaskErrorKind, message string, cause error, ctx map[string]string) *ScheduledTaskError {
	return &ScheduledTaskError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsScheduledTaskError reports whether err is a *ScheduledTaskError of the given kind.
func IsScheduledTaskError(err error, kind ScheduledTaskErrorKind) bool {
	var ste *ScheduledTaskError
	if errors.As(err, &ste) {
		return ste.Kind == kind
	}
	return false
}

// Sentinel errors for errors.Is matching.
var (
	ErrScheduledTaskAlreadyExists    = &ScheduledTaskError{Kind: ScheduledTaskErrorAlreadyExists}
	ErrScheduledTaskNotFound         = &ScheduledTaskError{Kind: ScheduledTaskErrorNotFound}
	ErrScheduledTaskBuiltinTask      = &ScheduledTaskError{Kind: ScheduledTaskErrorBuiltinTask}
	ErrScheduledTaskInvalidPath      = &ScheduledTaskError{Kind: ScheduledTaskErrorInvalidPath}
	ErrScheduledTaskInvalidTrigger   = &ScheduledTaskError{Kind: ScheduledTaskErrorInvalidTrigger}
	ErrScheduledTaskInvalidAction    = &ScheduledTaskError{Kind: ScheduledTaskErrorInvalidAction}
	ErrScheduledTaskPasswordRequired = &ScheduledTaskError{Kind: ScheduledTaskErrorPasswordRequired}
	ErrScheduledTaskPasswordForbidden = &ScheduledTaskError{Kind: ScheduledTaskErrorPasswordForbidden}
	ErrScheduledTaskPermissionDenied = &ScheduledTaskError{Kind: ScheduledTaskErrorPermissionDenied}
	ErrScheduledTaskRunning          = &ScheduledTaskError{Kind: ScheduledTaskErrorRunning}
	ErrScheduledTaskUnknown          = &ScheduledTaskError{Kind: ScheduledTaskErrorUnknown}
)

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

// ScheduledTaskPrincipalInput carries the principal configuration.
type ScheduledTaskPrincipalInput struct {
	UserID            string
	Password          *string // nil = not provided / unchanged
	PasswordWoVersion int64
	LogonType         string // empty = Windows default
	RunLevel          string // empty = Windows default ("Limited")
}

// ScheduledTaskActionInput carries a single executable action.
type ScheduledTaskActionInput struct {
	Execute          string
	Arguments        string
	WorkingDirectory string
}

// ScheduledTaskTriggerInput carries the configuration for a single trigger.
type ScheduledTaskTriggerInput struct {
	Type               string
	Enabled            *bool
	StartBoundary      string
	EndBoundary        string
	ExecutionTimeLimit string
	Delay              string
	DaysInterval       int64
	DaysOfWeek         []string
	WeeksInterval      int64
	UserID             string
	Subscription       string
}

// ScheduledTaskSettingsInput carries task-level execution settings.
type ScheduledTaskSettingsInput struct {
	AllowDemandStart           bool
	AllowHardTerminate         bool
	StartWhenAvailable         bool
	RunOnlyIfNetworkAvailable  bool
	ExecutionTimeLimit         string
	MultipleInstances          string
	DisallowStartIfOnBatteries bool
	StopIfGoingOnBatteries     bool
	WakeToRun                  bool
	RunOnlyIfIdle              bool
}

// ScheduledTaskInput is the root input struct passed to Create and Update.
type ScheduledTaskInput struct {
	Name        string
	Path        string
	Description string
	Enabled     bool
	Principal   *ScheduledTaskPrincipalInput
	Actions     []ScheduledTaskActionInput
	Triggers    []ScheduledTaskTriggerInput
	Settings    *ScheduledTaskSettingsInput
}

// ---------------------------------------------------------------------------
// State types — returned by Read / Create / Update
// ---------------------------------------------------------------------------

// ScheduledTaskPrincipalState is the observed principal (password never populated).
type ScheduledTaskPrincipalState struct {
	UserID    string
	LogonType string
	RunLevel  string
}

// ScheduledTaskActionState is the observed state of a single action.
type ScheduledTaskActionState struct {
	Execute          string
	Arguments        string
	WorkingDirectory string
}

// ScheduledTaskTriggerState is the observed state of a single trigger.
type ScheduledTaskTriggerState struct {
	Type               string
	Enabled            bool
	StartBoundary      string
	EndBoundary        string
	ExecutionTimeLimit string
	Delay              string
	DaysInterval       int64
	DaysOfWeek         []string
	WeeksInterval      int64
	UserID             string
	Subscription       string
}

// ScheduledTaskSettingsState is the observed state of the task settings.
type ScheduledTaskSettingsState struct {
	AllowDemandStart           bool
	AllowHardTerminate         bool
	StartWhenAvailable         bool
	RunOnlyIfNetworkAvailable  bool
	ExecutionTimeLimit         string
	MultipleInstances          string
	DisallowStartIfOnBatteries bool
	StopIfGoingOnBatteries     bool
	WakeToRun                  bool
	RunOnlyIfIdle              bool
}

// ScheduledTaskState is the root state returned by Read/Create/Update.
type ScheduledTaskState struct {
	Name           string
	Path           string
	Description    string
	Enabled        bool
	State          string
	LastRunTime    string
	LastTaskResult int64
	NextRunTime    string
	Principal      *ScheduledTaskPrincipalState
	Actions        []ScheduledTaskActionState
	Triggers       []ScheduledTaskTriggerState
	Settings       *ScheduledTaskSettingsState
}

// ---------------------------------------------------------------------------
// ScheduledTaskClient interface
// ---------------------------------------------------------------------------

// ScheduledTaskClient manages Windows Scheduled Tasks over WinRM.
type ScheduledTaskClient interface {
	Create(ctx context.Context, input ScheduledTaskInput) (*ScheduledTaskState, error)
	Read(ctx context.Context, id string) (*ScheduledTaskState, error)
	Update(ctx context.Context, id string, input ScheduledTaskInput) (*ScheduledTaskState, error)
	Delete(ctx context.Context, id string) error
	ImportByID(ctx context.Context, id string) (*ScheduledTaskState, error)
}

