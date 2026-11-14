// Package winclient — ScheduledTaskClient interface and associated types.
//
// Source: windows_scheduled_task spec v1 (2026-04-27).
// Implementation lives in scheduled_task.go.
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// ScheduledTaskErrorKind — typed error categories
// ---------------------------------------------------------------------------

// ScheduledTaskErrorKind categorises errors returned by ScheduledTaskClient.
type ScheduledTaskErrorKind string

const (
	ScheduledTaskErrorAlreadyExists     = "already_exists"
	ScheduledTaskErrorNotFound          = "not_found"
	ScheduledTaskErrorBuiltinTask       = "builtin_task"
	ScheduledTaskErrorInvalidPath       = "invalid_path"
	ScheduledTaskErrorInvalidTrigger    = "invalid_trigger"
	ScheduledTaskErrorInvalidAction     = "invalid_action"
	ScheduledTaskErrorPasswordRequired  = "password_required"
	ScheduledTaskErrorPasswordForbidden = "password_forbidden"
	ScheduledTaskErrorPermissionDenied  = "permission_denied"
	ScheduledTaskErrorRunning           = "task_running"
	ScheduledTaskErrorInvalidInput      = "invalid_input"
	ScheduledTaskErrorUnknown           = "unknown"
)

// ScheduledTaskError is the structured error type returned by ScheduledTaskClient methods.
type ScheduledTaskError = ResourceError

// NewScheduledTaskError constructs a *ScheduledTaskError.
func NewScheduledTaskError(kind ScheduledTaskErrorKind, message string, cause error, ctx map[string]string) *ScheduledTaskError {
	return NewResourceError("windows_scheduled_task", string(kind), message, cause, ctx)
}

// IsScheduledTaskError reports whether err is a *ScheduledTaskError of the given kind.
func IsScheduledTaskError(err error, kind ScheduledTaskErrorKind) bool {
	return IsResourceError(err, "windows_scheduled_task", string(kind))
}

// Sentinel errors for errors.Is matching.
var (
	ErrScheduledTaskAlreadyExists     = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorAlreadyExists}
	ErrScheduledTaskNotFound          = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorNotFound}
	ErrScheduledTaskBuiltinTask       = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorBuiltinTask}
	ErrScheduledTaskInvalidPath       = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorInvalidPath}
	ErrScheduledTaskInvalidTrigger    = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorInvalidTrigger}
	ErrScheduledTaskInvalidAction     = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorInvalidAction}
	ErrScheduledTaskPasswordRequired  = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorPasswordRequired}
	ErrScheduledTaskPasswordForbidden = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorPasswordForbidden}
	ErrScheduledTaskPermissionDenied  = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorPermissionDenied}
	ErrScheduledTaskRunning           = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorRunning}
	ErrScheduledTaskInvalidInput      = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorInvalidInput}
	ErrScheduledTaskUnknown           = &ScheduledTaskError{Resource: "windows_scheduled_task", Kind: ScheduledTaskErrorUnknown}
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

// ScheduledTaskClient manages Windows Scheduled Tasks over SSH.
type ScheduledTaskClient interface {
	Create(ctx context.Context, input ScheduledTaskInput) (*ScheduledTaskState, error)
	Read(ctx context.Context, id string) (*ScheduledTaskState, error)
	Update(ctx context.Context, id string, input ScheduledTaskInput) (*ScheduledTaskState, error)
	Delete(ctx context.Context, id string) error
	ImportByID(ctx context.Context, id string) (*ScheduledTaskState, error)
}
