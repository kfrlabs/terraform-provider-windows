package utils

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ResourceError represents an error in a Windows resource operation
type ResourceError struct {
	Operation   string
	ResourceID  string
	Property    string
	Command     string
	Stdout      string
	Stderr      string
	OriginalErr error
}

// Error implements the error interface
func (e *ResourceError) Error() string {
	var details []string

	if e.ResourceID != "" {
		details = append(details, fmt.Sprintf("resource: '%s'", e.ResourceID))
	}
	if e.Property != "" {
		details = append(details, fmt.Sprintf("property: '%s'", e.Property))
	}

	errMsg := fmt.Sprintf("failed to perform operation %s", e.Operation)
	if len(details) > 0 {
		errMsg += fmt.Sprintf(" (%s)", strings.Join(details, ", "))
	}

	if e.Command != "" {
		errMsg += fmt.Sprintf("\nCommand: %s", e.Command)
	}
	if e.Stdout != "" {
		errMsg += fmt.Sprintf("\nStandard output: %s", e.Stdout)
	}
	if e.Stderr != "" {
		errMsg += fmt.Sprintf("\nError output: %s", e.Stderr)
	}

	var baseErr string
	if exitErr, ok := e.OriginalErr.(*ssh.ExitError); ok {
		baseErr = fmt.Sprintf("exit code %d", exitErr.ExitStatus())
	} else if e.OriginalErr == context.DeadlineExceeded {
		baseErr = "timeout exceeded"
	} else if e.OriginalErr != nil {
		baseErr = e.OriginalErr.Error()
	}

	if baseErr != "" {
		errMsg += fmt.Sprintf("\nError: %s", baseErr)
	}

	return errMsg
}

// Unwrap retrieves the original error
func (e *ResourceError) Unwrap() error {
	return e.OriginalErr
}

// HandleResourceError creates a formatted error for Windows resource operations
func HandleResourceError(operation, resourceID, property string, err error) error {
	if err == nil {
		return nil
	}

	return &ResourceError{
		Operation:   operation,
		ResourceID:  resourceID,
		Property:    property,
		OriginalErr: err,
	}
}

// HandleCommandError creates a formatted error for command execution errors
func HandleCommandError(operation, resourceID, property, command, stdout, stderr string, err error) error {
	if err == nil {
		return nil
	}

	return &ResourceError{
		Operation:   operation,
		ResourceID:  resourceID,
		Property:    property,
		Command:     command,
		Stdout:      stdout,
		Stderr:      stderr,
		OriginalErr: err,
	}
}
