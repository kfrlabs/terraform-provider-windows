package utils

import (
	"context"
	"fmt"
	"regexp"
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

// CleanPowerShellError nettoie les erreurs CLIXML de PowerShell
func CleanPowerShellError(stderr string) string {
	if stderr == "" {
		return ""
	}

	// Si ce n'est pas du CLIXML, retourner tel quel
	if !strings.Contains(stderr, "#< CLIXML") && !strings.Contains(stderr, "<Objs") {
		return stderr
	}

	var cleanLines []string

	// Extraire les lignes d'erreur du XML
	errorPattern := regexp.MustCompile(`<S S="Error">([^<]+)</S>`)
	matches := errorPattern.FindAllStringSubmatch(stderr, -1)

	for _, match := range matches {
		if len(match) > 1 {
			// Nettoyer les entités XML
			line := match[1]
			line = strings.ReplaceAll(line, "_x000D__x000A_", "")
			line = strings.ReplaceAll(line, "_x000D_", "")
			line = strings.ReplaceAll(line, "_x000A_", "")
			line = strings.TrimSpace(line)

			// Ignorer les lignes vides et de position
			if line != "" &&
				!strings.HasPrefix(line, "At line:") &&
				!strings.HasPrefix(line, "+") &&
				!strings.Contains(line, "CategoryInfo") &&
				!strings.Contains(line, "FullyQualifiedErrorId") {
				cleanLines = append(cleanLines, line)
			}
		}
	}

	if len(cleanLines) > 0 {
		return strings.Join(cleanLines, "\n")
	}

	// Fallback: retourner une version simplifiée
	return "PowerShell error (see details above)"
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

	// Nettoyer stderr si présent
	if e.Stderr != "" {
		cleanedError := CleanPowerShellError(e.Stderr)
		if cleanedError != "" {
			errMsg += fmt.Sprintf("\nPowerShell Error: %s", cleanedError)
		}
	}

	// Afficher stdout seulement si utile
	if e.Stdout != "" && !strings.Contains(e.Stdout, "#< CLIXML") {
		errMsg += fmt.Sprintf("\nOutput: %s", e.Stdout)
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
		errMsg += fmt.Sprintf("\nUnderlying error: %s", baseErr)
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
