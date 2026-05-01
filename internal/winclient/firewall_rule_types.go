// Package winclient defines the WindowsFirewallRuleClient interface and
// associated types for managing Windows Defender Firewall rules via WinRM.
//
// Spec alignment: windows_firewall_rule spec v1 (2026-05-01).
package winclient

import (
	"context"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// FirewallRuleErrorKind
// ---------------------------------------------------------------------------

// FirewallRuleErrorKind categorises errors returned by
// WindowsFirewallRuleClient operations.
type FirewallRuleErrorKind string

const (
	// FirewallRuleErrorNotFound is returned when the target rule does not exist.
	FirewallRuleErrorNotFound FirewallRuleErrorKind = "not_found"

	// FirewallRuleErrorAlreadyExists is returned when Create detects a
	// pre-existing rule with the same Name.
	FirewallRuleErrorAlreadyExists FirewallRuleErrorKind = "already_exists"

	// FirewallRuleErrorPermission is returned when WinRM or NetSecurity
	// refuses the operation due to insufficient privileges.
	FirewallRuleErrorPermission FirewallRuleErrorKind = "permission_denied"

	// FirewallRuleErrorReadOnlyStore is returned when Create, Update or Delete
	// is attempted against a read-only policy store (GroupPolicy or RSOP).
	FirewallRuleErrorReadOnlyStore FirewallRuleErrorKind = "read_only_store"

	// FirewallRuleErrorInvalidInput is returned when PowerShell rejects a
	// parameter value.
	FirewallRuleErrorInvalidInput FirewallRuleErrorKind = "invalid_input"

	// FirewallRuleErrorUnknown is returned for unexpected PowerShell errors
	// or WinRM transport failures.
	FirewallRuleErrorUnknown FirewallRuleErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// FirewallRuleError
// ---------------------------------------------------------------------------

// FirewallRuleError is the structured error type returned by all
// WindowsFirewallRuleClient methods.
type FirewallRuleError struct {
	Kind    FirewallRuleErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *FirewallRuleError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_firewall_rule [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_firewall_rule [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *FirewallRuleError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *FirewallRuleError) Is(target error) bool {
	t, ok := target.(*FirewallRuleError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewFirewallRuleError constructs a *FirewallRuleError.
func NewFirewallRuleError(kind FirewallRuleErrorKind, message string, cause error, ctx map[string]string) *FirewallRuleError {
	return &FirewallRuleError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsFirewallRuleError reports whether err is a *FirewallRuleError with the given kind.
func IsFirewallRuleError(err error, kind FirewallRuleErrorKind) bool {
	var fe *FirewallRuleError
	if errors.As(err, &fe) {
		return fe.Kind == kind
	}
	return false
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// Pre-constructed sentinel *FirewallRuleError values for errors.Is.
var (
	ErrFirewallRuleNotFound      = &FirewallRuleError{Kind: FirewallRuleErrorNotFound}
	ErrFirewallRuleAlreadyExists = &FirewallRuleError{Kind: FirewallRuleErrorAlreadyExists}
	ErrFirewallRulePermission    = &FirewallRuleError{Kind: FirewallRuleErrorPermission}
	ErrFirewallRuleReadOnlyStore = &FirewallRuleError{Kind: FirewallRuleErrorReadOnlyStore}
	ErrFirewallRuleInvalidInput  = &FirewallRuleError{Kind: FirewallRuleErrorInvalidInput}
	ErrFirewallRuleUnknown       = &FirewallRuleError{Kind: FirewallRuleErrorUnknown}
)

// ---------------------------------------------------------------------------
// FirewallRuleInput
// ---------------------------------------------------------------------------

// FirewallRuleInput carries the desired configuration for a Windows Defender
// Firewall rule. Consumed by Create and Update methods.
type FirewallRuleInput struct {
	Name                string
	DisplayName         string
	Description         string
	Enabled             *bool
	Direction           string
	Action              string
	Profile             []string
	EdgeTraversalPolicy string
	Group               string
	PolicyStore         string
	Protocol            string
	LocalPort           []string
	RemotePort          []string
	LocalAddress        []string
	RemoteAddress       []string
	Program             string
	Service             string
	InterfaceType       string
}

// ---------------------------------------------------------------------------
// FirewallRuleState
// ---------------------------------------------------------------------------

// FirewallRuleState holds the observed state of a Windows Defender Firewall
// rule as returned by the Read pipeline.
type FirewallRuleState struct {
	Name                string
	DisplayName         string
	Description         string
	Enabled             bool
	Direction           string
	Action              string
	Profile             []string
	EdgeTraversalPolicy string
	Group               string
	PolicyStore         string
	Protocol            string
	LocalPort           []string
	RemotePort          []string
	LocalAddress        []string
	RemoteAddress       []string
	Program             string
	Service             string
	InterfaceType       string
}

// ---------------------------------------------------------------------------
// WindowsFirewallRuleClient
// ---------------------------------------------------------------------------

// WindowsFirewallRuleClient defines the contract for managing Windows Defender
// Firewall rules via WinRM (NetSecurity PowerShell module).
type WindowsFirewallRuleClient interface {
	// Create adds a new firewall rule via New-NetFirewallRule, then calls Read
	// to populate all computed filter attributes.
	Create(ctx context.Context, input FirewallRuleInput) (*FirewallRuleState, error)

	// Read retrieves the current state of the named firewall rule.
	// Returns (nil, nil) when the rule does not exist.
	Read(ctx context.Context, name, policyStore string) (*FirewallRuleState, error)

	// Update applies in-place changes to an existing firewall rule.
	Update(ctx context.Context, name, policyStore string, input FirewallRuleInput) (*FirewallRuleState, error)

	// Delete removes the firewall rule. ItemNotFoundException is treated as success.
	Delete(ctx context.Context, name, policyStore string) error
}
