// Package winclient defines the WindowsFirewallRuleClient interface and
// associated types for managing Windows Defender Firewall rules via SSH.
//
// Spec alignment: windows_firewall_rule spec v1 (2026-05-01).
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// FirewallRuleErrorKind
// ---------------------------------------------------------------------------

// FirewallRuleErrorKind categorises errors returned by
// WindowsFirewallRuleClient operations.
type FirewallRuleErrorKind string

const (
	// FirewallRuleErrorNotFound is returned when the target rule does not exist.
	FirewallRuleErrorNotFound = "not_found"

	// FirewallRuleErrorAlreadyExists is returned when Create detects a
	// pre-existing rule with the same Name.
	FirewallRuleErrorAlreadyExists = "already_exists"

	// FirewallRuleErrorPermission is returned when SSH or NetSecurity
	// refuses the operation due to insufficient privileges.
	FirewallRuleErrorPermission = "permission_denied"

	// FirewallRuleErrorReadOnlyStore is returned when Create, Update or Delete
	// is attempted against a read-only policy store (GroupPolicy or RSOP).
	FirewallRuleErrorReadOnlyStore = "read_only_store"

	// FirewallRuleErrorInvalidInput is returned when PowerShell rejects a
	// parameter value.
	FirewallRuleErrorInvalidInput = "invalid_input"

	// FirewallRuleErrorUnknown is returned for unexpected PowerShell errors
	// or SSH transport failures.
	FirewallRuleErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// FirewallRuleError
// ---------------------------------------------------------------------------

// FirewallRuleError is the structured error type returned by all
// WindowsFirewallRuleClient methods.
type FirewallRuleError = ResourceError

// NewFirewallRuleError constructs a *FirewallRuleError.
func NewFirewallRuleError(kind FirewallRuleErrorKind, message string, cause error, ctx map[string]string) *FirewallRuleError {
	return NewResourceError("windows_firewall_rule", string(kind), message, cause, ctx)
}

// IsFirewallRuleError reports whether err is a *FirewallRuleError with the given kind.
func IsFirewallRuleError(err error, kind FirewallRuleErrorKind) bool {
	return IsResourceError(err, "windows_firewall_rule", string(kind))
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// Pre-constructed sentinel *FirewallRuleError values for errors.Is.
var (
	ErrFirewallRuleNotFound      = &FirewallRuleError{Resource: "windows_firewall_rule", Kind: FirewallRuleErrorNotFound}
	ErrFirewallRuleAlreadyExists = &FirewallRuleError{Resource: "windows_firewall_rule", Kind: FirewallRuleErrorAlreadyExists}
	ErrFirewallRulePermission    = &FirewallRuleError{Resource: "windows_firewall_rule", Kind: FirewallRuleErrorPermission}
	ErrFirewallRuleReadOnlyStore = &FirewallRuleError{Resource: "windows_firewall_rule", Kind: FirewallRuleErrorReadOnlyStore}
	ErrFirewallRuleInvalidInput  = &FirewallRuleError{Resource: "windows_firewall_rule", Kind: FirewallRuleErrorInvalidInput}
	ErrFirewallRuleUnknown       = &FirewallRuleError{Resource: "windows_firewall_rule", Kind: FirewallRuleErrorUnknown}
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
// Firewall rules via SSH (NetSecurity PowerShell module).
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
