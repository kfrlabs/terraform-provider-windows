// Package winclient defines the WindowsDSCResourceClient interface and
// associated types for the generic windows_dsc_resource gateway (issue #293).
//
// The gateway drives any DSC resource through Invoke-DscResource
// (Test/Set/Get) without ever changing the Local Configuration Manager
// settings: every operation first reads Get-DscLocalConfigurationManager and
// fails closed with lcm_conflict when the node is in Pull refresh mode or
// the LCM reports a busy/pending state.
//
// Security invariants:
//   - Only module_name and resource_name are interpolated into PowerShell
//     script bodies, and only through psQuote. Property values never reach
//     the script text: they travel on stdin as a JSON document.
//   - Credential passwords travel on a second stdin line and are rebuilt
//     server-side into PSCredential objects. They are never written to
//     DSCResourceError.Message or Context.
//   - Get output is redacted Go-side: PSCredential values (including nested
//     ones) become null and null-valued keys are dropped from
//     current_state_json, so secrets never reach Terraform state.
//
// File layout:
//
//	DSCResourceErrorKind  — string enum of typed error categories (11 kinds)
//	DSCResourceError      — structured error type with Kind, Message, Context, Cause
//	Sentinel errors       — pre-constructed *DSCResourceError values for errors.Is
//	DSCPropertySchema     — one Get-DscResource property entry
//	DSCResourceSchema     — normalised resource schema plus resolved module version
//	DSCredential          — username/password pair for one PSCredential property
//	DSCEnsureInput        — input parameters for Ensure/Read operations
//	DSCEnsureResult       — observed outcome of an Ensure/Read operation
//	DSCDeleteInput        — input parameters for Delete
//	WindowsDSCResourceClient — Ensure/Read/Delete interface
package winclient

import (
	"context"
)

// ---------------------------------------------------------------------------
// DSCResourceErrorKind — typed error categories
// ---------------------------------------------------------------------------

// DSCResourceErrorKind categorises errors returned by
// WindowsDSCResourceClient operations. Use errors.Is(err, ErrDSCResource*) or
// IsDSCResourceError(err, kind) for programmatic error handling.
type DSCResourceErrorKind string

const (
	// DSCResourceErrorModuleNotFound is returned when the requested DSC
	// module is not installed on the target host, or when module_version
	// pins a version that is not installed.
	DSCResourceErrorModuleNotFound = "module_not_found"

	// DSCResourceErrorResourceNotFound is returned when the requested DSC
	// resource is not exposed by the resolved module on the target host.
	// On Read it drops the Terraform resource from state.
	DSCResourceErrorResourceNotFound = "resource_not_found"

	// DSCResourceErrorInvalidProperty is returned when properties names an
	// unknown property, or when a PSCredential-typed property is passed
	// inline instead of through credential_properties_wo.
	DSCResourceErrorInvalidProperty = "invalid_property"

	// DSCResourceErrorMissingProperty is returned when a mandatory
	// (IsMandatory) schema property — including a mandatory PSCredential —
	// has no value.
	DSCResourceErrorMissingProperty = "missing_property"

	// DSCResourceErrorInvalidValue is returned when a property value cannot
	// be coerced to its schema type, violates a ValueMap, or carries a
	// newline that the stdin line protocol cannot transport.
	DSCResourceErrorInvalidValue = "invalid_value"

	// DSCResourceErrorLCMConflict is returned when the Local Configuration
	// Manager would fight the direct Invoke-DscResource call: RefreshMode
	// Pull, or an LCMState showing a busy/pending operation. The message
	// carries remediation steps. The gateway never changes LCM settings.
	DSCResourceErrorLCMConflict = "lcm_conflict"

	// DSCResourceErrorNotConverged is returned when Set reports success but
	// the follow-up Test still reports InDesiredState=false.
	DSCResourceErrorNotConverged = "not_converged"

	// DSCResourceErrorSetFailed is returned when Invoke-DscResource -Method
	// Set throws an error that no more specific kind explains.
	DSCResourceErrorSetFailed = "set_failed"

	// DSCResourceErrorAccessDenied is returned when the SSH user lacks the
	// privilege to invoke the DSC resource.
	DSCResourceErrorAccessDenied = "access_denied"

	// DSCResourceErrorUnsupported is returned when the resource or the host
	// does not support the requested operation.
	DSCResourceErrorUnsupported = "unsupported"

	// DSCResourceErrorUnknown is returned for unexpected PowerShell errors
	// or SSH transport failures.
	DSCResourceErrorUnknown = "unknown"
)

// ---------------------------------------------------------------------------
// DSCResourceError — structured error type
// ---------------------------------------------------------------------------

// DSCResourceError is the structured error type returned by all
// WindowsDSCResourceClient methods.
//
// Callers should use errors.Is(err, ErrDSCResource*) for kind matching, or
// errors.As(err, &de) to access the full Context map.
//
// SECURITY: credential passwords MUST NEVER appear in Message, Context, or
// anywhere the error might be surfaced in provider logs or Terraform output.
type DSCResourceError = ResourceError

// NewDSCResourceError constructs a *DSCResourceError. Pass a nil cause when
// no underlying error exists. The ctx map may be nil.
func NewDSCResourceError(kind DSCResourceErrorKind, message string, cause error, ctx map[string]string) *DSCResourceError {
	return NewResourceError("windows_dsc_resource", string(kind), message, cause, ctx)
}

// IsDSCResourceError reports whether err is a *DSCResourceError with the
// given kind.
func IsDSCResourceError(err error, kind DSCResourceErrorKind) bool {
	return IsResourceError(err, "windows_dsc_resource", string(kind))
}

// ---------------------------------------------------------------------------
// Sentinel errors — use with errors.Is
// ---------------------------------------------------------------------------

// Pre-constructed sentinel *DSCResourceError values. Because
// DSCResourceError.Is compares by Kind, errors.Is(returnedErr,
// ErrDSCResourceNotFound) returns true for any
// *DSCResourceError{Kind: DSCResourceErrorNotFound}, regardless of Message or
// Context.
var (
	ErrDSCResourceModuleNotFound   = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorModuleNotFound}
	ErrDSCResourceResourceNotFound = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorResourceNotFound}
	ErrDSCResourceInvalidProperty  = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorInvalidProperty}
	ErrDSCResourceMissingProperty  = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorMissingProperty}
	ErrDSCResourceInvalidValue     = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorInvalidValue}
	ErrDSCResourceLCMConflict      = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorLCMConflict}
	ErrDSCResourceNotConverged     = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorNotConverged}
	ErrDSCResourceSetFailed        = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorSetFailed}
	ErrDSCResourceAccessDenied     = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorAccessDenied}
	ErrDSCResourceUnsupported      = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorUnsupported}
	ErrDSCResourceUnknown          = &DSCResourceError{Resource: "windows_dsc_resource", Kind: DSCResourceErrorUnknown}
)

// ---------------------------------------------------------------------------
// Schema types
// ---------------------------------------------------------------------------

// DSCPropertySchema describes one property of a DSC resource as reported by
// Get-DscResource. PropertyType is normalised Go-side (brackets stripped,
// lower-cased): "string", "bool", "uint32", "string[]", "pscredential", or
// an embedded-instance type name such as "msft_keyvaluepair".
type DSCPropertySchema struct {
	// Name is the DSC property name (case-insensitive on the host).
	Name string

	// PropertyType is the normalised type name (see above).
	PropertyType string

	// Values is the ValueMap allow-list. Empty means unconstrained.
	Values []string

	// Mandatory mirrors the IsMandatory flag from Get-DscResource.
	Mandatory bool

	// IsKey mirrors the IsKey flag from Get-DscResource. Key properties
	// identify the resource instance and feed the Terraform ID hash.
	IsKey bool
}

// IsCredential reports whether the property takes a PSCredential value.
// Such values must arrive through credential_properties_wo, never inline in
// properties.
func (p DSCPropertySchema) IsCredential() bool {
	return p.PropertyType == "pscredential"
}

// DSCResourceSchema is the normalised Get-DscResource view of one DSC
// resource in one resolved module version.
type DSCResourceSchema struct {
	// ModuleName is the DSC module name as requested.
	ModuleName string

	// ModuleVersion is the resolved module version: the pinned
	// module_version when set, otherwise the highest installed version.
	ModuleVersion string

	// ResourceName is the DSC resource name as requested.
	ResourceName string

	// Properties carries the resource property entries in host order.
	Properties []DSCPropertySchema
}

// Property looks up a schema property by name (case-insensitive). Returns
// nil when the name is not a known property.
func (s *DSCResourceSchema) Property(name string) *DSCPropertySchema {
	for i := range s.Properties {
		if equalFoldDSC(s.Properties[i].Name, name) {
			return &s.Properties[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Input / result types
// ---------------------------------------------------------------------------

// DSCredential carries one PSCredential property value: the target property
// name is the map key in DSCEnsureInput.Credentials, never a field here.
// The password must not contain carriage return or line feed characters:
// credentials travel on a single stdin line consumed with ReadLine().
type DSCredential struct {
	// Username is the credential user name (for example "DOMAIN\svc" or
	// ".\localuser").
	Username string

	// Password is the credential plaintext. It is sent to Windows on stdin
	// and never logged or included in any error message.
	Password string
}

// DSCEnsureInput carries the desired configuration for one DSC resource
// instance. It is consumed by Ensure and Read.
type DSCEnsureInput struct {
	// ModuleName is the DSC module name (for example
	// "PSDesiredStateConfiguration"). Required.
	ModuleName string

	// ModuleVersion pins an exact module version. Empty means the highest
	// installed version, reported back as ResolvedModuleVersion.
	ModuleVersion string

	// ResourceName is the DSC resource name (for example "Environment").
	// Required.
	ResourceName string

	// Properties holds the desired resource properties (already
	// user-supplied; coerced and validated against the schema before any
	// host call). Credential-typed values must NOT appear here.
	Properties map[string]any

	// Credentials maps a PSCredential property name to its value. The map
	// key is the DSC property name.
	Credentials map[string]DSCredential
}

// DSCEnsureResult holds the observed outcome of an Ensure or Read operation.
type DSCEnsureResult struct {
	// ID is the deterministic Terraform ID
	// "<module>|<resource>|<sha256 hex of the canonical key-properties
	// JSON>". Computed by Ensure from the coerced properties and the schema
	// key selection (Key-marked, else mandatory, else sorted-all).
	ID string

	// InDesiredState is the Invoke-DscResource -Method Test outcome after
	// convergence (Ensure) or as observed (Read).
	InDesiredState bool

	// CurrentState is the redacted Invoke-DscResource -Method Get output:
	// credential values are null-dropped and null-valued keys are omitted.
	CurrentState map[string]any

	// RebootRequired mirrors the RebootRequired flag reported by
	// Invoke-DscResource. Advisory only: the gateway schedules no reboot.
	RebootRequired bool

	// ResolvedModuleVersion is the module version the operation ran
	// against: the pinned module_version, or the highest installed version.
	ResolvedModuleVersion string
}

// DSCDeleteInput carries the destroy configuration for one DSC resource
// instance. It is consumed by Delete.
type DSCDeleteInput struct {
	// ModuleName is the DSC module name. Required.
	ModuleName string

	// ModuleVersion pins an exact module version. Empty means the highest
	// installed version.
	ModuleVersion string

	// ResourceName is the DSC resource name. Required.
	ResourceName string

	// DestroyProperties holds the desired absent-state properties (for
	// example Ensure=Absent). Nil means no destroy configuration: Delete is
	// state-only and makes no remote call.
	DestroyProperties map[string]any

	// HasDestroy reports whether DestroyProperties was configured (even
	// when it holds zero properties). It distinguishes "not configured"
	// from "configured empty".
	HasDestroy bool

	// Credentials maps a PSCredential property name to its value, as in
	// DSCEnsureInput. WriteOnly values are unavailable at destroy time, so
	// this is usually empty and mandatory credentials then fail closed
	// with a missing_property diagnostic.
	Credentials map[string]DSCredential
}

// ---------------------------------------------------------------------------
// WindowsDSCResourceClient — Ensure/Read/Delete interface
// ---------------------------------------------------------------------------

// WindowsDSCResourceClient defines the contract for managing arbitrary DSC
// resources over SSH via Invoke-DscResource.
//
// Error taxonomy: all methods return *DSCResourceError (wrapped in error).
// Use errors.Is(err, ErrDSCResource*) or IsDSCResourceError(err, kind) to
// branch on specific error kinds in the resource CRUD handlers.
//
//	Notable invariants:
//	  - Every operation first checks the LCM (Get-DscLocalConfigurationManager)
//	    and fails with ErrDSCResourceLCMConflict in Pull refresh mode or when
//	    the LCM reports a busy/pending state. LCM settings are never changed.
//	  - The resource schema is fetched per operation with a scoped
//	    Get-DscResource -Name -Module query (never unfiltered), and property
//	    values are coerced and validated pure-Go before any Invoke-DscResource
//	    call.
//	  - Ensure is Test-driven: Test first, Set only on drift, then re-Test.
//	    A Set that does not converge is ErrDSCResourceNotConverged.
type WindowsDSCResourceClient interface {
	// Ensure converges the target to the desired input (Test, then Set on
	// drift, then re-Test) and returns the observed post-convergence state
	// including the redacted Get output.
	Ensure(ctx context.Context, input DSCEnsureInput) (*DSCEnsureResult, error)

	// Read reports the live state without changing it (Test plus Get, never
	// Set). Returns (nil, nil) when the module or resource is gone from the
	// host: the resource handler must call resp.State.RemoveResource().
	Read(ctx context.Context, input DSCEnsureInput) (*DSCEnsureResult, error)

	// Delete converges the target to the destroy configuration via Set
	// (full replacement semantics: destroy_properties is the complete
	// desired state). With no destroy configuration it is state-only and
	// makes no remote call.
	Delete(ctx context.Context, input DSCDeleteInput) error
}
