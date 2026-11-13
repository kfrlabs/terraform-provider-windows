// Package winclient defines the WindowsPowerPlanClient interface and
// associated types for managing the active power plan (singleton) of a
// remote Windows host over SSH.
//
// Spec alignment: windows_power_plan spec (issue #288).
//
// Scope note: the active power plan is a singleton — the host always has
// exactly one active plan. Apply (shared by Create and Update) resolves the
// desired plan to a GUID, writes the configured AC/DC setting values with
// powercfg /setacvalueindex|/setdcvalueindex, activates the plan with
// powercfg /setactive, then verifies by re-reading. Delete never removes
// anything by default and only re-applies the pre-existing values captured
// at Create time when the operator opts in with restore_on_destroy.
package winclient

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// PowerPlanErrorKind
// ---------------------------------------------------------------------------

// PowerPlanErrorKind categorises errors returned by WindowsPowerPlanClient
// operations.
type PowerPlanErrorKind string

const (
	// PowerPlanErrorPlanNotFound is returned when the desired power plan
	// GUID is absent from the host (Get-CimInstance Win32_PowerPlan finds
	// no InstanceID Microsoft:PowerPlan\{guid}) and create_if_missing is
	// false — or when the duplicatescheme template itself is unavailable.
	PowerPlanErrorPlanNotFound PowerPlanErrorKind = "plan_not_found"

	// PowerPlanErrorSettingNotFound is returned when a configured
	// subgroup or setting alias cannot be resolved (powercfg /aliases
	// carries no such entry) or the setting GUID is unknown to the host
	// (no Win32_PowerSetting instance).
	PowerPlanErrorSettingNotFound PowerPlanErrorKind = "setting_not_found"

	// PowerPlanErrorInvalidValue is returned when a configured AC/DC
	// value is rejected by the host: out of the setting's range (from
	// Win32_PowerSettingDefinitionRangeData where available) or a
	// powercfg /setacvalueindex|/setdcvalueindex exit-code failure.
	PowerPlanErrorInvalidValue PowerPlanErrorKind = "invalid_value"

	// PowerPlanErrorUnsupported is returned when power plans are
	// unavailable on the target host: powercfg.exe is missing (typically
	// containers, which share the host power policy) or no active plan
	// can be observed.
	PowerPlanErrorUnsupported PowerPlanErrorKind = "unsupported"

	// PowerPlanErrorAccessDenied is returned when the SSH user lacks the
	// privilege to read or change the power configuration.
	PowerPlanErrorAccessDenied PowerPlanErrorKind = "access_denied"

	// PowerPlanErrorUnknown is returned for unexpected PowerShell errors
	// or SSH transport failures.
	PowerPlanErrorUnknown PowerPlanErrorKind = "unknown"
)

// ---------------------------------------------------------------------------
// PowerPlanError
// ---------------------------------------------------------------------------

// PowerPlanError is the structured error type returned by all
// WindowsPowerPlanClient methods.
type PowerPlanError struct {
	Kind    PowerPlanErrorKind
	Message string
	Context map[string]string
	Cause   error
}

// Error implements the error interface.
func (e *PowerPlanError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_power_plan [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_power_plan [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause for errors.As / errors.Is chain walking.
func (e *PowerPlanError) Unwrap() error { return e.Cause }

// Is implements errors.Is comparison by Kind only.
func (e *PowerPlanError) Is(target error) bool {
	t, ok := target.(*PowerPlanError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// NewPowerPlanError constructs a *PowerPlanError.
func NewPowerPlanError(kind PowerPlanErrorKind, message string, cause error, ctx map[string]string) *PowerPlanError {
	return &PowerPlanError{Kind: kind, Message: message, Cause: cause, Context: ctx}
}

// IsPowerPlanError reports whether err is a *PowerPlanError with the given kind.
func IsPowerPlanError(err error, kind PowerPlanErrorKind) bool {
	var pe *PowerPlanError
	if errors.As(err, &pe) {
		return pe.Kind == kind
	}
	return false
}

// Sentinel errors for use with errors.Is.
var (
	ErrPowerPlanNotFound = &PowerPlanError{Kind: PowerPlanErrorPlanNotFound}
	// ErrPowerPlanSettingNotFound is returned when a subgroup/setting
	// reference cannot be resolved.
	ErrPowerPlanSettingNotFound = &PowerPlanError{Kind: PowerPlanErrorSettingNotFound}
	// ErrPowerPlanSettingFound is deprecated: use ErrPowerPlanSettingNotFound.
	// Kept for compatibility; it aliases the same error.
	ErrPowerPlanSettingFound = ErrPowerPlanSettingNotFound
	ErrPowerPlanInvalidValue = &PowerPlanError{Kind: PowerPlanErrorInvalidValue}
	ErrPowerPlanUnsupported  = &PowerPlanError{Kind: PowerPlanErrorUnsupported}
	ErrPowerPlanAccessDenied = &PowerPlanError{Kind: PowerPlanErrorAccessDenied}
	ErrPowerPlanUnknown      = &PowerPlanError{Kind: PowerPlanErrorUnknown}
)

// ---------------------------------------------------------------------------
// Plan aliases and canonical GUIDs
// ---------------------------------------------------------------------------

// Canonical power plan GUIDs. Plan identity is GUID-only everywhere:
// ElementName is localised and must never be used as an identity key.
const (
	// PowerPlanBalancedGUID is the Balanced plan template.
	PowerPlanBalancedGUID = "381b4222-f694-41f0-9685-ff5bb260df2e"
	// PowerPlanHighPerformanceGUID is the High performance plan template.
	PowerPlanHighPerformanceGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
	// PowerPlanPowerSaverGUID is the Power saver plan template.
	PowerPlanPowerSaverGUID = "a1841308-3541-4fab-bc81-f71556f20b4a"
	// PowerPlanUltimatePerformanceGUID is the Ultimate Performance plan
	// template. It is absent from some hosts (and some SKUs); pair it
	// with create_if_missing (powercfg /duplicatescheme) when needed.
	PowerPlanUltimatePerformanceGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"
)

// powerPlanAliases maps lower-case plan aliases to their canonical
// lower-case GUIDs. Resolution is case-insensitive.
var powerPlanAliases = map[string]string{
	"balanced":             PowerPlanBalancedGUID,
	"high_performance":     PowerPlanHighPerformanceGUID,
	"power_saver":          PowerPlanPowerSaverGUID,
	"ultimate_performance": PowerPlanUltimatePerformanceGUID,
}

// powerPlanGUIDRe accepts the canonical GUID spelling (braces and urn:uuid
// prefixes are rejected: powercfg and WMI carry bare GUIDs).
var powerPlanGUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsPowerPlanGUID reports whether s is a bare power plan GUID (any case).
func IsPowerPlanGUID(s string) bool {
	return powerPlanGUIDRe.MatchString(strings.TrimSpace(s))
}

// ResolvePowerPlanReference resolves a plan reference — a bare GUID (any
// case) or one of the known aliases (balanced, high_performance,
// power_saver, ultimate_performance, case-insensitive) — to its canonical
// lower-case GUID. Anything else is a plan_not_found error; plan names are
// never accepted because ElementName is localised.
func ResolvePowerPlanReference(ref string) (string, error) {
	trimmed := strings.TrimSpace(ref)
	if IsPowerPlanGUID(trimmed) {
		return strings.ToLower(trimmed), nil
	}
	if guid, ok := powerPlanAliases[strings.ToLower(trimmed)]; ok {
		return guid, nil
	}
	return "", NewPowerPlanError(
		PowerPlanErrorPlanNotFound,
		fmt.Sprintf("unknown power plan %q: must be a GUID or one of balanced, high_performance, power_saver, ultimate_performance", ref),
		nil,
		map[string]string{"plan": ref},
	)
}

// ---------------------------------------------------------------------------
// PowerPlanInput — parameters for Apply
// ---------------------------------------------------------------------------

// PowerPlanSettingInput is one managed power setting override: the
// subgroup and setting are GUIDs or powercfg aliases (SUB_SLEEP,
// STANDBYIDLE, DISKIDLE, VIDEOIDLE, PROCTHROTTLEMIN, ...), resolved on the
// host via powercfg /aliases. At least one of ACValue / DCValue must be
// set; values are setting indices and must be >= 0. DC values are always
// stored (Windows keeps them even on hosts without a battery).
type PowerPlanSettingInput struct {
	Subgroup string
	Setting  string
	ACValue  *int64
	DCValue  *int64
}

// PowerPlanSettingKey identifies one managed setting for Read: only the
// subgroup and setting references are needed, values come from the host.
type PowerPlanSettingKey struct {
	Subgroup string
	Setting  string
}

// PowerPlanInput carries the desired active-plan configuration. Consumed
// by Apply (Create and Update share the operation: the active plan is a
// singleton, so there is no separate Create/Update client operation).
type PowerPlanInput struct {
	// Plan is the desired plan: a GUID or a known alias (balanced,
	// high_performance, power_saver, ultimate_performance).
	Plan string

	// CreateIfMissing duplicates the plan template on the host
	// (powercfg /duplicatescheme) when the resolved plan GUID is
	// absent. Without it a missing plan is a plan_not_found error.
	CreateIfMissing bool

	// Settings carries the managed setting overrides. Only listed
	// settings are written; every other setting of the plan is left
	// untouched.
	Settings []PowerPlanSettingInput
}

// ValidatePowerPlanSettingValue rejects negative setting values
// (invalid_value). The primary gate is the provider plan validator; this
// is the defence-in-depth host-side and client-side check.
func ValidatePowerPlanSettingValue(v int64) error {
	if v < 0 {
		return NewPowerPlanError(
			PowerPlanErrorInvalidValue,
			fmt.Sprintf("power setting value %d is out of range: must be >= 0", v),
			nil,
			map[string]string{"value": fmt.Sprintf("%d", v)},
		)
	}
	return nil
}

// ValidatePowerPlanInput rejects an unresolvable plan reference, empty
// subgroup/setting references, settings with neither AC nor DC value, and
// negative values — before anything reaches the host.
func ValidatePowerPlanInput(in PowerPlanInput) error {
	if _, err := ResolvePowerPlanReference(in.Plan); err != nil {
		return err
	}
	for i, s := range in.Settings {
		ctx := map[string]string{
			"setting":  s.Setting,
			"subgroup": s.Subgroup,
			"index":    fmt.Sprintf("%d", i),
		}
		if strings.TrimSpace(s.Subgroup) == "" || strings.TrimSpace(s.Setting) == "" {
			return NewPowerPlanError(
				PowerPlanErrorSettingNotFound,
				fmt.Sprintf("power setting %d has an empty subgroup or setting reference", i),
				nil,
				ctx,
			)
		}
		if s.ACValue == nil && s.DCValue == nil {
			return NewPowerPlanError(
				PowerPlanErrorInvalidValue,
				fmt.Sprintf("power setting %q requires at least one of ac_value or dc_value", s.Setting),
				nil,
				ctx,
			)
		}
		for _, v := range []*int64{s.ACValue, s.DCValue} {
			if v != nil {
				if err := ValidatePowerPlanSettingValue(*v); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// PowerPlanState — observed state returned by Read/Apply/Restore
// ---------------------------------------------------------------------------

// PowerPlanSettingState is the observed value of one managed setting.
// SubgroupGUID and SettingGUID are the resolved canonical lower-case
// GUIDs. ACValue / DCValue are nil when the host carries no value for
// that power source.
type PowerPlanSettingState struct {
	SubgroupGUID string
	SettingGUID  string
	ACValue      *int64
	DCValue      *int64
}

// PowerPlanState is the observed power plan state of the remote Windows
// host.
//
// MachineID is the value of HKLM:\SOFTWARE\Microsoft\Cryptography\
// MachineGuid — stable per machine, anchors the Terraform resource ID.
// PlanGUID is the resolved GUID of the active plan (identity);
// PlanName is the localised ElementName, informational only and never
// used for identity or drift. Settings carries the observed values of
// the managed settings in input order. DuplicatedPlanGUID is populated
// by Apply only: the GUID of a plan duplicated via /duplicatescheme,
// "" otherwise (the provider owns its cleanup on destroy).
type PowerPlanState struct {
	MachineID          string
	PlanGUID           string
	PlanName           string
	Settings           []PowerPlanSettingState
	DuplicatedPlanGUID string
}

// ---------------------------------------------------------------------------
// PowerPlanListState — data source view
// ---------------------------------------------------------------------------

// PowerPlanInfo describes one power plan known to the host.
type PowerPlanInfo struct {
	GUID     string
	Name     string
	IsActive bool
}

// PowerPlanListState is the singleton list view: the active plan plus
// every plan known to the host.
type PowerPlanListState struct {
	MachineID      string
	ActivePlanGUID string
	ActivePlanName string
	Plans          []PowerPlanInfo
}

// ---------------------------------------------------------------------------
// PowerPlanSnapshot — private-state restore payload
// ---------------------------------------------------------------------------

// PowerPlanSnapshot is the pre-existing state captured at Create (or
// import) time so Delete with restore_on_destroy can re-apply it.
// OwnedPlanGUID is filled in after Apply when create_if_missing
// duplicated a plan: the provider deletes that plan on destroy when it
// is inactive.
type PowerPlanSnapshot struct {
	PlanGUID      string
	Settings      []PowerPlanSettingState
	OwnedPlanGUID string
}

// ---------------------------------------------------------------------------
// WindowsPowerPlanClient — Read/Apply/List/Restore/DeletePlan contract
// ---------------------------------------------------------------------------

// WindowsPowerPlanClient defines the contract for managing the active
// power plan of a remote Windows host over SSH.
//
// All methods accept a context.Context for cancellation/timeout
// propagation. All methods return *PowerPlanError (wrapped in error).
//
//	Notable invariants:
//	  - Singleton: the host has exactly one active plan. Create and
//	    Update on the resource layer both funnel into Apply (resolve the
//	    plan, write the configured values, activate, verify by
//	    re-reading).
//	  - GUID-only identity: plan, subgroup and setting references are
//	    always resolved to GUIDs (plan aliases in Go, subgroup/setting
//	    aliases on the host via powercfg /aliases). ElementName and
//	    powercfg /query text are never parsed for state.
//	  - Activation uses powercfg /setactive gated on the exit code;
//	    Win32_PowerPlan.Activate() is unreliable on recent builds and is
//	    never called.
//	  - Restore re-activates the snapshot plan and its values verbatim
//	    (used by Delete with restore_on_destroy). DeletePlan removes a
//	    duplicated plan and is idempotent (missing plans are success).
type WindowsPowerPlanClient interface {
	// Read returns the active plan and the observed values of the
	// listed settings.
	//
	// Returns ErrPowerPlanUnsupported when power plans are
	// unavailable on the host (no powercfg, no active plan).
	// Returns ErrPowerPlanSettingNotFound when a subgroup/setting
	// reference cannot be resolved. Returns
	// ErrPowerPlanAccessDenied when the reads are refused.
	Read(ctx context.Context, settings []PowerPlanSettingKey) (*PowerPlanState, error)

	// Apply resolves the desired plan (duplicating the template when
	// CreateIfMissing and the plan is absent), writes the configured
	// AC/DC values, activates the plan and verifies by re-reading.
	Apply(ctx context.Context, input PowerPlanInput) (*PowerPlanState, error)

	// List returns the active plan plus every plan known to the host.
	List(ctx context.Context) (*PowerPlanListState, error)

	// Restore re-activates the snapshot plan and re-applies its
	// captured setting values verbatim.
	Restore(ctx context.Context, snapshot PowerPlanSnapshot) (*PowerPlanState, error)

	// DeletePlan removes the named plan (powercfg /delete). Missing
	// plans are success. Deleting the active plan is an error — the
	// caller must ensure the plan is inactive first.
	DeletePlan(ctx context.Context, guid string) error
}
