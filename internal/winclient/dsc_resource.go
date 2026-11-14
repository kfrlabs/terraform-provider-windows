// Package winclient — DSCResourceClient is the concrete
// WindowsDSCResourceClient backed by PowerShell over SSH (issue #293).
//
// The implementation drives any DSC resource through Invoke-DscResource
// (Test/Set/Get). Every operation starts with a scoped preflight script
// (Get-DscLocalConfigurationManager plus Get-DscResource -Name with a
// resolved module object, never unfiltered) whose output is parsed and
// re-gated Go-side. Property values are coerced and validated pure-Go
// before any Invoke-DscResource call.
//
// Security invariants:
//   - Only module_name and resource_name are interpolated into PowerShell
//     script bodies, and only through psQuote (single-quoted PowerShell
//     literal with embedded single-quotes doubled).
//   - Property values travel on stdin as a JSON document (first line) and
//     credentials on a second stdin line, rebuilt server-side into
//     PSCredential objects. Passwords never reach the script body, error
//     messages or Context maps.
//   - Get output is redacted Go-side (RedactDSCState) before it leaves this
//     package.
//
// Reused helpers from the same package:
//   - psQuote       - safe PS string literal (psquote.go)
//   - runEnvelope   - shared JSON envelope pipeline (envelope.go)
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Compile-time assertion: DSCResourceClient satisfies
// WindowsDSCResourceClient.
var _ WindowsDSCResourceClient = (*DSCResourceClient)(nil)

// DSCResourceClient is the PowerShell/SSH-backed WindowsDSCResourceClient.
type DSCResourceClient struct {
	c *Client
}

// NewDSCResourceClient wraps the given SSH Client.
func NewDSCResourceClient(c *Client) *DSCResourceClient {
	return &DSCResourceClient{c: c}
}

// runDSCPowerShell is the package-level indirection used by
// DSCResourceClient. Tests may override it; production code must not. It
// always runs in a one-shot Windows PowerShell 5.1 process: Invoke-DscResource
// / PSDesiredStateConfiguration 1.1 do not exist in the persistent pwsh 7
// session, whose module path cannot see the inbox 5.1 DSC module. The
// stdin string carries the properties JSON document on the first line and
// the credentials JSON document on the second line; scripts that take no
// payload pass "".
var runDSCPowerShell = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	return c.RunPowerShell5WithInput(ctx, script, stdin)
}

// mapDSCKind converts a script-emitted kind string to DSCResourceErrorKind.
func mapDSCKind(k string) DSCResourceErrorKind {
	switch DSCResourceErrorKind(k) {
	case DSCResourceErrorModuleNotFound,
		DSCResourceErrorResourceNotFound,
		DSCResourceErrorInvalidProperty,
		DSCResourceErrorMissingProperty,
		DSCResourceErrorInvalidValue,
		DSCResourceErrorLCMConflict,
		DSCResourceErrorNotConverged,
		DSCResourceErrorSetFailed,
		DSCResourceErrorAccessDenied,
		DSCResourceErrorUnsupported:
		return DSCResourceErrorKind(k)
	default:
		return DSCResourceErrorUnknown
	}
}

// runDSCEnvelope executes script (prefixed with dscPsHeader) with the given
// stdin through the shared runEnvelope helper. Transport/PS-level errors
// that bypass Emit-Err are translated into *DSCResourceError.
func (d *DSCResourceClient) runDSCEnvelope(ctx context.Context, op, script, stdin, module, resource string, scrubContext bool) (*psResponse, error) {
	baseContext := map[string]string{"module": module, "resource": resource, "host": d.c.cfg.Host}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, in string) (string, string, error) {
			return runDSCPowerShell(ctx, d.c, full, in)
		},
		op, dscPsHeader+"\n"+script, stdin, baseContext)
	if eerr == nil {
		return resp, nil
	}
	// Get output may carry credential-bearing host values: scrub
	// transport/no-envelope/invalid-JSON context for Get callers.
	// Success-path state is redacted separately by RedactDSCState.
	ctxMap := eerr.Context
	if scrubContext {
		ctxMap = nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			fmt.Sprintf("operation %q on DSC resource %q (module %q) timed out or was cancelled", op, resource, module),
			eerr.Cause,
			ctxMap,
		)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			eerr.Message,
			eerr.Cause,
			ctxMap,
		)
	}
	return resp, NewDSCResourceError(mapDSCKind(eerr.RemoteKind), eerr.Message, nil, ctxMap)
}

// gateDSCLCM fails closed with lcm_conflict when refreshMode is Pull or
// lcmState shows a busy/pending operation. PUSH and Disabled refresh modes
// combined with an Idle (or empty) LCM state pass. The comparison is
// case-insensitive; surrounding whitespace is ignored.
func gateDSCLCM(refreshMode, lcmState, module, resource string) error {
	if strings.EqualFold(strings.TrimSpace(refreshMode), "Pull") {
		return NewDSCResourceError(
			DSCResourceErrorLCMConflict,
			fmt.Sprintf("DSC resource %q (module %q) refused: the LCM RefreshMode is Pull. %s",
				resource, module, dscLCMRemediation),
			nil,
			map[string]string{"refresh_mode": refreshMode, "lcm_state": lcmState},
		)
	}
	s := strings.ToLower(strings.TrimSpace(lcmState))
	if s != "" && s != "idle" {
		return NewDSCResourceError(
			DSCResourceErrorLCMConflict,
			fmt.Sprintf("DSC resource %q (module %q) refused: the LCM reports LCMState %q. %s",
				resource, module, lcmState, dscLCMRemediation),
			nil,
			map[string]string{"refresh_mode": refreshMode, "lcm_state": lcmState},
		)
	}
	return nil
}

// dscPreflight runs the LCM gate plus the scoped schema fetch and returns
// the normalised schema. A missing module or resource surfaces the typed
// module_not_found / resource_not_found errors; an LCM conflict surfaces
// lcm_conflict with remediation text.
func (d *DSCResourceClient) dscPreflight(ctx context.Context, module, version, resource string) (*DSCResourceSchema, error) {
	script := strings.NewReplacer(
		"@@MODULENAME@@", psQuote(module),
		"@@MODULEVERSION@@", psQuote(version),
		"@@RESOURCENAME@@", psQuote(resource),
	).Replace(dscPreflightBody)

	resp, err := d.runDSCEnvelope(ctx, "preflight", script, "", module, resource, false)
	if err != nil {
		return nil, err
	}
	var data dscPreflightData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC preflight JSON",
			jerr,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	if gerr := gateDSCLCM(data.RefreshMode, data.LCMState, module, resource); gerr != nil {
		return nil, gerr
	}
	schema := &DSCResourceSchema{
		ModuleName:    data.ModuleName,
		ModuleVersion: data.ModuleVersion,
		ResourceName:  data.ResourceName,
	}
	if schema.ModuleName == "" {
		schema.ModuleName = module
	}
	if schema.ResourceName == "" {
		schema.ResourceName = resource
	}
	for _, p := range data.Properties {
		schema.Properties = append(schema.Properties, DSCPropertySchema{
			Name:         p.Name,
			PropertyType: normalizeDSCType(p.PropertyType),
			Values:       p.Values,
			Mandatory:    p.IsMandatory,
			IsKey:        p.IsKey,
		})
	}
	return schema, nil
}

// ---------------------------------------------------------------------------
// Invoke helpers
// ---------------------------------------------------------------------------

// dscTestData mirrors the Test-method envelope payload.
type dscTestData struct {
	InDesiredState bool `json:"in_desired_state"`
	RebootRequired bool `json:"reboot_required"`
}

// dscSetData mirrors the Set-method envelope payload.
type dscSetData struct {
	RebootRequired bool `json:"reboot_required"`
}

// dscGetData mirrors the Get-method envelope payload.
type dscGetData struct {
	State map[string]any `json:"state"`
}

// dscInvoke runs one Invoke-DscResource method with the given coerced
// properties and credentials documents. scrubContext scrubs envelope
// error context (Get output may be credential-bearing).
func (d *DSCResourceClient) dscInvoke(ctx context.Context, method, module, version, resource, stdin string, scrubContext bool) (*psResponse, error) {
	script := strings.NewReplacer(
		"@@MODULENAME@@", psQuote(module),
		"@@MODULEVERSION@@", psQuote(version),
		"@@RESOURCENAME@@", psQuote(resource),
		"@@METHOD@@", psQuote(method),
	).Replace(dscInvokeBody)
	return d.runDSCEnvelope(ctx, "Invoke-DscResource "+method, script, stdin, module, resource, scrubContext)
}

// dscTest runs Method Test and decodes the outcome.
func (d *DSCResourceClient) dscTest(ctx context.Context, module, version, resource, stdin string) (bool, bool, error) {
	resp, err := d.dscInvoke(ctx, "Test", module, version, resource, stdin, false)
	if err != nil {
		return false, false, err
	}
	var data dscTestData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return false, false, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC Test JSON",
			jerr,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	return data.InDesiredState, data.RebootRequired, nil
}

// dscSet runs Method Set and decodes the reboot flag.
func (d *DSCResourceClient) dscSet(ctx context.Context, module, version, resource, stdin string) (bool, error) {
	resp, err := d.dscInvoke(ctx, "Set", module, version, resource, stdin, false)
	if err != nil {
		return false, err
	}
	var data dscSetData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return false, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC Set JSON",
			jerr,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	return data.RebootRequired, nil
}

// dscGet runs Method Get and decodes the live state. A JSON parse failure
// carries no response payload in its context: Get output may carry
// credential-bearing host values, so the raw document is never embedded in
// error context.
func (d *DSCResourceClient) dscGet(ctx context.Context, module, version, resource, stdin string) (map[string]any, error) {
	resp, err := d.dscInvoke(ctx, "Get", module, version, resource, stdin, true)
	if err != nil {
		return nil, err
	}
	var data dscGetData
	if jerr := json.Unmarshal(resp.Data, &data); jerr != nil {
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to parse DSC Get JSON",
			jerr,
			nil,
		)
	}
	if data.State == nil {
		data.State = map[string]any{}
	}
	return data.State, nil
}

// dscPrepare coerces and validates the desired properties and composes the
// stdin payload shared by Test/Set/Get. It returns the coerced properties
// (schema-canonical keys) and the two-line stdin document.
func dscPrepare(schema *DSCResourceSchema, props map[string]any, creds map[string]DSCredential) (map[string]any, string, error) {
	coerced, err := CoerceDSCProperties(schema, props, creds)
	if err != nil {
		return nil, "", err
	}
	propsJSON, jerr := json.Marshal(coerced)
	if jerr != nil {
		return nil, "", NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to encode the DSC properties document",
			jerr,
			nil,
		)
	}
	stdin, serr := ComposeDSCStdin(string(propsJSON), creds)
	if serr != nil {
		return nil, "", serr
	}
	return coerced, stdin, nil
}

// dscConverge runs the Test-driven converge loop: Test first, Set only on
// drift, then re-Test. A Set that does not converge is not_converged.
// Returns the reboot flag observed along the way.
func (d *DSCResourceClient) dscConverge(ctx context.Context, schema *DSCResourceSchema, coerced map[string]any, stdin string) (bool, error) {
	desired, rbTest, err := d.dscTest(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return false, err
	}
	if desired {
		return rbTest, nil
	}
	rbSet, err := d.dscSet(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return false, err
	}
	again, rbRetest, err := d.dscTest(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return false, err
	}
	if !again {
		keys := make([]string, 0, len(coerced))
		for k := range coerced {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return false, NewDSCResourceError(
			DSCResourceErrorNotConverged,
			fmt.Sprintf("DSC resource %q (module %q) did not converge: Set completed but the follow-up Test still reports InDesiredState=false. Inspect the resource properties outside Terraform (Test-DscConfiguration, event logs) for a resource that cannot satisfy the desired state.",
				schema.ResourceName, schema.ModuleName),
			nil,
			map[string]string{
				"module":   schema.ModuleName,
				"resource": schema.ResourceName,
				// Property names only: values never enter diagnostics.
				"properties": strings.Join(keys, ", "),
			},
		)
	}
	return rbTest || rbSet || rbRetest, nil
}

// ---------------------------------------------------------------------------
// Ensure / Read / Delete
// ---------------------------------------------------------------------------

// Ensure converges the target to the desired input (Test, then Set on drift,
// then re-Test) and returns the observed post-convergence state including
// the redacted Get output.
func (d *DSCResourceClient) Ensure(ctx context.Context, input DSCEnsureInput) (*DSCEnsureResult, error) {
	if strings.TrimSpace(input.ModuleName) == "" || strings.TrimSpace(input.ResourceName) == "" {
		return nil, NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			"module_name and resource_name must not be empty.",
			nil,
			map[string]string{"module": input.ModuleName, "resource": input.ResourceName},
		)
	}
	if input.Properties == nil {
		input.Properties = map[string]any{}
	}
	if input.Credentials == nil {
		input.Credentials = map[string]DSCredential{}
	}
	schema, err := d.dscPreflight(ctx, input.ModuleName, input.ModuleVersion, input.ResourceName)
	if err != nil {
		return nil, err
	}
	coerced, stdin, err := dscPrepare(schema, input.Properties, input.Credentials)
	if err != nil {
		return nil, err
	}
	reboot, err := d.dscConverge(ctx, schema, coerced, stdin)
	if err != nil {
		return nil, err
	}
	raw, err := d.dscGet(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return nil, err
	}
	return &DSCEnsureResult{
		ID:                    BuildDSCResourceID(schema.ModuleName, schema.ResourceName, DSCKeyProperties(schema, coerced)),
		InDesiredState:        true,
		CurrentState:          RedactDSCState(schema, raw),
		RebootRequired:        reboot,
		ResolvedModuleVersion: schema.ModuleVersion,
	}, nil
}

// Read reports the live state without changing it (Test plus Get, never
// Set). Returns (nil, nil) when the module or resource is gone from the
// host, so the resource handler can drop it from state.
func (d *DSCResourceClient) Read(ctx context.Context, input DSCEnsureInput) (*DSCEnsureResult, error) {
	if strings.TrimSpace(input.ModuleName) == "" || strings.TrimSpace(input.ResourceName) == "" {
		return nil, NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			"module_name and resource_name must not be empty.",
			nil,
			map[string]string{"module": input.ModuleName, "resource": input.ResourceName},
		)
	}
	if input.Properties == nil {
		input.Properties = map[string]any{}
	}
	if input.Credentials == nil {
		input.Credentials = map[string]DSCredential{}
	}
	schema, err := d.dscPreflight(ctx, input.ModuleName, input.ModuleVersion, input.ResourceName)
	if err != nil {
		if IsDSCResourceError(err, DSCResourceErrorModuleNotFound) ||
			IsDSCResourceError(err, DSCResourceErrorResourceNotFound) {
			return nil, nil
		}
		return nil, err
	}
	coerced, stdin, err := dscPrepare(schema, input.Properties, input.Credentials)
	if err != nil {
		return nil, err
	}
	desired, reboot, err := d.dscTest(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return nil, err
	}
	raw, err := d.dscGet(ctx, schema.ModuleName, schema.ModuleVersion, schema.ResourceName, stdin)
	if err != nil {
		return nil, err
	}
	return &DSCEnsureResult{
		ID:                    BuildDSCResourceID(schema.ModuleName, schema.ResourceName, DSCKeyProperties(schema, coerced)),
		InDesiredState:        desired,
		CurrentState:          RedactDSCState(schema, raw),
		RebootRequired:        reboot,
		ResolvedModuleVersion: schema.ModuleVersion,
	}, nil
}

// Delete converges the target to the destroy configuration via Set (full
// replacement semantics: destroy_properties is the complete desired state).
// With no destroy configuration it is state-only and makes no remote call.
// A module or resource gone from the host is success.
func (d *DSCResourceClient) Delete(ctx context.Context, input DSCDeleteInput) error {
	if !input.HasDestroy {
		return nil
	}
	if strings.TrimSpace(input.ModuleName) == "" || strings.TrimSpace(input.ResourceName) == "" {
		return NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			"module_name and resource_name must not be empty.",
			nil,
			map[string]string{"module": input.ModuleName, "resource": input.ResourceName},
		)
	}
	props := input.DestroyProperties
	if props == nil {
		props = map[string]any{}
	}
	creds := input.Credentials
	if creds == nil {
		creds = map[string]DSCredential{}
	}
	schema, err := d.dscPreflight(ctx, input.ModuleName, input.ModuleVersion, input.ResourceName)
	if err != nil {
		if IsDSCResourceError(err, DSCResourceErrorModuleNotFound) ||
			IsDSCResourceError(err, DSCResourceErrorResourceNotFound) {
			return nil
		}
		return err
	}
	dscCoerced, stdin, err := dscPrepare(schema, props, creds)
	if err != nil {
		return err
	}
	_, err = d.dscConverge(ctx, schema, dscCoerced, stdin)
	return err
}
