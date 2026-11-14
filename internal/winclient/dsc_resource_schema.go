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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Preflight types and pure-Go property schema/coercion. Split from dsc_resource.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// Preflight (LCM + schema)
// ---------------------------------------------------------------------------

// dscPreflightProp mirrors one property entry of the preflight JSON payload.
type dscPreflightProp struct {
	Name         string   `json:"name"`
	PropertyType string   `json:"property_type"`
	Values       []string `json:"values"`
	IsMandatory  bool     `json:"is_mandatory"`
	IsKey        bool     `json:"is_key"`
}

// dscPreflightData mirrors the JSON payload emitted by dscPreflightBody.
type dscPreflightData struct {
	RefreshMode   string             `json:"refresh_mode"`
	LCMState      string             `json:"lcm_state"`
	ModuleName    string             `json:"module_name"`
	ModuleVersion string             `json:"module_version"`
	ResourceName  string             `json:"resource_name"`
	Properties    []dscPreflightProp `json:"properties"`
}

// ---------------------------------------------------------------------------
// Pure-Go coercion, validation, ID hash, stdin composition, redaction
// ---------------------------------------------------------------------------

// equalFoldDSC compares two DSC names case-insensitively. DSC property,
// module and resource names are case-insensitive on the host.
func equalFoldDSC(a, b string) bool {
	return strings.EqualFold(a, b)
}

// normalizeDSCType strips PowerShell type-literal brackets and lower-cases
// the name: "[string]" becomes "string", "[PSCredential]" becomes
// "pscredential", "UInt32" becomes "uint32". Array spellings ("string[]")
// keep their "[]" suffix.
func normalizeDSCType(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimPrefix(t, "[")
	t = strings.TrimSuffix(t, "]")
	return strings.ToLower(strings.TrimSpace(t))
}

// dscIsIntegerType reports whether the normalised schema type is coerced as
// an integer.
func dscIsIntegerType(pt string) bool {
	switch pt {
	case "uint16", "uint32", "uint64", "sint16", "sint32", "sint64",
		"int", "int16", "int32", "int64", "byte", "sbyte":
		return true
	default:
		return false
	}
}

// dscIsArrayType reports whether the normalised schema type is an array
// ("string[]", "uint32[]", ...).
func dscIsArrayType(pt string) bool {
	return strings.HasSuffix(pt, "[]")
}

// dscArrayBase strips the "[]" suffix from an array type name.
func dscArrayBase(pt string) string {
	return strings.TrimSuffix(pt, "[]")
}

// dscIsScalar reports whether v is a JSON scalar (string, bool or number).
func dscIsScalar(v any) bool {
	switch v.(type) {
	case string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return true
	default:
		return false
	}
}

// dscToInt64 converts a JSON number to int64. Floats must be integral;
// unsigned and narrow types are range-checked by the caller via dscIntMax.
func dscToInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		if uint64(n) > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case float32:
		f := float64(n)
		if f != float64(int64(f)) {
			return 0, false
		}
		return int64(f), true
	case float64:
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}

// dscIntMax returns the maximum value for a normalised integer schema type.
func dscIntMax(pt string) int64 {
	switch pt {
	case "byte", "uint8":
		return 255
	case "uint16":
		return 65535
	case "uint32":
		return 4294967295
	case "int8", "sbyte":
		return 127
	case "int16", "sint16":
		return 32767
	case "int32", "sint32":
		return 2147483647
	default:
		return 9223372036854775807
	}
}

// dscIntMin returns the minimum value for a normalised integer schema type.
func dscIntMin(pt string) int64 {
	switch pt {
	case "byte", "uint8", "uint16", "uint32", "uint64":
		return 0
	case "int8", "sbyte":
		return -128
	case "int16", "sint16":
		return -32768
	case "int32", "sint32":
		return -2147483648
	default:
		return -9223372036854775808
	}
}

// CoerceDSCProperties validates props against schema and returns the coerced
// property document sent to the host. Output keys use the schema canonical
// casing; null-valued inputs are dropped (treated as unset).
//
// Rules:
//   - Unknown property names are invalid_property.
//   - PSCredential-typed properties must arrive through creds (the
//     credential_properties_wo map keyed by property name), never inline:
//     an inline value is invalid_property with guidance.
//   - Mandatory schema properties (IsMandatory) with no value — neither in
//     props nor, for credentials, in creds — are missing_property.
//   - Values are coerced by normalised schema type (string, bool, integer
//     with range checks, string[]/integer[]/bool[] arrays, embedded
//     instances as one-level maps). Mismatches are invalid_value.
//   - Non-empty ValueMap lists constrain the value (case-insensitive) and
//     canonicalise string values to the schema entry; violations are
//     invalid_value.
func CoerceDSCProperties(schema *DSCResourceSchema, props map[string]any, creds map[string]DSCredential) (map[string]any, error) {
	ctx := map[string]string{"module": schema.ModuleName, "resource": schema.ResourceName}

	// Index the supplied properties case-insensitively.
	lowered := make(map[string]string, len(props))
	for name := range props {
		lowered[strings.ToLower(name)] = name
	}
	loweredCreds := make(map[string]string, len(creds))
	for name := range creds {
		loweredCreds[strings.ToLower(name)] = name
	}

	// Unknown properties fail before anything else, so a typo can never
	// silently ride along to the host.
	supplied := make([]string, 0, len(props))
	for name := range props {
		supplied = append(supplied, name)
	}
	sort.Strings(supplied)
	for _, name := range supplied {
		sp := schema.Property(name)
		if sp == nil {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("DSC resource %q (module %q) has no property %q.",
					schema.ResourceName, schema.ModuleName, name),
				nil,
				extendDSCContext(ctx, map[string]string{"property": name}),
			)
		}
		if sp.IsCredential() {
			// A credential passed inline is a distinct, guided error:
			// the value belongs in credential_properties_wo.
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("DSC property %q takes a PSCredential: pass it through credential_properties_wo[%q], never inline in properties.",
					sp.Name, sp.Name),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name}),
			)
		}
	}
	for name := range creds {
		if schema.Property(name) == nil {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("credential_properties_wo[%q] names no property of DSC resource %q (module %q).",
					name, schema.ResourceName, schema.ModuleName),
				nil,
				extendDSCContext(ctx, map[string]string{"property": name}),
			)
		}
		if !schema.Property(name).IsCredential() {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidProperty,
				fmt.Sprintf("credential_properties_wo[%q] targets DSC property %q, which is not a PSCredential: pass plain values through properties instead.",
					name, schema.Property(name).Name),
				nil,
				extendDSCContext(ctx, map[string]string{"property": name}),
			)
		}
	}

	out := make(map[string]any, len(props))
	for i := range schema.Properties {
		sp := &schema.Properties[i]
		if sp.IsCredential() {
			_, ok := loweredCreds[strings.ToLower(sp.Name)]
			if sp.Mandatory && !ok {
				return nil, NewDSCResourceError(
					DSCResourceErrorMissingProperty,
					fmt.Sprintf("DSC property %q is mandatory: pass it through credential_properties_wo[%q].",
						sp.Name, sp.Name),
					nil,
					extendDSCContext(ctx, map[string]string{"property": sp.Name}),
				)
			}
			continue
		}
		rawName, ok := lowered[strings.ToLower(sp.Name)]
		if !ok {
			if sp.Mandatory {
				return nil, NewDSCResourceError(
					DSCResourceErrorMissingProperty,
					fmt.Sprintf("DSC property %q is mandatory: set properties[%q].",
						sp.Name, sp.Name),
					nil,
					extendDSCContext(ctx, map[string]string{"property": sp.Name}),
				)
			}
			continue
		}
		v := props[rawName]
		if v == nil {
			if sp.Mandatory {
				return nil, NewDSCResourceError(
					DSCResourceErrorMissingProperty,
					fmt.Sprintf("DSC property %q is mandatory: set properties[%q] to a non-null value.",
						sp.Name, sp.Name),
					nil,
					extendDSCContext(ctx, map[string]string{"property": sp.Name}),
				)
			}
			continue
		}
		coerced, err := coerceDSCValue(sp, v, ctx)
		if err != nil {
			return nil, err
		}
		out[sp.Name] = coerced
	}
	return out, nil
}

// coerceDSCValue coerces one property value to its schema type.
func coerceDSCValue(sp *DSCPropertySchema, v any, ctx map[string]string) (any, error) {
	pt := sp.PropertyType
	if dscIsArrayType(pt) {
		items, ok := v.([]any)
		if !ok {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q takes an array of %s: got %s.",
					sp.Name, dscArrayBase(pt), dscTypeName(v)),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name}),
			)
		}
		base := dscArrayBase(pt)
		elem := &DSCPropertySchema{Name: sp.Name, PropertyType: base, Values: sp.Values}
		coerced := make([]any, 0, len(items))
		for _, item := range items {
			c, err := coerceDSCScalar(elem, item, ctx)
			if err != nil {
				return nil, err
			}
			coerced = append(coerced, c)
		}
		return coerced, nil
	}
	if dscIsIntegerType(pt) || pt == "string" || pt == "bool" || pt == "boolean" {
		return coerceDSCScalar(sp, v, ctx)
	}
	// Embedded instance: a one-level map. Nested maps inside are rejected
	// (nested-1-level support); deeper structures must be flattened by the
	// operator.
	m, ok := v.(map[string]any)
	if !ok {
		return nil, NewDSCResourceError(
			DSCResourceErrorInvalidValue,
			fmt.Sprintf("DSC property %q takes an embedded instance (object with scalar values): got %s.",
				sp.Name, dscTypeName(v)),
			nil,
			extendDSCContext(ctx, map[string]string{"property": sp.Name}),
		)
	}
	nested := make(map[string]any, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		nv := m[k]
		if nv == nil {
			continue
		}
		if sub, ok := nv.(map[string]any); ok && len(sub) > 0 {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q supports one nesting level: nested object %q must hold only scalar or array values.",
					sp.Name, k),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
			)
		}
		if items, ok := nv.([]any); ok {
			for _, item := range items {
				if _, isMap := item.(map[string]any); isMap {
					return nil, NewDSCResourceError(
						DSCResourceErrorInvalidValue,
						fmt.Sprintf("DSC property %q supports one nesting level: nested array %q must hold only scalar values.",
							sp.Name, k),
						nil,
						extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
					)
				}
				if !dscIsScalar(item) {
					return nil, NewDSCResourceError(
						DSCResourceErrorInvalidValue,
						fmt.Sprintf("DSC property %q supports one nesting level: nested array %q must hold only scalar values, got %s.",
							sp.Name, k, dscTypeName(item)),
						nil,
						extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
					)
				}
			}
		} else if !dscIsScalar(nv) {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q supports one nesting level: nested value %q must be a scalar or an array, got %s.",
					sp.Name, k, dscTypeName(nv)),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name + "." + k}),
			)
		}
		nested[k] = nv
	}
	return nested, nil
}

// coerceDSCScalar coerces one scalar value to a string, bool or integer
// schema type and enforces the ValueMap allow-list.
func coerceDSCScalar(sp *DSCPropertySchema, v any, ctx map[string]string) (any, error) {
	pt := sp.PropertyType
	var coerced any
	switch {
	case pt == "string":
		s, ok := v.(string)
		if !ok {
			return nil, dscInvalidValue(sp, "a string", v, ctx)
		}
		coerced = s
	case pt == "bool" || pt == "boolean":
		b, ok := v.(bool)
		if !ok {
			return nil, dscInvalidValue(sp, "a boolean", v, ctx)
		}
		coerced = b
	case dscIsIntegerType(pt):
		n, ok := dscToInt64(v)
		if !ok || n < dscIntMin(pt) || n > dscIntMax(pt) {
			return nil, dscInvalidValue(sp, fmt.Sprintf("an integer in [%d, %d]", dscIntMin(pt), dscIntMax(pt)), v, ctx)
		}
		coerced = n
	default:
		return nil, NewDSCResourceError(
			DSCResourceErrorUnknown,
			fmt.Sprintf("DSC property %q has an unrecognised schema type %q: cannot coerce the value.",
				sp.Name, sp.PropertyType),
			nil,
			extendDSCContext(ctx, map[string]string{"property": sp.Name}),
		)
	}
	if len(sp.Values) > 0 {
		s := fmt.Sprintf("%v", coerced)
		matched := false
		canonical := ""
		for _, allowed := range sp.Values {
			if strings.EqualFold(s, allowed) {
				matched = true
				canonical = allowed
				break
			}
		}
		if !matched {
			return nil, NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("DSC property %q value %q is not in the ValueMap (%s).",
					sp.Name, s, strings.Join(sp.Values, ", ")),
				nil,
				extendDSCContext(ctx, map[string]string{"property": sp.Name}),
			)
		}
		// Canonicalise string values to the schema Values entry so
		// case variants ("Present" vs "present") hash to the same
		// Terraform ID. Non-string scalars keep their typed value.
		if pt == "string" {
			return canonical, nil
		}
	}
	return coerced, nil
}

// dscInvalidValue builds an invalid_value error for a scalar coercion
// failure. The offending value itself is never echoed (it may be long, and
// only its type is diagnostic).
func dscInvalidValue(sp *DSCPropertySchema, want string, v any, ctx map[string]string) *DSCResourceError {
	return NewDSCResourceError(
		DSCResourceErrorInvalidValue,
		fmt.Sprintf("DSC property %q takes %s: got %s.", sp.Name, want, dscTypeName(v)),
		nil,
		extendDSCContext(ctx, map[string]string{"property": sp.Name}),
	)
}

// dscTypeName names the Go-dynamic type of a property value for diagnostics.
func dscTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "bool"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "number"
	case float32, float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "value"
	}
}

// extendDSCContext returns a copy of ctx with extra entries overlaid. The
// caller's map is never mutated.
func extendDSCContext(ctx map[string]string, extra map[string]string) map[string]string {
	out := make(map[string]string, len(ctx)+len(extra))
	for k, v := range ctx {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Terraform ID hash
// ---------------------------------------------------------------------------

// DSCKeyProperties selects the properties feeding the Terraform ID hash:
// the Key-marked properties present in props, else the mandatory properties
// present in props, else every supplied property. Matching is
// case-insensitive; returned keys use the schema canonical casing when
// known. Credential values never feed the ID.
func DSCKeyProperties(schema *DSCResourceSchema, props map[string]any) map[string]any {
	lowered := make(map[string]string, len(props))
	for name := range props {
		lowered[strings.ToLower(name)] = name
	}
	collect := func(names []string) map[string]any {
		out := make(map[string]any, len(names))
		for _, n := range names {
			if raw, ok := lowered[strings.ToLower(n)]; ok {
				if props[raw] != nil {
					out[n] = props[raw]
				}
			}
		}
		return out
	}
	var keys, mandatory []string
	for i := range schema.Properties {
		sp := &schema.Properties[i]
		if sp.IsCredential() {
			continue
		}
		if sp.IsKey {
			keys = append(keys, sp.Name)
		}
		if sp.Mandatory {
			mandatory = append(mandatory, sp.Name)
		}
	}
	if out := collect(keys); len(keys) > 0 && len(out) > 0 {
		return out
	}
	if out := collect(mandatory); len(mandatory) > 0 && len(out) > 0 {
		return out
	}
	// Fall back to every supplied property, sorted for determinism.
	names := make([]string, 0, len(props))
	for name, v := range props {
		if v == nil {
			continue
		}
		if sp := schema.Property(name); sp != nil && sp.IsCredential() {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make(map[string]any, len(names))
	for _, n := range names {
		out[n] = props[n]
	}
	return out
}

// BuildDSCResourceID returns the Terraform ID
// "<module>|<resource>|<sha256 hex of the canonical key-properties JSON>".
// encoding/json marshals maps with sorted keys at every level, so the hash
// is deterministic for equal key sets.
func BuildDSCResourceID(module, resource string, keyProps map[string]any) string {
	canon, err := json.Marshal(keyProps)
	if err != nil {
		canon = []byte("{}")
	}
	sum := sha256.Sum256(canon)
	return module + "|" + resource + "|" + hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Stdin composition
// ---------------------------------------------------------------------------

// ComposeDSCStdin builds the two-line stdin payload for the invoke script:
// the coerced properties JSON document, then the credentials JSON document
// ({property: {username, password}}). Usernames and passwords must not
// contain carriage return or line feed characters: the script consumes each
// line with ReadLine(), so anything from the first line break on would be
// silently truncated. An empty propertiesJSON becomes "{}".
func ComposeDSCStdin(propertiesJSON string, creds map[string]DSCredential) (string, error) {
	if strings.TrimSpace(propertiesJSON) == "" {
		propertiesJSON = "{}"
	}
	credDoc := make(map[string]map[string]string, len(creds))
	names := make([]string, 0, len(creds))
	for name := range creds {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		c := creds[name]
		if strings.ContainsAny(c.Username, "\r\n") {
			return "", NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("credential_properties_wo[%q].username must not contain carriage return or line feed characters: secrets are read with ReadLine().",
					name),
				nil,
				map[string]string{"property": name},
			)
		}
		if strings.ContainsAny(c.Password, "\r\n") {
			return "", NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("credential_properties_wo[%q].password must not contain carriage return or line feed characters: secrets are read with ReadLine().",
					name),
				nil,
				map[string]string{"property": name},
			)
		}
		if c.Username == "" {
			return "", NewDSCResourceError(
				DSCResourceErrorInvalidValue,
				fmt.Sprintf("credential_properties_wo[%q].username must not be empty.", name),
				nil,
				map[string]string{"property": name},
			)
		}
		credDoc[name] = map[string]string{"username": c.Username, "password": c.Password}
	}
	credJSON, err := json.Marshal(credDoc)
	if err != nil {
		return "", NewDSCResourceError(
			DSCResourceErrorUnknown,
			"failed to encode the DSC credentials document",
			err,
			nil,
		)
	}
	return propertiesJSON + "\n" + string(credJSON) + "\n", nil
}

// ---------------------------------------------------------------------------
// Get redaction
// ---------------------------------------------------------------------------

// Redacted credential values become null and null-valued keys are dropped
// from current_state_json, so secrets never reach Terraform state.

// isDSCCredentialLike reports whether a nested Get-output object looks like
// a serialised PSCredential ({UserName, Password} in any casing).
func isDSCCredentialLike(m map[string]any) bool {
	var hasUser, hasPass bool
	for k := range m {
		lk := strings.ToLower(k)
		if lk == "username" {
			hasUser = true
		}
		if lk == "password" {
			hasPass = true
		}
	}
	return hasUser && hasPass
}

// redactDSCValue recursively redacts a Get-output value: credential-like
// maps are dropped (reported as not kept), null map values are omitted at
// every level, null array elements are skipped, and nested maps and arrays
// are walked to any depth.
func redactDSCValue(v any) (any, bool) {
	if v == nil {
		return nil, false
	}
	if m, ok := v.(map[string]any); ok {
		if isDSCCredentialLike(m) {
			return nil, false
		}
		out := make(map[string]any, len(m))
		for k, nv := range m {
			if nv == nil {
				continue
			}
			if rv, ok := redactDSCValue(nv); ok {
				out[k] = rv
			}
		}
		return out, true
	}
	if arr, ok := v.([]any); ok {
		out := make([]any, 0, len(arr))
		for _, e := range arr {
			if e == nil {
				continue
			}
			if rv, ok := redactDSCValue(e); ok {
				out = append(out, rv)
			}
		}
		return out, true
	}
	return v, true
}

// RedactDSCState returns a copy of the Invoke-DscResource -Method Get output
// safe to persist: PSCredential values (including nested ones) are dropped
// and null-valued keys are omitted. Keys keep the schema canonical casing
// when known, otherwise the host casing.
func RedactDSCState(schema *DSCResourceSchema, state map[string]any) map[string]any {
	out := make(map[string]any, len(state))
	for k, v := range state {
		if v == nil {
			continue
		}
		sp := schema.Property(k)
		if sp == nil {
			// Drop anything the schema does not declare: Invoke-DscResource
			// serialises the live CimInstance with envelope metadata
			// (CimClass, CimInstanceProperties, CimSystemProperties with
			// ServerName, ConfigurationName, ...). Keeping it would persist
			// host-specific noise in current_state_json and churn the
			// state on every read.
			continue
		}
		if sp.IsCredential() {
			continue
		}
		name := sp.Name
		if m, ok := v.(map[string]any); ok {
			if rv, keep := redactDSCValue(m); keep {
				if rm, ok := rv.(map[string]any); ok {
					out[name] = rm
				} else {
					out[name] = rv
				}
			}
			continue
		}
		if arr, ok := v.([]any); ok {
			if rv, keep := redactDSCValue(arr); keep {
				out[name] = rv
			}
			continue
		}
		out[name] = v
	}
	return out
}
