// Package winclient — unit tests for the generic DSC gateway (issue #293).
//
// Every test runs against an in-memory fake transport (runDSCPowerShell is
// overridden); no Windows host is required.
package winclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testDSCSchema returns a representative Environment-like schema used across
// the coercion, ID and redaction tests.
func testDSCSchema() *DSCResourceSchema {
	return &DSCResourceSchema{
		ModuleName:    "PSDesiredStateConfiguration",
		ModuleVersion: "1.1",
		ResourceName:  "Environment",
		Properties: []DSCPropertySchema{
			{Name: "Name", PropertyType: "string", Mandatory: true, IsKey: true},
			{Name: "Value", PropertyType: "string"},
			{Name: "Ensure", PropertyType: "string", Values: []string{"Present", "Absent"}},
			{Name: "Path", PropertyType: "bool"},
			{Name: "Target", PropertyType: "string", Values: []string{"Process", "Machine"}},
			{Name: "Port", PropertyType: "uint32"},
			{Name: "Credential", PropertyType: "pscredential", Mandatory: true},
			{Name: "DependsOn", PropertyType: "string[]"},
		},
	}
}

// ---------------------------------------------------------------------------
// Error kinds and sentinels
// ---------------------------------------------------------------------------

func TestDSCErrorKinds_MatchByKind(t *testing.T) {
	cases := []struct {
		kind     DSCResourceErrorKind
		sentinel *DSCResourceError
	}{
		{DSCResourceErrorModuleNotFound, ErrDSCResourceModuleNotFound},
		{DSCResourceErrorResourceNotFound, ErrDSCResourceResourceNotFound},
		{DSCResourceErrorInvalidProperty, ErrDSCResourceInvalidProperty},
		{DSCResourceErrorMissingProperty, ErrDSCResourceMissingProperty},
		{DSCResourceErrorInvalidValue, ErrDSCResourceInvalidValue},
		{DSCResourceErrorLCMConflict, ErrDSCResourceLCMConflict},
		{DSCResourceErrorNotConverged, ErrDSCResourceNotConverged},
		{DSCResourceErrorSetFailed, ErrDSCResourceSetFailed},
		{DSCResourceErrorAccessDenied, ErrDSCResourceAccessDenied},
		{DSCResourceErrorUnsupported, ErrDSCResourceUnsupported},
		{DSCResourceErrorUnknown, ErrDSCResourceUnknown},
	}
	for _, tc := range cases {
		err := NewDSCResourceError(tc.kind, "msg", nil, nil)
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("kind %q does not match its sentinel", tc.kind)
		}
		if !IsDSCResourceError(err, tc.kind) {
			t.Errorf("IsDSCResourceError(%q) = false", tc.kind)
		}
		if IsDSCResourceError(err, DSCResourceErrorKind("other")) {
			t.Errorf("IsDSCResourceError(%q, other) = true", tc.kind)
		}
	}
}

func TestMapDSCKind(t *testing.T) {
	if got := mapDSCKind("lcm_conflict"); got != DSCResourceErrorLCMConflict {
		t.Errorf("mapDSCKind(lcm_conflict) = %q", got)
	}
	if got := mapDSCKind("set_failed"); got != DSCResourceErrorSetFailed {
		t.Errorf("mapDSCKind(set_failed) = %q", got)
	}
	if got := mapDSCKind("bogus"); got != DSCResourceErrorUnknown {
		t.Errorf("mapDSCKind(bogus) = %q, want unknown", got)
	}
}

// ---------------------------------------------------------------------------
// LCM gate fixtures
// ---------------------------------------------------------------------------

func TestGateDSCLCM(t *testing.T) {
	cases := []struct {
		name        string
		refreshMode string
		lcmState    string
		wantErrKind DSCResourceErrorKind
	}{
		{"push idle passes", "PUSH", "Idle", ""},
		{"push lowercase passes", "push", "idle", ""},
		{"disabled idle passes", "Disabled", "Idle", ""},
		{"disabled empty state passes", "Disabled", "", ""},
		{"pull idle conflicts", "Pull", "Idle", DSCResourceErrorLCMConflict},
		{"pull casing conflicts", "pull", "IDLE", DSCResourceErrorLCMConflict},
		{"push busy conflicts", "PUSH", "Busy", DSCResourceErrorLCMConflict},
		{"push pending reboot conflicts", "PUSH", "PendingReboot", DSCResourceErrorLCMConflict},
		{"push pending configuration conflicts", "Push", "PendingConfiguration", DSCResourceErrorLCMConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := gateDSCLCM(tc.refreshMode, tc.lcmState, "M", "R")
			if tc.wantErrKind == "" {
				if err != nil {
					t.Fatalf("gateDSCLCM() = %v, want nil", err)
				}
				return
			}
			if !IsDSCResourceError(err, tc.wantErrKind) {
				t.Fatalf("gateDSCLCM() = %v, want kind %q", err, tc.wantErrKind)
			}
			// The remediation text must state that LCM settings are never
			// changed by the gateway.
			if !strings.Contains(err.Error(), "never changes LCM settings") {
				t.Errorf("lcm_conflict message lacks the never-changes-LCM remediation: %q", err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Coercion table
// ---------------------------------------------------------------------------

func TestCoerceDSCProperties(t *testing.T) {
	creds := map[string]DSCredential{"Credential": {Username: "u", Password: "p"}}
	cases := []struct {
		name    string
		props   map[string]any
		creds   map[string]DSCredential
		wantErr DSCResourceErrorKind
		check   func(t *testing.T, out map[string]any)
	}{
		{
			name:  "valid full document canonicalises keys",
			props: map[string]any{"name": "X", "value": "1", "ensure": "Present", "path": true, "target": "machine", "port": int64(80)},
			creds: creds,
			check: func(t *testing.T, out map[string]any) {
				if out["Name"] != "X" {
					t.Errorf("canonical key casing not applied: %v", out)
				}
				if out["Port"] != int64(80) {
					t.Errorf("Port = %v (%T), want int64(80)", out["Port"], out["Port"])
				}
				// ValueMap match is case-insensitive but canonicalises to the schema entry.
				if out["Target"] != "Machine" {
					t.Errorf("Target = %v, want Machine (schema canonical)", out["Target"])
				}
			},
		},
		{
			name:    "unknown property",
			props:   map[string]any{"Name": "X", "Bogus": "1"},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidProperty,
		},
		{
			name:    "credential passed inline",
			props:   map[string]any{"Name": "X", "Credential": "u"},
			creds:   map[string]DSCredential{},
			wantErr: DSCResourceErrorInvalidProperty,
		},
		{
			name:    "missing mandatory string",
			props:   map[string]any{"Value": "1"},
			creds:   creds,
			wantErr: DSCResourceErrorMissingProperty,
		},
		{
			name:    "missing mandatory credential",
			props:   map[string]any{"Name": "X"},
			creds:   map[string]DSCredential{},
			wantErr: DSCResourceErrorMissingProperty,
		},
		{
			name:    "null mandatory is missing",
			props:   map[string]any{"Name": nil},
			creds:   creds,
			wantErr: DSCResourceErrorMissingProperty,
		},
		{
			name:    "string type mismatch",
			props:   map[string]any{"Name": "X", "Value": int64(1)},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidValue,
		},
		{
			name:    "bool type mismatch",
			props:   map[string]any{"Name": "X", "Path": "true"},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidValue,
		},
		{
			name:    "integer out of range",
			props:   map[string]any{"Name": "X", "Port": int64(1 << 40)},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidValue,
		},
		{
			name:    "fractional float rejected",
			props:   map[string]any{"Name": "X", "Port": 1.5},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidValue,
		},
		{
			name:  "integral float accepted",
			props: map[string]any{"Name": "X", "Port": 80.0},
			creds: creds,
			check: func(t *testing.T, out map[string]any) {
				if out["Port"] != int64(80) {
					t.Errorf("Port = %v", out["Port"])
				}
			},
		},
		{
			name:    "valuemap violation",
			props:   map[string]any{"Name": "X", "Ensure": "Sometimes"},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidValue,
		},
		{
			name:    "array element type mismatch",
			props:   map[string]any{"Name": "X", "DependsOn": []any{"[x]", int64(1)}},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidValue,
		},
		{
			name:    "non-array for array type",
			props:   map[string]any{"Name": "X", "DependsOn": "[x]"},
			creds:   creds,
			wantErr: DSCResourceErrorInvalidValue,
		},
		{
			name:  "null optional dropped",
			props: map[string]any{"Name": "X", "Value": nil},
			creds: creds,
			check: func(t *testing.T, out map[string]any) {
				if _, ok := out["Value"]; ok {
					t.Errorf("null optional must be dropped: %v", out)
				}
			},
		},
		{
			name:    "credential for non-credential property",
			props:   map[string]any{"Name": "X"},
			creds:   map[string]DSCredential{"Value": {Username: "u", Password: "p"}},
			wantErr: DSCResourceErrorInvalidProperty,
		},
		{
			name:    "credential for unknown property",
			props:   map[string]any{"Name": "X"},
			creds:   map[string]DSCredential{"Bogus": {Username: "u", Password: "p"}},
			wantErr: DSCResourceErrorInvalidProperty,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := CoerceDSCProperties(testDSCSchema(), tc.props, tc.creds)
			if tc.wantErr != "" {
				if !IsDSCResourceError(err, tc.wantErr) {
					t.Fatalf("CoerceDSCProperties() = %v, want kind %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CoerceDSCProperties() = %v, want nil", err)
			}
			if tc.check != nil {
				tc.check(t, out)
			}
		})
	}
}

func TestCoerceDSCProperties_EmbeddedOneLevel(t *testing.T) {
	schema := &DSCResourceSchema{
		ModuleName: "M", ResourceName: "R",
		Properties: []DSCPropertySchema{
			{Name: "Filter", PropertyType: "msft_keyvaluepair"},
		},
	}
	// One nesting level passes.
	out, err := CoerceDSCProperties(schema,
		map[string]any{"Filter": map[string]any{"Key": "k", "Value": "v", "N": int64(1)}},
		nil)
	if err != nil {
		t.Fatalf("one-level embedded = %v, want nil", err)
	}
	embedded, ok := out["Filter"].(map[string]any)
	if !ok || embedded["Key"] != "k" {
		t.Errorf("embedded content lost: %v", out)
	}
	// Two nesting levels fail.
	_, err = CoerceDSCProperties(schema,
		map[string]any{"Filter": map[string]any{"Sub": map[string]any{"K": "v"}}},
		nil)
	if !IsDSCResourceError(err, DSCResourceErrorInvalidValue) {
		t.Errorf("two-level embedded = %v, want invalid_value", err)
	}
	// A non-map for an embedded type fails.
	_, err = CoerceDSCProperties(schema, map[string]any{"Filter": "k=v"}, nil)
	if !IsDSCResourceError(err, DSCResourceErrorInvalidValue) {
		t.Errorf("scalar embedded = %v, want invalid_value", err)
	}
}

// ---------------------------------------------------------------------------
// ID hash
// ---------------------------------------------------------------------------

func TestBuildDSCResourceID(t *testing.T) {
	schema := testDSCSchema()
	// Key-marked properties feed the ID: only Name here.
	id1 := BuildDSCResourceID("M", "R", DSCKeyProperties(schema, map[string]any{"Name": "X", "Value": "1"}))
	id2 := BuildDSCResourceID("M", "R", DSCKeyProperties(schema, map[string]any{"Name": "X", "Value": "2"}))
	if id1 != id2 {
		t.Errorf("non-key property change altered the ID: %q vs %q", id1, id2)
	}
	id3 := BuildDSCResourceID("M", "R", DSCKeyProperties(schema, map[string]any{"Name": "Y", "Value": "1"}))
	if id1 == id3 {
		t.Errorf("key property change did not alter the ID: %q", id1)
	}
	if !strings.HasPrefix(id1, "M|R|") {
		t.Errorf("ID %q lacks the module|resource| prefix", id1)
	}
	hexPart := strings.TrimPrefix(id1, "M|R|")
	if len(hexPart) != 64 {
		t.Errorf("ID hash %q is not 64 hex chars", hexPart)
	}
	// The hash is the SHA-256 of the canonical JSON of the key properties.
	canon, _ := json.Marshal(map[string]any{"Name": "X"})
	sum := sha256.Sum256(canon)
	if want := "M|R|" + hex.EncodeToString(sum[:]); id1 != want {
		t.Errorf("ID = %q, want %q", id1, want)
	}
	// Case-insensitive key matching with canonical output keys.
	keys := DSCKeyProperties(schema, map[string]any{"name": "X"})
	if keys["Name"] != "X" {
		t.Errorf("key props = %v, want canonical Name key", keys)
	}
	// No Key marks: mandatory properties feed the ID.
	noKey := &DSCResourceSchema{ModuleName: "M", ResourceName: "R", Properties: []DSCPropertySchema{
		{Name: "A", PropertyType: "string", Mandatory: true},
		{Name: "B", PropertyType: "string"},
	}}
	idA := BuildDSCResourceID("M", "R", DSCKeyProperties(noKey, map[string]any{"A": "1", "B": "x"}))
	idB := BuildDSCResourceID("M", "R", DSCKeyProperties(noKey, map[string]any{"A": "1", "B": "y"}))
	if idA != idB {
		t.Errorf("non-mandatory change altered the mandatory-keyed ID")
	}
	// No Key or mandatory marks: every supplied property feeds the ID.
	plain := &DSCResourceSchema{ModuleName: "M", ResourceName: "R", Properties: []DSCPropertySchema{
		{Name: "B", PropertyType: "string"},
		{Name: "A", PropertyType: "string"},
	}}
	idC := BuildDSCResourceID("M", "R", DSCKeyProperties(plain, map[string]any{"B": "2", "A": "1"}))
	idD := BuildDSCResourceID("M", "R", DSCKeyProperties(plain, map[string]any{"A": "1", "B": "2"}))
	if idC != idD {
		t.Errorf("map order altered the sorted-all ID: %q vs %q", idC, idD)
	}
}

// ---------------------------------------------------------------------------
// Stdin composition
// ---------------------------------------------------------------------------

func TestComposeDSCStdin(t *testing.T) {
	stdin, err := ComposeDSCStdin(`{"Name":"X"}`, map[string]DSCredential{
		"Credential": {Username: "DOMAIN\\u", Password: "s3cret"},
	})
	if err != nil {
		t.Fatalf("ComposeDSCStdin() = %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(stdin, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdin has %d lines, want 2 (properties + credentials)", len(lines))
	}
	if lines[0] != `{"Name":"X"}` {
		t.Errorf("first line = %q, want the properties JSON document", lines[0])
	}
	var credDoc map[string]map[string]string
	if jerr := json.Unmarshal([]byte(lines[1]), &credDoc); jerr != nil {
		t.Fatalf("second line is not JSON: %v", jerr)
	}
	if credDoc["Credential"]["username"] != "DOMAIN\\u" || credDoc["Credential"]["password"] != "s3cret" {
		t.Errorf("credential line = %v", credDoc)
	}
	// Empty documents and nil credentials are legal.
	stdin, err = ComposeDSCStdin("", nil)
	if err != nil {
		t.Fatalf("ComposeDSCStdin(empty) = %v", err)
	}
	if stdin != "{}\n{}\n" {
		t.Errorf("empty ComposeDSCStdin() = %q, want %q", stdin, "{}\n{}\n")
	}
	// Newlines in secrets fail closed: ReadLine would truncate them.
	for _, tc := range []struct {
		name string
		cred DSCredential
	}{
		{"newline password", DSCredential{Username: "u", Password: "a\nb"}},
		{"cr password", DSCredential{Username: "u", Password: "a\rb"}},
		{"newline username", DSCredential{Username: "a\nb", Password: "p"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ComposeDSCStdin("{}", map[string]DSCredential{"Credential": tc.cred})
			if !IsDSCResourceError(err, DSCResourceErrorInvalidValue) {
				t.Errorf("ComposeDSCStdin() = %v, want invalid_value", err)
			}
		})
	}
	if _, err := ComposeDSCStdin("{}", map[string]DSCredential{"Credential": {Username: "", Password: "p"}}); !IsDSCResourceError(err, DSCResourceErrorInvalidValue) {
		t.Errorf("empty username = %v, want invalid_value", err)
	}
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

func TestRedactDSCState(t *testing.T) {
	schema := testDSCSchema()
	raw := map[string]any{
		"Name":  "X",
		"Value": "1",
		"Nulls": nil,
		"Credential": map[string]any{
			"UserName": "u",
			"Password": "System.Security.SecureString",
		},
		"Nested": map[string]any{
			"Key":        "k",
			"NullNested": nil,
			"Cred":       map[string]any{"username": "u", "password": "p"},
		},
	}
	redacted := RedactDSCState(schema, raw)
	if _, ok := redacted["Credential"]; ok {
		t.Errorf("credential value survived redaction: %v", redacted)
	}
	if _, ok := redacted["Nulls"]; ok {
		t.Errorf("null value survived redaction: %v", redacted)
	}
	nested, ok := redacted["Nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested object lost its shape: %v", redacted)
	}
	if _, ok := nested["Cred"]; ok {
		t.Errorf("nested credential survived redaction: %v", nested)
	}
	if _, ok := nested["NullNested"]; ok {
		t.Errorf("nested null survived redaction: %v", nested)
	}
	if redacted["Name"] != "X" || nested["Key"] != "k" {
		t.Errorf("plain values lost: %v", redacted)
	}
	// Serialised output carries no secret.
	out, _ := json.Marshal(redacted)
	if strings.Contains(string(out), "SecureString") || strings.Contains(string(out), `"password"`) {
		t.Errorf("serialised redacted state leaks secrets: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Fake-transport converge tests
// ---------------------------------------------------------------------------

// newDSCTestClient builds a winclient.Client without touching the network
// (the transport hook is always stubbed in these tests).
func newDSCTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:                  "localhost",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

// dscFakePreflight is the canned Emit-OK payload for the preflight script.
const dscFakePreflight = `{"ok":true,"data":{"refresh_mode":"PUSH","lcm_state":"Idle","module_name":"PSDesiredStateConfiguration","module_version":"1.1","resource_name":"Environment","properties":[{"name":"Name","property_type":"[string]","values":[],"is_mandatory":true,"is_key":true},{"name":"Value","property_type":"[string]","values":[],"is_mandatory":false,"is_key":false},{"name":"Ensure","property_type":"[string]","values":["Present","Absent"],"is_mandatory":false,"is_key":false},{"name":"Credential","property_type":"[PSCredential]","values":[],"is_mandatory":false,"is_key":false}]}}`

// dscFakeTransport returns a runDSCPowerShell fake serving canned responses.
// testDesired controls the Test outcome; setCalls counts Set invocations.
func dscFakeTransport(testDesired []bool, setCalls *int) func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	testIdx := 0
	return func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		switch {
		case strings.Contains(script, "$modReqVer"):
			return dscFakePreflight + "\n", "", nil
		case strings.Contains(script, "$method = 'Test'"):
			desired := false
			if testIdx < len(testDesired) {
				desired = testDesired[testIdx]
			}
			testIdx++
			if desired {
				return "{\"ok\":true,\"data\":{\"in_desired_state\":true,\"reboot_required\":false}}\n", "", nil
			}
			return "{\"ok\":true,\"data\":{\"in_desired_state\":false,\"reboot_required\":false}}\n", "", nil
		case strings.Contains(script, "$method = 'Set'"):
			*setCalls++
			return "{\"ok\":true,\"data\":{\"reboot_required\":true}}\n", "", nil
		case strings.Contains(script, "$method = 'Get'"):
			return "{\"ok\":true,\"data\":{\"state\":{\"Name\":\"X\",\"Value\":\"1\",\"Credential\":{\"UserName\":\"u\",\"Password\":\"System.Security.SecureString\"}}}}\n", "", nil
		default:
			return "{\"ok\":false,\"kind\":\"unknown\",\"message\":\"unexpected script\"}\n", "", nil
		}
	}
}

func withDSCFake(t *testing.T, fake func(ctx context.Context, c *Client, script, stdin string) (string, string, error)) {
	t.Helper()
	old := runDSCPowerShell
	runDSCPowerShell = fake
	t.Cleanup(func() { runDSCPowerShell = old })
}

func TestDSCEnsure_ConvergesOnDrift(t *testing.T) {
	var setCalls int
	withDSCFake(t, dscFakeTransport([]bool{false, true}, &setCalls))

	c := NewDSCResourceClient(newDSCTestClient(t))
	res, err := c.Ensure(context.Background(), DSCEnsureInput{
		ModuleName:   "PSDesiredStateConfiguration",
		ResourceName: "Environment",
		Properties:   map[string]any{"Name": "X", "Value": "1"},
	})
	if err != nil {
		t.Fatalf("Ensure() = %v", err)
	}
	if setCalls != 1 {
		t.Errorf("Set called %d times, want 1", setCalls)
	}
	if !res.InDesiredState {
		t.Errorf("InDesiredState = false after converge")
	}
	if !res.RebootRequired {
		t.Errorf("RebootRequired = false, want the Set reboot flag")
	}
	if res.ResolvedModuleVersion != "1.1" {
		t.Errorf("ResolvedModuleVersion = %q, want 1.1", res.ResolvedModuleVersion)
	}
	// The Get credential must be redacted before it leaves the client.
	if _, ok := res.CurrentState["Credential"]; ok {
		t.Errorf("CurrentState leaks the credential: %v", res.CurrentState)
	}
	if res.CurrentState["Name"] != "X" {
		t.Errorf("CurrentState = %v", res.CurrentState)
	}
}

func TestDSCEnsure_SkipsSetWhenDesired(t *testing.T) {
	var setCalls int
	withDSCFake(t, dscFakeTransport([]bool{true}, &setCalls))

	c := NewDSCResourceClient(newDSCTestClient(t))
	res, err := c.Ensure(context.Background(), DSCEnsureInput{
		ModuleName:   "PSDesiredStateConfiguration",
		ResourceName: "Environment",
		Properties:   map[string]any{"Name": "X"},
	})
	if err != nil {
		t.Fatalf("Ensure() = %v", err)
	}
	if setCalls != 0 {
		t.Errorf("Set called %d times on an in-desired host, want 0", setCalls)
	}
	if !res.InDesiredState {
		t.Errorf("InDesiredState = false, want true")
	}
}

func TestDSCEnsure_NotConverged(t *testing.T) {
	var setCalls int
	withDSCFake(t, dscFakeTransport([]bool{false, false}, &setCalls))

	c := NewDSCResourceClient(newDSCTestClient(t))
	_, err := c.Ensure(context.Background(), DSCEnsureInput{
		ModuleName:   "PSDesiredStateConfiguration",
		ResourceName: "Environment",
		Properties:   map[string]any{"Name": "X"},
	})
	if !IsDSCResourceError(err, DSCResourceErrorNotConverged) {
		t.Fatalf("Ensure() = %v, want not_converged", err)
	}
}

func TestDSCEnsure_LCMConflictFromHost(t *testing.T) {
	withDSCFake(t, func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		return "{\"ok\":false,\"kind\":\"lcm_conflict\",\"message\":\"RefreshMode is Pull. windows_dsc_resource never changes LCM settings.\"}\n", "", nil
	})
	c := NewDSCResourceClient(newDSCTestClient(t))
	_, err := c.Ensure(context.Background(), DSCEnsureInput{
		ModuleName: "M", ResourceName: "R", Properties: map[string]any{},
	})
	if !IsDSCResourceError(err, DSCResourceErrorLCMConflict) {
		t.Fatalf("Ensure() = %v, want lcm_conflict", err)
	}
}

func TestDSCEnsure_ModuleNotFound(t *testing.T) {
	withDSCFake(t, func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		return "{\"ok\":false,\"kind\":\"module_not_found\",\"message\":\"DSC module 'Nope' is not installed on the target host.\"}\n", "", nil
	})
	c := NewDSCResourceClient(newDSCTestClient(t))
	_, err := c.Ensure(context.Background(), DSCEnsureInput{
		ModuleName: "Nope", ResourceName: "R", Properties: map[string]any{},
	})
	if !IsDSCResourceError(err, DSCResourceErrorModuleNotFound) {
		t.Fatalf("Ensure() = %v, want module_not_found", err)
	}
}

func TestDSCRead_MissingResourceReturnsNil(t *testing.T) {
	withDSCFake(t, func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		return "{\"ok\":false,\"kind\":\"resource_not_found\",\"message\":\"DSC resource 'R' was not found.\"}\n", "", nil
	})
	c := NewDSCResourceClient(newDSCTestClient(t))
	res, err := c.Read(context.Background(), DSCEnsureInput{
		ModuleName: "M", ResourceName: "R", Properties: map[string]any{},
	})
	if err != nil {
		t.Fatalf("Read() = %v, want nil", err)
	}
	if res != nil {
		t.Errorf("Read() = %v, want (nil, nil) for a missing resource", res)
	}
}

func TestDSCDelete_StateOnlyMakesNoCall(t *testing.T) {
	calls := 0
	withDSCFake(t, func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		calls++
		return "{}\n", "", nil
	})
	c := NewDSCResourceClient(newDSCTestClient(t))
	if err := c.Delete(context.Background(), DSCDeleteInput{
		ModuleName: "M", ResourceName: "R", HasDestroy: false,
	}); err != nil {
		t.Fatalf("Delete() = %v, want nil", err)
	}
	if calls != 0 {
		t.Errorf("state-only Delete made %d host calls, want 0", calls)
	}
}

func TestDSCStdin_ReachesHostIntact(t *testing.T) {
	var setCalls int
	var gotStdin string
	inner := dscFakeTransport([]bool{false, true}, &setCalls)
	old := runDSCPowerShell
	runDSCPowerShell = func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		if strings.Contains(script, "$method = 'Set'") {
			gotStdin = stdin
			return inner(context.Background(), nil, script, stdin)
		}
		return inner(context.Background(), nil, script, stdin)
	}
	t.Cleanup(func() { runDSCPowerShell = old })

	c := NewDSCResourceClient(newDSCTestClient(t))
	_, err := c.Ensure(context.Background(), DSCEnsureInput{
		ModuleName:   "PSDesiredStateConfiguration",
		ResourceName: "Environment",
		Properties:   map[string]any{"Name": "X"},
		Credentials:  map[string]DSCredential{"Credential": {Username: "u", Password: "p"}},
	})
	if err != nil {
		t.Fatalf("Ensure() = %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(gotStdin, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("Set stdin has %d lines, want 2", len(lines))
	}
	var props map[string]any
	if jerr := json.Unmarshal([]byte(lines[0]), &props); jerr != nil {
		t.Fatalf("first stdin line is not JSON: %v", jerr)
	}
	if props["Name"] != "X" {
		t.Errorf("properties line = %v", props)
	}
	// psQuote must only wrap module/resource names: property values travel
	// on stdin, never in the script body. The script must not contain the
	// property value as a quoted literal.
	if strings.Contains(gotStdin, "'") {
		t.Errorf("stdin should carry raw JSON, got quoting: %q", gotStdin)
	}
}
