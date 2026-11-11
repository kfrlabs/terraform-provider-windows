// Package winclient — unit tests for RegistryKeyClientImpl.
//
// Tests stub the package-level runRegistryKeyPowerShell hook so no real
// SSH connection is required. Edge cases covered:
//
//	List/Ensure: empty key, multi-value, Default ("") value, kinds summary,
//	  found=false, malformed JSON, length mismatch, permission_denied,
//	  transport error
//	DeleteValues: idempotent on key_not_found, empty list is a no-op,
//	  script carries DeleteValue with quoted hive/path/names, Default ("")
//	  passes through as an empty quoted name
//	DeleteKey: idempotent on key_not_found, invalid_input when subkeys
//	  remain, script carries Remove-Item -Recurse with quoted Registry::
//	  path, registryKeyPSPath hive mapping
//	mapRegistryKeyErrorKind: all branches including unknown fallback
//	RegistryKeyError: Error(), Unwrap(), Is(), sentinels, IsRegistryKeyError()
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newRKTestClient creates a *RegistryKeyClientImpl for tests.
func newRKTestClient(t *testing.T) *RegistryKeyClientImpl {
	t.Helper()
	c, err := New(Config{
		Host:                  "winrk01",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewRegistryKeyClient(c)
}

// stubRKRun replaces runRegistryKeyPowerShell for the duration of a test.
// Returns a restore closure that must be deferred.
func stubRKRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runRegistryKeyPowerShell
	runRegistryKeyPowerShell = fn
	return func() { runRegistryKeyPowerShell = prev }
}

// rkOKEnvelope marshals an ok=true envelope to a newline-terminated JSON string.
func rkOKEnvelope(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("rkOKEnvelope marshal: %v", err)
	}
	return string(b) + "\n"
}

// rkErrEnvelope marshals an ok=false envelope to a newline-terminated JSON string.
func rkErrEnvelope(t *testing.T, kind, msg string, ctx map[string]string) string {
	t.Helper()
	if ctx == nil {
		ctx = map[string]string{}
	}
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": ctx,
	})
	if err != nil {
		t.Fatalf("rkErrEnvelope marshal: %v", err)
	}
	return string(b) + "\n"
}

// rkKeyData builds a List/Ensure data payload from parallel names/kinds slices.
func rkKeyData(names []string, kinds []string) map[string]any {
	return map[string]any{
		"found":       true,
		"value_names": names,
		"value_kinds": kinds,
	}
}

// ---------------------------------------------------------------------------
// List — payload parsing
// ---------------------------------------------------------------------------

func TestRegistryKeyList_Empty(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkOKEnvelope(t, rkKeyData([]string{}, []string{})), "", nil
	})()

	st, err := r.List(context.Background(), "HKLM", `SOFTWARE\MyApp`)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !st.Found {
		t.Error("Found must be true for an existing empty key")
	}
	if len(st.ValueNames) != 0 {
		t.Errorf("ValueNames = %v, want empty", st.ValueNames)
	}
}

func TestRegistryKeyList_Multi(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkOKEnvelope(t, rkKeyData(
			[]string{"Version", "InstallDir", "Flags"},
			[]string{"REG_SZ", "REG_EXPAND_SZ", "REG_DWORD"},
		)), "", nil
	})()

	st, err := r.List(context.Background(), "HKLM", `SOFTWARE\MyApp`)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(st.ValueNames) != 3 || len(st.Values) != 3 {
		t.Fatalf("ValueNames = %v, Values = %v", st.ValueNames, st.Values)
	}
	if st.Values[0] != (RegistryKeyValueSummary{Name: "Version", Kind: RegistryValueKindString}) {
		t.Errorf("Values[0] = %+v", st.Values[0])
	}
	if st.Values[2].Kind != RegistryValueKindDWord {
		t.Errorf("Values[2].Kind = %q", st.Values[2].Kind)
	}
}

func TestRegistryKeyList_DefaultValue(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkOKEnvelope(t, rkKeyData([]string{""}, []string{"REG_SZ"})), "", nil
	})()

	st, err := r.List(context.Background(), "HKLM", `SOFTWARE\MyApp`)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(st.ValueNames) != 1 || st.ValueNames[0] != "" {
		t.Errorf("ValueNames = %q, want [\"\"] (Default value)", st.ValueNames)
	}
	if len(st.Values) != 1 || st.Values[0].Name != "" {
		t.Errorf("Values = %+v, want single Default entry", st.Values)
	}
}

func TestRegistryKeyList_NotFound(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkOKEnvelope(t, map[string]any{"found": false}), "", nil
	})()

	st, err := r.List(context.Background(), "HKLM", `SOFTWARE\Ghost`)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if st == nil || st.Found {
		t.Errorf("expected Found=false state, got %+v", st)
	}
}

func TestRegistryKeyList_Malformed(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "{not-json}\n", "", nil
	})()

	if _, err := r.List(context.Background(), "HKLM", `SOFTWARE\MyApp`); err == nil {
		t.Error("expected error for malformed JSON envelope")
	}
}

func TestRegistryKeyList_LengthMismatch(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkOKEnvelope(t, rkKeyData([]string{"A", "B"}, []string{"REG_SZ"})), "", nil
	})()

	if _, err := r.List(context.Background(), "HKLM", `SOFTWARE\MyApp`); err == nil {
		t.Error("expected error for value_names/value_kinds length mismatch")
	}
}

func TestRegistryKeyList_PermissionDenied(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkErrEnvelope(t, "permission_denied", "access denied", nil), "", nil
	})()

	_, err := r.List(context.Background(), "HKLM", `SOFTWARE\MyApp`)
	if !IsRegistryKeyError(err, RegistryKeyErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

func TestRegistryKeyList_TransportError(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return "", "boom", errors.New("ssh dial failed")
	})()

	_, err := r.List(context.Background(), "HKLM", `SOFTWARE\MyApp`)
	if !IsRegistryKeyError(err, RegistryKeyErrorUnknown) {
		t.Errorf("expected unknown transport error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Ensure — script contents
// ---------------------------------------------------------------------------

func TestRegistryKeyEnsure_Script(t *testing.T) {
	r := newRKTestClient(t)
	var got string
	defer stubRKRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return rkOKEnvelope(t, rkKeyData([]string{}, []string{})), "", nil
	})()

	if _, err := r.EnsureKey(context.Background(), "HKLM", `SOFTWARE\MyApp`); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	for _, want := range []string{"CreateSubKey", "GetValueNames", "'HKLM'", `'SOFTWARE\MyApp'`} {
		if !strings.Contains(got, want) {
			t.Errorf("Ensure script missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// DeleteValues
// ---------------------------------------------------------------------------

func TestRegistryKeyDeleteValues_Script(t *testing.T) {
	r := newRKTestClient(t)
	var got string
	defer stubRKRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return rkOKEnvelope(t, map[string]any{"deleted": true}), "", nil
	})()

	if err := r.DeleteValues(context.Background(), "HKLM", `SOFTWARE\MyApp`, []string{"Version", ""}); err != nil {
		t.Fatalf("DeleteValues: %v", err)
	}
	// DeleteValue handles the Default ("") value; Remove-ItemProperty cannot
	// address it, so the loop must stay on the .NET API.
	for _, want := range []string{"DeleteValue", "Get-RegHive", "'HKLM'", `'SOFTWARE\MyApp'`, `'Version'`, `''`} {
		if !strings.Contains(got, want) {
			t.Errorf("DeleteValues script missing %q", want)
		}
	}
	if strings.Contains(got, "Remove-ItemProperty") {
		t.Error("DeleteValues script must not use Remove-ItemProperty (cannot delete the Default value)")
	}
}

func TestRegistryKeyDeleteValues_EmptyIsNoOp(t *testing.T) {
	r := newRKTestClient(t)
	called := false
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		called = true
		return rkOKEnvelope(t, map[string]any{"deleted": true}), "", nil
	})()

	if err := r.DeleteValues(context.Background(), "HKLM", `SOFTWARE\MyApp`, nil); err != nil {
		t.Fatalf("DeleteValues(nil): %v", err)
	}
	if called {
		t.Error("DeleteValues with no names must not run any script")
	}
}

func TestRegistryKeyDeleteValues_KeyNotFoundIsNoOp(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkOKEnvelope(t, map[string]any{"deleted": false, "reason": "key_not_found"}), "", nil
	})()

	if err := r.DeleteValues(context.Background(), "HKLM", `SOFTWARE\Ghost`, []string{"A"}); err != nil {
		t.Fatalf("DeleteValues on missing key must be a no-op, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteKey
// ---------------------------------------------------------------------------

func TestRegistryKeyDeleteKey_ScriptRecursive(t *testing.T) {
	r := newRKTestClient(t)
	var got string
	defer stubRKRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return rkOKEnvelope(t, map[string]any{"deleted": true}), "", nil
	})()

	if err := r.DeleteKey(context.Background(), "HKLM", `SOFTWARE\MyApp`, true); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	for _, want := range []string{
		"Remove-Item", "-Recurse:$true",
		`'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\MyApp'`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("DeleteKey script missing %q", want)
		}
	}
}

func TestRegistryKeyDeleteKey_ScriptNonRecursive(t *testing.T) {
	r := newRKTestClient(t)
	var got string
	defer stubRKRun(func(_ context.Context, _ *Client, script string) (string, string, error) {
		got = script
		return rkOKEnvelope(t, map[string]any{"deleted": true}), "", nil
	})()

	if err := r.DeleteKey(context.Background(), "HKCU", `SOFTWARE\MyApp`, false); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	for _, want := range []string{"-Recurse:$false", "Get-ChildItem", "HKEY_CURRENT_USER"} {
		if !strings.Contains(got, want) {
			t.Errorf("DeleteKey script missing %q", want)
		}
	}
}

func TestRegistryKeyDeleteKey_KeyNotFoundIsNoOp(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkOKEnvelope(t, map[string]any{"deleted": false, "reason": "key_not_found"}), "", nil
	})()

	if err := r.DeleteKey(context.Background(), "HKLM", `SOFTWARE\Ghost`, false); err != nil {
		t.Fatalf("DeleteKey on missing key must be a no-op, got %v", err)
	}
}

func TestRegistryKeyDeleteKey_SubkeysRemain(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		return rkErrEnvelope(t, "invalid_input", "key has subkeys; set recursive=true to delete the key tree", nil), "", nil
	})()

	err := r.DeleteKey(context.Background(), "HKLM", `SOFTWARE\MyApp`, false)
	if !IsRegistryKeyError(err, RegistryKeyErrorInvalidInput) {
		t.Errorf("expected invalid_input, got %v", err)
	}
}

func TestRegistryKeyDeleteKey_BadHive(t *testing.T) {
	r := newRKTestClient(t)
	defer stubRKRun(func(_ context.Context, _ *Client, _ string) (string, string, error) {
		t.Error("no script must run for an unknown hive")
		return "", "", nil
	})()

	if err := r.DeleteKey(context.Background(), "HKZZ", `SOFTWARE\MyApp`, true); !IsRegistryKeyError(err, RegistryKeyErrorInvalidInput) {
		t.Errorf("expected invalid_input for unknown hive, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// registryKeyPSPath / error kinds / error type
// ---------------------------------------------------------------------------

func TestRegistryKeyPSPath_Mapping(t *testing.T) {
	for hive, full := range map[string]string{
		"HKLM": "HKEY_LOCAL_MACHINE",
		"HKCU": "HKEY_CURRENT_USER",
		"HKCR": "HKEY_CLASSES_ROOT",
		"HKU":  "HKEY_USERS",
		"HKCC": "HKEY_CURRENT_CONFIG",
		"hklm": "HKEY_LOCAL_MACHINE",
	} {
		got, err := registryKeyPSPath(hive)
		if err != nil {
			t.Errorf("registryKeyPSPath(%q): %v", hive, err)
			continue
		}
		if !strings.Contains(got, full) || !strings.Contains(got, "Registry::") {
			t.Errorf("registryKeyPSPath(%q) = %q, want Registry::%s", hive, got, full)
		}
	}
	if _, err := registryKeyPSPath("HKZZ"); !IsRegistryKeyError(err, RegistryKeyErrorInvalidInput) {
		t.Errorf("expected invalid_input, got %v", err)
	}
}

func TestMapRegistryKeyErrorKind(t *testing.T) {
	cases := map[string]RegistryKeyErrorKind{
		"not_found":         RegistryKeyErrorNotFound,
		"permission_denied": RegistryKeyErrorPermission,
		"invalid_input":     RegistryKeyErrorInvalidInput,
		"nope":              RegistryKeyErrorUnknown,
		"":                  RegistryKeyErrorUnknown,
	}
	for in, want := range cases {
		if got := mapRegistryKeyErrorKind(in); got != want {
			t.Errorf("mapRegistryKeyErrorKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistryKeyError_Methods(t *testing.T) {
	base := NewRegistryKeyError(RegistryKeyErrorPermission, "denied", nil, map[string]string{"hive": "HKLM"})
	if !strings.Contains(base.Error(), "permission_denied") || !strings.Contains(base.Error(), "denied") {
		t.Errorf("Error() = %q", base.Error())
	}
	if !errors.Is(base, ErrRegistryKeyPermission) {
		t.Error("errors.Is must match by Kind")
	}
	if errors.Is(base, ErrRegistryKeyNotFound) {
		t.Error("errors.Is must not match a different Kind")
	}
	withCause := NewRegistryKeyError(RegistryKeyErrorUnknown, "x", errors.New("root"), nil)
	if !strings.Contains(withCause.Error(), "root") {
		t.Errorf("Error() with cause = %q", withCause.Error())
	}
	if withCause.Unwrap() == nil {
		t.Error("Unwrap must return the cause")
	}
}
