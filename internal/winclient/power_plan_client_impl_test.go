// Package winclient — unit tests for PowerPlanClient.
//
// These tests stub the package-level seam runPowerPlanPowerShell to inject
// scripted stdout/stderr/err triples and capture the emitted scripts.
// Coverage targets (issue #288):
//
//	PowerPlanError: Error(), Unwrap(), Is(), sentinels, IsPowerPlanError
//	mapPowerPlanKind: all known kinds + unknown fallback
//	Aliases: static table, case-insensitive, GUID passthrough + canonicalisation
//	GUID validation: IsPowerPlanGUID
//	ValidatePowerPlanInput: plan, subgroup/setting, ac/dc matrix, range
//	Header conventions: Classify-PowerPlan, InvariantCulture,
//	  root\cimv2\power, powercfg /aliases cache, $LASTEXITCODE gates,
//	  /setacvalueindex|/setdcvalueindex + /setactive (no Activate()),
//	  no exit, no powercfg /query parsing, GUID-only identity (ElementName
//	  informational)
//	Read: happy-path mapping, unsupported preflight, remote-kind mapping,
//	  timeout, transport, setting_not_found on unknown alias
//	Apply: script shape (alias resolution on host, set AC/DC, setactive),
//	  duplicatescheme when create_if_missing, plan_not_found without it,
//	  invalid_value on set exit-code failure, verify mismatch, client-side
//	  rejection without host traffic
//	List: active + plans mapping, unsupported when no active plan
//	Restore: re-activates snapshot verbatim, never duplicates
//	DeletePlan: idempotent on missing plans
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ppCall records one invocation of the stubbed runner.
type ppCall struct {
	script string
}

// stubPpRun replaces runPowerPlanPowerShell with fn and captures every
// script. It returns the captured calls and a restore function.
func stubPpRun(calls *[]ppCall, fn func(script string) (string, string, error)) func() {
	prev := runPowerPlanPowerShell
	runPowerPlanPowerShell = func(_ context.Context, _ *Client, script string) (string, string, error) {
		if calls != nil {
			*calls = append(*calls, ppCall{script: script})
		}
		return fn(script)
	}
	return func() { runPowerPlanPowerShell = prev }
}

func newPpTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Host:                  "win01",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// ppOK marshals data as an Emit-OK envelope line.
func ppOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

// ppErr marshals an Emit-Err envelope line.
func ppErr(t *testing.T, kind, msg string) string {
	t.Helper()
	ctx := map[string]string{}
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": ctx,
	})
	if err != nil {
		t.Fatalf("marshal err: %v", err)
	}
	return string(b) + "\n"
}

// ppStatePayload builds a Read/Apply state payload with the given overrides.
func ppStatePayload(overrides map[string]any) map[string]any {
	base := map[string]any{
		"machine_id":           "11111111-2222-3333-4444-555555555555",
		"plan_guid":            PowerPlanHighPerformanceGUID,
		"plan_name":            "High performance",
		"duplicated_plan_guid": "",
		"settings": []any{
			map[string]any{
				"subgroup_guid": "238c9fa8-0aad-41ed-83f4-97be242c8f20",
				"setting_guid":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
				"ac_value":      0,
				"dc_value":      0,
			},
		},
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

// ppListPayload builds a List payload with the given overrides.
func ppListPayload(overrides map[string]any) map[string]any {
	base := map[string]any{
		"machine_id":       "11111111-2222-3333-4444-555555555555",
		"active_plan_guid": PowerPlanHighPerformanceGUID,
		"active_plan_name": "High performance",
		"plans": []any{
			map[string]any{"guid": PowerPlanBalancedGUID, "name": "Balanced", "is_active": false},
			map[string]any{"guid": PowerPlanHighPerformanceGUID, "name": "High performance", "is_active": true},
			map[string]any{"guid": PowerPlanPowerSaverGUID, "name": "Power saver", "is_active": false},
		},
	}
	for k, v := range overrides {
		base[k] = v
	}
	return base
}

var ppExitRe = regexp.MustCompile(`(?m)^\s*exit(\s|;|$)`)

// ---------------------------------------------------------------------------
// PowerPlanError
// ---------------------------------------------------------------------------

func TestPowerPlanError_ErrorWithCause(t *testing.T) {
	cause := errors.New("boom")
	e := NewPowerPlanError(PowerPlanErrorAccessDenied, "denied", cause, map[string]string{"host": "win01"})
	msg := e.Error()
	if !strings.Contains(msg, "access_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "boom") {
		t.Errorf("missing kind/message/cause: %q", msg)
	}
	e2 := NewPowerPlanError(PowerPlanErrorUnknown, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestPowerPlanError_Is(t *testing.T) {
	e := NewPowerPlanError(PowerPlanErrorPlanNotFound, "x", nil, nil)
	if !errors.Is(e, ErrPowerPlanNotFound) {
		t.Error("errors.Is(ErrPowerPlanNotFound) should match by kind")
	}
	if errors.Is(e, ErrPowerPlanAccessDenied) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsPowerPlanError(e, PowerPlanErrorPlanNotFound) {
		t.Error("IsPowerPlanError should match")
	}
	if IsPowerPlanError(errors.New("plain"), PowerPlanErrorPlanNotFound) {
		t.Error("IsPowerPlanError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-PowerPlanError should be false")
	}
	var pe *PowerPlanError
	if !errors.As(NewPowerPlanError(PowerPlanErrorUnknown, "m", nil, nil), &pe) {
		t.Error("errors.As should extract *PowerPlanError")
	}
}

func TestMapPowerPlanKind(t *testing.T) {
	cases := map[string]PowerPlanErrorKind{
		"plan_not_found":    PowerPlanErrorPlanNotFound,
		"setting_not_found": PowerPlanErrorSettingNotFound,
		"invalid_value":     PowerPlanErrorInvalidValue,
		"unsupported":       PowerPlanErrorUnsupported,
		"access_denied":     PowerPlanErrorAccessDenied,
		"":                  PowerPlanErrorUnknown,
		"weird_kind":        PowerPlanErrorUnknown,
	}
	for in, want := range cases {
		if got := mapPowerPlanKind(in); got != want {
			t.Errorf("mapPowerPlanKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Aliases and GUID handling
// ---------------------------------------------------------------------------

func TestPowerPlanAliasTable(t *testing.T) {
	for alias, want := range map[string]string{
		"balanced":             PowerPlanBalancedGUID,
		"high_performance":     PowerPlanHighPerformanceGUID,
		"power_saver":          PowerPlanPowerSaverGUID,
		"ultimate_performance": PowerPlanUltimatePerformanceGUID,
	} {
		got, err := ResolvePowerPlanReference(alias)
		if err != nil {
			t.Errorf("alias %q rejected: %v", alias, err)
			continue
		}
		if got != want {
			t.Errorf("alias %q = %q, want %q", alias, got, want)
		}
	}
}

func TestResolvePowerPlanReference_CaseInsensitive(t *testing.T) {
	for _, ref := range []string{"High_Performance", "HIGH_PERFORMANCE", " Balanced "} {
		if _, err := ResolvePowerPlanReference(ref); err != nil {
			t.Errorf("alias %q should resolve case-insensitively (trimmed), got %v", ref, err)
		}
	}
	got, err := ResolvePowerPlanReference("8C5E7FDA-E8BF-4A96-9A85-A6E23A8C635C")
	if err != nil {
		t.Fatalf("upper-case GUID rejected: %v", err)
	}
	if got != PowerPlanHighPerformanceGUID {
		t.Errorf("GUID not canonicalised to lower-case: %q", got)
	}
}

func TestResolvePowerPlanReference_Rejects(t *testing.T) {
	for _, ref := range []string{"", "High performance", "Balanced (recommended)", "381b4222-f694-41f0-9685", "{381b4222-f694-41f0-9685-ff5bb260df2e}"} {
		if _, err := ResolvePowerPlanReference(ref); !IsPowerPlanError(err, PowerPlanErrorPlanNotFound) {
			t.Errorf("ref %q should yield plan_not_found, got %v", ref, err)
		}
	}
}

func TestIsPowerPlanGUID(t *testing.T) {
	if !IsPowerPlanGUID(PowerPlanBalancedGUID) || !IsPowerPlanGUID(strings.ToUpper(PowerPlanBalancedGUID)) {
		t.Error("canonical GUIDs must validate in either case")
	}
	for _, s := range []string{"", "balanced", "  ", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"} {
		if IsPowerPlanGUID(s) {
			t.Errorf("%q must not validate as a GUID", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

func ppInt(v int64) *int64 { return &v }

func TestValidatePowerPlanSettingValue(t *testing.T) {
	for _, v := range []int64{0, 1, 3600} {
		if err := ValidatePowerPlanSettingValue(v); err != nil {
			t.Errorf("value %d should be valid, got %v", v, err)
		}
	}
	if err := ValidatePowerPlanSettingValue(-1); !IsPowerPlanError(err, PowerPlanErrorInvalidValue) {
		t.Errorf("negative value should yield invalid_value, got %v", err)
	}
}

func TestValidatePowerPlanInput(t *testing.T) {
	valid := PowerPlanInput{
		Plan:     "high_performance",
		Settings: []PowerPlanSettingInput{{Subgroup: "SUB_DISK", Setting: "DISKIDLE", ACValue: ppInt(0)}},
	}
	if err := ValidatePowerPlanInput(valid); err != nil {
		t.Errorf("valid input rejected: %v", err)
	}
	// DC-only is a valid single-source override; DC values are stored
	// even on hosts without a battery.
	dcOnly := PowerPlanInput{
		Plan:     PowerPlanBalancedGUID,
		Settings: []PowerPlanSettingInput{{Subgroup: "SUB_SLEEP", Setting: "STANDBYIDLE", DCValue: ppInt(0)}},
	}
	if err := ValidatePowerPlanInput(dcOnly); err != nil {
		t.Errorf("DC-only input rejected: %v", err)
	}
	if err := ValidatePowerPlanInput(PowerPlanInput{Plan: "bogus"}); !IsPowerPlanError(err, PowerPlanErrorPlanNotFound) {
		t.Errorf("bogus plan should yield plan_not_found, got %v", err)
	}
	if err := ValidatePowerPlanInput(PowerPlanInput{Plan: "balanced", Settings: []PowerPlanSettingInput{{Subgroup: "", Setting: "DISKIDLE", ACValue: ppInt(0)}}}); !IsPowerPlanError(err, PowerPlanErrorSettingNotFound) {
		t.Errorf("empty subgroup should yield setting_not_found, got %v", err)
	}
	if err := ValidatePowerPlanInput(PowerPlanInput{Plan: "balanced", Settings: []PowerPlanSettingInput{{Subgroup: "SUB_DISK", Setting: "DISKIDLE"}}}); !IsPowerPlanError(err, PowerPlanErrorInvalidValue) {
		t.Errorf("setting with neither AC nor DC should yield invalid_value, got %v", err)
	}
	if err := ValidatePowerPlanInput(PowerPlanInput{Plan: "balanced", Settings: []PowerPlanSettingInput{{Subgroup: "SUB_DISK", Setting: "DISKIDLE", ACValue: ppInt(-5)}}}); !IsPowerPlanError(err, PowerPlanErrorInvalidValue) {
		t.Errorf("negative AC value should yield invalid_value, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Header invariants
// ---------------------------------------------------------------------------

func TestPowerPlanHeader_Conventions(t *testing.T) {
	for _, want := range []string{
		"function Classify-PowerPlan",
		"InvariantCulture",
		"function Get-PowerAliasTable",
		"function Resolve-PowerGuid",
		"function Read-PowerSettingValue",
		"function Get-PowerPlans",
		"root\\cimv2\\power",
		"Win32_PowerPlan",
		"Win32_PowerSettingDataIndex",
		"SettingIndexValue",
		"function Emit-OK",
		"function Emit-Err",
	} {
		if !strings.Contains(psPowerPlanHeader, want) {
			t.Errorf("psPowerPlanHeader missing %q", want)
		}
	}
	// MachineGuid lives in the bodies; plan matching keys off the
	// InstanceID regex in Get-PowerPlans (header).
	if !strings.Contains(ppReadBody+ppApplyBody+ppListBody, "MachineGuid") {
		t.Error("power plan bodies missing MachineGuid")
	}
	if !strings.Contains(psPowerPlanHeader, "Microsoft:PowerPlan") {
		t.Error("psPowerPlanHeader missing the plan InstanceID match")
	}
	full := psPowerPlanHeader + ppReadBody + ppApplyBody + ppListBody + ppDeleteBody
	for _, want := range []string{
		"/aliases",
		"/setacvalueindex",
		"/setdcvalueindex",
		"/setactive",
		"/duplicatescheme",
		"/delete",
		"$LASTEXITCODE",
		"System32\\powercfg.exe",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("power plan scripts missing %q", want)
		}
	}
	// Activation uses powercfg /setactive (exit-code gated):
	// Win32_PowerPlan.Activate() is unreliable and never called.
	if strings.Contains(full, "Activate()") || strings.Contains(full, ".Activate(") {
		t.Error("scripts must never call Win32_PowerPlan.Activate()")
	}
	// Identity is GUID-only: ElementName is surfaced informationally but
	// never matched on; powercfg /query text is never parsed.
	if strings.Contains(full, "/query") {
		t.Error("scripts must never parse powercfg /query text")
	}
	if strings.Count(full, "ElementName") != 1 {
		t.Errorf("ElementName must appear exactly once (informational plan_name), got %d", strings.Count(full, "ElementName"))
	}
	if ppExitRe.MatchString(full) {
		t.Error("power plan scripts must not contain an exit statement (shared session)")
	}
	// Unsupported detection: powercfg.exe presence is probed via
	// Test-Path, and the empty-active-plan case emits unsupported.
	for _, want := range []string{"Test-Path -LiteralPath $PowerCfg", "'unsupported'"} {
		if !strings.Contains(full, want) {
			t.Errorf("scripts missing unsupported handling %q", want)
		}
	}
}

func TestPowerPlanAliasTable_GuidFirst(t *testing.T) {
	// Real `powercfg /aliases` output lists the GUID first
	// ("<guid>  SCHEME_MIN"), so the GUID-first match must be primary
	// with the alias-first spelling kept as a fallback.
	guidFirst := `([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s+([A-Za-z][A-Za-z0-9_]*)`
	aliasFirst := `([A-Za-z][A-Za-z0-9_]*)\s+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`
	if !strings.Contains(psPowerPlanHeader, guidFirst) {
		t.Error("Get-PowerAliasTable must match GUID-first powercfg /aliases lines")
	}
	if !strings.Contains(psPowerPlanHeader, aliasFirst) {
		t.Error("Get-PowerAliasTable must keep the alias-first match as a fallback")
	}
	if strings.Index(psPowerPlanHeader, guidFirst) > strings.Index(psPowerPlanHeader, aliasFirst) {
		t.Error("GUID-first match must be primary (appear before the alias-first fallback)")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestPowerPlanRead_MapsPayload(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppOK(t, ppStatePayload(nil)), "", nil
	})
	defer restore()

	st, err := NewPowerPlanClient(newPpTestClient(t)).Read(context.Background(), []PowerPlanSettingKey{{Subgroup: "SUB_DISK", Setting: "DISKIDLE"}})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st.PlanGUID != PowerPlanHighPerformanceGUID {
		t.Errorf("PlanGUID = %q", st.PlanGUID)
	}
	if st.PlanName == "" {
		t.Error("PlanName must be populated (informational)")
	}
	if st.MachineID == "" {
		t.Error("MachineID must be populated")
	}
	if len(st.Settings) != 1 {
		t.Fatalf("want 1 setting, got %d", len(st.Settings))
	}
	s := st.Settings[0]
	if s.SubgroupGUID != "238c9fa8-0aad-41ed-83f4-97be242c8f20" || s.SettingGUID != "29f6c1db-86da-48c5-9fdb-f2b67b1f44da" {
		t.Errorf("setting GUIDs not normalised: %+v", s)
	}
	if s.ACValue == nil || *s.ACValue != 0 || s.DCValue == nil || *s.DCValue != 0 {
		t.Errorf("setting values = %+v, want AC=0 DC=0", s)
	}
	if st.DuplicatedPlanGUID != "" {
		t.Error("Read must not report a duplicated plan")
	}
}

func TestPowerPlanRead_SettingsRendered(t *testing.T) {
	var got string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		got = script
		return ppOK(t, ppStatePayload(map[string]any{"settings": []any{}})), "", nil
	})
	defer restore()

	_, err := NewPowerPlanClient(newPpTestClient(t)).Read(context.Background(), []PowerPlanSettingKey{
		{Subgroup: "SUB_DISK", Setting: "DISKIDLE"},
		{Subgroup: "238c9fa8-0aad-41ed-83f4-97be242c8f20", Setting: "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"},
	})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	for _, want := range []string{
		"@{ Sub = 'SUB_DISK'; Setting = 'DISKIDLE' }",
		"@{ Sub = '238c9fa8-0aad-41ed-83f4-97be242c8f20'; Setting = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' }",
		"Resolve-PowerGuid",
		"Microsoft:PowerSetting\\{",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("read script missing %q", want)
		}
	}
}

func TestPowerPlanRead_Unsupported(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "unsupported", "powercfg.exe is not available on the target host"), "", nil
	})
	defer restore()

	_, err := NewPowerPlanClient(newPpTestClient(t)).Read(context.Background(), nil)
	if !errors.Is(err, ErrPowerPlanUnsupported) {
		t.Errorf("expected ErrPowerPlanUnsupported, got %v", err)
	}
}

func TestPowerPlanRead_SettingNotFound(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "setting_not_found", "subgroup NOSUCH could not be resolved via powercfg /aliases"), "", nil
	})
	defer restore()

	_, err := NewPowerPlanClient(newPpTestClient(t)).Read(context.Background(),
		[]PowerPlanSettingKey{{Subgroup: "NOSUCH", Setting: "DISKIDLE"}})
	if !errors.Is(err, ErrPowerPlanSettingNotFound) {
		t.Errorf("expected ErrPowerPlanSettingNotFound, got %v", err)
	}
}

func TestPowerPlanRead_RemoteKindMapping(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want *PowerPlanError
	}{
		{"plan_not_found", ErrPowerPlanNotFound},
		{"setting_not_found", ErrPowerPlanSettingNotFound},
		{"invalid_value", ErrPowerPlanInvalidValue},
		{"unsupported", ErrPowerPlanUnsupported},
		{"access_denied", ErrPowerPlanAccessDenied},
		{"bogus_kind", ErrPowerPlanUnknown},
	} {
		var calls []ppCall
		restore := stubPpRun(&calls, func(_ string) (string, string, error) {
			return ppErr(t, tc.kind, "remote failure"), "", nil
		})
		_, err := NewPowerPlanClient(newPpTestClient(t)).Read(context.Background(), nil)
		restore()
		if !errors.Is(err, tc.want) {
			t.Errorf("kind %q: expected %v, got %v", tc.kind, tc.want, err)
		}
	}
}

func TestPowerPlanRead_Timeout(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return "", "", context.DeadlineExceeded
	})
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	_, err := NewPowerPlanClient(newPpTestClient(t)).Read(ctx, nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected a timeout error, got %v", err)
	}
}

func TestPowerPlanRead_Transport(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return "", "boom", fmt.Errorf("dial tcp: connection refused")
	})
	defer restore()

	_, err := NewPowerPlanClient(newPpTestClient(t)).Read(context.Background(), nil)
	if !errors.Is(err, ErrPowerPlanUnknown) {
		t.Errorf("expected ErrPowerPlanUnknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

func ppApplyInput() PowerPlanInput {
	return PowerPlanInput{
		Plan:     "high_performance",
		Settings: []PowerPlanSettingInput{{Subgroup: "SUB_DISK", Setting: "DISKIDLE", ACValue: ppInt(0), DCValue: ppInt(0)}},
	}
}

func TestPowerPlanApply_ScriptShape(t *testing.T) {
	var got string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		got = script
		return ppOK(t, ppStatePayload(nil)), "", nil
	})
	defer restore()

	st, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), ppApplyInput())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if st.PlanGUID != PowerPlanHighPerformanceGUID {
		t.Errorf("PlanGUID = %q", st.PlanGUID)
	}
	for _, want := range []string{
		"'" + PowerPlanHighPerformanceGUID + "'",
		"$CreateIfMissing = $false",
		"@{ Sub = 'SUB_DISK'; Setting = 'DISKIDLE'; AC = 0; DC = 0 }",
		"/setacvalueindex $effective",
		"/setdcvalueindex $effective",
		"/setactive $effective",
		"$LASTEXITCODE",
		"Get-PowerAliasTable",
		"Microsoft:PowerSetting\\{",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("apply script missing %q", want)
		}
	}
	if strings.Contains(got, "/duplicatescheme") && !strings.Contains(got, "$CreateIfMissing") {
		t.Error("duplicatescheme must be guarded by $CreateIfMissing")
	}
	if ppExitRe.MatchString(got) {
		t.Error("apply script must not contain an exit statement (shared session)")
	}
}

func TestPowerPlanApply_DCStoredWithoutBattery(t *testing.T) {
	// A DC-only override is a valid single-source apply: Windows stores
	// DC values even on hosts without a battery, so no warning or skip.
	var got string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		got = script
		p := ppStatePayload(map[string]any{"settings": []any{
			map[string]any{
				"subgroup_guid": "238c9fa8-0aad-41ed-83f4-97be242c8f20",
				"setting_guid":  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
				"ac_value":      nil,
				"dc_value":      0,
			},
		}})
		return ppOK(t, p), "", nil
	})
	defer restore()

	in := PowerPlanInput{
		Plan:     "balanced",
		Settings: []PowerPlanSettingInput{{Subgroup: "SUB_SLEEP", Setting: "STANDBYIDLE", DCValue: ppInt(0)}},
	}
	st, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(got, "DC = 0") || !strings.Contains(got, "AC = $null") {
		t.Errorf("DC-only apply must render DC = 0 and AC = $null, got:\n%s", got)
	}
	if st.Settings[0].ACValue != nil || st.Settings[0].DCValue == nil {
		t.Errorf("DC-only state must keep AC nil and DC set: %+v", st.Settings[0])
	}
}

func TestPowerPlanApply_CreateIfMissingDuplicates(t *testing.T) {
	var got string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		got = script
		return ppOK(t, ppStatePayload(map[string]any{
			"plan_guid":            "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6",
			"duplicated_plan_guid": "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6",
			"settings":             []any{},
		})), "", nil
	})
	defer restore()

	in := ppApplyInput()
	in.Plan = "ultimate_performance"
	in.CreateIfMissing = true
	st, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), in)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(got, "$CreateIfMissing = $true") {
		t.Error("create_if_missing must render $CreateIfMissing = $true")
	}
	if !strings.Contains(got, "/duplicatescheme") {
		t.Error("apply script must duplicate the template when create_if_missing")
	}
	if st.DuplicatedPlanGUID != "a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6" {
		t.Errorf("DuplicatedPlanGUID = %q", st.DuplicatedPlanGUID)
	}
}

func TestPowerPlanApply_MissingPlanWithoutFlag(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "plan_not_found", "power plan e9a42b02-d5df-448d-aa00-03f14749eb61 was not found on the target host"), "", nil
	})
	defer restore()

	in := ppApplyInput()
	in.Plan = "ultimate_performance"
	if _, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), in); !errors.Is(err, ErrPowerPlanNotFound) {
		t.Errorf("expected ErrPowerPlanNotFound, got %v", err)
	}
}

func TestPowerPlanApply_InvalidValueOnSetFailure(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "invalid_value", "powercfg /setacvalueindex failed (exit 87): Invalid Parameters"), "", nil
	})
	defer restore()

	if _, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), ppApplyInput()); !errors.Is(err, ErrPowerPlanInvalidValue) {
		t.Errorf("expected ErrPowerPlanInvalidValue, got %v", err)
	}
}

func TestPowerPlanApply_VerifyMismatchErrors(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "unknown", "power plan change did not take effect: active plan is not 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"), "", nil
	})
	defer restore()

	if _, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), ppApplyInput()); !errors.Is(err, ErrPowerPlanUnknown) {
		t.Errorf("verify mismatch should yield ErrPowerPlanUnknown, got %v", err)
	}
}

func TestPowerPlanApply_InvalidInputFailsClientSide(t *testing.T) {
	calls := 0
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		calls++
		return ppOK(t, ppStatePayload(nil)), "", nil
	})
	defer restore()

	in := ppApplyInput()
	in.Plan = "bogus"
	if _, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), in); !errors.Is(err, ErrPowerPlanNotFound) {
		t.Errorf("bogus plan should yield ErrPowerPlanNotFound, got %v", err)
	}
	if calls != 0 {
		t.Error("client-side plan rejection must not reach the host")
	}

	in = ppApplyInput()
	in.Settings[0].ACValue = ppInt(-1)
	if _, err := NewPowerPlanClient(newPpTestClient(t)).Apply(context.Background(), in); !errors.Is(err, ErrPowerPlanInvalidValue) {
		t.Errorf("negative value should yield ErrPowerPlanInvalidValue, got %v", err)
	}
	if calls != 0 {
		t.Error("client-side value rejection must not reach the host")
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestPowerPlanList_MapsPayload(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppOK(t, ppListPayload(nil)), "", nil
	})
	defer restore()

	ls, err := NewPowerPlanClient(newPpTestClient(t)).List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if ls.ActivePlanGUID != PowerPlanHighPerformanceGUID {
		t.Errorf("ActivePlanGUID = %q", ls.ActivePlanGUID)
	}
	if ls.ActivePlanName == "" {
		t.Error("ActivePlanName must be populated (informational)")
	}
	if len(ls.Plans) != 3 {
		t.Fatalf("want 3 plans, got %d", len(ls.Plans))
	}
	active := 0
	for _, p := range ls.Plans {
		if p.GUID == "" {
			t.Error("plan GUID must be populated")
		}
		if p.IsActive {
			active++
			if p.GUID != PowerPlanHighPerformanceGUID {
				t.Errorf("active plan = %q", p.GUID)
			}
		}
	}
	if active != 1 {
		t.Errorf("want exactly 1 active plan, got %d", active)
	}
}

func TestPowerPlanList_NoActivePlanUnsupported(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "unsupported", "No active power plan was found on the target host (power plans are unavailable, e.g. containers)."), "", nil
	})
	defer restore()

	_, err := NewPowerPlanClient(newPpTestClient(t)).List(context.Background())
	if !errors.Is(err, ErrPowerPlanUnsupported) {
		t.Errorf("expected ErrPowerPlanUnsupported, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

func TestPowerPlanRestore_ReappliesSnapshot(t *testing.T) {
	var got string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		got = script
		return ppOK(t, ppStatePayload(map[string]any{"plan_guid": PowerPlanBalancedGUID})), "", nil
	})
	defer restore()

	snap := PowerPlanSnapshot{
		PlanGUID: PowerPlanBalancedGUID,
		Settings: []PowerPlanSettingState{{
			SubgroupGUID: "238c9fa8-0aad-41ed-83f4-97be242c8f20",
			SettingGUID:  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
			ACValue:      ppInt(0),
			DCValue:      ppInt(0),
		}},
	}
	st, err := NewPowerPlanClient(newPpTestClient(t)).Restore(context.Background(), snap)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if st.PlanGUID != PowerPlanBalancedGUID {
		t.Errorf("restored PlanGUID = %q", st.PlanGUID)
	}
	for _, want := range []string{
		"'" + PowerPlanBalancedGUID + "'",
		"$CreateIfMissing = $false",
		"/setactive $effective",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("restore script missing %q", want)
		}
	}
	if !strings.Contains(got, "$CreateIfMissing = $false") {
		t.Error("restore must render $CreateIfMissing = $false so a missing snapshot plan fails closed instead of duplicating a template")
	}
	if !strings.Contains(got, "'plan_not_found' ('power plan ' + $PlanGuid + ' was not found on the target host')") {
		t.Error("restore must fail closed with plan_not_found when the snapshot plan is absent")
	}
}

func TestPowerPlanRestore_SkipsNullValuedSettings(t *testing.T) {
	var got string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		got = script
		return ppOK(t, ppStatePayload(map[string]any{"plan_guid": PowerPlanBalancedGUID, "settings": []any{}})), "", nil
	})
	defer restore()

	snap := PowerPlanSnapshot{
		PlanGUID: PowerPlanBalancedGUID,
		Settings: []PowerPlanSettingState{{
			SubgroupGUID: "238c9fa8-0aad-41ed-83f4-97be242c8f20",
			SettingGUID:  "29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
		}},
	}
	if _, err := NewPowerPlanClient(newPpTestClient(t)).Restore(context.Background(), snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !strings.Contains(got, "$Settings = @()") {
		t.Errorf("all-null snapshot settings must render an empty settings array, got:\n%s", got)
	}
}

func TestPowerPlanRestore_MissingPlanErrors(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "plan_not_found", "power plan 381b4222-f694-41f0-9685-ff5bb260df2e was not found on the target host"), "", nil
	})
	defer restore()

	snap := PowerPlanSnapshot{PlanGUID: PowerPlanBalancedGUID}
	if _, err := NewPowerPlanClient(newPpTestClient(t)).Restore(context.Background(), snap); !errors.Is(err, ErrPowerPlanNotFound) {
		t.Errorf("expected ErrPowerPlanNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeletePlan
// ---------------------------------------------------------------------------

func TestPowerPlanDeletePlan_ScriptShape(t *testing.T) {
	var got string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		got = script
		return ppOK(t, nil), "", nil
	})
	defer restore()

	guid := "A1B2C3D4-E5F6-47A8-9B0C-D1E2F3A4B5C6"
	if err := NewPowerPlanClient(newPpTestClient(t)).DeletePlan(context.Background(), guid); err != nil {
		t.Fatalf("DeletePlan: %v", err)
	}
	for _, want := range []string{
		"'a1b2c3d4-e5f6-47a8-9b0c-d1e2f3a4b5c6'",
		"/delete $PlanGuid",
		"$LASTEXITCODE",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("delete script missing %q", want)
		}
	}
}

func TestPowerPlanDeletePlan_MissingIsSuccess(t *testing.T) {
	// The script maps a "does not exist" /delete failure to Emit-OK
	// itself (idempotent): the client sees a plain OK envelope.
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppOK(t, nil), "", nil
	})
	defer restore()

	if err := NewPowerPlanClient(newPpTestClient(t)).DeletePlan(context.Background(), PowerPlanBalancedGUID); err != nil {
		t.Errorf("missing plan must be success, got %v", err)
	}
}

func TestPowerPlanDeleteScript_PreChecksExistence(t *testing.T) {
	// Missing-plan idempotency must not depend on localised powercfg text:
	// the delete script pre-checks existence locale-free via Get-PowerPlans
	// (GUID-parsed WMI) and short-circuits before calling /delete.
	var gotScript string
	restore := stubPpRun(nil, func(script string) (string, string, error) {
		gotScript = script
		return ppOK(t, nil), "", nil
	})
	defer restore()

	if err := NewPowerPlanClient(newPpTestClient(t)).DeletePlan(context.Background(), PowerPlanBalancedGUID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"Get-PowerPlans", "Emit-OK $null; return"} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("delete script missing locale-free pre-check %q", want)
		}
	}
}

func TestPowerPlanDeletePlan_PlanNotFoundEnvelopeIsSuccess(t *testing.T) {
	// Any other "not found" phrasing surfaces as a typed plan_not_found
	// envelope (via Classify-PowerPlan); the Go caller treats it as
	// success so idempotency does not depend on English substrings.
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "plan_not_found", "powercfg /delete failed (exit 1): the specified scheme could not be found"), "", nil
	})
	defer restore()

	if err := NewPowerPlanClient(newPpTestClient(t)).DeletePlan(context.Background(), PowerPlanBalancedGUID); err != nil {
		t.Errorf("plan_not_found envelope must be success, got %v", err)
	}
}

func TestPowerPlanSentinelAlias(t *testing.T) {
	// Deprecated alias stays compatible with the canonical sentinel.
	if ErrPowerPlanSettingFound != ErrPowerPlanSettingNotFound {
		t.Error("ErrPowerPlanSettingFound must alias ErrPowerPlanSettingNotFound")
	}
	if !errors.Is(NewPowerPlanError(PowerPlanErrorSettingNotFound, "x", nil, nil), ErrPowerPlanSettingNotFound) {
		t.Error("errors.Is with ErrPowerPlanSettingNotFound must match by kind")
	}
}

func TestPowerPlanDeletePlan_FailureSurfaces(t *testing.T) {
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		return ppErr(t, "unknown", "powercfg /delete failed (exit 1): some other failure"), "", nil
	})
	defer restore()

	// A script-side failure still surfaces to the caller.
	if err := NewPowerPlanClient(newPpTestClient(t)).DeletePlan(context.Background(), PowerPlanBalancedGUID); err == nil {
		t.Fatal("a script-side failure must still surface")
	}
}

func TestPowerPlanDeletePlan_RejectsNonGUID(t *testing.T) {
	calls := 0
	restore := stubPpRun(nil, func(_ string) (string, string, error) {
		calls++
		return ppOK(t, nil), "", nil
	})
	defer restore()

	if err := NewPowerPlanClient(newPpTestClient(t)).DeletePlan(context.Background(), "balanced"); !IsPowerPlanError(err, PowerPlanErrorPlanNotFound) {
		t.Errorf("non-GUID delete should yield plan_not_found, got %v", err)
	}
	if calls != 0 {
		t.Error("non-GUID delete must not reach the host")
	}
}
