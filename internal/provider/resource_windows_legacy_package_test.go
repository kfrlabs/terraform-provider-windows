// Package provider — unit tests for windows_legacy_package_resource.go.
//
// These tests do NOT require a real Windows host or TF_ACC. They cover:
//
//   - Metadata: TypeName == windows_legacy_package
//   - Schema: every documented attribute is present + counts
//   - Pre-compiled regexes (lpNameRe, lpSourcePathRe, lpSourceURLRe,
//     lpChecksumRe, lpProductIDRe)
//   - addLPDiag: *LegacyPackageError path (with/without cause/context),
//     plain-error fallback, deterministic context ordering
//   - Configure: nil ProviderData (no-op), wrong type (error), happy path
//   - ConfigValidators: ExactlyOneOf source_path/source_url present,
//     legacyPackageSourceValidator (http requires checksum, unpinned-URL
//     and md5/sha1 warnings)
//   - ImportState: empty id, valid id, whitespace trimmed
//   - applyState: state-merge semantics on observable fields
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	fwvalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestLegacyPackageResource_Metadata(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_legacy_package" {
		t.Errorf("TypeName = %q", resp.TypeName)
	}
}

func TestLegacyPackageResource_Schema_AllAttributes(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	want := []string{
		"id", "name", "installer_type",
		"source_path", "source_url",
		"checksum", "insecure_skip_verify",
		"product_id", "display_name_pattern", "display_name_match",
		"install_args", "install_args_wo", "install_args_wo_version",
		"uninstall_args", "uninstall_command",
		"valid_exit_codes", "working_directory",
		"timeout_seconds", "log_path", "keep_log", "environment",
		"installed_version", "installed", "install_date",
		"timeouts",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing %q", k)
		}
	}
	if len(resp.Schema.Attributes) != len(want) {
		t.Errorf("attribute count = %d, want %d", len(resp.Schema.Attributes), len(want))
	}
	if resp.Schema.MarkdownDescription == "" {
		t.Error("MarkdownDescription should be non-empty")
	}
}

func TestLegacyPackageForceNewModifiersAdoptImportedAttributes(t *testing.T) {
	ctx := context.Background()
	stringModifier := legacyPackageStringRequiresReplaceOnKnownPriorState()
	stringResponse := &planmodifier.StringResponse{}
	stringModifier.PlanModifyString(ctx, planmodifier.StringRequest{
		PlanValue:  types.StringValue("https://example.invalid/package.msi"),
		StateValue: types.StringNull(),
	}, stringResponse)
	if stringResponse.RequiresReplace {
		t.Fatal("unobservable ForceNew string should be adopted after import, not replaced")
	}
	stringResponse = &planmodifier.StringResponse{}
	stringModifier.PlanModifyString(ctx, planmodifier.StringRequest{
		PlanValue:  types.StringValue("https://example.invalid/new.msi"),
		StateValue: types.StringValue("https://example.invalid/old.msi"),
	}, stringResponse)
	if !stringResponse.RequiresReplace {
		t.Fatal("changing a known ForceNew string must still replace")
	}

	boolModifier := legacyPackageBoolRequiresReplaceOnKnownPriorState()
	boolResponse := &planmodifier.BoolResponse{}
	boolModifier.PlanModifyBool(ctx, planmodifier.BoolRequest{
		PlanValue:  types.BoolValue(true),
		StateValue: types.BoolNull(),
	}, boolResponse)
	if boolResponse.RequiresReplace {
		t.Fatal("unobservable ForceNew bool should be adopted after import, not replaced")
	}
	boolResponse = &planmodifier.BoolResponse{}
	boolModifier.PlanModifyBool(ctx, planmodifier.BoolRequest{
		PlanValue:  types.BoolValue(true),
		StateValue: types.BoolValue(false),
	}, boolResponse)
	if !boolResponse.RequiresReplace {
		t.Fatal("changing a known ForceNew bool must still replace")
	}

	oldArgs, diags := types.ListValueFrom(ctx, types.StringType, []string{"/old"})
	if diags.HasError() {
		t.Fatalf("old list value: %v", diags)
	}
	newArgs, diags := types.ListValueFrom(ctx, types.StringType, []string{"/new"})
	if diags.HasError() {
		t.Fatalf("new list value: %v", diags)
	}
	listModifier := legacyPackageListRequiresReplaceOnKnownPriorState()
	listResponse := &planmodifier.ListResponse{}
	listModifier.PlanModifyList(ctx, planmodifier.ListRequest{PlanValue: newArgs, StateValue: types.ListNull(types.StringType)}, listResponse)
	if listResponse.RequiresReplace {
		t.Fatal("unobservable ForceNew list should be adopted after import, not replaced")
	}
	listResponse = &planmodifier.ListResponse{}
	listModifier.PlanModifyList(ctx, planmodifier.ListRequest{PlanValue: newArgs, StateValue: oldArgs}, listResponse)
	if !listResponse.RequiresReplace {
		t.Fatal("changing a known ForceNew list must still replace")
	}
}

// ---------------------------------------------------------------------------
// Pre-compiled regexes
// ---------------------------------------------------------------------------

func TestLPRegex_Name(t *testing.T) {
	good := []string{"a", "Foo_Bar.1", "z-9", strings.Repeat("a", 128)}
	bad := []string{"", "name with space", "naïve", strings.Repeat("a", 129), "n/a"}
	for _, s := range good {
		if !lpNameRe.MatchString(s) {
			t.Errorf("expected %q to match lpNameRe", s)
		}
	}
	for _, s := range bad {
		if lpNameRe.MatchString(s) {
			t.Errorf("expected %q NOT to match lpNameRe", s)
		}
	}
}

func TestLPRegex_SourcePath(t *testing.T) {
	for _, s := range []string{`C:\inst.msi`, `D:\path\to\setup.exe`} {
		if !lpSourcePathRe.MatchString(s) {
			t.Errorf("expected %q to match", s)
		}
	}
	for _, s := range []string{"", "/usr/local/bin", "C:", `C:\`, `\\unc\share\x.msi`} {
		if lpSourcePathRe.MatchString(s) {
			t.Errorf("expected %q NOT to match", s)
		}
	}
}

func TestLPRegex_SourceURL(t *testing.T) {
	for _, s := range []string{"http://x", "https://example.com/inst.msi"} {
		if !lpSourceURLRe.MatchString(s) {
			t.Errorf("expected %q to match", s)
		}
	}
	for _, s := range []string{"", "ftp://x", "file:///c:/x"} {
		if lpSourceURLRe.MatchString(s) {
			t.Errorf("expected %q NOT to match", s)
		}
	}
}

func TestLPRegex_Checksum(t *testing.T) {
	for _, s := range []string{"sha256:deadbeef", "sha512:abcd", "sha1:00", "md5:abcd",
		// Algo name is case-insensitive: the Go-side validator lowercases
		// before comparison and the PowerShell host uppercases for
		// Get-FileHash (aggressive CLI campaign, 2026-11-17).
		"SHA256:DEADBEEF", "Sha512:abcd", "SHA1:00", "MD5:abcd"} {
		if !lpChecksumRe.MatchString(s) {
			t.Errorf("expected %q to match", s)
		}
	}
	for _, s := range []string{"", "sha256:", "sha384:abcd", "deadbeef", "sha256:zz"} {
		if lpChecksumRe.MatchString(s) {
			t.Errorf("expected %q NOT to match", s)
		}
	}
}

func TestLPRegex_ProductID(t *testing.T) {
	for _, s := range []string{"{01234567-89AB-CDEF-0123-456789ABCDEF}", "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"} {
		if !lpProductIDRe.MatchString(s) {
			t.Errorf("expected %q to match", s)
		}
	}
	for _, s := range []string{"", "01234567-89AB-CDEF-0123-456789ABCDEF", "{xxx}", "{01234}"} {
		if lpProductIDRe.MatchString(s) {
			t.Errorf("expected %q NOT to match", s)
		}
	}
}

// ---------------------------------------------------------------------------
// addLPDiag
// ---------------------------------------------------------------------------

func TestAddLPDiag_StructuredErrorWithContext(t *testing.T) {
	err := &winclient.LegacyPackageError{
		Kind:    "checksum_mismatch",
		Message: "hash differs",
		Cause:   errors.New("expected sha256:abc, got sha256:def"),
		Context: map[string]string{"host": "winlp01", "operation": "Create", "algo": "sha256"},
	}
	var diags diag.Diagnostics
	addLPDiag(&diags, err, "Create")
	if !diags.HasError() {
		t.Fatal("expected diag error")
	}
	d := diags[0]
	if !strings.Contains(d.Summary(), "checksum_mismatch") {
		t.Errorf("summary missing kind: %q", d.Summary())
	}
	detail := d.Detail()
	for _, want := range []string{"hash differs", "expected sha256:abc", "host=winlp01", "algo=sha256"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail missing %q: %q", want, detail)
		}
	}
	// Deterministic ordering: keys sorted alphabetically.
	algoIdx := strings.Index(detail, "algo=")
	hostIdx := strings.Index(detail, "host=")
	opIdx := strings.Index(detail, "operation=")
	if algoIdx < 0 || hostIdx < 0 || opIdx < 0 || algoIdx >= hostIdx || hostIdx >= opIdx {
		t.Errorf("context not sorted alphabetically: algo=%d host=%d operation=%d in %q", algoIdx, hostIdx, opIdx, detail)
	}
}

func TestAddLPDiag_StructuredErrorNoCauseNoContext(t *testing.T) {
	err := &winclient.LegacyPackageError{Kind: "unknown", Message: "boom"}
	var diags diag.Diagnostics
	addLPDiag(&diags, err, "Read")
	if !diags.HasError() {
		t.Fatal("expected diag error")
	}
	if strings.Contains(diags[0].Detail(), "Context:") {
		t.Errorf("Context section should be omitted when empty: %q", diags[0].Detail())
	}
}

func TestAddLPDiag_PlainError(t *testing.T) {
	var diags diag.Diagnostics
	addLPDiag(&diags, errors.New("plain failure"), "Delete")
	if !diags.HasError() {
		t.Fatal("expected diag error")
	}
	if !strings.Contains(diags[0].Summary(), "Delete") {
		t.Errorf("summary missing op: %q", diags[0].Summary())
	}
	if !strings.Contains(diags[0].Detail(), "plain failure") {
		t.Errorf("detail missing message: %q", diags[0].Detail())
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestLegacyPackageResource_Configure_NilProviderData(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("nil ProviderData should be a no-op, got: %v", resp.Diagnostics)
	}
	if r.lp != nil {
		t.Error("lp should remain nil")
	}
}

func TestLegacyPackageResource_Configure_WrongType(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not a *winclient.Client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected diag error on wrong type")
	}
}

func TestLegacyPackageResource_Configure_HappyPath(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "x", Username: "u", Password: "p", InsecureIgnoreHostKey: winclient.BoolPtr(true)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := &windowsLegacyPackageResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.lp == nil {
		t.Error("lp client not constructed")
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

func TestLegacyPackageResource_ConfigValidators_NotEmpty(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	v := r.ConfigValidators(context.Background())
	if len(v) < 2 {
		t.Fatalf("expected at least two ConfigValidators (ExactlyOneOf source_path/source_url + source integrity), got %d", len(v))
	}
}

// ---------------------------------------------------------------------------
// legacyPackageSourceValidator (issue #175)
// ---------------------------------------------------------------------------

// lpSourceTestConfig builds a tfsdk.Config with the given source_url/checksum
// values (empty string = null) for driving the source integrity validator.
func lpSourceTestConfig(t *testing.T, schemaResp *resource.SchemaResponse, sourceURL, checksum string) tfsdk.Config {
	t.Helper()
	str := tftypes.String
	b := tftypes.Bool
	num := tftypes.Number
	urlVal := tftypes.NewValue(str, nil)
	if sourceURL != "" {
		urlVal = tftypes.NewValue(str, sourceURL)
	}
	sumVal := tftypes.NewValue(str, nil)
	if checksum != "" {
		sumVal = tftypes.NewValue(str, checksum)
	}
	raw := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                      str,
		"name":                    str,
		"installer_type":          str,
		"source_path":             str,
		"source_url":              str,
		"checksum":                str,
		"insecure_skip_verify":    b,
		"product_id":              str,
		"display_name_pattern":    str,
		"display_name_match":      str,
		"install_args":            tftypes.List{ElementType: str},
		"install_args_wo":         tftypes.List{ElementType: str},
		"install_args_wo_version": num,
		"uninstall_args":          tftypes.List{ElementType: str},
		"uninstall_command":       str,
		"valid_exit_codes":        tftypes.List{ElementType: num},
		"working_directory":       str,
		"timeout_seconds":         num,
		"log_path":                str,
		"keep_log":                b,
		"environment":             tftypes.Map{ElementType: str},
		"installed_version":       str,
		"installed":               b,
		"install_date":            str,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}},
	}}, map[string]tftypes.Value{
		"id":                      tftypes.NewValue(str, nil),
		"name":                    tftypes.NewValue(str, "pkg"),
		"installer_type":          tftypes.NewValue(str, "msi"),
		"source_path":             tftypes.NewValue(str, nil),
		"source_url":              urlVal,
		"checksum":                sumVal,
		"insecure_skip_verify":    tftypes.NewValue(b, nil),
		"product_id":              tftypes.NewValue(str, nil),
		"display_name_pattern":    tftypes.NewValue(str, nil),
		"display_name_match":      tftypes.NewValue(str, nil),
		"install_args":            tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo":         tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo_version": tftypes.NewValue(num, nil),
		"uninstall_args":          tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"uninstall_command":       tftypes.NewValue(str, nil),
		"valid_exit_codes":        tftypes.NewValue(tftypes.List{ElementType: num}, nil),
		"working_directory":       tftypes.NewValue(str, nil),
		"timeout_seconds":         tftypes.NewValue(num, nil),
		"log_path":                tftypes.NewValue(str, nil),
		"keep_log":                tftypes.NewValue(b, nil),
		"environment":             tftypes.NewValue(tftypes.Map{ElementType: str}, nil),
		"installed_version":       tftypes.NewValue(str, nil),
		"installed":               tftypes.NewValue(b, nil),
		"install_date":            tftypes.NewValue(str, nil),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}}, nil),
	})
	return tfsdk.Config{Schema: schemaResp.Schema, Raw: raw}
}

func lpSourceValidatorDiags(t *testing.T, sourceURL, checksum string) diag.Diagnostics {
	t.Helper()
	r := &windowsLegacyPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	var validator legacyPackageSourceValidator
	for _, v := range r.ConfigValidators(context.Background()) {
		if sv, ok := v.(legacyPackageSourceValidator); ok {
			validator = sv
		}
	}
	resp := &resource.ValidateConfigResponse{}
	validator.ValidateResource(context.Background(), resource.ValidateConfigRequest{
		Config: lpSourceTestConfig(t, schemaResp, sourceURL, checksum),
	}, resp)
	return resp.Diagnostics
}

func lpDiagCounts(diags diag.Diagnostics) (errors, warnings int) {
	for _, d := range diags {
		switch d.Severity() {
		case diag.SeverityError:
			errors++
		case diag.SeverityWarning:
			warnings++
		}
	}
	return errors, warnings
}

func TestLegacyPackageSourceValidator_StrictChecksumMode(t *testing.T) {
	t.Run("https without checksum errors in strict mode", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "1")
		diags := lpSourceValidatorDiags(t, "https://mirror.internal/pkg.msi", "")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 1 || gotWarn != 0 {
			t.Fatalf("errors=%d warnings=%d, want errors=1 warnings=0 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("whitespace-only checksum counts as missing in strict mode", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "1")
		diags := lpSourceValidatorDiags(t, "https://mirror.internal/pkg.msi", "   ")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 1 || gotWarn != 0 {
			t.Fatalf("errors=%d warnings=%d, want errors=1 warnings=0 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("padded sha256 checksum parses cleanly in strict mode", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "1")
		diags := lpSourceValidatorDiags(t, "https://mirror.internal/pkg.msi", " sha256:deadbeef")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 0 || gotWarn != 0 {
			t.Fatalf("errors=%d warnings=%d, want errors=0 warnings=0 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("https with sha256 is clean in strict mode", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "true")
		diags := lpSourceValidatorDiags(t, "https://mirror.internal/pkg.msi", "sha256:deadbeef")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 0 || gotWarn != 0 {
			t.Fatalf("errors=%d warnings=%d, want errors=0 warnings=0 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("md5 errors in strict mode", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "YES")
		diags := lpSourceValidatorDiags(t, "https://mirror.internal/pkg.msi", "md5:abcd")
		gotErr, _ := lpDiagCounts(diags)
		if gotErr != 1 {
			t.Fatalf("expected 1 error for md5 in strict mode, got errors=%d (diags: %v)", gotErr, diags)
		}
	})
	t.Run("http without checksum errors in strict mode", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "1")
		diags := lpSourceValidatorDiags(t, "http://mirror.internal/pkg.msi", "")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 1 || gotWarn != 0 {
			t.Fatalf("errors=%d warnings=%d, want errors=1 warnings=0 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("http with md5 errors without warning in strict mode", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "1")
		diags := lpSourceValidatorDiags(t, "http://mirror.internal/pkg.msi", "md5:abcd")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 1 || gotWarn != 0 {
			t.Fatalf("errors=%d warnings=%d, want errors=1 warnings=0 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("https without checksum warns only when non-strict", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "")
		diags := lpSourceValidatorDiags(t, "https://mirror.internal/pkg.msi", "")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 0 || gotWarn != 1 {
			t.Fatalf("errors=%d warnings=%d, want errors=0 warnings=1 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("unset env preserves non-strict behavior", func(t *testing.T) {
		t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "")
		if strictChecksumMode() {
			t.Fatal("strictChecksumMode should be false when WINDOWS_REQUIRE_CHECKSUM is empty (unset-equivalent)")
		}
		diags := lpSourceValidatorDiags(t, "https://mirror.internal/pkg.msi", "")
		gotErr, gotWarn := lpDiagCounts(diags)
		if gotErr != 0 || gotWarn != 1 {
			t.Fatalf("errors=%d warnings=%d, want errors=0 warnings=1 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
}

func TestStrictChecksumMode(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{" True ", true},
		{"yes", true},
		{"YES", true},
		{" yes ", true},
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"strict", false},
	}
	for _, tc := range cases {
		t.Run("value="+tc.value, func(t *testing.T) {
			t.Setenv("WINDOWS_REQUIRE_CHECKSUM", tc.value)
			if got := strictChecksumMode(); got != tc.want {
				t.Errorf("strictChecksumMode() = %v, want %v for value %q", got, tc.want, tc.value)
			}
		})
	}
}
func TestLegacyPackageSourceValidator(t *testing.T) {
	t.Setenv("WINDOWS_REQUIRE_CHECKSUM", "")
	cases := []struct {
		name       string
		sourceURL  string
		checksum   string
		wantErrors int
		wantWarns  int
		wantSubstr string // expected in an error/warning detail
	}{
		{"http without checksum fails", "http://mirror.internal/pkg.msi", "", 1, 0, "checksum is required"},
		{"HTTP uppercase scheme without checksum fails", "HTTP://mirror.internal/pkg.msi", "", 1, 0, "checksum is required"},
		{"https without checksum warns", "https://mirror.internal/pkg.msi", "", 0, 1, "Unpinned"},
		{"https with whitespace-only checksum warns as missing", "https://mirror.internal/pkg.msi", "   ", 0, 1, "Unpinned"},
		{"https with padded sha256 is clean", "https://mirror.internal/pkg.msi", " sha256:deadbeef", 0, 0, ""},
		{"https with sha256 is clean", "https://mirror.internal/pkg.msi", "sha256:deadbeef", 0, 0, ""},
		{"https with sha512 is clean", "https://mirror.internal/pkg.msi", "sha512:deadbeef", 0, 0, ""},
		{"http with sha256 is clean", "http://mirror.internal/pkg.msi", "sha256:deadbeef", 0, 0, ""},
		{"https with md5 warns", "https://mirror.internal/pkg.msi", "md5:abcd", 0, 1, "Weak checksum"},
		{"https with sha1 warns", "https://mirror.internal/pkg.msi", "sha1:00", 0, 1, "Weak checksum"},
		{"http with md5 warns but checksum present so no error", "http://mirror.internal/pkg.msi", "md5:abcd", 0, 1, "Weak checksum"},
		{"no source_url is clean", "", "sha256:deadbeef", 0, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := lpSourceValidatorDiags(t, tc.sourceURL, tc.checksum)
			gotErr, gotWarn := lpDiagCounts(diags)
			if gotErr != tc.wantErrors || gotWarn != tc.wantWarns {
				t.Errorf("errors=%d warnings=%d, want errors=%d warnings=%d (diags: %v)",
					gotErr, gotWarn, tc.wantErrors, tc.wantWarns, diags)
			}
			if tc.wantSubstr != "" {
				found := false
				for _, d := range diags {
					if strings.Contains(d.Summary(), tc.wantSubstr) || strings.Contains(d.Detail(), tc.wantSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected a diagnostic containing %q, got: %v", tc.wantSubstr, diags)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// valid_exit_codes element range (CLI salvo regression test)
// ---------------------------------------------------------------------------

// TestLegacyPackageValidExitCodes_Range covers the validation gap found by
// the Terraform CLI salvo: exit codes outside the int32 range passed
// validate and died opaquely at apply time (the PowerShell install/uninstall
// pipelines cast every entry with [int], which throws mid-script without an
// Emit-Err envelope). They must be rejected at plan time instead. Negative
// int32 values stay allowed: Windows reports crash codes (e.g. 0xC0000005)
// as negative int32 via .NET Process.ExitCode.
func TestLegacyPackageValidExitCodes_Range(t *testing.T) {
	ctx := context.Background()
	r := &windowsLegacyPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	attr, ok := schemaResp.Schema.Attributes["valid_exit_codes"].(schema.ListAttribute)
	if !ok {
		t.Fatal("valid_exit_codes must be a schema.ListAttribute")
	}
	if len(attr.Validators) == 0 {
		t.Fatal("valid_exit_codes must carry element-range validators (out-of-int32 values fail opaquely at apply)")
	}
	run := func(values []int64) diag.Diagnostics {
		t.Helper()
		list, diags := types.ListValueFrom(ctx, types.Int64Type, values)
		if diags.HasError() {
			t.Fatalf("ListValueFrom(%v): %v", values, diags)
		}
		var out diag.Diagnostics
		for _, v := range attr.Validators {
			resp := &fwvalidator.ListResponse{}
			v.ValidateList(ctx, fwvalidator.ListRequest{ConfigValue: list}, resp)
			out.Append(resp.Diagnostics...)
		}
		return out
	}
	for _, values := range [][]int64{{0, 3010}, {-1073741819}, {-2147483648}, {2147483647}} {
		t.Run("accept", func(t *testing.T) {
			if diags := run(values); diags.HasError() {
				t.Errorf("values %v must be accepted, got: %v", values, diags)
			}
		})
	}
	for _, values := range [][]int64{{2147483648}, {-2147483649}, {99999999999}, {0, -99999999999}} {
		t.Run("reject", func(t *testing.T) {
			if diags := run(values); !diags.HasError() {
				t.Errorf("values %v must be rejected (outside int32 range)", values)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func lpNullRawState() tftypes.Value {
	return lpStateWith(nil)
}

// lpTimeoutsWithRead builds a `timeouts {}` value carrying a read duration.
func lpTimeoutsWithRead(d string) tftypes.Value {
	str := tftypes.String
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": str,
		"read":   str,
		"update": str,
		"delete": str,
	}}, map[string]tftypes.Value{
		"create": tftypes.NewValue(str, nil),
		"read":   tftypes.NewValue(str, d),
		"update": tftypes.NewValue(str, nil),
		"delete": tftypes.NewValue(str, nil),
	})
}

// lpStateWith builds a complete legacy-package state with optional overrides.
func lpStateWith(overrides map[string]tftypes.Value) tftypes.Value {
	str := tftypes.String
	b := tftypes.Bool
	num := tftypes.Number
	base := map[string]tftypes.Value{
		"id":                      tftypes.NewValue(str, nil),
		"name":                    tftypes.NewValue(str, nil),
		"installer_type":          tftypes.NewValue(str, nil),
		"source_path":             tftypes.NewValue(str, nil),
		"source_url":              tftypes.NewValue(str, nil),
		"checksum":                tftypes.NewValue(str, nil),
		"insecure_skip_verify":    tftypes.NewValue(b, nil),
		"product_id":              tftypes.NewValue(str, nil),
		"display_name_pattern":    tftypes.NewValue(str, nil),
		"display_name_match":      tftypes.NewValue(str, nil),
		"install_args":            tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo":         tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo_version": tftypes.NewValue(num, nil),
		"uninstall_args":          tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"uninstall_command":       tftypes.NewValue(str, nil),
		"valid_exit_codes":        tftypes.NewValue(tftypes.List{ElementType: num}, nil),
		"working_directory":       tftypes.NewValue(str, nil),
		"timeout_seconds":         tftypes.NewValue(num, nil),
		"log_path":                tftypes.NewValue(str, nil),
		"keep_log":                tftypes.NewValue(b, nil),
		"environment":             tftypes.NewValue(tftypes.Map{ElementType: str}, nil),
		"installed_version":       tftypes.NewValue(str, nil),
		"installed":               tftypes.NewValue(b, nil),
		"install_date":            tftypes.NewValue(str, nil),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}}, nil),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                      str,
		"name":                    str,
		"installer_type":          str,
		"source_path":             str,
		"source_url":              str,
		"checksum":                str,
		"insecure_skip_verify":    b,
		"product_id":              str,
		"display_name_pattern":    str,
		"display_name_match":      str,
		"install_args":            tftypes.List{ElementType: str},
		"install_args_wo":         tftypes.List{ElementType: str},
		"install_args_wo_version": num,
		"uninstall_args":          tftypes.List{ElementType: str},
		"uninstall_command":       str,
		"valid_exit_codes":        tftypes.List{ElementType: num},
		"working_directory":       str,
		"timeout_seconds":         num,
		"log_path":                str,
		"keep_log":                b,
		"environment":             tftypes.Map{ElementType: str},
		"installed_version":       str,
		"installed":               b,
		"install_date":            str,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}},
	}}, base)
}

// deadlineLPClient captures the ctx deadline seen by Read (issue #196).
type deadlineLPClient struct {
	deadline time.Time
	ok       bool
}

func (f *deadlineLPClient) Create(_ context.Context, _ winclient.LegacyPackageInput) (*winclient.LegacyPackageState, error) {
	return nil, nil
}

func (f *deadlineLPClient) Read(ctx context.Context, id string) (*winclient.LegacyPackageState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return &winclient.LegacyPackageState{
		ID:               id,
		ProductID:        id,
		InstalledVersion: "1.0.0",
		Installed:        true,
		InstallDate:      "2026-01-15",
	}, nil
}

func (f *deadlineLPClient) Update(_ context.Context, _ string, _ winclient.LegacyPackageInput) (*winclient.LegacyPackageState, error) {
	return nil, nil
}

func (f *deadlineLPClient) Delete(_ context.Context, _ string, _ winclient.LegacyPackageInput) error {
	return nil
}

// lpNullTimeoutsValue is the absent value for the `timeouts {}` block.
func lpNullTimeoutsValue() tftypes.Value {
	str := tftypes.String
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": str,
		"read":   str,
		"update": str,
		"delete": str,
	}}, nil)
}

// TestLegacyPackageRead_BoundedByTimeouts verifies Read runs under a deadline
// derived from `timeouts.read` (issue #196): lpDefaultTimeout when the block
// is absent, the configured value when set.
func TestLegacyPackageRead_BoundedByTimeouts(t *testing.T) {
	id := "{01234567-89AB-CDEF-0123-456789ABCDEF}"
	cases := []struct {
		name     string
		timeouts tftypes.Value
		want     time.Duration
	}{
		{"default", lpNullTimeoutsValue(), lpDefaultTimeout},
		{"custom", lpTimeoutsWithRead("5s"), 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &deadlineLPClient{}
			r := &windowsLegacyPackageResource{lp: fake}
			schemaResp := &resource.SchemaResponse{}
			r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
			prior := tfsdk.State{
				Schema: schemaResp.Schema,
				Raw: lpStateWith(map[string]tftypes.Value{
					"id":       tftypes.NewValue(tftypes.String, id),
					"timeouts": tc.timeouts,
				}),
			}
			resp := &resource.ReadResponse{
				State: tfsdk.State{Schema: schemaResp.Schema, Raw: prior.Raw.Copy()},
			}
			r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound (issue #196)")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
	}
}

func TestLegacyPackageResource_ImportState_Empty(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: lpNullRawState()}}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: ""}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error on empty import id")
	}
}

func TestLegacyPackageResource_ImportState_Valid(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: lpNullRawState()}}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "  {01234567-89AB-CDEF-0123-456789ABCDEF}  "}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	var got types.String
	if d := resp.State.GetAttribute(context.Background(), path.Root("id"), &got); d.HasError() {
		t.Fatalf("get id: %v", d)
	}
	if got.ValueString() != "{01234567-89AB-CDEF-0123-456789ABCDEF}" {
		t.Errorf("id = %q (whitespace must be trimmed)", got.ValueString())
	}
}

// TestLegacyPackageResource_ImportState_SeedsDefaults is the regression test
// for the post-import perpetual diff found by the Terraform CLI salvo: the
// schema defaults that are not observable on the host (display_name_match and
// keep_log) must be seeded at import time. Read cannot populate them, so
// leaving them null renders plan null -> "legacy"/false on every run even
// when the config omits both attributes and the host state is reconciled.
func TestLegacyPackageResource_ImportState_SeedsDefaults(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: lpNullRawState()}}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "{01234567-89AB-CDEF-0123-456789ABCDEF}"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	var match types.String
	if d := resp.State.GetAttribute(context.Background(), path.Root("display_name_match"), &match); d.HasError() {
		t.Fatalf("get display_name_match: %v", d)
	}
	if match.IsNull() || match.ValueString() != "legacy" {
		t.Errorf("display_name_match = %q (must be seeded to the schema default \"legacy\")", match.ValueString())
	}
	var keep types.Bool
	if d := resp.State.GetAttribute(context.Background(), path.Root("keep_log"), &keep); d.HasError() {
		t.Fatalf("get keep_log: %v", d)
	}
	if keep.IsNull() || keep.ValueBool() {
		t.Errorf("keep_log = %v (must be seeded to the schema default false)", keep)
	}
}

// ---------------------------------------------------------------------------
// applyState
// ---------------------------------------------------------------------------

func TestApplyState_PopulatesObservableFields(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	m := windowsLegacyPackageModel{
		LogPath: types.StringNull(),
	}
	r.applyState(&m, &winclient.LegacyPackageState{
		ID:               "{ABC}",
		ProductID:        "{ABC}",
		LogPath:          `C:\Windows\TEMP\install.log`,
		InstalledVersion: "1.0.0",
		Installed:        true,
		InstallDate:      "2026-01-15",
	})
	if m.ID.ValueString() != "{ABC}" {
		t.Errorf("ID = %q", m.ID.ValueString())
	}
	if m.LogPath.ValueString() != `C:\Windows\TEMP\install.log` {
		t.Errorf("LogPath = %q", m.LogPath.ValueString())
	}
	if m.InstalledVersion.ValueString() != "1.0.0" || !m.Installed.ValueBool() {
		t.Errorf("InstalledVersion=%q Installed=%v", m.InstalledVersion.ValueString(), m.Installed.ValueBool())
	}
}

func TestApplyState_KeepsUserLogPathWhenRemoteEmpty(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	m := windowsLegacyPackageModel{
		LogPath: types.StringValue(`C:\user\set.log`),
	}
	r.applyState(&m, &winclient.LegacyPackageState{ID: "{X}", Installed: true})
	if m.LogPath.ValueString() != `C:\user\set.log` {
		t.Errorf("LogPath should be preserved when remote.LogPath empty: %q", m.LogPath.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Partial state on failure (ADR-0012): a (state, error) return persists the
// observed state before the error diagnostic (tainted); a nil state stays
// error-only.
// ---------------------------------------------------------------------------

// fakeLPClient is a stub LegacyPackageClient for partial-failure handler tests.
type fakeLPClient struct {
	createOut *winclient.LegacyPackageState
	createErr error
	updateOut *winclient.LegacyPackageState
	updateErr error
}

func (f *fakeLPClient) Create(_ context.Context, _ winclient.LegacyPackageInput) (*winclient.LegacyPackageState, error) {
	return f.createOut, f.createErr
}

func (f *fakeLPClient) Read(_ context.Context, _ string) (*winclient.LegacyPackageState, error) {
	return nil, nil
}

func (f *fakeLPClient) Update(_ context.Context, _ string, _ winclient.LegacyPackageInput) (*winclient.LegacyPackageState, error) {
	return f.updateOut, f.updateErr
}

func (f *fakeLPClient) Delete(_ context.Context, _ string, _ winclient.LegacyPackageInput) error {
	return nil
}

// lpPlan builds a tfsdk.Plan for the legacy-package schema with a minimal
// valid MSI installer configuration.
func lpPlan(t *testing.T, schemaResp *resource.SchemaResponse) tfsdk.Plan {
	t.Helper()
	return tfsdk.Plan{Schema: schemaResp.Schema, Raw: lpStateWith(map[string]tftypes.Value{
		"name":           tftypes.NewValue(tftypes.String, "pkg"),
		"installer_type": tftypes.NewValue(tftypes.String, "msi"),
		"source_path":    tftypes.NewValue(tftypes.String, `C:\inst.msi`),
	})}
}

func TestLegacyPackageCreate_PartialStateOnError(t *testing.T) {
	ctx := context.Background()
	fake := &fakeLPClient{
		createOut: &winclient.LegacyPackageState{
			ID:               "{01234567-89AB-CDEF-0123-456789ABCDEF}",
			ProductID:        "{01234567-89AB-CDEF-0123-456789ABCDEF}",
			InstalledVersion: "1.0.0",
			Installed:        true,
			InstallDate:      "2026-01-15",
		},
		createErr: &winclient.LegacyPackageError{Kind: "unknown", Message: "reconcile failed"},
	}
	r := &windowsLegacyPackageResource{lp: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: lpNullRawState()}}
	r.Create(ctx, resource.CreateRequest{Plan: lpPlan(t, schemaResp)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag from reconcile failure")
	}
	var m windowsLegacyPackageModel
	if d := resp.State.Get(ctx, &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != "{01234567-89AB-CDEF-0123-456789ABCDEF}" {
		t.Errorf("partial state must be persisted (tainted), got id=%q", m.ID.ValueString())
	}
	if m.InstalledVersion.ValueString() != "1.0.0" {
		t.Errorf("partial state must carry the observed installed_version, got %q", m.InstalledVersion.ValueString())
	}
}

func TestLegacyPackageCreate_NilStateOnError_StaysStateless(t *testing.T) {
	ctx := context.Background()
	fake := &fakeLPClient{
		createErr: &winclient.LegacyPackageError{Kind: "already_exists", Message: "package already installed"},
	}
	r := &windowsLegacyPackageResource{lp: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: lpNullRawState()}}
	r.Create(ctx, resource.CreateRequest{Plan: lpPlan(t, schemaResp)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag from already_exists")
	}
	// The handler never touches state on a nil-state error: no observed
	// state is persisted, so the resource stays stateless (ID null).
	var id types.String
	if d := resp.State.GetAttribute(ctx, path.Root("id"), &id); d.HasError() {
		t.Fatalf("GetAttribute id: %v", d)
	}
	if !id.IsNull() {
		t.Errorf("nil-state error must stay stateless, got id=%q", id.ValueString())
	}
}

func TestLegacyPackageUpdate_PartialStateOnError(t *testing.T) {
	ctx := context.Background()
	id := "{01234567-89AB-CDEF-0123-456789ABCDEF}"
	fake := &fakeLPClient{
		updateOut: &winclient.LegacyPackageState{
			ID:               id,
			ProductID:        id,
			InstalledVersion: "9.9.9",
			Installed:        true,
			InstallDate:      "2026-02-02",
		},
		updateErr: &winclient.LegacyPackageError{Kind: "unknown", Message: "reconcile failed"},
	}
	r := &windowsLegacyPackageResource{lp: fake}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	prior := tfsdk.State{Schema: schemaResp.Schema, Raw: lpStateWith(map[string]tftypes.Value{
		"id":                tftypes.NewValue(tftypes.String, id),
		"name":              tftypes.NewValue(tftypes.String, "pkg"),
		"installer_type":    tftypes.NewValue(tftypes.String, "msi"),
		"source_path":       tftypes.NewValue(tftypes.String, `C:\inst.msi`),
		"product_id":        tftypes.NewValue(tftypes.String, id),
		"installed_version": tftypes.NewValue(tftypes.String, "1.0.0"),
		"installed":         tftypes.NewValue(tftypes.Bool, true),
		"install_date":      tftypes.NewValue(tftypes.String, "2026-01-15"),
	})}
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: lpStateWith(map[string]tftypes.Value{
		"id":              tftypes.NewValue(tftypes.String, id),
		"name":            tftypes.NewValue(tftypes.String, "pkg"),
		"installer_type":  tftypes.NewValue(tftypes.String, "msi"),
		"source_path":     tftypes.NewValue(tftypes.String, `C:\inst.msi`),
		"timeout_seconds": tftypes.NewValue(tftypes.Number, 600),
	})}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: prior.Raw}}

	r.Update(ctx, resource.UpdateRequest{Plan: plan, State: prior}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag from reconcile failure")
	}
	var m windowsLegacyPackageModel
	if d := resp.State.Get(ctx, &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != id {
		t.Errorf("partial state must be persisted on update failure, got id=%q", m.ID.ValueString())
	}
	if m.InstalledVersion.ValueString() != "9.9.9" {
		t.Errorf("partial state must carry the observed installed_version (not prior 1.0.0), got %q", m.InstalledVersion.ValueString())
	}
}

// ---------------------------------------------------------------------------
// display_name_match (issue #405)
// ---------------------------------------------------------------------------

func TestLegacyPackageResource_Schema_DisplayNameMatch(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Schema.Version != 1 {
		t.Errorf("schema Version = %d, want 1", resp.Schema.Version)
	}
	attr, ok := resp.Schema.Attributes["display_name_match"]
	if !ok {
		t.Fatal("schema missing display_name_match")
	}
	strAttr, ok := attr.(schema.StringAttribute)
	if !ok {
		t.Fatalf("display_name_match is %T, want schema.StringAttribute", attr)
	}
	if !strAttr.Optional || !strAttr.Computed {
		t.Errorf("display_name_match must be Optional+Computed, got Optional=%v Computed=%v", strAttr.Optional, strAttr.Computed)
	}
	if strAttr.Default == nil {
		t.Error("display_name_match must carry the legacy default")
	} else if desc := strAttr.Default.Description(context.Background()); !strings.Contains(desc, "legacy") {
		t.Errorf("default description = %q, want it to mention legacy", desc)
	}
	if len(strAttr.PlanModifiers) != 0 {
		t.Errorf("display_name_match must NOT be ForceNew (discovery-only, state-only in place), got %d plan modifiers", len(strAttr.PlanModifiers))
	}
}

// lpMatchTestConfig builds a tfsdk.Config for the display_name_match
// validator (empty string = null).
func lpMatchTestConfig(t *testing.T, schemaResp *resource.SchemaResponse, installerType, pattern, match string) tfsdk.Config {
	t.Helper()
	str := tftypes.String
	b := tftypes.Bool
	num := tftypes.Number
	strOrNull := func(s string) tftypes.Value {
		if s == "" {
			return tftypes.NewValue(str, nil)
		}
		return tftypes.NewValue(str, s)
	}
	raw := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                      str,
		"name":                    str,
		"installer_type":          str,
		"source_path":             str,
		"source_url":              str,
		"checksum":                str,
		"insecure_skip_verify":    b,
		"product_id":              str,
		"display_name_pattern":    str,
		"display_name_match":      str,
		"install_args":            tftypes.List{ElementType: str},
		"install_args_wo":         tftypes.List{ElementType: str},
		"install_args_wo_version": num,
		"uninstall_args":          tftypes.List{ElementType: str},
		"uninstall_command":       str,
		"valid_exit_codes":        tftypes.List{ElementType: num},
		"working_directory":       str,
		"timeout_seconds":         num,
		"log_path":                str,
		"keep_log":                b,
		"environment":             tftypes.Map{ElementType: str},
		"installed_version":       str,
		"installed":               b,
		"install_date":            str,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}},
	}}, map[string]tftypes.Value{
		"id":                      tftypes.NewValue(str, nil),
		"name":                    tftypes.NewValue(str, "pkg"),
		"installer_type":          strOrNull(installerType),
		"source_path":             tftypes.NewValue(str, `C:\inst.exe`),
		"source_url":              tftypes.NewValue(str, nil),
		"checksum":                tftypes.NewValue(str, nil),
		"insecure_skip_verify":    tftypes.NewValue(b, nil),
		"product_id":              tftypes.NewValue(str, nil),
		"display_name_pattern":    strOrNull(pattern),
		"display_name_match":      strOrNull(match),
		"install_args":            tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo":         tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo_version": tftypes.NewValue(num, nil),
		"uninstall_args":          tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"uninstall_command":       tftypes.NewValue(str, nil),
		"valid_exit_codes":        tftypes.NewValue(tftypes.List{ElementType: num}, nil),
		"working_directory":       tftypes.NewValue(str, nil),
		"timeout_seconds":         tftypes.NewValue(num, nil),
		"log_path":                tftypes.NewValue(str, nil),
		"keep_log":                tftypes.NewValue(b, nil),
		"environment":             tftypes.NewValue(tftypes.Map{ElementType: str}, nil),
		"installed_version":       tftypes.NewValue(str, nil),
		"installed":               tftypes.NewValue(b, nil),
		"install_date":            tftypes.NewValue(str, nil),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}}, nil),
	})
	return tfsdk.Config{Schema: schemaResp.Schema, Raw: raw}
}

func lpMatchValidatorDiags(t *testing.T, installerType, pattern, match string) diag.Diagnostics {
	t.Helper()
	ctx := context.Background()
	r := &windowsLegacyPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	var validator legacyPackageDisplayNameMatchValidator
	found := false
	for _, v := range r.ConfigValidators(ctx) {
		if sv, ok := v.(legacyPackageDisplayNameMatchValidator); ok {
			validator = sv
			found = true
		}
	}
	if !found {
		t.Fatal("legacyPackageDisplayNameMatchValidator missing from ConfigValidators")
	}
	resp := &resource.ValidateConfigResponse{}
	validator.ValidateResource(ctx, resource.ValidateConfigRequest{
		Config: lpMatchTestConfig(t, schemaResp, installerType, pattern, match),
	}, resp)
	return resp.Diagnostics
}

func TestLegacyPackageDisplayNameMatchValidator(t *testing.T) {
	cases := []struct {
		name          string
		installerType string
		pattern       string
		match         string
		wantErrors    int
		wantWarns     int
		wantSubstr    string
	}{
		{"explicit match without pattern errors", "exe", "", "wildcard", 1, 0, "display_name_pattern"},
		{"exact without pattern errors", "exe", "", "exact", 1, 0, "display_name_pattern"},
		{"unset mode without pattern is clean (computed default must not trigger)", "exe", "", "", 0, 0, ""},
		{"msi ignores explicit match without pattern", "msi", "", "regex", 0, 0, ""},
		{"msi ignores metachar pattern", "msi", "Foo (64-bit).", "", 0, 0, ""},
		{"legacy metachar pattern warns", "exe", "VLC media player (64-bit).", "", 0, 1, "Ambiguous"},
		{"explicit legacy metachar pattern warns", "exe", "VLC media player (64-bit).", "legacy", 0, 1, "Ambiguous"},
		{"explicit regex suppresses the warning", "exe", "^VLC media player.*$", "regex", 0, 0, ""},
		{"explicit wildcard is clean on plain pattern", "exe", "VLC media player*", "wildcard", 0, 0, ""},
		{"explicit exact is clean", "exe", "VLC media player", "exact", 0, 0, ""},
		{"plain pattern without metachars is clean", "exe", "VLC media player", "", 0, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := lpMatchValidatorDiags(t, tc.installerType, tc.pattern, tc.match)
			gotErr, gotWarn := lpDiagCounts(diags)
			if gotErr != tc.wantErrors || gotWarn != tc.wantWarns {
				t.Errorf("errors=%d warnings=%d, want errors=%d warnings=%d (diags: %v)",
					gotErr, gotWarn, tc.wantErrors, tc.wantWarns, diags)
			}
			if tc.wantSubstr != "" {
				found := false
				for _, d := range diags {
					if strings.Contains(d.Summary(), tc.wantSubstr) || strings.Contains(d.Detail(), tc.wantSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected a diagnostic containing %q, got: %v", tc.wantSubstr, diags)
				}
			}
		})
	}
}

func TestLegacyPackageDisplayNameMatchValidator_MetacharTable(t *testing.T) {
	warnChars := []string{".", "+", "(", ")", "^", "$", "{", "}", "|", "\\"}
	for _, c := range warnChars {
		t.Run("warns on "+c, func(t *testing.T) {
			diags := lpMatchValidatorDiags(t, "exe", "Foo"+c+"Bar", "")
			_, gotWarn := lpDiagCounts(diags)
			if gotWarn != 1 {
				t.Errorf("pattern containing %q should warn once, got warnings=%d (diags: %v)", c, gotWarn, diags)
			}
		})
	}
	cleanPatterns := []string{"VLC media player*", "VLC?player", "VLC [a-z] player", "plain name"}
	for _, p := range cleanPatterns {
		t.Run("clean on "+p, func(t *testing.T) {
			diags := lpMatchValidatorDiags(t, "exe", p, "")
			gotErr, gotWarn := lpDiagCounts(diags)
			if gotErr != 0 || gotWarn != 0 {
				t.Errorf("pattern %q should be clean, got errors=%d warnings=%d (diags: %v)", p, gotErr, gotWarn, diags)
			}
		})
	}
}

// lpV0StateRaw builds a v0 (pre-display_name_match) state value.
func lpV0StateRaw(name string) tftypes.Value {
	str := tftypes.String
	b := tftypes.Bool
	num := tftypes.Number
	attrTypes := map[string]tftypes.Type{
		"id":                      str,
		"name":                    str,
		"installer_type":          str,
		"source_path":             str,
		"source_url":              str,
		"checksum":                str,
		"insecure_skip_verify":    b,
		"product_id":              str,
		"display_name_pattern":    str,
		"install_args":            tftypes.List{ElementType: str},
		"install_args_wo":         tftypes.List{ElementType: str},
		"install_args_wo_version": num,
		"uninstall_args":          tftypes.List{ElementType: str},
		"uninstall_command":       str,
		"valid_exit_codes":        tftypes.List{ElementType: num},
		"working_directory":       str,
		"timeout_seconds":         num,
		"log_path":                str,
		"keep_log":                b,
		"environment":             tftypes.Map{ElementType: str},
		"installed_version":       str,
		"installed":               b,
		"install_date":            str,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}},
	}
	vals := map[string]tftypes.Value{
		"id":                      tftypes.NewValue(str, "{01234567-89AB-CDEF-0123-456789ABCDEF}"),
		"name":                    tftypes.NewValue(str, name),
		"installer_type":          tftypes.NewValue(str, "exe"),
		"source_path":             tftypes.NewValue(str, `C:\inst.exe`),
		"source_url":              tftypes.NewValue(str, nil),
		"checksum":                tftypes.NewValue(str, nil),
		"insecure_skip_verify":    tftypes.NewValue(b, nil),
		"product_id":              tftypes.NewValue(str, nil),
		"display_name_pattern":    tftypes.NewValue(str, "VLC*"),
		"install_args":            tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo":         tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"install_args_wo_version": tftypes.NewValue(num, nil),
		"uninstall_args":          tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"uninstall_command":       tftypes.NewValue(str, nil),
		"valid_exit_codes":        tftypes.NewValue(tftypes.List{ElementType: num}, nil),
		"working_directory":       tftypes.NewValue(str, nil),
		"timeout_seconds":         tftypes.NewValue(num, nil),
		"log_path":                tftypes.NewValue(str, nil),
		"keep_log":                tftypes.NewValue(b, nil),
		"environment":             tftypes.NewValue(tftypes.Map{ElementType: str}, nil),
		"installed_version":       tftypes.NewValue(str, "3.0.20"),
		"installed":               tftypes.NewValue(b, true),
		"install_date":            tftypes.NewValue(str, "2026-01-15"),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}}, nil),
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: attrTypes}, vals)
}

func TestLegacyPackageUpgradeStateV0ToV1(t *testing.T) {
	ctx := context.Background()
	r := &windowsLegacyPackageResource{}
	upgraders := r.UpgradeState(ctx)
	up, ok := upgraders[0]
	if !ok {
		t.Fatal("UpgradeState must define a 0 -> 1 upgrader")
	}
	if up.PriorSchema == nil {
		t.Fatal("PriorSchema must not be nil")
	}
	if up.PriorSchema.Version != 0 {
		t.Errorf("PriorSchema Version = %d, want 0", up.PriorSchema.Version)
	}
	if _, ok := up.PriorSchema.Attributes["display_name_match"]; ok {
		t.Error("v0 prior schema must not contain display_name_match")
	}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	req := resource.UpgradeStateRequest{
		State: &tfsdk.State{Schema: *up.PriorSchema, Raw: lpV0StateRaw("vlc")},
	}
	resp := &resource.UpgradeStateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	up.StateUpgrader(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("upgrader diags: %v", resp.Diagnostics)
	}
	var got windowsLegacyPackageModel
	if d := resp.State.Get(ctx, &got); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if got.DisplayNameMatch.ValueString() != "legacy" {
		t.Errorf("DisplayNameMatch = %q, want legacy (zero diff)", got.DisplayNameMatch.ValueString())
	}
	if got.Name.ValueString() != "vlc" || got.DisplayNamePattern.ValueString() != "VLC*" {
		t.Errorf("upgrader must preserve v0 fields, got name=%q pattern=%q", got.Name.ValueString(), got.DisplayNamePattern.ValueString())
	}
	if got.InstalledVersion.ValueString() != "3.0.20" || !got.Installed.ValueBool() {
		t.Errorf("upgrader must preserve computed fields, got version=%q installed=%v", got.InstalledVersion.ValueString(), got.Installed.ValueBool())
	}
}

func TestLegacyPackageModelToInput_MapsDisplayNameMatch(t *testing.T) {
	ctx := context.Background()
	r := &windowsLegacyPackageResource{}
	m := windowsLegacyPackageModel{
		Name:               types.StringValue("vlc"),
		InstallerType:      types.StringValue("exe"),
		SourcePath:         types.StringValue(`C:\inst.exe`),
		DisplayNamePattern: types.StringValue("^VLC.*$"),
		DisplayNameMatch:   types.StringValue("regex"),
	}
	in, diags := r.modelToInput(ctx, m)
	if diags.HasError() {
		t.Fatalf("modelToInput diags: %v", diags)
	}
	if in.DisplayNameMatch != "regex" {
		t.Errorf("DisplayNameMatch = %q, want regex", in.DisplayNameMatch)
	}
	if in.DisplayNamePattern != "^VLC.*$" {
		t.Errorf("DisplayNamePattern = %q", in.DisplayNamePattern)
	}
}
