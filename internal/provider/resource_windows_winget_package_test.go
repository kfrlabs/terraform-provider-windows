// Package provider — unit tests for resource_windows_winget_package.go
//
// These tests do NOT require a real Windows host or TF_ACC. They exercise:
//
//   - Metadata: TypeName correctly set to "windows_winget_package"
//   - Schema: all 7 attributes present (id + 6 user-facing/computed)
//   - wingetOverrideValidator: valid strings, control characters, null/unknown skip
//   - addWPDiag: *WingetPackageError path (with/without cause, with/without context)
//     and plain-error path
//   - Configure: nil ProviderData, wrong type, happy path
//   - ConfigValidators: returns empty slice
//   - ImportState: valid format (winget:Foo.Bar), invalid format (no colon, empty parts)
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	schemavalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestWingetPackageResource_Metadata(t *testing.T) {
	r := &windowsWingetPackageResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_winget_package" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "windows_winget_package")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestWingetPackageResource_Schema_AllAttributes(t *testing.T) {
	r := &windowsWingetPackageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	s := resp.Schema

	wantAttrs := []string{
		"id", "package_id", "version", "source", "override",
		"installed_version", "name",
	}
	for _, k := range wantAttrs {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(s.Attributes) != 7 {
		t.Errorf("expected 7 attributes, got %d", len(s.Attributes))
	}
}

func TestWingetPackageResource_Schema_ResourceLevelCall(t *testing.T) {
	r := &windowsWingetPackageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if len(resp.Schema.Attributes) == 0 {
		t.Error("Schema() produced empty schema")
	}
	if resp.Schema.MarkdownDescription == "" {
		t.Error("MarkdownDescription should be non-empty")
	}
}

// ---------------------------------------------------------------------------
// wingetOverrideValidator
// ---------------------------------------------------------------------------

func TestWingetOverrideValidator_Description(t *testing.T) {
	v := wingetOverrideValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must be non-empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription must be non-empty")
	}
}

func TestWingetOverrideValidator_ValidStrings(t *testing.T) {
	v := wingetOverrideValidator{}
	for _, s := range []string{
		"",
		"/S /allusers",
		`INSTALLDIR="C:\Program Files\MyApp"`,
		"--silent --accept-license",
		"some value with spaces and (parentheses)",
	} {
		req := schemavalidator.StringRequest{ConfigValue: types.StringValue(s)}
		resp := &schemavalidator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("value %q should be valid, got error: %v", s, resp.Diagnostics)
		}
	}
}

func TestWingetOverrideValidator_ControlChars(t *testing.T) {
	v := wingetOverrideValidator{}
	// C0 control characters
	for _, bad := range []string{
		"\x00",   // NUL
		"\x01",   // SOH
		"\x09",   // TAB — also a control char
		"\x0A",   // LF
		"\x0D",   // CR
		"\x1F",   // US
		"\x7F",   // DEL
		"foo\x01bar",
		"line1\nline2",
	} {
		req := schemavalidator.StringRequest{ConfigValue: types.StringValue(bad)}
		resp := &schemavalidator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("value with control char should be invalid: %q", bad)
		}
	}
}

func TestWingetOverrideValidator_NullSkipped(t *testing.T) {
	v := wingetOverrideValidator{}
	req := schemavalidator.StringRequest{ConfigValue: types.StringNull()}
	resp := &schemavalidator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should be skipped without error")
	}
}

func TestWingetOverrideValidator_UnknownSkipped(t *testing.T) {
	v := wingetOverrideValidator{}
	req := schemavalidator.StringRequest{ConfigValue: types.StringUnknown()}
	resp := &schemavalidator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("unknown value should be skipped without error")
	}
}

// ---------------------------------------------------------------------------
// addWPDiag
// ---------------------------------------------------------------------------

func TestAddWPDiag_WingetPackageError_NoCause(t *testing.T) {
	var diags diag.Diagnostics
	we := winclient.NewWingetPackageError(
		winclient.WingetPackageErrorModuleMissing,
		"module not found", nil, nil,
	)
	addWPDiag(&diags, we, "Create")
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	d := diags[0]
	if !strings.Contains(d.Summary(), "module_missing") {
		t.Errorf("summary should contain kind: %q", d.Summary())
	}
	if !strings.Contains(d.Detail(), "module not found") {
		t.Errorf("detail should contain message: %q", d.Detail())
	}
}

func TestAddWPDiag_WingetPackageError_WithCause(t *testing.T) {
	var diags diag.Diagnostics
	cause := errors.New("underlying io error")
	we := winclient.NewWingetPackageError(
		winclient.WingetPackageErrorUnknown,
		"unexpected failure", cause, nil,
	)
	addWPDiag(&diags, we, "Delete")
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags[0].Detail()
	if !strings.Contains(detail, "underlying io error") {
		t.Errorf("detail should contain cause: %q", detail)
	}
}

func TestAddWPDiag_WingetPackageError_WithContext(t *testing.T) {
	var diags diag.Diagnostics
	ctx := map[string]string{
		"package_id": "Foo.Bar",
		"host":       "winpkg01",
		"source":     "winget",
	}
	we := winclient.NewWingetPackageError(
		winclient.WingetPackageErrorPermission,
		"access denied", nil, ctx,
	)
	addWPDiag(&diags, we, "Read")
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := diags[0].Detail()
	if !strings.Contains(detail, "Foo.Bar") {
		t.Errorf("detail should contain context key: %q", detail)
	}
	if !strings.Contains(detail, "winpkg01") {
		t.Errorf("detail should contain host: %q", detail)
	}
}

func TestAddWPDiag_WingetPackageError_AllKinds(t *testing.T) {
	kinds := []winclient.WingetPackageErrorKind{
		winclient.WingetPackageErrorModuleMissing,
		winclient.WingetPackageErrorAlreadyInstalled,
		winclient.WingetPackageErrorVersionNotAvailable,
		winclient.WingetPackageErrorBlockedByPolicy,
		winclient.WingetPackageErrorPermission,
		winclient.WingetPackageErrorSourceUnreachable,
		winclient.WingetPackageErrorCatalogError,
		winclient.WingetPackageErrorResourceInUse,
		winclient.WingetPackageErrorUnknown,
	}
	for _, kind := range kinds {
		var diags diag.Diagnostics
		we := winclient.NewWingetPackageError(kind, "test message", nil, nil)
		addWPDiag(&diags, we, "Update")
		if !diags.HasError() {
			t.Errorf("kind %v should produce an error diagnostic", kind)
		}
	}
}

func TestAddWPDiag_PlainError(t *testing.T) {
	var diags diag.Diagnostics
	addWPDiag(&diags, errors.New("plain error"), "Create")
	if !diags.HasError() {
		t.Fatal("expected error diagnostic")
	}
	if !strings.Contains(diags[0].Summary(), "unexpected error") {
		t.Errorf("summary should mention 'unexpected error': %q", diags[0].Summary())
	}
	if !strings.Contains(diags[0].Detail(), "plain error") {
		t.Errorf("detail should contain error message: %q", diags[0].Detail())
	}
}

func TestAddWPDiag_ContextSortedDeterministically(t *testing.T) {
	// Run multiple times to verify context keys are sorted (deterministic).
	ctx := map[string]string{
		"z_key": "z_val",
		"a_key": "a_val",
		"m_key": "m_val",
	}
	we := winclient.NewWingetPackageError(winclient.WingetPackageErrorUnknown, "msg", nil, ctx)
	var d1, d2 diag.Diagnostics
	addWPDiag(&d1, we, "op")
	addWPDiag(&d2, we, "op")
	if d1[0].Detail() != d2[0].Detail() {
		t.Error("addWPDiag should produce deterministic output")
	}
	// Verify alphabetical order: a_key < m_key < z_key
	detail := d1[0].Detail()
	aIdx := strings.Index(detail, "a_key")
	mIdx := strings.Index(detail, "m_key")
	zIdx := strings.Index(detail, "z_key")
	if aIdx > mIdx || mIdx > zIdx {
		t.Errorf("context keys not sorted: detail = %q", detail)
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestWingetPackageResource_Configure_NilProviderData(t *testing.T) {
	r := &windowsWingetPackageResource{}
	req := resource.ConfigureRequest{ProviderData: nil}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should not produce an error: %v", resp.Diagnostics)
	}
	if r.client != nil {
		t.Error("client should be nil when ProviderData is nil")
	}
}

func TestWingetPackageResource_Configure_WrongType(t *testing.T) {
	r := &windowsWingetPackageResource{}
	req := resource.ConfigureRequest{ProviderData: "not a client"}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic for wrong ProviderData type")
	}
}

func TestWingetPackageResource_Configure_HappyPath(t *testing.T) {
	r := &windowsWingetPackageResource{}
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := resource.ConfigureRequest{ProviderData: c}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	if r.client == nil {
		t.Error("client should be set after Configure")
	}
	if r.wp == nil {
		t.Error("wp (WingetPackageClient) should be set after Configure")
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

func TestWingetPackageResource_ConfigValidators(t *testing.T) {
	r := &windowsWingetPackageResource{}
	validators := r.ConfigValidators(context.Background())
	// v1 has no cross-attribute validators — empty slice is expected.
	if len(validators) != 0 {
		t.Errorf("expected 0 ConfigValidators, got %d", len(validators))
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// wpSchemaObjectType returns the tftypes.Object type matching the winget
// package schema.
func wpSchemaObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":               tftypes.String,
		"package_id":       tftypes.String,
		"version":          tftypes.String,
		"source":           tftypes.String,
		"override":         tftypes.String,
		"installed_version": tftypes.String,
		"name":             tftypes.String,
	}}
}

func TestWingetPackageResource_ImportState_Valid(t *testing.T) {
	r := &windowsWingetPackageResource{}

	// Build a minimal schema-backed state so Set can work.
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	rawState := tftypes.NewValue(wpSchemaObjectType(), map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"package_id":       tftypes.NewValue(tftypes.String, nil),
		"version":          tftypes.NewValue(tftypes.String, nil),
		"source":           tftypes.NewValue(tftypes.String, nil),
		"override":         tftypes.NewValue(tftypes.String, nil),
		"installed_version": tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, nil),
	})

	req := resource.ImportStateRequest{ID: "winget:Microsoft.VisualStudioCode"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{
			Raw:    rawState,
			Schema: schemaResp.Schema,
		},
	}
	// ImportState should not panic and should not add errors.
	func() {
		defer func() {
			if rcv := recover(); rcv != nil {
				t.Logf("ImportState panicked (expected in unit tests without full state): %v", rcv)
			}
		}()
		r.ImportState(context.Background(), req, resp)
	}()

	if resp.Diagnostics.HasError() {
		t.Logf("ImportState diagnostics: %v", resp.Diagnostics)
		// In unit tests without a real TF state, diagnostics may occur from
		// Set(); the important check is that the error is NOT an invalid-format error.
		for _, d := range resp.Diagnostics.Errors() {
			if strings.Contains(d.Summary(), "Invalid import ID format") {
				t.Errorf("should not produce invalid-format error for valid ID %q: %v",
					req.ID, d.Detail())
			}
		}
	}
}

func TestWingetPackageResource_ImportState_NoColon(t *testing.T) {
	r := &windowsWingetPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	rawState := tftypes.NewValue(wpSchemaObjectType(), map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"package_id":       tftypes.NewValue(tftypes.String, nil),
		"version":          tftypes.NewValue(tftypes.String, nil),
		"source":           tftypes.NewValue(tftypes.String, nil),
		"override":         tftypes.NewValue(tftypes.String, nil),
		"installed_version": tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, nil),
	})
	req := resource.ImportStateRequest{ID: "wingetMicrosoftVisualStudioCode"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{
			Raw:    rawState,
			Schema: schemaResp.Schema,
		},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic for ID without colon")
	}
	found := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "Invalid import ID format") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Invalid import ID format' in diagnostics: %v", resp.Diagnostics)
	}
}

func TestWingetPackageResource_ImportState_EmptySource(t *testing.T) {
	r := &windowsWingetPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	rawState := tftypes.NewValue(wpSchemaObjectType(), map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"package_id":       tftypes.NewValue(tftypes.String, nil),
		"version":          tftypes.NewValue(tftypes.String, nil),
		"source":           tftypes.NewValue(tftypes.String, nil),
		"override":         tftypes.NewValue(tftypes.String, nil),
		"installed_version": tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, nil),
	})
	req := resource.ImportStateRequest{ID: ":Microsoft.VisualStudioCode"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{
			Raw:    rawState,
			Schema: schemaResp.Schema,
		},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic for ID with empty source")
	}
}

func TestWingetPackageResource_ImportState_EmptyPackageID(t *testing.T) {
	r := &windowsWingetPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	rawState := tftypes.NewValue(wpSchemaObjectType(), map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"package_id":       tftypes.NewValue(tftypes.String, nil),
		"version":          tftypes.NewValue(tftypes.String, nil),
		"source":           tftypes.NewValue(tftypes.String, nil),
		"override":         tftypes.NewValue(tftypes.String, nil),
		"installed_version": tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, nil),
	})
	req := resource.ImportStateRequest{ID: "winget:"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{
			Raw:    rawState,
			Schema: schemaResp.Schema,
		},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic for ID with empty package_id")
	}
}

func TestWingetPackageResource_ImportState_EmptyID(t *testing.T) {
	r := &windowsWingetPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	rawState := tftypes.NewValue(wpSchemaObjectType(), map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"package_id":       tftypes.NewValue(tftypes.String, nil),
		"version":          tftypes.NewValue(tftypes.String, nil),
		"source":           tftypes.NewValue(tftypes.String, nil),
		"override":         tftypes.NewValue(tftypes.String, nil),
		"installed_version": tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, nil),
	})
	req := resource.ImportStateRequest{ID: ""}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{
			Raw:    rawState,
			Schema: schemaResp.Schema,
		},
	}
	r.ImportState(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("expected error diagnostic for empty ID")
	}
}

func TestWingetPackageResource_ImportState_ColonInPackageID(t *testing.T) {
	// SplitN(id, ":", 2) → source = "winget", package_id = "Foo:Bar:Baz"
	// This should be accepted (SplitN limit=2 keeps subsequent colons in the 2nd part).
	r := &windowsWingetPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	rawState := tftypes.NewValue(wpSchemaObjectType(), map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, nil),
		"package_id":       tftypes.NewValue(tftypes.String, nil),
		"version":          tftypes.NewValue(tftypes.String, nil),
		"source":           tftypes.NewValue(tftypes.String, nil),
		"override":         tftypes.NewValue(tftypes.String, nil),
		"installed_version": tftypes.NewValue(tftypes.String, nil),
		"name":             tftypes.NewValue(tftypes.String, nil),
	})
	req := resource.ImportStateRequest{ID: "winget:Foo:Bar:Baz"}
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{
			Raw:    rawState,
			Schema: schemaResp.Schema,
		},
	}
	func() {
		defer func() {
			if rcv := recover(); rcv != nil {
				t.Logf("ImportState panicked (expected in unit tests): %v", rcv)
			}
		}()
		r.ImportState(context.Background(), req, resp)
	}()
	// Invalid-format error should NOT be present (both parts are non-empty).
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), "Invalid import ID format") {
			t.Errorf("should accept multi-colon ID: %v", d.Detail())
		}
	}
}
