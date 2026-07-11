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
//   - ConfigValidators: ExactlyOneOf source_path/source_url present
//   - ImportState: empty id, valid id, whitespace trimmed
//   - applyState: state-merge semantics on observable fields
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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
		"product_id", "display_name_pattern",
		"install_args", "uninstall_args", "uninstall_command",
		"valid_exit_codes", "working_directory",
		"timeout_seconds", "log_path", "environment",
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
	for _, s := range []string{"sha256:deadbeef", "sha1:00", "md5:abcd"} {
		if !lpChecksumRe.MatchString(s) {
			t.Errorf("expected %q to match", s)
		}
	}
	for _, s := range []string{"", "sha256:", "sha512:abcd", "deadbeef", "sha256:zz"} {
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
	c, err := winclient.New(winclient.Config{Host: "x", Username: "u", Password: "p"})
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
	if len(v) == 0 {
		t.Fatal("expected at least one ConfigValidator (ExactlyOneOf source_path/source_url)")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func lpNullRawState() tftypes.Value {
	str := tftypes.String
	b := tftypes.Bool
	num := tftypes.Number
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                   str,
		"name":                 str,
		"installer_type":       str,
		"source_path":          str,
		"source_url":           str,
		"checksum":             str,
		"insecure_skip_verify": b,
		"product_id":           str,
		"display_name_pattern": str,
		"install_args":         tftypes.List{ElementType: str},
		"uninstall_args":       tftypes.List{ElementType: str},
		"uninstall_command":    str,
		"valid_exit_codes":     tftypes.List{ElementType: num},
		"working_directory":    str,
		"timeout_seconds":      num,
		"log_path":             str,
		"environment":          tftypes.Map{ElementType: str},
		"installed_version":    str,
		"installed":            b,
		"install_date":         str,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"update": str,
			"delete": str,
		}},
	}}, map[string]tftypes.Value{
		"id":                   tftypes.NewValue(str, nil),
		"name":                 tftypes.NewValue(str, nil),
		"installer_type":       tftypes.NewValue(str, nil),
		"source_path":          tftypes.NewValue(str, nil),
		"source_url":           tftypes.NewValue(str, nil),
		"checksum":             tftypes.NewValue(str, nil),
		"insecure_skip_verify": tftypes.NewValue(b, nil),
		"product_id":           tftypes.NewValue(str, nil),
		"display_name_pattern": tftypes.NewValue(str, nil),
		"install_args":         tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"uninstall_args":       tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"uninstall_command":    tftypes.NewValue(str, nil),
		"valid_exit_codes":     tftypes.NewValue(tftypes.List{ElementType: num}, nil),
		"working_directory":    tftypes.NewValue(str, nil),
		"timeout_seconds":      tftypes.NewValue(num, nil),
		"log_path":             tftypes.NewValue(str, nil),
		"environment":          tftypes.NewValue(tftypes.Map{ElementType: str}, nil),
		"installed_version":    tftypes.NewValue(str, nil),
		"installed":            tftypes.NewValue(b, nil),
		"install_date":         tftypes.NewValue(str, nil),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"update": str,
			"delete": str,
		}}, nil),
	})
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
