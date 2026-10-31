// Package provider — unit tests for the windows_file resource.
//
// Focus: schema shape (including the write-only contract), content encoding
// (EC-9, EC-10), path validation (CV-7, EC-11) and diagnostic mapping.
// End-to-end CRUD against a real host lives in resource_windows_file_acc_test.go.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func fileSchema(t *testing.T) schema.Schema {
	t.Helper()
	resp := &resource.SchemaResponse{}
	NewWindowsFileResource().(*windowsFileResource).Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	return resp.Schema
}

func TestWindowsFileResource_Metadata(t *testing.T) {
	resp := &resource.MetadataResponse{}
	NewWindowsFileResource().Metadata(context.Background(),
		resource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_file" {
		t.Errorf("TypeName = %q, want windows_file", resp.TypeName)
	}
}

func TestWindowsFileResource_SchemaShape(t *testing.T) {
	s := fileSchema(t)
	for _, k := range []string{
		"id", "path", "content", "content_base64", "content_wo", "content_base64_wo",
		"content_wo_version", "source", "source_url", "source_url_sha256",
		"source_url_headers", "source_url_insecure_skip_verify", "download_on",
		"encoding", "overwrite", "create_parents", "attributes",
		"content_sha256", "size_bytes", "last_write_time", "timeouts",
	} {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema is missing attribute %q", k)
		}
	}

	// The write-only contract: sensitive, write-only, never computed.
	for _, k := range []string{"content_wo", "content_base64_wo"} {
		a, ok := s.Attributes[k].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s is not a StringAttribute", k)
		}
		if !a.WriteOnly {
			t.Errorf("%s must be WriteOnly", k)
		}
		if !a.Sensitive {
			t.Errorf("%s must be Sensitive", k)
		}
		if a.Computed {
			t.Errorf("%s must not be Computed", k)
		}
	}

	// Ownership/ACL are out of scope: they belong to windows_file_acl.
	for _, k := range []string{"owner", "permissions", "acl", "access_rule"} {
		if _, ok := s.Attributes[k]; ok {
			t.Errorf("attribute %q must not exist on windows_file; ACLs belong to windows_file_acl", k)
		}
	}

	// path is ForceNew.
	p, ok := s.Attributes["path"].(schema.StringAttribute)
	if !ok || !p.Required || len(p.PlanModifiers) == 0 {
		t.Error("path must be Required with a RequiresReplace plan modifier")
	}
}

func TestWindowsFileResource_ConfigValidatorsPresent(t *testing.T) {
	r := NewWindowsFileResource().(*windowsFileResource)
	// CV-1, the four encoding conflicts and the cross-field validator live at
	// resource level; CV-2 and CV-5 are attribute-level AlsoRequires.
	if got := len(r.ConfigValidators(context.Background())); got < 6 {
		t.Errorf("got %d resource-level config validators, want at least 6", got)
	}

	// CV-2 must be one-directional: a write-only content requires the version
	// token, but the version token must not force both write-only variants.
	s := fileSchema(t)
	for _, k := range []string{"content_wo", "content_base64_wo"} {
		a := s.Attributes[k].(schema.StringAttribute)
		if len(a.Validators) == 0 {
			t.Errorf("%s must require content_wo_version", k)
		}
	}
}

// CV-7 / EC-11: path shape.
func TestWindowsFilePathRegex(t *testing.T) {
	valid := []string{
		`C:\inetpub\wwwroot\web.config`,
		`D:\data\file with spaces.txt`,
		`\\srv01\share\app.ini`,
		`C:\tmp\it's.txt`,
	}
	invalid := []string{
		`relative\path.txt`,
		`/etc/passwd`,
		`C:file.txt`,
		``,
	}
	for _, v := range valid {
		if !windowsFilePathRegex.MatchString(v) {
			t.Errorf("%q should be accepted", v)
		}
	}
	for _, v := range invalid {
		if windowsFilePathRegex.MatchString(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

// EC-9 / EC-10: encodings are byte-exact and never rewrite line endings.
func TestEncodeFileContent(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		enc     string
		want    []byte
		wantErr bool
	}{
		{"utf8 default", "abc", "", []byte("abc"), false},
		{"utf8", "caf\u00e9", fileEncodingUTF8, []byte{'c', 'a', 'f', 0xC3, 0xA9}, false},
		{"utf8 bom", "a", fileEncodingUTF8BOM, []byte{0xEF, 0xBB, 0xBF, 'a'}, false},
		{"utf16le", "ab", fileEncodingUTF16LE, []byte{'a', 0, 'b', 0}, false},
		{"utf16le bom", "a", fileEncodingUTF16LEBOM, []byte{0xFF, 0xFE, 'a', 0}, false},
		{"latin1", "caf\u00e9", fileEncodingLatin1, []byte{'c', 'a', 'f', 0xE9}, false},
		{"ascii rejects non-ascii", "caf\u00e9", fileEncodingASCII, nil, true},
		{"latin1 rejects cjk", "\u6f22", fileEncodingLatin1, nil, true},
		{"unknown encoding", "a", "ebcdic", nil, true},
		{"crlf preserved verbatim", "a\r\nb", fileEncodingUTF8, []byte("a\r\nb"), false},
		{"lf preserved verbatim", "a\nb", fileEncodingUTF8, []byte("a\nb"), false},
		{"empty content is a 0-byte file (EC-8)", "", fileEncodingUTF8, []byte{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeFileContent(tc.in, tc.enc)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != string(tc.want) {
				t.Errorf("got % x, want % x", got, tc.want)
			}
		})
	}
}

func TestSha256HexAndBase64RoundTrip(t *testing.T) {
	// Well-known digest of the empty input.
	if got := sha256Hex(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("sha256Hex(nil) = %s", got)
	}
	b, err := decodeBase64(encodeBase64([]byte("hello")))
	if err != nil || string(b) != "hello" {
		t.Errorf("round trip failed: %q, %v", b, err)
	}
	if _, err := decodeBase64("!!!"); err == nil {
		t.Error("expected an error for malformed base64")
	}
}

func TestAddFileDiag_ActionableMessages(t *testing.T) {
	cases := []struct {
		kind     winclient.FileErrorKind
		wantHint string
	}{
		{winclient.FileErrorAlreadyExists, "overwrite = true"},
		{winclient.FileErrorPathNotFound, "create_parents = true"},
		{winclient.FileErrorTypeConflict, "files only"},
		{winclient.FileErrorPermission, "elevated account"},
		{winclient.FileErrorLocked, "retried three times"},
		{winclient.FileErrorDiskFull, "left untouched"},
		{winclient.FileErrorChecksumMismatch, "source_url_sha256"},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			var diags diag.Diagnostics
			addFileDiag(&diags, "Create", winclient.NewFileError(tc.kind, "boom", nil, nil))
			if !diags.HasError() {
				t.Fatal("expected an error diagnostic")
			}
			if !strings.Contains(diags.Errors()[0].Detail(), tc.wantHint) {
				t.Errorf("detail %q should guide the user with %q", diags.Errors()[0].Detail(), tc.wantHint)
			}
		})
	}
}

func TestNullifyWriteOnly(t *testing.T) {
	m := &windowsFileModel{}
	m.ContentWO = typesStringValue("secret")
	m.ContentBase64WO = typesStringValue("c2VjcmV0")
	nullifyWriteOnly(m)
	if !m.ContentWO.IsNull() || !m.ContentBase64WO.IsNull() {
		t.Error("write-only values must never reach the state")
	}
}

func typesStringValue(s string) types.String { return types.StringValue(s) }

// ---------------------------------------------------------------------------
// fileCrossFieldValidator: source_url integrity coherence (issue #204,
// mirrors legacyPackageSourceValidator posture from issue #175)
// ---------------------------------------------------------------------------

// fileSourceTestConfig builds a tfsdk.Config driving the cross-field
// validator. Empty sourceURL/sha256/downloadOn mean null; insecure is always
// set explicitly since the attribute defaults to false.
func fileSourceTestConfig(t *testing.T, schemaResp *resource.SchemaResponse, sourceURL, sha256, downloadOn string, insecure bool) tfsdk.Config {
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
		"id":                              str,
		"path":                            str,
		"content":                         str,
		"content_base64":                  str,
		"content_wo":                      str,
		"content_base64_wo":               str,
		"content_wo_version":              str,
		"source":                          str,
		"source_url":                      str,
		"source_url_sha256":               str,
		"source_url_headers":              tftypes.Map{ElementType: str},
		"source_url_insecure_skip_verify": b,
		"download_on":                     str,
		"encoding":                        str,
		"overwrite":                       b,
		"create_parents":                  b,
		"attributes":                      tftypes.List{ElementType: str},
		"content_sha256":                  str,
		"size_bytes":                      num,
		"last_write_time":                 str,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}},
	}}, map[string]tftypes.Value{
		"id":                              tftypes.NewValue(str, nil),
		"path":                            tftypes.NewValue(str, `C:\Temp\file.bin`),
		"content":                         tftypes.NewValue(str, nil),
		"content_base64":                  tftypes.NewValue(str, nil),
		"content_wo":                      tftypes.NewValue(str, nil),
		"content_base64_wo":               tftypes.NewValue(str, nil),
		"content_wo_version":              tftypes.NewValue(str, nil),
		"source":                          tftypes.NewValue(str, nil),
		"source_url":                      strOrNull(sourceURL),
		"source_url_sha256":               strOrNull(sha256),
		"source_url_headers":              tftypes.NewValue(tftypes.Map{ElementType: str}, nil),
		"source_url_insecure_skip_verify": tftypes.NewValue(b, insecure),
		"download_on":                     strOrNull(downloadOn),
		"encoding":                        tftypes.NewValue(str, nil),
		"overwrite":                       tftypes.NewValue(b, nil),
		"create_parents":                  tftypes.NewValue(b, nil),
		"attributes":                      tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"content_sha256":                  tftypes.NewValue(str, nil),
		"size_bytes":                      tftypes.NewValue(num, nil),
		"last_write_time":                 tftypes.NewValue(str, nil),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}}, nil),
	})
	return tfsdk.Config{Schema: schemaResp.Schema, Raw: raw}
}

func fileSourceValidatorDiags(t *testing.T, sourceURL, sha256, downloadOn string, insecure bool) diag.Diagnostics {
	t.Helper()
	r := NewWindowsFileResource().(*windowsFileResource)
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	var validator fileCrossFieldValidator
	for _, v := range r.ConfigValidators(context.Background()) {
		if fv, ok := v.(fileCrossFieldValidator); ok {
			validator = fv
		}
	}
	resp := &resource.ValidateConfigResponse{}
	validator.ValidateResource(context.Background(), resource.ValidateConfigRequest{
		Config: fileSourceTestConfig(t, schemaResp, sourceURL, sha256, downloadOn, insecure),
	}, resp)
	return resp.Diagnostics
}

func fileDiagCounts(diags diag.Diagnostics) (errors, warnings int) {
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

func TestFileSourceValidator(t *testing.T) {
	const digest = "9f2b1c1f0a7e4d3b8c6a5e4f3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0"
	cases := []struct {
		name       string
		sourceURL  string
		sha256     string
		downloadOn string
		insecure   bool
		wantErrors int
		wantWarns  int
		wantSubstr string // expected in an error/warning summary or detail
	}{
		{"http without digest fails", "http://mirror.internal/file.bin", "", "", false, 1, 0, "source_url_sha256 is required for http://"},
		{"HTTP uppercase scheme without digest fails", "HTTP://mirror.internal/file.bin", "", "", false, 1, 0, "source_url_sha256 is required for http://"},
		{"http without digest fails regardless of download_on", "http://mirror.internal/file.bin", "", "target", false, 2, 0, "source_url_sha256 is required for http://"},
		{"http with digest is clean", "http://mirror.internal/file.bin", digest, "", false, 0, 0, ""},
		{"https without digest warns", "https://mirror.internal/file.bin", "", "", false, 0, 1, "Unpinned source_url"},
		{"https without digest warns integrity-first", "https://mirror.internal/file.bin", "", "", false, 0, 1, "compromised mirror"},
		{"https with digest is clean", "https://mirror.internal/file.bin", digest, "", false, 0, 0, ""},
		{"target without digest still fails as CV-4", "https://mirror.internal/file.bin", "", "target", false, 1, 0, "requires source_url_sha256"},
		{"target with digest is clean", "https://mirror.internal/file.bin", digest, "target", false, 0, 0, ""},
		{"no source_url is clean", "", "", "", false, 0, 0, ""},
		{"insecure skip verify warns", "https://mirror.internal/file.bin", digest, "", true, 0, 1, "TLS verification disabled"},
		{"insecure skip verify without digest voids origin check", "https://mirror.internal/file.bin", "", "", true, 0, 2, "only remaining origin check"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := fileSourceValidatorDiags(t, tc.sourceURL, tc.sha256, tc.downloadOn, tc.insecure)
			gotErr, gotWarn := fileDiagCounts(diags)
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

// The source_url schema regex is case-insensitive so that an uppercase
// HTTP:// URL passes schema validation and reaches the case-insensitive
// integrity gate (which the blessed HTTP:// validator case relies on).
func TestFileSourceURLSchemaAcceptsUppercaseScheme(t *testing.T) {
	s := fileSchema(t)
	attr, ok := s.Attributes["source_url"].(schema.StringAttribute)
	if !ok {
		t.Fatal("source_url is not a StringAttribute")
	}
	for _, raw := range []string{"http://mirror.internal/file.bin", "HTTP://mirror.internal/file.bin", "HTTPS://mirror.internal/file.bin"} {
		for _, sv := range attr.Validators {
			req := validator.StringRequest{
				Path:        path.Root("source_url"),
				ConfigValue: types.StringValue(raw),
			}
			resp := &validator.StringResponse{}
			sv.ValidateString(context.Background(), req, resp)
			if resp.Diagnostics.HasError() {
				t.Errorf("source_url %q should pass schema validation, got: %v", raw, resp.Diagnostics)
			}
		}
	}
}

// An unknown (or absent) source_url must not produce spurious unpinned-URL
// warnings, and the insecure_skip_verify detail extension must stay gated on
// a known URL, mirroring legacy_package's early return on null/unknown.
func TestFileSourceValidator_UnknownSourceURL(t *testing.T) {
	t.Run("unknown source_url is quiet", func(t *testing.T) {
		diags := fileSourceValidatorDiagsUnknownURL(t, "", false)
		if gotErr, gotWarn := fileDiagCounts(diags); gotErr != 0 || gotWarn != 0 {
			t.Errorf("errors=%d warnings=%d, want 0/0 (diags: %v)", gotErr, gotWarn, diags)
		}
	})
	t.Run("unknown source_url with insecure warns once without origin-check extension", func(t *testing.T) {
		diags := fileSourceValidatorDiagsUnknownURL(t, "", true)
		gotErr, gotWarn := fileDiagCounts(diags)
		if gotErr != 0 || gotWarn != 1 {
			t.Fatalf("errors=%d warnings=%d, want 0/1 (diags: %v)", gotErr, gotWarn, diags)
		}
		for _, d := range diags {
			if strings.Contains(d.Detail(), "only remaining origin check") {
				t.Errorf("unknown source_url must not extend the insecure warning with the origin-check detail, got: %v", diags)
			}
		}
	})
}

// fileSourceValidatorDiagsUnknownURL drives fileCrossFieldValidator with an
// unknown source_url (sha256 null unless given, download_on null).
func fileSourceValidatorDiagsUnknownURL(t *testing.T, sha256 string, insecure bool) diag.Diagnostics {
	t.Helper()
	r := NewWindowsFileResource().(*windowsFileResource)
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	var v fileCrossFieldValidator
	for _, cv := range r.ConfigValidators(context.Background()) {
		if fv, ok := cv.(fileCrossFieldValidator); ok {
			v = fv
		}
	}
	str := tftypes.String
	b := tftypes.Bool
	num := tftypes.Number
	shaVal := tftypes.NewValue(str, nil)
	if sha256 != "" {
		shaVal = tftypes.NewValue(str, sha256)
	}
	raw := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                              str,
		"path":                            str,
		"content":                         str,
		"content_base64":                  str,
		"content_wo":                      str,
		"content_base64_wo":               str,
		"content_wo_version":              str,
		"source":                          str,
		"source_url":                      str,
		"source_url_sha256":               str,
		"source_url_headers":              tftypes.Map{ElementType: str},
		"source_url_insecure_skip_verify": b,
		"download_on":                     str,
		"encoding":                        str,
		"overwrite":                       b,
		"create_parents":                  b,
		"attributes":                      tftypes.List{ElementType: str},
		"content_sha256":                  str,
		"size_bytes":                      num,
		"last_write_time":                 str,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}},
	}}, map[string]tftypes.Value{
		"id":                              tftypes.NewValue(str, nil),
		"path":                            tftypes.NewValue(str, `C:\Temp\file.bin`),
		"content":                         tftypes.NewValue(str, nil),
		"content_base64":                  tftypes.NewValue(str, nil),
		"content_wo":                      tftypes.NewValue(str, nil),
		"content_base64_wo":               tftypes.NewValue(str, nil),
		"content_wo_version":              tftypes.NewValue(str, nil),
		"source":                          tftypes.NewValue(str, nil),
		"source_url":                      tftypes.NewValue(str, tftypes.UnknownValue),
		"source_url_sha256":               shaVal,
		"source_url_headers":              tftypes.NewValue(tftypes.Map{ElementType: str}, nil),
		"source_url_insecure_skip_verify": tftypes.NewValue(b, insecure),
		"download_on":                     tftypes.NewValue(str, nil),
		"encoding":                        tftypes.NewValue(str, nil),
		"overwrite":                       tftypes.NewValue(b, nil),
		"create_parents":                  tftypes.NewValue(b, nil),
		"attributes":                      tftypes.NewValue(tftypes.List{ElementType: str}, nil),
		"content_sha256":                  tftypes.NewValue(str, nil),
		"size_bytes":                      tftypes.NewValue(num, nil),
		"last_write_time":                 tftypes.NewValue(str, nil),
		"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": str,
			"read":   str,
			"update": str,
			"delete": str,
		}}, nil),
	})
	resp := &resource.ValidateConfigResponse{}
	v.ValidateResource(context.Background(), resource.ValidateConfigRequest{
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: raw},
	}, resp)
	return resp.Diagnostics
}
