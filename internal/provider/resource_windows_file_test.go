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
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"

	"github.com/hashicorp/terraform-plugin-framework/types"

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
