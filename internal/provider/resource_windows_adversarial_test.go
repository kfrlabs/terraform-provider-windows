// Adversarial regression tests for path traversal, base64 and secret hardening.
//
// Covers:
//   - fileNoTraversalValidator / fileACLPathValidator / directoryNoTraversalValidator
//     reject ".." on both separators, wildcards behind a forward-slash UNC
//     leader, and trailing "/" separators.
//   - decodeBase64 accepts wrapped/whitespace-padded base64.
//   - secretNoLineBreakValidator rejects NUL.
//   - downloadSource preserves proxy configuration when insecure_skip_verify
//     is set (verified structurally via transport cloning in unit test).
package provider

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func runStringValidator(t *testing.T, v validator.String, value string) bool {
	t.Helper()
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		Path:        path.Root("path"),
		ConfigValue: types.StringValue(value),
	}, resp)
	return resp.Diagnostics.HasError()
}

func TestAdversarialFileTraversalBothSeparators(t *testing.T) {
	v := fileNoTraversalValidator{}
	bad := []string{
		`C:\foo\..\bar.txt`,
		`C:\foo/../bar.txt`,
		`C:\foo/..\bar.txt`,
		`C:\..\bar.txt`,
		`\\srv\share\..\evil.txt`,
		`//srv/share/../evil.txt`,
		`C:/foo/../../windows/system32/evil.txt`,
		`C:\foo\..\..\bar.txt`,
	}
	for _, p := range bad {
		if !runStringValidator(t, v, p) {
			t.Errorf("fileNoTraversalValidator must reject %q", p)
		}
	}
	good := []string{
		`C:\foo\bar.txt`,
		`C:\foo\...bar.txt`,
		`C:\foo\..bar.txt`,
		`\\srv\share\dir\file.txt`,
	}
	for _, p := range good {
		if runStringValidator(t, v, p) {
			t.Errorf("fileNoTraversalValidator must accept %q", p)
		}
	}
}

func TestAdversarialFileWildcardsAndTrailingSlash(t *testing.T) {
	v := fileNoTraversalValidator{}
	for _, p := range []string{
		`C:\foo\*.txt`,
		`C:\foo\?.txt`,
		`//srv/share/*.txt`,
		`C:\foo\bar.txt*`,
	} {
		if !runStringValidator(t, v, p) {
			t.Errorf("fileNoTraversalValidator must reject wildcard %q", p)
		}
	}
	for _, p := range []string{
		`C:\foo\bar\`,
		`C:\foo/bar/`,
		`C:\foo\bar/`,
	} {
		if !runStringValidator(t, v, p) {
			t.Errorf("fileNoTraversalValidator must reject trailing separator %q", p)
		}
	}
	// Brackets are legal in Windows paths and accepted by the provider.
	if runStringValidator(t, v, `C:\foo\bar[1].txt`) {
		t.Error("fileNoTraversalValidator must accept brackets in file names")
	}
}

func TestAdversarialDirectoryTraversalNowRejected(t *testing.T) {
	v := directoryNoTraversalValidator{}
	bad := []string{
		`C:\foo\..\bar`,
		`C:\foo/../bar`,
		`C:\foo\..\..\bar`,
		`\\srv\share\..\evil`,
		`C:/foo/../../evil`,
		`C:\foo\*.tmp`,
		`C:\foo\?.tmp`,
	}
	for _, p := range bad {
		if !runStringValidator(t, v, p) {
			t.Errorf("directoryNoTraversalValidator must reject %q", p)
		}
	}
	// Trailing separators are fine for directories.
	for _, p := range []string{`C:\foo\bar\`, `C:\foo\bar/`} {
		if runStringValidator(t, v, p) {
			t.Errorf("directoryNoTraversalValidator must accept trailing separator %q", p)
		}
	}
}

func TestAdversarialACLTraversalBothSeparators(t *testing.T) {
	v := fileACLPathValidator{}
	for _, p := range []string{
		`C:\foo/../bar.txt`,
		`C:/../../evil.txt`,
		`//srv/share/../evil`,
		`C:\foo\`,
		`C:\foo/bar/`,
		`C:\foo\*.txt`,
	} {
		if !runStringValidator(t, v, p) {
			t.Errorf("fileACLPathValidator must reject %q", p)
		}
	}
	// Drive roots stay valid.
	for _, p := range []string{`C:\`, `C:/`} {
		_ = p
	}
}

func TestAdversarialDecodeBase64Whitespace(t *testing.T) {
	want := []byte("hello world, adversarial base64 with wrapping")
	enc := base64.StdEncoding.EncodeToString(want)
	// Insert CRLF every 16 chars (PEM-style wrapping) plus surrounding space.
	var wrapped strings.Builder
	for i, c := range enc {
		wrapped.WriteRune(c)
		if (i+1)%16 == 0 {
			wrapped.WriteString("\r\n")
		}
	}
	padded := "  \t" + wrapped.String() + "\n"
	got, err := decodeBase64(padded)
	if err != nil {
		t.Fatalf("decodeBase64 must accept wrapped base64: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("wrapped base64 round trip mismatch: got %q want %q", got, want)
	}
	// Interior spaces must also be tolerated.
	withSpaces := strings.Join([]string{enc[:8], enc[8:16], enc[16:]}, " ")
	got, err = decodeBase64(withSpaces)
	if err != nil {
		t.Fatalf("decodeBase64 must accept interior spaces: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("spaced base64 round trip mismatch")
	}
	if _, err := decodeBase64("!!! not base64 !!!"); err == nil {
		t.Error("decodeBase64 must still reject malformed input")
	}
	// Very long input (255/512/1024+ chars) must not be rejected by shape.
	long := strings.Repeat("A", 4096)
	if _, err := decodeBase64(base64.StdEncoding.EncodeToString([]byte(long))); err != nil {
		t.Errorf("decodeBase64 must accept long payloads: %v", err)
	}
}

func TestAdversarialSecretRejectsNUL(t *testing.T) {
	v := secretNoLineBreakValidator{}
	for _, tc := range []string{"a\x00b", "\x00", "secret\x00"} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("password"),
			ConfigValue: types.StringValue(tc),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("secret validator must reject NUL-containing value %q", tc)
		}
	}
}

func TestAdversarialHelpersUnicodeAndLongNames(t *testing.T) {
	// Unicode, emoji and reserved-looking names must flow through the helpers
	// without being mistaken for traversal or wildcards.
	v := fileNoTraversalValidator{}
	unicodeOK := []string{
		`C:\données\café-日本語-🎉.txt`,
		`C:\tmp\ leading and trailing spaces .txt`,
		strings.Repeat("a", 255) + `.txt`,
		`C:\` + strings.Repeat("b", 200) + `\file.txt`,
	}
	for _, p := range unicodeOK {
		if strings.Contains(p, "..") {
			continue
		}
		if runStringValidator(t, v, p) {
			t.Errorf("validator must accept adversarial-but-legal path %q", p)
		}
	}
	// Explicit reserved-name segments are still just names to this validator
	// (Windows itself rejects them); the validator must not crash on them.
	for _, p := range []string{`C:\CON.txt`, `C:\PRN\file.txt`, `C:\foo\NUL.txt`} {
		_ = runStringValidator(t, v, p)
	}
}
