// Package winclient — unit tests for FileClientImpl.
//
// The package-level runFilePowerShell hook is stubbed, so no SSH connection is
// needed. Coverage focus:
//
//	T-1   content travels on stdin and never appears in the script body
//	EC-2  directory at the target path -> type_conflict
//	EC-3  existing file with overwrite=false -> already_exists
//	EC-4  Read on a missing file -> (nil, nil), not an error
//	EC-12 Delete of a missing file -> silent success
//	EC-14 psQuote hardening for paths containing a quote
//	CV-4  download_on=target without a pinned digest is refused Go-side
//	T-2   content size cap and base64 validation
package winclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newFileTestClient(t *testing.T) (*Client, *FileClientImpl) {
	t.Helper()
	c, err := New(Config{
		Host:                  "winfile01",
		Username:              "u",
		Password:              "p",
		Timeout:               30 * time.Second,
		InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, NewFileClient(c)
}

func stubFileRun(fn func(ctx context.Context, c *Client, script, stdin string) (string, string, error)) func() {
	prev := runFilePowerShell
	runFilePowerShell = fn
	return func() { runFilePowerShell = prev }
}

func fileOKEnvelope(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b) + "\n"
}

func fileErrEnvelope(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": false, "kind": kind, "message": msg})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b) + "\n"
}

func sampleFileData() map[string]any {
	return map[string]any{
		"found":           true,
		"sha256":          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"size_bytes":      12,
		"last_write_time": "2026-09-30T19:00:00Z",
		"attributes":      []string{"archive"},
	}
}

// T-1: the payload must be streamed on stdin, never interpolated in the script.
func TestFileSet_ContentTravelsOnStdinOnly(t *testing.T) {
	_, fc := newFileTestClient(t)

	secret := "super-secret-connection-string"
	payload := base64.StdEncoding.EncodeToString([]byte(secret))

	var gotScript, gotStdin string
	defer stubFileRun(func(_ context.Context, _ *Client, script, stdin string) (string, string, error) {
		gotScript, gotStdin = script, stdin
		return fileOKEnvelope(t, sampleFileData()), "", nil
	})()

	if _, err := fc.Set(context.Background(), FileInput{
		Path:          `C:\inetpub\wwwroot\web.config`,
		ContentBase64: payload,
		Overwrite:     true,
		CreateParents: true,
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if strings.Contains(gotScript, payload) || strings.Contains(gotScript, secret) {
		t.Error("content leaked into the script body; it must travel on stdin only (T-1)")
	}
	if gotStdin != payload {
		t.Errorf("stdin = %q, want the base64 payload", gotStdin)
	}
	if !strings.Contains(gotScript, "[Console]::In.ReadToEnd()") {
		t.Error("script should read its payload from stdin")
	}
	if !strings.Contains(gotScript, "[System.IO.File]::Replace") {
		t.Error("script should use Replace() to preserve the target ACL (EC-15)")
	}
}

// EC-14: a path containing a single quote must be escaped, not concatenated.
func TestFileSet_PathQuotingHardening(t *testing.T) {
	_, fc := newFileTestClient(t)

	var gotScript string
	defer stubFileRun(func(_ context.Context, _ *Client, script, _ string) (string, string, error) {
		gotScript = script
		return fileOKEnvelope(t, sampleFileData()), "", nil
	})()

	evil := `C:\tmp\it's'; Remove-Item C:\ -Recurse; '.txt`
	if _, err := fc.Set(context.Background(), FileInput{Path: evil, ContentBase64: "", Overwrite: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if strings.Contains(gotScript, "Remove-Item C:\\ -Recurse;\n") {
		t.Error("path was not quoted safely")
	}
	if !strings.Contains(gotScript, "''") {
		t.Error("expected doubled single quotes from psQuote")
	}
}

func TestFileSet_ErrorKinds(t *testing.T) {
	cases := []struct {
		name string
		kind string
		want FileErrorKind
	}{
		{"directory at path (EC-2)", "type_conflict", FileErrorTypeConflict},
		{"exists with overwrite=false (EC-3)", "already_exists", FileErrorAlreadyExists},
		{"locked by another process (EC-7)", "file_locked", FileErrorLocked},
		{"disk full (EC-13)", "disk_full", FileErrorDiskFull},
		{"bad checksum (EC-16)", "checksum_mismatch", FileErrorChecksumMismatch},
		{"unmapped kind falls back", "wat", FileErrorUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, fc := newFileTestClient(t)
			defer stubFileRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
				return fileErrEnvelope(t, tc.kind, "boom"), "", nil
			})()
			_, err := fc.Set(context.Background(), FileInput{Path: `C:\a.txt`, ContentBase64: ""})
			if !IsFileError(err, tc.want) {
				t.Fatalf("err = %v, want kind %s", err, tc.want)
			}
		})
	}
}

// EC-4: a missing file is not an error, it is an empty state.
func TestFileRead_MissingFileReturnsNilNil(t *testing.T) {
	_, fc := newFileTestClient(t)
	defer stubFileRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return fileOKEnvelope(t, map[string]any{"found": false}), "", nil
	})()

	st, err := fc.Read(context.Background(), `C:\missing.txt`)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st != nil {
		t.Fatalf("state = %+v, want nil", st)
	}
}

// D-1: Read must not ask the host for file bytes.
func TestFileRead_NeverTransfersContent(t *testing.T) {
	_, fc := newFileTestClient(t)
	var gotScript string
	defer stubFileRun(func(_ context.Context, _ *Client, script, _ string) (string, string, error) {
		gotScript = script
		return fileOKEnvelope(t, sampleFileData()), "", nil
	})()

	st, err := fc.Read(context.Background(), `C:\a.txt`)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if st == nil || st.SizeBytes != 12 || len(st.Attributes) != 1 || st.Attributes[0] != "archive" {
		t.Fatalf("unexpected state %+v", st)
	}
	if strings.Contains(gotScript, "ReadAllBytes") || strings.Contains(gotScript, "ToBase64String") {
		t.Error("Read must never pull file content back (D-1)")
	}
}

// Import path (b): content is returned below the ceiling, flagged above it.
func TestFileReadContent_TruncationCeiling(t *testing.T) {
	_, fc := newFileTestClient(t)
	defer stubFileRun(func(_ context.Context, _ *Client, script, _ string) (string, string, error) {
		if !strings.Contains(script, "1048576") {
			t.Errorf("expected the import ceiling in the script, got:\n%s", script)
		}
		return fileOKEnvelope(t, map[string]any{
			"found": true, "truncated": true, "size_bytes": 5 << 20,
			"sha256": "abc", "content_base64": "",
		}), "", nil
	})()

	c, err := fc.ReadContent(context.Background(), `C:\big.bin`, FileImportMaxBytes)
	if err != nil {
		t.Fatalf("ReadContent: %v", err)
	}
	if c == nil || !c.Truncated || c.ContentBase64 != "" {
		t.Fatalf("expected a truncated, empty payload, got %+v", c)
	}
}

// EC-12: deleting an absent file is a silent success.
func TestFileDelete_Idempotent(t *testing.T) {
	_, fc := newFileTestClient(t)
	defer stubFileRun(func(_ context.Context, _ *Client, _, _ string) (string, string, error) {
		return fileOKEnvelope(t, map[string]any{"deleted": false, "reason": "not_found"}), "", nil
	})()

	if err := fc.Delete(context.Background(), `C:\gone.txt`); err != nil {
		t.Fatalf("Delete should be idempotent, got %v", err)
	}
}

// CV-4: the host downloading on its own is only acceptable with a pinned digest.
func TestBuildFileSetScript_TargetDownloadRequiresChecksum(t *testing.T) {
	_, _, err := buildFileSetScript(FileInput{
		Path:             `C:\tmp\app.msi`,
		DownloadOnTarget: true,
		SourceURL:        "https://repo.example.com/app.msi",
	})
	if !IsFileError(err, FileErrorInvalidInput) {
		t.Fatalf("err = %v, want invalid_input", err)
	}

	script, stdin, err := buildFileSetScript(FileInput{
		Path:             `C:\tmp\app.msi`,
		DownloadOnTarget: true,
		SourceURL:        "https://repo.example.com/app.msi",
		SourceURLSHA256:  strings.Repeat("a", 64),
		SourceURLHeaders: map[string]string{"Authorization": "Bearer t", "Accept": "*/*"},
	})
	if err != nil {
		t.Fatalf("buildFileSetScript: %v", err)
	}
	if stdin != "" {
		t.Error("target-side download must not use stdin")
	}
	if !strings.Contains(script, "Invoke-WebRequest") {
		t.Error("expected a target-side download")
	}
	// Deterministic, sorted header rendering.
	if !strings.Contains(script, "@{'Accept' = '*/*'; 'Authorization' = 'Bearer t'}") {
		t.Errorf("headers not rendered deterministically:\n%s", script)
	}
}

// T-2: base64 validity and the hard size cap are enforced before transport.
func TestValidateFileContentBase64(t *testing.T) {
	if _, err := ValidateFileContentBase64("not base64!!"); !IsFileError(err, FileErrorInvalidInput) {
		t.Errorf("expected invalid_input for malformed base64, got %v", err)
	}
	if n, err := ValidateFileContentBase64(base64.StdEncoding.EncodeToString([]byte("hello"))); err != nil || n != 5 {
		t.Errorf("size = %d, err = %v; want 5, nil", n, err)
	}
	tooBig := base64.StdEncoding.EncodeToString(make([]byte, FileMaxContentBytes+1))
	if _, err := ValidateFileContentBase64(tooBig); !IsFileError(err, FileErrorInvalidInput) {
		t.Errorf("expected invalid_input above the cap, got %v", err)
	}
}

func TestNormaliseFileAttributes(t *testing.T) {
	got, err := NormaliseFileAttributes([]string{"readonly", "hidden", "hidden"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(got, ",") != "hidden,readonly" {
		t.Errorf("got %v, want a deduplicated, stable order", got)
	}
	if _, err := NormaliseFileAttributes([]string{"compressed"}); !IsFileError(err, FileErrorInvalidInput) {
		t.Errorf("expected invalid_input for an unknown attribute, got %v", err)
	}
	// EC/CV-6.
	if _, err := NormaliseFileAttributes([]string{"system", "temporary"}); !IsFileError(err, FileErrorInvalidInput) {
		t.Errorf("system + temporary must be rejected, got %v", err)
	}
}

func TestPsHeadersHashtable_Empty(t *testing.T) {
	if got := psHeadersHashtable(nil); got != "@{}" {
		t.Errorf("got %q, want @{}", got)
	}
}
