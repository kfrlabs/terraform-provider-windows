// Package winclient — unit tests for SmbShareClient.
//
// These tests stub the package-level seam runSmbSharePowerShell to inject
// scripted stdout/stderr/err triples. They cover the edge cases from the
// windows_smb_share spec (issue #221):
//
//	EC-1  Share absent in Read           -> (nil, nil)
//	EC-2  Create on existing share       -> already_exists + import hint
//	EC-3  Share path missing             -> path_not_found
//	EC-4  Trustee unresolvable           -> principal_not_found
//	EC-5  Delete already absent          -> no-op, no error
//	EC-6  Admin/auchen share import      -> refused at the provider layer
//	EC-7  LanmanServer stopped           -> server_service_unavailable
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func newSmbTestClient(t *testing.T) *Client {
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

// stubSmbRun replaces runSmbSharePowerShell for the duration of a test.
func stubSmbRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runSmbSharePowerShell
	runSmbSharePowerShell = fn
	return func() { runSmbSharePowerShell = prev }
}

func smbOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func smbErr(t *testing.T, kind, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok":      false,
		"kind":    kind,
		"message": msg,
		"context": map[string]string{},
	})
	if err != nil {
		t.Fatalf("marshal err: %v", err)
	}
	return string(b) + "\n"
}

func fakeSmbData(name string) map[string]any {
	return map[string]any{
		"found":                   true,
		"name":                    name,
		"path":                    `D:\Shares\Finance`,
		"description":             "Finance share",
		"folder_enumeration_mode": "AccessBased",
		"caching_mode":            "None",
		"concurrent_user_limit":   0,
		"encrypt_data":            true,
		"special":                 false,
		"full_access":             []any{map[string]any{"name": `BUILTIN\Administrators`, "sid": "S-1-5-32-544"}},
		"change_access":           []any{},
		"read_access":             []any{map[string]any{"name": "Everyone", "sid": "S-1-1-1"}},
		"no_access":               []any{},
	}
}

// -----------------------------------------------------------------------------
// SmbShareError type
// -----------------------------------------------------------------------------

func TestSmbShareError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	e := NewSmbShareError(SmbShareErrorAccessDenied, "denied", cause, map[string]string{"name": "Finance"})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "underlying") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewSmbShareError(SmbShareErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestSmbShareError_Is_And_IsSmbShareError(t *testing.T) {
	e := NewSmbShareError(SmbShareErrorNotFound, "x", nil, nil)
	if !errors.Is(e, ErrSmbShareNotFound) {
		t.Error("errors.Is(ErrSmbShareNotFound) should match by kind")
	}
	if errors.Is(e, ErrSmbShareAccessDenied) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsSmbShareError(e, SmbShareErrorNotFound) {
		t.Error("IsSmbShareError should match")
	}
	if IsSmbShareError(errors.New("plain"), SmbShareErrorNotFound) {
		t.Error("IsSmbShareError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-SmbShareError should be false")
	}
}

func TestMapSmbShareKind(t *testing.T) {
	cases := map[string]SmbShareErrorKind{
		"not_found":                  SmbShareErrorNotFound,
		"already_exists":             SmbShareErrorAlreadyExists,
		"path_not_found":             SmbShareErrorPathNotFound,
		"permission_denied":          SmbShareErrorAccessDenied,
		"invalid_name":               SmbShareErrorInvalidName,
		"principal_not_found":        SmbShareErrorPrincipalNotFound,
		"server_service_unavailable": SmbShareErrorServerServiceUnavailable,
		"":                           SmbShareErrorUnknown,
		"weird_kind":                 SmbShareErrorUnknown,
	}
	for in, want := range cases {
		if got := mapSmbShareKind(in); got != want {
			t.Errorf("mapSmbShareKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// ValidateSmbShareName / NormalizeSmbSharePath
// -----------------------------------------------------------------------------

func TestValidateSmbShareName(t *testing.T) {
	valid := []string{"Finance", "finance-data_2026", "S-1-5-32-544-data", strings.Repeat("a", 80)}
	for _, n := range valid {
		if err := ValidateSmbShareName(n); err != nil {
			t.Errorf("name %q should be valid, got %v", n, err)
		}
	}
	invalid := []string{
		"",
		strings.Repeat("a", 81),
		`a\b`, `a/b`, "a[b", "a]b", "a:b", "a|b", "a<b", "a>b",
		"a+b", "a=b", "a;b", "a,b", "a*b", "a?b", `a"b`,
		"a\x00b", "IPC$", "ipc$", "ADMIN$", "C$", "z$",
	}
	for _, n := range invalid {
		err := ValidateSmbShareName(n)
		if !IsSmbShareError(err, SmbShareErrorInvalidName) {
			t.Errorf("name %q should yield invalid_name, got %v", n, err)
		}
	}
}

func TestNormalizeSmbSharePath(t *testing.T) {
	got, err := NormalizeSmbSharePath(`D:\Shares\Finance\`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != `D:\Shares\Finance` {
		t.Errorf("trailing backslash not normalised: %q", got)
	}
	got, err = NormalizeSmbSharePath(`D:\`)
	if err != nil || got != `D:\` {
		t.Errorf("drive root must be preserved: %q, %v", got, err)
	}
	for _, p := range []string{`\\server\share`, `D:/Shares`, `relative\path`, `D:`, ``} {
		if _, err := NormalizeSmbSharePath(p); !IsSmbShareError(err, SmbShareErrorInvalidName) {
			t.Errorf("path %q should yield invalid_name, got %v", p, err)
		}
	}
}

// -----------------------------------------------------------------------------
// ValidateSmbShareSettings
// -----------------------------------------------------------------------------

func TestNormalizeSmbSharePath_RejectsForwardSlashes(t *testing.T) {
	for _, p := range []string{`D:\Shares/Sub`, `D:\Shares/`, `D:/Shares`} {
		if _, err := NormalizeSmbSharePath(p); !IsSmbShareError(err, SmbShareErrorInvalidName) {
			t.Errorf("path %q mixes or uses forward slashes and must yield invalid_name, got %v", p, err)
		}
	}
}

func TestValidateSmbShareSettings_Limits(t *testing.T) {
	s := SmbShareSettings{ConcurrentUserLimit: SmbShareMaxConcurrentUserLimit + 1}
	if err := ValidateSmbShareSettings(&s); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("concurrent_user_limit above UInt32 must yield invalid_name, got %v", err)
	}
	s = SmbShareSettings{Description: strings.Repeat("a", SmbShareMaxDescriptionLength+1)}
	if err := ValidateSmbShareSettings(&s); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("description above %d chars must yield invalid_name, got %v", SmbShareMaxDescriptionLength, err)
	}
}

func TestValidateSmbShareSettings_DuplicateAcrossSets(t *testing.T) {
	s := SmbShareSettings{FullAccess: []string{`BUILTIN\Administrators`}, ReadAccess: []string{`builtin\administrators`}}
	if err := ValidateSmbShareSettings(&s); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("case-insensitive duplicate should yield invalid_name, got %v", err)
	}
	// SID-aware: Everyone and its canonical SID are the same trustee.
	s = SmbShareSettings{FullAccess: []string{"Everyone"}, ReadAccess: []string{"S-1-1-1"}}
	if err := ValidateSmbShareSettings(&s); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("Everyone/S-1-1-1 duplicate should yield invalid_name, got %v", err)
	}
	// Same principal twice within one set is fine (sets cannot hold it twice).
	s = SmbShareSettings{FullAccess: []string{"Everyone"}}
	if err := ValidateSmbShareSettings(&s); err != nil {
		t.Errorf("single-set use should be valid, got %v", err)
	}
}

func TestValidateSmbShareSettings_EnumsAndLimit(t *testing.T) {
	s := SmbShareSettings{FolderEnumerationMode: "Bogus"}
	if err := ValidateSmbShareSettings(&s); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("bad folder_enumeration_mode should yield invalid_name, got %v", err)
	}
	s = SmbShareSettings{CachingMode: "Bogus"}
	if err := ValidateSmbShareSettings(&s); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("bad caching_mode should yield invalid_name, got %v", err)
	}
	s = SmbShareSettings{ConcurrentUserLimit: -1}
	if err := ValidateSmbShareSettings(&s); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("negative concurrent_user_limit should yield invalid_name, got %v", err)
	}
	s = SmbShareSettings{}
	if err := ValidateSmbShareSettings(&s); err != nil {
		t.Fatalf("empty settings should be valid, got %v", err)
	}
	if s.FolderEnumerationMode != SmbShareFolderEnumerationUnrestricted || s.CachingMode != SmbShareCachingManual {
		t.Errorf("empty enums should fall back to Windows defaults, got %+v", s)
	}
}

func TestSmbShareBroadPrincipal(t *testing.T) {
	for _, p := range []string{"Everyone", "everyone", "S-1-1-1", "Authenticated Users", "S-1-5-11"} {
		if !SmbShareBroadPrincipal(p) {
			t.Errorf("%q should be a broad principal", p)
		}
	}
	for _, p := range []string{`BUILTIN\Administrators`, "S-1-5-32-544", "DOMAIN\\user", ""} {
		if SmbShareBroadPrincipal(p) {
			t.Errorf("%q should not be a broad principal", p)
		}
	}
}

// -----------------------------------------------------------------------------
// runSmbShareEnvelope: ctx cancel / transport / no envelope / bad JSON
// -----------------------------------------------------------------------------

func TestRunSmbShareEnvelope_Timeout(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := NewSmbShareClient(newSmbTestClient(t))
	_, err := s.Read(ctx, "Finance")
	if !IsSmbShareError(err, SmbShareErrorUnknown) {
		t.Errorf("expected unknown (timeout) kind, got %v", err)
	}
	var se *SmbShareError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SmbShareError, got %T", err)
	}
	if !strings.Contains(se.Message, `"read"`) || !strings.Contains(se.Message, "Finance") {
		t.Errorf("Message = %q, want operation and share name", se.Message)
	}
}

func TestRunSmbShareEnvelope_TransportError(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "boom", errors.New("ssh dial failed")
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	_, err := s.Read(context.Background(), "Finance")
	if !IsSmbShareError(err, SmbShareErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunSmbShareEnvelope_NoEnvelope(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "not json at all", "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	_, err := s.Read(context.Background(), "Finance")
	if !IsSmbShareError(err, SmbShareErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunSmbShareEnvelope_BadJSON(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "{not valid json}", "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	_, err := s.Read(context.Background(), "Finance")
	if !IsSmbShareError(err, SmbShareErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Remote error kinds, one fixture each
// -----------------------------------------------------------------------------

func TestSmbShareRemoteKinds(t *testing.T) {
	cases := []struct {
		remote string
		want   SmbShareErrorKind
	}{
		{"not_found", SmbShareErrorNotFound},
		{"already_exists", SmbShareErrorAlreadyExists},
		{"path_not_found", SmbShareErrorPathNotFound},
		{"permission_denied", SmbShareErrorAccessDenied},
		{"invalid_name", SmbShareErrorInvalidName},
		{"principal_not_found", SmbShareErrorPrincipalNotFound},
		{"server_service_unavailable", SmbShareErrorServerServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
				return smbErr(t, tc.remote, "boom "+tc.remote), "", nil
			})
			defer restore()

			s := NewSmbShareClient(newSmbTestClient(t))
			_, err := s.Read(context.Background(), "Finance")
			if !IsSmbShareError(err, tc.want) {
				t.Errorf("remote kind %q should map to %q, got %v", tc.remote, tc.want, err)
			}
		})
	}
}

// TestClassifySmbShare_CimJobExceptionRecord pins the Server 2025 /
// PowerShell 7 missing-share record: Get-SmbShare throws
// Microsoft.PowerShell.Cmdletization.Cim.CimJobException (not CimException)
// with CategoryInfo Category ObjectNotFound, FullyQualifiedErrorId
// CmdletizationQuery_NotFound_Name,Get-SmbShare and the message "No
// MSFT_SMBShare objects found with property 'Name' equal to ...".
//
// PowerShell cannot run in unit tests, so this pins the facets of that
// record the embedded Classify-SmbShare must honour — type-agnostic
// CategoryInfo/FullyQualifiedErrorId checks plus the MSFT_SMBShare message
// fallback — on the exact script shipped to the host. Envelope-kind mapping
// alone (TestSmbShareRemoteKinds) cannot catch a classifier that only
// recognises the PS5 CimException type: on PS7 the record classified as
// unknown, so read returned an error and the create preflight aborted.
func TestClassifySmbShare_CimJobExceptionRecord(t *testing.T) {
	// The classifier ships inside every script: capture what Read sends.
	var gotScript string
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		gotScript = script
		// What the fixed classifier emits for the PS7 record: the share is
		// absent, so the script reports found:false rather than an error.
		return smbOK(t, map[string]any{"found": false}), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	if st, err := s.Read(context.Background(), "Finance"); err != nil || st != nil {
		t.Fatalf("expected (nil, nil) for a missing share, got (%+v, %v)", st, err)
	}
	if !strings.Contains(gotScript, "function Classify-SmbShare") {
		t.Fatal("read script must ship Classify-SmbShare to the host")
	}
	// PS7 throws CimJobException, not CimException: the CategoryInfo and
	// FullyQualifiedErrorId checks must not sit behind a CimException-only
	// gate, or the ObjectNotFound/CmdletizationQuery_NotFound_Name record
	// classifies as unknown.
	if strings.Contains(gotScript, "if ($ex -is [Microsoft.Management.Infrastructure.CimException])") {
		t.Error("Classify-SmbShare must not gate CategoryInfo/FullyQualifiedErrorId checks on CimException: PS7 throws CimJobException")
	}
	for _, want := range []string{
		"$Rec.CategoryInfo.Category",
		"ObjectNotFound",
		"$Rec.FullyQualifiedErrorId",
		"CmdletizationQuery_NotFound_Name",
		"No MSFT_SMBShare objects found",
	} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("Classify-SmbShare must honour the CimJobException missing-share record, script missing %q", want)
		}
	}
}

// -----------------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------------

func TestSmbShareCreate_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		gotScript = script
		return smbOK(t, fakeSmbData("Finance")), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	st, err := s.Create(context.Background(), SmbShareInput{
		Name: "Finance",
		Path: `D:\Shares\Finance`,
		SmbShareSettings: SmbShareSettings{
			Description:           "Finance share",
			FolderEnumerationMode: SmbShareFolderEnumerationAccessBased,
			CachingMode:           SmbShareCachingNone,
			EncryptData:           true,
			FullAccess:            []string{"S-1-5-32-544"},
			ManageAccess:          true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Name != "Finance" || st.Path != `D:\Shares\Finance` || !st.EncryptData {
		t.Errorf("unexpected state: %+v", st)
	}
	if len(st.FullAccess) != 1 || st.FullAccess[0].SID != "S-1-5-32-544" {
		t.Errorf("unexpected full_access: %+v", st.FullAccess)
	}
	// Every user value is quoted: the SID must appear as a PS literal.
	if !strings.Contains(gotScript, "'S-1-5-32-544'") {
		t.Errorf("script must interpolate the trustee through psQuote, got:\n%s", gotScript)
	}
	// Update ordering is grant-new-first, then revoke-stale: the Sync function
	// grants (Grant/Block) in Phase 1 and revokes in Phase 2.
	grantIdx := strings.Index(gotScript, "Phase 1")
	revokeIdx := strings.Index(gotScript, "Phase 2")
	if grantIdx < 0 || revokeIdx < 0 || grantIdx > revokeIdx {
		t.Errorf("Sync-SmbShareAccess must grant (Phase 1) before revoking (Phase 2)")
	}
	if !strings.Contains(gotScript, "Grant-SmbShareAccess") || !strings.Contains(gotScript, "Revoke-SmbShareAccess") {
		t.Errorf("sync script must use Grant/Block/Revoke-SmbShareAccess -Force")
	}
	// Create converges with New-SmbShare; only the delete path removes.
	if !strings.Contains(gotScript, "New-SmbShare") || strings.Contains(gotScript, "Remove-SmbShare") {
		t.Errorf("create script must create (not remove) the share")
	}
}

func TestSmbShareCreate_NormalisesTrailingBackslash(t *testing.T) {
	var gotScript string
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		gotScript = script
		return smbOK(t, fakeSmbData("Finance")), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	if _, err := s.Create(context.Background(), SmbShareInput{Name: "Finance", Path: `D:\Shares\Finance\`}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(gotScript, `D:\Shares\Finance\`) {
		t.Errorf("path must be normalised before interpolation, got:\n%s", gotScript)
	}
}

func TestSmbShareCreate_AlreadyExists(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return smbErr(t, "already_exists", "SMB share Finance already exists"), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	_, err := s.Create(context.Background(), SmbShareInput{Name: "Finance", Path: `D:\Shares\Finance`})
	if !IsSmbShareError(err, SmbShareErrorAlreadyExists) {
		t.Errorf("expected already_exists, got %v", err)
	}
}

func TestSmbShareCreate_InvalidNameShortCircuits(t *testing.T) {
	called := false
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		called = true
		return "", "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	if _, err := s.Create(context.Background(), SmbShareInput{Name: "IPC$", Path: `D:\x`}); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("expected invalid_name, got %v", err)
	}
	if called {
		t.Error("invalid input must not reach the host")
	}
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestSmbShareRead_NotFound(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return smbOK(t, map[string]any{"found": false}), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	st, err := s.Read(context.Background(), "Finance")
	if err != nil || st != nil {
		t.Errorf("expected (nil, nil), got (%+v, %v)", st, err)
	}
}

func TestSmbShareRead_HappyPath(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return smbOK(t, fakeSmbData("Finance")), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	st, err := s.Read(context.Background(), "Finance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.FolderEnumerationMode != "AccessBased" || st.CachingMode != "None" || st.Special {
		t.Errorf("unexpected state: %+v", st)
	}
	if len(st.ReadAccess) != 1 || st.ReadAccess[0].Name != "Everyone" {
		t.Errorf("unexpected read_access: %+v", st.ReadAccess)
	}
}

// TestSmbShareRead_SingleElementObject pins the ConvertTo-Json quirk: a
// one-element access list arrives as a bare object, not an array.
func TestSmbShareRead_SingleElementObject(t *testing.T) {
	data := fakeSmbData("Finance")
	data["read_access"] = map[string]any{"name": "Everyone", "sid": "S-1-1-1"}
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return smbOK(t, data), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	st, err := s.Read(context.Background(), "Finance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(st.ReadAccess) != 1 || st.ReadAccess[0].SID != "S-1-1-1" {
		t.Errorf("single-element object not parsed: %+v", st.ReadAccess)
	}
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

func TestSmbShareUpdate_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		gotScript = script
		return smbOK(t, fakeSmbData("Finance")), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	st, err := s.Update(context.Background(), SmbShareUpdateInput{
		Name: "Finance",
		SmbShareSettings: SmbShareSettings{
			Description:  "updated",
			EncryptData:  true,
			ManageAccess: true,
			ReadAccess:   []string{"Everyone"},
			FullAccess:   []string{`BUILTIN\Administrators`},
			ChangeAccess: []string{},
			NoAccess:     []string{},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st == nil || st.Name != "Finance" {
		t.Errorf("unexpected state: %+v", st)
	}
	if !strings.Contains(gotScript, "Set-SmbShare") || !strings.Contains(gotScript, "-Force") {
		t.Errorf("update script must use Set-SmbShare -Force, got:\n%s", gotScript)
	}
}

func TestSmbShareUpdate_NotFound(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return smbErr(t, "not_found", "share not found"), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	_, err := s.Update(context.Background(), SmbShareUpdateInput{Name: "Finance"})
	if !IsSmbShareError(err, SmbShareErrorNotFound) {
		t.Errorf("expected not_found, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestSmbShareDelete_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		gotScript = script
		return smbOK(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	if err := s.Delete(context.Background(), "Finance"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "Remove-SmbShare") || !strings.Contains(gotScript, "-Force") {
		t.Errorf("delete script must use Remove-SmbShare -Force, got:\n%s", gotScript)
	}
}

func TestSmbShareDelete_Idempotent(t *testing.T) {
	restore := stubSmbRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return smbOK(t, map[string]any{"deleted": false}), "", nil
	})
	defer restore()

	s := NewSmbShareClient(newSmbTestClient(t))
	if err := s.Delete(context.Background(), "Finance"); err != nil {
		t.Errorf("deleting an absent share should be a no-op, got %v", err)
	}
}

func TestSmbShareDelete_EmptyName(t *testing.T) {
	s := NewSmbShareClient(newSmbTestClient(t))
	if err := s.Delete(context.Background(), ""); !IsSmbShareError(err, SmbShareErrorInvalidName) {
		t.Errorf("expected invalid_name, got %v", err)
	}
}
