// Package winclient — unit tests for DirectoryClient.
//
// These tests stub the package-level seam runDirectoryPowerShell to inject
// scripted stdout/stderr/err triples. They cover the edge cases from the
// windows_directory spec:
//
//	EC-1  Directory absent in Read          -> (nil, nil)
//	EC-2  Path is a file                    -> type_conflict
//	EC-3  Missing parent, no create_parents -> invalid_input
//	EC-4  Delete non-empty, no recursive    -> not_empty
//	EC-5  Delete already absent             -> no-op, no error
//	EC-6  Permission denied                 -> permission_denied
//	EC-9  Create on an already-present dir  -> no error (idempotent)
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

func newDirTestClient(t *testing.T) *Client {
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

// stubDirRun replaces runDirectoryPowerShell for the duration of a test.
func stubDirRun(fn func(ctx context.Context, c *Client, script string) (string, string, error)) func() {
	prev := runDirectoryPowerShell
	runDirectoryPowerShell = fn
	return func() { runDirectoryPowerShell = prev }
}

func dirOK(t *testing.T, data any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatalf("marshal ok: %v", err)
	}
	return string(b) + "\n"
}

func dirErr(t *testing.T, kind, msg string) string {
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

func fakeDirData(existsChildren bool, itemCount int64, attrs []string) map[string]any {
	if attrs == nil {
		attrs = []string{}
	}
	return map[string]any{
		"found":           true,
		"exists_children": existsChildren,
		"item_count":      itemCount,
		"last_write_time": "2026-10-01T12:00:00Z",
		"attributes":      attrs,
	}
}

// -----------------------------------------------------------------------------
// DirectoryError type
// -----------------------------------------------------------------------------

func TestDirectoryError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("underlying")
	e := NewDirectoryError(DirectoryErrorPermission, "denied", cause, map[string]string{"path": `C:\x`})
	if e.Unwrap() != cause {
		t.Error("Unwrap mismatch")
	}
	msg := e.Error()
	if !strings.Contains(msg, "permission_denied") || !strings.Contains(msg, "denied") || !strings.Contains(msg, "underlying") {
		t.Errorf("Error() unexpected: %q", msg)
	}
	e2 := NewDirectoryError(DirectoryErrorNotFound, "gone", nil, nil)
	if strings.Contains(e2.Error(), "<nil>") {
		t.Errorf("no-cause Error leaks <nil>: %q", e2.Error())
	}
}

func TestDirectoryError_Is_And_IsDirectoryError(t *testing.T) {
	e := NewDirectoryError(DirectoryErrorNotFound, "x", nil, nil)
	if !errors.Is(e, ErrDirectoryNotFound) {
		t.Error("errors.Is(ErrDirectoryNotFound) should match by kind")
	}
	if errors.Is(e, ErrDirectoryPermission) {
		t.Error("errors.Is across kinds should not match")
	}
	if !IsDirectoryError(e, DirectoryErrorNotFound) {
		t.Error("IsDirectoryError should match")
	}
	if IsDirectoryError(errors.New("plain"), DirectoryErrorNotFound) {
		t.Error("IsDirectoryError on plain error must be false")
	}
	if e.Is(errors.New("plain")) {
		t.Error("Is against non-DirectoryError should be false")
	}
}

func TestMapDirectoryKind(t *testing.T) {
	cases := map[string]DirectoryErrorKind{
		"not_found":         DirectoryErrorNotFound,
		"type_conflict":     DirectoryErrorTypeConflict,
		"permission_denied": DirectoryErrorPermission,
		"not_empty":         DirectoryErrorNotEmpty,
		"invalid_input":     DirectoryErrorInvalidInput,
		"":                  DirectoryErrorUnknown,
		"weird_kind":        DirectoryErrorUnknown,
	}
	for in, want := range cases {
		if got := mapDirectoryKind(in); got != want {
			t.Errorf("mapDirectoryKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// NormaliseDirectoryAttributes
// -----------------------------------------------------------------------------

func TestNormaliseDirectoryAttributes(t *testing.T) {
	out, err := NormaliseDirectoryAttributes([]string{"system", "hidden", "readonly"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"hidden", "readonly", "system"}
	if len(out) != len(want) {
		t.Fatalf("got %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("got %v, want %v", out, want)
		}
	}
}

func TestNormaliseDirectoryAttributes_Unknown(t *testing.T) {
	_, err := NormaliseDirectoryAttributes([]string{"bogus"})
	if !IsDirectoryError(err, DirectoryErrorInvalidInput) {
		t.Errorf("expected invalid_input, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Input validation short-circuits
// -----------------------------------------------------------------------------

func TestDirectoryRead_EmptyPath(t *testing.T) {
	d := NewDirectoryClient(newDirTestClient(t))
	if _, err := d.Read(context.Background(), ""); !IsDirectoryError(err, DirectoryErrorInvalidInput) {
		t.Errorf("empty path should yield invalid_input, got %v", err)
	}
}

func TestDirectoryCreate_EmptyPath(t *testing.T) {
	d := NewDirectoryClient(newDirTestClient(t))
	if _, err := d.Create(context.Background(), DirectoryInput{}); !IsDirectoryError(err, DirectoryErrorInvalidInput) {
		t.Errorf("empty path should yield invalid_input, got %v", err)
	}
}

func TestDirectoryDelete_EmptyPath(t *testing.T) {
	d := NewDirectoryClient(newDirTestClient(t))
	if err := d.Delete(context.Background(), "", false); !IsDirectoryError(err, DirectoryErrorInvalidInput) {
		t.Errorf("empty path should yield invalid_input, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// runDirectoryEnvelope: ctx cancel / transport / no envelope / bad JSON
// -----------------------------------------------------------------------------

func TestRunDirectoryEnvelope_Timeout(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "", context.Canceled
	})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Read(ctx, `C:\dir`)
	if !IsDirectoryError(err, DirectoryErrorUnknown) {
		t.Errorf("expected unknown (timeout) kind, got %v", err)
	}
}

func TestRunDirectoryEnvelope_TransportError(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "", "boom", errors.New("ssh dial failed")
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Read(context.Background(), `C:\dir`)
	if !IsDirectoryError(err, DirectoryErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunDirectoryEnvelope_NoEnvelope(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "not json at all", "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Read(context.Background(), `C:\dir`)
	if !IsDirectoryError(err, DirectoryErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

func TestRunDirectoryEnvelope_BadJSON(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return "{not valid json}", "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Read(context.Background(), `C:\dir`)
	if !IsDirectoryError(err, DirectoryErrorUnknown) {
		t.Errorf("expected unknown kind, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------------

func TestDirectoryCreate_HappyPath(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirOK(t, fakeDirData(false, 0, nil)), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	ds, err := d.Create(context.Background(), DirectoryInput{Path: `C:\app\logs`, CreateParents: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ds.Path != `C:\app\logs` || ds.ExistsChildren || ds.ItemCount != 0 {
		t.Errorf("unexpected state: %+v", ds)
	}
}

func TestDirectoryCreate_TypeConflict_EC2(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirErr(t, "type_conflict", "path is a file"), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Create(context.Background(), DirectoryInput{Path: `C:\app\file.txt`})
	if !IsDirectoryError(err, DirectoryErrorTypeConflict) {
		t.Errorf("expected type_conflict, got %v", err)
	}
}

func TestDirectoryCreate_MissingParent_EC3(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirErr(t, "invalid_input", "parent directory does not exist"), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Create(context.Background(), DirectoryInput{Path: `C:\missing\logs`, CreateParents: false})
	if !IsDirectoryError(err, DirectoryErrorInvalidInput) {
		t.Errorf("expected invalid_input, got %v", err)
	}
}

func TestDirectoryCreate_Idempotent_EC9(t *testing.T) {
	// Pre-existing directory: the PS layer never errors, it just reports state.
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirOK(t, fakeDirData(true, 3, []string{"hidden"})), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	ds, err := d.Create(context.Background(), DirectoryInput{Path: `C:\existing`, Attributes: []string{"hidden"}})
	if err != nil {
		t.Fatalf("unexpected error on idempotent create: %v", err)
	}
	if !ds.ExistsChildren || ds.ItemCount != 3 {
		t.Errorf("unexpected state: %+v", ds)
	}
}

func TestDirectoryCreate_InvalidAttribute(t *testing.T) {
	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Create(context.Background(), DirectoryInput{Path: `C:\x`, Attributes: []string{"bogus"}})
	if !IsDirectoryError(err, DirectoryErrorInvalidInput) {
		t.Errorf("expected invalid_input, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------------

func TestDirectoryRead_NotFound_EC1(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirOK(t, map[string]any{"found": false}), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	ds, err := d.Read(context.Background(), `C:\missing`)
	if err != nil || ds != nil {
		t.Errorf("expected (nil, nil), got (%+v, %v)", ds, err)
	}
}

func TestDirectoryRead_PathIsFile_EC2(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirErr(t, "type_conflict", "path is a file"), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Read(context.Background(), `C:\app\file.txt`)
	if !IsDirectoryError(err, DirectoryErrorTypeConflict) {
		t.Errorf("expected type_conflict, got %v", err)
	}
}

func TestDirectoryRead_HappyPath(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirOK(t, fakeDirData(true, 2, []string{"readonly", "system"})), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	ds, err := d.Read(context.Background(), `C:\app`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ds.ItemCount != 2 || len(ds.Attributes) != 2 {
		t.Errorf("unexpected state: %+v", ds)
	}
}

func TestDirectoryRead_PermissionDenied_EC6(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirErr(t, "permission_denied", "access is denied"), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Read(context.Background(), `C:\locked`)
	if !IsDirectoryError(err, DirectoryErrorPermission) {
		t.Errorf("expected permission_denied, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

func TestDirectoryUpdate_HappyPath(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirOK(t, fakeDirData(false, 0, []string{"hidden"})), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	ds, err := d.Update(context.Background(), `C:\app`, []string{"hidden"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ds.Attributes) != 1 || ds.Attributes[0] != "hidden" {
		t.Errorf("unexpected state: %+v", ds)
	}
}

func TestDirectoryUpdate_NotFound(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirErr(t, "not_found", "directory does not exist"), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	_, err := d.Update(context.Background(), `C:\gone`, nil)
	if !IsDirectoryError(err, DirectoryErrorNotFound) {
		t.Errorf("expected not_found, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestDirectoryDelete_Idempotent_EC5(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirOK(t, map[string]any{"deleted": false}), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	if err := d.Delete(context.Background(), `C:\gone`, false); err != nil {
		t.Errorf("deleting an absent directory should be a no-op, got %v", err)
	}
}

func TestDirectoryDelete_NotEmpty_EC4(t *testing.T) {
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		return dirErr(t, "not_empty", "directory is not empty"), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	err := d.Delete(context.Background(), `C:\app`, false)
	if !IsDirectoryError(err, DirectoryErrorNotEmpty) {
		t.Errorf("expected not_empty, got %v", err)
	}
}

func TestDirectoryDelete_Recursive_HappyPath(t *testing.T) {
	var gotScript string
	restore := stubDirRun(func(ctx context.Context, c *Client, script string) (string, string, error) {
		gotScript = script
		return dirOK(t, map[string]any{"deleted": true}), "", nil
	})
	defer restore()

	d := NewDirectoryClient(newDirTestClient(t))
	if err := d.Delete(context.Background(), `C:\app`, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotScript, "Recursive:$true") {
		t.Errorf("expected Recursive:$true in script, got: %s", gotScript)
	}
}

func TestDirectoryDelete_EmptyPath_InvalidInput(t *testing.T) {
	d := NewDirectoryClient(newDirTestClient(t))
	if err := d.Delete(context.Background(), "   ", false); !IsDirectoryError(err, DirectoryErrorInvalidInput) {
		t.Errorf("expected invalid_input, got %v", err)
	}
}
