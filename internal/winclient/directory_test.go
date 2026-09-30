package winclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newDirectoryTestClient(t *testing.T) *DirectoryClientImpl {
	t.Helper()
	c, err := New(Config{Host: "windir01", Username: "u", Password: "p", Timeout: 30 * time.Second, InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewDirectoryClient(c)
}

func directoryEnvelope(t *testing.T, ok bool, data any, kind string) string {
	t.Helper()
	m := map[string]any{"ok": ok}
	if ok {
		m["data"] = data
	} else {
		m["kind"] = kind
		m["message"] = "boom"
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func stubDirectoryRun(fn func(context.Context, *Client, string) (string, string, error)) func() {
	prev := runDirectoryPowerShell
	runDirectoryPowerShell = fn
	return func() { runDirectoryPowerShell = prev }
}

func TestDirectorySetQuotesPathAndParsesState(t *testing.T) {
	client := newDirectoryTestClient(t)
	var script string
	defer stubDirectoryRun(func(_ context.Context, _ *Client, got string) (string, string, error) {
		script = got
		return directoryEnvelope(t, true, map[string]any{
			"found": true, "last_write_time": "2026-10-01T00:00:00Z", "attributes": []string{"hidden"},
		}, ""), "", nil
	})()
	state, err := client.Set(context.Background(), DirectoryInput{Path: `C:\tmp\it's`, CreateParents: true, Attributes: []string{"hidden"}})
	if err != nil {
		t.Fatal(err)
	}
	if state.Path != `C:\tmp\it's` || len(state.Attributes) != 1 || state.Attributes[0] != "hidden" {
		t.Fatalf("state = %+v", state)
	}
	if !strings.Contains(script, "''") || strings.Contains(script, "Remove-Item C:\\ -Recurse") {
		t.Fatal("path was not safely quoted")
	}
}

func TestDirectoryReadMissingReturnsNil(t *testing.T) {
	client := newDirectoryTestClient(t)
	defer stubDirectoryRun(func(context.Context, *Client, string) (string, string, error) {
		return directoryEnvelope(t, true, map[string]any{"found": false}, ""), "", nil
	})()
	state, err := client.Read(context.Background(), `C:\missing`)
	if err != nil {
		t.Fatal(err)
	}
	if state != nil {
		t.Fatalf("state = %+v, want nil", state)
	}
}

func TestDirectoryDeleteErrorKind(t *testing.T) {
	client := newDirectoryTestClient(t)
	defer stubDirectoryRun(func(context.Context, *Client, string) (string, string, error) {
		return directoryEnvelope(t, false, nil, "directory_not_empty"), "", nil
	})()
	if err := client.Delete(context.Background(), `C:\data`, false); !IsDirectoryError(err, DirectoryErrorNotEmpty) {
		t.Fatalf("err = %v", err)
	}
}
