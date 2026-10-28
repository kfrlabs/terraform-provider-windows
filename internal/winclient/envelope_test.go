package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// envelopeRunner returns a runner that serves one canned result and records
// the script/stdin it was called with.
func envelopeRunner(stdout, stderr string, err error, gotScript, gotStdin *string) EnvelopeRunner {
	return func(_ context.Context, script, stdin string) (string, string, error) {
		if gotScript != nil {
			*gotScript = script
		}
		if gotStdin != nil {
			*gotStdin = stdin
		}
		return stdout, stderr, err
	}
}

func TestRunEnvelopeSuccess(t *testing.T) {
	var script, stdin string
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner(`{"ok":true,"data":{"value":"x"}}`, "", nil, &script, &stdin),
		"read", "Get-Thing", "secret\n", map[string]string{"host": "win01"})

	if eerr != nil {
		t.Fatalf("unexpected error: %v", eerr)
	}
	if resp == nil || !resp.OK {
		t.Fatalf("unexpected envelope: %+v", resp)
	}
	if string(resp.Data) != `{"value":"x"}` {
		t.Errorf("Data = %s", resp.Data)
	}
	if script != "Get-Thing" || stdin != "secret\n" {
		t.Errorf("runner received script=%q stdin=%q", script, stdin)
	}
}

func TestRunEnvelopeTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	base := map[string]string{"host": "win01", "path": `C:\dir`}
	resp, eerr := runEnvelope(ctx,
		envelopeRunner("", "", context.Canceled, nil, nil),
		"read", "Get-Thing", "", base)

	if eerr == nil {
		t.Fatal("expected a timeout error")
	}
	if resp != nil {
		t.Errorf("timeout must not return an envelope, got %+v", resp)
	}
	if eerr.Stage != EnvelopeStageTimeout {
		t.Errorf("Stage = %q, want %q", eerr.Stage, EnvelopeStageTimeout)
	}
	if !errors.Is(eerr, context.Canceled) {
		t.Errorf("Cause should wrap context.Canceled, got %v", eerr)
	}
	if !strings.Contains(eerr.Message, `"read"`) || !strings.Contains(eerr.Message, "timed out or was cancelled") {
		t.Errorf("Message = %q", eerr.Message)
	}
	if eerr.Context["host"] != "win01" || eerr.Context["path"] != `C:\dir` || eerr.Context["operation"] != "read" {
		t.Errorf("Context = %#v", eerr.Context)
	}
	if base["operation"] != "" {
		t.Errorf("base context was mutated: %#v", base)
	}
}

func TestRunEnvelopeTransportError(t *testing.T) {
	transportErr := errors.New("ssh dial failed")
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner("partial-out", "partial-err", transportErr, nil, nil),
		"create", "New-Thing", "", map[string]string{"host": "win01"})

	if eerr == nil {
		t.Fatal("expected a transport error")
	}
	if resp != nil {
		t.Errorf("transport failure must not return an envelope, got %+v", resp)
	}
	if eerr.Stage != EnvelopeStageTransport {
		t.Errorf("Stage = %q, want %q", eerr.Stage, EnvelopeStageTransport)
	}
	if !errors.Is(eerr, transportErr) {
		t.Errorf("Cause should wrap the transport error, got %v", eerr)
	}
	if eerr.Context["operation"] != "create" || eerr.Context["stdout"] != "partial-out" || eerr.Context["stderr"] != "partial-err" {
		t.Errorf("Context = %#v", eerr.Context)
	}
}

func TestRunEnvelopeNoEnvelope(t *testing.T) {
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner("not json at all", "warn", nil, nil, nil),
		"delete", "Remove-Thing", "", map[string]string{"host": "win01"})

	if eerr == nil {
		t.Fatal("expected a missing-envelope error")
	}
	if resp != nil {
		t.Errorf("missing envelope must not return an envelope, got %+v", resp)
	}
	if eerr.Stage != EnvelopeStageNoEnvelope {
		t.Errorf("Stage = %q, want %q", eerr.Stage, EnvelopeStageNoEnvelope)
	}
	if !strings.Contains(eerr.Message, "no JSON envelope returned") {
		t.Errorf("Message = %q", eerr.Message)
	}
	if eerr.Context["stdout"] != "not json at all" || eerr.Context["stderr"] != "warn" {
		t.Errorf("Context = %#v", eerr.Context)
	}
}

func TestRunEnvelopeInvalidJSON(t *testing.T) {
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner("{not valid json}", "", nil, nil, nil),
		"update", "Set-Thing", "", map[string]string{"host": "win01"})

	if eerr == nil {
		t.Fatal("expected an invalid-JSON error")
	}
	if resp != nil {
		t.Errorf("invalid JSON must not return an envelope, got %+v", resp)
	}
	if eerr.Stage != EnvelopeStageInvalidJSON {
		t.Errorf("Stage = %q, want %q", eerr.Stage, EnvelopeStageInvalidJSON)
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(eerr, &syntaxErr) {
		t.Errorf("Cause should wrap the JSON syntax error, got %v", eerr)
	}
	if !strings.Contains(eerr.Message, "invalid JSON envelope") {
		t.Errorf("Message = %q", eerr.Message)
	}
	if eerr.Context["stdout"] != "{not valid json}" {
		t.Errorf("Context = %#v", eerr.Context)
	}
}

func TestRunEnvelopeRemoteError(t *testing.T) {
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner(`{"ok":false,"kind":"not_found","message":"dir is gone","context":{"path":"script-path","detail":"d"}}`, "", nil, nil, nil),
		"read", "Get-Thing", "", map[string]string{"host": "win01", "path": `C:\dir`})

	if eerr == nil {
		t.Fatal("expected a remote error")
	}
	if resp == nil || resp.OK {
		t.Fatalf("remote error should still return the envelope, got %+v", resp)
	}
	if eerr.Stage != EnvelopeStageRemote {
		t.Errorf("Stage = %q, want %q", eerr.Stage, EnvelopeStageRemote)
	}
	if eerr.RemoteKind != "not_found" || eerr.Message != "dir is gone" {
		t.Errorf("kind/message = %q/%q", eerr.RemoteKind, eerr.Message)
	}
	// Client-supplied identity must override a script-provided value, and
	// unrelated script context must survive.
	if eerr.Context["path"] != `C:\dir` {
		t.Errorf("path = %q, want the client-supplied value", eerr.Context["path"])
	}
	if eerr.Context["detail"] != "d" || eerr.Context["host"] != "win01" || eerr.Context["operation"] != "read" {
		t.Errorf("Context = %#v", eerr.Context)
	}
	if eerr.Cause != nil {
		t.Errorf("remote rejection has no Go cause, got %v", eerr.Cause)
	}
}

func TestRunEnvelopeNilRunner(t *testing.T) {
	_, eerr := runEnvelope(context.Background(), nil, "read", "Get-Thing", "", nil)
	if eerr == nil {
		t.Fatal("expected an error for a nil runner")
	}
	if eerr.Stage != EnvelopeStageTransport {
		t.Errorf("Stage = %q, want %q", eerr.Stage, EnvelopeStageTransport)
	}
	if eerr.Context["operation"] != "read" {
		t.Errorf("Context = %#v", eerr.Context)
	}
}
