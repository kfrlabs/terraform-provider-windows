// Package winclient — envelope scan hardening regression tests (campaign).
//
//   - (a) a trailing `{...}` noise line without an `ok` field must not shadow
//     a real envelope: scan newest-first for an object with an `ok` boolean.
//   - (b) BOM/whitespace-prefixed envelopes still parse.
//   - (c) truncated JSON keeps stderr in context (invalid_json stage).
//   - (d) a transport error with a valid envelope on stdout preserves the
//     typed (remote) kind instead of collapsing to transport.
package winclient

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunEnvelope_TrailingNoiseDoesNotShadowEnvelope(t *testing.T) {
	stdout := "{\"ok\":true,\"data\":{\"value\":\"x\"}}\n" + "{\"foo\":1}\n"
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner(stdout, "", nil, nil, nil),
		"read", "Get-Thing", "", map[string]string{"host": "win01"})
	if eerr != nil {
		t.Fatalf("unexpected error: %v", eerr)
	}
	if resp == nil || !resp.OK || string(resp.Data) != `{"value":"x"}` {
		t.Fatalf("unexpected envelope: %+v", resp)
	}
}

func TestRunEnvelope_BOMAndWhitespacePrefixedEnvelope(t *testing.T) {
	for _, stdout := range []string{
		"  \uFEFF{\"ok\":true,\"data\":{\"value\":\"x\"}}\n",
		"\uFEFF  {\"ok\":true,\"data\":{\"value\":\"x\"}}\n",
		"   {\"ok\":true,\"data\":{\"value\":\"x\"}}\n",
		"WARNING: something\n{\"ok\":true,\"data\":{\"value\":\"x\"}}\n",
	} {
		resp, eerr := runEnvelope(context.Background(),
			envelopeRunner(stdout, "", nil, nil, nil),
			"read", "Get-Thing", "", map[string]string{"host": "win01"})
		if eerr != nil {
			t.Fatalf("stdout %q: unexpected error: %v", stdout, eerr)
		}
		if resp == nil || !resp.OK {
			t.Fatalf("stdout %q: unexpected envelope: %+v", stdout, resp)
		}
	}
}

func TestRunEnvelope_TruncatedJSONKeepsStderr(t *testing.T) {
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner("{\"ok\":true,\"data\":", "boom happened", nil, nil, nil),
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
	if eerr.Context["stderr"] != "boom happened" {
		t.Errorf("stderr missing from invalid_json context: %#v", eerr.Context)
	}
	if eerr.Context["stdout"] != "{\"ok\":true,\"data\":" {
		t.Errorf("stdout missing from invalid_json context: %#v", eerr.Context)
	}
}

func TestRunEnvelope_TransportErrorWithValidEnvelopePreservesKind(t *testing.T) {
	transportErr := errors.New("ssh dial failed")
	stdout := "{\"ok\":false,\"kind\":\"not_found\",\"message\":\"dir is gone\",\"context\":{}}\n"
	resp, eerr := runEnvelope(context.Background(),
		envelopeRunner(stdout, "partial-err", transportErr, nil, nil),
		"read", "Get-Thing", "", map[string]string{"host": "win01"})
	if eerr == nil {
		t.Fatal("expected a remote error")
	}
	if eerr.Stage != EnvelopeStageRemote {
		t.Errorf("Stage = %q, want %q (typed kind preserved)", eerr.Stage, EnvelopeStageRemote)
	}
	if eerr.RemoteKind != "not_found" {
		t.Errorf("RemoteKind = %q, want %q", eerr.RemoteKind, "not_found")
	}
	if resp == nil {
		t.Fatal("expected the envelope to be returned alongside the remote error")
	}
}

// A transport that reports cancellation/expiry maps to the timeout stage
// even when the outer context has not (yet) observed it: the context may
// expire between the failed call and the classification check on a loaded
// machine, and inner deadlines surface as context errors with a live outer
// context. (A full-suite run on Windows once mapped the stub error below to
// transport because of exactly this race.)
func TestRunEnvelope_ContextErrorMapsToTimeoutWithLiveContext(t *testing.T) {
	for name, err := range map[string]error{
		"deadline": context.DeadlineExceeded,
		"canceled": context.Canceled,
		"wrapped":  errors.Join(errors.New("dial tcp: i/o timeout"), context.DeadlineExceeded),
	} {
		resp, eerr := runEnvelope(context.Background(),
			envelopeRunner("", "boom", err, nil, nil),
			"list", "Get-Thing", "", map[string]string{"host": "win01"})
		if eerr == nil {
			t.Fatalf("%s: expected a timeout error", name)
		}
		if resp != nil {
			t.Errorf("%s: timeout must not return an envelope", name)
		}
		if eerr.Stage != EnvelopeStageTimeout {
			t.Errorf("%s: Stage = %q, want %q", name, eerr.Stage, EnvelopeStageTimeout)
		}
	}

	// A genuinely expired outer context still maps to timeout with the
	// context error as the cause.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond)
	if ctx.Err() == nil {
		t.Fatal("test setup: context must be expired")
	}
	_, eerr := runEnvelope(ctx,
		envelopeRunner("", "", errors.New("ssh: handshake failed"), nil, nil),
		"list", "Get-Thing", "", map[string]string{"host": "win01"})
	if eerr == nil || eerr.Stage != EnvelopeStageTimeout {
		t.Fatalf("expired context must map to timeout, got %+v", eerr)
	}

	// A non-context transport error with a live context stays transport.
	_, eerr = runEnvelope(context.Background(),
		envelopeRunner("", "boom", errors.New("ssh dial failed"), nil, nil),
		"list", "Get-Thing", "", map[string]string{"host": "win01"})
	if eerr == nil || eerr.Stage != EnvelopeStageTransport {
		t.Fatalf("plain transport error must stay transport, got %+v", eerr)
	}
}
