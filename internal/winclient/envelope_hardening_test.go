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
