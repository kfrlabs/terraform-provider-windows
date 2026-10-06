package winclient

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

// decodePowerShell reverses encodePowerShell: base64 -> UTF-16LE -> string.
// It mirrors what the REPL bootstrap does on the remote host.
func decodePowerShell(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("UTF-16LE payload has odd length %d", len(raw))
	}
	u16 := make([]uint16, len(raw)/2)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &u16); err != nil {
		t.Fatalf("utf16 read: %v", err)
	}
	return string(utf16.Decode(u16))
}

func TestEncodePowerShellRoundTrip(t *testing.T) {
	for _, script := range []string{
		"",
		"Get-Service",
		"Write-Output 'héllo € ✓'", // non-ASCII must survive UTF-16LE
	} {
		if got := decodePowerShell(t, encodePowerShell(script)); got != script {
			t.Errorf("round-trip mismatch: got %q want %q", got, script)
		}
	}
}

// assignmentLine returns the trimmed first line of script that assigns to
// target (the first line containing "target ="), together with its offset in
// script so callers can assert on ordering.
func assignmentLine(script, target string) (line string, offset int, ok bool) {
	off := 0
	for _, l := range strings.Split(script, "\n") {
		if trimmed := strings.TrimSpace(l); strings.Contains(trimmed, target+" =") {
			return trimmed, off, true
		}
		off += len(l) + 1
	}
	return "", 0, false
}

// TestBootstrapsForceUTF8OutputEncoding is the regression guard for #102: both
// bootstraps must force the console encoding to UTF-8 before anything is read
// or written.
//
// Every response byte reaches Go through [Console]::Out.WriteLine, whose
// encoding is [Console]::OutputEncoding — the OEM/ANSI code page on
// powershell.exe 5.1 with a redirected stdout, not UTF-8. Non-ASCII
// characters (a windows_service or windows_local_group description) were lost
// there, and encoding/json then had nothing left to decode.
//
// The corruption happens inside Windows, on the remote host, so no pure-Go test
// can reproduce it: the fake SSH server in sshtest_test.go serves canned
// responses and never executes PowerShell, and TestEncodePowerShellRoundTrip
// only round-trips encodePowerShell in-process without touching a transport.
// Asserting on the bootstrap source is therefore the strongest guard this
// side can offer — it is what makes the fix impossible to delete by accident.
func TestBootstrapsForceUTF8OutputEncoding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		// before is a substring that must still appear AFTER the encoding
		// assignments: [Console]::Out caches a writer built from the encoding
		// in force when it is first used, and on the one-shot transport the
		// stdin reader must not be read before the encoding is settled either.
		before string
	}{
		{"oneShotBootstrap", oneShotBootstrap, "$b64=[Console]::In.ReadLine()"},
		{"psReplBootstrap", psReplBootstrap, "[Console]::Out.WriteLine('" + replReadyPrefix + "'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The encoder must be BOM-less: New-Object Text.UTF8Encoding
			// $false. The [Text.Encoding]::UTF8 static property emits a BOM
			// on redirected stdout, which would prefix the first JSON /
			// handshake line and break prefix matching.
			if !strings.Contains(tc.script, "New-Object Text.UTF8Encoding $false") {
				t.Errorf("%s never constructs the BOM-less UTF-8 encoder (New-Object Text.UTF8Encoding $false)", tc.name)
			}
			// [Console]::OutputEncoding governs how PowerShell encodes what it
			// writes to the console (and how it decodes native exes' stdout);
			// $OutputEncoding governs pipe-to-native input. Both matter.
			lastAssignment := -1
			for _, target := range []string{"[Console]::OutputEncoding", "$OutputEncoding"} {
				line, offset, ok := assignmentLine(tc.script, target)
				if !ok {
					t.Errorf("%s never assigns %s", tc.name, target)
					continue
				}
				if !strings.Contains(line, "$__wcUtf8NoBom") {
					t.Errorf("%s assigns %s to %q, want the BOM-less $__wcUtf8NoBom encoder", tc.name, target, line)
				}
				if strings.Contains(line, "[Text.Encoding]::UTF8") {
					t.Errorf("%s assigns %s via BOM-emitting [Text.Encoding]::UTF8: %q", tc.name, target, line)
				}
				// The assignment must stay guarded: $ErrorActionPreference is
				// 'Stop' on the very first line of both bootstraps, so an
				// unguarded assignment that throws on some host (no console
				// attached, restricted language mode) would break EVERY call
				// there instead of degrading to the previous behaviour.
				if !strings.HasPrefix(line, "try {") || !strings.Contains(line, "} catch {") {
					t.Errorf("%s assigns %s outside a try/catch guard: %q", tc.name, target, line)
				}
				lastAssignment = max(lastAssignment, offset)
			}
			idx := strings.Index(tc.script, tc.before)
			if idx < 0 {
				t.Fatalf("%s no longer contains %q", tc.name, tc.before)
			}
			if lastAssignment > idx {
				t.Errorf("%s sets the encoding after %q, so the first write keeps the old code page", tc.name, tc.before)
			}
		})
	}
}

// TestExtractLastJSONLinePreservesNonASCII pins the Go half of the #102 fix:
// once the remote host emits UTF-8, the envelope must reach encoding/json
// byte-for-byte. extractLastJSONLine only picks and trims lines, it never
// transcodes or re-escapes, so a multi-byte payload must come back verbatim —
// the corruption it cannot repair happened on the Windows side, before these
// bytes existed.
func TestExtractLastJSONLinePreservesNonASCII(t *testing.T) {
	const envelope = `{"ok":true,"data":{"description":"Service café — naïve ✓ Ünïcødé"}}`
	if len(envelope) == len([]rune(envelope)) {
		t.Fatal("test envelope is pure ASCII, it would not exercise multi-byte handling")
	}
	cases := []struct{ name, in string }{
		{"only envelope", envelope + "\n"},
		{"after a PS warning", "WARNING: la description a été tronquée\n" + envelope + "\r\n"},
		{"last of several", `{"ok":true,"data":{"description":"ümlaut"}}` + "\n" + envelope + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractLastJSONLine(tc.in); got != envelope {
				t.Errorf("extractLastJSONLine returned %q (%d bytes), want %q (%d bytes)", got, len(got), envelope, len(envelope))
			}
		})
	}
}

// TestJSONUnmarshalPreservesNonASCIIIntoStateStructs is the other half of the
// #102 decode-side guard: the unexported structs the resources read from the
// envelope must keep multi-byte text exactly as emitted. Neither struct nor
// encoding/json normalises anything, so a mangled description on the wire
// surfaces verbatim as a drifted attribute in state.
func TestJSONUnmarshalPreservesNonASCIIIntoStateStructs(t *testing.T) {
	t.Run("stateData", func(t *testing.T) {
		const desc = "Gestionnaire de vulnerabilities — ✓"
		var d stateData
		if err := json.Unmarshal([]byte(`{"name":"WinDefend","description":"`+desc+`","hostname":"WIN01"}`), &d); err != nil {
			t.Fatalf("unmarshal stateData: %v", err)
		}
		if d.Description != desc {
			t.Errorf("stateData.Description = %q, want %q", d.Description, desc)
		}
		if got := normaliseState(&d); got.Description != desc {
			t.Errorf("normaliseState description = %q, want %q", got.Description, desc)
		}
	})
	t.Run("psLocalGroup", func(t *testing.T) {
		const desc = "Utilisateurs du domaine — Ünïcødé ✓"
		var g psLocalGroup
		if err := json.Unmarshal([]byte(`{"Name":"Ops","Description":"`+desc+`","SID":{"Value":"S-1-5-32-544"}}`), &g); err != nil {
			t.Fatalf("unmarshal psLocalGroup: %v", err)
		}
		if g.Description != desc {
			t.Errorf("psLocalGroup.Description = %q, want %q", g.Description, desc)
		}
	})
}

// TestReplBootstrapCommandConstantLength is the core regression guard for
// #39: the command line must be small and independent of the script size,
// since the script never rides on the command line — the REPL loop keeps
// that guarantee for every call, not just the first.
func TestReplBootstrapCommandConstantLength(t *testing.T) {
	cmd := replBootstrapCommand()
	// The REPL bootstrap is a fixed script (loop, framing, handshake) so it
	// is naturally longer than the old one-shot bootstrap, but it must stay
	// well clear of Windows' ~8191-char command-line limit (#39) and, above
	// all, never grow with whatever script gets sent later.
	if len(cmd) >= 4096 {
		t.Fatalf("bootstrap command unexpectedly long: %d chars", len(cmd))
	}
	if cmd2 := replBootstrapCommand(); cmd != cmd2 {
		t.Fatalf("replBootstrapCommand is not deterministic")
	}
}

func TestReplBootstrapCommandExcludesScript(t *testing.T) {
	// A large script that would blow past Windows' ~8191-char command-line
	// limit if inlined as -EncodedCommand (base64 of UTF-16LE ~= 2.7x).
	large := strings.Repeat("Get-Service -Name 'svc';", 4000) // ~96 KB
	cmd := replBootstrapCommand()
	if strings.Contains(cmd, encodePowerShell(large)) {
		t.Fatal("bootstrap command must not contain any script payload")
	}
	if len(cmd) >= 8191 {
		t.Fatalf("command line %d chars exceeds Windows limit", len(cmd))
	}
}

func TestEncodeReplRequestLayout(t *testing.T) {
	cases := []struct {
		name   string
		script string
		secret string
	}{
		{"no secret", "Get-Service", ""},
		{"secret line", "$p=[Console]::In.ReadLine()", "s3cr3t-pÄss"},
		{"json blob", "$raw=[Console]::In.ReadToEnd()", `{"names":["a","b"],"opts":{"x":1}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := encodeReplRequest(tc.script, tc.secret)
			line1, rest, found := strings.Cut(raw, "\n")
			if !found {
				t.Fatal("request has no newline separating script from secret")
			}
			if got := decodePowerShell(t, line1); got != tc.script {
				t.Errorf("line 1 decodes to %q, want %q", got, tc.script)
			}
			line2, remainder, found := strings.Cut(rest, "\n")
			if !found {
				t.Fatal("request has no newline terminating the secret line")
			}
			if remainder != "" {
				t.Errorf("unexpected trailing data after secret line: %q", remainder)
			}
			gotSecret, err := base64.StdEncoding.DecodeString(line2)
			if err != nil {
				t.Fatalf("secret line is not base64: %v", err)
			}
			if string(gotSecret) != tc.secret {
				t.Errorf("secret = %q, want %q", gotSecret, tc.secret)
			}
		})
	}
}
