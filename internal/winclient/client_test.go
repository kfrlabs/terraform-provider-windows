package winclient

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
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
