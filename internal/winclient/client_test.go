package winclient

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
)

// decodePowerShell reverses encodePowerShell: base64 -> UTF-16LE -> string.
// It mirrors what the psBootstrap does on the remote host.
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

// TestBootstrapCommandConstantLength is the core regression guard for #39: the
// command line must be small and independent of the script size, since the
// script no longer rides on the command line.
func TestBootstrapCommandConstantLength(t *testing.T) {
	cmd := bootstrapCommand()
	if len(cmd) >= 1000 {
		t.Fatalf("bootstrap command unexpectedly long: %d chars", len(cmd))
	}
	// A second call must be identical: the bootstrap does not embed the script.
	if cmd2 := bootstrapCommand(); cmd != cmd2 {
		t.Fatalf("bootstrapCommand is not deterministic")
	}
}

func TestBootstrapCommandExcludesScript(t *testing.T) {
	// A large script that would blow past Windows' ~8191-char command-line
	// limit if inlined as -EncodedCommand (base64 of UTF-16LE ~= 2.7x).
	large := strings.Repeat("Get-Service -Name 'svc';", 4000) // ~96 KB
	cmd := bootstrapCommand()
	if strings.Contains(cmd, encodePowerShell(large)) {
		t.Fatal("bootstrap command must not contain the script payload")
	}
	if len(cmd) >= 8191 {
		t.Fatalf("command line %d chars exceeds Windows limit for a large script", len(cmd))
	}
}

func TestComposeStdinLayout(t *testing.T) {
	cases := []struct {
		name   string
		script string
		input  string
	}{
		{"no input", "Get-Service", ""},
		{"secret line", "$p=[Console]::In.ReadLine()", "s3cr3t-pÄss"},
		{"json blob", "$raw=[Console]::In.ReadToEnd()", `{"names":["a","b"],"opts":{"x":1}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := io.ReadAll(composeStdin(tc.script, tc.input))
			if err != nil {
				t.Fatalf("read stdin: %v", err)
			}
			line1, rest, found := strings.Cut(string(raw), "\n")
			if !found {
				t.Fatal("stdin has no newline separating script from input")
			}
			if got := decodePowerShell(t, line1); got != tc.script {
				t.Errorf("line 1 decodes to %q, want %q", got, tc.script)
			}
			if rest != tc.input {
				t.Errorf("remainder = %q, want %q", rest, tc.input)
			}
		})
	}
}
