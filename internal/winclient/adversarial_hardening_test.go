// Adversarial hardening tests for winclient connection validation and
// base64 handling (no Windows host required).
package winclient

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAdversarialNewRejectsBadPortAndTimeout(t *testing.T) {
	base := Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true}
	for _, port := range []int{-1, -22, 0 - 0, 65536, 100000} {
		if port == 0 {
			continue // 0 means "default to 22"
		}
		cfg := base
		cfg.Port = port
		if _, err := New(cfg); err == nil {
			t.Errorf("New must reject port %d", port)
		}
	}
	for _, d := range []time.Duration{-time.Second, -time.Nanosecond} {
		cfg := base
		cfg.Timeout = d
		if _, err := New(cfg); err == nil {
			t.Errorf("New must reject negative timeout %s", d)
		}
	}
	// Zero values still default.
	cfg := base
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New with defaults must succeed: %v", err)
	}
	if c.Config().Port == 0 || c.Config().Timeout == 0 {
		t.Errorf("New must apply port/timeout defaults, got %+v", c.Config())
	}
	_ = c.Close()
	// Boundary ports are accepted.
	for _, port := range []int{1, 22, 443, 65535} {
		cfg := base
		cfg.Port = port
		c, err := New(cfg)
		if err != nil {
			t.Errorf("New must accept port %d: %v", port, err)
		} else {
			_ = c.Close()
		}
	}
}

func TestAdversarialValidateBase64Whitespace(t *testing.T) {
	want := []byte(strings.Repeat("adversarial-base64 ", 100))
	enc := base64.StdEncoding.EncodeToString(want)
	var wrapped strings.Builder
	for i, c := range enc {
		wrapped.WriteRune(c)
		if (i+1)%20 == 0 {
			wrapped.WriteString("\n")
		}
	}
	size, err := ValidateFileContentBase64(" \r\n\t" + wrapped.String() + " \r\n")
	if err != nil {
		t.Fatalf("ValidateFileContentBase64 must accept wrapped base64: %v", err)
	}
	if size != int64(len(want)) {
		t.Errorf("size = %d, want %d", size, len(want))
	}
	if _, err := ValidateFileContentBase64("!!!"); err == nil {
		t.Error("ValidateFileContentBase64 must reject malformed input")
	}
	tooBig := base64.StdEncoding.EncodeToString(make([]byte, FileMaxContentBytes+1))
	if _, err := ValidateFileContentBase64(tooBig); err == nil {
		t.Error("ValidateFileContentBase64 must reject oversized payloads")
	}
}

func TestAdversarialPsQuoteInjectionMatrix(t *testing.T) {
	payloads := []string{
		"x'; Write-Output INJECTED; '",
		"x’; Write-Output INJECTED; ’",
		"';$(whoami);'",
		"';`whoami`;'",
		"$env:SECRET",
		"${env:SECRET}",
		"$(Get-Credential)",
		"@('a','b')",
		"a`nb",
		"a\"b",
		"'‘’‚‛",
		strings.Repeat("A", 1024) + "';evil;'",
		"café-日本語-🎉';evil;'",
		"C:\\foo\\bar';evil;'",
		"a\rb\nc",
		"a\x00b';evil;'",
	}
	for _, in := range payloads {
		got := psQuote(in)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Fatalf("psQuote(%q) missing delimiters: %q", in, got)
		}
		inner := got[1 : len(got)-1]
		// No bare ASCII or Unicode quote may survive undoubled.
		runes := []rune(inner)
		for i := 0; i < len(runes); i++ {
			switch runes[i] {
			case '\'', '‘', '’', '‚', '‛':
				if i+1 >= len(runes) || runes[i+1] != runes[i] {
					t.Errorf("psQuote(%q) leaves bare quote %U", in, runes[i])
				} else {
					i++
				}
			}
		}
	}
}
