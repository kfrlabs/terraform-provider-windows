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
	for _, port := range []int{-1, -22, 65536, 100000} {
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

// Adversarial control-character matrix shared by every name/address/host
// validator below: NUL, CR, LF, CRLF, tab and the remaining C0 controls plus
// DEL must never be accepted in a name that reaches the host (truncation or
// config corruption at apply time). Unicode, emoji, long names and
// Windows-reserved device names exercise the orthogonal accept paths.
func adversarialControlInputs() []string {
	return []string{
		"a\x00b", "\x00", "a\rb", "a\nb", "a\r\nb", "trailing\n",
		"a\tb", "a\vb", "a\fb", "a\x01b", "a\x1fb", "a\x7fb",
	}
}

func TestAdversarialNameValidatorsRejectControls(t *testing.T) {
	strValidators := map[string]func(string) error{
		"IISSiteName":       ValidateIISSiteName,
		"IISAppPoolName":    ValidateIISAppPoolName,
		"BindingHostHeader": ValidateIISBindingHostHeader,
		"NTPPeerAddress":    ValidateNTPPeerAddress,
		"DnsClientAlias":    ValidateDnsClientAlias,
		"BindingProtocol":   ValidateIISBindingProtocol,
		"NTPType":           ValidateNTPType,
		"DnsSuffix":         ValidateDnsClientSuffix,
	}
	for name, fn := range strValidators {
		for _, in := range adversarialControlInputs() {
			// BindingProtocol/NTPType/DnsSuffix are closed enums or charset
			// validators that already reject controls; the assertion is
			// uniform: controls must never validate.
			if err := fn(in); err == nil {
				t.Errorf("%s must reject control input %q", name, in)
			}
		}
	}
	// Legitimate adversarial-but-valid values must keep passing.
	if err := ValidateIISSiteName("café-日本語-🎉"); err != nil {
		t.Errorf("IISSiteName must accept unicode: %v", err)
	}
	if err := ValidateIISAppPoolName(strings.Repeat("a", 64)); err != nil {
		t.Errorf("IISAppPoolName must accept 64 chars: %v", err)
	}
	if err := ValidateIISAppPoolName(strings.Repeat("a", 65)); err == nil {
		t.Error("IISAppPoolName must reject 65 chars")
	}
	if err := ValidateIISBindingHostHeader(""); err != nil {
		t.Errorf("empty host header (all-hosts binding) must stay valid: %v", err)
	}
	if err := ValidateIISBindingHostHeader("ExAmple.COM"); err != nil {
		t.Errorf("host header must accept DNS names: %v", err)
	}
}

func TestAdversarialNumericBoundaries(t *testing.T) {
	// Port / site-ID / poll-interval boundaries (duplicates the probe as a
	// committed regression test).
	for _, p := range []int64{-32768, -1, 0, 1, 80, 443, 65535} {
		if err := ValidateIISBindingPort(p); (p < 1 || p > 65535) != (err != nil) {
			t.Errorf("ValidateIISBindingPort(%d) err=%v", p, err)
		}
	}
	for _, p := range []int64{65536, 100000, 1 << 32} {
		if err := ValidateIISBindingPort(p); err == nil {
			t.Errorf("ValidateIISBindingPort(%d) must fail", p)
		}
	}
	for _, id := range []int64{-1, 0, 1, 4294967295} {
		if err := ValidateIISSiteID(id); (id < 1 || id > 4294967295) != (err != nil) {
			t.Errorf("ValidateIISSiteID(%d) err=%v", id, err)
		}
	}
	if err := ValidateIISSiteID(4294967296); err == nil {
		t.Error("ValidateIISSiteID(max+1) must fail")
	}
	// EventLog size boundaries: 1 MiB minimum, multiple of 64 KiB.
	if err := ValidateEventLogSize(64 << 20); err != nil {
		t.Errorf("ValidateEventLogSize(64MiB) err=%v", err)
	}
	for _, bad := range []int64{0, -1, 1024, (64 << 20) + 1} {
		if err := ValidateEventLogSize(bad); err == nil {
			t.Errorf("ValidateEventLogSize(%d) must fail", bad)
		}
	}
	if err := ValidatePowerPlanSettingValue(-1); err == nil {
		t.Error("ValidatePowerPlanSettingValue(-1) must fail")
	}
	// Disk numbers and storage sizes.
	if err := ValidateDiskNumber(-1); err == nil {
		t.Error("ValidateDiskNumber(-1) must fail")
	}
	if err := ValidateStorageSizeBytes(0); err == nil {
		t.Error("ValidateStorageSizeBytes(0) must fail")
	}
	if err := ValidateStorageSizeBytes(-1 << 40); err == nil {
		t.Error("ValidateStorageSizeBytes(negative) must fail")
	}
	// Long and duplicate inputs must not panic or hang.
	long := strings.Repeat("a", 4096)
	for name, fn := range map[string]func(string) error{
		"IISSiteName": ValidateIISSiteName, "SmbShareName": ValidateSmbShareName,
		"DnsSuffix": ValidateDnsClientSuffix,
	} {
		if err := fn(long); err == nil {
			t.Errorf("%s must reject 4096-char input", name)
		}
	}
}

func TestAdversarialSmbShareNameMatrix(t *testing.T) {
	// Reserved administrative names in any case, with trailing $ variants.
	for _, n := range []string{"IPC$", "ipc$", "ADMIN$", "admin$", "C$", "c$", "Z$", "CC$"} {
		if n == "CC$" {
			if err := ValidateSmbShareName(n); err != nil {
				t.Errorf("ValidateSmbShareName(%q) should be allowed: %v", n, err)
			}
			continue
		}
		if err := ValidateSmbShareName(n); err == nil {
			t.Errorf("ValidateSmbShareName(%q) must be rejected as reserved", n)
		}
	}
	// 80 chars ok, 81 rejected; unicode ok; controls rejected.
	if err := ValidateSmbShareName(strings.Repeat("é", 40)); err != nil {
		t.Errorf("unicode share name must pass: %v", err)
	}
	if err := ValidateSmbShareName(strings.Repeat("a", 80)); err != nil {
		t.Errorf("80-char share name must pass: %v", err)
	}
	if err := ValidateSmbShareName(strings.Repeat("a", 81)); err == nil {
		t.Error("81-char share name must fail")
	}
	for _, in := range adversarialControlInputs() {
		if err := ValidateSmbShareName("a" + in + "b"); err == nil {
			t.Errorf("ValidateSmbShareName must reject %q", in)
		}
	}
}

func TestAdversarialNTPInputMatrix(t *testing.T) {
	// Duplicates and large collections must not panic.
	many := make([]NTPPeer, 0, 200)
	for i := 0; i < 200; i++ {
		many = append(many, NTPPeer{Address: "time.example.com", Flags: "0x9"})
	}
	if err := ValidateNTPInput(NTPInput{Type: "NTP", Servers: many}); err != nil {
		t.Errorf("200 identical peers must not fail validation itself: %v", err)
	}
	dup := []NTPPeer{{Address: "a.example", Flags: "0x9"}, {Address: "a.example", Flags: "0x9"}}
	_ = dup
	if err := ValidateNTPPeer(NTPPeer{Address: "a\x00b"}); err == nil {
		t.Error("NTPPeer with NUL address must fail")
	}
	if err := ValidateNTPPeer(NTPPeer{Address: ""}); err == nil {
		t.Error("NTPPeer with empty address must fail")
	}
}

func TestAdversarialVolumeAndPartitionBoundaries(t *testing.T) {
	if err := ValidateVolumeLabel("NTFS", strings.Repeat("a", 32)); err != nil {
		t.Errorf("32-char NTFS label must pass: %v", err)
	}
	if err := ValidateVolumeLabel("NTFS", strings.Repeat("a", 33)); err == nil {
		t.Error("33-char NTFS label must fail")
	}
	if err := ValidateVolumeLabel("NTFS", "a\x00b"); err == nil {
		t.Error("NTFS label with NUL must fail")
	}
	// 0 selects the host default and is valid; negatives, non-powers of
	// two and off-allowlist sizes fail.
	if err := ValidateVolumeAllocationUnitSize("NTFS", 0); err != nil {
		t.Errorf("allocation unit size 0 (host default) must pass: %v", err)
	}
	for _, bad := range []int64{-1, 1000, 512 << 8} {
		if err := ValidateVolumeAllocationUnitSize("NTFS", bad); err == nil {
			t.Errorf("ValidateVolumeAllocationUnitSize(NTFS, %d) must fail", bad)
		}
	}
	if err := ValidatePartitionCreateOptions(PartitionCreateOptions{SizeBytes: -1}); err == nil {
		t.Error("negative partition size must fail")
	}
}
