// Package winclient — unit tests for the shared IIS helper (issue #283 A).
//
// Covers: psIISHeader prelude (streams, envelope, Ensure-IIS detection and
// hint, idempotent import, shared Classify-IIS), IISTimeSpanToMinutes /
// IISMinutesToTimeSpan (incl. round-trip), ValidateIISAppPoolName,
// psEscapeWildcard, IISConfigChangedOnDisk.
package winclient

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// psIISHeader content
// ---------------------------------------------------------------------------

func TestPSIISHeader_Prelude(t *testing.T) {
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'",
		"$ProgressPreference    = 'SilentlyContinue'",
		"$WarningPreference     = 'SilentlyContinue'",
		"function Emit-OK",
		"function Emit-Err",
		"function Classify-IIS",
		"function Ensure-IIS",
		"InvariantCulture",
	} {
		if !strings.Contains(psIISHeader, want) {
			t.Errorf("psIISHeader missing %q", want)
		}
	}
	// Go raw-string literals must not contain PowerShell backtick escapes.
	if strings.Contains(psIISHeader, "`n") || strings.Contains(psIISHeader, "`t") {
		t.Error("psIISHeader must not contain PowerShell backtick escape sequences")
	}
}

func TestPSIISHeader_EnsureIIS(t *testing.T) {
	for _, want := range []string{
		"Get-Service W3SVC,WAS",
		"Get-Module -ListAvailable WebAdministration",
		"Import-Module WebAdministration",
		"'iis_not_installed'",
		"windows_feature",
		"Web-Server",
		"Web-Mgmt-Console",
		"Web-Scripting-Tools",
		"missing_service",
		"missing_module",
	} {
		if !strings.Contains(psIISHeader, want) {
			t.Errorf("Ensure-IIS must detect IIS and hint at windows_feature; header missing %q", want)
		}
	}
	// The guard returns a status instead of exiting the shared session (#81).
	if !strings.Contains(psIISHeader, "return $false") || !strings.Contains(psIISHeader, "return $true") {
		t.Error("Ensure-IIS must return $false/$true instead of exiting the persistent session")
	}
}

func TestPSIISHeader_ClassifyIIS(t *testing.T) {
	for _, want := range []string{
		"Cannot read configuration file",
		"Access is denied",
		"0x800700b7",
		"0x80070002",
		"0x8007052e",
		"'invalid_identity'",
		"'access_denied'",
		"'already_exists'",
		"'not_found'",
		"'config_locked'",
	} {
		if !strings.Contains(psIISHeader, want) {
			t.Errorf("Classify-IIS missing shared substring/kind %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// TimeSpan <-> minutes
// ---------------------------------------------------------------------------

func TestIISTimeSpanToMinutes(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"00:00:00", 0},
		{"00:05:00", 5},
		{"00:20:00", 20},
		{"01:00:00", 60},
		{"1.00:00:00", 1440},
		{"1.01:00:00", 1500},
		{"00:19:59", 19}, // sub-minute remainder truncates
		{"00:00:30", 0},  // sub-minute remainder truncates
		{"2.03:04:05", 3064},
		{"00:05:00.1234567", 5}, // fractional seconds tolerated
	}
	for _, tc := range cases {
		if got, err := IISTimeSpanToMinutes(tc.in); err != nil || got != tc.want {
			t.Errorf("IISTimeSpanToMinutes(%q) = (%d, %v), want (%d, nil)", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "nope", "5", "00:05", "1:2:3:4", "25:00:00", "00:05:00:00", "-01:00:00"} {
		if _, err := IISTimeSpanToMinutes(bad); err == nil {
			t.Errorf("IISTimeSpanToMinutes(%q) should fail", bad)
		}
	}
}

func TestIISMinutesToTimeSpan(t *testing.T) {
	cases := map[int64]string{
		0:    "00:00:00",
		5:    "00:05:00",
		60:   "01:00:00",
		1440: "1.00:00:00",
		1500: "1.01:00:00",
	}
	for in, want := range cases {
		if got := IISMinutesToTimeSpan(in); got != want {
			t.Errorf("IISMinutesToTimeSpan(%d) = %q, want %q", in, got, want)
		}
	}
	if got := IISMinutesToTimeSpan(-5); got != "00:00:00" {
		t.Errorf("negative minutes must clamp to zero, got %q", got)
	}
}

func TestIISTimeSpan_RoundTrip(t *testing.T) {
	for _, mins := range []int64{0, 1, 5, 20, 59, 60, 90, 1439, 1440, 1500, 10080, 43200} {
		back, err := IISTimeSpanToMinutes(IISMinutesToTimeSpan(mins))
		if err != nil || back != mins {
			t.Errorf("round-trip(%d): got (%d, %v)", mins, back, err)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateIISAppPoolName
// ---------------------------------------------------------------------------

func TestValidateIISAppPoolName(t *testing.T) {
	for _, ok := range []string{"api", "DefaultAppPool", "a", "pool-1_name.test", "x'y", strings.Repeat("a", 64)} {
		if err := ValidateIISAppPoolName(ok); err != nil {
			t.Errorf("name %q should be valid, got %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", strings.Repeat("a", 65),
		" leading", "trailing ", " ",
		"a/b", `a\b`, "a[b", "a]b", "a:b", "a;b", "a,b", "a?b", "a*b",
		`a"b`, "a<b", "a>b", "a|b",
	} {
		if err := ValidateIISAppPoolName(bad); err == nil {
			t.Errorf("name %q should be rejected", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// psEscapeWildcard / IISConfigChangedOnDisk
// ---------------------------------------------------------------------------

func TestPSEscapeWildcard(t *testing.T) {
	if got := psEscapeWildcard("api"); got != "api" {
		t.Errorf("plain name must pass through, got %q", got)
	}
	if got := psEscapeWildcard("a*[b]?c"); got != "a`*`[b`]`?c" {
		t.Errorf("wildcards must be backtick-escaped, got %q", got)
	}
}

func TestIISConfigChangedOnDisk(t *testing.T) {
	if !IISConfigChangedOnDisk("Cannot commit configuration changes because the file has changed on disk (0x80070002).") {
		t.Error("known flake message must be retryable")
	}
	if !IISConfigChangedOnDisk("Cannot commit configuration changes because the FILE HAS CHANGED ON DISK.") {
		t.Error("flake match must be case-insensitive")
	}
	for _, other := range []string{"", "Access is denied", "Cannot read configuration file", "0x800700b7",
		"IIS application pool 'file has changed on disk' already exists",
		"Cannot commit configuration changes (0x80070005)"} {
		if IISConfigChangedOnDisk(other) {
			t.Errorf("message %q must not be retryable", other)
		}
	}
}

func TestIISRetryBackoff_Short(t *testing.T) {
	for attempt := 1; attempt <= 3; attempt++ {
		if got := iisRetryBackoff(attempt); got <= 0 || got > 5*time.Second {
			t.Errorf("backoff(%d) = %v, want a short positive delay", attempt, got)
		}
	}
}
