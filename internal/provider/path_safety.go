// Package provider: shared Windows path-safety helpers.
//
// Aggressive Terraform CLI campaign (2026-11-16) finding: writing
// `C:\...\NUL.txt` through windows_file reported "Creation complete" and
// every later plan/refresh said "No changes", yet no usable file exists —
// Win32 resolves the name to the NUL device while .NET happily manages a
// phantom only it can see. The same divergence applies to every DOS device
// name (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without extension) and,
// by Win32 name-stripping, to final segments ending in a space or dot
// (`trail.txt ` is stored as `trail.txt` while the state keeps the
// unstripped spelling).
//
// Both create-path validators (windows_file, windows_directory) reject these
// spellings at plan time through validateFinalPathSegment.
package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// reservedDeviceBases is the exact set of DOS device names Windows resolves
// without touching the filesystem. Comparison is case-insensitive and
// applies to the base of the final segment (before the first '.'), so
// `NUL.txt` and `com1` are rejected exactly like bare `NUL`.
var reservedDeviceBases = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true,
	"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
	"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// finalPathSegment returns the last non-empty segment of p split on either
// Windows separator (`\` or `/`). Skipping empties tolerates a trailing
// separator, which windows_directory permits.
func finalPathSegment(p string) string {
	segs := strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' })
	if len(segs) == 0 {
		return ""
	}
	return segs[len(segs)-1]
}

// reservedDeviceBase reports whether seg names a DOS device: its base (up to
// the first '.') matches a reserved device name case-insensitively. Only an
// exact base match counts, so `content.txt` and `COM10` stay valid.
func reservedDeviceBase(seg string) bool {
	base := seg
	if i := strings.Index(base, "."); i >= 0 {
		base = base[:i]
	}
	return reservedDeviceBases[strings.ToUpper(base)]
}

// hasStrippedTrailingChar reports a trailing space or dot, which Win32
// silently strips from the on-disk name so the state spelling never matches
// reality.
func hasStrippedTrailingChar(seg string) bool {
	return strings.HasSuffix(seg, " ") || strings.HasSuffix(seg, ".")
}

// validateFinalPathSegment rejects final segments that Win32 resolves away
// from the declared spelling: DOS device names and trailing spaces/dots.
func validateFinalPathSegment(p string, attrPath path.Path, diags *diag.Diagnostics) {
	seg := finalPathSegment(p)
	if seg == "" {
		return
	}
	if reservedDeviceBase(seg) {
		diags.AddAttributeError(attrPath, "Invalid path",
			fmt.Sprintf(`path %q names a reserved Windows device (CON, PRN, AUX, NUL, COM1-9, LPT1-9): `+
				`Windows resolves it without creating a usable file, so Terraform would manage a phantom`, p))
		return
	}
	if hasStrippedTrailingChar(seg) {
		diags.AddAttributeError(attrPath, "Invalid path",
			fmt.Sprintf(`path %q ends in a space or dot, which Windows strips from the on-disk name: `+
				`the state spelling would never match reality`, p))
	}
}
