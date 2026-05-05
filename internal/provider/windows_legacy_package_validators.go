// Pre-compiled regular expressions used by the windows_legacy_package schema.
// Kept in a dedicated file so unit tests can target them without dragging the
// full resource type in.
package provider

import "regexp"

var (
	// name: 1-128 chars, alnum / dot / underscore / hyphen.
	lpNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

	// source_path: absolute Windows path (drive letter + colon + backslash).
	lpSourcePathRe = regexp.MustCompile(`^[A-Za-z]:\\.+`)

	// source_url: http or https URL.
	lpSourceURLRe = regexp.MustCompile(`^https?://`)

	// checksum: <algo>:<hex>.
	lpChecksumRe = regexp.MustCompile(`^(sha256|sha1|md5):[0-9a-fA-F]+$`)

	// product_id: GUID enclosed in braces.
	lpProductIDRe = regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`)
)
