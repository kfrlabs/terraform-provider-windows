package ssh

import (
	"encoding/xml"
	"regexp"
	"strings"
)

// CLIXMLParser handles parsing of PowerShell CLIXML output.
// CLIXML is PowerShell's XML serialization format used for remote/background job output.
//
// When PowerShell runs remotely (via SSH, WinRM, or background jobs), it serializes
// output streams (stdout, stderr, progress, etc.) into CLIXML format.
//
// Example CLIXML:
// <Objs><S S="Error">Error message here</S></Objs>

// ParseCLIXMLError extracts human-readable error messages from PowerShell CLIXML output.
// It looks for <S S="Error"> tags and concatenates their content.
//
// Parameters:
//   - clixml: The CLIXML string to parse (typically from stderr)
//
// Returns:
//   - string: Cleaned error message(s), or original string if not CLIXML
func ParseCLIXMLError(clixml string) string {
	// Quick check: if it doesn't look like CLIXML, return as-is
	if !strings.Contains(clixml, "#< CLIXML") && !strings.Contains(clixml, "<Objs") {
		return clixml
	}

	// Try XML parsing first (most robust)
	if cleanMsg := parseXMLCLIXML(clixml); cleanMsg != "" {
		return cleanMsg
	}

	// Fallback to regex extraction (when XML is malformed)
	if cleanMsg := parseRegexCLIXML(clixml); cleanMsg != "" {
		return cleanMsg
	}

	// If all else fails, return original
	return clixml
}

// parseXMLCLIXML parses CLIXML using Go's XML parser.
// This is the most robust method but may fail if XML is malformed.
func parseXMLCLIXML(clixml string) string {
	// CLIXML structure (simplified):
	// <Objs>
	//   <S S="Error">Error message</S>
	//   <S S="Warning">Warning message</S>
	//   <Obj S="progress">...</Obj>
	// </Objs>

	type StringElement struct {
		S       string `xml:"S,attr"` // Stream type: Error, Warning, Output, etc.
		Content string `xml:",chardata"`
	}

	type Objs struct {
		Strings []StringElement `xml:"S"`
	}

	// Remove the CLIXML header if present
	xmlContent := strings.TrimPrefix(clixml, "#< CLIXML\n")
	xmlContent = strings.TrimSpace(xmlContent)

	var objs Objs
	if err := xml.Unmarshal([]byte(xmlContent), &objs); err != nil {
		// XML parsing failed, will try regex fallback
		return ""
	}

	// Extract all error messages
	var errorMessages []string
	for _, s := range objs.Strings {
		if s.S == "Error" && s.Content != "" {
			// Clean up PowerShell formatting artifacts
			cleanMsg := cleanPowerShellError(s.Content)
			if cleanMsg != "" {
				errorMessages = append(errorMessages, cleanMsg)
			}
		}
	}

	if len(errorMessages) > 0 {
		return strings.Join(errorMessages, "\n")
	}

	return ""
}

// parseRegexCLIXML extracts error messages using regex patterns.
// This is a fallback when XML parsing fails due to malformed CLIXML.
func parseRegexCLIXML(clixml string) string {
	// Match: <S S="Error">error content</S>
	// We need to handle content that may span multiple lines or contain other XML
	errorPattern := regexp.MustCompile(`<S S="Error">([^<]+)</S>`)
	matches := errorPattern.FindAllStringSubmatch(clixml, -1)

	if len(matches) == 0 {
		return ""
	}

	// Collect all error messages
	var errorMessages []string
	for _, match := range matches {
		if len(match) > 1 {
			cleanMsg := cleanPowerShellError(match[1])
			if cleanMsg != "" {
				errorMessages = append(errorMessages, cleanMsg)
			}
		}
	}

	if len(errorMessages) > 0 {
		return strings.Join(errorMessages, "\n")
	}

	return ""
}

// cleanPowerShellError removes PowerShell formatting artifacts from error messages.
// PowerShell error messages often contain:
// - _x000D__x000A_ (carriage return + line feed encoded)
// - + symbols for stack trace continuation
// - Extra whitespace
func cleanPowerShellError(msg string) string {
	// Replace encoded line breaks with actual line breaks
	msg = strings.ReplaceAll(msg, "_x000D__x000A_", "\n")
	msg = strings.ReplaceAll(msg, "_x000D_", "\n")
	msg = strings.ReplaceAll(msg, "_x000A_", "\n")

	// Split into lines for processing
	lines := strings.Split(msg, "\n")
	var cleanLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip PowerShell call stack lines (start with +)
		if strings.HasPrefix(line, "+") {
			continue
		}

		// Skip generic context indicators
		if strings.HasPrefix(line, "At line:") {
			continue
		}

		cleanLines = append(cleanLines, line)
	}

	result := strings.Join(cleanLines, "\n")
	return strings.TrimSpace(result)
}

// ExtractMainError extracts the primary error message from a cleaned error string.
// This is useful when you want just the first/main error without stack traces.
func ExtractMainError(errorMsg string) string {
	lines := strings.Split(errorMsg, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for the main error pattern
		// Example: "Install-WindowsFeature : ArgumentNotValid: The role..."
		if strings.Contains(line, ":") && len(line) > 10 {
			// Extract the part after the first colon (the actual error)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
			return line
		}
	}

	// If no structured error found, return first non-empty line
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}

	return errorMsg
}
