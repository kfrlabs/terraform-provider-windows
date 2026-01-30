package validators

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// powershellStringValidator validates that a string is safe for PowerShell execution
type powershellStringValidator struct {
	allowEmpty bool
}

// PowerShellString returns a validator that ensures a string is safe for PowerShell execution.
// It checks for potentially dangerous characters and patterns that could lead to command injection.
//
// Usage:
//
//	"feature_name": schema.StringAttribute{
//	    Required: true,
//	    Validators: []validator.String{
//	        validators.PowerShellString(),
//	    },
//	}
func PowerShellString() validator.String {
	return &powershellStringValidator{
		allowEmpty: false,
	}
}

// PowerShellStringAllowEmpty returns a validator that allows empty strings but validates non-empty ones.
func PowerShellStringAllowEmpty() validator.String {
	return &powershellStringValidator{
		allowEmpty: true,
	}
}

// Description returns a plain text description of the validator's behavior
func (v powershellStringValidator) Description(ctx context.Context) string {
	return "string must be safe for PowerShell execution (no special characters that could cause injection)"
}

// MarkdownDescription returns a markdown formatted description
func (v powershellStringValidator) MarkdownDescription(ctx context.Context) string {
	return "String must be safe for PowerShell execution. The following characters are not allowed: `` ` ``, `$`, `;`, `|`, `&`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`, `\"`, `'` (unless properly escaped)"
}

// ValidateString performs the validation
func (v powershellStringValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// If the value is unknown or null, skip validation
	if req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}

	value := req.ConfigValue.ValueString()

	// Allow empty strings if configured
	if value == "" {
		if v.allowEmpty {
			return
		}
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Empty String Not Allowed",
			"The value cannot be an empty string for PowerShell execution.",
		)
		return
	}

	// List of dangerous characters and patterns for PowerShell injection
	dangerousChars := []string{
		"`",  // Backtick - PowerShell escape character
		"$",  // Variable expansion
		";",  // Command separator
		"|",  // Pipeline
		"&",  // Background execution / AND operator
		"<",  // Input redirection
		">",  // Output redirection
		"(",  // Subexpression
		")",  // Subexpression
		"{",  // Script block
		"}",  // Script block
		"[",  // Array/type cast
		"]",  // Array/type cast
		"\"", // Double quote (can break string boundaries)
		"'",  // Single quote (can break string boundaries)
		"\n", // Newline
		"\r", // Carriage return
		"\t", // Tab
	}

	// Check for dangerous characters
	for _, char := range dangerousChars {
		if strings.Contains(value, char) {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid Character in String",
				fmt.Sprintf("The value contains a dangerous character '%s' that could lead to PowerShell injection. "+
					"Value: %q", char, value),
			)
			return
		}
	}

	// Check for potentially dangerous patterns
	dangerousPatterns := []string{
		"Invoke-Expression",
		"IEX",
		"Invoke-Command",
		"ICM",
		"Start-Process",
		"New-Object",
		"DownloadString",
		"DownloadFile",
		"WebClient",
		"Invoke-WebRequest",
		"wget",
		"curl",
		"Invoke-RestMethod",
		"irm",
		"iwr",
	}

	valueLower := strings.ToLower(value)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(valueLower, strings.ToLower(pattern)) {
			resp.Diagnostics.AddAttributeWarning(
				req.Path,
				"Potentially Dangerous Pattern Detected",
				fmt.Sprintf("The value contains a potentially dangerous PowerShell pattern: %s. "+
					"This may be flagged as suspicious. Value: %q", pattern, value),
			)
		}
	}

	// Validate length (reasonable limit for PowerShell parameters)
	if len(value) > 1024 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"String Too Long",
			fmt.Sprintf("The value is too long (%d characters). Maximum allowed is 1024 characters for PowerShell safety.",
				len(value)),
		)
		return
	}

	// Check for null bytes
	if strings.Contains(value, "\x00") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Null Byte",
			"The value contains null bytes which are not allowed in PowerShell strings.",
		)
		return
	}

	// Validate it's printable ASCII or valid Unicode
	if !isValidString(value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid String Encoding",
			"The value contains invalid characters or encoding issues.",
		)
		return
	}
}

// isValidString checks if a string contains only valid printable characters
func isValidString(s string) bool {
	// Allow alphanumeric, spaces, hyphens, underscores, dots
	// This is a strict whitelist approach for maximum security
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9\s._-]+$`)
	return validPattern.MatchString(s)
}

// QuotePowerShellString safely quotes a string for PowerShell execution.
// This function should be used when constructing PowerShell commands with user input.
//
// Example:
//
//	featureName := validators.QuotePowerShellString("Web-Server")
//	command := fmt.Sprintf("Install-WindowsFeature -Name %s", featureName)
func QuotePowerShellString(s string) string {
	// PowerShell single quotes are the safest - they don't allow variable expansion
	// We need to escape single quotes by doubling them
	escaped := strings.ReplaceAll(s, "'", "''")
	return fmt.Sprintf("'%s'", escaped)
}

// IsSafePowerShellString performs the same validation as PowerShellString validator
// but returns a boolean instead of adding diagnostics. Useful for programmatic validation.
func IsSafePowerShellString(s string) bool {
	if s == "" {
		return false
	}

	// Check dangerous characters
	dangerousChars := []string{"`", "$", ";", "|", "&", "<", ">", "(", ")", "{", "}", "[", "]", "\"", "'", "\n", "\r", "\t"}
	for _, char := range dangerousChars {
		if strings.Contains(s, char) {
			return false
		}
	}

	// Check length
	if len(s) > 1024 {
		return false
	}

	// Check null bytes
	if strings.Contains(s, "\x00") {
		return false
	}

	// Check if valid string
	return isValidString(s)
}
