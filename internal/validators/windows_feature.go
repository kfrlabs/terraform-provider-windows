package validators

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// windowsFeatureNameValidator validates that a string is a valid Windows feature name
type windowsFeatureNameValidator struct{}

// WindowsFeatureName returns a validator that ensures a string is a valid Windows feature name.
// Windows feature names follow specific naming conventions and this validator enforces them.
//
// Valid examples:
//   - "Web-Server"
//   - "Web-Asp-Net45"
//   - "RSAT-ADDS"
//   - "FS-FileServer"
//
// Usage:
//
//	"feature": schema.StringAttribute{
//	    Required: true,
//	    Validators: []validator.String{
//	        validators.WindowsFeatureName(),
//	    },
//	}
func WindowsFeatureName() validator.String {
	return &windowsFeatureNameValidator{}
}

// Description returns a plain text description of the validator's behavior
func (v windowsFeatureNameValidator) Description(ctx context.Context) string {
	return "string must be a valid Windows feature name (alphanumeric with hyphens, 1-100 characters)"
}

// MarkdownDescription returns a markdown formatted description
func (v windowsFeatureNameValidator) MarkdownDescription(ctx context.Context) string {
	return "String must be a valid Windows feature name. Feature names must:\n\n" +
		"- Start with a letter or number\n" +
		"- Contain only letters, numbers, and hyphens\n" +
		"- Be between 1 and 100 characters long\n" +
		"- Not start or end with a hyphen\n\n" +
		"Examples: `Web-Server`, `RSAT-ADDS`, `FS-FileServer`"
}

// ValidateString performs the validation
func (v windowsFeatureNameValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// If the value is unknown or null, skip validation
	if req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}

	value := req.ConfigValue.ValueString()

	// Check if empty
	if value == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Empty Feature Name",
			"Windows feature name cannot be empty.",
		)
		return
	}

	// Check length (Windows feature names are typically short, max 100 chars)
	if len(value) > 100 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Feature Name Too Long",
			fmt.Sprintf("Windows feature name is too long (%d characters). Maximum length is 100 characters. "+
				"Value: %q", len(value), value),
		)
		return
	}

	if len(value) < 1 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Feature Name Too Short",
			"Windows feature name must be at least 1 character long.",
		)
		return
	}

	// Windows feature names follow a specific pattern:
	// - Must start with alphanumeric
	// - Can contain alphanumeric and hyphens
	// - Cannot start or end with hyphen
	// - Case insensitive but conventionally use Title-Case-With-Hyphens
	featurePattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)

	if !featurePattern.MatchString(value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Feature Name Format",
			fmt.Sprintf("Windows feature name has invalid format. "+
				"Feature names must start and end with alphanumeric characters and contain only letters, numbers, and hyphens. "+
				"Value: %q", value),
		)
		return
	}

	// Check for consecutive hyphens (not typically valid)
	if strings.Contains(value, "--") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Feature Name",
			fmt.Sprintf("Windows feature name cannot contain consecutive hyphens. Value: %q", value),
		)
		return
	}

	// Warn if the feature name doesn't follow common conventions
	if !hasValidFeatureNameConvention(value) {
		resp.Diagnostics.AddAttributeWarning(
			req.Path,
			"Non-Standard Feature Name",
			fmt.Sprintf("The feature name %q doesn't follow standard Windows feature naming conventions. "+
				"While this may be valid, ensure it's a correct feature name. "+
				"Standard names use Title-Case-With-Hyphens (e.g., 'Web-Server', 'RSAT-ADDS').", value),
		)
	}
}

// hasValidFeatureNameConvention checks if the name follows common Windows feature naming patterns
func hasValidFeatureNameConvention(name string) bool {
	// Common patterns in Windows feature names:
	// 1. Multiple segments separated by hyphens
	// 2. Each segment typically starts with capital letter
	// 3. Common prefixes: Web-, RSAT-, FS-, AD-, DNS-, DHCP-, etc.

	segments := strings.Split(name, "-")

	// Single segment features are often valid (e.g., "IIS", "DNS")
	if len(segments) == 1 {
		return true
	}

	// Check if most segments start with uppercase (allowing for some flexibility)
	uppercaseCount := 0
	for _, segment := range segments {
		if len(segment) > 0 && segment[0] >= 'A' && segment[0] <= 'Z' {
			uppercaseCount++
		}
	}

	// If more than half of segments start with uppercase, consider it conventional
	return uppercaseCount >= len(segments)/2
}

// Common Windows feature name prefixes for validation
var commonFeaturePrefixes = []string{
	"Web-",           // IIS web server features
	"RSAT-",          // Remote Server Administration Tools
	"FS-",            // File Services
	"AD-",            // Active Directory
	"DNS-",           // DNS Server
	"DHCP-",          // DHCP Server
	"Print-",         // Print Services
	"NET-",           // .NET Framework features
	"WDS-",           // Windows Deployment Services
	"RDS-",           // Remote Desktop Services
	"NPAS-",          // Network Policy and Access Services
	"ADCS-",          // Active Directory Certificate Services
	"ADRMS-",         // Active Directory Rights Management Services
	"ADFS-",          // Active Directory Federation Services
	"WSUS-",          // Windows Server Update Services
	"BitLocker-",     // BitLocker features
	"BranchCache-",   // BranchCache features
	"DirectAccess-",  // DirectAccess features
	"Failover-",      // Failover Clustering
	"Hyper-V-",       // Hyper-V features
	"MultiPoint-",    // MultiPoint Services
	"NLB-",           // Network Load Balancing
	"Storage-",       // Storage Services
	"FileAndStorage-",// File and Storage Services
	"UpdateServices-",// Windows Server Update Services
	"VolumeActivation-", // Volume Activation Services
	"WAS-",           // Windows Process Activation Service
	"Windows-",       // Generic Windows features
}

// IsCommonFeaturePrefix checks if a feature name starts with a known Windows feature prefix
func IsCommonFeaturePrefix(name string) bool {
	for _, prefix := range commonFeaturePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// ValidateFeatureName performs the same validation as WindowsFeatureName validator
// but returns an error instead of adding diagnostics. Useful for programmatic validation.
func ValidateFeatureName(name string) error {
	if name == "" {
		return fmt.Errorf("feature name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("feature name too long (%d characters, max 100)", len(name))
	}

	featurePattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)
	if !featurePattern.MatchString(name) {
		return fmt.Errorf("invalid feature name format: %q", name)
	}

	if strings.Contains(name, "--") {
		return fmt.Errorf("feature name cannot contain consecutive hyphens: %q", name)
	}

	return nil
}

// NormalizeFeatureName normalizes a Windows feature name to standard format
// This is useful for comparing feature names case-insensitively
func NormalizeFeatureName(name string) string {
	// Windows feature names are case-insensitive
	// Convert to lowercase for comparison
	return strings.ToLower(strings.TrimSpace(name))
}

// FeatureNameEquals compares two feature names case-insensitively
func FeatureNameEquals(name1, name2 string) bool {
	return NormalizeFeatureName(name1) == NormalizeFeatureName(name2)
}
