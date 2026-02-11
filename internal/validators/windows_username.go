package validators

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// ============================================================================
// WINDOWS USERNAME VALIDATOR
// ============================================================================

// WindowsUsername returns a validator that validates Windows username format
func WindowsUsername() validator.String {
	return &windowsUsernameValidator{}
}

type windowsUsernameValidator struct{}

// Description returns a plain text description of the validator's behavior
func (v windowsUsernameValidator) Description(ctx context.Context) string {
	return "validates Windows username format (1-20 characters, no special chars)"
}

// MarkdownDescription returns a markdown formatted description of the validator's behavior
func (v windowsUsernameValidator) MarkdownDescription(ctx context.Context) string {
	return "Validates Windows username format: 1-20 characters, alphanumeric and limited special characters allowed.\n\n" +
		"**Rules:**\n" +
		"- Length: 1 to 20 characters\n" +
		"- Cannot contain: `\" / \\ [ ] : ; | = , + * ? < > @`\n" +
		"- Cannot consist only of dots or spaces\n" +
		"- Cannot end with a period"
}

// ValidateString performs the validation
func (v windowsUsernameValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// Skip validation if value is null or unknown
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	username := req.ConfigValue.ValueString()

	// Validate username using standalone function
	if err := ValidateUsername(username); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Windows Username",
			err.Error(),
		)
	}
}

// ValidateUsername performs standalone validation of a Windows username
// This function can be used outside of the Framework validator context (e.g., in imports)
func ValidateUsername(username string) error {
	// Rule 1: Length must be between 1 and 20 characters
	if len(username) < 1 {
		return fmt.Errorf("username cannot be empty")
	}

	if len(username) > 20 {
		return fmt.Errorf("username must be between 1 and 20 characters, got %d characters", len(username))
	}

	// Rule 2: Cannot contain invalid characters for Windows usernames
	// Invalid chars: " / \ [ ] : ; | = , + * ? < > @
	invalidChars := regexp.MustCompile(`["/\\[\]:;|=,+*?<>@]`)
	if invalidChars.MatchString(username) {
		return fmt.Errorf("username cannot contain these characters: \" / \\ [ ] : ; | = , + * ? < > @")
	}

	// Rule 3: Cannot be only dots or spaces
	onlyDotsOrSpaces := regexp.MustCompile(`^[. ]+$`)
	if onlyDotsOrSpaces.MatchString(username) {
		return fmt.Errorf("username cannot consist only of dots or spaces")
	}

	// Rule 4: Cannot end with a period (Windows restriction)
	if username[len(username)-1] == '.' {
		return fmt.Errorf("username cannot end with a period")
	}

	return nil
}
