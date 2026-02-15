package validators

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// ============================================================================
// WINDOWS GROUP NAME VALIDATOR
// ============================================================================

// WindowsGroupName returns a validator that validates Windows group name format
func WindowsGroupName() validator.String {
	return &windowsGroupNameValidator{}
}

type windowsGroupNameValidator struct{}

// Description returns a plain text description of the validator's behavior
func (v windowsGroupNameValidator) Description(ctx context.Context) string {
	return "validates Windows group name format (1-256 characters, no special chars)"
}

// MarkdownDescription returns a markdown formatted description of the validator's behavior
func (v windowsGroupNameValidator) MarkdownDescription(ctx context.Context) string {
	return "Validates Windows group name format: 1-256 characters, alphanumeric and limited special characters allowed.\n\n" +
		"**Rules:**\n" +
		"- Length: 1 to 256 characters\n" +
		"- Cannot contain: `\" / \\ [ ] : ; | = , + * ? < > @`\n" +
		"- Cannot consist only of dots or spaces\n" +
		"- Cannot end with a period"
}

// ValidateString performs the validation
func (v windowsGroupNameValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// Skip validation if value is null or unknown
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	groupname := req.ConfigValue.ValueString()

	// Validate group name using standalone function
	if err := ValidateGroupName(groupname); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Windows Group Name",
			err.Error(),
		)
	}
}

// ValidateGroupName performs standalone validation of a Windows group name
// This function can be used outside of the Framework validator context (e.g., in imports)
func ValidateGroupName(groupname string) error {
	// Rule 1: Length must be between 1 and 256 characters
	if len(groupname) < 1 {
		return fmt.Errorf("group name cannot be empty")
	}

	if len(groupname) > 256 {
		return fmt.Errorf("group name must be between 1 and 256 characters, got %d characters", len(groupname))
	}

	// Rule 2: Cannot contain invalid characters for Windows group names
	// Invalid chars: " / \ [ ] : ; | = , + * ? < > @
	invalidChars := regexp.MustCompile(`["/\\[\]:;|=,+*?<>@]`)
	if invalidChars.MatchString(groupname) {
		return fmt.Errorf("group name cannot contain these characters: \" / \\ [ ] : ; | = , + * ? < > @")
	}

	// Rule 3: Cannot be only dots or spaces
	onlyDotsOrSpaces := regexp.MustCompile(`^[. ]+$`)
	if onlyDotsOrSpaces.MatchString(groupname) {
		return fmt.Errorf("group name cannot consist only of dots or spaces")
	}

	// Rule 4: Cannot end with a period (Windows restriction)
	if groupname[len(groupname)-1] == '.' {
		return fmt.Errorf("group name cannot end with a period")
	}

	return nil
}
