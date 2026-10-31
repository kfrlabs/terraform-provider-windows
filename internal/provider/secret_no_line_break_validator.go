// Package provider — shared plan-time validator for secret attributes.
//
// Secrets on windows_local_user, windows_scheduled_task and windows_service
// are streamed to the target over stdin and consumed with
// [Console]::In.ReadLine(). A value containing a carriage return or line
// feed would be silently truncated at the first line break, so every secret
// attribute rejects \r and \n at plan time instead (issue #195).
package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// secretNoLineBreakValidator rejects secret values containing carriage
// return or line feed characters. The diagnostic never echoes the value
// because these attributes are Sensitive.
type secretNoLineBreakValidator struct{}

// Description returns a plain-text description.
func (secretNoLineBreakValidator) Description(_ context.Context) string {
	return "must not contain carriage return or line feed characters"
}

// MarkdownDescription returns a Markdown description.
func (v secretNoLineBreakValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString rejects values containing \r or \n. Null and unknown
// values are skipped. For WriteOnly attributes the framework validates the
// configured value, so wiring this validator on a WriteOnly attribute still
// covers the operator-supplied secret.
func (secretNoLineBreakValidator) ValidateString(
	_ context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.ContainsAny(req.ConfigValue.ValueString(), "\r\n") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Secret must not contain line breaks",
			"The value must not contain carriage return (\\r) or line feed (\\n) characters: "+
				"secrets are read with ReadLine(), so anything from the first line break on "+
				"would be silently truncated. If the value comes from file(), wrap it with "+
				"trimspace() to strip the trailing newline.",
		)
	}
}
