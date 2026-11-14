// Package provider — plan-time validator for the timeout attribute.
//
// The timeout bounds only the SSH connection establishment (TCP dial plus
// handshake) and is expressed as a Go duration string (e.g. "30s", "2m").
// A non-positive or unparsable value could never dial successfully, so it
// fails fast at plan time instead (issue #350).
package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// timeoutDurationValidator accepts any positive Go duration string with no
// upper bound. Null and unknown values are skipped: null falls back to
// WINDOWS_TIMEOUT (then New's 30s default), and unknown values are rechecked
// once known.
type timeoutDurationValidator struct{}

// Description returns a plain-text description.
func (timeoutDurationValidator) Description(_ context.Context) string {
	return "must be a positive Go duration string (e.g. 30s, 2m)"
}

// MarkdownDescription returns a Markdown description.
func (v timeoutDurationValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString rejects values that are not positive Go durations. Null
// and unknown values are skipped.
func (timeoutDurationValidator) ValidateString(
	_ context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	d, err := time.ParseDuration(s)
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid timeout",
			fmt.Sprintf("Could not parse duration %q: %s. Use a Go duration string such as 30s or 2m.", s, err),
		)
		return
	}
	if d <= 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid timeout",
			fmt.Sprintf("Timeout must be a positive duration, got %q.", s),
		)
	}
}
