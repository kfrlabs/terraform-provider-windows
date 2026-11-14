// Package provider: windows_scheduled_task resource implementation.
//
// Spec: windows_scheduled_task v1 (2026-04-27).
// Framework: terraform-plugin-framework v1.13.0.
// Client: winclient.ScheduledTaskClientImpl (ScheduledTasks PS module + COM).
package provider

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// Validators and their regexes. Split from resource_windows_scheduled_task.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// scheduledTaskNameRe rejects Windows-reserved characters (\/:*?"<>|) and enforces
// a 1-238 character length limit matching the Task Scheduler maximum.
// Uses a double-quoted Go string so each `\\` produces one literal backslash in the
// compiled regex pattern, making the intent explicit and gofmt-stable.
var scheduledTaskNameRe = regexp.MustCompile("^[^\\\\/:*?\"<>|]{1,238}$")

type scheduledTaskNameValidator struct{}

func (v scheduledTaskNameValidator) Description(_ context.Context) string {
	return `task name must not contain \ / : * ? " < > | and be 1-238 characters`
}
func (v scheduledTaskNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if !scheduledTaskNameRe.MatchString(req.ConfigValue.ValueString()) {
		resp.Diagnostics.AddAttributeError(req.Path,
			"Invalid task name",
			`Task name must be 1–238 characters and must not contain any of: \ / : * ? " < > |`)
	}
}

// scheduledTaskPathRe validates the Task Scheduler folder path format.
// A valid path starts with a backslash and every segment ends with a backslash,
// e.g. "\" (root) or "\Custom\" or "\Custom\Sub\".
// Segment content is any non-backslash sequence, allowing Unicode names, digits,
// spaces, and punctuation — matching the actual Task Scheduler folder name rules.
// Uses a double-quoted Go string: each `\\\\` produces one literal backslash in the
// compiled regex pattern, keeping the escape intent transparent.
var scheduledTaskPathRe = regexp.MustCompile(`^\\([^\\]+\\)*$`)

type scheduledTaskPathValidator struct{}

func (v scheduledTaskPathValidator) Description(_ context.Context) string {
	return `task path must start with a backslash and each folder segment must end with a backslash, e.g. "\" or "\Custom\" or "\Custom\Sub\"`
}
func (v scheduledTaskPathValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskPathValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val != "\\" && !scheduledTaskPathRe.MatchString(val) {
		resp.Diagnostics.AddAttributeError(req.Path,
			"Invalid task path",
			`Task path must start and end with backslash (e.g. "\" or "\Custom\Sub\").`)
	}
}

// scheduledTaskPrincipalCrossFieldValidator enforces EC-4/EC-5 password rules.
type scheduledTaskPrincipalCrossFieldValidator struct{}

func (v scheduledTaskPrincipalCrossFieldValidator) Description(_ context.Context) string {
	return "validates principal password/logon_type mutual-exclusion (EC-4/EC-5)"
}
func (v scheduledTaskPrincipalCrossFieldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskPrincipalCrossFieldValidator) ValidateResource(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var model windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.Principal.IsNull() || model.Principal.IsUnknown() {
		return
	}
	var principal windowsScheduledTaskPrincipalModel
	resp.Diagnostics.Append(model.Principal.As(ctx, &principal, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})...)
	if resp.Diagnostics.HasError() {
		return
	}
	if principal.LogonType.IsNull() || principal.LogonType.IsUnknown() {
		return
	}
	logonType := principal.LogonType.ValueString()

	// Tier 3: enforce mutual exclusion between password (legacy) and
	// password_wo (WriteOnly) inside the principal block. Cannot use
	// resourcevalidator.Conflicting at the top level because the
	// attributes are nested inside a SingleNestedAttribute; resolved
	// inline here against the As-decoded principal model.
	pwSet := !principal.Password.IsNull() && !principal.Password.IsUnknown()
	pwWoSet := !principal.PasswordWO.IsNull() && !principal.PasswordWO.IsUnknown()
	if pwSet && pwWoSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("principal").AtName("password_wo"),
			"Conflicting attributes",
			"`principal.password` and `principal.password_wo` are mutually exclusive. "+
				"Pick one: `password_wo` (recommended, never persisted in state) "+
				"or `password` (legacy, persisted as Sensitive in state).")
		return
	}

	// EC-4 is checked after WriteOnly values are overlaid from req.Config in
	// Create/Update. The framework intentionally omits WriteOnly values from
	// ValidateConfig, so checking them here rejects valid password_wo configs.
	// EC-5: forbidden logon types must have neither credential attribute.
	for _, forbidden := range []string{"Interactive", "S4U", "Group", "ServiceAccount"} {
		if logonType == forbidden && (pwSet || pwWoSet) {
			attrName := "password"
			if pwWoSet {
				attrName = "password_wo"
			}
			resp.Diagnostics.AddAttributeError(
				path.Root("principal").AtName(attrName),
				"Conflicting attributes",
				fmt.Sprintf(`%s must not be set when logon_type is %q (EC-5).`, attrName, logonType))
			break
		}
	}
}

// scheduledTaskTriggerCrossFieldValidator enforces EC-7 trigger type rules.
type scheduledTaskTriggerCrossFieldValidator struct{}

func (v scheduledTaskTriggerCrossFieldValidator) Description(_ context.Context) string {
	return "validates trigger type cross-field rules (EC-7)"
}
func (v scheduledTaskTriggerCrossFieldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v scheduledTaskTriggerCrossFieldValidator) ValidateResource(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var model windowsScheduledTaskModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.Triggers.IsNull() || model.Triggers.IsUnknown() {
		return
	}
	var triggers []windowsScheduledTaskTriggerModel
	resp.Diagnostics.Append(model.Triggers.ElementsAs(ctx, &triggers, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Triggers is a Set: elements have no stable index, so diagnostics are
	// reported against the collection plus the offending attribute name
	// rather than a per-element index path.
	trigPath := path.Root("triggers")
	for _, t := range triggers {
		if t.Type.IsNull() || t.Type.IsUnknown() {
			continue
		}
		tt := t.Type.ValueString()
		if (tt == "Once" || tt == "Daily" || tt == "Weekly") && t.StartBoundary.IsNull() {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("start_boundary"),
				"Missing required attribute",
				fmt.Sprintf(`start_boundary is required when trigger type is %q (EC-7).`, tt))
		}
		if tt == "Weekly" {
			if t.DaysOfWeek.IsNull() || t.DaysOfWeek.IsUnknown() {
				resp.Diagnostics.AddAttributeError(trigPath.AtName("days_of_week"),
					"Missing required attribute", `days_of_week is required when trigger type is "Weekly" (EC-7).`)
			} else {
				var days []string
				resp.Diagnostics.Append(t.DaysOfWeek.ElementsAs(ctx, &days, false)...)
				if len(days) == 0 {
					resp.Diagnostics.AddAttributeError(trigPath.AtName("days_of_week"),
						"Invalid attribute value", `days_of_week must not be empty when trigger type is "Weekly" (EC-7).`)
				}
			}
		} else if !t.DaysOfWeek.IsNull() && !t.DaysOfWeek.IsUnknown() {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("days_of_week"),
				"Conflicting attribute",
				fmt.Sprintf(`days_of_week must not be set when trigger type is %q (EC-7).`, tt))
		}
		if !t.DaysInterval.IsNull() && !t.DaysInterval.IsUnknown() && tt != "Daily" {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("days_interval"),
				"Conflicting attribute",
				fmt.Sprintf(`days_interval is only valid for "Daily" triggers, got %q (EC-7).`, tt))
		}
		if !t.WeeksInterval.IsNull() && !t.WeeksInterval.IsUnknown() && tt != "Weekly" {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("weeks_interval"),
				"Conflicting attribute",
				fmt.Sprintf(`weeks_interval is only valid for "Weekly" triggers, got %q (EC-7).`, tt))
		}
		if !t.UserID.IsNull() && !t.UserID.IsUnknown() && tt != "AtLogon" {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("user_id"),
				"Conflicting attribute",
				fmt.Sprintf(`user_id (trigger-level) is only valid for "AtLogon" triggers, got %q (EC-7).`, tt))
		}
		if !t.Delay.IsNull() && !t.Delay.IsUnknown() && t.Delay.ValueString() != "" && !scheduledTaskTriggerAllowsDelay(tt) {
			// MSFT_TaskDailyTrigger / MSFT_TaskTimeTrigger (Once) /
			// MSFT_TaskWeeklyTrigger expose no Delay property: assigning it
			// throws, the winclient try/catch swallows it, Windows registers
			// the trigger without delay, and apply then fails with
			// "inconsistent result after apply". Fail fast at plan instead.
			resp.Diagnostics.AddAttributeError(trigPath.AtName("delay"),
				"Conflicting attribute",
				fmt.Sprintf(`delay is only valid for "AtLogon", "AtStartup" and "OnEvent" triggers, got %q (EC-7).`, tt))
		}
		if tt == "OnEvent" {
			if t.Subscription.IsNull() || t.Subscription.IsUnknown() || t.Subscription.ValueString() == "" {
				resp.Diagnostics.AddAttributeError(trigPath.AtName("subscription"),
					"Missing required attribute",
					`subscription (XPath query) is required when trigger type is "OnEvent" (EC-7).`)
			}
		} else if !t.Subscription.IsNull() && !t.Subscription.IsUnknown() {
			resp.Diagnostics.AddAttributeError(trigPath.AtName("subscription"),
				"Conflicting attribute",
				fmt.Sprintf(`subscription must not be set when trigger type is %q (EC-7).`, tt))
		}
	}
}

func scheduledTaskTriggerAllowsDelay(triggerType string) bool {
	switch triggerType {
	case "AtLogon", "AtStartup", "OnEvent":
		return true
	default:
		return false
	}
}
