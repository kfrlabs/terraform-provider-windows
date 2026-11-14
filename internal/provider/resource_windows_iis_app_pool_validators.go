// Package provider - resource_windows_iis_app_pool implements the full
// Terraform resource lifecycle for windows_iis_app_pool.
//
// An IIS application pool is provisioned through the WebAdministration
// module (New-WebAppPool plus per-attribute Set-ItemProperty in one script,
// Start/Stop-WebAppPool for runtime state). Every non-identity attribute is
// Optional+Computed: only configured attributes are enforced, unconfigured
// ones reflect the observed value (same semantics as
// windows_firewall_profile).
//
// The SpecificUser identity password is WriteOnly + Sensitive
// (identity_password_wo): it travels to the host on stdin, is never
// persisted in state, and is re-sent only when identity_password_wo_version
// changes (same pattern as windows_local_user password_wo).
//
// Spec alignment: windows_iis_app_pool spec v1 (issue #283).
// Framework:      terraform-plugin-framework v1.19.0.
package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Validators and their regexes. Split from resource_windows_iis_app_pool.go (issue #349, no changes).
// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// iisAppPoolUsernameRe accepts the account shapes IIS understands (#324),
// deliberately permissive so built-in accounts are never rejected:
// DOMAIN\user (including `BUILTIN\...` and `NT AUTHORITY\...`), UPN
// (user@domain), or a bare local name. Emptiness is rejected by the length
// check alongside; presence for SpecificUser stays in
// iisAppPoolIdentityValidator.
var iisAppPoolUsernameRe = regexp.MustCompile(`^([^@\\]+\\[^@\\]+|[^@]+@[^@]+|[^@\\]+)$`)

const iisAppPoolUsernameDesc = "must be a DOMAIN\\user account, a UPN (user@domain), or a bare local account name"

// iisAppPoolNameValidator enforces the pool-name rules at plan time
// (mirroring winclient.ValidateIISAppPoolName): no forbidden characters and
// no leading/trailing spaces. Length is covered by LengthBetween.
type iisAppPoolNameValidator struct{}

func (v iisAppPoolNameValidator) Description(_ context.Context) string {
	return "Application pool name must not contain / \\ [ ] : ; , ? * \" < > | and must not have leading or trailing spaces."
}

func (v iisAppPoolNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisAppPoolNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if strings.TrimSpace(val) != val {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid application pool name",
			fmt.Sprintf("Application pool name %q must not have leading or trailing spaces.", val),
		)
		return
	}
	if strings.ContainsAny(val, `/\[]:;,?*"<>|`) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid application pool name",
			fmt.Sprintf("Application pool name %q must not contain any of / \\ [ ] : ; , ? * \" < > |.", val),
		)
	}
}

// iisAppPoolScheduleRe matches a 24h HH:MM:SS entry.
var iisAppPoolScheduleRe = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d:[0-5]\d$`)

// iisAppPoolScheduleValidator validates every recycling_schedule entry as
// HH:MM:SS (24h). Null and unknown sets are skipped; unknown elements defer
// to apply-time handling.
type iisAppPoolScheduleValidator struct{}

func (v iisAppPoolScheduleValidator) Description(_ context.Context) string {
	return "Each recycling schedule entry must be HH:MM:SS (24h)."
}

func (v iisAppPoolScheduleValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisAppPoolScheduleValidator) ValidateSet(ctx context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var entries []types.String
	diags := req.ConfigValue.ElementsAs(ctx, &entries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, e := range entries {
		if e.IsNull() || e.IsUnknown() {
			continue
		}
		if !iisAppPoolScheduleRe.MatchString(e.ValueString()) {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid recycling schedule entry",
				fmt.Sprintf("Recycling schedule entry %q must be HH:MM:SS (24h), e.g. \"03:00:00\".", e.ValueString()),
			)
		}
	}
}

// iisAppPoolIdentityValidator enforces the SpecificUser credential contract
// at plan time and warns on the LocalSystem identity.
type iisAppPoolIdentityValidator struct{}

func (v iisAppPoolIdentityValidator) Description(_ context.Context) string {
	return "Requires identity_username and identity_password_wo when identity_type is SpecificUser; warns on LocalSystem."
}

func (v iisAppPoolIdentityValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisAppPoolIdentityValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var identityType types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_type"), &identityType)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if identityType.IsNull() || identityType.IsUnknown() {
		return
	}
	switch identityType.ValueString() {
	case "LocalSystem":
		resp.Diagnostics.AddAttributeWarning(
			path.Root("identity_type"),
			"Application pool runs as LocalSystem",
			"identity_type = \"LocalSystem\" runs the pool's worker processes with full machine privileges. "+
				"Prefer \"ApplicationPoolIdentity\" (the default, least privilege) unless the workload genuinely "+
				"requires SYSTEM.",
		)
	case "SpecificUser":
		var username types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_username"), &username)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if username.IsNull() || (!username.IsUnknown() && username.ValueString() == "") {
			if !username.IsUnknown() {
				resp.Diagnostics.AddAttributeError(
					path.Root("identity_username"),
					"identity_username is required for SpecificUser",
					"identity_type = \"SpecificUser\" requires identity_username (e.g. \"CONTOSO\\svc-web\").",
				)
			}
		}
		var password types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_password_wo"), &password)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if password.IsNull() || (!password.IsUnknown() && password.ValueString() == "") {
			if !password.IsUnknown() {
				resp.Diagnostics.AddAttributeError(
					path.Root("identity_password_wo"),
					"identity_password_wo is required for SpecificUser",
					"identity_type = \"SpecificUser\" requires identity_password_wo together with "+
						"identity_password_wo_version (rotation counter).",
				)
			}
		}
	default:
		// A username or password configured without SpecificUser is inert:
		// IIS only consumes the credential for that identity type.
		var username types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_username"), &username)...)
		var password types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("identity_password_wo"), &password)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if (!username.IsNull() && !username.IsUnknown() && username.ValueString() != "") ||
			(!password.IsNull() && !password.IsUnknown() && password.ValueString() != "") {
			resp.Diagnostics.AddAttributeWarning(
				path.Root("identity_type"),
				"Identity credential without SpecificUser",
				"identity_username / identity_password_wo are only consumed when identity_type = "+
					"\"SpecificUser\"; with the current identity type they are stored but inert.",
			)
		}
	}
}
