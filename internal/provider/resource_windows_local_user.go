// Package provider contains the Terraform resource implementation for
// windows_local_user.
//
// Spec alignment: windows_local_user spec v1 (2026-04-25).
// Framework:      terraform-plugin-framework v1.13.0.
//
// Design notes:
//   - The Terraform resource ID is the user SID (ADR-LU-1), stable across renames.
//   - name changes trigger Rename-LocalUser -SID in place (EC-5, no ForceNew).
//   - Built-in accounts (RID 500/501/503/504) cannot be destroyed (ADR-LU-2, EC-2).
//   - Password is Sensitive only (ADR-LU-3, TPF v1.13.0 constraint); injected via
//     stdin, never in script body or logs.
//   - Import accepts SID ("S-" prefix) or SAM name (EC-11).
//   - account_never_expires=true conflicts with account_expires (EC-14).
//   - account_expires must be in the future at Create time (EC-13).
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ecritel/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsLocalUserResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsLocalUserResource)(nil)
	_ resource.ResourceWithImportState = (*windowsLocalUserResource)(nil)
)

// NewWindowsLocalUserResource is the constructor registered in provider.go.
func NewWindowsLocalUserResource() resource.Resource {
	return &windowsLocalUserResource{}
}

// windowsLocalUserResource is the TPF resource type for windows_local_user.
type windowsLocalUserResource struct {
	client *winclient.Client
	user   winclient.LocalUserClient
}

// ---------------------------------------------------------------------------
// windowsLocalUserModel — Terraform state / plan model
// ---------------------------------------------------------------------------

// windowsLocalUserModel is the Terraform state/plan model for windows_local_user.
// Field tags match the snake_case attribute names in the schema.
//
// Password is stored as Sensitive; it is preserved verbatim from prior state
// on every Read (Windows cannot return the plaintext, ADR-LU-3).
type windowsLocalUserModel struct {
	ID                       types.String `tfsdk:"id"`
	SID                      types.String `tfsdk:"sid"`
	Name                     types.String `tfsdk:"name"`
	FullName                 types.String `tfsdk:"full_name"`
	Description              types.String `tfsdk:"description"`
	Password                 types.String `tfsdk:"password"`
	PasswordWoVersion        types.Int64  `tfsdk:"password_wo_version"`
	Enabled                  types.Bool   `tfsdk:"enabled"`
	PasswordNeverExpires     types.Bool   `tfsdk:"password_never_expires"`
	UserMayNotChangePassword types.Bool   `tfsdk:"user_may_not_change_password"`
	AccountNeverExpires      types.Bool   `tfsdk:"account_never_expires"`
	AccountExpires           types.String `tfsdk:"account_expires"`
	LastLogon                types.String `tfsdk:"last_logon"`
	PasswordLastSet          types.String `tfsdk:"password_last_set"`
	PrincipalSource          types.String `tfsdk:"principal_source"`
}

// ---------------------------------------------------------------------------
// Schema validators
// ---------------------------------------------------------------------------

// localUserNameRegex enforces structural constraints for Windows local SAM
// account names (EC-10): 1..20 characters, none of which are the forbidden
// characters / \ [ ] : ; | = , + * ? < > "
//
// Written as a double-quoted Go string (NOT a raw backtick string) to avoid
// the backtick-truncation issue documented in ADR-LU-5 / ADR-LG-9.
var localUserNameRegex = regexp.MustCompile(
	"^[^/\\\\\\[\\]:;|=,+*?<>\"]{1,20}$",
)

// localUserNameValidator enforces whitespace rules for the name attribute (EC-10).
type localUserNameValidator struct{}

// Description returns a plain-text description.
func (localUserNameValidator) Description(_ context.Context) string {
	return "must not consist solely of whitespace and must not start or end with a space"
}

// MarkdownDescription returns a Markdown description.
func (v localUserNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString enforces whitespace constraints for the name attribute.
func (localUserNameValidator) ValidateString(
	_ context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()

	if strings.TrimSpace(val) == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid local user name",
			fmt.Sprintf("name %q consists solely of whitespace characters, "+
				"which Windows rejects as a local SAM account name (EC-10)", val),
		)
		return
	}
	if len(val) > 0 && (val[0] == ' ' || val[len(val)-1] == ' ') {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid local user name",
			fmt.Sprintf("name %q must not start or end with a space (EC-10)", val),
		)
	}
}

// rfc3339Validator validates that a string attribute is a valid RFC3339 timestamp.
type rfc3339Validator struct{}

// Description returns a plain-text description.
func (rfc3339Validator) Description(_ context.Context) string {
	return "must be a valid RFC3339 timestamp (e.g. \"2027-12-31T23:59:59Z\")"
}

// MarkdownDescription returns a Markdown description.
func (v rfc3339Validator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString validates the RFC3339 format of account_expires.
func (rfc3339Validator) ValidateString(
	_ context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if _, err := time.Parse(time.RFC3339, val); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid RFC3339 timestamp",
			fmt.Sprintf("%q is not a valid RFC3339 timestamp "+
				"(expected e.g. \"2027-12-31T23:59:59Z\"): %s", val, err),
		)
	}
}

// accountExpiresConflictValidator checks that account_expires is not set when
// account_never_expires=true (EC-14, ADR-LU-8).
//
// A plain ConflictsWith validator cannot be used here because account_never_expires
// has Default: true and is always non-null in a valid config, which would make
// account_expires unusable even when account_never_expires=false.
type accountExpiresConflictValidator struct{}

// Description returns a plain-text description.
func (accountExpiresConflictValidator) Description(_ context.Context) string {
	return "account_expires is mutually exclusive with account_never_expires = true (EC-14)"
}

// MarkdownDescription returns a Markdown description.
func (v accountExpiresConflictValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString enforces the mutual exclusion when account_never_expires = true.
func (accountExpiresConflictValidator) ValidateString(
	ctx context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}

	var neverExpires types.Bool
	diags := req.Config.GetAttribute(ctx, path.Root("account_never_expires"), &neverExpires)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !neverExpires.IsNull() && !neverExpires.IsUnknown() && neverExpires.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Conflicting attributes (EC-14)",
			"account_never_expires and account_expires are mutually exclusive; "+
				"set account_never_expires = false when specifying account_expires.",
		)
	}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsLocalUserResource) Metadata(
	_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_local_user"
}

// Schema returns the complete TPF schema for the windows_local_user resource.
func (r *windowsLocalUserResource) Schema(
	_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse,
) {
	resp.Schema = windowsLocalUserSchemaDefinition()
}

// windowsLocalUserSchemaDefinition returns the complete TPF schema.
func windowsLocalUserSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a Windows local user account (SAM database) on a remote host " +
			"via WinRM and PowerShell (`Microsoft.PowerShell.LocalAccounts` module, available " +
			"from Windows Server 2016 / Windows 10 build 1607 and later).\n\n" +
			"The Terraform resource ID is set to the user **SID** (e.g. `S-1-5-21-…-1001`), " +
			"which is stable across renames. A change to the `name` attribute triggers " +
			"`Rename-LocalUser` in place — no resource replacement (ADR-LU-1).\n\n" +
			"~> **Password:** The `password` attribute is `Sensitive` but **not natively " +
			"write-only** in TPF v1.13.0 (write-only support requires TPF ≥ 1.14.0 + Terraform CLI " +
			"≥ 1.11). The plaintext is injected via stdin inside the PowerShell script and " +
			"**never appears in WinRM trace logs or diagnostic output** (ADR-LU-3).\n\n" +
			"~> **Built-in accounts:** Attempting `terraform destroy` on a built-in account " +
			"(RID 500/501/503/504) results in a **hard error**. Use `terraform state rm` instead.",

		Attributes: map[string]schema.Attribute{
			// ---- Terraform ID / SID ----
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Terraform resource ID. Equal to sid (the user SID). Stable across renames.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sid": schema.StringAttribute{
				Computed: true,
				Description: "Security Identifier of the user account (e.g. \"S-1-5-21-...-1001\"). " +
					"Assigned by Windows at creation time and stable across renames. " +
					"Used as the Terraform resource ID (ADR-LU-1). Read-only.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// ---- Identity ----
			"name": schema.StringAttribute{
				Required: true,
				Description: "SAM account name of the local user (e.g. \"svc-backup\", \"jdoe\"). " +
					"Length: 1..20 characters (SAM hard limit, EC-10, ADR-LU-5). " +
					"Forbidden characters: / \\ [ ] : ; | = , + * ? < > \". " +
					"A change triggers Rename-LocalUser (no resource replacement).",
				MarkdownDescription: "SAM account name of the local user (e.g. `svc-backup`, `jdoe`).\n\n" +
					"Constraints:\n" +
					"  * Length: 1..20 characters (Windows SAM hard limit, EC-10, ADR-LU-5)\n" +
					"  * Forbidden characters: `/` `\\\\` `[` `]` `:` `;` `|` `=` `,` `+` `*` `?` `<` `>` `\"`\n" +
					"  * Must not consist solely of whitespace\n" +
					"  * Must not start or end with a space\n\n" +
					"**In-place rename:** a name change issues `Rename-LocalUser -SID` \u2014 " +
					"no resource replacement (ADR-LU-1, EC-5).",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 20),
					stringvalidator.RegexMatches(
						localUserNameRegex,
						"must not contain any of the forbidden characters: / \\ [ ] : ; | = , + * ? < > \"",
					),
					localUserNameValidator{},
				},
			},
			"full_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
				Description: "Display name of the user (New-LocalUser -FullName / Set-LocalUser -FullName). " +
					"Optional; defaults to empty string.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(0, 256),
				},
			},
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
				MarkdownDescription: "Optional free-text description of the user account.\n\n" +
					"~> **48-character limit:** Windows hard-limits LocalUser descriptions to " +
					"**48 characters** (EC-8, ADR-LU-9). This is different from `windows_local_group` " +
					"which allows 256 characters. The schema enforces this limit at plan time.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(0, 48),
				},
			},

			// ---- Credentials ----
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "Password for the user account. Must satisfy the local password policy " +
					"(minimum length, complexity). Required at Create; if omitted the provider raises " +
					"a diagnostic error before calling `New-LocalUser`.\n\n" +
					"The plaintext is injected via stdin inside the PowerShell script and **never " +
					"appears in WinRM trace logs or provider diagnostics** (ADR-LU-3, EC-6).\n\n" +
					"After `terraform import`, this attribute is `null`. Set it in HCL before " +
					"the next apply (EC-11).",
			},
			"password_wo_version": schema.Int64Attribute{
				Optional: true,
				Description: "Monotonically increasing version counter for password rotation (EC-6). " +
					"When this value changes between plan and apply, the provider re-applies the " +
					"password via Set-LocalUser -Password regardless of whether the password value " +
					"changed. Conventionally starts at 1. Must be a positive integer if set.",
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},

			// ---- Account state & flags ----
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				Description: "Whether the account is enabled (true, default) or disabled (false). " +
					"Controlled via Enable-LocalUser / Disable-LocalUser.",
			},
			"password_never_expires": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "When true, the account password never expires regardless of the local " +
					"password policy. Maps to -PasswordNeverExpires.",
			},
			"user_may_not_change_password": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "When true, the user is prevented from changing their own password. " +
					"Maps to -UserMayNotChangePassword (double-negative Windows semantics: " +
					"true = cannot change, false = can change).",
			},
			"account_never_expires": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				Description: "When true (default), the account never expires (-AccountNeverExpires). " +
					"When false, the account expires at account_expires. " +
					"Mutually exclusive with account_expires when true (EC-14, ADR-LU-8).",
			},
			"account_expires": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "RFC3339 timestamp at which the account expires " +
					"(e.g. `\"2027-12-31T23:59:59Z\"`). When set, `account_never_expires` must " +
					"be `false`. Must be in the future at Create time (EC-13). " +
					"At Update time, past values are forwarded to Windows without blocking.",
				Validators: []validator.String{
					rfc3339Validator{},
					accountExpiresConflictValidator{},
				},
			},

			// ---- Computed / read-only ----
			"last_logon": schema.StringAttribute{
				Computed: true,
				Description: "RFC3339 timestamp of the last logon, or empty string if never logged on. " +
					"Informational only; drift on this field does not trigger an Update.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"password_last_set": schema.StringAttribute{
				Computed: true,
				Description: "RFC3339 timestamp of the last password change, or empty string if not set. " +
					"Refreshed after a provider-initiated password rotation. " +
					"Does NOT drive autonomous Update cycles (ADR-LU-4).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"principal_source": schema.StringAttribute{
				Computed: true,
				Description: "Origin of the account as reported by Windows (\"Local\" for local accounts). " +
					"Exposed for consistency with windows_local_group_member.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure extracts the *winclient.Client from provider data and constructs
// a LocalUserClientImpl.
func (r *windowsLocalUserResource) Configure(
	_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.client = c
	r.user = winclient.NewLocalUserClient(c)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create creates the Windows local user and persists the full returned state.
//
// Pre-flight (delegated to client):
//   - Module guard.
//   - Name collision check (EC-1).
//
// EC-13: account_expires must be in the future at Create time.
func (r *windowsLocalUserResource) Create(
	ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse,
) {
	var plan windowsLocalUserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// EC-13: account_expires must be in the future at Create time.
	if !plan.AccountExpires.IsNull() && !plan.AccountExpires.IsUnknown() {
		expStr := plan.AccountExpires.ValueString()
		if expStr != "" {
			t, err := time.Parse(time.RFC3339, expStr)
			if err == nil && t.Before(time.Now().UTC()) {
				resp.Diagnostics.AddAttributeError(
					path.Root("account_expires"),
					"account_expires must be in the future at Create time (EC-13)",
					fmt.Sprintf(
						"account_expires %q is already in the past. "+
							"To create an immediately-expired account, create without account_expires then update.",
						expStr,
					),
				)
				return
			}
		}
	}

	// Require password at Create time.
	password := plan.Password.ValueString()
	if plan.Password.IsNull() || password == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"password is required at Create time",
			"Windows requires a password for local user accounts. "+
				"Set the password attribute in your configuration.",
		)
		return
	}

	input := planToUserInput(plan)

	us, err := r.user.Create(ctx, input, password)
	if err != nil {
		addLocalUserDiag(&resp.Diagnostics, "Create windows_local_user failed", err)
		return
	}

	next := stateFromUser(us)
	next.Password = plan.Password
	next.PasswordWoVersion = plan.PasswordWoVersion

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes the Terraform state from the observed Windows state.
//
// EC-3: calls resp.State.RemoveResource() when the user no longer exists.
// EC-4: uses strings.EqualFold for name comparison to avoid spurious renames
// on case-only differences (Windows casing wins in state).
// ADR-LU-3: password and password_wo_version are preserved from prior state.
func (r *windowsLocalUserResource) Read(
	ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse,
) {
	var state windowsLocalUserModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sid := state.SID.ValueString()
	if sid == "" {
		sid = state.ID.ValueString()
	}

	us, err := r.user.Read(ctx, sid)
	if err != nil {
		addLocalUserDiag(&resp.Diagnostics, "Read windows_local_user failed", err)
		return
	}
	if us == nil {
		// EC-3: user disappeared outside Terraform — signal re-creation.
		resp.State.RemoveResource(ctx)
		return
	}

	next := stateFromUser(us)

	// Preserve sensitive/write-only fields (ADR-LU-3): Windows cannot return them.
	next.Password = state.Password
	next.PasswordWoVersion = state.PasswordWoVersion

	// EC-4 / ADR-LU: case-insensitive name normalisation.
	// Keep prior state name when Windows casing differs only in case.
	priorName := state.Name.ValueString()
	if strings.EqualFold(us.Name, priorName) {
		next.Name = types.StringValue(priorName)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place changes. The mandatory call order (ADR-LU-6) is:
//  1. Rename (if name changed, case-insensitive check).
//  2. Set-LocalUser (scalar attributes).
//  3. SetPassword (if password_wo_version changed or password value changed).
//  4. Enable / Disable (if enabled changed).
//
// All steps use -SID throughout. After all steps, state is refreshed via Read.
func (r *windowsLocalUserResource) Update(
	ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse,
) {
	var plan, prior windowsLocalUserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sid := prior.SID.ValueString()
	if sid == "" {
		sid = prior.ID.ValueString()
	}

	// Step 1: Rename if name changed (case-insensitive comparison, EC-5).
	if !strings.EqualFold(plan.Name.ValueString(), prior.Name.ValueString()) {
		if err := r.user.Rename(ctx, sid, plan.Name.ValueString()); err != nil {
			addLocalUserDiag(&resp.Diagnostics, "Rename windows_local_user failed", err)
			return
		}
	}

	// Step 2: Update scalar attributes if any changed.
	if scalarAttrsChanged(plan, prior) {
		input := planToUserInput(plan)
		if _, err := r.user.Update(ctx, sid, input); err != nil {
			addLocalUserDiag(&resp.Diagnostics, "Update windows_local_user (Set-LocalUser) failed", err)
			return
		}
	}

	// Step 3: Password rotation (EC-6).
	// Trigger: password_wo_version changed OR password value changed OR
	// password is set in plan but was null in prior state (post-import).
	needsPasswordRotation := !plan.PasswordWoVersion.Equal(prior.PasswordWoVersion) ||
		(!plan.Password.IsNull() && !plan.Password.Equal(prior.Password)) ||
		(!plan.Password.IsNull() && prior.Password.IsNull())

	if needsPasswordRotation {
		pw := plan.Password.ValueString()
		if pw == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("password"),
				"password required for rotation",
				"password_wo_version changed or password value changed, "+
					"but the password attribute is empty. Set a non-empty password.",
			)
			return
		}
		if err := r.user.SetPassword(ctx, sid, pw); err != nil {
			addLocalUserDiag(&resp.Diagnostics, "SetPassword windows_local_user failed", err)
			return
		}
	}

	// Step 4: Enable / Disable if enabled changed.
	if !plan.Enabled.Equal(prior.Enabled) {
		var err error
		if plan.Enabled.ValueBool() {
			err = r.user.Enable(ctx, sid)
		} else {
			err = r.user.Disable(ctx, sid)
		}
		if err != nil {
			addLocalUserDiag(&resp.Diagnostics, "Enable/Disable windows_local_user failed", err)
			return
		}
	}

	// Refresh state after all mutations.
	us, err := r.user.Read(ctx, sid)
	if err != nil {
		addLocalUserDiag(&resp.Diagnostics, "Read after Update windows_local_user failed", err)
		return
	}
	if us == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	next := stateFromUser(us)
	next.Password = plan.Password
	next.PasswordWoVersion = plan.PasswordWoVersion

	// EC-4: if name was equal (case-fold), keep plan name to avoid diff.
	if strings.EqualFold(us.Name, plan.Name.ValueString()) {
		next.Name = plan.Name
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the Windows local user.
//
// EC-2 / ADR-LU-2: returns a hard error (not a warning) if the user's SID
// RID is 500/501/503/504 (built-in account). This check is performed inside
// the client before Remove-LocalUser is called.
func (r *windowsLocalUserResource) Delete(
	ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse,
) {
	var state windowsLocalUserModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sid := state.SID.ValueString()
	if sid == "" {
		sid = state.ID.ValueString()
	}

	if err := r.user.Delete(ctx, sid); err != nil {
		addLocalUserDiag(&resp.Diagnostics, "Delete windows_local_user failed", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState — EC-11
// ---------------------------------------------------------------------------

// ImportState handles terraform import for windows_local_user.
//
// The import ID may be either:
//   - A SID string (auto-detected: starts with "S-") → ImportBySID (EC-11)
//   - A SAM account name (all other values) → ImportByName (EC-11)
//
// After import, password is null. The operator MUST set the password in HCL
// and apply to reconcile (EC-11, ADR-LU-3).
func (r *windowsLocalUserResource) ImportState(
	ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse,
) {
	importID := req.ID

	var us *winclient.UserState
	var err error

	if strings.HasPrefix(importID, "S-") {
		us, err = r.user.ImportBySID(ctx, importID)
		if err != nil {
			addLocalUserDiag(&resp.Diagnostics,
				fmt.Sprintf("Cannot import windows_local_user by SID %q", importID), err)
			return
		}
	} else {
		us, err = r.user.ImportByName(ctx, importID)
		if err != nil {
			addLocalUserDiag(&resp.Diagnostics,
				fmt.Sprintf("Cannot import windows_local_user by name %q", importID), err)
			return
		}
	}

	if us == nil {
		resp.Diagnostics.AddError(
			"Import failed: user not found",
			fmt.Sprintf("No local user found with name or SID %q on the target host (EC-11).", importID),
		)
		return
	}

	next := stateFromUser(us)
	// Password and PasswordWoVersion are null after import (EC-11, ADR-LU-3).
	next.Password = types.StringNull()
	next.PasswordWoVersion = types.Int64Null()

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// stateFromUser converts a *winclient.UserState into a windowsLocalUserModel.
// Password and PasswordWoVersion are intentionally NOT set — the caller is
// responsible for preserving or setting them (ADR-LU-3).
func stateFromUser(us *winclient.UserState) windowsLocalUserModel {
	m := windowsLocalUserModel{
		ID:                       types.StringValue(us.SID),
		SID:                      types.StringValue(us.SID),
		Name:                     types.StringValue(us.Name),
		FullName:                 types.StringValue(us.FullName),
		Description:              types.StringValue(us.Description),
		Enabled:                  types.BoolValue(us.Enabled),
		PasswordNeverExpires:     types.BoolValue(us.PasswordNeverExpires),
		UserMayNotChangePassword: types.BoolValue(us.UserMayNotChangePassword),
		AccountNeverExpires:      types.BoolValue(us.AccountNeverExpires),
		LastLogon:                types.StringValue(us.LastLogon),
		PasswordLastSet:          types.StringValue(us.PasswordLastSet),
		PrincipalSource:          types.StringValue(us.PrincipalSource),
	}

	if us.AccountExpires != "" {
		m.AccountExpires = types.StringValue(us.AccountExpires)
	} else {
		m.AccountExpires = types.StringNull()
	}

	// Caller sets Password and PasswordWoVersion.
	return m
}

// planToUserInput converts a plan/state model into a winclient.UserInput.
func planToUserInput(m windowsLocalUserModel) winclient.UserInput {
	return winclient.UserInput{
		Name:                     m.Name.ValueString(),
		FullName:                 m.FullName.ValueString(),
		Description:              m.Description.ValueString(),
		PasswordNeverExpires:     m.PasswordNeverExpires.ValueBool(),
		UserMayNotChangePassword: m.UserMayNotChangePassword.ValueBool(),
		AccountNeverExpires:      m.AccountNeverExpires.ValueBool(),
		AccountExpires:           m.AccountExpires.ValueString(),
		Enabled:                  m.Enabled.ValueBool(),
	}
}

// scalarAttrsChanged returns true if any Set-LocalUser-managed attribute
// differs between plan and prior state.
func scalarAttrsChanged(plan, prior windowsLocalUserModel) bool {
	return !plan.FullName.Equal(prior.FullName) ||
		!plan.Description.Equal(prior.Description) ||
		!plan.PasswordNeverExpires.Equal(prior.PasswordNeverExpires) ||
		!plan.UserMayNotChangePassword.Equal(prior.UserMayNotChangePassword) ||
		!plan.AccountNeverExpires.Equal(prior.AccountNeverExpires) ||
		!plan.AccountExpires.Equal(prior.AccountExpires)
}

// addLocalUserDiag converts a winclient error into a TPF diagnostic.
func addLocalUserDiag(diags *diag.Diagnostics, summary string, err error) {
	var lue *winclient.LocalUserError
	if errors.As(err, &lue) {
		detail := lue.Message
		if len(lue.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range lue.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if lue.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", lue.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
