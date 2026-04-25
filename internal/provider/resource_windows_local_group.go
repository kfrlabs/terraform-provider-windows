// Package provider contains the Terraform resource implementation for
// windows_local_group.
//
// Spec alignment: windows_local_group spec v1 (2026-04-25).
// Framework:      terraform-plugin-framework v1.13.0.
//
// Design notes:
//   - The Terraform resource ID is the group SID (ADR-LG-1), stable across renames.
//   - A change to the name attribute triggers Rename-LocalGroup in place — no
//     resource replacement (EC-5).
//   - Built-in groups (SID prefix S-1-5-32-*) cannot be destroyed (EC-2, ADR-LG-2).
//   - Read uses strings.EqualFold for name drift comparison to prevent spurious
//     renames on case-only differences (EC-4, ADR-LG-4).
//   - Import accepts either a group name or a SID string; auto-detected by
//     "S-" prefix (EC-10, ADR-LG-6).
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsLocalGroupResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsLocalGroupResource)(nil)
	_ resource.ResourceWithImportState = (*windowsLocalGroupResource)(nil)
)

// NewWindowsLocalGroupResource is the constructor registered in provider.go.
func NewWindowsLocalGroupResource() resource.Resource {
	return &windowsLocalGroupResource{}
}

// windowsLocalGroupResource is the TPF resource type for windows_local_group.
type windowsLocalGroupResource struct {
	client *winclient.Client
	grp    winclient.WindowsLocalGroupClient
}

// ---------------------------------------------------------------------------
// windowsLocalGroupModel — Terraform state / plan model
// ---------------------------------------------------------------------------

// windowsLocalGroupModel is the Terraform state/plan model for the
// windows_local_group resource. Field tags match the snake_case attribute
// names declared in the schema below.
//
// SID is anchored as the Terraform resource ID (ADR-LG-1): it survives
// renames and ensures the resource target is unambiguous even when an
// operator performs an out-of-band rename.
type windowsLocalGroupModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	SID         types.String `tfsdk:"sid"`
}

// ---------------------------------------------------------------------------
// localGroupNameRegex — name character-class validator (EC-6)
// ---------------------------------------------------------------------------

// localGroupNameRegex enforces the structural constraint for Windows local
// group names: 1..256 characters, none of which may be the forbidden
// characters / \ [ ] : ; | = , + * ? < > "
//
// Written as a double-quoted Go string (NOT a raw backtick string) to avoid
// the backtick-truncation issue documented in ADR-LG-9.
//
// Character-class breakdown inside [^ ... ]:
//
//	/        forward slash            (literal)
//	\\\\     Go \\  → regex \\  → matches literal backslash
//	\\[      Go \[  → regex \[  → matches literal [
//	\\]      Go \]  → regex \]  → matches literal ]
//	:;|=,+*?<>  matched literally (no escaping needed inside a char class)
//	\"       Go "   → regex "   → matches literal double-quote
var localGroupNameRegex = regexp.MustCompile(
	"^[^/\\\\\\[\\]:;|=,+*?<>\"]{1,256}$",
)

// ---------------------------------------------------------------------------
// localGroupNameValidator — whitespace rule validator (EC-6)
// ---------------------------------------------------------------------------

// localGroupNameValidator enforces the whitespace rules that the character-
// class regex above cannot express (EC-6):
//
//   - Must not consist solely of whitespace characters.
//   - Must not start or end with a space.
type localGroupNameValidator struct{}

// Description returns a plain-text description.
func (localGroupNameValidator) Description(_ context.Context) string {
	return "must not consist solely of whitespace and must not start or end with a space"
}

// MarkdownDescription returns a Markdown description.
func (v localGroupNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString enforces the whitespace constraints.
func (localGroupNameValidator) ValidateString(
	_ context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()

	// Rule 1: must not be solely whitespace.
	if strings.TrimSpace(val) == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid local group name",
			fmt.Sprintf(
				"name %q consists solely of whitespace characters, "+
					"which Windows rejects as a local group name (EC-6)",
				val,
			),
		)
		return
	}

	// Rule 2: must not start or end with a space.
	if len(val) > 0 && (val[0] == ' ' || val[len(val)-1] == ' ') {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid local group name",
			fmt.Sprintf(
				"name %q must not start or end with a space "+
					"(Windows enforces this restriction at the API layer, EC-6)",
				val,
			),
		)
	}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsLocalGroupResource) Metadata(
	_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_local_group"
}

// Schema returns the complete TPF schema for the windows_local_group resource.
func (r *windowsLocalGroupResource) Schema(
	_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse,
) {
	resp.Schema = windowsLocalGroupSchemaDefinition()
}

// windowsLocalGroupSchemaDefinition returns the complete TPF schema for the
// windows_local_group resource (4 attributes, validators, plan modifiers,
// defaults).
//
// Canonical usage:
//
//	func (r *windowsLocalGroupResource) Schema(...) { resp.Schema = windowsLocalGroupSchemaDefinition() }
func windowsLocalGroupSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a Windows local group (Local Users and Groups) on a remote " +
			"host via WinRM and PowerShell (`Microsoft.PowerShell.LocalAccounts` module, " +
			"available from Windows Server 2016 / Windows 10 and later).\n\n" +
			"This resource manages **only the group entity itself** (name, description, SID). " +
			"Membership management is out of scope for v1 and is delegated to the future " +
			"`windows_local_group_member` resource (ADR-LG-3).\n\n" +
			"The Terraform resource ID is set to the group **SID** (e.g. `S-1-5-21-\u2026-1001`), " +
			"which Windows assigns at creation time and which remains stable across renames. " +
			"A change to the `name` attribute triggers `Rename-LocalGroup` in place — no " +
			"resource replacement (ADR-LG-1).\n\n" +
			"~> **Scope:** Windows **local** groups only. Domain groups visible in ADUC are " +
			"**not** manageable through this resource. Domain-joined machines are fully supported " +
			"for *local* group management (EC-9).\n\n" +
			"~> **Built-in groups:** Attempting to `terraform destroy` a built-in group " +
			"(SID prefix `S-1-5-32-*`, e.g. Administrators, Users, Guests) results in a " +
			"**hard error** — not a warning (ADR-LG-2, EC-2).",

		Attributes: map[string]schema.Attribute{
			// id — computed only, equal to sid (ADR-LG-1)
			"id": schema.StringAttribute{
				Computed: true,
				Description: "Terraform resource ID. Equal to sid (the group Security Identifier). " +
					"Stable across renames.",
				MarkdownDescription: "Terraform resource ID. Equal to `sid` (the group Security " +
					"Identifier). **Stable across renames**: renaming the group via the `name` " +
					"attribute does not change the resource ID (ADR-LG-1).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// name — required, NOT ForceNew (in-place rename via Rename-LocalGroup)
			"name": schema.StringAttribute{
				Required: true,
				Description: "Name of the local group (e.g. \"AppAdmins\"). " +
					"Length: 1..256 characters. " +
					"Forbidden characters: / \\ [ ] : ; | = , + * ? < > \". " +
					"Must not consist solely of whitespace. Must not start or end with a space. " +
					"A change in this attribute triggers Rename-LocalGroup (no resource replacement). " +
					"Windows stores group names case-insensitively; Read normalises to the casing " +
					"returned by Windows (ADR-LG-4, EC-4).",
				MarkdownDescription: "Name of the local group (e.g. `AppAdmins`).\n\n" +
					"Constraints (enforced by schema validators, EC-6):\n" +
					"  * Length: 1..256 characters\n" +
					"  * Forbidden characters: `/` `\\` `[` `]` `:` `;` `|` `=` `,` `+` `*` `?` `<` `>` `\"`\n" +
					"  * Must not consist solely of whitespace characters\n" +
					"  * Must not start or end with a space\n\n" +
					"**In-place rename:** a change in this attribute issues " +
					"`Rename-LocalGroup -SID <sid> -NewName <new_name>` — no resource replacement " +
					"(ADR-LG-1, EC-5).\n\n" +
					"**Case normalisation:** drift comparison uses `strings.EqualFold` so a " +
					"case-only difference does not trigger a spurious rename (ADR-LG-4, EC-4).",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 256),
					stringvalidator.RegexMatches(
						localGroupNameRegex,
						"must not contain any of the forbidden characters: / \\ [ ] : ; | = , + * ? < > \"",
					),
					localGroupNameValidator{},
				},
			},

			// description — optional+computed, default "", max 256 chars (EC-7)
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
				Description: "Optional free-text description of the group. " +
					"Windows caps this at 256 characters (EC-7). " +
					"An empty string is valid and represents no description. " +
					"Defaults to an empty string when omitted in HCL.",
				MarkdownDescription: "Optional free-text description of the group.\n\n" +
					"Windows caps descriptions at **256 characters** (EC-7). " +
					"An empty string (`\"\"`) is valid and clears any existing description. " +
					"Defaults to `\"\"` when omitted in HCL.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(0, 256),
				},
			},

			// sid — computed only, UseStateForUnknown (ADR-LG-1)
			"sid": schema.StringAttribute{
				Computed: true,
				Description: "Security Identifier of the group (e.g. \"S-1-5-21-...-1001\"). " +
					"Assigned by Windows at creation time and stable across renames. " +
					"Used as the canonical Terraform resource ID. Read-only.",
				MarkdownDescription: "Security Identifier (SID) of the group. Assigned by Windows " +
					"when `New-LocalGroup` completes and stable across renames (ADR-LG-1). " +
					"Read-only computed attribute.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure extracts the *winclient.Client from the provider data and
// constructs a LocalGroupClient.
func (r *windowsLocalGroupResource) Configure(
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
	r.grp = winclient.NewLocalGroupClient(c)
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

// Create creates the Windows local group and persists the full returned state.
//
// Pre-flight checks (delegated to the client):
//   - Module availability guard (EC-9).
//   - Name collision check → ErrLocalGroupAlreadyExists (EC-1).
func (r *windowsLocalGroupResource) Create(
	ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse,
) {
	var plan windowsLocalGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := winclient.GroupInput{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
	}

	gs, err := r.grp.Create(ctx, input)
	if err != nil {
		addLocalGroupDiag(&resp.Diagnostics, "Create windows_local_group failed", err)
		return
	}

	state := stateFromGroup(gs)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Read refreshes the Terraform state from the observed Windows state.
//
// EC-3: calls resp.State.RemoveResource() when the group no longer exists.
// EC-4 / ADR-LG-4: if the Windows name differs from the prior state name only
// in case (strings.EqualFold), the prior state name is kept to prevent a
// spurious plan diff on the next terraform plan.
func (r *windowsLocalGroupResource) Read(
	ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse,
) {
	var state windowsLocalGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sid := state.SID.ValueString()
	if sid == "" {
		sid = state.ID.ValueString()
	}

	gs, err := r.grp.Read(ctx, sid)
	if err != nil {
		addLocalGroupDiag(&resp.Diagnostics, "Read windows_local_group failed", err)
		return
	}
	if gs == nil {
		// EC-3: group disappeared outside Terraform — signal re-creation.
		resp.State.RemoveResource(ctx)
		return
	}

	next := stateFromGroup(gs)

	// EC-4 / ADR-LG-4: Case-insensitive name normalisation.
	// If the Windows-returned name differs from the prior state name only in
	// casing, keep the prior state name to avoid a permanent plan diff.
	priorName := state.Name.ValueString()
	if strings.EqualFold(gs.Name, priorName) {
		next.Name = types.StringValue(priorName)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Update applies in-place changes (rename and/or description update).
//
// EC-5: Rename-LocalGroup is called when the desired name differs from the
// current name (case-insensitive comparison is performed inside the PS script,
// so case-only changes are skipped).
// After a successful update, state is refreshed by re-reading from Windows.
func (r *windowsLocalGroupResource) Update(
	ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse,
) {
	var plan, prior windowsLocalGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sid := prior.SID.ValueString()
	if sid == "" {
		sid = prior.ID.ValueString()
	}

	input := winclient.GroupInput{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
	}

	gs, err := r.grp.Update(ctx, sid, input)
	if err != nil {
		addLocalGroupDiag(&resp.Diagnostics, "Update windows_local_group failed", err)
		return
	}

	next := stateFromGroup(gs)

	// EC-4 / ADR-LG-4: if the update did not actually rename (case-only diff),
	// Windows still holds the old casing. Store the plan name (HCL value) to
	// keep the state consistent with the configuration and prevent a perpetual
	// plan diff.
	if strings.EqualFold(gs.Name, plan.Name.ValueString()) {
		next.Name = plan.Name
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

// Delete removes the Windows local group.
//
// EC-2 / ADR-LG-2: returns a hard error (not a warning) if the group's SID
// matches the BUILTIN authority prefix "S-1-5-32-*". This check is performed
// inside the client before Remove-LocalGroup is called.
func (r *windowsLocalGroupResource) Delete(
	ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse,
) {
	var state windowsLocalGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sid := state.SID.ValueString()
	if sid == "" {
		sid = state.ID.ValueString()
	}

	if err := r.grp.Delete(ctx, sid); err != nil {
		addLocalGroupDiag(&resp.Diagnostics, "Delete windows_local_group failed", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState — EC-10
// ---------------------------------------------------------------------------

// ImportState handles terraform import for the windows_local_group resource.
//
// The import ID may be either:
//   - A SID string (auto-detected: starts with "S-") → ImportBySID (EC-10)
//   - A group name (all other values) → ImportByName (EC-10)
//
// On success the resource ID is set to the group SID regardless of which
// import path was used, so subsequent plan/apply operations use the stable
// SID path (ADR-LG-1, ADR-LG-6).
func (r *windowsLocalGroupResource) ImportState(
	ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse,
) {
	importID := req.ID

	var gs *winclient.GroupState
	var err error

	if strings.HasPrefix(importID, "S-") {
		// SID-based import path (EC-10).
		gs, err = r.grp.ImportBySID(ctx, importID)
		if err != nil {
			addLocalGroupDiag(&resp.Diagnostics,
				fmt.Sprintf("Cannot import windows_local_group by SID %q", importID), err)
			return
		}
	} else {
		// Name-based import path (EC-10).
		gs, err = r.grp.ImportByName(ctx, importID)
		if err != nil {
			addLocalGroupDiag(&resp.Diagnostics,
				fmt.Sprintf("Cannot import windows_local_group by name %q", importID), err)
			return
		}
	}

	if gs == nil {
		resp.Diagnostics.AddError(
			"Import failed: group not found",
			fmt.Sprintf("No local group found with name or SID %q on the target host (EC-10).", importID),
		)
		return
	}

	state := stateFromGroup(gs)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// stateFromGroup converts a *winclient.GroupState into a windowsLocalGroupModel
// with both id and sid set to the group SID (ADR-LG-1).
func stateFromGroup(gs *winclient.GroupState) windowsLocalGroupModel {
	return windowsLocalGroupModel{
		ID:          types.StringValue(gs.SID),
		Name:        types.StringValue(gs.Name),
		Description: types.StringValue(gs.Description),
		SID:         types.StringValue(gs.SID),
	}
}

// addLocalGroupDiag converts a winclient error into a TPF diagnostic. The
// LocalGroupError.Message is safe to surface; Context entries are appended as
// a detail block for operator visibility.
func addLocalGroupDiag(diags *diag.Diagnostics, summary string, err error) {
	var lge *winclient.LocalGroupError
	if errors.As(err, &lge) {
		detail := lge.Message
		if len(lge.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range lge.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if lge.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", lge.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// pathAttr is defined in provider.go — reuse it here rather than redefining.
// (It returns path.Root(attr) for use in AddAttributeError calls.)
var _ = path.Root // ensure path import is used
