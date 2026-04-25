// Package provider contains the Terraform resource implementation for
// windows_local_group_member.
//
// Spec alignment: windows_local_group_member spec v1 (2026-04-25).
// Framework:      terraform-plugin-framework v1.13.0.
//
// Design notes:
//   - The Terraform resource ID is the composite string "<group_sid>/<member_sid>"
//     (ADR-LGM-1). Both SIDs are stable across renames; "/" is safe because
//     SID strings never contain forward slashes.
//   - All user-visible attributes are ForceNew (RequiresReplace). The Update
//     handler is therefore a no-op that copies plan to state (EC-11).
//   - group_sid is resolved at Create time via ResolveGroup (ADR-LGM-6).
//     member is preserved as-supplied in state; member_sid is the source of
//     truth for drift detection and Delete (ADR-LGM-4, ADR-LGM-2).
//   - Read calls Get which applies the three-tier orphan-SID fallback (EC-6).
//   - Import accepts "<group_name_or_sid>/<member_name_or_sid>"; the handler
//     resolves both sides to SIDs using ResolveGroup + List (ADR-LGM-1).
//   - BUILTIN groups (Administrators, etc.) are explicitly supported (EC-9).
//     The BUILTIN-delete guard from windows_local_group does NOT apply here.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/ecritel/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsLocalGroupMemberResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsLocalGroupMemberResource)(nil)
	_ resource.ResourceWithImportState = (*windowsLocalGroupMemberResource)(nil)
)

// NewWindowsLocalGroupMemberResource is the constructor registered in provider.go.
func NewWindowsLocalGroupMemberResource() resource.Resource {
	return &windowsLocalGroupMemberResource{}
}

// windowsLocalGroupMemberResource is the TPF resource type for
// windows_local_group_member.
type windowsLocalGroupMemberResource struct {
	client *winclient.Client
	member winclient.ClientLocalGroupMember
}

// ---------------------------------------------------------------------------
// windowsLocalGroupMemberModel — Terraform state / plan model
// ---------------------------------------------------------------------------

// windowsLocalGroupMemberModel is the Terraform state/plan model for the
// windows_local_group_member resource. Field tags match the snake_case
// attribute names declared in the schema below.
//
// Composite resource ID = "<group_sid>/<member_sid>" (ADR-LGM-1).
// member is stored as-supplied (ADR-LGM-4); member_sid is the source of truth.
type windowsLocalGroupMemberModel struct {
	ID                    types.String `tfsdk:"id"`
	Group                 types.String `tfsdk:"group"`
	GroupSID              types.String `tfsdk:"group_sid"`
	Member                types.String `tfsdk:"member"`
	MemberSID             types.String `tfsdk:"member_sid"`
	MemberName            types.String `tfsdk:"member_name"`
	MemberPrincipalSource types.String `tfsdk:"member_principal_source"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsLocalGroupMemberResource) Metadata(
	_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_local_group_member"
}

// Schema returns the complete TPF schema for the windows_local_group_member
// resource (7 attributes, validators, plan modifiers — inlined from schema.go).
func (r *windowsLocalGroupMemberResource) Schema(
	_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse,
) {
	resp.Schema = windowsLocalGroupMemberSchemaDefinition()
}

// windowsLocalGroupMemberSchemaDefinition returns the complete TPF schema for
// the windows_local_group_member resource (7 attributes).
func windowsLocalGroupMemberSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the membership of **exactly one** member in a Windows local " +
			"group on a remote host via WinRM and PowerShell " +
			"(`Microsoft.PowerShell.LocalAccounts` module, Windows Server 2016 / " +
			"Windows 10 and later).\n\n" +
			"Each resource instance represents one `(group, member)` pair. The " +
			"**non-authoritative** pattern means Terraform only manages the specific " +
			"membership it created, leaving out-of-band memberships undisturbed (EC-12).\n\n" +
			"The **composite resource ID** is `\"<group_sid>/<member_sid>\"` " +
			"(e.g. `S-1-5-32-544/S-1-5-21-123456789-1001`). Both SIDs are stable " +
			"across renames (ADR-LGM-1).\n\n" +
			"~> **BUILTIN groups are fully supported** as the primary use case " +
			"(Administrators `S-1-5-32-544`, Remote Desktop Users `S-1-5-32-555`, etc., EC-9).\n\n" +
			"~> **Non-authoritative:** do **not** use this resource concurrently with a " +
			"future authoritative membership resource on the same group (EC-12).",

		Attributes: map[string]schema.Attribute{

			// id — composite computed: "<group_sid>/<member_sid>"
			"id": schema.StringAttribute{
				Computed: true,
				Description: "Composite Terraform resource ID: \"<group_sid>/<member_sid>\" " +
					"(e.g. \"S-1-5-32-544/S-1-5-21-123456789-1001\"). Both SIDs are " +
					"stable across renames.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// group — required, ForceNew
			"group": schema.StringAttribute{
				Required: true,
				Description: "Name or SID of the target local group " +
					"(e.g. \"Administrators\", \"S-1-5-32-544\", \"MyCustomGroup\"). " +
					"Resolved to group_sid at Create time. Any change destroys and " +
					"recreates the resource.",
				MarkdownDescription: "Name or SID of the target local group " +
					"(e.g. `\"Administrators\"`, `\"S-1-5-32-544\"`, `\"MyCustomGroup\"`).\n\n" +
					"Accepted formats:\n" +
					"  * **Group name** — resolved via `Get-LocalGroup -Name`\n" +
					"  * **SID string** (starts with `\"S-\"`) — resolved via `Get-LocalGroup -SID`\n\n" +
					"Resolved to `group_sid` at Create time; `group_sid` is the stable " +
					"handle for all subsequent operations (ADR-LGM-6).\n\n" +
					"~> **ForceNew:** any change destroys and recreates the resource.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 256),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			// group_sid — computed, UseStateForUnknown
			"group_sid": schema.StringAttribute{
				Computed: true,
				Description: "Security Identifier of the group, resolved at Create time " +
					"from the group attribute. Stable across group renames (ADR-LGM-1).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// member — required, ForceNew
			"member": schema.StringAttribute{
				Required: true,
				Description: "Identity string for the member to add. " +
					"Accepted formats: \"DOMAIN\\\\username\", \"MACHINE\\\\username\", " +
					"\"username\", \"user@domain.tld\", \"S-1-5-21-...-XXXX\". " +
					"Stored as-supplied in state (ADR-LGM-4). Any change destroys and " +
					"recreates the resource.",
				MarkdownDescription: "Identity string for the member to add.\n\n" +
					"Accepted formats:\n" +
					"  * `\"DOMAIN\\\\username\"` — domain user\n" +
					"  * `\"MACHINE\\\\username\"` — local account with explicit prefix\n" +
					"  * `\"username\"` — local account (implicit local machine)\n" +
					"  * `\"user@domain.tld\"` — UPN format\n" +
					"  * `\"S-1-5-21-...-XXXX\"` — direct SID string\n\n" +
					"**Stored as-supplied in state** (ADR-LGM-4). `member_sid` is the " +
					"source of truth for drift detection and the Delete operation.\n\n" +
					"~> **ForceNew:** any change destroys and recreates the resource.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 512),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			// member_sid — computed, UseStateForUnknown
			"member_sid": schema.StringAttribute{
				Computed: true,
				Description: "Security Identifier of the member, resolved by Windows " +
					"after Add-LocalGroupMember completes. Source of truth for drift " +
					"detection and the Delete operation (ADR-LGM-2).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// member_name — computed, UseStateForUnknown
			"member_name": schema.StringAttribute{
				Computed: true,
				Description: "Canonical display name of the member as returned by Windows " +
					"(Get-LocalGroupMember .Name). Set to member_sid for orphaned AD SIDs (EC-6).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// member_principal_source — computed, UseStateForUnknown
			"member_principal_source": schema.StringAttribute{
				Computed: true,
				Description: "Origin of the member account as reported by Windows. " +
					"Possible values: \"Local\", \"ActiveDirectory\", \"AzureAD\", " +
					"\"MicrosoftAccount\", \"Unknown\". Set to \"Unknown\" for orphaned " +
					"AD SIDs (EC-6).",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"Local",
						"ActiveDirectory",
						"AzureAD",
						"MicrosoftAccount",
						"Unknown",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure extracts the *winclient.Client from the provider data and
// constructs a LocalGroupMemberClient.
func (r *windowsLocalGroupMemberResource) Configure(
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
	r.member = winclient.NewLocalGroupMemberClient(c)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create resolves the group, adds the member, and persists the full state.
//
// Steps (per spec §operations.create):
//   0. Resolve group name/SID to group_sid via ResolveGroup (ADR-LGM-6).
//   1-4. Delegated to LocalGroupMemberClient.Add (SID resolution, duplicate
//        check, Add-LocalGroupMember, Read-back via Get).
//   5. Set ID = "<group_sid>/<member_sid>".
//
// Edge-case diagnostics:
//   - EC-2: group not found → hard error on attribute "group"
//   - EC-1: member already exists → hard error with import hint
//   - EC-3: member identity unresolvable → hard error on attribute "member"
//   - EC-8: insufficient permissions → hard error
func (r *windowsLocalGroupMemberResource) Create(
	ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse,
) {
	var plan windowsLocalGroupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 0: Resolve group name/SID → group_sid (ADR-LGM-6).
	grpState, resolveErr := winclient.ResolveGroup(ctx, r.client, plan.Group.ValueString())
	if resolveErr != nil {
		var lge *winclient.LocalGroupError
		if errors.As(resolveErr, &lge) && lge.Kind == winclient.LocalGroupErrorNotFound {
			resp.Diagnostics.AddAttributeError(
				path.Root("group"),
				"Create windows_local_group_member failed: group not found (EC-2)",
				fmt.Sprintf(
					"Local group %q was not found on host %s. "+
						"Ensure the group exists before adding members.",
					plan.Group.ValueString(), lge.Context["host"],
				),
			)
		} else {
			addLocalGroupMemberDiag(&resp.Diagnostics,
				"Create windows_local_group_member failed: could not resolve group", resolveErr)
		}
		return
	}
	groupSID := grpState.SID

	tflog.Debug(ctx, "windows_local_group_member Create: resolved group",
		map[string]interface{}{
			"group":     plan.Group.ValueString(),
			"group_sid": groupSID,
		})

	// Steps 1-4: Add the member (SID pre-resolution, duplicate check,
	// Add-LocalGroupMember, Read-back).
	input := winclient.LocalGroupMemberInput{
		GroupSID: groupSID,
		Member:   plan.Member.ValueString(),
	}
	memberState, addErr := r.member.Add(ctx, input)
	if addErr != nil {
		addLocalGroupMemberCreateDiag(&resp.Diagnostics, plan.Member.ValueString(), addErr)
		return
	}

	tflog.Debug(ctx, "windows_local_group_member Create: member added",
		map[string]interface{}{
			"group_sid":              groupSID,
			"member_sid":             memberState.MemberSID,
			"member_principal_source": memberState.PrincipalSource,
		})

	// Step 5: Build and persist state.
	state := windowsLocalGroupMemberModel{
		ID:                    types.StringValue(groupSID + "/" + memberState.MemberSID),
		Group:                 plan.Group,
		GroupSID:              types.StringValue(groupSID),
		Member:                plan.Member,
		MemberSID:             types.StringValue(memberState.MemberSID),
		MemberName:            types.StringValue(memberState.MemberName),
		MemberPrincipalSource: types.StringValue(memberState.PrincipalSource),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes the Terraform state from the observed Windows state.
//
// Drift handling:
//   - EC-4: membership removed outside Terraform → RemoveResource.
//   - EC-5: group deleted outside Terraform → RemoveResource (distinct log).
//   - EC-6: orphaned AD SID → fallback tiers in LocalGroupMemberClient.Get.
//
// Per ADR-LGM-4, the member attribute is NOT overwritten from Windows; only
// member_sid, member_name, and member_principal_source are refreshed.
func (r *windowsLocalGroupMemberResource) Read(
	ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse,
) {
	var state windowsLocalGroupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse composite ID → groupSID / memberSID.
	groupSID, memberSID, ok := parseCompositeID(state.ID.ValueString())
	if !ok {
		// Fallback: try GroupSID / MemberSID attrs (import path tolerance).
		groupSID = state.GroupSID.ValueString()
		memberSID = state.MemberSID.ValueString()
	}

	tflog.Debug(ctx, "windows_local_group_member Read",
		map[string]interface{}{
			"group_sid":  groupSID,
			"member_sid": memberSID,
		})

	memberState, err := r.member.Get(ctx, groupSID, memberSID)
	if err != nil {
		if winclient.IsLocalGroupMemberError(err, winclient.LocalGroupMemberErrorGroupNotFound) {
			// EC-5: group deleted outside Terraform.
			tflog.Debug(ctx, "windows_local_group_member Read: group not found, removing from state",
				map[string]interface{}{"group_sid": groupSID})
			resp.State.RemoveResource(ctx)
			return
		}
		addLocalGroupMemberDiag(&resp.Diagnostics,
			"Read windows_local_group_member failed", err)
		return
	}

	if memberState == nil {
		// EC-4: membership removed outside Terraform.
		tflog.Debug(ctx, "windows_local_group_member Read: membership absent, removing from state",
			map[string]interface{}{"group_sid": groupSID, "member_sid": memberSID})
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh only computed attributes (ADR-LGM-4: member preserved as-supplied).
	state.MemberSID = types.StringValue(memberState.MemberSID)
	state.MemberName = types.StringValue(memberState.MemberName)
	state.MemberPrincipalSource = types.StringValue(memberState.PrincipalSource)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Update — no-op (all attributes are ForceNew, EC-11)
// ---------------------------------------------------------------------------

// Update is a no-op because all user-visible attributes carry the
// RequiresReplace plan modifier. The framework will never call Update in
// practice; this implementation is required by the resource.Resource interface.
func (r *windowsLocalGroupMemberResource) Update(
	ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse,
) {
	// All attributes are RequiresReplace — this handler should never be invoked.
	tflog.Debug(ctx, "windows_local_group_member Update: no-op (all attributes are ForceNew, EC-11)")
	var plan windowsLocalGroupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the membership via Remove-LocalGroupMember -Member <member_sid>
// (ADR-LGM-2). The member SID is used rather than the display name to handle
// renamed accounts and orphaned AD SIDs (EC-6).
//
// Idempotency: "member not found" and "group not found" are treated as success.
func (r *windowsLocalGroupMemberResource) Delete(
	ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse,
) {
	var state windowsLocalGroupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupSID, memberSID, ok := parseCompositeID(state.ID.ValueString())
	if !ok {
		groupSID = state.GroupSID.ValueString()
		memberSID = state.MemberSID.ValueString()
	}

	tflog.Debug(ctx, "windows_local_group_member Delete",
		map[string]interface{}{
			"group_sid":  groupSID,
			"member_sid": memberSID,
		})

	if err := r.member.Remove(ctx, groupSID, memberSID); err != nil {
		addLocalGroupMemberDiag(&resp.Diagnostics,
			"Delete windows_local_group_member failed", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState handles terraform import for the windows_local_group_member
// resource.
//
// The import ID format is "<group>/<member>" where:
//   - group  may be a group name or a SID string (auto-detected by "S-" prefix).
//   - member may be a member display name or a SID string (auto-detected).
//
// The handler resolves group → groupSID via ResolveGroup, then searches the
// member list (List with orphan fallback) for a matching entry by SID or name.
// On success, state is populated with all 7 attributes (ADR-LGM-1).
func (r *windowsLocalGroupMemberResource) ImportState(
	ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse,
) {
	importID := req.ID

	// Split on first "/" — safe because SID strings and group names never
	// contain forward slashes.
	slashIdx := strings.Index(importID, "/")
	if slashIdx < 1 || slashIdx >= len(importID)-1 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf(
				"Expected format \"<group>/<member>\" (name or SID for each side), got %q.",
				importID,
			),
		)
		return
	}
	groupStr := importID[:slashIdx]
	memberStr := importID[slashIdx+1:]

	// Step 1: Resolve group to SID (ADR-LGM-6).
	grpState, resolveErr := winclient.ResolveGroup(ctx, r.client, groupStr)
	if resolveErr != nil {
		addLocalGroupMemberDiag(&resp.Diagnostics,
			fmt.Sprintf("Cannot import windows_local_group_member: group %q not found", groupStr),
			resolveErr)
		return
	}
	groupSID := grpState.SID

	// Step 2: List all group members (with orphan fallback).
	members, listErr := r.member.List(ctx, groupSID)
	if listErr != nil {
		addLocalGroupMemberDiag(&resp.Diagnostics,
			"Cannot import windows_local_group_member: list members failed", listErr)
		return
	}

	// Step 3: Find the requested member by SID or display name.
	memberIsSID := strings.HasPrefix(memberStr, "S-")
	var found *winclient.LocalGroupMemberState
	for _, m := range members {
		if memberIsSID {
			if strings.EqualFold(m.MemberSID, memberStr) {
				found = m
				break
			}
		} else {
			if strings.EqualFold(m.MemberName, memberStr) {
				found = m
				break
			}
		}
	}

	if found == nil {
		resp.Diagnostics.AddError(
			"Cannot import windows_local_group_member: member not found",
			fmt.Sprintf(
				"Member %q was not found in group %q (SID: %s). "+
					"Ensure the membership exists and try again.",
				memberStr, groupStr, groupSID,
			),
		)
		return
	}

	tflog.Debug(ctx, "windows_local_group_member ImportState: membership found",
		map[string]interface{}{
			"group_sid":  groupSID,
			"member_sid": found.MemberSID,
		})

	state := windowsLocalGroupMemberModel{
		ID:                    types.StringValue(groupSID + "/" + found.MemberSID),
		Group:                 types.StringValue(groupStr),
		GroupSID:              types.StringValue(groupSID),
		Member:                types.StringValue(memberStr),
		MemberSID:             types.StringValue(found.MemberSID),
		MemberName:            types.StringValue(found.MemberName),
		MemberPrincipalSource: types.StringValue(found.PrincipalSource),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseCompositeID splits a composite resource ID "<group_sid>/<member_sid>"
// into its two SID components. Returns (groupSID, memberSID, true) on success,
// or ("", "", false) if the ID is malformed.
func parseCompositeID(id string) (groupSID, memberSID string, ok bool) {
	idx := strings.Index(id, "/")
	if idx < 1 || idx >= len(id)-1 {
		return "", "", false
	}
	return id[:idx], id[idx+1:], true
}

// addLocalGroupMemberDiag converts a winclient error into a TPF diagnostic.
// LocalGroupMemberError.Message is safe to surface; Context entries are
// appended as a detail block for operator visibility.
func addLocalGroupMemberDiag(diags *diag.Diagnostics, summary string, err error) {
	var lgme *winclient.LocalGroupMemberError
	if errors.As(err, &lgme) {
		detail := lgme.Message
		if len(lgme.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range lgme.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if lgme.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", lgme.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	// Fall back to LocalGroupError (from ResolveGroup).
	var lge *winclient.LocalGroupError
	if errors.As(err, &lge) {
		detail := lge.Message
		if len(lge.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range lge.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// addLocalGroupMemberCreateDiag emits attribute-targeted diagnostics for the
// Create path, routing EC-specific errors to the appropriate attribute.
func addLocalGroupMemberCreateDiag(diags *diag.Diagnostics, memberInput string, err error) {
	var lgme *winclient.LocalGroupMemberError
	if !errors.As(err, &lgme) {
		addLocalGroupMemberDiag(diags, "Create windows_local_group_member failed", err)
		return
	}

	switch lgme.Kind {
	case winclient.LocalGroupMemberErrorAlreadyExists:
		// EC-1: duplicate membership — emit import hint.
		diags.AddAttributeError(
			path.Root("member"),
			"Create windows_local_group_member failed: member already exists (EC-1)",
			lgme.Message,
		)

	case winclient.LocalGroupMemberErrorUnresolvable:
		// EC-3 / EC-10: member identity cannot be resolved.
		subType := lgme.Context["sub_type"]
		var detail string
		switch subType {
		case "domain":
			detail = fmt.Sprintf(
				"The identity %q could not be resolved to a SID because the domain "+
					"is unreachable or the account does not exist (EC-10). "+
					"Verify that the host is domain-joined and that the account exists.",
				memberInput,
			)
		default:
			detail = fmt.Sprintf(
				"The identity %q could not be resolved to a local account SID (EC-3). "+
					"Verify that the account exists on the target host.",
				memberInput,
			)
		}
		if lgme.Message != "" {
			detail += "\n\nWindows error: " + lgme.Message
		}
		diags.AddAttributeError(path.Root("member"),
			"Create windows_local_group_member failed: member identity unresolvable", detail)

	case winclient.LocalGroupMemberErrorGroupNotFound:
		// EC-2: group disappeared between resolve and add.
		diags.AddAttributeError(path.Root("group"),
			"Create windows_local_group_member failed: group not found (EC-2)",
			lgme.Message)

	case winclient.LocalGroupMemberErrorPermission:
		// EC-8: insufficient permissions.
		diags.AddError(
			"Create windows_local_group_member failed: access denied (EC-8)",
			fmt.Sprintf(
				"The WinRM user does not have permission to add members to this group. "+
					"Windows error: %s",
				lgme.Message,
			),
		)

	default:
		addLocalGroupMemberDiag(diags, "Create windows_local_group_member failed", err)
	}
}

// pathMember is a compile-time check that the "path" import is used.
var _ = path.Root("id")
