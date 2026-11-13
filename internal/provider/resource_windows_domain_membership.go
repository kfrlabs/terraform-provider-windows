// Package provider: windows_domain_membership resource implementation.
//
// This file contains the TPF schema, model, custom validators and full
// CRUD + ImportState handlers for the windows_domain_membership resource.
// All SSH interaction is delegated to winclient.DomainMembershipClient
// (internal/winclient/domain_membership.go).
//
// Framework: terraform-plugin-framework v1.19.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Fallback per-operation timeouts when the user does not provide a
// `timeouts {}` block. Join/unjoin issue blocking Win32/DC calls that can
// stall against an unreachable domain controller; every CRUD handler bounds
// its work with these defaults so a stall surfaces a timeout diagnostic
// instead of blocking Terraform indefinitely.
const (
	domainMembershipDefaultCreateTimeout = 15 * time.Minute
	domainMembershipDefaultDeleteTimeout = 15 * time.Minute
	domainMembershipDefaultReadTimeout   = 5 * time.Minute
	domainMembershipDefaultUpdateTimeout = 5 * time.Minute
)

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsDomainMembershipResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsDomainMembershipResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsDomainMembershipResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsDomainMembershipResource)(nil)
)

// NewWindowsDomainMembershipResource is the constructor registered in
// provider.go.
func NewWindowsDomainMembershipResource() resource.Resource {
	return &windowsDomainMembershipResource{}
}

// windowsDomainMembershipResource is the TPF resource type for
// windows_domain_membership.
type windowsDomainMembershipResource struct {
	dm winclient.WindowsDomainMembershipClient
}

// windowsDomainMembershipModel is the Terraform state/plan model for the
// windows_domain_membership resource.
type windowsDomainMembershipModel struct {
	ID              types.String   `tfsdk:"id"`
	Domain          types.String   `tfsdk:"domain"`
	OUPath          types.String   `tfsdk:"ou_path"`
	Server          types.String   `tfsdk:"server"`
	JoinCredential  types.Object   `tfsdk:"join_credential"`
	Restart         types.Bool     `tfsdk:"restart"`
	UnjoinOnDestroy types.Bool     `tfsdk:"unjoin_on_destroy"`
	UnjoinWorkgroup types.String   `tfsdk:"unjoin_workgroup_name"`
	ComputerName    types.String   `tfsdk:"computer_name"`
	PendingReboot   types.Bool     `tfsdk:"pending_reboot"`
	SecureChannelOk types.Bool     `tfsdk:"secure_channel_ok"`
	Timeouts        timeouts.Value `tfsdk:"timeouts"`
}

// windowsDomainMembershipCredentialModel is the nested join_credential model.
//
// Password handling mirrors windows_local_user / windows_scheduled_task:
//   - `password` (legacy-shaped): Sensitive but persisted in state. Required
//     at destroy time when unjoin_on_destroy=true, because DeleteRequest
//     carries no Config in framework v1.19 and password_wo is unavailable.
//   - `password_wo` (WriteOnly): never persisted in state; available at
//     Create only via req.Config.
type windowsDomainMembershipCredentialModel struct {
	Username   types.String `tfsdk:"username"`
	Password   types.String `tfsdk:"password"`
	PasswordWO types.String `tfsdk:"password_wo"`
}

// domainMembershipCredentialAttrTypes is the attribute type map for the
// join_credential nested object.
var domainMembershipCredentialAttrTypes = map[string]attr.Type{
	"username":    types.StringType,
	"password":    types.StringType,
	"password_wo": types.StringType,
}

// domainMembershipDomainRegex accepts DNS-style domain names with a
// per-label rule (RFC 1035 hostname labels, up to 63 chars each):
// every dot-separated label must start and end alphanumerically with only
// interior hyphens, so "a..b" (empty label) and "a-.b" (label ending in a
// hyphen) are rejected. Single-label NetBIOS-style names such as "corp"
// remain allowed for lab domains; a second schema validator below rejects
// purely numeric names (e.g. "123").
var domainMembershipDomainRegex = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// domainMembershipDomainLetterRegex requires at least one ASCII letter so
// purely numeric names are rejected (Go RE2 has no lookahead, hence the
// separate validator instead of embedding it above).
var domainMembershipDomainLetterRegex = regexp.MustCompile(`[A-Za-z]`)

// Metadata sets the resource type name ("windows_domain_membership").
func (r *windowsDomainMembershipResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain_membership"
}

// Schema returns the complete TPF schema.
func (r *windowsDomainMembershipResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsDomainMembershipSchemaDefinition(ctx)
}

// windowsDomainMembershipSchemaDefinition returns the resource schema.
// Extracted into a function so it can be unit-tested independently of the
// resource type.
func windowsDomainMembershipSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Joins a remote Windows host to an Active Directory domain " +
			"(`Add-Computer`) over SSH and PowerShell, and optionally unjoins it on destroy (`Remove-Computer`).\n\n" +
			"The Terraform resource ID is the lower-cased domain DNS name. The join credential travels to the host on " +
			"stdin and never appears in the script body or logs.\n\n" +
			"A domain join only takes full effect after a reboot: `Add-Computer` is invoked **without** `-Restart`, " +
			"and when `restart = true` a detached host reboot is scheduled ~60s after the join (likewise for the unjoin), " +
			"so the reboot lands after Terraform records state. With `restart = false` (default), `pending_reboot` records " +
			"the requirement and the host must be rebooted out-of-band.\n\n" +
			"`ou_path` and `server` are **create-only**: they are used for the initial `Add-Computer` call and never read back. Changing either " +
			"later forces replacement (a new join) — the computer account is never moved in place.\n\n" +
			"**Destroy semantics:** by default destroy is a no-op (the host stays domain-joined). With " +
			"`unjoin_on_destroy = true` the host is unjoined into `unjoin_workgroup_name` on destroy. The unjoin " +
			"credential must come from the state-persisted `join_credential.password`: `password_wo` is WriteOnly and " +
			"unavailable at destroy time, so that combination is rejected at plan time.\n\n" +
			"`Update` re-reads the live host to refresh the Computed attributes (`computer_name`, `pending_reboot`, " +
			"`secure_channel_ok`) and therefore requires the host to be reachable — an unreachable host fails the update " +
			"instead of silently keeping prior values.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform resource ID. Equal to the lower-cased domain DNS name.",
				MarkdownDescription: "Terraform resource ID. Equal to the lower-cased domain DNS name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domain": schema.StringAttribute{
				Required:            true,
				Description:         "DNS name of the Active Directory domain to join. ForceNew. The resource id is the lower-cased form.",
				MarkdownDescription: "DNS name of the Active Directory domain to join (e.g. `corp.example.com`). **ForceNew.** The resource `id` is the lower-cased form.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
					stringvalidator.RegexMatches(domainMembershipDomainRegex,
						"must be a valid DNS domain name (dot-separated labels of alphanumerics with interior hyphens only)"),
					stringvalidator.RegexMatches(domainMembershipDomainLetterRegex,
						"must contain at least one letter (numeric-only names are not valid DNS domain names)"),
				},
			},
			"ou_path": schema.StringAttribute{
				Optional:            true,
				Description:         "Distinguished name of the OU for the computer account (e.g. \"OU=Servers,DC=corp,DC=example,DC=com\"). Create-only: used for the initial Add-Computer call, never read back; changing it later forces replacement.",
				MarkdownDescription: "Distinguished name of the OU for the computer account (e.g. `\"OU=Servers,DC=corp,DC=example,DC=com\"`). **Create-only:** used for the initial `Add-Computer` call and never read back. Changing it later forces replacement (the computer account is never moved in place).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"server": schema.StringAttribute{
				Optional:            true,
				Description:         "Optional domain controller (or domain) name passed to Add-Computer -Server. Create-only: changing it later forces replacement.",
				MarkdownDescription: "Optional domain controller (or domain) name passed to `Add-Computer -Server`. **Create-only:** changing it later forces replacement.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"join_credential": schema.SingleNestedAttribute{
				Required:            true,
				Description:         "Domain credential used for the join (and for the unjoin when unjoin_on_destroy is true). Exactly one of password / password_wo must be set.",
				MarkdownDescription: "Domain credential used for the join (and for the unjoin when `unjoin_on_destroy` is `true`). Exactly one of `password` / `password_wo` must be set.",
				Attributes: map[string]schema.Attribute{
					"username": schema.StringAttribute{
						Required:            true,
						Description:         "Domain account for the join (UPN or DOMAIN\\user). ForceNew.",
						MarkdownDescription: "Domain account for the join (UPN or `DOMAIN\\user`). **ForceNew.**",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
						Validators: []validator.String{
							stringvalidator.LengthBetween(1, 256),
						},
					},
					"password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Domain password. Sensitive on the wire but persisted in terraform.tfstate. Required (instead of password_wo) when unjoin_on_destroy is true, because the WriteOnly value is unavailable at destroy time. ForceNew.",
						MarkdownDescription: "Domain password. Sensitive on the wire but persisted in `terraform.tfstate`. " +
							"Required (instead of `password_wo`) when `unjoin_on_destroy` is `true`, because the WriteOnly value is unavailable at destroy time. **ForceNew.**\n\n" +
							"The value must not contain carriage return or line feed characters " +
							"(rejected at plan time): secrets are read with `ReadLine()`, so anything " +
							"from the first line break on would be silently truncated. If the value " +
							"comes from `file()`, wrap it with `trimspace()` to strip the trailing newline.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
						Validators: []validator.String{
							secretNoLineBreakValidator{},
						},
					},
					"password_wo": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
						Description: "Write-only domain password (TPF v1.14+ WriteOnly). Never persisted in state. Cannot be combined with unjoin_on_destroy. ForceNew.",
						MarkdownDescription: "Write-only domain password (TPF v1.14+ WriteOnly). " +
							"The plaintext is never persisted in `terraform.tfstate` — the framework drops it " +
							"from state automatically. Cannot be combined with `unjoin_on_destroy` (the WriteOnly value is unavailable at destroy time). **ForceNew.**\n\n" +
							"The value must not contain carriage return or line feed characters " +
							"(rejected at plan time against the configured value): secrets are read " +
							"with `ReadLine()`, so anything from the first line break on would be " +
							"silently truncated. If the value comes from `file()`, wrap it with " +
							"`trimspace()` to strip the trailing newline.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
						Validators: []validator.String{
							secretNoLineBreakValidator{},
						},
					},
				},
			},
			"restart": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "When true and the join/unjoin leaves a pending reboot, schedule a detached host reboot ~60s after the operation. Default false.",
				MarkdownDescription: "When `true` and the join/unjoin leaves a pending reboot, schedule a detached host reboot ~60s after the operation (`shutdown.exe /r /t 60`), so the reboot lands after Terraform records state. When `false` and a reboot is required, `pending_reboot` is set and the host must be rebooted out-of-band. Default `false`.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"unjoin_on_destroy": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "When true, terraform destroy unjoins the host into unjoin_workgroup_name. Requires join_credential.password (not password_wo). Default false: destroy is a no-op.",
				MarkdownDescription: "When `true`, `terraform destroy` unjoins the host into `unjoin_workgroup_name` (`Remove-Computer`). Requires `join_credential.password` (the state-persisted password — `password_wo` is unavailable at destroy time). Default `false`: destroy is a no-op and the host stays domain-joined.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"unjoin_workgroup_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("WORKGROUP"),
				Description:         "Workgroup the host joins when unjoin_on_destroy unjoins it. NetBIOS 1..15 chars. Default WORKGROUP.",
				MarkdownDescription: "Workgroup the host joins when `unjoin_on_destroy` unjoins it. NetBIOS rule: 1..15 chars, alphanumeric + hyphen, cannot start/end with a hyphen, cannot be purely numeric. Default `WORKGROUP`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 15),
					stringvalidator.RegexMatches(netbiosNameRegex,
						"must match ^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$ (NetBIOS structural rule)"),
					netbiosNameValidator{},
				},
			},
			"computer_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Active computer name (Win32_ComputerSystem.Name). Informational only.",
				MarkdownDescription: "Active computer name (`Win32_ComputerSystem.Name`). Informational only — never drives a diff.",
			},
			"pending_reboot": schema.BoolAttribute{
				Computed:            true,
				Description:         "True when the OS exposes a pending reboot flag. Informational only.",
				MarkdownDescription: "True when the OS exposes a pending reboot flag. Informational only — never drives a diff.",
			},
			"secure_channel_ok": schema.BoolAttribute{
				Computed:            true,
				Description:         "Test-ComputerSecureChannel result. Informational only; may be false while a join reboot is pending.",
				MarkdownDescription: "`Test-ComputerSecureChannel` result. Informational only — never drives a diff (may be `false` while a join reboot is pending).",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			"timeouts": timeouts.Attributes(ctx, dmTimeoutsOpts),
		},
	}
}

// ConfigValidators enforces the credential exactly-one-of rule and the
// unjoin_on_destroy/password_wo incompatibility.
func (r *windowsDomainMembershipResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("join_credential").AtName("password"),
			path.MatchRoot("join_credential").AtName("password_wo"),
		),
		domainMembershipUnjoinValidator{},
	}
}

// domainMembershipUnjoinValidator rejects unjoin_on_destroy=true combined
// with password_wo: DeleteRequest carries no Config in framework v1.19, so
// the WriteOnly value is unavailable at destroy time and the unjoin could
// never authenticate. The state-persisted password must be used instead.
type domainMembershipUnjoinValidator struct{}

// Description returns a plain-text description.
func (domainMembershipUnjoinValidator) Description(_ context.Context) string {
	return "unjoin_on_destroy requires join_credential.password (password_wo is unavailable at destroy time)"
}

// MarkdownDescription returns the Markdown variant.
func (v domainMembershipUnjoinValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateResource enforces the unjoin credential rule against the config.
func (domainMembershipUnjoinValidator) ValidateResource(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var model windowsDomainMembershipModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.UnjoinOnDestroy.IsNull() || model.UnjoinOnDestroy.IsUnknown() || !model.UnjoinOnDestroy.ValueBool() {
		return
	}
	if model.JoinCredential.IsNull() || model.JoinCredential.IsUnknown() {
		return
	}
	var cred windowsDomainMembershipCredentialModel
	resp.Diagnostics.Append(model.JoinCredential.As(ctx, &cred, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Unknown passwords cannot be validated yet (plan-time unknowns from
	// references); skip validation and fail closed at Delete when the
	// password is still absent.
	if cred.Password.IsUnknown() {
		return
	}
	if !cred.Password.IsNull() && !cred.Password.IsUnknown() && cred.Password.ValueString() != "" {
		return
	}
	resp.Diagnostics.AddAttributeError(
		path.Root("join_credential").AtName("password"),
		"password required for unjoin_on_destroy",
		"unjoin_on_destroy = true requires join_credential.password (persisted in state). "+
			"password_wo is WriteOnly and therefore unavailable at destroy time: "+
			"DeleteRequest carries no Config in terraform-plugin-framework v1.19, so the unjoin could never authenticate. "+
			"Set join_credential.password instead of password_wo.",
	)
}

// Configure extracts the shared *winclient.Client from provider data.
func (r *windowsDomainMembershipResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.dm = winclient.NewDomainMembershipClient(c)
}

// -----------------------------------------------------------------------------
// CRUD
// -----------------------------------------------------------------------------

// Create joins the host to the configured domain.
func (r *windowsDomainMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config windowsDomainMembershipModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, domainMembershipDefaultCreateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	cred, diags := domainMembershipCredentialFromModel(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	password, attrPath := effectiveDomainPassword(ctx, config, cred)
	if password == "" {
		resp.Diagnostics.AddAttributeError(
			attrPath,
			"Missing join credential",
			"Exactly one of join_credential.password and join_credential.password_wo must be set.",
		)
		return
	}

	domain := strings.ToLower(strings.TrimSpace(plan.Domain.ValueString()))
	in := winclient.DomainJoinInput{
		Domain:   domain,
		OUPath:   plan.OUPath.ValueString(),
		Server:   plan.Server.ValueString(),
		Username: cred.Username.ValueString(),
		Password: password,
		Restart:  plan.Restart.ValueBool(),
	}

	tflog.Debug(ctx, "windows_domain_membership Create", map[string]interface{}{
		"domain": domain,
	})

	state, result, err := r.dm.Join(ctx, in)
	if err != nil {
		addDomainMembershipDiag(&resp.Diagnostics, "Create windows_domain_membership failed", err)
		return
	}
	final := domainMembershipModelFromState(ctx, state, plan)
	final.ID = types.StringValue(domain)
	final.Domain = plan.Domain
	if result != nil && result.RebootScheduled {
		final.PendingReboot = types.BoolValue(true)
	}
	warnDomainReboot(&resp.Diagnostics, final.PendingReboot.ValueBool(), plan.Restart.ValueBool(), "join")
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Read refreshes Terraform state from the live host. A host that left the
// domain out-of-band (PartOfDomain=false) is removed from state so Terraform
// recreates the membership. A domain mismatch is tolerated while a reboot is
// pending (the join may not have taken effect yet) and otherwise also
// removes the resource from state.
func (r *windowsDomainMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsDomainMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, domainMembershipDefaultReadTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	live, err := r.dm.Read(ctx)
	if err != nil {
		addDomainMembershipDiag(&resp.Diagnostics, "Read windows_domain_membership failed", err)
		return
	}
	if live == nil || !live.PartOfDomain {
		tflog.Warn(ctx, "windows_domain_membership host left the domain out-of-band — removing from state",
			map[string]interface{}{"domain": state.Domain.ValueString()})
		resp.State.RemoveResource(ctx)
		return
	}
	if !strings.EqualFold(live.Domain, state.Domain.ValueString()) {
		if state.PendingReboot.ValueBool() {
			tflog.Warn(ctx, "windows_domain_membership domain mismatch tolerated while a reboot is pending",
				map[string]interface{}{
					"state_domain": state.Domain.ValueString(),
					"live_domain":  live.Domain,
				})
		} else {
			tflog.Warn(ctx, "windows_domain_membership host joined a different domain out-of-band — removing from state",
				map[string]interface{}{
					"state_domain": state.Domain.ValueString(),
					"live_domain":  live.Domain,
				})
			resp.State.RemoveResource(ctx)
			return
		}
	}
	final := domainMembershipModelFromState(ctx, live, state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Update applies in-place, state-only changes and then re-reads the live
// host to refresh the Computed attributes (computer_name, pending_reboot,
// secure_channel_ok). Only restart, timeouts (and the unjoin_* destroy
// behaviour) are mutable in place; no remote mutation is performed.
// domain, ou_path, server and join_credential changes force replacement
// via RequiresReplace, so Update only ever sees in-place fields drift.
func (r *windowsDomainMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsDomainMembershipModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, domainMembershipDefaultUpdateTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_domain_membership Update (state-only, refresh computed from live)", map[string]interface{}{
		"domain": plan.Domain.ValueString(),
	})

	// No remote mutation: project the plan through, preserving the
	// persisted credential from prior state. ou_path/server carry
	// RequiresReplace, so any change to them replaces instead of reaching
	// Update — plan values are authoritative here.
	final := plan
	final.ID = prior.ID
	// The WriteOnly password is never in state; keep it null even if a test
	// plan carries one (defensive, mirrors scheduled_task).
	final.JoinCredential = domainMembershipCredentialForState(ctx, &resp.Diagnostics, plan.JoinCredential, prior.JoinCredential)
	if resp.Diagnostics.HasError() {
		return
	}

	// Refresh Computed attributes from the live host instead of copying
	// prior values, so a reboot (or any out-of-band change) that flipped
	// pending_reboot / secure_channel_ok / computer_name is reflected.
	// Update requires host reachability: a refresh failure errors instead
	// of silently keeping prior values. Unlike Read, Update cannot remove
	// the resource from state, so out-of-band drift is an error.
	live, err := r.dm.Read(ctx)
	if err != nil {
		addDomainMembershipDiag(&resp.Diagnostics, "Update windows_domain_membership failed", err)
		return
	}
	if live == nil || !live.PartOfDomain {
		resp.Diagnostics.AddError(
			"Update windows_domain_membership failed",
			"The host is not joined to a domain (PartOfDomain=false), so the Computed attributes "+
				"cannot be refreshed. Update cannot remove the resource from state like Read does: "+
				"re-join the host out-of-band or remove the resource with terraform state rm / taint.",
		)
		return
	}
	if !strings.EqualFold(live.Domain, plan.Domain.ValueString()) {
		if prior.PendingReboot.ValueBool() {
			tflog.Warn(ctx, "windows_domain_membership domain mismatch tolerated while a reboot is pending",
				map[string]interface{}{
					"state_domain": plan.Domain.ValueString(),
					"live_domain":  live.Domain,
				})
		} else {
			resp.Diagnostics.AddError(
				"Update windows_domain_membership failed",
				fmt.Sprintf("The host is joined to %q, not the configured %q. Update cannot remove the resource "+
					"from state like Read does: re-join the host out-of-band or replace the resource.",
					live.Domain, plan.Domain.ValueString()),
			)
			return
		}
	}
	final.ComputerName = types.StringValue(live.ComputerName)
	final.PendingReboot = types.BoolValue(live.PendingReboot)
	final.SecureChannelOk = types.BoolValue(live.SecureChannelOk)
	warnDomainReboot(&resp.Diagnostics, final.PendingReboot.ValueBool(), plan.Restart.ValueBool(), "update")
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Delete unjoins the host when unjoin_on_destroy is true, and is a no-op
// otherwise. The unjoin credential must come from the state-persisted
// password: DeleteRequest carries no Config in framework v1.19, so
// password_wo (WriteOnly, never in state) is unavailable here — the
// ConfigValidator rejects that combination at plan time, and this handler
// fails closed when the password is absent.
func (r *windowsDomainMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsDomainMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, domainMembershipDefaultDeleteTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	if !state.UnjoinOnDestroy.ValueBool() {
		tflog.Warn(ctx,
			"windows_domain_membership destroy is a no-op; the host stays joined to its domain",
			map[string]interface{}{"domain": state.Domain.ValueString()})
		return
	}

	// Already-absent short-circuit without the secret: Read needs no
	// credential, so a host that already left the domain succeeds even when
	// the state password is missing. Best-effort: on Read failure fall
	// through to the password gate and the authoritative Unjoin call.
	if live, rerr := r.dm.Read(ctx); rerr == nil && live != nil && !live.PartOfDomain {
		tflog.Warn(ctx,
			"windows_domain_membership host already workgroup-joined; skipping unjoin",
			map[string]interface{}{"domain": state.Domain.ValueString()})
		return
	}

	var cred windowsDomainMembershipCredentialModel
	resp.Diagnostics.Append(state.JoinCredential.As(ctx, &cred, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})...)
	if resp.Diagnostics.HasError() {
		return
	}
	password := ""
	if !cred.Password.IsNull() && !cred.Password.IsUnknown() {
		password = cred.Password.ValueString()
	}
	if password == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("join_credential").AtName("password"),
			"password required for unjoin_on_destroy",
			"unjoin_on_destroy = true but join_credential.password is not set in state. "+
				"password_wo is WriteOnly and therefore unavailable at destroy time "+
				"(DeleteRequest carries no Config in terraform-plugin-framework v1.19). "+
				"Set join_credential.password before destroying, or set unjoin_on_destroy = false.",
		)
		return
	}

	domain := state.Domain.ValueString()
	tflog.Debug(ctx, "windows_domain_membership Delete (unjoin)", map[string]interface{}{
		"domain": domain,
	})
	live, result, err := r.dm.Unjoin(ctx, winclient.DomainUnjoinInput{
		Username:      cred.Username.ValueString(),
		Password:      password,
		WorkgroupName: state.UnjoinWorkgroup.ValueString(),
		Restart:       state.Restart.ValueBool(),
	})
	if err != nil {
		addDomainMembershipDiag(&resp.Diagnostics, "Delete windows_domain_membership failed", err)
		return
	}
	pending := state.PendingReboot.ValueBool()
	rebootScheduled := false
	if live != nil {
		pending = live.PendingReboot
	}
	if result != nil {
		rebootScheduled = result.RebootScheduled
		if result.RebootScheduled {
			pending = true
		}
	}
	if pending || rebootScheduled {
		warnDomainReboot(&resp.Diagnostics, true, state.Restart.ValueBool(), "unjoin")
	}
}

// ImportState imports a domain membership by its domain DNS name
// (e.g. `terraform import windows_domain_membership.this corp.example.com`).
// The host is verified to actually be joined to that domain; the
// join_credential must be supplied in configuration (it is never in state
// for password_wo, and import cannot recover a password).
func (r *windowsDomainMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	domain := strings.ToLower(strings.TrimSpace(req.ID))
	if domain == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("import ID %q must be the domain DNS name (e.g. corp.example.com)", req.ID),
		)
		return
	}
	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the read default.
	ctx, cancel := context.WithTimeout(ctx, domainMembershipDefaultReadTimeout)
	defer cancel()

	live, err := r.dm.Read(ctx)
	if err != nil {
		addDomainMembershipDiag(&resp.Diagnostics, fmt.Sprintf("Cannot import windows_domain_membership %q", req.ID), err)
		return
	}
	if live == nil || !live.PartOfDomain {
		resp.Diagnostics.AddError(
			"Import failed: host is not domain-joined",
			fmt.Sprintf("The target host is not joined to a domain (PartOfDomain=false), so %q cannot be imported.", req.ID),
		)
		return
	}
	if !strings.EqualFold(live.Domain, domain) {
		resp.Diagnostics.AddError(
			"Import failed: domain mismatch",
			fmt.Sprintf("The target host is joined to %q, not %q.", live.Domain, domain),
		)
		return
	}

	credObj, diags := types.ObjectValue(domainMembershipCredentialAttrTypes, map[string]attr.Value{
		"username":    types.StringNull(),
		"password":    types.StringNull(),
		"password_wo": types.StringNull(),
	})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m := windowsDomainMembershipModel{
		ID:              types.StringValue(domain),
		Domain:          types.StringValue(domain),
		OUPath:          types.StringNull(),
		Server:          types.StringNull(),
		JoinCredential:  credObj,
		Restart:         types.BoolValue(false),
		UnjoinOnDestroy: types.BoolValue(false),
		UnjoinWorkgroup: types.StringValue("WORKGROUP"),
		ComputerName:    types.StringValue(live.ComputerName),
		PendingReboot:   types.BoolValue(live.PendingReboot),
		SecureChannelOk: types.BoolValue(live.SecureChannelOk),
		Timeouts:        domainMembershipNullTimeouts(),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// dmTimeoutsOpts declares which per-operation timeouts the resource exposes.
var dmTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// domainMembershipNullTimeouts returns a null timeouts value carrying the
// schema's attribute types. The zero timeouts.Value wraps an object with NO
// attribute types, which the framework rejects on State.Set — the failure
// mode on import, where there is no prior state to copy the value from.
func domainMembershipNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if dmTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if dmTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if dmTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if dmTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// domainMembershipCredentialFromModel decodes the join_credential object
// from the plan, falling back to an empty model when absent.
func domainMembershipCredentialFromModel(ctx context.Context, plan *windowsDomainMembershipModel) (windowsDomainMembershipCredentialModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	var cred windowsDomainMembershipCredentialModel
	if plan.JoinCredential.IsNull() || plan.JoinCredential.IsUnknown() {
		return cred, diags
	}
	diags.Append(plan.JoinCredential.As(ctx, &cred, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: true,
	})...)
	return cred, diags
}

// effectiveDomainPassword returns the plaintext join password to use for
// Create along with the schema path holding it (used for targeted
// diagnostics). WriteOnly values are null in the plan handed to
// ApplyResourceChange, so the password_wo candidate must come from config
// (windows_file content_wo precedent).
//
// Returns ("", path.Root("join_credential").AtName("password")) when neither
// attribute is set.
func effectiveDomainPassword(ctx context.Context, config windowsDomainMembershipModel, cred windowsDomainMembershipCredentialModel) (string, path.Path) {
	woPath := path.Root("join_credential").AtName("password_wo")
	pwPath := path.Root("join_credential").AtName("password")
	var cfgCred windowsDomainMembershipCredentialModel
	if !config.JoinCredential.IsNull() && !config.JoinCredential.IsUnknown() {
		if d := config.JoinCredential.As(ctx, &cfgCred, basetypes.ObjectAsOptions{
			UnhandledNullAsEmpty:    true,
			UnhandledUnknownAsEmpty: true,
		}); !d.HasError() {
			if !cfgCred.PasswordWO.IsNull() && !cfgCred.PasswordWO.IsUnknown() {
				if v := cfgCred.PasswordWO.ValueString(); v != "" {
					return v, woPath
				}
			}
		}
	}
	if !cred.PasswordWO.IsNull() && !cred.PasswordWO.IsUnknown() {
		if v := cred.PasswordWO.ValueString(); v != "" {
			return v, woPath
		}
	}
	if !cred.Password.IsNull() && !cred.Password.IsUnknown() {
		if v := cred.Password.ValueString(); v != "" {
			return v, pwPath
		}
	}
	return "", pwPath
}

// domainMembershipModelFromState projects a winclient.DomainMembershipState
// onto a windowsDomainMembershipModel, preserving operator-managed fields
// (domain spelling, ou_path, server, credential, restart, unjoin behaviour,
// timeouts) from the prior plan/state.
func domainMembershipModelFromState(_ context.Context, live *winclient.DomainMembershipState, prior windowsDomainMembershipModel) windowsDomainMembershipModel {
	out := windowsDomainMembershipModel{
		Domain:          prior.Domain,
		OUPath:          prior.OUPath,
		Server:          prior.Server,
		JoinCredential:  prior.JoinCredential,
		Restart:         prior.Restart,
		UnjoinOnDestroy: prior.UnjoinOnDestroy,
		UnjoinWorkgroup: prior.UnjoinWorkgroup,
		Timeouts:        prior.Timeouts,
	}
	if out.Restart.IsNull() || out.Restart.IsUnknown() {
		out.Restart = types.BoolValue(false)
	}
	if out.UnjoinOnDestroy.IsNull() || out.UnjoinOnDestroy.IsUnknown() {
		out.UnjoinOnDestroy = types.BoolValue(false)
	}
	if out.UnjoinWorkgroup.IsNull() || out.UnjoinWorkgroup.IsUnknown() || out.UnjoinWorkgroup.ValueString() == "" {
		out.UnjoinWorkgroup = types.StringValue("WORKGROUP")
	}
	if live != nil {
		out.ComputerName = types.StringValue(live.ComputerName)
		out.PendingReboot = types.BoolValue(live.PendingReboot)
		out.SecureChannelOk = types.BoolValue(live.SecureChannelOk)
	} else {
		out.ComputerName = types.StringValue("")
		out.PendingReboot = types.BoolValue(false)
		out.SecureChannelOk = types.BoolValue(false)
	}
	return out
}

// domainMembershipCredentialForState rebuilds the join_credential state
// object from the plan while guaranteeing the WriteOnly password never
// lands in state: password_wo is forced to null and the persisted password
// falls back to the prior state value when the plan does not carry one.
func domainMembershipCredentialForState(ctx context.Context, diags *diag.Diagnostics, planCred, priorCred types.Object) types.Object {
	var plan, prior windowsDomainMembershipCredentialModel
	if !planCred.IsNull() && !planCred.IsUnknown() {
		diags.Append(planCred.As(ctx, &plan, basetypes.ObjectAsOptions{
			UnhandledNullAsEmpty:    true,
			UnhandledUnknownAsEmpty: true,
		})...)
	}
	if !priorCred.IsNull() && !priorCred.IsUnknown() {
		diags.Append(priorCred.As(ctx, &prior, basetypes.ObjectAsOptions{
			UnhandledNullAsEmpty:    true,
			UnhandledUnknownAsEmpty: true,
		})...)
	}
	if diags.HasError() {
		return planCred
	}
	if plan.Password.IsNull() || plan.Password.IsUnknown() {
		plan.Password = prior.Password
	}
	// WriteOnly values are dropped from state by the framework; null it here
	// explicitly so the intent is obvious and no test double can smuggle one
	// through.
	plan.PasswordWO = types.StringNull()
	obj, d := types.ObjectValueFrom(ctx, domainMembershipCredentialAttrTypes, plan)
	diags.Append(d...)
	return obj
}

// warnDomainReboot emits the reboot-follow-up warning shared by Create and
// Delete: manual reboot (restart=false) or deferred reboot scheduled
// (restart=true — the reboot lands ~60s after the operation, so the warning
// doubles as the out-of-band fallback if the host has not gone down).
func warnDomainReboot(diags *diag.Diagnostics, pending, restart bool, op string) {
	if !pending {
		return
	}
	if !restart {
		diags.AddWarning(
			"Reboot required",
			fmt.Sprintf("The domain %s reported a pending reboot. "+
				"Set restart=true to schedule a deferred reboot after the operation, or reboot the target host out-of-band.", op),
		)
		return
	}
	diags.AddWarning(
		"Deferred reboot scheduled",
		fmt.Sprintf("The domain %s reported a pending reboot. "+
			"A detached host reboot was scheduled in ~60s (shutdown.exe /r /t 60) because restart=true. "+
			"If the host has not rebooted, reboot it out-of-band; pending_reboot records the requirement.", op),
	)
}

// addDomainMembershipDiag converts a winclient error into a TPF diagnostic.
func addDomainMembershipDiag(diags *diag.Diagnostics, summary string, err error) {
	var de *winclient.DomainMembershipError
	if errors.As(err, &de) {
		detail := de.Message
		if len(de.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range de.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if de.Cause != nil {
			detail += "\n\nCause: " + de.Cause.Error()
		}
		if de.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", de.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
