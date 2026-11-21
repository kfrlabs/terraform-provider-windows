// Package provider - resource_windows_firewall_rule implements the full
// Terraform resource lifecycle for windows_firewall_rule.
//
// The resource manages a single Windows Defender Firewall rule on a remote
// host via SSH + PowerShell (NetSecurity module). It delegates all
// SSH/PS interaction to winclient.FirewallRuleClient.
//
// Spec alignment: windows_firewall_rule spec v1 (2026-05-01).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

var (
	_ resource.Resource                     = (*windowsFirewallRuleResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsFirewallRuleResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsFirewallRuleResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*windowsFirewallRuleResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsFirewallRuleResource)(nil)
)

// NewWindowsFirewallRuleResource is the constructor registered in provider.go.
func NewWindowsFirewallRuleResource() resource.Resource {
	return &windowsFirewallRuleResource{}
}

// windowsFirewallRuleResource is the TPF resource type for windows_firewall_rule.
type windowsFirewallRuleResource struct {
	fw winclient.WindowsFirewallRuleClient
}

// firewallRuleDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Firewall rule operations
// (New/Set/Remove-NetFirewallRule) are normally fast, but a stalled or
// severed PowerShell/SSH session must never block Terraform forever
// (issue #122): every CRUD handler bounds its work with this default. A
// misconfigured rule can sever the very SSH connection Terraform uses,
// so the bound is load-bearing for this resource in particular.
const firewallRuleDefaultTimeout = 10 * time.Minute

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsFirewallRuleModel is the Terraform state/plan model for
// windows_firewall_rule. Every tfsdk tag matches an attribute key in
// windowsFirewallRuleSchemaDefinition.
type windowsFirewallRuleModel struct {
	ID                  types.String               `tfsdk:"id"`
	Name                types.String               `tfsdk:"name"`
	DisplayName         types.String               `tfsdk:"display_name"`
	Description         types.String               `tfsdk:"description"`
	Enabled             types.Bool                 `tfsdk:"enabled"`
	Direction           types.String               `tfsdk:"direction"`
	Action              types.String               `tfsdk:"action"`
	Profile             types.List                 `tfsdk:"profile"`
	EdgeTraversalPolicy types.String               `tfsdk:"edge_traversal_policy"`
	Group               types.String               `tfsdk:"group"`
	PolicyStore         types.String               `tfsdk:"policy_store"`
	Protocol            firewallProtocolValue      `tfsdk:"protocol"`
	LocalPort           firewallCanonicalListValue `tfsdk:"local_port"`
	RemotePort          firewallCanonicalListValue `tfsdk:"remote_port"`
	LocalAddress        firewallCanonicalListValue `tfsdk:"local_address"`
	RemoteAddress       firewallCanonicalListValue `tfsdk:"remote_address"`
	Program             types.String               `tfsdk:"program"`
	Service             types.String               `tfsdk:"service"`
	InterfaceType       types.String               `tfsdk:"interface_type"`
	Timeouts            timeouts.Value             `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsFirewallRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_firewall_rule resource.
func (r *windowsFirewallRuleResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsFirewallRuleSchemaDefinition(ctx)
}

// windowsFirewallRuleSchemaDefinition returns the complete TPF schema for
// windows_firewall_rule (19 user-facing attributes + id + the
// per-operation `timeouts` block).
func windowsFirewallRuleSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a Windows Defender Firewall with Advanced Security rule " +
			"on a remote Windows host via SSH and PowerShell (`NetSecurity` module). " +
			"One Terraform resource maps to exactly one `NetFirewallRule`, keyed on its " +
			"stable technical `Name` (InstanceID), which is distinct from `display_name`.\n\n" +
			"**Partial failures:** if creation fails after the rule was already registered in the firewall " +
			"policy store, the provider persists the observed state before reporting the error, so the resource " +
			"is marked tainted. If update fails after Windows applied part of the change, the provider saves " +
			"the observed partial state before reporting the error. " +
			"Fix the cause and run `terraform apply` again to reconcile.\n\n" +
			"A nil state on error does not guarantee nothing was created: a failure that returns no state " +
			"leaves an orphaned rule that must be removed with `Remove-NetFirewallRule` or re-adopted " +
			"with `terraform import`.\n\n" +
			"Import format: `<name>` (PersistentStore assumed) or `<policy_store>/<name>`.",

		Attributes: map[string]schema.Attribute{

			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier. Set to the technical firewall rule Name (InstanceID).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"name": schema.StringAttribute{
				Required: true,
				Description: "Stable technical identifier of the firewall rule (InstanceID). " +
					"Used as the Terraform resource ID. Immutable after creation (ForceNew). " +
					"Max 1024 characters; null bytes are not permitted.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 1024),
					stringvalidator.RegexMatches(
						regexp.MustCompile("^[^\x00]+$"),
						"must not contain embedded null bytes",
					),
				},
			},

			"display_name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable name shown in the Windows Firewall UI. Must be non-empty.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},

			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Free-form description of the firewall rule. Mutable in-place.",
			},

			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether the rule is active. Defaults to true on creation.",
			},

			"direction": schema.StringAttribute{
				Required:    true,
				Description: "Traffic direction. One of: `Inbound`, `Outbound`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Inbound", "Outbound"),
				},
			},

			"action": schema.StringAttribute{
				Required:    true,
				Description: "Action taken on matching traffic. One of: `Allow`, `Block`, `NotConfigured`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Allow", "Block", "NotConfigured"),
				},
			},

			"profile": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
				Description: "Network profiles the rule applies to. Valid elements: " +
					"`Any`, `Domain`, `Private`, `Public`, `NotApplicable`. " +
					"`Any` must appear alone (enforced in ConfigValidators CV-1).",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("Any", "Domain", "Private", "Public", "NotApplicable"),
					),
				},
			},

			"edge_traversal_policy": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Edge-traversal behaviour. One of: `Block`, `Allow`, `DeferToUser`, `DeferToApp`.",
				Validators: []validator.String{
					stringvalidator.OneOf("Block", "Allow", "DeferToUser", "DeferToApp"),
				},
			},

			"group": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Rule group (RuleGroup). Immutable after creation (ForceNew). " +
					"Set-NetFirewallRule cannot rename a Group.",
				Validators: []validator.String{
					firewallSafeStringValidator{},
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},

			"policy_store": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("PersistentStore"),
				Description: "Policy store the rule lives in. Defaults to `PersistentStore`. " +
					"Immutable after creation (ForceNew). `GroupPolicy` and `RSOP` are read-only. " +
					"One of: `PersistentStore`, `ActiveStore`, `GroupPolicy`, `RSOP`, " +
					"`SystemDefaults`, `StaticServiceStore`, `ConfigurableServiceStore`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(
						"PersistentStore", "ActiveStore", "GroupPolicy", "RSOP",
						"SystemDefaults", "StaticServiceStore", "ConfigurableServiceStore",
					),
				},
			},

			"protocol": schema.StringAttribute{
				Optional:   true,
				Computed:   true,
				CustomType: firewallProtocolType{},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					// No canonicalising plan modifier here (F01/F02): the
					// plan must stay identical to the configuration —
					// rewriting it (tcp → TCP, 1 → ICMPv4, ...) makes
					// Terraform core reject the plan with "Provider produced
					// invalid plan". The canonical spelling is applied at
					// Create/Update time (modelToFirewallInput) and the state
					// stores what Windows reports (parseFirewallRuleState);
					// plan and state still compare equal thanks to
					// firewallProtocolValue StringSemanticEquals on the
					// Create/Update/Read path. On the plan path (where the
					// framework never runs SemanticEquals) ModifyPlan folds
					// the plan back to the prior value when semantically
					// equal (F08), which keeps the post-import plan empty.
				},
				Description: "IP protocol keyword (`TCP`, `UDP`, `ICMPv4`, `ICMPv6`, `IGMP`, `Any`) " +
					"or numeric string 0-255. Populated from Get-NetFirewallPortFilter.",
				Validators: []validator.String{
					firewallProtocolValidator{},
				},
			},

			"local_port": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				CustomType:  firewallCanonicalListType{kind: firewallListKindPort},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
					// No canonicalising plan modifier here (F01/F03): the
					// plan must stay identical to the configuration —
					// rewriting it (X-X → X, sorting, ...) makes Terraform
					// core reject the plan with "Provider produced invalid
					// plan". The canonical form is applied at Create/Update
					// time (modelToFirewallInput) and the state stores what
					// Windows reports (parseFirewallRuleState); plan and
					// state still compare equal thanks to
					// firewallCanonicalListValue ListSemanticEquals on the
					// Create/Update/Read path. On the plan path ModifyPlan
					// folds the plan back to the prior value when
					// semantically equal (F08).
				},
				Description: "Local TCP/UDP port(s). Accepts numeric ports, ranges, and keywords. " +
					"Valid only when protocol is `TCP` or `UDP` (CV-2). Populated from Get-NetFirewallPortFilter.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						firewallPortValidator{},
					),
				},
			},

			"remote_port": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				CustomType:  firewallCanonicalListType{kind: firewallListKindPort},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
					// F01/F03: no canonicalising plan modifier, see local_port.
				},
				Description: "Remote TCP/UDP port(s). Same constraints as local_port. " +
					"Populated from Get-NetFirewallPortFilter.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						firewallPortValidator{},
					),
				},
			},

			"local_address": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				CustomType:  firewallCanonicalListType{kind: firewallListKindAddress},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
					// F03: no canonicalising plan modifier, see local_port.
					// Combining `Any` with other addresses is rejected by
					// CV-3 (Windows silently drops the combined `Any`).
				},
				Description: "Local IP addresses, CIDR ranges, or address keywords. " +
					"Populated from Get-NetFirewallAddressFilter.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						firewallAddressValidator{},
					),
				},
			},

			"remote_address": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				CustomType:  firewallCanonicalListType{kind: firewallListKindAddress},
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
					// F03: no canonicalising plan modifier, see local_port.
				},
				Description: "Remote addresses. Same constraints as local_address. " +
					"Populated from Get-NetFirewallAddressFilter.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						firewallAddressValidator{},
					),
				},
			},

			"program": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Full path to the matched program executable, or `\"Any\"`. Populated from Get-NetFirewallApplicationFilter.",
				Validators: []validator.String{
					firewallSafeStringValidator{},
				},
			},

			"service": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Short name of the matched Windows service, or `\"Any\"`. Populated from Get-NetFirewallServiceFilter.",
				Validators: []validator.String{
					firewallSafeStringValidator{},
				},
			},

			"interface_type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Interface type. One of: `Any`, `Wireless`, `Wired`, `RemoteAccess`. Populated from Get-NetFirewallInterfaceTypeFilter.",
				Validators: []validator.String{
					stringvalidator.OneOf("Any", "Wireless", "Wired", "RemoteAccess"),
				},
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// firewallRuleDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely (issue #122).
			"timeouts": timeouts.Attributes(ctx, fwTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// ConfigValidators returns the resource-level cross-field validators:
//   - CV-1 (firewallRuleProfileValidator): "Any" must appear alone in profile.
//   - CV-2 (firewallRulePortProtocolValidator): ports only valid with TCP/UDP.
//   - CV-3 (firewallRuleAddressAnyValidator): "Any" must appear alone in
//     local_address / remote_address (F03: Windows silently drops a combined
//     Any, which otherwise surfaces as an inconsistent result after apply).
func (r *windowsFirewallRuleResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		firewallRuleProfileValidator{},
		firewallRulePortProtocolValidator{},
		firewallRuleAddressAnyValidator{},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates a
// FirewallRuleClient for this resource instance.
func (r *windowsFirewallRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := configuredClient(req.ProviderData, &resp.Diagnostics)
	if c == nil {
		return
	}
	r.fw = winclient.NewFirewallRuleClient(c)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create provisions a new Windows Firewall rule and saves the full state.
func (r *windowsFirewallRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsFirewallRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, firewallRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	input, diags := modelToFirewallInput(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Windows Firewall rule", map[string]any{
		"name":         input.Name,
		"policy_store": input.PolicyStore,
	})

	state, err := r.fw.Create(ctx, input)
	if err != nil {
		// Partial failure (ADR-0012): the rule may already exist on the
		// host. Persist the observed state so the resource is tainted
		// rather than dropped from state. A nil state (for example, the
		// already_exists pre-flight) stays error-only.
		if state != nil {
			m := firewallStateToModel(state)
			m.Timeouts = plan.Timeouts
			resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
		}
		addFirewallDiag(&resp.Diagnostics, "Error creating Windows Firewall rule", err)
		return
	}

	m := firewallStateToModel(state)
	// Preserve the user-configured per-operation timeouts: the projection
	// covers only Win32-observed fields, and Set overwrites the full state.
	m.Timeouts = plan.Timeouts
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live Windows Firewall rule.
func (r *windowsFirewallRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsFirewallRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, firewallRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	name := state.Name.ValueString()
	policyStore := state.PolicyStore.ValueString()

	tflog.Debug(ctx, "Reading Windows Firewall rule", map[string]any{
		"name":         name,
		"policy_store": policyStore,
	})

	fwState, err := r.fw.Read(ctx, name, policyStore)
	if err != nil {
		addFirewallDiag(&resp.Diagnostics, "Error reading Windows Firewall rule", err)
		return
	}

	if fwState == nil {
		// Rule deleted out-of-band.
		tflog.Warn(ctx, "Windows Firewall rule not found; removing from state", map[string]any{
			"name":         name,
			"policy_store": policyStore,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	m := firewallStateToModel(fwState)
	m.Timeouts = state.Timeouts
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place attribute changes to an existing firewall rule.
func (r *windowsFirewallRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsFirewallRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, firewallRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// name, group, and policy_store are ForceNew so they never change here.
	name := plan.Name.ValueString()
	policyStore := plan.PolicyStore.ValueString()

	input, diags := modelToFirewallInput(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating Windows Firewall rule", map[string]any{
		"name":         name,
		"policy_store": policyStore,
	})

	fwState, err := r.fw.Update(ctx, name, policyStore, input)
	if err != nil {
		// Partial failure (ADR-0012): persist the observed state so the
		// resource keeps its partial state rather than staying at prior
		// state. A nil state stays error-only.
		if fwState != nil {
			m := firewallStateToModel(fwState)
			m.Timeouts = plan.Timeouts
			resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
		}
		addFirewallDiag(&resp.Diagnostics, "Error updating Windows Firewall rule", err)
		return
	}

	m := firewallStateToModel(fwState)
	m.Timeouts = plan.Timeouts
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the Windows Firewall rule (idempotent).
func (r *windowsFirewallRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsFirewallRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, firewallRuleDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	name := state.Name.ValueString()
	policyStore := state.PolicyStore.ValueString()

	tflog.Debug(ctx, "Deleting Windows Firewall rule", map[string]any{
		"name":         name,
		"policy_store": policyStore,
	})

	if err := r.fw.Delete(ctx, name, policyStore); err != nil {
		if winclient.IsFirewallRuleError(err, winclient.FirewallRuleErrorNotFound) {
			return // already gone
		}
		addFirewallDiag(&resp.Diagnostics, "Error deleting Windows Firewall rule", err)
	}
}

// ---------------------------------------------------------------------------
// ModifyPlan — fold semantically-equal spellings toward prior state (F08)
// ---------------------------------------------------------------------------

// ModifyPlan folds the plan back to the prior state value for the protocol
// and filter-list attributes when both spellings describe the same Windows
// filter. The framework only runs StringSemanticEquals/ListSemanticEquals on
// the Create/Update/Read responses — never inside PlanResourceChange — so
// after an import (which stores the canonical Windows spelling) the next
// plan compares the verbatim configuration against the canonical prior with
// no semantic pass and reports a perpetual diff (protocol udp→UDP,
// reordered ports, ...). Copying the prior value into the plan is always
// legal for these Optional+Computed attributes (unlike inventing the
// canonical spelling in a plan modifier, which core rejects with "Provider
// produced invalid plan", F01/F02/F03 attempt 2): on the post-import path the
// plan becomes prior-identical and empty, on the normal path prior and plan
// already match verbatim so folding is a no-op, and genuine changes still
// flow through untouched.
func (r *windowsFirewallRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return // create / destroy
	}
	var plan, state windowsFirewallRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Protocol: fold only when both sides are known and canonicalise equal
	// (udp vs UDP, 6 vs TCP, ...). Unknown/null means nothing to compare.
	if !plan.Protocol.IsNull() && !plan.Protocol.IsUnknown() &&
		!state.Protocol.IsNull() && !state.Protocol.IsUnknown() &&
		winclient.CanonicalFirewallProtocol(plan.Protocol.ValueString()) ==
			winclient.CanonicalFirewallProtocol(state.Protocol.ValueString()) {
		plan.Protocol = state.Protocol
	}

	// Filter lists: fold each list whose planned and prior values describe
	// the same Windows filter (per-element folding, dedup, order-insensitive).
	for _, l := range []struct {
		kind  firewallListKind
		plan  *firewallCanonicalListValue
		prior firewallCanonicalListValue
	}{
		{firewallListKindPort, &plan.LocalPort, state.LocalPort},
		{firewallListKindPort, &plan.RemotePort, state.RemotePort},
		{firewallListKindAddress, &plan.LocalAddress, state.LocalAddress},
		{firewallListKindAddress, &plan.RemoteAddress, state.RemoteAddress},
	} {
		folded, ok := foldFirewallListValue(ctx, l.kind, l.plan, &l.prior, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if ok {
			*l.plan = folded
		}
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// foldFirewallListValue returns the prior list value when the planned and
// prior lists describe the same Windows filter, and false when they genuinely
// differ (or when either side is unset/unknown and there is nothing safe to
// compare). A Null/Unknown element on either side also refuses to fold, like
// the toRaw guard in ListSemanticEquals.
func foldFirewallListValue(ctx context.Context, kind firewallListKind, planned, prior *firewallCanonicalListValue, diags *diag.Diagnostics) (firewallCanonicalListValue, bool) {
	if planned.IsNull() || planned.IsUnknown() || prior.IsNull() || prior.IsUnknown() {
		return *planned, false
	}
	var plannedElems, priorElems []types.String
	diags.Append(planned.ElementsAs(ctx, &plannedElems, false)...)
	diags.Append(prior.ElementsAs(ctx, &priorElems, false)...)
	if diags.HasError() {
		return *planned, false
	}
	toRaw := func(elems []types.String) ([]string, bool) {
		raw := make([]string, 0, len(elems))
		for _, el := range elems {
			if el.IsNull() || el.IsUnknown() {
				return nil, false
			}
			raw = append(raw, el.ValueString())
		}
		return raw, true
	}
	plannedRaw, ok := toRaw(plannedElems)
	if !ok {
		return *planned, false
	}
	priorRaw, ok := toRaw(priorElems)
	if !ok {
		return *planned, false
	}
	if firewallCanonicalListStringsEqual(kind, plannedRaw, priorRaw) {
		return *prior, true
	}
	return *planned, false
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState supports two import ID formats:
//   - "<name>"                  → PersistentStore assumed
//   - "<policy_store>/<name>"   → explicit store
func (r *windowsFirewallRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID
	var name, policyStore string

	if idx := strings.Index(id, "/"); idx >= 0 {
		policyStore = id[:idx]
		name = id[idx+1:]
	} else {
		name = id
		policyStore = "PersistentStore"
	}

	if name == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID %q must be '<name>' or '<policy_store>/<name>'.", id),
		)
		return
	}

	if r.fw == nil {
		resp.Diagnostics.AddError("Provider not configured",
			"ImportState needs a configured provider client. Configure the windows provider (or WINDOWS_* environment) and retry the import.")
		return
	}

	tflog.Debug(ctx, "Importing Windows Firewall rule", map[string]any{
		"name":         name,
		"policy_store": policyStore,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, firewallRuleDefaultTimeout)
	defer cancel()

	fwState, err := r.fw.Read(ctx, name, policyStore)
	if err != nil {
		addFirewallDiag(&resp.Diagnostics, "Error importing Windows Firewall rule", err)
		return
	}
	if fwState == nil {
		resp.Diagnostics.AddError(
			"Firewall rule not found",
			fmt.Sprintf("Firewall rule %q not found in policy store %q.", name, policyStore),
		)
		return
	}

	m := firewallStateToModel(fwState)
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by State.Set — use a typed null instead (the
	// subsequent Read fills in the configured values).
	m.Timeouts = fwNullTimeouts()
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helper: modelToFirewallInput
// ---------------------------------------------------------------------------

// modelToFirewallInput converts a Terraform model to a FirewallRuleInput.
func modelToFirewallInput(ctx context.Context, m windowsFirewallRuleModel) (winclient.FirewallRuleInput, diag.Diagnostics) {
	var diags diag.Diagnostics

	profile, d := stringsFromList(ctx, m.Profile)
	diags.Append(d...)

	localPort, d := stringsFromList(ctx, m.LocalPort.ListValue)
	diags.Append(d...)

	remotePort, d := stringsFromList(ctx, m.RemotePort.ListValue)
	diags.Append(d...)

	localAddress, d := stringsFromList(ctx, m.LocalAddress.ListValue)
	diags.Append(d...)

	remoteAddress, d := stringsFromList(ctx, m.RemoteAddress.ListValue)
	diags.Append(d...)

	if diags.HasError() {
		return winclient.FirewallRuleInput{}, diags
	}

	enabled := m.Enabled.ValueBool()
	// F01/F02/F03: canonicalise apply-side so the values sent to Windows use
	// the spelling Windows reports back: degenerate port ranges collapse
	// (55014-55014 → 55014), protocol spellings fold to canonical form
	// (tcp → TCP, 1 → ICMPv4) and filter lists are deduped + sorted. The plan
	// keeps the raw configuration (no rewriting plan modifier), and the
	// state stores the canonical Windows spelling (parseFirewallRuleState);
	// plan and post-apply state still compare equal thanks to the
	// SemanticEquals on the custom types, so neither "invalid plan" nor
	// "inconsistent result after apply" can fire here.
	return winclient.FirewallRuleInput{
		Name:                m.Name.ValueString(),
		DisplayName:         m.DisplayName.ValueString(),
		Description:         m.Description.ValueString(),
		Enabled:             &enabled,
		Direction:           m.Direction.ValueString(),
		Action:              m.Action.ValueString(),
		Profile:             profile,
		EdgeTraversalPolicy: m.EdgeTraversalPolicy.ValueString(),
		Group:               m.Group.ValueString(),
		PolicyStore:         m.PolicyStore.ValueString(),
		Protocol:            winclient.CanonicalFirewallProtocol(m.Protocol.ValueString()),
		LocalPort:           winclient.CanonicalFirewallPortList(localPort),
		RemotePort:          winclient.CanonicalFirewallPortList(remotePort),
		LocalAddress:        winclient.CanonicalFirewallAddressList(localAddress),
		RemoteAddress:       winclient.CanonicalFirewallAddressList(remoteAddress),
		Program:             m.Program.ValueString(),
		Service:             m.Service.ValueString(),
		InterfaceType:       m.InterfaceType.ValueString(),
	}, diags
}

// ---------------------------------------------------------------------------
// Helper: firewallStateToModel
// ---------------------------------------------------------------------------

// fwTimeoutsOpts declares which per-operation timeouts the resource exposes.
// The schema and fwNullTimeouts both derive from it; keep them together,
// since a null timeouts value whose attribute types disagree with the schema
// is rejected by the framework as a provider type error.
var fwTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// fwNullTimeouts returns a null timeouts value carrying the schema's attribute
// types. The zero timeouts.Value wraps an object with NO attribute types,
// which the framework rejects on State.Set — the failure mode on import,
// where there is no prior state to copy the value from.
func fwNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if fwTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if fwTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if fwTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if fwTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// firewallStateToModel converts a FirewallRuleState to a Terraform model.
// The state keeps the canonical Windows spelling (already normalised by
// parseFirewallRuleState); it is compared to the raw configuration by the
// SemanticEquals on the custom types, so no plan rewriting is needed.
func firewallStateToModel(s *winclient.FirewallRuleState) windowsFirewallRuleModel {
	profile := listFromStrings(s.Profile)
	localPort := firewallCanonicalListFromStrings(firewallListKindPort, s.LocalPort)
	remotePort := firewallCanonicalListFromStrings(firewallListKindPort, s.RemotePort)
	localAddress := firewallCanonicalListFromStrings(firewallListKindAddress, s.LocalAddress)
	remoteAddress := firewallCanonicalListFromStrings(firewallListKindAddress, s.RemoteAddress)

	m := windowsFirewallRuleModel{
		ID:                  types.StringValue(s.Name),
		Name:                types.StringValue(s.Name),
		DisplayName:         types.StringValue(s.DisplayName),
		Description:         strOrNull(s.Description),
		Enabled:             types.BoolValue(s.Enabled),
		Direction:           types.StringValue(s.Direction),
		Action:              types.StringValue(s.Action),
		Profile:             profile,
		EdgeTraversalPolicy: types.StringValue(s.EdgeTraversalPolicy),
		Group:               types.StringValue(s.Group),
		PolicyStore:         types.StringValue(s.PolicyStore),
		Protocol:            firewallProtocolValueOf(s.Protocol),
		LocalPort:           localPort,
		RemotePort:          remotePort,
		LocalAddress:        localAddress,
		RemoteAddress:       remoteAddress,
		Program:             types.StringValue(s.Program),
		Service:             types.StringValue(s.Service),
		InterfaceType:       types.StringValue(s.InterfaceType),
	}
	return m
}

// ---------------------------------------------------------------------------
// Helper: list <-> []string converters
// ---------------------------------------------------------------------------

// stringsFromList extracts a []string from a types.List of StringType elements.
func stringsFromList(ctx context.Context, l types.List) ([]string, diag.Diagnostics) {
	if l.IsNull() || l.IsUnknown() {
		return nil, nil
	}
	var elems []types.String
	diags := l.ElementsAs(ctx, &elems, false)
	if diags.HasError() {
		return nil, diags
	}
	out := make([]string, 0, len(elems))
	for _, el := range elems {
		if !el.IsNull() && !el.IsUnknown() {
			out = append(out, el.ValueString())
		}
	}
	return out, nil
}

// listFromStrings converts a []string to a types.List of StringType.
func listFromStrings(strs []string) types.List {
	if len(strs) == 0 {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}
	vals := make([]attr.Value, len(strs))
	for i, s := range strs {
		vals[i] = types.StringValue(s)
	}
	return types.ListValueMust(types.StringType, vals)
}

// ---------------------------------------------------------------------------
// Helper: addFirewallDiag
// ---------------------------------------------------------------------------

// addFirewallDiag appends a diagnostic from a firewall client error.
// It enriches the message with context fields when available.
func addFirewallDiag(d *diag.Diagnostics, summary string, err error) {
	var fe *winclient.FirewallRuleError
	if errors.As(err, &fe) {
		detail := fe.Message
		if len(fe.Context) > 0 {
			var parts []string
			for k, v := range fe.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if fe.Cause != nil {
			detail += "\n\nCause: " + fe.Cause.Error()
		}
		d.AddError(summary+" ["+fe.Kind+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// firewallPortRe accepts the NetFirewallRule port-filter grammar at plan
// time (#324): the `Any` keyword (case-insensitive, as Windows reports
// `Any`), a single numeric port, or a numeric range. Protocol scoping
// (ports only valid with TCP/UDP) stays in firewallRulePortProtocolValidator
// (CV-2); numeric bounds (0-65535) and reversed ranges are enforced by
// firewallPortValidator at plan time.
var firewallPortRe = regexp.MustCompile(`^(?i)(ANY|[0-9]+(-[0-9]+)?)$`)

const firewallPortDesc = "must be `Any`, a numeric port 0-65535 (e.g. `80`), or a numeric range within 0-65535 with start <= end (e.g. `8000-8100`)"

// firewallPortValidator tightens firewallPortRe at plan time: `Any`
// (case-insensitive), a single numeric port 0-65535, or a numeric range
// where both ends are 0-65535 and start <= end (reversed ranges rejected).
type firewallPortValidator struct{}

func (v firewallPortValidator) Description(_ context.Context) string {
	return "Port " + firewallPortDesc + "."
}

func (v firewallPortValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallPortValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if strings.EqualFold(val, "Any") {
		return
	}
	if !firewallPortRe.MatchString(val) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid port value",
			fmt.Sprintf("port %q "+firewallPortDesc+".", val))
		return
	}
	if strings.Contains(val, "-") {
		parts := strings.SplitN(val, "-", 2)
		lo, errLo := strconv.Atoi(parts[0])
		hi, errHi := strconv.Atoi(parts[1])
		if errLo != nil || errHi != nil || lo < 0 || lo > 65535 || hi < 0 || hi > 65535 {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid port value",
				fmt.Sprintf("port range %q must have both ends within 0-65535.", val))
			return
		}
		if lo > hi {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid port value",
				fmt.Sprintf("port range %q is reversed: start must be <= end.", val))
			return
		}
		return
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 || n > 65535 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid port value",
			fmt.Sprintf("port %q must be within 0-65535.", val))
		return
	}
}

// firewallAddressValidator accepts `Any` (case-insensitive), a single IP
// address, or a CIDR range. Anything else — including shell metacharacters
// (`;`, `$`, `(`, `)`, quotes, backticks) — is rejected at plan time so a
// crafted address can never reach the PowerShell command line.
type firewallAddressValidator struct{}

func (v firewallAddressValidator) Description(_ context.Context) string {
	return "Address must be `Any`, an IP address, or a CIDR range."
}

func (v firewallAddressValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallAddressValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if strings.EqualFold(strings.TrimSpace(val), "Any") {
		return
	}
	if ip := net.ParseIP(strings.TrimSpace(val)); ip != nil {
		return
	}
	if _, _, err := net.ParseCIDR(strings.TrimSpace(val)); err == nil {
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid address value",
		fmt.Sprintf("address %q must be `Any`, an IP address, or a CIDR range.", val))
}

// firewallSafeStringValidator guards program/service/group: values travel
// through psQuote, but plan-time rejection of line breaks, null bytes and
// shell/PowerShell metacharacters (`;`, `$`, `(`, `)`, backtick, quotes,
// `&`, `|`, `<`, `>`) keeps obvious injection payloads out of config.
type firewallSafeStringValidator struct{}

func (v firewallSafeStringValidator) Description(_ context.Context) string {
	return "must not contain line breaks, null bytes, or characters ; $ ( ) ` \" ' & | < >"
}

func (v firewallSafeStringValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallSafeStringValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if val == "" {
		return
	}
	if strings.ContainsAny(val, "\r\n\x00;$()`\"'&|<>") {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
			fmt.Sprintf("value %q must not contain line breaks, null bytes, or characters ; $ ( ) ` \" ' & | < >.", val))
	}
}

// firewallProtocolValidator validates that the protocol attribute value is
// either a well-known keyword or a numeric string in the range 0-255.
type firewallProtocolValidator struct{}

func (v firewallProtocolValidator) Description(_ context.Context) string {
	return "Protocol must be a keyword (TCP, UDP, ICMPv4, ICMPv6, IGMP, Any) or a numeric string 0-255."
}

func (v firewallProtocolValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallProtocolValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()

	keywords := []string{"TCP", "UDP", "ICMPv4", "ICMPv6", "IGMP", "Any"}
	for _, kw := range keywords {
		if strings.EqualFold(val, kw) {
			return
		}
	}

	n, err := strconv.Atoi(val)
	if err == nil && n >= 0 && n <= 255 {
		return
	}

	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid protocol value",
		fmt.Sprintf(
			"protocol must be one of TCP, UDP, ICMPv4, ICMPv6, IGMP, Any, or a numeric string 0-255; got %q.",
			val,
		),
	)
}

// firewallRuleProfileValidator rejects a profile list that mixes "Any" with
// other profile values (CV-1, ADR-FR-7).
type firewallRuleProfileValidator struct{}

func (v firewallRuleProfileValidator) Description(_ context.Context) string {
	return `CV-1: profile "Any" must not be combined with other profile values.`
}

func (v firewallRuleProfileValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallRuleProfileValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var profile types.List
	diags := req.Config.GetAttribute(ctx, path.Root("profile"), &profile)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if profile.IsNull() || profile.IsUnknown() {
		return
	}

	var elements []types.String
	diags = profile.ElementsAs(ctx, &elements, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasAny := false
	count := 0
	for _, el := range elements {
		if el.IsNull() || el.IsUnknown() {
			continue
		}
		count++
		if el.ValueString() == "Any" {
			hasAny = true
		}
	}

	if hasAny && count > 1 {
		resp.Diagnostics.AddAttributeError(
			path.Root("profile"),
			"Invalid profile combination",
			`profile "Any" must not be combined with other profile values `+
				"(Domain, Private, Public, NotApplicable). "+
				`Use ["Any"] alone, or list explicit profiles without "Any".`,
		)
	}
}

// firewallRulePortProtocolValidator rejects non-empty local_port or
// remote_port when protocol is not TCP or UDP (CV-2, ADR-FR-8).
type firewallRulePortProtocolValidator struct{}

func (v firewallRulePortProtocolValidator) Description(_ context.Context) string {
	return "CV-2: local_port and remote_port are only valid when protocol is TCP or UDP."
}

func (v firewallRulePortProtocolValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallRulePortProtocolValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var protocol firewallProtocolValue
	var localPort firewallCanonicalListValue
	var remotePort firewallCanonicalListValue

	diags := req.Config.GetAttribute(ctx, path.Root("protocol"), &protocol)
	resp.Diagnostics.Append(diags...)
	diags = req.Config.GetAttribute(ctx, path.Root("local_port"), &localPort)
	resp.Diagnostics.Append(diags...)
	diags = req.Config.GetAttribute(ctx, path.Root("remote_port"), &remotePort)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}
	if protocol.IsNull() || protocol.IsUnknown() {
		return
	}

	proto := winclient.CanonicalFirewallProtocol(protocol.ValueString())
	isTCPOrUDP := proto == "TCP" || proto == "UDP"
	if isTCPOrUDP {
		return
	}

	if !localPort.IsNull() && !localPort.IsUnknown() && len(localPort.Elements()) > 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("local_port"),
			"Invalid port specification for protocol",
			fmt.Sprintf(
				"local_port can only be set when protocol is TCP or UDP; got protocol=%q.",
				proto,
			),
		)
	}

	if !remotePort.IsNull() && !remotePort.IsUnknown() && len(remotePort.Elements()) > 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("remote_port"),
			"Invalid port specification for protocol",
			fmt.Sprintf(
				"remote_port can only be set when protocol is TCP or UDP; got protocol=%q.",
				proto,
			),
		)
	}
}

// firewallRuleAddressAnyValidator rejects a local_address or remote_address
// list that mixes "Any" (case-insensitive) with other address values
// (CV-3, mirror of CV-1 for profile). Windows silently drops an `Any`
// combined with concrete addresses, so accepting it would surface as an
// inconsistent result after apply (F03).
type firewallRuleAddressAnyValidator struct{}

func (v firewallRuleAddressAnyValidator) Description(_ context.Context) string {
	return `CV-3: address list "Any" must not be combined with other address values.`
}

func (v firewallRuleAddressAnyValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v firewallRuleAddressAnyValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	for _, name := range []string{"local_address", "remote_address"} {
		var list firewallCanonicalListValue
		diags := req.Config.GetAttribute(ctx, path.Root(name), &list)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		if list.IsNull() || list.IsUnknown() {
			continue
		}

		var elements []types.String
		diags = list.ElementsAs(ctx, &elements, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		hasAny := false
		count := 0
		for _, el := range elements {
			if el.IsNull() || el.IsUnknown() {
				continue
			}
			// Skip blank elements: firewallAddressValidator already rejects
			// them as invalid values, so they must not count as "other
			// address values" for the Any combination check.
			if strings.TrimSpace(el.ValueString()) == "" {
				continue
			}
			count++
			if strings.EqualFold(strings.TrimSpace(el.ValueString()), "Any") {
				hasAny = true
			}
		}

		if hasAny && count > 1 {
			resp.Diagnostics.AddAttributeError(
				path.Root(name),
				"Invalid address combination",
				fmt.Sprintf(
					"%s %q must not be combined with other address values "+
						"(Windows silently drops the combined `Any`). "+
						`Use ["Any"] alone, or list explicit addresses without "Any".`,
					name, "Any",
				),
			)
		}
	}
}

// ---------------------------------------------------------------------------
// Semantic equality: state-side canonicalisation (F01/F02/F03)
// ---------------------------------------------------------------------------
//
// The plan must stay identical to the configuration: any plan modifier that
// rewrites a planned value (tcp → TCP, 55014-55014 → 55014, sorting, ...)
// makes Terraform core reject the whole plan with "Provider produced invalid
// plan" (F01/F02/F03). Canonicalisation therefore happens apply-side only
// (modelToFirewallInput / buildFirewallParams) and state-side
// (parseFirewallRuleState stores the canonical Windows spelling).
//
// The custom types below only relax the *comparison*: a raw configured value
// and the canonical state value compare equal when Windows treats them as
// the same rule, so neither "invalid plan" (plan == config, untouched) nor
// "inconsistent result after apply" (raw plan vs canonical state) can fire.
// This mirrors the windows_scheduled_task durationValue /
// subscriptionXMLValue precedent. The stored strings are never rewritten by
// the equality check.

// firewallProtocolValue is the framework value type for the "protocol"
// attribute. It implements semantic equality so that equivalent spellings of
// the same protocol (tcp/TCP/6, 1/ICMPv4, any/Any, ...) compare equal,
// avoiding both a "provider produced inconsistent result after apply" error
// (on create) and a false diff on later refresh.
type firewallProtocolValue struct {
	basetypes.StringValue
}

func firewallProtocolValueOf(s string) firewallProtocolValue {
	return firewallProtocolValue{StringValue: types.StringValue(s)}
}

func (v firewallProtocolValue) Equal(o attr.Value) bool {
	other, ok := o.(firewallProtocolValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v firewallProtocolValue) Type(context.Context) attr.Type {
	return firewallProtocolType{}
}

func (v firewallProtocolValue) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	other, ok := newValuable.(firewallProtocolValue)
	if !ok {
		diags.AddError("Semantic Equality Check Error",
			fmt.Sprintf("expected firewallProtocolValue, got %T", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || other.IsNull() || other.IsUnknown() {
		return false, diags
	}
	return winclient.CanonicalFirewallProtocol(v.ValueString()) ==
		winclient.CanonicalFirewallProtocol(other.ValueString()), diags
}

// firewallProtocolType is the attr.Type counterpart of firewallProtocolValue.
type firewallProtocolType struct {
	basetypes.StringType
}

func (t firewallProtocolType) Equal(o attr.Type) bool {
	other, ok := o.(firewallProtocolType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t firewallProtocolType) String() string {
	return "firewallProtocolType"
}

func (t firewallProtocolType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return firewallProtocolValue{StringValue: in}, nil
}

func (t firewallProtocolType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T for firewallProtocolType", attrValue)
	}
	valuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("error converting StringValue to firewallProtocolValue: %v", diags)
	}
	return valuable, nil
}

func (t firewallProtocolType) ValueType(context.Context) attr.Value {
	return firewallProtocolValue{}
}

// firewallListKind selects the per-element canonicalisation used by
// firewallCanonicalListValue.ListSemanticEquals.
type firewallListKind string

const (
	// firewallListKindPort canonicalises port tokens (degenerate range
	// collapse, `any` casing).
	firewallListKindPort firewallListKind = "port"
	// firewallListKindAddress canonicalises address tokens (`any` casing).
	firewallListKindAddress firewallListKind = "address"
)

// firewallCanonicalListValue is the framework value type for the
// filter-list attributes (local_port, remote_port, local_address,
// remote_address). It implements semantic equality so that a raw configured
// list and the canonical state list compare equal when they describe the
// same Windows filter: per-element canonicalisation (degenerate ranges,
// `any` casing), deduplication and order-insensitivity.
type firewallCanonicalListValue struct {
	basetypes.ListValue
	kind firewallListKind
}

func firewallCanonicalListFromStrings(kind firewallListKind, strs []string) firewallCanonicalListValue {
	if len(strs) == 0 {
		return firewallCanonicalListValue{
			ListValue: types.ListValueMust(types.StringType, []attr.Value{}),
			kind:      kind,
		}
	}
	vals := make([]attr.Value, len(strs))
	for i, s := range strs {
		vals[i] = types.StringValue(s)
	}
	return firewallCanonicalListValue{
		ListValue: types.ListValueMust(types.StringType, vals),
		kind:      kind,
	}
}

func firewallCanonicalListNull(kind firewallListKind) firewallCanonicalListValue {
	return firewallCanonicalListValue{
		ListValue: types.ListNull(types.StringType),
		kind:      kind,
	}
}

func firewallCanonicalListUnknown(kind firewallListKind) firewallCanonicalListValue {
	return firewallCanonicalListValue{
		ListValue: types.ListUnknown(types.StringType),
		kind:      kind,
	}
}

func (v firewallCanonicalListValue) Equal(o attr.Value) bool {
	other, ok := o.(firewallCanonicalListValue)
	if !ok {
		return false
	}
	return v.kind == other.kind && v.ListValue.Equal(other.ListValue)
}

func (v firewallCanonicalListValue) Type(context.Context) attr.Type {
	return firewallCanonicalListType{kind: v.kind}
}

func (v firewallCanonicalListValue) ListSemanticEquals(ctx context.Context, newValuable basetypes.ListValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	other, ok := newValuable.(firewallCanonicalListValue)
	if !ok {
		diags.AddError("Semantic Equality Check Error",
			fmt.Sprintf("expected firewallCanonicalListValue, got %T", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || other.IsNull() || other.IsUnknown() {
		return false, diags
	}
	var planned, current []types.String
	diags.Append(v.ElementsAs(ctx, &planned, false)...)
	diags.Append(other.ElementsAs(ctx, &current, false)...)
	if diags.HasError() {
		return false, diags
	}
	toRaw := func(elems []types.String) ([]string, bool) {
		raw := make([]string, 0, len(elems))
		for _, el := range elems {
			if el.IsNull() || el.IsUnknown() {
				return nil, false
			}
			raw = append(raw, el.ValueString())
		}
		return raw, true
	}
	rawPlanned, ok := toRaw(planned)
	if !ok {
		return false, diags
	}
	rawCurrent, ok := toRaw(current)
	if !ok {
		return false, diags
	}
	return firewallCanonicalListStringsEqual(v.kind, rawPlanned, rawCurrent), diags
}

// firewallCanonicalListStringsEqual reports whether two raw filter lists
// describe the same Windows filter: each side is canonicalised (per-element
// folding, deduplication, sorting) and the results are compared exactly.
func firewallCanonicalListStringsEqual(kind firewallListKind, a, b []string) bool {
	var canonicalise func([]string) []string
	if kind == firewallListKindAddress {
		canonicalise = winclient.CanonicalFirewallAddressList
	} else {
		canonicalise = winclient.CanonicalFirewallPortList
	}
	ca, cb := canonicalise(a), canonicalise(b)
	if len(ca) != len(cb) {
		return false
	}
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

// firewallCanonicalListType is the attr.Type counterpart of
// firewallCanonicalListValue.
type firewallCanonicalListType struct {
	basetypes.ListType
	kind firewallListKind
}

func (t firewallCanonicalListType) Equal(o attr.Type) bool {
	other, ok := o.(firewallCanonicalListType)
	if !ok {
		return false
	}
	return t.kind == other.kind
}

func (t firewallCanonicalListType) String() string {
	return fmt.Sprintf("firewallCanonicalListType(%s)", string(t.kind))
}

// ElementType and TerraformType are fixed to string lists: the embedded
// basetypes.ListType carries no ElemType (the kind selects the equality,
// not the element type), so the defaults derived from it would describe
// List[DynamicPseudoType] and reject real state values on Set.
func (t firewallCanonicalListType) ElementType() attr.Type {
	return types.StringType
}

func (t firewallCanonicalListType) TerraformType(context.Context) tftypes.Type {
	return tftypes.List{ElementType: tftypes.String}
}

func (t firewallCanonicalListType) ValueFromList(_ context.Context, in basetypes.ListValue) (basetypes.ListValuable, diag.Diagnostics) {
	return firewallCanonicalListValue{ListValue: in, kind: t.kind}, nil
}

func (t firewallCanonicalListType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	if in.Type() == nil {
		return firewallCanonicalListNull(t.kind), nil
	}
	want := tftypes.List{ElementType: tftypes.String}
	if !in.Type().Equal(want) {
		return nil, fmt.Errorf("can't use %s as value of firewallCanonicalListType(%s), can only use %s values",
			in.String(), string(t.kind), want.String())
	}
	if !in.IsKnown() {
		return firewallCanonicalListUnknown(t.kind), nil
	}
	if in.IsNull() {
		return firewallCanonicalListNull(t.kind), nil
	}
	var tfElems []tftypes.Value
	if err := in.As(&tfElems); err != nil {
		return nil, err
	}
	elems := make([]attr.Value, 0, len(tfElems))
	for _, tfElem := range tfElems {
		av, err := types.StringType.ValueFromTerraform(ctx, tfElem)
		if err != nil {
			return nil, err
		}
		elems = append(elems, av)
	}
	return firewallCanonicalListValue{
		ListValue: basetypes.NewListValueMust(types.StringType, elems),
		kind:      t.kind,
	}, nil
}

func (t firewallCanonicalListType) ValueType(context.Context) attr.Value {
	return firewallCanonicalListNull(t.kind)
}
