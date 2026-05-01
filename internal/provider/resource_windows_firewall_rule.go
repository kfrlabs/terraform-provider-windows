// Package provider - resource_windows_firewall_rule implements the full
// Terraform resource lifecycle for windows_firewall_rule.
//
// The resource manages a single Windows Defender Firewall rule on a remote
// host via WinRM + PowerShell (NetSecurity module). It delegates all
// WinRM/PS interaction to winclient.FirewallRuleClient.
//
// Spec alignment: windows_firewall_rule spec v1 (2026-05-01).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
	_ resource.ResourceWithConfigValidators = (*windowsFirewallRuleResource)(nil)
)

// NewWindowsFirewallRuleResource is the constructor registered in provider.go.
func NewWindowsFirewallRuleResource() resource.Resource {
	return &windowsFirewallRuleResource{}
}

// windowsFirewallRuleResource is the TPF resource type for windows_firewall_rule.
type windowsFirewallRuleResource struct {
	client *winclient.Client
	fw     winclient.WindowsFirewallRuleClient
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsFirewallRuleModel is the Terraform state/plan model for
// windows_firewall_rule. Every tfsdk tag matches an attribute key in
// windowsFirewallRuleSchemaDefinition.
type windowsFirewallRuleModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	DisplayName         types.String `tfsdk:"display_name"`
	Description         types.String `tfsdk:"description"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	Direction           types.String `tfsdk:"direction"`
	Action              types.String `tfsdk:"action"`
	Profile             types.List   `tfsdk:"profile"`
	EdgeTraversalPolicy types.String `tfsdk:"edge_traversal_policy"`
	Group               types.String `tfsdk:"group"`
	PolicyStore         types.String `tfsdk:"policy_store"`
	Protocol            types.String `tfsdk:"protocol"`
	LocalPort           types.List   `tfsdk:"local_port"`
	RemotePort          types.List   `tfsdk:"remote_port"`
	LocalAddress        types.List   `tfsdk:"local_address"`
	RemoteAddress       types.List   `tfsdk:"remote_address"`
	Program             types.String `tfsdk:"program"`
	Service             types.String `tfsdk:"service"`
	InterfaceType       types.String `tfsdk:"interface_type"`
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
func (r *windowsFirewallRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsFirewallRuleSchemaDefinition()
}

// windowsFirewallRuleSchemaDefinition returns the complete TPF schema for
// windows_firewall_rule (19 user-facing attributes + id).
func windowsFirewallRuleSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a Windows Defender Firewall with Advanced Security rule " +
			"on a remote Windows host via WinRM and PowerShell (`NetSecurity` module). " +
			"One Terraform resource maps to exactly one `NetFirewallRule`, keyed on its " +
			"stable technical `Name` (InstanceID), which is distinct from `display_name`.\n\n" +
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
				Optional:    true,
				Computed:    true,
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
				PlanModifiers: []planmodifier.String{
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
				Optional: true,
				Computed: true,
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
				Description: "Local TCP/UDP port(s). Accepts numeric ports, ranges, and keywords. " +
					"Valid only when protocol is `TCP` or `UDP` (CV-2). Populated from Get-NetFirewallPortFilter.",
			},

			"remote_port": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Remote TCP/UDP port(s). Same constraints as local_port. " +
					"Populated from Get-NetFirewallPortFilter.",
			},

			"local_address": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Local IP addresses, CIDR ranges, or address keywords. " +
					"Populated from Get-NetFirewallAddressFilter.",
			},

			"remote_address": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Remote addresses. Same constraints as local_address. " +
					"Populated from Get-NetFirewallAddressFilter.",
			},

			"program": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Full path to the matched program executable, or `\"Any\"`. Populated from Get-NetFirewallApplicationFilter.",
			},

			"service": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Short name of the matched Windows service, or `\"Any\"`. Populated from Get-NetFirewallServiceFilter.",
			},

			"interface_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Interface type. One of: `Any`, `Wireless`, `Wired`, `RemoteAccess`. Populated from Get-NetFirewallInterfaceTypeFilter.",
				Validators: []validator.String{
					stringvalidator.OneOf("Any", "Wireless", "Wired", "RemoteAccess"),
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// ConfigValidators returns the resource-level cross-field validators:
//   - CV-1 (firewallRuleProfileValidator): "Any" must appear alone in profile.
//   - CV-2 (firewallRulePortProtocolValidator): ports only valid with TCP/UDP.
func (r *windowsFirewallRuleResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		firewallRuleProfileValidator{},
		firewallRulePortProtocolValidator{},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level WinRM client and creates a
// FirewallRuleClient for this resource instance.
func (r *windowsFirewallRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T.", req.ProviderData),
		)
		return
	}
	r.client = client
	r.fw = winclient.NewFirewallRuleClient(client)
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
		addFirewallDiag(&resp.Diagnostics, "Error creating Windows Firewall rule", err)
		return
	}

	m, diags := firewallStateToModel(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
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

	m, diags := firewallStateToModel(ctx, fwState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
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
		addFirewallDiag(&resp.Diagnostics, "Error updating Windows Firewall rule", err)
		return
	}

	m, diags := firewallStateToModel(ctx, fwState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
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

	name := state.Name.ValueString()
	policyStore := state.PolicyStore.ValueString()

	tflog.Debug(ctx, "Deleting Windows Firewall rule", map[string]any{
		"name":         name,
		"policy_store": policyStore,
	})

	if err := r.fw.Delete(ctx, name, policyStore); err != nil {
		addFirewallDiag(&resp.Diagnostics, "Error deleting Windows Firewall rule", err)
	}
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

	tflog.Debug(ctx, "Importing Windows Firewall rule", map[string]any{
		"name":         name,
		"policy_store": policyStore,
	})

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

	m, diags := firewallStateToModel(ctx, fwState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
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

	localPort, d := stringsFromList(ctx, m.LocalPort)
	diags.Append(d...)

	remotePort, d := stringsFromList(ctx, m.RemotePort)
	diags.Append(d...)

	localAddress, d := stringsFromList(ctx, m.LocalAddress)
	diags.Append(d...)

	remoteAddress, d := stringsFromList(ctx, m.RemoteAddress)
	diags.Append(d...)

	if diags.HasError() {
		return winclient.FirewallRuleInput{}, diags
	}

	enabled := m.Enabled.ValueBool()
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
		Protocol:            m.Protocol.ValueString(),
		LocalPort:           localPort,
		RemotePort:          remotePort,
		LocalAddress:        localAddress,
		RemoteAddress:       remoteAddress,
		Program:             m.Program.ValueString(),
		Service:             m.Service.ValueString(),
		InterfaceType:       m.InterfaceType.ValueString(),
	}, diags
}

// ---------------------------------------------------------------------------
// Helper: firewallStateToModel
// ---------------------------------------------------------------------------

// firewallStateToModel converts a FirewallRuleState to a Terraform model.
func firewallStateToModel(ctx context.Context, s *winclient.FirewallRuleState) (windowsFirewallRuleModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	profile := listFromStrings(s.Profile)
	localPort := listFromStrings(s.LocalPort)
	remotePort := listFromStrings(s.RemotePort)
	localAddress := listFromStrings(s.LocalAddress)
	remoteAddress := listFromStrings(s.RemoteAddress)

	m := windowsFirewallRuleModel{
		ID:                  types.StringValue(s.Name),
		Name:                types.StringValue(s.Name),
		DisplayName:         types.StringValue(s.DisplayName),
		Description:         types.StringValue(s.Description),
		Enabled:             types.BoolValue(s.Enabled),
		Direction:           types.StringValue(s.Direction),
		Action:              types.StringValue(s.Action),
		Profile:             profile,
		EdgeTraversalPolicy: types.StringValue(s.EdgeTraversalPolicy),
		Group:               types.StringValue(s.Group),
		PolicyStore:         types.StringValue(s.PolicyStore),
		Protocol:            types.StringValue(s.Protocol),
		LocalPort:           localPort,
		RemotePort:          remotePort,
		LocalAddress:        localAddress,
		RemoteAddress:       remoteAddress,
		Program:             types.StringValue(s.Program),
		Service:             types.StringValue(s.Service),
		InterfaceType:       types.StringValue(s.InterfaceType),
	}
	return m, diags
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
		d.AddError(summary+" ["+string(fe.Kind)+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

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
	var protocol types.String
	var localPort types.List
	var remotePort types.List

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

	proto := protocol.ValueString()
	isTCPOrUDP := strings.EqualFold(proto, "TCP") || strings.EqualFold(proto, "UDP")
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
