// Package provider: windows_firewall_rule data source implementation.
//
// Reads the observed state of a Windows Defender Firewall rule by its
// technical Name (InstanceID), without managing its lifecycle. Mirrors the
// resource schema in read-only form (no plan modifiers, no validators on
// user input beyond Required/Optional, no defaults).
//
// Spec alignment: windows_firewall_rule spec v1 (2026-05-01).
package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

var (
	_ datasource.DataSource              = (*windowsFirewallRuleDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsFirewallRuleDataSource)(nil)
)

// NewWindowsFirewallRuleDataSource is the constructor registered in provider.go.
func NewWindowsFirewallRuleDataSource() datasource.DataSource {
	return &windowsFirewallRuleDataSource{}
}

// windowsFirewallRuleDataSource is the TPF data source type for windows_firewall_rule.
type windowsFirewallRuleDataSource struct {
	client *winclient.Client
	fw     winclient.WindowsFirewallRuleClient
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsFirewallRuleDataSourceModel mirrors windowsFirewallRuleModel for the
// data source (read-only). Tfsdk tags must match the schema attribute keys.
type windowsFirewallRuleDataSourceModel struct {
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

// Metadata sets the data source type name ("windows_firewall_rule").
func (d *windowsFirewallRuleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

// Schema returns the TPF data source schema for windows_firewall_rule.
//
// `name` is Required. `policy_store` is Optional with implicit default
// "PersistentStore" applied at Read time. All other attributes are Computed.
func (d *windowsFirewallRuleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a Windows Defender Firewall " +
			"with Advanced Security rule on a remote Windows host via WinRM and " +
			"PowerShell (`NetSecurity` module). The rule is looked up by its stable " +
			"technical `name` (InstanceID), distinct from `display_name`.\n\n" +
			"Returns a Terraform error when the rule does not exist in the target " +
			"`policy_store` (defaults to `PersistentStore`).",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; equal to the technical firewall rule Name (InstanceID).",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Stable technical identifier of the firewall rule (InstanceID) to look up.",
			},
			"policy_store": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Policy store the rule lives in. Defaults to `PersistentStore`. " +
					"One of: `PersistentStore`, `ActiveStore`, `GroupPolicy`, `RSOP`, " +
					"`SystemDefaults`, `StaticServiceStore`, `ConfigurableServiceStore`.",
			},
			"display_name": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable name shown in the Windows Firewall UI.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Free-form description of the rule.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the rule is active.",
			},
			"direction": schema.StringAttribute{
				Computed:    true,
				Description: "Traffic direction (`Inbound` or `Outbound`).",
			},
			"action": schema.StringAttribute{
				Computed:    true,
				Description: "Action taken on matching traffic (`Allow`, `Block`, `NotConfigured`).",
			},
			"profile": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Network profiles the rule applies to.",
			},
			"edge_traversal_policy": schema.StringAttribute{
				Computed:    true,
				Description: "Edge-traversal behaviour.",
			},
			"group": schema.StringAttribute{
				Computed:    true,
				Description: "Rule group (RuleGroup).",
			},
			"protocol": schema.StringAttribute{
				Computed:    true,
				Description: "IP protocol keyword (`TCP`, `UDP`, `ICMPv4`, `ICMPv6`, `IGMP`, `Any`) or numeric 0-255.",
			},
			"local_port": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Local TCP/UDP port(s).",
			},
			"remote_port": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Remote TCP/UDP port(s).",
			},
			"local_address": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Local IP addresses, CIDR ranges, or address keywords.",
			},
			"remote_address": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Remote IP addresses, CIDR ranges, or address keywords.",
			},
			"program": schema.StringAttribute{
				Computed:    true,
				Description: "Full path to the matched program executable, or `Any`.",
			},
			"service": schema.StringAttribute{
				Computed:    true,
				Description: "Short name of the matched Windows service, or `Any`.",
			},
			"interface_type": schema.StringAttribute{
				Computed:    true,
				Description: "Interface type (`Any`, `Wireless`, `Wired`, `RemoteAccess`).",
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// instantiates a FirewallRuleClient for Read calls.
func (d *windowsFirewallRuleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = c
	d.fw = winclient.NewFirewallRuleClient(c)
}

// Read fetches the firewall rule state from the remote Windows host.
//
// It applies the implicit "PersistentStore" default for `policy_store` when
// unset, mirroring the resource semantics. A missing rule yields an explicit
// error diagnostic (data sources do not silently disappear).
func (d *windowsFirewallRuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsFirewallRuleDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := config.Name.ValueString()
	policyStore := config.PolicyStore.ValueString()
	if policyStore == "" {
		policyStore = "PersistentStore"
	}

	tflog.Debug(ctx, "windows_firewall_rule data source Read start", map[string]interface{}{
		"name":         name,
		"policy_store": policyStore,
	})

	state, err := d.fw.Read(ctx, name, policyStore)
	if err != nil {
		if winclient.IsFirewallRuleError(err, winclient.FirewallRuleErrorNotFound) {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_firewall_rule %q", name),
				fmt.Sprintf("No firewall rule named %q was found in policy store %q on the target host.", name, policyStore),
			)
			return
		}
		addFirewallDataSourceDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_firewall_rule %q failed", name), err)
		return
	}
	if state == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_firewall_rule %q", name),
			fmt.Sprintf("No firewall rule named %q was found in policy store %q on the target host.", name, policyStore),
		)
		return
	}

	model := firewallStateToDataSourceModel(state)

	tflog.Debug(ctx, "windows_firewall_rule data source Read end", map[string]interface{}{
		"name":      model.Name.ValueString(),
		"direction": model.Direction.ValueString(),
		"action":    model.Action.ValueString(),
		"enabled":   model.Enabled.ValueBool(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// firewallStateToDataSourceModel projects a winclient.FirewallRuleState into
// the data source model, reusing listFromStrings from the resource file.
func firewallStateToDataSourceModel(s *winclient.FirewallRuleState) windowsFirewallRuleDataSourceModel {
	return windowsFirewallRuleDataSourceModel{
		ID:                  types.StringValue(s.Name),
		Name:                types.StringValue(s.Name),
		DisplayName:         types.StringValue(s.DisplayName),
		Description:         types.StringValue(s.Description),
		Enabled:             types.BoolValue(s.Enabled),
		Direction:           types.StringValue(s.Direction),
		Action:              types.StringValue(s.Action),
		Profile:             listFromStrings(s.Profile),
		EdgeTraversalPolicy: types.StringValue(s.EdgeTraversalPolicy),
		Group:               types.StringValue(s.Group),
		PolicyStore:         types.StringValue(s.PolicyStore),
		Protocol:            types.StringValue(s.Protocol),
		LocalPort:           listFromStrings(s.LocalPort),
		RemotePort:          listFromStrings(s.RemotePort),
		LocalAddress:        listFromStrings(s.LocalAddress),
		RemoteAddress:       listFromStrings(s.RemoteAddress),
		Program:             types.StringValue(s.Program),
		Service:             types.StringValue(s.Service),
		InterfaceType:       types.StringValue(s.InterfaceType),
	}
}

// addFirewallDataSourceDiag enriches a data source diagnostic with kind /
// context / cause when the underlying error is a *winclient.FirewallRuleError,
// and falls back to err.Error() otherwise. Mirrors addFirewallDiag (resource).
func addFirewallDataSourceDiag(diags *diag.Diagnostics, summary string, err error) {
	var fe *winclient.FirewallRuleError
	if errors.As(err, &fe) {
		detail := fmt.Sprintf("[%s] %s", fe.Kind, fe.Message)
		if fe.Cause != nil {
			detail += "\n\nCause: " + fe.Cause.Error()
		}
		if len(fe.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range fe.Context {
				detail += fmt.Sprintf(" %s=%s", k, v)
			}
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
