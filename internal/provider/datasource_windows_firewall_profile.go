// Package provider: windows_firewall_profile data source implementation.
//
// Reads the observed state of an existing firewall profile (Domain, Private
// or Public) without managing it. Every sibling-resource setting is exposed
// read-only instead, including the GPO-managed NotConfigured tri-states
// (surfaced as null) and the read-only timeouts{read} block.
package provider

import (
	"context"
	"errors"
	"fmt"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsFirewallProfileDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsFirewallProfileDataSource)(nil)
)

// NewWindowsFirewallProfileDataSource is the constructor registered in provider.go.
func NewWindowsFirewallProfileDataSource() datasource.DataSource {
	return &windowsFirewallProfileDataSource{}
}

// windowsFirewallProfileDataSource is the TPF data source type for windows_firewall_profile.
type windowsFirewallProfileDataSource struct {
	fp winclient.WindowsFirewallProfileClient
}

// firewallProfileDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (firewallProfileDefaultTimeout) so a stalled session surfaces a
// timeout diagnostic instead of blocking plan forever.
const firewallProfileDSDefaultTimeout = firewallProfileDefaultTimeout

// windowsFirewallProfileDataSourceModel is the Terraform state model for the
// windows_firewall_profile data source.
type windowsFirewallProfileDataSourceModel struct {
	ID                              types.String     `tfsdk:"id"`
	Name                            types.String     `tfsdk:"name"`
	Enabled                         types.Bool       `tfsdk:"enabled"`
	DefaultInboundAction            types.String     `tfsdk:"default_inbound_action"`
	DefaultOutboundAction           types.String     `tfsdk:"default_outbound_action"`
	AllowInboundRules               types.Bool       `tfsdk:"allow_inbound_rules"`
	AllowLocalFirewallRules         types.Bool       `tfsdk:"allow_local_firewall_rules"`
	AllowLocalIPsecRules            types.Bool       `tfsdk:"allow_local_ipsec_rules"`
	AllowUnicastResponseToMulticast types.Bool       `tfsdk:"allow_unicast_response_to_multicast"`
	NotifyOnListen                  types.Bool       `tfsdk:"notify_on_listen"`
	LogFileName                     types.String     `tfsdk:"log_file_name"`
	LogMaxSizeKilobytes             types.Int64      `tfsdk:"log_max_size_kilobytes"`
	LogAllowed                      types.Bool       `tfsdk:"log_allowed"`
	LogBlocked                      types.Bool       `tfsdk:"log_blocked"`
	LogIgnored                      types.Bool       `tfsdk:"log_ignored"`
	DisabledInterfaceAliases        types.Set        `tfsdk:"disabled_interface_aliases"`
	Timeouts                        dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_firewall_profile").
func (d *windowsFirewallProfileDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_profile"
}

// Schema returns the TPF schema for the windows_firewall_profile data source.
func (d *windowsFirewallProfileDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a Windows Defender Firewall profile (`Domain`, " +
			"`Private` or `Public`) on a remote Windows host without managing it.\n\n" +
			"Group Policy owns the `ActiveStore` view: when a GPO manages a profile, the observed values can " +
			"diverge from what the sibling resource writes (`PersistentStore`), and GPO-managed `NotConfigured` " +
			"tri-states are reported as unset (`null`) rather than exposed as values.\n\n" +
			"Returns an error when the profile does not exist on the target host (profiles always exist, so " +
			"this indicates a broken firewall stack).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the profile name (`Domain`, `Private` or `Public`).",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Firewall profile name on the target host. One of `Domain`, `Private`, `Public`.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the firewall is active for this profile, as observed on the host.",
			},
			"default_inbound_action": schema.StringAttribute{
				Computed:    true,
				Description: "Default inbound action, as observed on the host (`Allow`, `Block`, or `NotConfigured` when GPO-managed).",
			},
			"default_outbound_action": schema.StringAttribute{
				Computed:    true,
				Description: "Default outbound action, as observed on the host.",
			},
			"allow_inbound_rules": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether inbound rules are honoured, as observed on the host (null when GPO-managed `NotConfigured`).",
			},
			"allow_local_firewall_rules": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether locally created firewall rules are honoured, as observed on the host.",
			},
			"allow_local_ipsec_rules": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether locally created IPsec rules are honoured, as observed on the host.",
			},
			"allow_unicast_response_to_multicast": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether unicast responses to multicast traffic are allowed, as observed on the host.",
			},
			"notify_on_listen": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the user is notified when an application starts listening, as observed on the host.",
			},
			"log_file_name": schema.StringAttribute{
				Computed:    true,
				Description: "Path of the firewall log file, as observed on the host.",
			},
			"log_max_size_kilobytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Maximum size of the firewall log file in kilobytes, as observed on the host.",
			},
			"log_allowed": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether allowed connections are logged, as observed on the host.",
			},
			"log_blocked": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether blocked connections are logged, as observed on the host.",
			},
			"log_ignored": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether ignored packets are logged, as observed on the host.",
			},
			"disabled_interface_aliases": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Interfaces excluded from this profile, as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to firewallProfileDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsFirewallProfileDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.fp = winclient.NewFirewallProfileClient(c)
}

// Read fetches the observed profile state from the remote Windows host by
// calling the sibling resource's FirewallProfileClient.Read with the
// configured name. A nil result triggers a `not found` diagnostic (data
// sources never silently clear state). Other typed
// *winclient.FirewallProfileError values surface via addFirewallProfileDiag,
// mirroring the resource Read path.
func (d *windowsFirewallProfileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsFirewallProfileDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, firewallProfileDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Name.ValueString()
	tflog.Debug(ctx, "windows_firewall_profile data source Read start", map[string]interface{}{"name": target})

	if err := winclient.ValidateFirewallProfileName(target); err != nil {
		addFirewallProfileDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_firewall_profile %q failed", target), err)
		return
	}

	observed, err := d.fp.Read(ctx, target)
	if err != nil {
		var fe *winclient.FirewallProfileError
		if errors.As(err, &fe) && fe.Kind == winclient.FirewallProfileErrorInvalidProfile {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_firewall_profile %q", target),
				fmt.Sprintf("No firewall profile %q was found on the target host.", target),
			)
			return
		}
		addFirewallProfileDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_firewall_profile %q failed", target), err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_firewall_profile %q", target),
			fmt.Sprintf("No firewall profile %q was found on the target host.", target),
		)
		return
	}

	aliases, dgs := types.SetValueFrom(ctx, types.StringType, nonNilStrings(observed.DisabledInterfaceAliases))
	resp.Diagnostics.Append(dgs...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsFirewallProfileDataSourceModel{
		ID:                              types.StringValue(observed.Name),
		Name:                            types.StringValue(observed.Name),
		Enabled:                         types.BoolValue(observed.Enabled),
		DefaultInboundAction:            types.StringValue(observed.DefaultInboundAction),
		DefaultOutboundAction:           types.StringValue(observed.DefaultOutboundAction),
		AllowInboundRules:               triToBool(observed.AllowInboundRules),
		AllowLocalFirewallRules:         triToBool(observed.AllowLocalFirewallRules),
		AllowLocalIPsecRules:            triToBool(observed.AllowLocalIPsecRules),
		AllowUnicastResponseToMulticast: triToBool(observed.AllowUnicastResponseToMulticast),
		NotifyOnListen:                  types.BoolValue(observed.NotifyOnListen),
		LogFileName:                     types.StringValue(observed.LogFileName),
		LogMaxSizeKilobytes:             types.Int64Value(observed.LogMaxSizeKilobytes),
		LogAllowed:                      triToBool(observed.LogAllowed),
		LogBlocked:                      triToBool(observed.LogBlocked),
		LogIgnored:                      triToBool(observed.LogIgnored),
		DisabledInterfaceAliases:        aliases,
		Timeouts:                        config.Timeouts,
	}

	tflog.Debug(ctx, "windows_firewall_profile data source Read end", map[string]interface{}{
		"name":    state.Name.ValueString(),
		"enabled": state.Enabled.ValueBool(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// nonNilStrings normalises a nil slice to an empty one so SetValueFrom
// renders an empty set instead of a null one in data source state.
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
