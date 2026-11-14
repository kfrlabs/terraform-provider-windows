// Package provider - resource_windows_dns_client implements the full
// Terraform resource lifecycle for windows_dns_client.
//
// One resource manages the DNS client settings of one network interface
// (Set-DnsClientServerAddress / Set-DnsClient via SSH and PowerShell).
// Creating a second resource for the same interface races the first: the
// last writer wins for the managed families.
//
// Partial management: a null ipv4_server_addresses / ipv6_server_addresses
// means the family is unmanaged (left untouched, including DHCP-provided
// servers); an empty list resets the family to automatic (DHCP); a
// non-empty list replaces the static servers in order. The same applies to
// connection_specific_suffix and the registration flags: null leaves the
// host value untouched.
//
// Static servers are read from the Tcpip/Tcpip6 registry
// (Interfaces\{guid}\NameServer); the effective_* attributes include
// DHCP-provided servers and come from Get-DnsClientServerAddress.
//
// Spec alignment: windows_dns_client spec (issue #229).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
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
	_ resource.Resource                     = (*windowsDNSClientResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsDNSClientResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsDNSClientResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsDNSClientResource)(nil)
)

// NewWindowsDNSClientResource is the constructor registered in provider.go.
func NewWindowsDNSClientResource() resource.Resource {
	return &windowsDNSClientResource{}
}

// windowsDNSClientResource is the TPF resource type for windows_dns_client.
type windowsDNSClientResource struct {
	dns winclient.DnsClientClient
}

// dnsClientDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. DNS operations are normally
// fast, but a stalled PowerShell/SSH session must never block Terraform
// forever.
const dnsClientDefaultTimeout = 10 * time.Minute

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsDNSClientModel is the Terraform state/plan model for
// windows_dns_client. Every tfsdk tag matches an attribute key in
// windowsDNSClientSchemaDefinition.
type windowsDNSClientModel struct {
	ID                            types.String   `tfsdk:"id"`
	InterfaceAlias                types.String   `tfsdk:"interface_alias"`
	IPv4ServerAddresses           types.List     `tfsdk:"ipv4_server_addresses"`
	IPv6ServerAddresses           types.List     `tfsdk:"ipv6_server_addresses"`
	ConnectionSpecificSuffix      types.String   `tfsdk:"connection_specific_suffix"`
	RegisterThisConnectionAddress types.Bool     `tfsdk:"register_this_connection_address"`
	UseSuffixWhenRegistering      types.Bool     `tfsdk:"use_suffix_when_registering"`
	ResetOnDestroy                types.Bool     `tfsdk:"reset_on_destroy"`
	InterfaceIndex                types.Int64    `tfsdk:"interface_index"`
	InterfaceGUID                 types.String   `tfsdk:"interface_guid"`
	EffectiveIPv4                 types.List     `tfsdk:"effective_ipv4"`
	EffectiveIPv6                 types.List     `tfsdk:"effective_ipv6"`
	Timeouts                      timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsDNSClientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns_client"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_dns_client resource.
func (r *windowsDNSClientResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsDNSClientSchemaDefinition(ctx)
}

// windowsDNSClientSchemaDefinition returns the complete TPF schema for
// windows_dns_client. interface_alias is Required + ForceNew (the id);
// every other setting is Optional+Computed (partial management: only
// configured attributes are sent to the host).
func windowsDNSClientSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the DNS client settings of one network interface on a remote " +
			"Windows host (`Set-DnsClientServerAddress` / `Set-DnsClient` via SSH and PowerShell). " +
			"One resource owns one interface: creating a second resource for the same interface races " +
			"the first (last writer wins for the managed families).\n\n" +
			"Managed versus unmanaged (`null` versus `[]`): every setting except `interface_alias` is " +
			"`Optional` + `Computed` (partial management). `null` (omitted) leaves the host value " +
			"untouched and undiffed; an explicitly empty list resets the family to automatic (DHCP). " +
			"For example, omitting `ipv4_server_addresses` keeps whatever the host has (static or DHCP), " +
			"while `ipv4_server_addresses = []` removes every static IPv4 server so the interface uses " +
			"DHCP-provided servers only.\n\n" +
			"| Value | Meaning |\n" +
			"|---|---|\n" +
			"| `null` (omitted) | Unmanaged: the host value is left untouched. |\n" +
			"| `[]` (empty) | Reset to automatic: static servers are removed, DHCP provides servers. " +
			"Only meaningful on a configured (non-`null`) list. |\n" +
			"| `[\"a\", \"b\"]` | Static: the listed servers replace the family in order. |\n\n" +
			"Static versus effective: `ipv4_server_addresses` / `ipv6_server_addresses` track the " +
			"statically configured servers (registry `Tcpip`/`Tcpip6` `Interfaces\\{guid}\\NameServer`). " +
			"`effective_ipv4` / `effective_ipv6` are read-only and DHCP-inclusive: they report the live " +
			"servers from `Get-DnsClientServerAddress` (static plus DHCP-provided). When a family is " +
			"automatic, the managed list is `[]` while the effective list shows the DHCP-provided servers.\n\n" +
			"Manage only secondary NICs with this resource: changing DNS on the management NIC can break " +
			"name resolution for the host itself.\n\n" +
			"Import format: `<interface_alias>`. Import adopts the live state: both families become " +
			"managed (automatic families import as `[]`).",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier: the canonical (trimmed) interface alias.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"interface_alias": schema.StringAttribute{
				Required: true,
				Description: "Network interface alias (e.g. `\"Ethernet 2\"`). Matched exactly and " +
					"case-insensitively, never as a wildcard. Immutable after creation (ForceNew). " +
					"The configured spelling is preserved in state; the id carries the trimmed form.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					dnsClientAliasValidator{},
				},
			},

			"ipv4_server_addresses": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Static IPv4 DNS servers in query order (first answer wins). `null` leaves " +
					"the family unmanaged; `[]` resets it to automatic (DHCP); a list replaces the " +
					"static servers. Loopback addresses are allowed; unspecified, multicast, limited " +
					"broadcast (`255.255.255.255`) and zone-ID addresses are rejected, as are duplicates " +
					"and IPv6 addresses.",
				Validators: []validator.List{
					dnsClientServerAddressesValidator{wantV6: false},
				},
				PlanModifiers: []planmodifier.List{
					dnsClientServerAddressesNormalizeModifier{wantV6: false},
				},
			},

			"ipv6_server_addresses": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Static IPv6 DNS servers in query order (first answer wins). `null` leaves " +
					"the family unmanaged; `[]` resets it to automatic (DHCP); a list replaces the " +
					"static servers. Addresses are stored canonically (lower-case, compressed) with the " +
					"configured order preserved. Loopback addresses are allowed; unspecified, multicast " +
					"and zone-ID addresses are rejected, as are duplicates and IPv4 addresses.",
				Validators: []validator.List{
					dnsClientServerAddressesValidator{wantV6: true},
				},
				PlanModifiers: []planmodifier.List{
					dnsClientServerAddressesNormalizeModifier{wantV6: true},
				},
			},

			"connection_specific_suffix": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Connection-specific DNS suffix (e.g. `\"corp.example.com\"`). `null` leaves " +
					"the suffix unmanaged. The suffix cannot be cleared in place: an empty string is " +
					"rejected, and `null` leaves the host value untouched. To clear a managed suffix, " +
					"destroy with `reset_on_destroy = true`. Must follow DNS name rules (labels of 1-63 " +
					"letters, digits and hyphens, starting and ending with a letter or digit; total length " +
					"at most 253).",
				Validators: []validator.String{
					dnsClientSuffixValidator{},
				},
			},

			"register_this_connection_address": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Whether to register this connection's address in DNS (`Set-DnsClient " +
					"-RegisterThisConnectionsAddress`). `null` leaves the flag unmanaged.",
			},

			"use_suffix_when_registering": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Whether to use the connection-specific suffix when registering in DNS " +
					"(`Set-DnsClient -UseSuffixWhenRegistering`). `null` leaves the flag unmanaged.",
			},

			"reset_on_destroy": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "When `true`, destroy resets every managed family to automatic (DHCP) and " +
					"clears the connection-specific suffix when it was managed. Defaults to `false`: " +
					"destroy makes no remote change.",
			},

			"interface_index": schema.Int64Attribute{
				Computed:    true,
				Description: "Numeric interface index, as observed on the host.",
			},

			"interface_guid": schema.StringAttribute{
				Computed:    true,
				Description: "Interface GUID (braces included), as observed on the host.",
			},

			"effective_ipv4": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Live IPv4 DNS servers, as observed on the host (static plus DHCP-provided).",
			},

			"effective_ipv6": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Live IPv6 DNS servers, as observed on the host (static plus DHCP-provided).",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// dnsClientDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, dnsClientTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// dnsClientAliasValidator rejects blank interface aliases.
type dnsClientAliasValidator struct{}

func (v dnsClientAliasValidator) Description(_ context.Context) string {
	return "Interface alias must not be blank."
}

func (v dnsClientAliasValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v dnsClientAliasValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.TrimSpace(req.ConfigValue.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid interface alias",
			"interface_alias must not be blank.",
		)
	}
}

// dnsClientServerAddressesValidator validates one family's server list at
// plan time: every element must parse via netip, belong to the family, carry
// no zone ID, and avoid unspecified/multicast/broadcast values; loopback is
// allowed. Duplicates are rejected after canonicalisation.
type dnsClientServerAddressesValidator struct {
	wantV6 bool
}

func (v dnsClientServerAddressesValidator) Description(_ context.Context) string {
	if v.wantV6 {
		return "IPv6 DNS server addresses must be valid, unique unicast addresses without a zone ID."
	}
	return "IPv4 DNS server addresses must be valid, unique unicast addresses without a zone ID."
}

func (v dnsClientServerAddressesValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v dnsClientServerAddressesValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var raw []string
	resp.Diagnostics.Append(req.ConfigValue.ElementsAs(ctx, &raw, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := winclient.ValidateDnsClientServerAddresses(raw, v.wantV6); err != nil {
		var de *winclient.DnsClientError
		if errors.As(err, &de) {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid DNS server address", de.Message)
			return
		}
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid DNS server address", err.Error())
	}
}

// dnsClientServerAddressesNormalizeModifier canonicalises each planned
// server address at plan time (trimmed, IPv4-mapped addresses unmapped,
// lower-case compressed form) so a cosmetic spelling such as "2001:DB8::53"
// plans as the canonical "2001:db8::53" the state carries, instead of
// showing a perpetual diff. Invalid input is left untouched for the
// attribute validator to report.
type dnsClientServerAddressesNormalizeModifier struct {
	wantV6 bool
}

func (m dnsClientServerAddressesNormalizeModifier) Description(_ context.Context) string {
	return "Normalises DNS server addresses to their canonical form."
}

func (m dnsClientServerAddressesNormalizeModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m dnsClientServerAddressesNormalizeModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	var raw []string
	resp.Diagnostics.Append(req.PlanValue.ElementsAs(ctx, &raw, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	canonical, err := winclient.ValidateDnsClientServerAddresses(raw, m.wantV6)
	if err != nil {
		return // the attribute validator reports invalid input
	}
	v, d := types.ListValueFrom(ctx, types.StringType, canonical)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.PlanValue = v
}

// dnsClientSuffixValidator validates the connection-specific suffix at plan
// time against DNS name rules.
type dnsClientSuffixValidator struct{}

func (v dnsClientSuffixValidator) Description(_ context.Context) string {
	return "Connection-specific suffix must be a valid DNS name."
}

func (v dnsClientSuffixValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v dnsClientSuffixValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := winclient.ValidateDnsClientSuffix(req.ConfigValue.ValueString()); err != nil {
		var de *winclient.DnsClientError
		if errors.As(err, &de) {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid connection-specific suffix", de.Message)
			return
		}
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid connection-specific suffix", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates a
// DnsClientClient for this resource instance.
func (r *windowsDNSClientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.dns = winclient.NewDnsClientClient(client)
}

// ---------------------------------------------------------------------------
// Helpers: canonicalisation, settings, state projection
// ---------------------------------------------------------------------------

// canonicalDNSClientAlias trims the alias; the trimmed form is the resource
// ID while interface_alias keeps the configured spelling.
func canonicalDNSClientAlias(alias string) string {
	return strings.TrimSpace(alias)
}

// dnsClientListToStrings reads an Optional+Computed list attribute: null
// means unmanaged, otherwise the element values in order.
func dnsClientListToStrings(ctx context.Context, list types.List) ([]string, bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	if list.IsNull() || list.IsUnknown() {
		return nil, false, diags
	}
	var out []string
	diags.Append(list.ElementsAs(ctx, &out, false)...)
	if diags.HasError() {
		return nil, false, diags
	}
	if out == nil {
		out = []string{}
	}
	return out, true, diags
}

// dnsClientStringsToList projects observed addresses into state. A nil input
// renders as a null list (unmanaged); any non-nil input — including empty —
// renders as a (possibly empty) list value.
func dnsClientStringsToList(ctx context.Context, in []string) (types.List, diag.Diagnostics) {
	if in == nil {
		return types.ListNull(types.StringType), nil
	}
	return types.ListValueFrom(ctx, types.StringType, in)
}

// dnsClientMustList is the infallible variant for computed effective lists
// (strings are already validated); it falls back to an empty list when the
// conversion unexpectedly fails.
func dnsClientMustList(in []string) types.List {
	if in == nil {
		in = []string{}
	}
	v, diags := types.ListValueFrom(context.Background(), types.StringType, in)
	if diags.HasError() {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}
	return v
}

// modelToDnsClientSettings projects the plan's managed attributes onto
// winclient settings. Null attributes stay unmanaged.
func modelToDnsClientSettings(ctx context.Context, plan windowsDNSClientModel) (winclient.DnsClientSettings, diag.Diagnostics) {
	var diags diag.Diagnostics
	var s winclient.DnsClientSettings
	if v4, ok, d := dnsClientListToStrings(ctx, plan.IPv4ServerAddresses); d.HasError() {
		diags.Append(d...)
	} else if ok {
		s.IPv4Set = true
		s.IPv4Addresses = v4
	}
	if v6, ok, d := dnsClientListToStrings(ctx, plan.IPv6ServerAddresses); d.HasError() {
		diags.Append(d...)
	} else if ok {
		s.IPv6Set = true
		s.IPv6Addresses = v6
	}
	if diags.HasError() {
		return winclient.DnsClientSettings{}, diags
	}
	if !plan.ConnectionSpecificSuffix.IsNull() && !plan.ConnectionSpecificSuffix.IsUnknown() {
		s.SuffixSet = true
		v := plan.ConnectionSpecificSuffix.ValueString()
		s.ConnectionSpecificSuffix = &v
	}
	if !plan.RegisterThisConnectionAddress.IsNull() && !plan.RegisterThisConnectionAddress.IsUnknown() {
		v := plan.RegisterThisConnectionAddress.ValueBool()
		s.RegisterThisConnectionAddress = &v
	}
	if !plan.UseSuffixWhenRegistering.IsNull() && !plan.UseSuffixWhenRegistering.IsUnknown() {
		v := plan.UseSuffixWhenRegistering.ValueBool()
		s.UseSuffixWhenRegistering = &v
	}
	return s, diags
}

// dnsClientSettingsForUpdate projects the plan onto settings but drops every
// attribute that is already at its prior-state value, so Update emits only
// configured changes. Unmanaged (null) plan attributes stay unmanaged.
func dnsClientSettingsForUpdate(ctx context.Context, plan, prior windowsDNSClientModel) (winclient.DnsClientSettings, diag.Diagnostics) {
	s, diags := modelToDnsClientSettings(ctx, plan)
	if diags.HasError() {
		return winclient.DnsClientSettings{}, diags
	}
	if s.IPv4Set && plan.IPv4ServerAddresses.Equal(prior.IPv4ServerAddresses) {
		s.IPv4Set = false
		s.IPv4Addresses = nil
	}
	if s.IPv6Set && plan.IPv6ServerAddresses.Equal(prior.IPv6ServerAddresses) {
		s.IPv6Set = false
		s.IPv6Addresses = nil
	}
	if s.SuffixSet && plan.ConnectionSpecificSuffix.Equal(prior.ConnectionSpecificSuffix) {
		s.SuffixSet = false
		s.ConnectionSpecificSuffix = nil
	}
	if s.RegisterThisConnectionAddress != nil && plan.RegisterThisConnectionAddress.Equal(prior.RegisterThisConnectionAddress) {
		s.RegisterThisConnectionAddress = nil
	}
	if s.UseSuffixWhenRegistering != nil && plan.UseSuffixWhenRegistering.Equal(prior.UseSuffixWhenRegistering) {
		s.UseSuffixWhenRegistering = nil
	}
	return s, diags
}

// dnsClientStateToModel projects an observed DnsClientState into a Terraform
// model. Managed attributes (non-null in plan) take the observed static
// values; unmanaged attributes stay null. Effective lists, index and GUID
// always reflect the host. The configured alias spelling, timeouts and
// reset_on_destroy are preserved from the plan.
func dnsClientStateToModel(ctx context.Context, plan windowsDNSClientModel, observed *winclient.DnsClientState) (windowsDNSClientModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := windowsDNSClientModel{
		ID:                            types.StringValue(canonicalDNSClientAlias(plan.InterfaceAlias.ValueString())),
		InterfaceAlias:                plan.InterfaceAlias,
		ResetOnDestroy:                plan.ResetOnDestroy,
		Timeouts:                      plan.Timeouts,
		InterfaceIndex:                types.Int64Value(int64(observed.InterfaceIndex)),
		InterfaceGUID:                 types.StringValue(observed.InterfaceGUID),
		EffectiveIPv4:                 dnsClientMustList(observed.EffectiveIPv4),
		EffectiveIPv6:                 dnsClientMustList(observed.EffectiveIPv6),
		IPv4ServerAddresses:           types.ListNull(types.StringType),
		IPv6ServerAddresses:           types.ListNull(types.StringType),
		ConnectionSpecificSuffix:      types.StringNull(),
		RegisterThisConnectionAddress: types.BoolNull(),
		UseSuffixWhenRegistering:      types.BoolNull(),
	}
	if !plan.IPv4ServerAddresses.IsNull() {
		v, d := dnsClientStringsToList(ctx, observed.StaticIPv4)
		diags.Append(d...)
		m.IPv4ServerAddresses = v
	}
	if !plan.IPv6ServerAddresses.IsNull() {
		v, d := dnsClientStringsToList(ctx, observed.StaticIPv6)
		diags.Append(d...)
		m.IPv6ServerAddresses = v
	}
	if !plan.ConnectionSpecificSuffix.IsNull() {
		m.ConnectionSpecificSuffix = types.StringValue(observed.ConnectionSpecificSuffix)
	}
	if !plan.RegisterThisConnectionAddress.IsNull() {
		m.RegisterThisConnectionAddress = types.BoolValue(observed.RegisterThisConnectionAddress)
	}
	if !plan.UseSuffixWhenRegistering.IsNull() {
		m.UseSuffixWhenRegistering = types.BoolValue(observed.UseSuffixWhenRegistering)
	}
	return m, diags
}

// dnsClientTimeoutsOpts declares which per-operation timeouts the resource exposes.
var dnsClientTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// dnsClientNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func dnsClientNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if dnsClientTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if dnsClientTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if dnsClientTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if dnsClientTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create applies the planned DNS client settings (idempotent with Update)
// and stores the resulting state. When nothing is managed the call is a
// read-only adoption of the live state.
func (r *windowsDNSClientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsDNSClientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, dnsClientDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	settings, diags := modelToDnsClientSettings(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	alias := canonicalDNSClientAlias(plan.InterfaceAlias.ValueString())

	tflog.Debug(ctx, "Creating Windows DNS client settings", map[string]any{
		"interface_alias": alias,
	})

	var observed *winclient.DnsClientState
	var err error
	if settings.DnsClientConfigured() {
		observed, err = r.dns.Apply(ctx, alias, settings)
	} else {
		observed, err = r.dns.Read(ctx, alias)
	}
	if err != nil {
		addDNSClientDiag(&resp.Diagnostics, "Error creating Windows DNS client settings", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"DNS client interface not found",
			fmt.Sprintf("No interface matching alias %q was found on the target host.", alias),
		)
		return
	}

	m, diags := dnsClientStateToModel(ctx, plan, observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live DNS client settings. A
// renamed-away or removed interface drops the resource from state. Managed
// attributes refresh to the observed static values; unmanaged attributes
// stay null.
func (r *windowsDNSClientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsDNSClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, dnsClientDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	alias := state.ID.ValueString()
	if alias == "" {
		alias = canonicalDNSClientAlias(state.InterfaceAlias.ValueString())
	}

	tflog.Debug(ctx, "Reading Windows DNS client settings", map[string]any{
		"interface_alias": alias,
	})

	observed, err := r.dns.Read(ctx, alias)
	if err != nil {
		addDNSClientDiag(&resp.Diagnostics, "Error reading Windows DNS client settings", err)
		return
	}
	if observed == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	plan := state
	plan.InterfaceAlias = types.StringValue(alias)
	if state.InterfaceAlias.ValueString() != "" {
		plan.InterfaceAlias = state.InterfaceAlias
	}
	m, diags := dnsClientStateToModel(ctx, plan, observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies only the configured changes (attributes already at their
// prior-state value are not re-sent) and refreshes the state. interface_alias
// is ForceNew so it never changes here.
func (r *windowsDNSClientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsDNSClientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsDNSClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, dnsClientDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	settings, diags := dnsClientSettingsForUpdate(ctx, plan, prior)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// interface_alias is ForceNew so the plan spelling matches the prior ID.
	alias := prior.ID.ValueString()
	if alias == "" {
		alias = canonicalDNSClientAlias(plan.InterfaceAlias.ValueString())
	}

	tflog.Debug(ctx, "Updating Windows DNS client settings", map[string]any{
		"interface_alias": alias,
	})

	var observed *winclient.DnsClientState
	var err error
	if settings.DnsClientConfigured() {
		observed, err = r.dns.Apply(ctx, alias, settings)
	} else {
		observed, err = r.dns.Read(ctx, alias)
	}
	if err != nil {
		addDNSClientDiag(&resp.Diagnostics, "Error updating Windows DNS client settings", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"DNS client interface not found",
			fmt.Sprintf("No interface matching alias %q was found on the target host.", alias),
		)
		return
	}

	plan.InterfaceAlias = prior.InterfaceAlias
	m, diags := dnsClientStateToModel(ctx, plan, observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.ID = prior.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the resource from state. With reset_on_destroy it first
// resets every managed family to automatic (DHCP) and clears the
// connection-specific suffix when it was managed; otherwise it makes no
// remote change.
func (r *windowsDNSClientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsDNSClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, dnsClientDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	alias := state.ID.ValueString()
	if alias == "" {
		alias = canonicalDNSClientAlias(state.InterfaceAlias.ValueString())
	}

	tflog.Debug(ctx, "Deleting Windows DNS client settings", map[string]any{
		"interface_alias": alias,
	})

	if !state.ResetOnDestroy.ValueBool() {
		return
	}

	observed, err := r.dns.Reset(ctx, alias,
		!state.IPv4ServerAddresses.IsNull(),
		!state.IPv6ServerAddresses.IsNull(),
		!state.ConnectionSpecificSuffix.IsNull())
	if err != nil {
		addDNSClientDiag(&resp.Diagnostics, "Error resetting Windows DNS client settings", err)
		return
	}
	_ = observed
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts the DNS client settings of an existing interface by
// alias. Both families become managed: automatic families import as empty
// lists. The suffix imports as managed when set, and the registration flags
// import with their observed values.
func (r *windowsDNSClientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	alias := canonicalDNSClientAlias(strings.TrimSpace(req.ID))
	if alias == "" {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must be the interface alias (e.g. \"Ethernet 2\"); got %q.", req.ID))
		return
	}

	tflog.Debug(ctx, "Importing Windows DNS client settings", map[string]any{
		"interface_alias": alias,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, dnsClientDefaultTimeout)
	defer cancel()

	observed, err := r.dns.Read(ctx, alias)
	if err != nil {
		addDNSClientDiag(&resp.Diagnostics, "Error importing Windows DNS client settings", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"DNS client interface not found",
			fmt.Sprintf("No interface matching alias %q was found on the target host.", alias),
		)
		return
	}

	plan := windowsDNSClientModel{
		InterfaceAlias:                types.StringValue(alias),
		ResetOnDestroy:                types.BoolValue(false),
		Timeouts:                      dnsClientNullTimeouts(),
		RegisterThisConnectionAddress: types.BoolValue(observed.RegisterThisConnectionAddress),
		UseSuffixWhenRegistering:      types.BoolValue(observed.UseSuffixWhenRegistering),
	}
	m, diags := dnsClientStateToModel(ctx, plan, observed)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import manages both families unconditionally: an automatic family
	// imports as an empty (non-null) list. The suffix imports as managed
	// when set on the host, and unmanaged (null) when unset.
	m.IPv4ServerAddresses = dnsClientMustList(observed.StaticIPv4)
	m.IPv6ServerAddresses = dnsClientMustList(observed.StaticIPv6)
	if observed.ConnectionSpecificSuffix == "" {
		m.ConnectionSpecificSuffix = types.StringNull()
	} else {
		m.ConnectionSpecificSuffix = types.StringValue(observed.ConnectionSpecificSuffix)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// dnsClientNoValidator is a placeholder ConfigValidator list entry point:
// the resource needs no cross-field validation beyond the attribute
// validators because each family validates independently (mixed families
// never interact: IPv4 lists reject IPv6 addresses and vice versa).
func (r *windowsDNSClientResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return nil
}

// ---------------------------------------------------------------------------
// Helper: addDNSClientDiag
// ---------------------------------------------------------------------------

// addDNSClientDiag appends a diagnostic from a dns-client error. Typed
// errors are enriched with context fields when available.
func addDNSClientDiag(d *diag.Diagnostics, summary string, err error) {
	var de *winclient.DnsClientError
	if errors.As(err, &de) {
		detail := de.Message
		if len(de.Context) > 0 {
			var parts []string
			for k, v := range de.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if de.Cause != nil {
			detail += "\n\nCause: " + de.Cause.Error()
		}
		d.AddError(summary+" ["+de.Kind+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
