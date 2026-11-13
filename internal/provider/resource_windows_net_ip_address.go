// Package provider - resource_windows_net_ip_address implements the full
// Terraform resource lifecycle for windows_net_ip_address.
//
// One static IP address on one network interface (New-NetIPAddress /
// Set-NetIPAddress / Remove-NetIPAddress). Several resources may target the
// same interface, one per address. The default gateway is deliberately not
// managed here (see windows_net_route).
//
// Safety: every mutating operation consults the shared management-path
// guard (winclient.Client.ManagementPath, computed per operation, never
// cached): touching the management address is refused fail-closed with
// management_path_at_risk, and an undeterminable path fails closed with
// management_path_unknown. Both are bypassable only through
// unsafe_skip_management_check.
//
// Spec alignment: windows_net_ip_address spec v1 (issue #230).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
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
	_ resource.Resource                     = (*windowsNetIPAddressResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsNetIPAddressResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsNetIPAddressResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsNetIPAddressResource)(nil)
)

// NewWindowsNetIPAddressResource is the constructor registered in provider.go.
func NewWindowsNetIPAddressResource() resource.Resource {
	return &windowsNetIPAddressResource{}
}

// windowsNetIPAddressResource is the TPF resource type for windows_net_ip_address.
type windowsNetIPAddressResource struct {
	ip winclient.NetIPAddressClient
}

// netIPAddressDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Address operations are
// normally fast (plus a ~10 s duplicate-detection poll on create), but a
// stalled PowerShell/SSH session must never block Terraform forever.
const netIPAddressDefaultTimeout = 10 * time.Minute

// netIPAddressPrivateKeyDHCP is the private-state key recording whether
// this resource disabled DHCP (so destroy with restore_dhcp_on_destroy can
// re-enable it).
const netIPAddressPrivateKeyDHCP = "dhcp_disabled_by_us"

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsNetIPAddressModel is the Terraform state/plan model for
// windows_net_ip_address. Every tfsdk tag matches an attribute key in
// windowsNetIPAddressSchemaDefinition.
type windowsNetIPAddressModel struct {
	ID                        types.String   `tfsdk:"id"`
	InterfaceAlias            types.String   `tfsdk:"interface_alias"`
	IPAddress                 types.String   `tfsdk:"ip_address"`
	PrefixLength              types.Int64    `tfsdk:"prefix_length"`
	SkipAsSource              types.Bool     `tfsdk:"skip_as_source"`
	DisableDHCP               types.Bool     `tfsdk:"disable_dhcp"`
	RestoreDHCPOnDestroy      types.Bool     `tfsdk:"restore_dhcp_on_destroy"`
	UnsafeSkipManagementCheck types.Bool     `tfsdk:"unsafe_skip_management_check"`
	InterfaceIndex            types.Int64    `tfsdk:"interface_index"`
	AddressFamily             types.String   `tfsdk:"address_family"`
	AddressState              types.String   `tfsdk:"address_state"`
	PrefixOrigin              types.String   `tfsdk:"prefix_origin"`
	Timeouts                  timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsNetIPAddressResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_net_ip_address"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_net_ip_address resource.
func (r *windowsNetIPAddressResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsNetIPAddressSchemaDefinition(ctx)
}

// windowsNetIPAddressSchemaDefinition returns the complete TPF schema for
// windows_net_ip_address.
func windowsNetIPAddressSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages one static IP address on one network interface of a remote Windows host " +
			"(`New-NetIPAddress` / `Set-NetIPAddress` / `Remove-NetIPAddress` via SSH and PowerShell). " +
			"Several resources may target the same interface, one per address.\n\n" +
			"`interface_alias` and `ip_address` are immutable after creation (ForceNew); `prefix_length` and " +
			"`skip_as_source` are updated in place. The address is stored canonically (`netip`: lower-case, " +
			"compressed IPv6). The default gateway is deliberately not managed here: it belongs to " +
			"`windows_net_route`, which would otherwise fight over an address this resource does not own.\n\n" +
			"Safety — managing the management interface: every mutating operation consults a management-path " +
			"guard that refuses, fail-closed, to remove or alter the address the provider's own SSH session " +
			"arrived on (or the route carrying it). When the path cannot be determined the operation is " +
			"refused as well. `unsafe_skip_management_check` bypasses the guard entirely: the change may " +
			"apply and still end in an apply error (transport lost, timeout), and the host must stay " +
			"reachable at the provider `host` address afterwards. " +
			"Configure the management NIC out-of-band (unattend, cloud-init, DHCP reservation) and manage " +
			"only secondary NICs with this resource.\n\n" +
			"Import format: `<interface_alias>|<ip_address>`. Only addresses with prefix origin `Manual` " +
			"are importable.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier: `<interface_alias>|<canonical ip_address>`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"interface_alias": schema.StringAttribute{
				Required: true,
				Description: "Network interface alias (e.g. `\"Ethernet 2\"`). Matched exactly and " +
					"case-insensitively, never as a wildcard. Immutable after creation (ForceNew). " +
					"Must not contain `|` (used as the import-ID separator).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					netIPAddressAliasValidator{},
				},
			},

			"ip_address": schema.StringAttribute{
				Required: true,
				Description: "Static IPv4 or IPv6 address, stored canonically. Unspecified, loopback, " +
					"multicast, IPv4 broadcast and zone-ID (`%eth0`) addresses are rejected; link-local " +
					"addresses warn. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					netIPAddressStringValidator{},
				},
			},

			"prefix_length": schema.Int64Attribute{
				Required: true,
				Description: "Subnet prefix length: 1-32 for IPv4, 1-128 for IPv6 (validated against " +
					"the address family at plan time). Updated in place.",
				Validators: []validator.Int64{
					// Attribute-level range gate (#324): the family refinement
					// (1-32 for IPv4) stays in netIPAddressConfigValidator.
					int64validator.Between(1, 128),
				},
			},

			"skip_as_source": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Excludes the address from outbound source selection. Updated in place. Defaults to `false`.",
			},

			"disable_dhcp": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "IPv4 only: disables DHCP on the interface before creating the address " +
					"(required when the interface still has DHCP enabled). Tracked in private state so " +
					"destroy with `restore_dhcp_on_destroy` can re-enable it. Defaults to `false`.",
			},

			"restore_dhcp_on_destroy": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "When `true`, destroy re-enables DHCP on the interface, but only if this " +
					"resource disabled it. Defaults to `false`: destroy only removes the address. " +
					"Forcing a new lease (`ipconfig /renew`) is a manual step and out of scope.",
			},

			"unsafe_skip_management_check": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Bypasses the management-path guard entirely. The change may apply and " +
					"still end in an apply error (transport lost, timeout); the host must stay reachable " +
					"at the provider `host` address afterwards. Defaults to `false`.",
			},

			"interface_index": schema.Int64Attribute{
				Computed:    true,
				Description: "Numeric interface index owning the address, as observed on the host.",
			},

			"address_family": schema.StringAttribute{
				Computed:    true,
				Description: "Address family, as observed on the host: `IPv4` or `IPv6`.",
			},

			"address_state": schema.StringAttribute{
				Computed:    true,
				Description: "Duplicate-detection state, as observed on the host: `Preferred`, `Tentative`, `Duplicate` or `Deprecated`.",
			},

			"prefix_origin": schema.StringAttribute{
				Computed:    true,
				Description: "How the address was provisioned, as observed on the host: `Manual`, `Dhcp`, `WellKnown`, `RouterAdvertisement` or `Other`.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// netIPAddressDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, netIPAddressTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// netIPAddressAliasValidator rejects aliases containing '|' (the import-ID
// separator) so IDs stay unambiguous.
type netIPAddressAliasValidator struct{}

func (v netIPAddressAliasValidator) Description(_ context.Context) string {
	return "Interface alias must not contain '|'."
}

func (v netIPAddressAliasValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v netIPAddressAliasValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.Contains(req.ConfigValue.ValueString(), "|") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid interface alias",
			fmt.Sprintf("interface_alias must not contain '|' (it separates the alias from the address in the import ID); got %q.", req.ConfigValue.ValueString()),
		)
	}
}

// netIPAddressStringValidator validates the address at plan time: parseable
// via netip, no unspecified/loopback/multicast/broadcast/zone IDs; a warning
// (not an error) on link-local addresses.
type netIPAddressStringValidator struct{}

func (v netIPAddressStringValidator) Description(_ context.Context) string {
	return "IP address must be a valid, assignable unicast address without a zone ID."
}

func (v netIPAddressStringValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v netIPAddressStringValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := req.ConfigValue.ValueString()
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid IP address",
			fmt.Sprintf("ip_address must be a valid IPv4 or IPv6 address; got %q.", raw),
		)
		return
	}
	if zone := addr.Zone(); zone != "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid IP address",
			fmt.Sprintf("ip_address must not carry a zone ID (%q); got %q.", zone, raw),
		)
		return
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified():
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP address",
			fmt.Sprintf("ip_address must not be the unspecified address; got %q.", raw))
	case addr.IsLoopback():
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP address",
			fmt.Sprintf("ip_address must not be a loopback address; got %q.", raw))
	case addr.IsMulticast():
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP address",
			fmt.Sprintf("ip_address must not be a multicast address; got %q.", raw))
	case addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP address",
			fmt.Sprintf("ip_address must not be the IPv4 broadcast address; got %q.", raw))
	case addr.IsLinkLocalUnicast():
		resp.Diagnostics.AddAttributeWarning(req.Path, "Link-local IP address",
			fmt.Sprintf("ip_address %q is link-local: it is only reachable on its local link. This is accepted but usually not what a static assignment intends.", raw))
	}
}

// netIPAddressConfigValidator cross-checks prefix_length against the address
// family and rejects disable_dhcp on IPv6 at plan time.
type netIPAddressConfigValidator struct{}

func (v netIPAddressConfigValidator) Description(_ context.Context) string {
	return "Validates prefix_length against the address family and disable_dhcp against IPv4."
}

func (v netIPAddressConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v netIPAddressConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var ip types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("ip_address"), &ip)...)
	var prefix types.Int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("prefix_length"), &prefix)...)
	var disable types.Bool
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("disable_dhcp"), &disable)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if ip.IsNull() || ip.IsUnknown() || prefix.IsNull() || prefix.IsUnknown() {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip.ValueString()))
	if err != nil {
		return // the attribute validator reports this
	}
	addr = addr.Unmap()
	p := prefix.ValueInt64()
	if addr.Is6() {
		if p < 1 || p > 128 {
			resp.Diagnostics.AddAttributeError(path.Root("prefix_length"), "Invalid prefix length",
				fmt.Sprintf("prefix_length must be 1-128 for IPv6 address %q; got %d.", ip.ValueString(), p))
		}
		if !disable.IsNull() && !disable.IsUnknown() && disable.ValueBool() {
			resp.Diagnostics.AddAttributeError(path.Root("disable_dhcp"), "disable_dhcp is IPv4 only",
				"disable_dhcp must not be set for an IPv6 address.")
		}
	} else if p < 1 || p > 32 {
		resp.Diagnostics.AddAttributeError(path.Root("prefix_length"), "Invalid prefix length",
			fmt.Sprintf("prefix_length must be 1-32 for IPv4 address %q; got %d.", ip.ValueString(), p))
	}
}

// ConfigValidators returns the resource-level cross-field validators.
func (r *windowsNetIPAddressResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		netIPAddressConfigValidator{},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates a
// NetIPAddressClient for this resource instance.
func (r *windowsNetIPAddressResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.ip = winclient.NewNetIPAddressClient(client)
}

// ---------------------------------------------------------------------------
// Helpers: canonicalisation, ID, private state
// ---------------------------------------------------------------------------

// canonicalNetIPAddress parses and canonicalises an address (netip:
// lower-case, compressed IPv6, IPv4-mapped IPv6 unmapped).
func canonicalNetIPAddress(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if zone := addr.Zone(); zone != "" {
		return "", fmt.Errorf("IP address %q must not carry a zone ID", raw)
	}
	return addr.Unmap().String(), nil
}

// netIPAddressID builds the resource ID from the configured alias spelling
// and the canonical address.
func netIPAddressID(alias, canonical string) string {
	return strings.TrimSpace(alias) + "|" + canonical
}

// splitNetIPAddressID parses an ID back into alias and address, trimming
// surrounding whitespace on both parts so IDs with spacing around the
// separator still resolve to the configured values.
func splitNetIPAddressID(id string) (alias, ip string, err error) {
	parts := strings.Split(id, "|")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("import ID %q must have the form <interface_alias>|<ip_address>", id)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

// setNetIPAddressDHCPFlag records whether this resource disabled DHCP in
// private state. setKey is a closure over the response Private data (kept
// injectable so unit tests can capture it without framework internals).
func setNetIPAddressDHCPFlag(ctx context.Context, setKey func(context.Context, string, []byte) diag.Diagnostics, disabled bool) error {
	var raw []byte
	if disabled {
		raw = []byte("true")
	}
	diags := setKey(ctx, netIPAddressPrivateKeyDHCP, raw)
	if diags.HasError() {
		parts := make([]string, 0, len(diags))
		for _, d := range diags {
			parts = append(parts, d.Summary()+": "+d.Detail())
		}
		return fmt.Errorf("%s", strings.Join(parts, "; "))
	}
	return nil
}

// getNetIPAddressDHCPFlag reads the flag back. A missing or empty value
// means "not disabled by us".
func getNetIPAddressDHCPFlag(ctx context.Context, getKey func(context.Context, string) ([]byte, diag.Diagnostics)) bool {
	raw, diags := getKey(ctx, netIPAddressPrivateKeyDHCP)
	if diags.HasError() {
		return false
	}
	return string(raw) == "true"
}

// netIPAddressStateToModel projects an observed NetIPAddressInfo into a
// Terraform model, preserving the non-host-managed plan values (flags and
// timeouts) and the configured alias spelling.
func netIPAddressStateToModel(plan windowsNetIPAddressModel, info *winclient.NetIPAddressInfo) windowsNetIPAddressModel {
	return windowsNetIPAddressModel{
		ID:                        types.StringValue(netIPAddressID(plan.InterfaceAlias.ValueString(), info.IPAddress)),
		InterfaceAlias:            plan.InterfaceAlias,
		IPAddress:                 types.StringValue(info.IPAddress),
		PrefixLength:              types.Int64Value(int64(info.PrefixLength)),
		SkipAsSource:              types.BoolValue(info.SkipAsSource),
		DisableDHCP:               plan.DisableDHCP,
		RestoreDHCPOnDestroy:      plan.RestoreDHCPOnDestroy,
		UnsafeSkipManagementCheck: plan.UnsafeSkipManagementCheck,
		InterfaceIndex:            types.Int64Value(int64(info.InterfaceIndex)),
		AddressFamily:             types.StringValue(info.AddressFamily),
		AddressState:              types.StringValue(info.AddressState),
		PrefixOrigin:              types.StringValue(info.PrefixOrigin),
		Timeouts:                  plan.Timeouts,
	}
}

// netIPAddressTimeoutsOpts declares which per-operation timeouts the resource exposes.
var netIPAddressTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// netIPAddressNullTimeouts returns a null timeouts value carrying the
// schema's attribute types. The zero timeouts.Value wraps an object with NO
// attribute types, which the framework rejects on State.Set — the failure
// mode on import, where there is no prior state to copy the value from.
func netIPAddressNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if netIPAddressTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if netIPAddressTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if netIPAddressTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if netIPAddressTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create provisions the static address and stores the resulting state. When
// the address is still Tentative after the duplicate-detection poll, a
// warning (not an error) is recorded.
func (r *windowsNetIPAddressResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsNetIPAddressModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, netIPAddressDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	canonical, err := canonicalNetIPAddress(plan.IPAddress.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("ip_address"), "Invalid IP address", err.Error())
		return
	}

	tflog.Debug(ctx, "Creating Windows static IP address", map[string]any{
		"interface_alias": plan.InterfaceAlias.ValueString(),
		"ip_address":      canonical,
	})

	info, dhcpDisabled, err := r.ip.Create(ctx, winclient.NetIPAddressInput{
		InterfaceAlias:            plan.InterfaceAlias.ValueString(),
		IPAddress:                 canonical,
		PrefixLength:              int(plan.PrefixLength.ValueInt64()),
		SkipAsSource:              plan.SkipAsSource.ValueBool(),
		DisableDHCP:               plan.DisableDHCP.ValueBool(),
		UnsafeSkipManagementCheck: plan.UnsafeSkipManagementCheck.ValueBool(),
	})
	if err != nil {
		addNetIPAddressDiag(&resp.Diagnostics, "Error creating Windows static IP address", err)
		// The client best-effort restores DHCP after a post-disable
		// failure; a residual disable cannot be recorded in private state
		// (no state is saved on a failed create), so it surfaces as a
		// warning naming the manual re-enable step.
		if dhcpDisabled {
			resp.Diagnostics.AddWarning(
				"DHCP remains disabled after a failed create",
				fmt.Sprintf("DHCP was disabled on interface %q but creating the address failed and DHCP could not be re-enabled automatically. Re-enable it manually (Set-NetIPInterface -InterfaceAlias %q -AddressFamily IPv4 -Dhcp Enabled).",
					plan.InterfaceAlias.ValueString(), plan.InterfaceAlias.ValueString()),
			)
		}
		return
	}

	if err := setNetIPAddressDHCPFlag(ctx, resp.Private.SetKey, dhcpDisabled); err != nil {
		addNetIPAddressDiag(&resp.Diagnostics, "Error tracking DHCP state", err)
		return
	}

	if info.AddressState == "Tentative" {
		resp.Diagnostics.AddWarning(
			"IP address still tentative",
			fmt.Sprintf("Address %s on interface %q is still Tentative after the duplicate-detection poll: it may not be usable yet. This is a warning, not a failure.",
				info.IPAddress, info.InterfaceAlias),
		)
	}

	m := netIPAddressStateToModel(plan, info)
	m.IPAddress = types.StringValue(canonical)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live address. A missing address
// (or renamed-away interface) removes the resource from state.
func (r *windowsNetIPAddressResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsNetIPAddressModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, netIPAddressDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	alias, ip, err := splitNetIPAddressID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Reading Windows static IP address", map[string]any{
		"interface_alias": alias,
		"ip_address":      ip,
	})

	info, err := r.ip.Read(ctx, alias, ip)
	if err != nil {
		addNetIPAddressDiag(&resp.Diagnostics, "Error reading Windows static IP address", err)
		return
	}
	if info == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	m := netIPAddressStateToModel(state, info)
	m.InterfaceAlias = types.StringValue(alias)
	m.IPAddress = types.StringValue(info.IPAddress)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update changes prefix length and/or SkipAsSource in place. Enabling
// disable_dhcp here disables DHCP idempotently; disabling the flag again
// does not re-enable it (see restore_dhcp_on_destroy on delete).
func (r *windowsNetIPAddressResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsNetIPAddressModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsNetIPAddressModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, netIPAddressDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	canonical, err := canonicalNetIPAddress(plan.IPAddress.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("ip_address"), "Invalid IP address", err.Error())
		return
	}

	tflog.Debug(ctx, "Updating Windows static IP address", map[string]any{
		"interface_alias": plan.InterfaceAlias.ValueString(),
		"ip_address":      canonical,
	})

	info, dhcpDisabled, err := r.ip.Update(ctx,
		plan.InterfaceAlias.ValueString(), canonical,
		int(plan.PrefixLength.ValueInt64()),
		plan.SkipAsSource.ValueBool(),
		plan.DisableDHCP.ValueBool(),
		plan.UnsafeSkipManagementCheck.ValueBool(),
	)
	if err != nil {
		addNetIPAddressDiag(&resp.Diagnostics, "Error updating Windows static IP address", err)
		// The client best-effort restores DHCP after a post-disable
		// failure. A residual disable is accumulated into private state
		// best-effort (the framework may drop it with the failed update),
		// and always surfaces as a warning naming the manual step.
		stillDisabled := getNetIPAddressDHCPFlag(ctx, req.Private.GetKey) || dhcpDisabled
		if serr := setNetIPAddressDHCPFlag(ctx, resp.Private.SetKey, stillDisabled); serr != nil && dhcpDisabled {
			addNetIPAddressDiag(&resp.Diagnostics, "Error tracking DHCP state", serr)
		}
		if dhcpDisabled {
			resp.Diagnostics.AddWarning(
				"DHCP remains disabled after a failed update",
				fmt.Sprintf("DHCP was disabled on interface %q but updating the address failed and DHCP could not be re-enabled automatically. Re-enable it manually (Set-NetIPInterface -InterfaceAlias %q -AddressFamily IPv4 -Dhcp Enabled).",
					plan.InterfaceAlias.ValueString(), plan.InterfaceAlias.ValueString()),
			)
		}
		return
	}

	// Private state accumulates: once this resource has disabled DHCP, it
	// stays recorded until a destroy restores it.
	stillDisabled := getNetIPAddressDHCPFlag(ctx, req.Private.GetKey) || dhcpDisabled
	if err := setNetIPAddressDHCPFlag(ctx, resp.Private.SetKey, stillDisabled); err != nil {
		addNetIPAddressDiag(&resp.Diagnostics, "Error tracking DHCP state", err)
		return
	}

	if info.AddressState == "Tentative" {
		resp.Diagnostics.AddWarning(
			"IP address still tentative",
			fmt.Sprintf("Address %s on interface %q is still Tentative: it may not be usable yet. This is a warning, not a failure.",
				info.IPAddress, info.InterfaceAlias),
		)
	}

	m := netIPAddressStateToModel(plan, info)
	m.IPAddress = types.StringValue(canonical)
	m.ID = prior.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the address via Remove-NetIPAddress. With
// restore_dhcp_on_destroy and a resource-recorded DHCP disable, it re-enables
// DHCP afterwards; forcing a new lease (ipconfig /renew) stays a manual step.
func (r *windowsNetIPAddressResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsNetIPAddressModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, netIPAddressDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	alias, ip, err := splitNetIPAddressID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Deleting Windows static IP address", map[string]any{
		"interface_alias": alias,
		"ip_address":      ip,
	})

	if err := r.ip.Delete(ctx, alias, ip, state.UnsafeSkipManagementCheck.ValueBool()); err != nil {
		addNetIPAddressDiag(&resp.Diagnostics, "Error deleting Windows static IP address", err)
		return
	}

	if state.RestoreDHCPOnDestroy.ValueBool() && getNetIPAddressDHCPFlag(ctx, req.Private.GetKey) {
		if err := r.ip.RestoreDHCP(ctx, alias); err != nil {
			resp.Diagnostics.AddWarning(
				"DHCP restore failed",
				fmt.Sprintf("The address was removed, but DHCP could not be re-enabled on interface %q: %s. Re-enable it manually (Set-NetIPInterface -AddressFamily IPv4 -Dhcp Enabled).", alias, err.Error()),
			)
		}
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing static address by
// `<interface_alias>|<ip_address>`. Only addresses with prefix origin Manual
// are importable; DHCP (and other) origins are refused with a clear error. A
// Create over an existing non-manual address fails the same way via the
// already_exists/address_in_use_elsewhere pre-flights.
func (r *windowsNetIPAddressResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	alias, rawIP, err := splitNetIPAddressID(strings.TrimSpace(req.ID))
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must have the form <interface_alias>|<ip_address>; got %q.", req.ID))
		return
	}
	canonical, cerr := canonicalNetIPAddress(rawIP)
	if cerr != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID address part must be a valid IPv4 or IPv6 address; got %q.", rawIP))
		return
	}

	tflog.Debug(ctx, "Importing Windows static IP address", map[string]any{
		"interface_alias": alias,
		"ip_address":      canonical,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, netIPAddressDefaultTimeout)
	defer cancel()

	info, err := r.ip.Read(ctx, alias, canonical)
	if err != nil {
		addNetIPAddressDiag(&resp.Diagnostics, "Error importing Windows static IP address", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Static IP address not found",
			fmt.Sprintf("No address %s on interface %q was found on the target host.", canonical, alias),
		)
		return
	}
	if info.PrefixOrigin != "Manual" {
		resp.Diagnostics.AddError(
			"Address is not statically assigned",
			fmt.Sprintf("Only addresses with prefix origin Manual are importable; address %s on interface %q has prefix origin %q. Remove any conflicting configuration and let this resource manage a Manual address instead.",
				canonical, alias, info.PrefixOrigin),
		)
		return
	}

	plan := windowsNetIPAddressModel{
		InterfaceAlias:            types.StringValue(alias),
		IPAddress:                 types.StringValue(canonical),
		PrefixLength:              types.Int64Value(int64(info.PrefixLength)),
		SkipAsSource:              types.BoolValue(info.SkipAsSource),
		DisableDHCP:               types.BoolValue(false),
		RestoreDHCPOnDestroy:      types.BoolValue(false),
		UnsafeSkipManagementCheck: types.BoolValue(false),
		Timeouts:                  netIPAddressNullTimeouts(),
	}
	m := netIPAddressStateToModel(plan, info)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helper: addNetIPAddressDiag
// ---------------------------------------------------------------------------

// addNetIPAddressDiag appends a diagnostic from a net-ip-address client
// error. Guard refusals keep their full guidance (naming the management
// address and the escape hatch); other kinds are enriched with context
// fields when available.
func addNetIPAddressDiag(d *diag.Diagnostics, summary string, err error) {
	var ne *winclient.NetIPAddressError
	if errors.As(err, &ne) {
		detail := ne.Message
		if len(ne.Context) > 0 {
			var parts []string
			for k, v := range ne.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if ne.Cause != nil {
			detail += "\n\nCause: " + ne.Cause.Error()
		}
		d.AddError(summary+" ["+string(ne.Kind)+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
