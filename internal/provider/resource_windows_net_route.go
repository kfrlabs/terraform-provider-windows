// Package provider - resource_windows_net_route implements the full
// Terraform resource lifecycle for windows_net_route.
//
// One persistent IP route on one network interface (New-NetRoute /
// Set-NetRoute / Remove-NetRoute without -PolicyStore, so the Windows
// default both-stores behaviour keeps the route reboot-surviving): static
// routes to remote networks, on-link routes (next hop 0.0.0.0 / ::) and
// manually managed default gateways. windows_net_ip_address deliberately
// does not own the default gateway; this resource does.
//
// Safety: every mutating operation consults the shared management-path
// guard (winclient.Client.ManagementPath, computed per operation, never
// cached): deleting, replacing or re-metricing the exact management route
// is refused fail-closed with management_path_at_risk, as is creating or
// updating a route that would hijack the SSH session's return path (more
// specific covering prefix, or the same prefix length with an
// equal-or-better effective metric via a different next hop or interface).
// When the path cannot be determined the operation is refused with
// management_path_unknown. Both are bypassable only through
// unsafe_skip_management_check.
//
// Spec alignment: windows_net_route spec v1 (issue #231).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
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
	_ resource.Resource                     = (*windowsNetRouteResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsNetRouteResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsNetRouteResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsNetRouteResource)(nil)
)

// NewWindowsNetRouteResource is the constructor registered in provider.go.
func NewWindowsNetRouteResource() resource.Resource {
	return &windowsNetRouteResource{}
}

// windowsNetRouteResource is the TPF resource type for windows_net_route.
type windowsNetRouteResource struct {
	routes winclient.NetRouteClient
}

// netRouteDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Route operations are fast,
// but a stalled PowerShell/SSH session must never block Terraform forever.
const netRouteDefaultTimeout = 10 * time.Minute

// netRouteDefaultMetric is the Windows default route metric, used when
// `route_metric` is omitted.
const netRouteDefaultMetric = 256

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsNetRouteModel is the Terraform state/plan model for
// windows_net_route. Every tfsdk tag matches an attribute key in
// windowsNetRouteSchemaDefinition.
type windowsNetRouteModel struct {
	ID                        types.String   `tfsdk:"id"`
	InterfaceAlias            types.String   `tfsdk:"interface_alias"`
	DestinationPrefix         types.String   `tfsdk:"destination_prefix"`
	NextHop                   types.String   `tfsdk:"next_hop"`
	RouteMetric               types.Int64    `tfsdk:"route_metric"`
	UnsafeSkipManagementCheck types.Bool     `tfsdk:"unsafe_skip_management_check"`
	InterfaceIndex            types.Int64    `tfsdk:"interface_index"`
	AddressFamily             types.String   `tfsdk:"address_family"`
	InterfaceMetric           types.Int64    `tfsdk:"interface_metric"`
	EffectiveMetric           types.Int64    `tfsdk:"effective_metric"`
	Protocol                  types.String   `tfsdk:"protocol"`
	Timeouts                  timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsNetRouteResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_net_route"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_net_route resource.
func (r *windowsNetRouteResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsNetRouteSchemaDefinition(ctx)
}

// windowsNetRouteSchemaDefinition returns the complete TPF schema for
// windows_net_route.
func windowsNetRouteSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages one persistent IP route on one network interface of a remote Windows host " +
			"(`New-NetRoute` / `Set-NetRoute` / `Remove-NetRoute` without `-PolicyStore`, so the Windows default " +
			"both-stores behaviour keeps the route reboot-surviving, via SSH and PowerShell): " +
			"static routes to remote networks, on-link routes, and manually managed default gateways.\n\n" +
			"`interface_alias`, `destination_prefix` and `next_hop` identify the route and are immutable after creation " +
			"(ForceNew); only `route_metric` is updated in place. `destination_prefix` must be in canonical masked CIDR " +
			"form (`10.0.0.5/24` is a plan-time error that names `10.0.0.0/24`); `0.0.0.0/0` and `::/0` are default routes. " +
			"`next_hop` must be the same family as the prefix; `0.0.0.0` / `::` means on-link (no gateway).\n\n" +
			"Route metric vs interface metric: Windows selects routes by longest prefix first, then by the lowest " +
			"**effective metric** (`route_metric` + `interface_metric`). This resource manages the route metric; the " +
			"interface metric is observed. Adding a manual default route with a **higher** effective metric than the " +
			"existing one is the supported \"backup gateway\" pattern: the existing route keeps winning until it " +
			"disappears.\n\n" +
			"Safety — this resource changes routing for the whole host and can sever its own SSH session: deleting, " +
			"replacing or re-metricing the route that carries the provider's own SSH return traffic is refused " +
			"fail-closed, as is creating or updating a route that would hijack that traffic. When the management path " +
			"cannot be determined the operation is refused as well. `unsafe_skip_management_check` bypasses the guard " +
			"entirely: the change may apply and still end in an apply error (transport lost, timeout), and the host must " +
			"stay reachable at the provider `host` address afterwards. " +
			"Consider a `precondition` on the `windows_net_route` data source reading back the default route before " +
			"changing gateways.\n\n" +
			"Import format: `<interface_alias>|<destination_prefix>|<next_hop>`. Only routes with protocol `NetMgmt` " +
			"are importable; automatic routes (`Local` on-link routes derived from addresses, `Dhcp` gateways) are " +
			"refused with a clear error.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier: `<interface_alias>|<destination_prefix>|<next_hop>`.",
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
					netRouteAliasValidator{},
				},
			},

			"destination_prefix": schema.StringAttribute{
				Required: true,
				Description: "Route destination in CIDR form (e.g. `\"198.51.100.0/24\"`, `\"0.0.0.0/0\"` for the " +
					"IPv4 default route). Must be in canonical masked form: host bits set is a plan-time error " +
					"that names the canonical form. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					netRoutePrefixValidator{},
				},
			},

			"next_hop": schema.StringAttribute{
				Required: true,
				Description: "Gateway address in canonical spelling. Must be the same family as " +
					"`destination_prefix`. `0.0.0.0` / `::` means on-link (no gateway). Multicast and loopback " +
					"addresses are rejected. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					netRouteNextHopValidator{},
				},
			},

			"route_metric": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(netRouteDefaultMetric),
				Description: "Route metric (0-9999). Added to the interface metric to form the effective metric " +
					"Windows uses for route selection. Updated in place. Defaults to `256` (the Windows default).",
				Validators: []validator.Int64{
					int64validator.Between(0, 9999),
				},
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
				Description: "Numeric interface index owning the route, as observed on the host.",
			},

			"address_family": schema.StringAttribute{
				Computed:    true,
				Description: "Address family, as observed on the host: `IPv4` or `IPv6`.",
			},

			"interface_metric": schema.Int64Attribute{
				Computed:    true,
				Description: "Interface metric from `Get-NetIPInterface`, as observed on the host.",
			},

			"effective_metric": schema.Int64Attribute{
				Computed:    true,
				Description: "Effective metric Windows uses for route selection (`route_metric` + `interface_metric`), as observed on the host.",
			},

			"protocol": schema.StringAttribute{
				Computed:    true,
				Description: "Route protocol, as observed on the host: `NetMgmt` for routes this resource creates.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// netRouteDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, netRouteTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// netRouteAliasValidator rejects aliases containing '|' (the import-ID
// separator) so IDs stay unambiguous.
type netRouteAliasValidator struct{}

func (v netRouteAliasValidator) Description(_ context.Context) string {
	return "Interface alias must not contain '|'."
}

func (v netRouteAliasValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v netRouteAliasValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.Contains(req.ConfigValue.ValueString(), "|") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid interface alias",
			fmt.Sprintf("interface_alias must not contain '|' (it separates the parts of the import ID); got %q.", req.ConfigValue.ValueString()),
		)
	}
}

// netRoutePrefixValidator validates the destination prefix at plan time:
// parseable CIDR, canonical masked form (host bits set names the canonical
// form).
type netRoutePrefixValidator struct{}

func (v netRoutePrefixValidator) Description(_ context.Context) string {
	return "Destination prefix must be a canonical masked CIDR prefix."
}

func (v netRoutePrefixValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v netRoutePrefixValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := req.ConfigValue.ValueString()
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid destination prefix",
			fmt.Sprintf("destination_prefix must be a valid CIDR prefix (e.g. \"198.51.100.0/24\", \"0.0.0.0/0\"); got %q.", raw),
		)
		return
	}
	if p.Masked() != p {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Destination prefix has host bits set",
			fmt.Sprintf("destination_prefix %q is not in canonical masked form; use %q.", raw, p.Masked().String()),
		)
	}
}

// netRouteNextHopValidator validates the next hop at plan time: parseable
// via netip, no zone IDs; unspecified (on-link) is allowed here, multicast,
// loopback and IPv4 broadcast are rejected. Family agreement with the
// prefix is checked by netRouteConfigValidator.
type netRouteNextHopValidator struct{}

func (v netRouteNextHopValidator) Description(_ context.Context) string {
	return "Next hop must be a valid unicast address without a zone ID, or the unspecified address for on-link routes."
}

func (v netRouteNextHopValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v netRouteNextHopValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := req.ConfigValue.ValueString()
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid next hop",
			fmt.Sprintf("next_hop must be a valid IPv4 or IPv6 address (or 0.0.0.0 / :: for on-link routes); got %q.", raw),
		)
		return
	}
	if zone := addr.Zone(); zone != "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid next hop",
			fmt.Sprintf("next_hop must not carry a zone ID (%q); got %q.", zone, raw),
		)
		return
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified():
		// On-link spelling: allowed.
	case addr.IsMulticast():
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid next hop",
			fmt.Sprintf("next_hop must not be a multicast address (on-link routes use 0.0.0.0 or ::); got %q.", raw))
	case addr.IsLoopback():
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid next hop",
			fmt.Sprintf("next_hop must not be a loopback address; got %q.", raw))
	case addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid next hop",
			fmt.Sprintf("next_hop must not be the IPv4 broadcast address; got %q.", raw))
	}
}

// netRouteConfigValidator cross-checks destination_prefix against next_hop:
// both must parse (attribute validators report the rest) and agree on the
// address family.
type netRouteConfigValidator struct{}

func (v netRouteConfigValidator) Description(_ context.Context) string {
	return "Validates the next hop against the destination prefix family."
}

func (v netRouteConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v netRouteConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var prefix types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("destination_prefix"), &prefix)...)
	var nextHop types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("next_hop"), &nextHop)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if prefix.IsNull() || prefix.IsUnknown() || nextHop.IsNull() || nextHop.IsUnknown() {
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(prefix.ValueString()))
	if err != nil {
		return // the attribute validator reports this
	}
	nh, err := netip.ParseAddr(strings.TrimSpace(nextHop.ValueString()))
	if err != nil {
		return // the attribute validator reports this
	}
	if nh.Unmap().Is4() == p.Addr().Is6() {
		resp.Diagnostics.AddAttributeError(path.Root("next_hop"), "Address family mismatch",
			fmt.Sprintf("next_hop %q must be the same address family as destination_prefix %q.", nextHop.ValueString(), p.Masked().String()))
	}
}

// ConfigValidators returns the resource-level cross-field validators.
func (r *windowsNetRouteResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		netRouteConfigValidator{},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates a
// NetRouteClient for this resource instance.
func (r *windowsNetRouteResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.routes = winclient.NewNetRouteClient(client)
}

// ---------------------------------------------------------------------------
// Helpers: canonicalisation, ID
// ---------------------------------------------------------------------------

// canonicalNetRoutePrefix parses and canonicalises a destination prefix
// (netip masked form).
func canonicalNetRoutePrefix(raw string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	return p.Masked().String(), nil
}

// canonicalNetRouteNextHop parses and canonicalises a next hop (netip,
// IPv4-mapped IPv6 unmapped).
func canonicalNetRouteNextHop(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if zone := addr.Zone(); zone != "" {
		return "", fmt.Errorf("next hop %q must not carry a zone ID", raw)
	}
	return addr.Unmap().String(), nil
}

// netRouteID builds the resource ID from the configured alias spelling and
// the canonical prefix and next hop.
func netRouteID(alias, prefix, nextHop string) string {
	return strings.TrimSpace(alias) + "|" + prefix + "|" + nextHop
}

// splitNetRouteID parses an ID back into alias, prefix and next hop,
// trimming surrounding whitespace on all parts.
func splitNetRouteID(id string) (alias, prefix, nextHop string, err error) {
	parts := strings.Split(id, "|")
	if len(parts) != 3 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return "", "", "", fmt.Errorf("import ID %q must have the form <interface_alias>|<destination_prefix>|<next_hop>", id)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), nil
}

// netRouteStateToModel projects an observed NetRouteInfo into a Terraform
// model, preserving the non-host-managed plan values (flags and timeouts)
// and the configured alias spelling.
func netRouteStateToModel(plan windowsNetRouteModel, info *winclient.NetRouteInfo) windowsNetRouteModel {
	return windowsNetRouteModel{
		ID:                        types.StringValue(netRouteID(plan.InterfaceAlias.ValueString(), info.DestinationPrefix, info.NextHop)),
		InterfaceAlias:            plan.InterfaceAlias,
		DestinationPrefix:         types.StringValue(info.DestinationPrefix),
		NextHop:                   types.StringValue(info.NextHop),
		RouteMetric:               types.Int64Value(int64(info.RouteMetric)),
		UnsafeSkipManagementCheck: plan.UnsafeSkipManagementCheck,
		InterfaceIndex:            types.Int64Value(int64(info.InterfaceIndex)),
		AddressFamily:             types.StringValue(info.AddressFamily),
		InterfaceMetric:           types.Int64Value(int64(info.InterfaceMetric)),
		EffectiveMetric:           types.Int64Value(int64(info.EffectiveMetric)),
		Protocol:                  types.StringValue(info.Protocol),
		Timeouts:                  plan.Timeouts,
	}
}

// netRouteTimeoutsOpts declares which per-operation timeouts the resource exposes.
var netRouteTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// netRouteNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO
// attribute types, which the framework rejects on State.Set — the failure
// mode on import, where there is no prior state to copy the value from.
func netRouteNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if netRouteTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if netRouteTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if netRouteTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if netRouteTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create provisions the persistent route and stores the resulting state.
func (r *windowsNetRouteResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsNetRouteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, netRouteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	prefix, err := canonicalNetRoutePrefix(plan.DestinationPrefix.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("destination_prefix"), "Invalid destination prefix", err.Error())
		return
	}
	nextHop, err := canonicalNetRouteNextHop(plan.NextHop.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("next_hop"), "Invalid next hop", err.Error())
		return
	}

	tflog.Debug(ctx, "Creating Windows persistent route", map[string]any{
		"interface_alias": plan.InterfaceAlias.ValueString(),
		"prefix":          prefix,
		"next_hop":        nextHop,
	})

	info, err := r.routes.Create(ctx, winclient.NetRouteInput{
		InterfaceAlias:            plan.InterfaceAlias.ValueString(),
		DestinationPrefix:         prefix,
		NextHop:                   nextHop,
		RouteMetric:               int(plan.RouteMetric.ValueInt64()),
		UnsafeSkipManagementCheck: plan.UnsafeSkipManagementCheck.ValueBool(),
	})
	if err != nil {
		addNetRouteDiag(&resp.Diagnostics, "Error creating Windows persistent route", err)
		return
	}

	m := netRouteStateToModel(plan, info)
	m.DestinationPrefix = types.StringValue(prefix)
	m.NextHop = types.StringValue(nextHop)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live route. A missing route (or
// renamed-away interface) removes the resource from state.
func (r *windowsNetRouteResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsNetRouteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, netRouteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	alias, prefix, nextHop, err := splitNetRouteID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Reading Windows persistent route", map[string]any{
		"interface_alias": alias,
		"prefix":          prefix,
		"next_hop":        nextHop,
	})

	info, err := r.routes.Read(ctx, alias, prefix, nextHop)
	if err != nil {
		addNetRouteDiag(&resp.Diagnostics, "Error reading Windows persistent route", err)
		return
	}
	if info == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	m := netRouteStateToModel(state, info)
	m.InterfaceAlias = types.StringValue(alias)
	m.DestinationPrefix = types.StringValue(info.DestinationPrefix)
	m.NextHop = types.StringValue(info.NextHop)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update changes the route metric in place. Identity attributes
// (interface_alias, destination_prefix, next_hop) force replacement via
// RequiresReplace, so Update only ever sees a metric change.
func (r *windowsNetRouteResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsNetRouteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsNetRouteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, netRouteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	prefix, err := canonicalNetRoutePrefix(plan.DestinationPrefix.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("destination_prefix"), "Invalid destination prefix", err.Error())
		return
	}
	nextHop, err := canonicalNetRouteNextHop(plan.NextHop.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("next_hop"), "Invalid next hop", err.Error())
		return
	}

	tflog.Debug(ctx, "Updating Windows persistent route", map[string]any{
		"interface_alias": plan.InterfaceAlias.ValueString(),
		"prefix":          prefix,
		"next_hop":        nextHop,
	})

	info, err := r.routes.Update(ctx,
		plan.InterfaceAlias.ValueString(), prefix, nextHop,
		int(plan.RouteMetric.ValueInt64()),
		plan.UnsafeSkipManagementCheck.ValueBool(),
	)
	if err != nil {
		addNetRouteDiag(&resp.Diagnostics, "Error updating Windows persistent route", err)
		return
	}

	m := netRouteStateToModel(plan, info)
	m.NextHop = types.StringValue(nextHop)
	m.DestinationPrefix = types.StringValue(prefix)
	m.ID = prior.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the persistent route via Remove-NetRoute.
func (r *windowsNetRouteResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsNetRouteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, netRouteDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	alias, prefix, nextHop, err := splitNetRouteID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Deleting Windows persistent route", map[string]any{
		"interface_alias": alias,
		"prefix":          prefix,
		"next_hop":        nextHop,
	})

	if err := r.routes.Delete(ctx, alias, prefix, nextHop, state.UnsafeSkipManagementCheck.ValueBool()); err != nil {
		addNetRouteDiag(&resp.Diagnostics, "Error deleting Windows persistent route", err)
		return
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing persistent route by
// `<interface_alias>|<destination_prefix>|<next_hop>`. Only routes with
// protocol NetMgmt are importable; automatic routes (Local on-link routes
// derived from addresses, Dhcp gateways) are refused with a clear error.
func (r *windowsNetRouteResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	alias, rawPrefix, rawNextHop, err := splitNetRouteID(strings.TrimSpace(req.ID))
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must have the form <interface_alias>|<destination_prefix>|<next_hop>; got %q.", req.ID))
		return
	}
	prefix, perr := canonicalNetRoutePrefix(rawPrefix)
	if perr != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID prefix part must be a valid CIDR prefix; got %q.", rawPrefix))
		return
	}
	nextHop, nerr := canonicalNetRouteNextHop(rawNextHop)
	if nerr != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID next hop part must be a valid IPv4 or IPv6 address; got %q.", rawNextHop))
		return
	}

	tflog.Debug(ctx, "Importing Windows persistent route", map[string]any{
		"interface_alias": alias,
		"prefix":          prefix,
		"next_hop":        nextHop,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, netRouteDefaultTimeout)
	defer cancel()

	info, err := r.routes.Read(ctx, alias, prefix, nextHop)
	if err != nil {
		addNetRouteDiag(&resp.Diagnostics, "Error importing Windows persistent route", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Persistent route not found",
			fmt.Sprintf("No route %s via %s on interface %q was found on the target host.", prefix, nextHop, alias),
		)
		return
	}
	if !strings.EqualFold(info.Protocol, "NetMgmt") {
		resp.Diagnostics.AddError(
			"Route is not statically managed",
			fmt.Sprintf("Only routes with protocol NetMgmt are importable; route %s via %s on interface %q has protocol %q. Remove any conflicting configuration and let this resource manage a NetMgmt route instead.",
				prefix, nextHop, alias, info.Protocol),
		)
		return
	}

	plan := windowsNetRouteModel{
		InterfaceAlias:            types.StringValue(alias),
		DestinationPrefix:         types.StringValue(prefix),
		NextHop:                   types.StringValue(nextHop),
		RouteMetric:               types.Int64Value(int64(info.RouteMetric)),
		UnsafeSkipManagementCheck: types.BoolValue(false),
		Timeouts:                  netRouteNullTimeouts(),
	}
	m := netRouteStateToModel(plan, info)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helper: addNetRouteDiag
// ---------------------------------------------------------------------------

// addNetRouteDiag appends a diagnostic from a net-route client error.
// Guard refusals keep their full guidance (naming the management path and
// the escape hatch); other kinds are enriched with context fields when
// available.
func addNetRouteDiag(d *diag.Diagnostics, summary string, err error) {
	var ne *winclient.NetRouteError
	if errors.As(err, &ne) {
		detail := ne.Message
		if len(ne.Context) > 0 {
			keys := make([]string, 0, len(ne.Context))
			for k := range ne.Context {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%s", k, ne.Context[k]))
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
