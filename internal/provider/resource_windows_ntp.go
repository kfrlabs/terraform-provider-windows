// Package provider: windows_ntp resource implementation.
//
// This file contains the TPF schema, model, custom validators and full
// CRUD + ImportState handlers for the windows_ntp resource. All SSH
// interaction is delegated to winclient.NTPClient (internal/winclient).
//
// The W32Time time source is a singleton: the host always has exactly one,
// so Create and Update share one idempotent Set operation (registry writes
// via Set-ItemProperty, w32tm /config /update, optional resync), Read
// refreshes from the live host and never removes the resource from state,
// and Delete makes no remote change unless restore_on_destroy re-applies
// the pre-existing values captured into private state at Create (or import)
// time.
//
// Spec alignment: windows_ntp spec (issue #287).
// Framework:       terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsNTPResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsNTPResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsNTPResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsNTPResource)(nil)
)

// NewWindowsNTPResource is the constructor registered in provider.go.
func NewWindowsNTPResource() resource.Resource { return &windowsNTPResource{} }

// windowsNTPResource is the TPF resource type for windows_ntp.
type windowsNTPResource struct {
	ntp winclient.WindowsNTPClient
}

// ntpDefaultTimeout is the fallback per-operation timeout when the user
// does not provide a `timeouts {}` block. W32Time reads and writes are
// normally fast, but a stalled PowerShell/SSH session must never block
// Terraform forever: every CRUD handler bounds its work with this default.
const ntpDefaultTimeout = 5 * time.Minute

// ntpPrivateKey is the private-state key holding the JSON-encoded
// pre-existing W32Time state captured at Create (or import) time. Delete
// with restore_on_destroy re-applies it verbatim.
const ntpPrivateKey = "original_state"

// windowsNTPServerModel is one element of the servers list. Field tags
// match the nested attribute names declared in the schema below.
type windowsNTPServerModel struct {
	Address types.String `tfsdk:"address"`
	Flags   types.String `tfsdk:"flags"`
}

// windowsNTPModel is the Terraform state/plan model for the windows_ntp
// resource. Field tags match the snake_case attribute names declared in
// the schema below.
//
// ID is anchored on MachineID (HKLM MachineGuid): it survives time-source
// changes and is refreshed from the live host on every Read.
type windowsNTPModel struct {
	ID                           types.String   `tfsdk:"id"`
	Type                         types.String   `tfsdk:"type"`
	Servers                      types.List     `tfsdk:"servers"`
	SpecialPollIntervalSeconds   types.Int64    `tfsdk:"special_poll_interval_seconds"`
	Reliable                     types.Bool     `tfsdk:"reliable"`
	NtpServerEnabled             types.Bool     `tfsdk:"ntp_server_enabled"`
	MaxPosPhaseCorrectionSeconds types.Int64    `tfsdk:"max_pos_phase_correction_seconds"`
	MaxNegPhaseCorrectionSeconds types.Int64    `tfsdk:"max_neg_phase_correction_seconds"`
	ManageService                types.Bool     `tfsdk:"manage_service"`
	ResyncOnApply                types.Bool     `tfsdk:"resync_on_apply"`
	RestoreOnDestroy             types.Bool     `tfsdk:"restore_on_destroy"`
	CurrentSource                types.String   `tfsdk:"current_source"`
	PolicyOverride               types.Bool     `tfsdk:"policy_override"`
	DomainJoined                 types.Bool     `tfsdk:"domain_joined"`
	Timeouts                     timeouts.Value `tfsdk:"timeouts"`
}

// ntpServerElementAttrTypes returns the attribute types of one servers
// list element.
func ntpServerElementAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"address": types.StringType,
		"flags":   types.StringType,
	}
}

// ntpServerElementObjectType returns the object type of one servers list
// element.
func ntpServerElementObjectType() attr.Type {
	return types.ObjectType{AttrTypes: ntpServerElementAttrTypes()}
}

// ntpLowercaseFlagsModifier is a plan modifier normalising peer flags to
// lower-case (the canonical "0xN" spelling the host stores). Without it a
// configured "0X9" would plan a perpetual diff against the observed "0x9".
type ntpLowercaseFlagsModifier struct{}

// Description returns a human-readable description for plan output.
func (ntpLowercaseFlagsModifier) Description(_ context.Context) string {
	return "Normalises NTP peer flags to lower-case."
}

// MarkdownDescription returns the Markdown variant of Description.
func (m ntpLowercaseFlagsModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

// PlanModifyString lower-cases a known, non-null flags value.
func (ntpLowercaseFlagsModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	resp.PlanValue = types.StringValue(strings.ToLower(req.PlanValue.ValueString()))
}

// Metadata sets the resource type name ("windows_ntp").
func (r *windowsNTPResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ntp"
}

// Schema returns the complete TPF schema.
func (r *windowsNTPResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsNTPSchemaDefinition(ctx)
}

// windowsNTPSchemaDefinition returns the resource schema. Extracted into a
// function so it can be unit-tested independently of the resource type.
func windowsNTPSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the Windows Time service (W32Time) time source of a remote Windows machine over SSH/PowerShell.\n\n" +
			"The time source is a **singleton**: the host always has exactly one, so creating this resource never " +
			"provisions anything new — it only writes the W32Time registry values in place (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time`), " +
			"runs `w32tm /config /update` (and, by default, a warning-only `w32tm /resync /rediscover`), and deleting it makes no remote change unless " +
			"`restore_on_destroy` is set. No `w32tm` query output is ever parsed (its text is localised): the registry is the source of truth.\n\n" +
			"`type` selects the sync type (`NTP`, `NT5DS`, `AllSync`, `NoSync`). `servers` carries the NTP peers (`NtpServer`, " +
			"`addr,flags` space-separated, order preserved) — required for `NTP`/`AllSync`, forbidden for `NT5DS`/`NoSync`. " +
			"Peer flags default to `0x9` (SpecialInterval + Client) and are normalised to lower-case.\n\n" +
			"By default the `W32Time` service is set to `Automatic` start and started (`manage_service`); set it to `false` when a " +
			"`windows_service` resource owns W32Time. The Terraform resource ID is anchored on `id` (HKLM `MachineGuid`), not on the time source, " +
			"so it survives configuration changes.\n\n" +
			"**Destroy is a no-op by default:** a Windows machine cannot exist without a time source; `terraform destroy` only removes " +
			"the resource from state unless `restore_on_destroy` re-applies the pre-existing values.\n\n" +
			"Import format: any non-empty ID (its value is ignored; the live time source is adopted, e.g. `current`).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform resource ID. Equal to the host MachineGuid (HKLM Cryptography MachineGuid). Stable across time-source changes.",
				MarkdownDescription: "Terraform resource ID. Equal to the host `MachineGuid` (`HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`). Stable across time-source changes.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Required:            true,
				Description:         "W32Time sync type (W32Time Parameters Type). One of NTP, NT5DS, AllSync, NoSync.",
				MarkdownDescription: "W32Time sync type (`W32Time\\Parameters\\Type`). One of `NTP`, `NT5DS`, `AllSync`, `NoSync`.",
				Validators: []validator.String{
					stringvalidator.OneOf("NTP", "NT5DS", "AllSync", "NoSync"),
				},
			},
			"servers": schema.ListNestedAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "NTP peers (W32Time Parameters NtpServer), in order. Required for type NTP/AllSync, forbidden for NT5DS/NoSync. Unconfigured types leave the host peer list untouched.",
				MarkdownDescription: "NTP peers (`W32Time\\Parameters\\NtpServer`), in order. Required for type `NTP`/`AllSync`, forbidden for `NT5DS`/`NoSync`. When omitted the host peer list is left untouched.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"address": schema.StringAttribute{
							Required:            true,
							Description:         "Peer hostname, IPv4 or IPv6 address. Must not contain whitespace or commas.",
							MarkdownDescription: "Peer hostname, IPv4 or IPv6 address. Must not contain whitespace or commas.",
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
								stringvalidator.RegexMatches(ntpServerAddressRegex, ntpServerAddressRegexDesc),
							},
						},
						"flags": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							Default:             stringdefault.StaticString(winclient.DefaultNTPPeerFlags),
							Description:         "Per-peer flags. Hex 0x1-0xF, normalised to lower-case. Default: 0x9 (SpecialInterval + Client).",
							MarkdownDescription: "Per-peer flags. Hex `0x1`-`0xF`, normalised to lower-case. Default: `0x9` (SpecialInterval + Client).",
							Validators: []validator.String{
								stringvalidator.RegexMatches(ntpServerFlagsRegex, ntpServerFlagsRegexDesc),
							},
							PlanModifiers: []planmodifier.String{
								ntpLowercaseFlagsModifier{},
							},
						},
					},
				},
			},
			"special_poll_interval_seconds": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Description:         "Poll interval in seconds (W32Time NtpClient SpecialPollInterval). 16-86400. Only used by peers with the 0x1 (SpecialInterval) flag; otherwise a plan-time warning is emitted.",
				MarkdownDescription: "Poll interval in seconds (`W32Time\\TimeProviders\\NtpClient\\SpecialPollInterval`). `16`-`86400`. Only used by peers with the `0x1` (`SpecialInterval`) flag; otherwise a plan-time warning is emitted.",
				Validators: []validator.Int64{
					int64validator.Between(winclient.NTPMinPollIntervalSeconds, winclient.NTPMaxPollIntervalSeconds),
				},
			},
			"reliable": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Whether this host is a reliable time source (W32Time Config AnnounceFlags: true writes 5, false writes 10).",
				MarkdownDescription: "Whether this host is a reliable time source (`W32Time\\Config\\AnnounceFlags`: `true` writes `5`, `false` writes `10`).",
			},
			"ntp_server_enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Whether this host answers NTP requests (W32Time NtpServer Enabled). Enabling it warns: UDP/123 must be reachable (see windows_firewall_rule).",
				MarkdownDescription: "Whether this host answers NTP requests (`W32Time\\TimeProviders\\NtpServer\\Enabled`). Enabling it warns: UDP/123 must be reachable (see `windows_firewall_rule`).",
			},
			"max_pos_phase_correction_seconds": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Description:         "Largest forward clock correction the service may apply, in seconds (W32Time Config MaxPosPhaseCorrection).",
				MarkdownDescription: "Largest forward clock correction the service may apply, in seconds (`W32Time\\Config\\MaxPosPhaseCorrection`).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},
			"max_neg_phase_correction_seconds": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Description:         "Largest backward clock correction the service may apply, in seconds (W32Time Config MaxNegPhaseCorrection).",
				MarkdownDescription: "Largest backward clock correction the service may apply, in seconds (`W32Time\\Config\\MaxNegPhaseCorrection`).",
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},
			"manage_service": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				Description:         "When true, set the W32Time service StartupType to Automatic and start it before applying. Set to false when a windows_service resource owns W32Time: the service is then left untouched.",
				MarkdownDescription: "When `true`, set the `W32Time` service `StartupType` to `Automatic` and start it before applying. Set to `false` when a `windows_service` resource owns `W32Time`: the service is then left untouched. Default: `true`.",
			},
			"resync_on_apply": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				Description:         "When true, run w32tm /resync /rediscover after applying. A resync failure surfaces as a warning, never as an error (the peer may be unreachable at apply time). Default: true.",
				MarkdownDescription: "When `true`, run `w32tm /resync /rediscover` after applying. A resync failure surfaces as a warning, never as an error (the peer may be unreachable at apply time). Default: `true`.",
			},
			"restore_on_destroy": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "When true, destroy re-applies the pre-existing W32Time values captured at creation (or import) time. Defaults to false: destroy makes no remote change.",
				MarkdownDescription: "When `true`, destroy re-applies the pre-existing W32Time values captured at creation (or import) time. Defaults to `false`: destroy makes no remote change.",
			},
			"current_source": schema.StringAttribute{
				Computed:            true,
				Description:         "Current time source as reported by w32tm /query /source (opaque peer name, never parsed). Empty when the query fails (e.g. the service is stopped). Informational only: never produces drift.",
				MarkdownDescription: "Current time source as reported by `w32tm /query /source` (opaque peer name, never parsed). Empty when the query fails (e.g. the service is stopped). Informational only: never produces drift.",
			},
			"policy_override": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether Group Policy carries Type or NtpServer for W32Time (HKLM SOFTWARE Policies Microsoft W32Time Parameters). When true, the GPO value wins at the next policy refresh and Terraform-managed values may diverge.",
				MarkdownDescription: "Whether Group Policy carries `Type` or `NtpServer` for W32Time (`HKLM\\SOFTWARE\\Policies\\Microsoft\\W32Time\\Parameters`). When `true`, the GPO value wins at the next policy refresh and Terraform-managed values may diverge.",
			},
			"domain_joined": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the host is joined to an Active Directory domain (Win32_ComputerSystem PartOfDomain). Domain-joined hosts should use type NT5DS unless this host is the PDC emulator.",
				MarkdownDescription: "Whether the host is joined to an Active Directory domain (`Win32_ComputerSystem.PartOfDomain`). Domain-joined hosts should use type `NT5DS` unless this host is the PDC emulator.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to ntpDefaultTimeout
			// so a stalled PowerShell/SSH session surfaces a timeout
			// diagnostic instead of blocking Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, ntpTimeoutsOpts),
		},
	}
}

// Shared validator regexes so the schema and the validator message stay in
// sync. Compiled once at package load.
var (
	ntpServerAddressRegex     = regexp.MustCompile(`^[^\s,]+$`)
	ntpServerAddressRegexDesc = "must not contain whitespace or commas"
	ntpServerFlagsRegex       = regexp.MustCompile(`(?i)^0x[1-9a-f]$`)
	ntpServerFlagsRegexDesc   = "must be hex 0x1-0xF (e.g. 0x9)"
)

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// ConfigValidators returns the resource-level cross-field validators:
//   - windowsNTPConfigValidator: type x servers matrix (error) plus the
//     SpecialPollInterval-without-0x1-peer advisory (warning).
func (r *windowsNTPResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		windowsNTPConfigValidator{},
	}
}

// windowsNTPConfigValidator enforces the type x servers matrix at plan
// time (peers required for NTP/AllSync, forbidden for NT5DS/NoSync) and
// warns when special_poll_interval_seconds is set while no configured peer
// carries the 0x1 (SpecialInterval) flag that makes the interval effective.
type windowsNTPConfigValidator struct{}

func (v windowsNTPConfigValidator) Description(_ context.Context) string {
	return "Enforces the NTP type x servers matrix and warns on ineffective poll intervals."
}

func (v windowsNTPConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v windowsNTPConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var typ types.String
	diags := req.Config.GetAttribute(ctx, path.Root("type"), &typ)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var servers types.List
	diags = req.Config.GetAttribute(ctx, path.Root("servers"), &servers)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if typ.IsNull() || typ.IsUnknown() {
		return
	}
	usesPeers := typ.ValueString() == winclient.NTPTypeNTP || typ.ValueString() == winclient.NTPTypeAllSync

	if servers.IsUnknown() {
		return
	}
	if servers.IsNull() {
		if usesPeers {
			resp.Diagnostics.AddAttributeError(
				path.Root("servers"),
				"Missing NTP servers",
				fmt.Sprintf("type %q requires at least one NTP server peer: configure servers.", typ.ValueString()),
			)
		}
		return
	}
	var elems []windowsNTPServerModel
	diags = servers.ElementsAs(ctx, &elems, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !usesPeers && len(elems) > 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("servers"),
			"Servers forbidden for this NTP type",
			fmt.Sprintf("type %q does not consume NTP peers: remove servers (the host peer list is left untouched).", typ.ValueString()),
		)
		return
	}
	if usesPeers && len(elems) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("servers"),
			"Missing NTP servers",
			fmt.Sprintf("type %q requires at least one NTP server peer: configure servers.", typ.ValueString()),
		)
		return
	}
	// Advisory: the poll interval only affects peers flagged 0x1.
	var poll types.Int64
	diags = req.Config.GetAttribute(ctx, path.Root("special_poll_interval_seconds"), &poll)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if poll.IsNull() || poll.IsUnknown() || !usesPeers {
		return
	}
	for _, e := range elems {
		if e.Flags.IsNull() || e.Flags.IsUnknown() {
			// Unset flags default to 0x9 (not 0x1): no need to warn twice.
			continue
		}
		if strings.EqualFold(e.Flags.ValueString(), "0x1") {
			return
		}
	}
	resp.Diagnostics.AddAttributeWarning(
		path.Root("special_poll_interval_seconds"),
		"Ineffective poll interval",
		"special_poll_interval_seconds only affects peers with the 0x1 (SpecialInterval) flag, "+
			"and none of the configured servers carries it: the value is applied to the host but no peer honours it.",
	)
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates an NTPClient
// for this resource instance.
func (r *windowsNTPResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.ntp = winclient.NewNTPClient(client)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create tunes the (always pre-existing) W32Time time source in place and
// saves the full state. When restore_on_destroy is set, the pre-existing
// values are captured into private state first so Delete can re-apply
// them.
func (r *windowsNTPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsNTPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, ntpDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	if plan.RestoreOnDestroy.ValueBool() {
		pre, err := r.ntp.Read(ctx)
		if err != nil {
			addNTPDiag(&resp.Diagnostics, "Error reading pre-existing Windows NTP state", err)
			return
		}
		if err := setNTPSnapshot(ctx, resp.Private.SetKey, pre); err != nil {
			addNTPDiag(&resp.Diagnostics, "Error capturing pre-existing Windows NTP state", err)
			return
		}
	}

	in, diags := ntpModelToInput(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Windows NTP time source (tuning in place)", map[string]any{
		"type": in.Type,
	})

	state, err := r.ntp.Set(ctx, in)
	if err != nil {
		addNTPDiag(&resp.Diagnostics, "Error creating Windows NTP time source", err)
		return
	}

	maybeWarnNTPResync(&resp.Diagnostics, state)

	m, diags := ntpStateToModel(state, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	addNTPStateWarnings(&resp.Diagnostics, m)
	addNTPVmICWarning(&resp.Diagnostics, state)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live W32Time time source. The
// time source always exists, so a read failure surfaces an error
// diagnostic instead of silently removing the resource from state.
func (r *windowsNTPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsNTPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, ntpDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "Reading Windows NTP time source", map[string]any{
		"type": state.Type.ValueString(),
	})

	live, err := r.ntp.Read(ctx)
	if err != nil {
		addNTPDiag(&resp.Diagnostics, "Error reading Windows NTP time source", err)
		return
	}

	m, diags := ntpStateToModel(live, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	addNTPStateWarnings(&resp.Diagnostics, m)
	addNTPVmICWarning(&resp.Diagnostics, live)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place time-source changes. Like Create it funnels into
// Set; the restore snapshot captured at Create time is left untouched
// (restore always returns to the pre-existing values, not to the previous
// plan).
func (r *windowsNTPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsNTPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsNTPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, ntpDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	in, diags := ntpModelToInput(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating Windows NTP time source", map[string]any{
		"type": in.Type,
	})

	live, err := r.ntp.Set(ctx, in)
	if err != nil {
		addNTPDiag(&resp.Diagnostics, "Error updating Windows NTP time source", err)
		return
	}

	maybeWarnNTPResync(&resp.Diagnostics, live)

	m, diags := ntpStateToModel(live, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	addNTPStateWarnings(&resp.Diagnostics, m)
	addNTPVmICWarning(&resp.Diagnostics, live)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the resource from state. By default it makes no remote
// change (the host always has a time source). With restore_on_destroy it
// re-applies the snapshot captured at Create (or import) time without
// resyncing; when no snapshot exists it warns and leaves the host
// untouched rather than guessing.
func (r *windowsNTPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsNTPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, ntpDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	tflog.Debug(ctx, "Deleting Windows NTP time source", map[string]any{
		"type":               state.Type.ValueString(),
		"restore_on_destroy": state.RestoreOnDestroy.ValueBool(),
	})

	if !state.RestoreOnDestroy.ValueBool() {
		return
	}

	snap, ok := getNTPSnapshot(ctx, req.Private.GetKey)
	if !ok {
		resp.Diagnostics.AddWarning(
			"NTP restore skipped: no snapshot",
			"restore_on_destroy is set, but the pre-existing snapshot of the W32Time time source could not be read "+
				"(it may be corrupt or from an incompatible version). Leaving the host untouched.",
		)
		return
	}
	if snap == nil {
		resp.Diagnostics.AddWarning(
			"NTP restore skipped: no snapshot",
			"restore_on_destroy is set, but no pre-existing snapshot of the W32Time time source was captured "+
				"(the resource may predate snapshotting or the snapshot was lost). Leaving the host untouched.",
		)
		return
	}

	in, diags := ntpSnapshotToInput(snap, state.ManageService.ValueBool())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	restored, err := r.ntp.Set(ctx, in)
	if err != nil {
		addNTPDiag(&resp.Diagnostics, "Error restoring Windows NTP time source", err)
		return
	}
	maybeWarnNTPResync(&resp.Diagnostics, restored)
	addNTPStateWarnings(&resp.Diagnostics, mustNTPStateToModel(&resp.Diagnostics, restored, state))
	addNTPVmICWarning(&resp.Diagnostics, restored)
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts the live W32Time time source: any non-empty import ID
// is accepted and ignored (the time source is a singleton), the observed
// values become the snapshot for a later restore_on_destroy.
func (r *windowsNTPResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if strings.TrimSpace(req.ID) == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			"Import requires a non-empty ID (its value is ignored; the live W32Time time source is adopted). For example: terraform import windows_ntp.this current",
		)
		return
	}

	tflog.Debug(ctx, "Importing Windows NTP time source (singleton: live time source is adopted)")

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, ntpDefaultTimeout)
	defer cancel()

	live, err := r.ntp.Read(ctx)
	if err != nil {
		addNTPDiag(&resp.Diagnostics, "Error importing Windows NTP time source", err)
		return
	}

	if err := setNTPSnapshot(ctx, resp.Private.SetKey, live); err != nil {
		addNTPDiag(&resp.Diagnostics, "Error capturing pre-existing Windows NTP state", err)
		return
	}

	m, diags := ntpStateToModel(live, windowsNTPModel{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by the framework on State.Set — use a typed
	// null instead (the subsequent Read fills in the configured values).
	m.Timeouts = ntpNullTimeouts()
	m.ManageService = types.BoolValue(true)
	m.ResyncOnApply = types.BoolValue(true)
	m.RestoreOnDestroy = types.BoolValue(false)
	addNTPStateWarnings(&resp.Diagnostics, m)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------------------------------------------------------------------------
// Helper: modelToInput / snapshotToInput
// ---------------------------------------------------------------------------

// ntpModelToInput converts a Terraform plan to an NTPInput delta: null or
// unknown attributes stay nil and are never written. Unknowns arise on
// first plan for Optional+Computed attributes; the post-apply Read fills
// the state.
func ntpModelToInput(ctx context.Context, m windowsNTPModel) (winclient.NTPInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	in := winclient.NTPInput{
		Type:          m.Type.ValueString(),
		ManageService: m.ManageService.ValueBool(),
		ResyncOnApply: m.ResyncOnApply.ValueBool(),
	}
	if !m.Servers.IsNull() && !m.Servers.IsUnknown() {
		var elems []windowsNTPServerModel
		diags.Append(m.Servers.ElementsAs(ctx, &elems, false)...)
		if diags.HasError() {
			return in, diags
		}
		for _, e := range elems {
			flags := e.Flags.ValueString()
			if e.Flags.IsNull() || e.Flags.IsUnknown() {
				flags = winclient.DefaultNTPPeerFlags
			}
			in.Servers = append(in.Servers, winclient.NTPPeer{
				Address: e.Address.ValueString(),
				Flags:   flags,
			})
		}
	}
	if !m.SpecialPollIntervalSeconds.IsNull() && !m.SpecialPollIntervalSeconds.IsUnknown() {
		v := m.SpecialPollIntervalSeconds.ValueInt64()
		in.SpecialPollIntervalSeconds = &v
	}
	if !m.Reliable.IsNull() && !m.Reliable.IsUnknown() {
		v := m.Reliable.ValueBool()
		in.Reliable = &v
	}
	if !m.NtpServerEnabled.IsNull() && !m.NtpServerEnabled.IsUnknown() {
		v := m.NtpServerEnabled.ValueBool()
		in.NtpServerEnabled = &v
	}
	if !m.MaxPosPhaseCorrectionSeconds.IsNull() && !m.MaxPosPhaseCorrectionSeconds.IsUnknown() {
		v := m.MaxPosPhaseCorrectionSeconds.ValueInt64()
		in.MaxPosPhaseCorrectionSeconds = &v
	}
	if !m.MaxNegPhaseCorrectionSeconds.IsNull() && !m.MaxNegPhaseCorrectionSeconds.IsUnknown() {
		v := m.MaxNegPhaseCorrectionSeconds.ValueInt64()
		in.MaxNegPhaseCorrectionSeconds = &v
	}
	return in, diags
}

// ntpSnapshotToInput converts a captured snapshot into a verbatim restore
// input: every snapshot field is set (including the raw AnnounceFlags
// DWORD, which wins over the Reliable mapping), resync stays off
// (delete-time restore never resyncs) and the service ensure honours the
// resource's manage_service intent. DWORD fields are range-checked
// (0..4294967295) before rendering so a corrupt snapshot fails closed
// instead of reaching Set-ItemProperty.
func ntpSnapshotToInput(snap *winclient.NTPState, manageService bool) (winclient.NTPInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	const maxDWORD = int64(4294967295)
	rangeErr := func(name string, v int64) {
		diags.AddError(
			"Invalid NTP restore snapshot",
			fmt.Sprintf("Cannot restore the pre-existing W32Time state: %s %d is out of range (must be between 0 and %d). Leaving the host untouched.", name, v, maxDWORD),
		)
	}
	if snap.AnnounceFlags < 0 || snap.AnnounceFlags > maxDWORD {
		rangeErr("AnnounceFlags", snap.AnnounceFlags)
	}
	if snap.SpecialPollIntervalSeconds < 0 || snap.SpecialPollIntervalSeconds > maxDWORD {
		rangeErr("SpecialPollInterval", snap.SpecialPollIntervalSeconds)
	}
	if snap.MaxPosPhaseCorrectionSeconds < 0 || snap.MaxPosPhaseCorrectionSeconds > maxDWORD {
		rangeErr("MaxPosPhaseCorrection", snap.MaxPosPhaseCorrectionSeconds)
	}
	if snap.MaxNegPhaseCorrectionSeconds < 0 || snap.MaxNegPhaseCorrectionSeconds > maxDWORD {
		rangeErr("MaxNegPhaseCorrection", snap.MaxNegPhaseCorrectionSeconds)
	}
	if diags.HasError() {
		return winclient.NTPInput{}, diags
	}
	announce := snap.AnnounceFlags
	poll := snap.SpecialPollIntervalSeconds
	serverEnabled := snap.NtpServerEnabled
	maxPos := snap.MaxPosPhaseCorrectionSeconds
	maxNeg := snap.MaxNegPhaseCorrectionSeconds
	return winclient.NTPInput{
		Type:                         snap.Type,
		Servers:                      snap.Servers,
		SpecialPollIntervalSeconds:   &poll,
		AnnounceFlags:                &announce,
		NtpServerEnabled:             &serverEnabled,
		MaxPosPhaseCorrectionSeconds: &maxPos,
		MaxNegPhaseCorrectionSeconds: &maxNeg,
		ManageService:                manageService,
		ResyncOnApply:                false,
	}, diags
}

// ---------------------------------------------------------------------------
// Helper: stateToModel
// ---------------------------------------------------------------------------

// ntpTimeoutsOpts declares which per-operation timeouts the resource exposes.
var ntpTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// ntpNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func ntpNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if ntpTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if ntpTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if ntpTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if ntpTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// ntpServersToListValue projects observed peers onto a Terraform list value
// (empty list, never null, when the host carries no peers).
func ntpServersToListValue(servers []winclient.NTPPeer) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := ntpServerElementObjectType()
	if len(servers) == 0 {
		lv, d := types.ListValue(elemType, []attr.Value{})
		diags.Append(d...)
		return lv, diags
	}
	vals := make([]attr.Value, 0, len(servers))
	for _, p := range servers {
		obj, d := types.ObjectValue(ntpServerElementAttrTypes(), map[string]attr.Value{
			"address": types.StringValue(p.Address),
			"flags":   types.StringValue(p.Flags),
		})
		diags.Append(d...)
		vals = append(vals, obj)
	}
	lv, d := types.ListValue(elemType, vals)
	diags.Append(d...)
	return lv, diags
}

// ntpStateToModel projects an observed NTPState into a Terraform model.
// Every managed attribute reflects the observed value (the plan was unknown
// for unconfigured Computed attributes), while current_source,
// policy_override and domain_joined are informational and never diffed.
// The input-only intent (manage_service, resync_on_apply,
// restore_on_destroy), the user-configured timeouts and the resource ID
// anchor are preserved from the prior plan/state across the projection
// (Set overwrites the full state object).
func ntpStateToModel(state *winclient.NTPState, prior windowsNTPModel) (windowsNTPModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	servers, d := ntpServersToListValue(state.Servers)
	diags.Append(d...)
	if diags.HasError() {
		return windowsNTPModel{}, diags
	}
	id := types.StringValue(state.MachineID)
	if state.MachineID == "" {
		// The host must always report a MachineGuid. If it ever goes
		// missing mid-life, keep the anchored ID rather than writing an
		// empty one Terraform forbids; with no prior ID (Create with an
		// unreadable MachineGuid) fall back to the singleton literal,
		// mirroring the windows_ntp data source.
		if !prior.ID.IsNull() && !prior.ID.IsUnknown() && prior.ID.ValueString() != "" {
			id = prior.ID
		} else {
			id = types.StringValue("current")
		}
	}
	manage := prior.ManageService
	if manage.IsNull() || manage.IsUnknown() {
		manage = types.BoolValue(true)
	}
	resync := prior.ResyncOnApply
	if resync.IsNull() || resync.IsUnknown() {
		resync = types.BoolValue(true)
	}
	restore := prior.RestoreOnDestroy
	if restore.IsNull() || restore.IsUnknown() {
		restore = types.BoolValue(false)
	}
	return windowsNTPModel{
		ID:                           id,
		Type:                         types.StringValue(state.Type),
		Servers:                      servers,
		SpecialPollIntervalSeconds:   types.Int64Value(state.SpecialPollIntervalSeconds),
		Reliable:                     types.BoolValue(state.Reliable),
		NtpServerEnabled:             types.BoolValue(state.NtpServerEnabled),
		MaxPosPhaseCorrectionSeconds: types.Int64Value(state.MaxPosPhaseCorrectionSeconds),
		MaxNegPhaseCorrectionSeconds: types.Int64Value(state.MaxNegPhaseCorrectionSeconds),
		ManageService:                manage,
		ResyncOnApply:                resync,
		RestoreOnDestroy:             restore,
		CurrentSource:                types.StringValue(state.CurrentSource),
		PolicyOverride:               types.BoolValue(state.PolicyOverride),
		DomainJoined:                 types.BoolValue(state.DomainJoined),
		Timeouts:                     prior.Timeouts,
	}, diags
}

// mustNTPStateToModel is the Delete-path projection: diagnostics are
// appended to the response directly since Delete has no model to return.
func mustNTPStateToModel(diags *diag.Diagnostics, state *winclient.NTPState, prior windowsNTPModel) windowsNTPModel {
	m, d := ntpStateToModel(state, prior)
	diags.Append(d...)
	return m
}

// ---------------------------------------------------------------------------
// Helper: warnings
// ---------------------------------------------------------------------------

// maybeWarnNTPResync surfaces a non-fatal w32tm /resync failure recorded
// on the returned state as a warning (the peer may be unreachable at apply
// time; the registry configuration itself applied and verified cleanly).
func maybeWarnNTPResync(diags *diag.Diagnostics, state *winclient.NTPState) {
	if state == nil || strings.TrimSpace(state.ResyncWarning) == "" {
		return
	}
	diags.AddWarning(
		"Time resynchronisation failed (warning only)",
		fmt.Sprintf("The W32Time configuration was applied and verified, but w32tm /resync /rediscover reported: %s. "+
			"The host will converge to the configured peers on its next poll; re-apply once the peers are reachable to resync immediately.",
			strings.TrimSpace(state.ResyncWarning)),
	)
}

// addNTPStateWarnings surfaces advisory (never blocking) diagnostics after
// a successful operation:
//
//   - Domain-joined hosts with a type other than NT5DS break the domain
//     time hierarchy (unless this host is the PDC emulator holding the
//     domain time source role).
//   - A Group Policy override means the GPO value wins at the next policy
//     refresh and Terraform-managed values may diverge.
//   - An enabled Hyper-V time-sync provider (VMICTimeProvider) can fight
//     NTP for the guest clock.
//   - An enabled NTP server role needs UDP/123 reachable from its clients
//     (see windows_firewall_rule).
func addNTPStateWarnings(diags *diag.Diagnostics, m windowsNTPModel) {
	if m.DomainJoined.ValueBool() && m.Type.ValueString() != winclient.NTPTypeNT5DS {
		diags.AddWarning(
			"Domain-joined host not using domain time hierarchy",
			fmt.Sprintf("The host is joined to an Active Directory domain but type is %q instead of NT5DS. "+
				"Domain members are expected to sync from the domain hierarchy; use a peer-based type only on the PDC emulator "+
				"(or a host intentionally decoupled from domain time).",
				m.Type.ValueString()),
		)
	}
	if m.PolicyOverride.ValueBool() {
		diags.AddWarning(
			"Group Policy manages W32Time",
			"HKLM\\SOFTWARE\\Policies\\Microsoft\\W32Time\\Parameters carries Type or NtpServer for this host. "+
				"The Group Policy value wins at the next policy refresh, which can undo the Terraform-managed settings.",
		)
	}
	if m.NtpServerEnabled.ValueBool() {
		diags.AddWarning(
			"NTP server role enabled",
			"This host now answers NTP requests. Ensure UDP/123 is reachable from its NTP clients "+
				"(see the windows_firewall_rule resource); otherwise the role has no effect.",
		)
	}
}

// addNTPVmICWarning surfaces the Hyper-V time-sync provider advisory. It
// takes the winclient state directly because VmICEnabled is a
// warning-only signal with no Terraform attribute.
func addNTPVmICWarning(diags *diag.Diagnostics, state *winclient.NTPState) {
	if state == nil || !state.VmICEnabled {
		return
	}
	diags.AddWarning(
		"Hyper-V time synchronisation is enabled",
		"The Hyper-V time-sync provider (VMICTimeProvider) is enabled on this guest and can fight NTP for the guest clock. "+
			"On generation-2 VMs managed by this provider, consider disabling host time sync for stable NTP convergence.",
	)
}

// ---------------------------------------------------------------------------
// Helper: private-state snapshot
// ---------------------------------------------------------------------------

// setNTPSnapshot stores the pre-existing W32Time state as JSON in private
// state so Delete with restore_on_destroy can re-apply it. setKey is a
// closure over the response Private data (kept injectable so unit tests can
// capture the snapshot without framework internals).
func setNTPSnapshot(ctx context.Context, setKey func(context.Context, string, []byte) diag.Diagnostics, st *winclient.NTPState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	diags := setKey(ctx, ntpPrivateKey, raw)
	if diags.HasError() {
		return errors.New(diagsToString(diags))
	}
	return nil
}

// getNTPSnapshot reads the snapshot back. A nil snapshot with a true
// return means "no snapshot captured". getKey is a closure over the request
// Private data.
func getNTPSnapshot(ctx context.Context, getKey func(context.Context, string) ([]byte, diag.Diagnostics)) (*winclient.NTPState, bool) {
	raw, diags := getKey(ctx, ntpPrivateKey)
	if diags.HasError() {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, true
	}
	var st winclient.NTPState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, false
	}
	return &st, true
}

// ---------------------------------------------------------------------------
// Helper: addNTPDiag
// ---------------------------------------------------------------------------

// addNTPDiag appends a diagnostic from an NTP client error, enriching it
// with context fields when available.
func addNTPDiag(d *diag.Diagnostics, summary string, err error) {
	var ne *winclient.NTPError
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
