// Package provider - resource_windows_iis_binding implements the full
// Terraform resource lifecycle for windows_iis_binding.
//
// One IIS binding on one site (New-WebBinding -SslFlags /
// Remove-WebBinding, AddSslCertificate / RemoveSslCertificate for the
// certificate pair, Start-Website when the site's serverAutoStart asks for
// it). The binding identity is "<site>|<protocol>|<bindingInformation>"
// (bindingInformation is "IP:port:hostheader", e.g. "*:443:example.com").
//
// site_name, protocol, ip_address, port and host_header are Required (or
// defaulted) and ForceNew: they identify the listener. require_sni,
// certificate_thumbprint and certificate_store_name are updated in place
// (remove plus re-add in one script). An SSH-port lockout guard refuses to
// bind the management port (provider port plus probed ManagementPath
// ServerPort) fail-closed with would_lock_out before anything is applied.
//
// Spec alignment: windows_iis_binding spec v1 (issue #285).
// Framework:      terraform-plugin-framework v1.19.0.
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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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
	_ resource.Resource                     = (*windowsIISBindingResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsIISBindingResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsIISBindingResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsIISBindingResource)(nil)
)

// NewWindowsIISBindingResource is the constructor registered in provider.go.
func NewWindowsIISBindingResource() resource.Resource {
	return &windowsIISBindingResource{}
}

// windowsIISBindingResource is the TPF resource type for windows_iis_binding.
type windowsIISBindingResource struct {
	binding winclient.WindowsIISBindingClient
}

// iisBindingDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Binding operations are
// normally fast, but a stalled PowerShell/SSH session must never block
// Terraform forever: every CRUD handler bounds its work with this default.
const iisBindingDefaultTimeout = 10 * time.Minute

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsIISBindingModel is the Terraform state/plan model for
// windows_iis_binding. Every tfsdk tag matches an attribute key in
// windowsIISBindingSchemaDefinition.
type windowsIISBindingModel struct {
	ID                    types.String   `tfsdk:"id"`
	SiteName              types.String   `tfsdk:"site_name"`
	Protocol              types.String   `tfsdk:"protocol"`
	IPAddress             types.String   `tfsdk:"ip_address"`
	Port                  types.Int64    `tfsdk:"port"`
	HostHeader            types.String   `tfsdk:"host_header"`
	RequireSNI            types.Bool     `tfsdk:"require_sni"`
	CertificateThumbprint types.String   `tfsdk:"certificate_thumbprint"`
	CertificateStoreName  types.String   `tfsdk:"certificate_store_name"`
	BindingInformation    types.String   `tfsdk:"binding_information"`
	Timeouts              timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsIISBindingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iis_binding"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_iis_binding resource.
func (r *windowsIISBindingResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsIISBindingSchemaDefinition(ctx)
}

// windowsIISBindingSchemaDefinition returns the complete TPF schema for
// windows_iis_binding. The identity attributes (site_name, protocol,
// ip_address, port, host_header) are ForceNew; require_sni,
// certificate_thumbprint and certificate_store_name are updated in place;
// binding_information is Computed (the canonical "IP:port:hostheader").
func windowsIISBindingSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages one IIS binding on a site on a remote Windows host via SSH and PowerShell " +
			"(`WebAdministration` module: `New-WebBinding -SslFlags`, `Remove-WebBinding`, `AddSslCertificate` / " +
			"`RemoveSslCertificate`, `Start-Website`).\n\n" +
			"The binding identity is `<site>|<protocol>|<bindingInformation>` (`bindingInformation` is " +
			"`IP:port:hostheader`, e.g. `*:443:example.com`). `site_name`, `protocol`, `ip_address`, `port` " +
			"and `host_header` identify the listener and are immutable after creation (ForceNew); `require_sni`, " +
			"`certificate_thumbprint` and `certificate_store_name` are updated in place (the binding is removed " +
			"and re-added with the new certificate/SNI pair in one script).\n\n" +
			"`certificate_thumbprint` and `require_sni` need `protocol = \"https\"`; `require_sni = true` " +
			"additionally needs a `host_header` (SNI selects the certificate by server name). Certificates live " +
			"in `Cert:\\LocalMachine\\<store>` and are managed by `windows_certificate` — they are never created " +
			"implicitly, and a certificate without a private key is refused.\n\n" +
			"Safety: creating a binding on the SSH management port is refused fail-closed (`would_lock_out`): " +
			"binding HTTP.sys to the port the provider's own session arrived on risks cutting the management " +
			"connection.\n\n" +
			"Requires IIS on the target host: install it with the `windows_feature` resource (`Web-Server`; " +
			"add `Web-Mgmt-Console` / `Web-Scripting-Tools` for the `WebAdministration` module on Server Core).\n\n" +
			"Import format: `<site>|<protocol>|<bindingInformation>` (e.g. `web|https|*:443:example.com`).",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier: `<site>|<protocol>|<bindingInformation>`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"site_name": schema.StringAttribute{
				Required: true,
				Description: "Owning IIS site. 1-64 characters; must not contain `/ \\ [ ] : ; , ? * \" < > |` " +
					"and must not have leading or trailing spaces. The site must already exist (manage it with " +
					"`windows_iis_site`); it is never created implicitly. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					iisSiteNameValidator{},
				},
			},

			"protocol": schema.StringAttribute{
				Required:    true,
				Description: "Binding protocol. One of `http`, `https`. Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("http", "https"),
				},
			},

			"ip_address": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("*"),
				Description: "IP address to listen on (`\"*\"` listens on all unassigned addresses; zone IDs are rejected). The configured spelling is preserved in state; the canonical form (`netip`: lower-case, compressed IPv6) appears in `binding_information` and `id`. Immutable after creation (ForceNew). Defaults to `\"*\"`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					iisBindingIPAddressValidator{},
				},
			},

			"port": schema.Int64Attribute{
				Required:    true,
				Description: "Port to listen on (1-65535). Binding the SSH management port is refused fail-closed (`would_lock_out`). Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.Between(1, 65535),
				},
			},

			"host_header": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Host header (server name). Empty means the catch-all binding. Must not contain `|`, `:` or whitespace. Required when `require_sni` is true. The configured spelling is preserved in state; the lower-case canonical form appears in `binding_information` and `id`. Immutable after creation (ForceNew). Defaults to `\"\"`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					iisBindingHostHeaderValidator{},
				},
			},

			"require_sni": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Whether the binding requires Server Name Indication (`SslFlags` bit 0). Needs `protocol = \"https\"` and a non-empty `host_header`. Updated in place. Defaults to `false`.",
			},

			"certificate_thumbprint": schema.StringAttribute{
				Optional:    true,
				Description: "Thumbprint of the certificate to bind (`Cert:\\LocalMachine\\<store>`). 40 hex characters (spaces allowed, case-insensitive). Needs `protocol = \"https\"`. The certificate must already exist (manage it with `windows_certificate`) and carry a private key. Omit (null) for no certificate. Updated in place. The configured spelling is preserved in state while it matches the bound certificate; an out-of-band change surfaces the observed canonical thumbprint (upper-case without spaces).",
				Validators: []validator.String{
					iisBindingThumbprintValidator{},
				},
			},

			"certificate_store_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("My"),
				Description: "LocalMachine store holding the certificate. One of `My`, `WebHosting`. Only meaningful alongside `certificate_thumbprint`. Updated in place. Defaults to `My`.",
				Validators: []validator.String{
					stringvalidator.OneOf("My", "WebHosting"),
				},
			},

			"binding_information": schema.StringAttribute{
				Computed:    true,
				Description: "Canonical binding information (`IP:port:hostheader`, e.g. `*:443:example.com`; IPv6 addresses are bracketed).",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// iisBindingDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, iisBindingTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// iisBindingIPAddressValidator accepts "*" or a parseable IP address
// without a zone ID at plan time (canonicalisation happens in the CRUD
// handlers via winclient.NormalizeIISBindingIPAddress).
type iisBindingIPAddressValidator struct{}

func (v iisBindingIPAddressValidator) Description(_ context.Context) string {
	return "IP address must be \"*\" or a valid IPv4/IPv6 address without a zone ID."
}

func (v iisBindingIPAddressValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisBindingIPAddressValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := req.ConfigValue.ValueString()
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "*" {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid IP address",
			fmt.Sprintf("ip_address must be \"*\" or a valid IPv4/IPv6 address; got %q.", raw),
		)
		return
	}
	if zone := addr.Zone(); zone != "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid IP address",
			fmt.Sprintf("ip_address must not carry a zone ID (%q); got %q.", zone, raw),
		)
	}
}

// iisBindingHostHeaderValidator mirrors
// winclient.ValidateIISBindingHostHeader at plan time: the header is the
// last bindingInformation segment and the import-ID-safe alphabet, so "|",
// ":" and whitespace are rejected.
type iisBindingHostHeaderValidator struct{}

func (v iisBindingHostHeaderValidator) Description(_ context.Context) string {
	return "Host header must not contain \"|\", \":\" or whitespace."
}

func (v iisBindingHostHeaderValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisBindingHostHeaderValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	if err := winclient.ValidateIISBindingHostHeader(val); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid host header", err.Error())
	}
}

// iisBindingThumbprintValidator accepts a 40-hex thumbprint (spaces
// tolerated, case-insensitive) at plan time. Null, unknown and empty
// values mean "no certificate" and are skipped.
type iisBindingThumbprintValidator struct{}

func (v iisBindingThumbprintValidator) Description(_ context.Context) string {
	return "Certificate thumbprint must be 40 hex characters (spaces allowed)."
}

func (v iisBindingThumbprintValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisBindingThumbprintValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.TrimSpace(req.ConfigValue.ValueString()) == "" {
		return
	}
	if _, err := winclient.NormalizeIISBindingThumbprint(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid certificate thumbprint", err.Error())
	}
}

// iisBindingConfigValidator cross-checks the https-only matrix at plan
// time: certificate_thumbprint and require_sni need protocol https, and
// require_sni additionally needs a host header (SNI selects the
// certificate by server name). Unknown values defer to the client-side
// ValidateIISBindingInput check instead of erroring early.
type iisBindingConfigValidator struct{}

func (v iisBindingConfigValidator) Description(_ context.Context) string {
	return "Validates that certificate_thumbprint and require_sni are only set for https bindings, and that require_sni has a host header."
}

func (v iisBindingConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v iisBindingConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var protocol types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("protocol"), &protocol)...)
	var requireSNI types.Bool
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("require_sni"), &requireSNI)...)
	var hostHeader types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("host_header"), &hostHeader)...)
	var thumbprint types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("certificate_thumbprint"), &thumbprint)...)
	var storeName types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("certificate_store_name"), &storeName)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if protocol.IsNull() || protocol.IsUnknown() {
		return
	}
	proto := strings.ToLower(strings.TrimSpace(protocol.ValueString()))
	thumbSet := !thumbprint.IsNull() && !thumbprint.IsUnknown() && strings.TrimSpace(thumbprint.ValueString()) != ""
	if !thumbSet && !storeName.IsNull() && !storeName.IsUnknown() {
		if canon, err := winclient.CanonicalizeIISBindingStoreName(storeName.ValueString()); err == nil && canon != winclient.IISBindingStoreMy {
			resp.Diagnostics.AddAttributeWarning(path.Root("certificate_store_name"), "certificate_store_name without a certificate",
				fmt.Sprintf("certificate_store_name = %q is ignored without certificate_thumbprint (no certificate is bound, so the store carries no host meaning); omit it or set certificate_thumbprint.", storeName.ValueString()))
		}
	}
	if thumbSet && proto != winclient.IISBindingProtocolHTTPS {
		resp.Diagnostics.AddAttributeError(path.Root("certificate_thumbprint"), "certificate_thumbprint needs https",
			fmt.Sprintf("certificate_thumbprint requires protocol = \"https\" (SNI certificates cannot ride a clear-text binding); got protocol %q.", protocol.ValueString()))
	}
	if requireSNI.IsNull() || requireSNI.IsUnknown() {
		return
	}
	if !requireSNI.ValueBool() {
		return
	}
	if proto != winclient.IISBindingProtocolHTTPS {
		resp.Diagnostics.AddAttributeError(path.Root("require_sni"), "require_sni needs https",
			fmt.Sprintf("require_sni requires protocol = \"https\"; got protocol %q.", protocol.ValueString()))
		return
	}
	if hostHeader.IsNull() || hostHeader.IsUnknown() {
		return
	}
	if strings.TrimSpace(hostHeader.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("require_sni"), "require_sni needs a host header",
			"require_sni = true requires a non-empty host_header: SNI selects the certificate by server name.")
	}
}

// ConfigValidators returns the resource-level cross-field validators.
func (r *windowsIISBindingResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		iisBindingConfigValidator{},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates an
// IISBindingClient for this resource instance.
func (r *windowsIISBindingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := configuredClient(req.ProviderData, &resp.Diagnostics)
	if c == nil {
		return
	}
	r.binding = winclient.NewIISBindingClient(c)
}

// ---------------------------------------------------------------------------
// Helpers: canonicalisation, input projection, state projection
// ---------------------------------------------------------------------------

// canonicalIISBindingPlan resolves the configured identity fields to their
// canonical forms: lower-case protocol, netip IP ("*" stays "*"),
// lower-case host, validated port. Attribute validators already enforce
// the shapes; errors here surface as attribute diagnostics.
func canonicalIISBindingPlan(m windowsIISBindingModel) (protocol, ip, host string, port int64, diags diag.Diagnostics) {
	protocol, err := winclient.CanonicalizeIISBindingProtocol(m.Protocol.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("protocol"), "Invalid protocol", err.Error())
		return "", "", "", 0, diags
	}
	ip, err = winclient.NormalizeIISBindingIPAddress(m.IPAddress.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("ip_address"), "Invalid IP address", err.Error())
		return "", "", "", 0, diags
	}
	host = winclient.NormalizeIISBindingHostHeader(m.HostHeader.ValueString())
	if err := winclient.ValidateIISBindingHostHeader(m.HostHeader.ValueString()); err != nil {
		diags.AddAttributeError(path.Root("host_header"), "Invalid host header", err.Error())
		return "", "", "", 0, diags
	}
	port = m.Port.ValueInt64()
	if err := winclient.ValidateIISBindingPort(port); err != nil {
		diags.AddAttributeError(path.Root("port"), "Invalid port", err.Error())
		return "", "", "", 0, diags
	}
	return protocol, ip, host, port, diags
}

// modelToIISBindingCreateInput converts a Terraform plan model to an
// IISBindingInput for Create: null/unknown in-place attributes stay nil
// and are never sent to the host.
func modelToIISBindingCreateInput(m windowsIISBindingModel, protocol, ip, host string, port int64) winclient.IISBindingInput {
	in := winclient.IISBindingInput{
		SiteName:             m.SiteName.ValueString(),
		Protocol:             protocol,
		IPAddress:            ip,
		Port:                 port,
		HostHeader:           host,
		CertificateStoreName: winclient.IISBindingStoreMy,
	}
	if !m.RequireSNI.IsNull() && !m.RequireSNI.IsUnknown() {
		v := m.RequireSNI.ValueBool()
		in.RequireSNI = &v
	}
	if !m.CertificateThumbprint.IsNull() && !m.CertificateThumbprint.IsUnknown() &&
		strings.TrimSpace(m.CertificateThumbprint.ValueString()) != "" {
		if norm, err := winclient.NormalizeIISBindingThumbprint(m.CertificateThumbprint.ValueString()); err == nil {
			in.CertificateThumbprint = &norm
		} else {
			raw := strings.TrimSpace(m.CertificateThumbprint.ValueString())
			in.CertificateThumbprint = &raw
		}
		if !m.CertificateStoreName.IsNull() && !m.CertificateStoreName.IsUnknown() {
			if canon, err := winclient.CanonicalizeIISBindingStoreName(m.CertificateStoreName.ValueString()); err == nil {
				in.CertificateStoreName = canon
			}
		}
	}
	return in
}

// iisBindingInPlaceChanged reports whether any in-place attribute
// (require_sni, certificate_thumbprint, certificate_store_name) differs
// between plan and prior state.
func iisBindingInPlaceChanged(plan, prior windowsIISBindingModel) bool {
	if !plan.RequireSNI.Equal(prior.RequireSNI) {
		return true
	}
	planThumb := ""
	if !plan.CertificateThumbprint.IsNull() && !plan.CertificateThumbprint.IsUnknown() {
		if norm, err := winclient.NormalizeIISBindingThumbprint(plan.CertificateThumbprint.ValueString()); err == nil {
			planThumb = norm
		} else {
			planThumb = strings.TrimSpace(plan.CertificateThumbprint.ValueString())
		}
	}
	priorThumb := ""
	if !prior.CertificateThumbprint.IsNull() {
		priorThumb = strings.TrimSpace(prior.CertificateThumbprint.ValueString())
	}
	if planThumb != priorThumb {
		return true
	}
	// The store only matters while a certificate is bound: an empty
	// effective thumbprint on both sides means "no certificate", and a
	// store-only drift then carries no host meaning.
	if planThumb != "" && !plan.CertificateStoreName.Equal(prior.CertificateStoreName) {
		return true
	}
	return false
}

// modelToIISBindingUpdateInput builds the Update input from plan and prior
// state. Untouched in-place attributes inherit the observed prior values
// so the remove plus re-add round-trips the live certificate instead of
// dropping it; an explicit null thumbprint removes the certificate ("").
func modelToIISBindingUpdateInput(plan, prior windowsIISBindingModel, protocol, ip, host string, port int64) winclient.IISBindingInput {
	in := winclient.IISBindingInput{
		SiteName:             plan.SiteName.ValueString(),
		Protocol:             protocol,
		IPAddress:            ip,
		Port:                 port,
		HostHeader:           host,
		CertificateStoreName: winclient.IISBindingStoreMy,
	}
	if !plan.RequireSNI.IsUnknown() {
		if plan.RequireSNI.IsNull() {
			if !prior.RequireSNI.IsNull() && !prior.RequireSNI.IsUnknown() {
				v := prior.RequireSNI.ValueBool()
				in.RequireSNI = &v
			}
		} else {
			v := plan.RequireSNI.ValueBool()
			in.RequireSNI = &v
		}
	}
	switch {
	case plan.CertificateThumbprint.IsUnknown():
		if !prior.CertificateThumbprint.IsNull() {
			v := strings.TrimSpace(prior.CertificateThumbprint.ValueString())
			in.CertificateThumbprint = &v
		}
	case plan.CertificateThumbprint.IsNull():
		if prior.CertificateThumbprint.IsNull() || strings.TrimSpace(prior.CertificateThumbprint.ValueString()) == "" {
			in.CertificateThumbprint = nil
		} else {
			empty := ""
			in.CertificateThumbprint = &empty
		}
	default:
		if norm, err := winclient.NormalizeIISBindingThumbprint(plan.CertificateThumbprint.ValueString()); err == nil {
			in.CertificateThumbprint = &norm
		} else {
			raw := strings.TrimSpace(plan.CertificateThumbprint.ValueString())
			in.CertificateThumbprint = &raw
		}
	}
	store := plan.CertificateStoreName
	if store.IsNull() || store.IsUnknown() {
		store = prior.CertificateStoreName
	}
	if !store.IsNull() && !store.IsUnknown() {
		if canon, err := winclient.CanonicalizeIISBindingStoreName(store.ValueString()); err == nil {
			in.CertificateStoreName = canon
		}
	}
	return in
}

// iisBindingTimeoutsOpts declares which per-operation timeouts the resource exposes.
var iisBindingTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// iisBindingNullTimeouts returns a null timeouts value carrying the
// schema's attribute types. The zero timeouts.Value wraps an object with NO
// attribute types, which the framework rejects on State.Set — the failure
// mode on import, where there is no prior state to copy the value from.
func iisBindingNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if iisBindingTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if iisBindingTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if iisBindingTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if iisBindingTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// iisBindingPreserveIPSpelling keeps the configured ip_address spelling in
// state while it denotes the observed listener (netip normalisation), and
// surfaces the observed canonical address otherwise. Identity attributes
// cannot drift in place: a host-side change is a different binding, the
// Read-by-ID lookup misses, and the resource is dropped from state.
func iisBindingPreserveIPSpelling(plan types.String, observed string) types.String {
	if plan.IsNull() || plan.IsUnknown() {
		return types.StringValue(observed)
	}
	if norm, err := winclient.NormalizeIISBindingIPAddress(plan.ValueString()); err == nil && norm == observed {
		return plan
	}
	return types.StringValue(observed)
}

// iisBindingPreserveHostSpelling keeps the configured host_header spelling
// in state while it lower-cases to the observed header, and surfaces the
// observed header otherwise (same identity reasoning as
// iisBindingPreserveIPSpelling).
func iisBindingPreserveHostSpelling(plan types.String, observed string) types.String {
	if plan.IsNull() || plan.IsUnknown() {
		return types.StringValue(observed)
	}
	if winclient.NormalizeIISBindingHostHeader(plan.ValueString()) == observed {
		return plan
	}
	return types.StringValue(observed)
}

// iisBindingProjectThumbprint resolves the in-place certificate_thumbprint
// for state: the configured spelling is kept while it matches the bound
// certificate (hex-normalised comparison, so case/spacing differences are
// not drift); a genuine out-of-band change surfaces the observed canonical
// thumbprint (upper-case without spaces) so the next plan reconciles it,
// and an empty host side projects to null ("no certificate"). A null or
// empty plan with a bound certificate is itself drift (someone bound a
// certificate out-of-band) and surfaces the observed value.
func iisBindingProjectThumbprint(plan types.String, observed string) types.String {
	obsNorm, obsErr := winclient.NormalizeIISBindingThumbprint(observed)
	if plan.IsUnknown() {
		if obsErr != nil {
			return types.StringNull()
		}
		return types.StringValue(obsNorm)
	}
	if plan.IsNull() || strings.TrimSpace(plan.ValueString()) == "" {
		if obsErr != nil {
			return types.StringNull()
		}
		return types.StringValue(obsNorm)
	}
	planNorm, planErr := winclient.NormalizeIISBindingThumbprint(plan.ValueString())
	if planErr != nil || obsErr != nil || planNorm != obsNorm {
		if obsErr != nil {
			return types.StringNull()
		}
		return types.StringValue(obsNorm)
	}
	return plan
}

// iisBindingStateToModel projects an observed IISBindingState into a
// Terraform model. The ForceNew identity attributes keep the planned
// spelling (a known configured value can never be rewritten at plan time:
// the framework rejects a plan that disagrees with a non-null config when
// there is no prior state, so the canonical value-rewriting plan modifiers
// used to break every non-canonical create with "Provider produced invalid
// plan"). The host always stores the canonical form; it surfaces in the
// canonical `binding_information` and `id` either way, and every host call
// is built from the canonicalised input, so the spelling in state carries
// no host meaning. Identity attributes cannot drift in place (any
// host-side change is a different binding: the Read-by-ID lookup misses
// and the resource is dropped from state).
//
// The in-place certificate pair follows the windows_power_plan precedent
// (PreservePlanSpelling + genuine drift surfaces observed): while the
// configured spelling matches the bound certificate it is kept verbatim,
// and an out-of-band change surfaces the observed canonical thumbprint so
// the next plan reconciles it. An empty observed thumbprint is null; an
// empty observed store falls back to "My" so the default stays diff-free.
func iisBindingStateToModel(plan windowsIISBindingModel, s *winclient.IISBindingState) windowsIISBindingModel {
	m := windowsIISBindingModel{
		ID:                 types.StringValue(winclient.IISBindingID(s.SiteName, s.Protocol, s.BindingInformation)),
		SiteName:           plan.SiteName,
		Protocol:           types.StringValue(s.Protocol),
		IPAddress:          iisBindingPreserveIPSpelling(plan.IPAddress, s.IPAddress),
		Port:               types.Int64Value(s.Port),
		HostHeader:         iisBindingPreserveHostSpelling(plan.HostHeader, s.HostHeader),
		RequireSNI:         types.BoolValue(s.RequireSNI),
		BindingInformation: types.StringValue(s.BindingInformation),
		Timeouts:           plan.Timeouts,
	}
	m.CertificateThumbprint = iisBindingProjectThumbprint(plan.CertificateThumbprint, s.CertificateThumbprint)
	if strings.TrimSpace(s.CertificateStoreName) == "" {
		m.CertificateStoreName = types.StringValue(winclient.IISBindingStoreMy)
	} else {
		m.CertificateStoreName = types.StringValue(strings.TrimSpace(s.CertificateStoreName))
	}
	return m
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create adds the binding, binds the certificate when configured, and
// stores the resulting state. The SSH-port guard runs client-side before
// anything is applied.
func (r *windowsIISBindingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsIISBindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, iisBindingDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	protocol, ip, host, port, diags := canonicalIISBindingPlan(plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Windows IIS binding", map[string]any{
		"site_name": plan.SiteName.ValueString(),
		"protocol":  protocol,
		"port":      port,
	})

	state, err := r.binding.Create(ctx, modelToIISBindingCreateInput(plan, protocol, ip, host, port))
	if err != nil {
		addIISBindingDiag(&resp.Diagnostics, "Error creating Windows IIS binding", err)
		return
	}
	if state == nil {
		resp.Diagnostics.AddError(
			"Windows IIS binding not found",
			fmt.Sprintf("IIS binding %q was not found on site %q after creation.", winclient.BuildIISBindingInformation(ip, port, host), plan.SiteName.ValueString()),
		)
		return
	}

	m := iisBindingStateToModel(plan, state)
	m.Timeouts = plan.Timeouts
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live binding. A binding deleted
// out-of-band (or a site deleted out-of-band) removes the resource from
// state. The timeouts block is preserved from prior state (it is user
// configuration, not observed state).
func (r *windowsIISBindingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsIISBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, iisBindingDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	site, protocol, bindingInfo, err := winclient.ParseIISBindingID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Reading Windows IIS binding", map[string]any{
		"site_name": site,
		"protocol":  protocol,
	})

	observed, err := r.binding.Read(ctx, site, protocol, bindingInfo)
	if err != nil {
		addIISBindingDiag(&resp.Diagnostics, "Error reading Windows IIS binding", err)
		return
	}
	if observed == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	m := iisBindingStateToModel(state, observed)
	m.Timeouts = state.Timeouts
	m.SiteName = state.SiteName
	m.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies the in-place attributes (require_sni plus the certificate
// pair) by removing and re-adding the binding in one script. Identity
// attributes are ForceNew and never change here. When nothing in place
// changed, the host is simply re-read.
func (r *windowsIISBindingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsIISBindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, iisBindingDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	protocol, ip, host, port, diags := canonicalIISBindingPlan(plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Identity attributes are ForceNew so they never change here.
	site := plan.SiteName.ValueString()
	tflog.Debug(ctx, "Updating Windows IIS binding", map[string]any{
		"site_name": site,
		"protocol":  protocol,
	})

	if !iisBindingInPlaceChanged(plan, prior) {
		// Nothing changed: refresh from the host instead of issuing a
		// no-op remove plus re-add.
		siteID, protoID, biID, err := winclient.ParseIISBindingID(prior.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid resource ID", err.Error())
			return
		}
		observed, err := r.binding.Read(ctx, siteID, protoID, biID)
		if err != nil {
			addIISBindingDiag(&resp.Diagnostics, "Error updating Windows IIS binding", err)
			return
		}
		if observed == nil {
			resp.Diagnostics.AddError(
				"Windows IIS binding not found",
				fmt.Sprintf("IIS binding %q on site %q does not exist on the target host.", biID, siteID),
			)
			return
		}
		m := iisBindingStateToModel(plan, observed)
		m.Timeouts = plan.Timeouts
		m.SiteName = plan.SiteName
		m.ID = prior.ID
		resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
		return
	}

	observed, err := r.binding.Update(ctx, modelToIISBindingUpdateInput(plan, prior, protocol, ip, host, port))
	if err != nil {
		addIISBindingDiag(&resp.Diagnostics, "Error updating Windows IIS binding", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"Windows IIS binding not found",
			fmt.Sprintf("IIS binding %q on site %q does not exist on the target host.", winclient.BuildIISBindingInformation(ip, port, host), site),
		)
		return
	}

	m := iisBindingStateToModel(plan, observed)
	m.Timeouts = plan.Timeouts
	m.SiteName = plan.SiteName
	m.ID = prior.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the SSL certificate binding (when https) and then the
// binding itself. A binding already gone out-of-band is already absent
// (no error).
func (r *windowsIISBindingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsIISBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, iisBindingDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	site, protocol, bindingInfo, err := winclient.ParseIISBindingID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Deleting Windows IIS binding", map[string]any{
		"site_name": site,
		"protocol":  protocol,
	})

	if err := r.binding.Delete(ctx, site, protocol, bindingInfo); err != nil {
		addIISBindingDiag(&resp.Diagnostics, "Error deleting Windows IIS binding", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing binding by
// `<site>|<protocol>|<bindingInformation>`.
func (r *windowsIISBindingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	site, protocol, bindingInfo, err := winclient.ParseIISBindingID(strings.TrimSpace(req.ID))
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must have the form <site>|<protocol>|<bindingInformation> (e.g. web|https|*:443:example.com); got %q: %s.", req.ID, err))
		return
	}

	tflog.Debug(ctx, "Importing Windows IIS binding", map[string]any{
		"site_name": site,
		"protocol":  protocol,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, iisBindingDefaultTimeout)
	defer cancel()

	observed, err := r.binding.Read(ctx, site, protocol, bindingInfo)
	if err != nil {
		addIISBindingDiag(&resp.Diagnostics, "Error importing Windows IIS binding", err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			"Windows IIS binding not found",
			fmt.Sprintf("IIS binding %q (%s) on site %q does not exist on the target host.", bindingInfo, protocol, site),
		)
		return
	}

	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by State.Set — use a typed null instead (the
	// subsequent Read fills in the configured values).
	plan := windowsIISBindingModel{
		SiteName:   types.StringValue(observed.SiteName),
		Protocol:   types.StringValue(observed.Protocol),
		IPAddress:  types.StringValue(observed.IPAddress),
		Port:       types.Int64Value(observed.Port),
		HostHeader: types.StringValue(observed.HostHeader),
		RequireSNI: types.BoolValue(observed.RequireSNI),
		Timeouts:   iisBindingNullTimeouts(),
	}
	m := iisBindingStateToModel(plan, observed)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helper: addIISBindingDiag
// ---------------------------------------------------------------------------

// addIISBindingDiag appends a diagnostic from a binding client error.
// would_lock_out refusals keep their full guidance (naming the management
// port); other kinds are enriched with context fields when available.
func addIISBindingDiag(d *diag.Diagnostics, summary string, err error) {
	var be *winclient.IISBindingError
	if errors.As(err, &be) {
		detail := be.Message
		if len(be.Context) > 0 {
			var parts []string
			for k, v := range be.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if be.Cause != nil {
			detail += "\n\nCause: " + be.Cause.Error()
		}
		d.AddError(summary+" ["+be.Kind+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
