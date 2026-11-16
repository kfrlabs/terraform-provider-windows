// Package provider - resource_windows_certificate implements the full
// Terraform resource lifecycle for windows_certificate.
//
// A single X.509 certificate in a Windows certificate store
// (Cert:\<location>\<store>) on the target host, imported from a PEM blob or
// a PFX bundle via X509Certificate2 / X509Certificate2Collection +
// X509Store.Add over SSH and PowerShell. The PEM / PFX payload and the PFX
// password travel to the host on stdin (RunPowerShellWithInput) and never
// appear in the script body or logs; the PFX material is WriteOnly and never
// reaches state.
//
// Spec alignment: windows_certificate spec v1 (issue #222).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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
	_ resource.Resource                     = (*windowsCertificateResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsCertificateResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsCertificateResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsCertificateResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*windowsCertificateResource)(nil)
)

// NewWindowsCertificateResource is the constructor registered in provider.go.
func NewWindowsCertificateResource() resource.Resource {
	return &windowsCertificateResource{}
}

// windowsCertificateResource is the TPF resource type for windows_certificate.
type windowsCertificateResource struct {
	certs winclient.CertificateClient
}

// certificateDefaultTimeout is the fallback per-operation timeout when the
// user does not provide a `timeouts {}` block. Store operations are fast,
// but a stalled PowerShell/SSH session must never block Terraform forever.
const certificateDefaultTimeout = 10 * time.Minute

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsCertificateModel is the Terraform state/plan model for
// windows_certificate. Every tfsdk tag matches an attribute key in
// windowsCertificateSchemaDefinition.
type windowsCertificateModel struct {
	ID               types.String        `tfsdk:"id"`
	StoreLocation    types.String        `tfsdk:"store_location"`
	StoreName        types.String        `tfsdk:"store_name"`
	CertificatePEM   certificatePEMValue `tfsdk:"certificate_pem"`
	PFXBase64WO      types.String        `tfsdk:"pfx_base64_wo"`
	PFXPasswordWO    types.String        `tfsdk:"pfx_password_wo"`
	PFXWOVersion     types.Int64         `tfsdk:"pfx_wo_version"`
	Exportable       types.Bool          `tfsdk:"exportable"`
	FriendlyName     types.String        `tfsdk:"friendly_name"`
	DeletePrivateKey types.Bool          `tfsdk:"delete_private_key"`
	Thumbprint       types.String        `tfsdk:"thumbprint"`
	ThumbprintSHA256 types.String        `tfsdk:"thumbprint_sha256"`
	Subject          types.String        `tfsdk:"subject"`
	Issuer           types.String        `tfsdk:"issuer"`
	SerialNumber     types.String        `tfsdk:"serial_number"`
	NotBefore        types.String        `tfsdk:"not_before"`
	NotAfter         types.String        `tfsdk:"not_after"`
	DNSNames         types.List          `tfsdk:"dns_names"`
	HasPrivateKey    types.Bool          `tfsdk:"has_private_key"`
	Timeouts         timeouts.Value      `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_certificate resource.
func (r *windowsCertificateResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsCertificateSchemaDefinition(ctx)
}

// windowsCertificateSchemaDefinition returns the complete TPF schema for
// windows_certificate.
func windowsCertificateSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a single X.509 certificate in a Windows certificate store " +
			"(`Cert:\\<location>\\<store>`) on a remote Windows host via SSH and PowerShell " +
			"(`X509Certificate2` / `X509Certificate2Collection` + `X509Store.Add`).\n\n" +
			"Exactly one payload must be set: `certificate_pem` (a PEM-encoded certificate, stored in state " +
			"in normalised form) or `pfx_base64_wo` (a base64-encoded PFX/PKCS#12 bundle, WriteOnly, never in state) " +
			"together with `pfx_wo_version`. The payload and the optional `pfx_password_wo` travel to the host on " +
			"stdin and never appear in the script, logs or state.\n\n" +
			"Rotation of a PFX bundle is driven exclusively by `pfx_wo_version`: bump the version and re-apply with " +
			"the new bundle (its value cannot be diffed). Changing only the bundle without bumping the version is a " +
			"no-op. Changing any identity attribute replaces the certificate: use a `lifecycle` " +
			"`create_before_destroy` block when the new certificate must be usable before the old one is removed.\n\n" +
			"Only `friendly_name` is updated in place. `delete_private_key` (default `true`) controls whether " +
			"destroy also deletes the private key from the key store.\n\n" +
			"Import format: `<store_location>/<store_name>/<thumbprint>` (e.g. `LocalMachine/My/A1B2...`). " +
			"A PFX-backed certificate is recognised by its private key and imports with `pfx_wo_version = 1`: " +
			"add the bundle and password back in configuration before the next apply.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier: `<store_location>/<store_name>/<thumbprint>`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"store_location": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(winclient.CertificateStoreLocalMachine),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(winclient.CertificateStoreLocalMachine, winclient.CertificateStoreCurrentUser),
				},
				Description: "Certificate store location: `LocalMachine` (default) or `CurrentUser`. Immutable after creation (ForceNew).",
			},

			"store_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("My"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					certificateStoreNameValidator{},
				},
				Description: "Certificate store name (e.g. `My`, the default). Immutable after creation (ForceNew). Must not contain `/` or `\\`.",
			},

			"certificate_pem": schema.StringAttribute{
				Optional:   true,
				CustomType: certificatePEMType{},
				PlanModifiers: []planmodifier.String{
					certificatePEMRequiresReplaceModifier{},
				},
				Validators: []validator.String{
					certificatePEMValidator{},
				},
				Description: "PEM-encoded certificate (the CERTIFICATE block; surrounding text such as a chain or private key is ignored, only the first certificate is imported). Exactly one of `certificate_pem` and `pfx_base64_wo` must be set. Stored in state in normalised form. Changing it replaces the certificate.",
			},

			"pfx_base64_wo": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					// A WriteOnly value cannot be diffed, so the version
					// counter is what drives rotation and is mandatory
					// (windows_file content_wo precedent).
					stringvalidator.AlsoRequires(path.MatchRoot("pfx_wo_version")),
					certificateBase64Validator{},
				},
				Description: "Write-only base64-encoded PFX/PKCS#12 bundle (TPF v1.14+ WriteOnly). Exactly one of `certificate_pem` and `pfx_base64_wo` must be set. The plaintext is never persisted in state; rotation is driven exclusively by `pfx_wo_version`. Changing only the bundle without bumping the version is a no-op.",
			},

			"pfx_password_wo": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					// A password without its bundle is a misconfiguration:
					// the bundle is what the password decrypts (pfx_base64_wo
					// already requires the version counter in the other direction).
					stringvalidator.AlsoRequires(path.MatchRoot("pfx_base64_wo")),
					secretNoLineBreakValidator{},
				},
				Description: "Write-only password decrypting the PFX bundle (TPF v1.14+ WriteOnly). Omit for an unprotected bundle. The value must not contain carriage return or line feed characters (rejected at plan time): secrets are read with `ReadLine()`, so anything from the first line break on would be silently truncated. If the value comes from `file()`, wrap it with `trimspace()` to strip the trailing newline.",
			},

			"pfx_wo_version": schema.Int64Attribute{
				Optional: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
					int64validator.AlsoRequires(path.MatchRoot("pfx_base64_wo")),
				},
				Description: "Version counter for `pfx_base64_wo` rotation. Change this value to replace the certificate with a new bundle: when it changes, the provider re-imports the configured bundle. Conventionally starts at 1. Changing only the bundle without changing this version leaves the stored certificate untouched.",
			},

			"exportable": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
				Description: "Marks the imported private key exportable. PFX bundles only; rejected with `certificate_pem`. Immutable after creation (ForceNew). Defaults to `false`.",
			},

			"friendly_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Display name of the certificate. The only attribute updated in place; setting it to `\"\"` clears the display name.",
			},

			"delete_private_key": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether destroy also deletes the private key from the key store. Defaults to `true`. Only affects destroy.",
			},

			"thumbprint": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-1 thumbprint (uppercase hex), as observed on the host.",
			},

			"thumbprint_sha256": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 digest of the certificate (uppercase hex), as observed on the host.",
			},

			"subject": schema.StringAttribute{
				Computed:    true,
				Description: "Distinguished name of the subject, as observed on the host.",
			},

			"issuer": schema.StringAttribute{
				Computed:    true,
				Description: "Distinguished name of the issuer, as observed on the host.",
			},

			"serial_number": schema.StringAttribute{
				Computed:    true,
				Description: "Serial number hex string, as observed on the host.",
			},

			"not_before": schema.StringAttribute{
				Computed:    true,
				Description: "Start of the validity period (RFC 3339 UTC), as observed on the host.",
			},

			"not_after": schema.StringAttribute{
				Computed:    true,
				Description: "End of the validity period (RFC 3339 UTC), as observed on the host.",
			},

			"dns_names": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "DNS entries of the subject-alternative-name extension, as observed on the host (possibly empty).",
			},

			"has_private_key": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the stored certificate carries a private key, as observed on the host.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// certificateDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, certificateTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// certificateStoreNameValidator rejects '/' (the import-ID separator) and
// '\' (never valid in a store name and fatal to Cert: paths) in store_name.
type certificateStoreNameValidator struct{}

func (v certificateStoreNameValidator) Description(_ context.Context) string {
	return "Store name must not contain '/' or '\\'."
}

func (v certificateStoreNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v certificateStoreNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.ContainsAny(req.ConfigValue.ValueString(), "/\\") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid store name",
			fmt.Sprintf("store_name must not contain '/' or '\\' ('/' separates the parts of the import ID); got %q.", req.ConfigValue.ValueString()),
		)
	}
}

// certificatePEMValidator checks at plan time that certificate_pem carries
// at least a CERTIFICATE block. Full parsing happens in winclient.
type certificatePEMValidator struct{}

func (v certificatePEMValidator) Description(_ context.Context) string {
	return "Certificate PEM must contain a CERTIFICATE block."
}

func (v certificatePEMValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v certificatePEMValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := winclient.ParseCertificatePEM(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid certificate PEM",
			"certificate_pem must contain a PEM-encoded certificate (a -----BEGIN CERTIFICATE----- block).",
		)
	}
}

// certificateBase64Validator checks at plan time that pfx_base64_wo is
// valid base64 (all whitespace, e.g. newlines from a wrapped file() value,
// is stripped before decoding to match .NET FromBase64String).
type certificateBase64Validator struct{}

func (v certificateBase64Validator) Description(_ context.Context) string {
	return "PFX bundle must be valid base64."
}

func (v certificateBase64Validator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v certificateBase64Validator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	// Strip all whitespace (spaces, tabs, CR/LF) before decoding, matching
	// .NET FromBase64String which tolerates embedded whitespace.
	if _, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(req.ConfigValue.ValueString()), "")); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid PFX bundle",
			"pfx_base64_wo must be valid base64 (e.g. filebase64(\"cert.pfx\")).",
		)
	}
}

// certificatePEMValue is the framework value type for the certificate_pem
// attribute. It implements value-semantic equality so that cosmetic
// spellings of the same certificate (CRLF line endings from Windows-edited
// files, re-wrapped base64, surrounding text) compare equal, avoiding both a
// "provider produced invalid plan" error on create and a false diff on later
// refresh (windows_scheduled_task durationValue precedent).
//
// Equal itself is DER-aware, not just StringSemanticEquals: the framework's
// RequiresReplace plan modifier compares with Equal (never with
// StringSemanticEquals) at plan time, so an exact-but-textual Equal would
// force a replacement after every import that rewraps the PEM (aggressive
// CLI campaign, 2026-11-16: DER-identical import planned 1 to add,
// 1 to destroy).
//
// The state value is never rewritten: the normalised spelling the provider
// stores is kept as-is. Equality is only relaxed at comparison time.
type certificatePEMValue struct {
	basetypes.StringValue
}

func certificatePEMValueOf(s string) certificatePEMValue {
	return certificatePEMValue{StringValue: types.StringValue(s)}
}

func certificatePEMNull() certificatePEMValue {
	return certificatePEMValue{StringValue: types.StringNull()}
}

func (v certificatePEMValue) Equal(o attr.Value) bool {
	other, ok := o.(certificatePEMValue)
	if !ok {
		return false
	}
	if v.StringValue.Equal(other.StringValue) {
		return true
	}
	// Textually different spellings of the same certificate compare equal
	// (DER comparison): RequiresReplace uses Equal at plan time, so without
	// this an import that rewraps the PEM would force a replacement.
	return certificatePEMsEquivalent(v.ValueString(), other.ValueString())
}

func (v certificatePEMValue) Type(_ context.Context) attr.Type {
	return certificatePEMType{}
}

func (v certificatePEMValue) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	other, ok := newValuable.(certificatePEMValue)
	if !ok {
		diags.AddError("Semantic Equality Check Error",
			fmt.Sprintf("expected certificatePEMValue, got %T", newValuable))
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || other.IsNull() || other.IsUnknown() {
		return false, diags
	}
	return certificatePEMsEquivalent(v.ValueString(), other.ValueString()), diags
}

// certificatePEMType is the attr.Type counterpart of certificatePEMValue.
type certificatePEMType struct {
	basetypes.StringType
}

func (t certificatePEMType) Equal(o attr.Type) bool {
	other, ok := o.(certificatePEMType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t certificatePEMType) String() string {
	return "certificatePEMType"
}

func (t certificatePEMType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return certificatePEMValue{StringValue: in}, nil
}

func (t certificatePEMType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T for certificatePEMType", attrValue)
	}
	valuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("error converting StringValue to certificatePEMValue: %v", diags)
	}
	return valuable, nil
}

func (t certificatePEMType) ValueType(context.Context) attr.Value {
	return certificatePEMValue{}
}

// certificatePEMRequiresReplaceModifier is a DER-aware replacement for
// stringplanmodifier.RequiresReplace on certificate_pem.
//
// The framework erases custom value types before invoking plan modifiers
// (AttributePlanModifyString calls ToStringValue, handing modifiers a plain
// basetypes.StringValue), so neither certificatePEMValue.Equal nor
// StringSemanticEquals is consulted on the plan path: an import that merely
// rewraps the PEM would force a replacement of a DER-identical certificate
// (aggressive CLI campaign, 2026-11-16). This modifier compares DER bytes
// instead: identical DER reuses the state value (no diff at all), and only
// a genuinely different certificate requires replacement.
type certificatePEMRequiresReplaceModifier struct{}

func (m certificatePEMRequiresReplaceModifier) Description(_ context.Context) string {
	return "If the value of this attribute changes, Terraform will destroy and recreate the resource."
}

func (m certificatePEMRequiresReplaceModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m certificatePEMRequiresReplaceModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do not replace on resource creation or destroy.
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	// Nulls and unknowns are left to the other modifiers and core.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() ||
		req.StateValue.IsNull() || req.StateValue.IsUnknown() {
		return
	}
	if certificatePEMsEquivalent(req.PlanValue.ValueString(), req.StateValue.ValueString()) {
		// DER-identical: keep the state spelling so the plan is empty.
		resp.PlanValue = req.StateValue
		return
	}
	resp.RequiresReplace = true
}

// certificatePEMsEquivalent reports whether two PEM spellings denote the same
// certificate (identical DER bytes). It falls back to exact string equality
// when either side is byte-identical, and returns false when either side
// cannot be parsed, so an unexpected value still compares strictly rather
// than silently matching something else.
func certificatePEMsEquivalent(a, b string) bool {
	if a == b {
		return true
	}
	da, errA := winclient.ParseCertificatePEM(a)
	db, errB := winclient.ParseCertificatePEM(b)
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(da, db)
}

// certificateConfigValidator enforces the cross-field security rules:
// CurrentUser trusted-root stores are refused, any trusted-root store
// warns, and exportable with a PEM payload is refused.
type certificateConfigValidator struct{}

func (v certificateConfigValidator) Description(_ context.Context) string {
	return "Validates the certificate store and payload combination."
}

func (v certificateConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v certificateConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var location types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("store_location"), &location)...)
	var storeName types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("store_name"), &storeName)...)
	var pem certificatePEMValue
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("certificate_pem"), &pem)...)
	var exportable types.Bool
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("exportable"), &exportable)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if location.IsNull() || location.IsUnknown() || storeName.IsNull() || storeName.IsUnknown() {
		return
	}
	loc := location.ValueString()
	store := storeName.ValueString()
	// Trust anchors are machine-wide: managing CurrentUser Root/AuthRoot
	// from Terraform would silently split the trust view per user.
	if strings.EqualFold(loc, winclient.CertificateStoreCurrentUser) &&
		(strings.EqualFold(store, "Root") || strings.EqualFold(store, "AuthRoot")) {
		resp.Diagnostics.AddAttributeError(
			path.Root("store_name"),
			"Unsupported store",
			fmt.Sprintf("store %q in location CurrentUser cannot be managed: trust anchors are machine-wide, manage them in LocalMachine instead.", store),
		)
		return
	}
	// Installing into a trusted-root store makes the host trust the
	// certificate's issuer chain: always worth a second look.
	if strings.EqualFold(store, "Root") || strings.EqualFold(store, "AuthRoot") {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("store_name"),
			"Writing to a trusted-root store",
			fmt.Sprintf("store %q in location %s is a trusted-root store: importing a certificate here makes the host trust its issuer chain. Only proceed with certificates from a source you trust.", store, loc),
		)
	}
	if !exportable.IsNull() && !exportable.IsUnknown() && exportable.ValueBool() &&
		!pem.IsNull() && !pem.IsUnknown() && strings.TrimSpace(pem.ValueString()) != "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("exportable"),
			"Conflicting attributes",
			"exportable applies to PFX bundles only and must not be set with certificate_pem.",
		)
	}
}

// ConfigValidators returns the resource-level cross-field validators.
func (r *windowsCertificateResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		// Exactly one payload: PEM in state, or a WriteOnly PFX bundle
		// (windows_file content-source precedent: resourcevalidator sees
		// WriteOnly values in config).
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("certificate_pem"),
			path.MatchRoot("pfx_base64_wo"),
		),
		certificateConfigValidator{},
	}
}

// ---------------------------------------------------------------------------
// ModifyPlan — suppress cosmetic PEM respellings
// ---------------------------------------------------------------------------

// ModifyPlan restores the observed computed attributes from state when the
// planned certificate is DER-identical to the state certificate. Terraform
// core proposes unknown computed values whenever the config spelling differs
// textually from state (it compares raw strings), which would otherwise leave
// a perpetual in-place update after every import that rewraps the PEM, even
// though certificatePEMRequiresReplaceModifier already established that the
// certificate itself is unchanged (aggressive CLI campaign, 2026-11-16).
//
// Suppression only happens when nothing else changed: a genuinely different
// store, friendly name, exportability, key-deletion policy or PFX rotation
// still flows through the normal replace/update path untouched. (Attribute
// plan modifiers run before resource ModifyPlan but their RequiresReplace
// paths are accumulated separately, so this method re-checks the
// user-configurable attributes directly.)
func (r *windowsCertificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return // create / destroy
	}
	var plan, state windowsCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.CertificatePEM.IsNull() || plan.CertificatePEM.IsUnknown() ||
		state.CertificatePEM.IsNull() || state.CertificatePEM.IsUnknown() {
		return // PFX path or incomplete values: nothing to compare
	}
	if !certificatePEMsEquivalent(plan.CertificatePEM.ValueString(), state.CertificatePEM.ValueString()) {
		return // genuinely different certificate
	}
	if !plan.StoreLocation.Equal(state.StoreLocation) ||
		!plan.StoreName.Equal(state.StoreName) ||
		!plan.FriendlyName.Equal(state.FriendlyName) ||
		!plan.Exportable.Equal(state.Exportable) ||
		!plan.DeletePrivateKey.Equal(state.DeletePrivateKey) ||
		!plan.PFXWOVersion.Equal(state.PFXWOVersion) {
		return // some other attribute really changed
	}
	// DER-identical: the remote object is unchanged, so the observed values
	// carry over untouched and the plan is empty.
	plan.Subject = state.Subject
	plan.Issuer = state.Issuer
	plan.SerialNumber = state.SerialNumber
	plan.NotBefore = state.NotBefore
	plan.NotAfter = state.NotAfter
	plan.DNSNames = state.DNSNames
	plan.Thumbprint = state.Thumbprint
	plan.ThumbprintSHA256 = state.ThumbprintSHA256
	plan.HasPrivateKey = state.HasPrivateKey
	plan.CertificatePEM = state.CertificatePEM
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates a
// CertificateClient for this resource instance.
func (r *windowsCertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := configuredClient(req.ProviderData, &resp.Diagnostics)
	if c == nil {
		return
	}
	r.certs = winclient.NewCertificateClient(c)
}

// ---------------------------------------------------------------------------
// Helpers: ID, timeouts, diagnostics
// ---------------------------------------------------------------------------

// certificateID builds the resource ID from the canonical location, the
// configured store spelling and the canonical thumbprint.
func certificateID(location, store, thumbprint string) string {
	return location + "/" + store + "/" + thumbprint
}

// splitCertificateID parses an ID back into location, store and thumbprint,
// trimming surrounding whitespace on all parts.
func splitCertificateID(id string) (location, store, thumbprint string, err error) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return "", "", "", fmt.Errorf("import ID %q must have the form <store_location>/<store_name>/<thumbprint>", id)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), nil
}

// certificateTimeoutsOpts declares which per-operation timeouts the resource exposes.
var certificateTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// certificateNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO
// attribute types, which the framework rejects on State.Set — the failure
// mode on import, where there is no prior state to copy the value from.
func certificateNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if certificateTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if certificateTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if certificateTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if certificateTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// certificateStateToModel projects an observed CertificateInfo into a
// Terraform model, preserving the operator-managed plan values (payload
// selection, timeouts) and the delete behaviour.
func certificateStateToModel(ctx context.Context, plan windowsCertificateModel, info *winclient.CertificateInfo) (windowsCertificateModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	dns, dgs := types.ListValueFrom(ctx, types.StringType, info.DNSNames)
	diags.Append(dgs...)
	if diags.HasError() {
		return windowsCertificateModel{}, diags
	}
	m := windowsCertificateModel{
		ID:               types.StringValue(certificateID(info.StoreLocation, info.StoreName, info.Thumbprint)),
		StoreLocation:    types.StringValue(info.StoreLocation),
		StoreName:        types.StringValue(info.StoreName),
		Exportable:       plan.Exportable,
		FriendlyName:     types.StringValue(info.FriendlyName),
		DeletePrivateKey: plan.DeletePrivateKey,
		Thumbprint:       types.StringValue(info.Thumbprint),
		ThumbprintSHA256: types.StringValue(info.ThumbprintSHA256),
		Subject:          types.StringValue(info.Subject),
		Issuer:           types.StringValue(info.Issuer),
		SerialNumber:     types.StringValue(info.SerialNumber),
		NotBefore:        types.StringValue(info.NotBefore),
		NotAfter:         types.StringValue(info.NotAfter),
		DNSNames:         dns,
		HasPrivateKey:    types.BoolValue(info.HasPrivateKey),
		Timeouts:         plan.Timeouts,
	}
	// The PFX material is WriteOnly and never reaches state; the version
	// counter and the PEM spelling ride along from the plan.
	m.PFXBase64WO = types.StringNull()
	m.PFXPasswordWO = types.StringNull()
	m.PFXWOVersion = plan.PFXWOVersion
	if plan.CertificatePEM.IsNull() {
		m.CertificatePEM = certificatePEMNull()
	} else if info.NormalizedPEM != "" {
		m.CertificatePEM = certificatePEMValueOf(info.NormalizedPEM)
	} else {
		m.CertificatePEM = plan.CertificatePEM
	}
	return m, diags
}

// effectiveCertificatePFX returns the PFX bundle and password to use for
// Create / Update along with the schema path holding the bundle. WriteOnly
// values are null in the plan handed to ApplyResourceChange, so the
// candidates must come from req.Config first (windows_file content_wo
// precedent); the plan value is still consulted as a fallback for callers
// that bypass Config (unit tests driving Plan only).
func effectiveCertificatePFX(plan, config windowsCertificateModel) (bundle, password string, hasPassword bool) {
	if !config.PFXBase64WO.IsNull() && !config.PFXBase64WO.IsUnknown() {
		if v := strings.TrimSpace(config.PFXBase64WO.ValueString()); v != "" {
			bundle = v
		}
	}
	if bundle == "" && !plan.PFXBase64WO.IsNull() && !plan.PFXBase64WO.IsUnknown() {
		if v := strings.TrimSpace(plan.PFXBase64WO.ValueString()); v != "" {
			bundle = v
		}
	}
	if !config.PFXPasswordWO.IsNull() && !config.PFXPasswordWO.IsUnknown() {
		password, hasPassword = config.PFXPasswordWO.ValueString(), true
	} else if !plan.PFXPasswordWO.IsNull() && !plan.PFXPasswordWO.IsUnknown() {
		password, hasPassword = plan.PFXPasswordWO.ValueString(), true
	}
	return bundle, password, hasPassword
}

// addCertificateDiag appends a diagnostic from a certificate client error.
// Typed kinds keep their machine-readable suffix; secrets never appear in
// messages or context by construction (payloads travel on stdin).
func addCertificateDiag(d *diag.Diagnostics, summary string, err error) {
	var ce *winclient.CertificateError
	if errors.As(err, &ce) {
		detail := ce.Message
		if len(ce.Context) > 0 {
			keys := make([]string, 0, len(ce.Context))
			for k := range ce.Context {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%s", k, ce.Context[k]))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if ce.Cause != nil {
			detail += "\n\nCause: " + ce.Cause.Error()
		}
		d.AddError(summary+" ["+ce.Kind+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create imports the certificate into the store and stores the resulting state.
func (r *windowsCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config windowsCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.Config.Raw.IsNull() {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, certificateDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	pemValue := ""
	if !plan.CertificatePEM.IsNull() && !plan.CertificatePEM.IsUnknown() {
		pemValue = strings.TrimSpace(plan.CertificatePEM.ValueString())
	}
	pfxBundle, pfxPassword, hasPFXPassword := effectiveCertificatePFX(plan, config)
	if pemValue == "" && pfxBundle == "" {
		resp.Diagnostics.AddError(
			"Missing certificate payload",
			"Exactly one of certificate_pem and pfx_base64_wo must be set.",
		)
		return
	}

	input := winclient.CertificateInput{
		StoreLocation:  plan.StoreLocation.ValueString(),
		StoreName:      plan.StoreName.ValueString(),
		CertificatePEM: pemValue,
		PFXBase64:      pfxBundle,
		Exportable:     plan.Exportable.ValueBool(),
		FriendlyName:   certificateEffectiveFriendlyName(plan.FriendlyName),
	}
	if hasPFXPassword {
		pw := pfxPassword
		input.PFXPassword = &pw
	}

	tflog.Debug(ctx, "Creating Windows certificate", map[string]any{
		"store_location": input.StoreLocation,
		"store_name":     input.StoreName,
		"is_pfx":         pfxBundle != "",
	})

	info, err := r.certs.Create(ctx, input)
	if err != nil {
		addCertificateDiag(&resp.Diagnostics, "Error creating Windows certificate", err)
		return
	}

	m, md := certificateStateToModel(ctx, plan, info)
	resp.Diagnostics.Append(md...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// certificateEffectiveFriendlyName resolves the friendly name for a mutating
// call: null/unknown means "leave the Windows default".
func certificateEffectiveFriendlyName(v types.String) string {
	if v.IsNull() || v.IsUnknown() {
		return ""
	}
	return v.ValueString()
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the store. A missing certificate
// (not_found) removes the resource from state; a missing store
// (store_not_found) is an error diagnostic, never a silent removal. A PEM
// resource refreshes certificate_pem in normalised form.
func (r *windowsCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, certificateDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	location, store, thumbprint, err := splitCertificateID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Reading Windows certificate", map[string]any{
		"store_location": location,
		"store_name":     store,
		"thumbprint":     thumbprint,
	})

	info, err := r.certs.Read(ctx, location, store, thumbprint)
	if err != nil {
		addCertificateDiag(&resp.Diagnostics, "Error reading Windows certificate", err)
		return
	}
	if info == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	m, md := certificateStateToModel(ctx, state, info)
	resp.Diagnostics.Append(md...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Keep the configured store spelling: the store object echoes the same
	// name, and the location is canonical already.
	m.StoreLocation = state.StoreLocation
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update renames the certificate's friendly name in place. Every other
// attribute forces replacement via RequiresReplace, so Update only ever sees
// a friendly-name change (or a delete_private_key toggle, which only affects
// destroy and is stored as-is).
func (r *windowsCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, certificateDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	friendly := certificateEffectiveFriendlyName(plan.FriendlyName)
	if plan.FriendlyName.IsNull() || plan.FriendlyName.IsUnknown() {
		friendly = certificateEffectiveFriendlyName(prior.FriendlyName)
	}

	location, store, thumbprint, err := splitCertificateID(prior.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Updating Windows certificate", map[string]any{
		"store_location": location,
		"store_name":     store,
		"thumbprint":     thumbprint,
	})

	info, err := r.certs.UpdateFriendlyName(ctx, location, store, thumbprint, friendly)
	if err != nil {
		addCertificateDiag(&resp.Diagnostics, "Error updating Windows certificate", err)
		return
	}

	m, md := certificateStateToModel(ctx, plan, info)
	resp.Diagnostics.Append(md...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.ID = prior.ID
	m.StoreLocation = prior.StoreLocation
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the certificate from the store, deleting the private key
// first when delete_private_key is true.
func (r *windowsCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, certificateDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	location, store, thumbprint, err := splitCertificateID(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}

	tflog.Debug(ctx, "Deleting Windows certificate", map[string]any{
		"store_location": location,
		"store_name":     store,
		"thumbprint":     thumbprint,
	})

	deleteKey := true
	if !state.DeletePrivateKey.IsNull() && !state.DeletePrivateKey.IsUnknown() {
		deleteKey = state.DeletePrivateKey.ValueBool()
	}
	if err := r.certs.Delete(ctx, location, store, thumbprint, deleteKey); err != nil {
		if winclient.IsCertificateError(err, winclient.CertificateErrorNotFound) {
			return // already gone
		}
		addCertificateDiag(&resp.Diagnostics, "Error deleting Windows certificate", err)
		return
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing certificate by
// `<store_location>/<store_name>/<thumbprint>`. A certificate carrying a
// private key is assumed PFX-backed and imports with pfx_wo_version = 1:
// add the bundle and password back in configuration before the next apply.
// Import always records exportable = false in state: reconcile exportable in
// configuration before the first apply (it forces replacement when changed).
// A keyless certificate imports with its normalised PEM in certificate_pem.
func (r *windowsCertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	location, store, thumbprint, err := splitCertificateID(strings.TrimSpace(req.ID))
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must have the form <store_location>/<store_name>/<thumbprint>; got %q.", req.ID))
		return
	}
	canonicalLocation, lerr := winclient.CanonicalCertificateStoreLocation(location)
	if lerr != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID store location must be %q or %q; got %q.",
				winclient.CertificateStoreLocalMachine, winclient.CertificateStoreCurrentUser, location))
		return
	}
	location = canonicalLocation

	tflog.Debug(ctx, "Importing Windows certificate", map[string]any{
		"store_location": location,
		"store_name":     store,
		"thumbprint":     thumbprint,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, certificateDefaultTimeout)
	defer cancel()

	info, err := r.certs.Read(ctx, location, store, thumbprint)
	if err != nil {
		addCertificateDiag(&resp.Diagnostics, "Error importing Windows certificate", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Certificate not found",
			fmt.Sprintf("No certificate %s was found in %s\\%s on the target host.", thumbprint, location, store),
		)
		return
	}

	plan := windowsCertificateModel{
		StoreLocation:    types.StringValue(location),
		StoreName:        types.StringValue(store),
		Exportable:       types.BoolValue(false),
		FriendlyName:     types.StringValue(info.FriendlyName),
		DeletePrivateKey: types.BoolValue(true),
		Timeouts:         certificateNullTimeouts(),
	}
	if info.HasPrivateKey {
		plan.PFXWOVersion = types.Int64Value(1)
	} else if info.NormalizedPEM != "" {
		plan.CertificatePEM = certificatePEMValueOf(info.NormalizedPEM)
	}
	m, md := certificateStateToModel(ctx, plan, info)
	resp.Diagnostics.Append(md...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}
