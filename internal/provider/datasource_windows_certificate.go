// Package provider: windows_certificate data source implementation.
//
// Reads the observed state of a certificate in a Windows certificate store
// without managing it. Lookup is by thumbprint or by subject (exactly one of
// the two), optionally narrowed by store location and name, and reuses the
// sibling resource's winclient.CertificateClient (no new winclient code).
package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource                     = (*windowsCertificateDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*windowsCertificateDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*windowsCertificateDataSource)(nil)
)

// NewWindowsCertificateDataSource is the constructor registered in provider.go.
func NewWindowsCertificateDataSource() datasource.DataSource {
	return &windowsCertificateDataSource{}
}

// windowsCertificateDataSource is the TPF data source type for windows_certificate.
type windowsCertificateDataSource struct {
	certs winclient.CertificateClient
}

// certificateDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (certificateDefaultTimeout) so a stalled session surfaces a
// timeout diagnostic instead of blocking plan forever.
const certificateDSDefaultTimeout = certificateDefaultTimeout

// windowsCertificateDataSourceModel is the Terraform state model for the
// windows_certificate data source.
type windowsCertificateDataSourceModel struct {
	ID               types.String     `tfsdk:"id"`
	Thumbprint       types.String     `tfsdk:"thumbprint"`
	Subject          types.String     `tfsdk:"subject"`
	StoreLocation    types.String     `tfsdk:"store_location"`
	StoreName        types.String     `tfsdk:"store_name"`
	MostRecent       types.Bool       `tfsdk:"most_recent"`
	ThumbprintSHA256 types.String     `tfsdk:"thumbprint_sha256"`
	Issuer           types.String     `tfsdk:"issuer"`
	SerialNumber     types.String     `tfsdk:"serial_number"`
	NotBefore        types.String     `tfsdk:"not_before"`
	NotAfter         types.String     `tfsdk:"not_after"`
	DNSNames         types.List       `tfsdk:"dns_names"`
	HasPrivateKey    types.Bool       `tfsdk:"has_private_key"`
	FriendlyName     types.String     `tfsdk:"friendly_name"`
	Timeouts         dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_certificate", the same
// Terraform type name as the sibling resource per ADR-0009).
func (d *windowsCertificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

// Schema returns the TPF schema for the windows_certificate data source.
func (d *windowsCertificateDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a certificate in a Windows certificate store " +
			"on a remote Windows host without managing it.\n\n" +
			"Lookup is by `thumbprint` or by `subject` (exactly one of the two), optionally narrowed by " +
			"`store_location` and `store_name`. A subject lookup matching several certificates resolves " +
			"deterministically to the most recently issued one when `most_recent` is true (the default); " +
			"with `most_recent = false` several matches are an error. Zero matches are always an error. " +
			"The subject must match the host-reported Subject verbatim (order, spacing and escaping must " +
			"match; no DN normalisation is applied).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: `<store_location>/<store_name>/<thumbprint>` of the observed certificate.",
			},
			"thumbprint": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "SHA-1 thumbprint (uppercase hex) of the certificate. Exactly one of thumbprint or subject must be specified.",
			},
			"subject": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Distinguished name of the subject (e.g. \"CN=example.com\"). Matched exactly and case-insensitively against the host-reported Subject verbatim: copy the value from the observed subject attribute (order, spacing and escaping must match). Exactly one of thumbprint or subject must be specified.",
			},
			"store_location": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Certificate store location to search: LocalMachine or CurrentUser. Defaults to LocalMachine.",
				Validators: []validator.String{
					stringvalidator.OneOf(winclient.CertificateStoreLocalMachine, winclient.CertificateStoreCurrentUser),
				},
			},
			"store_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Certificate store name to search. Defaults to My. Must not contain '/' or '\\'.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					certificateStoreNameValidator{},
				},
			},
			"most_recent": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "When a subject lookup matches several certificates, pick the most recently issued one (latest not_before). Defaults to true; with false several matches are an error. Ignored for thumbprint lookups.",
			},
			"thumbprint_sha256": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 digest of the certificate (uppercase hex), as observed on the host.",
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
			"friendly_name": schema.StringAttribute{
				Computed:    true,
				Description: "Display name of the certificate, as observed on the host (possibly empty).",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to certificateDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// ConfigValidators enforces ExactlyOneOf(thumbprint, subject).
func (d *windowsCertificateDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("thumbprint"),
			path.MatchRoot("subject"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsCertificateDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.certs = winclient.NewCertificateClient(c)
}

// certificateDataSourceDefaults fills the store filters and most_recent
// from their documented defaults when the configuration omits them.
func certificateDataSourceDefaults(config windowsCertificateDataSourceModel) (location, store string, mostRecent bool) {
	location = winclient.CertificateStoreLocalMachine
	if !config.StoreLocation.IsNull() && !config.StoreLocation.IsUnknown() && config.StoreLocation.ValueString() != "" {
		location = config.StoreLocation.ValueString()
	}
	store = "My"
	if !config.StoreName.IsNull() && !config.StoreName.IsUnknown() && config.StoreName.ValueString() != "" {
		store = config.StoreName.ValueString()
	}
	mostRecent = true
	if !config.MostRecent.IsNull() && !config.MostRecent.IsUnknown() {
		mostRecent = config.MostRecent.ValueBool()
	}
	return location, store, mostRecent
}

// pickMostRecentCertificate returns the candidate with the latest not_before.
// Ties resolve deterministically by thumbprint order.
func pickMostRecentCertificate(cands []*winclient.CertificateInfo) *winclient.CertificateInfo {
	ordered := append([]*winclient.CertificateInfo(nil), cands...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].NotBefore != ordered[j].NotBefore {
			return ordered[i].NotBefore > ordered[j].NotBefore
		}
		return ordered[i].Thumbprint < ordered[j].Thumbprint
	})
	return ordered[0]
}

// Read fetches the observed certificate state from the remote Windows host
// by calling the sibling resource's CertificateClient. A nil result or an
// empty match set triggers a `not found` diagnostic (data sources never
// silently clear state). Other typed *winclient.CertificateError values are
// surfaced via addCertificateDiag, mirroring the resource Read path.
func (d *windowsCertificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsCertificateDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, certificateDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	location, store, mostRecent := certificateDataSourceDefaults(config)

	var observed *winclient.CertificateInfo
	if !config.Thumbprint.IsNull() && !config.Thumbprint.IsUnknown() && config.Thumbprint.ValueString() != "" {
		target := config.Thumbprint.ValueString()
		tflog.Debug(ctx, "windows_certificate data source Read by thumbprint", map[string]interface{}{
			"store_location": location, "store_name": store, "thumbprint": target,
		})
		info, err := d.certs.Read(ctx, location, store, target)
		if err != nil {
			var ce *winclient.CertificateError
			if errors.As(err, &ce) && ce.Kind == winclient.CertificateErrorNotFound {
				resp.Diagnostics.AddError(
					fmt.Sprintf("Data source not found: windows_certificate %q", target),
					fmt.Sprintf("No certificate %s was found in %s\\%s on the target host.", target, location, store),
				)
				return
			}
			addCertificateDiag(&resp.Diagnostics, "Read data source", err)
			return
		}
		if info == nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_certificate %q", target),
				fmt.Sprintf("No certificate %s was found in %s\\%s on the target host.", target, location, store),
			)
			return
		}
		observed = info
	} else {
		subject := config.Subject.ValueString()
		tflog.Debug(ctx, "windows_certificate data source Read by subject", map[string]interface{}{
			"store_location": location, "store_name": store, "subject": subject,
		})
		cands, err := d.certs.LookupBySubject(ctx, location, store, subject)
		if err != nil {
			var ce *winclient.CertificateError
			if errors.As(err, &ce) && ce.Kind == winclient.CertificateErrorNotFound {
				resp.Diagnostics.AddError(
					fmt.Sprintf("Data source not found: windows_certificate %q", subject),
					fmt.Sprintf("No certificate with subject %q was found in %s\\%s on the target host.", subject, location, store),
				)
				return
			}
			addCertificateDiag(&resp.Diagnostics, "Read data source", err)
			return
		}
		if len(cands) == 0 {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_certificate %q", subject),
				fmt.Sprintf("No certificate with subject %q was found in %s\\%s on the target host.", subject, location, store),
			)
			return
		}
		if len(cands) > 1 && !mostRecent {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Ambiguous data source lookup: windows_certificate %q", subject),
				fmt.Sprintf("%d certificates with subject %q were found in %s\\%s; set most_recent = true to pick the most recently issued one.", len(cands), subject, location, store),
			)
			return
		}
		observed = pickMostRecentCertificate(cands)
	}

	dns, dgs := types.ListValueFrom(ctx, types.StringType, observed.DNSNames)
	resp.Diagnostics.Append(dgs...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsCertificateDataSourceModel{
		ID:               types.StringValue(certificateID(observed.StoreLocation, observed.StoreName, observed.Thumbprint)),
		Thumbprint:       types.StringValue(observed.Thumbprint),
		Subject:          types.StringValue(observed.Subject),
		StoreLocation:    types.StringValue(observed.StoreLocation),
		StoreName:        types.StringValue(observed.StoreName),
		MostRecent:       types.BoolValue(mostRecent),
		ThumbprintSHA256: types.StringValue(observed.ThumbprintSHA256),
		Issuer:           types.StringValue(observed.Issuer),
		SerialNumber:     types.StringValue(observed.SerialNumber),
		NotBefore:        types.StringValue(observed.NotBefore),
		NotAfter:         types.StringValue(observed.NotAfter),
		DNSNames:         dns,
		HasPrivateKey:    types.BoolValue(observed.HasPrivateKey),
		FriendlyName:     types.StringValue(observed.FriendlyName),
		Timeouts:         config.Timeouts,
	}

	tflog.Debug(ctx, "windows_certificate data source Read end", map[string]interface{}{
		"thumbprint": state.Thumbprint.ValueString(),
		"subject":    state.Subject.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
