// Package provider — unit tests for the windows_certificate resource.
//
// These tests exercise the schema, validators, helpers and CRUD handlers
// without SSH. A fakeCertificateClient is injected into
// windowsCertificateResource.certs.
//
// Edge cases covered (issue #222):
//
//	Metadata                 — returns "windows_certificate"
//	Schema                   — ForceNew identity/payload attributes,
//	                           WriteOnly+Sensitive PFX attrs, defaults,
//	                           timeouts block
//	Validators               — store name rejects '/'; PEM shape; base64
//	                           shape; CR/LF rejection on pfx_password_wo
//	Normalize modifier       — CRLF converges to the normalised PEM
//	Config validator         — CurrentUser+Root refused; Root warns;
//	                           exportable+PEM refused
//	ID helpers               — build/split (trims parts), bad IDs
//	Create (PEM happy)       — canonical ID, normalised PEM in state
//	Create (PFX overlay)     — WriteOnly values forwarded from config
//	Create (missing/remote)  — fail-closed diagnostics
//	Read (happy/missing)     — refresh computed, missing removes state
//	Update/Delete            — friendly-name forwarded, key flag forwarded
//	ImportState              — keyless PEM vs keyed PFX (version 1)
package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// fakeCertificateClient
// ---------------------------------------------------------------------------

type fakeCertificateClient struct {
	createIn  winclient.CertificateInput
	createOut *winclient.CertificateInfo
	createErr error

	readLocation string
	readStore    string
	readThumb    string
	readOut      *winclient.CertificateInfo
	readErr      error

	lookupLocation string
	lookupStore    string
	lookupSubject  string
	lookupOut      []*winclient.CertificateInfo
	lookupErr      error

	updateLocation string
	updateStore    string
	updateThumb    string
	updateFriendly string
	updateOut      *winclient.CertificateInfo
	updateErr      error

	deleteLocation string
	deleteStore    string
	deleteThumb    string
	deleteKey      bool
	deleteErr      error
}

func (f *fakeCertificateClient) Create(_ context.Context, in winclient.CertificateInput) (*winclient.CertificateInfo, error) {
	f.createIn = in
	return f.createOut, f.createErr
}

func (f *fakeCertificateClient) Read(_ context.Context, location, store, thumbprint string) (*winclient.CertificateInfo, error) {
	f.readLocation, f.readStore, f.readThumb = location, store, thumbprint
	return f.readOut, f.readErr
}

func (f *fakeCertificateClient) LookupBySubject(_ context.Context, location, store, subject string) ([]*winclient.CertificateInfo, error) {
	f.lookupLocation, f.lookupStore, f.lookupSubject = location, store, subject
	return f.lookupOut, f.lookupErr
}

func (f *fakeCertificateClient) UpdateFriendlyName(_ context.Context, location, store, thumbprint, friendlyName string) (*winclient.CertificateInfo, error) {
	f.updateLocation, f.updateStore, f.updateThumb, f.updateFriendly = location, store, thumbprint, friendlyName
	return f.updateOut, f.updateErr
}

func (f *fakeCertificateClient) Delete(_ context.Context, location, store, thumbprint string, deletePrivateKey bool) error {
	f.deleteLocation, f.deleteStore, f.deleteThumb, f.deleteKey = location, store, thumbprint, deletePrivateKey
	return f.deleteErr
}

// certFixturePEM mints a throwaway self-signed certificate for tests (no
// committed key material) and returns its PEM encoding.
func certFixturePEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xC3A7),
		Subject:      pkix.Name{CommonName: "tf-cert-fixture.example.com"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{"tf-cert-fixture.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// okCertificateInfo builds a realistic CertificateInfo for tests.
func okCertificateInfo(pemText string) *winclient.CertificateInfo {
	normalised, err := winclient.NormalizeCertificatePEM(pemText)
	if err != nil {
		panic(err)
	}
	return &winclient.CertificateInfo{
		StoreLocation:    winclient.CertificateStoreLocalMachine,
		StoreName:        "My",
		Thumbprint:       "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
		ThumbprintSHA256: "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
		Subject:          "CN=tf-cert-fixture.example.com",
		Issuer:           "CN=tf-cert-fixture.example.com",
		SerialNumber:     "C3A7",
		NotBefore:        "2026-01-01T00:00:00Z",
		NotAfter:         "2027-01-01T00:00:00Z",
		DNSNames:         []string{"tf-cert-fixture.example.com"},
		HasPrivateKey:    false,
		FriendlyName:     "",
		NormalizedPEM:    normalised,
	}
}

// ---------------------------------------------------------------------------
// tftypes helpers for the windows_certificate schema
// ---------------------------------------------------------------------------

func certObjType() tftypes.Object {
	strList := tftypes.List{ElementType: tftypes.String}
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"store_location":     tftypes.String,
		"store_name":         tftypes.String,
		"certificate_pem":    tftypes.String,
		"pfx_base64_wo":      tftypes.String,
		"pfx_password_wo":    tftypes.String,
		"pfx_wo_version":     tftypes.Number,
		"exportable":         tftypes.Bool,
		"friendly_name":      tftypes.String,
		"delete_private_key": tftypes.Bool,
		"thumbprint":         tftypes.String,
		"thumbprint_sha256":  tftypes.String,
		"subject":            tftypes.String,
		"issuer":             tftypes.String,
		"serial_number":      tftypes.String,
		"not_before":         tftypes.String,
		"not_after":          tftypes.String,
		"dns_names":          strList,
		"has_private_key":    tftypes.Bool,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func certNullStr() tftypes.Value { return tftypes.NewValue(tftypes.String, nil) }
func certNullNum() tftypes.Value { return tftypes.NewValue(tftypes.Number, nil) }
func certNullBool() tftypes.Value {
	return tftypes.NewValue(tftypes.Bool, nil)
}
func certNullList() tftypes.Value {
	return tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil)
}

func certNullTimeoutsVal() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, map[string]tftypes.Value{
		"create": certNullStr(),
		"read":   certNullStr(),
		"update": certNullStr(),
		"delete": certNullStr(),
	})
}

func certObjBase(t *testing.T) map[string]tftypes.Value {
	t.Helper()
	return map[string]tftypes.Value{
		"id":                 certNullStr(),
		"store_location":     tftypes.NewValue(tftypes.String, "LocalMachine"),
		"store_name":         tftypes.NewValue(tftypes.String, "My"),
		"certificate_pem":    tftypes.NewValue(tftypes.String, certFixturePEM(t)),
		"pfx_base64_wo":      certNullStr(),
		"pfx_password_wo":    certNullStr(),
		"pfx_wo_version":     certNullNum(),
		"exportable":         tftypes.NewValue(tftypes.Bool, false),
		"friendly_name":      certNullStr(),
		"delete_private_key": tftypes.NewValue(tftypes.Bool, true),
		"thumbprint":         certNullStr(),
		"thumbprint_sha256":  certNullStr(),
		"subject":            certNullStr(),
		"issuer":             certNullStr(),
		"serial_number":      certNullStr(),
		"not_before":         certNullStr(),
		"not_after":          certNullStr(),
		"dns_names":          certNullList(),
		"has_private_key":    certNullBool(),
		"timeouts":           certNullTimeoutsVal(),
	}
}

func certObj(t *testing.T, overrides map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	base := certObjBase(t)
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(certObjType(), base)
}

func certState(t *testing.T, overrides map[string]tftypes.Value) tfsdk.State {
	t.Helper()
	s := windowsCertificateSchemaDefinition(context.Background())
	return tfsdk.State{Raw: certObj(t, overrides), Schema: s}
}

func certPlan(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Plan {
	t.Helper()
	s := windowsCertificateSchemaDefinition(context.Background())
	return tfsdk.Plan{Raw: certObj(t, overrides), Schema: s}
}

func certConfig(t *testing.T, overrides map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	s := windowsCertificateSchemaDefinition(context.Background())
	return tfsdk.Config{Raw: certObj(t, overrides), Schema: s}
}

func certDiagSummaries(d diag.Diagnostics) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Summary()+": "+x.Detail())
	}
	return out
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestWindowsCertificateResource_Metadata(t *testing.T) {
	r := &windowsCertificateResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_certificate" {
		t.Errorf("TypeName = %q, want windows_certificate", resp.TypeName)
	}
}

func TestWindowsCertificateResource_Schema(t *testing.T) {
	r := &windowsCertificateResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics: %v", certDiagSummaries(schemaResp.Diagnostics))
	}
	s := schemaResp.Schema

	get := func(name string) schema.Attribute {
		a, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("schema missing attribute %q", name)
		}
		return a
	}
	requiresReplace := func(attr schema.Attribute) bool {
		var descs []string
		switch v := attr.(type) {
		case schema.StringAttribute:
			for _, m := range v.PlanModifiers {
				descs = append(descs, m.Description(context.Background()))
			}
		case schema.Int64Attribute:
			for _, m := range v.PlanModifiers {
				descs = append(descs, m.Description(context.Background()))
			}
		case schema.BoolAttribute:
			for _, m := range v.PlanModifiers {
				descs = append(descs, m.Description(context.Background()))
			}
		default:
			return false
		}
		for _, d := range descs {
			// RequiresReplace() describes itself as destroy-and-recreate.
			if strings.Contains(strings.ToLower(d), "recreate") {
				return true
			}
		}
		return false
	}

	// ForceNew attributes.
	for _, name := range []string{"store_location", "store_name", "certificate_pem", "pfx_base64_wo", "pfx_password_wo", "pfx_wo_version", "exportable"} {
		if !requiresReplace(get(name)) {
			t.Errorf("%s must be ForceNew (RequiresReplace)", name)
		}
	}
	// friendly_name must NOT force replacement (the only in-place attribute).
	if requiresReplace(get("friendly_name")) {
		t.Error("friendly_name must NOT have RequiresReplace (in-place update)")
	}
	// Defaults.
	storeLocationAttr, ok := get("store_location").(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", storeLocationAttr)
	}
	if d := storeLocationAttr.Default; d == nil {
		t.Error("store_location must default to LocalMachine")
	}
	storeNameAttr, ok := get("store_name").(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected schema.StringAttribute, got %T", storeNameAttr)
	}
	if d := storeNameAttr.Default; d == nil {
		t.Error("store_name must default to My")
	}
	exportableAttr, ok := get("exportable").(schema.BoolAttribute)
	if !ok {
		t.Fatalf("expected schema.BoolAttribute, got %T", exportableAttr)
	}
	if d := exportableAttr.Default; d == nil {
		t.Error("exportable must default to false")
	}
	deleteKeyAttr, ok := get("delete_private_key").(schema.BoolAttribute)
	if !ok {
		t.Fatalf("expected schema.BoolAttribute, got %T", deleteKeyAttr)
	}
	if d := deleteKeyAttr.Default; d == nil {
		t.Error("delete_private_key must default to true")
	}
	// WriteOnly + Sensitive PFX material.
	for _, name := range []string{"pfx_base64_wo", "pfx_password_wo"} {
		a, ok := get(name).(schema.StringAttribute)
		if !ok {
			t.Fatalf("expected schema.StringAttribute, got %T", a)
		}
		if !a.WriteOnly || !a.Sensitive || !a.Optional {
			t.Errorf("%s must be Optional+Sensitive+WriteOnly", name)
		}
	}
	// Computed-only observed attributes.
	for _, name := range []string{"id", "thumbprint", "thumbprint_sha256", "subject", "issuer", "serial_number", "not_before", "not_after"} {
		a, ok := get(name).(schema.StringAttribute)
		if !ok {
			t.Fatalf("expected schema.StringAttribute, got %T", a)
		}
		if !a.Computed || a.Required || a.Optional {
			t.Errorf("%s must be Computed-only", name)
		}
	}
	hasKeyAttr, ok := get("has_private_key").(schema.BoolAttribute)
	if !ok {
		t.Fatalf("expected schema.BoolAttribute, got %T", hasKeyAttr)
	}
	if !hasKeyAttr.Computed || hasKeyAttr.Required || hasKeyAttr.Optional {
		t.Error("has_private_key must be Computed-only")
	}
	if _, ok := s.Attributes["timeouts"]; !ok {
		t.Error("schema must expose a timeouts block")
	}
	if _, ok := s.Attributes["dns_names"]; !ok {
		t.Error("schema must expose dns_names")
	}
}

// TestSchema_CertificatePfxPasswordWO_AlsoRequiresBundle mirrors
// TestSchema_ServicePasswordWO_AlsoRequiresVersion: a password without its
// bundle is a misconfiguration rejected at plan time (a password alone
// decrypts nothing, and an unprotected bundle legitimately omits it).
func TestSchema_CertificatePfxPasswordWO_AlsoRequiresBundle(t *testing.T) {
	s := windowsCertificateSchemaDefinition(context.Background())
	a, ok := s.Attributes["pfx_password_wo"]
	if !ok {
		t.Fatal("schema missing pfx_password_wo")
	}
	wo, ok := a.(schema.StringAttribute)
	if !ok {
		t.Fatalf("pfx_password_wo must be a StringAttribute, got %T", a)
	}
	found := false
	for _, v := range wo.Validators {
		if strings.Contains(v.Description(context.Background()), "pfx_base64_wo") {
			found = true
		}
	}
	if !found {
		t.Error("pfx_password_wo must AlsoRequires pfx_base64_wo (pfx_base64_wo precedent)")
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

func TestCertificateStoreNameValidator(t *testing.T) {
	v := certificateStoreNameValidator{}
	run := func(val string) diag.Diagnostics {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("store_name"), ConfigValue: types.StringValue(val)}, resp)
		return resp.Diagnostics
	}
	for _, good := range []string{"My", "Root", "TrustedPublisher", "My Store"} {
		if d := run(good); d.HasError() {
			t.Errorf("store %q must pass, got %v", good, certDiagSummaries(d))
		}
	}
	for _, bad := range []string{"My/Store", `My\Store`} {
		if d := run(bad); !d.HasError() {
			t.Errorf("store %q must fail", bad)
		}
	}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("store_name"), ConfigValue: types.StringNull()}, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null store must skip")
	}
}

func TestCertificatePEMValidator(t *testing.T) {
	v := certificatePEMValidator{}
	run := func(val string) diag.Diagnostics {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("certificate_pem"), ConfigValue: types.StringValue(val)}, resp)
		return resp.Diagnostics
	}
	if d := run(certFixturePEM(t)); d.HasError() {
		t.Errorf("fixture PEM must pass, got %v", certDiagSummaries(d))
	}
	for _, bad := range []string{"not a pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", ""} {
		if d := run(bad); !d.HasError() {
			t.Errorf("input %q must fail", bad)
		}
	}
}

func TestCertificateBase64Validator(t *testing.T) {
	v := certificateBase64Validator{}
	run := func(val string) diag.Diagnostics {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("pfx_base64_wo"), ConfigValue: types.StringValue(val)}, resp)
		return resp.Diagnostics
	}
	if d := run("aGVsbG8="); d.HasError() {
		t.Errorf("valid base64 must pass, got %v", certDiagSummaries(d))
	}
	// file() trailing newline is tolerated (stripped before decoding, like
	// .NET FromBase64String).
	if d := run("aGVsbG8=\n"); d.HasError() {
		t.Errorf("trailing newline must be tolerated, got %v", certDiagSummaries(d))
	}
	// Embedded whitespace (wrapped base64) is stripped as well.
	if d := run("aGVs\nbG8="); d.HasError() {
		t.Errorf("embedded newline must be tolerated, got %v", certDiagSummaries(d))
	}
	if d := run("%%not-base64%%"); !d.HasError() {
		t.Error("garbage must fail")
	}
}

func TestCertificatePEMNormalizeModifier(t *testing.T) {
	m := certificatePEMNormalizeModifier{}
	pemText := certFixturePEM(t)
	normalised, err := winclient.NormalizeCertificatePEM(pemText)
	if err != nil {
		t.Fatalf("fixture must normalise: %v", err)
	}
	modify := func(v types.String) types.String {
		// Mirror the framework: the response starts pre-populated with
		// the proposed value, so an unset PlanValue keeps the original.
		resp := &planmodifier.StringResponse{PlanValue: v}
		m.PlanModifyString(context.Background(), planmodifier.StringRequest{
			Path:      path.Root("certificate_pem"),
			PlanValue: v,
		}, resp)
		return resp.PlanValue
	}
	// CRLF converges to the normalised PEM.
	crlf := strings.ReplaceAll(pemText, "\n", "\r\n")
	if got := modify(types.StringValue(crlf)); got.ValueString() != normalised {
		t.Error("CRLF input must converge to the normalised PEM")
	}
	// Unparseable input passes through for the validator to report.
	if got := modify(types.StringValue("garbage")); got.ValueString() != "garbage" {
		t.Error("unparseable input must pass through for the validator")
	}
	// Null and unknown are no-ops.
	if got := modify(types.StringNull()); !got.IsNull() {
		t.Error("null must stay null")
	}
	if got := modify(types.StringUnknown()); !got.IsUnknown() {
		t.Error("unknown must stay unknown")
	}
}

func TestCertificateConfigValidator(t *testing.T) {
	v := certificateConfigValidator{}
	run := func(location, store, pem string, exportable bool) diag.Diagnostics {
		over := map[string]tftypes.Value{
			"store_location": tftypes.NewValue(tftypes.String, location),
			"store_name":     tftypes.NewValue(tftypes.String, store),
			"certificate_pem": func() tftypes.Value {
				if pem == "" {
					return certNullStr()
				}
				return tftypes.NewValue(tftypes.String, pem)
			}(),
			"exportable": tftypes.NewValue(tftypes.Bool, exportable),
		}
		req := resource.ValidateConfigRequest{Config: certConfig(t, over)}
		resp := &resource.ValidateConfigResponse{}
		v.ValidateResource(context.Background(), req, resp)
		return resp.Diagnostics
	}
	pemText := certFixturePEM(t)
	if d := run("LocalMachine", "My", pemText, false); d.HasError() {
		t.Errorf("happy path must pass, got %v", certDiagSummaries(d))
	}
	// CurrentUser trusted roots are refused.
	if d := run("CurrentUser", "Root", pemText, false); !d.HasError() {
		t.Error("CurrentUser Root must fail")
	} else if joined := strings.Join(certDiagSummaries(d), "\n"); !strings.Contains(joined, "trust anchors") {
		t.Errorf("refusal must explain trust anchors, got:\n%s", joined)
	}
	if d := run("CurrentUser", "AuthRoot", pemText, false); !d.HasError() {
		t.Error("CurrentUser AuthRoot must fail")
	}
	// Any Root store warns.
	d := run("LocalMachine", "Root", pemText, false)
	if d.HasError() {
		t.Fatalf("LocalMachine Root must only warn, got %v", certDiagSummaries(d))
	}
	if len(d) == 0 {
		t.Error("LocalMachine Root must warn")
	}
	// exportable with PEM is refused.
	if d := run("LocalMachine", "My", pemText, true); !d.HasError() {
		t.Error("exportable with PEM must fail")
	}
}

// ---------------------------------------------------------------------------
// ID helpers
// ---------------------------------------------------------------------------

func TestCertificateIDHelpers(t *testing.T) {
	if id := certificateID("LocalMachine", "My", "ABC123"); id != "LocalMachine/My/ABC123" {
		t.Errorf("id = %q", id)
	}
	loc, store, thumb, err := splitCertificateID("LocalMachine/My/ABC123")
	if err != nil || loc != "LocalMachine" || store != "My" || thumb != "ABC123" {
		t.Errorf("split = %q, %q, %q, %v", loc, store, thumb, err)
	}
	loc, store, thumb, err = splitCertificateID(" LocalMachine / My / ABC123 ")
	if err != nil || loc != "LocalMachine" || store != "My" || thumb != "ABC123" {
		t.Errorf("spaced split = %q, %q, %q, %v", loc, store, thumb, err)
	}
	for _, bad := range []string{"", "no-separator", "a/b", "a/b/c/d", "/My/ABC", "LocalMachine//ABC", "LocalMachine/My/"} {
		if _, _, _, err := splitCertificateID(bad); err == nil {
			t.Errorf("ID %q must fail", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure / effective PFX
// ---------------------------------------------------------------------------

func TestWindowsCertificateResource_Configure(t *testing.T) {
	r := &windowsCertificateResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "nope"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong provider data type must error")
	}
}

func TestEffectiveCertificatePFX(t *testing.T) {
	plan := windowsCertificateModel{}
	config := windowsCertificateModel{
		PFXBase64WO:   types.StringValue("  YnVuZGxl  "),
		PFXPasswordWO: types.StringValue("pw"),
	}
	bundle, password, ok := effectiveCertificatePFX(plan, config)
	if !ok || bundle != "YnVuZGxl" || password != "pw" {
		t.Errorf("config precedence: got %q, %q, %v", bundle, password, ok)
	}
	// Plan fallback for callers bypassing Config (unit tests driving Plan).
	// No password is configured, so only the bundle is reported.
	planOnly := windowsCertificateModel{PFXBase64WO: types.StringValue("cGxhbg==")}
	if bundle, _, _ := effectiveCertificatePFX(planOnly, windowsCertificateModel{}); bundle != "cGxhbg==" {
		t.Errorf("plan fallback: got %q", bundle)
	}
	if _, _, ok := effectiveCertificatePFX(windowsCertificateModel{}, windowsCertificateModel{}); ok {
		t.Error("empty must report unset")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestWindowsCertificateResource_Create_PEMHappyPath(t *testing.T) {
	pemText := certFixturePEM(t)
	fc := &fakeCertificateClient{createOut: okCertificateInfo(pemText)}
	r := &windowsCertificateResource{certs: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: certPlan(t, nil), Config: certConfig(t, nil)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", certDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.StoreLocation != "LocalMachine" || fc.createIn.StoreName != "My" {
		t.Errorf("unexpected store: %+v", fc.createIn)
	}
	if strings.TrimSpace(fc.createIn.CertificatePEM) == "" || fc.createIn.PFXBase64 != "" {
		t.Errorf("PEM must be forwarded, PFX empty: %+v", fc.createIn)
	}
	var model windowsCertificateModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("id = %q", model.ID.ValueString())
	}
	wantPEM, _ := winclient.NormalizeCertificatePEM(pemText)
	if model.CertificatePEM.ValueString() != wantPEM {
		t.Error("state PEM must be the normalised form")
	}
	if !model.PFXBase64WO.IsNull() || !model.PFXPasswordWO.IsNull() || !model.PFXWOVersion.IsNull() {
		t.Error("WriteOnly material must never reach state")
	}
	if model.Subject.ValueString() != "CN=tf-cert-fixture.example.com" || model.HasPrivateKey.ValueBool() {
		t.Errorf("computed not refreshed: %+v", model)
	}
}

func TestWindowsCertificateResource_Create_PFXOverlaysConfig(t *testing.T) {
	pemText := certFixturePEM(t)
	info := okCertificateInfo(pemText)
	info.HasPrivateKey = true
	fc := &fakeCertificateClient{createOut: info}
	r := &windowsCertificateResource{certs: fc}
	plan := certPlan(t, map[string]tftypes.Value{
		"certificate_pem": certNullStr(),
		"pfx_wo_version":  tftypes.NewValue(tftypes.Number, 1),
	})
	config := certConfig(t, map[string]tftypes.Value{
		"certificate_pem": certNullStr(),
		"pfx_base64_wo":   tftypes.NewValue(tftypes.String, "YnVuZGxl"),
		"pfx_password_wo": tftypes.NewValue(tftypes.String, "pw"),
		"pfx_wo_version":  tftypes.NewValue(tftypes.Number, 1),
	})
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: config}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", certDiagSummaries(resp.Diagnostics))
	}
	if fc.createIn.PFXBase64 != "YnVuZGxl" {
		t.Errorf("bundle not forwarded from config, got %q", fc.createIn.PFXBase64)
	}
	if fc.createIn.PFXPassword == nil || *fc.createIn.PFXPassword != "pw" {
		t.Errorf("password not forwarded from config: %+v", fc.createIn.PFXPassword)
	}
	var model windowsCertificateModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.CertificatePEM.ValueString() != "" && !model.CertificatePEM.IsNull() {
		t.Errorf("PFX state must keep certificate_pem null, got %q", model.CertificatePEM.ValueString())
	}
	if model.PFXWOVersion.ValueInt64() != 1 {
		t.Errorf("version must ride along in state, got %v", model.PFXWOVersion)
	}
}

func TestWindowsCertificateResource_Create_MissingPayload(t *testing.T) {
	fc := &fakeCertificateClient{}
	r := &windowsCertificateResource{certs: fc}
	plan := certPlan(t, map[string]tftypes.Value{
		"certificate_pem": certNullStr(),
	})
	config := certConfig(t, map[string]tftypes.Value{
		"certificate_pem": certNullStr(),
	})
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan, Config: config}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("missing payload must fail closed")
	}
}

func TestWindowsCertificateResource_Create_AlreadyExists(t *testing.T) {
	fc := &fakeCertificateClient{createErr: winclient.NewCertificateError(
		winclient.CertificateErrorAlreadyExists, "present; terraform import", nil, nil)}
	r := &windowsCertificateResource{certs: fc}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Create(context.Background(), resource.CreateRequest{Plan: certPlan(t, nil), Config: certConfig(t, nil)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an already_exists diagnostic")
	}
	if joined := strings.Join(certDiagSummaries(resp.Diagnostics), "\n"); !strings.Contains(joined, "already_exists") {
		t.Errorf("diagnostic must name already_exists, got:\n%s", joined)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestWindowsCertificateResource_Read(t *testing.T) {
	pemText := certFixturePEM(t)
	wantPEM, _ := winclient.NormalizeCertificatePEM(pemText)
	_ = wantPEM
	fc := &fakeCertificateClient{readOut: okCertificateInfo(pemText)}
	r := &windowsCertificateResource{certs: fc}
	state := certState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", certDiagSummaries(resp.Diagnostics))
	}
	if fc.readLocation != "LocalMachine" || fc.readStore != "My" || fc.readThumb != "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("unexpected read args: %q %q %q", fc.readLocation, fc.readStore, fc.readThumb)
	}
	var model windowsCertificateModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.Subject.ValueString() != "CN=tf-cert-fixture.example.com" {
		t.Errorf("computed not refreshed: %+v", model)
	}
}

func TestWindowsCertificateResource_Read_MissingRemoves(t *testing.T) {
	fc := &fakeCertificateClient{readOut: nil}
	r := &windowsCertificateResource{certs: fc}
	state := certState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("missing must not error: %v", certDiagSummaries(resp.Diagnostics))
	}
	if !resp.State.Raw.IsNull() {
		t.Error("missing certificate must remove the resource from state")
	}
}

func TestWindowsCertificateResource_Read_Error(t *testing.T) {
	fc := &fakeCertificateClient{readErr: winclient.NewCertificateError(
		winclient.CertificateErrorAccessDenied, "denied", nil, nil)}
	r := &windowsCertificateResource{certs: fc}
	state := certState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("remote error must surface")
	}
}

// ---------------------------------------------------------------------------
// Update / Delete
// ---------------------------------------------------------------------------

func TestWindowsCertificateResource_Update_FriendlyName(t *testing.T) {
	pemText := certFixturePEM(t)
	out := okCertificateInfo(pemText)
	out.FriendlyName = "renamed"
	fc := &fakeCertificateClient{updateOut: out}
	r := &windowsCertificateResource{certs: fc}
	prior := certState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan: certPlan(t, map[string]tftypes.Value{
			"friendly_name": tftypes.NewValue(tftypes.String, "renamed"),
		}),
		State: prior,
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", certDiagSummaries(resp.Diagnostics))
	}
	if fc.updateLocation != "LocalMachine" || fc.updateStore != "My" ||
		fc.updateThumb != "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" || fc.updateFriendly != "renamed" {
		t.Errorf("unexpected update args: %+v", fc)
	}
	var model windowsCertificateModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("update must preserve the ID, got %q", model.ID.ValueString())
	}
	if model.FriendlyName.ValueString() != "renamed" {
		t.Errorf("friendly name not refreshed: %+v", model)
	}
}

func TestWindowsCertificateResource_Delete(t *testing.T) {
	for _, deleteKey := range []bool{true, false} {
		fc := &fakeCertificateClient{}
		r := &windowsCertificateResource{certs: fc}
		state := certState(t, map[string]tftypes.Value{
			"id":                 tftypes.NewValue(tftypes.String, "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
			"delete_private_key": tftypes.NewValue(tftypes.Bool, deleteKey),
		})
		resp := &resource.DeleteResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
		r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)

		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", certDiagSummaries(resp.Diagnostics))
		}
		if fc.deleteLocation != "LocalMachine" || fc.deleteStore != "My" ||
			fc.deleteThumb != "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" || fc.deleteKey != deleteKey {
			t.Errorf("unexpected delete args: %+v", fc)
		}
	}
}

func TestWindowsCertificateResource_Delete_InvalidID(t *testing.T) {
	fc := &fakeCertificateClient{}
	r := &windowsCertificateResource{certs: fc}
	state := certState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "not-an-id"),
	})
	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("invalid ID must error")
	}
}

func TestWindowsCertificateResource_Delete_NotFound_Idempotent(t *testing.T) {
	fc := &fakeCertificateClient{deleteErr: winclient.NewCertificateError(
		winclient.CertificateErrorNotFound, "certificate not found", nil, nil)}
	r := &windowsCertificateResource{certs: fc}
	state := certState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete of a missing certificate should be a no-op, got: %v", certDiagSummaries(resp.Diagnostics))
	}
}

func TestWindowsCertificateResource_Delete_PermissionDenied(t *testing.T) {
	fc := &fakeCertificateClient{deleteErr: winclient.NewCertificateError(
		winclient.CertificateErrorAccessDenied, "access denied", nil, nil)}
	r := &windowsCertificateResource{certs: fc}
	state := certState(t, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic for delete failure")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestWindowsCertificateResource_ImportState_PEM(t *testing.T) {
	pemText := certFixturePEM(t)
	fc := &fakeCertificateClient{readOut: okCertificateInfo(pemText)}
	r := &windowsCertificateResource{certs: fc}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), resource.ImportStateRequest{
		ID: "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", certDiagSummaries(resp.Diagnostics))
	}
	var model windowsCertificateModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("id = %q", model.ID.ValueString())
	}
	wantPEM, _ := winclient.NormalizeCertificatePEM(pemText)
	if model.CertificatePEM.ValueString() != wantPEM {
		t.Error("keyless import must carry the normalised PEM")
	}
	if !model.PFXWOVersion.IsNull() {
		t.Error("keyless import must leave the PFX version null")
	}
}

func TestWindowsCertificateResource_ImportState_PFX(t *testing.T) {
	pemText := certFixturePEM(t)
	info := okCertificateInfo(pemText)
	info.HasPrivateKey = true
	info.NormalizedPEM = ""
	fc := &fakeCertificateClient{readOut: info}
	r := &windowsCertificateResource{certs: fc}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	// Lowercase location canonicalises.
	r.ImportState(context.Background(), resource.ImportStateRequest{
		ID: "localmachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", certDiagSummaries(resp.Diagnostics))
	}
	var model windowsCertificateModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.PFXWOVersion.ValueInt64() != 1 {
		t.Errorf("keyed import must set pfx_wo_version = 1, got %v", model.PFXWOVersion)
	}
	if !model.CertificatePEM.IsNull() {
		t.Error("keyed import must leave certificate_pem null")
	}
	if model.StoreLocation.ValueString() != "LocalMachine" {
		t.Errorf("location must canonicalise, got %q", model.StoreLocation.ValueString())
	}
}

func TestWindowsCertificateResource_ImportState_BadIDs(t *testing.T) {
	fc := &fakeCertificateClient{}
	r := &windowsCertificateResource{certs: fc}
	for _, bad := range []string{"", "no-separator", "a/b", "Nope/My/ABC123", "LocalMachine/My/"} {
		resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
		r.ImportState(context.Background(), resource.ImportStateRequest{ID: bad}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("ID %q must fail", bad)
		}
	}
}

func TestWindowsCertificateResource_ImportState_NotFound(t *testing.T) {
	fc := &fakeCertificateClient{readOut: nil}
	r := &windowsCertificateResource{certs: fc}
	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: windowsCertificateSchemaDefinition(context.Background())}}
	r.ImportState(context.Background(), resource.ImportStateRequest{
		ID: "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("missing certificate must fail the import")
	}
}
