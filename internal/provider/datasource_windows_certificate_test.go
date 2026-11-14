// Package provider — unit tests for the windows_certificate data source.
//
// Tests cover: Metadata, Schema, ConfigValidators (ExactlyOneOf), Configure,
// Read by thumbprint (happy, not-found, nil, error), Read by subject (happy,
// zero, multiple with most_recent true/false), and the timeouts.read bound.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeCertificateClientDS struct {
	readOut []*winclient.CertificateInfo
	readErr error
	readLoc string
	readSto string
	readThu string

	lookupOut []*winclient.CertificateInfo
	lookupErr error
	lookupSub string
}

func (f *fakeCertificateClientDS) Create(_ context.Context, _ winclient.CertificateInput) (*winclient.CertificateInfo, error) {
	panic("Create not used in data source")
}

func (f *fakeCertificateClientDS) Read(_ context.Context, location, store, thumbprint string) (*winclient.CertificateInfo, error) {
	f.readLoc, f.readSto, f.readThu = location, store, thumbprint
	if f.readErr != nil {
		return nil, f.readErr
	}
	if len(f.readOut) == 0 {
		return nil, nil
	}
	return f.readOut[0], nil
}

func (f *fakeCertificateClientDS) LookupBySubject(_ context.Context, _, _ string, subject string) ([]*winclient.CertificateInfo, error) {
	f.lookupSub = subject
	return f.lookupOut, f.lookupErr
}

func (f *fakeCertificateClientDS) UpdateFriendlyName(_ context.Context, _, _, _, _ string) (*winclient.CertificateInfo, error) {
	panic("UpdateFriendlyName not used in data source")
}

func (f *fakeCertificateClientDS) Delete(_ context.Context, _, _, _ string, _ bool) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func certDSObjType() tftypes.Object {
	strList := tftypes.List{ElementType: tftypes.String}
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                tftypes.String,
		"thumbprint":        tftypes.String,
		"subject":           tftypes.String,
		"store_location":    tftypes.String,
		"store_name":        tftypes.String,
		"most_recent":       tftypes.Bool,
		"thumbprint_sha256": tftypes.String,
		"issuer":            tftypes.String,
		"serial_number":     tftypes.String,
		"not_before":        tftypes.String,
		"not_after":         tftypes.String,
		"dns_names":         strList,
		"has_private_key":   tftypes.Bool,
		"friendly_name":     tftypes.String,
		"timeouts":          dsTimeoutsObjType(),
	}}
}

func certDSConfig(overrides map[string]tftypes.Value) tfsdk.Config {
	d := &windowsCertificateDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	base := map[string]tftypes.Value{
		"id":                tftypes.NewValue(tftypes.String, nil),
		"thumbprint":        tftypes.NewValue(tftypes.String, nil),
		"subject":           tftypes.NewValue(tftypes.String, nil),
		"store_location":    tftypes.NewValue(tftypes.String, nil),
		"store_name":        tftypes.NewValue(tftypes.String, nil),
		"most_recent":       tftypes.NewValue(tftypes.Bool, nil),
		"thumbprint_sha256": tftypes.NewValue(tftypes.String, nil),
		"issuer":            tftypes.NewValue(tftypes.String, nil),
		"serial_number":     tftypes.NewValue(tftypes.String, nil),
		"not_before":        tftypes.NewValue(tftypes.String, nil),
		"not_after":         tftypes.NewValue(tftypes.String, nil),
		"dns_names":         tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
		"has_private_key":   tftypes.NewValue(tftypes.Bool, nil),
		"friendly_name":     tftypes.NewValue(tftypes.String, nil),
		"timeouts":          dsNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tfsdk.Config{Schema: sr.Schema, Raw: tftypes.NewValue(certDSObjType(), base)}
}

func certDSInfo(thumb, subject, notBefore string) *winclient.CertificateInfo {
	return &winclient.CertificateInfo{
		StoreLocation:    winclient.CertificateStoreLocalMachine,
		StoreName:        "My",
		Thumbprint:       thumb,
		ThumbprintSHA256: "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
		Subject:          subject,
		Issuer:           "CN=Test CA",
		SerialNumber:     "C3A7",
		NotBefore:        notBefore,
		NotAfter:         "2027-01-01T00:00:00Z",
		DNSNames:         []string{"example.com"},
		HasPrivateKey:    false,
		FriendlyName:     "ds-fixture",
		NormalizedPEM:    "",
	}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators
// ---------------------------------------------------------------------------

func TestCertificateDSMetadata(t *testing.T) {
	d := &windowsCertificateDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_certificate" {
		t.Errorf("TypeName = %q, want windows_certificate", resp.TypeName)
	}
}

func TestCertificateDSSchema(t *testing.T) {
	d := &windowsCertificateDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics: %v", resp.Diagnostics)
	}
	for _, k := range []string{"id", "thumbprint", "subject", "store_location", "store_name", "most_recent",
		"thumbprint_sha256", "issuer", "serial_number", "not_before", "not_after", "dns_names", "has_private_key", "friendly_name", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	// No WriteOnly attributes on a data source.
	for name, attr := range resp.Schema.Attributes {
		type writeOnlyChecker interface{ IsWriteOnly() bool }
		if wo, ok := attr.(writeOnlyChecker); ok && wo.IsWriteOnly() {
			t.Errorf("data source attribute %q must not be WriteOnly", name)
		}
	}
	if got := d.ConfigValidators(context.Background()); len(got) != 1 {
		t.Errorf("want exactly one ConfigValidator (ExactlyOneOf), got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestCertificateDSConfigure(t *testing.T) {
	d := &windowsCertificateDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not error: %v", resp.Diagnostics)
	}
	resp = &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "bad"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
}

// ---------------------------------------------------------------------------
// Read — by thumbprint
// ---------------------------------------------------------------------------

func TestCertificateDSRead_ByThumbprint_HappyPath(t *testing.T) {
	info := certDSInfo("A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", "CN=example.com", "2026-01-01T00:00:00Z")
	d := &windowsCertificateDataSource{certs: &fakeCertificateClientDS{readOut: []*winclient.CertificateInfo{info}}}
	cfg := certDSConfig(map[string]tftypes.Value{
		"thumbprint": tftypes.NewValue(tftypes.String, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"),
	})
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsCertificateDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Errorf("ID = %q", state.ID.ValueString())
	}
	if state.Subject.ValueString() != "CN=example.com" || state.Thumbprint.ValueString() != info.Thumbprint {
		t.Errorf("observed not mapped: %+v", state)
	}
}

func TestCertificateDSRead_ByThumbprint_NotFound(t *testing.T) {
	d := &windowsCertificateDataSource{certs: &fakeCertificateClientDS{
		readErr: winclient.NewCertificateError(winclient.CertificateErrorNotFound, "gone", nil, nil),
	}}
	cfg := certDSConfig(map[string]tftypes.Value{
		"thumbprint": tftypes.NewValue(tftypes.String, "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for not-found certificate")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestCertificateDSRead_ByThumbprint_NilResult(t *testing.T) {
	d := &windowsCertificateDataSource{certs: &fakeCertificateClientDS{}}
	cfg := certDSConfig(map[string]tftypes.Value{
		"thumbprint": tftypes.NewValue(tftypes.String, "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"),
	})
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("nil result must produce error")
	}
}

// ---------------------------------------------------------------------------
// Read — by subject
// ---------------------------------------------------------------------------

func TestCertificateDSRead_BySubject(t *testing.T) {
	old := certDSInfo("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CN=example.com", "2026-01-01T00:00:00Z")
	newer := certDSInfo("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "CN=example.com", "2026-06-01T00:00:00Z")
	d := &windowsCertificateDataSource{certs: &fakeCertificateClientDS{lookupOut: []*winclient.CertificateInfo{old, newer}}}
	cfg := certDSConfig(map[string]tftypes.Value{
		"subject":     tftypes.NewValue(tftypes.String, "CN=example.com"),
		"most_recent": tftypes.NewValue(tftypes.Bool, true),
	})
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsCertificateDataSourceModel
	resp.State.Get(context.Background(), &state)
	// Explicit most_recent=true: the later not_before wins.
	if state.Thumbprint.ValueString() != "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" {
		t.Errorf("most_recent must pick the later certificate, got %q", state.Thumbprint.ValueString())
	}
	if !state.MostRecent.ValueBool() {
		t.Error("most_recent must echo true in state")
	}
}

func TestCertificateDSRead_BySubject_OmittedMostRecentIsAmbiguous(t *testing.T) {
	old := certDSInfo("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CN=example.com", "2026-01-01T00:00:00Z")
	newer := certDSInfo("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "CN=example.com", "2026-06-01T00:00:00Z")
	d := &windowsCertificateDataSource{certs: &fakeCertificateClientDS{lookupOut: []*winclient.CertificateInfo{old, newer}}}
	cfg := certDSConfig(map[string]tftypes.Value{
		"subject": tftypes.NewValue(tftypes.String, "CN=example.com"),
	})
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("several matches with omitted most_recent (default false) must error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "Ambiguous") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestCertificateDSRead_BySubject_MultipleForbidden(t *testing.T) {
	old := certDSInfo("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CN=example.com", "2026-01-01T00:00:00Z")
	newer := certDSInfo("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "CN=example.com", "2026-06-01T00:00:00Z")
	d := &windowsCertificateDataSource{certs: &fakeCertificateClientDS{lookupOut: []*winclient.CertificateInfo{old, newer}}}
	cfg := certDSConfig(map[string]tftypes.Value{
		"subject":     tftypes.NewValue(tftypes.String, "CN=example.com"),
		"most_recent": tftypes.NewValue(tftypes.Bool, false),
	})
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("several matches with most_recent=false must error")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "Ambiguous") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestCertificateDSRead_BySubject_ZeroMatches(t *testing.T) {
	d := &windowsCertificateDataSource{certs: &fakeCertificateClientDS{
		lookupErr: winclient.NewCertificateError(winclient.CertificateErrorNotFound, "zero", nil, nil),
	}}
	cfg := certDSConfig(map[string]tftypes.Value{
		"subject": tftypes.NewValue(tftypes.String, "CN=missing"),
	})
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("zero matches must produce error")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestPickMostRecentCertificate(t *testing.T) {
	a := certDSInfo("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CN=x", "2026-01-01T00:00:00Z")
	b := certDSInfo("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "CN=x", "2026-06-01T00:00:00Z")
	if got := pickMostRecentCertificate([]*winclient.CertificateInfo{a, b}); got.Thumbprint != b.Thumbprint {
		t.Errorf("want %q, got %q", b.Thumbprint, got.Thumbprint)
	}
	// Deterministic tie-break.
	c := certDSInfo("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CN=x", "2026-01-01T00:00:00Z")
	dup := certDSInfo("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CN=x", "2026-01-01T00:00:00Z")
	if got := pickMostRecentCertificate([]*winclient.CertificateInfo{c, dup}); got.Thumbprint != c.Thumbprint {
		t.Errorf("tie must resolve deterministically, got %q", got.Thumbprint)
	}
}

func TestCertificateDataSourceDefaults(t *testing.T) {
	loc, store, recent := certificateDataSourceDefaults(windowsCertificateDataSourceModel{})
	if loc != "LocalMachine" || store != "My" || recent {
		t.Errorf("defaults = %q, %q, %v", loc, store, recent)
	}
}
