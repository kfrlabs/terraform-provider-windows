// Package provider — unit tests for the windows_iis_site data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative inputs), Configure, Read happy path (incl. the bindings
// view), not-found (typed and nil, with a single-line detail), generic
// error, invalid name short-circuit, timeouts.read deadline propagation
// and null-config default resolution.
package provider

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeIISSiteClientDS struct {
	readOut  *winclient.IISSiteState
	readErr  error
	readName string

	deadline time.Time
	ok       bool
}

func (f *fakeIISSiteClientDS) Read(ctx context.Context, name string) (*winclient.IISSiteState, error) {
	f.readName = name
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

func (f *fakeIISSiteClientDS) Create(_ context.Context, _ winclient.IISSiteInput) (*winclient.IISSiteState, error) {
	panic("Create not used in data source")
}

func (f *fakeIISSiteClientDS) Update(_ context.Context, _ winclient.IISSiteInput) (*winclient.IISSiteState, error) {
	panic("Update not used in data source")
}

func (f *fakeIISSiteClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func siteDSBindingsType() tftypes.List {
	return tftypes.List{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"protocol":            tftypes.String,
		"binding_information": tftypes.String,
	}}}
}

func siteDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                         tftypes.String,
		"name":                       tftypes.String,
		"site_id":                    tftypes.Number,
		"physical_path":              tftypes.String,
		"application_pool":           tftypes.String,
		"auto_start":                 tftypes.Bool,
		"preload_enabled":            tftypes.Bool,
		"enabled_protocols":          tftypes.String,
		"log_enabled":                tftypes.Bool,
		"log_directory":              tftypes.String,
		"log_format":                 tftypes.String,
		"connection_timeout_seconds": tftypes.Number,
		"max_connections":            tftypes.Number,
		"bindings":                   siteDSBindingsType(),
		"state":                      tftypes.String,
		"timeouts":                   dsTimeoutsObjType(),
	}}
}

func siteDSConfig(name string) tfsdk.Config {
	d := &windowsIISSiteDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := map[string]tftypes.Value{}
	for k, t := range siteDSObjType().AttributeTypes {
		if k == "name" {
			vals[k] = tftypes.NewValue(t, name)
			continue
		}
		if k == "timeouts" {
			vals[k] = dsNullTimeoutsValue()
			continue
		}
		vals[k] = tftypes.NewValue(t, nil)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(siteDSObjType(), vals),
	}
}

func siteDSState() *winclient.IISSiteState {
	st := okIISSiteState()
	st.Bindings = []winclient.IISSiteBinding{{Protocol: "http", BindingInformation: "*:80:web"}}
	return st
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestIISSiteDSMetadata(t *testing.T) {
	d := &windowsIISSiteDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_iis_site" {
		t.Errorf("TypeName = %q, want windows_iis_site", resp.TypeName)
	}
}

func TestNewWindowsIISSiteDataSource_NotNil(t *testing.T) {
	if NewWindowsIISSiteDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestIISSiteDSSchema_AllAttributes(t *testing.T) {
	d := &windowsIISSiteDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "name", "site_id", "physical_path",
		"application_pool", "auto_start", "preload_enabled",
		"enabled_protocols", "log_enabled", "log_directory", "log_format",
		"connection_timeout_seconds", "max_connections",
		"bindings", "state", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestIISSiteDSSchema_QueryKeyRequired(t *testing.T) {
	d := &windowsIISSiteDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type requiredChecker interface{ IsRequired() bool }
	type computedChecker interface{ IsComputed() bool }
	a := resp.Schema.Attributes["name"]
	if a == nil {
		t.Fatal("attribute name not found")
	}
	rc, ok := a.(requiredChecker)
	if !ok || !rc.IsRequired() {
		t.Error("attribute name must be Required")
	}
	if cc, ok := a.(computedChecker); !ok || cc.IsComputed() {
		t.Error("attribute name must not be Computed: it is the lookup key")
	}
}

func TestIISSiteDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsIISSiteDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"id", "site_id", "physical_path",
		"application_pool", "auto_start", "preload_enabled",
		"enabled_protocols", "log_enabled", "log_directory", "log_format",
		"connection_timeout_seconds", "max_connections",
		"bindings", "state"} {
		a := resp.Schema.Attributes[k]
		if a == nil {
			t.Errorf("attribute %q not found", k)
			continue
		}
		cc, ok := a.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
		if oc, ok := a.(optionalChecker); ok && oc.IsOptional() {
			t.Errorf("attribute %q must not be Optional: observed state is read-only", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestIISSiteDSConfigure_Nil(t *testing.T) {
	d := &windowsIISSiteDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestIISSiteDSConfigure_WrongType(t *testing.T) {
	d := &windowsIISSiteDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestIISSiteDSConfigure_CorrectType(t *testing.T) {
	d := &windowsIISSiteDataSource{}
	resp := &datasource.ConfigureResponse{}
	c := &winclient.Client{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path
// ---------------------------------------------------------------------------

func TestIISSiteDSRead_HappyPath(t *testing.T) {
	d := &windowsIISSiteDataSource{
		site: &fakeIISSiteClientDS{readOut: siteDSState()},
	}
	cfg := siteDSConfig("web")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsIISSiteDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "web" {
		t.Errorf("ID = %q, want the site name", state.ID.ValueString())
	}
	if state.SiteID.ValueInt64() != 2 {
		t.Errorf("SiteID = %d, want 2", state.SiteID.ValueInt64())
	}
	if state.PhysicalPath.ValueString() != `C:\inetpub\wwwroot` {
		t.Errorf("PhysicalPath = %q, want the observed path", state.PhysicalPath.ValueString())
	}
	if state.State.ValueString() != "Stopped" {
		t.Errorf("State = %q, want Stopped", state.State.ValueString())
	}
	var bindings []windowsIISSiteBindingModel
	if dgs := state.Bindings.ElementsAs(context.Background(), &bindings, false); dgs.HasError() {
		t.Fatalf("bindings ElementsAs: %v", dgs)
	}
	if len(bindings) != 1 || bindings[0].Protocol.ValueString() != "http" ||
		bindings[0].BindingInformation.ValueString() != "*:80:web" {
		t.Errorf("bindings = %+v, want the observed view", bindings)
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read
// ---------------------------------------------------------------------------

func TestIISSiteDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", iisSiteDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeIISSiteClientDS{readOut: siteDSState()}
			d := &windowsIISSiteDataSource{site: fake}
			cfg := siteDSConfig("web")
			if tc.customRead != "" {
				cfg = dsConfigWithReadTimeout(t, cfg, tc.customRead)
			}
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
			d.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Timeouts — null-config default resolution
// ---------------------------------------------------------------------------

func siteDSnTimeouts(t *testing.T, read *string) dstimeouts.Value {
	t.Helper()
	var v attr.Value = types.StringNull()
	if read != nil {
		v = types.StringValue(*read)
	}
	obj, diags := types.ObjectValue(
		map[string]attr.Type{"read": types.StringType},
		map[string]attr.Value{"read": v},
	)
	if diags.HasError() {
		t.Fatalf("ObjectValue: %v", diags)
	}
	return dstimeouts.Value{Object: obj}
}

func TestIISSiteDSnTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := siteDSnTimeouts(t, nil).Read(ctx, iisSiteDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != iisSiteDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, iisSiteDSDefaultTimeout)
	}
	if iisSiteDSDefaultTimeout != iisSiteDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", iisSiteDSDefaultTimeout, iisSiteDefaultTimeout)
	}

	custom := "45s"
	got, diags = siteDSnTimeouts(t, &custom).Read(ctx, iisSiteDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("custom timeouts diags: %v", diags)
	}
	if got != 45*time.Second {
		t.Errorf("custom timeouts resolved to %v, want 45s", got)
	}
}

// ---------------------------------------------------------------------------
// Read — not found (typed and nil) / generic error
// ---------------------------------------------------------------------------

func TestIISSiteDSRead_TypedNotFound(t *testing.T) {
	d := &windowsIISSiteDataSource{
		site: &fakeIISSiteClientDS{
			readErr: &winclient.IISSiteError{Kind: winclient.IISSiteErrorNotFound, Message: "gone"},
		},
	}
	cfg := siteDSConfig("web")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for typed not_found")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestIISSiteDSRead_NilResult(t *testing.T) {
	d := &windowsIISSiteDataSource{
		site: &fakeIISSiteClientDS{readOut: nil, readErr: nil},
	}
	cfg := siteDSConfig("web")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for nil state result")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestIISSiteDSRead_NotFoundDetailSingleLine(t *testing.T) {
	want := regexp.MustCompile(`No IIS site named .* was found on the target host\.`)

	cases := []struct {
		name   string
		client *fakeIISSiteClientDS
	}{
		{"typed", &fakeIISSiteClientDS{
			readErr: &winclient.IISSiteError{Kind: winclient.IISSiteErrorNotFound, Message: "gone"},
		}},
		{"nil", &fakeIISSiteClientDS{readOut: nil, readErr: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &windowsIISSiteDataSource{site: tc.client}
			cfg := siteDSConfig("web")
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

			d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatal("expected not-found error")
			}
			detail := resp.Diagnostics[0].Detail()
			if strings.Contains(detail, "\n") {
				t.Errorf("not-found detail must be a single line, got: %q", detail)
			}
			if !want.MatchString(detail) {
				t.Errorf("not-found detail %q does not match %v", detail, want)
			}
		})
	}
}

func TestIISSiteDSRead_TypedError(t *testing.T) {
	d := &windowsIISSiteDataSource{
		site: &fakeIISSiteClientDS{
			readErr: &winclient.IISSiteError{Kind: winclient.IISSiteErrorAccessDenied, Message: "denied"},
		},
	}
	cfg := siteDSConfig("web")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
}

func TestIISSiteDSRead_GenericError(t *testing.T) {
	d := &windowsIISSiteDataSource{
		site: &fakeIISSiteClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := siteDSConfig("web")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}

func TestIISSiteDSRead_InvalidName(t *testing.T) {
	d := &windowsIISSiteDataSource{
		site: &fakeIISSiteClientDS{readOut: siteDSState()},
	}
	fake, ok := d.site.(*fakeIISSiteClientDS)
	if !ok {
		t.Fatalf("expected *fakeIISSiteClientDS, got %T", fake)
	}
	cfg := siteDSConfig("a/b")
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for an invalid site name")
	}
	if fake.readName != "" {
		t.Errorf("invalid name must not reach the host, got read of %q", fake.readName)
	}
}
