// Package provider — unit tests for the windows_firewall_profile data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative inputs), Configure, Read happy path (incl. tri-state nulls and
// the alias set), not-found (typed and nil, with a single-line detail),
// generic error, timeouts.read deadline propagation and null-config default
// resolution.
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

type fakeFirewallProfileClientDS struct {
	readOut  *winclient.FirewallProfileState
	readErr  error
	readName string

	deadline time.Time
	ok       bool
}

func (f *fakeFirewallProfileClientDS) Read(ctx context.Context, name string) (*winclient.FirewallProfileState, error) {
	f.readName = name
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

func (f *fakeFirewallProfileClientDS) Apply(_ context.Context, _ string, _ winclient.FirewallProfileSettings) (*winclient.FirewallProfileState, error) {
	panic("Apply not used in data source")
}

func (f *fakeFirewallProfileClientDS) Restore(_ context.Context, _ winclient.FirewallProfileState) (*winclient.FirewallProfileState, error) {
	panic("Restore not used in data source")
}

func (f *fakeFirewallProfileClientDS) SSHProfile(_ context.Context) (string, error) {
	panic("SSHProfile not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func fpDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                                  tftypes.String,
		"name":                                tftypes.String,
		"enabled":                             tftypes.Bool,
		"default_inbound_action":              tftypes.String,
		"default_outbound_action":             tftypes.String,
		"allow_inbound_rules":                 tftypes.Bool,
		"allow_local_firewall_rules":          tftypes.Bool,
		"allow_local_ipsec_rules":             tftypes.Bool,
		"allow_unicast_response_to_multicast": tftypes.Bool,
		"notify_on_listen":                    tftypes.Bool,
		"log_file_name":                       tftypes.String,
		"log_max_size_kilobytes":              tftypes.Number,
		"log_allowed":                         tftypes.Bool,
		"log_blocked":                         tftypes.Bool,
		"log_ignored":                         tftypes.Bool,
		"disabled_interface_aliases":          tftypes.Set{ElementType: tftypes.String},
		"timeouts":                            dsTimeoutsObjType(),
	}}
}

func fpDSConfig(name string) tfsdk.Config {
	d := &windowsFirewallProfileDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := map[string]tftypes.Value{}
	for k, t := range fpDSObjType().AttributeTypes {
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
		Raw:    tftypes.NewValue(fpDSObjType(), vals),
	}
}

func fpDSState() *winclient.FirewallProfileState {
	st := okFirewallProfileState("Public")
	st.DisabledInterfaceAliases = []string{"Ethernet 2"}
	return st
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestFirewallProfileDSMetadata(t *testing.T) {
	d := &windowsFirewallProfileDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_firewall_profile" {
		t.Errorf("TypeName = %q, want windows_firewall_profile", resp.TypeName)
	}
}

func TestNewWindowsFirewallProfileDataSource_NotNil(t *testing.T) {
	if NewWindowsFirewallProfileDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestFirewallProfileDSSchema_AllAttributes(t *testing.T) {
	d := &windowsFirewallProfileDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "name", "enabled",
		"default_inbound_action", "default_outbound_action",
		"allow_inbound_rules", "allow_local_firewall_rules", "allow_local_ipsec_rules",
		"allow_unicast_response_to_multicast", "notify_on_listen",
		"log_file_name", "log_max_size_kilobytes", "log_allowed", "log_blocked", "log_ignored",
		"disabled_interface_aliases", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestFirewallProfileDSSchema_QueryKeyRequired(t *testing.T) {
	d := &windowsFirewallProfileDataSource{}
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

func TestFirewallProfileDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsFirewallProfileDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"id", "enabled",
		"default_inbound_action", "default_outbound_action",
		"allow_inbound_rules", "allow_local_firewall_rules", "allow_local_ipsec_rules",
		"allow_unicast_response_to_multicast", "notify_on_listen",
		"log_file_name", "log_max_size_kilobytes", "log_allowed", "log_blocked", "log_ignored",
		"disabled_interface_aliases"} {
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

func TestFirewallProfileDSConfigure_Nil(t *testing.T) {
	d := &windowsFirewallProfileDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestFirewallProfileDSConfigure_WrongType(t *testing.T) {
	d := &windowsFirewallProfileDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestFirewallProfileDSConfigure_CorrectType(t *testing.T) {
	d := &windowsFirewallProfileDataSource{}
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

func TestFirewallProfileDSRead_HappyPath(t *testing.T) {
	d := &windowsFirewallProfileDataSource{
		fp: &fakeFirewallProfileClientDS{readOut: fpDSState()},
	}
	cfg := fpDSConfig("Public")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsFirewallProfileDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "Public" {
		t.Errorf("ID = %q, want the profile name", state.ID.ValueString())
	}
	if !state.Enabled.ValueBool() {
		t.Error("Enabled should be true")
	}
	if state.DefaultInboundAction.ValueString() != "Allow" {
		t.Errorf("DefaultInboundAction = %q, want Allow", state.DefaultInboundAction.ValueString())
	}
	if state.LogMaxSizeKilobytes.ValueInt64() != 4096 {
		t.Errorf("LogMaxSizeKilobytes = %d, want 4096", state.LogMaxSizeKilobytes.ValueInt64())
	}
	// GPO-managed NotConfigured tri-states surface as null in the data source too.
	if !state.AllowLocalFirewallRules.IsNull() || !state.AllowLocalIPsecRules.IsNull() ||
		!state.AllowUnicastResponseToMulticast.IsNull() {
		t.Error("NotConfigured tri-states must be null in the data source")
	}
	if state.AllowInboundRules.ValueBool() != true {
		t.Error("AllowInboundRules should be true")
	}
	var aliases []string
	state.DisabledInterfaceAliases.ElementsAs(context.Background(), &aliases, false)
	if len(aliases) != 1 || aliases[0] != "Ethernet 2" {
		t.Errorf("disabled_interface_aliases = %v, want [Ethernet 2]", aliases)
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read
// ---------------------------------------------------------------------------

func TestFirewallProfileDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", firewallProfileDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeFirewallProfileClientDS{readOut: fpDSState()}
			d := &windowsFirewallProfileDataSource{fp: fake}
			cfg := fpDSConfig("Public")
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

func fpDSnTimeouts(t *testing.T, read *string) dstimeouts.Value {
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

func TestFirewallProfileDSnTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := fpDSnTimeouts(t, nil).Read(ctx, firewallProfileDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != firewallProfileDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, firewallProfileDSDefaultTimeout)
	}
	if firewallProfileDSDefaultTimeout != firewallProfileDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", firewallProfileDSDefaultTimeout, firewallProfileDefaultTimeout)
	}

	custom := "45s"
	got, diags = fpDSnTimeouts(t, &custom).Read(ctx, firewallProfileDSDefaultTimeout)
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

func TestFirewallProfileDSRead_TypedNotFound(t *testing.T) {
	d := &windowsFirewallProfileDataSource{
		fp: &fakeFirewallProfileClientDS{
			readErr: &winclient.FirewallProfileError{Kind: winclient.FirewallProfileErrorInvalidProfile, Message: "bad profile"},
		},
	}
	cfg := fpDSConfig("Public")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for typed invalid_profile")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestFirewallProfileDSRead_NilResult(t *testing.T) {
	d := &windowsFirewallProfileDataSource{
		fp: &fakeFirewallProfileClientDS{readOut: nil, readErr: nil},
	}
	cfg := fpDSConfig("Public")
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

func TestFirewallProfileDSRead_NotFoundDetailSingleLine(t *testing.T) {
	want := regexp.MustCompile(`No firewall profile .* was found on the target host\.`)

	cases := []struct {
		name   string
		client *fakeFirewallProfileClientDS
	}{
		{"typed", &fakeFirewallProfileClientDS{
			readErr: &winclient.FirewallProfileError{Kind: winclient.FirewallProfileErrorInvalidProfile, Message: "bad"},
		}},
		{"nil", &fakeFirewallProfileClientDS{readOut: nil, readErr: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &windowsFirewallProfileDataSource{fp: tc.client}
			cfg := fpDSConfig("Public")
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

func TestFirewallProfileDSRead_TypedError(t *testing.T) {
	d := &windowsFirewallProfileDataSource{
		fp: &fakeFirewallProfileClientDS{
			readErr: &winclient.FirewallProfileError{Kind: winclient.FirewallProfileErrorAccessDenied, Message: "denied"},
		},
	}
	cfg := fpDSConfig("Public")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
}

func TestFirewallProfileDSRead_GenericError(t *testing.T) {
	d := &windowsFirewallProfileDataSource{
		fp: &fakeFirewallProfileClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := fpDSConfig("Public")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}

func TestFirewallProfileDSRead_InvalidName(t *testing.T) {
	d := &windowsFirewallProfileDataSource{
		fp: &fakeFirewallProfileClientDS{readOut: fpDSState()},
	}
	fake := d.fp.(*fakeFirewallProfileClientDS)
	cfg := fpDSConfig("Bogus")
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for an invalid profile name")
	}
	if fake.readName != "" {
		t.Errorf("invalid name must not reach the host, got read of %q", fake.readName)
	}
}
