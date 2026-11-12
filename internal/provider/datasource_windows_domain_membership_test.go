// Package provider — unit tests for the windows_domain_membership data source.
//
// windows_domain_membership is a singleton: no Required lookup keys.
// check_secure_channel is Optional+Computed (default true). Tests cover:
// Metadata, Schema, Configure, Read workgroup/joined paths, the
// check_secure_channel=false skip, unknown domain roles, Read errors and
// timeout bounding.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeDomainMembershipClientDS struct {
	readOut  *winclient.DomainMembershipState
	readErr  error
	readOpts *winclient.DomainMembershipReadOptions

	deadline time.Time
	ok       bool
}

func (f *fakeDomainMembershipClientDS) Read(_ context.Context) (*winclient.DomainMembershipState, error) {
	return f.readOut, f.readErr
}

func (f *fakeDomainMembershipClientDS) ReadWithOptions(ctx context.Context, opts winclient.DomainMembershipReadOptions) (*winclient.DomainMembershipState, error) {
	f.deadline, f.ok = ctx.Deadline()
	f.readOpts = &opts
	return f.readOut, f.readErr
}

func (f *fakeDomainMembershipClientDS) Join(_ context.Context, _ winclient.DomainJoinInput) (*winclient.DomainMembershipState, *winclient.DomainJoinResult, error) {
	panic("Join not used in data source")
}

func (f *fakeDomainMembershipClientDS) Unjoin(_ context.Context, _ winclient.DomainUnjoinInput) (*winclient.DomainMembershipState, *winclient.DomainUnjoinResult, error) {
	panic("Unjoin not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func domainMembershipDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                   tftypes.String,
		"part_of_domain":       tftypes.Bool,
		"domain":               tftypes.String,
		"workgroup":            tftypes.String,
		"computer_name":        tftypes.String,
		"dns_host_name":        tftypes.String,
		"fqdn":                 tftypes.String,
		"netbios_domain":       tftypes.String,
		"domain_role":          tftypes.String,
		"pending_reboot":       tftypes.Bool,
		"secure_channel_ok":    tftypes.Bool,
		"check_secure_channel": tftypes.Bool,
		"timeouts":             dsTimeoutsObjType(),
	}}
}

func domainMembershipDSConfig(checkSecureChannel tftypes.Value) tfsdk.Config {
	d := &windowsDomainMembershipDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(domainMembershipDSObjType(), map[string]tftypes.Value{
			"id":                   tftypes.NewValue(tftypes.String, nil),
			"part_of_domain":       tftypes.NewValue(tftypes.Bool, nil),
			"domain":               tftypes.NewValue(tftypes.String, nil),
			"workgroup":            tftypes.NewValue(tftypes.String, nil),
			"computer_name":        tftypes.NewValue(tftypes.String, nil),
			"dns_host_name":        tftypes.NewValue(tftypes.String, nil),
			"fqdn":                 tftypes.NewValue(tftypes.String, nil),
			"netbios_domain":       tftypes.NewValue(tftypes.String, nil),
			"domain_role":          tftypes.NewValue(tftypes.String, nil),
			"pending_reboot":       tftypes.NewValue(tftypes.Bool, nil),
			"secure_channel_ok":    tftypes.NewValue(tftypes.Bool, nil),
			"check_secure_channel": checkSecureChannel,
			"timeouts":             dsNullTimeoutsValue(),
		}),
	}
}

func domainMembershipDSNullConfig() tfsdk.Config {
	return domainMembershipDSConfig(tftypes.NewValue(tftypes.Bool, nil))
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestDomainMembershipDSMetadata(t *testing.T) {
	d := &windowsDomainMembershipDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_domain_membership" {
		t.Errorf("TypeName = %q, want windows_domain_membership", resp.TypeName)
	}
}

func TestNewWindowsDomainMembershipDataSource_NotNil(t *testing.T) {
	if NewWindowsDomainMembershipDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestDomainMembershipDSSchema_AllAttributes(t *testing.T) {
	d := &windowsDomainMembershipDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "part_of_domain", "domain", "workgroup", "computer_name",
		"dns_host_name", "fqdn", "netbios_domain", "domain_role",
		"pending_reboot", "secure_channel_ok", "check_secure_channel",
		"timeouts",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	if len(resp.Schema.Attributes) != len(want) {
		t.Errorf("schema has %d attributes, want %d", len(resp.Schema.Attributes), len(want))
	}
}

func TestDomainMembershipDSSchema_NoRequired(t *testing.T) {
	d := &windowsDomainMembershipDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for k, attr := range resp.Schema.Attributes {
		type requiredChecker interface{ IsRequired() bool }
		rc, ok := attr.(requiredChecker)
		if ok && rc.IsRequired() {
			t.Errorf("domain membership DS attribute %q is Required, but singleton DS should have no required keys", k)
		}
	}
}

func TestDomainMembershipDSSchema_CheckSecureChannelDefault(t *testing.T) {
	d := &windowsDomainMembershipDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	attr, ok := resp.Schema.Attributes["check_secure_channel"]
	if !ok {
		t.Fatal("schema missing check_secure_channel")
	}
	type optionalChecker interface{ IsOptional() bool }
	type computedChecker interface{ IsComputed() bool }
	if oc, ok := attr.(optionalChecker); !ok || !oc.IsOptional() {
		t.Error("check_secure_channel must be Optional")
	}
	if cc, ok := attr.(computedChecker); !ok || !cc.IsComputed() {
		t.Error("check_secure_channel must be Computed")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestDomainMembershipDSConfigure_Nil(t *testing.T) {
	d := &windowsDomainMembershipDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestDomainMembershipDSConfigure_WrongType(t *testing.T) {
	d := &windowsDomainMembershipDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 42}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestDomainMembershipDSConfigure_CorrectType(t *testing.T) {
	d := &windowsDomainMembershipDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — joined host
// ---------------------------------------------------------------------------

func joinedDMState() *winclient.DomainMembershipState {
	return &winclient.DomainMembershipState{
		Domain:          "corp.example.com",
		PartOfDomain:    true,
		ComputerName:    "WIN01",
		DNSHostName:     "win01.corp.example.com",
		NetBIOSDomain:   "CORP",
		DomainRole:      "MemberServer",
		MachineID:       "machine-guid-123",
		PendingReboot:   false,
		SecureChannelOk: true,
	}
}

func TestDomainMembershipDSRead_Joined(t *testing.T) {
	fake := &fakeDomainMembershipClientDS{readOut: joinedDMState()}
	d := &windowsDomainMembershipDataSource{dm: fake}
	cfg := domainMembershipDSNullConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsDomainMembershipDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "machine-guid-123" {
		t.Errorf("ID = %q, want machine_id", state.ID.ValueString())
	}
	if !state.PartOfDomain.ValueBool() {
		t.Error("PartOfDomain should be true")
	}
	if state.Domain.ValueString() != "corp.example.com" {
		t.Errorf("Domain = %q", state.Domain.ValueString())
	}
	if state.Workgroup.IsNull() || state.Workgroup.ValueString() != "" {
		t.Errorf("Workgroup = %q, want empty when joined", state.Workgroup.ValueString())
	}
	if state.ComputerName.ValueString() != "WIN01" {
		t.Errorf("ComputerName = %q", state.ComputerName.ValueString())
	}
	if state.DNSHostName.ValueString() != "win01.corp.example.com" {
		t.Errorf("DNSHostName = %q", state.DNSHostName.ValueString())
	}
	if state.FQDN.ValueString() != state.DNSHostName.ValueString() {
		t.Errorf("FQDN = %q, want dns_host_name alias %q", state.FQDN.ValueString(), state.DNSHostName.ValueString())
	}
	if state.NetBIOSDomain.ValueString() != "CORP" {
		t.Errorf("NetBIOSDomain = %q", state.NetBIOSDomain.ValueString())
	}
	if state.DomainRole.ValueString() != "MemberServer" {
		t.Errorf("DomainRole = %q", state.DomainRole.ValueString())
	}
	if state.SecureChannelOk.IsNull() || !state.SecureChannelOk.ValueBool() {
		t.Errorf("SecureChannelOk should be true, got null=%v", state.SecureChannelOk.IsNull())
	}
	if !state.CheckSecureChannel.ValueBool() {
		t.Error("CheckSecureChannel should default to true in state")
	}
	if fake.readOpts == nil || !fake.readOpts.CheckSecureChannel {
		t.Errorf("ReadWithOptions opts = %+v, want CheckSecureChannel=true", fake.readOpts)
	}
}

// ---------------------------------------------------------------------------
// Read — workgroup host
// ---------------------------------------------------------------------------

func TestDomainMembershipDSRead_Workgroup(t *testing.T) {
	fake := &fakeDomainMembershipClientDS{readOut: &winclient.DomainMembershipState{
		PartOfDomain:      false,
		Workgroup:         "WORKGROUP",
		ComputerName:      "WIN01",
		DNSHostName:       "win01",
		DomainRole:        "StandaloneWorkstation",
		MachineID:         "machine-guid-456",
		SecureChannelOk:   false,
		SecureChannelNull: true,
	}}
	d := &windowsDomainMembershipDataSource{dm: fake}
	cfg := domainMembershipDSNullConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsDomainMembershipDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.PartOfDomain.ValueBool() {
		t.Error("PartOfDomain should be false")
	}
	if state.Domain.ValueString() != "" {
		t.Errorf("Domain = %q, want empty (never the workgroup name)", state.Domain.ValueString())
	}
	if state.Workgroup.ValueString() != "WORKGROUP" {
		t.Errorf("Workgroup = %q, want WORKGROUP", state.Workgroup.ValueString())
	}
	if state.NetBIOSDomain.ValueString() != "" {
		t.Errorf("NetBIOSDomain = %q, want empty when not joined", state.NetBIOSDomain.ValueString())
	}
	if state.DomainRole.ValueString() != "StandaloneWorkstation" {
		t.Errorf("DomainRole = %q", state.DomainRole.ValueString())
	}
	if !state.SecureChannelOk.IsNull() {
		t.Error("SecureChannelOk should be null for a workgroup host")
	}
	if state.ID.ValueString() != "machine-guid-456" {
		t.Errorf("ID = %q, want machine_id", state.ID.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — check_secure_channel=false skips the probe
// ---------------------------------------------------------------------------

func TestDomainMembershipDSRead_SkipSecureChannel(t *testing.T) {
	fake := &fakeDomainMembershipClientDS{readOut: &winclient.DomainMembershipState{
		Domain:            "corp.example.com",
		PartOfDomain:      true,
		ComputerName:      "WIN01",
		DNSHostName:       "win01.corp.example.com",
		NetBIOSDomain:     "CORP",
		DomainRole:        "MemberServer",
		MachineID:         "machine-guid-789",
		SecureChannelOk:   false,
		SecureChannelNull: true,
	}}
	d := &windowsDomainMembershipDataSource{dm: fake}
	cfg := domainMembershipDSConfig(tftypes.NewValue(tftypes.Bool, false))
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	if fake.readOpts == nil || fake.readOpts.CheckSecureChannel {
		t.Errorf("ReadWithOptions opts = %+v, want CheckSecureChannel=false", fake.readOpts)
	}
	var state windowsDomainMembershipDataSourceModel
	resp.State.Get(context.Background(), &state)
	if !state.SecureChannelOk.IsNull() {
		t.Error("SecureChannelOk should be null when the probe is skipped")
	}
	if state.CheckSecureChannel.ValueBool() {
		t.Error("CheckSecureChannel should stay false in state")
	}
}

// ---------------------------------------------------------------------------
// Read — empty machine ID falls back to "current"
// ---------------------------------------------------------------------------

func TestDomainMembershipDSRead_EmptyMachineIDFallsBack(t *testing.T) {
	out := joinedDMState()
	out.MachineID = ""
	d := &windowsDomainMembershipDataSource{dm: &fakeDomainMembershipClientDS{readOut: out}}
	cfg := domainMembershipDSNullConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsDomainMembershipDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "current" {
		t.Errorf("ID = %q, want current fallback", state.ID.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — error paths
// ---------------------------------------------------------------------------

func TestDomainMembershipDSRead_Error(t *testing.T) {
	d := &windowsDomainMembershipDataSource{dm: &fakeDomainMembershipClientDS{
		readErr: errors.New("SSH unreachable"),
	}}
	cfg := domainMembershipDSNullConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from read failure")
	}
}

func TestDomainMembershipDSRead_NilState(t *testing.T) {
	d := &windowsDomainMembershipDataSource{dm: &fakeDomainMembershipClientDS{}}
	cfg := domainMembershipDSNullConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from nil state")
	}
}

// TestDomainMembershipDSRead_BoundedByTimeouts verifies the data source
// Read runs under a deadline derived from `timeouts.read` (issue #197):
// domainMembershipDSDefaultTimeout when the block is absent, the configured
// value when set.
func TestDomainMembershipDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", domainMembershipDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeDomainMembershipClientDS{readOut: joinedDMState()}
			d := &windowsDomainMembershipDataSource{dm: fake}
			cfg := domainMembershipDSNullConfig()
			if tc.customRead != "" {
				cfg = dsConfigWithReadTimeout(t, cfg, tc.customRead)
			}
			resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
			d.Read(ctx, datasource.ReadRequest{Config: cfg}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read diags: %v", resp.Diagnostics)
			}
			if !fake.ok {
				t.Fatal("Read ran without a context deadline; timeouts.read is not bound (issue #197)")
			}
			if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > tc.want {
				t.Errorf("Read deadline in %v, want (0, %v]", remaining, tc.want)
			}
		})
	}
}
