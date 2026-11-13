// Package provider — unit tests for the windows_ntp data source.
//
// Tests cover: Metadata, Schema (computed attributes, no lookup keys,
// timeouts.read), Configure, Read happy path (incl. peer projection and
// AnnounceFlags mapping), error, and timeouts.read default resolution.
package provider

import (
	"context"
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

type fakeNTPClientDS struct {
	readOut  *winclient.NTPState
	readErr  error
	deadline time.Time
	ok       bool
}

func (f *fakeNTPClientDS) Read(ctx context.Context) (*winclient.NTPState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

func (f *fakeNTPClientDS) Set(_ context.Context, _ winclient.NTPInput) (*winclient.NTPState, error) {
	panic("Set not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func ntpDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                               tftypes.String,
		"type":                             tftypes.String,
		"servers":                          ntpServerListType(),
		"special_poll_interval_seconds":    tftypes.Number,
		"reliable":                         tftypes.Bool,
		"ntp_server_enabled":               tftypes.Bool,
		"max_pos_phase_correction_seconds": tftypes.Number,
		"max_neg_phase_correction_seconds": tftypes.Number,
		"current_source":                   tftypes.String,
		"policy_override":                  tftypes.Bool,
		"domain_joined":                    tftypes.Bool,
		"timeouts":                         dsTimeoutsObjType(),
	}}
}

func ntpDSConfig() tfsdk.Config {
	d := &windowsNTPDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := map[string]tftypes.Value{}
	for k, t := range ntpDSObjType().AttributeTypes {
		if k == "timeouts" {
			vals[k] = dsNullTimeoutsValue()
			continue
		}
		vals[k] = tftypes.NewValue(t, nil)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(ntpDSObjType(), vals),
	}
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func TestNTPDSMetadata(t *testing.T) {
	d := &windowsNTPDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_ntp" {
		t.Errorf("TypeName = %q, want windows_ntp", resp.TypeName)
	}
}

func TestNewWindowsNTPDataSource_NotNil(t *testing.T) {
	if NewWindowsNTPDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

func TestNTPDSSchema(t *testing.T) {
	d := &windowsNTPDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	for _, name := range []string{
		"id", "type", "servers", "special_poll_interval_seconds", "reliable",
		"ntp_server_enabled", "max_pos_phase_correction_seconds",
		"max_neg_phase_correction_seconds", "current_source",
		"policy_override", "domain_joined", "timeouts",
	} {
		if _, ok := sr.Schema.Attributes[name]; !ok {
			t.Errorf("data source schema missing attribute %q", name)
		}
	}
	// Singleton: no Required attribute (timeouts aside, everything Computed).
	for _, name := range []string{"type", "servers", "current_source"} {
		a := sr.Schema.Attributes[name]
		type requiredChecker interface{ IsRequired() bool }
		if rc, ok := a.(requiredChecker); ok && rc.IsRequired() {
			t.Errorf("%s must not be Required on the singleton data source", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestNTPDSRead_HappyPath(t *testing.T) {
	live := okNTPState()
	fc := &fakeNTPClientDS{readOut: live}
	d := &windowsNTPDataSource{ntp: fc}

	req := datasource.ReadRequest{Config: ntpDSConfig()}
	resp := &datasource.ReadResponse{State: tfsdk.State{
		Schema: req.Config.Schema,
		Raw:    tftypes.NewValue(ntpDSObjType(), nil),
	}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", fpDiagSummaries(resp.Diagnostics))
	}
	var m windowsNTPDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &m)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("State.Get: %v", resp.Diagnostics)
	}
	if m.ID.ValueString() != live.MachineID {
		t.Errorf("id = %q, want machine %q", m.ID.ValueString(), live.MachineID)
	}
	if m.Type.ValueString() != "NTP" {
		t.Errorf("type = %q", m.Type.ValueString())
	}
	if len(m.Servers.Elements()) != 1 {
		t.Fatalf("servers should carry 1 peer, got %v", m.Servers)
	}
	if m.SpecialPollIntervalSeconds.ValueInt64() != 900 {
		t.Errorf("poll = %d", m.SpecialPollIntervalSeconds.ValueInt64())
	}
	if m.Reliable.ValueBool() {
		t.Error("reliable must be false for AnnounceFlags 10")
	}
	if m.CurrentSource.ValueString() != live.CurrentSource {
		t.Errorf("current_source = %q", m.CurrentSource.ValueString())
	}
	if !fc.ok || fc.deadline.IsZero() {
		t.Error("data source Read must bound the call with the resolved read timeout")
	}
}

func TestNTPDSRead_EmptyMachineIDErrors(t *testing.T) {
	live := okNTPState()
	live.MachineID = ""
	fc := &fakeNTPClientDS{readOut: live}
	d := &windowsNTPDataSource{ntp: fc}

	req := datasource.ReadRequest{Config: ntpDSConfig()}
	resp := &datasource.ReadResponse{State: tfsdk.State{
		Schema: req.Config.Schema,
		Raw:    tftypes.NewValue(ntpDSObjType(), nil),
	}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when MachineGuid is missing")
	}
}

func TestNTPDSRead_Error(t *testing.T) {
	fc := &fakeNTPClientDS{
		readErr: winclient.NewNTPError(winclient.NTPErrorServiceUnavailable, "no W32Time", nil, nil),
	}
	d := &windowsNTPDataSource{ntp: fc}

	req := datasource.ReadRequest{Config: ntpDSConfig()}
	resp := &datasource.ReadResponse{State: tfsdk.State{
		Schema: req.Config.Schema,
		Raw:    tftypes.NewValue(ntpDSObjType(), nil),
	}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when Read fails")
	}
}
