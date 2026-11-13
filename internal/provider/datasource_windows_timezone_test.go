// Package provider — unit tests for the windows_timezone data source.
//
// windows_timezone is a singleton: no Required lookup keys. Tests cover:
// Metadata, Schema (all computed, no required keys, exact attribute set),
// Configure, Read happy path, Read error, and the timeouts.read bound
// (issue #197 pattern).
package provider

import (
	"context"
	"errors"
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

type fakeTimezoneClientDS struct {
	readOut *winclient.TimezoneState
	readErr error

	deadline time.Time
	ok       bool
}

func (f *fakeTimezoneClientDS) Read(ctx context.Context) (*winclient.TimezoneState, error) {
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

func (f *fakeTimezoneClientDS) Set(_ context.Context, _ winclient.TimezoneInput) (*winclient.TimezoneState, error) {
	panic("Set not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func timezoneDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                            tftypes.String,
		"timezone_id":                   tftypes.String,
		"display_name":                  tftypes.String,
		"base_utc_offset":               tftypes.String,
		"supports_daylight_saving_time": tftypes.Bool,
		"current_utc_offset":            tftypes.String,
		"daylight_saving_disabled":      tftypes.Bool,
		"tzautoupdate_enabled":          tftypes.Bool,
		"timeouts":                      dsTimeoutsObjType(),
	}}
}

func timezoneDSConfig() tfsdk.Config {
	d := &windowsTimezoneDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(timezoneDSObjType(), map[string]tftypes.Value{
			"id":                            tftypes.NewValue(tftypes.String, nil),
			"timezone_id":                   tftypes.NewValue(tftypes.String, nil),
			"display_name":                  tftypes.NewValue(tftypes.String, nil),
			"base_utc_offset":               tftypes.NewValue(tftypes.String, nil),
			"supports_daylight_saving_time": tftypes.NewValue(tftypes.Bool, nil),
			"current_utc_offset":            tftypes.NewValue(tftypes.String, nil),
			"daylight_saving_disabled":      tftypes.NewValue(tftypes.Bool, nil),
			"tzautoupdate_enabled":          tftypes.NewValue(tftypes.Bool, nil),
			"timeouts":                      dsNullTimeoutsValue(),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestTimezoneDSMetadata(t *testing.T) {
	d := &windowsTimezoneDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_timezone" {
		t.Errorf("TypeName = %q, want windows_timezone", resp.TypeName)
	}
}

func TestNewWindowsTimezoneDataSource_NotNil(t *testing.T) {
	if NewWindowsTimezoneDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestTimezoneDSSchema_AllAttributes(t *testing.T) {
	d := &windowsTimezoneDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{"id", "timezone_id", "display_name", "base_utc_offset",
		"supports_daylight_saving_time", "current_utc_offset",
		"daylight_saving_disabled", "tzautoupdate_enabled", "timeouts"}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestTimezoneDSSchema_AllComputed(t *testing.T) {
	d := &windowsTimezoneDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for k, attr := range resp.Schema.Attributes {
		type requiredChecker interface{ IsRequired() bool }
		rc, ok := attr.(requiredChecker)
		if ok && rc.IsRequired() {
			t.Errorf("timezone DS attribute %q is Required, but singleton DS should have no required keys", k)
		}
	}
}

func TestTimezoneDSSchema_NoExtraAttributes(t *testing.T) {
	d := &windowsTimezoneDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	// Singleton: 9 attributes (id + 7 computed + timeouts).
	if len(resp.Schema.Attributes) != 9 {
		t.Errorf("schema has %d attributes, want 9", len(resp.Schema.Attributes))
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestTimezoneDSConfigure_Nil(t *testing.T) {
	d := &windowsTimezoneDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestTimezoneDSConfigure_WrongType(t *testing.T) {
	d := &windowsTimezoneDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 42}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
}

func TestTimezoneDSConfigure_CorrectType(t *testing.T) {
	d := &windowsTimezoneDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path
// ---------------------------------------------------------------------------

func TestTimezoneDSRead_HappyPath(t *testing.T) {
	d := &windowsTimezoneDataSource{
		tz: &fakeTimezoneClientDS{readOut: okTimezoneState()},
	}
	cfg := timezoneDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsTimezoneDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != okTimezoneState().MachineID {
		t.Errorf("ID = %q, want machine_id %q", state.ID.ValueString(), okTimezoneState().MachineID)
	}
	if state.TimezoneID.ValueString() != "Romance Standard Time" {
		t.Errorf("TimezoneID = %q", state.TimezoneID.ValueString())
	}
	if state.DisplayName.ValueString() == "" {
		t.Error("DisplayName must be populated")
	}
	if state.BaseUTCOffset.ValueString() != "+01:00" {
		t.Errorf("BaseUTCOffset = %q", state.BaseUTCOffset.ValueString())
	}
	if state.CurrentUTCOffset.ValueString() != "+02:00" {
		t.Errorf("CurrentUTCOffset = %q", state.CurrentUTCOffset.ValueString())
	}
	if !state.SupportsDST.ValueBool() {
		t.Error("SupportsDST must be true")
	}
	if state.DaylightSavingDisabled.ValueBool() {
		t.Error("DaylightSavingDisabled must be false")
	}
	if state.TzautoupdateEnabled.ValueBool() {
		t.Error("TzautoupdateEnabled must be false")
	}
}

// TestTimezoneDSRead_EmptyMachineIDErrors pins the empty-GUID behaviour:
// an unreadable MachineGuid is an error, never a placeholder ID.
func TestTimezoneDSRead_EmptyMachineIDErrors(t *testing.T) {
	out := okTimezoneState()
	out.MachineID = ""
	d := &windowsTimezoneDataSource{
		tz: &fakeTimezoneClientDS{readOut: out},
	}
	cfg := timezoneDSConfig()
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when MachineGuid is missing")
	}
}

// ---------------------------------------------------------------------------
// Read — error
// ---------------------------------------------------------------------------

func TestTimezoneDSRead_Error(t *testing.T) {
	d := &windowsTimezoneDataSource{
		tz: &fakeTimezoneClientDS{
			readErr: errors.New("SSH unreachable"),
		},
	}
	cfg := timezoneDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from read failure")
	}
}

// TestTimezoneDSRead_BoundedByTimeouts verifies the data source Read runs
// under a deadline derived from `timeouts.read`: timezoneDSDefaultTimeout
// when the block is absent, the configured value when set.
func TestTimezoneDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", timezoneDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeTimezoneClientDS{readOut: okTimezoneState()}
			d := &windowsTimezoneDataSource{tz: fake}
			cfg := timezoneDSConfig()
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
