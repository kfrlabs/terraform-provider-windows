// Package provider — unit tests for the windows_iis_app_pool data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative inputs), Configure, Read happy path (incl. the schedule set),
// not-found (typed and nil, with a single-line detail), generic error,
// invalid name short-circuit, timeouts.read deadline propagation and
// null-config default resolution.
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

type fakeIISAppPoolClientDS struct {
	readOut  *winclient.IISAppPoolState
	readErr  error
	readName string

	deadline time.Time
	ok       bool
}

func (f *fakeIISAppPoolClientDS) Read(ctx context.Context, name string) (*winclient.IISAppPoolState, error) {
	f.readName = name
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

func (f *fakeIISAppPoolClientDS) Create(_ context.Context, _ winclient.IISAppPoolInput) (*winclient.IISAppPoolState, error) {
	panic("Create not used in data source")
}

func (f *fakeIISAppPoolClientDS) Update(_ context.Context, _ winclient.IISAppPoolInput) (*winclient.IISAppPoolState, error) {
	panic("Update not used in data source")
}

func (f *fakeIISAppPoolClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func apDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                                 tftypes.String,
		"name":                               tftypes.String,
		"managed_runtime_version":            tftypes.String,
		"managed_pipeline_mode":              tftypes.String,
		"enable_32bit_app_on_win64":          tftypes.Bool,
		"start_mode":                         tftypes.String,
		"auto_start":                         tftypes.Bool,
		"queue_length":                       tftypes.Number,
		"identity_type":                      tftypes.String,
		"identity_username":                  tftypes.String,
		"load_user_profile":                  tftypes.Bool,
		"idle_timeout_minutes":               tftypes.Number,
		"idle_timeout_action":                tftypes.String,
		"max_processes":                      tftypes.Number,
		"recycling_periodic_restart_minutes": tftypes.Number,
		"recycling_schedule":                 tftypes.Set{ElementType: tftypes.String},
		"recycling_private_memory_kb":        tftypes.Number,
		"rapid_fail_protection":              tftypes.Bool,
		"cpu_limit_percent":                  tftypes.Number,
		"cpu_action":                         tftypes.String,
		"state":                              tftypes.String,
		"timeouts":                           dsTimeoutsObjType(),
	}}
}

func apDSConfig(name string) tfsdk.Config {
	d := &windowsIISAppPoolDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := map[string]tftypes.Value{}
	for k, t := range apDSObjType().AttributeTypes {
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
		Raw:    tftypes.NewValue(apDSObjType(), vals),
	}
}

func apDSState() *winclient.IISAppPoolState {
	st := okIISAppPoolState("api")
	st.RecyclingSchedule = []string{"03:00:00"}
	return st
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestIISAppPoolDSMetadata(t *testing.T) {
	d := &windowsIISAppPoolDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_iis_app_pool" {
		t.Errorf("TypeName = %q, want windows_iis_app_pool", resp.TypeName)
	}
}

func TestNewWindowsIISAppPoolDataSource_NotNil(t *testing.T) {
	if NewWindowsIISAppPoolDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestIISAppPoolDSSchema_AllAttributes(t *testing.T) {
	d := &windowsIISAppPoolDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"id", "name", "managed_runtime_version", "managed_pipeline_mode",
		"enable_32bit_app_on_win64", "start_mode", "auto_start", "queue_length",
		"identity_type", "identity_username", "load_user_profile", "idle_timeout_minutes",
		"idle_timeout_action", "max_processes", "recycling_periodic_restart_minutes",
		"recycling_schedule", "recycling_private_memory_kb", "rapid_fail_protection",
		"cpu_limit_percent", "cpu_action", "state", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
	// The password is never returned: neither the WriteOnly value nor its
	// version counter may appear in the data source schema.
	for _, k := range []string{"identity_password_wo", "identity_password_wo_version"} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("data source must not expose %q (passwords are never returned)", k)
		}
	}
}

func TestIISAppPoolDSSchema_QueryKeyRequired(t *testing.T) {
	d := &windowsIISAppPoolDataSource{}
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

func TestIISAppPoolDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsIISAppPoolDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type computedChecker interface{ IsComputed() bool }
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"id", "managed_runtime_version", "managed_pipeline_mode",
		"enable_32bit_app_on_win64", "start_mode", "auto_start", "queue_length",
		"identity_type", "identity_username", "load_user_profile", "idle_timeout_minutes",
		"idle_timeout_action", "max_processes", "recycling_periodic_restart_minutes",
		"recycling_schedule", "recycling_private_memory_kb", "rapid_fail_protection",
		"cpu_limit_percent", "cpu_action", "state"} {
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

func TestIISAppPoolDSConfigure_Nil(t *testing.T) {
	d := &windowsIISAppPoolDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestIISAppPoolDSConfigure_WrongType(t *testing.T) {
	d := &windowsIISAppPoolDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail missing type info: %s", resp.Diagnostics[0].Detail())
	}
}

func TestIISAppPoolDSConfigure_CorrectType(t *testing.T) {
	d := &windowsIISAppPoolDataSource{}
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

func TestIISAppPoolDSRead_HappyPath(t *testing.T) {
	d := &windowsIISAppPoolDataSource{
		pool: &fakeIISAppPoolClientDS{readOut: apDSState()},
	}
	cfg := apDSConfig("api")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsIISAppPoolDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "api" {
		t.Errorf("ID = %q, want the pool name", state.ID.ValueString())
	}
	if state.ManagedRuntimeVersion.ValueString() != "v4.0" {
		t.Errorf("ManagedRuntimeVersion = %q, want v4.0", state.ManagedRuntimeVersion.ValueString())
	}
	if state.QueueLength.ValueInt64() != 1000 {
		t.Errorf("QueueLength = %d, want 1000", state.QueueLength.ValueInt64())
	}
	if state.State.ValueString() != "Started" {
		t.Errorf("State = %q, want Started", state.State.ValueString())
	}
	var sched []string
	state.RecyclingSchedule.ElementsAs(context.Background(), &sched, false)
	if len(sched) != 1 || sched[0] != "03:00:00" {
		t.Errorf("recycling_schedule = %v, want [03:00:00]", sched)
	}
}

// ---------------------------------------------------------------------------
// Read — bounded by timeouts.read
// ---------------------------------------------------------------------------

func TestIISAppPoolDSRead_BoundedByTimeouts(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		customRead string // empty = absent timeouts block (default)
		want       time.Duration
	}{
		{"default", "", iisAppPoolDSDefaultTimeout},
		{"custom", "8s", 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeIISAppPoolClientDS{readOut: apDSState()}
			d := &windowsIISAppPoolDataSource{pool: fake}
			cfg := apDSConfig("api")
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

func apDSnTimeouts(t *testing.T, read *string) dstimeouts.Value {
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

func TestIISAppPoolDSnTimeouts_NullConfigDefault(t *testing.T) {
	ctx := context.Background()

	got, diags := apDSnTimeouts(t, nil).Read(ctx, iisAppPoolDSDefaultTimeout)
	if diags.HasError() {
		t.Fatalf("null timeouts diags: %v", diags)
	}
	if got != iisAppPoolDSDefaultTimeout {
		t.Errorf("null timeouts resolved to %v, want default %v", got, iisAppPoolDSDefaultTimeout)
	}
	if iisAppPoolDSDefaultTimeout != iisAppPoolDefaultTimeout {
		t.Errorf("data source default %v must reuse the sibling resource default %v", iisAppPoolDSDefaultTimeout, iisAppPoolDefaultTimeout)
	}

	custom := "45s"
	got, diags = apDSnTimeouts(t, &custom).Read(ctx, iisAppPoolDSDefaultTimeout)
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

func TestIISAppPoolDSRead_TypedNotFound(t *testing.T) {
	d := &windowsIISAppPoolDataSource{
		pool: &fakeIISAppPoolClientDS{
			readErr: &winclient.IISAppPoolError{Kind: winclient.IISAppPoolErrorNotFound, Message: "gone"},
		},
	}
	cfg := apDSConfig("api")
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

func TestIISAppPoolDSRead_NilResult(t *testing.T) {
	d := &windowsIISAppPoolDataSource{
		pool: &fakeIISAppPoolClientDS{readOut: nil, readErr: nil},
	}
	cfg := apDSConfig("api")
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

func TestIISAppPoolDSRead_NotFoundDetailSingleLine(t *testing.T) {
	want := regexp.MustCompile(`No IIS application pool named .* was found on the target host\.`)

	cases := []struct {
		name   string
		client *fakeIISAppPoolClientDS
	}{
		{"typed", &fakeIISAppPoolClientDS{
			readErr: &winclient.IISAppPoolError{Kind: winclient.IISAppPoolErrorNotFound, Message: "gone"},
		}},
		{"nil", &fakeIISAppPoolClientDS{readOut: nil, readErr: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &windowsIISAppPoolDataSource{pool: tc.client}
			cfg := apDSConfig("api")
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

func TestIISAppPoolDSRead_TypedError(t *testing.T) {
	d := &windowsIISAppPoolDataSource{
		pool: &fakeIISAppPoolClientDS{
			readErr: &winclient.IISAppPoolError{Kind: winclient.IISAppPoolErrorAccessDenied, Message: "denied"},
		},
	}
	cfg := apDSConfig("api")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from typed client error")
	}
}

func TestIISAppPoolDSRead_GenericError(t *testing.T) {
	d := &windowsIISAppPoolDataSource{
		pool: &fakeIISAppPoolClientDS{
			readErr: errors.New("transport failure"),
		},
	}
	cfg := apDSConfig("api")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic read error")
	}
}

func TestIISAppPoolDSRead_InvalidName(t *testing.T) {
	d := &windowsIISAppPoolDataSource{
		pool: &fakeIISAppPoolClientDS{readOut: apDSState()},
	}
	fake, ok := d.pool.(*fakeIISAppPoolClientDS)
	if !ok {
		t.Fatalf("expected *fakeIISAppPoolClientDS, got %T", fake)
	}
	cfg := apDSConfig("a/b")
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), datasource.ReadRequest{Config: cfg}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for an invalid pool name")
	}
	if fake.readName != "" {
		t.Errorf("invalid name must not reach the host, got read of %q", fake.readName)
	}
}
