// Package provider — unit tests for the windows_disk data source.
//
// Tests cover: Metadata, Schema, ConfigValidators (ExactlyOneOf), Configure,
// Read (happy path, not-found, ambiguous, protected, number warning) and the
// timeouts.read bound. The lookup reuses the sibling resource's
// WindowsDiskClient via a fake.
package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client (data source view: only Read is exercised)
// ---------------------------------------------------------------------------

type fakeDiskClientDS struct {
	readOut *winclient.DiskInfo
	readErr error
	readSel winclient.DiskSelector
}

func (f *fakeDiskClientDS) Read(_ context.Context, sel winclient.DiskSelector) (*winclient.DiskInfo, error) {
	f.readSel = sel
	return f.readOut, f.readErr
}

func (f *fakeDiskClientDS) Initialize(_ context.Context, _, _ string) (*winclient.DiskInfo, error) {
	panic("Initialize not used in data source")
}

func (f *fakeDiskClientDS) SetOnlineState(_ context.Context, _ string, _ bool) (*winclient.DiskInfo, error) {
	panic("SetOnlineState not used in data source")
}

func (f *fakeDiskClientDS) SetReadOnlyState(_ context.Context, _ string, _ bool) (*winclient.DiskInfo, error) {
	panic("SetReadOnlyState not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func diskDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"unique_id":          tftypes.String,
		"serial_number":      tftypes.String,
		"location":           tftypes.String,
		"number":             tftypes.Number,
		"is_offline":         tftypes.Bool,
		"is_read_only":       tftypes.Bool,
		"partition_style":    tftypes.String,
		"friendly_name":      tftypes.String,
		"bus_type":           tftypes.String,
		"health_status":      tftypes.String,
		"operational_status": tftypes.String,
		"size_bytes":         tftypes.Number,
		"is_boot":            tftypes.Bool,
		"is_system":          tftypes.Bool,
		"is_clustered":       tftypes.Bool,
		"timeouts":           dsTimeoutsObjType(),
	}}
}

func diskDSConfig(overrides map[string]tftypes.Value) tfsdk.Config {
	d := &windowsDiskDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	base := map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, nil),
		"unique_id":          tftypes.NewValue(tftypes.String, nil),
		"serial_number":      tftypes.NewValue(tftypes.String, nil),
		"location":           tftypes.NewValue(tftypes.String, nil),
		"number":             tftypes.NewValue(tftypes.Number, nil),
		"is_offline":         tftypes.NewValue(tftypes.Bool, nil),
		"is_read_only":       tftypes.NewValue(tftypes.Bool, nil),
		"partition_style":    tftypes.NewValue(tftypes.String, nil),
		"friendly_name":      tftypes.NewValue(tftypes.String, nil),
		"bus_type":           tftypes.NewValue(tftypes.String, nil),
		"health_status":      tftypes.NewValue(tftypes.String, nil),
		"operational_status": tftypes.NewValue(tftypes.String, nil),
		"size_bytes":         tftypes.NewValue(tftypes.Number, nil),
		"is_boot":            tftypes.NewValue(tftypes.Bool, nil),
		"is_system":          tftypes.NewValue(tftypes.Bool, nil),
		"is_clustered":       tftypes.NewValue(tftypes.Bool, nil),
		"timeouts":           dsNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tfsdk.Config{Schema: sr.Schema, Raw: tftypes.NewValue(diskDSObjType(), base)}
}

func diskDSState() tfsdk.State {
	d := &windowsDiskDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(diskDSObjType(), map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, nil),
		"unique_id":          tftypes.NewValue(tftypes.String, nil),
		"serial_number":      tftypes.NewValue(tftypes.String, nil),
		"location":           tftypes.NewValue(tftypes.String, nil),
		"number":             tftypes.NewValue(tftypes.Number, nil),
		"is_offline":         tftypes.NewValue(tftypes.Bool, nil),
		"is_read_only":       tftypes.NewValue(tftypes.Bool, nil),
		"partition_style":    tftypes.NewValue(tftypes.String, nil),
		"friendly_name":      tftypes.NewValue(tftypes.String, nil),
		"bus_type":           tftypes.NewValue(tftypes.String, nil),
		"health_status":      tftypes.NewValue(tftypes.String, nil),
		"operational_status": tftypes.NewValue(tftypes.String, nil),
		"size_bytes":         tftypes.NewValue(tftypes.Number, nil),
		"is_boot":            tftypes.NewValue(tftypes.Bool, nil),
		"is_system":          tftypes.NewValue(tftypes.Bool, nil),
		"is_clustered":       tftypes.NewValue(tftypes.Bool, nil),
		"timeouts":           dsNullTimeoutsValue(),
	})}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators / Configure
// ---------------------------------------------------------------------------

func TestDiskDSMetadata(t *testing.T) {
	d := &windowsDiskDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_disk" {
		t.Errorf("TypeName = %q, want windows_disk", resp.TypeName)
	}
}

func TestDiskDSSchema(t *testing.T) {
	d := &windowsDiskDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema diags: %v", resp.Diagnostics)
	}
	for _, k := range []string{"id", "unique_id", "serial_number", "location", "number",
		"is_offline", "is_read_only", "partition_style", "friendly_name", "bus_type",
		"health_status", "operational_status", "size_bytes", "is_boot", "is_system",
		"is_clustered", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestDiskDSConfigValidators_ExactlyOneOf(t *testing.T) {
	d := &windowsDiskDataSource{}
	validators := d.ConfigValidators(context.Background())
	if len(validators) != 1 {
		t.Fatalf("want exactly 1 ConfigValidator (ExactlyOneOf selectors), got %d", len(validators))
	}
	desc := validators[0].Description(context.Background())
	for _, want := range []string{"unique_id", "serial_number", "location", "number"} {
		if !strings.Contains(desc, want) {
			t.Errorf("ExactlyOneOf description should mention %q, got: %q", want, desc)
		}
	}
}

func TestDiskDSConfigure(t *testing.T) {
	d := &windowsDiskDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
	resp2 := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "nope"}, resp2)
	if !resp2.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should error")
	}
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	resp3 := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: c}, resp3)
	if resp3.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp3.Diagnostics)
	}
	if d.disks == nil {
		t.Error("Configure must populate disks")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestDiskDSRead_HappyPath(t *testing.T) {
	fake := &fakeDiskClientDS{readOut: okDiskInfo()}
	d := &windowsDiskDataSource{disks: fake}
	resp := &datasource.ReadResponse{State: diskDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: diskDSConfig(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
		}),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	var m windowsDiskDataSourceModel
	if dg := resp.State.Get(context.Background(), &m); dg.HasError() {
		t.Fatalf("State.Get: %v", dg)
	}
	if m.ID.ValueString() != okDiskInfo().UniqueID {
		t.Errorf("id = %q, want the UniqueId", m.ID.ValueString())
	}
	if m.Number.ValueInt64() != 2 || m.SizeBytes.ValueInt64() != 137438953472 {
		t.Errorf("observed fields not projected: number=%v size=%v", m.Number, m.SizeBytes)
	}
	if m.PartitionStyle.ValueString() != "GPT" {
		t.Errorf("partition_style = %q", m.PartitionStyle.ValueString())
	}
}

func TestDiskDSRead_NumberWarns(t *testing.T) {
	fake := &fakeDiskClientDS{readOut: okDiskInfo()}
	d := &windowsDiskDataSource{disks: fake}
	resp := &datasource.ReadResponse{State: diskDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: diskDSConfig(map[string]tftypes.Value{
			"number": tftypes.NewValue(tftypes.Number, 2),
		}),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Error("selecting by number must emit a stability warning")
	}
}

func TestDiskDSRead_NotFound(t *testing.T) {
	fake := &fakeDiskClientDS{readOut: nil, readErr: nil}
	d := &windowsDiskDataSource{disks: fake}
	resp := &datasource.ReadResponse{State: diskDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: diskDSConfig(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, "GONE"),
		}),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("zero matches must error")
	}
}

func TestDiskDSRead_Ambiguous(t *testing.T) {
	fake := &fakeDiskClientDS{
		readErr: winclient.NewDiskError(winclient.DiskErrorAmbiguous, "2 disks match", nil, nil),
	}
	d := &windowsDiskDataSource{disks: fake}
	resp := &datasource.ReadResponse{State: diskDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: diskDSConfig(map[string]tftypes.Value{
			"serial_number": tftypes.NewValue(tftypes.String, "DUP"),
		}),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("several matches must error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "ambiguous_disk") {
		t.Errorf("expected ambiguous_disk kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

func TestDiskDSRead_Protected(t *testing.T) {
	fake := &fakeDiskClientDS{
		readErr: winclient.NewDiskError(winclient.DiskErrorProtected,
			"Refusing to manage protected storage: the disk is the boot disk.", nil, nil),
	}
	d := &windowsDiskDataSource{disks: fake}
	resp := &datasource.ReadResponse{State: diskDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: diskDSConfig(map[string]tftypes.Value{
			"number": tftypes.NewValue(tftypes.Number, 0),
		}),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("protected storage must error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "protected_storage") {
		t.Errorf("expected protected_storage kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

func TestDiskDSRead_MissingSelector(t *testing.T) {
	fake := &fakeDiskClientDS{readOut: okDiskInfo()}
	d := &windowsDiskDataSource{disks: fake}
	resp := &datasource.ReadResponse{State: diskDSState()}
	d.Read(context.Background(), datasource.ReadRequest{Config: diskDSConfig(nil)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("no selector must error (defence in depth behind ExactlyOneOf)")
	}
}

// ---------------------------------------------------------------------------
// Timeouts bound
// ---------------------------------------------------------------------------

type deadlineDiskClientDS struct {
	fakeDiskClientDS
	deadline time.Time
	ok       bool
}

func (f *deadlineDiskClientDS) Read(ctx context.Context, _ winclient.DiskSelector) (*winclient.DiskInfo, error) {
	f.deadline, f.ok = ctx.Deadline()
	return okDiskInfo(), nil
}

func TestDiskDSRead_BoundedByTimeouts(t *testing.T) {
	fake := &deadlineDiskClientDS{}
	d := &windowsDiskDataSource{disks: fake}
	resp := &datasource.ReadResponse{State: diskDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: diskDSConfig(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
		}),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", resp.Diagnostics)
	}
	if !fake.ok {
		t.Fatal("Read ran without a context deadline; timeouts.read is not bound")
	}
	if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > diskDSDefaultTimeout {
		t.Errorf("Read deadline in %v, want (0, %v]", remaining, diskDSDefaultTimeout)
	}
}
