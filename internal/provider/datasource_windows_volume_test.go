// Package provider — unit tests for the windows_volume data source.
//
// Tests cover: Metadata, Schema, ConfigValidators (ExactlyOneOf), Configure,
// Read (happy path, not-found, protected, missing lookup) and the
// timeouts.read bound. The lookup reuses the sibling resource's
// WindowsVolumeClient via a fake.
package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client (data source view: only Lookup is exercised)
// ---------------------------------------------------------------------------

type fakeVolumeClientDS struct {
	lookupOut *winclient.VolumeInfo
	lookupErr error
	lookupIn  winclient.VolumeLookup
}

func (f *fakeVolumeClientDS) Format(_ context.Context, _ winclient.VolumeFormatOptions) (*winclient.VolumeInfo, error) {
	panic("Format not used in data source")
}

func (f *fakeVolumeClientDS) Read(_ context.Context, _ string) (*winclient.VolumeInfo, error) {
	panic("Read not used in data source")
}

func (f *fakeVolumeClientDS) SetLabel(_ context.Context, _, _ string) (*winclient.VolumeInfo, error) {
	panic("SetLabel not used in data source")
}

func (f *fakeVolumeClientDS) Lookup(_ context.Context, lookup winclient.VolumeLookup) (*winclient.VolumeInfo, error) {
	f.lookupIn = lookup
	return f.lookupOut, f.lookupErr
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func volumeDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                   tftypes.String,
		"drive_letter":         tftypes.String,
		"unique_id":            tftypes.String,
		"file_system_label":    tftypes.String,
		"partition_id":         tftypes.String,
		"file_system":          tftypes.String,
		"allocation_unit_size": tftypes.Number,
		"path":                 tftypes.String,
		"size_bytes":           tftypes.Number,
		"size_remaining_bytes": tftypes.Number,
		"health_status":        tftypes.String,
		"operational_status":   tftypes.String,
		"drive_type":           tftypes.String,
		"timeouts":             dsTimeoutsObjType(),
	}}
}

func volumeDSConfig(overrides map[string]tftypes.Value) tfsdk.Config {
	d := &windowsVolumeDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	base := map[string]tftypes.Value{
		"id":                   tftypes.NewValue(tftypes.String, nil),
		"drive_letter":         tftypes.NewValue(tftypes.String, nil),
		"unique_id":            tftypes.NewValue(tftypes.String, nil),
		"file_system_label":    tftypes.NewValue(tftypes.String, nil),
		"partition_id":         tftypes.NewValue(tftypes.String, nil),
		"file_system":          tftypes.NewValue(tftypes.String, nil),
		"allocation_unit_size": tftypes.NewValue(tftypes.Number, nil),
		"path":                 tftypes.NewValue(tftypes.String, nil),
		"size_bytes":           tftypes.NewValue(tftypes.Number, nil),
		"size_remaining_bytes": tftypes.NewValue(tftypes.Number, nil),
		"health_status":        tftypes.NewValue(tftypes.String, nil),
		"operational_status":   tftypes.NewValue(tftypes.String, nil),
		"drive_type":           tftypes.NewValue(tftypes.String, nil),
		"timeouts":             dsNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tfsdk.Config{Schema: sr.Schema, Raw: tftypes.NewValue(volumeDSObjType(), base)}
}

func volumeDSState() tfsdk.State {
	d := &windowsVolumeDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(volumeDSObjType(), map[string]tftypes.Value{
		"id":                   tftypes.NewValue(tftypes.String, nil),
		"drive_letter":         tftypes.NewValue(tftypes.String, nil),
		"unique_id":            tftypes.NewValue(tftypes.String, nil),
		"file_system_label":    tftypes.NewValue(tftypes.String, nil),
		"partition_id":         tftypes.NewValue(tftypes.String, nil),
		"file_system":          tftypes.NewValue(tftypes.String, nil),
		"allocation_unit_size": tftypes.NewValue(tftypes.Number, nil),
		"path":                 tftypes.NewValue(tftypes.String, nil),
		"size_bytes":           tftypes.NewValue(tftypes.Number, nil),
		"size_remaining_bytes": tftypes.NewValue(tftypes.Number, nil),
		"health_status":        tftypes.NewValue(tftypes.String, nil),
		"operational_status":   tftypes.NewValue(tftypes.String, nil),
		"drive_type":           tftypes.NewValue(tftypes.String, nil),
		"timeouts":             dsNullTimeoutsValue(),
	})}
}

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators / Configure
// ---------------------------------------------------------------------------

func TestVolumeDSMetadata(t *testing.T) {
	d := &windowsVolumeDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_volume" {
		t.Errorf("TypeName = %q, want windows_volume", resp.TypeName)
	}
}

func TestVolumeDSSchema(t *testing.T) {
	d := &windowsVolumeDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema diags: %v", resp.Diagnostics)
	}
	for _, k := range []string{"id", "drive_letter", "unique_id", "file_system_label",
		"partition_id", "file_system", "allocation_unit_size", "path",
		"size_bytes", "size_remaining_bytes", "health_status",
		"operational_status", "drive_type", "timeouts"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestVolumeDSConfigValidators_ExactlyOneOf(t *testing.T) {
	d := &windowsVolumeDataSource{}
	validators := d.ConfigValidators(context.Background())
	if len(validators) != 1 {
		t.Fatalf("want exactly 1 ConfigValidator (ExactlyOneOf lookups), got %d", len(validators))
	}
	desc := validators[0].Description(context.Background())
	for _, want := range []string{"drive_letter", "unique_id", "file_system_label"} {
		if !strings.Contains(desc, want) {
			t.Errorf("ExactlyOneOf description should mention %q, got: %q", want, desc)
		}
	}
}

func TestVolumeDSConfigure(t *testing.T) {
	d := &windowsVolumeDataSource{}
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
	if d.volumes == nil {
		t.Error("Configure must populate volumes")
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestVolumeDSRead_HappyPath(t *testing.T) {
	fake := &fakeVolumeClientDS{lookupOut: okVolumeInfo()}
	d := &windowsVolumeDataSource{volumes: fake}
	resp := &datasource.ReadResponse{State: volumeDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: volumeDSConfig(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, okVolumeUniqueID),
		}),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	var m windowsVolumeDataSourceModel
	if dg := resp.State.Get(context.Background(), &m); dg.HasError() {
		t.Fatalf("State.Get: %v", dg)
	}
	if m.ID.ValueString() != okVolumeUniqueID {
		t.Errorf("id = %q, want the UniqueId", m.ID.ValueString())
	}
	if m.PartitionID.ValueString() != okVolumePartitionID {
		t.Errorf("partition_id = %q, want the hosting partition", m.PartitionID.ValueString())
	}
	if m.FileSystem.ValueString() != "NTFS" || m.FileSystemLabel.ValueString() != "TFDATA" {
		t.Errorf("observed fields not projected: fs=%v label=%v", m.FileSystem, m.FileSystemLabel)
	}
	if m.DriveLetter.ValueString() != "E" || m.SizeBytes.ValueInt64() != 16777216 {
		t.Errorf("observed fields not projected: letter=%v size=%v", m.DriveLetter, m.SizeBytes)
	}
	if fake.lookupIn.UniqueID != okVolumeUniqueID {
		t.Errorf("lookup should carry the UniqueId, got %+v", fake.lookupIn)
	}
}

func TestVolumeDSRead_ByLetter(t *testing.T) {
	fake := &fakeVolumeClientDS{lookupOut: okVolumeInfo()}
	d := &windowsVolumeDataSource{volumes: fake}
	resp := &datasource.ReadResponse{State: volumeDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: volumeDSConfig(map[string]tftypes.Value{
			"drive_letter": tftypes.NewValue(tftypes.String, "E"),
		}),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.lookupIn.DriveLetter != "E" {
		t.Errorf("lookup should carry the drive letter, got %+v", fake.lookupIn)
	}
}

func TestVolumeDSRead_NotFound(t *testing.T) {
	fake := &fakeVolumeClientDS{
		lookupErr: winclient.NewVolumeError(winclient.VolumeErrorNotFound, "gone", nil, nil),
	}
	d := &windowsVolumeDataSource{volumes: fake}
	resp := &datasource.ReadResponse{State: volumeDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: volumeDSConfig(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, "GONE"),
		}),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("zero matches must error")
	}
}

func TestVolumeDSRead_Protected(t *testing.T) {
	fake := &fakeVolumeClientDS{
		lookupErr: winclient.NewVolumeError(winclient.VolumeErrorProtected,
			"Refusing to manage protected storage: the disk is the boot disk.", nil, nil),
	}
	d := &windowsVolumeDataSource{volumes: fake}
	resp := &datasource.ReadResponse{State: volumeDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: volumeDSConfig(map[string]tftypes.Value{
			"drive_letter": tftypes.NewValue(tftypes.String, "C"),
		}),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("protected storage must error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "protected_storage") {
		t.Errorf("expected protected_storage kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

func TestVolumeDSRead_MissingLookup(t *testing.T) {
	fake := &fakeVolumeClientDS{lookupOut: okVolumeInfo()}
	d := &windowsVolumeDataSource{volumes: fake}
	resp := &datasource.ReadResponse{State: volumeDSState()}
	d.Read(context.Background(), datasource.ReadRequest{Config: volumeDSConfig(nil)}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("no lookup must error (defence in depth behind ExactlyOneOf)")
	}
}

// ---------------------------------------------------------------------------
// volumeLookupFromTF
// ---------------------------------------------------------------------------

func TestVolumeLookupFromTF_Table(t *testing.T) {
	str := func(s string, set bool) types.String {
		if !set {
			return types.StringNull()
		}
		return types.StringValue(s)
	}
	cases := []struct {
		name   string
		letter string
		setL   bool
		uid    string
		setU   bool
		label  string
		setB   bool
		ok     bool
	}{
		{"letter", "E", true, "", false, "", false, true},
		{"letter colon", "E:", true, "", false, "", false, true},
		{"unique_id", "", false, "U1", true, "", false, true},
		{"label", "", false, "", false, "TFDATA", true, true},
		{"none", "", false, "", false, "", false, false},
		{"two", "E", true, "U1", true, "", false, false},
		{"blank letter counts as unset", "  ", true, "", false, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup, ok := volumeLookupFromTF(str(tc.letter, tc.setL), str(tc.uid, tc.setU), str(tc.label, tc.setB))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (lookup %+v)", ok, tc.ok, lookup)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Timeouts bound
// ---------------------------------------------------------------------------

type deadlineVolumeClientDS struct {
	fakeVolumeClientDS
	deadline time.Time
	ok       bool
}

func (f *deadlineVolumeClientDS) Lookup(ctx context.Context, _ winclient.VolumeLookup) (*winclient.VolumeInfo, error) {
	f.deadline, f.ok = ctx.Deadline()
	return okVolumeInfo(), nil
}

func TestVolumeDSRead_BoundedByTimeouts(t *testing.T) {
	fake := &deadlineVolumeClientDS{}
	d := &windowsVolumeDataSource{volumes: fake}
	resp := &datasource.ReadResponse{State: volumeDSState()}
	d.Read(context.Background(), datasource.ReadRequest{
		Config: volumeDSConfig(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, okVolumeUniqueID),
		}),
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", resp.Diagnostics)
	}
	if !fake.ok {
		t.Fatal("Read ran without a context deadline; timeouts.read is not bound")
	}
	if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > volumeDSDefaultTimeout {
		t.Errorf("Read deadline in %v, want (0, %v]", remaining, volumeDSDefaultTimeout)
	}
}
