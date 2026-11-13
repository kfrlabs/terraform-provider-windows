// Package provider — unit tests for windows_volume.
//
// These tests exercise schema, CRUD handlers, ImportState, ModifyPlan, helpers
// and addVolumeDiag without touching SSH. CRUD handlers are driven via a
// fakeVolumeClient injected into windowsVolumeResource.volumes.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake WindowsVolumeClient
// ---------------------------------------------------------------------------

type fakeVolumeClient struct {
	formatOut  *winclient.VolumeInfo
	formatErr  error
	formatOpts winclient.VolumeFormatOptions

	readOut *winclient.VolumeInfo
	readErr error
	readID  string

	labelOut   *winclient.VolumeInfo
	labelErr   error
	labelID    string
	labelValue string

	lookupOut    *winclient.VolumeInfo
	lookupErr    error
	lookupLookup winclient.VolumeLookup

	calls []string
}

func (f *fakeVolumeClient) Format(_ context.Context, opts winclient.VolumeFormatOptions) (*winclient.VolumeInfo, error) {
	f.calls = append(f.calls, "format")
	f.formatOpts = opts
	if f.formatErr != nil {
		return nil, f.formatErr
	}
	return f.formatOut, nil
}

func (f *fakeVolumeClient) Read(_ context.Context, uniqueID string) (*winclient.VolumeInfo, error) {
	f.calls = append(f.calls, "read")
	f.readID = uniqueID
	return f.readOut, f.readErr
}

func (f *fakeVolumeClient) SetLabel(_ context.Context, uniqueID, label string) (*winclient.VolumeInfo, error) {
	f.calls = append(f.calls, "set_label")
	f.labelID, f.labelValue = uniqueID, label
	if f.labelErr != nil {
		return nil, f.labelErr
	}
	return f.labelOut, nil
}

func (f *fakeVolumeClient) Lookup(_ context.Context, lookup winclient.VolumeLookup) (*winclient.VolumeInfo, error) {
	f.calls = append(f.calls, "lookup")
	f.lookupLookup = lookup
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.lookupOut, nil
}

var okVolumeUniqueID = `\\?\Volume{11111111-2222-3333-4444-555555555555}\`
var okVolumePartitionID = `SCSI\DISK&VEN_MSFT&PROD_VIRTUAL_DISK|EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`

func okVolumeInfo() *winclient.VolumeInfo {
	return &winclient.VolumeInfo{
		UniqueID:           okVolumeUniqueID,
		PartitionID:        okVolumePartitionID,
		DriveLetter:        "E",
		Path:               okVolumeUniqueID,
		FileSystem:         "NTFS",
		FileSystemLabel:    "TFDATA",
		AllocationUnitSize: 4096,
		SizeBytes:          16777216,
		SizeRemainingBytes: 16744448,
		HealthStatus:       "Healthy",
		OperationalStatus:  "OK",
		DriveType:          "Fixed",
	}
}

// ---------------------------------------------------------------------------
// Schema-shaped tftypes object helpers
// ---------------------------------------------------------------------------

func volumeObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                    tftypes.String,
		"partition_id":          tftypes.String,
		"file_system":           tftypes.String,
		"file_system_label":     tftypes.String,
		"allocation_unit_size":  tftypes.Number,
		"allow_format_existing": tftypes.Bool,
		"full_format":           tftypes.Bool,
		"drive_letter":          tftypes.String,
		"path":                  tftypes.String,
		"size_bytes":            tftypes.Number,
		"size_remaining_bytes":  tftypes.Number,
		"health_status":         tftypes.String,
		"operational_status":    tftypes.String,
		"drive_type":            tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func volumeNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func volumeObj(overrides map[string]tftypes.Value) tftypes.Value {
	base := map[string]tftypes.Value{
		"id":                    tftypes.NewValue(tftypes.String, nil),
		"partition_id":          tftypes.NewValue(tftypes.String, nil),
		"file_system":           tftypes.NewValue(tftypes.String, nil),
		"file_system_label":     tftypes.NewValue(tftypes.String, nil),
		"allocation_unit_size":  tftypes.NewValue(tftypes.Number, nil),
		"allow_format_existing": tftypes.NewValue(tftypes.Bool, nil),
		"full_format":           tftypes.NewValue(tftypes.Bool, nil),
		"drive_letter":          tftypes.NewValue(tftypes.String, nil),
		"path":                  tftypes.NewValue(tftypes.String, nil),
		"size_bytes":            tftypes.NewValue(tftypes.Number, nil),
		"size_remaining_bytes":  tftypes.NewValue(tftypes.Number, nil),
		"health_status":         tftypes.NewValue(tftypes.String, nil),
		"operational_status":    tftypes.NewValue(tftypes.String, nil),
		"drive_type":            tftypes.NewValue(tftypes.String, nil),
		"timeouts":              volumeNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(volumeObjectType(), base)
}

// ---------------------------------------------------------------------------
// Metadata + Schema
// ---------------------------------------------------------------------------

func TestVolumeMetadata(t *testing.T) {
	r := &windowsVolumeResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_volume" {
		t.Errorf("TypeName = %q, want windows_volume", resp.TypeName)
	}
}

func TestVolumeSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsVolumeSchemaDefinition(context.Background())
	want := []string{
		"id", "partition_id", "file_system", "file_system_label",
		"allocation_unit_size", "allow_format_existing", "full_format",
		"drive_letter", "path", "size_bytes", "size_remaining_bytes",
		"health_status", "operational_status", "drive_type", "timeouts",
	}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

// partition_id, file_system and allocation_unit_size must force replacement;
// the label updates in place.
func TestVolumeSchema_ForceNewAttributes(t *testing.T) {
	s := windowsVolumeSchemaDefinition(context.Background())

	matchesReplace := func(desc string) bool {
		l := strings.ToLower(desc)
		return strings.Contains(l, "replace") || strings.Contains(l, "recreate")
	}

	for _, name := range []string{"partition_id", "file_system"} {
		attr, ok := s.Attributes[name].(rschema.StringAttribute)
		if !ok {
			t.Fatalf("%s attr type = %T", name, s.Attributes[name])
		}
		found := false
		for _, m := range attr.PlanModifiers {
			if matchesReplace(m.Description(context.Background())) ||
				matchesReplace(m.MarkdownDescription(context.Background())) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s must have RequiresReplace plan modifier", name)
		}
	}

	numAttr, ok := s.Attributes["allocation_unit_size"].(rschema.Int64Attribute)
	if !ok {
		t.Fatalf("allocation_unit_size attr type = %T", s.Attributes["allocation_unit_size"])
	}
	foundNum := false
	for _, m := range numAttr.PlanModifiers {
		if matchesReplace(m.Description(context.Background())) ||
			matchesReplace(m.MarkdownDescription(context.Background())) {
			foundNum = true
		}
	}
	if !foundNum {
		t.Error("allocation_unit_size must have RequiresReplace plan modifier")
	}

	labelAttr, ok := s.Attributes["file_system_label"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("file_system_label attr type = %T", s.Attributes["file_system_label"])
	}
	for _, m := range labelAttr.PlanModifiers {
		if matchesReplace(m.Description(context.Background())) ||
			matchesReplace(m.MarkdownDescription(context.Background())) {
			t.Errorf("file_system_label must NOT force replacement (in-place knob)")
		}
	}

	// allow_format_existing and full_format default to false.
	for _, name := range []string{"allow_format_existing", "full_format"} {
		boolAttr, ok := s.Attributes[name].(rschema.BoolAttribute)
		if !ok {
			t.Fatalf("%s attr type = %T", name, s.Attributes[name])
		}
		if boolAttr.Default == nil {
			t.Errorf("%s must carry a default (false)", name)
		}
		if !boolAttr.Optional || !boolAttr.Computed {
			t.Errorf("%s must be Optional+Computed", name)
		}
	}
}

func TestVolumeSchema_TimeoutsDefaults(t *testing.T) {
	if volumeDefaultTimeout != 30*time.Minute {
		t.Errorf("volumeDefaultTimeout = %v, want 30m", volumeDefaultTimeout)
	}
	if !volumeTimeoutsOpts.Create || !volumeTimeoutsOpts.Read || !volumeTimeoutsOpts.Update || !volumeTimeoutsOpts.Delete {
		t.Error("all four timeouts operations must be exposed")
	}
}

// ---------------------------------------------------------------------------
// volumeFormatOptionsFromPlan
// ---------------------------------------------------------------------------

func TestVolumeFormatOptionsFromPlan_Table(t *testing.T) {
	str := func(s string) types.String {
		if s == "" {
			return types.StringNull()
		}
		return types.StringValue(s)
	}
	num := func(n int64, set bool) types.Int64 {
		if !set {
			return types.Int64Null()
		}
		return types.Int64Value(n)
	}
	cases := []struct {
		name      string
		fs        string
		label     string
		setAUS    bool
		aus       int64
		wantFS    string
		wantLabel string
		wantAUS   int64
		wantErr   bool
	}{
		{"minimal ntfs", "NTFS", "", false, 0, "NTFS", "", 0, false},
		{"lowercase canonicalizes", "ntfs", "TFDATA", true, 4096, "NTFS", "TFDATA", 4096, false},
		{"refs", "ReFS", "", true, 65536, "ReFS", "", 65536, false},
		{"exfat", "exfat", "BACKUP", false, 0, "exFAT", "BACKUP", 0, false},
		{"fat32", "FAT32", "", true, 32768, "FAT32", "", 32768, false},
		{"bad fs", "ext4", "", false, 0, "", "", 0, true},
		{"long label", "NTFS", strings.Repeat("A", 33), false, 0, "", "", 0, true},
		{"fat32 long label", "FAT32", strings.Repeat("A", 12), false, 0, "", "", 0, true},
		{"bad aus", "NTFS", "", true, 3000, "", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := windowsVolumeModel{
				PartitionID:        str(okVolumePartitionID),
				FileSystem:         str(tc.fs),
				FileSystemLabel:    str(tc.label),
				AllocationUnitSize: num(tc.aus, tc.setAUS),
			}
			opts, err := volumeFormatOptionsFromPlan(plan)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got opts %+v", opts)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.FileSystem != tc.wantFS || opts.FileSystemLabel != tc.wantLabel || opts.AllocationUnitSize != tc.wantAUS {
				t.Errorf("opts = %+v, want fs=%q label=%q aus=%d",
					opts, tc.wantFS, tc.wantLabel, tc.wantAUS)
			}
			if opts.PartitionID != okVolumePartitionID {
				t.Errorf("partition_id not carried: %q", opts.PartitionID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ModifyPlan — file_system change warns (destructive reformat)
// ---------------------------------------------------------------------------

func TestVolumeModifyPlan_FileSystemChangeWarns(t *testing.T) {
	r := &windowsVolumeResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: volumeObj(map[string]tftypes.Value{
		"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
		"file_system":  tftypes.NewValue(tftypes.String, "ReFS"),
	})}
	prior := tfsdk.State{Schema: schemaResp.Schema, Raw: volumeObj(map[string]tftypes.Value{
		"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
		"file_system":  tftypes.NewValue(tftypes.String, "NTFS"),
	})}
	resp := &resource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(context.Background(), resource.ModifyPlanRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("file_system change must warn, not error: %v", resp.Diagnostics)
	}
	var sawWarning bool
	for _, d := range resp.Diagnostics {
		if d.Severity() == diag.SeverityWarning && strings.Contains(d.Summary(), "reformats") {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Error("expected a destructive-reformat warning for file_system change")
	}
}

func TestVolumeModifyPlan_FileSystemUnchangedNoWarning(t *testing.T) {
	r := &windowsVolumeResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)
	raw := volumeObj(map[string]tftypes.Value{
		"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
		"file_system":  tftypes.NewValue(tftypes.String, "NTFS"),
	})
	resp := &resource.ModifyPlanResponse{Plan: tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw}}
	r.ModifyPlan(context.Background(), resource.ModifyPlanRequest{
		Plan:  tfsdk.Plan{Schema: schemaResp.Schema, Raw: raw.Copy()},
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: raw.Copy()},
	}, resp)
	if len(resp.Diagnostics) != 0 {
		t.Errorf("unchanged file_system must not warn: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// addVolumeDiag
// ---------------------------------------------------------------------------

func TestAddVolumeDiag_StructuredError(t *testing.T) {
	diags := &diag.Diagnostics{}
	ve := winclient.NewVolumeError(winclient.VolumeErrorProtected,
		"Refusing to manage protected storage: the disk is the boot disk.", nil,
		map[string]string{"unique_id": "U1"})
	addVolumeDiag(diags, "Read failed", ve)
	if !diags.HasError() {
		t.Fatal("expected error diag")
	}
	detail := (*diags)[0].Detail()
	for _, want := range []string{"protected_storage", "boot disk", "U1"} {
		if !strings.Contains(detail, want) {
			t.Errorf("missing %q in detail: %s", want, detail)
		}
	}
}

func TestAddVolumeDiag_PlainError(t *testing.T) {
	diags := &diag.Diagnostics{}
	addVolumeDiag(diags, "Generic", errors.New("boom"))
	if !diags.HasError() {
		t.Fatal("expected error diag")
	}
	if !strings.Contains((*diags)[0].Detail(), "boom") {
		t.Errorf("missing underlying text: %s", (*diags)[0].Detail())
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestVolumeConfigure_NilProviderData(t *testing.T) {
	r := &windowsVolumeResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
}

func TestVolumeConfigure_WrongType(t *testing.T) {
	r := &windowsVolumeResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should error")
	}
}

func TestVolumeConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsVolumeResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.volumes == nil {
		t.Error("Configure must populate volumes")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestVolumeCreate_Handler_HappyPath(t *testing.T) {
	fake := &fakeVolumeClient{formatOut: okVolumeInfo()}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"partition_id":          tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":           tftypes.NewValue(tftypes.String, "ntfs"),
			"file_system_label":     tftypes.NewValue(tftypes.String, "TFDATA"),
			"allocation_unit_size":  tftypes.NewValue(tftypes.Number, 4096),
			"allow_format_existing": tftypes.NewValue(tftypes.Bool, false),
			"full_format":           tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: volumeObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "format" {
		t.Errorf("expected single format call, calls=%v", fake.calls)
	}
	if fake.formatOpts.FileSystem != "NTFS" {
		t.Errorf("file system must be canonicalized to NTFS, got %q", fake.formatOpts.FileSystem)
	}
	if fake.formatOpts.PartitionID != okVolumePartitionID {
		t.Errorf("partition_id not forwarded: %q", fake.formatOpts.PartitionID)
	}
	var m windowsVolumeModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != okVolumeUniqueID {
		t.Errorf("id = %q, want the volume UniqueId", m.ID.ValueString())
	}
	if m.FileSystem.ValueString() != "NTFS" {
		t.Errorf("state file_system = %q, want canonical NTFS", m.FileSystem.ValueString())
	}
	if m.FileSystemLabel.ValueString() != "TFDATA" {
		t.Errorf("state label = %q", m.FileSystemLabel.ValueString())
	}
	if m.DriveLetter.ValueString() != "E" {
		t.Errorf("state drive_letter = %q", m.DriveLetter.ValueString())
	}
}

// Unsupported file systems never reach the host.
func TestVolumeCreate_Handler_InvalidPlan_NoRemoteCall(t *testing.T) {
	for _, override := range []map[string]tftypes.Value{
		{
			"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":  tftypes.NewValue(tftypes.String, "ext4"),
		},
		{
			"partition_id": tftypes.NewValue(tftypes.String, "bogus"),
			"file_system":  tftypes.NewValue(tftypes.String, "NTFS"),
		},
	} {
		fake := &fakeVolumeClient{formatOut: okVolumeInfo()}
		r := &windowsVolumeResource{volumes: fake}
		schemaDef := windowsVolumeSchemaDefinition(context.Background())
		plan := tfsdk.Plan{Schema: schemaDef, Raw: volumeObj(override)}
		resp := &resource.CreateResponse{
			State: tfsdk.State{Schema: schemaDef, Raw: volumeObj(nil)},
		}
		r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("expected error diag for %v", override)
		}
		if len(fake.calls) != 0 {
			t.Errorf("invalid plan must not reach the host, calls=%v", fake.calls)
		}
	}
}

func TestVolumeCreate_Handler_AlreadyFormatted(t *testing.T) {
	fake := &fakeVolumeClient{
		formatErr: winclient.NewVolumeError(winclient.VolumeErrorAlreadyFormatted,
			"already carries a formatted NTFS volume", nil, nil),
	}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":  tftypes.NewValue(tftypes.String, "NTFS"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: volumeObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected already_formatted error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "already_formatted") {
		t.Errorf("expected already_formatted kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// Read / Update / Delete
// ---------------------------------------------------------------------------

func TestVolumeRead_Handler_HappyPath(t *testing.T) {
	fake := &fakeVolumeClient{readOut: okVolumeInfo()}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if resp.State.Raw.IsNull() {
		t.Error("state should NOT be removed on happy read")
	}
	if fake.readID != okVolumeUniqueID {
		t.Errorf("Read should resolve by UniqueId, got %q", fake.readID)
	}
}

func TestVolumeRead_Handler_DriftRemoved(t *testing.T) {
	fake := &fakeVolumeClient{readOut: nil, readErr: nil}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state should be removed when the volume is gone or unformatted")
	}
}

func TestVolumeUpdate_Handler_Relabel(t *testing.T) {
	renamed := okVolumeInfo()
	renamed.FileSystemLabel = "RENAMED"
	fake := &fakeVolumeClient{readOut: okVolumeInfo(), labelOut: renamed}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":                tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id":      tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":       tftypes.NewValue(tftypes.String, "NTFS"),
			"file_system_label": tftypes.NewValue(tftypes.String, "TFDATA"),
		}),
	}
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":                tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id":      tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":       tftypes.NewValue(tftypes.String, "NTFS"),
			"file_system_label": tftypes.NewValue(tftypes.String, "RENAMED"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[0] != "read" || fake.calls[1] != "set_label" {
		t.Errorf("expected read + set_label, calls=%v", fake.calls)
	}
	if fake.labelValue != "RENAMED" {
		t.Errorf("label value = %q, want RENAMED", fake.labelValue)
	}
}

func TestVolumeUpdate_Handler_NullLabelNoRemoteWrite(t *testing.T) {
	fake := &fakeVolumeClient{readOut: okVolumeInfo()}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":                tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id":      tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":       tftypes.NewValue(tftypes.String, "NTFS"),
			"file_system_label": tftypes.NewValue(tftypes.String, "TFDATA"),
		}),
	}
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":  tftypes.NewValue(tftypes.String, "NTFS"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "read" {
		t.Errorf("null label must leave the volume unmanaged (read only), calls=%v", fake.calls)
	}
}

func TestVolumeDelete_Handler_StateOnly(t *testing.T) {
	fake := &fakeVolumeClient{}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
			"file_system":  tftypes.NewValue(tftypes.String, "NTFS"),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete must not error, got %v", resp.Diagnostics)
	}
	if len(fake.calls) != 0 {
		t.Errorf("Delete must make zero remote calls, calls=%v", fake.calls)
	}
}

// deadlineVolumeClient captures the ctx deadline seen by Read.
type deadlineVolumeClient struct {
	fakeVolumeClient
	deadline time.Time
	ok       bool
}

func (f *deadlineVolumeClient) Read(ctx context.Context, _ string) (*winclient.VolumeInfo, error) {
	f.deadline, f.ok = ctx.Deadline()
	return okVolumeInfo(), nil
}

func TestVolumeRead_BoundedByTimeouts(t *testing.T) {
	fake := &deadlineVolumeClient{}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: volumeObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okVolumeUniqueID),
			"partition_id": tftypes.NewValue(tftypes.String, okVolumePartitionID),
		}),
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Read(context.Background(), resource.ReadRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read diags: %v", resp.Diagnostics)
	}
	if !fake.ok {
		t.Fatal("Read ran without a context deadline; timeouts.read is not bound")
	}
	if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > volumeDefaultTimeout {
		t.Errorf("Read deadline in %v, want (0, %v]", remaining, volumeDefaultTimeout)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestVolumeImportState_ByUniqueID(t *testing.T) {
	fake := &fakeVolumeClient{lookupOut: okVolumeInfo()}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: volumeObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: okVolumeUniqueID}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	var m windowsVolumeModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != okVolumeUniqueID || m.PartitionID.ValueString() != okVolumePartitionID {
		t.Errorf("import state id/partition = %q/%q", m.ID.ValueString(), m.PartitionID.ValueString())
	}
	if m.FileSystem.ValueString() != "NTFS" {
		t.Errorf("import should record the observed file system, got %v", m.FileSystem)
	}
	if m.FileSystemLabel.ValueString() != "TFDATA" {
		t.Errorf("import should record the observed label, got %v", m.FileSystemLabel)
	}
	if m.AllocationUnitSize.ValueInt64() != 4096 {
		t.Errorf("import should record the observed allocation unit size, got %v", m.AllocationUnitSize)
	}
	if fake.lookupLookup.UniqueID == "" {
		t.Errorf("import by UniqueId should look up by UniqueId, got %+v", fake.lookupLookup)
	}
}

func TestVolumeImportState_ByDriveLetter(t *testing.T) {
	fake := &fakeVolumeClient{lookupOut: okVolumeInfo()}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: volumeObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "E:"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if fake.lookupLookup.DriveLetter != "E" {
		t.Errorf("import by E: should look up by drive letter, got %+v", fake.lookupLookup)
	}
	var m windowsVolumeModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != okVolumeUniqueID {
		t.Errorf("import id = %q", m.ID.ValueString())
	}
}

func TestVolumeImportState_EmptyID(t *testing.T) {
	fake := &fakeVolumeClient{}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: volumeObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "  "}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("empty import ID must error")
	}
	if len(fake.calls) != 0 {
		t.Errorf("invalid import ID must not reach the host, calls=%v", fake.calls)
	}
}

func TestVolumeImportState_NotFound(t *testing.T) {
	fake := &fakeVolumeClient{
		lookupErr: winclient.NewVolumeError(winclient.VolumeErrorNotFound, "gone", nil, nil),
	}
	r := &windowsVolumeResource{volumes: fake}
	schemaDef := windowsVolumeSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: volumeObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: okVolumeUniqueID}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("import of a missing volume must error")
	}
}

// ---------------------------------------------------------------------------
// Plan-time file system canonicalization
// ---------------------------------------------------------------------------

func TestVolumeFileSystemCanonicalizeModifier(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"lower", "ntfs", "NTFS"},
		{"upper", "NTFS", "NTFS"},
		{"refs", "refs", "ReFS"},
		{"exfat", "EXFAT", "exFAT"},
		{"fat32", "fat32", "FAT32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := volumeFileSystemCanonicalizeModifier{}
			resp := &planmodifier.StringResponse{}
			m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: types.StringValue(tc.in)}, resp)
			if resp.PlanValue.ValueString() != tc.want {
				t.Errorf("fs plan = %q, want canonical %q", resp.PlanValue.ValueString(), tc.want)
			}
		})
	}

	// Null and invalid values pass through for validators to handle.
	m := volumeFileSystemCanonicalizeModifier{}
	resp := &planmodifier.StringResponse{}
	m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: types.StringNull()}, resp)
	if resp.PlanValue != (types.StringNull()) && !resp.PlanValue.IsNull() {
		t.Errorf("null fs plan must pass through, got %v", resp.PlanValue)
	}
	resp = &planmodifier.StringResponse{}
	m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: types.StringValue("ext4")}, resp)
	if resp.PlanValue.ValueString() == "NTFS" {
		t.Errorf("invalid fs plan must not canonicalize, got %q", resp.PlanValue.ValueString())
	}
}
