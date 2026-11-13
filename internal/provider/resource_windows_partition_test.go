// Package provider — unit tests for windows_partition.
//
// These tests exercise schema, CRUD handlers, ImportState, helpers and
// addPartitionDiag without touching SSH. CRUD handlers are driven via a
// fakePartitionClient injected into windowsPartitionResource.partitions.
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
// Fake WindowsPartitionClient
// ---------------------------------------------------------------------------

type fakePartitionClient struct {
	readOut *winclient.PartitionInfo
	readErr error
	readID  string
	readKey string

	createOut  *winclient.PartitionInfo
	createErr  error
	createOpts winclient.PartitionCreateOptions

	growOut  *winclient.PartitionInfo
	growErr  error
	growID   string
	growKey  string
	growSize int64

	letterOut    *winclient.PartitionInfo
	letterErr    error
	letterID     string
	letterKey    string
	letterLetter string

	flagsOut    *winclient.PartitionInfo
	flagsErr    error
	flagsID     string
	flagsKey    string
	flagsHidden *bool
	flagsActive *bool

	deleteErr error
	deleteID  string
	deleteKey string

	calls []string
}

func (f *fakePartitionClient) Create(_ context.Context, opts winclient.PartitionCreateOptions) (*winclient.PartitionInfo, error) {
	f.calls = append(f.calls, "create")
	f.createOpts = opts
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createOut, nil
}

func (f *fakePartitionClient) Read(_ context.Context, diskUniqueID, key string) (*winclient.PartitionInfo, error) {
	f.calls = append(f.calls, "read")
	f.readID, f.readKey = diskUniqueID, key
	return f.readOut, f.readErr
}

func (f *fakePartitionClient) Grow(_ context.Context, diskUniqueID, key string, sizeBytes int64) (*winclient.PartitionInfo, error) {
	f.calls = append(f.calls, "grow")
	f.growID, f.growKey, f.growSize = diskUniqueID, key, sizeBytes
	if f.growErr != nil {
		return nil, f.growErr
	}
	return f.growOut, nil
}

func (f *fakePartitionClient) SetDriveLetter(_ context.Context, diskUniqueID, key, letter string) (*winclient.PartitionInfo, error) {
	f.calls = append(f.calls, "set_letter")
	f.letterID, f.letterKey, f.letterLetter = diskUniqueID, key, letter
	if f.letterErr != nil {
		return nil, f.letterErr
	}
	return f.letterOut, nil
}

func (f *fakePartitionClient) SetFlags(_ context.Context, diskUniqueID, key string, hidden, active *bool) (*winclient.PartitionInfo, error) {
	f.calls = append(f.calls, "set_flags")
	f.flagsID, f.flagsKey, f.flagsHidden, f.flagsActive = diskUniqueID, key, hidden, active
	if f.flagsErr != nil {
		return nil, f.flagsErr
	}
	return f.flagsOut, nil
}

func (f *fakePartitionClient) Delete(_ context.Context, diskUniqueID, key string) error {
	f.calls = append(f.calls, "delete")
	f.deleteID, f.deleteKey = diskUniqueID, key
	return f.deleteErr
}

func okPartitionInfo() *winclient.PartitionInfo {
	return &winclient.PartitionInfo{
		DiskUniqueID:      "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK",
		PartitionNumber:   3,
		GUID:              "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		OffsetBytes:       1048576,
		SizeBytes:         16777216,
		DriveLetter:       "E",
		GptType:           "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		MbrType:           "",
		IsHidden:          false,
		IsActive:          false,
		IsBoot:            false,
		IsSystem:          false,
		OperationalStatus: "Online",
		AccessPaths:       []string{`E:\`},
	}
}

func okPartitionID() string {
	id, err := winclient.BuildPartitionID(okPartitionInfo().DiskUniqueID,
		winclient.PartitionResourceKey(okPartitionInfo()))
	if err != nil {
		panic(err)
	}
	return id
}

// ---------------------------------------------------------------------------
// Schema-shaped tftypes object helpers
// ---------------------------------------------------------------------------

func partitionObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"disk_unique_id":     tftypes.String,
		"size_bytes":         tftypes.Number,
		"use_maximum_size":   tftypes.Bool,
		"offset_bytes":       tftypes.Number,
		"drive_letter":       tftypes.String,
		"gpt_type":           tftypes.String,
		"mbr_type":           tftypes.String,
		"is_hidden":          tftypes.Bool,
		"is_active":          tftypes.Bool,
		"partition_number":   tftypes.Number,
		"guid":               tftypes.String,
		"access_paths":       tftypes.List{ElementType: tftypes.String},
		"is_boot":            tftypes.Bool,
		"is_system":          tftypes.Bool,
		"operational_status": tftypes.String,
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func partitionNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func partitionObj(overrides map[string]tftypes.Value) tftypes.Value {
	emptyList := tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil)
	base := map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, nil),
		"disk_unique_id":     tftypes.NewValue(tftypes.String, nil),
		"size_bytes":         tftypes.NewValue(tftypes.Number, nil),
		"use_maximum_size":   tftypes.NewValue(tftypes.Bool, nil),
		"offset_bytes":       tftypes.NewValue(tftypes.Number, nil),
		"drive_letter":       tftypes.NewValue(tftypes.String, nil),
		"gpt_type":           tftypes.NewValue(tftypes.String, nil),
		"mbr_type":           tftypes.NewValue(tftypes.String, nil),
		"is_hidden":          tftypes.NewValue(tftypes.Bool, nil),
		"is_active":          tftypes.NewValue(tftypes.Bool, nil),
		"partition_number":   tftypes.NewValue(tftypes.Number, nil),
		"guid":               tftypes.NewValue(tftypes.String, nil),
		"access_paths":       emptyList,
		"is_boot":            tftypes.NewValue(tftypes.Bool, nil),
		"is_system":          tftypes.NewValue(tftypes.Bool, nil),
		"operational_status": tftypes.NewValue(tftypes.String, nil),
		"timeouts":           partitionNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(partitionObjectType(), base)
}

// ---------------------------------------------------------------------------
// Metadata + Schema
// ---------------------------------------------------------------------------

func TestPartitionMetadata(t *testing.T) {
	r := &windowsPartitionResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_partition" {
		t.Errorf("TypeName = %q, want windows_partition", resp.TypeName)
	}
}

func TestPartitionSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsPartitionSchemaDefinition(context.Background())
	want := []string{
		"id", "disk_unique_id", "size_bytes", "use_maximum_size",
		"offset_bytes", "drive_letter", "gpt_type", "mbr_type",
		"is_hidden", "is_active", "partition_number", "guid",
		"access_paths", "is_boot", "is_system", "operational_status",
		"timeouts",
	}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

// disk_unique_id, offset_bytes and the partition types must force
// replacement; the mutable knobs must update in place.
func TestPartitionSchema_ForceNewAttributes(t *testing.T) {
	s := windowsPartitionSchemaDefinition(context.Background())

	matchesReplace := func(desc string) bool {
		l := strings.ToLower(desc)
		return strings.Contains(l, "replace") || strings.Contains(l, "recreate")
	}

	for _, name := range []string{"disk_unique_id", "gpt_type", "mbr_type"} {
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

	numAttr, ok := s.Attributes["offset_bytes"].(rschema.Int64Attribute)
	if !ok {
		t.Fatalf("offset_bytes attr type = %T", s.Attributes["offset_bytes"])
	}
	foundNum := false
	for _, m := range numAttr.PlanModifiers {
		if matchesReplace(m.Description(context.Background())) ||
			matchesReplace(m.MarkdownDescription(context.Background())) {
			foundNum = true
		}
	}
	if !foundNum {
		t.Error("offset_bytes must have RequiresReplace plan modifier")
	}

	// use_maximum_size is create-only: edits must force replacement, never a
	// silent no-op.
	maxAttr, ok := s.Attributes["use_maximum_size"].(rschema.BoolAttribute)
	if !ok {
		t.Fatalf("use_maximum_size attr type = %T", s.Attributes["use_maximum_size"])
	}
	foundMax := false
	for _, m := range maxAttr.PlanModifiers {
		if matchesReplace(m.Description(context.Background())) ||
			matchesReplace(m.MarkdownDescription(context.Background())) {
			foundMax = true
		}
	}
	if !foundMax {
		t.Error("use_maximum_size must have RequiresReplace plan modifier (create-only)")
	}

	for _, name := range []string{"size_bytes", "drive_letter", "is_hidden", "is_active"} {
		a := s.Attributes[name]
		switch v := a.(type) {
		case rschema.StringAttribute:
			for _, m := range v.PlanModifiers {
				if matchesReplace(m.Description(context.Background())) ||
					matchesReplace(m.MarkdownDescription(context.Background())) {
					t.Errorf("%s must NOT force replacement (in-place knob)", name)
				}
			}
		case rschema.Int64Attribute:
			for _, m := range v.PlanModifiers {
				if matchesReplace(m.Description(context.Background())) ||
					matchesReplace(m.MarkdownDescription(context.Background())) {
					t.Errorf("%s must NOT force replacement (in-place knob)", name)
				}
			}
		case rschema.BoolAttribute:
			for _, m := range v.PlanModifiers {
				if matchesReplace(m.Description(context.Background())) ||
					matchesReplace(m.MarkdownDescription(context.Background())) {
					t.Errorf("%s must NOT force replacement (in-place knob)", name)
				}
			}
		}
	}
}

func TestPartitionConfigValidators_Conflicts(t *testing.T) {
	r := &windowsPartitionResource{}
	validators := r.ConfigValidators(context.Background())
	if len(validators) != 2 {
		t.Fatalf("want exactly 2 ConfigValidators (two Conflicting pairs), got %d", len(validators))
	}
	desc := validators[0].Description(context.Background()) + "\n" + validators[1].Description(context.Background())
	for _, want := range []string{"size_bytes", "use_maximum_size", "gpt_type", "mbr_type"} {
		if !strings.Contains(desc, want) {
			t.Errorf("Conflicting description should mention %q, got: %q", want, desc)
		}
	}
}

func TestPartitionSchema_TimeoutsDefaults(t *testing.T) {
	if partitionDefaultTimeout != 15*time.Minute {
		t.Errorf("partitionDefaultTimeout = %v, want 15m", partitionDefaultTimeout)
	}
	if !partitionTimeoutsOpts.Create || !partitionTimeoutsOpts.Read || !partitionTimeoutsOpts.Update || !partitionTimeoutsOpts.Delete {
		t.Error("all four timeouts operations must be exposed")
	}
}

// ---------------------------------------------------------------------------
// partitionCreateOptionsFromPlan
// ---------------------------------------------------------------------------

func TestPartitionCreateOptionsFromPlan_Table(t *testing.T) {
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
	boolean := func(b, set bool) types.Bool {
		if !set {
			return types.BoolNull()
		}
		return types.BoolValue(b)
	}
	cases := []struct {
		name       string
		size       int64
		setSize    bool
		useMax     bool
		setUseMax  bool
		letter     string
		gpt        string
		mbr        string
		wantSize   int64
		wantMax    bool
		wantLetter string
		wantGpt    string
		wantMbr    string
		wantErr    bool
	}{
		{"explicit size", 16777216, true, false, false, "", "", "", 16777216, false, "", "", "", false},
		{"use max", 0, false, true, true, "", "", "", 0, true, "", "", "", false},
		{"letter lowercased", 16777216, true, false, false, "e", "", "", 16777216, false, "E", "", "", false},
		{"gpt alias", 16777216, true, false, false, "", "basic_data", "", 16777216, false, "", "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "", false},
		{"mbr alias", 16777216, true, false, false, "", "", "ifs", 16777216, false, "", "", "0x07", false},
		{"missing size", 0, false, false, false, "", "", "", 0, false, "", "", "", true},
		{"both types", 16777216, true, false, false, "", "basic_data", "ifs", 0, false, "", "", "", true},
		{"reserved letter", 16777216, true, false, false, "C", "", "", 0, false, "", "", "", true},
		{"bad gpt", 16777216, true, false, false, "", "nope", "", 0, false, "", "", "", true},
		{"bad mbr", 16777216, true, false, false, "", "", "nope", 0, false, "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := windowsPartitionModel{
				DiskUniqueID:   str(okPartitionInfo().DiskUniqueID),
				SizeBytes:      num(tc.size, tc.setSize),
				UseMaximumSize: boolean(tc.useMax, tc.setUseMax),
				DriveLetter:    str(tc.letter),
				GptType:        str(tc.gpt),
				MbrType:        str(tc.mbr),
			}
			opts, err := partitionCreateOptionsFromPlan(plan)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got opts %+v", opts)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.SizeBytes != tc.wantSize || opts.UseMaximumSize != tc.wantMax ||
				opts.DriveLetter != tc.wantLetter || opts.GptType != tc.wantGpt || opts.MbrType != tc.wantMbr {
				t.Errorf("opts = %+v, want size=%d max=%v letter=%q gpt=%q mbr=%q",
					opts, tc.wantSize, tc.wantMax, tc.wantLetter, tc.wantGpt, tc.wantMbr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// addPartitionDiag
// ---------------------------------------------------------------------------

func TestAddPartitionDiag_StructuredError(t *testing.T) {
	diags := &diag.Diagnostics{}
	pe := winclient.NewPartitionError(winclient.PartitionErrorProtected,
		"Refusing to manage a protected partition: the partition is the boot partition.", nil,
		map[string]string{"key": "K1"})
	addPartitionDiag(diags, "Read failed", pe)
	if !diags.HasError() {
		t.Fatal("expected error diag")
	}
	detail := (*diags)[0].Detail()
	for _, want := range []string{"protected_storage", "boot partition", "K1"} {
		if !strings.Contains(detail, want) {
			t.Errorf("missing %q in detail: %s", want, detail)
		}
	}
}

func TestAddPartitionDiag_PlainError(t *testing.T) {
	diags := &diag.Diagnostics{}
	addPartitionDiag(diags, "Generic", errors.New("boom"))
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

func TestPartitionConfigure_NilProviderData(t *testing.T) {
	r := &windowsPartitionResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
}

func TestPartitionConfigure_WrongType(t *testing.T) {
	r := &windowsPartitionResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should error")
	}
}

func TestPartitionConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsPartitionResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.partitions == nil {
		t.Error("Configure must populate partitions")
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestPartitionCreate_Handler_HappyPath(t *testing.T) {
	fake := &fakePartitionClient{createOut: okPartitionInfo()}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"disk_unique_id": tftypes.NewValue(tftypes.String, okPartitionInfo().DiskUniqueID),
			"size_bytes":     tftypes.NewValue(tftypes.Number, 16777216),
			"drive_letter":   tftypes.NewValue(tftypes.String, "e"),
			"gpt_type":       tftypes.NewValue(tftypes.String, "basic_data"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "create" {
		t.Errorf("expected single create call, calls=%v", fake.calls)
	}
	if fake.createOpts.DriveLetter != "E" {
		t.Errorf("letter must be normalized to upper-case, got %q", fake.createOpts.DriveLetter)
	}
	if fake.createOpts.GptType != "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" {
		t.Errorf("gpt alias must resolve, got %q", fake.createOpts.GptType)
	}
	var m windowsPartitionModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != okPartitionID() {
		t.Errorf("id = %q, want %q", m.ID.ValueString(), okPartitionID())
	}
	if m.SizeBytes.ValueInt64() != 16777216 {
		t.Errorf("size_bytes not projected: %v", m.SizeBytes)
	}
	if m.DriveLetter.ValueString() != "E" {
		t.Errorf("state letter = %q, want normalized E", m.DriveLetter.ValueString())
	}
	if m.GptType.ValueString() != winclient.GPTBasicDataPartitionGUID {
		t.Errorf("state gpt_type = %q, want canonical %q", m.GptType.ValueString(), winclient.GPTBasicDataPartitionGUID)
	}
}

// Reserved letters and missing sizes never reach the host.
func TestPartitionCreate_Handler_InvalidPlan_NoRemoteCall(t *testing.T) {
	for _, override := range []map[string]tftypes.Value{
		{
			"disk_unique_id": tftypes.NewValue(tftypes.String, okPartitionInfo().DiskUniqueID),
			"size_bytes":     tftypes.NewValue(tftypes.Number, 16777216),
			"drive_letter":   tftypes.NewValue(tftypes.String, "C"),
		},
		{
			"disk_unique_id": tftypes.NewValue(tftypes.String, okPartitionInfo().DiskUniqueID),
			"drive_letter":   tftypes.NewValue(tftypes.String, "E"),
		},
	} {
		fake := &fakePartitionClient{createOut: okPartitionInfo()}
		r := &windowsPartitionResource{partitions: fake}
		schemaDef := windowsPartitionSchemaDefinition(context.Background())
		plan := tfsdk.Plan{Schema: schemaDef, Raw: partitionObj(override)}
		resp := &resource.CreateResponse{
			State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
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

// Configured hidden/active flags must be applied post-create via SetFlags:
// New-Partition carries no flag switches.
func TestPartitionCreate_Handler_AppliesConfiguredFlags(t *testing.T) {
	hiddenOut := okPartitionInfo()
	hiddenOut.IsHidden = true
	fake := &fakePartitionClient{createOut: okPartitionInfo(), flagsOut: hiddenOut}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"disk_unique_id": tftypes.NewValue(tftypes.String, okPartitionInfo().DiskUniqueID),
			"size_bytes":     tftypes.NewValue(tftypes.Number, 16777216),
			"is_hidden":      tftypes.NewValue(tftypes.Bool, true),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[0] != "create" || fake.calls[1] != "set_flags" {
		t.Fatalf("expected create + set_flags, calls=%v", fake.calls)
	}
	if fake.flagsHidden == nil || !*fake.flagsHidden {
		t.Errorf("set_flags must carry hidden=true, got %v", fake.flagsHidden)
	}
	if fake.flagsActive != nil {
		t.Errorf("unset is_active must stay nil, got %v", *fake.flagsActive)
	}
	if fake.flagsKey != okPartitionInfo().GUID {
		t.Errorf("set_flags key = %q, want the partition GUID", fake.flagsKey)
	}
	var m windowsPartitionModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if !m.IsHidden.ValueBool() {
		t.Error("state must reflect the applied hidden flag")
	}
}

func TestPartitionCreate_Handler_Protected(t *testing.T) {
	fake := &fakePartitionClient{
		createErr: winclient.NewPartitionError(winclient.PartitionErrorProtected,
			"Refusing to manage protected storage: the disk is the boot disk.", nil, nil),
	}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"disk_unique_id": tftypes.NewValue(tftypes.String, okPartitionInfo().DiskUniqueID),
			"size_bytes":     tftypes.NewValue(tftypes.Number, 16777216),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected protected_storage error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "protected_storage") {
		t.Errorf("expected protected_storage kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// Read / Update / Delete
// ---------------------------------------------------------------------------

func TestPartitionRead_Handler_HappyPath(t *testing.T) {
	fake := &fakePartitionClient{readOut: okPartitionInfo()}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, okPartitionID()),
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
	// Read resolves by the (disk, key) ID.
	if fake.readID != okPartitionInfo().DiskUniqueID || fake.readKey != okPartitionInfo().GUID {
		t.Errorf("Read should resolve by id pair, got (%q, %q)", fake.readID, fake.readKey)
	}
}

func TestPartitionRead_Handler_DriftRemoved(t *testing.T) {
	fake := &fakePartitionClient{readOut: nil, readErr: nil}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, okPartitionID()),
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
		t.Error("state should be removed when the partition is gone")
	}
}

func TestPartitionUpdate_Handler_Grow(t *testing.T) {
	grown := okPartitionInfo()
	grown.SizeBytes = 33554432
	fake := &fakePartitionClient{readOut: okPartitionInfo(), growOut: grown}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okPartitionID()),
			"size_bytes":   tftypes.NewValue(tftypes.Number, 16777216),
			"drive_letter": tftypes.NewValue(tftypes.String, "E"),
		}),
	}
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okPartitionID()),
			"size_bytes":   tftypes.NewValue(tftypes.Number, 33554432),
			"drive_letter": tftypes.NewValue(tftypes.String, "E"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[0] != "read" || fake.calls[1] != "grow" {
		t.Errorf("expected read + grow, calls=%v", fake.calls)
	}
	if fake.growSize != 33554432 {
		t.Errorf("grow size = %d, want 33554432", fake.growSize)
	}
}

func TestPartitionUpdate_Handler_ShrinkRefused(t *testing.T) {
	grown := okPartitionInfo()
	grown.SizeBytes = 33554432
	fake := &fakePartitionClient{readOut: grown}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, okPartitionID()),
			"size_bytes": tftypes.NewValue(tftypes.Number, 33554432),
		}),
	}
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id":         tftypes.NewValue(tftypes.String, okPartitionID()),
			"size_bytes": tftypes.NewValue(tftypes.Number, 16777216),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("shrink must fail")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "shrink_not_supported") {
		t.Errorf("expected shrink_not_supported kind, got: %v", diagDetails(resp.Diagnostics))
	}
	if len(fake.calls) != 1 {
		t.Errorf("shrink must not reach the host beyond the read, calls=%v", fake.calls)
	}
}

func TestPartitionUpdate_Handler_LetterChange(t *testing.T) {
	moved := okPartitionInfo()
	moved.DriveLetter = "F"
	fake := &fakePartitionClient{readOut: okPartitionInfo(), letterOut: moved}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okPartitionID()),
			"drive_letter": tftypes.NewValue(tftypes.String, "E"),
		}),
	}
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okPartitionID()),
			"drive_letter": tftypes.NewValue(tftypes.String, "f"),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[1] != "set_letter" || fake.letterLetter != "F" {
		t.Errorf("expected read + set_letter(F), calls=%v letter=%q", fake.calls, fake.letterLetter)
	}
}

func TestPartitionUpdate_Handler_LetterRemoval(t *testing.T) {
	bare := okPartitionInfo()
	bare.DriveLetter = ""
	bare.AccessPaths = []string{}
	fake := &fakePartitionClient{readOut: okPartitionInfo(), letterOut: bare}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okPartitionID()),
			"drive_letter": tftypes.NewValue(tftypes.String, "E"),
		}),
	}
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, okPartitionID()),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[1] != "set_letter" || fake.letterLetter != "" {
		t.Errorf("null letter must remove via set_letter(\"\"), calls=%v letter=%q", fake.calls, fake.letterLetter)
	}
}

func TestPartitionDelete_Handler_Removes(t *testing.T) {
	fake := &fakePartitionClient{}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, okPartitionID()),
		}),
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Delete(context.Background(), resource.DeleteRequest{State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete must not error, got %v", resp.Diagnostics)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "delete" {
		t.Errorf("Delete must call the client once, calls=%v", fake.calls)
	}
}

// deadlinePartitionClient captures the ctx deadline seen by Read.
type deadlinePartitionClient struct {
	fakePartitionClient
	deadline time.Time
	ok       bool
}

func (f *deadlinePartitionClient) Read(ctx context.Context, _, _ string) (*winclient.PartitionInfo, error) {
	f.deadline, f.ok = ctx.Deadline()
	return okPartitionInfo(), nil
}

func TestPartitionRead_BoundedByTimeouts(t *testing.T) {
	fake := &deadlinePartitionClient{}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: partitionObj(map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, okPartitionID()),
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
	if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > partitionDefaultTimeout {
		t.Errorf("Read deadline in %v, want (0, %v]", remaining, partitionDefaultTimeout)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestPartitionImportState_Handler(t *testing.T) {
	fake := &fakePartitionClient{readOut: okPartitionInfo()}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: okPartitionID()}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	var m windowsPartitionModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != okPartitionID() || m.DiskUniqueID.ValueString() != okPartitionInfo().DiskUniqueID {
		t.Errorf("import state id/disk = %q/%q", m.ID.ValueString(), m.DiskUniqueID.ValueString())
	}
	if m.SizeBytes.ValueInt64() != 16777216 {
		t.Errorf("import should record the observed size, got %v", m.SizeBytes)
	}
	if m.DriveLetter.ValueString() != "E" {
		t.Errorf("import should record the observed letter, got %v", m.DriveLetter)
	}
	if fake.readID != okPartitionInfo().DiskUniqueID || fake.readKey != okPartitionInfo().GUID {
		t.Errorf("import should read by id pair, got (%q, %q)", fake.readID, fake.readKey)
	}
}

// Import must populate the style-matching partition type in canonical form
// so the RequiresReplace pair does not force a destructive cycle; the other
// style stays null.
func TestPartitionImportState_PopulatesStyleType(t *testing.T) {
	newImportResp := func() *resource.ImportStateResponse {
		schemaDef := windowsPartitionSchemaDefinition(context.Background())
		return &resource.ImportStateResponse{
			State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
		}
	}

	// GPT: observed GptType populates gpt_type, mbr_type stays null.
	fake := &fakePartitionClient{readOut: okPartitionInfo()}
	r := &windowsPartitionResource{partitions: fake}
	resp := newImportResp()
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: okPartitionID()}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	var m windowsPartitionModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.GptType.ValueString() != winclient.GPTBasicDataPartitionGUID {
		t.Errorf("import gpt_type = %q, want canonical %q", m.GptType.ValueString(), winclient.GPTBasicDataPartitionGUID)
	}
	if !m.MbrType.IsNull() {
		t.Errorf("import mbr_type must stay null on GPT, got %v", m.MbrType)
	}

	// MBR: offset-keyed info populates mbr_type in canonical form,
	// gpt_type stays null.
	mbrInfo := okPartitionInfo()
	mbrInfo.GUID = ""
	mbrInfo.GptType = ""
	mbrInfo.MbrType = "7"
	mbrID, err := winclient.BuildPartitionID(mbrInfo.DiskUniqueID, winclient.PartitionResourceKey(mbrInfo))
	if err != nil {
		t.Fatalf("BuildPartitionID: %v", err)
	}
	fake = &fakePartitionClient{readOut: mbrInfo}
	r = &windowsPartitionResource{partitions: fake}
	resp = newImportResp()
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: mbrID}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.MbrType.ValueString() != "0x07" {
		t.Errorf("import mbr_type = %q, want canonical 0x07", m.MbrType.ValueString())
	}
	if !m.GptType.IsNull() {
		t.Errorf("import gpt_type must stay null on MBR, got %v", m.GptType)
	}
}

// Plan-time canonicalization converges alias spellings to the canonical
// form stored in state, so an alias config never diffs against canonical
// state on the RequiresReplace pair.
func TestPartitionTypeCanonicalizeModifiers(t *testing.T) {
	ctx := context.Background()

	gptCases := []struct {
		name string
		in   string
		want string
	}{
		{"alias lower", "basic_data", winclient.GPTBasicDataPartitionGUID},
		{"alias upper", "BASIC_DATA", winclient.GPTBasicDataPartitionGUID},
		{"braced guid", "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}", winclient.GPTBasicDataPartitionGUID},
		{"lower guid", "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", winclient.GPTBasicDataPartitionGUID},
	}
	for _, tc := range gptCases {
		t.Run("gpt/"+tc.name, func(t *testing.T) {
			m := partitionGPTTypeCanonicalizeModifier{}
			resp := &planmodifier.StringResponse{}
			m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: types.StringValue(tc.in)}, resp)
			if resp.PlanValue.ValueString() != tc.want {
				t.Errorf("gpt plan = %q, want canonical %q", resp.PlanValue.ValueString(), tc.want)
			}
		})
	}

	mbrCases := []struct {
		name string
		in   string
		want string
	}{
		{"alias lower", "ifs", "0x07"},
		{"alias upper", "IFS", "0x07"},
		{"decimal", "7", "0x07"},
		{"short hex", "0x7", "0x07"},
		{"lower hex", "0xb", "0x0B"},
	}
	for _, tc := range mbrCases {
		t.Run("mbr/"+tc.name, func(t *testing.T) {
			m := partitionMBRTypeCanonicalizeModifier{}
			resp := &planmodifier.StringResponse{}
			m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: types.StringValue(tc.in)}, resp)
			if resp.PlanValue.ValueString() != tc.want {
				t.Errorf("mbr plan = %q, want canonical %q", resp.PlanValue.ValueString(), tc.want)
			}
		})
	}

	// Null and invalid values pass through for validators to handle.
	m := partitionGPTTypeCanonicalizeModifier{}
	resp := &planmodifier.StringResponse{}
	m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: types.StringNull()}, resp)
	if resp.PlanValue != (types.StringNull()) && !resp.PlanValue.IsNull() {
		t.Errorf("null gpt plan must pass through, got %v", resp.PlanValue)
	}
	resp = &planmodifier.StringResponse{}
	m.PlanModifyString(ctx, planmodifier.StringRequest{PlanValue: types.StringValue("nope")}, resp)
	if resp.PlanValue.ValueString() == winclient.GPTBasicDataPartitionGUID {
		t.Errorf("invalid gpt plan must not canonicalize, got %q", resp.PlanValue.ValueString())
	}
}

func TestPartitionImportState_NotFound(t *testing.T) {
	fake := &fakePartitionClient{readOut: nil, readErr: nil}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: okPartitionID()}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("import of a missing partition must error")
	}
}

func TestPartitionImportState_EmptyID(t *testing.T) {
	fake := &fakePartitionClient{}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "  "}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("empty import ID must error")
	}
	if len(fake.calls) != 0 {
		t.Errorf("invalid import ID must not reach the host, calls=%v", fake.calls)
	}
}

func TestPartitionImportState_MalformedID(t *testing.T) {
	fake := &fakePartitionClient{}
	r := &windowsPartitionResource{partitions: fake}
	schemaDef := windowsPartitionSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: partitionObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "no-separator-here"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("malformed import ID must error")
	}
	if len(fake.calls) != 0 {
		t.Errorf("malformed import ID must not reach the host, calls=%v", fake.calls)
	}
}
