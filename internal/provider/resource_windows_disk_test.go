// Package provider — unit tests for windows_disk.
//
// These tests exercise schema, CRUD handlers, ImportState, helpers and
// addDiskDiag without touching SSH. CRUD handlers are driven via a
// fakeDiskClient injected into windowsDiskResource.disks.
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
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake WindowsDiskClient
// ---------------------------------------------------------------------------

type fakeDiskClient struct {
	readOut *winclient.DiskInfo
	readErr error
	readSel winclient.DiskSelector

	initOut   *winclient.DiskInfo
	initErr   error
	initID    string
	initStyle string

	onlineOut *winclient.DiskInfo
	onlineErr error
	onlineID  string
	onlineVal bool

	roOut *winclient.DiskInfo
	roErr error
	roID  string
	roVal bool

	calls []string
}

func (f *fakeDiskClient) Read(_ context.Context, sel winclient.DiskSelector) (*winclient.DiskInfo, error) {
	f.calls = append(f.calls, "read")
	f.readSel = sel
	return f.readOut, f.readErr
}

func (f *fakeDiskClient) Initialize(_ context.Context, id, style string) (*winclient.DiskInfo, error) {
	f.calls = append(f.calls, "initialize")
	f.initID, f.initStyle = id, style
	if f.initErr != nil {
		return nil, f.initErr
	}
	return f.initOut, nil
}

func (f *fakeDiskClient) SetOnlineState(_ context.Context, id string, offline bool) (*winclient.DiskInfo, error) {
	f.calls = append(f.calls, "set_online")
	f.onlineID, f.onlineVal = id, offline
	if f.onlineErr != nil {
		return nil, f.onlineErr
	}
	return f.onlineOut, nil
}

func (f *fakeDiskClient) SetReadOnlyState(_ context.Context, id string, readOnly bool) (*winclient.DiskInfo, error) {
	f.calls = append(f.calls, "set_read_only")
	f.roID, f.roVal = id, readOnly
	if f.roErr != nil {
		return nil, f.roErr
	}
	return f.roOut, nil
}

func okDiskInfo() *winclient.DiskInfo {
	return &winclient.DiskInfo{
		Number:            2,
		UniqueID:          "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK&REV_1.0",
		SerialNumber:      "6000C296-ABC",
		Location:          "PCI Slot 0",
		FriendlyName:      "Msft Virtual Disk",
		BusType:           "Virtual",
		HealthStatus:      "Healthy",
		OperationalStatus: "Online",
		PartitionStyle:    winclient.DiskPartitionStyleGPT,
		IsOffline:         false,
		IsReadOnly:        false,
		IsBoot:            false,
		IsSystem:          false,
		IsClustered:       false,
		SizeBytes:         137438953472,
	}
}

// ---------------------------------------------------------------------------
// Schema-shaped tftypes object helpers
// ---------------------------------------------------------------------------

func diskObjectType() tftypes.Object {
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
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"create": tftypes.String,
			"read":   tftypes.String,
			"update": tftypes.String,
			"delete": tftypes.String,
		}},
	}}
}

func diskNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"create": tftypes.String,
		"read":   tftypes.String,
		"update": tftypes.String,
		"delete": tftypes.String,
	}}, nil)
}

func diskObj(overrides map[string]tftypes.Value) tftypes.Value {
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
		"timeouts":           diskNullTimeoutsValue(),
	}
	for k, v := range overrides {
		base[k] = v
	}
	return tftypes.NewValue(diskObjectType(), base)
}

// ---------------------------------------------------------------------------
// Metadata + Schema
// ---------------------------------------------------------------------------

func TestDiskMetadata(t *testing.T) {
	r := &windowsDiskResource{}
	req := resource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_disk" {
		t.Errorf("TypeName = %q, want windows_disk", resp.TypeName)
	}
}

func TestDiskSchema_HasRequiredAttributes(t *testing.T) {
	s := windowsDiskSchemaDefinition(context.Background())
	want := []string{
		"id", "unique_id", "serial_number", "location", "number",
		"is_offline", "is_read_only", "partition_style",
		"friendly_name", "bus_type", "health_status", "operational_status",
		"size_bytes", "is_boot", "is_system", "is_clustered", "timeouts",
	}
	for _, k := range want {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

// Selectors and partition_style must force replacement; the mutable flags
// must update in place.
func TestDiskSchema_ForceNewAttributes(t *testing.T) {
	s := windowsDiskSchemaDefinition(context.Background())

	matchesReplace := func(desc string) bool {
		l := strings.ToLower(desc)
		return strings.Contains(l, "replace") || strings.Contains(l, "recreate")
	}

	for _, name := range []string{"unique_id", "serial_number", "location", "partition_style"} {
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

	numAttr, ok := s.Attributes["number"].(rschema.Int64Attribute)
	if !ok {
		t.Fatalf("number attr type = %T", s.Attributes["number"])
	}
	foundNum := false
	for _, m := range numAttr.PlanModifiers {
		if matchesReplace(m.Description(context.Background())) ||
			matchesReplace(m.MarkdownDescription(context.Background())) {
			foundNum = true
		}
	}
	if !foundNum {
		t.Error("number must have RequiresReplace plan modifier")
	}

	for _, name := range []string{"is_offline", "is_read_only"} {
		attr, ok := s.Attributes[name].(rschema.BoolAttribute)
		if !ok {
			t.Fatalf("%s attr type = %T", name, s.Attributes[name])
		}
		for _, m := range attr.PlanModifiers {
			if matchesReplace(m.Description(context.Background())) ||
				matchesReplace(m.MarkdownDescription(context.Background())) {
				t.Errorf("%s must NOT force replacement (in-place flag)", name)
			}
		}
	}
}

func TestDiskConfigValidators_ExactlyOneOf(t *testing.T) {
	r := &windowsDiskResource{}
	validators := r.ConfigValidators(context.Background())
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

func TestDiskSchema_TimeoutsDefaults(t *testing.T) {
	if diskDefaultTimeout != 10*time.Minute {
		t.Errorf("diskDefaultTimeout = %v, want 10m", diskDefaultTimeout)
	}
	if !diskTimeoutsOpts.Create || !diskTimeoutsOpts.Read || !diskTimeoutsOpts.Update || !diskTimeoutsOpts.Delete {
		t.Error("all four timeouts operations must be exposed")
	}
}

// ---------------------------------------------------------------------------
// diskSelectorFromTF
// ---------------------------------------------------------------------------

func TestDiskSelectorFromTF_Table(t *testing.T) {
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
		name         string
		uid, ser     string
		loc          string
		n            int64
		setNum       bool
		wantOK       bool
		wantDescribe string
	}{
		{"unique_id", "U1", "", "", 0, false, true, "unique_id"},
		{"serial", "", "S1", "", 0, false, true, "serial_number"},
		{"location", "", "", "L1", 0, false, true, "location"},
		{"number", "", "", "", 2, true, true, "number 2"},
		{"none", "", "", "", 0, false, false, ""},
		{"two", "U1", "S1", "", 0, false, false, ""},
		{"all", "U1", "S1", "L1", 1, true, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel, ok := diskSelectorFromTF(str(tc.uid), str(tc.ser), str(tc.loc), num(tc.n, tc.setNum))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && !strings.Contains(sel.Describe(), tc.wantDescribe) {
				t.Errorf("Describe = %q, want it to contain %q", sel.Describe(), tc.wantDescribe)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// addDiskDiag
// ---------------------------------------------------------------------------

func TestAddDiskDiag_StructuredError(t *testing.T) {
	diags := &diag.Diagnostics{}
	de := winclient.NewDiskError(winclient.DiskErrorProtected,
		"Refusing to manage protected storage: the disk is the boot disk.", nil,
		map[string]string{"unique_id": "U1"})
	addDiskDiag(diags, "Read failed", de)
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

func TestAddDiskDiag_PlainError(t *testing.T) {
	diags := &diag.Diagnostics{}
	addDiskDiag(diags, "Generic", errors.New("boom"))
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

func TestDiskConfigure_NilProviderData(t *testing.T) {
	r := &windowsDiskResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData should be a no-op, got %v", resp.Diagnostics)
	}
}

func TestDiskConfigure_WrongType(t *testing.T) {
	r := &windowsDiskResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong-type ProviderData should error")
	}
}

func TestDiskConfigure_Valid(t *testing.T) {
	c, err := winclient.New(winclient.Config{Host: "h", Username: "u", Password: "p", InsecureIgnoreHostKey: true})
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	r := &windowsDiskResource{}
	resp := &resource.ConfigureResponse{}
	r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: c}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if r.disks == nil {
		t.Error("Configure must populate disks")
	}
}

// ---------------------------------------------------------------------------
// Create (adopt)
// ---------------------------------------------------------------------------

func TestDiskCreate_Handler_HappyPathAdopt(t *testing.T) {
	fake := &fakeDiskClient{readOut: okDiskInfo()}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK&REV_1.0"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "read" {
		t.Errorf("adopt of an already-conformant disk must be read-only, calls=%v", fake.calls)
	}
	var m windowsDiskModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != okDiskInfo().UniqueID {
		t.Errorf("id = %q, want the UniqueId", m.ID.ValueString())
	}
	if m.SizeBytes.ValueInt64() != 137438953472 {
		t.Errorf("size_bytes not projected: %v", m.SizeBytes)
	}
}

func TestDiskCreate_Handler_NumberWarns(t *testing.T) {
	fake := &fakeDiskClient{readOut: okDiskInfo()}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"number": tftypes.NewValue(tftypes.Number, 2),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Error("selecting by number must emit a stability warning")
	}
	if got := resp.Diagnostics.Warnings()[0].Detail(); !strings.Contains(strings.ToLower(got), "unique_id") {
		t.Errorf("number warning should point at unique_id, got: %q", got)
	}
}

func TestDiskCreate_Handler_NotFound(t *testing.T) {
	fake := &fakeDiskClient{readOut: nil, readErr: nil}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"unique_id": tftypes.NewValue(tftypes.String, "MISSING"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag for zero matches")
	}
}

func TestDiskCreate_Handler_Ambiguous(t *testing.T) {
	fake := &fakeDiskClient{
		readErr: winclient.NewDiskError(winclient.DiskErrorAmbiguous, "2 disks match", nil, nil),
	}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"serial_number": tftypes.NewValue(tftypes.String, "DUP"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag for several matches")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "ambiguous_disk") {
		t.Errorf("expected ambiguous_disk kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

func TestDiskCreate_Handler_Protected(t *testing.T) {
	fake := &fakeDiskClient{
		readErr: winclient.NewDiskError(winclient.DiskErrorProtected,
			"Refusing to manage protected storage: the disk is the boot disk.", nil, nil),
	}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"number": tftypes.NewValue(tftypes.Number, 0),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected protected_storage error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "protected_storage") {
		t.Errorf("expected protected_storage kind, got: %v", diagDetails(resp.Diagnostics))
	}
}

func TestDiskCreate_Handler_OfflineFlagEnforced(t *testing.T) {
	after := okDiskInfo()
	after.IsOffline = true
	after.OperationalStatus = "Offline"
	fake := &fakeDiskClient{readOut: okDiskInfo(), onlineOut: after}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"unique_id":  tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"is_offline": tftypes.NewValue(tftypes.Bool, true),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[1] != "set_online" || !fake.onlineVal {
		t.Errorf("expected read + set_online(true), calls=%v", fake.calls)
	}
}

func TestDiskCreate_Handler_RAWInitialized(t *testing.T) {
	raw := okDiskInfo()
	raw.PartitionStyle = winclient.DiskPartitionStyleRAW
	raw.IsOffline = false
	init := okDiskInfo()
	init.PartitionStyle = winclient.DiskPartitionStyleGPT
	fake := &fakeDiskClient{readOut: raw, initOut: init}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"unique_id":       tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"partition_style": tftypes.NewValue(tftypes.String, "GPT"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[1] != "initialize" || fake.initStyle != "GPT" {
		t.Errorf("expected read + initialize(GPT), calls=%v style=%q", fake.calls, fake.initStyle)
	}
}

func TestDiskCreate_Handler_PartitionStyleMismatch(t *testing.T) {
	// Observed GPT vs desired MBR: no remote call beyond the initial read,
	// the mismatch is raised locally.
	fake := &fakeDiskClient{readOut: okDiskInfo()}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"unique_id":       tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"partition_style": tftypes.NewValue(tftypes.String, "MBR"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected partition_style_mismatch error")
	}
	if !strings.Contains(strings.Join(diagDetails(resp.Diagnostics), "\n"), "partition_style_mismatch") {
		t.Errorf("expected partition_style_mismatch kind, got: %v", diagDetails(resp.Diagnostics))
	}
	if len(fake.calls) != 1 {
		t.Errorf("mismatch must not reach the host beyond the read, calls=%v", fake.calls)
	}
}

func TestDiskCreate_Handler_OfflineRAWComesOnlineBeforeInitialize(t *testing.T) {
	// Offline RAW disk with is_offline=false + partition_style=GPT must
	// converge in one apply: set_online(false) first, then initialize.
	rawOffline := okDiskInfo()
	rawOffline.PartitionStyle = winclient.DiskPartitionStyleRAW
	rawOffline.IsOffline = true
	rawOffline.OperationalStatus = "Offline"
	rawOnline := okDiskInfo()
	rawOnline.PartitionStyle = winclient.DiskPartitionStyleRAW
	init := okDiskInfo()
	init.PartitionStyle = winclient.DiskPartitionStyleGPT
	fake := &fakeDiskClient{readOut: rawOffline, onlineOut: rawOnline, initOut: init}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"unique_id":       tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"partition_style": tftypes.NewValue(tftypes.String, "GPT"),
			"is_offline":      tftypes.NewValue(tftypes.Bool, false),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	want := []string{"read", "set_online", "initialize"}
	if len(fake.calls) != len(want) {
		t.Fatalf("expected calls %v, got %v", want, fake.calls)
	}
	for i, c := range want {
		if fake.calls[i] != c {
			t.Fatalf("expected calls %v, got %v", want, fake.calls)
		}
	}
	if fake.onlineVal {
		t.Errorf("expected set_online(false) before initialize, got offline=%v", fake.onlineVal)
	}
	if fake.initStyle != "GPT" {
		t.Errorf("initStyle = %q, want GPT", fake.initStyle)
	}
}

func TestDiskCreate_Handler_UnknownStyleDelegatesToHost(t *testing.T) {
	// An "Unknown" observed style is the projection of an empty host value,
	// not a real style: no local mismatch, Initialize runs and the host-side
	// RAW gate decides on live state.
	unknown := okDiskInfo()
	unknown.PartitionStyle = winclient.DiskPartitionStyleUnknown
	init := okDiskInfo()
	init.PartitionStyle = winclient.DiskPartitionStyleGPT
	fake := &fakeDiskClient{readOut: unknown, initOut: init}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"unique_id":       tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"partition_style": tftypes.NewValue(tftypes.String, "GPT"),
		}),
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[0] != "read" || fake.calls[1] != "initialize" {
		t.Errorf("Unknown style must delegate to the host gate, calls=%v", fake.calls)
	}
}

// ---------------------------------------------------------------------------
// Read / Update / Delete
// ---------------------------------------------------------------------------

func TestDiskRead_Handler_HappyPath(t *testing.T) {
	fake := &fakeDiskClient{readOut: okDiskInfo()}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"id":        tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"unique_id": tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
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
	// Read resolves by the resource ID (the UniqueId).
	if fake.readSel.UniqueID != okDiskInfo().UniqueID {
		t.Errorf("Read should resolve by ID UniqueId, got %q", fake.readSel.Describe())
	}
}

func TestDiskRead_Handler_DriftRemoved(t *testing.T) {
	fake := &fakeDiskClient{readOut: nil, readErr: nil}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"id":        tftypes.NewValue(tftypes.String, "GONE"),
			"unique_id": tftypes.NewValue(tftypes.String, "GONE"),
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
		t.Error("state should be removed when the disk is gone")
	}
}

func TestDiskUpdate_Handler_ReadOnlyFlag(t *testing.T) {
	after := okDiskInfo()
	after.IsReadOnly = true
	fake := &fakeDiskClient{readOut: okDiskInfo(), roOut: after}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"id":        tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"unique_id": tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
		}),
	}
	plan := tfsdk.Plan{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"id":           tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"unique_id":    tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"is_read_only": tftypes.NewValue(tftypes.Bool, true),
		}),
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: prior.Raw.Copy()},
	}
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: prior}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 2 || fake.calls[1] != "set_read_only" || !fake.roVal {
		t.Errorf("expected read + set_read_only(true), calls=%v", fake.calls)
	}
}

func TestDiskDelete_Handler_NoRemoteCall(t *testing.T) {
	fake := &fakeDiskClient{}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"id":        tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"unique_id": tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
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
		t.Errorf("Delete must make no remote call (state-only), calls=%v", fake.calls)
	}
}

// deadlineDiskClient captures the ctx deadline seen by Read.
type deadlineDiskClient struct {
	fakeDiskClient
	deadline time.Time
	ok       bool
}

func (f *deadlineDiskClient) Read(ctx context.Context, _ winclient.DiskSelector) (*winclient.DiskInfo, error) {
	f.deadline, f.ok = ctx.Deadline()
	return okDiskInfo(), nil
}

func TestDiskRead_BoundedByTimeouts(t *testing.T) {
	fake := &deadlineDiskClient{}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	prior := tfsdk.State{
		Schema: schemaDef,
		Raw: diskObj(map[string]tftypes.Value{
			"id":        tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
			"unique_id": tftypes.NewValue(tftypes.String, okDiskInfo().UniqueID),
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
	if remaining := time.Until(fake.deadline); remaining <= 0 || remaining > diskDefaultTimeout {
		t.Errorf("Read deadline in %v, want (0, %v]", remaining, diskDefaultTimeout)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func TestDiskImportState_Handler(t *testing.T) {
	fake := &fakeDiskClient{readOut: okDiskInfo()}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.ImportState(context.Background(),
		resource.ImportStateRequest{ID: okDiskInfo().UniqueID}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags: %v", resp.Diagnostics)
	}
	var m windowsDiskModel
	if d := resp.State.Get(context.Background(), &m); d.HasError() {
		t.Fatalf("State.Get: %v", d)
	}
	if m.ID.ValueString() != okDiskInfo().UniqueID || m.UniqueID.ValueString() != okDiskInfo().UniqueID {
		t.Errorf("import state id/unique_id = %q/%q", m.ID.ValueString(), m.UniqueID.ValueString())
	}
	if m.Number.ValueInt64() != 2 {
		t.Errorf("import should record the observed number, got %v", m.Number)
	}
	if fake.readSel.UniqueID != okDiskInfo().UniqueID {
		t.Errorf("import should read by UniqueId, got %q", fake.readSel.Describe())
	}
}

func TestDiskImportState_NotFound(t *testing.T) {
	fake := &fakeDiskClient{readOut: nil, readErr: nil}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "GONE"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("import of a missing disk must error")
	}
}

func TestDiskImportState_EmptyID(t *testing.T) {
	fake := &fakeDiskClient{}
	r := &windowsDiskResource{disks: fake}
	schemaDef := windowsDiskSchemaDefinition(context.Background())
	resp := &resource.ImportStateResponse{
		State: tfsdk.State{Schema: schemaDef, Raw: diskObj(nil)},
	}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: "  "}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("empty import ID must error")
	}
	if len(fake.calls) != 0 {
		t.Errorf("invalid import ID must not reach the host, calls=%v", fake.calls)
	}
}
