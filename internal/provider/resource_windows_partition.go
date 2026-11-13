// Package provider: windows_partition resource implementation.
//
// This file contains the TPF schema, model, and CRUD + ImportState handlers
// for the windows_partition resource. SSH interaction is delegated to
// winclient.PartitionClient (internal/winclient/partition.go); disk
// selection and the protected-storage guard live in
// internal/winclient/storage_common.go and internal/winclient/disk.go and
// are shared with windows_disk.
//
// The resource manages one partition on a data disk (New-Partition /
// Get-Partition / Resize-Partition / Set-Partition / Remove-Partition),
// including its drive letter. Identity is the
// "<disk_unique_id>|<guid_or_offset>" pair: the partition GUID on GPT disks,
// the byte offset on MBR disks — never the scan-time partition number.
// Deleting the resource destroys the partition and its data: the docs
// strongly recommend `lifecycle { prevent_destroy = true }`.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// partitionDefaultTimeout is the fallback per-operation timeout when the user
// does not provide a `timeouts {}` block. Partition operations (create with
// an explicit letter assignment, grow with a filesystem extension) can take
// minutes on large disks.
const partitionDefaultTimeout = 15 * time.Minute

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsPartitionResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsPartitionResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsPartitionResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsPartitionResource)(nil)
)

// NewWindowsPartitionResource is the constructor registered in provider.go.
func NewWindowsPartitionResource() resource.Resource { return &windowsPartitionResource{} }

// windowsPartitionResource is the TPF resource type for windows_partition.
type windowsPartitionResource struct {
	partitions winclient.WindowsPartitionClient
}

// windowsPartitionModel is the Terraform state/plan model for
// windows_partition.
type windowsPartitionModel struct {
	ID                types.String   `tfsdk:"id"`
	DiskUniqueID      types.String   `tfsdk:"disk_unique_id"`
	SizeBytes         types.Int64    `tfsdk:"size_bytes"`
	UseMaximumSize    types.Bool     `tfsdk:"use_maximum_size"`
	OffsetBytes       types.Int64    `tfsdk:"offset_bytes"`
	DriveLetter       types.String   `tfsdk:"drive_letter"`
	GptType           types.String   `tfsdk:"gpt_type"`
	MbrType           types.String   `tfsdk:"mbr_type"`
	IsHidden          types.Bool     `tfsdk:"is_hidden"`
	IsActive          types.Bool     `tfsdk:"is_active"`
	PartitionNumber   types.Int64    `tfsdk:"partition_number"`
	GUID              types.String   `tfsdk:"guid"`
	AccessPaths       types.List     `tfsdk:"access_paths"`
	IsBoot            types.Bool     `tfsdk:"is_boot"`
	IsSystem          types.Bool     `tfsdk:"is_system"`
	OperationalStatus types.String   `tfsdk:"operational_status"`
	Timeouts          timeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the resource type name ("windows_partition").
func (r *windowsPartitionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_partition"
}

// Schema returns the complete TPF schema.
func (r *windowsPartitionResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsPartitionSchemaDefinition(ctx)
}

// driveLetterPattern accepts a single upper-case letter D-Z. Lower-case and
// the reserved A/B/C are rejected at plan time so the configured spelling can
// never differ cosmetically from the upper-cased state (which would show a
// perpetual diff); NormalizeDriveLetter re-checks Go-side as defence in
// depth for direct API use.
var driveLetterPattern = regexp.MustCompile(`^[D-Z]$`)

// windowsPartitionSchemaDefinition returns the windows_partition schema.
//
// disk_unique_id adopts the hosting disk and forces replacement; so do
// offset_bytes, use_maximum_size and the partition types (a different
// offset, extent mode or type is a different partition). size_bytes grows in
// place (shrink is refused with shrink_not_supported). drive_letter,
// is_hidden and is_active update in place.
func windowsPartitionSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages one partition on a data disk on a remote Windows host via SSH and PowerShell " +
			"(`New-Partition` / `Get-Partition` / `Resize-Partition` / `Set-Partition` / `Remove-Partition`), " +
			"including its drive letter.\n\n" +
			"Identity is `<disk_unique_id>|<guid>` on GPT disks and `<disk_unique_id>|<offset>` on MBR disks " +
			"(partitions have no GUID there): the scan-time partition number is informational only and never " +
			"used to find the partition.\n\n" +
			"Deleting the resource **destroys the partition and its data** (`Remove-Partition`): consider " +
			"`lifecycle { prevent_destroy = true }` for partitions holding data. Protected partitions " +
			"(boot, system, EFI, MSR, recovery, or holding the active pagefile — or whose placement cannot " +
			"be determined, fail closed) are refused with `protected_storage`.\n\n" +
			"Typical layering is `windows_disk` → `windows_partition` → `windows_volume` (#292): adopt and " +
			"initialize the disk, carve the partition, then format it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier: `<disk_unique_id>|<guid>` on GPT, `<disk_unique_id>|<offset>` on MBR.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"disk_unique_id": schema.StringAttribute{
				Required:    true,
				Description: "Stable Get-Disk UniqueId of the hosting disk (e.g. the `id` of a `windows_disk` resource). ForceNew: a different disk is a different partition.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"size_bytes": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Desired partition size in bytes. Grows in place (`Resize-Partition`, which extends the file system with it for NTFS/ReFS); shrinking is refused with `shrink_not_supported` in v1. Conflicts with `use_maximum_size`.",
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
			"use_maximum_size": schema.BoolAttribute{
				Optional:    true,
				Description: "Create the partition from the largest free extent (`-UseMaximumSize`) instead of an explicit `size_bytes`. Create-only (ForceNew): later growth is not automatic (set `size_bytes` to grow).",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"offset_bytes": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Explicit partition offset in bytes (`New-Partition -Offset`). Null (default) places the partition at the first fitting extent. ForceNew.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},
			"drive_letter": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Single drive letter D-Z (upper-cased), assigned explicitly after creation (`Set-Partition -NewDriveLetter`; removal via `Remove-PartitionAccessPath`). Null removes the letter. A, B and C are rejected (floppy- and system-reserved). A letter already in use is a `drive_letter_in_use` error.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						driveLetterPattern,
						"must be a single upper-case drive letter D-Z (A, B and C are reserved)",
					),
				},
			},
			"gpt_type": schema.StringAttribute{
				Optional:    true,
				Description: "GPT partition type: alias `basic_data` (default, `{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}`), `msr`, `recovery`, or a literal GUID. GPT disks only (validated against the disk style at apply). ForceNew. Conflicts with `mbr_type`. Aliases are stored and planned in canonical GUID form.",
				PlanModifiers: []planmodifier.String{
					partitionGPTTypeCanonicalizeModifier{},
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"mbr_type": schema.StringAttribute{
				Optional:    true,
				Description: "MBR partition type byte: alias `IFS` (default, `0x07`), `FAT32`, `FAT32_LBA`, `EXTENDED`, `NTFS`, a hex byte (`0x00`-`0xFF`) or a decimal byte (`0`-`255`). MBR disks only (validated against the disk style at apply). ForceNew. Conflicts with `gpt_type`. Aliases and decimal bytes are stored and planned in canonical `0x..` form.",
				PlanModifiers: []planmodifier.String{
					partitionMBRTypeCanonicalizeModifier{},
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"is_hidden": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the partition is hidden (`Set-Partition -IsHidden`). Null (unset) leaves the observed state unmanaged.",
			},
			"is_active": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the partition is active (`Set-Partition -IsActive`). MBR only. Null (unset) leaves the observed state unmanaged.",
			},
			"partition_number": schema.Int64Attribute{
				Computed:    true,
				Description: "Get-Partition PartitionNumber, as observed on the host. Scan-time assignment, informational only: identity never relies on it.",
			},
			"guid": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Partition Guid, as observed on the host. The stable identity on GPT disks; empty on MBR disks (whose identity is the offset).",
			},
			"access_paths": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Get-Partition AccessPaths, as observed on the host.",
			},
			"is_boot": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the partition is the boot partition, as observed on the host. Boot partitions are refused with protected_storage.",
			},
			"is_system": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the partition is the system partition, as observed on the host. System partitions are refused with protected_storage.",
			},
			"operational_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Partition OperationalStatus (e.g. Online), as observed on the host.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			"timeouts": timeouts.Attributes(ctx, partitionTimeoutsOpts),
		},
	}
}

// ConfigValidators enforces the mutual exclusions: an explicit size against
// the largest-free-extent mode, and a GPT type against an MBR type.
func (r *windowsPartitionResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.Conflicting(
			path.MatchRoot("size_bytes"),
			path.MatchRoot("use_maximum_size"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("gpt_type"),
			path.MatchRoot("mbr_type"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (r *windowsPartitionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.partitions = winclient.NewPartitionClient(c)
}

// partitionTimeoutsOpts declares which per-operation timeouts the resource
// exposes. Delete removes the partition for real, so every operation binds
// its remote calls.
var partitionTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// partitionNullTimeouts returns a null timeouts value carrying the schema's
// attribute types (same pattern as the disk resource: the zero
// timeouts.Value wraps an object with no attribute types, which the
// framework rejects on State.Set).
func partitionNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if partitionTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if partitionTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if partitionTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if partitionTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// partitionModelFromInfo projects an observed PartitionInfo onto a model,
// preserving the operator-owned inputs carried by keep (plan on Create, prior
// state on Read). Partition types are stored in canonical form so an alias
// spelling (basic_data, ifs) and its canonical value (GUID, 0x07) never show
// a perpetual diff against the RequiresReplace pair.
func partitionModelFromInfo(ctx context.Context, info *winclient.PartitionInfo, keep windowsPartitionModel, tm timeouts.Value) (windowsPartitionModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := windowsPartitionModel{
		DiskUniqueID:      types.StringValue(info.DiskUniqueID),
		SizeBytes:         types.Int64Value(info.SizeBytes),
		PartitionNumber:   types.Int64Value(int64(info.PartitionNumber)),
		IsHidden:          types.BoolValue(info.IsHidden),
		IsActive:          types.BoolValue(info.IsActive),
		IsBoot:            types.BoolValue(info.IsBoot),
		IsSystem:          types.BoolValue(info.IsSystem),
		OperationalStatus: types.StringValue(info.OperationalStatus),
		Timeouts:          tm,
	}
	id, err := winclient.BuildPartitionID(info.DiskUniqueID, winclient.PartitionResourceKey(info))
	if err != nil {
		diags.AddError("Invalid partition identity", err.Error())
		return windowsPartitionModel{}, diags
	}
	m.ID = types.StringValue(id)
	if strings.TrimSpace(info.DriveLetter) == "" {
		m.DriveLetter = types.StringNull()
	} else {
		m.DriveLetter = types.StringValue(strings.ToUpper(strings.TrimSpace(info.DriveLetter)))
	}
	if strings.TrimSpace(info.GUID) == "" {
		m.GUID = types.StringNull()
	} else {
		m.GUID = types.StringValue(strings.TrimSpace(info.GUID))
	}
	paths, perr := types.ListValueFrom(ctx, types.StringType, info.AccessPaths)
	if perr.HasError() {
		diags.Append(perr...)
		return windowsPartitionModel{}, diags
	}
	m.AccessPaths = paths
	// Operator-owned inputs are preserved from keep; partition types are
	// converged to canonical form so alias and canonical spellings compare
	// equal. Observed values fill the gaps the configuration leaves open.
	m.UseMaximumSize = keep.UseMaximumSize
	m.GptType = canonicalPartitionGptState(keep.GptType)
	m.MbrType = canonicalPartitionMbrState(keep.MbrType)
	if keep.OffsetBytes.IsNull() || keep.OffsetBytes.IsUnknown() {
		m.OffsetBytes = types.Int64Value(info.OffsetBytes)
	} else {
		m.OffsetBytes = keep.OffsetBytes
	}
	return m, diags
}

// canonicalPartitionGptState converges a preserved gpt_type value to its
// canonical GUID form; null, unknown, empty and invalid values pass through
// untouched (validators report the invalid ones).
func canonicalPartitionGptState(v types.String) types.String {
	if v.IsNull() || v.IsUnknown() {
		return v
	}
	if strings.TrimSpace(v.ValueString()) == "" {
		return v
	}
	if canon, err := winclient.CanonicalizeGPTType(v.ValueString()); err == nil && canon != "" {
		return types.StringValue(canon)
	}
	return v
}

// canonicalPartitionMbrState converges a preserved mbr_type value to its
// canonical 0x.. form; null, unknown, empty and invalid values pass through
// untouched (validators report the invalid ones).
func canonicalPartitionMbrState(v types.String) types.String {
	if v.IsNull() || v.IsUnknown() {
		return v
	}
	if strings.TrimSpace(v.ValueString()) == "" {
		return v
	}
	if canon, err := winclient.CanonicalizeMBRType(v.ValueString()); err == nil && canon != "" {
		return types.StringValue(canon)
	}
	return v
}

// partitionGPTTypeCanonicalizeModifier converges a configured gpt_type alias
// to its canonical GUID at plan time, so the planned value compares equal
// to the canonical state recorded on Create and Import.
type partitionGPTTypeCanonicalizeModifier struct{}

func (m partitionGPTTypeCanonicalizeModifier) Description(_ context.Context) string {
	return "Normalises the GPT type alias to its canonical GUID."
}

func (m partitionGPTTypeCanonicalizeModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m partitionGPTTypeCanonicalizeModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	normalised, err := winclient.CanonicalizeGPTType(req.PlanValue.ValueString())
	if err != nil {
		return // the attribute validator reports malformed input
	}
	resp.PlanValue = types.StringValue(normalised)
}

// partitionMBRTypeCanonicalizeModifier converges a configured mbr_type alias
// or decimal byte to its canonical 0x.. form at plan time, so the planned
// value compares equal to the canonical state recorded on Create and Import.
type partitionMBRTypeCanonicalizeModifier struct{}

func (m partitionMBRTypeCanonicalizeModifier) Description(_ context.Context) string {
	return "Normalises the MBR type to its canonical 0x.. form."
}

func (m partitionMBRTypeCanonicalizeModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m partitionMBRTypeCanonicalizeModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	normalised, err := winclient.CanonicalizeMBRType(req.PlanValue.ValueString())
	if err != nil {
		return // the attribute validator reports malformed input
	}
	resp.PlanValue = types.StringValue(normalised)
}

// addPartitionDiag converts a winclient.PartitionError into a TPF diagnostic.
func addPartitionDiag(diags *diag.Diagnostics, summary string, err error) {
	var pe *winclient.PartitionError
	if errors.As(err, &pe) {
		detail := pe.Message
		if len(pe.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range pe.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if pe.Cause != nil {
			detail += "\n\nCause: " + pe.Cause.Error()
		}
		if pe.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", pe.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// partitionCreateOptionsFromPlan validates the plan's operator-owned inputs
// and renders the winclient Create options: the drive letter is normalized
// (upper-cased D-Z), the partition types resolve to their canonical forms,
// and size-vs-maximum is decided (plan unknown size with no maximum is an
// error: the schema leaves it Computed so the host-reported alignment lands
// in state, but the config must still say how large the partition is).
func partitionCreateOptionsFromPlan(plan windowsPartitionModel) (winclient.PartitionCreateOptions, error) {
	var opts winclient.PartitionCreateOptions
	opts.DiskUniqueID = strings.TrimSpace(plan.DiskUniqueID.ValueString())
	useMax := !plan.UseMaximumSize.IsNull() && !plan.UseMaximumSize.IsUnknown() && plan.UseMaximumSize.ValueBool()
	opts.UseMaximumSize = useMax
	if !useMax {
		if plan.SizeBytes.IsNull() || plan.SizeBytes.IsUnknown() {
			return opts, winclient.NewPartitionError(winclient.PartitionErrorUnknown,
				"size_bytes must be set unless use_maximum_size is true", nil, nil)
		}
		opts.SizeBytes = plan.SizeBytes.ValueInt64()
	}
	if !plan.OffsetBytes.IsNull() && !plan.OffsetBytes.IsUnknown() {
		opts.HasOffset = true
		opts.OffsetBytes = plan.OffsetBytes.ValueInt64()
	}
	if !plan.DriveLetter.IsNull() && !plan.DriveLetter.IsUnknown() && strings.TrimSpace(plan.DriveLetter.ValueString()) != "" {
		letter, err := winclient.NormalizeDriveLetter(plan.DriveLetter.ValueString())
		if err != nil {
			return opts, err
		}
		opts.DriveLetter = letter
	}
	if !plan.GptType.IsNull() && !plan.GptType.IsUnknown() && strings.TrimSpace(plan.GptType.ValueString()) != "" {
		gpt, err := winclient.CanonicalizeGPTType(plan.GptType.ValueString())
		if err != nil {
			return opts, err
		}
		opts.GptType = gpt
	}
	if !plan.MbrType.IsNull() && !plan.MbrType.IsUnknown() && strings.TrimSpace(plan.MbrType.ValueString()) != "" {
		mbr, err := winclient.CanonicalizeMBRType(plan.MbrType.ValueString())
		if err != nil {
			return opts, err
		}
		opts.MbrType = mbr
	}
	if err := winclient.ValidatePartitionCreateOptions(opts); err != nil {
		return opts, err
	}
	return opts, nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create carves the partition on the hosting disk (refusing protected,
// offline, read-only or RAW disks fail-closed), checks the free extent,
// assigns the configured letter explicitly, applies the configured
// hidden/active flags, and persists the observed state.
func (r *windowsPartitionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsPartitionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	createTimeout, diags := plan.Timeouts.Create(ctx, partitionDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	opts, err := partitionCreateOptionsFromPlan(plan)
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Create windows_partition failed", err)
		return
	}

	tflog.Debug(ctx, "windows_partition Create", map[string]interface{}{"disk_unique_id": opts.DiskUniqueID})

	info, err := r.partitions.Create(ctx, opts)
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Create windows_partition failed", err)
		return
	}

	// New-Partition carries no hidden/active switches, so configured flags
	// that differ from the observed state need an explicit Set-Partition
	// (same diff-gated write as Update).
	var wantHidden, wantActive *bool
	if !plan.IsHidden.IsNull() && !plan.IsHidden.IsUnknown() && plan.IsHidden.ValueBool() != info.IsHidden {
		v := plan.IsHidden.ValueBool()
		wantHidden = &v
	}
	if !plan.IsActive.IsNull() && !plan.IsActive.IsUnknown() && plan.IsActive.ValueBool() != info.IsActive {
		v := plan.IsActive.ValueBool()
		wantActive = &v
	}
	if wantHidden != nil || wantActive != nil {
		info, err = r.partitions.SetFlags(ctx, info.DiskUniqueID, winclient.PartitionResourceKey(info), wantHidden, wantActive)
		if err != nil {
			addPartitionDiag(&resp.Diagnostics, "Create windows_partition failed", err)
			return
		}
	}

	m, diags := partitionModelFromInfo(ctx, info, plan, plan.Timeouts)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The state keeps the normalized letter (upper-cased D-Z) and the
	// canonical partition types (GUID / 0x..) rather than the raw configured
	// spellings, matching ImportState.
	if opts.DriveLetter != "" {
		m.DriveLetter = types.StringValue(opts.DriveLetter)
	}
	if opts.GptType != "" {
		m.GptType = types.StringValue(opts.GptType)
	}
	if opts.MbrType != "" {
		m.MbrType = types.StringValue(opts.MbrType)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live host by the (disk, key) ID. A
// vanished disk or partition removes the resource from state; partition
// types recorded in state stay in canonical form.
func (r *windowsPartitionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsPartitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	readTimeout, diags := state.Timeouts.Read(ctx, partitionDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	disk, key, err := winclient.ParsePartitionID(state.ID.ValueString())
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Read windows_partition failed", err)
		return
	}
	tflog.Debug(ctx, "windows_partition Read", map[string]interface{}{"id": state.ID.ValueString()})

	info, err := r.partitions.Read(ctx, disk, key)
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Read windows_partition failed", err)
		return
	}
	if info == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	m, diags := partitionModelFromInfo(ctx, info, state, state.Timeouts)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update grows the partition in place, changes or removes the drive letter,
// and enforces the hidden/active flags. Disk, offset, maximum-size mode and
// partition types force replacement via RequiresReplace, so Update never
// sees them change; shrinking is refused with shrink_not_supported.
func (r *windowsPartitionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsPartitionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	updateTimeout, diags := plan.Timeouts.Update(ctx, partitionDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	disk, key, err := winclient.ParsePartitionID(prior.ID.ValueString())
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Update windows_partition failed", err)
		return
	}
	tflog.Debug(ctx, "windows_partition Update", map[string]interface{}{"id": prior.ID.ValueString()})

	info, err := r.partitions.Read(ctx, disk, key)
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Update windows_partition failed", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Partition not found",
			fmt.Sprintf("No partition %q was found on the target host; it may have been removed out of band.", prior.ID.ValueString()),
		)
		return
	}

	// Grow (shrink refused). A null or unknown planned size keeps the
	// observed size: the attribute is Computed so removing it from config
	// does not mean "shrink to nothing".
	if !plan.SizeBytes.IsNull() && !plan.SizeBytes.IsUnknown() {
		desired := plan.SizeBytes.ValueInt64()
		grow, derr := winclient.DecidePartitionResize(info.SizeBytes, desired)
		if derr != nil {
			addPartitionDiag(&resp.Diagnostics, "Update windows_partition failed", derr)
			return
		}
		if grow {
			info, err = r.partitions.Grow(ctx, disk, key, desired)
			if err != nil {
				addPartitionDiag(&resp.Diagnostics, "Update windows_partition failed", err)
				return
			}
		}
	}

	// Drive letter change or removal. Null means "no letter".
	wantLetter := ""
	if !plan.DriveLetter.IsNull() && !plan.DriveLetter.IsUnknown() && strings.TrimSpace(plan.DriveLetter.ValueString()) != "" {
		wantLetter, err = winclient.NormalizeDriveLetter(plan.DriveLetter.ValueString())
		if err != nil {
			addPartitionDiag(&resp.Diagnostics, "Update windows_partition failed", err)
			return
		}
	}
	if wantLetter != info.DriveLetter {
		info, err = r.partitions.SetDriveLetter(ctx, disk, key, wantLetter)
		if err != nil {
			addPartitionDiag(&resp.Diagnostics, "Update windows_partition failed", err)
			return
		}
	}

	// Hidden / active flags. Null (unset) leaves the flag unmanaged; only a
	// set value that differs from the observed state triggers a write.
	var wantHidden, wantActive *bool
	if !plan.IsHidden.IsNull() && !plan.IsHidden.IsUnknown() && plan.IsHidden.ValueBool() != info.IsHidden {
		v := plan.IsHidden.ValueBool()
		wantHidden = &v
	}
	if !plan.IsActive.IsNull() && !plan.IsActive.IsUnknown() && plan.IsActive.ValueBool() != info.IsActive {
		v := plan.IsActive.ValueBool()
		wantActive = &v
	}
	if wantHidden != nil || wantActive != nil {
		info, err = r.partitions.SetFlags(ctx, disk, key, wantHidden, wantActive)
		if err != nil {
			addPartitionDiag(&resp.Diagnostics, "Update windows_partition failed", err)
			return
		}
	}

	m, diags := partitionModelFromInfo(ctx, info, plan, plan.Timeouts)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete guards (never system/boot/recovery/MSR/pagefile partitions) then
// destroys the partition and its data with Remove-Partition. A missing
// partition is success.
func (r *windowsPartitionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsPartitionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteTimeout, diags := state.Timeouts.Delete(ctx, partitionDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	disk, key, err := winclient.ParsePartitionID(state.ID.ValueString())
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Delete windows_partition failed", err)
		return
	}
	tflog.Debug(ctx, "windows_partition Delete: destroying the partition and its data",
		map[string]interface{}{"id": state.ID.ValueString()})

	if err := r.partitions.Delete(ctx, disk, key); err != nil {
		addPartitionDiag(&resp.Diagnostics, "Delete windows_partition failed", err)
		return
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing partition by its ID
// ("<disk_unique_id>|<guid_or_offset>").
func (r *windowsPartitionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	disk, key, err := winclient.ParsePartitionID(strings.TrimSpace(req.ID))
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must be \"<disk_unique_id>|<guid_or_offset>\"; got %q.", req.ID))
		return
	}
	tflog.Debug(ctx, "Importing windows_partition", map[string]interface{}{"id": req.ID})

	// No prior state exists at import time, so a configured timeouts block
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, partitionDefaultTimeout)
	defer cancel()

	info, err := r.partitions.Read(ctx, disk, key)
	if err != nil {
		addPartitionDiag(&resp.Diagnostics, "Error importing windows_partition", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Partition not found",
			fmt.Sprintf("No partition %q was found on the target host.", req.ID),
		)
		return
	}

	empty := windowsPartitionModel{
		UseMaximumSize: types.BoolNull(),
		GptType:        types.StringNull(),
		MbrType:        types.StringNull(),
		Timeouts:       partitionNullTimeouts(),
	}
	// An import cannot know whether the partition was created with an
	// explicit size or the maximum extent: the observed values anchor the
	// state, and a size_bytes config that matches (or a use_maximum_size
	// config on a full-extent partition) converges with no diff. Drive
	// letter, flags, size, and the style-matching type are recorded from
	// the observed state; only use_maximum_size and the non-matching style
	// stay null. The partition
	// type matching the disk style (GUID on GPT, offset-keyed MBR) is
	// populated from the observed state in canonical form so the
	// RequiresReplace pair does not force a destructive cycle; the other
	// style stays null.
	m, diags := partitionModelFromInfo(ctx, info, empty, empty.Timeouts)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if g := strings.Trim(info.GUID, "{} "); g != "" && !strings.EqualFold(g, "00000000-0000-0000-0000-000000000000") {
		if strings.TrimSpace(info.GptType) != "" {
			if canon, cerr := winclient.CanonicalizeGPTType(info.GptType); cerr == nil {
				m.GptType = types.StringValue(canon)
			} else {
				m.GptType = types.StringValue(strings.TrimSpace(info.GptType))
			}
		}
	} else if strings.TrimSpace(info.MbrType) != "" {
		if canon, cerr := winclient.CanonicalizeMBRType(info.MbrType); cerr == nil {
			m.MbrType = types.StringValue(canon)
		} else {
			m.MbrType = types.StringValue(strings.TrimSpace(info.MbrType))
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}
