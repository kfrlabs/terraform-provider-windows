// Package provider: windows_volume resource implementation.
//
// This file contains the TPF schema, model, and CRUD + ImportState handlers
// for the windows_volume resource. SSH interaction is delegated to
// winclient.VolumeClient (internal/winclient/volume.go); disk selection, the
// protected-storage guard and partition resolution live in
// internal/winclient/storage_common.go, disk.go and partition.go and are
// shared with windows_disk (#290) and windows_partition (#291).
//
// The resource formats one partition on a data disk (Format-Volume /
// Get-Volume / Set-Volume) and manages its label in place. Identity is the
// Get-Volume UniqueId (the `\\?\Volume{...}\` object path). Formatting
// destroys the partition's data: an already-formatted partition is refused
// with `already_formatted` unless `allow_format_existing` is set, and the
// docs strongly recommend `lifecycle { prevent_destroy = true }`. Deleting
// the resource only drops the adoption from state and makes no remote call:
// volumes are never unformatted.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// volumeDefaultTimeout is the fallback per-operation timeout when the user
// does not provide a `timeouts {}` block. Formats (especially full formats,
// which scan for bad sectors) can take a long time on large disks.
const volumeDefaultTimeout = 30 * time.Minute

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsVolumeResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsVolumeResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsVolumeResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*windowsVolumeResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsVolumeResource)(nil)
)

// NewWindowsVolumeResource is the constructor registered in provider.go.
func NewWindowsVolumeResource() resource.Resource { return &windowsVolumeResource{} }

// windowsVolumeResource is the TPF resource type for windows_volume.
type windowsVolumeResource struct {
	volumes winclient.WindowsVolumeClient
}

// windowsVolumeModel is the Terraform state/plan model for windows_volume.
type windowsVolumeModel struct {
	ID                  types.String   `tfsdk:"id"`
	PartitionID         types.String   `tfsdk:"partition_id"`
	FileSystem          types.String   `tfsdk:"file_system"`
	FileSystemLabel     types.String   `tfsdk:"file_system_label"`
	AllocationUnitSize  types.Int64    `tfsdk:"allocation_unit_size"`
	AllowFormatExisting types.Bool     `tfsdk:"allow_format_existing"`
	FullFormat          types.Bool     `tfsdk:"full_format"`
	DriveLetter         types.String   `tfsdk:"drive_letter"`
	Path                types.String   `tfsdk:"path"`
	SizeBytes           types.Int64    `tfsdk:"size_bytes"`
	SizeRemainingBytes  types.Int64    `tfsdk:"size_remaining_bytes"`
	HealthStatus        types.String   `tfsdk:"health_status"`
	OperationalStatus   types.String   `tfsdk:"operational_status"`
	DriveType           types.String   `tfsdk:"drive_type"`
	Timeouts            timeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the resource type name ("windows_volume").
func (r *windowsVolumeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_volume"
}

// Schema returns the complete TPF schema.
func (r *windowsVolumeResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsVolumeSchemaDefinition(ctx)
}

// windowsVolumeSchemaDefinition returns the windows_volume schema.
//
// partition_id adopts the hosting partition and forces replacement; so do
// file_system (reformatting destroys data) and allocation_unit_size (it can
// only be set at format time). file_system_label updates in place via
// Set-Volume. allow_format_existing gates reformatting an already-formatted
// partition; full_format selects a slow full format over the default quick
// format (both are create-time only in effect and converge with no diff).
func windowsVolumeSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Formats one partition on a data disk on a remote Windows host via SSH and PowerShell " +
			"(`Format-Volume` / `Get-Volume` / `Set-Volume`) and manages its volume label.\n\n" +
			"Identity is the Get-Volume UniqueId (the `\\\\?\\Volume{...}\\` object path). The hosting " +
			"`partition_id` is the `windows_partition` ID (`<disk_unique_id>|<guid>` on GPT, " +
			"`<disk_unique_id>|<offset>` on MBR). Formatting destroys the partition's data: a partition " +
			"that already carries a file system is refused with `already_formatted` unless " +
			"`allow_format_existing` is set, and the boot/system/EFI/MSR/recovery/pagefile guard fails " +
			"closed with `protected_storage`.\n\n" +
			"Deleting the resource only drops the adoption from state and makes no remote call: the " +
			"volume and its data are left exactly as they are (volumes are never unformatted). Consider " +
			"`lifecycle { prevent_destroy = true }` for volumes holding data.\n\n" +
			"Typical layering is `windows_disk` → `windows_partition` → `windows_volume` (#292): adopt and " +
			"initialize the disk, carve the partition, then format it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier; the Get-Volume UniqueId of the formatted volume.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"partition_id": schema.StringAttribute{
				Required:    true,
				Description: "Hosting partition in `<disk_unique_id>|<guid_or_offset>` form (the `id` of a `windows_partition` resource: the GUID on GPT disks, the byte offset on MBR disks). ForceNew: a different partition is a different volume.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"file_system": schema.StringAttribute{
				Required:    true,
				Description: "File system to format the partition with: `NTFS`, `ReFS`, `exFAT` or `FAT32` (case-insensitive, stored in canonical form). ForceNew: changing it reformats the volume and destroys its data (plan warns).",
				PlanModifiers: []planmodifier.String{
					volumeFileSystemCanonicalizeModifier{},
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"file_system_label": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Volume label, enforced in place (`Set-Volume -NewFileSystemLabel`; empty clears it). Null (unset) leaves the observed label unmanaged. Length limits depend on the file system: 32 characters for NTFS/ReFS, 11 for exFAT/FAT32.",
				Validators: []validator.String{
					stringvalidator.LengthAtMost(32),
				},
			},
			"allocation_unit_size": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Allocation unit (cluster) size in bytes, set at format time only. ForceNew. Null (default) selects the host default. Must be a power of two between 512 and 2097152, further narrowed per file system: NTFS 512-65536, FAT32 512-32768, exFAT 512-2097152, ReFS 4096 or 65536 only.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(512),
				},
			},
			"allow_format_existing": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Permit formatting a partition that already carries a file system (reformatting destroys its data). Without it, formatting an already-formatted partition is an `already_formatted` error suggesting import instead.",
			},
			"full_format": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Perform a full format (which scans for bad sectors) instead of the default quick format. A full format can take a long time on large disks; the resource timeouts default to 30m to cover it.",
			},
			"drive_letter": schema.StringAttribute{
				Computed:    true,
				Description: "Assigned drive letter (upper-cased), as observed on the host. Empty when the volume has none; manage it with the `drive_letter` of `windows_partition`.",
			},
			"path": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume Path (the `\\\\?\\Volume{...}\\` object path), as observed on the host.",
			},
			"size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Get-Volume Size in bytes, as observed on the host.",
			},
			"size_remaining_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Get-Volume SizeRemaining in bytes, as observed on the host.",
			},
			"health_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume HealthStatus (e.g. Healthy), as observed on the host.",
			},
			"operational_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume OperationalStatus (e.g. OK), as observed on the host.",
			},
			"drive_type": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Volume DriveType (e.g. Fixed), as observed on the host.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			"timeouts": timeouts.Attributes(ctx, volumeTimeoutsOpts),
		},
	}
}

// ModifyPlan warns when a ForceNew input changes between state and plan.
// Replacement reformats a volume, which destroys its data: the file_system
// and allocation_unit_size warnings make the data loss explicit at plan
// time, while the partition_id warning calls out that a different hosting
// partition is formatted and the old volume is left untouched (delete is
// state-only).
func (r *windowsVolumeResource) ModifyPlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}
	var plan, prior windowsVolumeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.PartitionID.IsUnknown() && !prior.PartitionID.IsUnknown() &&
		!plan.PartitionID.Equal(prior.PartitionID) {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("partition_id"),
			"Changing partition_id replaces the volume",
			"partition_id changed, which forces replacement: the new hosting partition will be "+
				"formatted and any data on it will be destroyed, while the old volume is left "+
				"untouched (delete is state-only). Import the existing volume instead if the "+
				"data must be kept.",
		)
	}
	if !plan.FileSystem.IsUnknown() && !prior.FileSystem.IsUnknown() &&
		!plan.FileSystem.Equal(prior.FileSystem) {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("file_system"),
			"Changing file_system reformats the volume",
			"file_system changed, which forces replacement: the volume will be reformatted with the new "+
				"file system and all of its data will be destroyed. Import the existing volume instead if the "+
				"data must be kept.",
		)
	}
	if !plan.AllocationUnitSize.IsUnknown() && !prior.AllocationUnitSize.IsUnknown() &&
		!plan.AllocationUnitSize.Equal(prior.AllocationUnitSize) {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("allocation_unit_size"),
			"Changing allocation_unit_size reformats the volume",
			"allocation_unit_size changed, which forces replacement: the volume will be reformatted with "+
				"the new cluster size and all of its data will be destroyed. Import the existing volume "+
				"instead if the data must be kept.",
		)
	}
}

// ConfigValidators enforces the file-system-dependent limits at plan time:
// the volume label length (32 for NTFS/ReFS, 11 for exFAT/FAT32) and the
// allocation unit size (power of two in the per-file-system allow-list). The
// attribute validators stay coarse (label 32, size at least 512) so unknown
// file systems still plan; the exact limits run here and again at apply via
// volumeFormatOptionsFromPlan.
func (r *windowsVolumeResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{volumeConfigValidator{}}
}

// volumeConfigValidator runs the winclient label and allocation-unit checks
// against the configured file system at plan time.
type volumeConfigValidator struct{}

func (v volumeConfigValidator) Description(_ context.Context) string {
	return "validates file_system_label length and allocation_unit_size against the file system"
}

func (v volumeConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v volumeConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg windowsVolumeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// An unknown or unset file system cannot cross-validate yet: defer to
	// apply time (the attribute validator reports a missing value).
	if cfg.FileSystem.IsNull() || cfg.FileSystem.IsUnknown() {
		return
	}
	fs, err := winclient.CanonicalizeVolumeFileSystem(cfg.FileSystem.ValueString())
	if err != nil {
		return // apply reports the unsupported file system
	}
	if !cfg.FileSystemLabel.IsNull() && !cfg.FileSystemLabel.IsUnknown() {
		if verr := winclient.ValidateVolumeLabel(fs, cfg.FileSystemLabel.ValueString()); verr != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("file_system_label"),
				"Invalid file system label",
				verr.Error(),
			)
		}
	}
	if !cfg.AllocationUnitSize.IsNull() && !cfg.AllocationUnitSize.IsUnknown() {
		if verr := winclient.ValidateVolumeAllocationUnitSize(fs, cfg.AllocationUnitSize.ValueInt64()); verr != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("allocation_unit_size"),
				"Invalid allocation unit size",
				verr.Error(),
			)
		}
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (r *windowsVolumeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.volumes = winclient.NewVolumeClient(c)
}

// volumeTimeoutsOpts declares which per-operation timeouts the resource
// exposes. Delete is state-only (it makes no remote call), so the delete
// knob is never consumed and deletion is immediate and unbounded; it stays
// exposed only so the timeouts block keeps the same four-operation shape as
// every other resource (same pattern as windows_disk).
var volumeTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// volumeNullTimeouts returns a null timeouts value carrying the schema's
// attribute types (same pattern as the disk resource: the zero
// timeouts.Value wraps an object with no attribute types, which the
// framework rejects on State.Set).
func volumeNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if volumeTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if volumeTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if volumeTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if volumeTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// volumeModelFromInfo projects an observed VolumeInfo onto a model,
// preserving the operator-owned inputs carried by keep (plan on Create, prior
// state on Read). The file system is stored in canonical form so a
// lower-case spelling never shows a perpetual diff against RequiresReplace.
func volumeModelFromInfo(info *winclient.VolumeInfo, keep windowsVolumeModel, tm timeouts.Value) windowsVolumeModel {
	m := windowsVolumeModel{
		ID:                 types.StringValue(info.UniqueID),
		FileSystem:         types.StringValue(info.FileSystem),
		DriveLetter:        volumeStringOrNull(info.DriveLetter),
		Path:               volumeStringOrNull(info.Path),
		SizeBytes:          types.Int64Value(info.SizeBytes),
		SizeRemainingBytes: types.Int64Value(info.SizeRemainingBytes),
		HealthStatus:       volumeStringOrNull(info.HealthStatus),
		OperationalStatus:  volumeStringOrNull(info.OperationalStatus),
		DriveType:          volumeStringOrNull(info.DriveType),
		Timeouts:           tm,
	}
	// The hosting partition is Required, so keep always carries it; the
	// observed value is only a fallback for direct API use.
	if keep.PartitionID.IsNull() || keep.PartitionID.IsUnknown() || strings.TrimSpace(keep.PartitionID.ValueString()) == "" {
		m.PartitionID = types.StringValue(info.PartitionID)
	} else {
		m.PartitionID = keep.PartitionID
	}
	// The label and allocation unit size are Optional+Computed: a configured
	// value is authoritative, an absent one reflects the observed state.
	if keep.FileSystemLabel.IsNull() || keep.FileSystemLabel.IsUnknown() {
		m.FileSystemLabel = volumeStringOrNull(info.FileSystemLabel)
	} else {
		m.FileSystemLabel = keep.FileSystemLabel
	}
	if keep.AllocationUnitSize.IsNull() || keep.AllocationUnitSize.IsUnknown() {
		m.AllocationUnitSize = volumeInt64OrNull(info.AllocationUnitSize)
	} else {
		m.AllocationUnitSize = keep.AllocationUnitSize
	}
	m.AllowFormatExisting = keep.AllowFormatExisting
	m.FullFormat = keep.FullFormat
	return m
}

// volumeStringOrNull maps an empty observed string to null so unknown
// host-side spellings (e.g. a volume without a drive letter) do not pin an
// empty string into state.
func volumeStringOrNull(s string) types.String {
	if strings.TrimSpace(s) == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// volumeInt64OrNull maps a zero allocation unit size (the host reports none)
// to null so an absent value does not pin a zero into state.
func volumeInt64OrNull(v int64) types.Int64 {
	if v == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(v)
}

// volumeFileSystemCanonicalizeModifier converges a configured file_system
// spelling to its canonical form at plan time, so a lower-case config never
// diffs against the canonical state recorded on Create and Import.
type volumeFileSystemCanonicalizeModifier struct{}

func (m volumeFileSystemCanonicalizeModifier) Description(_ context.Context) string {
	return "Normalises the file system to its canonical form."
}

func (m volumeFileSystemCanonicalizeModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m volumeFileSystemCanonicalizeModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	normalised, err := winclient.CanonicalizeVolumeFileSystem(req.PlanValue.ValueString())
	if err != nil {
		return // the attribute validator reports malformed input
	}
	resp.PlanValue = types.StringValue(normalised)
}

// addVolumeDiag converts a winclient.VolumeError into a TPF diagnostic.
func addVolumeDiag(diags *diag.Diagnostics, summary string, err error) {
	var ve *winclient.VolumeError
	if errors.As(err, &ve) {
		detail := ve.Message
		if len(ve.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range ve.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if ve.Cause != nil {
			detail += "\n\nCause: " + ve.Cause.Error()
		}
		if ve.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", ve.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// volumeFormatOptionsFromPlan validates the plan's operator-owned inputs and
// renders the winclient Format options: the partition identity is split via
// the shared ParsePartitionID helper, the file system resolves to its
// canonical form, and the label and allocation unit size validate against
// it. A null label formats with the host default; a null allocation unit
// size does the same.
func volumeFormatOptionsFromPlan(plan windowsVolumeModel) (winclient.VolumeFormatOptions, error) {
	var opts winclient.VolumeFormatOptions
	opts.PartitionID = strings.TrimSpace(plan.PartitionID.ValueString())
	if plan.FileSystem.IsNull() || plan.FileSystem.IsUnknown() {
		return opts, winclient.NewVolumeError(winclient.VolumeErrorUnknown,
			"file_system must be set to NTFS, ReFS, exFAT or FAT32", nil, nil)
	}
	fs, err := winclient.CanonicalizeVolumeFileSystem(plan.FileSystem.ValueString())
	if err != nil {
		return opts, err
	}
	opts.FileSystem = fs
	if !plan.FileSystemLabel.IsNull() && !plan.FileSystemLabel.IsUnknown() {
		opts.FileSystemLabel = plan.FileSystemLabel.ValueString()
	}
	if !plan.AllocationUnitSize.IsNull() && !plan.AllocationUnitSize.IsUnknown() {
		opts.AllocationUnitSize = plan.AllocationUnitSize.ValueInt64()
	}
	if !plan.AllowFormatExisting.IsNull() && !plan.AllowFormatExisting.IsUnknown() {
		opts.AllowFormatExisting = plan.AllowFormatExisting.ValueBool()
	}
	if !plan.FullFormat.IsNull() && !plan.FullFormat.IsUnknown() {
		opts.FullFormat = plan.FullFormat.ValueBool()
	}
	if err := winclient.ValidateVolumeFormatOptions(opts); err != nil {
		return opts, err
	}
	return opts, nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create formats the hosting partition (refusing protected storage
// fail-closed and already-formatted partitions without
// allow_format_existing) and persists the observed state.
func (r *windowsVolumeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsVolumeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	createTimeout, diags := plan.Timeouts.Create(ctx, volumeDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	opts, err := volumeFormatOptionsFromPlan(plan)
	if err != nil {
		addVolumeDiag(&resp.Diagnostics, "Create windows_volume failed", err)
		return
	}

	tflog.Debug(ctx, "windows_volume Create", map[string]interface{}{"partition_id": opts.PartitionID})

	info, err := r.volumes.Format(ctx, opts)
	if err != nil {
		addVolumeDiag(&resp.Diagnostics, "Create windows_volume failed", err)
		return
	}

	// The state keeps the canonical file system (NTFS, ReFS, exFAT, FAT32)
	// rather than the raw configured spelling, matching ImportState.
	m := volumeModelFromInfo(info, plan, plan.Timeouts)
	m.FileSystem = types.StringValue(opts.FileSystem)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live host by UniqueId (the
// resource ID). A vanished or unformatted volume removes the resource from
// state; operator-owned inputs stay as recorded.
func (r *windowsVolumeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsVolumeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	readTimeout, diags := state.Timeouts.Read(ctx, volumeDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_volume Read", map[string]interface{}{"id": state.ID.ValueString()})

	info, err := r.volumes.Read(ctx, state.ID.ValueString())
	if err != nil {
		addVolumeDiag(&resp.Diagnostics, "Read windows_volume failed", err)
		return
	}
	if info == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	m := volumeModelFromInfo(info, state, state.Timeouts)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update re-labels the volume in place via Set-Volume. Partition, file
// system and allocation unit size force replacement via RequiresReplace, so
// Update never sees them change. A null planned label leaves the observed
// label unmanaged; anything else (including the empty string, which clears
// the label) is enforced.
func (r *windowsVolumeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsVolumeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	updateTimeout, diags := plan.Timeouts.Update(ctx, volumeDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_volume Update", map[string]interface{}{"id": prior.ID.ValueString()})

	info, err := r.volumes.Read(ctx, prior.ID.ValueString())
	if err != nil {
		addVolumeDiag(&resp.Diagnostics, "Update windows_volume failed", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Volume not found",
			fmt.Sprintf("No volume %q was found on the target host; it may have been removed or unformatted out of band.", prior.ID.ValueString()),
		)
		return
	}

	if !plan.FileSystemLabel.IsNull() && !plan.FileSystemLabel.IsUnknown() &&
		plan.FileSystemLabel.ValueString() != info.FileSystemLabel {
		if verr := winclient.ValidateVolumeLabel(info.FileSystem, plan.FileSystemLabel.ValueString()); verr != nil {
			addVolumeDiag(&resp.Diagnostics, "Update windows_volume failed", verr)
			return
		}
		info, err = r.volumes.SetLabel(ctx, prior.ID.ValueString(), plan.FileSystemLabel.ValueString())
		if err != nil {
			addVolumeDiag(&resp.Diagnostics, "Update windows_volume failed", err)
			return
		}
	}

	m := volumeModelFromInfo(info, plan, plan.Timeouts)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete (state-only)
// ---------------------------------------------------------------------------

// Delete drops the adoption from state and makes no remote call: volumes are
// never unformatted, so there is nothing to tear down on the host. The
// volume and its data are left exactly as they are. Because no remote call
// is made, the timeouts.delete value (kept for schema consistency, see
// volumeTimeoutsOpts) is not consumed: deletion is immediate and unbounded.
func (r *windowsVolumeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsVolumeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "windows_volume Delete: dropping the adoption from state only; the volume is left untouched",
		map[string]interface{}{"id": state.ID.ValueString()})
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing volume by its UniqueId or by drive letter
// ("E" or "E:"). The hosting partition_id is resolved host-side from the
// volume, so the required input repopulates without the operator looking it
// up.
func (r *windowsVolumeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	kind, value, err := winclient.ResolveVolumeImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must be the volume UniqueId or a drive letter such as E:; got %q.", req.ID))
		return
	}
	tflog.Debug(ctx, "Importing windows_volume", map[string]interface{}{"id": req.ID})

	// No prior state exists at import time, so a configured timeouts block
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, volumeDefaultTimeout)
	defer cancel()

	lookup := winclient.VolumeLookup{}
	if kind == winclient.VolumeImportByDriveLetter {
		lookup.DriveLetter = value
	} else {
		lookup.UniqueID = value
	}
	info, err := r.volumes.Lookup(ctx, lookup)
	if err != nil {
		addVolumeDiag(&resp.Diagnostics, "Error importing windows_volume", err)
		return
	}
	if strings.TrimSpace(info.PartitionID) == "" {
		resp.Diagnostics.AddError(
			"Volume hosting partition unknown",
			fmt.Sprintf("The hosting partition of volume %q could not be determined on the target host.", req.ID),
		)
		return
	}

	empty := windowsVolumeModel{
		PartitionID:         types.StringValue(info.PartitionID),
		FileSystemLabel:     types.StringNull(),
		AllocationUnitSize:  types.Int64Null(),
		AllowFormatExisting: types.BoolValue(false),
		FullFormat:          types.BoolValue(false),
		Timeouts:            volumeNullTimeouts(),
	}
	// The import records the observed file system (canonical), label and
	// allocation unit size; allow_format_existing and full_format anchor to
	// their defaults. A null allocation unit size stays null when the host
	// reports none.
	m := volumeModelFromInfo(info, empty, empty.Timeouts)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}
