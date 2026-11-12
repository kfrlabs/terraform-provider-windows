// Package provider: windows_disk resource implementation.
//
// This file contains the TPF schema, model, and CRUD + ImportState handlers
// for the windows_disk resource. SSH interaction is delegated to
// winclient.DiskClient (internal/winclient/disk.go); selector resolution and
// the protected-storage guard live in internal/winclient/storage_common.go.
//
// The resource is adoption-only: disks are physical (or virtual) hardware
// Terraform neither creates nor destroys. Create resolves exactly one of the
// four selectors to a single disk, initializes it when it is RAW and a
// partition style is desired, enforces the online/read-only flags, and
// records the stable UniqueId as the Terraform ID. Delete only drops the
// adoption from state and makes no remote call.
package provider

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// diskDefaultTimeout is the fallback per-operation timeout when the user
// does not provide a `timeouts {}` block. Disk operations are usually fast,
// but a stalled PowerShell/SSH session must never block Terraform forever.
const diskDefaultTimeout = 10 * time.Minute

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsDiskResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsDiskResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsDiskResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsDiskResource)(nil)
)

// NewWindowsDiskResource is the constructor registered in provider.go.
func NewWindowsDiskResource() resource.Resource { return &windowsDiskResource{} }

// windowsDiskResource is the TPF resource type for windows_disk.
type windowsDiskResource struct {
	disks winclient.WindowsDiskClient
}

// windowsDiskModel is the Terraform state/plan model for windows_disk.
type windowsDiskModel struct {
	ID                types.String   `tfsdk:"id"`
	UniqueID          types.String   `tfsdk:"unique_id"`
	SerialNumber      types.String   `tfsdk:"serial_number"`
	Location          types.String   `tfsdk:"location"`
	Number            types.Int64    `tfsdk:"number"`
	IsOffline         types.Bool     `tfsdk:"is_offline"`
	IsReadOnly        types.Bool     `tfsdk:"is_read_only"`
	PartitionStyle    types.String   `tfsdk:"partition_style"`
	FriendlyName      types.String   `tfsdk:"friendly_name"`
	BusType           types.String   `tfsdk:"bus_type"`
	HealthStatus      types.String   `tfsdk:"health_status"`
	OperationalStatus types.String   `tfsdk:"operational_status"`
	SizeBytes         types.Int64    `tfsdk:"size_bytes"`
	IsBoot            types.Bool     `tfsdk:"is_boot"`
	IsSystem          types.Bool     `tfsdk:"is_system"`
	IsClustered       types.Bool     `tfsdk:"is_clustered"`
	Timeouts          timeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the resource type name ("windows_disk").
func (r *windowsDiskResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_disk"
}

// Schema returns the complete TPF schema.
func (r *windowsDiskResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsDiskSchemaDefinition(ctx)
}

// windowsDiskSchemaDefinition returns the windows_disk schema.
//
// Exactly one selector (unique_id, serial_number, location, number) adopts
// the disk; every selector is ForceNew because a different disk is a
// different resource. partition_style is ForceNew as well: only RAW disks
// are initialized in place, converting an initialized disk would destroy
// data and is out of scope. is_offline and is_read_only are the only
// in-place updates.
func windowsDiskSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Adopts a physical disk on a remote Windows host via SSH and PowerShell " +
			"(`Get-Disk` / `Set-Disk` / `Initialize-Disk`) and manages its online/offline state, " +
			"read-only flag and — for uninitialized (`RAW`) disks only — its partition style.\n\n" +
			"The resource never creates or destroys disk hardware: Create resolves exactly one of " +
			"`unique_id`, `serial_number`, `location` or `number` to a single disk (zero matches is an " +
			"error, several matches are an `ambiguous_disk` error) and records the stable `unique_id` " +
			"as the Terraform ID; Delete only drops the adoption from state and makes no remote call, " +
			"so the disk and its data are left untouched.\n\n" +
			"Disks hosting the OS (`is_boot` / `is_system`), the active pagefile, the crash-dump target, " +
			"or clustered disks are refused fail-closed with `protected_storage`, as is a disk whose " +
			"placement cannot be determined. Prefer the `unique_id` selector: disk `number` values are " +
			"assigned by Windows at scan time and can shift across reboots or when disks are added or " +
			"removed (using `number` emits a warning).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier; the stable Get-Disk UniqueId of the adopted disk.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"unique_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Stable Get-Disk UniqueId of the disk to adopt (e.g. `SCSI\\DISK&VEN_...`). Exactly one of unique_id, serial_number, location and number must be set. ForceNew. This is the Terraform ID; prefer it over number.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"serial_number": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Get-Disk SerialNumber of the disk to adopt, matched case-insensitively after trimming whitespace. Exactly one of unique_id, serial_number, location and number must be set. ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"location": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Get-Disk Location (adapter path) of the disk to adopt, matched case-insensitively after trimming whitespace. Exactly one of unique_id, serial_number, location and number must be set. ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"number": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Get-Disk Number of the disk to adopt. Exactly one of unique_id, serial_number, location and number must be set. ForceNew. Disk numbers are assigned by Windows at scan time and can shift across reboots or when disks are added or removed: using number emits a warning, prefer unique_id.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
			},
			"is_offline": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the disk is offline (`Set-Disk -IsOffline`). Null (unset) leaves the observed state unmanaged; otherwise the flag is enforced in place.",
			},
			"is_read_only": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the disk is read-only (`Set-Disk -IsReadOnly`). Null (unset) leaves the observed state unmanaged; otherwise the flag is enforced in place.",
			},
			"partition_style": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Desired partition style for uninitialized (RAW) disks: GPT or MBR. Only a RAW disk is initialized in place; adopting an already-initialized disk with a different style is a partition_style_mismatch error (converting GPT<->MBR destroys data and is out of scope). Unset leaves the style unmanaged. ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(winclient.DiskPartitionStyleGPT, winclient.DiskPartitionStyleMBR),
				},
			},
			"friendly_name": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk FriendlyName, as observed on the host.",
			},
			"bus_type": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk BusType (e.g. SATA, NVMe, RAID, USB, Virtual), as observed on the host.",
			},
			"health_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk HealthStatus (e.g. Healthy), as observed on the host.",
			},
			"operational_status": schema.StringAttribute{
				Computed:    true,
				Description: "Get-Disk OperationalStatus (e.g. Online, Offline), as observed on the host.",
			},
			"size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Get-Disk Size in bytes, as observed on the host.",
			},
			"is_boot": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is the boot disk, as observed on the host. Boot disks are refused with protected_storage.",
			},
			"is_system": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is the system disk, as observed on the host. System disks are refused with protected_storage.",
			},
			"is_clustered": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the disk is clustered, as observed on the host. Clustered disks are refused with protected_storage.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			"timeouts": timeouts.Attributes(ctx, diskTimeoutsOpts),
		},
	}
}

// ConfigValidators enforces ExactlyOneOf over the four selectors.
func (r *windowsDiskResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("unique_id"),
			path.MatchRoot("serial_number"),
			path.MatchRoot("location"),
			path.MatchRoot("number"),
		),
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (r *windowsDiskResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.disks = winclient.NewDiskClient(c)
}

// diskTimeoutsOpts declares which per-operation timeouts the resource exposes.
// Create/Read/Update bound their remote calls. Delete is state-only (it
// makes no remote call), so the delete knob is never consumed and deletion
// is immediate and unbounded; it stays exposed only so the timeouts block
// keeps the same four-operation shape as every other resource.
var diskTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// diskSelectorFromTF builds a winclient.DiskSelector from the four Terraform
// selector values. The second return is false when the values do not carry
// exactly one selector (the schema ExactlyOneOf validator normally prevents
// this; the check is defence in depth for direct API use). Unknown values
// count as unset so a still-unknown selector surfaces as "none set" rather
// than a comparison against garbage.
func diskSelectorFromTF(uniqueID, serial, location types.String, number types.Int64) (winclient.DiskSelector, bool) {
	set := 0
	var sel winclient.DiskSelector
	if !uniqueID.IsNull() && !uniqueID.IsUnknown() && strings.TrimSpace(uniqueID.ValueString()) != "" {
		set++
		sel = winclient.DiskSelectorByUniqueID(uniqueID.ValueString())
	}
	if !serial.IsNull() && !serial.IsUnknown() && strings.TrimSpace(serial.ValueString()) != "" {
		set++
		sel = winclient.DiskSelectorBySerialNumber(serial.ValueString())
	}
	if !location.IsNull() && !location.IsUnknown() && strings.TrimSpace(location.ValueString()) != "" {
		set++
		sel = winclient.DiskSelectorByLocation(location.ValueString())
	}
	if !number.IsNull() && !number.IsUnknown() {
		set++
		sel = winclient.DiskSelectorByNumber(int(number.ValueInt64()))
	}
	if set != 1 {
		return winclient.DiskSelector{}, false
	}
	return sel, true
}

// warnOnNumberSelector emits the stability warning when the adoption uses
// the scan-time disk number instead of a stable identity.
func warnOnNumberSelector(diags *diag.Diagnostics, number types.Int64) {
	if !number.IsNull() && !number.IsUnknown() {
		diags.AddWarning(
			"Unstable disk selector",
			fmt.Sprintf("The disk is selected by number (%d), which Windows assigns at scan time and can shift "+
				"across reboots or when disks are added or removed. Prefer the unique_id selector: adopt once by "+
				"number, then replace the configuration with the observed unique_id from state.",
				number.ValueInt64()),
		)
	}
}

// diskNullTimeouts returns a null timeouts value carrying the schema's
// attribute types (same pattern as the certificate resource: the zero
// timeouts.Value wraps an object with no attribute types, which the
// framework rejects on State.Set).
func diskNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if diskTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if diskTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if diskTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if diskTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// diskModelFromInfo projects an observed DiskInfo onto a model, preserving
// the selector spellings carried by selectorsFrom (plan on Create, prior
// state on Read) and the operator-managed timeouts.
func diskModelFromInfo(info *winclient.DiskInfo, sel windowsDiskModel, tm timeouts.Value) windowsDiskModel {
	m := windowsDiskModel{
		ID:                types.StringValue(info.UniqueID),
		FriendlyName:      types.StringValue(info.FriendlyName),
		BusType:           types.StringValue(info.BusType),
		HealthStatus:      types.StringValue(info.HealthStatus),
		OperationalStatus: types.StringValue(info.OperationalStatus),
		SizeBytes:         types.Int64Value(info.SizeBytes),
		IsOffline:         types.BoolValue(info.IsOffline),
		IsReadOnly:        types.BoolValue(info.IsReadOnly),
		PartitionStyle:    types.StringValue(info.PartitionStyle),
		IsBoot:            types.BoolValue(info.IsBoot),
		IsSystem:          types.BoolValue(info.IsSystem),
		IsClustered:       types.BoolValue(info.IsClustered),
		Timeouts:          tm,
	}
	// Keep the configured (or previously recorded) selector spellings so a
	// cosmetic difference (case, padding) never shows a diff; unique_id falls
	// back to the observed value when it was not the configured selector.
	if sel.UniqueID.IsNull() || sel.UniqueID.IsUnknown() {
		m.UniqueID = types.StringValue(info.UniqueID)
	} else {
		m.UniqueID = sel.UniqueID
	}
	m.SerialNumber = sel.SerialNumber
	m.Location = sel.Location
	m.Number = sel.Number
	return m
}

// addDiskDiag converts a winclient.DiskError into a TPF diagnostic.
func addDiskDiag(diags *diag.Diagnostics, summary string, err error) {
	var de *winclient.DiskError
	if errors.As(err, &de) {
		detail := de.Message
		if len(de.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range de.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if de.Cause != nil {
			detail += "\n\nCause: " + de.Cause.Error()
		}
		if de.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", de.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}

// ensureDiskFlags enforces the desired partition style and the online /
// read-only flags, returning the re-read state after each change.
//
// Ordering matters: an offline disk cannot be initialized, so when the plan
// wants the disk online (is_offline=false) and a style change may need
// initializing, the disk is brought online first; otherwise an offline RAW
// disk with is_offline=false would fail with disk_offline instead of
// converging in one apply. A desired style different from the observed one
// initializes the disk, which only a RAW disk survives: anything else is a
// partition_style_mismatch error raised here (the client re-checks
// host-side against concurrent changes). An "Unknown" observed style (the
// projection of an empty host value, not a real style) skips the local
// mismatch short-circuit and is passed to Initialize so the host-side RAW
// gate decides on live state.
func (r *windowsDiskResource) ensureDiskFlags(ctx context.Context, cur *winclient.DiskInfo, style types.String, offline, readOnly types.Bool) (*winclient.DiskInfo, error) {
	styleWanted := !style.IsNull() && !style.IsUnknown() && strings.TrimSpace(style.ValueString()) != ""
	wantOnline := !offline.IsNull() && !offline.IsUnknown() && !offline.ValueBool()
	if styleWanted && cur.IsOffline && wantOnline {
		next, err := r.disks.SetOnlineState(ctx, cur.UniqueID, false)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	if styleWanted {
		want := strings.ToUpper(strings.TrimSpace(style.ValueString()))
		if cur.PartitionStyle != want {
			if cur.PartitionStyle != winclient.DiskPartitionStyleRAW && cur.PartitionStyle != winclient.DiskPartitionStyleUnknown {
				return nil, winclient.NewDiskError(winclient.DiskErrorPartitionStyleMismatch,
					fmt.Sprintf("disk %s already carries partition style %s (want %s): only RAW disks can be initialized in place",
						cur.UniqueID, cur.PartitionStyle, want),
					nil,
					map[string]string{"unique_id": cur.UniqueID, "current_style": cur.PartitionStyle, "desired_style": want})
			}
			next, err := r.disks.Initialize(ctx, cur.UniqueID, want)
			if err != nil {
				return nil, err
			}
			cur = next
		}
	}
	if !offline.IsNull() && !offline.IsUnknown() && offline.ValueBool() != cur.IsOffline {
		next, err := r.disks.SetOnlineState(ctx, cur.UniqueID, offline.ValueBool())
		if err != nil {
			return nil, err
		}
		cur = next
	}
	if !readOnly.IsNull() && !readOnly.IsUnknown() && readOnly.ValueBool() != cur.IsReadOnly {
		next, err := r.disks.SetReadOnlyState(ctx, cur.UniqueID, readOnly.ValueBool())
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// ---------------------------------------------------------------------------
// Create (adopt)
// ---------------------------------------------------------------------------

// Create adopts the single disk matching the configured selector: it reads
// the live disk (refusing protected storage fail-closed), initializes a RAW
// disk when a partition style is desired, enforces the configured
// online/read-only flags, and persists the observed state.
func (r *windowsDiskResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsDiskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	createTimeout, diags := plan.Timeouts.Create(ctx, diskDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	sel, ok := diskSelectorFromTF(plan.UniqueID, plan.SerialNumber, plan.Location, plan.Number)
	if !ok {
		resp.Diagnostics.AddError(
			"Missing disk selector",
			"Exactly one of unique_id, serial_number, location and number must be set.",
		)
		return
	}
	warnOnNumberSelector(&resp.Diagnostics, plan.Number)

	tflog.Debug(ctx, "windows_disk Create (adopt)", map[string]interface{}{"selector": sel.Describe()})

	info, err := r.disks.Read(ctx, sel)
	if err != nil {
		addDiskDiag(&resp.Diagnostics, "Create windows_disk failed", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Disk not found",
			fmt.Sprintf("No disk matches %s on the target host.", sel.Describe()),
		)
		return
	}

	info, err = r.ensureDiskFlags(ctx, info, plan.PartitionStyle, plan.IsOffline, plan.IsReadOnly)
	if err != nil {
		addDiskDiag(&resp.Diagnostics, "Create windows_disk failed", err)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, diskModelFromInfo(info, plan, plan.Timeouts))...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live host by UniqueId (the
// resource ID). A vanished disk removes the resource from state; selector
// spellings recorded at adoption are preserved verbatim.
func (r *windowsDiskResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsDiskModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	readTimeout, diags := state.Timeouts.Read(ctx, diskDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	id := state.ID.ValueString()
	if id == "" {
		id = state.UniqueID.ValueString()
	}
	tflog.Debug(ctx, "windows_disk Read", map[string]interface{}{"id": id})

	info, err := r.disks.Read(ctx, winclient.DiskSelectorByUniqueID(id))
	if err != nil {
		addDiskDiag(&resp.Diagnostics, "Read windows_disk failed", err)
		return
	}
	if info == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, diskModelFromInfo(info, state, state.Timeouts))...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update enforces the mutable flags in place. Selectors and partition_style
// force replacement via RequiresReplace, so Update only ever sees
// is_offline / is_read_only changes (plus timeouts block edits).
func (r *windowsDiskResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsDiskModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	updateTimeout, diags := plan.Timeouts.Update(ctx, diskDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	id := prior.ID.ValueString()
	if id == "" {
		id = prior.UniqueID.ValueString()
	}
	tflog.Debug(ctx, "windows_disk Update", map[string]interface{}{"id": id})

	info, err := r.disks.Read(ctx, winclient.DiskSelectorByUniqueID(id))
	if err != nil {
		addDiskDiag(&resp.Diagnostics, "Update windows_disk failed", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Disk not found",
			fmt.Sprintf("No disk with UniqueId %q was found on the target host; it may have been removed out of band.", id),
		)
		return
	}

	info, err = r.ensureDiskFlags(ctx, info, plan.PartitionStyle, plan.IsOffline, plan.IsReadOnly)
	if err != nil {
		addDiskDiag(&resp.Diagnostics, "Update windows_disk failed", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, diskModelFromInfo(info, prior, plan.Timeouts))...)
}

// ---------------------------------------------------------------------------
// Delete (state-only)
// ---------------------------------------------------------------------------

// Delete drops the adoption from state and makes no remote call: disks are
// hardware Terraform neither creates nor destroys, so there is nothing to
// tear down on the host. The disk and its data are left exactly as they are.
// Because no remote call is made, the timeouts.delete value (kept for schema
// consistency, see diskTimeoutsOpts) is not consumed: deletion is immediate
// and unbounded.
func (r *windowsDiskResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsDiskModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "windows_disk Delete: dropping the adoption from state only; the disk is left untouched",
		map[string]interface{}{"id": state.ID.ValueString()})
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing disk by its UniqueId.
func (r *windowsDiskResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import ID must be the disk UniqueId (e.g. Get-Disk UniqueId); got %q.", req.ID))
		return
	}
	tflog.Debug(ctx, "Importing windows_disk", map[string]interface{}{"unique_id": id})

	// No prior state exists at import time, so a configured timeouts block
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, diskDefaultTimeout)
	defer cancel()

	info, err := r.disks.Read(ctx, winclient.DiskSelectorByUniqueID(id))
	if err != nil {
		addDiskDiag(&resp.Diagnostics, "Error importing windows_disk", err)
		return
	}
	if info == nil {
		resp.Diagnostics.AddError(
			"Disk not found",
			fmt.Sprintf("No disk with UniqueId %q was found on the target host.", id),
		)
		return
	}

	plan := windowsDiskModel{
		UniqueID:     types.StringValue(info.UniqueID),
		SerialNumber: diskStringOrNull(info.SerialNumber),
		Location:     diskStringOrNull(info.Location),
		Number:       types.Int64Value(int64(info.Number)),
		Timeouts:     diskNullTimeouts(),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, diskModelFromInfo(info, plan, plan.Timeouts))...)
}

// diskStringOrNull maps an empty observed string to null so unknown
// host-side spellings (e.g. a virtual disk without serial) do not pin an
// empty string into a ForceNew selector.
func diskStringOrNull(s string) types.String {
	if strings.TrimSpace(s) == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}
