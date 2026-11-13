// Package provider - resource_windows_eventlog implements the full
// Terraform resource lifecycle for windows_eventlog.
//
// An event log (classic logs such as Application, System and Security, and
// modern channels such as Microsoft-Windows-PowerShell/Operational) always
// exists — Windows creates it with the OS or the owning feature. Create and
// Update are therefore the same operation (assign the configured properties
// on the .NET EventLogConfiguration object, then SaveChanges); only the
// attributes configured in Terraform are written. Delete makes no remote
// change by default; with restore_on_destroy it re-applies the pre-existing
// values captured into private state at Create (or import) time.
//
// Limit-EventLog is deliberately not used: it only handles classic logs,
// and its retention parameters have had no effect since Vista.
//
// Spec alignment: windows_eventlog spec (issue #289).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

var (
	_ resource.Resource                     = (*windowsEventLogResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsEventLogResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsEventLogResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsEventLogResource)(nil)
)

// NewWindowsEventLogResource is the constructor registered in provider.go.
func NewWindowsEventLogResource() resource.Resource {
	return &windowsEventLogResource{}
}

// windowsEventLogResource is the TPF resource type for windows_eventlog.
type windowsEventLogResource struct {
	el winclient.WindowsEventLogClient
}

// eventLogDefaultTimeout is the fallback per-operation timeout when the user
// does not provide a `timeouts {}` block. Event log reads and writes are
// normally fast, but a stalled PowerShell/SSH session must never block
// Terraform forever: every CRUD handler bounds its work with this default.
const eventLogDefaultTimeout = 5 * time.Minute

// eventLogPrivateKey is the private-state key holding the JSON-encoded
// pre-existing log state captured at Create (or import) time. Delete with
// restore_on_destroy re-applies it verbatim.
const eventLogPrivateKey = "original_state"

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsEventLogModel is the Terraform state/plan model for
// windows_eventlog. Every tfsdk tag matches an attribute key in
// windowsEventLogSchemaDefinition.
type windowsEventLogModel struct {
	ID               types.String   `tfsdk:"id"`
	Name             types.String   `tfsdk:"name"`
	MaximumSizeBytes types.Int64    `tfsdk:"maximum_size_bytes"`
	Retention        types.String   `tfsdk:"retention"`
	Enabled          types.Bool     `tfsdk:"enabled"`
	LogFilePath      types.String   `tfsdk:"log_file_path"`
	RestoreOnDestroy types.Bool     `tfsdk:"restore_on_destroy"`
	LogType          types.String   `tfsdk:"log_type"`
	IsClassicLog     types.Bool     `tfsdk:"is_classic_log"`
	RecordCount      types.Int64    `tfsdk:"record_count"`
	FileSizeBytes    types.Int64    `tfsdk:"file_size_bytes"`
	PolicyOverride   types.Bool     `tfsdk:"policy_override"`
	Timeouts         timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsEventLogResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_eventlog"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// Schema returns the complete TPF schema for the windows_eventlog resource.
func (r *windowsEventLogResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsEventLogSchemaDefinition(ctx)
}

// windowsEventLogSchemaDefinition returns the complete TPF schema for
// windows_eventlog. `name` is Required + ForceNew (the id); every other
// setting is Optional+Computed (partial management: only configured
// attributes are assigned before SaveChanges).
func windowsEventLogSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the size and retention policy of an existing Windows event log " +
			"on a remote Windows host via SSH and PowerShell (the .NET `EventLogConfiguration` API: " +
			"`Get-WinEvent -ListLog` plus `SaveChanges()`). A log always exists — Windows or the owning " +
			"feature creates it — so creating this resource never provisions anything new: it only tunes " +
			"the log's settings in place, and deleting it makes no remote change unless `restore_on_destroy` " +
			"is set.\n\n" +
			"Both classic logs (`Application`, `System`, `Security`) and modern channels " +
			"(`Microsoft-Windows-PowerShell/Operational`, matched literally — the `/` is part of the name, " +
			"never a path) are supported. Only the attributes configured in Terraform are written; every " +
			"other setting on the host is left untouched and undiffed. `record_count` and `file_size_bytes` " +
			"are observed informational values and never produce drift.\n\n" +
			"Group Policy owns the `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog` view: when a GPO " +
			"manages a log, the observed values can diverge from what Terraform writes at the next policy " +
			"refresh, which is reported through `policy_override` with a warning on every apply.\n\n" +
			"Shrinking `maximum_size_bytes` below the current file size is accepted by Windows (it applies " +
			"after the next clear or archive): the apply warns instead of failing.\n\n" +
			"Import format: `<log name>` (exact, e.g. `Application` or " +
			"`Microsoft-Windows-PowerShell/Operational`).",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier. Set to the exact event log name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"name": schema.StringAttribute{
				Required: true,
				Description: "Exact event log name (`LogName`), matched literally (never as a wildcard). " +
					"Classic logs (`Application`, `System`, `Security`) and modern channels " +
					"(`Microsoft-Windows-PowerShell/Operational`, where `/` is part of the name) are both valid. " +
					"Immutable after creation (ForceNew); the log always exists on the host.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},

			"maximum_size_bytes": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Maximum size of the event log file, in bytes. Must be a multiple of 64 KiB and at least 1 MiB. Sizes above 4 GiB warn on classic logs.",
				Validators: []validator.Int64{
					eventLogSizeValidator{},
				},
			},

			"retention": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "What happens when the log reaches its maximum size. One of `overwrite` (oldest events are overwritten, `Circular`), `archive` (the full log is archived and a new one started, `AutoBackup`), `retain` (stop logging when full, `Retain`; plan warns on the `Security` log because the host can halt when `CrashOnAuditFail` is set).",
				Validators: []validator.String{
					stringvalidator.OneOf("overwrite", "archive", "retain"),
				},
			},

			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the log is enabled (`IsEnabled`). Classic logs cannot be disabled: setting `false` on one fails with an `unsupported` error. Disabling an Analytic or Debug channel clears it.",
			},

			"log_file_path": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Path of the event log file (`LogFilePath`). Absolute or `%SystemRoot%`-based; the directory must exist on the host (validated host-side).",
			},

			"restore_on_destroy": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "When `true`, destroy re-applies the pre-existing log values captured at creation (or import) time. Defaults to `false`: destroy makes no remote change.",
			},

			"log_type": schema.StringAttribute{
				Computed:    true,
				Description: "Log type as reported by the host (`Administrative`, `Operational`, `Analytic` or `Debug`).",
			},

			"is_classic_log": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the log is a classic log (`Application`, `System`, `Security`, ...). Classic logs cannot be disabled.",
			},

			"record_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of records currently in the log. Informational only: never produces drift.",
			},

			"file_size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Current size of the log file on disk, in bytes. Informational only: never produces drift.",
			},

			"policy_override": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether Group Policy carries `MaxSize`, `Retention` or `AutoBackupLogFiles` for this log (`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\<log>`). When `true`, the GPO value wins at the next policy refresh and Terraform-managed values may diverge.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to
			// eventLogDefaultTimeout so a stalled or severed remote
			// command surfaces a timeout diagnostic instead of blocking
			// Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, eventLogTimeoutsOpts),
		},
	}
}

// ---------------------------------------------------------------------------
// ConfigValidators
// ---------------------------------------------------------------------------

// ConfigValidators returns the resource-level cross-field validators:
//   - eventLogRetentionValidator: warns when retention = retain on Security.
func (r *windowsEventLogResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		eventLogRetentionValidator{},
	}
}

// eventLogRetentionValidator warns (never errors) when retention = retain is
// combined with the Security log: with CrashOnAuditFail the host can halt
// when the log fills instead of merely stopping logging.
type eventLogRetentionValidator struct{}

func (v eventLogRetentionValidator) Description(_ context.Context) string {
	return "Warns when retention is retain on the Security log."
}

func (v eventLogRetentionValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v eventLogRetentionValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var name types.String
	diags := req.Config.GetAttribute(ctx, path.Root("name"), &name)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var retention types.String
	diags = req.Config.GetAttribute(ctx, path.Root("retention"), &retention)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if name.IsNull() || name.IsUnknown() || retention.IsNull() || retention.IsUnknown() {
		return
	}
	if retention.ValueString() != "retain" {
		return
	}
	if !strings.EqualFold(name.ValueString(), "Security") {
		return
	}
	resp.Diagnostics.AddAttributeWarning(
		path.Root("retention"),
		"Retain policy on the Security log",
		"retention = \"retain\" on the Security log stops logging when the log is full. When the "+
			"host's CrashOnAuditFail setting is enabled, a full Security log halts the system instead. "+
			"Prefer overwrite or archive unless retention is mandated.",
	)
}

// eventLogSizeValidator enforces the host granularity at plan time: at
// least 1 MiB and a multiple of 64 KiB.
type eventLogSizeValidator struct{}

func (v eventLogSizeValidator) Description(_ context.Context) string {
	return "Maximum size must be at least 1 MiB and a multiple of 64 KiB."
}

func (v eventLogSizeValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v eventLogSizeValidator) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	size := req.ConfigValue.ValueInt64()
	if size < winclient.EventLogMinSizeBytes {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid maximum_size_bytes",
			fmt.Sprintf("maximum_size_bytes must be at least %d (1 MiB); got %d.",
				winclient.EventLogMinSizeBytes, size),
		)
		return
	}
	if size%winclient.EventLogSizeMultipleBytes != 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid maximum_size_bytes",
			fmt.Sprintf("maximum_size_bytes must be a multiple of %d (64 KiB); got %d.",
				winclient.EventLogSizeMultipleBytes, size),
		)
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

// Configure stores the provider-level SSH client and creates an
// EventLogClient for this resource instance.
func (r *windowsEventLogResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T.", req.ProviderData),
		)
		return
	}
	r.el = winclient.NewEventLogClient(client)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create tunes the (always pre-existing) event log in place and saves the
// full state. When restore_on_destroy is set, the pre-existing values are
// captured into private state first so Delete can re-apply them.
func (r *windowsEventLogResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsEventLogModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, eventLogDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	name := plan.Name.ValueString()

	if plan.RestoreOnDestroy.ValueBool() {
		pre, err := r.el.Read(ctx, name)
		if err != nil {
			addEventLogDiag(&resp.Diagnostics, "Error reading pre-existing Windows event log", err)
			return
		}
		if pre == nil {
			resp.Diagnostics.AddError(
				"Event log not found",
				fmt.Sprintf("Event log %q does not exist on the target host.", name),
			)
			return
		}
		if err := setEventLogSnapshot(ctx, resp.Private.SetKey, pre); err != nil {
			addEventLogDiag(&resp.Diagnostics, "Error capturing pre-existing Windows event log", err)
			return
		}
	}

	settings, diags := modelToEventLogSettings(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating Windows event log (tuning in place)", map[string]any{
		"name": name,
	})

	state, err := r.el.Apply(ctx, name, settings)
	if err != nil {
		addEventLogDiag(&resp.Diagnostics, "Error creating Windows event log", err)
		return
	}

	addEventLogStateWarnings(&resp.Diagnostics, plan, state)

	m := eventLogStateToModel(state)
	// Preserve the user-configured per-operation timeouts and the
	// restore_on_destroy intent: the projection covers only host-observed
	// fields, and Set overwrites the full state.
	m.Timeouts = plan.Timeouts
	m.RestoreOnDestroy = plan.RestoreOnDestroy
	m.Name = plan.Name
	m.ID = types.StringValue(name)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read refreshes Terraform state from the live Windows event log. A log
// removed out-of-band (for example a feature log whose role was
// uninstalled) drops the resource from state.
func (r *windowsEventLogResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsEventLogModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, eventLogDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	name := state.Name.ValueString()

	tflog.Debug(ctx, "Reading Windows event log", map[string]any{
		"name": name,
	})

	elState, err := r.el.Read(ctx, name)
	if err != nil {
		var ee *winclient.EventLogError
		if errors.As(err, &ee) && ee.Kind == winclient.EventLogErrorNotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		addEventLogDiag(&resp.Diagnostics, "Error reading Windows event log", err)
		return
	}

	if elState == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	m := eventLogStateToModel(elState)
	m.Timeouts = state.Timeouts
	m.RestoreOnDestroy = state.RestoreOnDestroy
	m.Name = state.Name
	m.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place attribute changes to the event log. Like Create
// it writes only the configured attributes; the restore snapshot captured
// at Create time is left untouched (restore always returns to the
// pre-existing values, not to the previous plan).
func (r *windowsEventLogResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsEventLogModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsEventLogModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, eventLogDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// name is ForceNew so it never changes here.
	name := plan.Name.ValueString()

	settings, diags := modelToEventLogSettings(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating Windows event log", map[string]any{
		"name": name,
	})

	elState, err := r.el.Apply(ctx, name, settings)
	if err != nil {
		addEventLogDiag(&resp.Diagnostics, "Error updating Windows event log", err)
		return
	}

	addEventLogStateWarnings(&resp.Diagnostics, plan, elState)

	m := eventLogStateToModel(elState)
	m.Timeouts = plan.Timeouts
	m.RestoreOnDestroy = plan.RestoreOnDestroy
	m.Name = plan.Name
	m.ID = prior.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the resource from state. By default it makes no remote
// change (logs always exist and are owned by Windows or the owning
// feature). With restore_on_destroy it re-applies the snapshot captured at
// Create (or import) time; when no snapshot exists it warns and leaves the
// host untouched rather than guessing.
func (r *windowsEventLogResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsEventLogModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, eventLogDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	name := state.Name.ValueString()

	tflog.Debug(ctx, "Deleting Windows event log", map[string]any{
		"name":               name,
		"restore_on_destroy": state.RestoreOnDestroy.ValueBool(),
	})

	if !state.RestoreOnDestroy.ValueBool() {
		return
	}

	snap, ok := getEventLogSnapshot(ctx, req.Private.GetKey)
	if !ok {
		resp.Diagnostics.AddWarning(
			"Event log restore skipped: no snapshot",
			fmt.Sprintf("restore_on_destroy is set, but the pre-existing snapshot of log %q could not be read "+
				"(it may be corrupt or from an incompatible version). Leaving the host untouched.", name),
		)
		return
	}
	if snap == nil {
		resp.Diagnostics.AddWarning(
			"Event log restore skipped: no snapshot",
			fmt.Sprintf("restore_on_destroy is set, but no pre-existing snapshot of log %q was captured "+
				"(the resource may predate snapshotting or the snapshot was lost). Leaving the host untouched.", name),
		)
		return
	}

	if restored, err := r.el.Restore(ctx, *snap); err != nil {
		addEventLogDiag(&resp.Diagnostics, "Error restoring Windows event log", err)
	} else if restored != nil {
		addEventLogStateWarnings(&resp.Diagnostics, windowsEventLogModel{}, restored)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing event log by exact name. The observed
// values become the snapshot for a later restore_on_destroy.
func (r *windowsEventLogResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if name == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			"Import ID must be the exact event log name (e.g. Application or "+
				"Microsoft-Windows-PowerShell/Operational).",
		)
		return
	}

	tflog.Debug(ctx, "Importing Windows event log", map[string]any{
		"name": name,
	})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, eventLogDefaultTimeout)
	defer cancel()

	elState, err := r.el.Read(ctx, name)
	if err != nil {
		addEventLogDiag(&resp.Diagnostics, "Error importing Windows event log", err)
		return
	}
	if elState == nil {
		resp.Diagnostics.AddError(
			"Event log not found",
			fmt.Sprintf("Event log %q does not exist on the target host.", name),
		)
		return
	}

	if err := setEventLogSnapshot(ctx, resp.Private.SetKey, elState); err != nil {
		addEventLogDiag(&resp.Diagnostics, "Error capturing pre-existing Windows event log", err)
		return
	}

	m := eventLogStateToModel(elState)
	// Import starts from no prior state, so there are no user-configured
	// timeouts to preserve. The zero timeouts.Value carries no attribute
	// types and is rejected by State.Set — use a typed null instead (the
	// subsequent Read fills in the configured values).
	m.Timeouts = eventLogNullTimeouts()
	m.RestoreOnDestroy = types.BoolValue(false)
	m.Name = types.StringValue(elState.Name)
	m.ID = types.StringValue(elState.Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// ---------------------------------------------------------------------------
// Helper: modelToEventLogSettings
// ---------------------------------------------------------------------------

// modelToEventLogSettings converts a Terraform model to an
// EventLogSettings delta: null (or unknown) attributes stay nil and are
// never assigned before SaveChanges. An unknown attribute aborts with a
// diagnostic so the run defers instead of converging on a guess.
func modelToEventLogSettings(_ context.Context, m windowsEventLogModel) (winclient.EventLogSettings, diag.Diagnostics) {
	var diags diag.Diagnostics
	var s winclient.EventLogSettings

	if m.MaximumSizeBytes.IsUnknown() || m.Retention.IsUnknown() ||
		m.Enabled.IsUnknown() || m.LogFilePath.IsUnknown() {
		diags.AddError(
			"Unknown Windows event log setting",
			"One or more event log settings are unknown. Retry the apply once the referenced values are known instead of converging the log on a guess.",
		)
		return winclient.EventLogSettings{}, diags
	}

	if !m.MaximumSizeBytes.IsNull() {
		v := m.MaximumSizeBytes.ValueInt64()
		s.MaximumSizeBytes = &v
	}
	if !m.Retention.IsNull() {
		v := m.Retention.ValueString()
		// Only the three schema-known spellings are managed. The state
		// projection passes an unknown future host LogMode through
		// verbatim (Computed), so a value outside overwrite/archive/retain
		// must have been observed, not configured — the plan OneOf
		// validator guarantees user config is known. Leaving it unmanaged
		// keeps the next Update from failing closed in
		// EventLogRetentionToLogMode on a value the user never set.
		switch v {
		case "overwrite", "archive", "retain":
			s.Retention = &v
		}
	}
	if !m.Enabled.IsNull() {
		v := m.Enabled.ValueBool()
		s.Enabled = &v
	}
	if !m.LogFilePath.IsNull() {
		v := m.LogFilePath.ValueString()
		s.LogFilePath = &v
	}

	return s, diags
}

// ---------------------------------------------------------------------------
// Helper: eventLogStateToModel
// ---------------------------------------------------------------------------

// eventLogTimeoutsOpts declares which per-operation timeouts the resource exposes.
var eventLogTimeoutsOpts = timeouts.Opts{
	Create: true,
	Read:   true,
	Update: true,
	Delete: true,
}

// eventLogNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func eventLogNullTimeouts() timeouts.Value {
	attrTypes := map[string]attr.Type{}
	if eventLogTimeoutsOpts.Create {
		attrTypes["create"] = types.StringType
	}
	if eventLogTimeoutsOpts.Read {
		attrTypes["read"] = types.StringType
	}
	if eventLogTimeoutsOpts.Update {
		attrTypes["update"] = types.StringType
	}
	if eventLogTimeoutsOpts.Delete {
		attrTypes["delete"] = types.StringType
	}
	return timeouts.Value{Object: types.ObjectNull(attrTypes)}
}

// eventLogStateToModel projects an observed EventLogState into a Terraform
// model. Every managed attribute reflects the observed value (the plan was
// unknown for unconfigured Computed attributes), while record_count and
// file_size_bytes are informational and never diffed.
func eventLogStateToModel(s *winclient.EventLogState) windowsEventLogModel {
	return windowsEventLogModel{
		ID:               types.StringValue(s.Name),
		Name:             types.StringValue(s.Name),
		MaximumSizeBytes: types.Int64Value(s.MaximumSizeBytes),
		Retention:        types.StringValue(winclient.EventLogLogModeToRetention(s.LogMode)),
		Enabled:          types.BoolValue(s.IsEnabled),
		LogFilePath:      types.StringValue(s.LogFilePath),
		LogType:          types.StringValue(s.LogType),
		IsClassicLog:     types.BoolValue(s.IsClassic),
		RecordCount:      types.Int64Value(s.RecordCount),
		FileSizeBytes:    types.Int64Value(s.FileSizeBytes),
		PolicyOverride:   types.BoolValue(s.PolicyOverride),
	}
}

// ---------------------------------------------------------------------------
// Helper: state warnings
// ---------------------------------------------------------------------------

// addEventLogStateWarnings surfaces advisory (never blocking) diagnostics
// after a successful apply:
//
//   - Shrinking maximum_size_bytes below the current file size is accepted
//     by Windows but only applies after the next clear or archive.
//   - Sizes above 4 GiB on classic logs are accepted but unusual.
//   - A Group Policy override means the GPO value wins at the next policy
//     refresh and Terraform-managed values may diverge.
func addEventLogStateWarnings(d *diag.Diagnostics, plan windowsEventLogModel, observed *winclient.EventLogState) {
	if !plan.MaximumSizeBytes.IsNull() && !plan.MaximumSizeBytes.IsUnknown() {
		want := plan.MaximumSizeBytes.ValueInt64()
		if want < observed.FileSizeBytes {
			d.AddWarning(
				"Shrinking event log below its current file size",
				fmt.Sprintf("maximum_size_bytes %d is smaller than the current log file size %d on %q. "+
					"Windows accepts the new maximum but it only applies after the next clear or archive of the log.",
					want, observed.FileSizeBytes, observed.Name),
			)
		}
		if observed.IsClassic && want > winclient.EventLogClassicWarnSizeBytes {
			d.AddWarning(
				"Large maximum size on a classic event log",
				fmt.Sprintf("maximum_size_bytes %d exceeds 4 GiB on classic log %q. "+
					"Windows accepts the size, but classic logs were not designed for very large files.",
					want, observed.Name),
			)
		}
	}
	if observed.PolicyOverride {
		d.AddWarning(
			"Group Policy manages this event log",
			fmt.Sprintf("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\%s carries MaxSize, Retention "+
				"or AutoBackupLogFiles for log %q. The Group Policy value wins at the next policy refresh, "+
				"which can undo the Terraform-managed settings.", observed.Name, observed.Name),
		)
	}
}

// ---------------------------------------------------------------------------
// Helper: private-state snapshot
// ---------------------------------------------------------------------------

// setEventLogSnapshot stores the pre-existing log state as JSON in private
// state so Delete with restore_on_destroy can re-apply it. setKey is a
// closure over the response Private data (kept injectable so unit tests can
// capture the snapshot without framework internals).
func setEventLogSnapshot(ctx context.Context, setKey func(context.Context, string, []byte) diag.Diagnostics, st *winclient.EventLogState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	diags := setKey(ctx, eventLogPrivateKey, raw)
	if diags.HasError() {
		return errors.New(diagsToString(diags))
	}
	return nil
}

// getEventLogSnapshot reads the snapshot back. A nil snapshot with a true
// return means "no snapshot captured". getKey is a closure over the request
// Private data.
func getEventLogSnapshot(ctx context.Context, getKey func(context.Context, string) ([]byte, diag.Diagnostics)) (*winclient.EventLogState, bool) {
	raw, diags := getKey(ctx, eventLogPrivateKey)
	if diags.HasError() {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, true
	}
	var st winclient.EventLogState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, false
	}
	return &st, true
}

// ---------------------------------------------------------------------------
// Helper: addEventLogDiag
// ---------------------------------------------------------------------------

// addEventLogDiag appends a diagnostic from an event-log client error,
// enriching it with context fields when available.
func addEventLogDiag(d *diag.Diagnostics, summary string, err error) {
	var ee *winclient.EventLogError
	if errors.As(err, &ee) {
		detail := ee.Message
		if len(ee.Context) > 0 {
			var parts []string
			for k, v := range ee.Context {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		if ee.Cause != nil {
			detail += "\n\nCause: " + ee.Cause.Error()
		}
		d.AddError(summary+" ["+string(ee.Kind)+"]", detail)
		return
	}
	d.AddError(summary, err.Error())
}
