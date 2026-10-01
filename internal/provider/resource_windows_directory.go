// Package provider: windows_directory resource implementation.
//
// Manages the presence, attributes and absence of a directory on a remote
// Windows host over SSH + PowerShell. Content of the directory (files,
// sub-directories) is never managed here; only the directory entry itself.
//
// Spec alignment: windows_directory spec v1 (2026-10-01).
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsDirectoryResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsDirectoryResource)(nil)
	_ resource.ResourceWithImportState = (*windowsDirectoryResource)(nil)
)

// NewWindowsDirectoryResource is the constructor registered in provider.go.
func NewWindowsDirectoryResource() resource.Resource {
	return &windowsDirectoryResource{}
}

// windowsDirectoryResource is the TPF resource type for windows_directory.
type windowsDirectoryResource struct {
	client winclient.DirectoryClient
}

// windowsDirectoryModel is the Terraform plan/state model for windows_directory.
type windowsDirectoryModel struct {
	ID                      types.String `tfsdk:"id"`
	Path                    types.String `tfsdk:"path"`
	Ensure                  types.String `tfsdk:"ensure"`
	RecursiveDelete         types.Bool   `tfsdk:"recursive_delete"`
	CreateParentDirectories types.Bool   `tfsdk:"create_parent_directories"`
	Attributes              types.List   `tfsdk:"attributes"`

	ExistsChildren types.Bool   `tfsdk:"exists_children"`
	ItemCount      types.Int64  `tfsdk:"item_count"`
	LastWriteTime  types.String `tfsdk:"last_write_time"`
}

// Ensure values for the `ensure` attribute.
const (
	directoryEnsurePresent = "present"
	directoryEnsureAbsent  = "absent"
)

// windowsDirectoryPathRegex accepts a drive-letter path or a UNC path with at
// least one path segment beyond the root, and rejects the characters Windows
// forbids in a path (EC-8). A bare drive root (e.g. "C:\") is rejected
// (EC-10): recreating/deleting a drive root does not make sense for this
// resource.
var windowsDirectoryPathRegex = regexp.MustCompile(`^([A-Za-z]:\\|\\\\[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+\\)[^<>:"|?*\x00]+$`)

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *windowsDirectoryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_directory"
}

func (r *windowsDirectoryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsDirectorySchemaDefinition()
}

func windowsDirectorySchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a directory on a remote Windows host over SSH + PowerShell: presence, " +
			"NTFS attributes, and absence.\n\n" +
			"Content of the directory (files, sub-directories) is never managed here; this resource owns only " +
			"the directory entry itself. Ownership and ACLs are intentionally **not** managed here either: use " +
			"`windows_file_acl`, which already accepts a directory target.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Normalised absolute path of the directory. Identical to the import ID format.",
			},
			"path": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(windowsDirectoryPathRegex,
						`must be an absolute Windows path (C:\\dir\\subdir) or a UNC path (\\\\server\\share\\dir), and not a bare drive root`),
				},
				Description: "Absolute path of the directory on the target host. ForceNew.",
			},
			"ensure": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(directoryEnsurePresent),
				Validators: []validator.String{
					stringvalidator.OneOf(directoryEnsurePresent, directoryEnsureAbsent),
				},
				Description: "Whether the directory should be \"present\" (default) or \"absent\".",
			},
			"recursive_delete": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "When true, deleting the resource removes the directory's content as well " +
					"(`Remove-Item -Recurse`). When false (default), deleting a non-empty directory fails " +
					"explicitly rather than silently discarding files not managed by Terraform.",
			},
			"create_parent_directories": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Create missing parent directories. They are never removed on destroy.",
			},
			"attributes": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Directory attributes to enforce: hidden, readonly, system.",
			},

			"exists_children": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the directory directly contains at least one file or sub-directory.",
			},
			"item_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of items (files and sub-directories) directly contained in the directory (non-recursive).",
			},
			"last_write_time": schema.StringAttribute{
				Computed:    true,
				Description: "Last write timestamp of the directory, ISO 8601 UTC.",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *windowsDirectoryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			"Expected *winclient.Client for windows_directory resource configuration.")
		return
	}
	r.client = winclient.NewDirectoryClient(c)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// addDirectoryDiag appends a diagnostic from a DirectoryClient error.
func addDirectoryDiag(diags *diag.Diagnostics, op string, err error) {
	var de *winclient.DirectoryError
	if errors.As(err, &de) {
		switch de.Kind {
		case winclient.DirectoryErrorPermission:
			diags.AddError(
				fmt.Sprintf("Permission denied during %s", op),
				fmt.Sprintf("%s. Ensure the SSH credentials have sufficient NTFS permissions on the target directory.", de.Message),
			)
		case winclient.DirectoryErrorTypeConflict:
			diags.AddError(
				fmt.Sprintf("Path conflict during %s", op),
				de.Message,
			)
		case winclient.DirectoryErrorNotEmpty:
			diags.AddError(
				fmt.Sprintf("Directory not empty during %s", op),
				de.Message+" Set recursive_delete=true to delete its content as well.",
			)
		case winclient.DirectoryErrorInvalidInput:
			diags.AddError(
				fmt.Sprintf("Invalid input during %s", op),
				de.Message,
			)
		case winclient.DirectoryErrorNotFound:
			diags.AddError(
				fmt.Sprintf("Directory not found during %s", op),
				de.Message,
			)
		default:
			diags.AddError(
				fmt.Sprintf("Error during windows_directory %s", op),
				de.Message,
			)
		}
		return
	}
	diags.AddError(
		fmt.Sprintf("Error during windows_directory %s", op),
		err.Error(),
	)
}

// directoryAttributesFromModel extracts the string slice behind a
// types.List attribute. A null/unknown list yields an empty slice.
func directoryAttributesFromModel(ctx context.Context, l types.List, diags *diag.Diagnostics) []string {
	var attrs []string
	if l.IsNull() || l.IsUnknown() {
		return attrs
	}
	diags.Append(l.ElementsAs(ctx, &attrs, false)...)
	return attrs
}

// applyDirectoryState folds the observed host state into the model.
func applyDirectoryState(m *windowsDirectoryModel, ds *winclient.DirectoryState, diags *diag.Diagnostics) {
	m.ID = types.StringValue(ds.Path)
	m.ExistsChildren = types.BoolValue(ds.ExistsChildren)
	m.ItemCount = types.Int64Value(ds.ItemCount)
	m.LastWriteTime = types.StringValue(ds.LastWriteTime)

	attrs := ds.Attributes
	if attrs == nil {
		attrs = []string{}
	}
	elems := make([]attr.Value, len(attrs))
	for i, a := range attrs {
		elems[i] = types.StringValue(a)
	}
	list, d := types.ListValue(types.StringType, elems)
	diags.Append(d...)
	if !d.HasError() {
		m.Attributes = list
	}
}

// ---------------------------------------------------------------------------
// CRUD handlers
// ---------------------------------------------------------------------------

// Create ensures the directory exists with the declared attributes.
//
// Idempotent on an already-present directory (EC-9): a pre-existing directory
// is adopted rather than rejected, unlike windows_file.
func (r *windowsDirectoryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsDirectoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Ensure.ValueString() == directoryEnsureAbsent {
		// Nothing to create; a subsequent Read/Delete cycle will converge.
		plan.ID = types.StringValue(plan.Path.ValueString())
		plan.ExistsChildren = types.BoolValue(false)
		plan.ItemCount = types.Int64Value(0)
		plan.LastWriteTime = types.StringValue("")
		plan.Attributes = types.ListNull(types.StringType)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	attrs := directoryAttributesFromModel(ctx, plan.Attributes, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	input := winclient.DirectoryInput{
		Path:          plan.Path.ValueString(),
		CreateParents: plan.CreateParentDirectories.ValueBool(),
		Attributes:    attrs,
	}

	tflog.Debug(ctx, "windows_directory Create", map[string]interface{}{"path": input.Path})

	ds, err := r.client.Create(ctx, input)
	if err != nil {
		addDirectoryDiag(&resp.Diagnostics, "Create", err)
		return
	}

	applyDirectoryState(&plan, ds, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes Terraform state from the actual Windows directory.
//
// Returns (nil, nil) from the client when the directory is absent (EC-1);
// calls resp.State.RemoveResource() to signal drift.
func (r *windowsDirectoryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsDirectoryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := state.Path.ValueString()
	if path == "" {
		path = state.ID.ValueString()
	}

	tflog.Debug(ctx, "windows_directory Read", map[string]interface{}{"path": path})

	ds, err := r.client.Read(ctx, path)
	if err != nil {
		addDirectoryDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if ds == nil {
		if state.Ensure.ValueString() == directoryEnsureAbsent {
			// Converged: absent in config, absent on the host.
			return
		}
		resp.State.RemoveResource(ctx)
		return
	}

	applyDirectoryState(&state, ds, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies in-place changes to ensure/attributes.
//
// path is ForceNew so it cannot change here. ensure flips between
// present/absent by calling Create/Delete respectively; attributes are
// applied via DirectoryClient.Update.
func (r *windowsDirectoryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsDirectoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := plan.Path.ValueString()

	if plan.Ensure.ValueString() == directoryEnsureAbsent {
		tflog.Debug(ctx, "windows_directory Update (ensure=absent)", map[string]interface{}{"path": path})
		if err := r.client.Delete(ctx, path, plan.RecursiveDelete.ValueBool()); err != nil {
			addDirectoryDiag(&resp.Diagnostics, "Update", err)
			return
		}
		plan.ID = types.StringValue(path)
		plan.ExistsChildren = types.BoolValue(false)
		plan.ItemCount = types.Int64Value(0)
		plan.LastWriteTime = types.StringValue("")
		plan.Attributes = types.ListNull(types.StringType)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	attrs := directoryAttributesFromModel(ctx, plan.Attributes, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_directory Update", map[string]interface{}{"path": path})

	ds, err := r.client.Update(ctx, path, attrs)
	if err != nil {
		if winclient.IsDirectoryError(err, winclient.DirectoryErrorNotFound) {
			// The directory vanished out-of-band; (re)create it to converge.
			created, cerr := r.client.Create(ctx, winclient.DirectoryInput{
				Path:          path,
				CreateParents: plan.CreateParentDirectories.ValueBool(),
				Attributes:    attrs,
			})
			if cerr != nil {
				addDirectoryDiag(&resp.Diagnostics, "Update", cerr)
				return
			}
			ds = created
		} else {
			addDirectoryDiag(&resp.Diagnostics, "Update", err)
			return
		}
	}

	applyDirectoryState(&plan, ds, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete removes the Windows directory.
//
// Idempotent via the client: a missing directory is a silent no-op (EC-5).
func (r *windowsDirectoryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsDirectoryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := state.Path.ValueString()
	if path == "" {
		path = state.ID.ValueString()
	}

	tflog.Debug(ctx, "windows_directory Delete", map[string]interface{}{"path": path})

	if err := r.client.Delete(ctx, path, state.RecursiveDelete.ValueBool()); err != nil {
		addDirectoryDiag(&resp.Diagnostics, "Delete", err)
	}
}

// ImportState imports a directory by its absolute Windows path.
//
// ID format: the absolute path itself (e.g. "C:\ProgramData\app\logs").
// recursive_delete and create_parent_directories fall back to their schema
// defaults, since neither is observable on the host (EC-7).
func (r *windowsDirectoryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	path := req.ID
	if path == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import ID must be the absolute Windows path of the directory.")
		return
	}

	tflog.Debug(ctx, "windows_directory ImportState", map[string]interface{}{"path": path})

	ds, err := r.client.Read(ctx, path)
	if err != nil {
		addDirectoryDiag(&resp.Diagnostics, "ImportState", err)
		return
	}
	if ds == nil {
		resp.Diagnostics.AddError(
			"Import failed: directory not found",
			fmt.Sprintf("Directory %q does not exist on the target host. Verify the path, or use config+apply to create it.", path),
		)
		return
	}

	model := windowsDirectoryModel{
		Path:                    types.StringValue(path),
		Ensure:                  types.StringValue(directoryEnsurePresent),
		RecursiveDelete:         types.BoolValue(false),
		CreateParentDirectories: types.BoolValue(true),
	}
	applyDirectoryState(&model, ds, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
