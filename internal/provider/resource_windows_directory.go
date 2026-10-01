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
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

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
// CRUD handlers — STUBS (filled in by provider-coder)
// ---------------------------------------------------------------------------

func (r *windowsDirectoryResource) Create(_ context.Context, _ resource.CreateRequest, resp *resource.CreateResponse) {
	resp.Diagnostics.AddError("not implemented", "windows_directory Create is not yet implemented")
}

func (r *windowsDirectoryResource) Read(_ context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	resp.Diagnostics.AddError("not implemented", "windows_directory Read is not yet implemented")
}

func (r *windowsDirectoryResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("not implemented", "windows_directory Update is not yet implemented")
}

func (r *windowsDirectoryResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddError("not implemented", "windows_directory Delete is not yet implemented")
}

func (r *windowsDirectoryResource) ImportState(_ context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.AddError("not implemented", "windows_directory ImportState is not yet implemented")
}
