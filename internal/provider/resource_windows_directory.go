// Package provider: windows_directory resource implementation.
package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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

var (
	_ resource.Resource                = (*windowsDirectoryResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsDirectoryResource)(nil)
	_ resource.ResourceWithImportState = (*windowsDirectoryResource)(nil)
)

func NewWindowsDirectoryResource() resource.Resource { return &windowsDirectoryResource{} }

type windowsDirectoryResource struct{ client winclient.DirectoryClient }

type windowsDirectoryModel struct {
	ID            types.String `tfsdk:"id"`
	Path          types.String `tfsdk:"path"`
	CreateParents types.Bool   `tfsdk:"create_parents"`
	Attributes    types.List   `tfsdk:"attributes"`
	Recursive     types.Bool   `tfsdk:"recursive_delete"`
	LastWriteTime types.String `tfsdk:"last_write_time"`
}

func (r *windowsDirectoryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_directory"
}

func (r *windowsDirectoryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a directory on a remote Windows host over SSH and PowerShell. " +
			"The resource creates the directory, optionally creates missing parents, manages directory " +
			"attributes, and removes it on destroy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "The normalized absolute Windows path of the managed directory.",
			},
			"path": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(windowsFilePathRegex,
						`must be an absolute Windows path such as C:\\data\\app or \\server\\share\\app`),
					fileNoTraversalValidator{},
				},
				MarkdownDescription: "Absolute path of the directory on the target Windows host. Changing it replaces the resource.",
			},
			"create_parents": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				PlanModifiers:       []planmodifier.Bool{boolRequiresReplace{}},
				MarkdownDescription: "Create missing parent directories. Defaults to `true`.",
			},
			"attributes": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Validators: []validator.List{listvalidator.ValueStringsAre(stringvalidator.OneOf(
					winclient.DirectoryAttributeArchive,
					winclient.DirectoryAttributeHidden,
					winclient.DirectoryAttributeReadOnly,
					winclient.DirectoryAttributeSystem,
					winclient.DirectoryAttributeTemporary,
				))},
				MarkdownDescription: "Windows directory attributes to apply: `archive`, `hidden`, `readonly`, `system`, or `temporary`.",
			},
			"recursive_delete": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				PlanModifiers:       []planmodifier.Bool{boolRequiresReplace{}},
				MarkdownDescription: "Delete the directory contents recursively during destroy. Defaults to `false`.",
			},
			"last_write_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Last write time reported by the target Windows host in UTC.",
			},
		},
	}
}

// boolRequiresReplace keeps create/destroy-only switches from causing a
// meaningless Update call after the directory already exists.
type boolRequiresReplace struct{}

func (boolRequiresReplace) Description(context.Context) string {
	return "changing this value requires replacement"
}
func (b boolRequiresReplace) MarkdownDescription(ctx context.Context) string {
	return b.Description(ctx)
}
func (boolRequiresReplace) PlanModifyBool(_ context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	if !req.StateValue.IsNull() && !req.ConfigValue.IsNull() && !req.StateValue.IsUnknown() && !req.ConfigValue.IsUnknown() && req.StateValue.ValueBool() != req.ConfigValue.ValueBool() {
		resp.RequiresReplace = true
	}
}

func (r *windowsDirectoryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type", fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData))
		return
	}
	r.client = winclient.NewDirectoryClient(c)
}

func directoryAttributes(ctx context.Context, list types.List, diags *diag.Diagnostics) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var attrs []string
	diags.Append(list.ElementsAs(ctx, &attrs, false)...)
	return attrs
}

func applyDirectoryState(ctx context.Context, model *windowsDirectoryModel, state *winclient.DirectoryState, diags *diag.Diagnostics) {
	model.ID = types.StringValue(state.Path)
	model.Path = types.StringValue(state.Path)
	model.LastWriteTime = types.StringValue(state.LastWriteTime)
	attrs, d := types.ListValueFrom(ctx, types.StringType, state.Attributes)
	diags.Append(d...)
	model.Attributes = attrs
}

func addDirectoryDiag(diags *diag.Diagnostics, op string, err error) {
	var de *winclient.DirectoryError
	if errors.As(err, &de) {
		switch de.Kind {
		case winclient.DirectoryErrorTypeConflict:
			diags.AddError(fmt.Sprintf("Directory %s failed: path type conflict", op), de.Message+". The path must refer to a directory, not a file.")
		case winclient.DirectoryErrorPathNotFound:
			diags.AddError(fmt.Sprintf("Directory %s failed: parent not found", op), de.Message+". Set create_parents = true or create the parent first.")
		case winclient.DirectoryErrorNotEmpty:
			diags.AddError(fmt.Sprintf("Directory %s failed: directory is not empty", op), de.Message+". Set recursive_delete = true only when Terraform should remove its contents.")
		case winclient.DirectoryErrorPermission:
			diags.AddError(fmt.Sprintf("Directory %s failed: permission denied", op), de.Message+". Ensure the SSH account can modify this path.")
		default:
			diags.AddError(fmt.Sprintf("Directory %s failed", op), de.Message)
		}
		return
	}
	diags.AddError(fmt.Sprintf("Directory %s failed", op), err.Error())
}

func (r *windowsDirectoryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsDirectoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	input := winclient.DirectoryInput{Path: plan.Path.ValueString(), CreateParents: plan.CreateParents.ValueBool(), Attributes: directoryAttributes(ctx, plan.Attributes, &resp.Diagnostics)}
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "windows_directory Create", map[string]interface{}{"path": input.Path})
	state, err := r.client.Set(ctx, input)
	if err != nil {
		addDirectoryDiag(&resp.Diagnostics, "Create", err)
		return
	}
	applyDirectoryState(ctx, &plan, state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *windowsDirectoryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsDirectoryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	observed, err := r.client.Read(ctx, state.Path.ValueString())
	if err != nil {
		addDirectoryDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if observed == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	applyDirectoryState(ctx, &state, observed, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *windowsDirectoryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsDirectoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	input := winclient.DirectoryInput{Path: plan.Path.ValueString(), CreateParents: plan.CreateParents.ValueBool(), Attributes: directoryAttributes(ctx, plan.Attributes, &resp.Diagnostics)}
	if resp.Diagnostics.HasError() {
		return
	}
	state, err := r.client.Set(ctx, input)
	if err != nil {
		addDirectoryDiag(&resp.Diagnostics, "Update", err)
		return
	}
	applyDirectoryState(ctx, &plan, state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *windowsDirectoryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsDirectoryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "windows_directory Delete", map[string]interface{}{"path": state.Path.ValueString()})
	if err := r.client.Delete(ctx, state.Path.ValueString(), state.Recursive.ValueBool()); err != nil {
		addDirectoryDiag(&resp.Diagnostics, "Delete", err)
	}
}

func (r *windowsDirectoryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "The import ID must be an absolute Windows directory path.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), req.ID)...)
}
