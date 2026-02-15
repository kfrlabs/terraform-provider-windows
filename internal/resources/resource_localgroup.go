package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/common"
	"github.com/kfrlabs/terraform-provider-windows/internal/validators"
	"github.com/kfrlabs/terraform-provider-windows/internal/windows"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &localGroupResource{}
	_ resource.ResourceWithConfigure   = &localGroupResource{}
	_ resource.ResourceWithImportState = &localGroupResource{}
)

// NewLocalGroupResource is a helper function to simplify the provider implementation.
func NewLocalGroupResource() resource.Resource {
	return &localGroupResource{}
}

// localGroupResource is the resource implementation for managing Windows local groups.
type localGroupResource struct {
	providerData *common.ProviderData
}

// localGroupResourceModel maps the Terraform schema to Go struct for state management.
type localGroupResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	AllowExisting  types.Bool   `tfsdk:"allow_existing"`
	CommandTimeout types.Int64  `tfsdk:"command_timeout"`
	// Computed attributes (read-only)
	SID             types.String `tfsdk:"sid"`
	PrincipalSource types.String `tfsdk:"principal_source"`
	ObjectClass     types.String `tfsdk:"object_class"`
}

// Metadata returns the resource type name.
func (r *localGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_localgroup"
}

// Schema defines the schema for the resource.
func (r *localGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Windows local group.",
		MarkdownDescription: `Manages a Windows local group using PowerShell cmdlets.

This resource allows you to create, update, and delete local groups on Windows systems.

## Example Usage

` + "```terraform" + `
resource "windows_localgroup" "developers" {
  name        = "Developers"
  description = "Development team members"
}

resource "windows_localgroup" "admins" {
  name           = "CustomAdmins"
  description    = "Custom administrators group"
  allow_existing = false
}

# Adopt existing group
resource "windows_localgroup" "existing_group" {
  name           = "ExistingGroup"
  description    = "Managed by Terraform"
  allow_existing = true
}

# Use computed attributes
output "group_sid" {
  value = windows_localgroup.developers.sid
}
` + "```",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the resource (same as name).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the local group. Cannot be changed after creation. Must be 1-256 characters.",
				Required:    true,
				Validators: []validator.String{
					validators.WindowsGroupName(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "A description for the group. Optional, can be empty.",
				Optional:    true,
				Computed:    true,
			},
			"allow_existing": schema.BoolAttribute{
				Description: "If true, allows adopting an already existing group. If false, fails if the group already exists. Default is false.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"command_timeout": schema.Int64Attribute{
				Description: "Timeout in seconds for PowerShell commands. Default is 300 seconds (5 minutes).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(300),
			},
			// Computed-only attributes
			"sid": schema.StringAttribute{
				Description: "The Security Identifier (SID) of the group. This is a unique identifier assigned by Windows.",
				Computed:    true,
			},
			"principal_source": schema.StringAttribute{
				Description: "The source of the group. Typically 'Local' for local groups.",
				Computed:    true,
			},
			"object_class": schema.StringAttribute{
				Description: "The object class type. Typically 'Group' for group objects.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *localGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*common.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *common.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.providerData = providerData
}

// Create creates the resource and sets the initial Terraform state.
func (r *localGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan localGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupname := plan.Name.ValueString()

	tflog.Info(ctx, "Creating local group", map[string]interface{}{
		"groupname":      groupname,
		"allow_existing": plan.AllowExisting.ValueBool(),
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context
	timeout := time.Duration(plan.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Check if group already exists when allow_existing is enabled
	if plan.AllowExisting.ValueBool() {
		tflog.Debug(ctx, "Checking if group already exists", map[string]interface{}{
			"groupname": groupname,
		})

		groupInfo, err := windows.GetLocalGroupInfo(execCtx, client, groupname)
		if err == nil && groupInfo.Exists {
			tflog.Info(ctx, "Group already exists, adopting existing group", map[string]interface{}{
				"groupname": groupname,
				"sid":       groupInfo.SID,
			})

			// Populate state from existing group
			plan.ID = types.StringValue(groupname)
			plan.Description = types.StringValue(groupInfo.Description)
			// Computed attributes
			plan.SID = types.StringValue(groupInfo.SID)
			plan.PrincipalSource = types.StringValue(groupInfo.PrincipalSource)
			plan.ObjectClass = types.StringValue(groupInfo.ObjectClass)

			resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
			return
		}
	}

	// Create the local group using the shared package function
	createParams := windows.LocalGroupCreateParams{
		Name:        groupname,
		Description: plan.Description.ValueString(),
	}

	if err := windows.CreateLocalGroup(execCtx, client, createParams); err != nil {
		resp.Diagnostics.AddError(
			"Group Creation Failed",
			fmt.Sprintf("Failed to create local group '%s': %s", groupname, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Local group created successfully", map[string]interface{}{
		"groupname": groupname,
	})

	// Set the ID
	plan.ID = types.StringValue(groupname)

	// Read back the final state (including computed attributes)
	groupInfo, err := windows.GetLocalGroupInfo(execCtx, client, groupname)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Failed to Read Group Info",
			fmt.Sprintf("Group was created but failed to read its current state: %s", err.Error()),
		)
	} else {
		// Update state with actual values
		plan.Description = types.StringValue(groupInfo.Description)
		// Computed attributes
		plan.SID = types.StringValue(groupInfo.SID)
		plan.PrincipalSource = types.StringValue(groupInfo.PrincipalSource)
		plan.ObjectClass = types.StringValue(groupInfo.ObjectClass)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *localGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state localGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupname := state.Name.ValueString()

	tflog.Debug(ctx, "Reading local group state", map[string]interface{}{
		"groupname": groupname,
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context
	timeout := time.Duration(state.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Get group information using shared package function
	groupInfo, err := windows.GetLocalGroupInfo(execCtx, client, groupname)
	if err != nil {
		tflog.Warn(ctx, "Failed to read local group, removing from state", map[string]interface{}{
			"groupname": groupname,
			"error":     err.Error(),
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// If group doesn't exist, remove from state
	if !groupInfo.Exists {
		tflog.Debug(ctx, "Local group does not exist, removing from state", map[string]interface{}{
			"groupname": groupname,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state with current group information
	state.Description = types.StringValue(groupInfo.Description)
	// Computed attributes
	state.SID = types.StringValue(groupInfo.SID)
	state.PrincipalSource = types.StringValue(groupInfo.PrincipalSource)
	state.ObjectClass = types.StringValue(groupInfo.ObjectClass)

	tflog.Debug(ctx, "Local group read successfully", map[string]interface{}{
		"groupname": groupname,
		"sid":       groupInfo.SID,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *localGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan localGroupResourceModel
	var state localGroupResourceModel

	// Get both plan and state for comparison
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupname := plan.Name.ValueString()

	tflog.Info(ctx, "Updating local group", map[string]interface{}{
		"groupname": groupname,
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context
	timeout := time.Duration(plan.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build update parameters
	updateParams := windows.LocalGroupUpdateParams{
		Name:        groupname,
		Description: plan.Description.ValueStringPointer(),
	}

	// Update group properties (function handles checking if updates are needed)
	if err := windows.UpdateLocalGroup(execCtx, client, updateParams); err != nil {
		resp.Diagnostics.AddError(
			"Group Update Failed",
			fmt.Sprintf("Failed to update local group '%s': %s", groupname, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Local group updated successfully", map[string]interface{}{
		"groupname": groupname,
	})

	// Read back the updated state (including computed attributes)
	groupInfo, err := windows.GetLocalGroupInfo(execCtx, client, groupname)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Failed to Read Group Info",
			fmt.Sprintf("Group was updated but failed to read its current state: %s", err.Error()),
		)
	} else {
		// Update state with actual values
		plan.Description = types.StringValue(groupInfo.Description)
		// Computed attributes
		plan.SID = types.StringValue(groupInfo.SID)
		plan.PrincipalSource = types.StringValue(groupInfo.PrincipalSource)
		plan.ObjectClass = types.StringValue(groupInfo.ObjectClass)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *localGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state localGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupname := state.Name.ValueString()

	tflog.Info(ctx, "Deleting local group", map[string]interface{}{
		"groupname": groupname,
	})

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Create timeout context
	timeout := time.Duration(state.CommandTimeout.ValueInt64()) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Delete the local group using shared package function
	if err := windows.DeleteLocalGroup(execCtx, client, groupname); err != nil {
		resp.Diagnostics.AddError(
			"Group Deletion Failed",
			fmt.Sprintf("Failed to delete local group '%s': %s", groupname, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Local group deleted successfully", map[string]interface{}{
		"groupname": groupname,
	})
}

// ImportState imports an existing resource into Terraform state.
func (r *localGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	groupname := req.ID

	tflog.Info(ctx, "Importing local group", map[string]interface{}{
		"groupname": groupname,
	})

	// Validate group name format
	if err := validators.ValidateGroupName(groupname); err != nil {
		resp.Diagnostics.AddError(
			"Invalid Group Name",
			fmt.Sprintf("The group name '%s' is not valid: %s", groupname, err.Error()),
		)
		return
	}

	// Get SSH client
	client, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"SSH Client Error",
			fmt.Sprintf("Failed to get SSH client: %s", err.Error()),
		)
		return
	}
	defer cleanup()

	// Use default timeout for import operations
	execCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()

	// Get group information to verify it exists
	groupInfo, err := windows.GetLocalGroupInfo(execCtx, client, groupname)
	if err != nil {
		resp.Diagnostics.AddError(
			"Group Not Found",
			fmt.Sprintf("Failed to find local group '%s': %s", groupname, err.Error()),
		)
		return
	}

	if !groupInfo.Exists {
		resp.Diagnostics.AddError(
			"Group Not Found",
			fmt.Sprintf("Local group '%s' does not exist and cannot be imported.", groupname),
		)
		return
	}

	// Set imported state
	importedState := localGroupResourceModel{
		ID:             types.StringValue(groupname),
		Name:           types.StringValue(groupname),
		Description:    types.StringValue(groupInfo.Description),
		AllowExisting:  types.BoolValue(true),
		CommandTimeout: types.Int64Value(300),
		// Computed attributes
		SID:             types.StringValue(groupInfo.SID),
		PrincipalSource: types.StringValue(groupInfo.PrincipalSource),
		ObjectClass:     types.StringValue(groupInfo.ObjectClass),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &importedState)...)

	tflog.Info(ctx, "Local group imported successfully", map[string]interface{}{
		"groupname": groupname,
		"sid":       groupInfo.SID,
	})
}
