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
	_ resource.Resource                = &localUserResource{}
	_ resource.ResourceWithConfigure   = &localUserResource{}
	_ resource.ResourceWithImportState = &localUserResource{}
)

// NewLocalUserResource is a helper function to simplify the provider implementation.
func NewLocalUserResource() resource.Resource {
	return &localUserResource{}
}

// localUserResource is the resource implementation for managing Windows local users.
// It provides full lifecycle management (CRUD) for local user accounts
// using PowerShell cmdlets executed over SSH.
type localUserResource struct {
	providerData *common.ProviderData
}

// localUserResourceModel maps the Terraform schema to Go struct for state management.
// It includes both user-configurable attributes and computed values retrieved from Windows.
type localUserResourceModel struct {
	ID                       types.String `tfsdk:"id"`
	Username                 types.String `tfsdk:"username"`
	Password                 types.String `tfsdk:"password"`
	FullName                 types.String `tfsdk:"full_name"`
	Description              types.String `tfsdk:"description"`
	PasswordNeverExpires     types.Bool   `tfsdk:"password_never_expires"`
	UserCannotChangePassword types.Bool   `tfsdk:"user_cannot_change_password"`
	AccountDisabled          types.Bool   `tfsdk:"account_disabled"`
	AllowExisting            types.Bool   `tfsdk:"allow_existing"`
	CommandTimeout           types.Int64  `tfsdk:"command_timeout"`
	// Computed attributes (read-only)
	SID              types.String `tfsdk:"sid"`
	PasswordRequired types.Bool   `tfsdk:"password_required"`
	PasswordLastSet  types.String `tfsdk:"password_last_set"`
}

// Metadata returns the resource type name.
func (r *localUserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_localuser"
}

// Schema defines the schema for the resource.
func (r *localUserResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Windows local user account.",
		MarkdownDescription: `Manages a Windows local user account using PowerShell cmdlets.

This resource allows you to create, update, and delete local user accounts on Windows systems.

## Example Usage

` + "```terraform" + `
resource "windows_localuser" "admin" {
  username                    = "localadmin"
  password                    = "P@ssw0rd123!"
  full_name                   = "Local Administrator"
  description                 = "Local admin account"
  password_never_expires      = true
  user_cannot_change_password = false
  account_disabled            = false
}

resource "windows_localuser" "service_account" {
  username                    = "svc_account"
  password                    = "P@ssw0rd123!"
  description                 = "Service account"
  password_never_expires      = true
  user_cannot_change_password = true
  account_disabled            = false
  allow_existing              = true
}

# Use computed attributes
output "user_sid" {
  value = windows_localuser.admin.sid
}

output "password_last_set" {
  value = windows_localuser.admin.password_last_set
}
` + "```",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the resource (same as username).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"username": schema.StringAttribute{
				Description: "The name of the local user account. Cannot be changed after creation. Must be 1-20 characters.",
				Required:    true,
				Validators: []validator.String{
					validators.WindowsUsername(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
				Description: "The password for the local user account. The password must meet Windows password complexity requirements.",
				Required:    true,
				Sensitive:   true,
			},
			"full_name": schema.StringAttribute{
				Description: "The full name of the user. Optional, can be empty.",
				Optional:    true,
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description for the user account. Optional, can be empty.",
				Optional:    true,
				Computed:    true,
			},
			"password_never_expires": schema.BoolAttribute{
				Description: "If true, the password will never expire. Default is false.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"user_cannot_change_password": schema.BoolAttribute{
				Description: "If true, the user cannot change their password. Default is false.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"account_disabled": schema.BoolAttribute{
				Description: "If true, the account will be disabled. Default is false.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"allow_existing": schema.BoolAttribute{
				Description: "If true, allows adopting an already existing user. If false, fails if the user already exists. Default is false.",
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
				Description: "The Security Identifier (SID) of the user account. This is a unique identifier assigned by Windows.",
				Computed:    true,
			},
			"password_required": schema.BoolAttribute{
				Description: "Indicates whether a password is required for this account. This is a read-only attribute.",
				Computed:    true,
			},
			"password_last_set": schema.StringAttribute{
				Description: "The date and time when the password was last set, in ISO 8601 format. This is a read-only attribute.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *localUserResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *localUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan localUserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	username := plan.Username.ValueString()
	password := plan.Password.ValueString()

	tflog.Info(ctx, "Creating local user", map[string]interface{}{
		"username":                    username,
		"password_never_expires":      plan.PasswordNeverExpires.ValueBool(),
		"user_cannot_change_password": plan.UserCannotChangePassword.ValueBool(),
		"account_disabled":            plan.AccountDisabled.ValueBool(),
		"allow_existing":              plan.AllowExisting.ValueBool(),
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

	// Check if user already exists when allow_existing is enabled
	if plan.AllowExisting.ValueBool() {
		tflog.Debug(ctx, "Checking if user already exists", map[string]interface{}{
			"username": username,
		})

		userInfo, err := windows.GetLocalUserInfo(execCtx, client, username)
		if err == nil && userInfo.Exists {
			tflog.Info(ctx, "User already exists, adopting existing account", map[string]interface{}{
				"username": username,
				"enabled":  userInfo.Enabled,
				"sid":      userInfo.SID,
			})

			// Populate state from existing user
			plan.ID = types.StringValue(username)
			plan.FullName = types.StringValue(userInfo.FullName)
			plan.Description = types.StringValue(userInfo.Description)
			plan.PasswordNeverExpires = types.BoolValue(userInfo.PasswordNeverExpires)
			plan.UserCannotChangePassword = types.BoolValue(userInfo.UserMayNotChangePassword)
			plan.AccountDisabled = types.BoolValue(!userInfo.Enabled)
			// Computed attributes
			plan.SID = types.StringValue(userInfo.SID)
			plan.PasswordRequired = types.BoolValue(userInfo.PasswordRequired)
			plan.PasswordLastSet = types.StringValue(userInfo.PasswordLastSet)

			resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
			return
		}
	}

	// Create the local user using the shared package function
	createParams := windows.LocalUserCreateParams{
		Username:                 username,
		Password:                 password,
		FullName:                 plan.FullName.ValueString(),
		Description:              plan.Description.ValueString(),
		PasswordNeverExpires:     plan.PasswordNeverExpires.ValueBool(),
		UserCannotChangePassword: plan.UserCannotChangePassword.ValueBool(),
	}

	if err := windows.CreateLocalUser(execCtx, client, createParams); err != nil {
		resp.Diagnostics.AddError(
			"User Creation Failed",
			fmt.Sprintf("Failed to create local user '%s': %s", username, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Local user created successfully", map[string]interface{}{
		"username": username,
	})

	// Disable account if necessary
	if plan.AccountDisabled.ValueBool() {
		tflog.Debug(ctx, "Disabling user account", map[string]interface{}{
			"username": username,
		})

		if err := windows.SetLocalUserEnabled(execCtx, client, username, false); err != nil {
			resp.Diagnostics.AddError(
				"Failed to Disable User",
				fmt.Sprintf("User was created but failed to disable account: %s", err.Error()),
			)
			return
		}
	}

	// Set the ID
	plan.ID = types.StringValue(username)

	// Read back the final state (including computed attributes)
	userInfo, err := windows.GetLocalUserInfo(execCtx, client, username)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Failed to Read User Info",
			fmt.Sprintf("User was created but failed to read its current state: %s", err.Error()),
		)
	} else {
		// Update state with actual values
		plan.FullName = types.StringValue(userInfo.FullName)
		plan.Description = types.StringValue(userInfo.Description)
		plan.PasswordNeverExpires = types.BoolValue(userInfo.PasswordNeverExpires)
		plan.UserCannotChangePassword = types.BoolValue(userInfo.UserMayNotChangePassword)
		plan.AccountDisabled = types.BoolValue(!userInfo.Enabled)
		// Computed attributes
		plan.SID = types.StringValue(userInfo.SID)
		plan.PasswordRequired = types.BoolValue(userInfo.PasswordRequired)
		plan.PasswordLastSet = types.StringValue(userInfo.PasswordLastSet)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *localUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state localUserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	username := state.Username.ValueString()

	tflog.Debug(ctx, "Reading local user state", map[string]interface{}{
		"username": username,
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

	// Get user information using shared package function
	userInfo, err := windows.GetLocalUserInfo(execCtx, client, username)
	if err != nil {
		tflog.Warn(ctx, "Failed to read local user, removing from state", map[string]interface{}{
			"username": username,
			"error":    err.Error(),
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// If user doesn't exist, remove from state
	if !userInfo.Exists {
		tflog.Debug(ctx, "Local user does not exist, removing from state", map[string]interface{}{
			"username": username,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state with current user information
	state.FullName = types.StringValue(userInfo.FullName)
	state.Description = types.StringValue(userInfo.Description)
	state.PasswordNeverExpires = types.BoolValue(userInfo.PasswordNeverExpires)
	state.UserCannotChangePassword = types.BoolValue(userInfo.UserMayNotChangePassword)
	state.AccountDisabled = types.BoolValue(!userInfo.Enabled)
	// Computed attributes
	state.SID = types.StringValue(userInfo.SID)
	state.PasswordRequired = types.BoolValue(userInfo.PasswordRequired)
	state.PasswordLastSet = types.StringValue(userInfo.PasswordLastSet)

	tflog.Debug(ctx, "Local user read successfully", map[string]interface{}{
		"username": username,
		"enabled":  userInfo.Enabled,
		"sid":      userInfo.SID,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *localUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan localUserResourceModel
	var state localUserResourceModel

	// Get both plan and state for comparison
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	username := plan.Username.ValueString()

	tflog.Info(ctx, "Updating local user", map[string]interface{}{
		"username": username,
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

	// Update password ONLY if it actually changed
	if !plan.Password.Equal(state.Password) {
		tflog.Debug(ctx, "Password has changed, updating", map[string]interface{}{
			"username": username,
		})

		password := plan.Password.ValueString()
		if err := windows.SetLocalUserPassword(execCtx, client, username, password); err != nil {
			resp.Diagnostics.AddError(
				"Password Update Failed",
				fmt.Sprintf("Failed to update password for user '%s': %s", username, err.Error()),
			)
			return
		}
	}

	// Build update parameters for other attributes
	updateParams := windows.LocalUserUpdateParams{
		Username:                 username,
		FullName:                 plan.FullName.ValueStringPointer(),
		Description:              plan.Description.ValueStringPointer(),
		PasswordNeverExpires:     plan.PasswordNeverExpires.ValueBoolPointer(),
		UserCannotChangePassword: plan.UserCannotChangePassword.ValueBoolPointer(),
	}

	// Update user properties (function handles checking if updates are needed)
	if err := windows.UpdateLocalUser(execCtx, client, updateParams); err != nil {
		resp.Diagnostics.AddError(
			"User Update Failed",
			fmt.Sprintf("Failed to update local user '%s': %s", username, err.Error()),
		)
		return
	}

	// Handle account enable/disable separately if it changed
	if !plan.AccountDisabled.Equal(state.AccountDisabled) {
		disabled := plan.AccountDisabled.ValueBool()
		tflog.Debug(ctx, "Account disabled status has changed", map[string]interface{}{
			"username": username,
			"disabled": disabled,
		})

		if err := windows.SetLocalUserEnabled(execCtx, client, username, !disabled); err != nil {
			resp.Diagnostics.AddError(
				"Failed to Update Account Status",
				fmt.Sprintf("Failed to update account status for user '%s': %s", username, err.Error()),
			)
			return
		}
	}

	tflog.Info(ctx, "Local user updated successfully", map[string]interface{}{
		"username": username,
	})

	// Read back the updated state (including computed attributes)
	userInfo, err := windows.GetLocalUserInfo(execCtx, client, username)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Failed to Read User Info",
			fmt.Sprintf("User was updated but failed to read its current state: %s", err.Error()),
		)
	} else {
		// Update state with actual values
		plan.FullName = types.StringValue(userInfo.FullName)
		plan.Description = types.StringValue(userInfo.Description)
		plan.PasswordNeverExpires = types.BoolValue(userInfo.PasswordNeverExpires)
		plan.UserCannotChangePassword = types.BoolValue(userInfo.UserMayNotChangePassword)
		plan.AccountDisabled = types.BoolValue(!userInfo.Enabled)
		// Computed attributes
		plan.SID = types.StringValue(userInfo.SID)
		plan.PasswordRequired = types.BoolValue(userInfo.PasswordRequired)
		plan.PasswordLastSet = types.StringValue(userInfo.PasswordLastSet)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *localUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state localUserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	username := state.Username.ValueString()

	tflog.Info(ctx, "Deleting local user", map[string]interface{}{
		"username": username,
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

	// Delete the local user using shared package function
	if err := windows.DeleteLocalUser(execCtx, client, username); err != nil {
		resp.Diagnostics.AddError(
			"User Deletion Failed",
			fmt.Sprintf("Failed to delete local user '%s': %s", username, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Local user deleted successfully", map[string]interface{}{
		"username": username,
	})
}

// ImportState imports an existing resource into Terraform state.
func (r *localUserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	username := req.ID

	tflog.Info(ctx, "Importing local user", map[string]interface{}{
		"username": username,
	})

	// Validate username format
	if err := validators.ValidateUsername(username); err != nil {
		resp.Diagnostics.AddError(
			"Invalid Username",
			fmt.Sprintf("The username '%s' is not valid: %s", username, err.Error()),
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

	// Get user information to verify it exists
	userInfo, err := windows.GetLocalUserInfo(execCtx, client, username)
	if err != nil {
		resp.Diagnostics.AddError(
			"User Not Found",
			fmt.Sprintf("Failed to find local user '%s': %s", username, err.Error()),
		)
		return
	}

	if !userInfo.Exists {
		resp.Diagnostics.AddError(
			"User Not Found",
			fmt.Sprintf("Local user '%s' does not exist and cannot be imported.", username),
		)
		return
	}

	// Set imported state with default values for configuration attributes
	// Note: Password cannot be read from Windows, so it must be set manually in config
	importedState := localUserResourceModel{
		ID:                       types.StringValue(username),
		Username:                 types.StringValue(username),
		Password:                 types.StringValue(""), // Will be updated by user in config
		FullName:                 types.StringValue(userInfo.FullName),
		Description:              types.StringValue(userInfo.Description),
		PasswordNeverExpires:     types.BoolValue(userInfo.PasswordNeverExpires),
		UserCannotChangePassword: types.BoolValue(userInfo.UserMayNotChangePassword),
		AccountDisabled:          types.BoolValue(!userInfo.Enabled),
		AllowExisting:            types.BoolValue(true),
		CommandTimeout:           types.Int64Value(300),
		// Computed attributes
		SID:              types.StringValue(userInfo.SID),
		PasswordRequired: types.BoolValue(userInfo.PasswordRequired),
		PasswordLastSet:  types.StringValue(userInfo.PasswordLastSet),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &importedState)...)

	tflog.Info(ctx, "Local user imported successfully", map[string]interface{}{
		"username": username,
		"enabled":  userInfo.Enabled,
		"sid":      userInfo.SID,
	})

	// Add note about password
	resp.Diagnostics.AddWarning(
		"Password Not Imported",
		fmt.Sprintf("The password for user '%s' cannot be read from Windows. "+
			"You must set the 'password' attribute in your Terraform configuration after import. "+
			"The next 'terraform apply' will update the password.", username),
	)
}
