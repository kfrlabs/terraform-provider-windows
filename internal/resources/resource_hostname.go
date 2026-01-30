package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
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
)

// Ensure the implementation satisfies the expected interfaces
var (
	_ resource.Resource                = &hostnameResource{}
	_ resource.ResourceWithConfigure   = &hostnameResource{}
	_ resource.ResourceWithImportState = &hostnameResource{}
)

// NewHostnameResource is a helper function to create the resource
func NewHostnameResource() resource.Resource {
	return &hostnameResource{}
}

// hostnameResource is the resource implementation
type hostnameResource struct {
	providerData *common.ProviderData
}

// hostnameResourceModel describes the resource data model
type hostnameResourceModel struct {
	Hostname       types.String `tfsdk:"hostname"`
	Restart        types.Bool   `tfsdk:"restart"`
	PendingReboot  types.Bool   `tfsdk:"pending_reboot"`
	CommandTimeout types.Int64  `tfsdk:"command_timeout"`
}

// Metadata returns the resource type name
func (r *hostnameResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hostname"
}

// Schema defines the schema for the resource
func (r *hostnameResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Manages the hostname of a Windows machine.",
		MarkdownDescription: "Manages the hostname of a Windows machine with optional automatic restart.",

		Attributes: map[string]schema.Attribute{
			"hostname": schema.StringAttribute{
				Description: "The new hostname to apply to the Windows machine.",
				Required:    true,
				Validators: []validator.String{
					validators.PowerShellString(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"restart": schema.BoolAttribute{
				Description: "Restart the computer after renaming (default: false).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"pending_reboot": schema.BoolAttribute{
				Description: "Indicates if a reboot is pending for the hostname change to take effect.",
				Computed:    true,
			},
			"command_timeout": schema.Int64Attribute{
				Description: "Timeout in seconds for PowerShell commands (default: 300).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(300),
			},
		},
	}
}

// Configure adds the provider configured client to the resource
func (r *hostnameResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
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

// validateHostname validates hostname format according to RFC 1123 standards
func validateHostname(name string) error {
	if name == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("hostname exceeds maximum length of 255 characters")
	}

	// RFC 1123 hostname label validation
	labelRe := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$`)

	labels := strings.Split(name, ".")
	for _, lbl := range labels {
		if lbl == "" {
			return fmt.Errorf("hostname contains empty label")
		}
		if len(lbl) > 63 {
			return fmt.Errorf("hostname label '%s' exceeds 63 characters", lbl)
		}
		if !labelRe.MatchString(lbl) {
			return fmt.Errorf("hostname label '%s' contains invalid characters", lbl)
		}
	}
	return nil
}

// Create creates the resource and sets the initial Terraform state
func (r *hostnameResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hostnameResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hostname := plan.Hostname.ValueString()
	restart := plan.Restart.ValueBool()

	// Additional validation for hostname format (RFC 1123)
	if err := validateHostname(hostname); err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("hostname"),
			"Invalid Hostname Format",
			fmt.Sprintf("Hostname validation failed: %s", err),
		)
		return
	}

	tflog.Info(ctx, "Creating/updating hostname",
		map[string]any{
			"hostname": hostname,
			"restart":  restart,
		})

	// Get SSH client from provider data
	sshClient, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get SSH client",
			fmt.Sprintf("Could not acquire SSH client from pool: %s", err),
		)
		return
	}
	defer cleanup()

	// Get current hostname to check if change is needed
	checkCommand := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(ctx, checkCommand)
	currentHostname := strings.TrimSpace(stdout)

	if err != nil {
		tflog.Warn(ctx, "Could not retrieve current hostname",
			map[string]any{"error": err.Error()})
	} else {
		tflog.Info(ctx, "Current hostname retrieved",
			map[string]any{
				"current": currentHostname,
				"target":  hostname,
			})

		// Check if hostname is already set (case-insensitive comparison)
		if strings.EqualFold(currentHostname, hostname) {
			tflog.Info(ctx, "Hostname already set, no change needed",
				map[string]any{"hostname": hostname})

			plan.PendingReboot = types.BoolValue(false)
			resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
			return
		}

		tflog.Info(ctx, "Changing hostname",
			map[string]any{
				"from": currentHostname,
				"to":   hostname,
			})
	}

	// Build secure PowerShell command
	// Use single quotes and escape single quotes by doubling them
	safeHostname := strings.ReplaceAll(hostname, "'", "''")
	command := fmt.Sprintf("Rename-Computer -NewName '%s' -Force -ErrorAction Stop", safeHostname)
	if restart {
		command += " -Restart"
	}

	tflog.Debug(ctx, "Executing hostname change command")

	stdout, stderr, err := sshClient.ExecuteCommand(ctx, command)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to rename computer",
			fmt.Sprintf("Command failed: %s\nStdout: %s\nStderr: %s", err, stdout, stderr),
		)
		return
	}

	// Set appropriate state based on restart option
	if restart {
		tflog.Warn(ctx, "Computer is restarting, hostname change will be effective after reboot",
			map[string]any{"hostname": hostname})
		plan.PendingReboot = types.BoolValue(false)
	} else {
		tflog.Warn(ctx, "Hostname change requires reboot to take effect",
			map[string]any{
				"hostname": hostname,
				"action":   "Set restart=true or reboot manually",
			})
		plan.PendingReboot = types.BoolValue(true)
	}

	tflog.Info(ctx, "Hostname resource created successfully",
		map[string]any{"hostname": hostname})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data
func (r *hostnameResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hostnameResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	expected := state.Hostname.ValueString()
	pendingReboot := state.PendingReboot.ValueBool()

	tflog.Debug(ctx, "Reading hostname",
		map[string]any{
			"expected":       expected,
			"pending_reboot": pendingReboot,
		})

	// Get SSH client from provider data
	sshClient, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get SSH client",
			fmt.Sprintf("Could not acquire SSH client from pool: %s", err),
		)
		return
	}
	defer cleanup()

	// Get current hostname from the remote machine
	command := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(ctx, command)
	if err != nil {
		// If we can't verify but reboot is pending, keep resource in state
		if pendingReboot {
			tflog.Warn(ctx, "Could not verify hostname (machine may be rebooting), keeping resource in state")
			return
		}
		tflog.Warn(ctx, "Could not verify hostname, keeping resource in state",
			map[string]any{"error": err.Error()})
		return
	}

	currentHostname := strings.TrimSpace(stdout)

	tflog.Debug(ctx, "Hostname comparison",
		map[string]any{
			"current":  currentHostname,
			"expected": expected,
		})

	// Case-insensitive hostname comparison
	if !strings.EqualFold(currentHostname, expected) {
		if pendingReboot {
			tflog.Info(ctx, "Hostname not yet changed (pending reboot)",
				map[string]any{
					"current":  currentHostname,
					"expected": expected,
				})
			return
		}

		tflog.Warn(ctx, "Hostname mismatch, removing from state",
			map[string]any{
				"expected": expected,
				"actual":   currentHostname,
			})
		resp.State.RemoveResource(ctx)
		return
	}

	tflog.Info(ctx, "Hostname verified successfully",
		map[string]any{"hostname": expected})

	// Clear pending_reboot flag if hostname change is now effective
	if pendingReboot {
		tflog.Info(ctx, "Hostname change is now effective, clearing pending_reboot flag")
		state.PendingReboot = types.BoolValue(false)
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

// Update updates the resource and sets the updated Terraform state on success
func (r *hostnameResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan hostnameResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Hostname changes require replacement (handled by RequiresReplace plan modifier)
	// This Update should only be called for non-hostname changes (command_timeout, restart)
	tflog.Debug(ctx, "Updating hostname resource (non-hostname change)")

	// Save updated state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success
func (r *hostnameResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hostnameResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Deleting hostname resource (no action on remote host)",
		map[string]any{"hostname": state.Hostname.ValueString()})

	// Note: We don't actually change the hostname on the remote machine during delete
	// The resource is simply removed from Terraform state
}

// ImportState imports an existing resource into Terraform state
func (r *hostnameResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	hostname := req.ID

	// Validate hostname format according to RFC 1123
	if err := validateHostname(hostname); err != nil {
		resp.Diagnostics.AddError(
			"Invalid Hostname Format",
			fmt.Sprintf("The hostname to import is invalid: %s", err),
		)
		return
	}

	tflog.Info(ctx, "Importing hostname resource", map[string]any{"hostname": hostname})

	// Get SSH client from provider data
	sshClient, cleanup, err := r.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get SSH client",
			fmt.Sprintf("Could not acquire SSH client from pool: %s", err),
		)
		return
	}
	defer cleanup()

	// Verify hostname matches remote host
	checkCommand := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(ctx, checkCommand)
	if err != nil {
		tflog.Warn(ctx, "Could not verify remote hostname during import",
			map[string]any{"error": err.Error()})
	} else {
		currentHostname := strings.TrimSpace(stdout)
		if !strings.EqualFold(currentHostname, hostname) {
			resp.Diagnostics.AddError(
				"Hostname Mismatch",
				fmt.Sprintf("Imported hostname '%s' does not match remote host actual hostname '%s'. "+
					"Use the actual hostname or run 'Rename-Computer -NewName %s' on the remote host first",
					hostname, currentHostname, hostname),
			)
			return
		}
		tflog.Info(ctx, "Successfully verified hostname during import",
			map[string]any{"hostname": hostname})
	}

	// Set the resource attributes
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("hostname"), hostname)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("restart"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("pending_reboot"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("command_timeout"), 300)...)
}
