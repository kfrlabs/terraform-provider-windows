// Package provider: windows_feature resource implementation.
//
// This file contains the TPF schema, model, and CRUD + ImportState handlers
// for the windows_feature resource. WinRM interaction is delegated to
// winclient.FeatureClient (internal/winclient/feature.go).
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                = (*windowsFeatureResource)(nil)
	_ resource.ResourceWithConfigure   = (*windowsFeatureResource)(nil)
	_ resource.ResourceWithImportState = (*windowsFeatureResource)(nil)
)

// NewWindowsFeatureResource is the constructor registered in provider.go.
func NewWindowsFeatureResource() resource.Resource { return &windowsFeatureResource{} }

// windowsFeatureResource is the TPF resource type for windows_feature.
type windowsFeatureResource struct {
	client *winclient.Client
	feat   winclient.WindowsFeatureClient
}

// windowsFeatureModel is the Terraform state/plan model for windows_feature.
type windowsFeatureModel struct {
	ID                     types.String `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	DisplayName            types.String `tfsdk:"display_name"`
	Description            types.String `tfsdk:"description"`
	Installed              types.Bool   `tfsdk:"installed"`
	IncludeSubFeatures     types.Bool   `tfsdk:"include_sub_features"`
	IncludeManagementTools types.Bool   `tfsdk:"include_management_tools"`
	Source                 types.String `tfsdk:"source"`
	Restart                types.Bool   `tfsdk:"restart"`
	RestartPending         types.Bool   `tfsdk:"restart_pending"`
	InstallState           types.String `tfsdk:"install_state"`
}

// Metadata sets the resource type name ("windows_feature").
func (r *windowsFeatureResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_feature"
}

// Schema returns the complete TPF schema.
func (r *windowsFeatureResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsFeatureSchemaDefinition()
}

// windowsFeatureSchemaDefinition returns the windows_feature schema.
//
// ForceNew (RequiresReplace) on name, include_sub_features and
// include_management_tools because Install-WindowsFeature cannot retroactively
// shrink the feature tree once those switches have been applied.
func windowsFeatureSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages installation/uninstallation of a Windows Server role or feature " +
			"on a remote host via WinRM and PowerShell. Backed by Get/Install/Uninstall-WindowsFeature " +
			"(ServerManager module). Client SKUs are not supported — use Enable/Disable-WindowsOptionalFeature instead.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier; equals the feature short name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Technical name of the Windows feature (e.g. Web-Server, DNS, RSAT-AD-PowerShell). ForceNew.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`),
						"must start with an alphanumeric character and contain only [A-Za-z0-9._-]",
					),
					stringvalidator.LengthBetween(1, 256),
				},
			},
			"display_name": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable display name reported by Get-WindowsFeature.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description string returned by Get-WindowsFeature.",
			},
			"installed": schema.BoolAttribute{
				Computed:    true,
				Description: "True when InstallState=Installed.",
			},
			"include_sub_features": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Install all sub-features (-IncludeAllSubFeature). Default false. ForceNew.",
				Default:     booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"include_management_tools": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Install management tools (-IncludeManagementTools). Default false. ForceNew.",
				Default:     booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},
			"source": schema.StringAttribute{
				Optional:    true,
				Description: "Optional SxS / WIM source path used when feature payload has been removed (-Source). Required when current install_state=Removed.",
			},
			"restart": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Allow Install/Uninstall-WindowsFeature to reboot the host automatically when needed (-Restart). Default false.",
				Default:     booldefault.StaticBool(false),
			},
			"restart_pending": schema.BoolAttribute{
				Computed:    true,
				Description: "True if the last operation reported RestartNeeded=Yes or the OS exposes a pending reboot flag.",
			},
			"install_state": schema.StringAttribute{
				Computed:    true,
				Description: "Current install state: Installed, Available, or Removed.",
				Validators: []validator.String{
					stringvalidator.OneOf("Installed", "Available", "Removed"),
				},
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (r *windowsFeatureResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = c
	r.feat = winclient.NewFeatureClient(c)
}

// ImportState lets `terraform import windows_feature.foo Web-Server` work.
func (r *windowsFeatureResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

// -----------------------------------------------------------------------------
// CRUD
// -----------------------------------------------------------------------------

// Create installs the Windows feature and persists the observed state.
func (r *windowsFeatureResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsFeatureModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := winclient.FeatureInput{
		Name:                   plan.Name.ValueString(),
		IncludeSubFeatures:     plan.IncludeSubFeatures.ValueBool(),
		IncludeManagementTools: plan.IncludeManagementTools.ValueBool(),
		Source:                 plan.Source.ValueString(),
		Restart:                plan.Restart.ValueBool(),
	}

	info, result, err := r.feat.Install(ctx, in)
	if err != nil {
		addFeatureDiag(&resp.Diagnostics, "Create windows_feature failed", err)
		return
	}
	final := modelFromFeature(info, plan)
	applyInstallResult(&resp.Diagnostics, &final, plan, result)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Read refreshes Terraform state from the live host. Returns RemoveResource
// when the feature is no longer enumerable (drift recovery).
func (r *windowsFeatureResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsFeatureModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	if name == "" {
		name = state.ID.ValueString()
	}
	info, err := r.feat.Read(ctx, name)
	if err != nil {
		addFeatureDiag(&resp.Diagnostics, "Read windows_feature failed", err)
		return
	}
	if info == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	final := modelFromFeature(info, state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Update applies in-place changes. Only `source` and `restart` are mutable in
// place. Re-running Install-WindowsFeature is idempotent and refreshes state.
func (r *windowsFeatureResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior windowsFeatureModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	if name == "" {
		name = prior.Name.ValueString()
	}
	in := winclient.FeatureInput{
		Name:                   name,
		IncludeSubFeatures:     plan.IncludeSubFeatures.ValueBool(),
		IncludeManagementTools: plan.IncludeManagementTools.ValueBool(),
		Source:                 plan.Source.ValueString(),
		Restart:                plan.Restart.ValueBool(),
	}
	info, result, err := r.feat.Install(ctx, in)
	if err != nil {
		addFeatureDiag(&resp.Diagnostics, "Update windows_feature failed", err)
		return
	}
	final := modelFromFeature(info, plan)
	applyInstallResult(&resp.Diagnostics, &final, plan, result)
	resp.Diagnostics.Append(resp.State.Set(ctx, &final)...)
}

// Delete uninstalls the feature. Idempotent: a vanished feature is success.
func (r *windowsFeatureResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsFeatureModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	if name == "" {
		name = state.ID.ValueString()
	}
	in := winclient.FeatureInput{
		Name:                   name,
		IncludeManagementTools: state.IncludeManagementTools.ValueBool(),
		Restart:                state.Restart.ValueBool(),
	}
	_, result, err := r.feat.Uninstall(ctx, in)
	if err != nil {
		if winclient.IsFeatureError(err, winclient.FeatureErrorNotFound) {
			return // already gone
		}
		addFeatureDiag(&resp.Diagnostics, "Delete windows_feature failed", err)
		return
	}
	if result != nil && result.RestartNeeded && !state.Restart.ValueBool() {
		resp.Diagnostics.AddWarning(
			"Reboot required after uninstall",
			fmt.Sprintf("Uninstall-WindowsFeature reported RestartNeeded for feature %q. Reboot the target host to complete removal, or set restart=true.", name),
		)
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// modelFromFeature projects a winclient.FeatureInfo onto a windowsFeatureModel,
// preserving desired-input fields (include_*, source, restart) from prior plan.
func modelFromFeature(info *winclient.FeatureInfo, prior windowsFeatureModel) windowsFeatureModel {
	out := windowsFeatureModel{
		ID:                     types.StringValue(info.Name),
		Name:                   types.StringValue(info.Name),
		DisplayName:            types.StringValue(info.DisplayName),
		Description:            types.StringValue(info.Description),
		Installed:              types.BoolValue(info.Installed),
		InstallState:           types.StringValue(info.InstallState),
		RestartPending:         types.BoolValue(info.RestartPending),
		IncludeSubFeatures:     prior.IncludeSubFeatures,
		IncludeManagementTools: prior.IncludeManagementTools,
		Source:                 prior.Source,
		Restart:                prior.Restart,
	}
	if out.IncludeSubFeatures.IsNull() || out.IncludeSubFeatures.IsUnknown() {
		out.IncludeSubFeatures = types.BoolValue(false)
	}
	if out.IncludeManagementTools.IsNull() || out.IncludeManagementTools.IsUnknown() {
		out.IncludeManagementTools = types.BoolValue(false)
	}
	if out.Restart.IsNull() || out.Restart.IsUnknown() {
		out.Restart = types.BoolValue(false)
	}
	return out
}

// applyInstallResult overwrites RestartPending from the install result and
// emits a warning when a reboot is required but `restart` is disabled.
func applyInstallResult(diags *diag.Diagnostics, m *windowsFeatureModel, plan windowsFeatureModel, result *winclient.InstallResult) {
	if result == nil {
		return
	}
	if result.RestartNeeded {
		m.RestartPending = types.BoolValue(true)
		if !plan.Restart.ValueBool() {
			diags.AddWarning(
				"Reboot required",
				fmt.Sprintf("Install/Uninstall-WindowsFeature reported RestartNeeded for feature %q (ExitCode=%s). "+
					"Set restart=true to let the cmdlet reboot automatically, or reboot the target host out-of-band.",
					m.Name.ValueString(), result.ExitCode),
			)
		}
	}
}

// addFeatureDiag converts a winclient.FeatureError into a TPF diagnostic.
func addFeatureDiag(diags *diag.Diagnostics, summary string, err error) {
	var fe *winclient.FeatureError
	if errors.As(err, &fe) {
		detail := fe.Message
		if len(fe.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range fe.Context {
				detail += fmt.Sprintf("\n  %s = %s", k, v)
			}
		}
		if fe.Kind != "" {
			detail += fmt.Sprintf("\n\nKind: %s", fe.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
