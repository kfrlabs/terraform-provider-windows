// Package provider: windows_iis_app_pool data source implementation.
//
// Reads the observed state of an existing IIS application pool by name
// without managing it. Every sibling-resource setting is exposed read-only
// instead, plus the read-only timeouts{read} block. The SpecificUser
// password is never returned.
package provider

import (
	"context"
	"errors"
	"fmt"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsIISAppPoolDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsIISAppPoolDataSource)(nil)
)

// NewWindowsIISAppPoolDataSource is the constructor registered in provider.go.
func NewWindowsIISAppPoolDataSource() datasource.DataSource {
	return &windowsIISAppPoolDataSource{}
}

// windowsIISAppPoolDataSource is the TPF data source type for windows_iis_app_pool.
type windowsIISAppPoolDataSource struct {
	pool winclient.WindowsIISAppPoolClient
}

// iisAppPoolDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling resource
// default (iisAppPoolDefaultTimeout) so a stalled session surfaces a timeout
// diagnostic instead of blocking plan forever.
const iisAppPoolDSDefaultTimeout = iisAppPoolDefaultTimeout

// windowsIISAppPoolDataSourceModel is the Terraform state model for the
// windows_iis_app_pool data source. The SpecificUser password is
// deliberately absent: it is WriteOnly on the sibling resource and can never
// be read back from the host.
type windowsIISAppPoolDataSourceModel struct {
	ID                              types.String     `tfsdk:"id"`
	Name                            types.String     `tfsdk:"name"`
	ManagedRuntimeVersion           types.String     `tfsdk:"managed_runtime_version"`
	ManagedPipelineMode             types.String     `tfsdk:"managed_pipeline_mode"`
	Enable32BitAppOnWin64           types.Bool       `tfsdk:"enable_32bit_app_on_win64"`
	StartMode                       types.String     `tfsdk:"start_mode"`
	AutoStart                       types.Bool       `tfsdk:"auto_start"`
	QueueLength                     types.Int64      `tfsdk:"queue_length"`
	IdentityType                    types.String     `tfsdk:"identity_type"`
	IdentityUsername                types.String     `tfsdk:"identity_username"`
	LoadUserProfile                 types.Bool       `tfsdk:"load_user_profile"`
	IdleTimeoutMinutes              types.Int64      `tfsdk:"idle_timeout_minutes"`
	IdleTimeoutAction               types.String     `tfsdk:"idle_timeout_action"`
	MaxProcesses                    types.Int64      `tfsdk:"max_processes"`
	RecyclingPeriodicRestartMinutes types.Int64      `tfsdk:"recycling_periodic_restart_minutes"`
	RecyclingSchedule               types.Set        `tfsdk:"recycling_schedule"`
	RecyclingPrivateMemoryKB        types.Int64      `tfsdk:"recycling_private_memory_kb"`
	RapidFailProtection             types.Bool       `tfsdk:"rapid_fail_protection"`
	CPULimitPercent                 types.Int64      `tfsdk:"cpu_limit_percent"`
	CPUAction                       types.String     `tfsdk:"cpu_action"`
	State                           types.String     `tfsdk:"state"`
	Timeouts                        dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_iis_app_pool").
func (d *windowsIISAppPoolDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iis_app_pool"
}

// Schema returns the TPF schema for the windows_iis_app_pool data source.
func (d *windowsIISAppPoolDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of an existing IIS application pool by `name` " +
			"on a remote Windows host without managing it. Durations surface as whole minutes and " +
			"`cpu.limit` thousandths as whole percent, converted server-side.\n\n" +
			"Requires IIS on the target host: install it with the `windows_feature` resource (`Web-Server`; " +
			"add `Web-Mgmt-Console` / `Web-Scripting-Tools` for the `WebAdministration` module on Server Core).\n\n" +
			"Returns an error when the pool does not exist on the target host. The `SpecificUser` " +
			"password is never returned.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the application pool name.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Application pool name on the target host.",
			},
			"managed_runtime_version": schema.StringAttribute{
				Computed:    true,
				Description: "CLR version, as observed on the host (`\"\"` means No Managed Code).",
			},
			"managed_pipeline_mode": schema.StringAttribute{
				Computed:    true,
				Description: "Managed pipeline mode, as observed on the host.",
			},
			"enable_32bit_app_on_win64": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether 32-bit applications run on 64-bit Windows, as observed on the host.",
			},
			"start_mode": schema.StringAttribute{
				Computed:    true,
				Description: "Pool start mode, as observed on the host.",
			},
			"auto_start": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the pool starts automatically, as observed on the host.",
			},
			"queue_length": schema.Int64Attribute{
				Computed:    true,
				Description: "HTTP.sys request queue length, as observed on the host.",
			},
			"identity_type": schema.StringAttribute{
				Computed:    true,
				Description: "Pool identity, as observed on the host.",
			},
			"identity_username": schema.StringAttribute{
				Computed:    true,
				Description: "Account for a `SpecificUser` identity, as observed on the host.",
			},
			"load_user_profile": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether IIS loads the user profile for the pool identity, as observed on the host.",
			},
			"idle_timeout_minutes": schema.Int64Attribute{
				Computed:    true,
				Description: "Idle timeout in whole minutes, as observed on the host.",
			},
			"idle_timeout_action": schema.StringAttribute{
				Computed:    true,
				Description: "Action when the idle timeout elapses, as observed on the host.",
			},
			"max_processes": schema.Int64Attribute{
				Computed:    true,
				Description: "Maximum worker processes, as observed on the host.",
			},
			"recycling_periodic_restart_minutes": schema.Int64Attribute{
				Computed:    true,
				Description: "Periodic restart interval in whole minutes, as observed on the host.",
			},
			"recycling_schedule": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Daily recycle schedule (`HH:MM:SS` entries), as observed on the host.",
			},
			"recycling_private_memory_kb": schema.Int64Attribute{
				Computed:    true,
				Description: "Private-memory recycle threshold in kilobytes, as observed on the host.",
			},
			"rapid_fail_protection": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether rapid-fail protection is enabled, as observed on the host.",
			},
			"cpu_limit_percent": schema.Int64Attribute{
				Computed:    true,
				Description: "CPU limit in whole percent, as observed on the host.",
			},
			"cpu_action": schema.StringAttribute{
				Computed:    true,
				Description: "Action when the CPU limit is exceeded, as observed on the host.",
			},
			"state": schema.StringAttribute{
				Computed:    true,
				Description: "Runtime state of the pool (`Started` / `Stopped`), as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to iisAppPoolDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsIISAppPoolDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	d.pool = winclient.NewIISAppPoolClient(c)
}

// Read fetches the observed pool state from the remote Windows host by
// calling the sibling resource's IISAppPoolClient.Read with the configured
// name. A nil result triggers a `not found` diagnostic (data sources never
// silently clear state). Other typed *winclient.IISAppPoolError values
// surface via addIISAppPoolDiag, mirroring the resource Read path.
func (d *windowsIISAppPoolDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsIISAppPoolDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, iisAppPoolDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Name.ValueString()
	tflog.Debug(ctx, "windows_iis_app_pool data source Read start", map[string]interface{}{"name": target})

	if err := winclient.ValidateIISAppPoolName(target); err != nil {
		addIISAppPoolDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_iis_app_pool %q failed", target), err)
		return
	}

	observed, err := d.pool.Read(ctx, target)
	if err != nil {
		var ae *winclient.IISAppPoolError
		if errors.As(err, &ae) && ae.Kind == winclient.IISAppPoolErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_iis_app_pool %q", target),
				fmt.Sprintf("No IIS application pool named %q was found on the target host.", target),
			)
			return
		}
		addIISAppPoolDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_iis_app_pool %q failed", target), err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_iis_app_pool %q", target),
			fmt.Sprintf("No IIS application pool named %q was found on the target host.", target),
		)
		return
	}

	sched, dgs := types.SetValueFrom(ctx, types.StringType, nonNilStrings(observed.RecyclingSchedule))
	resp.Diagnostics.Append(dgs...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsIISAppPoolDataSourceModel{
		ID:                              types.StringValue(observed.Name),
		Name:                            types.StringValue(observed.Name),
		ManagedRuntimeVersion:           types.StringValue(observed.ManagedRuntimeVersion),
		ManagedPipelineMode:             types.StringValue(observed.ManagedPipelineMode),
		Enable32BitAppOnWin64:           types.BoolValue(observed.Enable32BitAppOnWin64),
		StartMode:                       types.StringValue(observed.StartMode),
		AutoStart:                       types.BoolValue(observed.AutoStart),
		QueueLength:                     types.Int64Value(observed.QueueLength),
		IdentityType:                    types.StringValue(observed.IdentityType),
		IdentityUsername:                types.StringValue(observed.IdentityUsername),
		LoadUserProfile:                 types.BoolValue(observed.LoadUserProfile),
		IdleTimeoutMinutes:              types.Int64Value(observed.IdleTimeoutMinutes),
		IdleTimeoutAction:               types.StringValue(observed.IdleTimeoutAction),
		MaxProcesses:                    types.Int64Value(observed.MaxProcesses),
		RecyclingPeriodicRestartMinutes: types.Int64Value(observed.RecyclingPeriodicRestartMinutes),
		RecyclingSchedule:               sched,
		RecyclingPrivateMemoryKB:        types.Int64Value(observed.RecyclingPrivateMemoryKB),
		RapidFailProtection:             types.BoolValue(observed.RapidFailProtection),
		CPULimitPercent:                 types.Int64Value(observed.CPULimitPercent),
		CPUAction:                       types.StringValue(observed.CPUAction),
		State:                           types.StringValue(observed.State),
		Timeouts:                        config.Timeouts,
	}

	tflog.Debug(ctx, "windows_iis_app_pool data source Read end", map[string]interface{}{
		"name":  state.Name.ValueString(),
		"state": state.State.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
