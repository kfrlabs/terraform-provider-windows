// Package provider: windows_service data source implementation.
//
// Reads the observed state of a Windows service by name without managing its
// lifecycle. Write-only and input-only attributes (status, service_password)
// are absent from this data source.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsServiceDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsServiceDataSource)(nil)
)

// NewWindowsServiceDataSource is the constructor registered in provider.go.
func NewWindowsServiceDataSource() datasource.DataSource {
	return &windowsServiceDataSource{}
}

// windowsServiceDataSource is the TPF data source type for windows_service.
type windowsServiceDataSource struct {
	client *winclient.Client
	svc    winclient.WindowsServiceClient
}

// windowsServiceDataSourceModel is the Terraform state model for the
// windows_service data source.
type windowsServiceDataSourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	DisplayName    types.String `tfsdk:"display_name"`
	Description    types.String `tfsdk:"description"`
	BinaryPath     types.String `tfsdk:"binary_path"`
	StartType      types.String `tfsdk:"start_type"`
	CurrentStatus  types.String `tfsdk:"current_status"`
	ServiceAccount types.String `tfsdk:"service_account"`
	Dependencies   types.List   `tfsdk:"dependencies"`
}

// Metadata sets the data source type name ("windows_service").
func (d *windowsServiceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

// Schema returns the TPF schema for the windows_service data source.
func (d *windowsServiceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of a Windows service without managing its lifecycle.\n\n" +
			"Write-only attributes (`status`, `service_password`) are intentionally absent.\n\n" +
			"Returns an error when the named service is not found in the Windows SCM.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; equal to the Windows short service name.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Short name of the Windows service to look up.",
			},
			"display_name": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable display name shown in services.msc.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Textual description of the service.",
			},
			"binary_path": schema.StringAttribute{
				Computed:    true,
				Description: "Full path to the service executable including any arguments.",
			},
			"start_type": schema.StringAttribute{
				Computed:    true,
				Description: "Service start mode: Automatic, AutomaticDelayedStart, Manual, or Disabled.",
			},
			"current_status": schema.StringAttribute{
				Computed:    true,
				Description: "Observed runtime state: Running, Stopped, or Paused.",
			},
			"service_account": schema.StringAttribute{
				Computed:    true,
				Description: "Account under which the service runs (e.g. LocalSystem, NT AUTHORITY\\NetworkService).",
			},
			"dependencies": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Ordered list of short service names this service depends on.",
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsServiceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = c
	d.svc = winclient.NewServiceClient(c)
}

// Read fetches the service state from the remote Windows host.
func (d *windowsServiceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsServiceDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := config.Name.ValueString()
	tflog.Debug(ctx, "windows_service data source Read start", map[string]interface{}{"name": name})

	svcState, err := d.svc.Read(ctx, name)
	if err != nil {
		if winclient.IsServiceError(err, winclient.ServiceErrorNotFound) {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_service %q", name),
				fmt.Sprintf("No Windows service named %q was found in the SCM on the target host.", name),
			)
			return
		}
		addServiceDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_service %q failed", name), err)
		return
	}
	if svcState == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_service %q", name),
			fmt.Sprintf("No Windows service named %q was found in the SCM on the target host.", name),
		)
		return
	}

	depVals := make([]attr.Value, 0, len(svcState.Dependencies))
	for _, dep := range svcState.Dependencies {
		depVals = append(depVals, types.StringValue(dep))
	}
	deps, diags := types.ListValue(types.StringType, depVals)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsServiceDataSourceModel{
		ID:             types.StringValue(svcState.Name),
		Name:           types.StringValue(svcState.Name),
		DisplayName:    types.StringValue(svcState.DisplayName),
		Description:    types.StringValue(svcState.Description),
		BinaryPath:     types.StringValue(svcState.BinaryPath),
		StartType:      types.StringValue(svcState.StartType),
		CurrentStatus:  types.StringValue(svcState.CurrentStatus),
		ServiceAccount: types.StringValue(svcState.ServiceAccount),
		Dependencies:   deps,
	}

	tflog.Debug(ctx, "windows_service data source Read end", map[string]interface{}{
		"name":           state.Name.ValueString(),
		"current_status": state.CurrentStatus.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
