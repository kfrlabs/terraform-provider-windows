// Package provider: windows_environment_variable data source implementation.
//
// Reads a single Windows environment variable by scope and name. Returns the
// stored value verbatim (unexpanded) and the registry kind (expand).
// Returns a Terraform error if the variable does not exist.
//
// Spec alignment: windows_environment_variable spec v1 (2026-04-26).
package provider

import (
	"context"
	"fmt"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsEnvVarDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsEnvVarDataSource)(nil)
)

// NewWindowsEnvironmentVariableDataSource is the constructor registered in provider.go.
func NewWindowsEnvironmentVariableDataSource() datasource.DataSource {
	return &windowsEnvVarDataSource{}
}

// windowsEnvVarDataSource is the TPF data source type for windows_environment_variable.
type windowsEnvVarDataSource struct {
	client winclient.EnvVarClient
}

// Metadata sets the data source type name ("windows_environment_variable").
func (d *windowsEnvVarDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment_variable"
}

// envVarDSDefaultTimeout bounds the data source Read when the configuration
// omits the `timeouts` block, matching the sibling resource default so a
// stalled session surfaces a timeout diagnostic instead of blocking plan
// forever (issue #197).
const envVarDSDefaultTimeout = 10 * time.Minute

// windowsEnvVarDataSourceModel is the Terraform state/config model for the
// windows_environment_variable data source.
type windowsEnvVarDataSourceModel struct {
	ID       types.String     `tfsdk:"id"`
	Name     types.String     `tfsdk:"name"`
	Value    types.String     `tfsdk:"value"`
	Scope    types.String     `tfsdk:"scope"`
	Expand   types.Bool       `tfsdk:"expand"`
	Timeouts dstimeouts.Value `tfsdk:"timeouts"`
}

// Schema returns the TPF schema for the windows_environment_variable data source.
func (d *windowsEnvVarDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a single Windows environment variable (`machine` or `user` scope) " +
			"from a remote host via SSH + PowerShell. Returns the stored value verbatim " +
			"(unexpanded) and the registry kind (`expand`). " +
			"Returns a Terraform error if the variable does not exist.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Composite ID `\"<scope>:<name>\"`. Populated by the provider.",
			},
			"name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					envVarNameValidator{},
				},
				MarkdownDescription: "Windows environment variable name to look up.",
			},
			"value": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Verbatim value as stored in the registry (unexpanded `%VAR%` tokens).",
			},
			"scope": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("machine", "user"),
				},
				MarkdownDescription: "Scope to look up: `\"machine\"` or `\"user\"`.",
			},
			"expand": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "`true` when the registry value kind is `REG_EXPAND_SZ`; `false` when `REG_SZ`.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to envVarDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the EnvVarClient.
func (d *windowsEnvVarDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewEnvVarClient(c)
}

// Read fetches the environment variable state from the remote Windows host.
//
// Returns a Terraform error (not a silent no-op) when the variable does not
// exist, because a data source that silently succeeds for a missing variable
// would create phantom data.
func (d *windowsEnvVarDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsEnvVarDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, envVarDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	scope := winclient.EnvVarScope(config.Scope.ValueString())
	name := config.Name.ValueString()

	tflog.Debug(ctx, "windows_environment_variable data source Read", map[string]interface{}{
		"scope": string(scope),
		"name":  name,
	})

	evState, err := d.client.Read(ctx, scope, name)
	if err != nil {
		addEnvVarDiag(&resp.Diagnostics, "data source Read", err)
		return
	}
	if evState == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_environment_variable %s:%s", string(scope), name),
			fmt.Sprintf(
				"Environment variable %q (scope=%q) does not exist on the target host.",
				name, string(scope),
			),
		)
		return
	}

	state := windowsEnvVarDataSourceModel{
		ID:       types.StringValue(envVarID(scope, name)),
		Scope:    config.Scope,
		Name:     config.Name,
		Value:    types.StringValue(evState.Value),
		Expand:   types.BoolValue(evState.Expand),
		Timeouts: config.Timeouts,
	}

	tflog.Debug(ctx, "windows_environment_variable data source Read end", map[string]interface{}{
		"id":     state.ID.ValueString(),
		"expand": state.Expand.ValueBool(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
