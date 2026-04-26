// Package provider: windows_registry_value data source implementation.
//
// Reads a single named registry value (or Default value) from a Windows
// registry key. The lookup keys are hive, path, and name (all Required).
// expand_environment_variables is Optional (affects how REG_EXPAND_SZ is read).
// The type and value fields are all Computed.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsRegistryValueDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsRegistryValueDataSource)(nil)
)

// NewWindowsRegistryValueDataSource is the constructor registered in provider.go.
func NewWindowsRegistryValueDataSource() datasource.DataSource {
	return &windowsRegistryValueDataSource{}
}

// windowsRegistryValueDataSource is the TPF data source type for
// windows_registry_value.
type windowsRegistryValueDataSource struct {
	client winclient.RegistryValueClient
}

// windowsRegistryValueDataSourceModel is the Terraform state model for the
// windows_registry_value data source.
type windowsRegistryValueDataSourceModel struct {
	ID                         types.String `tfsdk:"id"`
	Hive                       types.String `tfsdk:"hive"`
	Path                       types.String `tfsdk:"path"`
	Name                       types.String `tfsdk:"name"`
	ExpandEnvironmentVariables types.Bool   `tfsdk:"expand_environment_variables"`
	Type                       types.String `tfsdk:"type"`
	ValueString                types.String `tfsdk:"value_string"`
	ValueStrings               types.List   `tfsdk:"value_strings"`
	ValueBinary                types.String `tfsdk:"value_binary"`
}

// Metadata sets the data source type name ("windows_registry_value").
func (d *windowsRegistryValueDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_registry_value"
}

// Schema returns the TPF schema for the windows_registry_value data source.
func (d *windowsRegistryValueDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a single named Windows registry value without managing its lifecycle.\n\n" +
			"Lookup keys: `hive`, `path`, and `name` (all required; use `name = \"\"` for the Default value).\n\n" +
			"Returns an error when the registry key or value does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Composite ID: \"<HIVE>\\<PATH>\\<NAME>\". Trailing backslash when name is the Default value.",
			},
			"hive": schema.StringAttribute{
				Required:    true,
				Description: "Registry hive: HKLM, HKCU, HKCR, HKU, or HKCC (case-insensitive).",
			},
			"path": schema.StringAttribute{
				Required:    true,
				Description: "Subkey path under the hive (backslash-separated, no leading/trailing backslash).",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Value name. Use \"\" (empty string) to read the Default (unnamed) value.",
			},
			"expand_environment_variables": schema.BoolAttribute{
				Optional:    true,
				Description: "When true, Read returns expanded REG_EXPAND_SZ values. Default: false. Only relevant for type=REG_EXPAND_SZ.",
			},
			"type": schema.StringAttribute{
				Computed:    true,
				Description: "Registry value type: REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, REG_BINARY, or REG_NONE.",
			},
			"value_string": schema.StringAttribute{
				Computed:    true,
				Description: "String value for REG_SZ, REG_EXPAND_SZ, REG_DWORD (decimal uint32), REG_QWORD (decimal uint64).",
			},
			"value_strings": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Multi-string value for REG_MULTI_SZ.",
			},
			"value_binary": schema.StringAttribute{
				Computed:    true,
				Description: "Binary value for REG_BINARY/REG_NONE as a lowercase hex string.",
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the RegistryValueClient.
func (d *windowsRegistryValueDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewRegistryValueClient(c)
}

// Read fetches the registry value state from the remote Windows host.
func (d *windowsRegistryValueDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsRegistryValueDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hive := config.Hive.ValueString()
	regPath := config.Path.ValueString()
	name := config.Name.ValueString()
	expand := config.ExpandEnvironmentVariables.ValueBool()

	tflog.Debug(ctx, "windows_registry_value data source Read start", map[string]interface{}{
		"hive": hive,
		"path": regPath,
		"name": name,
	})

	rv, err := d.client.Read(ctx, hive, regPath, name, expand)
	if err != nil {
		if winclient.IsRegistryValueError(err, winclient.RegistryValueErrorNotFound) {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_registry_value %s\\%s\\%s", hive, regPath, name),
				fmt.Sprintf("No registry value named %q was found at hive=%s path=%s on the target host.", name, hive, regPath),
			)
			return
		}
		addRVDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if rv == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_registry_value %s\\%s\\%s", hive, regPath, name),
			fmt.Sprintf("No registry value named %q was found at hive=%s path=%s on the target host.", name, hive, regPath),
		)
		return
	}

	state := windowsRegistryValueDataSourceModel{
		ID:                         types.StringValue(rvID(rv.Hive, rv.Path, rv.Name)),
		Hive:                       types.StringValue(rv.Hive),
		Path:                       types.StringValue(rv.Path),
		Name:                       types.StringValue(rv.Name),
		ExpandEnvironmentVariables: config.ExpandEnvironmentVariables,
	}

	applyRVStateDS(&state, rv, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_registry_value data source Read end", map[string]interface{}{
		"hive": state.Hive.ValueString(),
		"path": state.Path.ValueString(),
		"name": state.Name.ValueString(),
		"type": state.Type.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// applyRVStateDS populates the type and value fields of the data source model
// from the registry value state returned by the client.
func applyRVStateDS(m *windowsRegistryValueDataSourceModel, rv *winclient.RegistryValueState, diags *diag.Diagnostics) {
	m.Type = types.StringValue(string(rv.Kind))

	// Reset all value fields.
	m.ValueString = types.StringNull()
	m.ValueStrings = types.ListNull(types.StringType)
	m.ValueBinary = types.StringNull()

	switch rv.Kind {
	case winclient.RegistryValueKindMultiString:
		strs := rv.ValueStrings
		if strs == nil {
			strs = []string{}
		}
		elems := make([]attr.Value, len(strs))
		for i, s := range strs {
			elems[i] = types.StringValue(s)
		}
		list, d := types.ListValue(types.StringType, elems)
		diags.Append(d...)
		if !d.HasError() {
			m.ValueStrings = list
		}

	case winclient.RegistryValueKindBinary, winclient.RegistryValueKindNone:
		hex := ""
		if rv.ValueBinary != nil {
			hex = *rv.ValueBinary
		}
		m.ValueBinary = types.StringValue(hex)

	default:
		if rv.ValueString != nil {
			m.ValueString = types.StringValue(*rv.ValueString)
		}
	}
}
