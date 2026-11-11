// Package provider: windows_registry_key data source implementation.
//
// Reads the value-name enumeration of a Windows registry key: the lookup
// keys are hive and path (both Required). value_names lists every value name
// (the Default value appears as ""), and values carries a name+kind summary
// per value for drift detection without purge. Full value payloads stay with
// the windows_registry_value data source. Returns an error when the key
// does not exist on the target host.
package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsRegistryKeyDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsRegistryKeyDataSource)(nil)
)

// NewWindowsRegistryKeyDataSource is the constructor registered in provider.go.
func NewWindowsRegistryKeyDataSource() datasource.DataSource {
	return &windowsRegistryKeyDataSource{}
}

// windowsRegistryKeyDataSource is the TPF data source type for
// windows_registry_key.
type windowsRegistryKeyDataSource struct {
	client winclient.RegistryKeyClient
}

// registryKeyDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block, matching the sibling resource
// default so a stalled session surfaces a timeout diagnostic instead of
// blocking plan forever (issue #197).
const registryKeyDSDefaultTimeout = 10 * time.Minute

// windowsRegistryKeyDataSourceModel is the Terraform state model for the
// windows_registry_key data source.
type windowsRegistryKeyDataSourceModel struct {
	ID         types.String     `tfsdk:"id"`
	Hive       types.String     `tfsdk:"hive"`
	Path       types.String     `tfsdk:"path"`
	ValueNames types.List       `tfsdk:"value_names"`
	Values     types.List       `tfsdk:"values"`
	Timeouts   dstimeouts.Value `tfsdk:"timeouts"`
}

// windowsRegistryKeyValueObjectType is the element type of the values list:
// one {name, type} object per value in the key.
func windowsRegistryKeyValueObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name": types.StringType,
		"type": types.StringType,
	}}
}

// Metadata sets the data source type name ("windows_registry_key").
func (d *windowsRegistryKeyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_registry_key"
}

// Schema returns the TPF schema for the windows_registry_key data source.
func (d *windowsRegistryKeyDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the value-name enumeration of a Windows registry key without managing its lifecycle.\n\n" +
			"Lookup keys: `hive` and `path` (both required).\n\n" +
			"`value_names` lists every value name (`\"\"` is the Default value); `values` adds the " +
			"registry type per name for drift detection without purge. For value payloads use the " +
			"`windows_registry_value` data source.\n\n" +
			"Returns an error when the registry key does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Composite ID: \"<HIVE>\\<PATH>\".",
			},
			"hive": schema.StringAttribute{
				Required:    true,
				Validators:  []validator.String{hiveEnumValidator{}},
				Description: "Registry hive: HKLM, HKCU, HKCR, HKU, or HKCC (case-insensitive, normalised to uppercase).",
			},
			"path": schema.StringAttribute{
				Required:    true,
				Validators:  []validator.String{registryPathValidator{}},
				Description: "Subkey path under the hive (backslash-separated, no leading/trailing backslash).",
			},
			"value_names": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Live value names enumerated in the key. The Default (unnamed) value appears as \"\".",
			},
			"values": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Value name (\"\" is the Default value).",
						},
						"type": schema.StringAttribute{
							Computed:    true,
							Description: "Registry value type: REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, REG_BINARY, or REG_NONE.",
						},
					},
				},
				Description: "Name+kind summary of every value in the key, for drift detection without purge.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to registryKeyDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the RegistryKeyClient.
func (d *windowsRegistryKeyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewRegistryKeyClient(c)
}

// Read fetches the registry key enumeration from the remote Windows host.
func (d *windowsRegistryKeyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsRegistryKeyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, registryKeyDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	hive := strings.ToUpper(config.Hive.ValueString())
	regPath := config.Path.ValueString()

	tflog.Debug(ctx, "windows_registry_key data source Read start", map[string]interface{}{
		"hive": hive,
		"path": regPath,
	})

	st, err := d.client.List(ctx, hive, regPath)
	if err != nil {
		addRKDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if st == nil || !st.Found {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_registry_key %s\\%s", hive, regPath),
			fmt.Sprintf("No registry key was found at hive=%s path=%s on the target host.", hive, regPath),
		)
		return
	}

	state := windowsRegistryKeyDataSourceModel{
		ID:       types.StringValue(rkID(hive, st.Path)),
		Hive:     types.StringValue(hive),
		Path:     types.StringValue(st.Path),
		Timeouts: config.Timeouts,
	}

	applyRKStateDS(&state, st, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_registry_key data source Read end", map[string]interface{}{
		"hive":        state.Hive.ValueString(),
		"path":        state.Path.ValueString(),
		"value_count": len(st.ValueNames),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// applyRKStateDS populates the value_names and values fields of the data
// source model from the registry key state returned by the client.
func applyRKStateDS(m *windowsRegistryKeyDataSourceModel, st *winclient.RegistryKeyState, diags *diag.Diagnostics) {
	names := st.ValueNames
	if names == nil {
		names = []string{}
	}
	nameElems := make([]attr.Value, len(names))
	for i, n := range names {
		nameElems[i] = types.StringValue(n)
	}
	nameList, d := types.ListValue(types.StringType, nameElems)
	diags.Append(d...)
	if !d.HasError() {
		m.ValueNames = nameList
	}

	objType := windowsRegistryKeyValueObjectType()
	summaries := st.Values
	if summaries == nil {
		summaries = []winclient.RegistryKeyValueSummary{}
	}
	objs := make([]attr.Value, len(summaries))
	for i, s := range summaries {
		obj, d := types.ObjectValue(objType.AttrTypes, map[string]attr.Value{
			"name": types.StringValue(s.Name),
			"type": types.StringValue(string(s.Kind)),
		})
		diags.Append(d...)
		if d.HasError() {
			return
		}
		objs[i] = obj
	}
	valList, d := types.ListValue(objType, objs)
	diags.Append(d...)
	if !d.HasError() {
		m.Values = valList
	}
}
