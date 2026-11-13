// Package provider: windows_power_plan data source implementation.
//
// Singleton data source — no lookup keys. Reads the active power plan of
// the remote Windows host (resolved GUID, localised name and the full
// list of known plans).
package provider

import (
	"context"
	"fmt"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsPowerPlanDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsPowerPlanDataSource)(nil)
)

// NewWindowsPowerPlanDataSource is the constructor registered in
// provider.go.
func NewWindowsPowerPlanDataSource() datasource.DataSource {
	return &windowsPowerPlanDataSource{}
}

// windowsPowerPlanDataSource is the TPF data source type for
// windows_power_plan.
type windowsPowerPlanDataSource struct {
	pp winclient.WindowsPowerPlanClient
}

// powerPlanDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block, matching the sibling resource
// default so a stalled session surfaces a timeout diagnostic instead of
// blocking plan forever.
const powerPlanDSDefaultTimeout = powerPlanDefaultTimeout

// windowsPowerPlanDataSourceModel is the Terraform state model for the
// windows_power_plan data source.
type windowsPowerPlanDataSourceModel struct {
	ID       types.String     `tfsdk:"id"`
	PlanGUID types.String     `tfsdk:"plan_guid"`
	PlanName types.String     `tfsdk:"plan_name"`
	Plans    types.List       `tfsdk:"plans"`
	Timeouts dstimeouts.Value `tfsdk:"timeouts"`
}

// powerPlanInfoElementAttrTypes returns the attribute types of one plans
// list element.
func powerPlanInfoElementAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"guid":      types.StringType,
		"name":      types.StringType,
		"is_active": types.BoolType,
	}
}

// Metadata sets the data source type name ("windows_power_plan").
func (d *windowsPowerPlanDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_power_plan"
}

// Schema returns the TPF schema for the windows_power_plan data source.
func (d *windowsPowerPlanDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the active power plan of the remote Windows host without " +
			"managing it. This is a **singleton** data source — no lookup keys are required.\n\n" +
			"Exposes the active plan's resolved `plan_guid` and its localised `plan_name` (informational only), " +
			"plus the full `plans` list (`guid`, `name`, `is_active`). Plan identity is GUID-only everywhere: " +
			"names are localised and never used for matching.\n\n" +
			"The Terraform data source ID is the stable `machine_id` (HKLM MachineGuid).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; the stable machine ID (HKLM MachineGuid).",
			},
			"plan_guid": schema.StringAttribute{
				Computed:            true,
				Description:         "Resolved GUID of the active power plan as observed on the host.",
				MarkdownDescription: "Resolved GUID of the active power plan as observed on the host.",
			},
			"plan_name": schema.StringAttribute{
				Computed:            true,
				Description:         "Localised display name (ElementName) of the active power plan. Informational only.",
				MarkdownDescription: "Localised display name (`ElementName`) of the active power plan. Informational only.",
			},
			"plans": schema.ListNestedAttribute{
				Computed:            true,
				Description:         "Every power plan known to the host, in host order (guid, name, is_active).",
				MarkdownDescription: "Every power plan known to the host, in host order (`guid`, `name`, `is_active`).",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"guid": schema.StringAttribute{
							Computed:            true,
							Description:         "Plan GUID as observed on the host.",
							MarkdownDescription: "Plan GUID as observed on the host.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							Description:         "Localised display name (ElementName). Informational only.",
							MarkdownDescription: "Localised display name (`ElementName`). Informational only.",
						},
						"is_active": schema.BoolAttribute{
							Computed:            true,
							Description:         "Whether this plan is the active plan.",
							MarkdownDescription: "Whether this plan is the active plan.",
						},
					},
				},
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever. Absent
			// configuration falls back to powerPlanDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsPowerPlanDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.pp = winclient.NewPowerPlanClient(c)
}

// Read fetches the active power plan and the plan list from the remote
// Windows host.
func (d *windowsPowerPlanDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsPowerPlanDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, powerPlanDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	tflog.Debug(ctx, "windows_power_plan data source Read start")

	live, err := d.pp.List(ctx)
	if err != nil {
		addPowerPlanDiag(&resp.Diagnostics, "Read windows_power_plan data source failed", err)
		return
	}

	// The ID is the stable machine ID. MachineGuid should always be
	// present; an unreadable value is an error, never a placeholder ID.
	if live.MachineID == "" {
		resp.Diagnostics.AddError(
			"Read windows_power_plan data source failed",
			"The host did not report a MachineGuid (HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid), so the stable singleton ID cannot be determined. Verify the host is reachable and the MachineGuid value is readable, then retry.",
		)
		return
	}
	id := live.MachineID

	elemType := types.ObjectType{AttrTypes: powerPlanInfoElementAttrTypes()}
	vals := make([]attr.Value, 0, len(live.Plans))
	for _, p := range live.Plans {
		obj, dg := types.ObjectValue(powerPlanInfoElementAttrTypes(), map[string]attr.Value{
			"guid":      types.StringValue(p.GUID),
			"name":      types.StringValue(p.Name),
			"is_active": types.BoolValue(p.IsActive),
		})
		resp.Diagnostics.Append(dg...)
		vals = append(vals, obj)
	}
	plans, dg := types.ListValue(elemType, vals)
	resp.Diagnostics.Append(dg...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsPowerPlanDataSourceModel{
		ID:       types.StringValue(id),
		PlanGUID: types.StringValue(live.ActivePlanGUID),
		PlanName: types.StringValue(live.ActivePlanName),
		Plans:    plans,
		Timeouts: config.Timeouts,
	}

	tflog.Debug(ctx, "windows_power_plan data source Read end", map[string]interface{}{
		"plan_guid": state.PlanGUID.ValueString(),
		"id":        state.ID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
