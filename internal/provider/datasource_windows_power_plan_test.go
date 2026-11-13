// Package provider — unit tests for the windows_power_plan data source.
//
// These tests exercise the schema and Read handler without SSH. A
// fakePowerPlanDataClient backs windowsPowerPlanDataSource.pp.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// fakePowerPlanDataClient is the minimal WindowsPowerPlanClient for data
// source tests (only List is consumed).
type fakePowerPlanDataClient struct {
	listOut *winclient.PowerPlanListState
	listErr error
}

func (f *fakePowerPlanDataClient) Read(_ context.Context, _ []winclient.PowerPlanSettingKey) (*winclient.PowerPlanState, error) {
	return nil, nil
}

func (f *fakePowerPlanDataClient) Apply(_ context.Context, _ winclient.PowerPlanInput) (*winclient.PowerPlanState, error) {
	return nil, nil
}

func (f *fakePowerPlanDataClient) List(_ context.Context) (*winclient.PowerPlanListState, error) {
	return f.listOut, f.listErr
}

func (f *fakePowerPlanDataClient) Restore(_ context.Context, _ winclient.PowerPlanSnapshot) (*winclient.PowerPlanState, error) {
	return nil, nil
}

func (f *fakePowerPlanDataClient) DeletePlan(_ context.Context, _ string) error {
	return nil
}

func TestWindowsPowerPlanDataSource_Metadata(t *testing.T) {
	d := &windowsPowerPlanDataSource{}
	req := datasource.MetadataRequest{ProviderTypeName: "windows"}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), req, resp)
	if resp.TypeName != "windows_power_plan" {
		t.Errorf("TypeName = %q, want windows_power_plan", resp.TypeName)
	}
}

func TestWindowsPowerPlanDataSource_Schema(t *testing.T) {
	d := &windowsPowerPlanDataSource{}
	req := datasource.SchemaRequest{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	for _, name := range []string{"id", "plan_guid", "plan_name", "plans", "timeouts"} {
		if _, ok := resp.Schema.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
}

func ppDSPlansElemType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"guid":      tftypes.String,
		"name":      tftypes.String,
		"is_active": tftypes.Bool,
	}}
}

func ppDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":        tftypes.String,
		"plan_guid": tftypes.String,
		"plan_name": tftypes.String,
		"plans":     tftypes.List{ElementType: ppDSPlansElemType()},
		"timeouts": tftypes.Object{AttributeTypes: map[string]tftypes.Type{
			"read": tftypes.String,
		}},
	}}
}

func ppDSNullPlans() tftypes.Value {
	return tftypes.NewValue(tftypes.List{ElementType: ppDSPlansElemType()}, nil)
}

func TestWindowsPowerPlanDataSource_Read(t *testing.T) {
	d := &windowsPowerPlanDataSource{pp: &fakePowerPlanDataClient{listOut: okPowerPlanList()}}
	s := func() tfsdk.Config {
		var ds windowsPowerPlanDataSource
		req := datasource.SchemaRequest{}
		sresp := &datasource.SchemaResponse{}
		ds.Schema(context.Background(), req, sresp)
		if sresp.Diagnostics.HasError() {
			t.Fatalf("schema diagnostics: %v", sresp.Diagnostics)
		}
		return tfsdk.Config{
			Schema: sresp.Schema,
			Raw: tftypes.NewValue(ppDSObjType(), map[string]tftypes.Value{
				"id":        tftypes.NewValue(tftypes.String, nil),
				"plan_guid": tftypes.NewValue(tftypes.String, nil),
				"plan_name": tftypes.NewValue(tftypes.String, nil),
				"plans":     ppDSNullPlans(),
				"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
					"read": tftypes.String,
				}}, map[string]tftypes.Value{
					"read": tftypes.NewValue(tftypes.String, nil),
				}),
			}),
		}
	}()

	req := datasource.ReadRequest{Config: s}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: s.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var model windowsPowerPlanDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("id = %q, want machine ID", model.ID.ValueString())
	}
	if model.PlanGUID.ValueString() != winclient.PowerPlanHighPerformanceGUID {
		t.Errorf("plan_guid = %q", model.PlanGUID.ValueString())
	}
	if model.PlanName.ValueString() != "High performance" {
		t.Errorf("plan_name = %q", model.PlanName.ValueString())
	}
	var plans []struct {
		GUID     types.String `tfsdk:"guid"`
		Name     types.String `tfsdk:"name"`
		IsActive types.Bool   `tfsdk:"is_active"`
	}
	if diags := model.Plans.ElementsAs(context.Background(), &plans, false); diags.HasError() {
		t.Fatalf("plans ElementsAs: %v", diags)
	}
	if len(plans) != 2 {
		t.Fatalf("want 2 plans, got %d", len(plans))
	}
	active := 0
	for _, p := range plans {
		if p.IsActive.ValueBool() {
			active++
			if p.GUID.ValueString() != winclient.PowerPlanHighPerformanceGUID {
				t.Errorf("active plan = %q", p.GUID.ValueString())
			}
		}
	}
	if active != 1 {
		t.Errorf("want exactly 1 active plan, got %d", active)
	}
}

func TestWindowsPowerPlanDataSource_ReadError(t *testing.T) {
	d := &windowsPowerPlanDataSource{pp: &fakePowerPlanDataClient{
		listErr: winclient.NewPowerPlanError(winclient.PowerPlanErrorUnsupported, "no powercfg", nil, nil),
	}}
	var ds windowsPowerPlanDataSource
	sreq := datasource.SchemaRequest{}
	sresp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), sreq, sresp)
	if sresp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", sresp.Diagnostics)
	}
	objType := ppDSObjType()
	req := datasource.ReadRequest{Config: tfsdk.Config{
		Schema: sresp.Schema,
		Raw: tftypes.NewValue(objType, map[string]tftypes.Value{
			"id":        tftypes.NewValue(tftypes.String, nil),
			"plan_guid": tftypes.NewValue(tftypes.String, nil),
			"plan_name": tftypes.NewValue(tftypes.String, nil),
			"plans":     ppDSNullPlans(),
			"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
				"read": tftypes.String,
			}}, map[string]tftypes.Value{
				"read": tftypes.NewValue(tftypes.String, nil),
			}),
		}),
	}}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: sresp.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an unsupported diagnostic")
	}
}

func TestWindowsPowerPlanDataSource_EmptyMachineIDErrors(t *testing.T) {
	listOut := okPowerPlanList()
	listOut.MachineID = ""
	d := &windowsPowerPlanDataSource{pp: &fakePowerPlanDataClient{listOut: listOut}}
	var ds windowsPowerPlanDataSource
	sreq := datasource.SchemaRequest{}
	sresp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), sreq, sresp)
	if sresp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", sresp.Diagnostics)
	}
	objType := ppDSObjType()
	req := datasource.ReadRequest{Config: tfsdk.Config{
		Schema: sresp.Schema,
		Raw: tftypes.NewValue(objType, map[string]tftypes.Value{
			"id":        tftypes.NewValue(tftypes.String, nil),
			"plan_guid": tftypes.NewValue(tftypes.String, nil),
			"plan_name": tftypes.NewValue(tftypes.String, nil),
			"plans":     ppDSNullPlans(),
			"timeouts": tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
				"read": tftypes.String,
			}}, map[string]tftypes.Value{
				"read": tftypes.NewValue(tftypes.String, nil),
			}),
		}),
	}}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: sresp.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic when MachineGuid is missing")
	}
}

func TestWindowsPowerPlanDataSource_Configure(t *testing.T) {
	d := &windowsPowerPlanDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}

	resp = &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("wrong ProviderData type must produce error")
	}

	resp = &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}
