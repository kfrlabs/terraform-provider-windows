// Package provider — Terraform resource implementation for windows_service.
//
// Spec alignment: windows_service spec v7 (2026-04-24).
// Wires Create / Read / Update / Delete / ImportState on the schema defined
// in resource_windows_service_schema.go, delegating all Windows-side work to
// a winclient.WindowsServiceClient built from the provider-scoped
// *winclient.Client.
package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ecritel/terraform-provider-windows/internal/winclient"
)

// Interface assertions.
var (
	_ resource.Resource                   = (*windowsServiceResource)(nil)
	_ resource.ResourceWithImportState    = (*windowsServiceResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsServiceResource)(nil)
	_ resource.ResourceWithConfigure      = (*windowsServiceResource)(nil)
)

// NewWindowsServiceResource returns a constructor for the framework registry.
func NewWindowsServiceResource() resource.Resource {
	return &windowsServiceResource{}
}

// windowsServiceResource is the Terraform resource implementation.
type windowsServiceResource struct {
	client winclient.WindowsServiceClient
}

// Metadata sets the resource type name.
func (r *windowsServiceResource) Metadata(
	_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

// Schema delegates to the shared schema definition.
func (r *windowsServiceResource) Schema(
	_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse,
) {
	resp.Schema = windowsServiceSchemaDefinition()
}

// ConfigValidators wires EC-4 / EC-11 plan-time checks.
func (r *windowsServiceResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{serviceAccountPasswordValidator{}}
}

// Configure receives the shared *winclient.Client from the provider and
// wraps it into a typed WindowsServiceClient.
func (r *windowsServiceResource) Configure(
	_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.client = winclient.NewWindowsServiceClient(c)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// inputFromModel converts a planned/stored model into the winclient input.
// dependenciesProvided=true iff the list attribute is non-null AND non-unknown.
func (r *windowsServiceResource) inputFromModel(
	ctx context.Context, m *windowsServiceModel, resp interface{ AddError(string, string) },
) (winclient.ServiceInput, bool) {
	in := winclient.ServiceInput{
		Name:            m.Name.ValueString(),
		BinaryPath:      m.BinaryPath.ValueString(),
		DisplayName:     m.DisplayName.ValueString(),
		Description:     m.Description.ValueString(),
		StartType:       m.StartType.ValueString(),
		DesiredStatus:   m.Status.ValueString(),
		ServiceAccount:  m.ServiceAccount.ValueString(),
		ServicePassword: m.ServicePassword.ValueString(),
	}
	if !m.Dependencies.IsNull() && !m.Dependencies.IsUnknown() {
		var deps []string
		diags := m.Dependencies.ElementsAs(ctx, &deps, false)
		if diags.HasError() {
			for _, d := range diags.Errors() {
				resp.AddError(d.Summary(), d.Detail())
			}
			return in, false
		}
		if deps == nil {
			deps = []string{}
		}
		in.Dependencies = deps
	}
	return in, true
}

// applyState fills the model from the observed ServiceState. service_password
// is preserved from the caller-supplied prior value (semantic write-only).
func applyState(ctx context.Context, m *windowsServiceModel, st *winclient.ServiceState, prevPassword types.String) error {
	m.ID = types.StringValue(st.Name)
	m.Name = types.StringValue(st.Name)
	m.DisplayName = types.StringValue(st.DisplayName)
	if st.Description == "" {
		m.Description = types.StringNull()
	} else {
		m.Description = types.StringValue(st.Description)
	}
	m.BinaryPath = types.StringValue(st.BinaryPath)
	m.StartType = types.StringValue(st.StartType)
	m.CurrentStatus = types.StringValue(st.CurrentStatus)
	if st.ServiceAccount == "" {
		m.ServiceAccount = types.StringNull()
	} else {
		m.ServiceAccount = types.StringValue(st.ServiceAccount)
	}
	// service_password: ADR SS6 — never populated from Windows; keep prior.
	m.ServicePassword = prevPassword

	deps := st.Dependencies
	if deps == nil {
		deps = []string{}
	}
	lv, diags := types.ListValueFrom(ctx, types.StringType, deps)
	if diags.HasError() {
		return fmt.Errorf("encode dependencies: %v", diags)
	}
	m.Dependencies = lv
	return nil
}

// classifyAndAddError surfaces a winclient error as a framework diagnostic.
func classifyAndAddError(diags interface{ AddError(string, string) }, action string, err error) {
	var se *winclient.ServiceError
	if errors.As(err, &se) {
		diags.AddError(
			fmt.Sprintf("windows_service %s failed (%s)", action, se.Kind),
			se.Error(),
		)
		return
	}
	diags.AddError(fmt.Sprintf("windows_service %s failed", action), err.Error())
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create implements resource.Resource.
func (r *windowsServiceResource) Create(
	ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse,
) {
	var plan windowsServiceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in, ok := r.inputFromModel(ctx, &plan, &resp.Diagnostics)
	if !ok {
		return
	}

	st, err := r.client.Create(ctx, in)
	if err != nil {
		classifyAndAddError(&resp.Diagnostics, "create", err)
		return
	}

	if err := applyState(ctx, &plan, st, plan.ServicePassword); err != nil {
		resp.Diagnostics.AddError("state encoding failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read implements resource.Resource. Handles drift → RemoveResource (EC-2).
func (r *windowsServiceResource) Read(
	ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse,
) {
	var state windowsServiceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()
	if name == "" {
		name = state.ID.ValueString()
	}

	st, err := r.client.Read(ctx, name)
	if err != nil {
		// Defensive: EC-2 is already nil,nil from client, but if a typed
		// not-found leaks out, honour it.
		if errors.Is(err, winclient.ErrServiceNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		classifyAndAddError(&resp.Diagnostics, "read", err)
		return
	}
	if st == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if err := applyState(ctx, &state, st, state.ServicePassword); err != nil {
		resp.Diagnostics.AddError("state encoding failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update implements resource.Resource.
func (r *windowsServiceResource) Update(
	ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse,
) {
	var plan windowsServiceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in, ok := r.inputFromModel(ctx, &plan, &resp.Diagnostics)
	if !ok {
		return
	}

	st, err := r.client.Update(ctx, plan.Name.ValueString(), in)
	if err != nil {
		classifyAndAddError(&resp.Diagnostics, "update", err)
		return
	}

	if err := applyState(ctx, &plan, st, plan.ServicePassword); err != nil {
		resp.Diagnostics.AddError("state encoding failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete implements resource.Resource.
func (r *windowsServiceResource) Delete(
	ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse,
) {
	var state windowsServiceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.Delete(ctx, state.Name.ValueString()); err != nil {
		classifyAndAddError(&resp.Diagnostics, "delete", err)
		return
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState imports an existing service by its Windows short name. After
// import service_password is null (ADR SS6) and must be added manually to HCL.
func (r *windowsServiceResource) ImportState(
	ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
