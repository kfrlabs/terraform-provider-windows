// Unit tests for issue #346: MSI verbose log keeps secrets in clear text.
//
// Covers the provider-side contract:
//
//   - install_args_wo is Optional+Sensitive+WriteOnly with a RequiresReplace
//     plan modifier; install_args_wo_version is Optional with AtLeast(1).
//   - keep_log is Optional+Computed and defaults to false (secure default).
//   - effectiveLegacyPackageInstallArgsWO prefers the config model (WriteOnly
//     values are null in the plan handed to ApplyResourceChange).
//   - modelToInput forwards keep_log; Delete threads the uninstall settings
//     from state into the client input so the uninstall log honors keep_log.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func lpSchemaForSecretTest(t *testing.T) schema.Schema {
	t.Helper()
	r := &windowsLegacyPackageResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	return resp.Schema
}

func TestLegacyPackageSecret_WriteOnlySchemaFlags(t *testing.T) {
	s := lpSchemaForSecretTest(t)

	wo, ok := s.Attributes["install_args_wo"].(schema.ListAttribute)
	if !ok {
		t.Fatal("install_args_wo must be a ListAttribute")
	}
	if !wo.Optional || !wo.Sensitive || !wo.WriteOnly {
		t.Errorf("install_args_wo must be Optional+Sensitive+WriteOnly, got optional=%v sensitive=%v writeOnly=%v",
			wo.Optional, wo.Sensitive, wo.WriteOnly)
	}
	if wo.Computed {
		t.Error("install_args_wo must not be Computed")
	}
	if len(wo.PlanModifiers) == 0 {
		t.Error("install_args_wo must carry a RequiresReplace plan modifier")
	}

	ver, ok := s.Attributes["install_args_wo_version"].(schema.Int64Attribute)
	if !ok {
		t.Fatal("install_args_wo_version must be an Int64Attribute")
	}
	if !ver.Optional {
		t.Error("install_args_wo_version must be Optional")
	}
	if len(ver.PlanModifiers) == 0 {
		t.Error("install_args_wo_version must carry a RequiresReplace plan modifier")
	}
}

func TestLegacyPackageSecret_KeepLogDefault(t *testing.T) {
	s := lpSchemaForSecretTest(t)

	keep, ok := s.Attributes["keep_log"].(schema.BoolAttribute)
	if !ok {
		t.Fatal("keep_log must be a BoolAttribute")
	}
	if !keep.Optional || !keep.Computed {
		t.Errorf("keep_log must be Optional+Computed, got optional=%v computed=%v", keep.Optional, keep.Computed)
	}
	if keep.Default == nil {
		t.Fatal("keep_log must have a default (secure default false)")
	}
}

func TestEffectiveLegacyPackageInstallArgsWO_ConfigPrecedence(t *testing.T) {
	ctx := context.Background()
	mkList := func(t *testing.T, vals ...string) types.List {
		t.Helper()
		v, diags := types.ListValueFrom(ctx, types.StringType, vals)
		if diags.HasError() {
			t.Fatalf("ListValueFrom: %v", diags)
		}
		return v
	}

	// Config wins when both are set (plan is null for WriteOnly at apply).
	got, diags := effectiveLegacyPackageInstallArgsWO(ctx,
		windowsLegacyPackageModel{InstallArgsWO: mkList(t, "PLAN=p")},
		windowsLegacyPackageModel{InstallArgsWO: mkList(t, "SERVICEPASSWORD=s3cret")},
	)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if len(got) != 1 || got[0] != "SERVICEPASSWORD=s3cret" {
		t.Errorf("config precedence: got %v", got)
	}

	// Plan fallback for callers bypassing Config (unit tests driving Plan).
	got, diags = effectiveLegacyPackageInstallArgsWO(ctx,
		windowsLegacyPackageModel{InstallArgsWO: mkList(t, "PLAN=p")},
		windowsLegacyPackageModel{},
	)
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if len(got) != 1 || got[0] != "PLAN=p" {
		t.Errorf("plan fallback: got %v", got)
	}

	// Empty reports unset.
	got, diags = effectiveLegacyPackageInstallArgsWO(ctx, windowsLegacyPackageModel{}, windowsLegacyPackageModel{})
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if len(got) != 0 {
		t.Errorf("empty must report unset, got %v", got)
	}
}

func TestModelToInput_ForwardsKeepLog(t *testing.T) {
	r := &windowsLegacyPackageResource{}
	in, diags := r.modelToInput(context.Background(), windowsLegacyPackageModel{
		Name:          types.StringValue("pkg"),
		InstallerType: types.StringValue("msi"),
		KeepLog:       types.BoolValue(true),
	})
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if !in.KeepLog {
		t.Error("modelToInput must forward keep_log=true")
	}
	in, diags = r.modelToInput(context.Background(), windowsLegacyPackageModel{
		Name:          types.StringValue("pkg"),
		InstallerType: types.StringValue("msi"),
	})
	if diags.HasError() {
		t.Fatalf("diags: %v", diags)
	}
	if in.KeepLog {
		t.Error("modelToInput must default keep_log to false when null")
	}
}

// captureLPClient records the Delete input so tests can assert the resource
// layer threads the uninstall settings from state.
type captureLPClient struct {
	fakeLPClient
	deleteInput winclient.LegacyPackageInput
	deleteID    string
}

func (f *captureLPClient) Delete(_ context.Context, id string, in winclient.LegacyPackageInput) error {
	f.deleteID = id
	f.deleteInput = in
	return nil
}

func TestLegacyPackageDelete_ThreadsUninstallSettings(t *testing.T) {
	ctx := context.Background()
	r := &windowsLegacyPackageResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)

	str := tftypes.String
	b := tftypes.Bool
	num := tftypes.Number
	raw := lpStateWith(map[string]tftypes.Value{
		"id":             tftypes.NewValue(str, "{01234567-89AB-CDEF-0123-456789ABCDEF}"),
		"installer_type": tftypes.NewValue(str, "msi"),
		"uninstall_args": tftypes.NewValue(tftypes.List{ElementType: str},
			[]tftypes.Value{tftypes.NewValue(str, "/quiet")}),
		"keep_log":        tftypes.NewValue(b, true),
		"timeout_seconds": tftypes.NewValue(num, 60),
	})

	capClient := &captureLPClient{}
	r.lp = capClient
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: raw},
	}
	r.Delete(ctx, resource.DeleteRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: raw},
	}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete diags: %v", resp.Diagnostics)
	}
	if capClient.deleteID != "{01234567-89AB-CDEF-0123-456789ABCDEF}" {
		t.Errorf("delete id = %q", capClient.deleteID)
	}
	if len(capClient.deleteInput.UninstallArgs) != 1 || capClient.deleteInput.UninstallArgs[0] != "/quiet" {
		t.Errorf("delete uninstall_args = %v, want [/quiet]", capClient.deleteInput.UninstallArgs)
	}
	if !capClient.deleteInput.KeepLog {
		t.Error("delete input must carry keep_log=true from state")
	}
	if capClient.deleteInput.TimeoutSeconds != 60 {
		t.Errorf("delete timeout_seconds = %d, want 60", capClient.deleteInput.TimeoutSeconds)
	}
}
