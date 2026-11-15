// Adversarial regression tests for ImportState crash-freedom.
//
// Every resource implements ImportState, which Terraform can invoke with an
// arbitrary ID string (including "" / whitespace / NUL / newlines / overlong
// input). With an unconfigured provider (nil client) 17 resources crashed
// with a nil-pointer dereference instead of reporting a diagnostic; each now
// carries a "Provider not configured" guard after ID validation. These tests
// lock both behaviours without a Windows host.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// adversarialImportIDs exercises empty, blank, relative, NUL-bearing,
// newline-bearing, traversal, overlong and reserved-name IDs.
func adversarialImportIDs() []string {
	return []string{
		"",
		"   ",
		"relative/path",
		"C:",
		"C:\\",
		"\x00",
		"C:\x00\\evil",
		"not a path \n",
		"C:\\foo/../bar",
		"\\\\srv\\share\\..\\evil",
		strings.Repeat("a", 1024),
		"CON",
		"*",
		"a/b/c/d/e",
	}
}

// importStateUnconfigured runs ImportState on a zero-value resource (nil
// client, as if Configure never ran) and returns panics as errors.
func importStateUnconfigured(t *testing.T, r resource.ResourceWithImportState, id string) (panicked any, diags resource.ImportStateResponse) {
	t.Helper()
	ctx := context.Background()
	defer func() {
		if rec := recover(); rec != nil {
			panicked = rec
		}
	}()
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	state := tfsdk.State{Schema: &schemaResp.Schema}
	resp := &resource.ImportStateResponse{State: state}
	r.ImportState(ctx, resource.ImportStateRequest{ID: id}, resp)
	return nil, *resp
}

func TestAdversarialImportStateNeverPanicsUnconfigured(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	count := 0
	for _, ctor := range p.Resources(ctx) {
		r := ctor()
		ri, ok := r.(resource.ResourceWithImportState)
		if !ok {
			continue
		}
		mr := &resource.MetadataResponse{}
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "windows"}, mr)
		for _, id := range adversarialImportIDs() {
			panicked, _ := importStateUnconfigured(t, ri, id)
			if panicked != nil {
				t.Errorf("%s: ImportState(%q) panicked on unconfigured client: %v", mr.TypeName, id, panicked)
			}
			count++
		}
	}
	if count == 0 {
		t.Fatal("no ImportState implementations walked")
	}
	t.Logf("exercised %d import calls without a panic", count)
}

// TestAdversarialImportStateUnconfiguredClientErrors asserts that a
// well-formed ID against an unconfigured client fails closed with a
// "Provider not configured" diagnostic (instead of crashing or silently
// succeeding) for every resource that reads the host during import.
func TestAdversarialImportStateUnconfiguredClientErrors(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	byName := map[string]resource.ResourceWithImportState{}
	for _, ctor := range p.Resources(ctx) {
		r := ctor()
		ri, ok := r.(resource.ResourceWithImportState)
		if !ok {
			continue
		}
		mr := &resource.MetadataResponse{}
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "windows"}, mr)
		byName[mr.TypeName] = ri
	}
	validIDs := map[string]string{
		"windows_directory":          `C:\import-test`,
		"windows_disk":               `368687a7-0000-0000-0000-000000000000`,
		"windows_dns_client":         `Ethernet0`,
		"windows_domain_membership":  `corp.example.com`,
		"windows_eventlog":           `Application`,
		"windows_firewall_rule":      `Test-Rule`,
		"windows_iis_app_pool":       `DefaultAppPool`,
		"windows_iis_site":           `Default Web Site`,
		"windows_local_group":        `Administrators`,
		"windows_local_group_member": `Administrators/Administrator`,
		"windows_local_user":         `Administrator`,
		"windows_ntp":                `current`,
		"windows_power_plan":         `current`,
		"windows_scheduled_task":     `\Microsoft\Windows\Test`,
		"windows_smb_share":          `testshare`,
		"windows_timezone":           `current`,
		"windows_volume":             `C:`,
	}
	for typeName, id := range validIDs {
		ri, ok := byName[typeName]
		if !ok {
			t.Errorf("%s: resource missing from registry", typeName)
			continue
		}
		panicked, resp := importStateUnconfigured(t, ri, id)
		if panicked != nil {
			t.Errorf("%s: ImportState(%q) panicked: %v", typeName, id, panicked)
			continue
		}
		if !resp.Diagnostics.HasError() {
			t.Errorf("%s: ImportState(%q) with unconfigured client must fail, got success", typeName, id)
			continue
		}
		found := false
		for _, d := range resp.Diagnostics.Errors() {
			if strings.Contains(d.Summary(), "Provider not configured") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: ImportState(%q) must report 'Provider not configured', got: %v", typeName, id, resp.Diagnostics)
		}
	}
}
