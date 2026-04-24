// Package provider — compile-only test stubs for windows_service.
//
// Acceptance tests (TestAccWindowsService_*) live in a follow-up KDust stage
// and require a real WinRM endpoint. This file only ensures the resource
// wires correctly with the framework types at build time.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// TestWindowsServiceResource_Metadata exercises Metadata() without any
// WinRM transport, guaranteeing the resource factory and schema compile.
func TestWindowsServiceResource_Metadata(t *testing.T) {
	t.Parallel()

	r := NewWindowsServiceResource()

	metaReq := resource.MetadataRequest{ProviderTypeName: "windows"}
	var metaResp resource.MetadataResponse
	r.Metadata(context.Background(), metaReq, &metaResp)
	if got, want := metaResp.TypeName, "windows_service"; got != want {
		t.Fatalf("TypeName = %q, want %q", got, want)
	}

	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Schema.Attributes == nil {
		t.Fatalf("schema attributes are nil")
	}
	for _, required := range []string{
		"id", "name", "binary_path", "start_type", "current_status",
	} {
		if _, ok := schemaResp.Schema.Attributes[required]; !ok {
			t.Errorf("missing schema attribute %q", required)
		}
	}
}
