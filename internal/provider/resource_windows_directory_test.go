package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func directorySchema(t *testing.T) schema.Schema {
	t.Helper()
	resp := &resource.SchemaResponse{}
	NewWindowsDirectoryResource().(*windowsDirectoryResource).Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	return resp.Schema
}

func TestWindowsDirectoryResource_Metadata(t *testing.T) {
	resp := &resource.MetadataResponse{}
	NewWindowsDirectoryResource().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_directory" {
		t.Fatalf("TypeName = %q", resp.TypeName)
	}
}

func TestWindowsDirectoryResource_SchemaShape(t *testing.T) {
	s := directorySchema(t)
	for _, name := range []string{"id", "path", "create_parents", "attributes", "recursive_delete", "last_write_time"} {
		if _, ok := s.Attributes[name]; !ok {
			t.Errorf("missing attribute %q", name)
		}
	}
	pathAttr, ok := s.Attributes["path"].(schema.StringAttribute)
	if !ok || !pathAttr.Required || len(pathAttr.PlanModifiers) == 0 {
		t.Error("path must be required and ForceNew")
	}
	for _, name := range []string{"create_parents", "recursive_delete"} {
		attr, ok := s.Attributes[name].(schema.BoolAttribute)
		if !ok || !attr.Optional || !attr.Computed || attr.Default == nil {
			t.Errorf("%s must be optional, computed and defaulted", name)
		}
	}
}
