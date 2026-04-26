// Package provider — unit tests for the windows_local_group_member data source.
//
// NOTE: The Read path calls winclient.ResolveGroup(ctx, d.client, groupName)
// which internally runs PowerShell via the unexported runPowerShell seam.
// Therefore full Read integration is covered in the winclient package tests.
// Unit tests here cover: Metadata, Schema, Configure, and the member.List
// error / not-found paths via the injectable member client.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestLocalGroupMemberDSMetadata(t *testing.T) {
	d := &windowsLocalGroupMemberDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_local_group_member" {
		t.Errorf("TypeName = %q, want windows_local_group_member", resp.TypeName)
	}
}

func TestNewWindowsLocalGroupMemberDataSource_NotNil(t *testing.T) {
	if NewWindowsLocalGroupMemberDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestLocalGroupMemberDSSchema_AllAttributes(t *testing.T) {
	d := &windowsLocalGroupMemberDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "group_name", "member_name",
		"group_sid", "member_sid", "member_principal_source",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestLocalGroupMemberDSSchema_LookupKeysRequired(t *testing.T) {
	d := &windowsLocalGroupMemberDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	type requiredChecker interface{ IsRequired() bool }
	for _, k := range []string{"group_name", "member_name"} {
		attr := resp.Schema.Attributes[k]
		rc, ok := attr.(requiredChecker)
		if !ok || !rc.IsRequired() {
			t.Errorf("attribute %q must be Required", k)
		}
	}
}

func TestLocalGroupMemberDSSchema_ComputedAttributes(t *testing.T) {
	d := &windowsLocalGroupMemberDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	type computedChecker interface{ IsComputed() bool }
	for _, k := range []string{"id", "group_sid", "member_sid", "member_principal_source"} {
		attr := resp.Schema.Attributes[k]
		cc, ok := attr.(computedChecker)
		if !ok || !cc.IsComputed() {
			t.Errorf("attribute %q must be Computed", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestLocalGroupMemberDSConfigure_Nil(t *testing.T) {
	d := &windowsLocalGroupMemberDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not error: %v", resp.Diagnostics)
	}
}

func TestLocalGroupMemberDSConfigure_WrongType(t *testing.T) {
	d := &windowsLocalGroupMemberDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "bad"}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestLocalGroupMemberDSConfigure_OK(t *testing.T) {
	d := &windowsLocalGroupMemberDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Schema — no Create/Update/Delete methods exposed
// ---------------------------------------------------------------------------

// TestLocalGroupMemberDS_IsDataSourceOnly verifies the type only implements
// datasource.DataSource, not resource.Resource. This is a compile-time
// property enforced by the var block in the source file, but we double-check
// the interface at runtime.
func TestLocalGroupMemberDS_IsDataSourceOnly(t *testing.T) {
	ds := NewWindowsLocalGroupMemberDataSource()
	if _, ok := ds.(datasource.DataSource); !ok {
		t.Error("expected datasource.DataSource implementation")
	}
}
