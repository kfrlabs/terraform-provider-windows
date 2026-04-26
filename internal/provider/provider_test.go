// Package provider — unit tests for the provider entrypoint (provider.go).
//
// These tests exercise Metadata, Schema, Resources, DataSources, pathAttr and
// the Configure handler. Configure is driven with a tfsdk.Config built from a
// tftypes.Value to cover both error paths (missing credentials, invalid
// timeout) and the happy path (a fully populated config that constructs a
// *winclient.Client).
package provider

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestProvider_New(t *testing.T) {
	ctor := New("test-version")
	if ctor == nil {
		t.Fatal("New returned nil constructor")
	}
	p := ctor()
	if p == nil {
		t.Fatal("constructor returned nil provider")
	}
}

func TestProvider_Metadata(t *testing.T) {
	p := &windowsProvider{version: "v0"}
	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)
	if resp.TypeName != "windows" {
		t.Errorf("TypeName = %q", resp.TypeName)
	}
	if resp.Version != "v0" {
		t.Errorf("Version = %q", resp.Version)
	}
}

func TestProvider_Schema(t *testing.T) {
	p := &windowsProvider{}
	resp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, resp)
	for _, k := range []string{"host", "port", "username", "password", "use_https", "insecure", "auth_type", "timeout"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("provider schema missing %q", k)
		}
	}
}

func TestProvider_ResourcesAndDataSources(t *testing.T) {
	p := &windowsProvider{}
	if got := len(p.Resources(context.Background())); got != 7 {
		t.Errorf("Resources len = %d, want 7 (service + feature + hostname + local_group + local_group_member + local_user + registry_value)", got)
	}
	if got := len(p.DataSources(context.Background())); got != 7 {
		t.Errorf("DataSources len = %d, want 7 (feature + hostname + local_group + local_group_member + local_user + registry_value + service)", got)
	}
}

func TestPathAttr(t *testing.T) {
	if p := pathAttr("host"); p.String() == "" {
		t.Error("pathAttr should produce a non-empty Path")
	}
}

// providerConfigObjectType matches the provider schema.
func providerConfigObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"host":      tftypes.String,
		"port":      tftypes.Number,
		"username":  tftypes.String,
		"password":  tftypes.String,
		"use_https": tftypes.Bool,
		"insecure":  tftypes.Bool,
		"auth_type": tftypes.String,
		"timeout":   tftypes.String,
	}}
}

func providerCfgValue(host, user, pass, timeout *string) tftypes.Value {
	s := func(p *string) tftypes.Value {
		if p == nil {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, *p)
	}
	return tftypes.NewValue(providerConfigObjectType(), map[string]tftypes.Value{
		"host":      s(host),
		"port":      tftypes.NewValue(tftypes.Number, nil),
		"username":  s(user),
		"password":  s(pass),
		"use_https": tftypes.NewValue(tftypes.Bool, nil),
		"insecure":  tftypes.NewValue(tftypes.Bool, nil),
		"auth_type": tftypes.NewValue(tftypes.String, nil),
		"timeout":   s(timeout),
	})
}

// TestProvider_Configure_HappyPath covers the full success path: config has
// host/username/password/timeout populated; the response gets a non-nil
// ResourceData (our *winclient.Client).
func TestProvider_Configure_HappyPath(t *testing.T) {
	// Avoid env-var bleed.
	os.Unsetenv("WINDOWS_HOST")
	os.Unsetenv("WINDOWS_USERNAME")
	os.Unsetenv("WINDOWS_PASSWORD")

	p := &windowsProvider{}
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)

	h, u, pw, to := "10.0.0.1", "admin", "secret", "15s"
	cfg := tfsdk.Config{Schema: schemaResp.Schema, Raw: providerCfgValue(&h, &u, &pw, &to)}
	req := provider.ConfigureRequest{Config: cfg}
	resp := &provider.ConfigureResponse{}
	p.Configure(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if resp.ResourceData == nil || resp.DataSourceData == nil {
		t.Error("Configure should populate ResourceData and DataSourceData")
	}
}

func TestProvider_Configure_MissingCredentials(t *testing.T) {
	os.Unsetenv("WINDOWS_HOST")
	os.Unsetenv("WINDOWS_USERNAME")
	os.Unsetenv("WINDOWS_PASSWORD")

	p := &windowsProvider{}
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)

	cfg := tfsdk.Config{Schema: schemaResp.Schema, Raw: providerCfgValue(nil, nil, nil, nil)}
	resp := &provider.ConfigureResponse{}
	p.Configure(context.Background(), provider.ConfigureRequest{Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diags for missing host/user/password")
	}
}

func TestProvider_Configure_InvalidTimeout(t *testing.T) {
	os.Unsetenv("WINDOWS_HOST")
	os.Unsetenv("WINDOWS_USERNAME")
	os.Unsetenv("WINDOWS_PASSWORD")

	p := &windowsProvider{}
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)

	h, u, pw, to := "x", "u", "p", "not-a-duration"
	cfg := tfsdk.Config{Schema: schemaResp.Schema, Raw: providerCfgValue(&h, &u, &pw, &to)}
	resp := &provider.ConfigureResponse{}
	p.Configure(context.Background(), provider.ConfigureRequest{Config: cfg}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag for invalid timeout")
	}
}
