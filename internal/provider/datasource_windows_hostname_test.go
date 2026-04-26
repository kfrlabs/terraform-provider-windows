// Package provider — unit tests for the windows_hostname data source.
//
// windows_hostname is a singleton: no Required lookup keys, no ExactlyOneOf.
// Tests cover: Metadata, Schema, Configure, Read happy path, Read error.
package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeHostnameClientDS struct {
	readOut *winclient.HostnameState
	readErr error
}

func (f *fakeHostnameClientDS) Create(_ context.Context, _ winclient.HostnameInput) (*winclient.HostnameState, error) {
	panic("Create not used in data source")
}
func (f *fakeHostnameClientDS) Read(_ context.Context, _ string) (*winclient.HostnameState, error) {
	return f.readOut, f.readErr
}
func (f *fakeHostnameClientDS) Update(_ context.Context, _ string, _ winclient.HostnameInput) (*winclient.HostnameState, error) {
	panic("Update not used in data source")
}
func (f *fakeHostnameClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func hostnameDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":             tftypes.String,
		"current_name":   tftypes.String,
		"pending_name":   tftypes.String,
		"reboot_pending": tftypes.Bool,
		"machine_id":     tftypes.String,
	}}
}

func hostnameDSConfig() tfsdk.Config {
	d := &windowsHostnameDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(hostnameDSObjType(), map[string]tftypes.Value{
			"id":             tftypes.NewValue(tftypes.String, nil),
			"current_name":   tftypes.NewValue(tftypes.String, nil),
			"pending_name":   tftypes.NewValue(tftypes.String, nil),
			"reboot_pending": tftypes.NewValue(tftypes.Bool, nil),
			"machine_id":     tftypes.NewValue(tftypes.String, nil),
		}),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestHostnameDSMetadata(t *testing.T) {
	d := &windowsHostnameDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_hostname" {
		t.Errorf("TypeName = %q, want windows_hostname", resp.TypeName)
	}
}

func TestNewWindowsHostnameDataSource_NotNil(t *testing.T) {
	if NewWindowsHostnameDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestHostnameDSSchema_AllAttributes(t *testing.T) {
	d := &windowsHostnameDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{"id", "current_name", "pending_name", "reboot_pending", "machine_id"}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestHostnameDSSchema_AllComputed(t *testing.T) {
	d := &windowsHostnameDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for k, attr := range resp.Schema.Attributes {
		type requiredChecker interface{ IsRequired() bool }
		rc, ok := attr.(requiredChecker)
		if ok && rc.IsRequired() {
			t.Errorf("hostname DS attribute %q is Required, but singleton DS should have no required keys", k)
		}
	}
}

func TestHostnameDSSchema_NoExtraAttributes(t *testing.T) {
	d := &windowsHostnameDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	// Singleton: 5 attributes (id + 4 computed).
	if len(resp.Schema.Attributes) != 5 {
		t.Errorf("schema has %d attributes, want 5", len(resp.Schema.Attributes))
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestHostnameDSConfigure_Nil(t *testing.T) {
	d := &windowsHostnameDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not produce error: %v", resp.Diagnostics)
	}
}

func TestHostnameDSConfigure_WrongType(t *testing.T) {
	d := &windowsHostnameDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 42}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
	if !strings.Contains(resp.Diagnostics[0].Detail(), "winclient.Client") {
		t.Errorf("error detail: %s", resp.Diagnostics[0].Detail())
	}
}

func TestHostnameDSConfigure_CorrectType(t *testing.T) {
	d := &windowsHostnameDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — happy path
// ---------------------------------------------------------------------------

func TestHostnameDSRead_HappyPath(t *testing.T) {
	d := &windowsHostnameDataSource{
		hn: &fakeHostnameClientDS{
			readOut: &winclient.HostnameState{
				CurrentName:   "WIN-SERVER01",
				PendingName:   "WIN-SERVER01",
				RebootPending: false,
				MachineID:     "abc-123-def",
			},
		},
	}
	cfg := hostnameDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}

	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected errors: %v", resp.Diagnostics)
	}
	var state windowsHostnameDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.ID.ValueString() != "current" {
		t.Errorf("ID = %q, want current", state.ID.ValueString())
	}
	if state.CurrentName.ValueString() != "WIN-SERVER01" {
		t.Errorf("CurrentName = %q", state.CurrentName.ValueString())
	}
	if state.MachineID.ValueString() != "abc-123-def" {
		t.Errorf("MachineID = %q", state.MachineID.ValueString())
	}
}

func TestHostnameDSRead_RebootPending(t *testing.T) {
	d := &windowsHostnameDataSource{
		hn: &fakeHostnameClientDS{
			readOut: &winclient.HostnameState{
				CurrentName:   "OLD-NAME",
				PendingName:   "NEW-NAME",
				RebootPending: true,
				MachineID:     "guid-123",
			},
		},
	}
	cfg := hostnameDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	var state windowsHostnameDataSourceModel
	resp.State.Get(context.Background(), &state)
	if !state.RebootPending.ValueBool() {
		t.Error("RebootPending should be true")
	}
	if state.PendingName.ValueString() != "NEW-NAME" {
		t.Errorf("PendingName = %q, want NEW-NAME", state.PendingName.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — error
// ---------------------------------------------------------------------------

func TestHostnameDSRead_Error(t *testing.T) {
	d := &windowsHostnameDataSource{
		hn: &fakeHostnameClientDS{
			readErr: errors.New("WinRM unreachable"),
		},
	}
	cfg := hostnameDSConfig()
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from read failure")
	}
}
