// Package provider — unit tests for the windows_local_user data source.
//
// Tests cover: Metadata, Schema, Configure, Read by name, Read by SID,
// not-found, nil result, generic error, full model mapping.
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

type fakeLocalUserClientDS struct {
	importByNameOut *winclient.UserState
	importByNameErr error
	importBySIDOut  *winclient.UserState
	importBySIDErr  error
}

func (f *fakeLocalUserClientDS) Create(_ context.Context, _ winclient.UserInput, _ string) (*winclient.UserState, error) {
	panic("Create not used in data source")
}
func (f *fakeLocalUserClientDS) Read(_ context.Context, _ string) (*winclient.UserState, error) {
	panic("Read not used in data source")
}
func (f *fakeLocalUserClientDS) Update(_ context.Context, _ string, _ winclient.UserInput) (*winclient.UserState, error) {
	panic("Update not used in data source")
}
func (f *fakeLocalUserClientDS) Rename(_ context.Context, _, _ string) error {
	panic("Rename not used in data source")
}
func (f *fakeLocalUserClientDS) SetPassword(_ context.Context, _, _ string) error {
	panic("SetPassword not used in data source")
}
func (f *fakeLocalUserClientDS) Enable(_ context.Context, _ string) error {
	panic("Enable not used in data source")
}
func (f *fakeLocalUserClientDS) Disable(_ context.Context, _ string) error {
	panic("Disable not used in data source")
}
func (f *fakeLocalUserClientDS) Delete(_ context.Context, _ string) error {
	panic("Delete not used in data source")
}
func (f *fakeLocalUserClientDS) ImportByName(_ context.Context, _ string) (*winclient.UserState, error) {
	return f.importByNameOut, f.importByNameErr
}
func (f *fakeLocalUserClientDS) ImportBySID(_ context.Context, _ string) (*winclient.UserState, error) {
	return f.importBySIDOut, f.importBySIDErr
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func localUserDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                           tftypes.String,
		"sid":                          tftypes.String,
		"name":                         tftypes.String,
		"full_name":                    tftypes.String,
		"description":                  tftypes.String,
		"enabled":                      tftypes.Bool,
		"password_never_expires":       tftypes.Bool,
		"user_may_not_change_password": tftypes.Bool,
		"account_never_expires":        tftypes.Bool,
		"account_expires":              tftypes.String,
		"last_logon":                   tftypes.String,
		"password_last_set":            tftypes.String,
		"principal_source":             tftypes.String,
	}}
}

func localUserDSConfigByName(name string) tfsdk.Config {
	d := &windowsLocalUserDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(localUserDSObjType(), map[string]tftypes.Value{
			"id":                           tftypes.NewValue(tftypes.String, nil),
			"sid":                          tftypes.NewValue(tftypes.String, nil),
			"name":                         tftypes.NewValue(tftypes.String, name),
			"full_name":                    tftypes.NewValue(tftypes.String, nil),
			"description":                  tftypes.NewValue(tftypes.String, nil),
			"enabled":                      tftypes.NewValue(tftypes.Bool, nil),
			"password_never_expires":       tftypes.NewValue(tftypes.Bool, nil),
			"user_may_not_change_password": tftypes.NewValue(tftypes.Bool, nil),
			"account_never_expires":        tftypes.NewValue(tftypes.Bool, nil),
			"account_expires":              tftypes.NewValue(tftypes.String, nil),
			"last_logon":                   tftypes.NewValue(tftypes.String, nil),
			"password_last_set":            tftypes.NewValue(tftypes.String, nil),
			"principal_source":             tftypes.NewValue(tftypes.String, nil),
		}),
	}
}

func localUserDSConfigBySID(sid string) tfsdk.Config {
	d := &windowsLocalUserDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw: tftypes.NewValue(localUserDSObjType(), map[string]tftypes.Value{
			"id":                           tftypes.NewValue(tftypes.String, nil),
			"sid":                          tftypes.NewValue(tftypes.String, sid),
			"name":                         tftypes.NewValue(tftypes.String, nil),
			"full_name":                    tftypes.NewValue(tftypes.String, nil),
			"description":                  tftypes.NewValue(tftypes.String, nil),
			"enabled":                      tftypes.NewValue(tftypes.Bool, nil),
			"password_never_expires":       tftypes.NewValue(tftypes.Bool, nil),
			"user_may_not_change_password": tftypes.NewValue(tftypes.Bool, nil),
			"account_never_expires":        tftypes.NewValue(tftypes.Bool, nil),
			"account_expires":              tftypes.NewValue(tftypes.String, nil),
			"last_logon":                   tftypes.NewValue(tftypes.String, nil),
			"password_last_set":            tftypes.NewValue(tftypes.String, nil),
			"principal_source":             tftypes.NewValue(tftypes.String, nil),
		}),
	}
}

func fakeUserState() *winclient.UserState {
	return &winclient.UserState{
		SID:                      "S-1-5-21-123-456-789-1001",
		Name:                     "jdoe",
		FullName:                 "John Doe",
		Description:              "Test user",
		Enabled:                  true,
		PasswordNeverExpires:     true,
		UserMayNotChangePassword: false,
		AccountNeverExpires:      true,
		AccountExpires:           "",
		LastLogon:                "2026-01-01T00:00:00Z",
		PasswordLastSet:          "2025-12-01T00:00:00Z",
		PrincipalSource:          "Local",
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestLocalUserDSMetadata(t *testing.T) {
	d := &windowsLocalUserDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_local_user" {
		t.Errorf("TypeName = %q, want windows_local_user", resp.TypeName)
	}
}

func TestNewWindowsLocalUserDataSource_NotNil(t *testing.T) {
	if NewWindowsLocalUserDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestLocalUserDSSchema_AllAttributes(t *testing.T) {
	d := &windowsLocalUserDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	want := []string{
		"id", "sid", "name", "full_name", "description",
		"enabled", "password_never_expires", "user_may_not_change_password",
		"account_never_expires", "account_expires", "last_logon",
		"password_last_set", "principal_source",
	}
	for _, k := range want {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema missing attribute %q", k)
		}
	}
}

func TestLocalUserDSSchema_NameAndSIDOptional(t *testing.T) {
	d := &windowsLocalUserDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	type optionalChecker interface{ IsOptional() bool }
	for _, k := range []string{"name", "sid"} {
		attr := resp.Schema.Attributes[k]
		oc, ok := attr.(optionalChecker)
		if !ok || !oc.IsOptional() {
			t.Errorf("attribute %q must be Optional (lookup key)", k)
		}
	}
}

func TestLocalUserDSSchema_NoPasswordAttributes(t *testing.T) {
	d := &windowsLocalUserDataSource{}
	resp := &datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, resp)
	for _, k := range []string{"password", "password_wo_version"} {
		if _, ok := resp.Schema.Attributes[k]; ok {
			t.Errorf("data source must NOT expose write-only attribute %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestLocalUserDSConfigure_Nil(t *testing.T) {
	d := &windowsLocalUserDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: nil}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("nil ProviderData must not error: %v", resp.Diagnostics)
	}
}

func TestLocalUserDSConfigure_WrongType(t *testing.T) {
	d := &windowsLocalUserDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 99}, resp)
	if !resp.Diagnostics.HasError() {
		t.Error("wrong type must produce error")
	}
}

func TestLocalUserDSConfigure_OK(t *testing.T) {
	d := &windowsLocalUserDataSource{}
	resp := &datasource.ConfigureResponse{}
	d.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: &winclient.Client{}}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("unexpected error: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// Read — by name
// ---------------------------------------------------------------------------

func TestLocalUserDSRead_ByName_HappyPath(t *testing.T) {
	us := fakeUserState()
	d := &windowsLocalUserDataSource{
		user: &fakeLocalUserClientDS{importByNameOut: us},
	}
	cfg := localUserDSConfigByName("jdoe")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsLocalUserDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.Name.ValueString() != "jdoe" {
		t.Errorf("Name = %q", state.Name.ValueString())
	}
	if state.SID.ValueString() != us.SID {
		t.Errorf("SID = %q", state.SID.ValueString())
	}
	if !state.Enabled.ValueBool() {
		t.Error("Enabled should be true")
	}
	if !state.PasswordNeverExpires.ValueBool() {
		t.Error("PasswordNeverExpires should be true")
	}
	if state.PrincipalSource.ValueString() != "Local" {
		t.Errorf("PrincipalSource = %q", state.PrincipalSource.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — by SID
// ---------------------------------------------------------------------------

func TestLocalUserDSRead_BySID_HappyPath(t *testing.T) {
	us := fakeUserState()
	d := &windowsLocalUserDataSource{
		user: &fakeLocalUserClientDS{importBySIDOut: us},
	}
	cfg := localUserDSConfigBySID("S-1-5-21-123-456-789-1001")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error: %v", resp.Diagnostics)
	}
	var state windowsLocalUserDataSourceModel
	resp.State.Get(context.Background(), &state)
	if state.FullName.ValueString() != "John Doe" {
		t.Errorf("FullName = %q", state.FullName.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read — not found
// ---------------------------------------------------------------------------

func TestLocalUserDSRead_NotFound(t *testing.T) {
	d := &windowsLocalUserDataSource{
		user: &fakeLocalUserClientDS{
			importByNameErr: winclient.NewLocalUserError(winclient.LocalUserErrorNotFound, "user not found", nil, nil),
		},
	}
	cfg := localUserDSConfigByName("ghost")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error for not-found user")
	}
	if !strings.Contains(resp.Diagnostics[0].Summary(), "not found") {
		t.Errorf("unexpected summary: %s", resp.Diagnostics[0].Summary())
	}
}

func TestLocalUserDSRead_NilResult(t *testing.T) {
	d := &windowsLocalUserDataSource{
		user: &fakeLocalUserClientDS{importByNameOut: nil, importByNameErr: nil},
	}
	cfg := localUserDSConfigByName("ghost")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("nil result must produce error")
	}
}

// ---------------------------------------------------------------------------
// Read — generic error
// ---------------------------------------------------------------------------

func TestLocalUserDSRead_GenericError(t *testing.T) {
	d := &windowsLocalUserDataSource{
		user: &fakeLocalUserClientDS{
			importByNameErr: errors.New("transport error"),
		},
	}
	cfg := localUserDSConfigByName("jdoe")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error from generic failure")
	}
}
