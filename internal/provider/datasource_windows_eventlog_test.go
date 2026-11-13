// Package provider — unit tests for the windows_eventlog data source.
//
// Tests cover: Metadata, Schema (query key, computed attributes, no
// declarative inputs), Configure, Read happy path (incl. modern channels
// and the LogMode mapping), not-found (typed and nil), generic error,
// and timeouts.read default resolution.
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

type fakeEventLogClientDS struct {
	readOut  *winclient.EventLogState
	readErr  error
	readName string

	deadline time.Time
	ok       bool
}

func (f *fakeEventLogClientDS) Read(ctx context.Context, name string) (*winclient.EventLogState, error) {
	f.readName = name
	f.deadline, f.ok = ctx.Deadline()
	return f.readOut, f.readErr
}

func (f *fakeEventLogClientDS) Apply(_ context.Context, _ string, _ winclient.EventLogSettings) (*winclient.EventLogState, error) {
	panic("Apply not used in data source")
}

func (f *fakeEventLogClientDS) Restore(_ context.Context, _ winclient.EventLogState) (*winclient.EventLogState, error) {
	panic("Restore not used in data source")
}

// ---------------------------------------------------------------------------
// tftypes helpers
// ---------------------------------------------------------------------------

func elDSObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"id":                 tftypes.String,
		"name":               tftypes.String,
		"maximum_size_bytes": tftypes.Number,
		"retention":          tftypes.String,
		"enabled":            tftypes.Bool,
		"log_file_path":      tftypes.String,
		"log_type":           tftypes.String,
		"is_classic_log":     tftypes.Bool,
		"record_count":       tftypes.Number,
		"file_size_bytes":    tftypes.Number,
		"policy_override":    tftypes.Bool,
		"timeouts":           dsTimeoutsObjType(),
	}}
}

func elDSConfig(name string) tfsdk.Config {
	d := &windowsEventLogDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	vals := map[string]tftypes.Value{}
	for k, t := range elDSObjType().AttributeTypes {
		if k == "name" {
			vals[k] = tftypes.NewValue(t, name)
			continue
		}
		if k == "timeouts" {
			vals[k] = dsNullTimeoutsValue()
			continue
		}
		vals[k] = tftypes.NewValue(t, nil)
	}
	return tfsdk.Config{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(elDSObjType(), vals),
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestEventLogDSMetadata(t *testing.T) {
	d := &windowsEventLogDataSource{}
	resp := &datasource.MetadataResponse{}
	d.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_eventlog" {
		t.Errorf("TypeName = %q, want windows_eventlog", resp.TypeName)
	}
}

func TestNewWindowsEventLogDataSource_NotNil(t *testing.T) {
	if NewWindowsEventLogDataSource() == nil {
		t.Fatal("constructor must not return nil")
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestEventLogDSSchema(t *testing.T) {
	d := &windowsEventLogDataSource{}
	sr := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &sr)
	for _, name := range []string{
		"id", "name", "maximum_size_bytes", "retention", "enabled",
		"log_file_path", "log_type", "is_classic_log", "record_count",
		"file_size_bytes", "policy_override", "timeouts",
	} {
		if _, ok := sr.Schema.Attributes[name]; !ok {
			t.Errorf("schema missing attribute %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func TestEventLogDSConfigure(t *testing.T) {
	d := &windowsEventLogDataSource{}
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

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestEventLogDSRead_HappyPath(t *testing.T) {
	fc := &fakeEventLogClientDS{readOut: okModernEventLogState("Microsoft-Windows-PowerShell/Operational")}
	d := &windowsEventLogDataSource{el: fc}

	cfg := elDSConfig("Microsoft-Windows-PowerShell/Operational")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	if fc.readName != "Microsoft-Windows-PowerShell/Operational" {
		t.Errorf("read name = %q, want the literal channel name", fc.readName)
	}
	var model windowsEventLogDataSourceModel
	resp.Diagnostics.Append(resp.State.Get(context.Background(), &model)...)
	if model.ID.ValueString() != "Microsoft-Windows-PowerShell/Operational" {
		t.Errorf("id = %q, want the log name", model.ID.ValueString())
	}
	if model.LogType.ValueString() != "Operational" || model.IsClassicLog.ValueBool() {
		t.Errorf("unexpected type/classic: %q/%v", model.LogType.ValueString(), model.IsClassicLog.ValueBool())
	}
	if model.Retention.ValueString() != "overwrite" {
		t.Errorf("Circular must project to overwrite, got %q", model.Retention.ValueString())
	}
	if model.RecordCount.ValueInt64() != 42 || model.FileSizeBytes.ValueInt64() != 69632 {
		t.Errorf("unexpected counters: %d/%d", model.RecordCount.ValueInt64(), model.FileSizeBytes.ValueInt64())
	}
}

func TestEventLogDSRead_NotFound(t *testing.T) {
	cfg := elDSConfig("NoSuchLog")
	// Nil result.
	d := &windowsEventLogDataSource{el: &fakeEventLogClientDS{readOut: nil}}
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("missing log must error (data sources never clear state)")
	}

	// Typed not_found.
	d2 := &windowsEventLogDataSource{el: &fakeEventLogClientDS{
		readErr: winclient.NewEventLogError(winclient.EventLogErrorNotFound, "gone", nil, nil),
	}}
	resp2 := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d2.Read(context.Background(), req, resp2)
	if !resp2.Diagnostics.HasError() {
		t.Fatal("typed not_found must error")
	}
}

func TestEventLogDSRead_GenericError(t *testing.T) {
	cfg := elDSConfig("Security")
	d := &windowsEventLogDataSource{el: &fakeEventLogClientDS{
		readErr: winclient.NewEventLogError(winclient.EventLogErrorAccessDenied, "denied", nil, nil),
	}}
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic")
	}
}

func TestEventLogDSRead_TimeoutBounded(t *testing.T) {
	fc := &fakeEventLogClientDS{readOut: okEventLogState("Application")}
	d := &windowsEventLogDataSource{el: fc}

	cfg := elDSConfig("Application")
	req := datasource.ReadRequest{Config: cfg}
	resp := &datasource.ReadResponse{State: tfsdk.State{Schema: cfg.Schema}}
	d.Read(context.Background(), req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", elDiagSummaries(resp.Diagnostics))
	}
	if !fc.ok {
		t.Fatal("data source Read must bound the call with a timeout context")
	}
	if time.Until(fc.deadline) > eventLogDSDefaultTimeout+time.Minute {
		t.Errorf("deadline %v exceeds the 5m default", fc.deadline)
	}
}
