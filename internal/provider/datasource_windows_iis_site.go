// Package provider: windows_iis_site data source implementation.
//
// Reads the observed state of an existing IIS site by name without
// managing it. Every sibling-resource setting is exposed read-only,
// including the bindings view (protocol plus binding_information, owned
// by windows_iis_binding), plus the read-only timeouts{read} block.
package provider

import (
	"context"
	"errors"
	"fmt"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsIISSiteDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsIISSiteDataSource)(nil)
)

// NewWindowsIISSiteDataSource is the constructor registered in provider.go.
func NewWindowsIISSiteDataSource() datasource.DataSource {
	return &windowsIISSiteDataSource{}
}

// windowsIISSiteDataSource is the TPF data source type for windows_iis_site.
type windowsIISSiteDataSource struct {
	site winclient.WindowsIISSiteClient
}

// iisSiteDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. It reuses the sibling
// resource default (iisSiteDefaultTimeout) so a stalled session surfaces
// a timeout diagnostic instead of blocking plan forever.
const iisSiteDSDefaultTimeout = iisSiteDefaultTimeout

// windowsIISSiteDataSourceModel is the Terraform state model for the
// windows_iis_site data source.
type windowsIISSiteDataSourceModel struct {
	ID                       types.String     `tfsdk:"id"`
	Name                     types.String     `tfsdk:"name"`
	SiteID                   types.Int64      `tfsdk:"site_id"`
	PhysicalPath             types.String     `tfsdk:"physical_path"`
	ApplicationPool          types.String     `tfsdk:"application_pool"`
	AutoStart                types.Bool       `tfsdk:"auto_start"`
	PreloadEnabled           types.Bool       `tfsdk:"preload_enabled"`
	EnabledProtocols         types.String     `tfsdk:"enabled_protocols"`
	LogEnabled               types.Bool       `tfsdk:"log_enabled"`
	LogDirectory             types.String     `tfsdk:"log_directory"`
	LogFormat                types.String     `tfsdk:"log_format"`
	ConnectionTimeoutSeconds types.Int64      `tfsdk:"connection_timeout_seconds"`
	MaxConnections           types.Int64      `tfsdk:"max_connections"`
	Bindings                 types.List       `tfsdk:"bindings"`
	State                    types.String     `tfsdk:"state"`
	Timeouts                 dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_iis_site").
func (d *windowsIISSiteDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iis_site"
}

// Schema returns the TPF schema for the windows_iis_site data source.
func (d *windowsIISSiteDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the observed state of an existing IIS site by `name` " +
			"on a remote Windows host without managing it. Connection timeout surfaces in whole " +
			"seconds, converted server-side. The `bindings` view (`protocol` plus " +
			"`binding_information`) is read-only here and managed by " +
			"`windows_iis_binding`.\n\n" +
			"Requires IIS on the target host: install it with the `windows_feature` resource (`Web-Server`; " +
			"add `Web-Mgmt-Console` / `Web-Scripting-Tools` for the `WebAdministration` module on Server Core).\n\n" +
			"Returns an error when the site does not exist on the target host.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source identifier: the site name.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Site name on the target host.",
			},
			"site_id": schema.Int64Attribute{
				Computed:    true,
				Description: "Numeric site ID, as observed on the host.",
			},
			"physical_path": schema.StringAttribute{
				Computed:    true,
				Description: "Physical path of the site root, as observed on the host.",
			},
			"application_pool": schema.StringAttribute{
				Computed:    true,
				Description: "Application pool serving the site root, as observed on the host.",
			},
			"auto_start": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the site starts automatically, as observed on the host.",
			},
			"preload_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the site root application is preloaded, as observed on the host.",
			},
			"enabled_protocols": schema.StringAttribute{
				Computed:    true,
				Description: "Protocols the site root application listens on, as observed on the host.",
			},
			"log_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether IIS logging is enabled for the site, as observed on the host.",
			},
			"log_directory": schema.StringAttribute{
				Computed:    true,
				Description: "Directory for the site log files, as observed on the host.",
			},
			"log_format": schema.StringAttribute{
				Computed:    true,
				Description: "Log file format, as observed on the host.",
			},
			"connection_timeout_seconds": schema.Int64Attribute{
				Computed:    true,
				Description: "Connection timeout in whole seconds, as observed on the host.",
			},
			"max_connections": schema.Int64Attribute{
				Computed:    true,
				Description: "Maximum concurrent connections, as observed on the host.",
			},
			"bindings": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Observed site bindings (`protocol` plus `binding_information`).",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"protocol": schema.StringAttribute{
							Computed:    true,
							Description: "Binding protocol (e.g. `http`, `https`).",
						},
						"binding_information": schema.StringAttribute{
							Computed:    true,
							Description: "Binding information (`IP:port:hostheader`).",
						},
					},
				},
			},
			"state": schema.StringAttribute{
				Computed:    true,
				Description: "Runtime state of the site (`Started` / `Stopped`), as observed on the host.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to iisSiteDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsIISSiteDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	d.site = winclient.NewIISSiteClient(c)
}

// Read fetches the observed site state from the remote Windows host by
// calling the sibling resource's IISSiteClient.Read with the configured
// name. A nil result triggers a `not found` diagnostic (data sources
// never silently clear state). Other typed *winclient.IISSiteError values
// surface via addIISSiteDiag, mirroring the resource Read path.
func (d *windowsIISSiteDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsIISSiteDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, iisSiteDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	target := config.Name.ValueString()
	tflog.Debug(ctx, "windows_iis_site data source Read start", map[string]interface{}{"name": target})

	if err := winclient.ValidateIISSiteName(target); err != nil {
		addIISSiteDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_iis_site %q failed", target), err)
		return
	}

	observed, err := d.site.Read(ctx, target)
	if err != nil {
		var ae *winclient.IISSiteError
		if errors.As(err, &ae) && ae.Kind == winclient.IISSiteErrorNotFound {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_iis_site %q", target),
				fmt.Sprintf("No IIS site named %q was found on the target host.", target),
			)
			return
		}
		addIISSiteDiag(&resp.Diagnostics, fmt.Sprintf("Read windows_iis_site %q failed", target), err)
		return
	}
	if observed == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_iis_site %q", target),
			fmt.Sprintf("No IIS site named %q was found on the target host.", target),
		)
		return
	}

	bindings, dgs := iisSiteBindingsToModel(observed.Bindings)
	resp.Diagnostics.Append(dgs...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := windowsIISSiteDataSourceModel{
		ID:                       types.StringValue(observed.Name),
		Name:                     types.StringValue(observed.Name),
		SiteID:                   types.Int64Value(observed.SiteID),
		PhysicalPath:             types.StringValue(observed.PhysicalPath),
		ApplicationPool:          types.StringValue(observed.ApplicationPool),
		AutoStart:                types.BoolValue(observed.AutoStart),
		PreloadEnabled:           types.BoolValue(observed.PreloadEnabled),
		EnabledProtocols:         types.StringValue(observed.EnabledProtocols),
		LogEnabled:               types.BoolValue(observed.LogEnabled),
		LogDirectory:             types.StringValue(observed.LogDirectory),
		LogFormat:                types.StringValue(observed.LogFormat),
		ConnectionTimeoutSeconds: types.Int64Value(observed.ConnectionTimeoutSeconds),
		MaxConnections:           types.Int64Value(observed.MaxConnections),
		Bindings:                 bindings,
		State:                    types.StringValue(observed.State),
		Timeouts:                 config.Timeouts,
	}

	tflog.Debug(ctx, "windows_iis_site data source Read end", map[string]interface{}{
		"name":  state.Name.ValueString(),
		"state": state.State.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
