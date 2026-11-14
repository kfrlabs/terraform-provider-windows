// Package provider: windows_installed_software data source implementation.
//
// Standalone collection data source — no sibling resource exists. Reads the
// installed software inventory of the remote Windows host (the Uninstall
// registry hives shared with windows_legacy_package, plus the loaded
// per-user hives on request) in a single round-trip, narrowed by optional
// filters (name_regex, publisher_regex, product_code, include flags). The
// result is a sorted `packages` list plus a `skipped_entries` count; an
// empty inventory match is valid (empty list, never an error).
//
// Filter inputs are Optional only (null means unfiltered; there is no
// framework bool default, so a null bool reads as false). `timeouts.read`
// defaults to 10m like the other collection-family data sources.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsInstalledSoftwareDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsInstalledSoftwareDataSource)(nil)
)

// NewWindowsInstalledSoftwareDataSource is the constructor registered in
// provider.go.
func NewWindowsInstalledSoftwareDataSource() datasource.DataSource {
	return &windowsInstalledSoftwareDataSource{}
}

// windowsInstalledSoftwareDataSource is the TPF data source type for
// windows_installed_software.
type windowsInstalledSoftwareDataSource struct {
	client winclient.WindowsInstalledSoftwareClient
}

// installedSoftwareDSDefaultTimeout bounds the data source Read when the
// configuration omits the `timeouts` block. There is no sibling resource to
// reuse a default from, so it uses 10m like the other collection-family
// (network_adapters) data sources, so a stalled session surfaces a timeout
// diagnostic instead of blocking plan forever.
const installedSoftwareDSDefaultTimeout = 10 * time.Minute

// windowsInstalledSoftwareDataSourceModel is the Terraform state model for
// the windows_installed_software data source.
type windowsInstalledSoftwareDataSourceModel struct {
	ID                      types.String     `tfsdk:"id"`
	NameRegex               types.String     `tfsdk:"name_regex"`
	PublisherRegex          types.String     `tfsdk:"publisher_regex"`
	ProductCode             types.String     `tfsdk:"product_code"`
	IncludeSystemComponents types.Bool       `tfsdk:"include_system_components"`
	IncludeUpdates          types.Bool       `tfsdk:"include_updates"`
	IncludeUserInstalls     types.Bool       `tfsdk:"include_user_installs"`
	Packages                types.List       `tfsdk:"packages"`
	SkippedEntries          types.Int64      `tfsdk:"skipped_entries"`
	Timeouts                dstimeouts.Value `tfsdk:"timeouts"`
}

// windowsInstalledSoftwareObjectType is the element type of the packages
// list: one object per matching installed package.
func windowsInstalledSoftwareObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":                   types.StringType,
		"version":                types.StringType,
		"publisher":              types.StringType,
		"install_date":           types.StringType,
		"install_location":       types.StringType,
		"product_code":           types.StringType,
		"is_msi":                 types.BoolType,
		"architecture":           types.StringType,
		"scope":                  types.StringType,
		"user_sid":               types.StringType,
		"estimated_size_kb":      types.Int64Type,
		"uninstall_string":       types.StringType,
		"quiet_uninstall_string": types.StringType,
		"registry_key":           types.StringType,
	}}
}

// Metadata sets the data source type name ("windows_installed_software").
func (d *windowsInstalledSoftwareDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_installed_software"
}

// Schema returns the TPF schema for the windows_installed_software data
// source.
func (d *windowsInstalledSoftwareDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the installed software inventory of the remote Windows host without " +
			"managing it. This is a **standalone collection** data source — no sibling resource exists.\n\n" +
			"Inventory comes from the machine-wide Uninstall registry hives (the same hives " +
			"`windows_legacy_package` reads), plus the loaded per-user hives under `HKU` when " +
			"`include_user_installs` is set. Optional filters narrow the result: `name_regex` and " +
			"`publisher_regex` (RE2 matches on the DisplayName and Publisher), `product_code` (an MSI " +
			"ProductCode GUID in any common spelling), `include_system_components` (keep entries with " +
			"`SystemComponent=1`, hidden from Programs and Features), `include_updates` (keep update " +
			"entries) and `include_user_installs`. Omitted filters match everything.\n\n" +
			"`packages` carries one object per matching entry, sorted by name (case-insensitive), then " +
			"version, then registry key; an empty match is a valid empty list, never an error. " +
			"`skipped_entries` counts registry keys skipped because their values were unreadable " +
			"(keys without a DisplayName are silently omitted and not counted). `Win32_Product` is " +
			"never queried.\n\n" +
			"The Terraform data source ID is a query-ID: the hex SHA-256 of the normalised filter set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID (query-ID); hex SHA-256 of the normalised filter set (regexes, normalised product code, bools).",
			},
			"name_regex": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to packages whose DisplayName matches this RE2 regular expression.",
			},
			"publisher_regex": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to packages whose Publisher matches this RE2 regular expression.",
			},
			"product_code": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to the package with this MSI ProductCode GUID, in any common spelling (with or without braces, any case).",
			},
			"include_system_components": schema.BoolAttribute{
				Optional:    true,
				Description: "Keep entries with SystemComponent=1 (hidden from Programs and Features). Omit (null) means false.",
			},
			"include_updates": schema.BoolAttribute{
				Optional:    true,
				Description: "Keep update entries (ReleaseType of Security Update/Update/Hotfix, or a non-empty ParentKeyName). Omit (null) means false.",
			},
			"include_user_installs": schema.BoolAttribute{
				Optional:    true,
				Description: "Additionally enumerate the Uninstall hives of the loaded per-user hives under HKU (domain SIDs S-1-5-21-*); service SIDs excluded; unloaded profiles not scanned. Omit (null) means false.",
			},
			"packages": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Package DisplayName, as observed on the host.",
						},
						"version": schema.StringAttribute{
							Computed:    true,
							Description: "DisplayVersion, as observed on the host.",
						},
						"publisher": schema.StringAttribute{
							Computed:    true,
							Description: "Package publisher, as observed on the host.",
						},
						"install_date": schema.StringAttribute{
							Computed:    true,
							Description: "Registry InstallDate normalised to YYYY-MM-DD; empty when the host value is missing or unparseable.",
						},
						"install_location": schema.StringAttribute{
							Computed:    true,
							Description: "InstallLocation, as observed on the host.",
						},
						"product_code": schema.StringAttribute{
							Computed:    true,
							Description: "MSI ProductCode GUID in upper-case with braces, derived from the registry key name; empty for non-MSI entries.",
						},
						"is_msi": schema.BoolAttribute{
							Computed:    true,
							Description: "True when the entry's WindowsInstaller value is 1.",
						},
						"architecture": schema.StringAttribute{
							Computed:    true,
							Description: "Registry view the entry was read from: x86 for the WOW6432Node hive, otherwise the host architecture (x64 or arm64).",
						},
						"scope": schema.StringAttribute{
							Computed:    true,
							Description: "machine for the HKLM hives, user for per-user HKU entries.",
						},
						"user_sid": schema.StringAttribute{
							Computed:    true,
							Description: "Owning user SID for user-scope entries; empty otherwise.",
						},
						"estimated_size_kb": schema.Int64Attribute{
							Computed:    true,
							Description: "EstimatedSize value in KB; 0 when unreported.",
						},
						"uninstall_string": schema.StringAttribute{
							Computed:    true,
							Description: "UninstallString, as observed on the host.",
						},
						"quiet_uninstall_string": schema.StringAttribute{
							Computed:    true,
							Description: "QuietUninstallString, as observed on the host.",
						},
						"registry_key": schema.StringAttribute{
							Computed:    true,
							Description: "Full registry path of the entry.",
						},
					},
				},
				Description: "Matching installed packages, sorted by name, version and registry key. Empty when no package matches the filters.",
			},
			"skipped_entries": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of registry keys skipped because their values were unreadable.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever (issue #197).
			// Absent configuration falls back to
			// installedSoftwareDSDefaultTimeout.
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the InstalledSoftwareClient.
func (d *windowsInstalledSoftwareDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = winclient.NewInstalledSoftwareClient(c)
}

// installedSoftwareFilterID builds the data source ID: the hex SHA-256 of
// the normalised filter set (raw regexes, normalised product code, bools),
// so identical filters share an ID and any filter change moves it. The
// preimage is the JSON encoding of the ordered field slice, so no
// separator-escaping ambiguity is possible (e.g. name "a|b" vs "b|c").
func installedSoftwareFilterID(nameRegex, publisherRegex, productCode string, system, updates, user bool) string {
	// Normalise the product code through the same canonicaliser the List
	// path uses, so every spelling of one GUID hashes to the same ID. An
	// invalid product code never reaches the host (List fails validation
	// first), so fall back to the lower/trimmed raw value for hashing.
	pcCanon := strings.ToLower(strings.TrimSpace(productCode))
	if strings.TrimSpace(productCode) != "" {
		if norm, merr := winclient.NormalizeInstalledSoftwareProductCode(productCode); merr == nil {
			pcCanon = norm
		}
	}
	canonical, _ := json.Marshal([]any{nameRegex, publisherRegex, pcCanon, system, updates, user})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Read lists the installed packages matching the configured filters.
func (d *windowsInstalledSoftwareDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsInstalledSoftwareDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, installedSoftwareDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	nameRegex := ""
	if !config.NameRegex.IsNull() && !config.NameRegex.IsUnknown() {
		nameRegex = strings.TrimSpace(config.NameRegex.ValueString())
	}
	publisherRegex := ""
	if !config.PublisherRegex.IsNull() && !config.PublisherRegex.IsUnknown() {
		publisherRegex = strings.TrimSpace(config.PublisherRegex.ValueString())
	}
	productCode := ""
	if !config.ProductCode.IsNull() && !config.ProductCode.IsUnknown() {
		productCode = config.ProductCode.ValueString()
	}
	system := false
	if !config.IncludeSystemComponents.IsNull() && !config.IncludeSystemComponents.IsUnknown() {
		system = config.IncludeSystemComponents.ValueBool()
	}
	updates := false
	if !config.IncludeUpdates.IsNull() && !config.IncludeUpdates.IsUnknown() {
		updates = config.IncludeUpdates.ValueBool()
	}
	user := false
	if !config.IncludeUserInstalls.IsNull() && !config.IncludeUserInstalls.IsUnknown() {
		user = config.IncludeUserInstalls.ValueBool()
	}

	tflog.Debug(ctx, "windows_installed_software data source Read start", map[string]interface{}{
		"name_regex": nameRegex, "publisher_regex": publisherRegex, "product_code": productCode,
		"include_system_components": system, "include_updates": updates, "include_user_installs": user,
	})

	result, err := d.client.List(ctx, winclient.InstalledSoftwareFilter{
		NameRegex:               nameRegex,
		PublisherRegex:          publisherRegex,
		ProductCode:             productCode,
		IncludeSystemComponents: system,
		IncludeUpdates:          updates,
		IncludeUserInstalls:     user,
	})
	if err != nil {
		addInstalledSoftwareDiag(&resp.Diagnostics, "Read windows_installed_software failed", err)
		return
	}
	packages := result.Packages
	if packages == nil {
		packages = []winclient.InstalledSoftware{}
	}

	state := windowsInstalledSoftwareDataSourceModel{
		ID:                      types.StringValue(installedSoftwareFilterID(nameRegex, publisherRegex, productCode, system, updates, user)),
		NameRegex:               config.NameRegex,
		PublisherRegex:          config.PublisherRegex,
		ProductCode:             config.ProductCode,
		IncludeSystemComponents: config.IncludeSystemComponents,
		IncludeUpdates:          config.IncludeUpdates,
		IncludeUserInstalls:     config.IncludeUserInstalls,
		SkippedEntries:          types.Int64Value(result.SkippedEntries),
		Timeouts:                config.Timeouts,
	}

	objType := windowsInstalledSoftwareObjectType()
	objs := make([]attr.Value, 0, len(packages))
	for _, p := range packages {
		obj, d := installedSoftwareToObject(objType, p)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		objs = append(objs, obj)
	}
	packagesList, diags := types.ListValue(objType, objs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Packages = packagesList

	tflog.Debug(ctx, "windows_installed_software data source Read end", map[string]interface{}{
		"id":              state.ID.ValueString(),
		"package_count":   len(packages),
		"skipped_entries": result.SkippedEntries,
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// installedSoftwareToObject projects one winclient.InstalledSoftware onto
// the packages element object type.
func installedSoftwareToObject(objType types.ObjectType, p winclient.InstalledSoftware) (attr.Value, diag.Diagnostics) {
	return types.ObjectValue(objType.AttrTypes, map[string]attr.Value{
		"name":                   types.StringValue(p.Name),
		"version":                types.StringValue(p.Version),
		"publisher":              types.StringValue(p.Publisher),
		"install_date":           types.StringValue(p.InstallDate),
		"install_location":       types.StringValue(p.InstallLocation),
		"product_code":           types.StringValue(p.ProductCode),
		"is_msi":                 types.BoolValue(p.IsMSI),
		"architecture":           types.StringValue(p.Architecture),
		"scope":                  types.StringValue(p.Scope),
		"user_sid":               types.StringValue(p.UserSID),
		"estimated_size_kb":      types.Int64Value(p.EstimatedSizeKB),
		"uninstall_string":       types.StringValue(p.UninstallString),
		"quiet_uninstall_string": types.StringValue(p.QuietUninstallString),
		"registry_key":           types.StringValue(p.RegistryKey),
	})
}

// addInstalledSoftwareDiag converts a *winclient.InstalledSoftwareError
// into a TPF diagnostic.
func addInstalledSoftwareDiag(diags *diag.Diagnostics, summary string, err error) {
	var ie *winclient.InstalledSoftwareError
	if errors.As(err, &ie) {
		detail := ie.Message
		if len(ie.Context) > 0 {
			keys := make([]string, 0, len(ie.Context))
			for k := range ie.Context {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			detail += "\n\nContext:"
			for _, k := range keys {
				detail += "\n  " + k + " = " + ie.Context[k]
			}
		}
		if ie.Cause != nil {
			detail += "\n\nCause: " + ie.Cause.Error()
		}
		if ie.Kind != "" {
			detail += "\n\nKind: " + string(ie.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
