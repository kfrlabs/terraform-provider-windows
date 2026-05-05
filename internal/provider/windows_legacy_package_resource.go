// Terraform resource skeleton for windows_legacy_package.
//
// Manages installation / update / uninstallation of legacy Windows software
// distributed as MSI packages or EXE installers (InstallShield, NSIS, Inno
// Setup, ...). Complements windows_winget_package for software not available
// via winget or shipped as a local/internal binary.
//
// Spec alignment: windows_legacy_package spec v1 (2026-05-05).
// Framework:      terraform-plugin-framework v1.13.0.
//
// NOTE: This file is the SchemaArchitect skeleton. The CRUD handlers are
// intentional stubs that return ErrNotImplemented diagnostics. The
// ProviderCoder task will replace each stub body with the real PowerShell-
// over-WinRM logic against winclient.LegacyPackageClient.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

var (
	_ resource.Resource                     = (*windowsLegacyPackageResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsLegacyPackageResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsLegacyPackageResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsLegacyPackageResource)(nil)
)

// NewWindowsLegacyPackageResource is the constructor registered in provider.go.
func NewWindowsLegacyPackageResource() resource.Resource {
	return &windowsLegacyPackageResource{}
}

// windowsLegacyPackageResource is the TPF resource type for windows_legacy_package.
type windowsLegacyPackageResource struct {
	client *winclient.Client
	lp     winclient.LegacyPackageClient
}

// ---------------------------------------------------------------------------
// Model — must match the schema attribute keys 1:1
// ---------------------------------------------------------------------------

type windowsLegacyPackageModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	InstallerType      types.String `tfsdk:"installer_type"`
	SourcePath         types.String `tfsdk:"source_path"`
	SourceURL          types.String `tfsdk:"source_url"`
	Checksum           types.String `tfsdk:"checksum"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
	ProductID          types.String `tfsdk:"product_id"`
	DisplayNamePattern types.String `tfsdk:"display_name_pattern"`
	InstallArgs        types.List   `tfsdk:"install_args"`
	UninstallArgs      types.List   `tfsdk:"uninstall_args"`
	UninstallCommand   types.String `tfsdk:"uninstall_command"`
	ValidExitCodes     types.List   `tfsdk:"valid_exit_codes"`
	WorkingDirectory   types.String `tfsdk:"working_directory"`
	TimeoutSeconds     types.Int64  `tfsdk:"timeout_seconds"`
	LogPath            types.String `tfsdk:"log_path"`
	Environment        types.Map    `tfsdk:"environment"`
	InstalledVersion   types.String `tfsdk:"installed_version"`
	Installed          types.Bool   `tfsdk:"installed"`
	InstallDate        types.String `tfsdk:"install_date"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *windowsLegacyPackageResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_legacy_package"
}

func (r *windowsLegacyPackageResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages legacy Windows installers (.msi via msiexec; .exe via Start-Process) over WinRM.",
		MarkdownDescription: "Installs, updates and uninstalls Windows software distributed as legacy installers " +
			"(`.exe` wrappers like InstallShield/NSIS/Inno Setup and Windows Installer `.msi` packages).\n\n" +
			"Complements `windows_winget_package` for software not available via winget or shipped as a " +
			"local/internal binary. Detection is performed against the standard Uninstall registry hives " +
			"(`HKLM:\\SOFTWARE\\...\\Uninstall\\*` and `Wow6432Node`).",
		Attributes: map[string]schema.Attribute{

			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform ID. ProductCode GUID for MSI; resolved exact DisplayName for EXE.",
				MarkdownDescription: "Terraform ID. **ProductCode GUID** for MSI; resolved exact `DisplayName` for EXE.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"name": schema.StringAttribute{
				Required:            true,
				Description:         "Logical Terraform identifier and display label for the package.",
				MarkdownDescription: "Logical Terraform identifier and display label for the package. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						lpNameRe,
						"must match ^[A-Za-z0-9._-]{1,128}$",
					),
				},
			},

			"installer_type": schema.StringAttribute{
				Required:            true,
				Description:         "Installer engine. msi uses msiexec; exe runs the binary directly.",
				MarkdownDescription: "Installer engine. `msi` uses `msiexec.exe`; `exe` runs the binary directly via `Start-Process`. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("msi", "exe"),
				},
			},

			"source_path": schema.StringAttribute{
				Optional:            true,
				Description:         "Local path on the target Windows host to the .msi/.exe file. Mutually exclusive with source_url.",
				MarkdownDescription: "Local path on the target Windows host to the `.msi`/`.exe` file. Mutually exclusive with `source_url`. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						lpSourcePathRe,
						"must be an absolute Windows path (e.g. C:\\\\path\\\\to\\\\file.msi)",
					),
				},
			},

			"source_url": schema.StringAttribute{
				Optional:            true,
				Description:         "HTTP/HTTPS URL fetched on the target host into $env:TEMP before exec. Mutually exclusive with source_path.",
				MarkdownDescription: "HTTP/HTTPS URL fetched on the target host into `$env:TEMP` before exec. Mutually exclusive with `source_path`. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						lpSourceURLRe,
						"must be an http:// or https:// URL",
					),
				},
			},

			"checksum": schema.StringAttribute{
				Optional:            true,
				Description:         "Expected installer checksum, format <algo>:<hex>. Verified before exec.",
				MarkdownDescription: "Expected installer checksum, format `<algo>:<hex>` where `<algo>` is one of `sha256`, `sha1`, `md5`. Verified before exec. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						lpChecksumRe,
						"must match ^(sha256|sha1|md5):[0-9a-fA-F]+$",
					),
				},
			},

			"insecure_skip_verify": schema.BoolAttribute{
				Optional:            true,
				Description:         "Disable TLS cert validation when fetching source_url. Not recommended; use only for internal CAs.",
				MarkdownDescription: "Disable TLS certificate validation when fetching `source_url`. **Not recommended** — use only for internal CAs. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
				},
			},

			"product_id": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "MSI ProductCode GUID. Auto-extracted from the MSI at Create when omitted.",
				MarkdownDescription: "MSI **ProductCode** GUID (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`). Auto-extracted from the MSI at Create when omitted. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						lpProductIDRe,
						"must be a GUID enclosed in braces, e.g. {01234567-89AB-CDEF-0123-456789ABCDEF}",
					),
				},
			},

			"display_name_pattern": schema.StringAttribute{
				Optional:            true,
				Description:         "Wildcard/regex matched against DisplayName under HKLM Uninstall (and Wow6432Node) to locate EXE installs. Required for exe when uninstall_command is empty.",
				MarkdownDescription: "Wildcard/regex matched against `DisplayName` under `HKLM:\\SOFTWARE\\...\\Uninstall\\*` (and `Wow6432Node`) to locate EXE installs. Required for `installer_type=exe` when `uninstall_command` is empty. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			"install_args": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Description:         "Extra args to the installer. MSI defaults injected by provider (/i,/qn,/norestart,/l*v <log>); EXE has no defaults.",
				MarkdownDescription: "Extra arguments to the installer. MSI defaults injected by provider (`/i`, `/qn`, `/norestart`, `/l*v <log>`); EXE has no defaults. Immutable (ForceNew).",
			},

			"uninstall_args": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Description:         "Extra args for uninstallation. MSI default ['/x',<product_id>,'/qn','/norestart']; appended to UninstallString for EXE.",
				MarkdownDescription: "Extra arguments for uninstallation. MSI default `['/x', <product_id>, '/qn', '/norestart']`; appended to `UninstallString` for EXE. Immutable (ForceNew).",
			},

			"uninstall_command": schema.StringAttribute{
				Optional:            true,
				Description:         "Explicit EXE uninstall command when registry UninstallString is unreliable.",
				MarkdownDescription: "Explicit EXE uninstall command when registry `UninstallString` is unreliable. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			"valid_exit_codes": schema.ListAttribute{
				ElementType:         types.Int64Type,
				Optional:            true,
				Description:         "Exit codes treated as success. Default [0,3010]. Updatable in place (only affects future runs).",
				MarkdownDescription: "Exit codes treated as success. Default `[0, 3010]`. **Updatable in place** (only affects future runs).",
			},

			"working_directory": schema.StringAttribute{
				Optional:            true,
				Description:         "CWD for the installer process. Defaults to the parent dir of the resolved installer.",
				MarkdownDescription: "Working directory for the installer process. Defaults to the parent directory of the resolved installer. Immutable (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			"timeout_seconds": schema.Int64Attribute{
				Optional:            true,
				Description:         "Hard timeout for install/uninstall. Default 1800. Updatable in place.",
				MarkdownDescription: "Hard timeout (seconds) for install/uninstall. Default `1800`. **Updatable in place**. Range: 1–86400.",
				Validators: []validator.Int64{
					int64validator.Between(1, 86400),
				},
			},

			"log_path": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Path to MSI /l*v log or EXE stdout/stderr capture. Auto-generated under $env:TEMP\\windows_legacy_package\\ when omitted. Updatable in place.",
				MarkdownDescription: "Path to MSI `/l*v` log or EXE stdout/stderr capture. Auto-generated under `$env:TEMP\\windows_legacy_package\\` when omitted. **Updatable in place**.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"environment": schema.MapAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Sensitive:           true,
				Description:         "Extra environment variables injected into the installer process. Updatable in place; marked sensitive (may carry license keys / proxy creds).",
				MarkdownDescription: "Extra environment variables injected into the installer process. **Updatable in place**; marked **sensitive** (may carry license keys / proxy credentials).",
			},

			"installed_version": schema.StringAttribute{
				Computed:            true,
				Description:         "DisplayVersion read from Uninstall registry (or MSI properties) post-install.",
				MarkdownDescription: "`DisplayVersion` read from the Uninstall registry (or MSI properties) post-install.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"installed": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the package is currently detected on the host.",
				MarkdownDescription: "Whether the package is currently detected on the host.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},

			"install_date": schema.StringAttribute{
				Computed:            true,
				Description:         "Install date from registry InstallDate, normalized to ISO-8601 when parseable.",
				MarkdownDescription: "Install date from registry `InstallDate`, normalized to ISO-8601 when parseable.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *windowsLegacyPackageResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = c
	// ProviderCoder will instantiate the concrete LegacyPackageClient impl here:
	//   r.lp = winclient.NewLegacyPackageClient(c)
}

// ConfigValidators enforces cross-attribute spec rules:
//
//   - Exactly one of source_path / source_url must be set.
//   - For installer_type=exe, at least one of display_name_pattern or
//     uninstall_command must be set (validated at Create by ProviderCoder, as
//     framework lacks a native conditional validator on a sibling enum value).
func (r *windowsLegacyPackageResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("source_path"),
			path.MatchRoot("source_url"),
		),
	}
}

// ---------------------------------------------------------------------------
// CRUD stubs — ProviderCoder fills these in.
// ---------------------------------------------------------------------------

const lpNotImpl = "will be implemented by ProviderCoder"

func (r *windowsLegacyPackageResource) Create(_ context.Context, _ resource.CreateRequest, resp *resource.CreateResponse) {
	resp.Diagnostics.AddError("not implemented", "Create "+lpNotImpl)
}

func (r *windowsLegacyPackageResource) Read(_ context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	resp.Diagnostics.AddError("not implemented", "Read "+lpNotImpl)
}

func (r *windowsLegacyPackageResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("not implemented", "Update "+lpNotImpl)
}

func (r *windowsLegacyPackageResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddError("not implemented", "Delete "+lpNotImpl)
}

func (r *windowsLegacyPackageResource) ImportState(_ context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.AddError("not implemented", "ImportState "+lpNotImpl)
}
