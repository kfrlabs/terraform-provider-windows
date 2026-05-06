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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
// Pre-compiled regular expressions used by the schema validators.
// ---------------------------------------------------------------------------

var (
	// name: 1-128 chars, alnum / dot / underscore / hyphen.
	lpNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

	// source_path: absolute Windows path (drive letter + colon + backslash).
	lpSourcePathRe = regexp.MustCompile(`^[A-Za-z]:\\.+`)

	// source_url: http or https URL.
	lpSourceURLRe = regexp.MustCompile(`^https?://`)

	// checksum: <algo>:<hex>.
	lpChecksumRe = regexp.MustCompile(`^(sha256|sha1|md5):[0-9a-fA-F]+$`)

	// product_id: GUID enclosed in braces.
	lpProductIDRe = regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`)
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
	r.lp = winclient.NewLegacyPackageClient(c)
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
// CRUD handlers
// ---------------------------------------------------------------------------

// Create runs the installer end-to-end: source resolution (local path or URL
// download), checksum verification, MSI ProductCode extraction (when needed),
// installer execution under timeout, exit-code validation, and state read-
// back from the Uninstall registry hives.
func (r *windowsLegacyPackageResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsLegacyPackageModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input, d := r.modelToInput(ctx, plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	// installer_type=exe requires display_name_pattern OR uninstall_command
	// (cross-attribute conditional rule, validated at apply time because TPF
	// lacks a native conditional validator on a sibling enum value).
	if input.InstallerType == "exe" && input.DisplayNamePattern == "" && input.UninstallCommand == "" {
		resp.Diagnostics.AddError(
			"Invalid configuration",
			"installer_type=\"exe\" requires either display_name_pattern or uninstall_command to be set.",
		)
		return
	}

	state, err := r.lp.Create(ctx, input)
	if err != nil {
		addLPDiag(&resp.Diagnostics, err, "Create")
		return
	}
	if state == nil {
		resp.Diagnostics.AddError(
			"windows_legacy_package Create returned no state",
			"The installer reported success but the package could not be detected in the Uninstall registry hives.",
		)
		return
	}

	r.applyState(&plan, state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the computed attributes from the Uninstall registry hives.
// When the entry is gone (manual uninstall, drift), the resource is removed
// from state so Terraform schedules re-create on the next apply.
func (r *windowsLegacyPackageResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsLegacyPackageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	if id == "" {
		// Nothing to refresh (fresh import edge-case).
		return
	}

	remote, err := r.lp.Read(ctx, id)
	if err != nil {
		addLPDiag(&resp.Diagnostics, err, "Read")
		return
	}
	if remote == nil {
		// Drift: the package was removed out of band.
		resp.State.RemoveResource(ctx)
		return
	}

	r.applyState(&state, remote)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies the in-place mutable attributes (valid_exit_codes,
// timeout_seconds, log_path, environment). All other attributes are ForceNew
// at the schema level and never reach this method. No Windows action is
// required: the new values affect future invocations only. The current
// observed state is refreshed via the client's Read helper to keep the
// computed attributes consistent.
func (r *windowsLegacyPackageResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsLegacyPackageModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior windowsLegacyPackageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input, d := r.modelToInput(ctx, plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := prior.ID.ValueString()
	remote, err := r.lp.Update(ctx, id, input)
	if err != nil {
		addLPDiag(&resp.Diagnostics, err, "Update")
		return
	}
	// Preserve the stable identifier and the user-set log_path / product_id
	// from the plan so the in-place update is reflected in state.
	plan.ID = prior.ID
	if plan.ProductID.IsUnknown() || plan.ProductID.IsNull() {
		plan.ProductID = prior.ProductID
	}
	if remote != nil {
		// Refresh observable computed attributes from the registry.
		plan.InstalledVersion = types.StringValue(remote.InstalledVersion)
		plan.Installed = types.BoolValue(remote.Installed)
		plan.InstallDate = types.StringValue(remote.InstallDate)
	} else {
		// Package not detected — preserve prior computed values to avoid
		// nullifying state on a transient registry hiccup.
		plan.InstalledVersion = prior.InstalledVersion
		plan.Installed = prior.Installed
		plan.InstallDate = prior.InstallDate
	}
	// log_path is updatable in place: keep the planned value (auto-generated
	// log paths are treated as UseStateForUnknown by the schema).
	if plan.LogPath.IsUnknown() {
		plan.LogPath = prior.LogPath
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete uninstalls the package. MSI uses msiexec /x; EXE prefers
// uninstall_command and falls back to the registry UninstallString
// (QuietUninstallString preferred). Idempotent: a missing entry is treated
// as success.
func (r *windowsLegacyPackageResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsLegacyPackageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	if id == "" {
		return
	}
	if err := r.lp.Delete(ctx, id); err != nil {
		addLPDiag(&resp.Diagnostics, err, "Delete")
		return
	}
}

// ImportState seeds the state with the supplied id (ProductCode GUID for MSI
// or exact DisplayName for EXE). The next Read populates all computed
// attributes. User-set configuration attributes (source_*, install_args, ...)
// are unknown at import time and must be re-supplied via the Terraform config
// to avoid plan drift.
func (r *windowsLegacyPackageResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			"Import ID must be a non-empty MSI ProductCode GUID (e.g. \"{01234567-89AB-CDEF-0123-456789ABCDEF}\") or the exact EXE DisplayName.",
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// modelToInput converts the Terraform plan/state model into the LegacyPackageInput
// consumed by the winclient. List/map values are unmarshalled element-by-element
// to preserve typed semantics; null and unknown collections are flattened to
// empty slices/maps so the JSON payload is stable.
func (r *windowsLegacyPackageResource) modelToInput(ctx context.Context, m windowsLegacyPackageModel) (winclient.LegacyPackageInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	in := winclient.LegacyPackageInput{
		Name:               m.Name.ValueString(),
		InstallerType:      m.InstallerType.ValueString(),
		SourcePath:         m.SourcePath.ValueString(),
		SourceURL:          m.SourceURL.ValueString(),
		Checksum:           m.Checksum.ValueString(),
		InsecureSkipVerify: m.InsecureSkipVerify.ValueBool(),
		ProductID:          m.ProductID.ValueString(),
		DisplayNamePattern: m.DisplayNamePattern.ValueString(),
		UninstallCommand:   m.UninstallCommand.ValueString(),
		WorkingDirectory:   m.WorkingDirectory.ValueString(),
		LogPath:            m.LogPath.ValueString(),
		TimeoutSeconds:     m.TimeoutSeconds.ValueInt64(),
	}

	if !m.InstallArgs.IsNull() && !m.InstallArgs.IsUnknown() {
		var v []string
		diags.Append(m.InstallArgs.ElementsAs(ctx, &v, false)...)
		in.InstallArgs = v
	}
	if !m.UninstallArgs.IsNull() && !m.UninstallArgs.IsUnknown() {
		var v []string
		diags.Append(m.UninstallArgs.ElementsAs(ctx, &v, false)...)
		in.UninstallArgs = v
	}
	if !m.ValidExitCodes.IsNull() && !m.ValidExitCodes.IsUnknown() {
		var v []int64
		diags.Append(m.ValidExitCodes.ElementsAs(ctx, &v, false)...)
		in.ValidExitCodes = v
	}
	if !m.Environment.IsNull() && !m.Environment.IsUnknown() {
		v := map[string]string{}
		diags.Append(m.Environment.ElementsAs(ctx, &v, false)...)
		in.Environment = v
	}
	return in, diags
}

// applyState writes the observed remote state into the Terraform model,
// keeping the user-supplied attributes untouched.
func (r *windowsLegacyPackageResource) applyState(m *windowsLegacyPackageModel, s *winclient.LegacyPackageState) {
	m.ID = types.StringValue(s.ID)
	m.ProductID = types.StringValue(s.ProductID)
	if s.LogPath != "" {
		m.LogPath = types.StringValue(s.LogPath)
	} else if m.LogPath.IsNull() || m.LogPath.IsUnknown() {
		m.LogPath = types.StringValue("")
	}
	m.InstalledVersion = types.StringValue(s.InstalledVersion)
	m.Installed = types.BoolValue(s.Installed)
	m.InstallDate = types.StringValue(s.InstallDate)
}

// addLPDiag translates a *winclient.LegacyPackageError into a Terraform error
// diagnostic. Context entries are appended in deterministic (sorted) order.
func addLPDiag(diags *diag.Diagnostics, err error, op string) {
	var le *winclient.LegacyPackageError
	if errors.As(err, &le) {
		summary := fmt.Sprintf("windows_legacy_package %s error [%s]", op, le.Kind)
		detail := le.Message
		if le.Cause != nil {
			detail += ": " + le.Cause.Error()
		}
		if len(le.Context) > 0 {
			keys := make([]string, 0, len(le.Context))
			for k := range le.Context {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, k+"="+le.Context[k])
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(
		fmt.Sprintf("windows_legacy_package %s unexpected error", op),
		err.Error(),
	)
}
