// Terraform resource lifecycle for windows_winget_package.
//
// Manages the install / update / uninstall lifecycle of a Windows software
// package via the Microsoft Windows Package Manager (winget) using the
// official PowerShell module Microsoft.WinGet.Client over WinRM.
//
// Spec alignment: windows_winget_package spec v1 (2026-05-01).
// Framework:      terraform-plugin-framework v1.13.0.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

var (
	_ resource.Resource                     = (*windowsWingetPackageResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsWingetPackageResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsWingetPackageResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsWingetPackageResource)(nil)
)

// NewWindowsWingetPackageResource is the constructor registered in provider.go.
func NewWindowsWingetPackageResource() resource.Resource {
	return &windowsWingetPackageResource{}
}

// windowsWingetPackageResource is the TPF resource type for windows_winget_package.
type windowsWingetPackageResource struct {
	client *winclient.Client
	wp     winclient.WingetPackageClient
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// windowsWingetPackageModel is the Terraform state/plan model for
// windows_winget_package. Every tfsdk tag matches an attribute key in the
// schema definition below.
type windowsWingetPackageModel struct {
	// Composite identifier: "<source>:<package_id>" (ADR-WP-1).
	ID types.String `tfsdk:"id"`

	// User-facing configuration attributes.
	PackageID types.String `tfsdk:"package_id"`
	Version   types.String `tfsdk:"version"`
	Source    types.String `tfsdk:"source"`
	Override  types.String `tfsdk:"override"`

	// Computed observability attributes populated from Get-WinGetPackage.
	InstalledVersion types.String `tfsdk:"installed_version"`
	Name             types.String `tfsdk:"name"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema / Configure / ConfigValidators
// ---------------------------------------------------------------------------

// Metadata sets the resource type name.
func (r *windowsWingetPackageResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_winget_package"
}

// Schema returns the complete TPF schema for the windows_winget_package resource.
func (r *windowsWingetPackageResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the install / update / uninstall lifecycle of a Windows " +
			"software package via the Microsoft Windows Package Manager (`winget`) using the " +
			"official PowerShell module `Microsoft.WinGet.Client`. " +
			"Access is performed over WinRM + PowerShell. " +
			"The module **must** already be installed on the target host; " +
			"the provider does **not** auto-install it.\n\n" +
			"Install scope is always `SystemOrUnknown` (machine-level), " +
			"silent mode is always enforced, and package/source agreements are " +
			"always auto-accepted.\n\n" +
			"**Import format**: `<source>:<package_id>` " +
			"(e.g. `winget:Microsoft.VisualStudioCode`).",

		Attributes: map[string]schema.Attribute{

			// ---- Identity (ADR-WP-1) ----

			"id": schema.StringAttribute{
				Computed: true,
				Description: "Composite Terraform identifier formatted as " +
					"`<source>:<package_id>` (e.g. `winget:Microsoft.VisualStudioCode`). " +
					"Set on creation and stable for the resource lifetime.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// ---- Configuration attributes ----

			"package_id": schema.StringAttribute{
				Required: true,
				Description: "winget catalog identifier (e.g. `Microsoft.VisualStudioCode`). " +
					"Matched exactly via `-MatchOption Equals`. " +
					"Immutable after creation (ForceNew). Length 1–255.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
					stringvalidator.RegexMatches(
						regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._+\\-]*$"),
						"must start with an alphanumeric character and contain only "+
							"alphanumeric characters, dots (.), underscores (_), "+
							"plus signs (+), and hyphens (-)",
					),
				},
			},

			"version": schema.StringAttribute{
				Optional: true,
				Description: "Pinned package version (e.g. `1.85.2`). " +
					"When null/absent, the *latest available* version is targeted: " +
					"Create installs latest, Read does **not** flag drift on newer " +
					"upstream versions, and Update is a no-op if any version is installed. " +
					"When set, a config change triggers `Update-WinGetPackage` in-place " +
					"(not ForceNew). Clearing back to null upgrades to latest. " +
					"Length 1–128 when set.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 128),
					stringvalidator.RegexMatches(
						regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._+\\-]*$"),
						"must start with an alphanumeric character and contain only "+
							"alphanumeric characters, dots (.), underscores (_), "+
							"plus signs (+), and hyphens (-)",
					),
				},
			},

			"source": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("winget"),
				Description: "winget source (catalog) name. Defaults to `winget`. " +
					"Allowed: `winget`, `msstore`. " +
					"Immutable after creation (ForceNew).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("winget", "msstore"),
				},
			},

			"override": schema.StringAttribute{
				Optional: true,
				Description: "Raw extra arguments forwarded to the underlying installer " +
					"via `-Override` on `Install-WinGetPackage` " +
					"(e.g. MSI properties). " +
					"Immutable after creation (ForceNew). Max 4096 chars. " +
					"Must not contain control characters (U+0000–U+001F, U+007F). " +
					"**Do not embed secrets here**: this value is logged by winget " +
					"and stored in Terraform state in plaintext.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtMost(4096),
					wingetOverrideValidator{},
				},
			},

			// ---- Computed observability attributes ----

			"installed_version": schema.StringAttribute{
				Computed: true,
				Description: "Version actually installed on the host " +
					"(`.InstalledVersion` from `Get-WinGetPackage`). " +
					"Populated on Create, Read, and Update.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			"name": schema.StringAttribute{
				Computed: true,
				Description: "Human-readable package display name " +
					"(`.Name` from `Get-WinGetPackage`). " +
					"Populated on Create, Read, and Update.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure stores the shared WinRM client and creates the winget package
// sub-client. Called by the framework after provider Configure.
func (r *windowsWingetPackageResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.wp = winclient.NewWingetPackageClient(c)
}

// ConfigValidators returns resource-level cross-field validators.
// v1 has no cross-attribute constraints; returns an empty slice as an
// extension point for future rules (e.g. msstore + override incompatibility).
func (r *windowsWingetPackageResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{}
}

// ---------------------------------------------------------------------------
// CRUD handlers
// ---------------------------------------------------------------------------

// Create installs a new package via Install-WinGetPackage (EC-1, EC-2
// pre-flights are inside the client). Populates computed attributes on success.
func (r *windowsWingetPackageResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsWingetPackageModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := winclient.WingetPackageInput{
		PackageID: plan.PackageID.ValueString(),
		Source:    plan.Source.ValueString(),
		Version:   plan.Version.ValueString(),  // empty string when null → "latest"
		Override:  plan.Override.ValueString(), // empty string when null → no override
	}

	state, err := r.wp.Install(ctx, input)
	if err != nil {
		addWPDiag(&resp.Diagnostics, err, "Create")
		return
	}

	// EC-6: emit a warning when winget signals a reboot is required.
	if state != nil && state.RebootRequired {
		resp.Diagnostics.AddWarning(
			"Windows reboot required",
			fmt.Sprintf(
				"Package %q from source %q was installed successfully, but the host "+
					"requires a reboot to complete the installation.",
				input.PackageID, input.Source,
			),
		)
	}

	// Build the Terraform state from the plan + remote observations.
	plan.ID = types.StringValue(plan.Source.ValueString() + ":" + plan.PackageID.ValueString())
	if state != nil {
		plan.InstalledVersion = types.StringValue(state.InstalledVersion)
		plan.Name = types.StringValue(state.Name)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the computed attributes from Get-WinGetPackage. If the
// package is absent (EC-3 drift), the resource is removed from state so
// Terraform re-creates it on the next apply. The desired `version` attribute
// is preserved unchanged (ADR-WP-5: no permadiff on "latest" semantics).
func (r *windowsWingetPackageResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsWingetPackageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.wp.Read(ctx, state.PackageID.ValueString(), state.Source.ValueString())
	if err != nil {
		addWPDiag(&resp.Diagnostics, err, "Read")
		return
	}

	// EC-3: package removed out of band → signal drift.
	if remote == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Update only the computed observability attributes; the desired `version`
	// is intentionally NOT updated to avoid permadiff (ADR-WP-5).
	state.InstalledVersion = types.StringValue(remote.InstalledVersion)
	state.Name = types.StringValue(remote.Name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies a version change via Update-WinGetPackage. Only triggered
// when the `version` attribute changes in the plan. All other mutable changes
// are either ForceNew (package_id, source, override) or computed
// (installed_version, name).
func (r *windowsWingetPackageResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan windowsWingetPackageModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state windowsWingetPackageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := winclient.WingetPackageInput{
		PackageID: plan.PackageID.ValueString(),
		Source:    plan.Source.ValueString(),
		Version:   plan.Version.ValueString(), // "" when cleared → "latest"
	}

	remote, err := r.wp.Update(ctx, input)
	if err != nil {
		addWPDiag(&resp.Diagnostics, err, "Update")
		return
	}

	// EC-6: warn on reboot required.
	if remote != nil && remote.RebootRequired {
		resp.Diagnostics.AddWarning(
			"Windows reboot required",
			fmt.Sprintf(
				"Package %q from source %q was updated successfully, but the host "+
					"requires a reboot to complete the update.",
				input.PackageID, input.Source,
			),
		)
	}

	// Preserve the stable ID (does not change on update).
	plan.ID = state.ID
	if remote != nil {
		plan.InstalledVersion = types.StringValue(remote.InstalledVersion)
		plan.Name = types.StringValue(remote.Name)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete uninstalls the package via Uninstall-WinGetPackage. PackageNotInstalled
// is treated as success for idempotency (EC-3). A RebootRequired status emits
// a warning but does not fail the deletion (EC-6).
func (r *windowsWingetPackageResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsWingetPackageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.wp.Uninstall(ctx, state.PackageID.ValueString(), state.Source.ValueString())
	if err != nil {
		addWPDiag(&resp.Diagnostics, err, "Delete")
		return
	}

	// EC-6: warn on reboot required.
	if result != nil && result.RebootRequired {
		resp.Diagnostics.AddWarning(
			"Windows reboot required",
			fmt.Sprintf(
				"Package %q from source %q was uninstalled successfully, but the host "+
					"requires a reboot to finalise the removal.",
				state.PackageID.ValueString(), state.Source.ValueString(),
			),
		)
	}
	// Terraform removes the resource from state automatically after Delete.
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState parses the import ID in "<source>:<package_id>" format (EC-11).
// The split is performed on the first colon only, for future-proofing against
// package IDs that might contain colons. The subsequent Read call populates
// all computed attributes.
func (r *windowsWingetPackageResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID format",
			fmt.Sprintf(
				"Expected \"<source>:<package_id>\" "+
					"(e.g. \"winget:Microsoft.VisualStudioCode\"), got: %q.\n\n"+
					"Split is on the first colon; both source and package_id must be non-empty.",
				id,
			),
		)
		return
	}
	source := parts[0]
	packageID := parts[1]

	// Seed the state with just enough for Read to run.
	// version and override are unknown at import time → null (correct semantic).
	imported := windowsWingetPackageModel{
		ID:               types.StringValue(id),
		PackageID:        types.StringValue(packageID),
		Source:           types.StringValue(source),
		Version:          types.StringNull(),
		Override:         types.StringNull(),
		InstalledVersion: types.StringValue(""),
		Name:             types.StringValue(""),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &imported)...)
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// wingetOverrideValidator rejects override values containing C0 control
// characters (U+0000–U+001F) or DEL (U+007F). These bytes break PowerShell
// argument quoting and cannot be safely forwarded to the installer.
type wingetOverrideValidator struct{}

func (v wingetOverrideValidator) Description(_ context.Context) string {
	return "override must not contain control characters (U+0000–U+001F, U+007F)."
}

func (v wingetOverrideValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// wingetOverrideControlCharRe matches C0 control characters and DEL.
var wingetOverrideControlCharRe = regexp.MustCompile("[\x00-\x1f\x7f]")

// ValidateString implements validator.String.
func (v wingetOverrideValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := req.ConfigValue.ValueString()
	loc := wingetOverrideControlCharRe.FindStringIndex(val)
	if loc == nil {
		return
	}
	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid override value",
		fmt.Sprintf(
			"override must not contain control characters (U+0000–U+001F, U+007F); "+
				"found a control character at byte offset %d. "+
				"Escape or remove the offending character before applying.",
			loc[0],
		),
	)
}

// ---------------------------------------------------------------------------
// Diagnostic helper
// ---------------------------------------------------------------------------

// addWPDiag translates a WingetPackageError into a Terraform error diagnostic.
// All context key-value pairs from the error are appended to the detail string
// in sorted order to make diagnostics deterministic across runs.
func addWPDiag(diags *diag.Diagnostics, err error, op string) {
	var we *winclient.WingetPackageError
	if errors.As(err, &we) {
		summary := fmt.Sprintf("windows_winget_package %s error [%s]", op, we.Kind)
		detail := we.Message
		if we.Cause != nil {
			detail += ": " + we.Cause.Error()
		}
		if len(we.Context) > 0 {
			keys := make([]string, 0, len(we.Context))
			for k := range we.Context {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, k+"="+we.Context[k])
			}
			detail += "\n\nContext: " + strings.Join(parts, ", ")
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(
		fmt.Sprintf("windows_winget_package %s unexpected error", op),
		err.Error(),
	)
}

// Ensure the path package is used (imported for ImportState SetAttribute paths).
var _ = path.Root
