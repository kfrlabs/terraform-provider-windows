// Package provider contains the Terraform Plugin Framework schema, model, and
// resource-level validators for the windows_service resource.
//
// Spec alignment: windows_service spec v7 (2026-04-24).
// Framework: terraform-plugin-framework v1.13.0.
//
// File layout:
//
//	windowsServiceModel             — tfsdk-tagged state/plan struct (10 attributes)
//	windowsServiceSchemaDefinition  — standalone function returning schema.Schema
//	serviceAccountPasswordValidator — resource.ConfigValidator (EC-4 + EC-11)
package provider

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// builtinAccountRe matches Windows built-in service accounts that must not
// receive a service_password (EC-11). Case-insensitive.
var builtinAccountRe = regexp.MustCompile(`(?i)^(LocalSystem$|NT AUTHORITY\\)`)

// windowsServiceModel is the Terraform state/plan model for windows_service.
//
// Attribute ordering mirrors the schema definition for readability.
//
// service_password is included in the model (Sensitive: true) but is NEVER
// populated from a live Windows read: the Read handler copies the value from
// prior state (semantic write-only — ADR SS6, spec § service_password).
// Migrate to native framework WriteOnly on TPF >= 1.14.0 upgrade (OQ-3).
type windowsServiceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	DisplayName     types.String `tfsdk:"display_name"`
	Description     types.String `tfsdk:"description"`
	BinaryPath      types.String `tfsdk:"binary_path"`
	StartType       types.String `tfsdk:"start_type"`
	Status          types.String `tfsdk:"status"`
	CurrentStatus   types.String `tfsdk:"current_status"`
	ServiceAccount  types.String `tfsdk:"service_account"`
	ServicePassword types.String `tfsdk:"service_password"`
	Dependencies    types.List   `tfsdk:"dependencies"` // element type: types.StringType
}

// windowsServiceSchemaDefinition returns the complete TPF schema for the
// windows_service resource (10 attributes, validators, plan modifiers, defaults).
//
// Canonical usage from the resource implementation:
//
//	func (r *windowsServiceResource) Schema(
//	    _ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse,
//	) {
//	    resp.Schema = windowsServiceSchemaDefinition()
//	}
func windowsServiceSchemaDefinition() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the full lifecycle of a Windows service on a remote host " +
			"via WinRM and PowerShell (`New-Service` / `Set-Service` / `Remove-Service` + " +
			"`sc.exe` helpers). Supports creation, in-place reconfiguration (display name, " +
			"description, start type, service account, dependencies), runtime state control " +
			"(`Running` / `Stopped` / `Paused`), and deletion with drift detection.\n\n" +
			"~> **Note on `binary_path`** Any change to `binary_path` **destroys and recreates** " +
			"the service (ForceNew). Stop production workloads and dependent services before " +
			"applying such a change (EC-5).\n\n" +
			"~> **Note on `service_password`** The Windows SCM never exposes passwords through " +
			"any read API. After `terraform import` the field is `null`; add it manually to HCL.",

		Attributes: map[string]schema.Attribute{

			// ------------------------------------------------------------------
			// id — computed only, UseStateForUnknown
			// ------------------------------------------------------------------
			"id": schema.StringAttribute{
				Computed: true,
				Description: "Resource identifier, set by the provider after successful creation. " +
					"Equal to the Windows short service name (`name`). " +
					"Preserved across plan/apply via UseStateForUnknown to avoid spurious " +
					"\"(known after apply)\" values in the plan output.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},

			// ------------------------------------------------------------------
			// name — required, ForceNew (RequiresReplace), regex validated
			// ------------------------------------------------------------------
			"name": schema.StringAttribute{
				Required: true,
				Description: "Short name (system identifier) of the Windows service as visible in " +
					"`sc.exe` or `services.msc` (e.g. `MyAppSvc`). " +
					"Cannot be changed after creation — the SCM exposes no rename API (ForceNew). " +
					"Must match ^[A-Za-z0-9_-.]{1,256}$ (1-256 chars: alphanumeric, underscore, hyphen, dot).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile("^[A-Za-z0-9_\\-\\.]{1,256}$"),
						"must contain only alphanumeric characters, underscores, hyphens, or dots "+
							"and be between 1 and 256 characters",
					),
				},
			},

			// ------------------------------------------------------------------
			// display_name — optional+computed, no schema default
			// ------------------------------------------------------------------
			"display_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Human-readable display name shown in `services.msc`. " +
					"Optional+Computed: if omitted at creation Windows sets it equal to `name`; " +
					"the provider captures the effective value after creation or import without " +
					"generating spurious diffs when the attribute is unconfigured (ADR SS2).",
			},

			// ------------------------------------------------------------------
			// description — optional only
			// ------------------------------------------------------------------
			"description": schema.StringAttribute{
				Optional: true,
				Description: "Textual description of the service displayed in `services.msc`. " +
					"Read back via `sc.exe qdescription <Name>`. " +
					"An empty string is stored in state when Windows returns no description; " +
					"omit the attribute to leave the description unmanaged.",
			},

			// ------------------------------------------------------------------
			// binary_path — required, ForceNew (RequiresReplace), length 1..32767
			// ------------------------------------------------------------------
			"binary_path": schema.StringAttribute{
				Required: true,
				Description: "Full path to the service executable including any command-line arguments " +
					"(e.g. `\"C:\\\\Program Files\\\\MyApp\\\\svc.exe\" --config C:\\\\myapp.conf`). " +
					"Paths containing spaces must be wrapped in escaped double-quotes in HCL. " +
					"Maximum 32 767 characters (Windows extended-path limit). " +
					"**Any change destroys and recreates the service (ForceNew).** " +
					"The Read layer applies EC-14 outer-quote normalisation before storing in state " +
					"to prevent spurious destroy+create diffs.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 32767),
				},
			},

			// ------------------------------------------------------------------
			// start_type — optional+computed, default "Automatic"
			// ------------------------------------------------------------------
			"start_type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Service start mode. One of: `Automatic`, `AutomaticDelayedStart`, " +
					"`Manual`, `Disabled`. Defaults to `Automatic` (matching the Windows SCM default). " +
					"`AutomaticDelayedStart` is implemented via `sc.exe config start= delayed-auto` " +
					"on all PowerShell versions (ADR SS3, EC-9). " +
					"Computed=true enables `terraform import` to capture the real start type from " +
					"`sc.exe qc` output, including the DELAYED flag that is invisible to `Get-Service`.",
				Default: stringdefault.StaticString("Automatic"),
				Validators: []validator.String{
					stringvalidator.OneOf(
						"Automatic",
						"AutomaticDelayedStart",
						"Manual",
						"Disabled",
					),
				},
			},

			// ------------------------------------------------------------------
			// status — optional only (NOT computed), null = observe-only mode
			// ------------------------------------------------------------------
			"status": schema.StringAttribute{
				Optional: true,
				Description: "Desired runtime state of the service after apply. " +
					"One of: `Running`, `Stopped`, `Paused`. " +
					"`Running` — start via `Start-Service`. " +
					"`Stopped` — stop via `Stop-Service -Force` (cascades to dependent services, EC-10). " +
					"`Paused` — suspend via `Suspend-Service` " +
					"(requires `CanPauseAndContinue = true`; see EC-13). " +
					"**If omitted (null in state)** the provider does not reconcile runtime state " +
					"(observe-only mode): `current_status` is read but no `Start`/`Stop` is issued. " +
					"Intentionally not Computed — null is the unambiguous observe-only sentinel (ADR SS4).",
				Validators: []validator.String{
					stringvalidator.OneOf("Running", "Stopped", "Paused"),
				},
			},

			// ------------------------------------------------------------------
			// current_status — computed only (observed state from Get-Service)
			// ------------------------------------------------------------------
			"current_status": schema.StringAttribute{
				Computed: true,
				Description: "Observed runtime state of the service at the time of the last Read: " +
					"`Running`, `Stopped`, or `Paused`. " +
					"Read-only computed attribute populated from `Get-Service .Status`. " +
					"Use `status` to express desired state; reference `current_status` in `output` " +
					"blocks to expose the observed value without coupling to desired-state " +
					"reconciliation (ADR SS5).",
			},

			// ------------------------------------------------------------------
			// service_account — optional only
			// ------------------------------------------------------------------
			"service_account": schema.StringAttribute{
				Optional: true,
				Description: "Account under which the service runs. " +
					"Examples: `LocalSystem`, `NT AUTHORITY\\NetworkService`, " +
					"`NT AUTHORITY\\LocalService`, `.\\MyLocalUser`, `DOMAIN\\svc-myapp`. " +
					"Windows defaults to `LocalSystem` if omitted. " +
					"Built-in accounts (`LocalSystem`, `NT AUTHORITY\\*`) must not be paired " +
					"with `service_password` — that combination causes SCM error 87 (EC-11). " +
					"The Read layer normalises `.\\user` to `HOSTNAME\\user` and treats " +
					"`LocalSystem` and `NT AUTHORITY\\SYSTEM` as equivalent before drift comparison " +
					"(ADR SS10, spec v7 clarification).",
			},

			// ------------------------------------------------------------------
			// service_password — optional, sensitive, semantic write-only
			// ------------------------------------------------------------------
			// IMPLEMENTATION NOTE (TPF v1.13.0 — no native WriteOnly):
			//   1. Sensitive: true  → value redacted in plan/apply output and provider logs.
			//   2. ServiceState struct does NOT contain ServicePassword.
			//   3. Read handler copies service_password from prior state, never from Windows.
			//   4. service_password is NEVER included in ServiceError.Message.
			// Migrate to native WriteOnly when upgrading to TPF >= 1.14.0 (OQ-3).
			"service_password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Password for `service_account`. Required when `service_account` is a " +
					"domain or local user account (not `LocalSystem` or `NT AUTHORITY\\*`). " +
					"**Sensitive and write-only**: the Windows SCM never exposes passwords via any " +
					"read API. The Read handler preserves the last-written value from prior state; " +
					"out-of-band password rotations on Windows are not detected by `terraform plan`. " +
					"After `terraform import` this field is `null` and must be set manually in HCL. " +
					"Cross-field validation (EC-4, EC-11): `service_password` without a non-built-in " +
					"`service_account` is rejected at plan time by `serviceAccountPasswordValidator`.",
			},

			// ------------------------------------------------------------------
			// dependencies — optional, list(string), order-sensitive
			// ------------------------------------------------------------------
			"dependencies": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Ordered list of short service names that this service depends on. " +
					"The SCM ensures these services are started before this one. " +
					"Order is preserved — `ListAttribute` not `SetAttribute` (ADR SS7). " +
					"An empty list (`[]`) removes all dependencies via `sc.exe config depend= /` " +
					"(forward-slash idiom; `depend= \"\"` is unreliable in -EncodedCommand context). " +
					"Always managed via `sc.exe config depend=` on all PowerShell versions (ADR SS3). " +
					"Read back via the `sc.exe qc` DEPENDENCIES multi-line section.",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// serviceAccountPasswordValidator
// ---------------------------------------------------------------------------

// serviceAccountPasswordValidator is a resource-level ConfigValidator that
// enforces EC-4 and EC-11 cross-field constraints at plan time, before any
// WinRM connection is opened.
//
//   - EC-4: service_password requires service_account to be non-null and
//     non-empty. Plan fails with an attribute-level error; no WinRM call made.
//
//   - EC-11: service_password must not be paired with a built-in account
//     (LocalSystem or NT AUTHORITY\*). Passing a password for built-in accounts
//     causes SCM error 87 "The parameter is incorrect".
//
// Register in the resource implementation:
//
//	func (r *windowsServiceResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
//	    return []resource.ConfigValidator{serviceAccountPasswordValidator{}}
//	}
type serviceAccountPasswordValidator struct{}

// Ensure compile-time satisfaction of resource.ConfigValidator.
var _ resource.ConfigValidator = serviceAccountPasswordValidator{}

// Description returns a plain-text description used in framework diagnostic output.
func (v serviceAccountPasswordValidator) Description(_ context.Context) string {
	return "Validates EC-4 and EC-11: service_password requires a non-empty, " +
		"non-built-in service_account."
}

// MarkdownDescription returns a Markdown description used in framework output.
func (v serviceAccountPasswordValidator) MarkdownDescription(_ context.Context) string {
	return "Validates **EC-4** and **EC-11**: `service_password` requires a non-empty, " +
		"non-built-in `service_account`."
}

// ValidateResource is invoked by the Terraform Plugin Framework at plan time.
// It reads the full resource configuration and applies the cross-field rules.
func (v serviceAccountPasswordValidator) ValidateResource(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var data windowsServiceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// service_password absent or unknown at plan time: nothing to validate.
	if data.ServicePassword.IsNull() || data.ServicePassword.IsUnknown() {
		return
	}

	// EC-4: service_password requires a non-empty service_account.
	if data.ServiceAccount.IsNull() || data.ServiceAccount.IsUnknown() ||
		data.ServiceAccount.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("service_password"),
			"service_password requires service_account (EC-4)",
			"service_password is set but service_account is null or empty. "+
				"Provide a non-built-in service_account (e.g. DOMAIN\\svc-app or .\\localuser) "+
				"when using service_password.",
		)
		return
	}

	// EC-11: service_password must not be used with built-in accounts.
	if builtinAccountRe.MatchString(data.ServiceAccount.ValueString()) {
		resp.Diagnostics.AddAttributeError(
			path.Root("service_password"),
			"service_password must not be used with built-in accounts (EC-11)",
			"service_account '"+data.ServiceAccount.ValueString()+"' is a built-in account. "+
				"Built-in accounts (LocalSystem, NT AUTHORITY\\*) do not accept a password — "+
				"passing one causes SCM error 87 \"The parameter is incorrect\". "+
				"Remove service_password or change service_account to a domain or local user.",
		)
	}
}
