// Package provider: windows_file_acl resource.
//
// Schema, validators, plan modification, CRUD and ImportState for
// windows_file_acl. SSH interaction is delegated to winclient.FileACLClientImpl.
//
// Three design decisions drive most of this file:
//
//   - No Computed attribute inside the access_rule block. Terraform cannot
//     reliably correlate the elements of a repeated block that carries computed
//     values, which yields "inconsistent result after apply" or endless churn.
//     The observed descriptor is exposed separately, in the computed
//     effective_access_rules list, and the blocks stay purely declarative.
//
//   - Read reconciles rather than overwrites. The declared rules are matched
//     against the host ACEs by SID and flags, and a matching rule is left
//     exactly as the operator wrote it: "Modify" stays "Modify" instead of being
//     rewritten into whatever keyword decomposition the mask produces, and a
//     bare account name is not replaced by its qualified form. Only a genuine
//     difference reaches the state, so only a genuine difference shows a plan.
//
//   - Identity comparison is SID-first. Comparing display names breaks as soon
//     as an account is renamed or qualified differently, which is the bug
//     already fixed once in windows_local_group_member.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ resource.Resource                     = (*windowsFileACLResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsFileACLResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsFileACLResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsFileACLResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*windowsFileACLResource)(nil)
)

// fileACLDefaultTimeout covers a Get-Acl/Set-Acl round trip over SSH.
const fileACLDefaultTimeout = 10 * time.Minute

// NewWindowsFileACLResource is the constructor registered in provider.go.
func NewWindowsFileACLResource() resource.Resource {
	return &windowsFileACLResource{}
}

// windowsFileACLResource is the TPF resource type for windows_file_acl.
type windowsFileACLResource struct {
	client winclient.FileACLClient
}

// windowsFileACLModel is the Terraform plan/state model for windows_file_acl.
type windowsFileACLModel struct {
	ID   types.String `tfsdk:"id"`
	Path types.String `tfsdk:"path"`
	Mode types.String `tfsdk:"mode"`

	Owner types.String `tfsdk:"owner"`

	InheritanceEnabled         types.Bool `tfsdk:"inheritance_enabled"`
	PreserveInheritedOnProtect types.Bool `tfsdk:"preserve_inherited_on_protect"`

	AccessRules []windowsFileACLRuleModel `tfsdk:"access_rule"`

	TargetType           types.String `tfsdk:"target_type"`
	OwnerSID             types.String `tfsdk:"owner_sid"`
	SDDL                 types.String `tfsdk:"sddl"`
	EffectiveAccessRules types.List   `tfsdk:"effective_access_rules"`

	Timeouts timeouts.Value `tfsdk:"timeouts"`
}

// windowsFileACLRuleModel is one access_rule block. It holds no computed
// attribute on purpose: see the package comment.
type windowsFileACLRuleModel struct {
	Identity    types.String `tfsdk:"identity"`
	Rights      types.Set    `tfsdk:"rights"`
	Type        types.String `tfsdk:"type"`
	Inheritance types.String `tfsdk:"inheritance"`
	Propagation types.String `tfsdk:"propagation"`
}

// fileACLEffectiveRuleAttrTypes describes one element of effective_access_rules.
var fileACLEffectiveRuleAttrTypes = map[string]attr.Type{
	"identity":     types.StringType,
	"identity_sid": types.StringType,
	"rights":       types.ListType{ElemType: types.StringType},
	"access_mask":  types.Int64Type,
	"type":         types.StringType,
	"inheritance":  types.StringType,
	"propagation":  types.StringType,
	"inherited":    types.BoolType,
}

var fileACLEffectiveRuleObjectType = types.ObjectType{AttrTypes: fileACLEffectiveRuleAttrTypes}

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators
// ---------------------------------------------------------------------------

func (r *windowsFileACLResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file_acl"
}

func (r *windowsFileACLResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsFileACLSchemaDefinition(ctx)
}

func windowsFileACLSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages the NTFS security descriptor of an existing file or directory on a remote " +
			"Windows host over SSH + PowerShell: owner, DACL and inheritance protection.\n\n" +
			"The target is never created nor deleted by this resource. Content is managed by `windows_file`, " +
			"which preserves the security descriptor on every write, so both resources can safely manage the " +
			"same path.\n\n" +
			"Audit entries (SACL) are out of scope: they require `SeSecurityPrivilege` and a different ACL type. " +
			"Permissions are never applied recursively.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Normalised absolute path of the secured target.",
			},
			"path": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(windowsFilePathRegex,
						`must be an absolute Windows path (C:\\dir\\file.txt) or a UNC path (\\\\server\\share\\dir)`),
					fileACLPathValidator{},
				},
				Description: "Absolute path of the file or directory whose security descriptor is managed. " +
					"The target must already exist. ForceNew.",
			},
			"mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(winclient.FileACLModeAuthoritative),
				Validators: []validator.String{
					stringvalidator.OneOf(winclient.FileACLModeAuthoritative, winclient.FileACLModeAdditive),
				},
				MarkdownDescription: "How the DACL is reconciled.\n\n" +
					"- `authoritative` (default): the explicit DACL is exactly the declared rules. Any explicit " +
					"entry that is not declared is removed, and an out-of-band addition shows up as drift.\n" +
					"- `additive`: only the declared rules are enforced. Other explicit entries are left untouched " +
					"and never diffed.",
			},
			"owner": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				MarkdownDescription: "Owner to enforce, as a SID, a qualified name (`DOMAIN\\\\user`, " +
					"`BUILTIN\\\\Administrators`) or a bare local name. When omitted, ownership is left untouched " +
					"and never diffed.\n\n" +
					"Changing the owner requires `SeTakeOwnershipPrivilege` and `SeRestorePrivilege` on the " +
					"connecting account.",
			},
			"inheritance_enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				Description: "Whether the target inherits permissions from its parent. Setting it to false " +
					"protects the target from inheritance.",
			},
			"preserve_inherited_on_protect": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				MarkdownDescription: "When inheritance is disabled, whether the previously inherited entries are " +
					"converted into explicit ones (`true`) or dropped (`false`).\n\n" +
					"This only has an observable effect in `additive` mode: in `authoritative` mode the converted " +
					"entries are not declared, so they are removed by the same apply.",
			},

			"target_type": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Whether the target is a file or a directory, as observed on the host.",
			},
			"owner_sid": schema.StringAttribute{
				Computed:    true,
				Description: "Canonical SID of the observed owner.",
			},
			"sddl": schema.StringAttribute{
				Computed: true,
				Description: "Security descriptor of the target in SDDL form, as observed on the host. " +
					"Exposed for diagnostics.",
			},
			"effective_access_rules": schema.ListAttribute{
				Computed:    true,
				ElementType: fileACLEffectiveRuleObjectType,
				MarkdownDescription: "Every entry of the observed DACL, inherited ones included, in the order " +
					"Windows returns them. Each element carries `identity`, `identity_sid`, `rights`, " +
					"`access_mask`, `type`, `inheritance`, `propagation` and `inherited`.",
			},

			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
		Blocks: map[string]schema.Block{
			"access_rule": schema.ListNestedBlock{
				MarkdownDescription: "One explicit DACL entry. Deny entries are written before allow entries, " +
					"in the canonical Windows order, whatever order the blocks are declared in.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"identity": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
							MarkdownDescription: "Trustee, as a SID (`S-1-5-32-544`), a qualified name " +
								"(`DOMAIN\\\\user`, `NT AUTHORITY\\\\SYSTEM`) or a bare local name. It is resolved " +
								"on the target and compared by SID, so renaming or re-qualifying an account does " +
								"not produce a spurious diff.",
						},
						"rights": schema.SetAttribute{
							Required:    true,
							ElementType: types.StringType,
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
								setvalidator.ValueStringsAre(stringvalidator.OneOf(winclient.FileACLValidRights()...)),
							},
							MarkdownDescription: "Rights granted or denied, from the `FileSystemRights` " +
								"enumeration. Composite values overlap (`Modify` includes `Read`), and comparison " +
								"is done on the resulting access mask, not on the keywords.",
						},
						"type": schema.StringAttribute{
							Optional: true,
							Computed: true,
							Default:  stringdefault.StaticString(winclient.FileACLTypeAllow),
							Validators: []validator.String{
								stringvalidator.OneOf(winclient.FileACLTypeAllow, winclient.FileACLTypeDeny),
							},
							Description: "Whether the entry allows or denies the rights. Defaults to allow.",
						},
						"inheritance": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.OneOf(
									winclient.FileACLInheritanceNone,
									winclient.FileACLInheritanceObject,
									winclient.FileACLInheritanceContainer,
									winclient.FileACLInheritanceContainerObject,
								),
							},
							MarkdownDescription: "What the entry propagates to. Defaults to `none` on a file and " +
								"`container_object` on a directory, which is why it is left unset rather than " +
								"defaulted in the schema: the target type is only known on the host. Any value " +
								"other than `none` is rejected on a file.",
						},
						"propagation": schema.StringAttribute{
							Optional: true,
							Computed: true,
							Default:  stringdefault.StaticString(winclient.FileACLPropagationNone),
							Validators: []validator.String{
								stringvalidator.OneOf(
									winclient.FileACLPropagationNone,
									winclient.FileACLPropagationInheritOnly,
									winclient.FileACLPropagationNoPropagate,
								),
							},
							Description: "How inheritance propagates. Requires an inheritance flag other than none.",
						},
					},
				},
			},
		},
	}
}

// ConfigValidators delegates the cross-field rules to winclient so validation
// and apply cannot drift apart.
func (r *windowsFileACLResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{fileACLCrossFieldValidator{}}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// fileACLPathValidator rejects traversal, wildcards and trailing separators.
// Unlike windows_file it accepts a directory, since a directory has an ACL too.
type fileACLPathValidator struct{}

func (v fileACLPathValidator) Description(_ context.Context) string {
	return `must not contain ".." segments, wildcards or a trailing separator`
}
func (v fileACLPathValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v fileACLPathValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	p := req.ConfigValue.ValueString()
	for _, seg := range strings.Split(p, `\`) {
		if seg == ".." {
			resp.Diagnostics.AddAttributeError(req.Path, "Invalid path",
				fmt.Sprintf(`path %q must not contain ".." segments`, p))
			return
		}
	}
	if strings.ContainsAny(strings.TrimPrefix(p, `\\`), "*?") {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid path",
			fmt.Sprintf("path %q must not contain wildcards", p))
		return
	}
	// A drive root (C:\) is legitimately the only path allowed to end with a
	// separator.
	if strings.HasSuffix(p, `\`) && len(strings.TrimSuffix(p, `\`)) > 2 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid path",
			fmt.Sprintf("path %q must not end with a separator", p))
	}
}

// fileACLCrossFieldValidator runs the winclient validation at plan time and
// warns about a combination that silently does nothing.
type fileACLCrossFieldValidator struct{}

func (v fileACLCrossFieldValidator) Description(_ context.Context) string {
	return "validates mode/access_rule/inheritance coherence"
}
func (v fileACLCrossFieldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v fileACLCrossFieldValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg windowsFileACLModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// An unknown value cannot be validated yet: defer to apply time. path is
	// specifically unknown whenever it references another resource, as in
	// path = windows_file.f.path, which is the idiomatic way to secure a file
	// this provider also creates. Validating it here would reject that config
	// outright with "path must not be empty".
	if cfg.Path.IsUnknown() || cfg.Mode.IsUnknown() ||
		cfg.InheritanceEnabled.IsUnknown() || cfg.PreserveInheritedOnProtect.IsUnknown() {
		return
	}
	for _, rule := range cfg.AccessRules {
		if rule.Identity.IsUnknown() || rule.Rights.IsUnknown() ||
			rule.Type.IsUnknown() || rule.Inheritance.IsUnknown() || rule.Propagation.IsUnknown() {
			return
		}
	}

	input, ok := fileACLInputFromModel(ctx, &cfg, nil, &resp.Diagnostics)
	if !ok {
		return
	}
	if err := winclient.ValidateFileACLInput(&input); err != nil {
		var fe *winclient.FileACLError
		if errors.As(err, &fe) {
			resp.Diagnostics.AddError("Invalid windows_file_acl configuration", fe.Message)
			return
		}
		resp.Diagnostics.AddError("Invalid windows_file_acl configuration", err.Error())
		return
	}

	// Flagged rather than rejected: the combination is harmless, but an operator
	// who sets it expects the inherited entries to survive, and they will not.
	if input.Mode == winclient.FileACLModeAuthoritative &&
		!cfg.InheritanceEnabled.IsNull() && !cfg.InheritanceEnabled.ValueBool() &&
		!cfg.PreserveInheritedOnProtect.IsNull() && cfg.PreserveInheritedOnProtect.ValueBool() {
		resp.Diagnostics.AddAttributeWarning(path.Root("preserve_inherited_on_protect"),
			"preserve_inherited_on_protect is ignored in authoritative mode",
			"Windows converts the inherited entries into explicit ones only when the descriptor is "+
				"committed, so they cannot be reconciled by the apply that creates them: the next apply "+
				"would remove them and no plan would ever be empty. Authoritative mode therefore protects "+
				"the target without preserving them, and the resulting DACL is exactly the declared "+
				"access_rule blocks. Declare the entries you want to keep, or use mode = \"additive\".")
	}
}

// ---------------------------------------------------------------------------
// Configure / ModifyPlan
// ---------------------------------------------------------------------------

func (r *windowsFileACLResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	r.client = winclient.NewFileACLClient(c)
}

// ModifyPlan marks the observed attributes unknown whenever the descriptor is
// going to be rewritten. Without it, Terraform proposes the prior state for
// them and the apply fails with "Provider produced inconsistent result after
// apply" as soon as the new descriptor differs.
func (r *windowsFileACLResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return // destroy, or create where everything is already unknown
	}

	var plan, state windowsFileACLModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if fileACLManagedEqual(&plan, &state) {
		return
	}

	plan.SDDL = types.StringUnknown()
	plan.EffectiveAccessRules = types.ListUnknown(fileACLEffectiveRuleObjectType)
	if !plan.Owner.IsNull() && !plan.Owner.Equal(state.Owner) {
		plan.OwnerSID = types.StringUnknown()
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// fileACLManagedEqual reports whether the two models describe the same desired
// descriptor.
func fileACLManagedEqual(a, b *windowsFileACLModel) bool {
	if !a.Mode.Equal(b.Mode) ||
		!a.Owner.Equal(b.Owner) ||
		!a.InheritanceEnabled.Equal(b.InheritanceEnabled) ||
		!a.PreserveInheritedOnProtect.Equal(b.PreserveInheritedOnProtect) ||
		len(a.AccessRules) != len(b.AccessRules) {
		return false
	}
	for i := range a.AccessRules {
		if !a.AccessRules[i].Identity.Equal(b.AccessRules[i].Identity) ||
			!a.AccessRules[i].Rights.Equal(b.AccessRules[i].Rights) ||
			!a.AccessRules[i].Type.Equal(b.AccessRules[i].Type) ||
			!a.AccessRules[i].Inheritance.Equal(b.AccessRules[i].Inheritance) ||
			!a.AccessRules[i].Propagation.Equal(b.AccessRules[i].Propagation) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *windowsFileACLResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsFileACLModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, d := plan.Timeouts.Create(ctx, fileACLDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file_acl Create", map[string]interface{}{"path": plan.Path.ValueString()})

	r.applyACL(ctx, &plan, nil, "Create", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *windowsFileACLResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsFileACLModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, d := state.Timeouts.Read(ctx, fileACLDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file_acl Read", map[string]interface{}{"path": state.Path.ValueString()})

	observed, err := r.client.Read(ctx, state.Path.ValueString())
	if err != nil {
		addFileACLDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if observed == nil {
		// The secured target is gone: there is no descriptor left to manage.
		resp.State.RemoveResource(ctx)
		return
	}

	applyFileACLState(ctx, &state, observed, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *windowsFileACLResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state windowsFileACLModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = state.ID

	timeout, d := plan.Timeouts.Update(ctx, fileACLDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file_acl Update", map[string]interface{}{"path": plan.Path.ValueString()})

	// The previously managed rules are what additive mode has to strip before
	// re-adding, so a shrinking rights list actually takes effect.
	prior, ok := fileACLRulesFromModel(ctx, state.AccessRules, &resp.Diagnostics)
	if !ok {
		return
	}

	r.applyACL(ctx, &plan, prior, "Update", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete restores inheritance and strips the managed entries. It never deletes
// the file or directory: this resource does not own the target's existence.
func (r *windowsFileACLResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsFileACLModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, d := state.Timeouts.Delete(ctx, fileACLDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file_acl Delete", map[string]interface{}{"path": state.Path.ValueString()})

	managed, ok := fileACLRulesFromModel(ctx, state.AccessRules, &resp.Diagnostics)
	if !ok {
		return
	}
	if err := r.client.Reset(ctx, state.Path.ValueString(), managed); err != nil {
		addFileACLDiag(&resp.Diagnostics, "Delete", err)
	}
}

// applyACL pushes the desired descriptor and folds the observed result back
// into the plan model.
func (r *windowsFileACLResource) applyACL(ctx context.Context, plan *windowsFileACLModel, prior []winclient.FileACLAccessRule, op string, diags *diag.Diagnostics) {
	input, ok := fileACLInputFromModel(ctx, plan, prior, diags)
	if !ok {
		return
	}

	observed, err := r.client.Set(ctx, input)
	if err != nil {
		addFileACLDiag(diags, op, err)
		return
	}
	if observed == nil {
		diags.AddError(fmt.Sprintf("ACL %s failed: target not found", op),
			fmt.Sprintf("%q does not exist on the target host. windows_file_acl secures an existing "+
				"file or directory and never creates it.", input.Path))
		return
	}

	// The declared rules are kept verbatim: only the observed-only attributes
	// are folded in, so the state matches the plan exactly.
	fileACLSetObserved(ctx, plan, observed, diags)
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing descriptor, keyed by path:
//
//	terraform import windows_file_acl.conf 'C:\data\app.conf'
//
// The imported mode is authoritative, so the following Read populates one
// access_rule per explicit entry and the first plan is clean.
func (r *windowsFileACLResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" || !windowsFilePathRegex.MatchString(id) {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf(`import ID %q must be an absolute Windows path, e.g. C:\data\app.conf`, req.ID))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mode"), winclient.FileACLModeAuthoritative)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("preserve_inherited_on_protect"), true)...)
	// Overwritten by the Read that follows; set so the state is complete.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("inheritance_enabled"), true)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("access_rule"), []windowsFileACLRuleModel{})...)
}

// ---------------------------------------------------------------------------
// Model conversion
// ---------------------------------------------------------------------------

// fileACLInputFromModel builds the winclient input from a plan or config model.
func fileACLInputFromModel(ctx context.Context, m *windowsFileACLModel, prior []winclient.FileACLAccessRule, diags *diag.Diagnostics) (winclient.FileACLInput, bool) {
	rules, ok := fileACLRulesFromModel(ctx, m.AccessRules, diags)
	if !ok {
		return winclient.FileACLInput{}, false
	}

	mode := m.Mode.ValueString()
	if m.Mode.IsNull() || m.Mode.IsUnknown() {
		mode = winclient.FileACLModeAuthoritative
	}
	// A null bool means "schema default", which is true for both of these.
	inheritance := true
	if !m.InheritanceEnabled.IsNull() && !m.InheritanceEnabled.IsUnknown() {
		inheritance = m.InheritanceEnabled.ValueBool()
	}
	preserve := true
	if !m.PreserveInheritedOnProtect.IsNull() && !m.PreserveInheritedOnProtect.IsUnknown() {
		preserve = m.PreserveInheritedOnProtect.ValueBool()
	}

	return winclient.FileACLInput{
		Path:                       m.Path.ValueString(),
		Mode:                       mode,
		Owner:                      m.Owner.ValueString(),
		InheritanceEnabled:         inheritance,
		PreserveInheritedOnProtect: preserve,
		AccessRules:                rules,
		PriorRules:                 prior,
	}, true
}

// fileACLRulesFromModel converts the access_rule blocks to client rules.
func fileACLRulesFromModel(ctx context.Context, blocks []windowsFileACLRuleModel, diags *diag.Diagnostics) ([]winclient.FileACLAccessRule, bool) {
	out := make([]winclient.FileACLAccessRule, 0, len(blocks))
	for _, block := range blocks {
		var rights []string
		if !block.Rights.IsNull() && !block.Rights.IsUnknown() {
			diags.Append(block.Rights.ElementsAs(ctx, &rights, false)...)
			if diags.HasError() {
				return nil, false
			}
		}
		out = append(out, winclient.FileACLAccessRule{
			Identity:    block.Identity.ValueString(),
			Rights:      rights,
			Type:        block.Type.ValueString(),
			Inheritance: block.Inheritance.ValueString(),
			Propagation: block.Propagation.ValueString(),
		})
	}
	return out, true
}

// fileACLSetObserved folds the observed-only attributes into the model, leaving
// the declared blocks untouched.
func fileACLSetObserved(ctx context.Context, m *windowsFileACLModel, st *winclient.FileACLState, diags *diag.Diagnostics) {
	m.ID = types.StringValue(st.Path)
	m.TargetType = types.StringValue(st.TargetType)
	m.OwnerSID = types.StringValue(st.OwnerSID)
	m.SDDL = types.StringValue(st.SDDL)
	m.InheritanceEnabled = types.BoolValue(st.InheritanceEnabled)

	list, d := fileACLEffectiveList(ctx, st.AccessRules)
	diags.Append(d...)
	if !d.HasError() {
		m.EffectiveAccessRules = list
	}
}

// applyFileACLState folds the observed descriptor into the state during Read,
// reconciling the declared blocks instead of overwriting them.
func applyFileACLState(ctx context.Context, m *windowsFileACLModel, st *winclient.FileACLState, diags *diag.Diagnostics) {
	fileACLSetObserved(ctx, m, st, diags)
	if diags.HasError() {
		return
	}

	mode := m.Mode.ValueString()
	if mode == "" {
		mode = winclient.FileACLModeAuthoritative
	}

	// Ownership is only reconciled when it is managed. An unmanaged owner
	// changing on the host is not drift.
	if !m.Owner.IsNull() && !fileACLIdentityMatches(m.Owner.ValueString(), st.Owner, st.OwnerSID) {
		m.Owner = types.StringValue(st.Owner)
	}

	m.AccessRules = reconcileFileACLRules(ctx, m.AccessRules, st, mode, diags)
}

// reconcileFileACLRules matches each declared rule against the observed explicit
// entries.
//
//   - matched and equivalent: the declared block is kept verbatim, so a rule
//     written as "Modify" is not rewritten and a bare account name is not
//     replaced by its qualified form.
//   - matched but different rights: the observed rights replace the declared
//     ones, which is what makes the drift visible in the next plan.
//   - not matched: the block is dropped from state, so the plan shows it has to
//     be re-created.
//   - observed but not declared: appended in authoritative mode only, so the
//     plan shows it has to be removed. In additive mode it is not managed and
//     is deliberately ignored.
func reconcileFileACLRules(ctx context.Context, declared []windowsFileACLRuleModel, st *winclient.FileACLState, mode string, diags *diag.Diagnostics) []windowsFileACLRuleModel {
	observed := st.ExplicitRules()
	consumed := make([]bool, len(observed))
	out := make([]windowsFileACLRuleModel, 0, len(declared))

	for _, block := range declared {
		idx := fileACLMatchRule(block, observed, consumed, st.TargetType)
		if idx < 0 {
			continue // vanished on the host
		}
		consumed[idx] = true

		declaredMask, err := fileACLBlockMask(ctx, block, diags)
		if err != nil || diags.HasError() {
			// An unparseable declared mask cannot be compared: surface the
			// observed rights so the difference is at least visible.
			out = append(out, fileACLBlockFromObserved(ctx, observed[idx], block, st.TargetType, diags))
			continue
		}
		if winclient.FileACLMasksEquivalent(declaredMask, observed[idx].AccessMask) {
			out = append(out, block)
			continue
		}
		out = append(out, fileACLBlockFromObserved(ctx, observed[idx], block, st.TargetType, diags))
	}

	if mode == winclient.FileACLModeAuthoritative {
		for i, rule := range observed {
			if consumed[i] {
				continue
			}
			out = append(out, fileACLBlockFromObserved(ctx, rule, windowsFileACLRuleModel{}, st.TargetType, diags))
		}
	}
	return out
}

// fileACLMatchRule finds the observed entry a declared block refers to, keyed on
// identity, access control type and the inheritance flags.
func fileACLMatchRule(block windowsFileACLRuleModel, observed []winclient.FileACLAccessRule, consumed []bool, targetType string) int {
	wantType := block.Type.ValueString()
	if wantType == "" {
		wantType = winclient.FileACLTypeAllow
	}
	wantInheritance := block.Inheritance.ValueString()
	if block.Inheritance.IsNull() || wantInheritance == "" {
		wantInheritance = fileACLDefaultInheritance(targetType)
	}
	wantPropagation := block.Propagation.ValueString()
	if block.Propagation.IsNull() || wantPropagation == "" {
		wantPropagation = winclient.FileACLPropagationNone
	}

	for i, rule := range observed {
		if consumed[i] {
			continue
		}
		if rule.Type != wantType || rule.Inheritance != wantInheritance || rule.Propagation != wantPropagation {
			continue
		}
		if fileACLIdentityMatches(block.Identity.ValueString(), rule.Identity, rule.IdentitySID) {
			return i
		}
	}
	return -1
}

// fileACLIdentityMatches compares a declared identity against an observed one.
//
// The SID is authoritative. Names are compared case-insensitively, and a bare
// name is accepted against a qualified one: the machine name of the host is not
// something a configuration should have to spell out, and it changes on every
// start of the disposable container used for acceptance tests.
func fileACLIdentityMatches(declared, observedName, observedSID string) bool {
	d := strings.TrimSpace(declared)
	if d == "" {
		return false
	}
	if strings.EqualFold(d, observedSID) || strings.EqualFold(d, observedName) {
		return true
	}
	// A SID that does not match the observed SID is never the same trustee.
	if strings.HasPrefix(strings.ToUpper(d), "S-1-") {
		return false
	}
	return strings.EqualFold(fileACLBareName(d), fileACLBareName(observedName))
}

// fileACLBareName strips the domain or machine qualifier from an account name.
func fileACLBareName(name string) string {
	if i := strings.LastIndex(name, `\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// fileACLDefaultInheritance mirrors the target-side default.
func fileACLDefaultInheritance(targetType string) string {
	if targetType == winclient.FileACLTargetDirectory {
		return winclient.FileACLInheritanceContainerObject
	}
	return winclient.FileACLInheritanceNone
}

// fileACLBlockMask resolves the access mask a declared block asks for.
func fileACLBlockMask(ctx context.Context, block windowsFileACLRuleModel, diags *diag.Diagnostics) (int64, error) {
	var rights []string
	if !block.Rights.IsNull() && !block.Rights.IsUnknown() {
		diags.Append(block.Rights.ElementsAs(ctx, &rights, false)...)
		if diags.HasError() {
			return 0, fmt.Errorf("cannot read rights")
		}
	}
	_, mask, err := winclient.NormaliseFileACLRights(rights)
	return mask, err
}

// fileACLBlockFromObserved renders an observed entry as an access_rule block.
//
// The declared block is passed in so the operator's own spelling survives
// wherever it is still accurate: rewriting a matching identity or an implicit
// inheritance would show a diff that does not exist.
func fileACLBlockFromObserved(ctx context.Context, rule winclient.FileACLAccessRule, declared windowsFileACLRuleModel, targetType string, diags *diag.Diagnostics) windowsFileACLRuleModel {
	elems := make([]attr.Value, len(rule.Rights))
	for i, right := range rule.Rights {
		elems[i] = types.StringValue(right)
	}
	rights, d := types.SetValue(types.StringType, elems)
	diags.Append(d...)

	identity := types.StringValue(rule.Identity)
	if !declared.Identity.IsNull() &&
		fileACLIdentityMatches(declared.Identity.ValueString(), rule.Identity, rule.IdentitySID) {
		identity = declared.Identity
	}

	// An inheritance left unset in the configuration stays unset when the host
	// agrees with the type-based default.
	inheritance := types.StringValue(rule.Inheritance)
	if declared.Inheritance.IsNull() && rule.Inheritance == fileACLDefaultInheritance(targetType) {
		inheritance = types.StringNull()
	}

	_ = ctx
	return windowsFileACLRuleModel{
		Identity:    identity,
		Rights:      rights,
		Type:        types.StringValue(rule.Type),
		Inheritance: inheritance,
		Propagation: types.StringValue(rule.Propagation),
	}
}

// fileACLEffectiveList renders the whole observed DACL as a computed list.
func fileACLEffectiveList(ctx context.Context, rules []winclient.FileACLAccessRule) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elems := make([]attr.Value, 0, len(rules))
	for _, rule := range rules {
		rightElems := make([]attr.Value, len(rule.Rights))
		for i, right := range rule.Rights {
			rightElems[i] = types.StringValue(right)
		}
		rights, d := types.ListValue(types.StringType, rightElems)
		diags.Append(d...)
		if d.HasError() {
			return types.ListNull(fileACLEffectiveRuleObjectType), diags
		}
		obj, d := types.ObjectValue(fileACLEffectiveRuleAttrTypes, map[string]attr.Value{
			"identity":     types.StringValue(rule.Identity),
			"identity_sid": types.StringValue(rule.IdentitySID),
			"rights":       rights,
			"access_mask":  types.Int64Value(rule.AccessMask),
			"type":         types.StringValue(rule.Type),
			"inheritance":  types.StringValue(rule.Inheritance),
			"propagation":  types.StringValue(rule.Propagation),
			"inherited":    types.BoolValue(rule.Inherited),
		})
		diags.Append(d...)
		if d.HasError() {
			return types.ListNull(fileACLEffectiveRuleObjectType), diags
		}
		elems = append(elems, obj)
	}
	list, d := types.ListValue(fileACLEffectiveRuleObjectType, elems)
	diags.Append(d...)
	_ = ctx
	return list, diags
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

// addFileACLDiag turns a FileACLClient error into an actionable diagnostic.
func addFileACLDiag(diags *diag.Diagnostics, op string, err error) {
	var fe *winclient.FileACLError
	if errors.As(err, &fe) {
		switch fe.Kind {
		case winclient.FileACLErrorNotFound:
			diags.AddError(fmt.Sprintf("ACL %s failed: target not found", op),
				fe.Message+" — windows_file_acl secures an existing file or directory and never creates it. "+
					"Use windows_file, or depends_on, to make sure the target exists first.")
		case winclient.FileACLErrorPathNotFound:
			diags.AddError(fmt.Sprintf("ACL %s failed: parent directory not found", op), fe.Message)
		case winclient.FileACLErrorTypeConflict:
			diags.AddError(fmt.Sprintf("ACL %s failed: target type conflict", op), fe.Message)
		case winclient.FileACLErrorPermission:
			diags.AddError(fmt.Sprintf("ACL %s failed: permission denied", op),
				fe.Message+" — reading or writing a security descriptor requires ReadPermissions and "+
					"ChangePermissions on the target, which an unelevated account rarely holds under "+
					"C:\\Windows or C:\\Program Files.")
		case winclient.FileACLErrorPrivilegeNotHeld:
			diags.AddError(fmt.Sprintf("ACL %s failed: missing privilege", op),
				fe.Message+" — changing the owner requires SeTakeOwnershipPrivilege and "+
					"SeRestorePrivilege. Connect with an account that holds them, or drop the owner "+
					"attribute to leave ownership untouched.")
		case winclient.FileACLErrorIdentityNotFound:
			diags.AddError(fmt.Sprintf("ACL %s failed: unknown identity", op),
				fe.Message+" — the trustee could not be resolved on the target host. Use a SID, or a name "+
					"qualified with the domain or machine it belongs to.")
		case winclient.FileACLErrorInvalidInput:
			diags.AddError(fmt.Sprintf("ACL %s failed: invalid input", op), fe.Message)
		case winclient.FileACLErrorLocked:
			diags.AddError(fmt.Sprintf("ACL %s failed: target is locked", op),
				fe.Message+" — another process holds the target open.")
		default:
			diags.AddError(fmt.Sprintf("ACL %s failed", op), fe.Error())
		}
		return
	}
	diags.AddError(fmt.Sprintf("ACL %s failed", op), err.Error())
}
