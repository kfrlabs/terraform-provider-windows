// Package provider: windows_smb_share resource implementation.
//
// Manages a single SMB share on a remote Windows host over SSH + PowerShell:
// the share itself (New-SmbShare / Set-SmbShare / Remove-SmbShare) plus its
// share-level access entries (Grant / Block / Revoke-SmbShareAccess).
//
// The shared directory itself is never created here: pair this resource with
// windows_directory, which owns the directory entry, and optionally with
// windows_file_acl for the NTFS permissions (Windows evaluates share and
// NTFS permissions together, the most restrictive winning).
//
// Access-set semantics (authoritative): when all four of full_access,
// change_access, read_access and no_access are omitted, the host access list
// is left untouched and never diffed. When at least one is configured, all
// four become authoritative: an empty set revokes every entry at that level,
// and any out-of-band entry (including the Everyone:Read entry New-SmbShare
// creates by default) is revoked as stale.
//
// Spec alignment: windows_smb_share spec v1 (issue #221).
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
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
	_ resource.Resource                     = (*windowsSmbShareResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsSmbShareResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsSmbShareResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsSmbShareResource)(nil)
)

// NewWindowsSmbShareResource is the constructor registered in provider.go.
func NewWindowsSmbShareResource() resource.Resource {
	return &windowsSmbShareResource{}
}

// windowsSmbShareResource is the TPF resource type for windows_smb_share.
type windowsSmbShareResource struct {
	client winclient.SmbShareClient
}

// windowsSmbShareModel is the Terraform plan/state model for windows_smb_share.
type windowsSmbShareModel struct {
	ID                    types.String `tfsdk:"id"`
	Name                  types.String `tfsdk:"name"`
	Path                  types.String `tfsdk:"path"`
	Description           types.String `tfsdk:"description"`
	FolderEnumerationMode types.String `tfsdk:"folder_enumeration_mode"`
	CachingMode           types.String `tfsdk:"caching_mode"`
	ConcurrentUserLimit   types.Int64  `tfsdk:"concurrent_user_limit"`
	EncryptData           types.Bool   `tfsdk:"encrypt_data"`

	FullAccess   types.Set `tfsdk:"full_access"`
	ChangeAccess types.Set `tfsdk:"change_access"`
	ReadAccess   types.Set `tfsdk:"read_access"`
	NoAccess     types.Set `tfsdk:"no_access"`

	Special  types.Bool     `tfsdk:"special"`
	Timeouts timeouts.Value `tfsdk:"timeouts"`
}

// smbShareDefaultTimeout is the fallback per-operation timeout when the user
// does not provide a `timeouts {}` block. Share operations are normally fast,
// but a stalled PowerShell/SSH session must never block Terraform forever:
// every CRUD handler bounds its work with this default.
const smbShareDefaultTimeout = 10 * time.Minute

// windowsSmbShareNameRegex accepts 1-80 characters excluding the characters
// Windows forbids in a share name plus control characters. Reserved
// administrative names (IPC$, ADMIN$, <letter>$) are rejected separately by
// smbShareNameValidator so the diagnostic names the rule that was broken.
var windowsSmbShareNameRegex = regexp.MustCompile("^[^\x00-\x1f\x7f\\\\/\\[\\]:|<>+=;,*?\"]{1,80}$")

// windowsSmbSharePathRegex accepts a local drive-letter path (C:\dir\subdir).
// UNC paths are rejected: a share path must be local to the target host.
var windowsSmbSharePathRegex = regexp.MustCompile(`^[A-Za-z]:\\`)

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators
// ---------------------------------------------------------------------------

func (r *windowsSmbShareResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_smb_share"
}

func (r *windowsSmbShareResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsSmbShareSchemaDefinition(ctx)
}

func windowsSmbShareSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a single SMB share on a remote Windows host over SSH + PowerShell: " +
			"the share itself (`New-SmbShare` / `Set-SmbShare` / `Remove-SmbShare`) plus its share-level access entries " +
			"(`Grant-SmbShareAccess` / `Block-SmbShareAccess` / `Revoke-SmbShareAccess`).\n\n" +
			"The shared directory itself is never created here: pair this resource with `windows_directory`, which owns " +
			"the directory entry. NTFS permissions stay with `windows_file_acl`; Windows evaluates share and NTFS " +
			"permissions together, the most restrictive winning.\n\n" +
			"When all four of `full_access`, `change_access`, `read_access` and `no_access` are omitted, the host access " +
			"list is unmanaged: it is left untouched and never diffed. When at least one is configured, all four become " +
			"authoritative: an empty set revokes every entry at that level, and any out-of-band entry (including the " +
			"`Everyone:Read` entry `New-SmbShare` creates by default) is revoked as stale. A principal may belong to at " +
			"most one set.\n\n" +
			"`encrypt_data` defaults to `false`, matching the Windows default; enabling it (`true`) is recommended " +
			"whenever the share carries sensitive data, so traffic cannot be read off the wire.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Share name. Identical to the import ID format.",
			},
			"name": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 80),
					stringvalidator.RegexMatches(windowsSmbShareNameRegex,
						`must be 1-80 characters without \ / [ ] : | < > + = ; , * ? " or control characters`),
					smbShareNameValidator{},
				},
				Description: "SMB share name. ForceNew. Reserved administrative names (IPC$, ADMIN$, <drive-letter>$) are rejected at plan time.",
			},
			"path": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(windowsSmbSharePathRegex,
						`must be a local absolute Windows path (D:\Shares\Finance); UNC paths are not accepted`),
				},
				Description: "Local absolute path of the shared directory on the target host (a trailing backslash is " +
					"normalised away). The directory must already exist at apply time; it is never created here. ForceNew.",
			},
			"description": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(256),
				},
				Description: "Free-form description of the share (≤256 characters).",
			},
			"folder_enumeration_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(winclient.SmbShareFolderEnumerationUnrestricted),
				Validators: []validator.String{
					stringvalidator.OneOf(winclient.SmbShareValidFolderEnumerationModes()...),
				},
				Description: "Whether users see only the files they can read (`AccessBased`) or everything " +
					"(`Unrestricted`, the default).",
			},
			"caching_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(winclient.SmbShareCachingManual),
				Validators: []validator.String{
					stringvalidator.OneOf(winclient.SmbShareValidCachingModes()...),
				},
				Description: "Offline file caching mode: `None`, `Manual` (the default), `Programs`, `Documents` or `BranchCache`.",
			},
			"concurrent_user_limit": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
					int64validator.AtMost(winclient.SmbShareMaxConcurrentUserLimit),
				},
				Description: "Maximum number of concurrent users (0 means no limit).",
			},
			"encrypt_data": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Whether SMB encryption is required for the share. Defaults to `false`; enabling it " +
					"(`true`) is recommended whenever the share carries sensitive data.",
			},

			"full_access": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
				},
				MarkdownDescription: "Trustees granted full share access, as SIDs (`S-1-5-32-544`), qualified names " +
					"(`BUILTIN\\Administrators`, `DOMAIN\\user`) or bare local names. Compared by SID: renaming or " +
					"re-qualifying an account does not produce a spurious diff. Authoritative when any access set is " +
					"configured; unmanaged when all four are omitted.",
			},
			"change_access": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
				},
				MarkdownDescription: "Trustees granted change share access. Same identity semantics as `full_access`. " +
					"Granting `Everyone` or `Authenticated Users` here warns (but still applies): prefer least privilege.",
			},
			"read_access": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
				},
				MarkdownDescription: "Trustees granted read share access. Same identity semantics as `full_access`.",
			},
			"no_access": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
				},
				MarkdownDescription: "Trustees explicitly denied share access (`Block-SmbShareAccess`). Same identity " +
					"semantics as `full_access`.",
			},

			"special": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether the share is administrative (`ADMIN$`, `C$`, `IPC$`). Special shares " +
					"are owned by Windows and cannot be imported; they are reported here for visibility.",
			},

			// Per-operation timeouts (terraform-plugin-framework-timeouts).
			// Create/Read/Update/Delete each default to smbShareDefaultTimeout
			// so a stalled remote command surfaces a timeout diagnostic
			// instead of blocking Terraform indefinitely.
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

// ConfigValidators delegates the cross-set duplicate rule to winclient so
// validation and apply cannot drift apart, and warns about over-broad grants.
func (r *windowsSmbShareResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{smbShareConfigValidator{}}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// smbShareNameValidator rejects the reserved administrative share names
// (IPC$, ADMIN$, <drive-letter>$) that the character-class regex above lets
// through, so the diagnostic names the rule that was broken.
type smbShareNameValidator struct{}

func (v smbShareNameValidator) Description(_ context.Context) string {
	return "must not be a reserved administrative share name (IPC$, ADMIN$, <drive-letter>$)"
}
func (v smbShareNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v smbShareNameValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	p := req.ConfigValue.ValueString()
	upper := strings.ToUpper(p)
	reserved := upper == "IPC$" || upper == "ADMIN$" ||
		(len(p) == 2 && upper[1] == '$' && upper[0] >= 'A' && upper[0] <= 'Z')
	if reserved {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid share name",
			fmt.Sprintf("share name %q is a reserved administrative share name (IPC$, ADMIN$, <drive-letter>$)", p))
	}
}

// smbShareConfigValidator runs the winclient cross-set validation at plan
// time and warns about over-broad grants.
type smbShareConfigValidator struct{}

func (v smbShareConfigValidator) Description(_ context.Context) string {
	return "validates that a principal belongs to at most one access set"
}
func (v smbShareConfigValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v smbShareConfigValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg windowsSmbShareModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// An unknown value cannot be validated yet: defer to apply time.
	if cfg.Name.IsUnknown() || cfg.Path.IsUnknown() || cfg.Description.IsUnknown() ||
		cfg.FolderEnumerationMode.IsUnknown() || cfg.CachingMode.IsUnknown() ||
		cfg.ConcurrentUserLimit.IsUnknown() || cfg.EncryptData.IsUnknown() ||
		cfg.FullAccess.IsUnknown() || cfg.ChangeAccess.IsUnknown() ||
		cfg.ReadAccess.IsUnknown() || cfg.NoAccess.IsUnknown() {
		return
	}

	settings, ok := smbShareSettingsFromModel(ctx, &cfg, &resp.Diagnostics)
	if !ok {
		return
	}
	if err := winclient.ValidateSmbShareSettings(&settings); err != nil {
		var se *winclient.SmbShareError
		if errors.As(err, &se) {
			resp.Diagnostics.AddError("Invalid windows_smb_share configuration", se.Message)
			return
		}
		resp.Diagnostics.AddError("Invalid windows_smb_share configuration", err.Error())
		return
	}

	// Over-broad grants are flagged rather than rejected: an operator who
	// writes them may mean it, but full/change for Everyone (or
	// Authenticated Users) deserves a second look.
	for _, bucket := range []struct {
		level string
		items []string
	}{
		{"full_access", settings.FullAccess},
		{"change_access", settings.ChangeAccess},
	} {
		for _, p := range bucket.items {
			if winclient.SmbShareBroadPrincipal(p) {
				resp.Diagnostics.AddAttributeWarning(
					path.Root(bucket.level),
					"Over-broad share access grant",
					fmt.Sprintf("principal %q in %s grants access to nearly anybody; prefer least privilege and "+
						"scope the share to the accounts that need it.", p, bucket.level),
				)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *windowsSmbShareResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = winclient.NewSmbShareClient(c)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// addSmbShareDiag appends a diagnostic from a SmbShareClient error.
func addSmbShareDiag(diags *diag.Diagnostics, op string, err error) {
	var se *winclient.SmbShareError
	if errors.As(err, &se) {
		switch se.Kind {
		case winclient.SmbShareErrorAlreadyExists:
			diags.AddError(
				fmt.Sprintf("SMB share %s failed: already exists", op),
				se.Message,
			)
		case winclient.SmbShareErrorNotFound:
			diags.AddError(
				fmt.Sprintf("SMB share %s failed: not found", op),
				se.Message+" — the share was removed out-of-band; apply will recreate it, or remove the resource from configuration.",
			)
		case winclient.SmbShareErrorPathNotFound:
			diags.AddError(
				fmt.Sprintf("SMB share %s failed: share path not found", op),
				se.Message+" — the shared directory must already exist on the target host. Manage it with windows_directory.",
			)
		case winclient.SmbShareErrorAccessDenied:
			diags.AddError(
				fmt.Sprintf("SMB share %s failed: permission denied", op),
				se.Message+" — managing shares requires an elevated (administrator) connection.",
			)
		case winclient.SmbShareErrorInvalidName:
			diags.AddError(
				fmt.Sprintf("SMB share %s failed: invalid name", op),
				se.Message,
			)
		case winclient.SmbShareErrorPrincipalNotFound:
			diags.AddError(
				fmt.Sprintf("SMB share %s failed: unknown trustee", op),
				se.Message+" — the trustee could not be resolved on the target host. Use a SID, or a name "+
					"qualified with the domain or machine it belongs to.",
			)
		case winclient.SmbShareErrorServerServiceUnavailable:
			diags.AddError(
				fmt.Sprintf("SMB share %s failed: Server service unavailable", op),
				se.Message+" — the LanmanServer service must be running on the target host to manage SMB shares.",
			)
		default:
			diags.AddError(
				fmt.Sprintf("Error during windows_smb_share %s", op),
				se.Message,
			)
		}
		return
	}
	diags.AddError(
		fmt.Sprintf("Error during windows_smb_share %s", op),
		err.Error(),
	)
}

// smbShareSettingsFromModel builds the winclient settings from a plan or
// config model. ManageAccess is derived from the sets' null-ness: all four
// null means unmanaged, any configured set (even empty) means authoritative.
// An unknown set cannot be decided yet: the handler aborts with a diagnostic
// so the run is deferred instead of silently skipping (or forcing) the access
// sync on a value that is not resolved.
func smbShareSettingsFromModel(ctx context.Context, m *windowsSmbShareModel, diags *diag.Diagnostics) (winclient.SmbShareSettings, bool) {
	if m.FullAccess.IsUnknown() || m.ChangeAccess.IsUnknown() || m.ReadAccess.IsUnknown() || m.NoAccess.IsUnknown() {
		diags.AddError(
			"Unknown SMB share access set",
			"One or more of full_access, change_access, read_access, no_access is unknown. "+
				"Retry the apply once the referenced values are known instead of converging the access list on a guess.",
		)
		return winclient.SmbShareSettings{}, false
	}
	decode := func(s types.Set) ([]string, bool) {
		if s.IsNull() || s.IsUnknown() {
			return nil, true
		}
		var out []string
		diags.Append(s.ElementsAs(ctx, &out, false)...)
		if diags.HasError() {
			return nil, false
		}
		if out == nil {
			out = []string{}
		}
		return out, true
	}
	full, ok := decode(m.FullAccess)
	if !ok {
		return winclient.SmbShareSettings{}, false
	}
	change, ok := decode(m.ChangeAccess)
	if !ok {
		return winclient.SmbShareSettings{}, false
	}
	read, ok := decode(m.ReadAccess)
	if !ok {
		return winclient.SmbShareSettings{}, false
	}
	no, ok := decode(m.NoAccess)
	if !ok {
		return winclient.SmbShareSettings{}, false
	}
	folderMode := m.FolderEnumerationMode.ValueString()
	if m.FolderEnumerationMode.IsNull() || m.FolderEnumerationMode.IsUnknown() {
		folderMode = ""
	}
	caching := m.CachingMode.ValueString()
	if m.CachingMode.IsNull() || m.CachingMode.IsUnknown() {
		caching = ""
	}
	return winclient.SmbShareSettings{
		Description:           m.Description.ValueString(),
		FolderEnumerationMode: folderMode,
		CachingMode:           caching,
		ConcurrentUserLimit:   m.ConcurrentUserLimit.ValueInt64(),
		EncryptData:           m.EncryptData.ValueBool(),
		FullAccess:            full,
		ChangeAccess:          change,
		ReadAccess:            read,
		NoAccess:              no,
		ManageAccess: (!m.FullAccess.IsNull() && !m.FullAccess.IsUnknown()) ||
			(!m.ChangeAccess.IsNull() && !m.ChangeAccess.IsUnknown()) ||
			(!m.ReadAccess.IsNull() && !m.ReadAccess.IsUnknown()) ||
			(!m.NoAccess.IsNull() && !m.NoAccess.IsUnknown()),
	}, true
}

// smbShareAccessManaged reports whether the model manages the host access
// list: true when at least one access set is configured, false when all four
// are null (unmanaged). Unknown sets are never managed: an undecided value
// must not flip the access list into authoritative mode.
func smbShareAccessManaged(m *windowsSmbShareModel) bool {
	return (!m.FullAccess.IsNull() && !m.FullAccess.IsUnknown()) ||
		(!m.ChangeAccess.IsNull() && !m.ChangeAccess.IsUnknown()) ||
		(!m.ReadAccess.IsNull() && !m.ReadAccess.IsUnknown()) ||
		(!m.NoAccess.IsNull() && !m.NoAccess.IsUnknown())
}

// smbShareIdentityMatches compares a declared trustee against an observed one.
//
// The SID is authoritative. Names are compared case-insensitively, and a bare
// name is accepted against a qualified one: the machine name of the host is
// not something a configuration should have to spell out.
func smbShareIdentityMatches(declared, observedName, observedSID string) bool {
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
	return strings.EqualFold(smbShareBareName(d), smbShareBareName(observedName))
}

// smbShareBareName strips the domain or machine qualifier from an account name.
func smbShareBareName(name string) string {
	if i := strings.LastIndex(name, `\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// reconcileSmbShareSet matches a declared access set against the observed
// trustees at the same level:
//
//   - matched: the declared spelling is kept verbatim, so "Modify"-style
//     rewrites and re-qualifications never show a diff.
//   - vanished on the host: dropped from state, so the plan recreates it.
//   - observed but not declared: appended (authoritative mode), so the plan
//     shows it has to be revoked.
//
// A null declared set means unmanaged and stays null — unless the access list
// as a whole is managed (managed=true), in which case a null set is
// authoritative-empty: observed names are returned as a non-null set so the
// plan shows the revoke, while an empty observed list keeps null (nothing to
// revoke, and a null plan already converges). An unknown declared set is
// returned unchanged: its value cannot be reconciled yet.
func reconcileSmbShareSet(ctx context.Context, declared types.Set, observed []winclient.SmbShareTrustee, managed bool, diags *diag.Diagnostics) types.Set {
	if declared.IsUnknown() {
		return declared
	}
	if declared.IsNull() {
		if !managed {
			return declared
		}
		// Authoritative-empty: nothing observed means nothing to revoke, so
		// keep null (a null plan already converges — materialising an empty
		// set here would perpetual-diff null vs empty). A non-empty observed
		// list is returned verbatim so the plan shows the revoke.
		if len(observed) == 0 {
			return declared
		}
		names := make([]string, 0, len(observed))
		for _, o := range observed {
			names = append(names, o.Name)
		}
		set, d := types.SetValueFrom(ctx, types.StringType, names)
		diags.Append(d...)
		if d.HasError() {
			return declared
		}
		return set
	}
	var elems []string
	diags.Append(declared.ElementsAs(ctx, &elems, false)...)
	if diags.HasError() {
		return declared
	}
	consumed := make([]bool, len(observed))
	out := make([]string, 0, len(elems)+len(observed))
	for _, d := range elems {
		idx := -1
		for i, o := range observed {
			if consumed[i] {
				continue
			}
			if smbShareIdentityMatches(d, o.Name, o.SID) {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue // vanished on the host
		}
		consumed[idx] = true
		out = append(out, d)
	}
	for i, o := range observed {
		if consumed[i] {
			continue
		}
		out = append(out, o.Name)
	}
	set, d := types.SetValueFrom(ctx, types.StringType, out)
	diags.Append(d...)
	if d.HasError() {
		return declared
	}
	return set
}

// applySmbShareInfo folds the observed host state into the model. Declared
// access entries that still match are kept verbatim (no spurious diffs);
// the timeouts block is never touched here.
func applySmbShareInfo(ctx context.Context, m *windowsSmbShareModel, st *winclient.SmbShareInfo, diags *diag.Diagnostics) {
	name := st.Name
	if m.Name.ValueString() != "" && strings.EqualFold(m.Name.ValueString(), st.Name) {
		name = m.Name.ValueString()
	}
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)

	sharePath := st.Path
	if m.Path.ValueString() != "" && strings.EqualFold(m.Path.ValueString(), st.Path) {
		sharePath = m.Path.ValueString()
	}
	m.Path = types.StringValue(sharePath)

	if st.Description == "" && m.Description.IsNull() {
		m.Description = types.StringNull()
	} else {
		m.Description = types.StringValue(st.Description)
	}
	m.FolderEnumerationMode = types.StringValue(st.FolderEnumerationMode)
	m.CachingMode = types.StringValue(st.CachingMode)
	m.ConcurrentUserLimit = types.Int64Value(st.ConcurrentUserLimit)
	m.EncryptData = types.BoolValue(st.EncryptData)
	m.Special = types.BoolValue(st.Special)

	managed := smbShareAccessManaged(m)
	m.FullAccess = reconcileSmbShareSet(ctx, m.FullAccess, st.FullAccess, managed, diags)
	m.ChangeAccess = reconcileSmbShareSet(ctx, m.ChangeAccess, st.ChangeAccess, managed, diags)
	m.ReadAccess = reconcileSmbShareSet(ctx, m.ReadAccess, st.ReadAccess, managed, diags)
	m.NoAccess = reconcileSmbShareSet(ctx, m.NoAccess, st.NoAccess, managed, diags)
}

// ---------------------------------------------------------------------------
// CRUD handlers
// ---------------------------------------------------------------------------

func (r *windowsSmbShareResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan windowsSmbShareModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, smbShareDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	settings, ok := smbShareSettingsFromModel(ctx, &plan, &resp.Diagnostics)
	if !ok {
		return
	}

	normPath, err := winclient.NormalizeSmbSharePath(plan.Path.ValueString())
	if err != nil {
		addSmbShareDiag(&resp.Diagnostics, "Create", err)
		return
	}

	tflog.Debug(ctx, "windows_smb_share Create", map[string]interface{}{
		"name": plan.Name.ValueString(),
		"path": normPath,
	})

	st, err := r.client.Create(ctx, winclient.SmbShareInput{
		Name:             plan.Name.ValueString(),
		Path:             normPath,
		SmbShareSettings: settings,
	})
	if err != nil {
		addSmbShareDiag(&resp.Diagnostics, "Create", err)
		return
	}

	applySmbShareInfo(ctx, &plan, st, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *windowsSmbShareResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsSmbShareModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := state.Timeouts.Read(ctx, smbShareDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	name := state.Name.ValueString()
	if name == "" {
		name = state.ID.ValueString()
	}

	tflog.Debug(ctx, "windows_smb_share Read", map[string]interface{}{"name": name})

	st, err := r.client.Read(ctx, name)
	if err != nil {
		addSmbShareDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if st == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	applySmbShareInfo(ctx, &state, st, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *windowsSmbShareResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state windowsSmbShareModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = state.ID

	updateTimeout, diags := plan.Timeouts.Update(ctx, smbShareDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	settings, ok := smbShareSettingsFromModel(ctx, &plan, &resp.Diagnostics)
	if !ok {
		return
	}

	tflog.Debug(ctx, "windows_smb_share Update", map[string]interface{}{"name": plan.Name.ValueString()})

	st, err := r.client.Update(ctx, winclient.SmbShareUpdateInput{
		Name:             plan.Name.ValueString(),
		SmbShareSettings: settings,
	})
	if err != nil {
		addSmbShareDiag(&resp.Diagnostics, "Update", err)
		return
	}

	applySmbShareInfo(ctx, &plan, st, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *windowsSmbShareResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsSmbShareModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, smbShareDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	name := state.Name.ValueString()
	if name == "" {
		name = state.ID.ValueString()
	}

	tflog.Debug(ctx, "windows_smb_share Delete", map[string]interface{}{"name": name})

	if err := r.client.Delete(ctx, name); err != nil {
		addSmbShareDiag(&resp.Diagnostics, "Delete", err)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

// ImportState adopts an existing share by name:
//
//	terraform import windows_smb_share.finance 'Finance'
//
// Special (administrative) shares are refused: they are owned by Windows, not
// by Terraform. Access sets start unmanaged (null); declare them to take
// over the access list authoritatively.
func (r *windowsSmbShareResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if err := winclient.ValidateSmbShareName(name); err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("import ID %q must be a valid SMB share name (1-80 characters, no reserved administrative name).", req.ID))
		return
	}

	tflog.Debug(ctx, "windows_smb_share ImportState", map[string]interface{}{"name": name})

	// No prior state exists at import time, so a configured timeouts.read
	// cannot be honoured; bound the remote call with the resource default.
	ctx, cancel := context.WithTimeout(ctx, smbShareDefaultTimeout)
	defer cancel()

	st, err := r.client.Read(ctx, name)
	if err != nil {
		addSmbShareDiag(&resp.Diagnostics, "ImportState", err)
		return
	}
	if st == nil {
		resp.Diagnostics.AddError(
			"Import failed: SMB share not found",
			fmt.Sprintf("SMB share %q does not exist on the target host. Verify the name, or use config+apply to create it.", name),
		)
		return
	}
	if st.Special {
		resp.Diagnostics.AddError(
			"Import failed: special share",
			fmt.Sprintf("SMB share %q is a special (administrative) share owned by Windows; it cannot be imported or managed by Terraform.", name),
		)
		return
	}

	model := windowsSmbShareModel{
		Timeouts: smbNullTimeouts(),
	}
	applySmbShareInfo(ctx, &model, st, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	// Import starts unmanaged: the observed access list is reported in the
	// following Read's drift, and declaring the sets takes it over.
	model.FullAccess = types.SetNull(types.StringType)
	model.ChangeAccess = types.SetNull(types.StringType)
	model.ReadAccess = types.SetNull(types.StringType)
	model.NoAccess = types.SetNull(types.StringType)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// smbNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with NO attribute
// types, which the framework rejects on State.Set — the failure mode on
// import, where there is no prior state to copy the value from.
func smbNullTimeouts() timeouts.Value {
	return timeouts.Value{Object: types.ObjectNull(map[string]attr.Type{
		"create": types.StringType,
		"read":   types.StringType,
		"update": types.StringType,
		"delete": types.StringType,
	})}
}
