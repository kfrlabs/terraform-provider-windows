// Package provider: windows_file resource implementation.
//
// Schema, validators, plan modification, CRUD and ImportState for
// windows_file. SSH interaction is delegated to winclient.FileClientImpl.
//
// Spec alignment: windows_file spec v1 (2026-09-30).
//
// Two design decisions drive most of this file:
//   - D-1/D-2: Read never transfers file bytes; drift is detected by comparing
//     the SHA-256 observed on the host with the SHA-256 of the desired content
//     computed in ModifyPlan. That is what makes `source` and `source_url`
//     idempotent without downloading anything on every refresh.
//   - Import (b): ImportState is the ONLY path allowed to pull content back,
//     and only below winclient.FileImportMaxBytes, so the first post-import
//     plan is clean instead of showing a phantom "" -> "<content>" diff.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
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
	_ resource.Resource                     = (*windowsFileResource)(nil)
	_ resource.ResourceWithConfigure        = (*windowsFileResource)(nil)
	_ resource.ResourceWithImportState      = (*windowsFileResource)(nil)
	_ resource.ResourceWithConfigValidators = (*windowsFileResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*windowsFileResource)(nil)
)

// fileDefaultTimeout covers a slow download plus a slow write.
const fileDefaultTimeout = 10 * time.Minute

// NewWindowsFileResource is the constructor registered in provider.go.
func NewWindowsFileResource() resource.Resource {
	return &windowsFileResource{}
}

// windowsFileResource is the TPF resource type for windows_file.
type windowsFileResource struct {
	client winclient.FileClient
}

// windowsFileModel is the Terraform plan/state model for windows_file.
type windowsFileModel struct {
	ID   types.String `tfsdk:"id"`
	Path types.String `tfsdk:"path"`

	Content          types.String `tfsdk:"content"`
	ContentBase64    types.String `tfsdk:"content_base64"`
	ContentWO        types.String `tfsdk:"content_wo"`
	ContentBase64WO  types.String `tfsdk:"content_base64_wo"`
	ContentWOVersion types.String `tfsdk:"content_wo_version"`
	Source           types.String `tfsdk:"source"`

	SourceURL                   types.String `tfsdk:"source_url"`
	SourceURLSHA256             types.String `tfsdk:"source_url_sha256"`
	SourceURLHeaders            types.Map    `tfsdk:"source_url_headers"`
	SourceURLInsecureSkipVerify types.Bool   `tfsdk:"source_url_insecure_skip_verify"`
	DownloadOn                  types.String `tfsdk:"download_on"`

	Encoding      types.String `tfsdk:"encoding"`
	Overwrite     types.Bool   `tfsdk:"overwrite"`
	CreateParents types.Bool   `tfsdk:"create_parents"`
	Attributes    types.List   `tfsdk:"attributes"`

	ContentSHA256 types.String `tfsdk:"content_sha256"`
	SizeBytes     types.Int64  `tfsdk:"size_bytes"`
	LastWriteTime types.String `tfsdk:"last_write_time"`

	Timeouts timeouts.Value `tfsdk:"timeouts"`
}

// Download modes for the `download_on` attribute.
const (
	fileDownloadOnTerraform = "terraform"
	fileDownloadOnTarget    = "target"
)

// windowsFilePathRegex accepts a drive-letter path or a UNC path and rejects
// the characters Windows forbids in a file name (CV-7, EC-14 companion).
var windowsFilePathRegex = regexp.MustCompile(`^([A-Za-z]:\\|\\\\[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+\\)[^<>:"|?*\x00]*$`)

var sha256HexRegex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// ---------------------------------------------------------------------------
// Metadata / Schema / ConfigValidators
// ---------------------------------------------------------------------------

func (r *windowsFileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (r *windowsFileResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = windowsFileSchemaDefinition(ctx)
}

func windowsFileSchemaDefinition(ctx context.Context) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a single file on a remote Windows host over SSH + PowerShell: content, " +
			"encoding and file attributes.\n\n" +
			"Ownership and ACLs are intentionally **not** managed here: use `windows_file_acl`. " +
			"Updating the content of an existing file preserves its security descriptor.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Normalised absolute path of the file.",
			},
			"path": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.RegexMatches(windowsFilePathRegex,
						`must be an absolute Windows path (C:\\dir\\file.txt) or a UNC path (\\\\server\\share\\file.txt)`),
					fileNoTraversalValidator{},
				},
				Description: "Absolute path of the file on the target host. ForceNew.",
			},

			"content": schema.StringAttribute{
				Optional:    true,
				Description: "Inline text content, written using `encoding`. Stored in state.",
			},
			"content_base64": schema.StringAttribute{
				Optional:    true,
				Description: "Base64-encoded binary content. Stored in state.",
			},
			"content_wo": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				Validators: []validator.String{
					// CV-2: a write-only value cannot be diffed, so the version
					// token is what drives updates and is mandatory.
					stringvalidator.AlsoRequires(path.MatchRoot("content_wo_version")),
				},
				Description: "Write-only inline text content: never persisted to state or plan. Requires `content_wo_version`.",
			},
			"content_base64_wo": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				Validators: []validator.String{
					// CV-2: a write-only value cannot be diffed, so the version
					// token is what drives updates and is mandatory.
					stringvalidator.AlsoRequires(path.MatchRoot("content_wo_version")),
				},
				Description: "Write-only base64 content: never persisted to state or plan. Requires `content_wo_version`.",
			},
			"content_wo_version": schema.StringAttribute{
				Optional: true,
				Description: "Arbitrary version token for write-only content. Terraform cannot diff a write-only value, " +
					"so bumping this token is what triggers a rewrite.",
			},
			"source": schema.StringAttribute{
				Optional: true,
				Description: "Path to a local file on the machine running Terraform. It is read and hashed at plan time, " +
					"so editing the local file produces a diff.",
			},

			"source_url": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^https?://`), "must be an http:// or https:// URL"),
				},
				Description: "HTTP(S) URL of the content to deploy.",
			},
			"source_url_sha256": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(sha256HexRegex, "must be a 64-character hex SHA-256 digest"),
					// CV-5: only meaningful alongside source_url.
					stringvalidator.AlsoRequires(path.MatchRoot("source_url")),
				},
				Description: "Expected SHA-256 of the downloaded payload. Required when `download_on = \"target\"`. " +
					"When omitted the provider must download the URL on every plan to detect drift.",
			},
			"source_url_headers": schema.MapAttribute{
				Optional:    true,
				Sensitive:   true,
				ElementType: types.StringType,
				Validators: []validator.Map{
					// CV-5: only meaningful alongside source_url.
					mapvalidator.AlsoRequires(path.MatchRoot("source_url")),
				},
				Description: "Additional HTTP headers (private repository tokens, etc.).",
			},
			"source_url_insecure_skip_verify": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Skip TLS certificate verification for `source_url`. Raises a warning diagnostic.",
			},
			"download_on": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(fileDownloadOnTerraform),
				Validators: []validator.String{
					stringvalidator.OneOf(fileDownloadOnTerraform, fileDownloadOnTarget),
				},
				Description: "`terraform` (default): the provider downloads and streams the bytes over SSH. " +
					"`target`: the Windows host downloads the URL itself (requires `source_url_sha256`).",
			},

			"encoding": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(fileEncodingUTF8),
				Validators: []validator.String{
					stringvalidator.OneOf(fileEncodings...),
				},
				Description: "Text encoding used for `content` / `content_wo`. Content is written verbatim: " +
					"no line-ending translation is performed.",
			},
			"overwrite": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "When false, creating the resource fails if the file already exists.",
			},
			"create_parents": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Create missing parent directories. They are never removed on destroy.",
			},
			"attributes": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "File attributes to enforce: hidden, readonly, archive, system, temporary.",
			},

			"content_sha256": schema.StringAttribute{
				Computed: true,
				Description: "SHA-256 of the file as observed on the host. Computed from the desired content at plan time, " +
					"which is what surfaces out-of-band changes and local `source` edits.",
			},
			"size_bytes": schema.Int64Attribute{
				Computed:    true,
				Description: "Size of the file in bytes.",
			},
			"last_write_time": schema.StringAttribute{
				Computed:    true,
				Description: "Last write timestamp of the file, ISO 8601 UTC.",
			},

			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Read:   true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

// ConfigValidators implements CV-1..CV-6 (CV-7 is attribute-level).
func (r *windowsFileResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		// CV-1: exactly one content source.
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("content"),
			path.MatchRoot("content_base64"),
			path.MatchRoot("content_wo"),
			path.MatchRoot("content_base64_wo"),
			path.MatchRoot("source"),
			path.MatchRoot("source_url"),
		),
		// CV-2 is enforced one-directionally at attribute level: each write-only
		// content requires content_wo_version. RequiredTogether would be wrong
		// here, since it would also force content_base64_wo whenever
		// content_wo_version is set alongside content_wo.
		// CV-3: encoding only applies to text content.
		resourcevalidator.Conflicting(
			path.MatchRoot("encoding"),
			path.MatchRoot("content_base64"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("encoding"),
			path.MatchRoot("content_base64_wo"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("encoding"),
			path.MatchRoot("source"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("encoding"),
			path.MatchRoot("source_url"),
		),
		// CV-5 is enforced at attribute level (AlsoRequires on source_url_sha256
		// and source_url_headers), CV-4 and CV-6 need value inspection and live
		// in ValidateResource below.
		fileCrossFieldValidator{},
	}
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

// fileNoTraversalValidator rejects ".." segments and wildcards (CV-7).
type fileNoTraversalValidator struct{}

func (v fileNoTraversalValidator) Description(_ context.Context) string {
	return `must not contain ".." segments or wildcards`
}
func (v fileNoTraversalValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v fileNoTraversalValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
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
	}
	if strings.HasSuffix(p, `\`) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid path",
			fmt.Sprintf("path %q must point at a file, not a directory", p))
	}
}

// fileCrossFieldValidator implements CV-4 (target download needs a pinned
// checksum) and CV-6 (system/temporary are mutually exclusive).
type fileCrossFieldValidator struct{}

func (v fileCrossFieldValidator) Description(_ context.Context) string {
	return "validates download_on/source_url_sha256 coherence and the attributes enum"
}
func (v fileCrossFieldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v fileCrossFieldValidator) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg windowsFileModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// CV-4: the host downloading on its own can only be verified by a pinned digest.
	if cfg.DownloadOn.ValueString() == fileDownloadOnTarget &&
		(cfg.SourceURLSHA256.IsNull() || cfg.SourceURLSHA256.ValueString() == "") {
		resp.Diagnostics.AddAttributeError(path.Root("source_url_sha256"),
			"source_url_sha256 is required",
			`download_on = "target" requires source_url_sha256: the provider never sees the payload, so a pinned digest is the only integrity check available.`)
	}

	if cfg.DownloadOn.ValueString() == fileDownloadOnTarget && cfg.SourceURL.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("download_on"),
			"download_on requires source_url",
			`download_on only applies to source_url.`)
	}

	// CV-6: validate the attributes enum and its exclusions.
	if !cfg.Attributes.IsNull() && !cfg.Attributes.IsUnknown() {
		var attrs []string
		resp.Diagnostics.Append(cfg.Attributes.ElementsAs(ctx, &attrs, false)...)
		if !resp.Diagnostics.HasError() {
			if _, err := winclient.NormaliseFileAttributes(attrs); err != nil {
				resp.Diagnostics.AddAttributeError(path.Root("attributes"), "Invalid file attributes", err.Error())
			}
		}
	}

	// Warn on an unpinned URL: every plan then performs a GET.
	if !cfg.SourceURL.IsNull() && cfg.SourceURLSHA256.IsNull() &&
		cfg.DownloadOn.ValueString() != fileDownloadOnTarget {
		resp.Diagnostics.AddAttributeWarning(path.Root("source_url"),
			"Unpinned source_url",
			"Without source_url_sha256 the provider must download the URL on every plan to detect drift. "+
				"Pin the digest to keep plans local and to get integrity verification.")
	}

	if cfg.SourceURLInsecureSkipVerify.ValueBool() {
		resp.Diagnostics.AddAttributeWarning(path.Root("source_url_insecure_skip_verify"),
			"TLS verification disabled",
			"source_url_insecure_skip_verify = true disables certificate validation for this download.")
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *windowsFileResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = winclient.NewFileClient(c)
}

// ---------------------------------------------------------------------------
// ModifyPlan — drift detection (D-2)
// ---------------------------------------------------------------------------

// ModifyPlan computes content_sha256 from the desired content so that a change
// to a local `source` file, or an out-of-band edit on the host, shows up as a
// diff at plan time.
//
// Write-only content is invisible during plan by design, so the sha stays
// unknown whenever content_wo_version changes and is carried over from state
// otherwise.
func (r *windowsFileResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy plan
	}

	var plan windowsFileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write-only inputs: value unavailable at plan time, fall back to the
	// version token.
	var cfg windowsFileModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !cfg.ContentWO.IsNull() || !cfg.ContentBase64WO.IsNull() || !cfg.ContentWOVersion.IsNull() {
		if req.State.Raw.IsNull() {
			return // create: everything is already unknown
		}
		var state windowsFileModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if state.ContentWOVersion.Equal(plan.ContentWOVersion) {
			// Unchanged version: the file is left alone, so the observed values
			// carry over untouched.
			plan.ContentSHA256 = state.ContentSHA256
		} else {
			// A bumped version rewrites the file, and the new content is
			// invisible at plan time: everything the write changes must be
			// unknown, otherwise Terraform rejects the apply result.
			markFileObservedUnknown(&plan)
		}
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}

	sha, ok := r.planContentSHA256(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !ok {
		// The desired content cannot be resolved yet (unknown value, or an
		// unpinned URL that could not be fetched): leave everything the write
		// would change as unknown.
		markFileObservedUnknown(&plan)
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}

	plan.ContentSHA256 = types.StringValue(sha)

	// On update, Terraform proposes the prior state for computed attributes.
	// Whenever the content actually changes, size_bytes and last_write_time
	// will differ after the write, so they have to be unknown in the plan or
	// the apply fails with "Provider produced inconsistent result after apply".
	if !req.State.Raw.IsNull() {
		var state windowsFileModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if state.ContentSHA256.ValueString() != sha {
			plan.SizeBytes = types.Int64Unknown()
			plan.LastWriteTime = types.StringUnknown()
		}
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// markFileObservedUnknown flags every attribute that a write necessarily
// changes, for the cases where the resulting bytes cannot be known at plan
// time.
func markFileObservedUnknown(plan *windowsFileModel) {
	plan.ContentSHA256 = types.StringUnknown()
	plan.SizeBytes = types.Int64Unknown()
	plan.LastWriteTime = types.StringUnknown()
}

// planContentSHA256 resolves the SHA-256 of the desired content without
// necessarily materialising the bytes: a pinned source_url digest is used
// as-is, so a pinned plan performs no network I/O at all.
func (r *windowsFileResource) planContentSHA256(ctx context.Context, m *windowsFileModel, diags *diag.Diagnostics) (string, bool) {
	switch {
	case !m.SourceURL.IsNull():
		if !m.SourceURLSHA256.IsNull() && m.SourceURLSHA256.ValueString() != "" {
			return strings.ToLower(m.SourceURLSHA256.ValueString()), true
		}
		if m.SourceURL.IsUnknown() || m.DownloadOn.ValueString() == fileDownloadOnTarget {
			return "", false
		}
		bytes, err := r.fetchURL(ctx, m, diags)
		if err != nil || bytes == nil {
			return "", false
		}
		return sha256Hex(bytes), true

	default:
		bytes, ok := resolveInlineBytes(m, diags)
		if !ok || bytes == nil {
			return "", false
		}
		return sha256Hex(bytes), true
	}
}

// fetchURL performs a provider-side download, tolerating plan-time failures by
// downgrading them to a warning: a transient network error must not break
// `terraform plan` for an unrelated change.
func (r *windowsFileResource) fetchURL(ctx context.Context, m *windowsFileModel, diags *diag.Diagnostics) ([]byte, error) {
	headers, ok := fileHeadersFromModel(ctx, m, diags)
	if !ok {
		return nil, fmt.Errorf("invalid headers")
	}
	body, err := downloadSource(ctx, m.SourceURL.ValueString(), headers, m.SourceURLInsecureSkipVerify.ValueBool())
	if err != nil {
		diags.AddAttributeWarning(path.Root("source_url"), "Could not download source_url during plan",
			err.Error()+"\n\nThe download will be retried during apply.")
		return nil, err
	}
	return body, nil
}

// resolveInlineBytes materialises content / content_base64 / source.
// Returns ok=false when a value is unknown or absent at this stage.
func resolveInlineBytes(m *windowsFileModel, diags *diag.Diagnostics) ([]byte, bool) {
	switch {
	case !m.Content.IsNull():
		if m.Content.IsUnknown() || m.Encoding.IsUnknown() {
			return nil, false
		}
		b, err := encodeFileContent(m.Content.ValueString(), m.Encoding.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("content"), "Cannot encode content", err.Error())
			return nil, false
		}
		return b, true

	case !m.ContentBase64.IsNull():
		if m.ContentBase64.IsUnknown() {
			return nil, false
		}
		b, err := decodeBase64(m.ContentBase64.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("content_base64"), "Invalid content_base64", err.Error())
			return nil, false
		}
		return b, true

	case !m.Source.IsNull():
		if m.Source.IsUnknown() {
			return nil, false
		}
		b, err := readLocalSource(m.Source.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("source"), "Cannot read source file", err.Error())
			return nil, false
		}
		return b, true
	}
	return nil, false
}

// fileHeadersFromModel converts the source_url_headers map into a Go map.
func fileHeadersFromModel(ctx context.Context, m *windowsFileModel, diags *diag.Diagnostics) (map[string]string, bool) {
	if m.SourceURLHeaders.IsNull() || m.SourceURLHeaders.IsUnknown() {
		return nil, true
	}
	out := map[string]string{}
	d := m.SourceURLHeaders.ElementsAs(ctx, &out, false)
	diags.Append(d...)
	if d.HasError() {
		return nil, false
	}
	return out, true
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func (r *windowsFileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config windowsFileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, d := plan.Timeouts.Create(ctx, fileDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file Create", map[string]interface{}{"path": plan.Path.ValueString()})

	r.setFile(ctx, &plan, &config, "Create", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	nullifyWriteOnly(&plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *windowsFileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state windowsFileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, d := state.Timeouts.Read(ctx, fileDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file Read", map[string]interface{}{"path": state.Path.ValueString()})

	fs, err := r.client.Read(ctx, state.Path.ValueString())
	if err != nil {
		addFileDiag(&resp.Diagnostics, "Read", err)
		return
	}
	if fs == nil {
		// File is gone (EC-4).
		resp.State.RemoveResource(ctx)
		return
	}

	applyFileState(ctx, &state, fs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	nullifyWriteOnly(&state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *windowsFileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state, config windowsFileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = state.ID

	timeout, d := plan.Timeouts.Update(ctx, fileDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file Update", map[string]interface{}{"path": plan.Path.ValueString()})

	// An update always overwrites: the resource already owns this file.
	plan.Overwrite = types.BoolValue(true)

	r.setFile(ctx, &plan, &config, "Update", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	nullifyWriteOnly(&plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *windowsFileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state windowsFileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, d := state.Timeouts.Delete(ctx, fileDefaultTimeout)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tflog.Debug(ctx, "windows_file Delete", map[string]interface{}{"path": state.Path.ValueString()})

	if err := r.client.Delete(ctx, state.Path.ValueString()); err != nil {
		addFileDiag(&resp.Diagnostics, "Delete", err)
	}
}

// setFile resolves the content and performs the write, then folds the observed
// state back into the model.
func (r *windowsFileResource) setFile(ctx context.Context, plan, config *windowsFileModel, op string, diags *diag.Diagnostics) {
	input := winclient.FileInput{
		Path:          plan.Path.ValueString(),
		Overwrite:     plan.Overwrite.ValueBool(),
		CreateParents: plan.CreateParents.ValueBool(),
	}

	if !plan.Attributes.IsNull() && !plan.Attributes.IsUnknown() {
		var attrs []string
		diags.Append(plan.Attributes.ElementsAs(ctx, &attrs, false)...)
		if diags.HasError() {
			return
		}
		input.Attributes = attrs
	}

	switch {
	case !plan.SourceURL.IsNull() && plan.DownloadOn.ValueString() == fileDownloadOnTarget:
		headers, ok := fileHeadersFromModel(ctx, plan, diags)
		if !ok {
			return
		}
		input.DownloadOnTarget = true
		input.SourceURL = plan.SourceURL.ValueString()
		input.SourceURLSHA256 = strings.ToLower(plan.SourceURLSHA256.ValueString())
		input.SourceURLHeaders = headers
		input.SourceURLInsecureSkipVerify = plan.SourceURLInsecureSkipVerify.ValueBool()

	case !plan.SourceURL.IsNull():
		headers, ok := fileHeadersFromModel(ctx, plan, diags)
		if !ok {
			return
		}
		body, err := downloadSource(ctx, plan.SourceURL.ValueString(), headers, plan.SourceURLInsecureSkipVerify.ValueBool())
		if err != nil {
			diags.AddError(fmt.Sprintf("File %s failed: download error", op), err.Error())
			return
		}
		if want := strings.ToLower(plan.SourceURLSHA256.ValueString()); want != "" {
			if got := sha256Hex(body); got != want {
				diags.AddError(fmt.Sprintf("File %s failed: checksum mismatch", op),
					fmt.Sprintf("source_url_sha256 is %s but the downloaded payload hashes to %s", want, got))
				return
			}
		}
		input.ContentBase64 = encodeBase64(body)
		warnLargeContent(int64(len(body)), diags)

	default:
		body, ok := resolveApplyBytes(plan, config, diags)
		if !ok {
			if !diags.HasError() {
				diags.AddError(fmt.Sprintf("File %s failed: no content", op),
					"no usable content source was resolved; this is a provider bug if the configuration passed validation")
			}
			return
		}
		input.ContentBase64 = encodeBase64(body)
		warnLargeContent(int64(len(body)), diags)
	}

	fs, err := r.client.Set(ctx, input)
	if err != nil {
		addFileDiag(diags, op, err)
		return
	}

	plan.ID = types.StringValue(plan.Path.ValueString())
	applyFileState(ctx, plan, fs, diags)
}

// resolveApplyBytes materialises the content at apply time. Write-only values
// are read from the configuration, which is the only place they exist.
func resolveApplyBytes(plan, config *windowsFileModel, diags *diag.Diagnostics) ([]byte, bool) {
	switch {
	case !config.ContentWO.IsNull():
		b, err := encodeFileContent(config.ContentWO.ValueString(), plan.Encoding.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("content_wo"), "Cannot encode content_wo", err.Error())
			return nil, false
		}
		return b, true

	case !config.ContentBase64WO.IsNull():
		b, err := decodeBase64(config.ContentBase64WO.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("content_base64_wo"), "Invalid content_base64_wo", err.Error())
			return nil, false
		}
		return b, true
	}
	return resolveInlineBytes(plan, diags)
}

// warnLargeContent surfaces the 1 MiB advisory threshold (T-2).
func warnLargeContent(size int64, diags *diag.Diagnostics) {
	if size > winclient.FileWarnContentBytes {
		diags.AddWarning("Large file content",
			fmt.Sprintf("This file is %d bytes. Content managed by windows_file is stored in the Terraform state and "+
				"re-transferred on every apply; the hard limit is %d bytes.", size, winclient.FileMaxContentBytes))
	}
}

// ---------------------------------------------------------------------------
// ImportState — decision (b)
// ---------------------------------------------------------------------------

// ImportState adopts an existing file.
//
// Import ID format: the absolute path, e.g.
//
//	terraform import windows_file.web 'C:\inetpub\wwwroot\web.config'
//
// Below winclient.FileImportMaxBytes the real content is fetched and written
// into `content` (valid UTF-8) or `content_base64`, so the first plan after the
// import is clean rather than showing a phantom content diff. Above that
// ceiling the content is left empty and a warning explains why.
func (r *windowsFileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" || !windowsFilePathRegex.MatchString(id) {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf(`import ID %q must be an absolute Windows path, e.g. C:\inetpub\wwwroot\web.config`, req.ID))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("path"), id)...)
	// Defaults for optional+computed attributes so the subsequent Read has a
	// complete state to work from.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("encoding"), fileEncodingUTF8)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("download_on"), fileDownloadOnTerraform)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("overwrite"), true)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("create_parents"), true)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("source_url_insecure_skip_verify"), false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.client == nil {
		return
	}

	content, err := r.client.ReadContent(ctx, id, winclient.FileImportMaxBytes)
	if err != nil {
		addFileDiag(&resp.Diagnostics, "Import", err)
		return
	}
	if content == nil {
		resp.Diagnostics.AddError("File not found",
			fmt.Sprintf("cannot import %q: the file does not exist on the target host", id))
		return
	}

	if content.Truncated {
		resp.Diagnostics.AddWarning("File content not imported",
			fmt.Sprintf("%q is %d bytes, above the %d byte import ceiling, so its content was not read back. "+
				"The first plan will show a diff on the content attribute and the first apply will rewrite the file.",
				id, content.SizeBytes, winclient.FileImportMaxBytes))
		return
	}

	raw, derr := decodeBase64(content.ContentBase64)
	if derr != nil {
		resp.Diagnostics.AddError("Cannot decode imported content", derr.Error())
		return
	}

	if utf8.Valid(raw) {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("content"), string(raw))...)
	} else {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("content_base64"), content.ContentBase64)...)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// applyFileState folds the observed host state into the model.
func applyFileState(ctx context.Context, m *windowsFileModel, fs *winclient.FileState, diags *diag.Diagnostics) {
	m.ID = types.StringValue(fs.Path)
	m.ContentSHA256 = types.StringValue(fs.SHA256)
	m.SizeBytes = types.Int64Value(fs.SizeBytes)
	m.LastWriteTime = types.StringValue(fs.LastWriteTime)

	attrs := fs.Attributes
	if attrs == nil {
		attrs = []string{}
	}
	elems := make([]attr.Value, len(attrs))
	for i, a := range attrs {
		elems[i] = types.StringValue(a)
	}
	list, d := types.ListValue(types.StringType, elems)
	diags.Append(d...)
	if !d.HasError() {
		m.Attributes = list
	}
	_ = ctx
}

// nullifyWriteOnly guarantees no write-only value ever reaches the state.
func nullifyWriteOnly(m *windowsFileModel) {
	m.ContentWO = types.StringNull()
	m.ContentBase64WO = types.StringNull()
}

// addFileDiag turns a FileClient error into an actionable diagnostic.
func addFileDiag(diags *diag.Diagnostics, op string, err error) {
	var fe *winclient.FileError
	if errors.As(err, &fe) {
		switch fe.Kind {
		case winclient.FileErrorTypeConflict:
			diags.AddError(fmt.Sprintf("File %s failed: path is a directory", op),
				fe.Message+" — windows_file manages files only.")
		case winclient.FileErrorAlreadyExists:
			diags.AddError(fmt.Sprintf("File %s failed: file already exists", op),
				fe.Message+" — set overwrite = true, or run terraform import to adopt the existing file.")
		case winclient.FileErrorPathNotFound:
			diags.AddError(fmt.Sprintf("File %s failed: parent directory not found", op),
				fe.Message+" — set create_parents = true to create it.")
		case winclient.FileErrorPermission:
			diags.AddError(fmt.Sprintf("File %s failed: permission denied", op),
				fe.Message+" (writing under C:\\Windows or C:\\Program Files requires an elevated account).")
		case winclient.FileErrorLocked:
			diags.AddError(fmt.Sprintf("File %s failed: file is locked", op),
				fe.Message+" — another process holds the file open; the provider already retried three times.")
		case winclient.FileErrorDiskFull:
			diags.AddError(fmt.Sprintf("File %s failed: disk full", op),
				fe.Message+" — the target file was left untouched.")
		case winclient.FileErrorDownloadFailed:
			diags.AddError(fmt.Sprintf("File %s failed: download error", op), fe.Message)
		case winclient.FileErrorChecksumMismatch:
			diags.AddError(fmt.Sprintf("File %s failed: checksum mismatch", op),
				fe.Message+" — the payload does not match source_url_sha256.")
		case winclient.FileErrorInvalidInput:
			diags.AddError(fmt.Sprintf("File %s failed: invalid input", op), fe.Message)
		default:
			diags.AddError(fmt.Sprintf("File %s failed", op), fe.Error())
		}
		return
	}
	diags.AddError(fmt.Sprintf("File %s failed", op), err.Error())
}
