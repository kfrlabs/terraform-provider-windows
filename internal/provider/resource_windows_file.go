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

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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
	_ resource.ResourceWithUpgradeState     = (*windowsFileResource)(nil)
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

// Download modes for the `download_on` attribute.
const (
	fileDownloadOnTerraform = "terraform"
	fileDownloadOnTarget    = "target"
)

// windowsFilePathRegex accepts a drive-letter path or a UNC path and rejects
// the characters Windows forbids in a file name (CV-7, EC-14 companion).
var windowsFilePathRegex = regexp.MustCompile(`^([A-Za-z]:\\|\\\\[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+\\)[^<>:"|?*\x00]*$`)

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
// ModifyPlan performs no network I/O (#325): an unpinned `source_url` leaves
// content_sha256 unknown and the download happens at apply time.
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

	sha, ok := planContentSHA256(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !ok {
		// The desired content cannot be resolved yet (unknown value, or an
		// unpinned source_url that is resolved at apply time): leave
		// everything the write would change as unknown.
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
// performing any network I/O (#325): a pinned source_url digest is used
// as-is, while an unpinned source_url leaves the hash unknown until apply
// fetches and verifies the payload. Plans therefore stay local even when
// the URL is unreachable.
func planContentSHA256(m *windowsFileModel, diags *diag.Diagnostics) (string, bool) {
	switch {
	case !m.SourceURL.IsNull():
		if !m.SourceURLSHA256.IsNull() && m.SourceURLSHA256.ValueString() != "" {
			return strings.ToLower(m.SourceURLSHA256.ValueString()), true
		}
		return "", false

	default:
		bytes, ok := resolveInlineBytes(m, diags)
		if !ok || bytes == nil {
			return "", false
		}
		return sha256Hex(bytes), true
	}
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
		if plan.SourceURLInsecureSkipVerify.ValueBool() {
			diags.AddAttributeWarning(path.Root("source_url_insecure_skip_verify"),
				"TLS verification disabled",
				"source_url_insecure_skip_verify = true disables certificate validation for this download. "+
					"The payload is still verified against source_url_sha256 when pinned; pin the digest so a "+
					"substituted payload cannot be written unnoticed.")
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
	set, d := types.SetValue(types.StringType, elems)
	diags.Append(d...)
	if !d.HasError() {
		m.Attributes = set
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
