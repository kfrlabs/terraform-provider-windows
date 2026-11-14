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

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Plan/state model and state upgrade. Split from resource_windows_file.go (issue #349, no changes).
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
	Attributes    types.Set    `tfsdk:"attributes"`

	ContentSHA256 types.String `tfsdk:"content_sha256"`
	SizeBytes     types.Int64  `tfsdk:"size_bytes"`
	LastWriteTime types.String `tfsdk:"last_write_time"`

	Timeouts timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// State upgrade (issue #324: attributes List -> Set)
// ---------------------------------------------------------------------------

// windowsFileModelV0 is the prior (v0) state shape, which still carries
// `attributes` as a List.
type windowsFileModelV0 struct {
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

// windowsFilePriorSchemaV0 returns the v0 schema: the current schema with
// `attributes` as a List.
func windowsFilePriorSchemaV0(ctx context.Context) *schema.Schema {
	s := windowsFileSchemaDefinition(ctx)
	s.Version = 0
	s.Attributes["attributes"] = schema.ListAttribute{
		Optional:    true,
		Computed:    true,
		ElementType: types.StringType,
		Description: "File attributes to enforce: hidden, readonly, archive, system, temporary.",
	}
	return &s
}

// UpgradeState maps the v0 List-based state to the v1 Set-based state.
func (r *windowsFileResource) UpgradeState(_ context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema:   windowsFilePriorSchemaV0(context.Background()),
			StateUpgrader: upgradeWindowsFileStateV0ToV1,
		},
	}
}

// upgradeWindowsFileStateV0ToV1 copies every v0 field into the current (v1)
// shape, converting the `attributes` list into a set. Element values are
// preserved; only the collection kind changes, so order no longer matters.
func upgradeWindowsFileStateV0ToV1(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	var prior windowsFileModelV0
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var attrs types.Set
	switch {
	case prior.Attributes.IsNull():
		attrs = types.SetNull(types.StringType)
	case prior.Attributes.IsUnknown():
		attrs = types.SetUnknown(types.StringType)
	default:
		var names []string
		resp.Diagnostics.Append(prior.Attributes.ElementsAs(ctx, &names, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		v, d := types.SetValueFrom(ctx, types.StringType, names)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		attrs = v
	}

	upgraded := windowsFileModel{
		ID:                          prior.ID,
		Path:                        prior.Path,
		Content:                     prior.Content,
		ContentBase64:               prior.ContentBase64,
		ContentWO:                   prior.ContentWO,
		ContentBase64WO:             prior.ContentBase64WO,
		ContentWOVersion:            prior.ContentWOVersion,
		Source:                      prior.Source,
		SourceURL:                   prior.SourceURL,
		SourceURLSHA256:             prior.SourceURLSHA256,
		SourceURLHeaders:            prior.SourceURLHeaders,
		SourceURLInsecureSkipVerify: prior.SourceURLInsecureSkipVerify,
		DownloadOn:                  prior.DownloadOn,
		Encoding:                    prior.Encoding,
		Overwrite:                   prior.Overwrite,
		CreateParents:               prior.CreateParents,
		Attributes:                  attrs,
		ContentSHA256:               prior.ContentSHA256,
		SizeBytes:                   prior.SizeBytes,
		LastWriteTime:               prior.LastWriteTime,
		Timeouts:                    prior.Timeouts,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
}
