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
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Metadata, Schema definition and ConfigValidators. Split from resource_windows_file.go (issue #349, no changes).
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
		Version: 1,
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
					stringvalidator.RegexMatches(regexp.MustCompile(`(?i)^https?://`), "must be an http:// or https:// URL"),
				},
				Description: "HTTP(S) URL of the content to deploy. An http:// URL requires source_url_sha256: " +
					"without integrity verification anyone on the network path can substitute the payload before it is written to the host. " +
					"Even over HTTPS, always pin source_url_sha256 so a compromised mirror or account cannot ship a trojaned payload unnoticed.",
				MarkdownDescription: "HTTP(S) URL of the content to deploy.\n\n" +
					"**Threat model:** an `http://` URL **requires** `source_url_sha256`: without integrity verification " +
					"anyone on the network path can substitute the payload before it is written to the host. " +
					"Even over HTTPS, always pin `source_url_sha256` so a compromised mirror or account cannot ship a trojaned payload unnoticed.",
			},
			"source_url_sha256": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(sha256HexRegex, "must be a 64-character hex SHA-256 digest"),
					// CV-5: only meaningful alongside source_url.
					stringvalidator.AlsoRequires(path.MatchRoot("source_url")),
				},
				Description: "Expected SHA-256 of the downloaded payload. Required with an http:// source_url and when " +
					"download_on = \"target\"; strongly recommended otherwise (see the source_url threat model). " +
					"Plans never download: a pinned digest is used as-is for content_sha256 and every payload is verified before it is written.",
				MarkdownDescription: "Expected SHA-256 of the downloaded payload.\n\n" +
					"Required with an `http://` `source_url` and when `download_on = \"target\"`; strongly recommended otherwise " +
					"(see the `source_url` threat model). Plans never download: a pinned digest is used as-is for `content_sha256` and every payload is verified before it is written.",
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
			"attributes": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "File attributes to enforce: hidden, readonly, archive, system, temporary.",
				Validators: []validator.Set{
					// Attribute-level enum (#324): duplicates the cross-field
					// NormaliseFileAttributes check (which also enforces the
					// system/temporary exclusion) with a per-element diagnostic.
					setvalidator.ValueStringsAre(
						stringvalidator.OneOf("hidden", "readonly", "archive", "system", "temporary"),
					),
				},
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
