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
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Validators. Split from resource_windows_file.go (issue #349, no changes).
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
// checksum) and CV-6 (system/temporary are mutually exclusive), plus the
// #204 plaintext-HTTP integrity gate (mirrors legacyPackageSourceValidator,
// issue #175; deliberately duplicated rather than shared so legacy_package
// behavior stays untouched).
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

	// Warn on an unpinned URL: the payload is written without integrity
	// verification, so a compromised mirror or account can ship a trojaned
	// payload unnoticed. A pinned digest also keeps plans local.
	// (An http:// URL without a digest errors below instead of warning;
	// download_on = "target" without a digest already errored above as CV-4.)
	digestMissing := cfg.SourceURLSHA256.IsNull() || cfg.SourceURLSHA256.IsUnknown() ||
		cfg.SourceURLSHA256.ValueString() == ""
	urlKnown := !cfg.SourceURL.IsNull() && !cfg.SourceURL.IsUnknown() &&
		cfg.SourceURL.ValueString() != ""
	isHTTP := urlKnown && strings.HasPrefix(strings.ToLower(cfg.SourceURL.ValueString()), "http://")
	if isHTTP {
		// #204 (cf. #175): plaintext HTTP without a pinned digest lets
		// anyone on the network path substitute the payload before it is
		// written to the host. Error regardless of download_on. The double
		// diagnostic with CV-4 (http + download_on = "target" + no digest)
		// is intentional: both rules are violated and each message is
		// actionable on its own. Unlike legacy_package, there is no early
		// return here because CV-4 and this gate check distinct conditions.
		if digestMissing {
			resp.Diagnostics.AddAttributeError(path.Root("source_url_sha256"),
				"source_url_sha256 is required for http:// source_url",
				"A file fetched over plaintext HTTP without a pinned digest can be substituted by "+
					"anyone on the network path before it is written to the host. "+
					"Set source_url_sha256 or switch source_url to https://.")
		}
	} else if urlKnown && digestMissing &&
		cfg.DownloadOn.ValueString() != fileDownloadOnTarget {
		resp.Diagnostics.AddAttributeWarning(path.Root("source_url"),
			"Unpinned source_url",
			"Without source_url_sha256 the downloaded payload is written without integrity verification. "+
				"Pin source_url_sha256 so a compromised mirror or account cannot ship a trojaned payload unnoticed.")
	}

	if cfg.SourceURLInsecureSkipVerify.ValueBool() {
		detail := "source_url_insecure_skip_verify = true disables certificate validation for this download."
		if digestMissing && urlKnown {
			detail += " Without a pinned source_url_sha256 this voids the only remaining origin check: " +
				"anyone on the network path can substitute the payload before it is written to the host."
		}
		resp.Diagnostics.AddAttributeWarning(path.Root("source_url_insecure_skip_verify"),
			"TLS verification disabled",
			detail)
	}
}
