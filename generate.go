// Package main: documentation generation entry point.
//
// `go generate ./...` invokes tfplugindocs which:
//   1. Boots a temporary instance of the provider in-process.
//   2. Reads every resource / data-source schema (including the new
//      `timeouts {}` blocks introduced in Tier 2).
//   3. Renders Markdown files under docs/ using the templates in
//      templates/ when present, falling back to the built-in defaults.
//
// The tool itself is pinned to a specific version through tools/tools.go.
// CI (or a release pipeline) is expected to run `make docs` and fail the
// build when docs/ drifts from the generated output.

package main

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name windows --rendered-provider-name windows
