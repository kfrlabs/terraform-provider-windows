// Build-tagged file used to track developer tooling versions in go.mod /
// go.sum without including them in the production binary.
//
// Run `go generate ./...` (or `make docs`) to regenerate the registry
// documentation under docs/. The actual generation directive lives in
// generate.go at the repository root.
//
//go:build tools

package tools

import (
	// Documentation generator for Terraform plugins. Pinned via go.mod.
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)
