// Package provider — regression tests for fileNoTraversalValidator (campaign).
//
// The traversal check must catch ".." segments regardless of separator:
// Windows accepts both `\` and `/`, so `C:/temp/../../evil` must fail
// exactly like its backslash spelling. Wildcards and trailing-separator
// behaviour are unchanged.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	schemavalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func validateFilePath(t *testing.T, p string) bool {
	t.Helper()
	v := fileNoTraversalValidator{}
	req := schemavalidator.StringRequest{
		Path:        path.Root("path"),
		ConfigValue: types.StringValue(p),
	}
	resp := &schemavalidator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	return resp.Diagnostics.HasError()
}

func TestFileNoTraversalValidator_RejectsForwardSlashTraversal(t *testing.T) {
	for _, bad := range []string{
		`C:/temp/../../evil`,
		`C:/temp/../evil.txt`,
		`//server/share/../evil.txt`,
		`C:\temp/../../evil.txt`,
		`C:/temp\..\evil.txt`,
	} {
		if !validateFilePath(t, bad) {
			t.Errorf("%q should be rejected (.. traversal)", bad)
		}
	}
}

func TestFileNoTraversalValidator_RejectsBackslashTraversal(t *testing.T) {
	for _, bad := range []string{
		`C:\temp\..\evil.txt`,
		`C:\temp\..\..\evil.txt`,
		`\\server\share\..\evil.txt`,
	} {
		if !validateFilePath(t, bad) {
			t.Errorf("%q should be rejected (.. traversal)", bad)
		}
	}
}

func TestFileNoTraversalValidator_AcceptsCleanPaths(t *testing.T) {
	for _, ok := range []string{
		`C:\temp\file.txt`,
		`C:/temp/file.txt`,
		`\\server\share\file.txt`,
		`C:\temp\sub.dir\file.txt`,
		`C:\temp\...txt`,
	} {
		if validateFilePath(t, ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
}

func TestFileNoTraversalValidator_NullSkipped(t *testing.T) {
	v := fileNoTraversalValidator{}
	req := schemavalidator.StringRequest{
		Path:        path.Root("path"),
		ConfigValue: types.StringNull(),
	}
	resp := &schemavalidator.StringResponse{}
	v.ValidateString(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Error("null value should be skipped without error")
	}
}
