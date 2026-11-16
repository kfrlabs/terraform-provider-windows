// Package provider — regression tests for the reserved-device / stripped-name
// plan-time rejection (aggressive Terraform CLI campaign, 2026-11-16).
//
// `C:\...\NUL.txt` applied cleanly, then plan/refresh reported "No changes"
// forever: Win32 resolves the name to the NUL device while .NET manages a
// phantom only it can see. Trailing spaces/dots diverge the same way by
// Win32 name-stripping. Both create-path validators must refuse these
// spellings before anything reaches the host.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	schemavalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestFinalPathSegment(t *testing.T) {
	for in, want := range map[string]string{
		`C:\temp\file.txt`:       "file.txt",
		`C:/temp/file.txt`:       "file.txt",
		`\\server\share\NUL.txt`: "NUL.txt",
		`C:\temp\sub\`:           "sub",
		`C:\temp\sub/`:           "sub",
		``:                       "",
	} {
		if got := finalPathSegment(in); got != want {
			t.Errorf("finalPathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReservedDeviceBase(t *testing.T) {
	for _, bad := range []string{
		"NUL", "nul", "NuL.TxT", "NUL.txt", "con", "CON.log",
		"PRN", "prn.", "AUX", "aux.dat", "COM1", "com9.sys",
		"LPT1", "lpt9", "COM4", "LPT5.txt",
	} {
		if !reservedDeviceBase(bad) {
			t.Errorf("%q should be a reserved device base", bad)
		}
	}
	for _, ok := range []string{
		"content.txt", "console", "COM10", "LPT10", "COM0", "null.txt",
		"my-nul-file", "auxiliary", "...txt", "", "COM1x", "xCOM1",
	} {
		if reservedDeviceBase(ok) {
			t.Errorf("%q must NOT be a reserved device base", ok)
		}
	}
}

func TestHasStrippedTrailingChar(t *testing.T) {
	for _, bad := range []string{"trail.txt ", "trail. ", "name.", "x ."} {
		if !hasStrippedTrailingChar(bad) {
			t.Errorf("%q should be flagged (stripped trailing char)", bad)
		}
	}
	for _, ok := range []string{"file.txt", "no-ext", "...txt", "a b", " a"} {
		if hasStrippedTrailingChar(ok) {
			t.Errorf("%q must NOT be flagged", ok)
		}
	}
}

// Both create-path validators must reject device names and stripped
// spellings, and keep accepting ordinary paths.
func TestCreatePathValidators_RejectUnsafeFinalSegments(t *testing.T) {
	fileV := fileNoTraversalValidator{}
	dirV := directoryNoTraversalValidator{}
	bad := []string{
		`C:\ProgramData\aggr-lab\NUL.txt`,
		`C:\ProgramData\aggr-lab\COM1`,
		`C:\ProgramData\aggr-lab\con.log`,
		`\\server\share\PRN`,
		`C:\ProgramData\aggr-lab\lpt9.dat`,
		`C:\ProgramData\aggr-lab\trail.txt `,
		`C:\ProgramData\aggr-lab\trail.`,
	}
	for _, p := range bad {
		for name, v := range map[string]schemavalidator.String{
			"file": fileV, "directory": dirV,
		} {
			req := schemavalidator.StringRequest{
				Path:        path.Root("path"),
				ConfigValue: types.StringValue(p),
			}
			resp := &schemavalidator.StringResponse{}
			v.ValidateString(context.Background(), req, resp)
			if !resp.Diagnostics.HasError() {
				t.Errorf("%s validator should reject %q", name, p)
			}
		}
	}
}

func TestCreatePathValidators_AcceptOrdinaryPaths(t *testing.T) {
	fileV := fileNoTraversalValidator{}
	dirV := directoryNoTraversalValidator{}
	ok := []string{
		`C:\ProgramData\aggr-lab\app.json`,
		`C:\ProgramData\aggr-lab\content.txt`,
		`C:\ProgramData\aggr-lab\COM10`,
		`\\server\share\data\file.txt`,
	}
	for _, p := range ok {
		for name, v := range map[string]schemavalidator.String{
			"file": fileV, "directory": dirV,
		} {
			req := schemavalidator.StringRequest{
				Path:        path.Root("path"),
				ConfigValue: types.StringValue(p),
			}
			resp := &schemavalidator.StringResponse{}
			v.ValidateString(context.Background(), req, resp)
			if resp.Diagnostics.HasError() {
				t.Errorf("%s validator should accept %q: %v", name, p, resp.Diagnostics)
			}
		}
	}
}
