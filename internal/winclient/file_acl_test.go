// Package winclient — unit tests for the windows_file_acl client layer.
//
// Focus: the mask arithmetic that the live-host probe proved to be the fragile
// part (Synchronize, composite alias overlap, FullControl), input validation,
// payload parsing, and the script hygiene invariants.
package winclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormaliseFileACLRights_Masks(t *testing.T) {
	tests := []struct {
		name     string
		in       []string
		wantMask int64
		wantOut  []string
	}{
		{"full control", []string{"FullControl"}, 0x1F01FF, []string{"FullControl"}},
		{"modify", []string{"Modify"}, 197055, []string{"Modify"}},
		{"read and execute", []string{"ReadAndExecute"}, 131241, []string{"ReadAndExecute"}},
		{"read", []string{"Read"}, 131209, []string{"Read"}},
		{"write", []string{"Write"}, 278, []string{"Write"}},
		// Overlapping aliases must OR, not duplicate, and the canonical order is
		// the table order rather than the order the operator happened to use.
		{"overlapping", []string{"Read", "ReadAndExecute"}, 131241, []string{"ReadAndExecute", "Read"}},
		{"case insensitive", []string{"fullcontrol"}, 0x1F01FF, []string{"FullControl"}},
		{"composed", []string{"Read", "Write"}, 131209 | 278, []string{"Read", "Write"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, mask, err := NormaliseFileACLRights(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mask != tc.wantMask {
				t.Errorf("mask = %d, want %d", mask, tc.wantMask)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantOut, ",") {
				t.Errorf("rights = %v, want %v", got, tc.wantOut)
			}
		})
	}
}

func TestNormaliseFileACLRights_Errors(t *testing.T) {
	if _, _, err := NormaliseFileACLRights(nil); !IsFileACLError(err, FileACLErrorInvalidInput) {
		t.Errorf("empty rights: got %v, want invalid_input", err)
	}
	if _, _, err := NormaliseFileACLRights([]string{"Telepathy"}); !IsFileACLError(err, FileACLErrorInvalidInput) {
		t.Errorf("unknown right: got %v, want invalid_input", err)
	}
}

// TestFileACLRightsFromMask_FullControlRoundTrip is the regression test for the
// bug the live probe caught: stripping Synchronize from FullControl decomposes
// 0x1F01FF into Modify + ChangePermissions + TakeOwnership + 0x40 instead of
// rendering FullControl.
func TestFileACLRightsFromMask_FullControlRoundTrip(t *testing.T) {
	rights, residual := FileACLRightsFromMask(0x1F01FF)
	if len(rights) != 1 || rights[0] != "FullControl" {
		t.Errorf("rights = %v, want [FullControl]", rights)
	}
	if residual != 0 {
		t.Errorf("residual = 0x%X, want 0", residual)
	}
}

func TestFileACLRightsFromMask(t *testing.T) {
	tests := []struct {
		name         string
		mask         int64
		wantFirst    string
		wantResidual int64
	}{
		{"modify", 197055, "Modify", 0},
		// A mask stored by the 3-argument constructor carries Synchronize; it is
		// implicit, so it must not surface as an unknown residual right.
		{"modify with synchronize", 197055 | FileACLRightSynchronize, "Modify", 0},
		{"read with synchronize", 131209 | FileACLRightSynchronize, "Read", 0},
		{"generic all is surfaced", 0x10000000, "", 0x10000000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rights, residual := FileACLRightsFromMask(tc.mask)
			if tc.wantFirst == "" {
				if len(rights) != 0 {
					t.Errorf("rights = %v, want empty", rights)
				}
			} else if len(rights) == 0 || rights[0] != tc.wantFirst {
				t.Errorf("rights = %v, want first %q", rights, tc.wantFirst)
			}
			if residual != tc.wantResidual {
				t.Errorf("residual = 0x%X, want 0x%X", residual, tc.wantResidual)
			}
		})
	}
}

// TestFileACLMasksEquivalent covers the observed non-determinism: the same
// declared right lands with or without Synchronize depending on the target type
// and on which API wrote the ACE.
func TestFileACLMasksEquivalent(t *testing.T) {
	if !FileACLMasksEquivalent(131209, 131209|FileACLRightSynchronize) {
		t.Error("Read and Read|Synchronize must compare equal")
	}
	if !FileACLMasksEquivalent(0x1F01FF, 0x1F01FF) {
		t.Error("FullControl must compare equal to itself")
	}
	if FileACLMasksEquivalent(131209, 197055) {
		t.Error("Read and Modify must not compare equal")
	}
}

func TestValidateFileACLInput(t *testing.T) {
	valid := func() FileACLInput {
		return FileACLInput{
			Path:               `C:\data\app.conf`,
			Mode:               FileACLModeAuthoritative,
			InheritanceEnabled: true,
			AccessRules: []FileACLAccessRule{
				{Identity: "BUILTIN\\Administrators", Rights: []string{"FullControl"}},
			},
		}
	}

	t.Run("accepts a valid input and defaults type", func(t *testing.T) {
		in := valid()
		if err := ValidateFileACLInput(&in); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if in.AccessRules[0].Type != FileACLTypeAllow {
			t.Errorf("type = %q, want allow", in.AccessRules[0].Type)
		}
		if in.AccessRules[0].AccessMask != 0x1F01FF {
			t.Errorf("mask = %d, want %d", in.AccessRules[0].AccessMask, 0x1F01FF)
		}
		// An unset inheritance stays unset: only the host knows the target type.
		if in.AccessRules[0].Inheritance != "" {
			t.Errorf("inheritance = %q, want empty", in.AccessRules[0].Inheritance)
		}
	})

	t.Run("rejects empty path", func(t *testing.T) {
		in := valid()
		in.Path = "   "
		if err := ValidateFileACLInput(&in); !IsFileACLError(err, FileACLErrorInvalidInput) {
			t.Errorf("got %v, want invalid_input", err)
		}
	})

	t.Run("rejects unknown mode", func(t *testing.T) {
		in := valid()
		in.Mode = "merge"
		if err := ValidateFileACLInput(&in); !IsFileACLError(err, FileACLErrorInvalidInput) {
			t.Errorf("got %v, want invalid_input", err)
		}
	})

	t.Run("defaults empty mode to authoritative", func(t *testing.T) {
		in := valid()
		in.Mode = ""
		if err := ValidateFileACLInput(&in); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if in.Mode != FileACLModeAuthoritative {
			t.Errorf("mode = %q, want authoritative", in.Mode)
		}
	})

	t.Run("rejects authoritative without rules", func(t *testing.T) {
		in := valid()
		in.AccessRules = nil
		if err := ValidateFileACLInput(&in); !IsFileACLError(err, FileACLErrorInvalidInput) {
			t.Errorf("got %v, want invalid_input", err)
		}
	})

	t.Run("allows additive without rules", func(t *testing.T) {
		in := valid()
		in.Mode = FileACLModeAdditive
		in.AccessRules = nil
		if err := ValidateFileACLInput(&in); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// Protecting a target with no allow entry makes it unreachable to everyone,
	// owner included, and is only recoverable by taking ownership.
	t.Run("rejects protected target with no allow rule", func(t *testing.T) {
		in := valid()
		in.InheritanceEnabled = false
		in.AccessRules = []FileACLAccessRule{
			{Identity: "BUILTIN\\Users", Rights: []string{"Write"}, Type: FileACLTypeDeny},
		}
		err := ValidateFileACLInput(&in)
		if !IsFileACLError(err, FileACLErrorInvalidInput) {
			t.Fatalf("got %v, want invalid_input", err)
		}
		if !strings.Contains(err.Error(), "empty effective DACL") {
			t.Errorf("message should explain the lockout risk, got %q", err.Error())
		}
	})

	t.Run("rejects duplicate rules", func(t *testing.T) {
		in := valid()
		in.AccessRules = []FileACLAccessRule{
			{Identity: "tfacc", Rights: []string{"Read"}},
			{Identity: "TFACC", Rights: []string{"Write"}},
		}
		if err := ValidateFileACLInput(&in); !IsFileACLError(err, FileACLErrorInvalidInput) {
			t.Errorf("got %v, want invalid_input", err)
		}
	})

	t.Run("rejects propagation without inheritance", func(t *testing.T) {
		in := valid()
		in.AccessRules = []FileACLAccessRule{
			{Identity: "tfacc", Rights: []string{"Read"}, Propagation: FileACLPropagationInheritOnly},
		}
		if err := ValidateFileACLInput(&in); !IsFileACLError(err, FileACLErrorInvalidInput) {
			t.Errorf("got %v, want invalid_input", err)
		}
	})

	t.Run("rejects empty identity", func(t *testing.T) {
		in := valid()
		in.AccessRules = []FileACLAccessRule{{Identity: " ", Rights: []string{"Read"}}}
		if err := ValidateFileACLInput(&in); !IsFileACLError(err, FileACLErrorInvalidInput) {
			t.Errorf("got %v, want invalid_input", err)
		}
	})
}

func TestFileACLError_Semantics(t *testing.T) {
	err := NewFileACLError(FileACLErrorPrivilegeNotHeld, "cannot set owner", nil,
		map[string]string{"path": `C:\x`})
	if !IsFileACLError(err, FileACLErrorPrivilegeNotHeld) {
		t.Error("IsFileACLError must match on kind")
	}
	if IsFileACLError(err, FileACLErrorPermission) {
		t.Error("IsFileACLError must not match a different kind")
	}
	if !strings.Contains(err.Error(), "privilege_not_held") {
		t.Errorf("Error() should carry the kind, got %q", err.Error())
	}
}

func TestParseFileACLPayload(t *testing.T) {
	t.Run("absent target yields nil state", func(t *testing.T) {
		st, err := parseFileACLPayload(json.RawMessage(`{"found":false}`), `C:\x`)
		if err != nil || st != nil {
			t.Errorf("got (%v, %v), want (nil, nil)", st, err)
		}
	})

	t.Run("masks are kept verbatim", func(t *testing.T) {
		raw := json.RawMessage(`{"found":true,"path":"C:\\d","target_type":"directory",` +
			`"owner":"BUILTIN\\Administrators","owner_sid":"S-1-5-32-544",` +
			`"inheritance_enabled":false,"sddl":"O:BAG:DUD:PAI","access_rules":[` +
			`{"identity":"tfacc","identity_sid":"S-1-5-21-1-2-3-1001","access_mask":2032127,` +
			`"type":"allow","inheritance":"container_object","propagation":"none","inherited":false}]}`)
		st, err := parseFileACLPayload(raw, `C:\d`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if st.TargetType != FileACLTargetDirectory || st.InheritanceEnabled {
			t.Errorf("unexpected state: %+v", st)
		}
		if len(st.AccessRules) != 1 {
			t.Fatalf("got %d rules, want 1", len(st.AccessRules))
		}
		if st.AccessRules[0].AccessMask != 2032127 {
			t.Errorf("mask = %d, want 2032127 (verbatim)", st.AccessRules[0].AccessMask)
		}
		if len(st.AccessRules[0].Rights) != 1 || st.AccessRules[0].Rights[0] != "FullControl" {
			t.Errorf("rights = %v, want [FullControl]", st.AccessRules[0].Rights)
		}
	})

	// ConvertTo-Json serialises a one-element array as a bare object.
	t.Run("tolerates a single rule as an object", func(t *testing.T) {
		raw := json.RawMessage(`{"found":true,"target_type":"file","access_rules":` +
			`{"identity":"tfacc","identity_sid":"S-1-1","access_mask":131209,"type":"allow","inherited":true}}`)
		st, err := parseFileACLPayload(raw, `C:\f`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(st.AccessRules) != 1 {
			t.Fatalf("got %d rules, want 1", len(st.AccessRules))
		}
		if len(st.ExplicitRules()) != 0 {
			t.Error("an inherited rule must not be reported as explicit")
		}
		if st.AccessRules[0].Inheritance != FileACLInheritanceNone {
			t.Errorf("inheritance = %q, want none", st.AccessRules[0].Inheritance)
		}
	})
}

// TestFileACLScriptHygiene guards the transport invariants: the mutating scripts
// take their input from stdin as JSON and interpolate nothing, and every script
// silences the progress stream, whose CLIXML noise would otherwise corrupt the
// JSON envelope.
func TestFileACLScriptHygiene(t *testing.T) {
	for name, body := range map[string]string{"set": psFileACLSetBody, "reset": psFileACLResetBody} {
		if strings.Contains(body, "@@") {
			t.Errorf("%s script must not interpolate placeholders: ACL data travels on stdin", name)
		}
		if !strings.Contains(body, "[Console]::In.ReadToEnd()") {
			t.Errorf("%s script must read its specification from stdin", name)
		}
	}
	if !strings.Contains(psFileACLReadBody, "@@PATH@@") {
		t.Error("read script must take a quoted path placeholder")
	}
	for _, pref := range []string{"$ErrorActionPreference = 'Stop'", "$ProgressPreference    = 'SilentlyContinue'"} {
		if !strings.Contains(psFileACLHeader, pref) {
			t.Errorf("header must set %s", pref)
		}
	}
	// Error classification must never depend on message text.
	if !strings.Contains(psFileACLHeader, "$ex.HResult -band 0xFFFF") {
		t.Error("classification must read Win32 codes from HResult, not from message text")
	}
}

func TestMapFileACLErrorKind(t *testing.T) {
	if got := mapFileACLErrorKind("identity_not_found"); got != FileACLErrorIdentityNotFound {
		t.Errorf("got %q, want identity_not_found", got)
	}
	if got := mapFileACLErrorKind("something_else"); got != FileACLErrorUnknown {
		t.Errorf("got %q, want unknown", got)
	}
}
