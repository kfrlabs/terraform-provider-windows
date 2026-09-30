// Package provider — unit tests for the windows_file_acl resource.
//
// Focus: the schema contract that keeps repeated blocks diff-stable, the Read
// reconciliation (which is where a wrong choice produces a permanent plan), SID
// vs display-name identity matching, and diagnostic mapping.
//
// The privilege_not_held path is covered here rather than in the acceptance
// suite on purpose: the SSH session on the test container holds a full admin
// token with SeTakeOwnershipPrivilege enabled, so the failure is not
// reproducible against a live host.
//
// End-to-end CRUD lives in resource_windows_file_acl_acc_test.go.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func fileACLSchema(t *testing.T) schema.Schema {
	t.Helper()
	resp := &resource.SchemaResponse{}
	NewWindowsFileACLResource().(*windowsFileACLResource).Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}
	return resp.Schema
}

func rightsSet(t *testing.T, rights ...string) types.Set {
	t.Helper()
	vals := make([]types.String, 0, len(rights))
	for _, r := range rights {
		vals = append(vals, types.StringValue(r))
	}
	set, d := types.SetValueFrom(context.Background(), types.StringType, vals)
	if d.HasError() {
		t.Fatalf("cannot build rights set: %v", d)
	}
	return set
}

// fileACLPathHasError runs the path validator in isolation.
func fileACLPathHasError(t *testing.T, p string) bool {
	t.Helper()
	resp := &validator.StringResponse{}
	fileACLPathValidator{}.ValidateString(context.Background(), validator.StringRequest{
		Path:        path.Root("path"),
		ConfigValue: types.StringValue(p),
	}, resp)
	return resp.Diagnostics.HasError()
}

func TestWindowsFileACLResource_Metadata(t *testing.T) {
	resp := &resource.MetadataResponse{}
	NewWindowsFileACLResource().Metadata(context.Background(),
		resource.MetadataRequest{ProviderTypeName: "windows"}, resp)
	if resp.TypeName != "windows_file_acl" {
		t.Errorf("TypeName = %q, want windows_file_acl", resp.TypeName)
	}
}

func TestWindowsFileACLResource_SchemaShape(t *testing.T) {
	s := fileACLSchema(t)
	for _, k := range []string{
		"id", "path", "mode", "owner", "inheritance_enabled", "preserve_inherited_on_protect",
		"target_type", "owner_sid", "sddl", "effective_access_rules", "timeouts",
	} {
		if _, ok := s.Attributes[k]; !ok {
			t.Errorf("schema is missing attribute %q", k)
		}
	}
	if _, ok := s.Blocks["access_rule"]; !ok {
		t.Fatal("schema is missing the access_rule block")
	}

	// path is ForceNew: a security descriptor belongs to one target.
	p, ok := s.Attributes["path"].(schema.StringAttribute)
	if !ok {
		t.Fatal("path is not a StringAttribute")
	}
	if !p.Required || len(p.PlanModifiers) == 0 {
		t.Error("path must be required and ForceNew")
	}

	// Observed-only attributes must never be writable.
	for _, k := range []string{"target_type", "owner_sid", "sddl"} {
		a := s.Attributes[k].(schema.StringAttribute)
		if !a.Computed || a.Optional || a.Required {
			t.Errorf("%s must be computed only", k)
		}
	}
}

// TestWindowsFileACLResource_BlockHasNoComputedAttribute pins the central schema
// decision. Terraform cannot correlate the elements of a repeated block that
// carries computed values: adding one here would reintroduce "inconsistent
// result after apply" or endless churn. Observed data belongs in
// effective_access_rules.
func TestWindowsFileACLResource_BlockHasNoComputedAttribute(t *testing.T) {
	s := fileACLSchema(t)
	block, ok := s.Blocks["access_rule"].(schema.ListNestedBlock)
	if !ok {
		t.Fatal("access_rule is not a ListNestedBlock")
	}
	for name, attribute := range block.NestedObject.Attributes {
		str, isString := attribute.(schema.StringAttribute)
		if isString && str.Computed && !str.Optional {
			t.Errorf("access_rule.%s is computed-only, which breaks block correlation", name)
		}
		if set, isSet := attribute.(schema.SetAttribute); isSet && set.Computed && !set.Optional {
			t.Errorf("access_rule.%s is computed-only, which breaks block correlation", name)
		}
	}

	// inheritance must stay nullable: its default depends on the target type,
	// which is only known on the host.
	inheritance, ok := block.NestedObject.Attributes["inheritance"].(schema.StringAttribute)
	if !ok {
		t.Fatal("access_rule.inheritance is missing")
	}
	if inheritance.Computed || inheritance.Default != nil {
		t.Error("access_rule.inheritance must have no schema default: it is target-type dependent")
	}
}

func TestWindowsFileACLResource_ConfigValidatorsPresent(t *testing.T) {
	v := NewWindowsFileACLResource().(*windowsFileACLResource).ConfigValidators(context.Background())
	if len(v) == 0 {
		t.Fatal("expected at least one config validator")
	}
}

func TestFileACLPathValidator(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{`C:\data\app.conf`, false},
		{`C:\data`, false}, // a directory has an ACL too
		{`C:\`, false},     // drive root
		{`\\server\share\dir`, false},
		{`C:\data\..\secret`, true},
		{`C:\data\*.conf`, true},
		{`C:\data\`, true}, // trailing separator
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			gotErr := fileACLPathHasError(t, tc.path)
			if gotErr != tc.wantErr {
				t.Errorf("path %q: error = %v, want %v", tc.path, gotErr, tc.wantErr)
			}
		})
	}
}

func TestFileACLIdentityMatches(t *testing.T) {
	tests := []struct {
		name     string
		declared string
		name_    string
		sid      string
		want     bool
	}{
		{"exact sid", "S-1-5-32-544", "BUILTIN\\Administrators", "S-1-5-32-544", true},
		{"exact name", "BUILTIN\\Administrators", "BUILTIN\\Administrators", "S-1-5-32-544", true},
		{"case insensitive name", "builtin\\administrators", "BUILTIN\\Administrators", "S-1-5-32-544", true},
		// The machine name of the test container changes on every start, so a
		// bare name has to match its qualified form.
		{"bare vs qualified", "tfacc", "AAA2DFF92841\\tfacc", "S-1-5-21-1-2-3-1001", true},
		{"qualified vs other machine", "OTHERHOST\\tfacc", "AAA2DFF92841\\tfacc", "S-1-5-21-1-2-3-1001", true},
		// A SID that does not match is never the same trustee, whatever the name.
		{"wrong sid", "S-1-5-32-545", "BUILTIN\\Administrators", "S-1-5-32-544", false},
		{"different account", "svc_app", "AAA2DFF92841\\tfacc", "S-1-5-21-1-2-3-1001", false},
		{"empty declared", "", "tfacc", "S-1-1", false},
		// An orphaned SID reads back with the SID as its display name.
		{"orphaned sid", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1002", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileACLIdentityMatches(tc.declared, tc.name_, tc.sid); got != tc.want {
				t.Errorf("fileACLIdentityMatches(%q, %q, %q) = %v, want %v",
					tc.declared, tc.name_, tc.sid, got, tc.want)
			}
		})
	}
}

func TestFileACLDefaultInheritance(t *testing.T) {
	if got := fileACLDefaultInheritance(winclient.FileACLTargetDirectory); got != winclient.FileACLInheritanceContainerObject {
		t.Errorf("directory default = %q, want container_object", got)
	}
	if got := fileACLDefaultInheritance(winclient.FileACLTargetFile); got != winclient.FileACLInheritanceNone {
		t.Errorf("file default = %q, want none", got)
	}
}

// TestReconcileFileACLRules is the core behavioural test: a matching rule must
// survive Read untouched, a drifting one must surface the observed rights, and
// an undeclared entry must only be reported in authoritative mode.
func TestReconcileFileACLRules(t *testing.T) {
	ctx := context.Background()

	declared := []windowsFileACLRuleModel{{
		Identity:    types.StringValue("tfacc"),
		Rights:      rightsSet(t, "Modify"),
		Type:        types.StringValue(winclient.FileACLTypeAllow),
		Inheritance: types.StringNull(),
		Propagation: types.StringValue(winclient.FileACLPropagationNone),
	}}

	t.Run("matching rule is kept verbatim", func(t *testing.T) {
		st := &winclient.FileACLState{
			TargetType: winclient.FileACLTargetFile,
			AccessRules: []winclient.FileACLAccessRule{{
				Identity: "HOSTX\\tfacc", IdentitySID: "S-1-5-21-1-2-3-1001",
				// The host reports the mask with Synchronize set, which must not
				// count as drift.
				AccessMask:  197055 | winclient.FileACLRightSynchronize,
				Rights:      []string{"Modify"},
				Type:        winclient.FileACLTypeAllow,
				Inheritance: winclient.FileACLInheritanceNone, Propagation: winclient.FileACLPropagationNone,
			}},
		}
		var diags diag.Diagnostics
		got := reconcileFileACLRules(ctx, declared, st, winclient.FileACLModeAuthoritative, &diags)
		if diags.HasError() {
			t.Fatalf("diagnostics: %v", diags)
		}
		if len(got) != 1 {
			t.Fatalf("got %d rules, want 1", len(got))
		}
		if got[0].Identity.ValueString() != "tfacc" {
			t.Errorf("identity was rewritten to %q; the operator's spelling must survive",
				got[0].Identity.ValueString())
		}
		if !got[0].Inheritance.IsNull() {
			t.Errorf("inheritance = %v, want null: the host agrees with the type default",
				got[0].Inheritance)
		}
	})

	t.Run("drifting rights surface the observed value", func(t *testing.T) {
		st := &winclient.FileACLState{
			TargetType: winclient.FileACLTargetFile,
			AccessRules: []winclient.FileACLAccessRule{{
				Identity: "HOSTX\\tfacc", IdentitySID: "S-1-5-21-1-2-3-1001",
				AccessMask: 131209, Rights: []string{"Read"},
				Type:        winclient.FileACLTypeAllow,
				Inheritance: winclient.FileACLInheritanceNone, Propagation: winclient.FileACLPropagationNone,
			}},
		}
		var diags diag.Diagnostics
		got := reconcileFileACLRules(ctx, declared, st, winclient.FileACLModeAuthoritative, &diags)
		if len(got) != 1 {
			t.Fatalf("got %d rules, want 1", len(got))
		}
		var rights []string
		got[0].Rights.ElementsAs(ctx, &rights, false)
		if len(rights) != 1 || rights[0] != "Read" {
			t.Errorf("rights = %v, want [Read] so the drift is visible", rights)
		}
	})

	t.Run("vanished rule is dropped from state", func(t *testing.T) {
		st := &winclient.FileACLState{TargetType: winclient.FileACLTargetFile}
		var diags diag.Diagnostics
		got := reconcileFileACLRules(ctx, declared, st, winclient.FileACLModeAuthoritative, &diags)
		if len(got) != 0 {
			t.Errorf("got %d rules, want 0", len(got))
		}
	})

	undeclared := &winclient.FileACLState{
		TargetType: winclient.FileACLTargetFile,
		AccessRules: []winclient.FileACLAccessRule{
			{
				Identity: "HOSTX\\tfacc", IdentitySID: "S-1-5-21-1-2-3-1001",
				AccessMask: 197055, Rights: []string{"Modify"},
				Type:        winclient.FileACLTypeAllow,
				Inheritance: winclient.FileACLInheritanceNone, Propagation: winclient.FileACLPropagationNone,
			},
			{
				Identity: "HOSTX\\intruder", IdentitySID: "S-1-5-21-1-2-3-1099",
				AccessMask: 0x1F01FF, Rights: []string{"FullControl"},
				Type:        winclient.FileACLTypeAllow,
				Inheritance: winclient.FileACLInheritanceNone, Propagation: winclient.FileACLPropagationNone,
			},
		},
	}

	t.Run("authoritative reports an undeclared entry", func(t *testing.T) {
		var diags diag.Diagnostics
		got := reconcileFileACLRules(ctx, declared, undeclared, winclient.FileACLModeAuthoritative, &diags)
		if len(got) != 2 {
			t.Fatalf("got %d rules, want 2 (declared + drift)", len(got))
		}
		if got[1].Identity.ValueString() != "HOSTX\\intruder" {
			t.Errorf("second rule = %q, want the undeclared entry", got[1].Identity.ValueString())
		}
	})

	t.Run("additive ignores an undeclared entry", func(t *testing.T) {
		var diags diag.Diagnostics
		got := reconcileFileACLRules(ctx, declared, undeclared, winclient.FileACLModeAdditive, &diags)
		if len(got) != 1 {
			t.Errorf("got %d rules, want 1: an unmanaged entry is not drift in additive mode", len(got))
		}
	})

	t.Run("inherited entries are never reconciled", func(t *testing.T) {
		st := &winclient.FileACLState{
			TargetType: winclient.FileACLTargetFile,
			AccessRules: []winclient.FileACLAccessRule{{
				Identity: "BUILTIN\\Users", IdentitySID: "S-1-5-32-545",
				AccessMask: 131209, Rights: []string{"Read"},
				Type: winclient.FileACLTypeAllow, Inherited: true,
				Inheritance: winclient.FileACLInheritanceNone, Propagation: winclient.FileACLPropagationNone,
			}},
		}
		var diags diag.Diagnostics
		got := reconcileFileACLRules(ctx, nil, st, winclient.FileACLModeAuthoritative, &diags)
		if len(got) != 0 {
			t.Errorf("got %d rules, want 0: inherited entries are not explicit", len(got))
		}
	})
}

func TestFileACLManagedEqual(t *testing.T) {
	mk := func(rights string) *windowsFileACLModel {
		return &windowsFileACLModel{
			Mode:                       types.StringValue(winclient.FileACLModeAuthoritative),
			Owner:                      types.StringNull(),
			InheritanceEnabled:         types.BoolValue(true),
			PreserveInheritedOnProtect: types.BoolValue(true),
			AccessRules: []windowsFileACLRuleModel{{
				Identity: types.StringValue("tfacc"),
				Rights:   rightsSet(t, rights),
				Type:     types.StringValue(winclient.FileACLTypeAllow),
			}},
		}
	}
	if !fileACLManagedEqual(mk("Modify"), mk("Modify")) {
		t.Error("identical models must compare equal")
	}
	if fileACLManagedEqual(mk("Modify"), mk("Read")) {
		t.Error("different rights must compare unequal")
	}
	a, b := mk("Modify"), mk("Modify")
	b.Owner = types.StringValue("BUILTIN\\Administrators")
	if fileACLManagedEqual(a, b) {
		t.Error("a managed owner must compare unequal to an unmanaged one")
	}
}

func TestAddFileACLDiag_ActionableMessages(t *testing.T) {
	tests := []struct {
		kind         winclient.FileACLErrorKind
		wantContains string
	}{
		{winclient.FileACLErrorNotFound, "never creates it"},
		{winclient.FileACLErrorPermission, "ChangePermissions"},
		// Untestable against the live container: its SSH session holds
		// SeTakeOwnershipPrivilege, so this is the only coverage of the path.
		{winclient.FileACLErrorPrivilegeNotHeld, "SeTakeOwnershipPrivilege"},
		{winclient.FileACLErrorIdentityNotFound, "qualified with the domain"},
		{winclient.FileACLErrorLocked, "holds the target open"},
		{winclient.FileACLErrorInvalidInput, "boom"},
	}
	for _, tc := range tests {
		t.Run(string(tc.kind), func(t *testing.T) {
			var diags diag.Diagnostics
			addFileACLDiag(&diags, "Create", winclient.NewFileACLError(tc.kind, "boom", nil, nil))
			if !diags.HasError() {
				t.Fatal("expected an error diagnostic")
			}
			joined := diags.Errors()[0].Summary() + " " + diags.Errors()[0].Detail()
			if !strings.Contains(joined, tc.wantContains) {
				t.Errorf("diagnostic %q does not mention %q", joined, tc.wantContains)
			}
		})
	}

	t.Run("non typed error still reports", func(t *testing.T) {
		var diags diag.Diagnostics
		addFileACLDiag(&diags, "Read", context.DeadlineExceeded)
		if !diags.HasError() {
			t.Error("expected an error diagnostic")
		}
	})
}
