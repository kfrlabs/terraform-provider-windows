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

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func fileACLSchema(t *testing.T) schema.Schema {
	t.Helper()
	resp := &resource.SchemaResponse{}
	aclRes, ok := NewWindowsFileACLResource().(*windowsFileACLResource)
	if !ok {
		t.Fatalf("expected *windowsFileACLResource, got %T", aclRes)
	}
	aclRes.Schema(context.Background(), resource.SchemaRequest{}, resp)
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
		a, ok := s.Attributes[k].(schema.StringAttribute)
		if !ok {
			t.Fatalf("expected schema.StringAttribute, got %T", a)
		}
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
	aclRes, ok := NewWindowsFileACLResource().(*windowsFileACLResource)
	if !ok {
		t.Fatalf("expected *windowsFileACLResource, got %T", aclRes)
	}
	v := aclRes.ConfigValidators(context.Background())
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

// TestWindowsFileACLResource_RightsCaseInsensitive pins the F02 fix: the schema
// accepts any casing of the FileSystemRights keywords (the winclient contract
// is case-insensitive via CanonicalFileACLRight, and the Set script only
// consumes the computed access mask), while unknown keywords are still
// rejected. It exercises the wired schema validators, not just the winclient
// helpers, because the bug was the schema-side OneOf.
func TestWindowsFileACLResource_RightsCaseInsensitive(t *testing.T) {
	s := fileACLSchema(t)
	block, ok := s.Blocks["access_rule"].(schema.ListNestedBlock)
	if !ok {
		t.Fatal("access_rule is not a ListNestedBlock")
	}
	rightsAttr, ok := block.NestedObject.Attributes["rights"].(schema.SetAttribute)
	if !ok {
		t.Fatal("access_rule.rights is not a SetAttribute")
	}
	validate := func(t *testing.T, rights ...string) bool {
		t.Helper()
		resp := &validator.SetResponse{}
		for _, v := range rightsAttr.Validators {
			v.ValidateSet(context.Background(), validator.SetRequest{
				Path:        path.Root("access_rule"),
				ConfigValue: rightsSet(t, rights...),
			}, resp)
		}
		return resp.Diagnostics.HasError()
	}
	for _, tc := range []struct {
		name    string
		rights  []string
		wantErr bool
	}{
		{"canonical", []string{"FullControl"}, false},
		{"lowercase", []string{"fullcontrol"}, false},
		{"uppercase", []string{"READANDEXECUTE"}, false},
		{"mixed set dedupes in winclient", []string{"read", "READ"}, false},
		{"unknown keyword", []string{"Execute"}, true},
		{"empty keyword", []string{""}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if gotErr := validate(t, tc.rights...); gotErr != tc.wantErr {
				t.Errorf("rights %v: error = %v, want %v", tc.rights, gotErr, tc.wantErr)
			}
		})
	}

	t.Run("unknown keyword message lists canonical values", func(t *testing.T) {
		resp := &validator.StringResponse{}
		fileACLRightValidator{}.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("rights"),
			ConfigValue: types.StringValue("Execute"),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Fatal("expected an error diagnostic")
		}
		detail := resp.Diagnostics.Errors()[0].Detail()
		if !strings.Contains(detail, "FullControl") {
			t.Errorf("diagnostic detail %q does not list canonical values", detail)
		}
	})

	t.Run("null and unknown are skipped", func(t *testing.T) {
		for name, val := range map[string]types.String{
			"null":    types.StringNull(),
			"unknown": types.StringUnknown(),
		} {
			resp := &validator.StringResponse{}
			fileACLRightValidator{}.ValidateString(context.Background(), validator.StringRequest{
				Path:        path.Root("rights"),
				ConfigValue: val,
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Errorf("%s value must not error", name)
			}
		}
	})
}

func TestFileACLIdentityMatches(t *testing.T) {
	tests := []struct {
		name         string
		declared     string
		observedName string
		sid          string
		want         bool
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
			if got := fileACLIdentityMatches(tc.declared, tc.observedName, tc.sid); got != tc.want {
				t.Errorf("fileACLIdentityMatches(%q, %q, %q) = %v, want %v",
					tc.declared, tc.observedName, tc.sid, got, tc.want)
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
		// No operator spelling exists for an undeclared entry, so the
		// canonical SID is stored rather than the host's display name.
		if got[1].Identity.ValueString() != "S-1-5-21-1-2-3-1099" {
			t.Errorf("second rule = %q, want the undeclared entry's SID", got[1].Identity.ValueString())
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

// TestFileACLBlockFromObservedIdentitySpelling pins the import normalisation:
// with no declared spelling to preserve, the canonical SID is stored so a
// SID-based configuration matches the imported state exactly.
func TestFileACLBlockFromObservedIdentitySpelling(t *testing.T) {
	ctx := context.Background()
	rule := winclient.FileACLAccessRule{
		Identity: "BUILTIN\\Administrators", IdentitySID: "S-1-5-32-544",
		AccessMask: 0x1F01FF, Rights: []string{"FullControl"},
		Type:        winclient.FileACLTypeAllow,
		Inheritance: winclient.FileACLInheritanceNone, Propagation: winclient.FileACLPropagationNone,
	}

	t.Run("empty declared stores the SID", func(t *testing.T) {
		var diags diag.Diagnostics
		got := fileACLBlockFromObserved(ctx, rule, windowsFileACLRuleModel{},
			winclient.FileACLTargetFile, &diags)
		if diags.HasError() {
			t.Fatalf("diagnostics: %v", diags)
		}
		if got.Identity.ValueString() != "S-1-5-32-544" {
			t.Errorf("identity = %q, want the canonical SID", got.Identity.ValueString())
		}
	})

	t.Run("empty declared without SID keeps the display name", func(t *testing.T) {
		var diags diag.Diagnostics
		nameless := rule
		nameless.IdentitySID = ""
		got := fileACLBlockFromObserved(ctx, nameless, windowsFileACLRuleModel{},
			winclient.FileACLTargetFile, &diags)
		if diags.HasError() {
			t.Fatalf("diagnostics: %v", diags)
		}
		if got.Identity.ValueString() != "BUILTIN\\Administrators" {
			t.Errorf("identity = %q, want the display name fallback", got.Identity.ValueString())
		}
	})

	t.Run("declared spelling survives when it matches", func(t *testing.T) {
		var diags diag.Diagnostics
		declared := windowsFileACLRuleModel{Identity: types.StringValue("S-1-5-32-544")}
		got := fileACLBlockFromObserved(ctx, rule, declared,
			winclient.FileACLTargetFile, &diags)
		if diags.HasError() {
			t.Fatalf("diagnostics: %v", diags)
		}
		if got.Identity.ValueString() != "S-1-5-32-544" {
			t.Errorf("identity = %q, want the operator's spelling", got.Identity.ValueString())
		}
	})
}

// TestFileACLPreserveDifferenceImmaterial pins when a
// preserve_inherited_on_protect difference cannot describe a real change, and
// may therefore be suppressed so an imported state yields an empty plan.
func TestFileACLPreserveDifferenceImmaterial(t *testing.T) {
	mk := func(mode string, inheritance types.Bool) *windowsFileACLModel {
		m := &windowsFileACLModel{
			Mode:                       types.StringValue(mode),
			InheritanceEnabled:         inheritance,
			PreserveInheritedOnProtect: types.BoolValue(false),
		}
		if mode == "" {
			m.Mode = types.StringNull()
		}
		return m
	}
	tests := []struct {
		name  string
		model *windowsFileACLModel
		want  bool
	}{
		{"unprotected ignores preserve", mk(winclient.FileACLModeAdditive, types.BoolValue(true)), true},
		{"authoritative protected ignores preserve", mk(winclient.FileACLModeAuthoritative, types.BoolValue(false)), true},
		{"additive protected honours preserve", mk(winclient.FileACLModeAdditive, types.BoolValue(false)), false},
		{"null mode defaults to authoritative", mk("", types.BoolValue(false)), true},
		{"null inheritance is conservative", mk(winclient.FileACLModeAuthoritative, types.BoolNull()), false},
		{"unknown inheritance is conservative", mk(winclient.FileACLModeAuthoritative, types.BoolUnknown()), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileACLPreserveDifferenceImmaterial(tc.model); got != tc.want {
				t.Errorf("fileACLPreserveDifferenceImmaterial() = %v, want %v", got, tc.want)
			}
		})
	}
}

// fileACLModifyPlanRaw encodes a model into Plan/State raw values through the
// schema, so ModifyPlan tests exercise the real tfsdk decode path instead of
// hand-written tftypes.
func fileACLModifyPlanRaw(t *testing.T, def schema.Schema, m *windowsFileACLModel, forPlan bool) tftypes.Value {
	t.Helper()
	ctx := context.Background()
	typ := def.Type().TerraformType(ctx)
	objTyp, ok := typ.(tftypes.Object)
	if !ok {
		t.Fatalf("schema terraform type = %T, want tftypes.Object", typ)
	}
	nullRaw := tftypes.NewValue(objTyp, nil)
	if forPlan {
		store := tfsdk.Plan{Schema: def, Raw: nullRaw}
		if d := store.Set(ctx, m); d.HasError() {
			t.Fatalf("Plan.Set: %v", d)
		}
		return store.Raw
	}
	store := tfsdk.State{Schema: def, Raw: nullRaw}
	if d := store.Set(ctx, m); d.HasError() {
		t.Fatalf("State.Set: %v", d)
	}
	return store.Raw
}

// fileACLNullTimeouts returns a null timeouts value carrying the schema's
// attribute types. The zero timeouts.Value wraps an object with no attribute
// types, which the framework rejects on Plan/State.Set.
func fileACLNullTimeouts() timeouts.Value {
	return timeouts.Value{Object: types.ObjectNull(map[string]attr.Type{
		"create": types.StringType,
		"read":   types.StringType,
		"update": types.StringType,
		"delete": types.StringType,
	})}
}

// TestFileACLModifyPlan_PreserveSuppressedWhenImmaterial is the end-to-end
// proof for the F01 import fix: a protected authoritative target whose
// imported state seeds preserve=true against a config spelling of false must
// leave the plan at preserve=true (suppression persisted even though the
// managed comparison is then equal). A protected additive target honours the
// flag, so the same difference must be conserved and the normal
// unknown-marking path must run.
func TestFileACLModifyPlan_PreserveSuppressedWhenImmaterial(t *testing.T) {
	ctx := context.Background()
	def := fileACLSchema(t)
	mkModel := func(mode string, preserve bool) *windowsFileACLModel {
		return &windowsFileACLModel{
			ID:                         types.StringValue(`C:\acc\file.txt`),
			Path:                       types.StringValue(`C:\acc\file.txt`),
			Mode:                       types.StringValue(mode),
			Owner:                      types.StringNull(),
			InheritanceEnabled:         types.BoolValue(false),
			PreserveInheritedOnProtect: types.BoolValue(preserve),
			AccessRules: []windowsFileACLRuleModel{{
				Identity:    types.StringValue("S-1-5-32-544"),
				Rights:      rightsSet(t, "FullControl"),
				Type:        types.StringValue(winclient.FileACLTypeAllow),
				Inheritance: types.StringValue(winclient.FileACLInheritanceNone),
				Propagation: types.StringValue(winclient.FileACLPropagationNone),
			}},
			TargetType:           types.StringNull(),
			OwnerSID:             types.StringNull(),
			SDDL:                 types.StringNull(),
			EffectiveAccessRules: types.ListNull(fileACLEffectiveRuleObjectType),
			Timeouts:             fileACLNullTimeouts(),
		}
	}
	runModifyPlan := func(t *testing.T, mode string, planPreserve, statePreserve bool) windowsFileACLModel {
		t.Helper()
		planRaw := fileACLModifyPlanRaw(t, def, mkModel(mode, planPreserve), true)
		stateRaw := fileACLModifyPlanRaw(t, def, mkModel(mode, statePreserve), false)
		r := &windowsFileACLResource{}
		resp := &resource.ModifyPlanResponse{Plan: tfsdk.Plan{Schema: def, Raw: planRaw}}
		r.ModifyPlan(ctx, resource.ModifyPlanRequest{
			Plan:  tfsdk.Plan{Schema: def, Raw: planRaw.Copy()},
			State: tfsdk.State{Schema: def, Raw: stateRaw.Copy()},
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("ModifyPlan diagnostics: %v", resp.Diagnostics)
		}
		var got windowsFileACLModel
		if d := resp.Plan.Get(ctx, &got); d.HasError() {
			t.Fatalf("plan Get: %v", d)
		}
		return got
	}

	t.Run("authoritative protected suppresses the seeded default", func(t *testing.T) {
		got := runModifyPlan(t, winclient.FileACLModeAuthoritative, false, true)
		if !got.PreserveInheritedOnProtect.Equal(types.BoolValue(true)) {
			t.Errorf("preserve = %v, want true (state spelling must win)", got.PreserveInheritedOnProtect)
		}
	})

	t.Run("additive protected conserves the difference", func(t *testing.T) {
		got := runModifyPlan(t, winclient.FileACLModeAdditive, false, true)
		if !got.PreserveInheritedOnProtect.Equal(types.BoolValue(false)) {
			t.Errorf("preserve = %v, want false (material difference must survive)", got.PreserveInheritedOnProtect)
		}
		if !got.SDDL.IsUnknown() {
			t.Error("SDDL must be unknown: a material difference takes the normal rewrite path")
		}
	})
}
