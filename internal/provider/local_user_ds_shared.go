// Package provider — shared windows_local_user(s) per-user projection.
//
// Design choice (issue #297): the singular windows_local_user data source is
// deliberately NOT refactored to use these helpers — its schema and Read
// mapping stay untouched to avoid regressions. The windows_local_users
// collection data source builds its `users` elements through them, and
// TestLocalUsersParityWithSingularDS pins both paths to identical values
// for the same UserState fixture.
//
// The nested attribute set mirrors the singular data source attributes
// exactly (same names, types and descriptions; only the `sid`/`name`
// lookup-key sentences are dropped — they describe the singular ExactlyOneOf
// constraint, which does not apply to a collection element) plus
// `is_builtin`, derived Go-side from the SID RID.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// localUserNestedAttrDef is one per-user attribute shared by the singular
// and collection data sources: a single definition list builds both the
// ListNestedAttribute schema map and the element object type, so the two
// can never drift apart.
type localUserNestedAttrDef struct {
	name string
	typ  attr.Type
	desc string
}

// localUserNestedAttrDefs returns the per-user attribute set: exactly the
// singular windows_local_user data source attributes plus is_builtin.
func localUserNestedAttrDefs() []localUserNestedAttrDef {
	str := types.StringType
	boolean := types.BoolType
	return []localUserNestedAttrDef{
		{"sid", str, "Security Identifier of the user."},
		{"name", str, "SAM account name of the user."},
		{"full_name", str, "Display name of the user account."},
		{"description", str, "Free-text description of the user account."},
		{"enabled", boolean, "True when the account is active and not disabled."},
		{"password_never_expires", boolean, "True when the account password has no expiry policy."},
		{"user_may_not_change_password", boolean, "True when self-service password change is blocked for this account."},
		{"account_never_expires", boolean, "True when the account has no expiry date set."},
		{"account_expires", str, "RFC3339 timestamp of the account expiry date, or empty string when the account never expires."},
		{"last_logon", str, "RFC3339 timestamp of the last logon, or empty string if the account has never been used."},
		{"password_last_set", str, "RFC3339 timestamp of the last password change, or empty string if not yet set."},
		{"principal_source", str, "Origin of the account: Local, ActiveDirectory, AzureAD, MicrosoftAccount, or Unknown."},
		{"is_builtin", boolean, "True when the account is a built-in account (SID RID below 1000, e.g. Administrator, Guest)."},
	}
}

// localUserNestedAttributes returns the per-user schema attributes for the
// collection `users` ListNestedAttribute (all Computed). An unsupported
// definition type surfaces as an error diagnostic instead of panicking, so
// a future attribute addition fails closed at schema build time.
func localUserNestedAttributes() (map[string]schema.Attribute, diag.Diagnostics) {
	var diags diag.Diagnostics
	defs := localUserNestedAttrDefs()
	attrs := make(map[string]schema.Attribute, len(defs))
	for _, d := range defs {
		switch d.typ {
		case types.StringType:
			attrs[d.name] = schema.StringAttribute{
				Computed:    true,
				Description: d.desc,
			}
		case types.BoolType:
			attrs[d.name] = schema.BoolAttribute{
				Computed:    true,
				Description: d.desc,
			}
		default:
			diags.AddError(
				"Unsupported local user attribute type",
				fmt.Sprintf("localUserNestedAttributes: unsupported attribute type %T for %q; expected types.StringType or types.BoolType.", d.typ, d.name),
			)
		}
	}
	return attrs, diags
}

// localUsersObjectType is the element type of the collection `users` list:
// one object per matching local user.
func localUsersObjectType() types.ObjectType {
	attrTypes := make(map[string]attr.Type, len(localUserNestedAttrDefs()))
	for _, d := range localUserNestedAttrDefs() {
		attrTypes[d.name] = d.typ
	}
	return types.ObjectType{AttrTypes: attrTypes}
}

// localUserStateToObject projects one winclient.UserState onto the
// collection `users` element object type. Empty strings stay empty (never
// null), mirroring the singular data source Read mapping; is_builtin is
// derived Go-side from the SID RID.
func localUserStateToObject(objType types.ObjectType, us winclient.UserState) (attr.Value, diag.Diagnostics) {
	return types.ObjectValue(objType.AttrTypes, map[string]attr.Value{
		"sid":                          types.StringValue(us.SID),
		"name":                         types.StringValue(us.Name),
		"full_name":                    types.StringValue(us.FullName),
		"description":                  types.StringValue(us.Description),
		"enabled":                      types.BoolValue(us.Enabled),
		"password_never_expires":       types.BoolValue(us.PasswordNeverExpires),
		"user_may_not_change_password": types.BoolValue(us.UserMayNotChangePassword),
		"account_never_expires":        types.BoolValue(us.AccountNeverExpires),
		"account_expires":              types.StringValue(us.AccountExpires),
		"last_logon":                   types.StringValue(us.LastLogon),
		"password_last_set":            types.StringValue(us.PasswordLastSet),
		"principal_source":             types.StringValue(us.PrincipalSource),
		"is_builtin":                   types.BoolValue(winclient.IsBuiltinLocalUserSID(us.SID)),
	})
}

// localUserNestedAttrNames returns the per-user attribute names in
// definition order (used by schema parity tests).
func localUserNestedAttrNames() []string {
	defs := localUserNestedAttrDefs()
	names := make([]string, 0, len(defs))
	for _, d := range defs {
		names = append(names, d.name)
	}
	return names
}

// localUserStringList projects a Go string slice onto a Terraform list
// value. A nil or empty slice becomes an empty (non-null) list so plans
// stay stable and empty inventories remain valid.
func localUserStringList(ctx context.Context, diags *diag.Diagnostics, in []string) types.List {
	if in == nil {
		in = []string{}
	}
	list, d := types.ListValueFrom(ctx, types.StringType, in)
	diags.Append(d...)
	return list
}
