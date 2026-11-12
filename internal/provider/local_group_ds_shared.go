// Package provider — shared windows_local_group(s) per-group projection.
//
// Design choice (issue #298): the singular windows_local_group data source is
// deliberately NOT refactored to use these helpers — its schema and Read
// mapping stay untouched to avoid regressions. The windows_local_groups
// collection data source builds its `groups` elements through them, and
// TestLocalGroupsParityWithSingularDS pins both paths to identical values
// for the same GroupState fixture.
//
// The nested attribute set mirrors the singular data source attributes
// exactly (same names, types and descriptions; only the `sid`/`name`
// lookup-key sentences are dropped — they describe the singular ExactlyOneOf
// constraint, which does not apply to a collection element) plus
// `is_builtin` and the `members` list (null when membership was not
// requested).
package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// localGroupNestedAttrDef is one per-group scalar attribute shared by the
// singular and collection data sources: a single definition list builds both
// the schema map and the element object type, so the two can never drift
// apart. The `members` list attribute is defined separately (see
// localGroupNestedAttributes) because its type is a nested list, not a
// scalar.
type localGroupNestedAttrDef struct {
	name string
	typ  attr.Type
	desc string
}

// localGroupNestedAttrDefs returns the per-group scalar attribute set: the
// singular windows_local_group data source attributes plus is_builtin.
func localGroupNestedAttrDefs() []localGroupNestedAttrDef {
	str := types.StringType
	boolean := types.BoolType
	return []localGroupNestedAttrDef{
		{"sid", str, "Security Identifier of the group."},
		{"name", str, "Name of the local group."},
		{"description", str, "Free-text description of the group as returned by Windows."},
		{"is_builtin", boolean, "True when the group is a built-in group (SID under the S-1-5-32 BUILTIN authority, e.g. Administrators)."},
	}
}

// localGroupMemberObjectType is the element type of each `members` list: one
// object per group member.
func localGroupMemberObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":             types.StringType,
		"sid":              types.StringType,
		"object_class":     types.StringType,
		"principal_source": types.StringType,
	}}
}

// localGroupMemberNestedAttributes returns the per-member schema attributes
// for the nested `members` ListNestedAttribute (all Computed).
func localGroupMemberNestedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Computed:    true,
			Description: "Display name of the member as reported by Windows; empty string for orphaned SIDs.",
		},
		"sid": schema.StringAttribute{
			Computed:    true,
			Description: "Security Identifier of the member account.",
		},
		"object_class": schema.StringAttribute{
			Computed:    true,
			Description: "Windows account class (e.g. User, Group); Unknown when the fallback tiers cannot observe it.",
		},
		"principal_source": schema.StringAttribute{
			Computed:    true,
			Description: "Account origin: Local, ActiveDirectory, AzureAD, MicrosoftAccount, or Unknown (orphaned SID).",
		},
	}
}

// localGroupNestedAttributes returns the per-group schema attributes for the
// collection `groups` ListNestedAttribute (all Computed).
func localGroupNestedAttributes() map[string]schema.Attribute {
	defs := localGroupNestedAttrDefs()
	attrs := make(map[string]schema.Attribute, len(defs)+1)
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
			panic("localGroupNestedAttributes: unsupported attribute type for " + d.name)
		}
	}
	attrs["members"] = schema.ListNestedAttribute{
		Computed: true,
		NestedObject: schema.NestedAttributeObject{
			Attributes: localGroupMemberNestedAttributes(),
		},
		Description: "Members of the group, sorted by member SID. Null when membership was not requested (include_members false); empty when the group has no members.",
	}
	return attrs
}

// localGroupsObjectType is the element type of the collection `groups` list:
// one object per matching local group.
func localGroupsObjectType() types.ObjectType {
	attrTypes := make(map[string]attr.Type, len(localGroupNestedAttrDefs())+1)
	for _, d := range localGroupNestedAttrDefs() {
		attrTypes[d.name] = d.typ
	}
	attrTypes["members"] = types.ListType{ElemType: localGroupMemberObjectType()}
	return types.ObjectType{AttrTypes: attrTypes}
}

// localGroupMemberStateToValue projects one winclient.LocalGroupMemberState
// onto the collection `members` element object type. Empty strings stay
// empty (never null); orphaned SIDs surface as empty name with the SID
// preserved, unlike the resource/member List ""->SID coercion.
func localGroupMemberStateToValue(objType types.ObjectType, m winclient.LocalGroupMemberState) (attr.Value, diag.Diagnostics) {
	return types.ObjectValue(objType.AttrTypes, map[string]attr.Value{
		"name":             types.StringValue(m.MemberName),
		"sid":              types.StringValue(m.MemberSID),
		"object_class":     types.StringValue(m.ObjectClass),
		"principal_source": types.StringValue(m.PrincipalSource),
	})
}

// localGroupStateToObject projects one winclient.GroupState onto the
// collection `groups` element object type. When includeMembers is false,
// `members` is null (membership was not requested); otherwise it is a list
// (empty but non-null when the group has no members).
func localGroupStateToObject(objType, memberObjType types.ObjectType, gs winclient.GroupState, includeMembers bool) (attr.Value, diag.Diagnostics) {
	var membersVal attr.Value = types.ListNull(memberObjType)
	if includeMembers {
		members := gs.Members
		if members == nil {
			members = []winclient.LocalGroupMemberState{}
		}
		objs := make([]attr.Value, 0, len(members))
		for _, m := range members {
			obj, d := localGroupMemberStateToValue(memberObjType, m)
			if d.HasError() {
				return nil, d
			}
			objs = append(objs, obj)
		}
		list, d := types.ListValue(memberObjType, objs)
		if d.HasError() {
			return nil, d
		}
		membersVal = list
	}
	return types.ObjectValue(objType.AttrTypes, map[string]attr.Value{
		"sid":         types.StringValue(gs.SID),
		"name":        types.StringValue(gs.Name),
		"description": types.StringValue(gs.Description),
		"is_builtin":  types.BoolValue(winclient.IsBuiltinLocalGroupSID(gs.SID)),
		"members":     membersVal,
	})
}

// localGroupNestedAttrNames returns the per-group scalar attribute names in
// definition order (used by schema parity tests).
func localGroupNestedAttrNames() []string {
	defs := localGroupNestedAttrDefs()
	names := make([]string, 0, len(defs))
	for _, d := range defs {
		names = append(names, d.name)
	}
	return names
}

// localGroupStringSet projects a Go string slice onto a Terraform set
// value. A nil or empty slice becomes an empty (non-null) set so plans
// stay stable and empty inventories remain valid.
func localGroupStringSet(ctx context.Context, diags *diag.Diagnostics, in []string) types.Set {
	if in == nil {
		in = []string{}
	}
	set, d := types.SetValueFrom(ctx, types.StringType, in)
	diags.Append(d...)
	return set
}

// localGroupSortedCopy returns a sorted copy of in (nil becomes an empty
// slice) for order-insensitive filter IDs.
func localGroupSortedCopy(in []string) []string {
	out := make([]string, 0, len(in))
	out = append(out, in...)
	sort.Strings(out)
	return out
}
