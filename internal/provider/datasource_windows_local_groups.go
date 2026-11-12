// Package provider: windows_local_groups data source implementation.
//
// Sibling collection of the windows_local_group data source: read-only
// inventory of every local group on the remote Windows host in a single
// round-trip, narrowed by optional filters (names, sids, name_regex,
// include_builtin, include_members). The result is a sorted `groups` list;
// `names` and `sids` double as exact-match filters and as convenience
// outputs carrying the matched values in the same order as `groups`. An
// empty inventory match is valid (empty lists, never an error).
//
// `names`/`sids` are Optional+Computed sets: when configured they restrict
// the inventory host-side (exact match); the state always carries the
// matched values in group order. `include_builtin` null defaults to true;
// `include_members` null defaults to false (and `members` is null on every
// group element unless membership was requested). `timeouts.read` defaults
// to 10m like the other collection-family data sources.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsLocalGroupsDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsLocalGroupsDataSource)(nil)
)

// NewWindowsLocalGroupsDataSource is the constructor registered in
// provider.go.
func NewWindowsLocalGroupsDataSource() datasource.DataSource {
	return &windowsLocalGroupsDataSource{}
}

// windowsLocalGroupsDataSource is the TPF data source type for
// windows_local_groups.
type windowsLocalGroupsDataSource struct {
	lister winclient.LocalGroupLister
}

// windowsLocalGroupsDataSourceModel is the Terraform state model for the
// windows_local_groups data source.
type windowsLocalGroupsDataSourceModel struct {
	ID             types.String     `tfsdk:"id"`
	Names          types.Set        `tfsdk:"names"`
	SIDs           types.Set        `tfsdk:"sids"`
	NameRegex      types.String     `tfsdk:"name_regex"`
	IncludeBuiltin types.Bool       `tfsdk:"include_builtin"`
	IncludeMembers types.Bool       `tfsdk:"include_members"`
	Groups         types.List       `tfsdk:"groups"`
	Timeouts       dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_local_groups").
func (d *windowsLocalGroupsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_groups"
}

// Schema returns the TPF schema for the windows_local_groups data source.
func (d *windowsLocalGroupsDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the local group inventory of the remote Windows host without " +
			"managing it. This is a **sibling collection** of `windows_local_group` — every `groups` " +
			"element carries the same attributes as the singular data source, plus `is_builtin` and " +
			"the `members` list.\n\n" +
			"Optional filters narrow the result: `names` / `sids` (exact match, host-side), `name_regex` " +
			"(RE2 match on the group name, case-sensitive unless prefixed with `(?i)`), `include_builtin` " +
			"(drop built-in groups such as Administrators and Users) and `include_members` (populate the " +
			"per-group `members` list with `name`, `sid`, `object_class` and `principal_source`). " +
			"Omitted filters match everything.\n\n" +
			"`groups` carries one object per matching group, sorted by name (case-insensitive); " +
			"`names` and `sids` carry the same groups in the same order. An empty match is a " +
			"valid empty list, never an error.\n\n" +
			"The Terraform data source ID is the hex SHA-256 of the normalised filter set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID; hex SHA-256 of the normalised filter set (sorted names, sorted SIDs, raw regex, include_builtin, include_members).",
			},
			"names": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Restrict the result to these group names (exact match, host-side). Omit (null) to match every name; the state carries the matched names in group order.",
			},
			"sids": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Restrict the result to these group SIDs (exact match, host-side). Omit (null) to match every SID; the state carries the matched SIDs in group order.",
			},
			"name_regex": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to groups whose name matches this RE2 regular expression (case-sensitive; prefix the pattern with (?i) for a case-insensitive match).",
			},
			"include_builtin": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to include built-in groups (SID under the S-1-5-32 BUILTIN authority, e.g. Administrators, Users). Omit (null) means true.",
			},
			"include_members": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to populate the per-group members list. Omit (null) means false; members is null on every group element unless requested.",
			},
			"groups": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: localGroupNestedAttributes(),
				},
				Description: "Matching local groups, sorted by name (case-insensitive). Empty when no group matches the filters.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to localGroupDSDefaultTimeout (shared with the singular data source).
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the LocalGroup inventory client. The field is the narrow
// LocalGroupLister interface so unit tests inject a fake without SSH.
func (d *windowsLocalGroupsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*winclient.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T", req.ProviderData),
		)
		return
	}
	d.lister = winclient.NewLocalGroupClient(c)
}

// localGroupsFilterID builds the data source ID: the hex SHA-256 of the
// normalised filter set (sorted names, sorted SIDs, raw regex,
// include_builtin, include_members), so identical filters share an ID and
// any filter change moves it. The preimage is the JSON encoding of the
// ordered field slice, so no separator-escaping ambiguity is possible.
// Nil slices normalise to empty so null and empty filters share an ID.
func localGroupsFilterID(names, sids []string, nameRegex string, includeBuiltin, includeMembers bool) string {
	canonical, _ := json.Marshal([]any{
		localGroupSortedCopy(names),
		localGroupSortedCopy(sids),
		nameRegex,
		includeBuiltin,
		includeMembers,
	})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Read lists the local groups matching the configured filters.
func (d *windowsLocalGroupsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsLocalGroupsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, localGroupDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	var names, sids []string
	if !config.Names.IsNull() && !config.Names.IsUnknown() {
		resp.Diagnostics.Append(config.Names.ElementsAs(ctx, &names, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if !config.SIDs.IsNull() && !config.SIDs.IsUnknown() {
		resp.Diagnostics.Append(config.SIDs.ElementsAs(ctx, &sids, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	names = localGroupSortedCopy(names)
	sids = localGroupSortedCopy(sids)
	nameRegex := ""
	if !config.NameRegex.IsNull() && !config.NameRegex.IsUnknown() {
		nameRegex = config.NameRegex.ValueString()
	}
	includeBuiltin := true
	if !config.IncludeBuiltin.IsNull() && !config.IncludeBuiltin.IsUnknown() {
		includeBuiltin = config.IncludeBuiltin.ValueBool()
	}
	includeMembers := false
	if !config.IncludeMembers.IsNull() && !config.IncludeMembers.IsUnknown() {
		includeMembers = config.IncludeMembers.ValueBool()
	}

	tflog.Debug(ctx, "windows_local_groups data source Read start", map[string]interface{}{
		"names": names, "sids": sids, "name_regex": nameRegex,
		"include_builtin": includeBuiltin, "include_members": includeMembers,
	})

	groups, err := d.lister.List(ctx, winclient.LocalGroupFilter{
		Names:          names,
		SIDs:           sids,
		NameRegex:      nameRegex,
		IncludeBuiltin: includeBuiltin,
		IncludeMembers: includeMembers,
	})
	if err != nil {
		addLocalGroupsDiag(&resp.Diagnostics, "Read windows_local_groups failed", err)
		return
	}
	if groups == nil {
		groups = []winclient.GroupState{}
	}

	state := windowsLocalGroupsDataSourceModel{
		ID:             types.StringValue(localGroupsFilterID(names, sids, nameRegex, includeBuiltin, includeMembers)),
		NameRegex:      config.NameRegex,
		IncludeBuiltin: config.IncludeBuiltin,
		IncludeMembers: config.IncludeMembers,
		Timeouts:       config.Timeouts,
	}

	objType := localGroupsObjectType()
	memberObjType := localGroupMemberObjectType()
	objs := make([]attr.Value, 0, len(groups))
	matchedNames := make([]string, 0, len(groups))
	matchedSIDs := make([]string, 0, len(groups))
	for _, g := range groups {
		obj, d := localGroupStateToObject(objType, memberObjType, g, includeMembers)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		objs = append(objs, obj)
		matchedNames = append(matchedNames, g.Name)
		matchedSIDs = append(matchedSIDs, g.SID)
	}
	groupsList, diags := types.ListValue(objType, objs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Groups = groupsList
	state.Names = localGroupStringSet(ctx, &resp.Diagnostics, matchedNames)
	if resp.Diagnostics.HasError() {
		return
	}
	state.SIDs = localGroupStringSet(ctx, &resp.Diagnostics, matchedSIDs)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_local_groups data source Read end", map[string]interface{}{
		"id":          state.ID.ValueString(),
		"group_count": len(groups),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// addLocalGroupsDiag converts a *winclient.LocalGroupError into a TPF
// diagnostic.
func addLocalGroupsDiag(diags *diag.Diagnostics, summary string, err error) {
	var lge *winclient.LocalGroupError
	if errors.As(err, &lge) {
		detail := lge.Message
		if len(lge.Context) > 0 {
			detail += "\n\nContext:"
			keys := make([]string, 0, len(lge.Context))
			for k := range lge.Context {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				detail += "\n  " + k + " = " + lge.Context[k]
			}
		}
		if lge.Cause != nil {
			detail += "\n\nCause: " + lge.Cause.Error()
		}
		if lge.Kind != "" {
			detail += "\n\nKind: " + string(lge.Kind)
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
