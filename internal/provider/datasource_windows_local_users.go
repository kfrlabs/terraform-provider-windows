// Package provider: windows_local_users data source implementation.
//
// Sibling collection of the windows_local_user data source: read-only
// inventory of every local user account on the remote Windows host in a
// single round-trip, narrowed by optional filters (name_regex, enabled,
// include_builtin). The result is a sorted `users` list plus the `names` and
// `sids` convenience lists (same order); an empty inventory match is valid
// (empty lists, never an error).
//
// Filter inputs are Optional only (null means unfiltered; `include_builtin`
// null defaults to true). `timeouts.read` defaults to 10m like the other
// collection-family data sources.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	dstimeouts "github.com/hashicorp/terraform-plugin-framework-timeouts/datasource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"strconv"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsLocalUsersDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsLocalUsersDataSource)(nil)
)

// NewWindowsLocalUsersDataSource is the constructor registered in
// provider.go.
func NewWindowsLocalUsersDataSource() datasource.DataSource {
	return &windowsLocalUsersDataSource{}
}

// windowsLocalUsersDataSource is the TPF data source type for
// windows_local_users.
type windowsLocalUsersDataSource struct {
	lister winclient.LocalUserLister
}

// windowsLocalUsersDataSourceModel is the Terraform state model for the
// windows_local_users data source.
type windowsLocalUsersDataSourceModel struct {
	ID             types.String     `tfsdk:"id"`
	NameRegex      types.String     `tfsdk:"name_regex"`
	Enabled        types.Bool       `tfsdk:"enabled"`
	IncludeBuiltin types.Bool       `tfsdk:"include_builtin"`
	Users          types.List       `tfsdk:"users"`
	Names          types.List       `tfsdk:"names"`
	SIDs           types.List       `tfsdk:"sids"`
	Timeouts       dstimeouts.Value `tfsdk:"timeouts"`
}

// Metadata sets the data source type name ("windows_local_users").
func (d *windowsLocalUsersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_users"
}

// Schema returns the TPF schema for the windows_local_users data source.
func (d *windowsLocalUsersDataSource) Schema(ctx context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	nestedAttrs, nestedDiags := localUserNestedAttributes()
	resp.Diagnostics.Append(nestedDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the local user inventory of the remote Windows host without " +
			"managing it. This is a **sibling collection** of `windows_local_user` — every `users` " +
			"element carries the same attributes as the singular data source, plus `is_builtin`.\n\n" +
			"Optional filters narrow the result: `name_regex` (RE2 match on the SAM account name), " +
			"`enabled` (keep only enabled or only disabled accounts) and `include_builtin` (drop " +
			"built-in accounts such as Administrator and Guest). Omitted filters match everything.\n\n" +
			"`users` carries one object per matching account, sorted by name (case-insensitive); " +
			"`names` and `sids` carry the same accounts in the same order. An empty match is a " +
			"valid empty list, never an error.\n\n" +
			"The Terraform data source ID is a query-ID: the hex SHA-256 of the normalised filter set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Data source ID (query-ID); hex SHA-256 of the normalised filter set (raw regex, enabled tri-state, include_builtin).",
			},
			"name_regex": schema.StringAttribute{
				Optional:    true,
				Description: "Restrict the result to users whose SAM account name matches this RE2 regular expression (case-sensitive; prefix the pattern with (?i) for a case-insensitive match).",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Restrict the result to enabled (true) or disabled (false) accounts. Omit (null) to match every account.",
			},
			"include_builtin": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to include built-in accounts (SID RID below 1000, e.g. Administrator, Guest). Omit (null) means true.",
			},
			"users": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: nestedAttrs,
				},
				Description: "Matching local users, sorted by name (case-insensitive). Empty when no user matches the filters.",
			},
			"names": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "SAM account names of the matching users, in the same order as users. Empty when no user matches the filters.",
			},
			"sids": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "SIDs of the matching users, in the same order as users. Empty when no user matches the filters.",
			},
			// Read timeout (terraform-plugin-framework-timeouts): bounds the
			// remote lookup so a stalled session surfaces a timeout
			// diagnostic instead of blocking plan forever.
			// Absent configuration falls back to localUserDSDefaultTimeout (shared with the singular data source).
			"timeouts": dstimeouts.Attributes(ctx),
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data and
// constructs the LocalUser inventory client. The field is the narrow
// LocalUserLister interface so unit tests inject a fake without SSH.
func (d *windowsLocalUsersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.lister = winclient.NewLocalUserClient(c)
}

// localUsersFilterID builds the data source ID: the hex SHA-256 of the
// normalised filter set (raw regex, enabled tri-state with null rendered as
// "all", include_builtin), so identical filters share an ID and any filter
// change moves it. The preimage is the JSON encoding of the ordered field
// slice, so no separator-escaping ambiguity is possible.
func localUsersFilterID(nameRegex string, enabled *bool, includeBuiltin bool) string {
	enabledStr := "all"
	if enabled != nil {
		enabledStr = strconv.FormatBool(*enabled)
	}
	canonical, _ := json.Marshal([]any{nameRegex, enabledStr, includeBuiltin})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Read lists the local users matching the configured filters.
func (d *windowsLocalUsersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsLocalUsersDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	readTimeout, diags := config.Timeouts.Read(ctx, localUserDSDefaultTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	nameRegex := ""
	if !config.NameRegex.IsNull() && !config.NameRegex.IsUnknown() {
		nameRegex = config.NameRegex.ValueString()
	}
	var enabled *bool
	if !config.Enabled.IsNull() && !config.Enabled.IsUnknown() {
		v := config.Enabled.ValueBool()
		enabled = &v
	}
	includeBuiltin := true
	if !config.IncludeBuiltin.IsNull() && !config.IncludeBuiltin.IsUnknown() {
		includeBuiltin = config.IncludeBuiltin.ValueBool()
	}

	tflog.Debug(ctx, "windows_local_users data source Read start", map[string]interface{}{
		"name_regex": nameRegex, "enabled": enabled, "include_builtin": includeBuiltin,
	})

	users, err := d.lister.List(ctx, winclient.LocalUserFilter{
		NameRegex:      nameRegex,
		Enabled:        enabled,
		IncludeBuiltin: includeBuiltin,
	})
	if err != nil {
		addLocalUsersDiag(&resp.Diagnostics, "Read windows_local_users failed", err)
		return
	}
	if users == nil {
		users = []winclient.UserState{}
	}

	state := windowsLocalUsersDataSourceModel{
		ID:             types.StringValue(localUsersFilterID(nameRegex, enabled, includeBuiltin)),
		NameRegex:      config.NameRegex,
		Enabled:        config.Enabled,
		IncludeBuiltin: config.IncludeBuiltin,
		Timeouts:       config.Timeouts,
	}

	objType := localUsersObjectType()
	objs := make([]attr.Value, 0, len(users))
	names := make([]string, 0, len(users))
	sids := make([]string, 0, len(users))
	for _, u := range users {
		obj, d := localUserStateToObject(objType, u)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		objs = append(objs, obj)
		names = append(names, u.Name)
		sids = append(sids, u.SID)
	}
	usersList, diags := types.ListValue(objType, objs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Users = usersList
	state.Names = localUserStringList(ctx, &resp.Diagnostics, names)
	state.SIDs = localUserStringList(ctx, &resp.Diagnostics, sids)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "windows_local_users data source Read end", map[string]interface{}{
		"id":         state.ID.ValueString(),
		"user_count": len(users),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// addLocalUsersDiag converts a *winclient.LocalUserError into a TPF
// diagnostic.
func addLocalUsersDiag(diags *diag.Diagnostics, summary string, err error) {
	var lue *winclient.LocalUserError
	if errors.As(err, &lue) {
		detail := lue.Message
		if len(lue.Context) > 0 {
			detail += "\n\nContext:"
			for k, v := range lue.Context {
				detail += "\n  " + k + " = " + v
			}
		}
		if lue.Cause != nil {
			detail += "\n\nCause: " + lue.Cause.Error()
		}
		if lue.Kind != "" {
			detail += "\n\nKind: " + lue.Kind
		}
		diags.AddError(summary, detail)
		return
	}
	diags.AddError(summary, err.Error())
}
