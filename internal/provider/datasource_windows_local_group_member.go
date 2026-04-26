// Package provider: windows_local_group_member data source implementation.
//
// Reads the observed state of a specific (group, member) pair by name.
// Both group_name and member_name are Required lookup keys. The resolved
// SIDs and principal source are returned as Computed attributes.
package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// Framework interface assertions.
var (
	_ datasource.DataSource              = (*windowsLocalGroupMemberDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*windowsLocalGroupMemberDataSource)(nil)
)

// NewWindowsLocalGroupMemberDataSource is the constructor registered in provider.go.
func NewWindowsLocalGroupMemberDataSource() datasource.DataSource {
	return &windowsLocalGroupMemberDataSource{}
}

// windowsLocalGroupMemberDataSource is the TPF data source type for
// windows_local_group_member.
type windowsLocalGroupMemberDataSource struct {
	client *winclient.Client
	member winclient.ClientLocalGroupMember
}

// windowsLocalGroupMemberDataSourceModel is the Terraform state model for the
// windows_local_group_member data source.
type windowsLocalGroupMemberDataSourceModel struct {
	ID                    types.String `tfsdk:"id"`
	GroupName             types.String `tfsdk:"group_name"`
	MemberName            types.String `tfsdk:"member_name"`
	GroupSID              types.String `tfsdk:"group_sid"`
	MemberSID             types.String `tfsdk:"member_sid"`
	MemberPrincipalSource types.String `tfsdk:"member_principal_source"`
}

// Metadata sets the data source type name ("windows_local_group_member").
func (d *windowsLocalGroupMemberDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_group_member"
}

// Schema returns the TPF schema for the windows_local_group_member data source.
func (d *windowsLocalGroupMemberDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the membership state of a specific (group, member) pair by name " +
			"without managing the membership lifecycle.\n\n" +
			"Both `group_name` and `member_name` are required. The resolved SIDs and " +
			"principal source are returned as computed attributes.\n\n" +
			"Returns an error when the group or member is not found.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Composite data source ID: \"<group_sid>/<member_sid>\".",
			},
			"group_name": schema.StringAttribute{
				Required:    true,
				Description: "Name or SID of the target local group (e.g. \"Administrators\" or \"S-1-5-32-544\").",
			},
			"member_name": schema.StringAttribute{
				Required:    true,
				Description: "Display name of the member to look up within the group.",
			},
			"group_sid": schema.StringAttribute{
				Computed:    true,
				Description: "Security Identifier of the group, resolved from group_name.",
			},
			"member_sid": schema.StringAttribute{
				Computed:    true,
				Description: "Security Identifier of the member account.",
			},
			"member_principal_source": schema.StringAttribute{
				Computed:    true,
				Description: "Account origin: Local, ActiveDirectory, AzureAD, MicrosoftAccount, or Unknown (orphaned SID).",
			},
		},
	}
}

// Configure extracts the shared *winclient.Client from provider data.
func (d *windowsLocalGroupMemberDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = c
	d.member = winclient.NewLocalGroupMemberClient(c)
}

// Read fetches the group membership state from the remote Windows host.
//
// Resolution flow:
//  1. ResolveGroup(ctx, c, groupName) → GroupState with SID.
//  2. member.List(ctx, groupSID) → all current members.
//  3. Match by MemberName (case-insensitive). Not found → AddError.
func (d *windowsLocalGroupMemberDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config windowsLocalGroupMemberDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupName := config.GroupName.ValueString()
	memberName := config.MemberName.ValueString()

	tflog.Debug(ctx, "windows_local_group_member data source Read start", map[string]interface{}{
		"group_name":  groupName,
		"member_name": memberName,
	})

	// Step 1: resolve group to SID.
	gs, err := winclient.ResolveGroup(ctx, d.client, groupName)
	if err != nil {
		if winclient.IsLocalGroupError(err, winclient.LocalGroupErrorNotFound) {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_local_group_member — group %q not found", groupName),
				fmt.Sprintf("No local group with name/SID %q was found on the target host.", groupName),
			)
			return
		}
		addLocalGroupDiag(&resp.Diagnostics, "windows_local_group_member data source: resolve group failed", err)
		return
	}

	// Step 2: list all members of the group.
	members, err := d.member.List(ctx, gs.SID)
	if err != nil {
		if winclient.IsLocalGroupMemberError(err, winclient.LocalGroupMemberErrorGroupNotFound) {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Data source not found: windows_local_group_member — group %q not found", groupName),
				fmt.Sprintf("Group %q (SID %s) was not found when listing members.", groupName, gs.SID),
			)
			return
		}
		addLocalGroupMemberDiag(&resp.Diagnostics, "windows_local_group_member data source: list members failed", err)

		return
	}

	// Step 3: find the member by name (case-insensitive).
	var found *winclient.LocalGroupMemberState
	for _, m := range members {
		if strings.EqualFold(m.MemberName, memberName) {
			found = m
			break
		}
	}

	if found == nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Data source not found: windows_local_group_member — member %q not found in group %q", memberName, groupName),
			fmt.Sprintf("No member named %q was found in group %q (SID %s). "+
				"Use Get-LocalGroupMember -Name %q on the target to verify.", memberName, groupName, gs.SID, groupName),
		)
		return
	}

	compositeID := found.GroupSID + "/" + found.MemberSID
	state := windowsLocalGroupMemberDataSourceModel{
		ID:                    types.StringValue(compositeID),
		GroupName:             types.StringValue(groupName),
		MemberName:            types.StringValue(found.MemberName),
		GroupSID:              types.StringValue(found.GroupSID),
		MemberSID:             types.StringValue(found.MemberSID),
		MemberPrincipalSource: types.StringValue(found.PrincipalSource),
	}

	tflog.Debug(ctx, "windows_local_group_member data source Read end", map[string]interface{}{
		"group_sid":  state.GroupSID.ValueString(),
		"member_sid": state.MemberSID.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Helper addLocalGroupMemberDiag is reused from resource_windows_local_group_member.go
// (same package).
