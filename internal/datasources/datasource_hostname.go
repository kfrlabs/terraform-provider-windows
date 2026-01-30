package datasources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/kfrlabs/terraform-provider-windows/internal/common"
)

// Ensure the implementation satisfies the expected interfaces
var (
	_ datasource.DataSource = &hostnameDataSource{}
)

// NewHostnameDataSource is a helper function to create the data source
func NewHostnameDataSource() datasource.DataSource {
	return &hostnameDataSource{}
}

// hostnameDataSource is the data source implementation
type hostnameDataSource struct {
	providerData *common.ProviderData
}

// hostnameDataSourceModel describes the data source data model
type hostnameDataSourceModel struct {
	ComputerName   types.String `tfsdk:"computer_name"`
	DNSHostname    types.String `tfsdk:"dns_hostname"`
	Domain         types.String `tfsdk:"domain"`
	Workgroup      types.String `tfsdk:"workgroup"`
	PartOfDomain   types.Bool   `tfsdk:"part_of_domain"`
	FQDN           types.String `tfsdk:"fqdn"`
	CommandTimeout types.Int64  `tfsdk:"command_timeout"`
}

// hostnameInfo represents the JSON structure returned by PowerShell
type hostnameInfo struct {
	ComputerName string `json:"ComputerName"`
	DNSHostName  string `json:"DNSHostName"`
	Domain       string `json:"Domain"`
	Workgroup    string `json:"Workgroup"`
	PartOfDomain bool   `json:"PartOfDomain"`
}

// Metadata returns the data source type name
func (d *hostnameDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hostname"
}

// Schema defines the schema for the data source
func (d *hostnameDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Retrieves hostname information from a Windows machine.",
		MarkdownDescription: "Retrieves comprehensive hostname information from a Windows machine including computer name, domain membership, and FQDN.",

		Attributes: map[string]schema.Attribute{
			"computer_name": schema.StringAttribute{
				Description: "The computer name (NetBIOS name).",
				Computed:    true,
			},
			"dns_hostname": schema.StringAttribute{
				Description: "The fully qualified DNS hostname.",
				Computed:    true,
			},
			"domain": schema.StringAttribute{
				Description: "The domain name if the computer is part of a domain.",
				Computed:    true,
			},
			"workgroup": schema.StringAttribute{
				Description: "The workgroup name if the computer is part of a workgroup.",
				Computed:    true,
			},
			"part_of_domain": schema.BoolAttribute{
				Description: "Whether the computer is part of a domain.",
				Computed:    true,
			},
			"fqdn": schema.StringAttribute{
				Description: "The fully qualified domain name (FQDN).",
				Computed:    true,
			},
			"command_timeout": schema.Int64Attribute{
				Description: "Timeout in seconds for PowerShell commands (default: 300).",
				Optional:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the data source
func (d *hostnameDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*common.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *common.ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.providerData = providerData
}

// Read refreshes the Terraform state with the latest data
func (d *hostnameDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data hostnameDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading Windows hostname data source")

	// Get SSH client from provider data
	sshClient, cleanup, err := d.providerData.GetSSHClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get SSH client",
			fmt.Sprintf("Could not acquire SSH client from pool: %s", err),
		)
		return
	}
	defer cleanup()

	// PowerShell command to retrieve all hostname information
	// Uses WMI to determine domain membership and environment variables for names
	command := `
$cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
@{
    'ComputerName' = $env:COMPUTERNAME
    'DNSHostName' = [System.Net.Dns]::GetHostName()
    'Domain' = $cs.Domain
    'Workgroup' = if ($cs.PartOfDomain) { '' } else { $cs.Domain }
    'PartOfDomain' = $cs.PartOfDomain
} | ConvertTo-Json -Compress
`

	tflog.Debug(ctx, "Executing command to retrieve hostname information")

	stdout, stderr, err := sshClient.ExecuteCommand(ctx, command)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get hostname information",
			fmt.Sprintf("Command failed: %s\nStdout: %s\nStderr: %s", err, stdout, stderr),
		)
		return
	}

	// Parse JSON output from PowerShell
	var info hostnameInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		resp.Diagnostics.AddError(
			"Failed to parse hostname information",
			fmt.Sprintf("Could not parse JSON output: %s\nOutput: %s", err, stdout),
		)
		return
	}

	// Build FQDN based on domain membership
	var fqdn string
	if info.PartOfDomain && info.Domain != "" {
		fqdn = fmt.Sprintf("%s.%s", strings.ToLower(info.ComputerName), strings.ToLower(info.Domain))
	} else {
		fqdn = strings.ToLower(info.ComputerName)
	}

	// Map response to data source model
	data.ComputerName = types.StringValue(info.ComputerName)
	data.DNSHostname = types.StringValue(info.DNSHostName)
	data.Domain = types.StringValue(info.Domain)
	data.Workgroup = types.StringValue(info.Workgroup)
	data.PartOfDomain = types.BoolValue(info.PartOfDomain)
	data.FQDN = types.StringValue(fqdn)

	tflog.Info(ctx, "Successfully read hostname data source",
		map[string]any{
			"computer_name":  info.ComputerName,
			"part_of_domain": info.PartOfDomain,
			"fqdn":           fqdn,
		})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
