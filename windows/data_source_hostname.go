package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// HostnameInfo represents hostname information
type HostnameInfo struct {
	ComputerName string `json:"ComputerName"`
	DNSHostName  string `json:"DNSHostName"`
	Domain       string `json:"Domain"`
	Workgroup    string `json:"Workgroup"`
	PartOfDomain bool   `json:"PartOfDomain"`
}

func DataSourceWindowsHostname() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsHostnameRead,

		Schema: map[string]*schema.Schema{
			"computer_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The computer name (NetBIOS name).",
			},
			"dns_hostname": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The fully qualified DNS hostname.",
			},
			"domain": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The domain name if the computer is part of a domain.",
			},
			"workgroup": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The workgroup name if the computer is part of a workgroup.",
			},
			"part_of_domain": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the computer is part of a domain.",
			},
			"fqdn": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The fully qualified domain name (FQDN).",
			},
			"command_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     300,
				Description: "Timeout in seconds for PowerShell commands.",
			},
		},
	}
}

func dataSourceWindowsHostnameRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Reading Windows hostname data source")

	// PowerShell command to retrieve all hostname information
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

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"get_hostname",
			"hostname_info",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	var info HostnameInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return utils.HandleResourceError("parse_hostname", "hostname_info", "output",
			fmt.Errorf("failed to parse hostname info: %w; output: %s", err, stdout))
	}

	// Build FQDN
	var fqdn string
	if info.PartOfDomain && info.Domain != "" {
		fqdn = fmt.Sprintf("%s.%s", strings.ToLower(info.ComputerName), strings.ToLower(info.Domain))
	} else {
		fqdn = strings.ToLower(info.ComputerName)
	}

	// Set all attributes
	d.SetId(info.ComputerName)
	if err := d.Set("computer_name", info.ComputerName); err != nil {
		return utils.HandleResourceError("read", info.ComputerName, "computer_name", err)
	}
	if err := d.Set("dns_hostname", info.DNSHostName); err != nil {
		return utils.HandleResourceError("read", info.ComputerName, "dns_hostname", err)
	}
	if err := d.Set("domain", info.Domain); err != nil {
		return utils.HandleResourceError("read", info.ComputerName, "domain", err)
	}
	if err := d.Set("workgroup", info.Workgroup); err != nil {
		return utils.HandleResourceError("read", info.ComputerName, "workgroup", err)
	}
	if err := d.Set("part_of_domain", info.PartOfDomain); err != nil {
		return utils.HandleResourceError("read", info.ComputerName, "part_of_domain", err)
	}
	if err := d.Set("fqdn", fqdn); err != nil {
		return utils.HandleResourceError("read", info.ComputerName, "fqdn", err)
	}

	tflog.Info(ctx, "Successfully read hostname data source",
		map[string]any{
			"computer_name":  info.ComputerName,
			"part_of_domain": info.PartOfDomain,
			"fqdn":           fqdn,
		})

	return nil
}
