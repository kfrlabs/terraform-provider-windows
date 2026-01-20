package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

func DataSourceWindowsLocalGroup() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsLocalGroupRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the local group to retrieve.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A description of the local group.",
			},
			"sid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The Security Identifier (SID) of the group.",
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

func dataSourceWindowsLocalGroupRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Reading local group: %s", name))

	// Validate name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return utils.HandleResourceError("validate", name, "name", err)
	}

	// Check if group exists using the same function from resource_localgroup.go
	info, err := checkLocalGroupExists(ctx, sshClient, name, timeout)
	if err != nil {
		return utils.HandleResourceError("read", name, "state", err)
	}

	if !info.Exists {
		return utils.HandleResourceError("read", name, "state",
			fmt.Errorf("local group %s does not exist", name))
	}

	// Set all attributes
	d.SetId(name)
	if err := d.Set("name", info.Name); err != nil {
		return utils.HandleResourceError("read", name, "name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", name, "description", err)
	}

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Successfully read local group: %s", name))
	return nil
}
