package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

func DataSourceWindowsService() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsServiceRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the Windows service to retrieve.",
			},
			"display_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The display name of the service.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A description of what the service does.",
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The current status of the service (Running, Stopped, etc.).",
			},
			"start_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The startup type of the service (Automatic, Manual, Disabled, Boot, System).",
			},
			"start_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The account under which the service runs.",
			},
			"binary_path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The path to the service executable.",
			},
			"service_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of service.",
			},
			"can_pause_and_continue": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the service can be paused and continued.",
			},
			"can_shutdown": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the service can be shut down.",
			},
			"can_stop": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the service can be stopped.",
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

func dataSourceWindowsServiceRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Reading Windows service: %s", name))

	// Validate service name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return utils.HandleResourceError("validate", name, "name", err)
	}

	// Check if service exists using the same function from resource_services.go
	info, err := checkServiceExists(ctx, sshClient, name, timeout)
	if err != nil {
		return utils.HandleResourceError("read", name, "state", err)
	}

	if !info.Exists {
		return utils.HandleResourceError("read", name, "state",
			fmt.Errorf("Windows service %s does not exist", name))
	}

	// Set all attributes
	d.SetId(name)
	if err := d.Set("name", info.Name); err != nil {
		return utils.HandleResourceError("read", name, "name", err)
	}
	if err := d.Set("display_name", info.DisplayName); err != nil {
		return utils.HandleResourceError("read", name, "display_name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", name, "description", err)
	}

	// Convert status and start_type using helper functions
	status := convertServiceStatus(info.Status)
	if err := d.Set("status", status); err != nil {
		return utils.HandleResourceError("read", name, "status", err)
	}

	startType := convertStartType(info.StartType)
	if err := d.Set("start_type", startType); err != nil {
		return utils.HandleResourceError("read", name, "start_type", err)
	}

	if err := d.Set("start_name", info.StartName); err != nil {
		return utils.HandleResourceError("read", name, "start_name", err)
	}
	if err := d.Set("binary_path", info.BinaryPathName); err != nil {
		return utils.HandleResourceError("read", name, "binary_path", err)
	}
	if err := d.Set("service_type", info.ServiceType); err != nil {
		return utils.HandleResourceError("read", name, "service_type", err)
	}

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Successfully read service: %s (status=%s, start_type=%s)", name, status, startType))
	return nil
}
