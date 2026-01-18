package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
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

	// Check if service exists using the same function from resource_services.go
	info, err := checkServiceExists(ctx, sshClient, name, timeout)
	if err != nil {
		return fmt.Errorf("failed to read service %s: %w", name, err)
	}

	if !info.Exists {
		return fmt.Errorf("Windows service %s does not exist", name)
	}

	// Set all attributes
	d.SetId(name)
	if err := d.Set("name", info.Name); err != nil {
		return fmt.Errorf("failed to set name: %w", err)
	}
	if err := d.Set("display_name", info.DisplayName); err != nil {
		return fmt.Errorf("failed to set display_name: %w", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return fmt.Errorf("failed to set description: %w", err)
	}
	
	// Convert status and start_type using helper functions
	status := convertServiceStatus(info.Status)
	if err := d.Set("status", status); err != nil {
		return fmt.Errorf("failed to set status: %w", err)
	}
	
	startType := convertStartType(info.StartType)
	if err := d.Set("start_type", startType); err != nil {
		return fmt.Errorf("failed to set start_type: %w", err)
	}
	
	if err := d.Set("start_name", info.StartName); err != nil {
		return fmt.Errorf("failed to set start_name: %w", err)
	}
	if err := d.Set("binary_path", info.BinaryPathName); err != nil {
		return fmt.Errorf("failed to set binary_path: %w", err)
	}
	if err := d.Set("service_type", info.ServiceType); err != nil {
		return fmt.Errorf("failed to set service_type: %w", err)
	}

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Successfully read service: %s (status=%s, start_type=%s)", name, status, startType))
	return nil
}
