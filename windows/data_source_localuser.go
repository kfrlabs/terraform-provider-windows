package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

func DataSourceWindowsLocalUser() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsLocalUserRead,

		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the local user account to retrieve.",
			},
			"full_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The full name of the user.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "A description of the user account.",
			},
			"password_never_expires": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the password never expires.",
			},
			"user_cannot_change_password": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the user cannot change their password.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the account is enabled.",
			},
			"password_changeable_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date when password can be changed.",
			},
			"password_expires": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Date when password expires.",
			},
			"last_logon": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last logon time.",
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

func dataSourceWindowsLocalUserRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Reading local user: %s", username))

	// Check if user exists using the same function from resource_localuser.go
	info, err := checkLocalUserExists(ctx, sshClient, username, timeout)
	if err != nil {
		return fmt.Errorf("failed to read local user %s: %w", username, err)
	}

	if !info.Exists {
		return fmt.Errorf("local user %s does not exist", username)
	}

	// Set all attributes
	d.SetId(username)
	if err := d.Set("username", username); err != nil {
		return fmt.Errorf("failed to set username: %w", err)
	}
	if err := d.Set("full_name", info.FullName); err != nil {
		return fmt.Errorf("failed to set full_name: %w", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return fmt.Errorf("failed to set description: %w", err)
	}
	if err := d.Set("password_never_expires", info.PasswordNeverExpires); err != nil {
		return fmt.Errorf("failed to set password_never_expires: %w", err)
	}
	if err := d.Set("user_cannot_change_password", info.UserMayNotChangePassword); err != nil {
		return fmt.Errorf("failed to set user_cannot_change_password: %w", err)
	}
	if err := d.Set("enabled", info.Enabled); err != nil {
		return fmt.Errorf("failed to set enabled: %w", err)
	}

	tflog.Info(ctx, fmt.Sprintf("[DATA SOURCE] Successfully read local user: %s", username))
	return nil
}
