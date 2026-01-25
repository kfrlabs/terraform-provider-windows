package resources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
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

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	username := d.Get("username").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Reading local user data source",
		map[string]any{"username": username})

	// Validate username for security
	if err := utils.ValidateField(username, username, "username"); err != nil {
		return utils.HandleResourceError("validate", username, "username", err)
	}

	// Check if user exists using the same function from resource_localuser.go
	info, err := checkLocalUserExists(ctx, sshClient, username, timeout)
	if err != nil {
		return utils.HandleResourceError("read", username, "state", err)
	}

	if !info.Exists {
		return utils.HandleResourceError("read", username, "state",
			fmt.Errorf("local user %s does not exist", username))
	}

	// Set all attributes
	d.SetId(username)
	if err := d.Set("username", username); err != nil {
		return utils.HandleResourceError("read", username, "username", err)
	}
	if err := d.Set("full_name", info.FullName); err != nil {
		return utils.HandleResourceError("read", username, "full_name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", username, "description", err)
	}
	if err := d.Set("password_never_expires", info.PasswordNeverExpires); err != nil {
		return utils.HandleResourceError("read", username, "password_never_expires", err)
	}
	if err := d.Set("user_cannot_change_password", info.UserMayNotChangePassword); err != nil {
		return utils.HandleResourceError("read", username, "user_cannot_change_password", err)
	}
	if err := d.Set("enabled", info.Enabled); err != nil {
		return utils.HandleResourceError("read", username, "enabled", err)
	}

	tflog.Info(ctx, "Successfully read local user data source",
		map[string]any{
			"username": username,
			"enabled":  info.Enabled,
		})

	return nil
}
