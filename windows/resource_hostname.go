package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// validateHostname validates hostname format
func validateHostname(name string) error {
	if name == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("hostname exceeds maximum length of 255 characters")
	}

	labelRe := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$`)

	labels := strings.Split(name, ".")
	for _, lbl := range labels {
		if lbl == "" {
			return fmt.Errorf("hostname contains empty label")
		}
		if len(lbl) > 63 {
			return fmt.Errorf("hostname label '%s' exceeds 63 characters", lbl)
		}
		if !labelRe.MatchString(lbl) {
			return fmt.Errorf("hostname label '%s' contains invalid characters", lbl)
		}
	}
	return nil
}

func ResourceWindowsHostname() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsHostnameCreate,
		Read:   resourceWindowsHostnameRead,
		Update: resourceWindowsHostnameUpdate,
		Delete: resourceWindowsHostnameDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceWindowsHostnameImport,
		},
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The new hostname to apply to the Windows machine.",
			},
			"restart": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Restart the computer after renaming.",
			},
			"pending_reboot": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates if a reboot is pending for the hostname change to take effect.",
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

func resourceWindowsHostnameCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	hostname := d.Get("hostname").(string)
	timeout := d.Get("command_timeout").(int)
	restart := d.Get("restart").(bool)

	// Validate hostname format
	if err := validateHostname(hostname); err != nil {
		return utils.HandleResourceError("validate", hostname, "hostname", err)
	}

	// Validate for PowerShell security
	if err := utils.ValidateField(hostname, hostname, "hostname"); err != nil {
		return err
	}

	tflog.Info(ctx, "Creating/updating hostname",
		map[string]any{
			"hostname": hostname,
			"restart":  restart,
		})

	// Get current hostname
	checkCommand := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(checkCommand, timeout)
	currentHostname := strings.TrimSpace(stdout)

	if err != nil {
		tflog.Warn(ctx, "Could not retrieve current hostname",
			map[string]any{"error": err.Error()})
	} else {
		tflog.Info(ctx, "Current hostname retrieved",
			map[string]any{
				"current": currentHostname,
				"target":  hostname,
			})

		// Check if hostname is already set
		if strings.EqualFold(currentHostname, hostname) {
			tflog.Info(ctx, "Hostname already set, no change needed",
				map[string]any{"hostname": hostname})
			d.SetId(hostname)
			if err := d.Set("pending_reboot", false); err != nil {
				return utils.HandleResourceError("create", hostname, "pending_reboot", err)
			}
			return nil
		}

		tflog.Info(ctx, "Changing hostname",
			map[string]any{
				"from": currentHostname,
				"to":   hostname,
			})
	}

	// Build secure command
	command := fmt.Sprintf("Rename-Computer -NewName %s -Force -ErrorAction Stop",
		powershell.QuotePowerShellString(hostname))
	if restart {
		command += " -Restart"
	}

	tflog.Debug(ctx, "Executing hostname change command")

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("create", hostname, "hostname", command, stdout, stderr, err)
	}

	d.SetId(hostname)

	if restart {
		tflog.Warn(ctx, "Computer is restarting, hostname change will be effective after reboot",
			map[string]any{"hostname": hostname})
		if err := d.Set("pending_reboot", false); err != nil {
			return utils.HandleResourceError("create", hostname, "pending_reboot", err)
		}
	} else {
		tflog.Warn(ctx, "Hostname change requires reboot to take effect",
			map[string]any{
				"hostname": hostname,
				"action":   "Set restart=true or reboot manually",
			})
		if err := d.Set("pending_reboot", true); err != nil {
			return utils.HandleResourceError("create", hostname, "pending_reboot", err)
		}
	}

	tflog.Info(ctx, "Hostname resource created successfully",
		map[string]any{"hostname": hostname})

	return nil
}

func resourceWindowsHostnameRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	expected := d.Id()
	if expected == "" {
		expected = d.Get("hostname").(string)
	}

	pendingReboot, _ := d.Get("pending_reboot").(bool)

	tflog.Debug(ctx, "Reading hostname",
		map[string]any{
			"expected":       expected,
			"pending_reboot": pendingReboot,
		})

	// Validate for PowerShell security
	if err := utils.ValidateField(expected, expected, "hostname"); err != nil {
		return utils.HandleResourceError("validate", expected, "hostname", err)
	}

	// Get current hostname
	command := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		if pendingReboot {
			tflog.Warn(ctx, "Could not verify hostname (machine may be rebooting), keeping resource in state")
			return nil
		}
		tflog.Warn(ctx, "Could not verify hostname, keeping resource in state",
			map[string]any{"error": err.Error()})
		return nil
	}

	currentHostname := strings.TrimSpace(stdout)

	tflog.Debug(ctx, "Hostname comparison",
		map[string]any{
			"current":  currentHostname,
			"expected": expected,
		})

	// Case-insensitive comparison
	if !strings.EqualFold(currentHostname, expected) {
		if pendingReboot {
			tflog.Info(ctx, "Hostname not yet changed (pending reboot)",
				map[string]any{
					"current":  currentHostname,
					"expected": expected,
				})
			return nil
		}

		tflog.Warn(ctx, "Hostname mismatch, removing from state",
			map[string]any{
				"expected": expected,
				"actual":   currentHostname,
			})
		d.SetId("")
		return nil
	}

	tflog.Info(ctx, "Hostname verified successfully",
		map[string]any{"hostname": expected})

	if pendingReboot {
		tflog.Info(ctx, "Hostname change is now effective, clearing pending_reboot flag")
		if err := d.Set("pending_reboot", false); err != nil {
			return utils.HandleResourceError("read", expected, "pending_reboot", err)
		}
	}

	return nil
}

func resourceWindowsHostnameUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	// If only command_timeout changed, no need to rename
	if d.HasChange("command_timeout") && !d.HasChange("hostname") && !d.HasChange("restart") {
		tflog.Debug(ctx, "Only command_timeout changed, skipping hostname update")
		return resourceWindowsHostnameRead(d, m)
	}

	// For any other change, reuse create which handles rename and restart
	return resourceWindowsHostnameCreate(d, m)
}

func resourceWindowsHostnameDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	tflog.Info(ctx, "Deleting hostname resource (no action on remote host)",
		map[string]any{"hostname": d.Id()})
	d.SetId("")
	return nil
}

func resourceWindowsHostnameImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	hostname := d.Id()

	// Validate hostname format
	if err := validateHostname(hostname); err != nil {
		return nil, utils.HandleResourceError("validate", hostname, "hostname", err)
	}

	// Validate for PowerShell security
	if err := utils.ValidateField(hostname, hostname, "hostname"); err != nil {
		return nil, utils.HandleResourceError("validate", hostname, "hostname", err)
	}

	// Set attributes and defaults
	if err := d.Set("hostname", hostname); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "hostname", err)
	}
	if err := d.Set("restart", false); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "restart", err)
	}
	if err := d.Set("pending_reboot", false); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "pending_reboot", err)
	}
	if err := d.Set("command_timeout", 300); err != nil {
		return nil, utils.HandleResourceError("import", hostname, "command_timeout", err)
	}

	// Verify hostname matches remote host
	checkCommand := "hostname"
	stdout, _, err := sshClient.ExecuteCommand(checkCommand, 300)
	if err != nil {
		tflog.Warn(ctx, "Could not verify remote hostname during import",
			map[string]any{"error": err.Error()})
	} else {
		currentHostname := strings.TrimSpace(stdout)
		if !strings.EqualFold(currentHostname, hostname) {
			return nil, fmt.Errorf("imported hostname '%s' does not match remote host actual hostname '%s'. "+
				"Use the actual hostname or run 'Rename-Computer -NewName %s' on the remote host first",
				hostname, currentHostname, hostname)
		}
		tflog.Info(ctx, "Successfully verified hostname during import",
			map[string]any{"hostname": hostname})
	}

	return []*schema.ResourceData{d}, nil
}
