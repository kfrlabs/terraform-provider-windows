package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// serviceInfo represents information about a Windows service
type serviceInfo struct {
	Exists         bool        `json:"Exists"`
	Name           string      `json:"Name"`
	DisplayName    string      `json:"DisplayName"`
	Description    string      `json:"Description"`
	Status         interface{} `json:"Status"`    // Can be string or int
	StartType      interface{} `json:"StartType"` // Can be string or int
	StartName      string      `json:"StartName"`
	BinaryPathName string      `json:"BinaryPathName"`
	ServiceType    string      `json:"ServiceType"`
}

// Service status constants (WMI Win32_Service Status codes)
const (
	ServiceStatusStopped         = 1
	ServiceStatusStartPending    = 2
	ServiceStatusStopPending     = 3
	ServiceStatusRunning         = 4
	ServiceStatusContinuePending = 5
	ServiceStatusPausePending    = 6
	ServiceStatusPaused          = 7
)

// Service start type constants (WMI Win32_Service StartMode codes)
const (
	ServiceStartTypeBoot      = 0
	ServiceStartTypeSystem    = 1
	ServiceStartTypeAutomatic = 2
	ServiceStartTypeManual    = 3
	ServiceStartTypeDisabled  = 4
)

// convertServiceStatus converts WMI Status code to string
func convertServiceStatus(status interface{}) string {
	switch v := status.(type) {
	case string:
		return v
	case float64:
		switch int(v) {
		case ServiceStatusStopped:
			return "Stopped"
		case ServiceStatusStartPending:
			return "Start Pending"
		case ServiceStatusStopPending:
			return "Stop Pending"
		case ServiceStatusRunning:
			return "Running"
		case ServiceStatusContinuePending:
			return "Continue Pending"
		case ServiceStatusPausePending:
			return "Pause Pending"
		case ServiceStatusPaused:
			return "Paused"
		default:
			return "Unknown"
		}
	default:
		return "Unknown"
	}
}

// convertStartType converts WMI StartType code to string
func convertStartType(startType interface{}) string {
	switch v := startType.(type) {
	case string:
		return v
	case float64:
		switch int(v) {
		case ServiceStartTypeBoot:
			return "Boot"
		case ServiceStartTypeSystem:
			return "System"
		case ServiceStartTypeAutomatic:
			return "Automatic"
		case ServiceStartTypeManual:
			return "Manual"
		case ServiceStartTypeDisabled:
			return "Disabled"
		default:
			return "Unknown"
		}
	default:
		return "Unknown"
	}
}

func ResourceWindowsService() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsServiceCreate,
		Read:   resourceWindowsServiceRead,
		Update: resourceWindowsServiceUpdate,
		Delete: resourceWindowsServiceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the Windows service (e.g., 'MyAppService'). Cannot be changed after creation.",
			},
			"display_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The display name of the service shown in Services application.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "A description of what the service does.",
			},
			"binary_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "The full path to the service executable (e.g., 'C:\\Program Files\\MyApp\\service.exe'). Required for new services.",
			},
			"start_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "Manual",
				Description:  "The startup type of the service: 'Automatic', 'Manual', 'Disabled', or 'Boot' (for driver services).",
				ValidateFunc: validation.StringInSlice([]string{"Automatic", "Manual", "Disabled", "Boot", "System"}, false),
			},
			"state": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "Stopped",
				Description:  "The desired state of the service: 'Running' or 'Stopped'.",
				ValidateFunc: validation.StringInSlice([]string{"Running", "Stopped"}, false),
			},
			"start_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The account under which the service runs (e.g., 'LocalSystem', 'NT AUTHORITY\\NetworkService', or 'DOMAIN\\username'). For user accounts, also provide 'credential'.",
			},
			"credential": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The password for the service account if 'start_name' is a domain or local user account. Format: 'password' (username is in start_name). Only used at creation and update.",
			},
			"load_order_group": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The load order group for driver services.",
			},
			"service_type": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "The type of service. Usually 'Win32OwnProcess' or 'Win32ShareProcess'. Read-only after creation.",
				ValidateFunc: validation.StringInSlice([]string{"Win32OwnProcess", "Win32ShareProcess", "KernelDriver", "FileSystemDriver"}, false),
			},
			"depend_on_service": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of service names this service depends on.",
			},
			"allow_existing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, adopt existing service instead of failing. If false, fail if service already exists.",
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

// checkServiceExists verifies whether a Windows service exists and retrieves its configuration
//
// This function executes a PowerShell command combining Get-Service and WMI queries
// to retrieve comprehensive service information.
//
// Parameters:
//   - ctx: Context for logging and cancellation
//   - sshClient: Authenticated SSH client to the Windows host
//   - name: The service name to check (must be validated before calling)
//   - timeout: Command execution timeout in seconds
//
// Returns:
//   - *serviceInfo: Service information if exists, with Exists=false if not found
//   - error: Any error during command execution or JSON parsing
func checkServiceExists(ctx context.Context, sshClient *ssh.Client, name string, timeout int) (*serviceInfo, error) {
	// Validate service name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return nil, err
	}

	tflog.Debug(ctx, "Checking if service exists", map[string]any{
		"service_name": name,
	})

	// PowerShell command to get service info as JSON with status code conversion
	command := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name %s -ErrorAction SilentlyContinue
if ($service) {
    $info = Get-WmiObject Win32_Service -Filter "Name='%s'" -ErrorAction SilentlyContinue
    
    # Convert Status code to string
    $statusString = switch ($service.Status.ToString()) {
        'Stopped' { 'Stopped' }
        'Running' { 'Running' }
        'Paused' { 'Paused' }
        default { $service.Status.ToString() }
    }
    
    # Convert StartType code to string
    $startTypeString = switch ($service.StartType.ToString()) {
        'Automatic' { 'Automatic' }
        'Manual' { 'Manual' }
        'Disabled' { 'Disabled' }
        'Boot' { 'Boot' }
        'System' { 'System' }
        default { $service.StartType.ToString() }
    }
    
    @{
        Exists = $true
        Name = $service.Name
        DisplayName = $service.DisplayName
        Description = $info.Description
        Status = $statusString
        StartType = $startTypeString
        StartName = $info.StartName
        BinaryPathName = $info.PathName
        ServiceType = $info.ServiceType
    } | ConvertTo-Json -Compress
} else {
    @{ Exists = $false } | ConvertTo-Json -Compress
}
`, powershell.QuotePowerShellString(name), name)

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to check service: %w; stderr: %s", err, stderr)
	}

	var info serviceInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse service info: %w; output: %s", err, stdout)
	}

	return &info, nil
}

// buildServiceCreationCommand builds a PowerShell command to create a new service
func buildServiceCreationCommand(d *schema.ResourceData, name, binaryPath string) (string, error) {
	// Start building the command parts
	params := []string{
		fmt.Sprintf("-Name %s", powershell.QuotePowerShellString(name)),
		fmt.Sprintf("-BinaryPathName %s", powershell.QuotePowerShellString(binaryPath)),
	}

	// Add display name if provided
	if displayName, ok, err := utils.ValidateSchemaOptionalString(d, "display_name", name); err != nil {
		return "", err
	} else if ok {
		params = append(params, fmt.Sprintf("-DisplayName %s", powershell.QuotePowerShellString(displayName)))
	}

	// Add start type
	startType := d.Get("start_type").(string)
	if err := utils.ValidateField(startType, name, "start_type"); err != nil {
		return "", err
	}
	params = append(params, fmt.Sprintf("-StartupType %s", powershell.QuotePowerShellString(startType)))

	// Add start name and credential if provided
	if startName, ok, err := utils.ValidateSchemaOptionalString(d, "start_name", name); err != nil {
		return "", err
	} else if ok {
		params = append(params, fmt.Sprintf("-StartName %s", powershell.QuotePowerShellString(startName)))

		if credential, hasCredential := d.GetOk("credential"); hasCredential {
			// Create a PowerShell credential object
			credCmd := fmt.Sprintf("(New-Object System.Management.Automation.PSCredential(%s, (ConvertTo-SecureString %s -AsPlainText -Force)))",
				powershell.QuotePowerShellString(startName),
				powershell.QuotePowerShellString(credential.(string)))
			params = append(params, fmt.Sprintf("-Credential %s", credCmd))
		}
	}

	// Add load order group if provided
	if loadOrderGroup, ok, err := utils.ValidateSchemaOptionalString(d, "load_order_group", name); err != nil {
		return "", err
	} else if ok {
		params = append(params, fmt.Sprintf("-LoadOrderGroup %s", powershell.QuotePowerShellString(loadOrderGroup)))
	}

	// Build final command
	command := "New-Service " + strings.Join(params, " ") + " -ErrorAction Stop"
	return command, nil
}

// setServiceDescription sets the description for a service
func setServiceDescription(ctx context.Context, sshClient *ssh.Client, name, description string, timeout int) error {
	if description == "" {
		return nil
	}

	if err := utils.ValidateField(description, name, "description"); err != nil {
		return err
	}

	descCmd := fmt.Sprintf("Set-Service -Name %s -Description %s -ErrorAction Stop",
		powershell.QuotePowerShellString(name),
		powershell.QuotePowerShellString(description))

	tflog.Debug(ctx, "Setting service description")
	stdout, stderr, err := sshClient.ExecuteCommand(descCmd, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"create",
			name,
			"description",
			descCmd,
			stdout,
			stderr,
			err,
		)
	}

	return nil
}

// setServiceState starts or stops a service based on desired state
func setServiceState(ctx context.Context, sshClient *ssh.Client, name, desiredState string, timeout int) error {
	if desiredState != "Running" && desiredState != "Stopped" {
		return nil
	}

	var command string
	var action string

	if desiredState == "Running" {
		command = fmt.Sprintf("Start-Service -Name %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name))
		action = "start"
	} else {
		command = fmt.Sprintf("Stop-Service -Name %s -Force -ErrorAction Stop",
			powershell.QuotePowerShellString(name))
		action = "stop"
	}

	tflog.Info(ctx, fmt.Sprintf("Setting service state to: %s", desiredState), map[string]any{
		"service_name": name,
		"action":       action,
	})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			action,
			name,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	tflog.Info(ctx, fmt.Sprintf("Service %s successfully", action+"ed"), map[string]any{
		"service_name": name,
	})

	return nil
}

func resourceWindowsServiceCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	tflog.Info(ctx, "Starting service creation", map[string]any{
		"service_name": name,
	})

	// Validate service name
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	// Check if service already exists
	info, err := checkServiceExists(ctx, sshClient, name, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", name, "state", err)
	}

	if info.Exists {
		if allowExisting {
			tflog.Info(ctx, "Service already exists, adopting it", map[string]any{
				"service_name":   name,
				"allow_existing": true,
			})
			d.SetId(name)
			return resourceWindowsServiceRead(d, m)
		}

		resourceName := "service"
		return utils.HandleResourceError(
			"create",
			name,
			"state",
			fmt.Errorf("service already exists. "+
				"To manage this existing service, either:\n"+
				"  1. Import it: terraform import windows_service.%s '%s'\n"+
				"  2. Set allow_existing = true in your configuration\n"+
				"  3. Remove it first (WARNING - will delete the service): sc.exe delete '%s'",
				resourceName, name, name),
		)
	}

	// Verify binary_path is provided for new service
	binaryPath, ok := d.GetOk("binary_path")
	if !ok {
		return utils.HandleResourceError("validate", name, "binary_path",
			fmt.Errorf("binary_path is required for creating a new service"))
	}

	// Validate binary_path
	if err := utils.ValidateField(binaryPath.(string), name, "binary_path"); err != nil {
		return err
	}

	// Build service creation command
	command, err := buildServiceCreationCommand(d, name, binaryPath.(string))
	if err != nil {
		return err
	}

	tflog.Info(ctx, "Creating service with command (credentials hidden)")
	tflog.Debug(ctx, "Executing service creation command", map[string]any{
		"service_name":   name,
		"has_credential": d.Get("credential").(string) != "",
	})

	// Execute service creation
	stdout, stderr, execErr := sshClient.ExecuteCommand(command, timeout)
	if execErr != nil {
		return utils.HandleCommandError(
			"create",
			name,
			"state",
			"New-Service (credentials hidden)",
			stdout,
			stderr,
			execErr,
		)
	}

	tflog.Info(ctx, "Service created successfully", map[string]any{
		"service_name": name,
	})

	// Set description if provided
	if description, ok := d.GetOk("description"); ok {
		if err := setServiceDescription(ctx, sshClient, name, description.(string), timeout); err != nil {
			return err
		}
	}

	// Set desired state
	desiredState := d.Get("state").(string)
	if err := setServiceState(ctx, sshClient, name, desiredState, timeout); err != nil {
		return err
	}

	d.SetId(name)
	tflog.Info(ctx, "Service resource created successfully", map[string]any{
		"service_name": name,
	})

	return resourceWindowsServiceRead(d, m)
}

func resourceWindowsServiceRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Id()
	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	tflog.Debug(ctx, "Reading service", map[string]any{
		"service_name": name,
	})

	info, err := checkServiceExists(ctx, sshClient, name, timeout)
	if err != nil {
		tflog.Warn(ctx, "Failed to read service, removing from state", map[string]any{
			"service_name": name,
			"error":        err.Error(),
		})
		d.SetId("")
		return nil
	}

	if !info.Exists {
		tflog.Debug(ctx, "Service does not exist, removing from state", map[string]any{
			"service_name": name,
		})
		d.SetId("")
		return nil
	}

	// Convert Status and StartType if necessary (fallback in case PowerShell conversion fails)
	status := convertServiceStatus(info.Status)
	startType := convertStartType(info.StartType)

	// Update state with all service attributes
	attributes := map[string]interface{}{
		"name":         info.Name,
		"display_name": info.DisplayName,
		"description":  info.Description,
		"state":        status,
		"start_type":   startType,
		"start_name":   info.StartName,
		"binary_path":  info.BinaryPathName,
		"service_type": info.ServiceType,
	}

	for key, value := range attributes {
		if err := d.Set(key, value); err != nil {
			return utils.HandleResourceError("read", name, key, err)
		}
	}

	tflog.Debug(ctx, "Service read successfully", map[string]any{
		"service_name": name,
		"status":       status,
		"start_type":   startType,
	})

	return nil
}

func resourceWindowsServiceUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Updating service", map[string]any{
		"service_name": name,
	})

	// Validate service name
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	// Track changes
	changes := make(map[string]string)

	// Update display_name
	if d.HasChange("display_name") {
		displayName := d.Get("display_name").(string)
		if err := utils.ValidateField(displayName, name, "display_name"); err != nil {
			return err
		}

		cmd := fmt.Sprintf("Set-Service -Name %s -DisplayName %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(displayName))

		changes["display_name"] = displayName

		tflog.Debug(ctx, "Updating display_name")
		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError("update", name, "display_name", cmd, stdout, stderr, err)
		}
	}

	// Update description
	if d.HasChange("description") {
		description := d.Get("description").(string)
		if err := utils.ValidateField(description, name, "description"); err != nil {
			return err
		}

		cmd := fmt.Sprintf("Set-Service -Name %s -Description %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(description))

		changes["description"] = description

		tflog.Debug(ctx, "Updating description")
		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError("update", name, "description", cmd, stdout, stderr, err)
		}
	}

	// Update start_type
	if d.HasChange("start_type") {
		startType := d.Get("start_type").(string)
		if err := utils.ValidateField(startType, name, "start_type"); err != nil {
			return err
		}

		cmd := fmt.Sprintf("Set-Service -Name %s -StartupType %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(startType))

		changes["start_type"] = startType

		tflog.Debug(ctx, "Updating start_type", map[string]any{
			"new_value": startType,
		})
		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError("update", name, "start_type", cmd, stdout, stderr, err)
		}
	}

	// Update service state
	if d.HasChange("state") {
		desiredState := d.Get("state").(string)
		changes["state"] = desiredState

		if err := setServiceState(ctx, sshClient, name, desiredState, timeout); err != nil {
			return err
		}
	}

	// Update start_name and credential
	if d.HasChange("start_name") || d.HasChange("credential") {
		startName := d.Get("start_name").(string)
		credential := d.Get("credential").(string)

		if startName != "" && credential != "" {
			if err := utils.ValidateField(startName, name, "start_name"); err != nil {
				return err
			}

			cmd := fmt.Sprintf("$cred = New-Object System.Management.Automation.PSCredential(%s, (ConvertTo-SecureString %s -AsPlainText -Force)); Set-Service -Name %s -Credential $cred -ErrorAction Stop",
				powershell.QuotePowerShellString(startName),
				powershell.QuotePowerShellString(credential),
				powershell.QuotePowerShellString(name))

			changes["start_name"] = startName
			changes["credential"] = "***REDACTED***"

			tflog.Info(ctx, "Updating service credentials", map[string]any{
				"start_name": startName,
			})
			stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return utils.HandleCommandError("update", name, "credential", "Set-Service (credentials hidden)", stdout, stderr, err)
			}
		}
	}

	if len(changes) > 0 {
		tflog.Info(ctx, "Service updated successfully", map[string]any{
			"service_name": name,
			"changes":      changes,
		})
	} else {
		tflog.Debug(ctx, "No changes detected for service", map[string]any{
			"service_name": name,
		})
	}

	return resourceWindowsServiceRead(d, m)
}

func resourceWindowsServiceDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Deleting service", map[string]any{
		"service_name": name,
	})

	// Validate service name
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	// Stop service if running
	stopCmd := fmt.Sprintf("Stop-Service -Name %s -Force -ErrorAction SilentlyContinue",
		powershell.QuotePowerShellString(name))

	tflog.Debug(ctx, "Stopping service if running", map[string]any{
		"service_name": name,
	})

	// Execute stop command (ignore errors as service might already be stopped)
	sshClient.ExecuteCommand(stopCmd, timeout)

	// Give service time to stop gracefully
	time.Sleep(2 * time.Second)

	// Remove service (Remove-Service available since PowerShell 6.0, otherwise use sc.exe)
	cmd := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
    Remove-Service -Name %s -Force -ErrorAction Stop
} else {
    sc.exe delete %s
    if ($LASTEXITCODE -ne 0) { 
        throw "Failed to delete service with exit code: $LASTEXITCODE" 
    }
}
`, powershell.QuotePowerShellString(name), powershell.QuotePowerShellString(name))

	tflog.Info(ctx, "Removing service", map[string]any{
		"service_name": name,
	})

	stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
	if err != nil {
		return utils.HandleCommandError("delete", name, "state", cmd, stdout, stderr, err)
	}

	d.SetId("")
	tflog.Info(ctx, "Service deleted successfully", map[string]any{
		"service_name": name,
	})

	return nil
}
