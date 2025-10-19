package resources

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
)

type serviceInfo struct {
	Exists         bool   `json:"Exists"`
	Name           string `json:"Name"`
	DisplayName    string `json:"DisplayName"`
	Description    string `json:"Description"`
	Status         string `json:"Status"`
	StartType      string `json:"StartType"`
	StartName      string `json:"StartName"`
	BinaryPathName string `json:"BinaryPathName"`
	ServiceType    string `json:"ServiceType"`
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
				Description: "The display name of the service shown in Services application.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A description of what the service does.",
			},
			"binary_path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The full path to the service executable (e.g., 'C:\\Program Files\\MyApp\\service.exe'). Cannot be changed after creation.",
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
			"command_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     300,
				Description: "Timeout in seconds for PowerShell commands.",
			},
		},
	}
}

func resourceWindowsServiceCreate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Verify service doesn't already exist
	checkCmd := fmt.Sprintf("Get-Service -Name '%s' -ErrorAction SilentlyContinue | Select-Object -First 1", name)
	stdout, _, _ := sshClient.ExecuteCommand(checkCmd, timeout)
	if stdout != "" {
		return fmt.Errorf("service '%s' already exists", name)
	}

	// Build New-Service command
	command := fmt.Sprintf("New-Service -Name '%s'", name)

	if displayName, ok := d.GetOk("display_name"); ok {
		command += fmt.Sprintf(" -DisplayName '%s'", displayName.(string))
	}

	if binaryPath, ok := d.GetOk("binary_path"); ok {
		command += fmt.Sprintf(" -BinaryPathName '%s'", binaryPath.(string))
	} else {
		return fmt.Errorf("binary_path is required for creating a new service")
	}

	if startName, ok := d.GetOk("start_name"); ok {
		command += fmt.Sprintf(" -StartupType '%s'", d.Get("start_type").(string))
		command += fmt.Sprintf(" -Credential (New-Object System.Management.Automation.PSCredential('%s', (ConvertTo-SecureString '%s' -AsPlainText -Force)))", startName.(string), d.Get("credential").(string))
	} else {
		command += fmt.Sprintf(" -StartupType '%s'", d.Get("start_type").(string))
	}

	if loadOrderGroup, ok := d.GetOk("load_order_group"); ok {
		command += fmt.Sprintf(" -LoadOrderGroup '%s'", loadOrderGroup.(string))
	}

	command += " -ErrorAction Stop"

	_, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	// Set description if provided
	if description, ok := d.GetOk("description"); ok {
		descCmd := fmt.Sprintf("Set-Service -Name '%s' -Description '%s' -ErrorAction Stop", name, description.(string))
		_, _, err := sshClient.ExecuteCommand(descCmd, timeout)
		if err != nil {
			return fmt.Errorf("failed to set service description: %w", err)
		}
	}

	// Set desired state
	if desiredState, ok := d.GetOk("state"); ok && desiredState.(string) == "Running" {
		startCmd := fmt.Sprintf("Start-Service -Name '%s' -ErrorAction Stop", name)
		_, _, err := sshClient.ExecuteCommand(startCmd, timeout)
		if err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}
	}

	d.SetId(name)
	return resourceWindowsServiceRead(d, m)
}

func resourceWindowsServiceRead(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	name := d.Id()
	timeout := d.Get("command_timeout").(int)

	// PowerShell command to get service info as JSON
	command := fmt.Sprintf(`
$service = Get-Service -Name '%s' -ErrorAction SilentlyContinue
if ($service) {
    $info = Get-WmiObject Win32_Service -Filter "Name='%s'" -ErrorAction SilentlyContinue
    @{
        Exists = $true
        Name = $service.Name
        DisplayName = $service.DisplayName
        Description = $info.Description
        Status = $service.Status
        StartType = $service.StartType
        StartName = $info.StartName
        BinaryPathName = $info.PathName
        ServiceType = $info.ServiceType
    } | ConvertTo-Json
} else {
    @{ Exists = $false } | ConvertTo-Json
}
`, name, name)

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return fmt.Errorf("failed to read service: %w", err)
	}

	var info serviceInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return fmt.Errorf("failed to parse service info: %w; output: %s", err, stdout)
	}

	if !info.Exists {
		d.SetId("")
		return nil
	}

	d.Set("name", info.Name)
	d.Set("display_name", info.DisplayName)
	d.Set("description", info.Description)
	d.Set("state", info.Status)
	d.Set("start_type", info.StartType)
	d.Set("start_name", info.StartName)
	d.Set("binary_path", info.BinaryPathName)
	d.Set("service_type", info.ServiceType)

	return nil
}

func resourceWindowsServiceUpdate(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Update display name
	if d.HasChange("display_name") {
		displayName := d.Get("display_name").(string)
		cmd := fmt.Sprintf("Set-Service -Name '%s' -DisplayName '%s' -ErrorAction Stop", name, displayName)
		_, _, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return fmt.Errorf("failed to update display name: %w", err)
		}
	}

	// Update description
	if d.HasChange("description") {
		description := d.Get("description").(string)
		cmd := fmt.Sprintf("Set-Service -Name '%s' -Description '%s' -ErrorAction Stop", name, description)
		_, _, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return fmt.Errorf("failed to update description: %w", err)
		}
	}

	// Update start type
	if d.HasChange("start_type") {
		startType := d.Get("start_type").(string)
		cmd := fmt.Sprintf("Set-Service -Name '%s' -StartupType '%s' -ErrorAction Stop", name, startType)
		_, _, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return fmt.Errorf("failed to update start type: %w", err)
		}
	}

	// Update service state
	if d.HasChange("state") {
		desiredState := d.Get("state").(string)
		if desiredState == "Running" {
			cmd := fmt.Sprintf("Start-Service -Name '%s' -ErrorAction Stop", name)
			_, _, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to start service: %w", err)
			}
		} else if desiredState == "Stopped" {
			cmd := fmt.Sprintf("Stop-Service -Name '%s' -Force -ErrorAction Stop", name)
			_, _, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to stop service: %w", err)
			}
		}
	}

	// Update start name and credential
	if d.HasChange("start_name") || d.HasChange("credential") {
		startName := d.Get("start_name").(string)
		credential := d.Get("credential").(string)

		if startName != "" && credential != "" {
			cmd := fmt.Sprintf("$cred = New-Object System.Management.Automation.PSCredential('%s', (ConvertTo-SecureString '%s' -AsPlainText -Force)); Set-Service -Name '%s' -Credential $cred -ErrorAction Stop", startName, credential, name)
			_, _, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return fmt.Errorf("failed to update service credential: %w", err)
			}
		}
	}

	return resourceWindowsServiceRead(d, m)
}

func resourceWindowsServiceDelete(d *schema.ResourceData, m interface{}) error {
	sshClient := m.(*ssh.Client)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	// Stop service if running
	stopCmd := fmt.Sprintf("Stop-Service -Name '%s' -Force -ErrorAction SilentlyContinue", name)
	sshClient.ExecuteCommand(stopCmd, timeout)

	// Delete service
	cmd := fmt.Sprintf("Remove-Service -Name '%s' -Force -ErrorAction Stop", name)
	_, _, err := sshClient.ExecuteCommand(cmd, timeout)
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	d.SetId("")
	return nil
}
