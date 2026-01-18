package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

type serviceInfo struct {
	Exists         bool        `json:"Exists"`
	Name           string      `json:"Name"`
	DisplayName    string      `json:"DisplayName"`
	Description    string      `json:"Description"`
	Status         interface{} `json:"Status"`    // Peut être string ou int
	StartType      interface{} `json:"StartType"` // Peut être string ou int
	StartName      string      `json:"StartName"`
	BinaryPathName string      `json:"BinaryPathName"`
	ServiceType    string      `json:"ServiceType"`
}

// convertServiceStatus convertit le code Status WMI en string
func convertServiceStatus(status interface{}) string {
	switch v := status.(type) {
	case string:
		return v
	case float64:
		// Codes WMI Win32_Service Status
		switch int(v) {
		case 1:
			return "Stopped"
		case 2:
			return "Start Pending"
		case 3:
			return "Stop Pending"
		case 4:
			return "Running"
		case 5:
			return "Continue Pending"
		case 6:
			return "Pause Pending"
		case 7:
			return "Paused"
		default:
			return "Unknown"
		}
	default:
		return "Unknown"
	}
}

// convertStartType convertit le code StartType WMI en string
func convertStartType(startType interface{}) string {
	switch v := startType.(type) {
	case string:
		return v
	case float64:
		// Codes WMI Win32_Service StartMode
		switch int(v) {
		case 0:
			return "Boot"
		case 1:
			return "System"
		case 2:
			return "Automatic"
		case 3:
			return "Manual"
		case 4:
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

// checkServiceExists vérifie si un service existe et retourne ses informations
func checkServiceExists(ctx context.Context, sshClient *ssh.Client, name string, timeout int) (*serviceInfo, error) {
	// Valider le nom du service pour sécurité
	if err := powershell.ValidatePowerShellArgument(name); err != nil {
		return nil, err
	}

	tflog.Debug(ctx, fmt.Sprintf("Checking if service exists: %s", name))

	// PowerShell command to get service info as JSON avec conversion des codes
	command := fmt.Sprintf(`
$service = Get-Service -Name %s -ErrorAction SilentlyContinue
if ($service) {
    $info = Get-WmiObject Win32_Service -Filter "Name='%s'" -ErrorAction SilentlyContinue
    
    # Convertir Status code en string
    $statusString = switch ($service.Status.ToString()) {
        'Stopped' { 'Stopped' }
        'Running' { 'Running' }
        'Paused' { 'Paused' }
        default { $service.Status.ToString() }
    }
    
    # Convertir StartType code en string
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

	stdout, _, err := sshClient.ExecuteCommand(command, timeout) // ← stderr remplacé par _
	if err != nil {
		return nil, fmt.Errorf("failed to check service: %w", err)
	}

	var info serviceInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse service info: %w; output: %s", err, stdout)
	}

	return &info, nil
}

func resourceWindowsServiceCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Starting service creation for: %s", name))

	// Valider le nom du service pour sécurité
	if err := powershell.ValidatePowerShellArgument(name); err != nil {
		return utils.HandleResourceError("validate", name, "name", err)
	}

	// Vérifier si le service existe déjà
	info, err := checkServiceExists(ctx, sshClient, name, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", name, "state", err)
	}

	if info.Exists {
		if allowExisting {
			tflog.Info(ctx, fmt.Sprintf("[CREATE] Service %s already exists, adopting it (allow_existing=true)", name))
			d.SetId(name)
			return resourceWindowsServiceRead(d, m)
		} else {
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
	}

	// Vérifier que binary_path est fourni pour créer un nouveau service
	binaryPath, ok := d.GetOk("binary_path")
	if !ok {
		return utils.HandleResourceError("validate", name, "binary_path",
			fmt.Errorf("binary_path is required for creating a new service"))
	}

	// Valider binary_path pour sécurité
	if err := powershell.ValidatePowerShellArgument(binaryPath.(string)); err != nil {
		return utils.HandleResourceError("validate", name, "binary_path", err)
	}

	// Construire la commande New-Service de manière sécurisée
	command := fmt.Sprintf("New-Service -Name %s -BinaryPathName %s",
		powershell.QuotePowerShellString(name),
		powershell.QuotePowerShellString(binaryPath.(string)))

	if displayName, ok := d.GetOk("display_name"); ok {
		if err := powershell.ValidatePowerShellArgument(displayName.(string)); err != nil {
			return utils.HandleResourceError("validate", name, "display_name", err)
		}
		command += fmt.Sprintf(" -DisplayName %s", powershell.QuotePowerShellString(displayName.(string)))
	}

	startType := d.Get("start_type").(string)
	if err := powershell.ValidatePowerShellArgument(startType); err != nil {
		return utils.HandleResourceError("validate", name, "start_type", err)
	}
	command += fmt.Sprintf(" -StartupType %s", powershell.QuotePowerShellString(startType))

	if startName, ok := d.GetOk("start_name"); ok {
		if err := powershell.ValidatePowerShellArgument(startName.(string)); err != nil {
			return utils.HandleResourceError("validate", name, "start_name", err)
		}

		credential, hasCredential := d.GetOk("credential")
		if hasCredential {
			// Créer un credential PowerShell sécurisé
			command += fmt.Sprintf(" -Credential (New-Object System.Management.Automation.PSCredential(%s, (ConvertTo-SecureString %s -AsPlainText -Force)))",
				powershell.QuotePowerShellString(startName.(string)),
				powershell.QuotePowerShellString(credential.(string)))
		}
	}

	if loadOrderGroup, ok := d.GetOk("load_order_group"); ok {
		if err := powershell.ValidatePowerShellArgument(loadOrderGroup.(string)); err != nil {
			return utils.HandleResourceError("validate", name, "load_order_group", err)
		}
		command += fmt.Sprintf(" -LoadOrderGroup %s", powershell.QuotePowerShellString(loadOrderGroup.(string)))
	}

	command += " -ErrorAction Stop"

	tflog.Info(ctx, "[CREATE] Creating service with command (credentials hidden)")

	// Masquer les credentials dans les logs
	logCommand := command
	if cred, ok := d.GetOk("credential"); ok {
		logCommand = strings.ReplaceAll(command, cred.(string), "***REDACTED***")
	}
	tflog.Debug(ctx, fmt.Sprintf("[CREATE] Executing: %s", logCommand))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"create",
			name,
			"state",
			"New-Service (credentials hidden)",
			stdout,
			stderr,
			err,
		)
	}

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Service created successfully: %s", name))

	// Définir la description si fournie
	if description, ok := d.GetOk("description"); ok {
		if err := powershell.ValidatePowerShellArgument(description.(string)); err != nil {
			return utils.HandleResourceError("validate", name, "description", err)
		}

		descCmd := fmt.Sprintf("Set-Service -Name %s -Description %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(description.(string)))

		tflog.Debug(ctx, "[CREATE] Setting service description")
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
	}

	// Définir l'état désiré
	desiredState := d.Get("state").(string)
	if desiredState == "Running" {
		startCmd := fmt.Sprintf("Start-Service -Name %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name))

		tflog.Info(ctx, fmt.Sprintf("[CREATE] Starting service: %s", name))
		stdout, stderr, err := sshClient.ExecuteCommand(startCmd, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"create",
				name,
				"state",
				startCmd,
				stdout,
				stderr,
				err,
			)
		}
		tflog.Info(ctx, fmt.Sprintf("[CREATE] Service started successfully: %s", name))
	}

	d.SetId(name)
	tflog.Info(ctx, fmt.Sprintf("[CREATE] Service resource created successfully with ID: %s", name))

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

	tflog.Debug(ctx, fmt.Sprintf("[READ] Reading service: %s", name))

	info, err := checkServiceExists(ctx, sshClient, name, timeout)
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("[READ] Failed to read service %s: %v", name, err))
		d.SetId("")
		return nil
	}

	if !info.Exists {
		tflog.Debug(ctx, fmt.Sprintf("[READ] Service %s does not exist, removing from state", name))
		d.SetId("")
		return nil
	}

	// Convertir Status et StartType si nécessaire (fallback au cas où la conversion PowerShell échoue)
	status := convertServiceStatus(info.Status)
	startType := convertStartType(info.StartType)

	// Mettre à jour le state
	if err := d.Set("name", info.Name); err != nil {
		return utils.HandleResourceError("read", name, "name", err)
	}
	if err := d.Set("display_name", info.DisplayName); err != nil {
		return utils.HandleResourceError("read", name, "display_name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", name, "description", err)
	}
	if err := d.Set("state", status); err != nil {
		return utils.HandleResourceError("read", name, "state", err)
	}
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

	tflog.Debug(ctx, fmt.Sprintf("[READ] Service read successfully: %s (status=%s, start_type=%s)", name, status, startType))
	return nil
}

func resourceWindowsServiceUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[UPDATE] Updating service: %s", name))

	// Valider le nom pour sécurité
	if err := powershell.ValidatePowerShellArgument(name); err != nil {
		return utils.HandleResourceError("validate", name, "name", err)
	}

	// Mettre à jour display_name
	if d.HasChange("display_name") {
		displayName := d.Get("display_name").(string)
		if err := powershell.ValidatePowerShellArgument(displayName); err != nil {
			return utils.HandleResourceError("validate", name, "display_name", err)
		}

		cmd := fmt.Sprintf("Set-Service -Name %s -DisplayName %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(displayName))

		tflog.Debug(ctx, "[UPDATE] Updating display_name")
		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"update",
				name,
				"display_name",
				cmd,
				stdout,
				stderr,
				err,
			)
		}
	}

	// Mettre à jour description
	if d.HasChange("description") {
		description := d.Get("description").(string)
		if err := powershell.ValidatePowerShellArgument(description); err != nil {
			return utils.HandleResourceError("validate", name, "description", err)
		}

		cmd := fmt.Sprintf("Set-Service -Name %s -Description %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(description))

		tflog.Debug(ctx, "[UPDATE] Updating description")
		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"update",
				name,
				"description",
				cmd,
				stdout,
				stderr,
				err,
			)
		}
	}

	// Mettre à jour start_type
	if d.HasChange("start_type") {
		startType := d.Get("start_type").(string)
		if err := powershell.ValidatePowerShellArgument(startType); err != nil {
			return utils.HandleResourceError("validate", name, "start_type", err)
		}

		cmd := fmt.Sprintf("Set-Service -Name %s -StartupType %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(startType))

		tflog.Debug(ctx, fmt.Sprintf("[UPDATE] Updating start_type to: %s", startType))
		stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"update",
				name,
				"start_type",
				cmd,
				stdout,
				stderr,
				err,
			)
		}
	}

	// Mettre à jour l'état du service
	if d.HasChange("state") {
		desiredState := d.Get("state").(string)

		if desiredState == "Running" {
			cmd := fmt.Sprintf("Start-Service -Name %s -ErrorAction Stop",
				powershell.QuotePowerShellString(name))

			tflog.Info(ctx, fmt.Sprintf("[UPDATE] Starting service: %s", name))
			stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return utils.HandleCommandError(
					"update",
					name,
					"state",
					cmd,
					stdout,
					stderr,
					err,
				)
			}
		} else if desiredState == "Stopped" {
			cmd := fmt.Sprintf("Stop-Service -Name %s -Force -ErrorAction Stop",
				powershell.QuotePowerShellString(name))

			tflog.Info(ctx, fmt.Sprintf("[UPDATE] Stopping service: %s", name))
			stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return utils.HandleCommandError(
					"update",
					name,
					"state",
					cmd,
					stdout,
					stderr,
					err,
				)
			}
		}
	}

	// Mettre à jour start_name et credential
	if d.HasChange("start_name") || d.HasChange("credential") {
		startName := d.Get("start_name").(string)
		credential := d.Get("credential").(string)

		if startName != "" && credential != "" {
			if err := powershell.ValidatePowerShellArgument(startName); err != nil {
				return utils.HandleResourceError("validate", name, "start_name", err)
			}

			cmd := fmt.Sprintf("$cred = New-Object System.Management.Automation.PSCredential(%s, (ConvertTo-SecureString %s -AsPlainText -Force)); Set-Service -Name %s -Credential $cred -ErrorAction Stop",
				powershell.QuotePowerShellString(startName),
				powershell.QuotePowerShellString(credential),
				powershell.QuotePowerShellString(name))

			tflog.Info(ctx, fmt.Sprintf("[UPDATE] Updating service credentials for: %s", startName))
			stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
			if err != nil {
				return utils.HandleCommandError(
					"update",
					name,
					"credential",
					"Set-Service (credentials hidden)",
					stdout,
					stderr,
					err,
				)
			}
		}
	}

	tflog.Info(ctx, fmt.Sprintf("[UPDATE] Service updated successfully: %s", name))
	return resourceWindowsServiceRead(d, m)
}

func resourceWindowsServiceDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DELETE] Deleting service: %s", name))

	// Valider le nom pour sécurité
	if err := powershell.ValidatePowerShellArgument(name); err != nil {
		return utils.HandleResourceError("validate", name, "name", err)
	}

	// Arrêter le service s'il est en cours d'exécution
	stopCmd := fmt.Sprintf("Stop-Service -Name %s -Force -ErrorAction SilentlyContinue",
		powershell.QuotePowerShellString(name))

	tflog.Debug(ctx, fmt.Sprintf("[DELETE] Stopping service if running: %s", name))
	sshClient.ExecuteCommand(stopCmd, timeout)

	// Supprimer le service (Remove-Service disponible depuis PowerShell 6.0, sinon utiliser sc.exe)
	cmd := fmt.Sprintf(`
if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
    Remove-Service -Name %s -Force -ErrorAction Stop
} else {
    sc.exe delete %s
    if ($LASTEXITCODE -ne 0) { throw "Failed to delete service" }
}
`, powershell.QuotePowerShellString(name), powershell.QuotePowerShellString(name))

	tflog.Info(ctx, fmt.Sprintf("[DELETE] Removing service: %s", name))
	stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"delete",
			name,
			"state",
			cmd,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId("")
	tflog.Info(ctx, fmt.Sprintf("[DELETE] Service deleted successfully: %s", name))
	return nil
}
