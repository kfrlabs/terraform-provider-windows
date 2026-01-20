package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

// LocalGroupInfo représente les informations d'un groupe local
type LocalGroupInfo struct {
	Exists      bool   `json:"Exists"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
}

func ResourceWindowsLocalGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsLocalGroupCreate,
		Read:   resourceWindowsLocalGroupRead,
		Update: resourceWindowsLocalGroupUpdate,
		Delete: resourceWindowsLocalGroupDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the local group. Cannot be changed after creation.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A description for the local group.",
			},
			"allow_existing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If true, adopt existing group instead of failing. If false, fail if group already exists.",
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

// checkLocalGroupExists vérifie si un groupe local existe et retourne ses informations
func checkLocalGroupExists(ctx context.Context, sshClient *ssh.Client, name string, timeout int) (*LocalGroupInfo, error) {
	// Valider le nom du groupe pour sécurité
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return nil, err
	}

	tflog.Debug(ctx, fmt.Sprintf("Checking if local group exists: %s", name))

	// Commande PowerShell qui retourne du JSON structuré
	command := fmt.Sprintf(`
$group = Get-LocalGroup -Name %s -ErrorAction SilentlyContinue
if ($group) {
    @{
        'Exists' = $true
        'Name' = $group.Name
        'Description' = $group.Description
    } | ConvertTo-Json -Compress
} else {
    @{ 'Exists' = $false } | ConvertTo-Json -Compress
}
`,
		powershell.QuotePowerShellString(name),
	)

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to check group: %w", err)
	}

	var info LocalGroupInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, fmt.Errorf("failed to parse group info: %w; output: %s", err, stdout)
	}

	return &info, nil
}

func resourceWindowsLocalGroupCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Starting local group creation for: %s", name))

	// Valider le nom du groupe pour sécurité
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	// Vérifier si le groupe existe déjà
	info, err := checkLocalGroupExists(ctx, sshClient, name, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", name, "state", err)
	}

	if info.Exists {
		if allowExisting {
			tflog.Info(ctx, fmt.Sprintf("[CREATE] Group %s already exists, adopting it (allow_existing=true)", name))
			d.SetId(name)
			return resourceWindowsLocalGroupRead(d, m)
		} else {
			resourceName := "localgroup"
			return utils.HandleResourceError(
				"create",
				name,
				"state",
				fmt.Errorf("local group already exists. "+
					"To manage this existing group, either:\n"+
					"  1. Import it: terraform import windows_localgroup.%s '%s'\n"+
					"  2. Set allow_existing = true in your configuration\n"+
					"  3. Remove it first (WARNING): Remove-LocalGroup -Name '%s' -Force",
					resourceName, name, name),
			)
		}
	}

	// Construire la commande de manière sécurisée
	command := fmt.Sprintf("New-LocalGroup -Name %s",
		powershell.QuotePowerShellString(name))

	// Ajouter la description si fournie
	if description, ok, err := utils.ValidateSchemaOptionalString(d, "description", name); err != nil {
		return err
	} else if ok {
		command += fmt.Sprintf(" -Description %s", powershell.QuotePowerShellString(description))
	}

	command += " -ErrorAction Stop"

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Creating local group: %s", name))
	tflog.Debug(ctx, fmt.Sprintf("[CREATE] Executing: %s", command))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"create",
			name,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId(name)
	tflog.Info(ctx, fmt.Sprintf("[CREATE] Local group created successfully with ID: %s", name))

	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupRead(d *schema.ResourceData, m interface{}) error {
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

	tflog.Debug(ctx, fmt.Sprintf("[READ] Reading local group: %s", name))

	info, err := checkLocalGroupExists(ctx, sshClient, name, timeout)
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("[READ] Failed to read local group %s: %v", name, err))
		d.SetId("")
		return nil
	}

	if !info.Exists {
		tflog.Debug(ctx, fmt.Sprintf("[READ] Local group %s does not exist, removing from state", name))
		d.SetId("")
		return nil
	}

	// Mettre à jour le state
	if err := d.Set("name", info.Name); err != nil {
		return utils.HandleResourceError("read", name, "name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", name, "description", err)
	}

	tflog.Debug(ctx, fmt.Sprintf("[READ] Local group read successfully: %s", name))
	return nil
}

func resourceWindowsLocalGroupUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[UPDATE] Updating local group: %s", name))

	// Valider le nom pour sécurité
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	// Mettre à jour la description
	if d.HasChange("description") {
		description := d.Get("description").(string)
		if err := utils.ValidateField(description, name, "description"); err != nil {
			return err
		}

		command := fmt.Sprintf("Set-LocalGroup -Name %s -Description %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(description))

		tflog.Debug(ctx, "[UPDATE] Updating description")
		tflog.Debug(ctx, fmt.Sprintf("[UPDATE] Executing: %s", command))

		stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return utils.HandleCommandError(
				"update",
				name,
				"description",
				command,
				stdout,
				stderr,
				err,
			)
		}
	}

	tflog.Info(ctx, fmt.Sprintf("[UPDATE] Local group updated successfully: %s", name))
	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, fmt.Sprintf("[DELETE] Deleting local group: %s", name))

	// Valider le nom pour sécurité
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	command := fmt.Sprintf("Remove-LocalGroup -Name %s -ErrorAction Stop",
		powershell.QuotePowerShellString(name))

	tflog.Debug(ctx, fmt.Sprintf("[DELETE] Executing: %s", command))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"delete",
			name,
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId("")
	tflog.Info(ctx, fmt.Sprintf("[DELETE] Local group deleted successfully: %s", name))
	return nil
}