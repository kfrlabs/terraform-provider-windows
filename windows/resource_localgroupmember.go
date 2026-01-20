package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/ssh"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

func ResourceWindowsLocalGroupMember() *schema.Resource {
	return &schema.Resource{
		Create: resourceWindowsLocalGroupMemberCreate,
		Read:   resourceWindowsLocalGroupMemberRead,
		Delete: resourceWindowsLocalGroupMemberDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"group": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the local group (e.g., 'Administrators', 'Users').",
			},
			"member": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the member to add to the group (e.g., 'AppUser', 'DOMAIN\\User').",
			},
			"command_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     300,
				ForceNew:    true,
				Description: "Timeout in seconds for PowerShell commands.",
			},
		},
	}
}

// checkMembershipExists vérifie si un membre appartient à un groupe
func checkMembershipExists(ctx context.Context, sshClient *ssh.Client, group, member string, timeout int) (bool, error) {
	// Valider les paramètres pour sécurité
	resourceID := fmt.Sprintf("%s/%s", group, member)
	if err := utils.ValidateField(group, resourceID, "group"); err != nil {
		return false, err
	}
	if err := utils.ValidateField(member, resourceID, "member"); err != nil {
		return false, err
	}

	tflog.Debug(ctx, fmt.Sprintf("Checking if member '%s' is in group '%s'", member, group))

	// Commande PowerShell pour vérifier l'appartenance
	// Note: Get-LocalGroupMember retourne les membres avec le format "COMPUTERNAME\Username"
	command := fmt.Sprintf(`
$group = %s
$member = %s
$found = $false

try {
    $members = Get-LocalGroupMember -Group $group -ErrorAction Stop
    foreach ($m in $members) {
        # Comparer en ignorant le préfixe COMPUTERNAME\ si présent
        $memberName = if ($m.Name -match '\\') { 
            ($m.Name -split '\\')[1] 
        } else { 
            $m.Name 
        }
        
        $searchName = if ($member -match '\\') { 
            ($member -split '\\')[1] 
        } else { 
            $member 
        }
        
        if ($memberName -eq $searchName) {
            $found = $true
            break
        }
    }
} catch {
    # Si le groupe n'existe pas ou erreur, retourner false
}

if ($found) { 'true' } else { 'false' }
`,
		powershell.QuotePowerShellString(group),
		powershell.QuotePowerShellString(member),
	)

	stdout, _, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return false, fmt.Errorf("failed to check membership: %w", err)
	}

	exists := strings.TrimSpace(stdout) == "true"
	return exists, nil
}

func resourceWindowsLocalGroupMemberCreate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	group := d.Get("group").(string)
	member := d.Get("member").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s/%s", group, member)

	tflog.Info(ctx, fmt.Sprintf("[CREATE] Adding member '%s' to group '%s'", member, group))

	// Valider les paramètres pour sécurité
	if err := utils.ValidateField(group, resourceID, "group"); err != nil {
		return err
	}
	if err := utils.ValidateField(member, resourceID, "member"); err != nil {
		return err
	}

	// Vérifier si le membre est déjà dans le groupe
	exists, err := checkMembershipExists(ctx, sshClient, group, member, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", resourceID, "state", err)
	}

	if exists {
		tflog.Info(ctx, fmt.Sprintf("[CREATE] Member '%s' is already in group '%s', adopting", member, group))
		d.SetId(resourceID)
		return resourceWindowsLocalGroupMemberRead(d, m)
	}

	// Ajouter le membre au groupe
	command := fmt.Sprintf("Add-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
		powershell.QuotePowerShellString(group),
		powershell.QuotePowerShellString(member))

	tflog.Debug(ctx, fmt.Sprintf("[CREATE] Executing: %s", command))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"create",
			resourceID,
			"membership",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId(resourceID)
	tflog.Info(ctx, fmt.Sprintf("[CREATE] Member added successfully: %s", resourceID))

	return resourceWindowsLocalGroupMemberRead(d, m)
}

func resourceWindowsLocalGroupMemberRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	// Parser l'ID au format "group/member"
	parts := strings.SplitN(d.Id(), "/", 2)
	if len(parts) != 2 {
		return utils.HandleResourceError("read", d.Id(), "id",
			fmt.Errorf("invalid ID format, expected 'group/member', got '%s'", d.Id()))
	}

	group := parts[0]
	member := parts[1]

	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	tflog.Debug(ctx, fmt.Sprintf("[READ] Checking membership: %s", d.Id()))

	exists, err := checkMembershipExists(ctx, sshClient, group, member, timeout)
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("[READ] Failed to read membership %s: %v", d.Id(), err))
		d.SetId("")
		return nil
	}

	if !exists {
		tflog.Debug(ctx, fmt.Sprintf("[READ] Membership %s does not exist, removing from state", d.Id()))
		d.SetId("")
		return nil
	}

	// Mettre à jour le state
	if err := d.Set("group", group); err != nil {
		return utils.HandleResourceError("read", d.Id(), "group", err)
	}
	if err := d.Set("member", member); err != nil {
		return utils.HandleResourceError("read", d.Id(), "member", err)
	}

	tflog.Debug(ctx, fmt.Sprintf("[READ] Membership verified: %s", d.Id()))
	return nil
}

func resourceWindowsLocalGroupMemberDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()
	sshClient := m.(*ssh.Client)

	group := d.Get("group").(string)
	member := d.Get("member").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := d.Id()

	tflog.Info(ctx, fmt.Sprintf("[DELETE] Removing member '%s' from group '%s'", member, group))

	// Valider les paramètres pour sécurité
	if err := utils.ValidateField(group, resourceID, "group"); err != nil {
		return err
	}
	if err := utils.ValidateField(member, resourceID, "member"); err != nil {
		return err
	}

	// Retirer le membre du groupe
	command := fmt.Sprintf("Remove-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
		powershell.QuotePowerShellString(group),
		powershell.QuotePowerShellString(member))

	tflog.Debug(ctx, fmt.Sprintf("[DELETE] Executing: %s", command))

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"delete",
			resourceID,
			"membership",
			command,
			stdout,
			stderr,
			err,
		)
	}

	d.SetId("")
	tflog.Info(ctx, fmt.Sprintf("[DELETE] Member removed successfully: %s", resourceID))
	return nil
}
