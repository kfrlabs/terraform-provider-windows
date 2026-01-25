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

// checkMembershipExists checks if a member belongs to a group
func checkMembershipExists(ctx context.Context, sshClient *ssh.Client, group, member string, timeout int) (bool, error) {
	// Validate parameters for security
	resourceID := fmt.Sprintf("%s/%s", group, member)
	if err := utils.ValidateField(group, resourceID, "group"); err != nil {
		return false, err
	}
	if err := utils.ValidateField(member, resourceID, "member"); err != nil {
		return false, err
	}

	tflog.Debug(ctx, "Checking group membership",
		map[string]any{
			"group":  group,
			"member": member,
		})

	// PowerShell command to check membership
	// Note: Get-LocalGroupMember returns members with format "COMPUTERNAME\Username"
	command := fmt.Sprintf(`
$group = %s
$member = %s
$found = $false

try {
    $members = Get-LocalGroupMember -Group $group -ErrorAction Stop
    foreach ($m in $members) {
        # Compare ignoring COMPUTERNAME\ prefix if present
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
    # If group doesn't exist or error, return false
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

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	group := d.Get("group").(string)
	member := d.Get("member").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s/%s", group, member)

	tflog.Info(ctx, "Adding member to group",
		map[string]any{
			"group":  group,
			"member": member,
		})

	// Validate parameters for security
	if err := utils.ValidateField(group, resourceID, "group"); err != nil {
		return err
	}
	if err := utils.ValidateField(member, resourceID, "member"); err != nil {
		return err
	}

	// Check if member is already in group
	exists, err := checkMembershipExists(ctx, sshClient, group, member, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", resourceID, "state", err)
	}

	if exists {
		tflog.Info(ctx, "Member already in group, adopting",
			map[string]any{
				"group":  group,
				"member": member,
			})
		d.SetId(resourceID)
		return resourceWindowsLocalGroupMemberRead(d, m)
	}

	// Add member to group
	command := fmt.Sprintf("Add-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
		powershell.QuotePowerShellString(group),
		powershell.QuotePowerShellString(member))

	tflog.Debug(ctx, "Executing member addition",
		map[string]any{
			"group":  group,
			"member": member,
		})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("create", resourceID, "membership", command, stdout, stderr, err)
	}

	d.SetId(resourceID)

	tflog.Info(ctx, "Member added successfully",
		map[string]any{
			"resource_id": resourceID,
		})

	// Log pool statistics if available
	if stats, ok := GetPoolStats(m); ok {
		tflog.Debug(ctx, "Pool statistics after create", map[string]any{"stats": stats.String()})
	}

	return resourceWindowsLocalGroupMemberRead(d, m)
}

func resourceWindowsLocalGroupMemberRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	// Parse ID format "group/member"
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

	tflog.Debug(ctx, "Reading group membership",
		map[string]any{
			"group":  group,
			"member": member,
		})

	exists, err := checkMembershipExists(ctx, sshClient, group, member, timeout)
	if err != nil {
		tflog.Warn(ctx, "Failed to read membership",
			map[string]any{
				"resource_id": d.Id(),
				"error":       err.Error(),
			})
		d.SetId("")
		return nil
	}

	if !exists {
		tflog.Debug(ctx, "Membership does not exist, removing from state",
			map[string]any{"resource_id": d.Id()})
		d.SetId("")
		return nil
	}

	// Update state
	if err := d.Set("group", group); err != nil {
		return utils.HandleResourceError("read", d.Id(), "group", err)
	}
	if err := d.Set("member", member); err != nil {
		return utils.HandleResourceError("read", d.Id(), "member", err)
	}

	tflog.Debug(ctx, "Membership verified",
		map[string]any{
			"group":  group,
			"member": member,
		})

	return nil
}

func resourceWindowsLocalGroupMemberDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	group := d.Get("group").(string)
	member := d.Get("member").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := d.Id()

	tflog.Info(ctx, "Removing member from group",
		map[string]any{
			"group":  group,
			"member": member,
		})

	// Validate parameters for security
	if err := utils.ValidateField(group, resourceID, "group"); err != nil {
		return err
	}
	if err := utils.ValidateField(member, resourceID, "member"); err != nil {
		return err
	}

	// Remove member from group
	command := fmt.Sprintf("Remove-LocalGroupMember -Group %s -Member %s -ErrorAction Stop",
		powershell.QuotePowerShellString(group),
		powershell.QuotePowerShellString(member))

	tflog.Debug(ctx, "Executing member removal",
		map[string]any{
			"group":  group,
			"member": member,
		})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("delete", resourceID, "membership", command, stdout, stderr, err)
	}

	d.SetId("")

	tflog.Info(ctx, "Member removed successfully",
		map[string]any{
			"group":  group,
			"member": member,
		})

	return nil
}

// ============================================================================
// BATCH OPERATIONS FOR MULTIPLE GROUP MEMBERSHIPS
// ============================================================================

// GroupMembershipConfig represents a group membership configuration
type GroupMembershipConfig struct {
	Group  string
	Member string
}

// AddMultipleGroupMembers adds multiple members to groups in a single batch
func AddMultipleGroupMembers(
	ctx context.Context,
	sshClient *ssh.Client,
	memberships []GroupMembershipConfig,
	timeout int,
) error {
	if len(memberships) == 0 {
		return nil
	}

	tflog.Info(ctx, "Adding multiple group members in batch",
		map[string]any{"count": len(memberships)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, m := range memberships {
		cmd := fmt.Sprintf("Add-LocalGroupMember -Group %s -Member %s -ErrorAction SilentlyContinue; $?",
			powershell.QuotePowerShellString(m.Group),
			powershell.QuotePowerShellString(m.Member))
		batch.Add(cmd)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch member additions",
		map[string]any{"membership_count": len(memberships)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_add",
			"multiple_memberships",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Check results
	failedMemberships := []string{}
	for i, m := range memberships {
		success, _ := result.GetStringResult(i)
		if success != "True" {
			failedMemberships = append(failedMemberships, fmt.Sprintf("%s/%s", m.Group, m.Member))
		}
	}

	if len(failedMemberships) > 0 {
		tflog.Warn(ctx, "Some memberships failed to add",
			map[string]any{
				"failed_count":       len(failedMemberships),
				"failed_memberships": failedMemberships,
			})
	}

	tflog.Info(ctx, "Successfully added group members in batch",
		map[string]any{
			"total":   len(memberships),
			"failed":  len(failedMemberships),
			"success": len(memberships) - len(failedMemberships),
		})

	return nil
}

// RemoveMultipleGroupMembers removes multiple members from groups in a single batch
func RemoveMultipleGroupMembers(
	ctx context.Context,
	sshClient *ssh.Client,
	memberships []GroupMembershipConfig,
	timeout int,
) error {
	if len(memberships) == 0 {
		return nil
	}

	tflog.Info(ctx, "Removing multiple group members in batch",
		map[string]any{"count": len(memberships)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, m := range memberships {
		cmd := fmt.Sprintf("Remove-LocalGroupMember -Group %s -Member %s -ErrorAction SilentlyContinue; $?",
			powershell.QuotePowerShellString(m.Group),
			powershell.QuotePowerShellString(m.Member))
		batch.Add(cmd)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch member removals",
		map[string]any{"membership_count": len(memberships)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_remove",
			"multiple_memberships",
			"state",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Check results
	failedMemberships := []string{}
	for i, m := range memberships {
		success, _ := result.GetStringResult(i)
		if success != "True" {
			failedMemberships = append(failedMemberships, fmt.Sprintf("%s/%s", m.Group, m.Member))
		}
	}

	if len(failedMemberships) > 0 {
		tflog.Warn(ctx, "Some memberships failed to remove",
			map[string]any{
				"failed_count":       len(failedMemberships),
				"failed_memberships": failedMemberships,
			})
	}

	tflog.Info(ctx, "Successfully removed group members in batch",
		map[string]any{
			"total":   len(memberships),
			"failed":  len(failedMemberships),
			"success": len(memberships) - len(failedMemberships),
		})

	return nil
}

// CheckMultipleMemberships checks multiple group memberships in a single batch
func CheckMultipleMemberships(
	ctx context.Context,
	sshClient *ssh.Client,
	memberships []GroupMembershipConfig,
	timeout int,
) (map[string]bool, error) {
	if len(memberships) == 0 {
		return make(map[string]bool), nil
	}

	tflog.Debug(ctx, "Checking multiple group memberships",
		map[string]any{"count": len(memberships)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, m := range memberships {
		command := fmt.Sprintf(`
$group = %s
$member = %s
$found = $false

try {
    $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
    foreach ($mbr in $members) {
        $memberName = if ($mbr.Name -match '\\') { 
            ($mbr.Name -split '\\')[1] 
        } else { 
            $mbr.Name 
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
} catch { }

if ($found) { 'true' } else { 'false' }`,
			powershell.QuotePowerShellString(m.Group),
			powershell.QuotePowerShellString(m.Member))

		batch.Add(command)
	}

	cmd := batch.Build()
	stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
	if err != nil {
		return nil, utils.HandleCommandError(
			"batch_check",
			"multiple_memberships",
			"state",
			cmd,
			stdout,
			stderr,
			err,
		)
	}

	// Parse results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return nil, fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Build result map
	membershipMap := make(map[string]bool)
	for i, m := range memberships {
		exists, _ := result.GetStringResult(i)
		resourceID := fmt.Sprintf("%s/%s", m.Group, m.Member)
		membershipMap[resourceID] = (strings.TrimSpace(exists) == "true")
	}

	tflog.Debug(ctx, "Membership status retrieved",
		map[string]any{"count": len(membershipMap)})

	return membershipMap, nil
}

// AddMembersToGroup adds multiple members to a single group (optimized for one group)
func AddMembersToGroup(
	ctx context.Context,
	sshClient *ssh.Client,
	group string,
	members []string,
	timeout int,
) error {
	if len(members) == 0 {
		return nil
	}

	tflog.Info(ctx, "Adding multiple members to single group",
		map[string]any{
			"group":        group,
			"member_count": len(members),
		})

	// Build batch command for adding all members to one group
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, member := range members {
		cmd := fmt.Sprintf("Add-LocalGroupMember -Group %s -Member %s -ErrorAction SilentlyContinue; $?",
			powershell.QuotePowerShellString(group),
			powershell.QuotePowerShellString(member))
		batch.Add(cmd)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch member additions to single group",
		map[string]any{
			"group":        group,
			"member_count": len(members),
		})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_add_to_group",
			group,
			"members",
			command,
			stdout,
			stderr,
			err,
		)
	}

	// Parse results
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputArray)
	if err != nil {
		return fmt.Errorf("failed to parse batch result: %w", err)
	}

	// Check results
	failedMembers := []string{}
	for i, member := range members {
		success, _ := result.GetStringResult(i)
		if success != "True" {
			failedMembers = append(failedMembers, member)
		}
	}

	if len(failedMembers) > 0 {
		tflog.Warn(ctx, "Some members failed to add to group",
			map[string]any{
				"group":          group,
				"failed_count":   len(failedMembers),
				"failed_members": failedMembers,
			})
	}

	tflog.Info(ctx, "Successfully added members to group",
		map[string]any{
			"group":   group,
			"total":   len(members),
			"failed":  len(failedMembers),
			"success": len(members) - len(failedMembers),
		})

	return nil
}
