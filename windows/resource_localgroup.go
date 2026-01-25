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

// LocalGroupInfo represents information about a local group
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

// checkLocalGroupExists checks if a local group exists and returns its information
func checkLocalGroupExists(ctx context.Context, sshClient *ssh.Client, name string, timeout int) (*LocalGroupInfo, error) {
	// Validate group name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return nil, err
	}

	tflog.Debug(ctx, "Checking if local group exists", map[string]any{"name": name})

	// PowerShell command that returns structured JSON
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

	// 1. Pool SSH avec cleanup
	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)
	allowExisting := d.Get("allow_existing").(bool)

	tflog.Info(ctx, "Creating local group", map[string]any{"name": name})

	// Validate group name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	// Check if group already exists
	info, err := checkLocalGroupExists(ctx, sshClient, name, timeout)
	if err != nil {
		return utils.HandleResourceError("check_existing", name, "state", err)
	}

	if info.Exists {
		if allowExisting {
			tflog.Info(ctx, "Group already exists, adopting it",
				map[string]any{"name": name})
			d.SetId(name)
			return resourceWindowsLocalGroupRead(d, m)
		}

		return utils.HandleResourceError(
			"create",
			name,
			"state",
			fmt.Errorf("local group already exists. "+
				"To manage this existing group, either:\n"+
				"  1. Import it: terraform import windows_localgroup.example '%s'\n"+
				"  2. Set allow_existing = true in your configuration",
				name),
		)
	}

	// Build command securely
	command := fmt.Sprintf("New-LocalGroup -Name %s",
		powershell.QuotePowerShellString(name))

	// Add description if provided
	if description, ok, err := utils.ValidateSchemaOptionalString(d, "description", name); err != nil {
		return err
	} else if ok {
		command += fmt.Sprintf(" -Description %s", powershell.QuotePowerShellString(description))
	}

	command += " -ErrorAction Stop"

	tflog.Debug(ctx, "Executing group creation", map[string]any{"name": name})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("create", name, "state", command, stdout, stderr, err)
	}

	d.SetId(name)

	tflog.Info(ctx, "Local group created successfully", map[string]any{"name": name})

	// Log pool statistics if available
	if stats, ok := GetPoolStats(m); ok {
		tflog.Debug(ctx, "Pool statistics after create", map[string]any{"stats": stats.String()})
	}

	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	name := d.Id()
	timeoutVal, ok := d.GetOk("command_timeout")
	var timeout int
	if !ok {
		timeout = 300
	} else {
		timeout = timeoutVal.(int)
	}

	tflog.Debug(ctx, "Reading local group", map[string]any{"name": name})

	info, err := checkLocalGroupExists(ctx, sshClient, name, timeout)
	if err != nil {
		tflog.Warn(ctx, "Failed to read local group", map[string]any{
			"name":  name,
			"error": err.Error(),
		})
		d.SetId("")
		return nil
	}

	if !info.Exists {
		tflog.Debug(ctx, "Local group does not exist, removing from state",
			map[string]any{"name": name})
		d.SetId("")
		return nil
	}

	// Update state
	if err := d.Set("name", info.Name); err != nil {
		return utils.HandleResourceError("read", name, "name", err)
	}
	if err := d.Set("description", info.Description); err != nil {
		return utils.HandleResourceError("read", name, "description", err)
	}

	tflog.Debug(ctx, "Local group read successfully", map[string]any{"name": name})

	return nil
}

func resourceWindowsLocalGroupUpdate(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Updating local group", map[string]any{"name": name})

	// Validate name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	// Update description
	if d.HasChange("description") {
		description := d.Get("description").(string)
		if err := utils.ValidateField(description, name, "description"); err != nil {
			return err
		}

		command := fmt.Sprintf("Set-LocalGroup -Name %s -Description %s -ErrorAction Stop",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(description))

		tflog.Debug(ctx, "Updating group description", map[string]any{"name": name})

		stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
		if err != nil {
			return utils.HandleCommandError("update", name, "description", command, stdout, stderr, err)
		}
	}

	tflog.Info(ctx, "Local group updated successfully", map[string]any{"name": name})

	return resourceWindowsLocalGroupRead(d, m)
}

func resourceWindowsLocalGroupDelete(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	tflog.Info(ctx, "Deleting local group", map[string]any{"name": name})

	// Validate name for security
	if err := utils.ValidateField(name, name, "name"); err != nil {
		return err
	}

	command := fmt.Sprintf("Remove-LocalGroup -Name %s -ErrorAction Stop",
		powershell.QuotePowerShellString(name))

	tflog.Debug(ctx, "Executing group deletion", map[string]any{"name": name})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("delete", name, "state", command, stdout, stderr, err)
	}

	d.SetId("")

	tflog.Info(ctx, "Local group deleted successfully", map[string]any{"name": name})

	return nil
}

// ============================================================================
// BATCH OPERATIONS FOR MULTIPLE LOCAL GROUPS
// ============================================================================

// LocalGroupConfig represents a local group configuration for batch operations
type LocalGroupConfig struct {
	Name        string
	Description string
}

// CreateMultipleLocalGroups creates multiple local groups in a batch
func CreateMultipleLocalGroups(
	ctx context.Context,
	sshClient *ssh.Client,
	groups []LocalGroupConfig,
	timeout int,
) error {
	if len(groups) == 0 {
		return nil
	}

	tflog.Info(ctx, "Creating multiple local groups in batch",
		map[string]any{"count": len(groups)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, group := range groups {
		cmd := fmt.Sprintf("New-LocalGroup -Name %s",
			powershell.QuotePowerShellString(group.Name))

		if group.Description != "" {
			cmd += fmt.Sprintf(" -Description %s",
				powershell.QuotePowerShellString(group.Description))
		}

		cmd += " -ErrorAction SilentlyContinue; "

		// Check if created
		cmd += fmt.Sprintf("(Get-LocalGroup -Name %s -ErrorAction SilentlyContinue) -ne $null",
			powershell.QuotePowerShellString(group.Name))

		batch.Add(cmd)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch group creation",
		map[string]any{"group_count": len(groups)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_create",
			"multiple_groups",
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
	failedGroups := []string{}
	for i, group := range groups {
		created, _ := result.GetStringResult(i)
		if created != "True" {
			failedGroups = append(failedGroups, group.Name)
		}
	}

	if len(failedGroups) > 0 {
		tflog.Warn(ctx, "Some groups failed to create",
			map[string]any{
				"failed_count":  len(failedGroups),
				"failed_groups": failedGroups,
			})
	}

	tflog.Info(ctx, "Successfully created local groups in batch",
		map[string]any{
			"total":   len(groups),
			"failed":  len(failedGroups),
			"success": len(groups) - len(failedGroups),
		})

	return nil
}

// CheckMultipleLocalGroupsExist checks if multiple local groups exist
func CheckMultipleLocalGroupsExist(
	ctx context.Context,
	sshClient *ssh.Client,
	names []string,
	timeout int,
) (map[string]*LocalGroupInfo, error) {
	if len(names) == 0 {
		return make(map[string]*LocalGroupInfo), nil
	}

	tflog.Debug(ctx, "Checking multiple local groups existence",
		map[string]any{"count": len(names)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, name := range names {
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
}`,
			powershell.QuotePowerShellString(name))

		batch.Add(command)
	}

	cmd := batch.Build()
	stdout, stderr, err := sshClient.ExecuteCommand(cmd, timeout)
	if err != nil {
		return nil, utils.HandleCommandError(
			"batch_check",
			"multiple_groups",
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
	infoMap := make(map[string]*LocalGroupInfo)
	for i, name := range names {
		infoStr, _ := result.GetStringResult(i)

		var info LocalGroupInfo
		if err := json.Unmarshal([]byte(infoStr), &info); err != nil {
			tflog.Warn(ctx, "Failed to parse group info",
				map[string]any{
					"name":  name,
					"error": err.Error(),
				})
			continue
		}

		infoMap[name] = &info
	}

	tflog.Debug(ctx, "Local group existence status retrieved",
		map[string]any{"count": len(infoMap)})

	return infoMap, nil
}

// DeleteMultipleLocalGroups deletes multiple local groups in a batch
func DeleteMultipleLocalGroups(
	ctx context.Context,
	sshClient *ssh.Client,
	names []string,
	timeout int,
) error {
	if len(names) == 0 {
		return nil
	}

	tflog.Info(ctx, "Deleting multiple local groups in batch",
		map[string]any{"count": len(names)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for _, name := range names {
		command := fmt.Sprintf("Remove-LocalGroup -Name %s -ErrorAction SilentlyContinue; (Get-LocalGroup -Name %s -ErrorAction SilentlyContinue) -eq $null",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(name))
		batch.Add(command)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch group deletion",
		map[string]any{"group_count": len(names)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_delete",
			"multiple_groups",
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

	// Check results (groups should NOT exist after deletion)
	notDeletedGroups := []string{}
	for i, name := range names {
		deleted, _ := result.GetStringResult(i)
		if deleted != "True" {
			notDeletedGroups = append(notDeletedGroups, name)
		}
	}

	if len(notDeletedGroups) > 0 {
		tflog.Warn(ctx, "Some groups failed to delete",
			map[string]any{
				"failed_count":  len(notDeletedGroups),
				"failed_groups": notDeletedGroups,
			})
	}

	tflog.Info(ctx, "Successfully deleted local groups in batch",
		map[string]any{
			"total":   len(names),
			"failed":  len(notDeletedGroups),
			"success": len(names) - len(notDeletedGroups),
		})

	return nil
}

// UpdateMultipleLocalGroupDescriptions updates descriptions for multiple groups
func UpdateMultipleLocalGroupDescriptions(
	ctx context.Context,
	sshClient *ssh.Client,
	updates map[string]string, // map[groupName]newDescription
	timeout int,
) error {
	if len(updates) == 0 {
		return nil
	}

	tflog.Info(ctx, "Updating multiple local group descriptions in batch",
		map[string]any{"count": len(updates)})

	// Build batch command
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputArray)

	for name, description := range updates {
		command := fmt.Sprintf("Set-LocalGroup -Name %s -Description %s -ErrorAction SilentlyContinue; $?",
			powershell.QuotePowerShellString(name),
			powershell.QuotePowerShellString(description))
		batch.Add(command)
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch group updates",
		map[string]any{"update_count": len(updates)})

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError(
			"batch_update",
			"multiple_groups",
			"description",
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
	failedGroups := []string{}
	i := 0
	for name := range updates {
		success, _ := result.GetStringResult(i)
		if success != "True" {
			failedGroups = append(failedGroups, name)
		}
		i++
	}

	if len(failedGroups) > 0 {
		tflog.Warn(ctx, "Some group updates failed",
			map[string]any{
				"failed_count":  len(failedGroups),
				"failed_groups": failedGroups,
			})
	}

	tflog.Info(ctx, "Successfully updated local groups in batch",
		map[string]any{
			"total":   len(updates),
			"failed":  len(failedGroups),
			"success": len(updates) - len(failedGroups),
		})

	return nil
}
