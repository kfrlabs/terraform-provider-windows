package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/powershell"
	"github.com/kfrlabs/terraform-provider-windows/windows/internal/utils"
)

func DataSourceWindowsRegistryValue() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceWindowsRegistryValueRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path to the registry key (e.g., 'HKLM:\\Software\\MyApp').",
			},
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "The name of the registry value. Empty string for default value.",
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The value stored in the registry.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of the registry value (String, DWord, Binary, etc.).",
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

func dataSourceWindowsRegistryValueRead(d *schema.ResourceData, m interface{}) error {
	ctx := context.Background()

	sshClient, cleanup, err := GetSSHClient(ctx, m)
	if err != nil {
		return err
	}
	defer cleanup()

	path := d.Get("path").(string)
	name := d.Get("name").(string)
	timeout := d.Get("command_timeout").(int)

	resourceID := fmt.Sprintf("%s\\%s", path, name)

	tflog.Info(ctx, "Reading registry value data source",
		map[string]any{
			"path": path,
			"name": name,
		})

	if err := utils.ValidateField(path, resourceID, "path"); err != nil {
		return utils.HandleResourceError("validate", resourceID, "path", err)
	}
	if name != "" {
		if err := utils.ValidateField(name, resourceID, "name"); err != nil {
			return utils.HandleResourceError("validate", resourceID, "name", err)
		}
	}

	// Use batch with OutputRaw
	batch := powershell.NewBatchCommandBuilder()
	batch.SetOutputFormat(powershell.OutputRaw) // ← CORRECTION ICI

	// Command 1: Check if key exists
	batch.Add(fmt.Sprintf("Test-Path -Path %s", powershell.QuotePowerShellString(path)))

	// Command 2: Get value
	if name == "" {
		batch.Add(fmt.Sprintf("(Get-ItemProperty -Path %s -ErrorAction SilentlyContinue).'(default)'",
			powershell.QuotePowerShellString(path)))
	} else {
		batch.Add(fmt.Sprintf("Get-ItemPropertyValue -Path %s -Name %s -ErrorAction SilentlyContinue",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name)))
	}

	// Command 3: Get type
	if name == "" {
		batch.Add(fmt.Sprintf("(Get-Item -Path %s -ErrorAction SilentlyContinue).GetValueKind('(default)')",
			powershell.QuotePowerShellString(path)))
	} else {
		batch.Add(fmt.Sprintf("(Get-Item -Path %s -ErrorAction SilentlyContinue).GetValueKind(%s)",
			powershell.QuotePowerShellString(path),
			powershell.QuotePowerShellString(name)))
	}

	command := batch.Build()

	tflog.Debug(ctx, "Executing batch command to read registry value")

	stdout, stderr, err := sshClient.ExecuteCommand(command, timeout)
	if err != nil {
		return utils.HandleCommandError("read_batch", resourceID, "state", command, stdout, stderr, err)
	}

	// Parse batch results with OutputRaw
	result, err := powershell.ParseBatchResult(stdout, powershell.OutputRaw) // ← CORRECTION ICI
	if err != nil {
		return utils.HandleResourceError("read", resourceID, "parse_result",
			fmt.Errorf("failed to parse batch result: %w", err))
	}

	if result.Count() < 3 {
		return utils.HandleResourceError("read", resourceID, "state",
			fmt.Errorf("incomplete batch result"))
	}

	// Result 1: Key existence
	keyExists, _ := result.GetStringResult(0)
	if keyExists != "True" {
		return utils.HandleResourceError("read", resourceID, "state",
			fmt.Errorf("registry key does not exist: %s", path))
	}

	// Result 2: Value
	currentValue, _ := result.GetStringResult(1)
	if currentValue == "" {
		return utils.HandleResourceError("read", resourceID, "state",
			fmt.Errorf("registry value does not exist: %s", resourceID))
	}
	currentValue = strings.TrimSpace(currentValue)

	// Result 3: Type
	valueType, _ := result.GetStringResult(2)
	if valueType == "" {
		valueType = "Unknown"
	}
	valueType = strings.TrimSpace(valueType)

	// Set all attributes
	d.SetId(resourceID)
	if err := d.Set("path", path); err != nil {
		return utils.HandleResourceError("read", resourceID, "path", err)
	}
	if err := d.Set("name", name); err != nil {
		return utils.HandleResourceError("read", resourceID, "name", err)
	}
	if err := d.Set("value", currentValue); err != nil {
		return utils.HandleResourceError("read", resourceID, "value", err)
	}
	if err := d.Set("type", valueType); err != nil {
		return utils.HandleResourceError("read", resourceID, "type", err)
	}

	tflog.Info(ctx, "Successfully read registry value data source",
		map[string]any{
			"resource_id": resourceID,
			"type":        valueType,
		})

	return nil
}
