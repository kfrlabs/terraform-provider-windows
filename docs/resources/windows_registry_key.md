# Windows Registry Key Resource

Manages Windows registry keys on a Windows server via SSH and PowerShell remote execution. This resource handles the creation and deletion of registry keys, including parent key creation if needed.

## Table of Contents

1. [Example Usage](#example-usage)
2. [Argument Reference](#argument-reference)
3. [Attributes Reference](#attributes-reference)
4. [Registry Hives](#registry-hives)
5. [Advanced Examples](#advanced-examples)
6. [Import](#import)
7. [Troubleshooting](#troubleshooting)

---

## Example Usage

### Basic Usage

```hcl
resource "windows_registry_key" "example" {
  path = "HKLM:\\Software\\MyApp"
}
```

### Force Creation of Parent Keys

```hcl
resource "windows_registry_key" "example" {
  path  = "HKLM:\\Software\\MyApp\\SubKey\\DeepKey"
  force = true
}
```

### With Custom Timeout

```hcl
resource "windows_registry_key" "example" {
  path            = "HKLM:\\Software\\MyApp"
  force           = true
  command_timeout = 300
}
```

---

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **path** | string | The full path to the registry key to create or manage. Must start with a valid registry hive (HKLM, HKCU, HKCR, HKU, HKCC). Example: `HKLM:\\Software\\MyApp\\SubKey`. |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **force** | bool | false | Whether to force the creation of all parent keys if they do not exist. When `true`, the provider will create the entire key path hierarchy. When `false`, the immediate parent key must already exist. |
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands executed on the remote server. Increase for complex registry operations. |

---

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | The registry key path (same as `path` argument). Used as the unique identifier. |
| **exists** | bool | Whether the registry key currently exists on the system. |
| **created** | bool | Whether the key was created by this resource or already existed. |
| **subkeys_count** | number | The number of subkeys contained within this registry key. |

---

## Registry Hives

Windows registry is organized into several main hives. Each hive has a specific purpose and permission level:

| Hive | Full Name | Description | Typical Use |
|------|-----------|-------------|-------------|
| **HKCR** | HKEY_CLASSES_ROOT | File associations and OLE object class definitions | File type associations, shell extensions |
| **HKCU** | HKEY_CURRENT_USER | Settings for the currently logged-in user | User preferences, application settings |
| **HKLM** | HKEY_LOCAL_MACHINE | System-wide configuration and hardware settings | Application configuration, system settings |
| **HKU** | HKEY_USERS | Settings for all users on the system | User profile data |
| **HKCC** | HKEY_CURRENT_CONFIG | Hardware profile information | Hardware configuration |

### Common Registry Paths

#### Application Configuration

```hcl
# Microsoft Office
resource "windows_registry_key" "office" {
  path = "HKLM:\\Software\\Microsoft\\Office"
}

# Windows Settings
resource "windows_registry_key" "windows" {
  path = "HKLM:\\Software\\Microsoft\\Windows"
}

# Installed Programs
resource "windows_registry_key" "programs" {
  path = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
}
```

#### System Services

```hcl
# Services configuration
resource "windows_registry_key" "services" {
  path = "HKLM:\\System\\CurrentControlSet\\Services"
}

# Network configuration
resource "windows_registry_key" "network" {
  path = "HKLM:\\System\\CurrentControlSet\\Services\\Tcpip"
}
```

#### User Settings

```hcl
# Current user preferences
resource "windows_registry_key" "user_software" {
  path = "HKCU:\\Software\\MyApp"
}

# Desktop settings
resource "windows_registry_key" "user_desktop" {
  path = "HKCU:\\Control Panel\\Desktop"
}
```

---

## Advanced Examples

### Nested Registry Key Structure

```hcl
resource "windows_registry_key" "app_root" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  force = true
}

resource "windows_registry_key" "app_config" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  force = false

  depends_on = [windows_registry_key.app_root]
}

resource "windows_registry_key" "app_advanced" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config\\Advanced"
  force = false

  depends_on = [windows_registry_key.app_config]
}
```

### Multiple Application Registry Keys

```hcl
variable "applications" {
  type = map(object({
    name     = string
    registry = string
  }))
  default = {
    app1 = {
      name     = "Application One"
      registry = "HKLM:\\Software\\App1"
    }
    app2 = {
      name     = "Application Two"
      registry = "HKLM:\\Software\\App2"
    }
  }
}

resource "windows_registry_key" "apps" {
  for_each = var.applications

  path  = each.value.registry
  force = true
}
```

### Registry Key with Values

```hcl
resource "windows_registry_key" "app_config" {
  path  = "HKLM:\\Software\\MyApp\\Settings"
  force = true
}

# Associate registry values with the key
resource "windows_registry_value" "app_version" {
  key   = windows_registry_key.app_config.path
  name  = "Version"
  type  = "string"
  value = "1.0.0"

  depends_on = [windows_registry_key.app_config]
}

resource "windows_registry_value" "app_enabled" {
  key   = windows_registry_key.app_config.path
  name  = "Enabled"
  type  = "dword"
  value = "1"

  depends_on = [windows_registry_key.app_config]
}
```

### Conditional Registry Key Creation

```hcl
variable "install_advanced_settings" {
  type    = bool
  default = false
}

resource "windows_registry_key" "standard" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_key" "advanced" {
  count   = var.install_advanced_settings ? 1 : 0
  path    = "HKLM:\\Software\\MyApp\\Advanced"
  force   = true

  depends_on = [windows_registry_key.standard]
}
```

### Registry Key Cleanup

```hcl
# Main application key
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}

# Temporary key that gets removed when Terraform is destroyed
resource "windows_registry_key" "temp_settings" {
  path  = "HKLM:\\Software\\MyApp\\Temp"
  force = true

  depends_on = [windows_registry_key.app]
}

# When you destroy the Terraform configuration, both keys will be removed
```

---

## Import

Registry keys can be imported using their registry path. This allows you to bring existing registry keys under Terraform management.

### Import Syntax

```shell
terraform import windows_registry_key.<resource_name> <registry_path>
```

### Import Examples

Import a single registry key:

```shell
terraform import windows_registry_key.example "HKLM:\\Software\\MyApp"
```

Import from HKCU (current user):

```shell
terraform import windows_registry_key.user_settings "HKCU:\\Software\\MyApp"
```

Create the resource configuration:

```hcl
resource "windows_registry_key" "example" {
  path = "HKLM:\\Software\\MyApp"
}
```

Then import the existing key:

```shell
terraform import windows_registry_key.example "HKLM:\\Software\\MyApp"
```

### Import Multiple Registry Keys

Create resource definitions:

```hcl
resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
}

resource "windows_registry_key" "app_cache" {
  path = "HKLM:\\Software\\MyCompany\\MyApp\\Cache"
}

resource "windows_registry_key" "user_prefs" {
  path = "HKCU:\\Software\\MyApp"
}
```

Import the existing keys:

```shell
terraform import windows_registry_key.app_config "HKLM:\\Software\\MyCompany\\MyApp\\Config"
terraform import windows_registry_key.app_cache "HKLM:\\Software\\MyCompany\\MyApp\\Cache"
terraform import windows_registry_key.user_prefs "HKCU:\\Software\\MyApp"
```

---

## Troubleshooting

### Key Creation Fails

**Issue**: `failed to create registry key` or `key creation error`

**Solutions**:
- Verify the registry path format uses double backslashes: `HKLM:\\Software\\MyApp`
- Ensure the hive name is valid: HKLM, HKCU, HKCR, HKU, or HKCC
- Verify SSH user has administrator privileges
- Check parent key exists or set `force = true`
- Run manual check: `Test-Path "Registry::HKLM\Software\MyApp"`

### Access Denied

**Issue**: `access denied` or `permission denied` error

**Solutions**:
- Verify SSH user is in the Administrators group
- Check with: `whoami /groups | find "S-1-5-32-544"`
- Some registry hives require elevation or specific permissions
- Check registry permissions: `regedit` → Right-click key → Permissions
- HKCU issues typically require running as the specific user

### Parent Key Does Not Exist

**Issue**: `parent key not found` or similar error

**Solutions**:
- Set `force = true` to automatically create parent keys
- Or manually create parent keys first with separate resources
- Example with force:
  ```hcl
  resource "windows_registry_key" "example" {
    path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
    force = true
  }
  ```

### Invalid Registry Path

**Issue**: `invalid path` or `malformed registry path`

**Solutions**:
- Use proper format: `HIVE:\\Path\\To\\Key`
- Use double backslashes: `\\` not `\`
- Do not use forward slashes `/`
- Valid examples:
  - `HKLM:\\Software\\Microsoft\\Windows`
  - `HKCU:\\Software\\MyApp`
  - `HKCR:\\.txt` (for file types)

### Key Already Exists

**Issue**: `key already exists` warning or error

**Solutions**:
- This is usually not an error; Terraform is idempotent
- If key exists, just import it: `terraform import windows_registry_key.example "HKLM:\\Software\\MyApp"`
- Check Terraform state: `terraform state list`
- If state is corrupted, refresh: `terraform refresh`

### SSH Connection Issues

**Issue**: Connection timeout or SSH error during key creation

**Solutions**:
- Increase `command_timeout` to allow more time
- Check network connectivity to the server
- Verify SSH credentials and access
- Test manually: `ssh admin@server-ip`

### Registry Key Path Issues

**Issue**: Special characters or spaces in registry path

**Solutions**:
- If path contains spaces, still use normal format: `HKLM:\\Software\\My App`
- Some characters may require escaping in PowerShell
- Test path manually: `Test-Path "Registry::HKLM\Software\My App"`
- For problematic characters, verify with: `Get-Item -Path "Registry::HKLM\..."`

### Circular Dependencies

**Issue**: `circular dependency detected` error

**Solutions**:
- Avoid creating circular references between registry keys
- Use `depends_on` explicitly to clarify order
- Example of correct dependency:
  ```hcl
  resource "windows_registry_key" "parent" {
    path = "HKLM:\\Software\\MyApp"
  }

  resource "windows_registry_key" "child" {
    path = "HKLM:\\Software\\MyApp\\Config"

    depends_on = [windows_registry_key.parent]
  }
  ```

### State Mismatch

**Issue**: Registry key exists but Terraform state says it doesn't

**Solutions**:
- Manually deleted registry key outside of Terraform
- Run `terraform refresh` to update state
- Or remove and re-import: `terraform state rm windows_registry_key.example`
- Always use Terraform to manage registry keys

---

## Best Practices

### Use Force Carefully

Only use `force = true` when you want to create an entire key hierarchy:

```hcl
# Good: Create entire path at once
resource "windows_registry_key" "app" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config\\Advanced"
  force = true
}

# Also acceptable: Create step by step with dependencies
resource "windows_registry_key" "company" {
  path = "HKLM:\\Software\\MyCompany"
}

resource "windows_registry_key" "app_folder" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
  depends_on = [windows_registry_key.company]
}
```

### Organize by Hive

Group registry keys by their hive for clarity:

```hcl
# Local machine settings
resource "windows_registry_key" "hklm_app" {
  path = "HKLM:\\Software\\MyApp"
}

# Current user settings
resource "windows_registry_key" "hkcu_app" {
  path = "HKCU:\\Software\\MyApp"
}
```

### Use Variables for Dynamic Paths

```hcl
variable "app_name" {
  type    = string
  default = "MyApp"
}

variable "company_name" {
  type    = string
  default = "MyCompany"
}

resource "windows_registry_key" "app" {
  path  = "HKLM:\\Software\\${var.company_name}\\${var.app_name}"
  force = true
}
```

### Combine with Registry Values

Always pair keys with their values for complete configuration:

```hcl
resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyApp"
}

# Add configuration values to the key
resource "windows_registry_value" "app_version" {
  key   = windows_registry_key.app_config.path
  name  = "Version"
  type  = "string"
  value = "1.0"

  depends_on = [windows_registry_key.app_config]
}
```

### Document Purpose

Add comments explaining why each registry key is needed:

```hcl
# Application configuration root - required for application startup
resource "windows_registry_key" "app_root" {
  path = "HKLM:\\Software\\MyApp"
}

# Performance tuning settings - optional optimization
resource "windows_registry_key" "app_perf" {
  path = "HKLM:\\Software\\MyApp\\Performance"
  depends_on = [windows_registry_key.app_root]
}
```

---

## Important Considerations

### Registry Backup

Before making large registry changes, consider backing up the registry:

```powershell
# On Windows server
reg export HKLM\Software\MyApp C:\Backup\MyApp.reg
```

### Testing

Always test registry changes in a development environment first:

```hcl
variable "environment" {
  type    = string
  default = "dev"
}

resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\${var.environment}-MyApp"
}
```

### Persistence

Registry keys persist across system reboots. No restart is required for key creation, but some applications may cache registry values and need to be restarted.

### Key Removal

When you destroy a Terraform configuration, all managed registry keys will be deleted. Be careful with:

```bash
terraform destroy  # This will remove all managed registry keys
```

---

## Limitations

- **No Key Enumeration**: This resource creates/manages specific keys only; it doesn't enumerate all subkeys
- **Registry Recovery**: Deleted registry keys cannot be automatically recovered; ensure proper backups
- **System Keys**: Some system registry keys cannot be modified due to Windows protections
- **Group Policy**: Group Policy may override registry settings configured here
- **User-Specific Keys**: HKCU keys apply only to the user running the SSH session