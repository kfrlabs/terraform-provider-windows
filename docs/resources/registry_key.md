# windows_registry_key

Manages Windows Registry keys.

## Example Usage

### Basic Registry Key Creation

```hcl
resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}
```

### Registry Key with Force Creation

```hcl
resource "windows_registry_key" "nested_config" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config\\Advanced"
  force = true  # Creates all parent keys if they don't exist
}
```

### Adopt Existing Registry Key

```hcl
resource "windows_registry_key" "existing_key" {
  path           = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion"
  allow_existing = true
}
```

### Multiple Related Keys

```hcl
resource "windows_registry_key" "app_root" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_key" "app_settings" {
  path = "${windows_registry_key.app_root.path}\\Settings"
}

resource "windows_registry_key" "app_logging" {
  path = "${windows_registry_key.app_root.path}\\Logging"
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required, Forces new resource) The path to the registry key using PowerShell drive notation (e.g., `HKLM:\\Software\\MyApp`, `HKCU:\\Software\\MyApp`). Cannot be changed after creation.
* `force` - (Optional) Whether to force the creation of parent keys if they do not exist. Defaults to `false`.
  - `false`: Parent keys must already exist
  - `true`: Parent keys are created automatically if missing
* `allow_existing` - (Optional) If `true`, adopt existing registry key instead of failing. If `false`, fail if key already exists. Defaults to `false`.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300` (5 minutes).

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The path to the registry key.

## Import

Registry keys can be imported using the registry path:

```shell
terraform import windows_registry_key.app_config "HKLM:\\Software\\MyApp"
```

**Note:** Use PowerShell drive notation (with `:\\`) when importing.

## Behavior Notes

### Path Notation

Always use PowerShell drive notation for registry paths:
- **Correct:** `HKLM:\\Software\\MyApp`
- **Incorrect:** `HKEY_LOCAL_MACHINE\\Software\\MyApp`

### Registry Hives

Common registry hive abbreviations:
* `HKLM:` - HKEY_LOCAL_MACHINE (system-wide settings)
* `HKCU:` - HKEY_CURRENT_USER (current user settings)
* `HKCR:` - HKEY_CLASSES_ROOT (file associations)
* `HKU:` - HKEY_USERS (all users)
* `HKCC:` - HKEY_CURRENT_CONFIG (hardware profile)

### Existing Key Handling

When creating a key resource:
- If the key **does not exist**, it will be created normally.
- If the key **already exists**:
  - With `allow_existing = false` (default): Resource creation fails with error message suggesting import or setting `allow_existing = true`.
  - With `allow_existing = true`: The existing key is adopted into Terraform state without modification.

### Force Creation

The `force` parameter determines how parent keys are handled:
- `force = false` (default): Parent keys must already exist, or creation will fail.
- `force = true`: All parent keys in the path are created automatically if they don't exist.

Example:
```hcl
# This will fail if HKLM:\Software\MyCompany doesn't exist
resource "windows_registry_key" "app_without_force" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}

# This will succeed and create MyCompany if needed
resource "windows_registry_key" "app_with_force" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  force = true
}
```

### Deletion Behavior

When a registry key resource is deleted:
- The key and **all its subkeys and values** are removed using `Remove-Item -Recurse`
- This is a destructive operation and cannot be undone
- Built-in Windows registry keys may be protected and deletion may fail

### Read Behavior

The Read operation verifies that the registry key still exists:
- If the key exists, it remains in Terraform state
- If the key is deleted outside Terraform, it's removed from state

## Complete Examples

### Application Configuration Structure

```hcl
# Create main application key
resource "windows_registry_key" "app_root" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}

# Create configuration subkeys
resource "windows_registry_key" "app_settings" {
  path = "${windows_registry_key.app_root.path}\\Settings"
}

resource "windows_registry_key" "app_database" {
  path = "${windows_registry_key.app_root.path}\\Database"
}

resource "windows_registry_key" "app_logging" {
  path = "${windows_registry_key.app_root.path}\\Logging"
}

# Add registry values
resource "windows_registry_value" "app_name" {
  path  = windows_registry_key.app_settings.path
  name  = "ApplicationName"
  value = "My Application"
  type  = "String"
}

resource "windows_registry_value" "log_level" {
  path  = windows_registry_key.app_logging.path
  name  = "LogLevel"
  value = "2"
  type  = "DWord"
}
```

### Per-User Configuration

```hcl
# Create per-user application settings
resource "windows_registry_key" "user_app_settings" {
  path = "HKCU:\\Software\\MyApp\\Settings"
  force = true
}

resource "windows_registry_value" "user_theme" {
  path  = windows_registry_key.user_app_settings.path
  name  = "Theme"
  value = "Dark"
  type  = "String"
}
```

### Environment-Specific Keys

```hcl
variable "environment" {
  type = string
}

resource "windows_registry_key" "env_config" {
  path  = "HKLM:\\Software\\MyApp\\Environments\\${var.environment}"
  force = true
}

resource "windows_registry_value" "env_name" {
  path  = windows_registry_key.env_config.path
  name  = "EnvironmentName"
  value = var.environment
  type  = "String"
}
```

### Conditional Key Creation

```hcl
variable "enable_debug" {
  type    = bool
  default = false
}

resource "windows_registry_key" "debug_settings" {
  count = var.enable_debug ? 1 : 0
  
  path = "HKLM:\\Software\\MyApp\\Debug"
}

resource "windows_registry_value" "debug_enabled" {
  count = var.enable_debug ? 1 : 0
  
  path  = windows_registry_key.debug_settings[0].path
  name  = "Enabled"
  value = "1"
  type  = "DWord"
}
```

## Best Practices

### 1. Use Force Judiciously

Only use `force = true` when you control the parent key structure:
```hcl
# Good: You own MyCompany\MyApp
resource "windows_registry_key" "app_config" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  force = true
}

# Risky: Modifying Microsoft's registry space
resource "windows_registry_key" "windows_config" {
  path  = "HKLM:\\Software\\Microsoft\\MyCustomKey"
  force = true  # Be cautious!
}
```

### 2. Organize Keys Hierarchically

Create parent keys first, then child keys:
```hcl
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_key" "app_config" {
  path = "${windows_registry_key.app.path}\\Config"
}
```

### 3. Document Key Purpose

Use comments to document what each key is for:
```hcl
# Application configuration root
resource "windows_registry_key" "app_root" {
  path = "HKLM:\\Software\\MyApp"
}

# Database connection settings
resource "windows_registry_key" "app_database" {
  path = "${windows_registry_key.app_root.path}\\Database"
}
```

### 4. Use Variables for Base Paths

```hcl
variable "app_registry_root" {
  type    = string
  default = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_key" "app_root" {
  path = var.app_registry_root
}

resource "windows_registry_key" "app_settings" {
  path = "${var.app_registry_root}\\Settings"
}
```

## Security Considerations

1. **HKLM vs HKCU:** 
   - `HKLM` affects all users and requires administrator privileges
   - `HKCU` affects only the current user

2. **Backup Before Deletion:** Registry changes can affect system stability. Test in non-production first.

3. **Built-in Keys:** Avoid modifying Windows built-in registry keys unless necessary.

4. **Permissions:** Ensure the user running Terraform has appropriate registry permissions.

## Troubleshooting

### "Access Denied" Errors
- Ensure you're running with administrator privileges for HKLM
- Check registry key permissions

### "Key Not Found" Without Force
- Parent keys don't exist
- Set `force = true` or create parent keys first

### Key Exists Error
- Set `allow_existing = true` to adopt existing keys
- Or import the existing key into Terraform state