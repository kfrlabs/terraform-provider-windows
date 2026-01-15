# windows_registry_key

Manages Windows Registry keys.

## Example Usage

### Basic Registry Key Creation

```hcl
resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}
```

### Registry Key with Force

```hcl
resource "windows_registry_key" "nested_key" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config\\Database"
  force = true  # Creates parent keys if they don't exist
}
```

### Multiple Related Keys

```hcl
resource "windows_registry_key" "company" {
  path = "HKLM:\\Software\\MyCompany"
}

resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
  
  depends_on = [windows_registry_key.company]
}

resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  
  depends_on = [windows_registry_key.app]
}
```

### HKCU Key for User Settings

```hcl
resource "windows_registry_key" "user_prefs" {
  path = "HKCU:\\Software\\MyApp\\Preferences"
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required, String, ForceNew) The full path to the registry key using PowerShell notation (e.g., `HKLM:\Software\MyApp`). Changing this will force recreation of the resource.

* `force` - (Optional, Boolean) Whether to force the creation of parent keys if they do not exist. Default: `false`.

* `command_timeout` - (Optional, Number) Timeout in seconds for PowerShell commands. Default: `300` (5 minutes).

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The registry key path.

## Import

Registry keys can be imported using their path:

```bash
terraform import windows_registry_key.app_config "HKLM:\\Software\\MyCompany\\MyApp"
```

## Registry Hives

### Available Hives

Windows Registry is organized into hives. In PowerShell notation:

| Hive | Full Name | Description |
|------|-----------|-------------|
| **HKLM:** | HKEY_LOCAL_MACHINE | Computer-wide settings |
| **HKCU:** | HKEY_CURRENT_USER | Current user settings |
| **HKCR:** | HKEY_CLASSES_ROOT | File associations and COM registration |
| **HKU:** | HKEY_USERS | All user profiles |
| **HKCC:** | HKEY_CURRENT_CONFIG | Current hardware profile |

### HKEY_LOCAL_MACHINE (HKLM:)

System-wide configuration. Requires administrator privileges.

```hcl
# Software settings
resource "windows_registry_key" "software" {
  path = "HKLM:\\Software\\MyApp"
}

# System settings
resource "windows_registry_key" "system" {
  path = "HKLM:\\System\\CurrentControlSet\\Services\\MyService"
}

# 32-bit app on 64-bit system
resource "windows_registry_key" "wow64" {
  path = "HKLM:\\Software\\WOW6432Node\\MyApp"
}
```

### HKEY_CURRENT_USER (HKCU:)

Settings for the user running the SSH session.

```hcl
resource "windows_registry_key" "user_settings" {
  path = "HKCU:\\Software\\MyApp"
}

resource "windows_registry_key" "env_vars" {
  path = "HKCU:\\Environment"
}
```

⚠️ **Note**: HKCU: refers to the SSH user's profile, not the local admin or other users.

### HKEY_CLASSES_ROOT (HKCR:)

File associations and COM object registrations.

```hcl
resource "windows_registry_key" "file_type" {
  path = "HKCR:\\.myext"
}

resource "windows_registry_key" "prog_id" {
  path = "HKCR:\\MyApp.Document"
}
```

### HKEY_USERS (HKU:)

All user profiles. Requires knowing the user SID.

```hcl
resource "windows_registry_key" "all_users" {
  path = "HKU:\\S-1-5-21-1234567890-1234567890-1234567890-1001\\Software\\MyApp"
}
```

## Path Format

### PowerShell Notation

Always use PowerShell registry notation with a colon after the hive:

✅ **Correct**:
```hcl
path = "HKLM:\\Software\\MyApp"
path = "HKCU:\\Software\\MyApp\\Settings"
path = "HKCR:\\.txt"
```

❌ **Incorrect**:
```hcl
path = "HKLM\\Software\\MyApp"      # Missing colon
path = "HKEY_LOCAL_MACHINE\\..."    # Wrong notation
path = "\\Registry\\Machine\\..."    # Wrong notation
```

### Backslashes

Use double backslashes (`\\`) in HCL strings:

```hcl
resource "windows_registry_key" "example" {
  path = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  #             ↑        ↑         ↑         ↑             ↑
  #           Double backslashes for path separators
}
```

Or use raw strings:

```hcl
resource "windows_registry_key" "example" {
  path = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
}
```

## Force Creation of Parent Keys

### Without Force

If parent keys don't exist, creation will fail:

```hcl
# This will fail if HKLM:\Software\MyCompany doesn't exist
resource "windows_registry_key" "app" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  force = false  # Default
}
```

### With Force

Parent keys will be created automatically:

```hcl
# This will create all parent keys if needed:
# - HKLM:\Software\MyCompany
# - HKLM:\Software\MyCompany\MyApp
# - HKLM:\Software\MyCompany\MyApp\Config
resource "windows_registry_key" "app" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  force = true
}
```

### Explicit Hierarchy (Recommended)

For better control and visibility, create keys explicitly:

```hcl
resource "windows_registry_key" "company" {
  path = "HKLM:\\Software\\MyCompany"
}

resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
  depends_on = [windows_registry_key.company]
}

resource "windows_registry_key" "config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  depends_on = [windows_registry_key.app]
}
```

## Common Use Cases

### Application Configuration

```hcl
# Main application key
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}

# Configuration subkey
resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  depends_on = [windows_registry_key.app]
}

# Database settings subkey
resource "windows_registry_key" "db_config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp\\Config\\Database"
  depends_on = [windows_registry_key.app_config]
}
```

### Windows Service Configuration

```hcl
resource "windows_registry_key" "service_params" {
  path = "HKLM:\\System\\CurrentControlSet\\Services\\MyService\\Parameters"
  force = true
}
```

### Uninstall Registry Key

```hcl
resource "windows_registry_key" "uninstall" {
  path = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MyApp"
}
```

### COM Registration

```hcl
resource "windows_registry_key" "com_object" {
  path = "HKCR:\\CLSID\\{12345678-1234-1234-1234-123456789012}"
}
```

## Deletion Behavior

When a `windows_registry_key` resource is removed from configuration or destroyed:

- The key and all its subkeys are deleted
- Deletion uses `-Recurse` flag (removes everything under the key)
- Built-in Windows keys cannot be deleted (will cause error)

```hcl
# Deleting this will remove the key and all subkeys
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}
```

⚠️ **Warning**: Be careful when deleting keys. Test in a non-production environment first.

## Relationship with Registry Values

Registry keys and values are separate resources:

```hcl
# Create the key
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}

# Create values in the key
resource "windows_registry_value" "app_name" {
  path  = windows_registry_key.app.path
  name  = "AppName"
  type  = "String"
  value = "My Application"
  
  depends_on = [windows_registry_key.app]
}

resource "windows_registry_value" "version" {
  path  = windows_registry_key.app.path
  name  = "Version"
  type  = "String"
  value = "1.0.0"
  
  depends_on = [windows_registry_key.app]
}
```

## Security Considerations

### Permissions Required

- **HKLM**: Requires administrator privileges
- **HKCU**: Works with user privileges (for current SSH user)
- **HKCR**: Requires administrator privileges
- **HKU**: Requires administrator privileges

### Sensitive Keys

Be careful when modifying these areas:

```hcl
# System configuration - can affect stability
"HKLM:\\System\\CurrentControlSet\\..."

# Security settings - can affect security
"HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

# Boot configuration - can prevent boot
"HKLM:\\BCD00000000"

# Services - can break services
"HKLM:\\System\\CurrentControlSet\\Services\\..."
```

### Registry Permissions

The SSH user needs:
- **Read** permission to check if key exists
- **Write** permission to create the key
- **Delete** permission to remove the key

Check permissions in `regedit.exe` → Right-click key → Permissions.

## Troubleshooting

### Permission Denied

**Issue**: Access denied when creating/deleting key

**Solution**:
- Ensure SSH user has administrator rights for HKLM
- Check registry key permissions in `regedit`
- For HKLM, user must be in Administrators group

### Path Not Found

**Issue**: Cannot create key - parent path doesn't exist

**Solution**:
- Use `force = true` to create parent keys automatically
- Or create parent keys explicitly with dependencies

### Key Already Exists

**Issue**: Key already exists (import or manual creation)

**Solution**:
- Import the key: `terraform import windows_registry_key.name "HKLM:\\Path"`
- Or manually delete the key and re-run Terraform

### Invalid Path Format

**Issue**: Invalid registry path format

**Solution**:
- Use PowerShell notation: `HKLM:\\...` (with colon)
- Use double backslashes: `\\` in HCL strings
- Check hive name is correct (HKLM:, HKCU:, etc.)

### Cannot Delete Built-in Key

**Issue**: Error deleting Windows system key

**Solution**:
- Don't delete built-in Windows keys
- Only manage keys for your application
- Review which keys are safe to delete

## Best Practices

### Naming Conventions

```hcl
# Use your company/organization name
"HKLM:\\Software\\MyCompany\\..."

# Use application name
"HKLM:\\Software\\MyCompany\\MyApp\\..."

# Use descriptive subkeys
"HKLM:\\Software\\MyCompany\\MyApp\\Configuration"
"HKLM:\\Software\\MyCompany\\MyApp\\Logging"
```

### Cleanup

Always clean up registry keys when removing application:

```hcl
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}

# When you remove this resource or run terraform destroy,
# the key will be deleted automatically
```

### Documentation

Document registry key purpose:

```hcl
resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyCompany\\MyApp\\Config"
  
  # Purpose: Application configuration settings
  # Created: 2024-01-15
  # Owner: Infrastructure Team
}
```

## Notes

- Key paths are case-insensitive in Windows
- Terraform tracks key existence, not permissions or subkeys
- Empty keys (no values) are valid
- Deleting a key removes all its subkeys and values
- Be cautious with built-in Windows registry keys
- Test registry changes in non-production first

## Related Resources

- `windows_registry_value` - Create values within registry keys
- Always create the key before creating values in it
- Consider using both resources together for complete registry configuration
