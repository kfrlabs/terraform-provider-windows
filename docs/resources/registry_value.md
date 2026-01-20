# windows_registry_value

Manages Windows Registry values within registry keys.

## Example Usage

### String Value

```hcl
resource "windows_registry_value" "app_name" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  name  = "ApplicationName"
  value = "My Application"
  type  = "String"
}
```

### DWord Value

```hcl
resource "windows_registry_value" "timeout" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "Timeout"
  value = "3600"
  type  = "DWord"
}
```

### Default Value

```hcl
resource "windows_registry_value" "default" {
  path  = "HKLM:\\Software\\MyApp"
  name  = ""  # Empty string for default value
  value = "Default application"
  type  = "String"
}
```

### Binary Value

```hcl
resource "windows_registry_value" "binary_data" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "BinaryData"
  value = "01020304"
  type  = "Binary"
}
```

### ExpandString Value

```hcl
resource "windows_registry_value" "install_path" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "InstallPath"
  value = "%ProgramFiles%\\MyApp"
  type  = "ExpandString"
}
```

### MultiString Value

```hcl
resource "windows_registry_value" "search_paths" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "SearchPaths"
  value = "C:\\Path1\nC:\\Path2\nC:\\Path3"
  type  = "MultiString"
}
```

### Adopt Existing Value

```hcl
resource "windows_registry_value" "existing_value" {
  path           = "HKLM:\\Software\\MyApp"
  name           = "Version"
  value          = "2.0"
  type           = "String"
  allow_existing = true
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required, Forces new resource) The path to the registry key using PowerShell drive notation (e.g., `HKLM:\\Software\\MyApp`). The key must already exist. Cannot be changed after creation.
* `name` - (Optional, Forces new resource) The name of the registry value. Use empty string `""` for the default value. Defaults to `""`. Cannot be changed after creation.
* `type` - (Optional, Forces new resource) The type of the registry value. Defaults to `String`. Valid values:
  - `String` - REG_SZ (regular string)
  - `ExpandString` - REG_EXPAND_SZ (string with environment variables)
  - `Binary` - REG_BINARY (binary data as hex string)
  - `DWord` - REG_DWORD (32-bit number as string)
  - `QWord` - REG_QWORD (64-bit number as string)
  - `MultiString` - REG_MULTI_SZ (multiple strings separated by `\n`)
  - `Unknown` - Unknown type (use with caution)
* `value` - (Optional) The value to set in the registry. Format depends on `type`:
  - `String`/`ExpandString`: Plain text
  - `DWord`/`QWord`: Numeric value as string (e.g., `"3600"`)
  - `Binary`: Hexadecimal string (e.g., `"01020304"`)
  - `MultiString`: Strings separated by `\n` (e.g., `"Line1\nLine2\nLine3"`)
* `allow_existing` - (Optional) If `true`, adopt existing registry value instead of failing. If `false`, fail if value already exists. Defaults to `false`.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300` (5 minutes).

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The full path to the registry value in the format `path\name`.

## Import

Registry values can be imported using the format `path\name`:

```shell
terraform import windows_registry_value.app_name "HKLM:\\Software\\MyApp\ApplicationName"
```

For the default value (empty name):
```shell
terraform import windows_registry_value.default "HKLM:\\Software\\MyApp\"
```

**Note:** Use PowerShell drive notation and include the backslash before the value name.

## Behavior Notes

### Registry Key Must Exist

The registry key specified in `path` must already exist before creating a value. Use `windows_registry_key` resource to create keys first:

```hcl
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_value" "app_name" {
  path  = windows_registry_key.app.path
  name  = "ApplicationName"
  value = "My Application"
  type  = "String"
}
```

### Existing Value Handling

When creating a value resource:
- If the value **does not exist**, it will be created normally.
- If the value **already exists**:
  - With `allow_existing = false` (default): Resource creation fails with error showing current value and suggesting import or setting `allow_existing = true`.
  - With `allow_existing = true`: The existing value is adopted and updated to match the configuration.

### Value Updates

When updating a registry value:
- Only the `value` attribute can be updated
- Changes to `path`, `name`, or `type` force recreation of the resource
- The value is updated using `Set-ItemProperty`

### Default Value

To manage the default value of a registry key, use an empty string for the `name`:
```hcl
resource "windows_registry_value" "default" {
  path  = "HKLM:\\Software\\MyApp"
  name  = ""  # Default value
  value = "Default"
  type  = "String"
}
```

### Data Type Specifics

**String / ExpandString:**
- Plain text values
- ExpandString expands environment variables (e.g., `%ProgramFiles%`) when read

**DWord / QWord:**
- Numeric values stored as strings in Terraform
- DWord: 32-bit (0 to 4,294,967,295)
- QWord: 64-bit (0 to 18,446,744,073,709,551,615)
- Example: `value = "1234"`

**Binary:**
- Hexadecimal string representation
- Example: `value = "01020304"` represents bytes [0x01, 0x02, 0x03, 0x04]

**MultiString:**
- Multiple strings separated by newline (`\n`)
- Example: `value = "String1\nString2\nString3"`

## Complete Examples

### Application Configuration

```hcl
# Create registry key structure
resource "windows_registry_key" "app_root" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}

resource "windows_registry_key" "app_config" {
  path = "${windows_registry_key.app_root.path}\\Config"
}

# Application metadata
resource "windows_registry_value" "app_name" {
  path  = windows_registry_key.app_root.path
  name  = "ApplicationName"
  value = "My Application"
  type  = "String"
}

resource "windows_registry_value" "app_version" {
  path  = windows_registry_key.app_root.path
  name  = "Version"
  value = "2.1.0"
  type  = "String"
}

resource "windows_registry_value" "install_date" {
  path  = windows_registry_key.app_root.path
  name  = "InstallDate"
  value = "2026-01-20"
  type  = "String"
}

# Configuration values
resource "windows_registry_value" "timeout" {
  path  = windows_registry_key.app_config.path
  name  = "Timeout"
  value = "3600"
  type  = "DWord"
}

resource "windows_registry_value" "max_connections" {
  path  = windows_registry_key.app_config.path
  name  = "MaxConnections"
  value = "100"
  type  = "DWord"
}

resource "windows_registry_value" "enable_logging" {
  path  = windows_registry_key.app_config.path
  name  = "EnableLogging"
  value = "1"
  type  = "DWord"
}
```

### Database Connection String

```hcl
resource "windows_registry_key" "app_db" {
  path = "HKLM:\\Software\\MyApp\\Database"
}

resource "windows_registry_value" "db_server" {
  path  = windows_registry_key.app_db.path
  name  = "Server"
  value = "sql-server-01.local"
  type  = "String"
}

resource "windows_registry_value" "db_name" {
  path  = windows_registry_key.app_db.path
  name  = "Database"
  value = "MyAppDB"
  type  = "String"
}

resource "windows_registry_value" "db_port" {
  path  = windows_registry_key.app_db.path
  name  = "Port"
  value = "1433"
  type  = "DWord"
}
```

### Environment-Specific Settings

```hcl
variable "environment" {
  type = string
}

variable "api_endpoint" {
  type = map(string)
  default = {
    dev  = "https://api-dev.example.com"
    prod = "https://api.example.com"
  }
}

resource "windows_registry_key" "app_env" {
  path  = "HKLM:\\Software\\MyApp\\Environment"
  force = true
}

resource "windows_registry_value" "environment" {
  path  = windows_registry_key.app_env.path
  name  = "Environment"
  value = var.environment
  type  = "String"
}

resource "windows_registry_value" "api_url" {
  path  = windows_registry_key.app_env.path
  name  = "ApiEndpoint"
  value = var.api_endpoint[var.environment]
  type  = "String"
}
```

### Feature Flags

```hcl
resource "windows_registry_key" "app_features" {
  path = "HKLM:\\Software\\MyApp\\Features"
}

resource "windows_registry_value" "feature_analytics" {
  path  = windows_registry_key.app_features.path
  name  = "EnableAnalytics"
  value = "1"
  type  = "DWord"
}

resource "windows_registry_value" "feature_beta" {
  path  = windows_registry_key.app_features.path
  name  = "EnableBetaFeatures"
  value = "0"
  type  = "DWord"
}
```

### Path Configuration with Environment Variables

```hcl
resource "windows_registry_key" "app_paths" {
  path = "HKLM:\\Software\\MyApp\\Paths"
}

resource "windows_registry_value" "install_path" {
  path  = windows_registry_key.app_paths.path
  name  = "InstallPath"
  value = "%ProgramFiles%\\MyApp"
  type  = "ExpandString"  # Will expand %ProgramFiles% when read
}

resource "windows_registry_value" "data_path" {
  path  = windows_registry_key.app_paths.path
  name  = "DataPath"
  value = "%ProgramData%\\MyApp\\Data"
  type  = "ExpandString"
}

resource "windows_registry_value" "log_path" {
  path  = windows_registry_key.app_paths.path
  name  = "LogPath"
  value = "%ProgramData%\\MyApp\\Logs"
  type  = "ExpandString"
}
```

### List of Search Paths (MultiString)

```hcl
resource "windows_registry_value" "search_paths" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "SearchPaths"
  value = join("\\n", [
    "C:\\Program Files\\MyApp\\Plugins",
    "C:\\Program Files\\MyApp\\Modules",
    "C:\\ProgramData\\MyApp\\Extensions"
  ])
  type = "MultiString"
}
```

## Best Practices

### 1. Create Keys Before Values

```hcl
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_value" "setting" {
  path  = windows_registry_key.app.path  # Reference the key
  name  = "Setting"
  value = "Value"
  type  = "String"
}
```

### 2. Use Appropriate Data Types

```hcl
# Numbers: Use DWord or QWord
resource "windows_registry_value" "port" {
  name  = "Port"
  value = "8080"  # String representation of number
  type  = "DWord"
}

# Paths with variables: Use ExpandString
resource "windows_registry_value" "install_dir" {
  name  = "InstallDir"
  value = "%ProgramFiles%\\MyApp"
  type  = "ExpandString"
}

# Boolean flags: Use DWord with 0/1
resource "windows_registry_value" "enabled" {
  name  = "Enabled"
  value = "1"  # 1 = true, 0 = false
  type  = "DWord"
}
```

### 3. Document Value Purpose

```hcl
# Application timeout in seconds
resource "windows_registry_value" "timeout" {
  path  = windows_registry_key.app_config.path
  name  = "TimeoutSeconds"
  value = "300"
  type  = "DWord"
}
```

### 4. Use Variables for Flexibility

```hcl
variable "app_config" {
  type = object({
    timeout         = number
    max_connections = number
    enable_logging  = bool
  })
}

resource "windows_registry_value" "timeout" {
  path  = windows_registry_key.app.path
  name  = "Timeout"
  value = tostring(var.app_config.timeout)
  type  = "DWord"
}
```

## Security Considerations

1. **Sensitive Data:** Avoid storing passwords or secrets in the registry. Use Windows Credential Manager or other secure storage instead.

2. **HKLM vs HKCU:**
   - `HKLM` (Local Machine) affects all users, requires admin privileges
   - `HKCU` (Current User) affects only current user

3. **Permissions:** Ensure Terraform has appropriate permissions to modify registry values.

4. **Backup:** Always back up registry keys before making changes in production.

## Troubleshooting

### "Registry key does not exist"
Create the parent key first:
```hcl
resource "windows_registry_key" "parent" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_value" "value" {
  path = windows_registry_key.parent.path
  name = "Setting"
  # ...
}
```

### "Value already exists"
- Set `allow_existing = true` to adopt it
- Or import the existing value

### Wrong Data Type
Ensure the `value` matches the `type`:
- DWord/QWord: Use string representation of numbers
- Binary: Use hexadecimal string
- MultiString: Separate with `\n`

### Access Denied
- Run with administrator privileges for HKLM
- Check registry key permissions