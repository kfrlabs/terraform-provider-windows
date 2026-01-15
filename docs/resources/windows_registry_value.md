# windows_registry_value

Manages Windows Registry values within registry keys.

## Example Usage

### String Value

```hcl
resource "windows_registry_value" "app_name" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  name  = "ApplicationName"
  type  = "String"
  value = "My Application"
}
```

### DWORD Value

```hcl
resource "windows_registry_value" "port" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  name  = "Port"
  type  = "DWord"
  value = "8080"
}
```

### Binary Value

```hcl
resource "windows_registry_value" "license_key" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  name  = "LicenseKey"
  type  = "Binary"
  value = "01020304"
}
```

### ExpandString Value (Environment Variables)

```hcl
resource "windows_registry_value" "install_path" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  name  = "InstallPath"
  type  = "ExpandString"
  value = "%ProgramFiles%\\MyApp"
}
```

### MultiString Value

```hcl
resource "windows_registry_value" "search_paths" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  name  = "SearchPaths"
  type  = "MultiString"
  value = "C:\\Path1\nC:\\Path2\nC:\\Path3"
}
```

### QWORD Value (64-bit)

```hcl
resource "windows_registry_value" "max_size" {
  path  = "HKLM:\\Software\\MyCompany\\MyApp"
  name  = "MaxSize"
  type  = "Qword"
  value = "9223372036854775807"
}
```

### Complete Application Configuration

```hcl
# Create the registry key first
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
}

# Application name
resource "windows_registry_value" "app_name" {
  path  = windows_registry_key.app.path
  name  = "AppName"
  type  = "String"
  value = "My Application"
  
  depends_on = [windows_registry_key.app]
}

# Version number
resource "windows_registry_value" "version" {
  path  = windows_registry_key.app.path
  name  = "Version"
  type  = "String"
  value = "1.0.0"
  
  depends_on = [windows_registry_key.app]
}

# Port number
resource "windows_registry_value" "port" {
  path  = windows_registry_key.app.path
  name  = "Port"
  type  = "DWord"
  value = "8080"
  
  depends_on = [windows_registry_key.app]
}

# Enable feature flag
resource "windows_registry_value" "enabled" {
  path  = windows_registry_key.app.path
  name  = "Enabled"
  type  = "DWord"
  value = "1"
  
  depends_on = [windows_registry_key.app]
}

# Install location
resource "windows_registry_value" "install_dir" {
  path  = windows_registry_key.app.path
  name  = "InstallDirectory"
  type  = "ExpandString"
  value = "%ProgramFiles%\\MyCompany\\MyApp"
  
  depends_on = [windows_registry_key.app]
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required, String, ForceNew) The full path to the parent registry key using PowerShell notation (e.g., `HKLM:\Software\MyApp`). Changing this will force recreation.

* `name` - (Optional, String, ForceNew) The name of the registry value. If not specified or empty, creates the default value `(Default)` for the key. Changing this will force recreation.

* `type` - (Optional, String, ForceNew) The type of the registry value. Default: `"String"`. Valid values:
  - `"String"` - Text string (REG_SZ)
  - `"ExpandString"` - Expandable text string with environment variables (REG_EXPAND_SZ)
  - `"Binary"` - Binary data (REG_BINARY)
  - `"DWord"` - 32-bit number (REG_DWORD)
  - `"MultiString"` - Multiple text strings (REG_MULTI_SZ)
  - `"Qword"` - 64-bit number (REG_QWORD)
  - `"Unknown"` - Unknown type (REG_NONE)

* `value` - (Optional, String) The value to set in the registry. Format depends on the type (see below).

* `command_timeout` - (Optional, Number) Timeout in seconds for PowerShell commands. Default: `300` (5 minutes).

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - Unique identifier in format `{path}\{name}` (e.g., `HKLM:\Software\MyApp\Version`).

## Import

Registry values can be imported using the path and name:

```bash
# Named value
terraform import windows_registry_value.port "HKLM:\\Software\\MyApp\\Port"

# Default value
terraform import windows_registry_value.default "HKLM:\\Software\\MyApp\\"
```

## Registry Value Types

### String (REG_SZ)

Standard text string.

```hcl
resource "windows_registry_value" "company_name" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "CompanyName"
  type  = "String"
  value = "My Company Inc."
}
```

**Use cases**:
- Application names
- Company names
- File paths (fixed)
- Configuration text

### ExpandString (REG_EXPAND_SZ)

Text string that can contain environment variables. Windows will expand these variables when reading the value.

```hcl
resource "windows_registry_value" "data_dir" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "DataDirectory"
  type  = "ExpandString"
  value = "%APPDATA%\\MyApp\\Data"
}

resource "windows_registry_value" "log_file" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "LogFile"
  type  = "ExpandString"
  value = "%SystemRoot%\\Logs\\myapp.log"
}
```

**Common environment variables**:
- `%ProgramFiles%` - C:\Program Files
- `%ProgramFiles(x86)%` - C:\Program Files (x86)
- `%SystemRoot%` - C:\Windows
- `%APPDATA%` - User's AppData\Roaming
- `%LOCALAPPDATA%` - User's AppData\Local
- `%TEMP%` - Temporary folder
- `%USERNAME%` - Current username
- `%COMPUTERNAME%` - Computer name

### DWord (REG_DWORD)

32-bit unsigned integer (0 to 4,294,967,295).

```hcl
# Boolean flag (0 = false, 1 = true)
resource "windows_registry_value" "enabled" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "Enabled"
  type  = "DWord"
  value = "1"
}

# Port number
resource "windows_registry_value" "port" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "Port"
  type  = "DWord"
  value = "8080"
}

# Timeout in seconds
resource "windows_registry_value" "timeout" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "TimeoutSeconds"
  type  = "DWord"
  value = "300"
}
```

**Use cases**:
- Boolean flags (0/1)
- Port numbers
- Timeouts
- Counters
- Enumeration values

### Qword (REG_QWORD)

64-bit unsigned integer (0 to 18,446,744,073,709,551,615).

```hcl
# Large file size limit (in bytes)
resource "windows_registry_value" "max_file_size" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "MaxFileSize"
  type  = "Qword"
  value = "10737418240"  # 10 GB
}

# Large counter
resource "windows_registry_value" "request_count" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "TotalRequests"
  type  = "Qword"
  value = "9223372036854775807"
}
```

**Use cases**:
- Large numbers
- File sizes
- Memory sizes
- Large counters

### Binary (REG_BINARY)

Binary data in hexadecimal format.

```hcl
# License key
resource "windows_registry_value" "license" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "License"
  type  = "Binary"
  value = "0102030405060708"
}

# Configuration blob
resource "windows_registry_value" "config_blob" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "ConfigBlob"
  type  = "Binary"
  value = "DEADBEEF"
}
```

**Format**: Hexadecimal string (each byte as 2 hex digits)
- `"01"` = byte with value 1
- `"FF"` = byte with value 255
- `"0102030405"` = 5 bytes

**Use cases**:
- License keys
- Encrypted data
- Binary configuration
- Certificates

### MultiString (REG_MULTI_SZ)

Multiple text strings, separated by newlines in Terraform.

```hcl
resource "windows_registry_value" "search_paths" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "SearchPaths"
  type  = "MultiString"
  value = "C:\\Path1\nC:\\Path2\nC:\\Path3"
}

resource "windows_registry_value" "allowed_users" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "AllowedUsers"
  type  = "MultiString"
  value = "CONTOSO\\User1\nCONTOSO\\User2\nCONTOSO\\User3"
}
```

**Format**: Separate each string with `\n` (newline)

**Use cases**:
- Search paths
- User lists
- Multiple configuration values
- Plugin lists

### Unknown (REG_NONE)

Empty or unknown type. Rarely used.

```hcl
resource "windows_registry_value" "placeholder" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "Placeholder"
  type  = "Unknown"
  value = ""
}
```

## Default Value

The default value (unnamed value) in a registry key can be set by omitting the `name` argument:

```hcl
resource "windows_registry_value" "default" {
  path  = "HKLU:\\Software\\MyApp"
  type  = "String"
  value = "Default value text"
  # No 'name' argument = default value
}
```

In the registry editor, this appears as `(Default)`.

## Common Use Cases

### Application Settings

```hcl
resource "windows_registry_key" "app_settings" {
  path = "HKLM:\\Software\\MyApp\\Settings"
}

resource "windows_registry_value" "server_url" {
  path  = windows_registry_key.app_settings.path
  name  = "ServerURL"
  type  = "String"
  value = "https://api.example.com"
  depends_on = [windows_registry_key.app_settings]
}

resource "windows_registry_value" "retry_count" {
  path  = windows_registry_key.app_settings.path
  name  = "RetryCount"
  type  = "DWord"
  value = "3"
  depends_on = [windows_registry_key.app_settings]
}

resource "windows_registry_value" "use_ssl" {
  path  = windows_registry_key.app_settings.path
  name  = "UseSSL"
  type  = "DWord"
  value = "1"
  depends_on = [windows_registry_key.app_settings]
}
```

### Windows Service Configuration

```hcl
resource "windows_registry_key" "service_params" {
  path = "HKLM:\\System\\CurrentControlSet\\Services\\MyService\\Parameters"
  force = true
}

resource "windows_registry_value" "service_port" {
  path  = windows_registry_key.service_params.path
  name  = "Port"
  type  = "DWord"
  value = "9000"
  depends_on = [windows_registry_key.service_params]
}

resource "windows_registry_value" "service_data_dir" {
  path  = windows_registry_key.service_params.path
  name  = "DataDirectory"
  type  = "ExpandString"
  value = "%ProgramData%\\MyService\\Data"
  depends_on = [windows_registry_key.service_params]
}
```

### Uninstall Information

```hcl
resource "windows_registry_key" "uninstall" {
  path = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MyApp"
}

resource "windows_registry_value" "display_name" {
  path  = windows_registry_key.uninstall.path
  name  = "DisplayName"
  type  = "String"
  value = "My Application"
  depends_on = [windows_registry_key.uninstall]
}

resource "windows_registry_value" "display_version" {
  path  = windows_registry_key.uninstall.path
  name  = "DisplayVersion"
  type  = "String"
  value = "1.0.0"
  depends_on = [windows_registry_key.uninstall]
}

resource "windows_registry_value" "publisher" {
  path  = windows_registry_key.uninstall.path
  name  = "Publisher"
  type  = "String"
  value = "My Company"
  depends_on = [windows_registry_key.uninstall]
}

resource "windows_registry_value" "install_location" {
  path  = windows_registry_key.uninstall.path
  name  = "InstallLocation"
  type  = "String"
  value = "C:\\Program Files\\MyApp"
  depends_on = [windows_registry_key.uninstall]
}

resource "windows_registry_value" "uninstall_string" {
  path  = windows_registry_key.uninstall.path
  name  = "UninstallString"
  type  = "String"
  value = "C:\\Program Files\\MyApp\\uninstall.exe"
  depends_on = [windows_registry_key.uninstall]
}
```

### Feature Flags

```hcl
locals {
  features = {
    "EnableLogging"      = "1"
    "EnableMetrics"      = "1"
    "EnableDebugMode"    = "0"
    "MaxConnections"     = "100"
  }
}

resource "windows_registry_key" "features" {
  path = "HKLM:\\Software\\MyApp\\Features"
}

resource "windows_registry_value" "feature_flags" {
  for_each = local.features
  
  path  = windows_registry_key.features.path
  name  = each.key
  type  = "DWord"
  value = each.value
  
  depends_on = [windows_registry_key.features]
}
```

## Dynamic Configuration

### From Variables

```hcl
variable "app_config" {
  type = map(string)
  default = {
    "ServerURL"  = "https://api.example.com"
    "APIKey"     = "secret-key-123"
    "Timeout"    = "30"
  }
}

resource "windows_registry_key" "config" {
  path = "HKLM:\\Software\\MyApp\\Config"
}

resource "windows_registry_value" "config_values" {
  for_each = var.app_config
  
  path  = windows_registry_key.config.path
  name  = each.key
  type  = "String"
  value = each.value
  
  depends_on = [windows_registry_key.config]
}
```

### Environment-Specific

```hcl
variable "environment" {
  default = "production"
}

locals {
  config_by_env = {
    development = {
      port     = "8080"
      log_level = "debug"
    }
    production = {
      port     = "443"
      log_level = "info"
    }
  }
  config = local.config_by_env[var.environment]
}

resource "windows_registry_value" "port" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "Port"
  type  = "DWord"
  value = local.config.port
}

resource "windows_registry_value" "log_level" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "LogLevel"
  type  = "String"
  value = local.config.log_level
}
```

## Security Considerations

### Sensitive Values

Mark sensitive registry values:

```hcl
variable "api_key" {
  type      = string
  sensitive = true
}

resource "windows_registry_value" "api_key" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "APIKey"
  type  = "String"
  value = var.api_key
}
```

### Permissions

The SSH user needs:
- **Read** permission to check current value
- **Write** permission to create/update value
- **Delete** permission to remove value

For HKLM keys, administrator privileges are required.

### Sensitive Keys

Be cautious with these registry areas:

```hcl
# Security settings
"HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

# Credentials (avoid storing passwords in plain text)
"HKLM:\\Software\\MyApp\\Credentials"

# System configuration
"HKLM:\\System\\CurrentControlSet\\Control"
```

## Troubleshooting

### Permission Denied

**Issue**: Access denied when creating/modifying value

**Solution**:
- Ensure SSH user has administrator rights (for HKLM)
- Check registry key permissions in `regedit`
- Verify the parent key exists and is writable

### Key Does Not Exist

**Issue**: Cannot create value because parent key doesn't exist

**Solution**:
- Create the key first with `windows_registry_key`
- Use `depends_on` to enforce order
```hcl
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_value" "setting" {
  path  = windows_registry_key.app.path
  name  = "Setting"
  type  = "String"
  value = "value"
  depends_on = [windows_registry_key.app]
}
```

### Invalid Type

**Issue**: Type validation error

**Solution**:
- Use one of the valid types: String, ExpandString, Binary, DWord, MultiString, Qword, Unknown
- Check spelling and capitalization

### Value Format Error

**Issue**: Value doesn't match type format

**Solution**:
- **DWord/Qword**: Use numeric string ("123" not "abc")
- **Binary**: Use hex string ("DEADBEEF")
- **MultiString**: Separate strings with `\n`

## Best Practices

### Organization

```hcl
# Group related values under subkeys
HKLM:\Software\MyApp\Database
HKLM:\Software\MyApp\Logging
HKLM:\Software\MyApp\Security
```

### Naming

```hcl
# Use descriptive names
"DatabaseConnectionString"  # Good
"DBConn"                   # Less clear

# Use PascalCase or camelCase consistently
"LogLevel" or "logLevel"
```

### Dependencies

```hcl
# Always ensure key exists before creating values
resource "windows_registry_key" "app" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_value" "setting" {
  path       = windows_registry_key.app.path
  depends_on = [windows_registry_key.app]
  # ...
}
```

### Documentation

```hcl
resource "windows_registry_value" "timeout" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "ConnectionTimeout"
  type  = "DWord"
  value = "30"
  
  # Purpose: Connection timeout in seconds
  # Default: 30 seconds
  # Valid range: 5-300 seconds
}
```

## Notes

- Value names are case-insensitive in Windows
- Maximum value name length: 16,383 characters
- Maximum value data size varies by type
- Empty string values are valid
- The default (unnamed) value is valid and commonly used
- Terraform stores the value in state (sensitive values are encrypted)

## Related Resources

- `windows_registry_key` - Create the parent key first
- Always create keys before creating values within them
- Use both resources together for complete registry configuration
