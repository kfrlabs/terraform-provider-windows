# Windows Registry Value Resource

Manages Windows registry values on a Windows server via SSH and PowerShell remote execution. This resource handles creation, modification, and deletion of registry values within existing registry keys.

## Table of Contents

1. [Example Usage](#example-usage)
2. [Argument Reference](#argument-reference)
3. [Attributes Reference](#attributes-reference)
4. [Registry Value Types](#registry-value-types)
5. [Advanced Examples](#advanced-examples)
6. [Import](#import)
7. [Troubleshooting](#troubleshooting)

---

## Example Usage

### Basic String Value

```hcl
resource "windows_registry_value" "example" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "ExampleValue"
  type  = "String"
  value = "Example"
}
```

### DWORD (Integer) Value

```hcl
resource "windows_registry_value" "example" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "MaxConnections"
  type  = "DWord"
  value = "100"
}
```

### With Custom Timeout

```hcl
resource "windows_registry_value" "example" {
  path            = "HKLM:\\Software\\MyApp"
  name            = "ExampleValue"
  type            = "String"
  value           = "Example"
  command_timeout = 300
}
```

---

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **path** | string | The registry key path where the value will be stored. Must start with a valid hive (HKLM, HKCU, HKCR, HKU, HKCC). Example: `HKLM:\\Software\\MyApp`. The key must already exist. |
| **name** | string | The name of the registry value to create or modify. Can contain spaces and special characters. The default value is named `(Default)`. |
| **type** | string | The data type of the registry value. Must be one of: `String`, `ExpandableString`, `Binary`, `DWord`, `MultiString`, or `QWord`. See [Registry Value Types](#registry-value-types) for details. |
| **value** | string | The data to store in the registry value. Format depends on the value type (see examples below). |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands executed on the remote server. Increase for large binary values or complex operations. |

---

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | Unique identifier combining path and value name (e.g., `HKLM:\Software\MyApp\ExampleValue`). |
| **exists** | bool | Whether the registry value currently exists on the system. |
| **previous_value** | string | The previous value before the change was applied. Useful for tracking modifications. |
| **value_kind** | string | The PowerShell value kind of the registry entry. |

---

## Registry Value Types

Windows registry supports several data types for values. Each type has specific formatting requirements:

### String (REG_SZ)

Standard text value. Can contain any characters including spaces.

```hcl
resource "windows_registry_value" "app_name" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "AppName"
  type  = "String"
  value = "My Application"
}
```

**Characteristics**:
- Variable length text
- Maximum size: 256 KB
- Can contain spaces and special characters
- Commonly used for application names, descriptions, paths

### ExpandableString (REG_EXPAND_SZ)

Text value that can contain environment variables that are expanded at runtime.

```hcl
resource "windows_registry_value" "path_value" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "InstallPath"
  type  = "ExpandableString"
  value = "%ProgramFiles%\\MyApp"
}
```

**Characteristics**:
- Text with environment variable references
- Variables use `%VARIABLE%` format
- Expanded when read by applications
- Common environment variables: `%ProgramFiles%`, `%SystemRoot%`, `%UserProfile%`

### Binary (REG_BINARY)

Raw binary data, typically represented as hexadecimal.

```hcl
resource "windows_registry_value" "binary_data" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "BinaryData"
  type  = "Binary"
  value = "48656C6C6F"  # "Hello" in hexadecimal
}
```

**Characteristics**:
- Hexadecimal representation (without spaces or 0x prefix)
- Used for complex data structures
- Maximum size: 1 MB
- Example: GUI settings, security certificates

### DWord (REG_DWORD)

32-bit unsigned integer value.

```hcl
resource "windows_registry_value" "max_connections" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "MaxConnections"
  type  = "DWord"
  value = "100"
}
```

**Characteristics**:
- Decimal number from 0 to 4,294,967,295
- Commonly used for configuration options
- Examples: timeout values, feature flags, counts
- Can also represent boolean (0 = false, 1 = true)

### QWord (REG_QWORD)

64-bit unsigned integer value.

```hcl
resource "windows_registry_value" "large_number" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "LargeValue"
  type  = "QWord"
  value = "9223372036854775807"
}
```

**Characteristics**:
- Decimal number from 0 to 18,446,744,073,709,551,615
- Used for large counters or file sizes
- Less common than DWord
- Requires 64-bit systems

### MultiString (REG_MULTI_SZ)

Multiple text strings stored as a single value.

```hcl
resource "windows_registry_value" "search_paths" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "SearchPaths"
  type  = "MultiString"
  value = "C:\\Path1\nC:\\Path2\nC:\\Path3"
}
```

**Characteristics**:
- Multiple strings separated by newlines (`\n`)
- Each string on its own line
- Maximum total size: 256 KB
- Used for path lists, server lists, etc.

---

## Advanced Examples

### Application Configuration Values

```hcl
# Create the application registry key first
resource "windows_registry_key" "app_config" {
  path  = "HKLM:\\Software\\MyApp"
  force = true
}

# Set application name
resource "windows_registry_value" "app_name" {
  path  = windows_registry_key.app_config.path
  name  = "AppName"
  type  = "String"
  value = "My Enterprise Application"

  depends_on = [windows_registry_key.app_config]
}

# Set installation path (expandable string)
resource "windows_registry_value" "install_path" {
  path  = windows_registry_key.app_config.path
  name  = "InstallPath"
  type  = "ExpandableString"
  value = "%ProgramFiles%\\MyApp"

  depends_on = [windows_registry_key.app_config]
}

# Set version number
resource "windows_registry_value" "version" {
  path  = windows_registry_key.app_config.path
  name  = "Version"
  type  = "String"
  value = "2.1.0"

  depends_on = [windows_registry_key.app_config]
}

# Enable feature (DWORD boolean)
resource "windows_registry_value" "feature_enabled" {
  path  = windows_registry_key.app_config.path
  name  = "FeatureEnabled"
  type  = "DWord"
  value = "1"

  depends_on = [windows_registry_key.app_config]
}
```

### Multiple Environment Configurations

```hcl
variable "environment" {
  type    = string
  default = "production"
}

variable "config_values" {
  type = map(object({
    debug_mode    = string
    max_threads   = string
    log_level     = string
  }))
  default = {
    development = {
      debug_mode  = "1"
      max_threads = "10"
      log_level   = "Debug"
    }
    production = {
      debug_mode  = "0"
      max_threads = "50"
      log_level   = "Error"
    }
  }
}

resource "windows_registry_key" "env_config" {
  path  = "HKLM:\\Software\\MyApp\\${var.environment}"
  force = true
}

resource "windows_registry_value" "debug_mode" {
  path  = windows_registry_key.env_config.path
  name  = "DebugMode"
  type  = "DWord"
  value = lookup(var.config_values[var.environment], "debug_mode", "0")

  depends_on = [windows_registry_key.env_config]
}

resource "windows_registry_value" "max_threads" {
  path  = windows_registry_key.env_config.path
  name  = "MaxThreads"
  type  = "DWord"
  value = lookup(var.config_values[var.environment], "max_threads", "10")

  depends_on = [windows_registry_key.env_config]
}

resource "windows_registry_value" "log_level" {
  path  = windows_registry_key.env_config.path
  name  = "LogLevel"
  type  = "String"
  value = lookup(var.config_values[var.environment], "log_level", "Info")

  depends_on = [windows_registry_key.env_config]
}
```

### Service Configuration

```hcl
resource "windows_registry_key" "service_config" {
  path  = "HKLM:\\Software\\MyCompany\\MyService"
  force = true
}

resource "windows_registry_value" "service_port" {
  path  = windows_registry_key.service_config.path
  name  = "Port"
  type  = "DWord"
  value = "8080"

  depends_on = [windows_registry_key.service_config]
}

resource "windows_registry_value" "service_host" {
  path  = windows_registry_key.service_config.path
  name  = "Host"
  type  = "String"
  value = "0.0.0.0"

  depends_on = [windows_registry_key.service_config]
}

resource "windows_registry_value" "service_timeout" {
  path  = windows_registry_key.service_config.path
  name  = "Timeout"
  type  = "DWord"
  value = "30000"  # 30 seconds

  depends_on = [windows_registry_key.service_config]
}

resource "windows_registry_value" "service_start_type" {
  path  = windows_registry_key.service_config.path
  name  = "StartType"
  type  = "String"
  value = "Automatic"

  depends_on = [windows_registry_key.service_config]
}
```

### Path List Configuration

```hcl
resource "windows_registry_key" "app_paths" {
  path  = "HKLM:\\Software\\MyApp"
  force = true
}

resource "windows_registry_value" "search_paths" {
  path  = windows_registry_key.app_paths.path
  name  = "SearchPaths"
  type  = "MultiString"
  value = "C:\\Program Files\\MyApp\\Plugins\nC:\\Program Files\\MyApp\\Extensions\nC:\\ProgramData\\MyApp\\Custom"

  depends_on = [windows_registry_key.app_paths]
}

resource "windows_registry_value" "log_paths" {
  path  = windows_registry_key.app_paths.path
  name  = "LogPaths"
  type  = "MultiString"
  value = "C:\\ProgramData\\MyApp\\Logs\n%TEMP%\\MyApp"

  depends_on = [windows_registry_key.app_paths]
}
```

### Conditional Registry Values

```hcl
variable "enable_advanced_features" {
  type    = bool
  default = false
}

resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyApp"
}

resource "windows_registry_value" "standard_setting" {
  path  = windows_registry_key.app_config.path
  name  = "StandardSetting"
  type  = "DWord"
  value = "1"

  depends_on = [windows_registry_key.app_config]
}

resource "windows_registry_value" "advanced_setting" {
  count = var.enable_advanced_features ? 1 : 0

  path  = windows_registry_key.app_config.path
  name  = "AdvancedFeature"
  type  = "String"
  value = "Enabled"

  depends_on = [windows_registry_key.app_config]
}
```

---

## Import

Registry values can be imported using the path and value name. This allows you to bring existing registry values under Terraform management.

### Import Syntax

```shell
terraform import windows_registry_value.<resource_name> "<path>\\<value_name>"
```

### Import Examples

Import a string value:

```shell
terraform import windows_registry_value.example "HKLM:\\Software\\MyApp\\ExampleValue"
```

Import a DWORD value:

```shell
terraform import windows_registry_value.max_connections "HKLM:\\Software\\MyApp\\MaxConnections"
```

Create the resource configuration:

```hcl
resource "windows_registry_value" "example" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "ExampleValue"
  type  = "String"
  value = ""
}
```

Then import the existing value:

```shell
terraform import windows_registry_value.example "HKLM:\\Software\\MyApp\\ExampleValue"
```

### Import Multiple Registry Values

Create resource definitions:

```hcl
resource "windows_registry_value" "app_name" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "AppName"
  type  = "String"
  value = ""
}

resource "windows_registry_value" "version" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "Version"
  type  = "String"
  value = ""
}

resource "windows_registry_value" "debug_mode" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "DebugMode"
  type  = "DWord"
  value = "0"
}
```

Import the existing values:

```shell
terraform import windows_registry_value.app_name "HKLM:\\Software\\MyApp\\AppName"
terraform import windows_registry_value.version "HKLM:\\Software\\MyApp\\Version"
terraform import windows_registry_value.debug_mode "HKLM:\\Software\\MyApp\\DebugMode"
```

---

## Troubleshooting

### Value Creation Fails

**Issue**: `failed to set registry value` or `registry value creation error`

**Solutions**:
- Verify the registry key exists (parent key must exist)
- Check registry path format uses double backslashes: `HKLM:\\Software\\MyApp`
- Ensure SSH user has administrator privileges
- Verify the value type is correct: String, DWord, Binary, etc.
- Test manually: `Get-ItemProperty -Path "Registry::HKLM\Software\MyApp" -Name "ValueName"`

### Access Denied

**Issue**: `access denied` or `permission denied` error

**Solutions**:
- Verify SSH user is in the Administrators group
- Check with: `whoami /groups | find "S-1-5-32-544"`
- Check registry key permissions: `regedit` → Right-click key → Permissions
- Some system values may not be modifiable
- For HKCU, ensure logged in as the correct user

### Registry Key Not Found

**Issue**: `parent key not found` or `key does not exist`

**Solutions**:
- Create the parent registry key first:
  ```hcl
  resource "windows_registry_key" "app" {
    path = "HKLM:\\Software\\MyApp"
  }

  resource "windows_registry_value" "setting" {
    path = windows_registry_key.app.path
    ...
  }
  ```
- Or verify key exists: `Test-Path "Registry::HKLM\Software\MyApp"`

### Type Mismatch

**Issue**: `type mismatch` or `invalid type` error

**Solutions**:
- Use correct type values: `String`, `DWord`, `Binary`, `MultiString`, `ExpandableString`, `QWord`
- Type names are case-sensitive in PowerShell
- Verify the value format matches the type:
  - DWord: decimal number (0-4294967295)
  - Binary: hexadecimal (no spaces or 0x prefix)
  - MultiString: strings separated by `\n`

### Invalid Value Format

**Issue**: `invalid value format` or `could not parse value`

**Solutions**:
- DWord values must be decimal numbers, not hexadecimal
- Binary values must be hexadecimal without `0x` prefix: `48656C6C6F` not `0x48656C6C6F`
- MultiString values use `\n` to separate: `"Line1\nLine2\nLine3"`
- String values can contain any characters
- Check for encoding issues with special characters

### Value Too Large

**Issue**: `value too large` or `data too large for registry`

**Solutions**:
- String and ExpandableString: max 256 KB
- Binary: max 1 MB
- MultiString: max 256 KB total
- Split large data across multiple values if needed
- For large configs, consider using external configuration files

### SSH Connection Issues

**Issue**: Connection timeout or SSH error

**Solutions**:
- Increase `command_timeout` to allow more time
- Check network connectivity: `ping server-ip`
- Verify SSH credentials
- Test manually: `ssh admin@server-ip`

### State Mismatch

**Issue**: Registry value exists but Terraform state says it doesn't

**Solutions**:
- Manually modified registry value outside Terraform
- Run `terraform refresh` to update state
- Or remove and re-import: `terraform state rm windows_registry_value.example`
- Always use Terraform to manage registry values

### Value Not Updated

**Issue**: `terraform apply` completes but registry value doesn't change

**Solutions**:
- Application may cache registry values; restart the application
- Some values require a system restart to take effect
- Verify the value actually changed: `Get-ItemProperty -Path "Registry::HKLM\Software\MyApp" -Name "ValueName"`
- Check for Group Policy overrides

### Special Characters in Value Name

**Issue**: Value name contains spaces or special characters

**Solutions**:
- Spaces and special characters in value names are supported
- Enclose in quotes if needed: `name = "My Value Name"`
- Verify with: `Get-ItemProperty -Path "Registry::HKLM\Software\MyApp"`

---

## Best Practices

### Always Create Parent Keys First