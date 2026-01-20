# windows_registry_value (Data Source)

Retrieves a value from the Windows Registry.

## Example Usage

### Read String Value

```hcl
data "windows_registry_value" "app_name" {
  path = "HKLM:\\Software\\MyCompany\\MyApp"
  name = "ApplicationName"
}

output "app_name" {
  value = data.windows_registry_value.app_name.value
}
```

### Read Default Value

```hcl
data "windows_registry_value" "default_value" {
  path = "HKLM:\\Software\\MyApp"
  name = ""  # Empty string for default value
}

output "default" {
  value = data.windows_registry_value.default_value.value
}
```

### Query Multiple Values

```hcl
data "windows_registry_value" "version" {
  path = "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion"
  name = "CurrentVersion"
}

data "windows_registry_value" "build" {
  path = "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion"
  name = "CurrentBuild"
}

output "windows_version" {
  value = "${data.windows_registry_value.version.value}.${data.windows_registry_value.build.value}"
}
```

### Use in Resource Configuration

```hcl
data "windows_registry_value" "install_path" {
  path = "HKLM:\\Software\\MyApp"
  name = "InstallPath"
}

resource "windows_registry_value" "data_path" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "DataPath"
  value = "${data.windows_registry_value.install_path.value}\\Data"
  type  = "String"
}
```

### Check Registry Value Type

```hcl
data "windows_registry_value" "config" {
  path = "HKLM:\\Software\\MyApp"
  name = "Config"
}

output "config_info" {
  value = {
    value = data.windows_registry_value.config.value
    type  = data.windows_registry_value.config.type
  }
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) The path to the registry key (e.g., `HKLM:\\Software\\MyApp`, `HKCU:\\Software\\MyApp`).
* `name` - (Optional) The name of the registry value. Use an empty string `""` for the default value. Defaults to `""`.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The full path including the value name (format: `path\name`).
* `value` - The value stored in the registry (converted to string).
* `type` - The type of the registry value. Possible values:
  * `String` - REG_SZ
  * `ExpandString` - REG_EXPAND_SZ
  * `Binary` - REG_BINARY
  * `DWord` - REG_DWORD
  * `MultiString` - REG_MULTI_SZ
  * `QWord` - REG_QWORD
  * `Unknown` - Unknown type

## Registry Hive Shortcuts

The following registry hive shortcuts are supported:

* `HKLM:` - HKEY_LOCAL_MACHINE
* `HKCU:` - HKEY_CURRENT_USER
* `HKCR:` - HKEY_CLASSES_ROOT
* `HKU:` - HKEY_USERS
* `HKCC:` - HKEY_CURRENT_CONFIG

## Notes

* The registry path must use PowerShell drive notation (e.g., `HKLM:\\` not `HKEY_LOCAL_MACHINE\`).
* All values are returned as strings. For DWord and QWord values, the numeric value is converted to a string.
* Binary values are returned as a space-separated string of hexadecimal bytes.
* MultiString values are returned as a newline-separated string.

## Error Handling

If the registry key or value does not exist, the data source will return an error. Ensure the path and value name are correct before querying.

## Example: Reading Windows Version

```hcl
data "windows_registry_value" "product_name" {
  path = "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion"
  name = "ProductName"
}

data "windows_registry_value" "current_build" {
  path = "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion"
  name = "CurrentBuild"
}

output "windows_info" {
  value = "${data.windows_registry_value.product_name.value} (Build ${data.windows_registry_value.current_build.value})"
}
```
