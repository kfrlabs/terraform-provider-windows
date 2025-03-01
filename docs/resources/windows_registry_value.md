# Windows Registry Value

## Example Usage

```hcl
resource "windows_registry_value" "example" {
  path            = "HKLM:\\Software\\MyApp"
  name            = "ExampleValue"
  type            = "String"
  value           = "Example"
  command_timeout = 300
}
```

## Argument Reference

- **path** (Required) - The path to the registry key (e.g., 'HKLM:\Software\MyApp').
- **name** (Optional) - The name of the registry value.
- **type** (Optional) - The type of the registry value (e.g., 'String', 'DWord', 'Binary').
- **value** (Optional) - The value to set in the registry.
- **command_timeout** (Optional) - Timeout in seconds for PowerShell commands.

## Import

Registry values can be imported using the `path` and `name`, e.g.

```shell
$ terraform import windows_registry_value.example HKLM:\\Software\\MyApp\\ExampleValue
``` 