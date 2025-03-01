# Windows Registry Key

## Example Usage

```hcl
resource "windows_registry_key" "example" {
  path            = "HKLM:\\Software\\MyApp"
  force           = true
  command_timeout = 300
}
```

## Argument Reference

- **path** (Required) - The path to the registry key (e.g., 'HKLM:\Software\MyApp').
- **force** (Optional) - Whether to force the creation of parent keys if they do not exist.
- **command_timeout** (Optional) - Timeout in seconds for PowerShell commands.

## Import

Registry keys can be imported using the `path`, e.g.

```shell
$ terraform import windows_registry_key.example HKLM:\\Software\\MyApp
``` 