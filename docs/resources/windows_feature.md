# Windows Feature

## Example Usage

```hcl
resource "windows_feature" "example" {
  feature                   = "Web-Server"
  restart                   = true
  include_all_sub_features  = true
  include_management_tools  = true
  command_timeout           = 300
}
```

## Argument Reference

- **feature** (Required) - The Windows feature to install or remove.
- **restart** (Optional) - Whether to restart the server automatically if needed.
- **include_all_sub_features** (Optional) - Whether to include all sub-features of the specified feature.
- **include_management_tools** (Optional) - Whether to include management tools for the specified feature.
- **command_timeout** (Optional) - Timeout in seconds for PowerShell commands.

## Import

Windows features can be imported using the `feature` name, e.g.

```shell
$ terraform import windows_feature.example Web-Server
``` 