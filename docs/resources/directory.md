---
page_title: "windows_directory Resource - windows"
subcategory: ""
description: |-
  Manages a directory on a remote Windows host over SSH and PowerShell.
---

# windows_directory (Resource)

Manages a directory on a remote Windows host over SSH and PowerShell. The resource creates the directory, optionally creates missing parents, manages directory attributes, and removes it on destroy.

## Example Usage

```terraform
resource "windows_directory" "application" {
  path            = "C:\\ProgramData\\Example\\Application"
  create_parents  = true
  attributes      = ["archive"]
  recursive_delete = true
}
```

## Argument Reference

* `path` (Required) is the absolute Windows path of the directory. Changing it replaces the resource.
* `create_parents` (Optional, default `true`) creates missing parent directories.
* `attributes` (Optional) manages the directory attributes `archive`, `hidden`, `readonly`, `system`, and `temporary`.
* `recursive_delete` (Optional, default `false`) removes all contents during destroy. When false, destroy fails rather than deleting files that the resource does not own.

## Attribute Reference

* `id` is the managed absolute path.
* `last_write_time` is the last write time reported by the target host in UTC.

## Import

Import an existing directory by its absolute Windows path:

```shell
terraform import windows_directory.application 'C:\ProgramData\Example\Application'
```
