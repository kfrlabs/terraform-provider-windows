# windows_localgroup (Data Source)

Retrieves information about a local group on a Windows server.

## Example Usage

### Basic Group Query

```hcl
data "windows_localgroup" "admins" {
  name = "Administrators"
}

output "admin_group_description" {
  value = data.windows_localgroup.admins.description
}
```

### Query Custom Group

```hcl
data "windows_localgroup" "app_admins" {
  name = "Application Admins"
}

output "group_info" {
  value = {
    name        = data.windows_localgroup.app_admins.name
    description = data.windows_localgroup.app_admins.description
  }
}
```

### Use with Group Members Data Source

```hcl
data "windows_localgroup" "users" {
  name = "Users"
}

data "windows_localgroupmembers" "users_list" {
  group_name = data.windows_localgroup.users.name
}

output "users_count" {
  value = data.windows_localgroupmembers.users_list.member_count
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the local group to retrieve.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the group.
* `description` - A description of the local group.
* `sid` - The Security Identifier (SID) of the group.

## Common Local Groups

Here are some commonly used Windows local groups:

* `Administrators` - Full control of the computer
* `Users` - Standard users
* `Remote Desktop Users` - Users who can connect via Remote Desktop
* `Backup Operators` - Can backup and restore files
* `Power Users` - Users with some administrative permissions (legacy)
* `IIS_IUSRS` - Built-in group for IIS

## Error Handling

If the specified group does not exist, the data source will return an error.
