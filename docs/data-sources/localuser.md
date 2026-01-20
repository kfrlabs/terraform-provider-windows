# windows_localuser (Data Source)

Retrieves information about a local user account on a Windows server.

## Example Usage

### Basic User Query

```hcl
data "windows_localuser" "admin" {
  username = "Administrator"
}

output "admin_enabled" {
  value = data.windows_localuser.admin.enabled
}
```

### Query Multiple Users

```hcl
data "windows_localuser" "app_user" {
  username = "AppServiceAccount"
}

output "user_info" {
  value = {
    full_name               = data.windows_localuser.app_user.full_name
    description             = data.windows_localuser.app_user.description
    enabled                 = data.windows_localuser.app_user.enabled
    password_never_expires  = data.windows_localuser.app_user.password_never_expires
  }
}
```

### Conditional Logic Based on User

```hcl
data "windows_localuser" "test_user" {
  username = "TestUser"
}

resource "windows_localgroupmember" "add_to_admins" {
  count = data.windows_localuser.test_user.enabled ? 1 : 0
  
  group  = "Administrators"
  member = data.windows_localuser.test_user.username
}
```

## Argument Reference

The following arguments are supported:

* `username` - (Required) The name of the local user account to retrieve.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The username.
* `full_name` - The full name of the user.
* `description` - A description of the user account.
* `password_never_expires` - Whether the password never expires (boolean).
* `user_cannot_change_password` - Whether the user cannot change their password (boolean).
* `enabled` - Whether the account is enabled (boolean).
* `password_changeable_date` - Date when the password can be changed.
* `password_expires` - Date when the password expires.
* `last_logon` - Last logon time.

## Error Handling

If the specified user does not exist, the data source will return an error. Ensure the user exists before querying, or handle the error appropriately in your Terraform configuration.
