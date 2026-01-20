# windows_localgroupmember

Manages membership of a user or group in a local Windows group.

## Example Usage

### Add User to Administrators Group

```hcl
resource "windows_localgroupmember" "admin_user" {
  group  = "Administrators"
  member = "AppAdmin"
}
```

### Add Domain User to Local Group

```hcl
resource "windows_localgroupmember" "domain_admin" {
  group  = "Administrators"
  member = "DOMAIN\\JohnDoe"
}
```

### Add User to Remote Desktop Users

```hcl
resource "windows_localgroupmember" "rdp_access" {
  group  = "Remote Desktop Users"
  member = "AppUser"
}
```

### Add Multiple Users to a Group

```hcl
variable "admin_users" {
  type    = list(string)
  default = ["User1", "User2", "User3"]
}

resource "windows_localgroupmember" "admins" {
  for_each = toset(var.admin_users)
  
  group  = "Administrators"
  member = each.value
}
```

### Add User with Dependencies

```hcl
resource "windows_localuser" "app_user" {
  username = "AppServiceAccount"
  password = var.app_password
}

resource "windows_localgroupmember" "app_user_admins" {
  group  = "Administrators"
  member = windows_localuser.app_user.username
}
```

### Add Service Account to IIS Group

```hcl
resource "windows_localuser" "iis_user" {
  username                    = "IISAppPoolUser"
  password                    = var.iis_password
  password_never_expires      = true
  user_cannot_change_password = true
}

resource "windows_localgroupmember" "iis_users" {
  group  = "IIS_IUSRS"
  member = windows_localuser.iis_user.username
}
```

## Argument Reference

The following arguments are supported:

* `group` - (Required) The name of the local group (e.g., `Administrators`, `Users`, `Remote Desktop Users`). Changing this forces a new resource to be created.
* `member` - (Required) The name of the member to add to the group. Can be a local user, domain user (format: `DOMAIN\User`), or another group. Changing this forces a new resource to be created.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`. Changing this forces a new resource to be created.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The resource ID in the format `group/member`.

## Import

Local group membership can be imported using the `group/member` format:

```shell
terraform import windows_localgroupmember.example "Administrators/AppUser"
```

For domain users, use the full domain\user format:

```shell
terraform import windows_localgroupmember.domain_user "Administrators/DOMAIN\\User"
```

## Notes

* If the member is already in the group when the resource is created, Terraform will adopt the existing membership rather than failing.
* The member name comparison is case-insensitive and handles computer name prefixes automatically (e.g., `COMPUTERNAME\User` matches `User`).
* For domain users, you can specify with or without the domain prefix. The provider will match correctly either way.

## Common Local Groups

Here are some commonly used Windows local groups:

* `Administrators` - Full control of the computer
* `Users` - Standard users
* `Remote Desktop Users` - Users who can connect via Remote Desktop
* `Backup Operators` - Can backup and restore files
* `Power Users` - Users with some administrative permissions (legacy)
* `IIS_IUSRS` - Built-in group for IIS application pools
* `Performance Monitor Users` - Can monitor performance counters
* `Event Log Readers` - Can read event logs

## Example: Complete User Setup

```hcl
# Create a service account
resource "windows_localuser" "service_account" {
  username                    = "MyServiceAccount"
  password                    = var.service_password
  full_name                   = "My Application Service Account"
  description                 = "Service account for MyApp"
  password_never_expires      = true
  user_cannot_change_password = true
}

# Add to IIS users group
resource "windows_localgroupmember" "iis_membership" {
  group  = "IIS_IUSRS"
  member = windows_localuser.service_account.username
}

# Add to Performance Monitor Users for monitoring
resource "windows_localgroupmember" "perfmon_membership" {
  group  = "Performance Monitor Users"
  member = windows_localuser.service_account.username
}
```
