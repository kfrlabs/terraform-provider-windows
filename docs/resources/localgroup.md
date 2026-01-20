# windows_localgroup

Manages local groups on Windows servers.

## Example Usage

### Basic Group Creation

```hcl
resource "windows_localgroup" "app_admins" {
  name        = "Application Admins"
  description = "Administrators for the application"
}
```

### Group with Members

```hcl
resource "windows_localgroup" "db_operators" {
  name        = "Database Operators"
  description = "Operators for database management"
}

resource "windows_localuser" "db_admin" {
  username = "DBAdmin"
  password = var.db_admin_password
}

resource "windows_localgroupmember" "db_admin_membership" {
  group  = windows_localgroup.db_operators.name
  member = windows_localuser.db_admin.username
}
```

### Adopt Existing Group

```hcl
resource "windows_localgroup" "existing_group" {
  name           = "Remote Desktop Users"
  allow_existing = true
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required, Forces new resource) The name of the local group. Cannot be changed after creation.
* `description` - (Optional) A description for the local group. Can be updated after creation.
* `allow_existing` - (Optional) If `true`, adopt existing group instead of failing. If `false`, fail if group already exists. Defaults to `false`.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300` (5 minutes).

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the local group.

## Import

Local groups can be imported using the group name:

```shell
terraform import windows_localgroup.app_admins "Application Admins"
```

## Behavior Notes

### Existing Group Handling

When creating a group resource:
- If the group **does not exist**, it will be created normally.
- If the group **already exists**:
  - With `allow_existing = false` (default): Resource creation fails with error message suggesting import or setting `allow_existing = true`.
  - With `allow_existing = true`: The existing group is adopted into Terraform state. The description will be updated to match the configuration.

### Description Updates

The `description` attribute can be updated after group creation. When you change the description in your configuration and apply, Terraform will update the group's description on the Windows system without recreating the group.

### Built-in Groups

Windows has several built-in local groups. You can manage these using `allow_existing = true`:

- **Administrators** - Full control of the computer
- **Users** - Standard users with limited privileges
- **Remote Desktop Users** - Users who can connect via RDP
- **Backup Operators** - Can backup and restore files
- **Power Users** - Legacy group with some administrative permissions
- **IIS_IUSRS** - Built-in group for IIS
- **Performance Monitor Users** - Can monitor performance counters
- **Event Log Readers** - Can read event logs

**Warning:** Be cautious when managing built-in groups, as changing their configuration could affect system functionality.

### Deletion Behavior

When a group resource is deleted:
- The group is removed from the Windows system using `Remove-LocalGroup`
- All members are automatically removed from the group
- If the group is a built-in group, deletion may fail (as built-in groups cannot be deleted)

## Complete Example

```hcl
# Create custom local group for application management
resource "windows_localgroup" "app_team" {
  name        = "AppTeam"
  description = "Application development and operations team"
}

# Create multiple users
resource "windows_localuser" "dev1" {
  username = "DevUser1"
  password = var.dev1_password
  full_name = "Developer One"
}

resource "windows_localuser" "dev2" {
  username = "DevUser2"
  password = var.dev2_password
  full_name = "Developer Two"
}

# Add users to the group
resource "windows_localgroupmember" "dev1_membership" {
  group  = windows_localgroup.app_team.name
  member = windows_localuser.dev1.username
}

resource "windows_localgroupmember" "dev2_membership" {
  group  = windows_localgroup.app_team.name
  member = windows_localuser.dev2.username
}

# Grant group access to another built-in group
resource "windows_localgroupmember" "app_team_rdp" {
  group  = "Remote Desktop Users"
  member = windows_localgroup.app_team.name
}
```

## Managing Built-in Groups

```hcl
# Adopt existing built-in group for management
resource "windows_localgroup" "rdp_users" {
  name           = "Remote Desktop Users"
  description    = "Managed by Terraform - Users who can connect via RDP"
  allow_existing = true
}

# Now you can manage membership of this group
resource "windows_localgroupmember" "rdp_access" {
  group  = windows_localgroup.rdp_users.name
  member = "AppUser"
}
```

## Common Use Cases

### Application Access Groups

```hcl
resource "windows_localgroup" "app_users" {
  name        = "MyApp Users"
  description = "Users with access to MyApp"
}

resource "windows_localgroup" "app_admins" {
  name        = "MyApp Admins"
  description = "Administrators for MyApp"
}
```

### Environment-Specific Groups

```hcl
variable "environment" {
  type = string
}

resource "windows_localgroup" "app_group" {
  name        = "MyApp-${var.environment}"
  description = "MyApp access for ${var.environment} environment"
}
```

### Hierarchical Access Control

```hcl
# Create role-based groups
resource "windows_localgroup" "operators" {
  name        = "Operators"
  description = "System operators with limited admin access"
}

resource "windows_localgroup" "developers" {
  name        = "Developers"
  description = "Application developers"
}

# Grant operators administrative access
resource "windows_localgroupmember" "operators_admin" {
  group  = "Administrators"
  member = windows_localgroup.operators.name
}

# Grant developers RDP access only
resource "windows_localgroupmember" "developers_rdp" {
  group  = "Remote Desktop Users"
  member = windows_localgroup.developers.name
}
```