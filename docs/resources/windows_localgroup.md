# Windows Local Group Resource

Manages local groups on a Windows server via SSH and PowerShell remote execution. This resource handles creation, modification, and deletion of local groups with support for group membership management.

## Table of Contents

1. [Example Usage](#example-usage)
2. [Argument Reference](#argument-reference)
3. [Attributes Reference](#attributes-reference)
4. [Common Local Groups](#common-local-groups)
5. [Advanced Examples](#advanced-examples)
6. [Import](#import)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## Example Usage

### Basic Usage

```hcl
resource "windows_localgroup" "example" {
  name = "MyAppUsers"
}
```

### Group with Description

```hcl
resource "windows_localgroup" "example" {
  name        = "MyAppUsers"
  description = "Users for MyApp application"
}
```

### Group with Members

```hcl
resource "windows_localgroup" "app_admins" {
  name        = "AppAdministrators"
  description = "Administrators for MyApp"
  members     = ["admin_user", "manager_user"]
}
```

### Group with Dynamic Members

```hcl
resource "windows_localgroup" "app_users" {
  name        = "AppUsers"
  description = "Application users"
  members = [
    windows_localuser.app_user1.username,
    windows_localuser.app_user2.username,
    "BUILTIN\\Users"
  ]
}
```

---

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **name** | string | The name of the local group to create or manage. Must be unique on the system. Maximum 256 characters. Group names cannot contain only periods or spaces. |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **description** | string | empty | A description or comment for the local group. Useful for documenting the group's purpose. Maximum 48 characters. |
| **members** | set(string) | [] | List of members (local users, domain users, or groups) to include in this local group. Can include usernames, domain accounts (DOMAIN\username), or built-in groups (BUILTIN\GroupName). |
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands executed on the remote server. Increase for systems with many group members. |

---

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | The group name (same as `name` argument). Used as the unique identifier. |
| **members** | set(string) | Current list of group members (actual state on the system). |
| **description** | string | The current description of the group. |

---

## Common Local Groups

Windows includes several built-in local groups that already exist on the system. While you cannot delete or recreate these groups, you can add members to them using the `windows_localgroup` resource with their exact names:

| Group Name | Description | Typical Use |
|------------|-------------|------------|
| **Administrators** | Full control of the computer | Administrative users, service accounts with elevated privileges |
| **Users** | Standard user permissions | Regular user accounts, service accounts |
| **Guests** | Limited access for temporary users | Guest accounts |
| **Remote Desktop Users** | Permission to log in via RDP | Users who need remote desktop access |
| **Power Users** | Power user permissions (deprecated) | Legacy application support |
| **Backup Operators** | Can backup and restore files | Backup service accounts |
| **Replicator** | Replication of files across domain | Domain synchronization |
| **Network Configuration Operators** | Manage network settings | Network administrators |
| **Performance Monitor Users** | Read performance monitoring data | Monitoring applications |
| **Performance Log Users** | Manage performance logs | Log collection services |
| **Event Log Readers** | Read Windows event logs | Monitoring and audit tools |
| **Distributed COM Users** | DCOM access permissions | COM component access |

### Adding Members to Built-in Groups

```hcl
# Add user to Remote Desktop Users group
resource "windows_localgroup" "rdp_users" {
  name    = "Remote Desktop Users"
  members = [
    "john.doe",
    "jane.smith",
    "DOMAIN\\DomainUser"
  ]
}

# Add user to Event Log Readers group
resource "windows_localgroup" "log_readers" {
  name    = "Event Log Readers"
  members = [
    windows_localuser.monitoring_account.username
  ]
}
```

---

## Advanced Examples

### Creating Application-Specific Groups

```hcl
# Create multiple application groups
variable "app_groups" {
  type = map(object({
    description = string
  }))
  default = {
    "WebAppAdmins" = {
      description = "Web application administrators"
    }
    "WebAppUsers" = {
      description = "Web application users"
    }
    "WebAppReaders" = {
      description = "Web application read-only access"
    }
  }
}

resource "windows_localgroup" "app_groups" {
  for_each = var.app_groups

  name        = each.key
  description = each.value.description
}
```

### Creating Groups with User Members

```hcl
# Create users first
resource "windows_localuser" "app_admin" {
  username = "app_admin"
  password = var.app_admin_password
  full_name = "Application Administrator"
}

resource "windows_localuser" "app_user1" {
  username = "app_user1"
  password = var.app_user1_password
  full_name = "Application User 1"
}

resource "windows_localuser" "app_user2" {
  username = "app_user2"
  password = var.app_user2_password
  full_name = "Application User 2"
}

# Create groups and add users
resource "windows_localgroup" "app_admins" {
  name        = "AppAdministrators"
  description = "Application administrators"
  members = [
    windows_localuser.app_admin.username
  ]
}

resource "windows_localgroup" "app_users" {
  name        = "AppUsers"
  description = "Application users"
  members = [
    windows_localuser.app_user1.username,
    windows_localuser.app_user2.username
  ]
}
```

### Hierarchical Group Structure

```hcl
# Create a hierarchical group structure
resource "windows_localgroup" "org_all_users" {
  name        = "OrgAllUsers"
  description = "All organization users"
}

resource "windows_localgroup" "org_department_it" {
  name        = "OrgIT"
  description = "IT department users"
  members = [
    windows_localuser.it_user1.username,
    windows_localuser.it_user2.username
  ]
}

resource "windows_localgroup" "org_department_hr" {
  name        = "OrgHR"
  description = "Human Resources department users"
  members = [
    windows_localuser.hr_user1.username,
    windows_localuser.hr_user2.username
  ]
}

# Add department groups to all users group
resource "windows_localgroup" "all_users_hierarchy" {
  name    = "OrgAllUsers"
  members = [
    windows_localgroup.org_department_it.name,
    windows_localgroup.org_department_hr.name
  ]

  depends_on = [
    windows_localgroup.org_department_it,
    windows_localgroup.org_department_hr
  ]
}
```

### Environment-Specific Groups

```hcl
variable "environment" {
  type    = string
  default = "production"
}

variable "dev_users" {
  type    = list(string)
  default = ["dev_user1", "dev_user2"]
}

variable "prod_users" {
  type    = list(string)
  default = ["prod_user1", "prod_user2"]
}

locals {
  members_by_env = {
    development = var.dev_users
    production  = var.prod_users
  }
}

resource "windows_localgroup" "env_specific" {
  name        = "AppUsers-${var.environment}"
  description = "Application users for ${var.environment}"
  members     = local.members_by_env[var.environment]
}
```

### Service Group Management

```hcl
# Create backup service group with necessary permissions
resource "windows_localuser" "backup_service" {
  username                    = "svc_backup"
  password                    = var.backup_service_password
  full_name                   = "Backup Service Account"
  password_never_expires      = true
  user_cannot_change_password = true
}

resource "windows_localgroup" "backup_operators" {
  name        = "BackupServiceGroup"
  description = "Service accounts for backup operations"
  members = [
    windows_localuser.backup_service.username,
    "Backup Operators"  # Built-in group
  ]
}

# Create monitoring service group
resource "windows_localuser" "monitoring_service" {
  username                    = "svc_monitoring"
  password                    = var.monitoring_service_password
  full_name                   = "Monitoring Service Account"
  password_never_expires      = true
  user_cannot_change_password = true
}

resource "windows_localgroup" "monitoring_group" {
  name        = "MonitoringServiceGroup"
  description = "Service accounts for monitoring"
  members = [
    windows_localuser.monitoring_service.username,
    "Event Log Readers",
    "Performance Log Users",
    "Performance Monitor Users"
  ]
}
```

### Adding to Built-in Administrator Group

```hcl
# Add specific users to Administrators
resource "windows_localuser" "sys_admin" {
  username = "sys_admin"
  password = var.sys_admin_password
  full_name = "System Administrator"
}

resource "windows_localgroup" "add_to_administrators" {
  name    = "Administrators"
  members = [
    windows_localuser.sys_admin.username,
    "DOMAIN\\Domain_Admins"  # Add domain admins if domain-joined
  ]
}
```

### Conditional Group Membership

```hcl
variable "enable_rdp_access" {
  type    = bool
  default = false
}

resource "windows_localuser" "remote_user" {
  count     = var.enable_rdp_access ? 1 : 0
  username  = "remote_user"
  password  = var.remote_user_password
  full_name = "Remote Access User"
}

resource "windows_localgroup" "rdp_access" {
  count   = var.enable_rdp_access ? 1 : 0
  name    = "RemoteDesktopAccess"
  description = "Users with remote desktop access"
  members = [
    windows_localuser.remote_user[0].username
  ]
}
```

---

## Import

Local groups can be imported using the group name, allowing you to bring existing local groups under Terraform management.

### Import Syntax

```shell
terraform import windows_localgroup.<resource_name> <group_name>
```

### Import Examples

Import a single local group:

```shell
terraform import windows_localgroup.example MyAppUsers
```

Import a built-in group (to manage its members):

```shell
terraform import windows_localgroup.rdp_users "Remote Desktop Users"
```

Import the Administrators group:

```shell
terraform import windows_localgroup.admins Administrators
```

Create the resource configuration:

```hcl
resource "windows_localgroup" "example" {
  name        = "MyAppUsers"
  description = "Users for MyApp"
}
```

Then import the existing group:

```shell
terraform import windows_localgroup.example MyAppUsers
```

### Import Multiple Groups

Create resource definitions:

```hcl
resource "windows_localgroup" "web_admins" {
  name = "WebAppAdmins"
}

resource "windows_localgroup" "app_users" {
  name = "AppUsers"
}

resource "windows_localgroup" "service_group" {
  name = "ServiceAccounts"
}
```

Import the existing groups:

```shell
terraform import windows_localgroup.web_admins WebAppAdmins
terraform import windows_localgroup.app_users AppUsers
terraform import windows_localgroup.service_group ServiceAccounts
```

---

## Troubleshooting

### Group Creation Fails

**Issue**: `failed to create local group` or `group creation error`

**Solutions**:
- Verify the group name is unique on the system: `Get-LocalGroup | Where-Object { $_.Name -eq "GroupName" }`
- Ensure SSH user has administrator privileges
- Check group name format (no special characters, max 256 characters)
- Group names cannot contain only periods or spaces
- Run manual creation: `New-LocalGroup -Name "GroupName" -Description "Description"`

### Access Denied

**Issue**: `access denied` or `permission denied` error

**Solutions**:
- Verify SSH user is in the Administrators group
- Check with: `whoami /groups | find "S-1-5-32-544"`
- Confirm sufficient privileges on the Windows server
- Check Windows Event Logs: `Get-EventLog -LogName System -Newest 20`

### Member Addition Fails

**Issue**: `failed to add member` or `member not found`

**Solutions**:
- Verify the member (user or group) exists on the system
- For local users: `Get-LocalUser -Name "username"`
- For local groups: `Get-LocalGroup -Name "groupname"`
- For domain accounts, use format: `DOMAIN\username`
- Check member name spelling (case-insensitive but must match exactly)
- Avoid circular group dependencies (group A containing group B, and B containing A)

### Group Already Exists

**Issue**: `group already exists` or `duplicate group` error

**Solutions**:
- If group already exists, import it: `terraform import windows_localgroup.example GroupName`
- Check existing groups: `Get-LocalGroup`
- If recreating, delete old group first via PowerShell: `Remove-LocalGroup -Name "GroupName"`
- Or use Terraform destroy, then apply

### Removing Built-in Groups

**Issue**: `cannot delete built-in group` or `operation not permitted`

**Solutions**:
- Built-in groups (Administrators, Users, etc.) cannot be deleted
- You can manage their members but cannot delete the group
- Built-in groups are system-managed
- Focus on managing membership instead of deletion

### Member Not Removed

**Issue**: Trying to remove member but operation fails

**Solutions**:
- Verify member is actually in the group: `Get-LocalGroupMember -Group "GroupName"`
- Check member name matches exactly (case-insensitive)
- Ensure no dependencies on member existence
- Try manual removal: `Remove-LocalGroupMember -Group "GroupName" -Member "MemberName"`

### SSH Connection Issues

**Issue**: Connection timeout or SSH error during group operations

**Solutions**:
- Increase `command_timeout` to allow more time
- Check network connectivity to the server
- Verify SSH credentials and access
- Test manually: `ssh admin@server-ip`

### Domain Account Member Issues

**Issue**: `cannot find domain account` or domain member not added

**Solutions**:
- For domain accounts, use full format: `DOMAIN\username` (not just username)
- Ensure the server is domain-joined: `wmic computersystem get domain`
- Verify domain account exists and is accessible
- Use correct domain name: check `Get-ADUser` from domain controller
- Example: `members = ["CONTOSO\\john.doe"]`

### State Mismatch

**Issue**: Group exists but Terraform state says it doesn't

**Solutions**:
- Group was created outside of Terraform
- Run `terraform refresh` to update state
- Or remove and re-import: `terraform state rm windows_localgroup.example`
- Always use Terraform to manage groups

### Group Name Conflicts

**Issue**: `group name already exists` when creating group

**Solutions**:
- Check for case variations in existing groups: `Get-LocalGroup | Select-Object Name`
- Group names are case-insensitive, but system recognizes them
- Ensure unique naming across all local groups
- Use descriptive prefixes for application-specific groups

### Large Member Lists

**Issue**: Timeout or performance issues with many members

**Solutions**:
- Increase `command_timeout` for large groups
- Consider splitting very large groups
- Monitor server resources during member addition
- For large enterprise groups, test with subset first

---

## Best Practices

### Use Descriptive Names

Create group names that clearly indicate their purpose:

```hcl
# Good: Clear purpose
resource "windows_localgroup" "web_app_admins" {
  name        = "WebAppAdministrators"
  description = "Administrative users for Web Application"
}

# Less clear
resource "windows_localgroup" "group1" {
  name = "G1"
}
```

### Document Purpose in Description

Always include meaningful descriptions:

```hcl
resource "windows_localgroup" "example" {
  name        = "MyAppUsers"
  description = "Users with access to MyApp - created for v2.0 rollout"
}
```

### Use Naming Conventions

Establish consistent naming patterns:

```hcl
# By purpose
resource "windows_localgroup" "app_admins" {
  name = "MyApp-Administrators"
}

resource "windows_localgroup" "app_users" {
  name = "MyApp-Users"
}

resource "windows_localgroup" "app_readers" {
  name = "MyApp-Readers"
}
```

### Organize with Variables

Use variables for maintainability:

```hcl
variable "app_name" {
  type    = string
  default = "MyApp"
}

locals {
  group_configs = {
    admins = {
      description = "Administrators"
    }
    users = {
      description = "Regular users"
    }
    readers = {
      description = "Read-only access"
    }
  }
}

resource "windows_localgroup" "app_groups" {
  for_each = local.group_configs

  name        = "${var.app_name}-${each.key}"
  description = each.value.description
}
```

### Reference Related Resources

Use resource references instead of hardcoding names:

```hcl
# Good: Dynamic references
resource "windows_localgroup" "app_group" {
  name    = "AppUsers"
  members = [
    windows_localuser.app_user1.username,
    windows_localuser.app_user2.username
  ]
}

# Avoid: Hardcoded names
resource "windows_localgroup" "bad_example" {
  name    = "AppUsers"
  members = ["hardcoded_user1", "hardcoded_user2"]
}
```

### Maintain Least Privilege

Keep group membership minimal and appropriate:

```hcl
# Good: Specific permissions
resource "windows_localgroup" "read_only_users" {
  name    = "AppReadOnly"
  members = ["user1", "user2"]
}

# Avoid: Excessive permissions
resource "windows_localgroup" "bad_permissions" {
  name    = "Administrators"
  members = ["all_users"]
}
```

### Use Dependencies for Group Hierarchies

Explicitly define dependencies when groups depend on other groups:

```hcl
resource "windows_localgroup" "parent_group" {
  name = "ParentGroup"
}

resource "windows_localgroup" "child_group" {
  name    = "ChildGroup"
  members = [windows_localgroup.parent_group.name]

  depends_on = [windows_localgroup.parent_group]
}
```

### Separate User and Group Creation

Keep user and group resources separate for clarity:

```hcl
# Users module or separate resource
resource "windows_localuser" "users" {
  for_each = var.user_definitions
  # ... user configuration
}

# Groups module or separate resource
resource "windows_localgroup" "groups" {
  for_each = var.group_definitions
  # ... group configuration
}

# Link users to groups
resource "windows_localgroup" "assign_members" {
  for_each = var.group_memberships
  
  name    = each.value.group
  members = each.value.users
}
```

---

## Important Considerations

### Group Persistence

Local groups persist across system reboots. Group membership and settings are stored in the local Windows Security Accounts Manager (SAM).

### Built-in Groups

Built-in groups (Administrators, Users, Guests, etc.) are system-managed and cannot be deleted. However, you can manage their members using this resource.

### Group Membership Updates

When you modify group members through Terraform, the changes take effect immediately. Existing group members in sessions will retain access until they log out and back in.

### Circular Dependencies

Avoid creating circular group dependencies:
- Group A contains Group B
- Group B contains Group A

This will cause errors.

### Domain and Local Groups

This resource manages **local groups only**. For domain groups, use domain management tools or separate resources.

### Group Deletion

When you destroy a Terraform configuration, all managed local groups (non-built-in) will be deleted:

```bash
terraform destroy  # This will remove all managed groups
```

Built-in groups will have their members updated to remove managed accounts, but the built-in groups themselves remain.

### Access Control

Adding a user to the Administrators group grants full system access. Carefully manage membership in privileged groups.

---

## Limitations

- **Local Groups Only**: Cannot manage domain groups; only local machine groups
- **No Group Nesting Depth Limits**: Windows allows nesting, but Terraform does not validate depth
- **No Built-in Group Deletion**: Built-in groups cannot be deleted via this resource
- **No Permissions Management**: This resource manages membership only; does not assign file/registry permissions
- **No Group Policies**: Group Policy application must be managed separately
- **Case Insensitivity**: Group names are case-insensitive, but be consistent in naming
- **No Scope Management**: No support for domain local vs. global vs. universal group scopes (local groups only)