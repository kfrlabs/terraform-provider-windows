# Windows Local User Resource

Manages local user accounts on a Windows server via SSH and PowerShell remote execution. This resource handles creation, modification, and deletion of local user accounts with support for password policies and group membership.

## Table of Contents

1. [Example Usage](#example-usage)
2. [Argument Reference](#argument-reference)
3. [Attributes Reference](#attributes-reference)
4. [Password Requirements](#password-requirements)
5. [Common Local Groups](#common-local-groups)
6. [Advanced Examples](#advanced-examples)
7. [Import](#import)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

---

## Example Usage

### Basic Usage

```hcl
resource "windows_localuser" "example" {
  username    = "johndoe"
  password    = "SuperSecureP@ssw0rd"
  full_name   = "John Doe"
  description = "Regular user account"
}
```

### Administrator User

```hcl
resource "windows_localuser" "admin_user" {
  username                    = "admin_user"
  password                    = "VerySecureP@ssw0rd!"
  full_name                   = "Administrator User"
  description                 = "Administrative user account"
  password_never_expires      = true
  user_cannot_change_password = true
  groups                      = ["Administrators", "Remote Desktop Users"]
}
```

### Service Account

```hcl
resource "windows_localuser" "service_account" {
  username                    = "svc_app"
  password                    = "ServiceP@ssw0rd123!"
  full_name                   = "Application Service Account"
  description                 = "Service account for MyApp"
  password_never_expires      = true
  user_cannot_change_password = true
  groups                      = ["Users"]
  command_timeout             = 300
}
```

### Disabled Account

```hcl
resource "windows_localuser" "disabled_user" {
  username           = "old_user"
  password           = "TemporaryP@ssw0rd"
  account_disabled   = true
  description        = "Disabled legacy account"
}
```

---

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **username** | string | The name of the local user account. Must be 1-20 characters, unique on the system. Can contain letters, numbers, and these special characters: `_` `-` `.` Only letters, numbers, and underscores are recommended. |
| **password** | string | The password for the local user account. Must meet Windows password complexity requirements (see [Password Requirements](#password-requirements)). Treat as sensitive data. |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **full_name** | string | empty | The full name or display name of the user. Can contain spaces and special characters. Used for identification purposes. Maximum 64 characters. |
| **description** | string | empty | A description or comment for the user account. Useful for documenting account purpose and owner. Maximum 48 characters. |
| **password_never_expires** | bool | false | If `true`, the account password will never expire. Useful for service accounts but not recommended for regular users. |
| **user_cannot_change_password** | bool | false | If `true`, the user cannot change their own password. Typically used for service accounts. |
| **account_disabled** | bool | false | If `true`, the account will be created or remain in a disabled state and cannot be used to log in. |
| **groups** | set(string) | [] | List of local group names this user should be a member of. Examples: `["Users"]`, `["Administrators", "Remote Desktop Users"]`. Groups are case-insensitive. |
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands executed on the remote server. Increase for systems under heavy load. |

---

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | The username of the local user (same as `username` argument). Used as the unique identifier. |
| **sid** | string | The Security Identifier (SID) of the user account. Unique identifier for the account in the Windows security system. |
| **enabled** | bool | Whether the account is currently enabled. Inverse of `account_disabled`. |
| **groups_member_of** | set(string) | List of local groups the user is a member of (actual current state). |
| **last_logon** | string | Timestamp of the user's last successful logon (if available). |

---

## Password Requirements

Windows enforces password complexity requirements at the operating system level. A password must meet **at least 3 of these 4 criteria**:

### Complexity Rules

1. **Uppercase Letters** - At least one letter A-Z
2. **Lowercase Letters** - At least one letter a-z
3. **Digits** - At least one number 0-9
4. **Special Characters** - At least one character like: `!@#$%^&*()_+-=[]{}|;:'",.<>?/~`

### Length Requirements

- **Minimum 8 characters** (enforced by default policy, but may be higher based on Group Policy)
- **Maximum 127 characters** (theoretical limit)

### Examples of Valid Passwords

```
✅ P@ssw0rd           (8 chars: uppercase, lowercase, digit, special)
✅ MyPassword123      (12 chars: uppercase, lowercase, digits)
✅ Complex!Pass1      (13 chars: all 4 categories)
✅ SecureP@ss         (9 chars: uppercase, lowercase, digit, special)
```

### Examples of Invalid Passwords

```
❌ password           (only lowercase, no complexity)
❌ PASSWORD123        (no special characters, only 11 chars might pass depending on policy)
❌ Pass1             (only 6 characters, too short)
❌ 12345678          (only digits)
```

### Password Policy Notes

- The default Windows password policy requires passwords to meet complexity rules
- Domain-joined computers may have stricter requirements defined by Group Policy
- Local security policy can be modified: `secpol.msc` on the server
- Service accounts often use generated passwords meeting these requirements

---

## Common Local Groups

Windows includes several built-in local groups for managing user permissions:

| Group Name | Description | Typical Use |
|------------|-------------|------------|
| **Administrators** | Full control of the computer | Administrative users, service accounts needing elevated privileges |
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
| **Certificate Service DCOM Access** | DCOM access for certificates | Certificate services |
| **RDS Endpoint Servers** | Remote Desktop Services access | RDS configurations |

---

## Advanced Examples

### Creating a Service Account with Group Permissions

```hcl
resource "windows_localuser" "web_app_service" {
  username                    = "svc_webapp"
  password                    = "WebAppSvc@2024Secure!"
  full_name                   = "Web Application Service Account"
  description                 = "Service account for IIS application pool"
  password_never_expires      = true
  user_cannot_change_password = true
  account_disabled            = false
  groups                      = ["Users", "Event Log Readers", "Performance Monitor Users"]
}
```

### Creating Multiple Users with Variables

```hcl
variable "environment" {
  type    = string
  default = "production"
}

variable "application_users" {
  type = map(object({
    full_name              = string
    description            = string
    password_never_expires = bool
    groups                 = list(string)
  }))
  default = {
    app_admin = {
      full_name              = "Application Administrator"
      description            = "Admin for critical application"
      password_never_expires = true
      groups                 = ["Administrators"]
    }
    app_service = {
      full_name              = "Application Service"
      description            = "Service account for application"
      password_never_expires = true
      groups                 = ["Users"]
    }
    app_monitor = {
      full_name              = "Monitoring Service"
      description            = "Application monitoring account"
      password_never_expires = true
      groups                 = ["Event Log Readers", "Performance Monitor Users"]
    }
  }
}

resource "windows_localuser" "app_users" {
  for_each = var.application_users

  username                    = "${var.environment}-${each.key}"
  password                    = random_password.user_passwords[each.key].result
  full_name                   = each.value.full_name
  description                 = each.value.description
  password_never_expires      = each.value.password_never_expires
  user_cannot_change_password = each.value.password_never_expires
  groups                      = each.value.groups
}

resource "random_password" "user_passwords" {
  for_each = var.application_users

  length      = 16
  special     = true
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}
```

### Creating Users with Password Generation

```hcl
resource "random_password" "service_password" {
  length      = 20
  special     = true
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
  min_special = 2

  override_special = "!@#$%^&*-_=+"
}

resource "windows_localuser" "managed_service" {
  username                    = "svc_managed"
  password                    = random_password.service_password.result
  full_name                   = "Managed Service Account"
  description                 = "Auto-generated service account"
  password_never_expires      = true
  user_cannot_change_password = true
  groups                      = ["Users"]
}

output "service_account_password" {
  description = "Password for managed service account"
  value       = random_password.service_password.result
  sensitive   = true
}
```

### Creating Users with Environment-Specific Settings

```hcl
variable "environment" {
  type    = string
  default = "dev"
}

locals {
  user_configs = {
    dev = {
      password_never_expires = false
      account_disabled       = false
      groups                 = ["Users"]
    }
    staging = {
      password_never_expires = false
      account_disabled       = false
      groups                 = ["Users"]
    }
    production = {
      password_never_expires = true
      account_disabled       = false
      groups                 = ["Users"]
    }
  }
}

resource "windows_localuser" "app_user" {
  username                    = "app_${var.environment}"
  password                    = var.app_user_password
  full_name                   = "Application User - ${upper(var.environment)}"
  description                 = "Application user for ${var.environment} environment"
  password_never_expires      = local.user_configs[var.environment].password_never_expires
  user_cannot_change_password = local.user_configs[var.environment].password_never_expires
  account_disabled            = local.user_configs[var.environment].account_disabled
  groups                      = local.user_configs[var.environment].groups
}
```

### Creating a Limited-Privilege Application User

```hcl
resource "windows_localuser" "app_limited" {
  username           = "app_readonly"
  password           = "SecureAppPass@123456"
  full_name          = "Application Read-Only User"
  description        = "Limited privilege user for read-only operations"
  account_disabled   = false
  groups             = ["Event Log Readers"]  # Read-only groups
}
```

### User Account with Temporary Expiration

```hcl
resource "windows_localuser" "temporary_user" {
  username           = "temp_contractor"
  password           = "TempP@ssw0rd2024"
  full_name          = "Temporary Contractor"
  description        = "Contractor access - expires 2024-12-31"
  account_disabled   = false
  groups             = ["Users"]
}

# Note: Account expiration must be managed separately via windows_registry_value
# This is documented as a limitation of the current resource
```

---

## Import

Local users can be imported using the username, allowing you to bring existing user accounts under Terraform management.

### Import Syntax

```shell
terraform import windows_localuser.<resource_name> <username>
```

### Import Examples

Import a single user:

```shell
terraform import windows_localuser.example johndoe
```

Import a service account:

```shell
terraform import windows_localuser.service_account svc_myapp
```

Create the resource configuration:

```hcl
resource "windows_localuser" "example" {
  username = "johndoe"
  password = "NewP@ssw0rd123"
}
```

Then import the existing user:

```shell
terraform import windows_localuser.example johndoe
```

### Import Multiple Users

Create resource definitions:

```hcl
resource "windows_localuser" "admin_user" {
  username = "admin_user"
  password = "AdminP@ssw0rd123"
}

resource "windows_localuser" "service_user" {
  username = "svc_app"
  password = "ServiceP@ssw0rd123"
}
```

Import the existing users:

```shell
terraform import windows_localuser.admin_user admin_user
terraform import windows_localuser.service_user svc_app
```

---

## Troubleshooting

### Password Complexity Errors

**Issue**: `password does not meet complexity requirements` or `invalid password`

**Solutions**:
- Ensure password contains at least 3 of these 4 categories:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Digits (0-9)
  - Special characters (!@#$%^&*...)
- Minimum 8 characters required
- Check local security policy: `secpol.msc` on the server
- Domain Group Policy may enforce stricter requirements
- Valid examples: `P@ssw0rd`, `Secure123!`, `MyApp@2024`

### Access Denied

**Issue**: `access denied` or `permission denied` error during user creation

**Solutions**:
- Verify the SSH user is in the Administrators group
- Check with: `whoami /groups | find "S-1-5-32-544"`
- Confirm sufficient privileges on the Windows server
- Check Windows Event Logs for detailed error: `Get-EventLog -LogName System -Newest 20`

### Group Membership Failed

**Issue**: `group not found` or `cannot add user to group`

**Solutions**:
- Verify the group exists on the system: `Get-LocalGroup -Name "GroupName"`
- Check group name spelling (case-insensitive but must match exactly)
- Avoid circular group dependencies
- Built-in groups may have different naming conventions
- Use `Get-LocalGroup | Format-Table Name` to list all groups
- Check for spelling: "Remote Desktop Users" not "Remote Desktop User"

### Username Already Exists

**Issue**: `user already exists` or `duplicate user` error

**Solutions**:
- If user already exists, import it: `terraform import windows_localuser.example username`
- Check existing users: `Get-LocalUser`
- If recreating, delete old account first via PowerShell: `Remove-LocalUser -Name "username"`
- Or use Terraform destroy, then apply

### SSH Connection Issues

**Issue**: Connection timeout or SSH error during user creation

**Solutions**:
- Increase `command_timeout` to allow more time
- Check network connectivity to the server
- Verify SSH credentials and access
- Test manually: `ssh admin@server-ip`

### User Cannot Change Password Setting Not Working

**Issue**: `user_cannot_change_password` setting not applied

**Solutions**:
- Both `user_cannot_change_password` and `password_never_expires` should be used together for service accounts
- Verify setting was applied: `Get-LocalUser -Name "username" | Select-Object PasswordNotRequired, PasswordLastSet`
- This requires specific permissions on the account
- Some Group Policies may override local settings

### Password Expiration Issues

**Issue**: `password_never_expires` not working as expected

**Solutions**:
- Verify setting was applied: `Get-LocalUser -Name "username" | Select-Object PasswordExpires`
- Domain Group Policy may enforce password expiration
- Check policy: `gpresult /h report.html`
- For local accounts only, check local security policy: `secpol.msc`

### State Mismatch

**Issue**: User exists but Terraform state says it doesn't

**Solutions**:
- User was created outside of Terraform
- Run `terraform refresh` to update state
- Or remove and re-import: `terraform state rm windows_localuser.example`
- Always use Terraform to manage user accounts

### Account Disabled Not Working

**Issue**: `account_disabled` setting is not taking effect

**Solutions**:
- Verify setting: `Get-LocalUser -Name "username" | Select-Object Enabled`
- Manually disable: `Disable-LocalUser -Name "username"`
- Check that the account is not required by running services
- Some accounts may be protected from disabling

---

## Best Practices

### Use Strong, Random Passwords

Generate strong passwords for all accounts:

```hcl
resource "random_password" "strong_password" {
  length      = 16
  special     = true
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1

  override_special = "!@#$%^&*-_=+"
}

resource "windows_localuser" "secure_user" {
  username = "app_user"
  password = random_password.strong_password.result
}
```

### Document Account Purpose

Always include meaningful descriptions:

```hcl
resource "windows_localuser" "example" {
  username    = "svc_reporting"
  password    = var.user_password
  full_name   = "Reporting Service Account"
  description = "SQL Server Reporting Services (SSRS) application pool identity"
}
```

### Use Service Accounts for Applications

Service accounts should have restricted permissions:

```hcl
resource "windows_localuser" "app_service" {
  username                    = "svc_myapp"
  password                    = var.app_service_password
  full_name                   = "MyApp Service Account"
  description                 = "Application service account - restricted to Users group"
  password_never_expires      = true
  user_cannot_change_password = true
  groups                      = ["Users"]
}
```

### Limit Administrative Access

Only add users to Administrators when absolutely necessary:

```hcl
# Good: Regular user
resource "windows_localuser" "regular_user" {
  username = "john.doe"
  password = var.john_password
  groups   = ["Users"]
}

# Avoid unless necessary: Administrative user
resource "windows_localuser" "admin_user" {
  username = "admin_user"
  password = var.admin_password
  groups   = ["Administrators"]
}
```

### Use Sensitive Variable Declaration

Protect passwords from appearing in logs:

```hcl
variable "user_password" {
  type        = string
  sensitive   = true
  description = "Password for user account"
}

resource "windows_localuser" "example" {
  username = "app_user"
  password = var.user_password
}
```

### Organize Users by Purpose

Use naming conventions for clarity:

```hcl
# Service accounts
resource "windows_localuser" "service_accounts" {
  for_each = {
    "svc_web"  = "Web Server Service"
    "svc_db"   = "Database Service"
    "svc_sync" = "Synchronization Service"
  }

  username    = each.key
  password    = var.service_passwords[each.key]
  full_name   = each.value
  description = "Service account for ${each.value}"
  groups      = ["Users"]
}

# Regular users
resource "windows_localuser" "regular_users" {
  for_each = {
    "john.doe"   = "John Doe"
    "jane.smith" = "Jane Smith"
  }

  username  = each.key
  password  = var.user_passwords[each.key]
  full_name = each.value
  groups    = ["Users", "Remote Desktop Users"]
}
```

### Use Variables for Sensitive Data

Never hardcode passwords in configuration:

```hcl
# ❌ Never do this
resource "windows_localuser" "bad_example" {
  username = "user"
  password = "MyPassword123!"  # Don't hardcode!
}

# ✅ Do this instead
variable "user_password" {
  type      = string
  sensitive = true
}

resource "windows_localuser" "good_example" {
  username = "user"
  password = var.user_password
}
```

### Keep Audit Trail

Document changes with descriptions:

```hcl
resource "windows_localuser" "monitored_account" {
  username    = "backup_service"
  password    = var.backup_service_password
  full_name   = "Backup Service Account"
  description = "Backup agent - created 2024-01-15 for daily backups"
  groups      = ["Backup Operators"]
}
```

---

## Important Considerations

### Account Persistence

User accounts persist across system reboots. Account settings are stored in the local Windows Security Accounts Manager (SAM).

### Password Management

- Passwords are stored as hashes in the SAM database
- Consider implementing a password rotation strategy
- For service accounts with `password_never_expires = true`, document password location securely
- Terraform state files contain sensitive information; protect them carefully

### Group Membership

- Adding a user to the Administrators group grants full system access
- Carefully manage membership in privileged groups
- User is a member of the Users group by default
- Group changes take effect immediately for future logons

### Account Deletion

When you destroy a Terraform configuration, all managed user accounts will be deleted:

```bash
terraform destroy  # This will remove all managed user accounts
```

### Built-in Accounts

Some system accounts (Administrator, Guest) cannot be deleted but can be disabled or modified.

### Disabled Accounts

Disabled accounts (`account_disabled = true`) cannot be used for logon but retain all their attributes and permissions until re-enabled.

---

## Limitations

- **No Account Expiration**: This resource cannot set account expiration dates; must be managed via registry or PowerShell
- **No Home Directory Management**: User profile paths are not managed by this resource
- **No Password History**: Password history limits must be managed via Group Policy
- **No Profile Path Setting**: User profile directory must be configured separately
- **No Script Path Setting**: Logon script paths must be configured separately
- **Limited to Local Accounts**: Cannot manage domain accounts; only local machine accounts
- **No Login Hours**: Login hour restrictions must be managed separately