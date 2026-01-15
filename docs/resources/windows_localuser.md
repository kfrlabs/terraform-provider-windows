# windows_localuser

Manages local user accounts on Windows servers.

## Example Usage

### Basic User Creation

```hcl
resource "windows_localuser" "john" {
  username = "john.doe"
  password = "P@ssw0rd123!"
}
```

### User with Full Configuration

```hcl
resource "windows_localuser" "admin_user" {
  username                      = "backup_admin"
  password                      = var.backup_admin_password
  full_name                     = "Backup Administrator"
  description                   = "Account for automated backups"
  password_never_expires        = true
  user_cannot_change_password   = false
  account_disabled              = false
  groups                        = ["Administrators", "Backup Operators"]
}
```

### Service Account

```hcl
resource "windows_localuser" "service_account" {
  username                    = "svc_webapp"
  password                    = var.service_password
  full_name                   = "Web Application Service Account"
  description                 = "Service account for web application"
  password_never_expires      = true
  user_cannot_change_password = true
  account_disabled            = false
}
```

### Disabled User Account

```hcl
resource "windows_localuser" "temp_user" {
  username         = "temp.contractor"
  password         = "TempP@ss123!"
  full_name        = "Temporary Contractor"
  description      = "Temporary access for contractor"
  account_disabled = true
}
```

### User with Group Memberships

```hcl
resource "windows_localuser" "operator" {
  username    = "monitoring_user"
  password    = var.monitoring_password
  full_name   = "Monitoring Operator"
  description = "Account for monitoring system"
  
  groups = [
    "Performance Monitor Users",
    "Event Log Readers",
    "Remote Management Users"
  ]
}
```

## Argument Reference

The following arguments are supported:

* `username` - (Required, String) The name of the local user account. Should follow Windows username conventions (letters, digits, periods, hyphens, underscores).

* `password` - (Required, String, Sensitive) The password for the local user account. Should follow the Windows password complexity requirements configured on the server.

* `full_name` - (Optional, String) The full name of the user (display name).

* `description` - (Optional, String) A description for the user account.

* `password_never_expires` - (Optional, Boolean) If true, the password will never expire. Default: `false`.

* `user_cannot_change_password` - (Optional, Boolean) If true, the user cannot change their own password. Default: `false`.

* `account_disabled` - (Optional, Boolean) If true, the account will be created in a disabled state. Default: `false`.

* `groups` - (Optional, Set of Strings) List of local groups this user should be a member of. Groups must already exist on the system.

* `command_timeout` - (Optional, Number) Timeout in seconds for PowerShell commands. Default: `300` (5 minutes).

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The username.

## Import

Local users can be imported using the username:

```bash
terraform import windows_localuser.john john.doe
```

When importing, Terraform will read the current state of the user including group memberships. However, the password cannot be retrieved and must be set in your configuration.

## Common Windows Groups

Here are commonly used local groups for the `groups` attribute:

### Administrative Groups
- `Administrators` - Full system access
- `Backup Operators` - Can backup and restore files
- `Power Users` - Limited administrative privileges

### Service Groups
- `Remote Desktop Users` - Can connect via RDP
- `Remote Management Users` - Can manage server remotely (WinRM)
- `IIS_IUSRS` - IIS worker process identity

### Monitoring Groups
- `Performance Monitor Users` - Can access performance data
- `Performance Log Users` - Can manage performance counters
- `Event Log Readers` - Can read event logs

### Network Groups
- `Network Configuration Operators` - Can manage network settings
- `Distributed COM Users` - Can launch DCOM applications

## Password Requirements

Windows enforces password complexity by default. Common requirements:

- Minimum length: 8 characters (configurable via Group Policy)
- Must contain characters from three of these categories:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Digits (0-9)
  - Special characters (!@#$%^&*())
- Cannot contain username or parts of full name

**Example of strong passwords**:
- `P@ssw0rd123!`
- `MyS3cure!Pass`
- `C0mpl3x#2024`

**Recommended practices**:
- Use Terraform variables with `sensitive = true` for passwords
- Store passwords in a secrets management system (Vault, AWS Secrets Manager, etc.)
- Rotate passwords regularly
- Use unique passwords for each account

## Managing Group Memberships

### Adding User to Multiple Groups

```hcl
resource "windows_localuser" "admin" {
  username = "backup_admin"
  password = var.password
  
  groups = [
    "Administrators",
    "Backup Operators",
    "Remote Desktop Users"
  ]
}
```

### Removing User from Groups

When you update the `groups` attribute, Terraform will:
- Add the user to any new groups in the list
- Remove the user from any groups no longer in the list

```hcl
# Before: member of Administrators, Backup Operators
# After: only member of Backup Operators

resource "windows_localuser" "admin" {
  username = "backup_admin"
  password = var.password
  
  groups = [
    "Backup Operators"  # Removed from Administrators
  ]
}
```

### Dynamic Group Assignment

```hcl
variable "is_admin" {
  type    = bool
  default = false
}

resource "windows_localuser" "user" {
  username = "app_user"
  password = var.password
  
  groups = var.is_admin ? ["Administrators", "Users"] : ["Users"]
}
```

## Account Lifecycle Management

### Creating Multiple Users

```hcl
variable "users" {
  type = map(object({
    full_name   = string
    description = string
    groups      = list(string)
  }))
  default = {
    "dev1" = {
      full_name   = "Developer One"
      description = "Development team member"
      groups      = ["Users", "Remote Desktop Users"]
    }
    "dev2" = {
      full_name   = "Developer Two"
      description = "Development team member"
      groups      = ["Users", "Remote Desktop Users"]
    }
  }
}

resource "windows_localuser" "developers" {
  for_each = var.users
  
  username    = each.key
  password    = var.default_password
  full_name   = each.value.full_name
  description = each.value.description
  groups      = each.value.groups
}
```

### Temporary Account with Expiration

While this resource doesn't directly support account expiration, you can combine it with external automation:

```hcl
resource "windows_localuser" "temp" {
  username    = "temp_user_${formatdate("YYYYMMDD", timestamp())}"
  password    = random_password.temp.result
  description = "Temporary account created ${formatdate("YYYY-MM-DD", timestamp())}"
}

resource "random_password" "temp" {
  length  = 16
  special = true
}

# Use external script or scheduled task to disable/delete after expiration
```

## Security Best Practices

### Password Management

```hcl
# Use Terraform variables marked as sensitive
variable "admin_password" {
  type      = string
  sensitive = true
}

resource "windows_localuser" "admin" {
  username = "admin_user"
  password = var.admin_password
}
```

```bash
# Pass password via environment variable
export TF_VAR_admin_password="P@ssw0rd123!"
terraform apply
```

### Least Privilege Principle

```hcl
# Regular user with minimal permissions
resource "windows_localuser" "app_service" {
  username                      = "svc_app"
  password                      = var.service_password
  description                   = "Application service account"
  password_never_expires        = true
  user_cannot_change_password   = true
  
  # Only add to groups necessary for the application
  groups = ["IIS_IUSRS"]
}
```

### Service Accounts

For service accounts, consider:

```hcl
resource "windows_localuser" "service" {
  username                    = "svc_backup"
  password                    = var.service_password
  full_name                   = "Backup Service Account"
  description                 = "Managed by Terraform - Do not modify manually"
  password_never_expires      = true
  user_cannot_change_password = true
  account_disabled            = false
  
  groups = ["Backup Operators"]
}
```

**Service account best practices**:
- Use descriptive names with `svc_` prefix
- Set `password_never_expires = true` to prevent service disruption
- Set `user_cannot_change_password = true` to prevent accidental changes
- Document the purpose in `description`
- Grant only necessary permissions via group memberships

## Updating User Attributes

### Changing Password

When you update the password in your configuration, Terraform will:
1. Detect the change during `terraform plan`
2. Update the password on the server during `terraform apply`
3. The user's session remains active (no logout)

⚠️ **Note**: The password is marked as sensitive and won't be displayed in plan output.

### Modifying Group Memberships

Terraform tracks group memberships and will:
- Add user to new groups
- Remove user from groups no longer listed
- Preserve memberships for groups managed outside Terraform (if not in the `groups` list)

### Enabling/Disabling Accounts

```hcl
resource "windows_localuser" "user" {
  username         = "john.doe"
  password         = var.password
  account_disabled = true  # Change from false to true to disable
}
```

## Troubleshooting

### User Already Exists

**Issue**: Error creating user because it already exists

**Solution**:
- Import the existing user: `terraform import windows_localuser.john john.doe`
- Or manually delete the user on Windows and re-run Terraform

### Permission Denied

**Issue**: `Access is denied` when creating/modifying users

**Solution**:
- The SSH user must have administrator rights
- Verify: `net localgroup Administrators`

### Password Complexity Error

**Issue**: Password does not meet complexity requirements

**Solution**:
- Check Windows password policy: `net accounts`
- Use a stronger password meeting all requirements
- Verify minimum length and character requirements

### Group Not Found

**Issue**: Error adding user to group because group doesn't exist

**Solution**:
- List available groups: `Get-LocalGroup`
- Create the group first (manually or with `windows_localgroup` resource)
- Use exact group name (case-sensitive)

### User Cannot Login

**Issue**: User created successfully but cannot login

**Solution**:
- Check if account is disabled: `Get-LocalUser -Name username | Select-Object Enabled`
- Verify Remote Desktop access: `net localgroup "Remote Desktop Users"`
- Check Group Policy restrictions

## Notes

- Username changes will force recreation of the user (new user will be created, old one deleted)
- Password updates are applied in-place without recreating the user
- Group memberships are managed as a set (order doesn't matter)
- The provider cannot read the current password from Windows (it's one-way encrypted)
- User profile data is not managed by this resource
- Home directory creation is not automatic (Windows default behavior)

## Related Resources

- `windows_localgroup` - Manage local groups
- Consider using Active Directory for domain environments
- For advanced user management, consider ADSI or Active Directory PowerShell module
