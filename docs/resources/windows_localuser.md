# Windows Local User Resource

Manages local user accounts on a Windows server via SSH and PowerShell remote execution.

## Example Usage

### Basic Usage

```hcl
resource "windows_localuser" "example" {
  username = "johndoe"
  password = "SuperSecureP@ssw0rd"
  full_name = "John Doe"
  description = "Regular user account"
}
```

### Advanced Usage with Groups

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

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **username** | string | The name of the local user account. Must be unique on the system. |
| **password** | string | The password for the local user account. Should meet Windows password complexity requirements. |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **full_name** | string | null | The full name of the user. |
| **description** | string | null | A description for the user account. |
| **password_never_expires** | bool | false | If true, the password will never expire. |
| **user_cannot_change_password** | bool | false | If true, the user cannot change their own password. |
| **account_disabled** | bool | false | If true, the account will be created in a disabled state. |
| **groups** | set(string) | [] | List of local groups this user should be a member of. |
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands. |

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | The username of the local user (same as username argument). |

## Import

Local users can be imported using the username:

```shell
terraform import windows_localuser.example username
```

## Advanced Examples

### Creating a Service Account

```hcl
resource "windows_localuser" "service_account" {
  username                    = "svc_app"
  password                    = "ServiceP@ssw0rd!"
  description                 = "Service account for application"
  password_never_expires      = true
  user_cannot_change_password = true
  groups                      = ["Users"]
}
```

### Creating Multiple Users

```hcl
variable "users" {
  type = map(object({
    full_name   = string
    description = string
    groups      = list(string)
  }))
  default = {
    "user1" = {
      full_name   = "User One"
      description = "First user"
      groups      = ["Users"]
    },
    "user2" = {
      full_name   = "User Two"
      description = "Second user"
      groups      = ["Users", "Remote Desktop Users"]
    }
  }
}

resource "windows_localuser" "multiple_users" {
  for_each = var.users

  username    = each.key
  password    = "ChangeMe123!"  # Should be changed on first login
  full_name   = each.value.full_name
  description = each.value.description
  groups      = each.value.groups
}
```

## Troubleshooting

### Password Requirements

Windows has specific password complexity requirements:
- At least 8 characters long
- Contains characters from at least 3 of these categories:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters (!@#$%^&*...)

### Common Issues

1. **Access Denied**
   - Ensure the SSH user has administrative privileges
   - Check Windows Event Logs for more details

2. **Group Membership Failed**
   - Verify the group exists on the system
   - Check group name spelling
   - Ensure no circular group dependencies

3. **Password Complexity**
   - Password doesn't meet Windows requirements
   - Local security policy may enforce additional requirements

## Best Practices

1. Always use strong passwords
2. Limit administrative access
3. Use descriptive usernames and full names
4. Document account purposes in descriptions
5. Regular password rotation unless specifically required otherwise