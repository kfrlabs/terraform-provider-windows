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
resource "windows_localuser" "service_account" {
  username                    = "AppServiceAccount"
  password                    = var.service_password
  full_name                   = "Application Service Account"
  description                 = "Service account for MyApp"
  password_never_expires      = true
  user_cannot_change_password = true
}
```

### Disabled User Account

```hcl
resource "windows_localuser" "temp_user" {
  username         = "TempUser"
  password         = var.temp_password
  description      = "Temporary account"
  account_disabled = true
}
```

### Adopt Existing User

```hcl
resource "windows_localuser" "existing_user" {
  username       = "Administrator"
  password       = var.admin_password
  allow_existing = true
}
```

## Argument Reference

The following arguments are supported:

* `username` - (Required, Forces new resource) The name of the local user account. Cannot be changed after creation.
* `password` - (Required, Sensitive) The password for the local user account. Changes to this field will trigger an update.
* `full_name` - (Optional) The full name of the user.
* `description` - (Optional) A description for the user account.
* `password_never_expires` - (Optional) If `true`, the password will never expire. Defaults to `false`.
* `user_cannot_change_password` - (Optional) If `true`, the user cannot change their password. Defaults to `false`.
* `account_disabled` - (Optional) If `true`, the account will be disabled. Defaults to `false`.
* `allow_existing` - (Optional) If `true`, adopt existing user instead of failing. If `false`, fail if user already exists. Defaults to `false`.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300` (5 minutes).

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The username of the local user.

## Import

Local users can be imported using the username:

```shell
terraform import windows_localuser.john "john.doe"
```

**Note:** When importing, you must provide the password in your configuration, as it cannot be retrieved from the system.

## Behavior Notes

### Existing User Handling

When creating a user resource:
- If the user **does not exist**, it will be created normally.
- If the user **already exists**:
  - With `allow_existing = false` (default): Resource creation fails with error message suggesting import or setting `allow_existing = true`.
  - With `allow_existing = true`: The existing user is adopted into Terraform state. The password and other attributes will be updated to match the configuration.

### Password Management

- The password is marked as **sensitive** and will not appear in Terraform logs or output.
- Password changes are detected and will trigger an update of the user account.
- The actual password value cannot be read from the system, so Terraform relies on the value in the configuration.

### Account Status

The `account_disabled` attribute controls whether the account is enabled:
- `account_disabled = false`: Account is enabled (default)
- `account_disabled = true`: Account is disabled and cannot be used to log in

### User Account Properties Update

When updating an existing user:
- Password changes are applied via `Set-LocalUser`
- Full name, description, and password policy flags can be updated
- Account enabled/disabled status can be toggled
- Username cannot be changed (ForceNew)

## Common Use Cases

### Service Accounts

```hcl
resource "windows_localuser" "iis_app_pool" {
  username                    = "IISAppPoolUser"
  password                    = var.iis_password
  full_name                   = "IIS Application Pool User"
  description                 = "User account for IIS application pool"
  password_never_expires      = true
  user_cannot_change_password = true
}

resource "windows_localgroupmember" "iis_membership" {
  group  = "IIS_IUSRS"
  member = windows_localuser.iis_app_pool.username
}
```

### Administrative User

```hcl
resource "windows_localuser" "app_admin" {
  username    = "AppAdmin"
  password    = var.admin_password
  full_name   = "Application Administrator"
  description = "Administrator for application management"
}

resource "windows_localgroupmember" "app_admin_membership" {
  group  = "Administrators"
  member = windows_localuser.app_admin.username
}
```

### Temporary User with Expiration

```hcl
resource "windows_localuser" "contractor" {
  username                    = "ContractorUser"
  password                    = var.contractor_password
  full_name                   = "External Contractor"
  description                 = "Temporary contractor access - Valid until 2026-06-30"
  password_never_expires      = false
  user_cannot_change_password = true
}
```

## Security Considerations

1. **Password Storage**: Store passwords in Terraform variables, environment variables, or a secure secrets management system. Never commit passwords to version control.

2. **Password Complexity**: Ensure passwords meet Windows complexity requirements:
   - At least 8 characters (recommended: 12+)
   - Mix of uppercase, lowercase, numbers, and symbols
   - Not containing the username

3. **Least Privilege**: Create users with minimal necessary permissions. Use group membership to grant additional access rather than making every user an administrator.

4. **Service Accounts**: For service accounts:
   - Set `password_never_expires = true`
   - Set `user_cannot_change_password = true`
   - Use descriptive names and descriptions
   - Document the purpose of each service account

## Password Change Example

```hcl
variable "current_password" {
  type      = string
  sensitive = true
}

resource "windows_localuser" "app_user" {
  username = "AppUser"
  password = var.current_password
  full_name = "Application User"
}

# To change the password, update the variable value and apply:
# terraform apply -var="current_password=NewP@ssw0rd456!"
```