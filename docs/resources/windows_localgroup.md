# windows_localgroup

Manages local groups on Windows servers.

## Example Usage

### Basic Group Creation

```hcl
resource "windows_localgroup" "app_admins" {
  group       = "Application Admins"
  description = "Administrators for the application"
}
```

### Group with Members

```hcl
resource "windows_localgroup" "backup_operators" {
  group       = "Backup Team"
  description = "Backup operators group"
  
  members = [
    "backup_admin",
    "svc_backup",
    "DOMAIN\\BackupUser"
  ]
}
```

### Group with Domain Users

```hcl
resource "windows_localgroup" "remote_support" {
  group       = "Remote Support"
  description = "Remote support team members"
  
  members = [
    "CONTOSO\\SupportTeam",
    "CONTOSO\\john.doe",
    "local_admin"
  ]
}
```

### Complete Example with Local Users

```hcl
# Create local users
resource "windows_localuser" "operator1" {
  username = "operator1"
  password = var.operator1_password
  full_name = "Operator One"
}

resource "windows_localuser" "operator2" {
  username = "operator2"
  password = var.operator2_password
  full_name = "Operator Two"
}

# Create group and add users
resource "windows_localgroup" "operators" {
  group       = "System Operators"
  description = "System operation team"
  
  members = [
    windows_localuser.operator1.username,
    windows_localuser.operator2.username
  ]
  
  depends_on = [
    windows_localuser.operator1,
    windows_localuser.operator2
  ]
}
```

## Argument Reference

The following arguments are supported:

* `group` - (Required, String, ForceNew) The name of the local group. Group name cannot be changed after creation (will force recreation).

* `description` - (Optional, String) A description for the local group.

* `members` - (Optional, Set of Strings) Members to ensure are part of the group. Members can be:
  - Local user accounts (e.g., `"username"`)
  - Domain users (e.g., `"DOMAIN\\username"`)
  - Domain groups (e.g., `"DOMAIN\\GroupName"`)

* `command_timeout` - (Optional, Number) Timeout in seconds for PowerShell commands. Default: `300` (5 minutes).

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The group name.

## Import

Local groups can be imported using the group name:

```bash
terraform import windows_localgroup.app_admins "Application Admins"
```

When importing, Terraform will read the current group description and members. Note that the members list may include domain users/groups if the server is domain-joined.

## Member Name Formats

### Local Users

For local user accounts, use just the username:

```hcl
members = [
  "john.doe",
  "admin_user",
  "svc_backup"
]
```

### Domain Users

For domain users, use the format `DOMAIN\username`:

```hcl
members = [
  "CONTOSO\\john.doe",
  "CONTOSO\\jane.smith",
  "AD\\admin_user"
]
```

### Domain Groups

Domain groups can also be members of local groups:

```hcl
members = [
  "CONTOSO\\Domain Admins",
  "CONTOSO\\IT Support",
  "AD\\Developers"
]
```

### Mixed Members

You can mix local and domain members:

```hcl
resource "windows_localgroup" "admins" {
  group = "Server Administrators"
  
  members = [
    "local_admin",              # Local user
    "CONTOSO\\Domain Admins",   # Domain group
    "CONTOSO\\john.doe",        # Domain user
    "svc_app"                   # Local user
  ]
}
```

## Managing Group Membership

### Adding Members

When you add members to the `members` list, Terraform will:
1. Detect the change during `terraform plan`
2. Add the new members during `terraform apply`
3. Preserve existing members not managed by Terraform (if any)

### Removing Members

When you remove members from the `members` list:
1. Terraform will detect the removal
2. Remove those members from the group during apply
3. Keep other members in the list

### Updating Members

```hcl
# Before
resource "windows_localgroup" "operators" {
  group = "Operators"
  members = ["user1", "user2", "user3"]
}

# After - user2 removed, user4 added
resource "windows_localgroup" "operators" {
  group = "operators"
  members = ["user1", "user3", "user4"]
}
```

Result:
- `user1` and `user3` remain in the group
- `user2` is removed from the group
- `user4` is added to the group

### Empty Group

To create a group with no members:

```hcl
resource "windows_localgroup" "future_use" {
  group       = "Reserved Group"
  description = "Reserved for future use"
  # No members attribute = empty group
}
```

## Common Use Cases

### Application-Specific Groups

```hcl
resource "windows_localgroup" "web_app_admins" {
  group       = "WebApp Admins"
  description = "Administrators for the web application"
  
  members = [
    "CONTOSO\\WebAppTeam",
    "local_webadmin"
  ]
}

resource "windows_localgroup" "web_app_users" {
  group       = "WebApp Users"
  description = "Users of the web application"
  
  members = [
    "CONTOSO\\AllEmployees",
    "CONTOSO\\Contractors"
  ]
}
```

### Service Account Groups

```hcl
resource "windows_localgroup" "service_accounts" {
  group       = "Service Accounts"
  description = "All service accounts on this server"
  
  members = [
    "svc_webapp",
    "svc_backup",
    "svc_monitoring"
  ]
}
```

### Delegation Groups

```hcl
resource "windows_localgroup" "log_readers" {
  group       = "Log Readers"
  description = "Users who can read logs"
  
  members = [
    "CONTOSO\\SecurityTeam",
    "monitoring_user"
  ]
}

# Use in ACL/permissions configuration
```

### Dynamic Member Assignment

```hcl
variable "dev_users" {
  type    = list(string)
  default = ["dev1", "dev2", "dev3"]
}

resource "windows_localuser" "developers" {
  for_each = toset(var.dev_users)
  
  username = each.value
  password = var.dev_password
}

resource "windows_localgroup" "developers" {
  group       = "Developers"
  description = "Development team members"
  
  members = [for user in windows_localuser.developers : user.username]
  
  depends_on = [windows_localuser.developers]
}
```

## Built-in Windows Groups

Some commonly used built-in local groups:

### Administrative
- `Administrators` - Full control of the computer
- `Power Users` - Legacy group (mostly deprecated)
- `Server Operators` - Can administer domain servers

### Remote Access
- `Remote Desktop Users` - Can log on remotely via RDP
- `Remote Management Users` - Can manage the server via WMI and WinRM

### Backup and Recovery
- `Backup Operators` - Can override security to back up files
- `Replicator` - Supports file replication

### Networking
- `Network Configuration Operators` - Can modify network settings
- `Distributed COM Users` - Can launch DCOM applications

### Monitoring
- `Performance Monitor Users` - Can access performance data locally/remotely
- `Performance Log Users` - Can manage performance counters and logs
- `Event Log Readers` - Can read event logs

### IIS (if installed)
- `IIS_IUSRS` - Used by IIS worker processes

⚠️ **Warning**: Be careful when modifying built-in groups as it can affect system security and functionality.

## Group Naming Best Practices

### Naming Conventions

```hcl
# Application-based
"AppName Admins"
"AppName Users"
"AppName Operators"

# Role-based
"Server Administrators"
"Backup Operators"
"Log Readers"

# Environment-based
"Production Support"
"Development Team"
"QA Testers"

# Function-based
"Database Admins"
"Web Server Managers"
"Security Auditors"
```

### Descriptive Names

```hcl
# ✅ Good - Clear and descriptive
resource "windows_localgroup" "sql_db_admins" {
  group = "SQL Database Administrators"
  description = "Administrators for SQL Server databases"
}

# ❌ Avoid - Too generic or unclear
resource "windows_localgroup" "group1" {
  group = "Group1"
  description = "Some users"
}
```

## Security Considerations

### Principle of Least Privilege

```hcl
# Create specific groups for specific tasks
resource "windows_localgroup" "file_readers" {
  group       = "File Readers"
  description = "Read-only access to shared files"
  members     = ["user1", "user2"]
}

# Instead of adding everyone to Administrators
# ❌ Don't do this unless necessary
resource "windows_localgroup" "bad_practice" {
  group   = "Administrators"
  members = ["user1", "user2", "user3"]  # Too many admins
}
```

### Domain User Management

When adding domain users to local groups:

```hcl
resource "windows_localgroup" "remote_admins" {
  group       = "Remote Administrators"
  description = "Can administer this server remotely"
  
  members = [
    "CONTOSO\\ServerAdmins",     # Domain group
    "CONTOSO\\john.doe",         # Specific user for emergency access
    "local_admin"                # Local admin account
  ]
}
```

Best practices:
- Prefer domain groups over individual domain users
- Use specific groups rather than broad groups (e.g., "IT Support" not "All Employees")
- Document why domain accounts need local access
- Regular review and audit of group memberships

### Audit and Compliance

```hcl
resource "windows_localgroup" "privileged_users" {
  group       = "Privileged Users"
  description = "Users with elevated privileges - AUDIT REQUIRED"
  
  members = [
    "admin_user",
    "CONTOSO\\ITAdmin"
  ]
  
  # Document in comments
  # Created: 2024-01-15
  # Owner: IT Security Team
  # Review: Quarterly
  # Last reviewed: 2024-01-15
}
```

## Troubleshooting

### Permission Denied

**Issue**: Error creating or modifying group

**Solution**:
- SSH user must have administrator rights
- Verify: `net localgroup Administrators`

### Member Not Found

**Issue**: Error adding member to group - member doesn't exist

**Solution**:
- For local users: Ensure user exists first (create with `windows_localuser`)
- For domain users: Verify username format (`DOMAIN\username`)
- Check that domain is accessible from the server
- List existing users: `Get-LocalUser` or `net user /domain`

### Group Already Exists

**Issue**: Error creating group because it already exists

**Solution**:
- Import the existing group: `terraform import windows_localgroup.name "Group Name"`
- Or manually delete the group and re-run Terraform

### Domain User Format Error

**Issue**: Cannot add domain user to group

**Solution**:
- Use correct format: `DOMAIN\username` (not `username@domain.com`)
- Use double backslash in HCL: `"DOMAIN\\username"`
- Verify domain connectivity: `nltest /dsgetdc:DOMAIN`

### Group Name Contains Spaces

**Issue**: Group name with spaces causing issues

**Solution**:
- Use quotes in Terraform: `group = "My Group Name"`
- Use quotes in import: `terraform import windows_localgroup.name "My Group Name"`

## Notes

- Group name changes will force recreation (ForceNew)
- Description can be updated without recreating the group
- Member order doesn't matter (stored as a Set)
- Built-in groups cannot be deleted
- Removing the resource from Terraform will delete the group (be careful with built-in groups)
- The provider manages group membership additively - members not in Terraform are left alone unless explicitly removed

## Relationship with Other Resources

### With Local Users

```hcl
resource "windows_localuser" "admin" {
  username = "app_admin"
  password = var.password
}

resource "windows_localgroup" "admins" {
  group   = "App Admins"
  members = [windows_localuser.admin.username]
  
  depends_on = [windows_localuser.admin]
}
```

### With Features

```hcl
# Install IIS
resource "windows_feature" "iis" {
  feature = "Web-Server"
}

# Create IIS administrators group
resource "windows_localgroup" "iis_admins" {
  group       = "IIS Administrators"
  description = "IIS Server Administrators"
  
  depends_on = [windows_feature.iis]
}
```

## Related Resources

- `windows_localuser` - Create users to add to groups
- `windows_feature` - Some features create their own groups
- Consider Active Directory groups for domain environments
