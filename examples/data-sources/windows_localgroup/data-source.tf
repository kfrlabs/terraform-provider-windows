# Read information about a specific local group
data "windows_localgroup" "administrators" {
  name = "Administrators"
}

# Output group information
output "administrators_info" {
  value = {
    name             = data.windows_localgroup.administrators.name
    sid              = data.windows_localgroup.administrators.sid
    description      = data.windows_localgroup.administrators.description
    principal_source = data.windows_localgroup.administrators.principal_source
    object_class     = data.windows_localgroup.administrators.object_class
  }
}

# Check if group exists before operations
data "windows_localgroup" "existing_group" {
  name = "CustomGroup"
}

resource "windows_localuser" "group_member" {
  username    = "groupuser"
  password    = var.user_password
  description = "Member of ${data.windows_localgroup.existing_group.name}"
}

# Read multiple built-in groups
data "windows_localgroup" "administrators" {
  name = "Administrators"
}

data "windows_localgroup" "users" {
  name = "Users"
}

data "windows_localgroup" "guests" {
  name = "Guests"
}

locals {
  builtin_groups = {
    administrators = data.windows_localgroup.administrators.sid
    users          = data.windows_localgroup.users.sid
    guests         = data.windows_localgroup.guests.sid
  }
}

output "builtin_group_sids" {
  value = local.builtin_groups
}

# Use group SID for ACL configurations
data "windows_localgroup" "backup_operators" {
  name = "Backup Operators"
}

output "backup_operators_sid" {
  value       = data.windows_localgroup.backup_operators.sid
  description = "Backup Operators SID for ACL configurations"
}

# Conditional group creation
data "windows_localgroup" "check_group" {
  name = "Developers"
}

resource "windows_localgroup" "create_if_missing" {
  count       = data.windows_localgroup.check_group.name == "" ? 1 : 0
  name        = "Developers"
  description = "Development team group created by Terraform"
}

# Read Remote Desktop Users group
data "windows_localgroup" "rdp_users" {
  name = "Remote Desktop Users"
}

output "rdp_group_info" {
  value = {
    sid         = data.windows_localgroup.rdp_users.sid
    description = data.windows_localgroup.rdp_users.description
  }
}

# Custom timeout for slow connections
data "windows_localgroup" "remote_group" {
  name            = "RemoteGroup"
  command_timeout = 600
}

# Security groups validation
data "windows_localgroup" "security_group" {
  name = "SecurityAuditors"
}

output "security_group_status" {
  value = {
    exists           = data.windows_localgroup.security_group.name != ""
    sid              = data.windows_localgroup.security_group.sid
    principal_source = data.windows_localgroup.security_group.principal_source
  }
}

# Read Hyper-V related groups
data "windows_localgroup" "hyperv_admins" {
  name = "Hyper-V Administrators"
}

output "hyperv_admin_sid" {
  value = data.windows_localgroup.hyperv_admins.sid
}

# Event Log Readers group
data "windows_localgroup" "log_readers" {
  name = "Event Log Readers"
}

output "log_readers_info" {
  value = {
    sid         = data.windows_localgroup.log_readers.sid
    object_class = data.windows_localgroup.log_readers.object_class
  }
}

# Performance Monitor Users group
data "windows_localgroup" "perf_users" {
  name = "Performance Monitor Users"
}

# Network Configuration Operators
data "windows_localgroup" "network_ops" {
  name = "Network Configuration Operators"
}

# Compare multiple groups
data "windows_localgroup" "power_users" {
  name = "Power Users"
}

data "windows_localgroup" "users" {
  name = "Users"
}

locals {
  power_users_sid = data.windows_localgroup.power_users.sid
  users_sid       = data.windows_localgroup.users.sid
  sids_different  = local.power_users_sid != local.users_sid
}

# Application-specific groups
data "windows_localgroup" "iis_users" {
  name = "IIS_IUSRS"
}

output "iis_users_sid" {
  value = data.windows_localgroup.iis_users.sid
}

# Cryptographic Operators
data "windows_localgroup" "crypto_ops" {
  name = "Cryptographic Operators"
}

# Distributed COM Users
data "windows_localgroup" "dcom_users" {
  name = "Distributed COM Users"
}

output "special_groups" {
  value = {
    crypto_ops = {
      sid         = data.windows_localgroup.crypto_ops.sid
      description = data.windows_localgroup.crypto_ops.description
    }
    dcom_users = {
      sid         = data.windows_localgroup.dcom_users.sid
      description = data.windows_localgroup.dcom_users.description
    }
  }
}

# Verify group before adding it to managed resources
data "windows_localgroup" "target_group" {
  name = "TargetGroup"
}

resource "windows_localgroup" "update_if_exists" {
  count          = data.windows_localgroup.target_group.name != "" ? 1 : 0
  name           = data.windows_localgroup.target_group.name
  description    = "Updated by Terraform"
  allow_existing = true
}