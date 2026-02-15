# Read information about a specific local user
data "windows_localuser" "admin" {
  username = "Administrator"
}

# Output user information
output "admin_user_info" {
  value = {
    username          = data.windows_localuser.admin.username
    full_name         = data.windows_localuser.admin.full_name
    description       = data.windows_localuser.admin.description
    sid               = data.windows_localuser.admin.sid
    enabled           = data.windows_localuser.admin.enabled
    password_required = data.windows_localuser.admin.password_required
  }
}

# Check if user exists before operations
data "windows_localuser" "existing_user" {
  username = "existinguser"
}

resource "windows_localgroup" "user_group" {
  count       = data.windows_localuser.existing_user.enabled ? 1 : 0
  name        = "Group_${data.windows_localuser.existing_user.username}"
  description = "Group for ${data.windows_localuser.existing_user.full_name}"
}

# Read multiple users
data "windows_localuser" "admin" {
  username = "Administrator"
}

data "windows_localuser" "guest" {
  username = "Guest"
}

locals {
  system_users = {
    admin = data.windows_localuser.admin.sid
    guest = data.windows_localuser.guest.sid
  }
}

# Check user account status
data "windows_localuser" "service_account" {
  username = "svc_webapp"
}

output "service_account_status" {
  value = {
    exists               = data.windows_localuser.service_account.username != ""
    enabled              = data.windows_localuser.service_account.enabled
    password_expires     = !data.windows_localuser.service_account.password_never_expires
    can_change_password  = !data.windows_localuser.service_account.user_cannot_change_password
    lockout_status       = data.windows_localuser.service_account.lockout_status
  }
}

# Validate user properties before applying changes
data "windows_localuser" "check_user" {
  username = "targetuser"
}

resource "windows_localuser" "update_if_needed" {
  count                       = data.windows_localuser.check_user.enabled ? 1 : 0
  username                    = data.windows_localuser.check_user.username
  password                    = var.user_password
  description                 = "Updated by Terraform"
  password_never_expires      = true
  user_cannot_change_password = true
  allow_existing              = true
}

# Use SID in configurations
data "windows_localuser" "admin_user" {
  username = "Administrator"
}

output "admin_sid" {
  value       = data.windows_localuser.admin_user.sid
  description = "Administrator SID for ACL configurations"
}

# Check password policy compliance
data "windows_localuser" "policy_check" {
  username = "testuser"
}

locals {
  password_policy_compliant = (
    data.windows_localuser.policy_check.password_required &&
    !data.windows_localuser.policy_check.password_expired &&
    data.windows_localuser.policy_check.password_age_days < 90
  )
}

output "password_compliance" {
  value = local.password_policy_compliant
}

# Monitor user account age
data "windows_localuser" "old_account" {
  username = "legacyuser"
}

output "account_age" {
  value = {
    created_days_ago       = data.windows_localuser.old_account.account_age_days
    password_last_set_days = data.windows_localuser.old_account.password_age_days
    last_logon_days        = data.windows_localuser.old_account.last_logon_days_ago
  }
}

# Custom timeout for slow connections
data "windows_localuser" "remote_user" {
  username        = "remoteuser"
  command_timeout = 600
}

# Conditional resource creation based on user state
data "windows_localuser" "temp_user" {
  username = "tempuser"
}

resource "windows_localuser" "create_if_missing" {
  count       = data.windows_localuser.temp_user.username == "" ? 1 : 0
  username    = "tempuser"
  password    = var.temp_password
  description = "Temporary user created by Terraform"
}

# Security audit - list user properties
data "windows_localuser" "audit_user" {
  username = "audituser"
}

output "security_audit" {
  value = {
    username                    = data.windows_localuser.audit_user.username
    enabled                     = data.windows_localuser.audit_user.enabled
    password_never_expires      = data.windows_localuser.audit_user.password_never_expires
    user_cannot_change_password = data.windows_localuser.audit_user.user_cannot_change_password
    lockout_status              = data.windows_localuser.audit_user.lockout_status
    password_expired            = data.windows_localuser.audit_user.password_expired
    sid                         = data.windows_localuser.audit_user.sid
  }
  sensitive = false
}

# Compare user configurations
data "windows_localuser" "user1" {
  username = "user1"
}

data "windows_localuser" "user2" {
  username = "user2"
}

locals {
  users_have_same_policy = (
    data.windows_localuser.user1.password_never_expires == data.windows_localuser.user2.password_never_expires &&
    data.windows_localuser.user1.user_cannot_change_password == data.windows_localuser.user2.user_cannot_change_password
  )
}