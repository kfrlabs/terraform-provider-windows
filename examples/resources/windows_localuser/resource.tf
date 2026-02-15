# Basic local user with minimal configuration
resource "windows_localuser" "basic" {
  username = "basicuser"
  password = "P@ssw0rd123!"
}

# Local administrator with full configuration
resource "windows_localuser" "admin" {
  username                    = "localadmin"
  password                    = "SecureP@ssw0rd!2024"
  full_name                   = "Local Administrator"
  description                 = "Local administrator account managed by Terraform"
  password_never_expires      = true
  user_cannot_change_password = false
  account_disabled            = false
}

# Service account with restricted password policy
resource "windows_localuser" "service_account" {
  username                    = "svc_webapp"
  password                    = var.service_account_password
  description                 = "Service account for web application"
  password_never_expires      = true
  user_cannot_change_password = true
  account_disabled            = false
}

# Disabled user account (for future use)
resource "windows_localuser" "disabled_user" {
  username         = "future_user"
  password         = "TempP@ssw0rd!"
  description      = "Account prepared but not yet active"
  account_disabled = true
}

# Temporary user with password expiration
resource "windows_localuser" "temp_user" {
  username                    = "tempuser"
  password                    = "TempP@ss123!"
  full_name                   = "Temporary User"
  description                 = "Temporary user account"
  password_never_expires      = false
  user_cannot_change_password = false
}

# Adopt existing user account
resource "windows_localuser" "existing_user" {
  username       = "existinguser"
  password       = var.existing_user_password
  description    = "Existing user now managed by Terraform"
  allow_existing = true
}

# User with custom command timeout
resource "windows_localuser" "slow_connection" {
  username        = "remoteuser"
  password        = "RemoteP@ss!"
  description     = "User on slow connection"
  command_timeout = 600 # 10 minutes
}

# Multiple users for a team
resource "windows_localuser" "developer" {
  for_each = toset(["dev1", "dev2", "dev3"])

  username                    = each.key
  password                    = var.developer_passwords[each.key]
  description                 = "Developer account for ${each.key}"
  password_never_expires      = false
  user_cannot_change_password = false
}

# User with computed attributes exported
resource "windows_localuser" "monitored_user" {
  username    = "monitoreduser"
  password    = "MonitorP@ss!"
  description = "User with exported attributes"
}

output "monitored_user_info" {
  value = {
    sid              = windows_localuser.monitored_user.sid
    password_last_set = windows_localuser.monitored_user.password_last_set
    password_required = windows_localuser.monitored_user.password_required
  }
  sensitive = false
}

# Backup administrator account
resource "windows_localuser" "backup_admin" {
  username                    = "backup_admin"
  password                    = var.backup_admin_password
  full_name                   = "Backup Administrator"
  description                 = "Emergency backup administrator account"
  password_never_expires      = true
  user_cannot_change_password = true
  account_disabled            = false
  allow_existing              = true
}

# Database service account
resource "windows_localuser" "db_service" {
  username                    = "svc_sqlserver"
  password                    = var.sql_service_password
  full_name                   = "SQL Server Service Account"
  description                 = "Service account for SQL Server"
  password_never_expires      = true
  user_cannot_change_password = true
}

# IIS application pool identity
resource "windows_localuser" "iis_apppool" {
  username                    = "iis_apppool_user"
  password                    = var.iis_password
  description                 = "IIS Application Pool Identity"
  password_never_expires      = true
  user_cannot_change_password = true
  account_disabled            = false
}

# Test user account
resource "windows_localuser" "test_user" {
  username    = "testuser"
  password    = "TestP@ssw0rd!"
  description = "Test user account"

  lifecycle {
    ignore_changes = [password]
  }
}