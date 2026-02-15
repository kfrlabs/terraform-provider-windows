# Basic local group with minimal configuration
resource "windows_localgroup" "developers" {
  name        = "Developers"
  description = "Development team members"
}

# Local group with detailed description
resource "windows_localgroup" "admins" {
  name        = "CustomAdmins"
  description = "Custom administrators group for application management"
}

# Adopt existing built-in group
resource "windows_localgroup" "existing_users" {
  name           = "Users"
  description    = "Standard users group managed by Terraform"
  allow_existing = true
}

# Group without description
resource "windows_localgroup" "basic_group" {
  name = "BasicGroup"
}

# Remote Desktop Users group
resource "windows_localgroup" "rdp_users" {
  name        = "RemoteDesktopUsers"
  description = "Users allowed to connect via Remote Desktop"
}

# Application-specific groups
resource "windows_localgroup" "webapp_users" {
  name        = "WebApp_Users"
  description = "Users with access to web application"
}

resource "windows_localgroup" "webapp_admins" {
  name        = "WebApp_Admins"
  description = "Administrators for web application"
}

# Database access groups
resource "windows_localgroup" "db_readers" {
  name        = "DB_Readers"
  description = "Read-only access to databases"
}

resource "windows_localgroup" "db_writers" {
  name        = "DB_Writers"
  description = "Read-write access to databases"
}

# Service management groups
resource "windows_localgroup" "service_operators" {
  name        = "ServiceOperators"
  description = "Users allowed to manage Windows services"
}

# Backup operators group
resource "windows_localgroup" "backup_ops" {
  name        = "BackupOperators"
  description = "Backup and restore operators"
}

# Multiple groups for different environments
resource "windows_localgroup" "environment_groups" {
  for_each = toset(["Dev_Team", "QA_Team", "Ops_Team"])

  name        = each.key
  description = "Access group for ${each.key}"
}

# Group with custom timeout
resource "windows_localgroup" "slow_connection" {
  name            = "RemoteGroup"
  description     = "Group on slow connection"
  command_timeout = 600 # 10 minutes
}

# File server access groups
resource "windows_localgroup" "fileserver_users" {
  name        = "FileServer_Users"
  description = "Standard file server access"
}

resource "windows_localgroup" "fileserver_powerusers" {
  name        = "FileServer_PowerUsers"
  description = "Advanced file server access with quota management"
}

# Monitoring and auditing group
resource "windows_localgroup" "auditors" {
  name        = "SecurityAuditors"
  description = "Security auditing and monitoring team"
}

# Hyper-V administrators
resource "windows_localgroup" "hyperv_admins" {
  name           = "Hyper-V Administrators"
  description    = "Hyper-V virtual machine administrators"
  allow_existing = true
}

# IIS management group
resource "windows_localgroup" "iis_admins" {
  name        = "IIS_Admins"
  description = "IIS web server administrators"
}

# Group with computed attributes exported
resource "windows_localgroup" "monitored_group" {
  name        = "MonitoredGroup"
  description = "Group with exported attributes"
}

output "monitored_group_info" {
  value = {
    name             = windows_localgroup.monitored_group.name
    sid              = windows_localgroup.monitored_group.sid
    principal_source = windows_localgroup.monitored_group.principal_source
    object_class     = windows_localgroup.monitored_group.object_class
  }
}

# Security groups for different access levels
resource "windows_localgroup" "level1_access" {
  name        = "Security_Level1"
  description = "Level 1 security access - Basic permissions"
}

resource "windows_localgroup" "level2_access" {
  name        = "Security_Level2"
  description = "Level 2 security access - Enhanced permissions"
}

resource "windows_localgroup" "level3_access" {
  name        = "Security_Level3"
  description = "Level 3 security access - Administrative permissions"
}

# Application service groups
resource "windows_localgroup" "app_services" {
  name        = "AppServices"
  description = "Service accounts for applications"
}

# Network administrators group
resource "windows_localgroup" "network_admins" {
  name        = "NetworkAdmins"
  description = "Network configuration and management"
}

# Print operators group
resource "windows_localgroup" "print_ops" {
  name        = "PrintOperators"
  description = "Print queue and printer management"
}

# Help desk group
resource "windows_localgroup" "helpdesk" {
  name        = "HelpDesk"
  description = "Help desk support team with limited admin rights"
}

# Certificate administrators
resource "windows_localgroup" "cert_admins" {
  name        = "CertificateAdmins"
  description = "Certificate management and PKI operations"
}

# Event log readers
resource "windows_localgroup" "log_readers" {
  name           = "Event Log Readers"
  description    = "Read access to Windows event logs"
  allow_existing = true
}

# Performance monitor users
resource "windows_localgroup" "perf_users" {
  name           = "Performance Monitor Users"
  description    = "Performance monitoring and diagnostics"
  allow_existing = true
}

# Distributed COM users
resource "windows_localgroup" "dcom_users" {
  name           = "Distributed COM Users"
  description    = "DCOM application access"
  allow_existing = true
}