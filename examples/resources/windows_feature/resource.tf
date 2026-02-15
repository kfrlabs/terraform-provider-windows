# Basic web server installation
resource "windows_feature" "web_server" {
  feature = "Web-Server"
}

# Web server with all sub-features and management tools
resource "windows_feature" "web_server_full" {
  feature                    = "Web-Server"
  include_all_sub_features   = true
  include_management_tools   = true
}

# Active Directory Domain Services with management tools
resource "windows_feature" "ad_domain_services" {
  feature                  = "AD-Domain-Services"
  include_management_tools = true
  allow_existing           = true
}

# DNS Server with automatic restart
resource "windows_feature" "dns_server" {
  feature = "DNS"
  restart = true
}

# DHCP Server with custom timeout
resource "windows_feature" "dhcp_server" {
  feature         = "DHCP"
  command_timeout = 600
}

# Hyper-V with all components
resource "windows_feature" "hyperv" {
  feature                    = "Hyper-V"
  include_all_sub_features   = true
  include_management_tools   = true
  restart                    = true
  command_timeout            = 900
}

# File Server Resource Manager (FSRM)
resource "windows_feature" "fsrm" {
  feature                  = "FS-Resource-Manager"
  include_management_tools = true
}

# Remote Desktop Services
resource "windows_feature" "rds" {
  feature                  = "RDS-RD-Server"
  include_all_sub_features = true
}

# Windows Server Backup
resource "windows_feature" "backup" {
  feature = "Windows-Server-Backup"
}

# Adopting an existing feature installation
resource "windows_feature" "existing_iis" {
  feature        = "Web-Server"
  allow_existing = true
}