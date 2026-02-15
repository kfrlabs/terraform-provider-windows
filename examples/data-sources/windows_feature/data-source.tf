# Read information about a specific Windows feature
data "windows_feature" "web_server" {
  feature = "Web-Server"
}

# Output feature information
output "web_server_info" {
  value = {
    name               = data.windows_feature.web_server.display_name
    installed          = data.windows_feature.web_server.installed
    install_state      = data.windows_feature.web_server.install_state
    feature_type       = data.windows_feature.web_server.feature_type
    restart_needed     = data.windows_feature.web_server.restart_needed
    sub_features_count = length(data.windows_feature.web_server.sub_features)
  }
}

# Check if a feature is installed before creating a resource
data "windows_feature" "hyperv" {
  feature = "Hyper-V"
}

resource "windows_feature" "hyperv_management" {
  count   = data.windows_feature.hyperv.installed ? 1 : 0
  feature = "Hyper-V-Tools"
}

# Read multiple features
data "windows_feature" "ad_domain_services" {
  feature = "AD-Domain-Services"
}

data "windows_feature" "dns" {
  feature = "DNS"
}

data "windows_feature" "dhcp" {
  feature = "DHCP"
}

# Conditional logic based on feature state
locals {
  web_server_ready = (
    data.windows_feature.web_server.installed &&
    data.windows_feature.web_server.install_state == "Installed" &&
    !data.windows_feature.web_server.restart_needed
  )
}

output "web_server_status" {
  value = local.web_server_ready ? "Ready" : "Not Ready"
}

# Check feature dependencies
data "windows_feature" "iis_base" {
  feature = "Web-Server"
}

data "windows_feature" "iis_asp_net" {
  feature = "Web-Asp-Net45"
}

output "iis_asp_net_available" {
  value = data.windows_feature.iis_asp_net.installed || data.windows_feature.iis_base.installed
}

# Read feature with custom timeout
data "windows_feature" "slow_connection" {
  feature         = "FS-Resource-Manager"
  command_timeout = 600
}

# Get all sub-features information
data "windows_feature" "rds" {
  feature = "RDS-RD-Server"
}

output "rds_sub_features" {
  value = data.windows_feature.rds.sub_features
}

# Verify feature before installation
data "windows_feature" "target_feature" {
  feature = "Web-Mgmt-Console"
}

resource "windows_feature" "install_if_not_present" {
  count                    = !data.windows_feature.target_feature.installed ? 1 : 0
  feature                  = data.windows_feature.target_feature.feature
  include_management_tools = true
}

# Check feature type before operations
data "windows_feature" "file_services" {
  feature = "FS-FileServer"
}

output "is_role" {
  value = data.windows_feature.file_services.feature_type == "Role"
}