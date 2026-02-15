# Read current hostname
data "windows_hostname" "current" {}

# Output hostname information
output "current_hostname" {
  value = data.windows_hostname.current.hostname
}

output "dns_hostname" {
  value = data.windows_hostname.current.dns_hostname
}

output "computer_info" {
  value = {
    hostname     = data.windows_hostname.current.hostname
    dns_hostname = data.windows_hostname.current.dns_hostname
    domain       = data.windows_hostname.current.domain
    part_of_domain = data.windows_hostname.current.part_of_domain
    workgroup    = data.windows_hostname.current.workgroup
  }
}

# Check if restart is needed
output "restart_pending" {
  value = data.windows_hostname.current.restart_pending
}

# Conditional hostname change based on current name
data "windows_hostname" "check" {}

resource "windows_hostname" "update" {
  count    = data.windows_hostname.check.hostname != "DESIRED-NAME" ? 1 : 0
  hostname = "DESIRED-NAME"
  restart  = true
}

# Use hostname in other resources or outputs
data "windows_hostname" "server" {}

locals {
  server_name = data.windows_hostname.server.hostname
  is_domain_joined = data.windows_hostname.server.part_of_domain
}

# Create naming convention based on hostname
data "windows_hostname" "base" {}

resource "windows_localuser" "admin" {
  username    = "admin_${lower(data.windows_hostname.base.hostname)}"
  password    = var.admin_password
  description = "Admin for ${data.windows_hostname.base.hostname}"
}

# Check domain membership
data "windows_hostname" "domain_check" {}

output "domain_membership" {
  value = {
    is_domain_member = data.windows_hostname.domain_check.part_of_domain
    domain_name      = data.windows_hostname.domain_check.domain
    workgroup_name   = data.windows_hostname.domain_check.workgroup
  }
}

# Verify hostname format before operations
data "windows_hostname" "validation" {}

locals {
  hostname_valid = length(data.windows_hostname.validation.hostname) <= 15
  hostname_compliant = !can(regex("[^A-Za-z0-9-]", data.windows_hostname.validation.hostname))
}

output "hostname_validation" {
  value = {
    valid     = local.hostname_valid
    compliant = local.hostname_compliant
  }
}

# Use with custom timeout for slow connections
data "windows_hostname" "remote" {
  command_timeout = 300
}

# Multi-environment hostname detection
data "windows_hostname" "env_detect" {}

locals {
  environment = (
    can(regex("^DEV-", data.windows_hostname.env_detect.hostname)) ? "development" :
    can(regex("^QA-", data.windows_hostname.env_detect.hostname)) ? "qa" :
    can(regex("^PROD-", data.windows_hostname.env_detect.hostname)) ? "production" :
    "unknown"
  )
}

output "detected_environment" {
  value = local.environment
}