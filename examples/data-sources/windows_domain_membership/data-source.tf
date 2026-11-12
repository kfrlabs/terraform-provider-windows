terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host     = var.windows_host
  username = var.windows_username
  password = var.windows_password
}

# Singleton — no lookup keys required.
data "windows_domain_membership" "current" {}

output "part_of_domain" {
  value = data.windows_domain_membership.current.part_of_domain
}

output "domain" {
  value = data.windows_domain_membership.current.domain
}

output "domain_role" {
  value = data.windows_domain_membership.current.domain_role
}

output "secure_channel_ok" {
  value = data.windows_domain_membership.current.secure_channel_ok
}

# Inventory-only read: skip the Test-ComputerSecureChannel probe
# (secure_channel_ok is then null).
data "windows_domain_membership" "inventory" {
  check_secure_channel = false
}

# Gate domain-dependent management on the observed join state.
resource "windows_local_group_member" "domain_admins" {
  count  = data.windows_domain_membership.current.part_of_domain ? 1 : 0
  group  = "Administrators"
  member = "CORP\\Domain Admins"
}
