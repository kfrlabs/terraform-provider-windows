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

# Read-only lookup of an existing static address: by address alone, or
# refined with the interface alias. Zero or several matches is an error.
data "windows_net_ip_address" "by_address" {
  ip_address = "192.0.2.10" # documentation range, RFC 5737
}

output "storage_interface" {
  value       = data.windows_net_ip_address.by_address.interface_alias
  description = "Interface owning the looked-up address."
}

output "storage_prefix_length" {
  value       = data.windows_net_ip_address.by_address.prefix_length
  description = "Observed prefix length of the looked-up address."
}
