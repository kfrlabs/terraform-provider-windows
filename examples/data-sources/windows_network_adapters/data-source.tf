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

# All physical, visible adapters that are up.
data "windows_network_adapters" "physical_up" {
  physical_only = true
  status        = "Up"
}

output "adapter_names" {
  value       = [for a in data.windows_network_adapters.physical_up.adapters : a.name]
  description = "Names of the physical adapters that are up."
}

locals {
  # Never place the storage address on the management NIC.
  storage_nic = [
    for a in data.windows_network_adapters.physical_up.adapters :
    a if !a.is_management
  ][0]
}

resource "windows_net_ip_address" "storage" {
  interface_alias = local.storage_nic.name
  ip_address      = "198.51.100.10"
  prefix_length   = 24
}
