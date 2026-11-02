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

# Static IPv4 address on a secondary NIC (storage network). The interface
# must already exist; disable_dhcp is required when the interface still has
# DHCP enabled. The default gateway is NOT managed here — use
# windows_net_route for it.
resource "windows_net_ip_address" "storage" {
  interface_alias = "Ethernet 2"
  ip_address      = "192.0.2.10" # documentation range, RFC 5737
  prefix_length   = 24
  disable_dhcp    = true

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "10m"
    read   = "5m"
    update = "10m"
    delete = "10m"
  }
}

# Static IPv6 address on the same secondary NIC. Several resources may target
# the same interface, one per address.
resource "windows_net_ip_address" "storage_v6" {
  interface_alias = "Ethernet 2"
  ip_address      = "2001:db8::10" # documentation range, RFC 3849
  prefix_length   = 64
}

output "storage_address_state" {
  value       = windows_net_ip_address.storage.address_state
  description = "Duplicate-detection state of the storage address (Preferred when healthy)."
}
