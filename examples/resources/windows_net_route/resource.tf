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

# Static route to a remote network (storage network) through a gateway on
# the same subnet. The gateway must be on-link on the interface; on-link
# routes below use the unspecified address instead.
resource "windows_net_route" "backup" {
  destination_prefix = "198.51.100.0/24" # documentation range, RFC 5737
  interface_alias    = "Ethernet 2"
  next_hop           = "192.0.2.1"
  route_metric       = 10

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

# On-link route (no gateway): the next hop is the unspecified address.
resource "windows_net_route" "onlink" {
  destination_prefix = "203.0.113.0/24" # documentation range, RFC 5737
  interface_alias    = "Ethernet 2"
  next_hop           = "0.0.0.0"
}

# Backup default gateway: a higher effective metric than the existing default
# route means this route stays idle until that route disappears. Only
# route_metric updates in place; changing the prefix, next hop or interface
# replaces the resource.
resource "windows_net_route" "backup_gateway" {
  destination_prefix = "0.0.0.0/0"
  interface_alias    = "Ethernet 2"
  next_hop           = "192.0.2.254"
  route_metric       = 500
}

# Guard a default-gateway change with a precondition on the current default
# route: refuse to apply when the live gateway is not the expected one.
resource "windows_net_route" "default" {
  destination_prefix = "0.0.0.0/0"
  interface_alias    = "Ethernet 2"
  next_hop           = "192.0.2.1"
  route_metric       = 256

  lifecycle {
    precondition {
      condition     = data.windows_net_route.current_default.next_hop == "192.0.2.1"
      error_message = "The live default gateway changed out-of-band; re-check before replacing it."
    }
  }
}

output "backup_effective_metric" {
  value       = windows_net_route.backup.effective_metric
  description = "Effective metric (route + interface) Windows uses to select the backup route."
}
